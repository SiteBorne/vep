"""Exact-input evidence reuse on real workspaces: when it applies, when it must refuse, and independent Python/Node chain verification."""
import json
import shutil
import subprocess
import unittest
from pathlib import Path

from tests.helpers import AUTH, VepTestCase
from vep import candidates, controller, reuse, snapshots, trustpolicy, versions
from vep.errors import StateError

ROOT = Path(__file__).resolve().parents[1]
NODE = shutil.which("node")
NOW = "2099-01-01T00:00:00Z"


class ReuseTests(VepTestCase):
    def certified_pair(self):
        e = self.env()
        a = e.candidate({"extra.py": "X = 1\n"})
        controller.enqueue(e.ws, a)
        out = controller.run_one(e.ws, controller.LocalToolWorker("w", AUTH))
        self.assertEqual(out["candidate_status"], "CERTIFIED")
        b = e.candidate({"extra.py": "X = 1\n"}, author="second-agent")  # byte-identical tree => identical snapshot id
        return e, a, b, out

    def raw_key(self, e):
        with e.ws.db.read() as c:
            return bytes.fromhex(c.execute("SELECT public_key_hex FROM trusted_keys").fetchone()["public_key_hex"])

    def policy(self, e, snap, **kw):
        return trustpolicy.make_policy("rp", [trustpolicy.issuer(self.raw_key(e))], ["vep-local-evaluator/*"], "TRUSTED_LOCAL", snapshot_id=snap, **kw)

    def test_identical_tree_gets_a_derived_attestation_that_names_the_original_proof(self):
        e, a, b, out = self.certified_pair()
        snap = candidates.get_state(e.ws, b)["snapshot_id"]
        self.assertEqual(snap, candidates.get_state(e.ws, a)["snapshot_id"])
        att, digest = reuse.derive(e.ws, b)
        self.assertEqual((att["original_candidate_id"], att["candidate_id"], att["reuse_mode"]), (a, b, "EXACT_INPUT"))
        with e.ws.db.read() as c:
            orig = c.execute("SELECT id FROM evidence WHERE candidate_id=?", (a,)).fetchone()["id"]
            self.assertIsNone(c.execute("SELECT id FROM evidence WHERE candidate_id=?", (b,)).fetchone())  # no evidence transplanted
        self.assertEqual(att["original_evidence_id"], orig)
        self.assertEqual(candidates.get_state(e.ws, b)["status"], "PROPOSED")  # a derived attestation is not a certificate
        self.assertEqual(reuse.derive(e.ws, b)[1], digest)  # idempotent
        bundle = reuse.export_bundle(e.ws, b)
        r = trustpolicy.verify_derived_authorized(bundle, self.policy(e, snap), NOW)
        self.assertEqual((r["valid"], r["assurance"]), (True, "AUTHORIZED_DERIVED"))
        self.assertEqual(r["derivation_chain"][2], a)

    def test_reuse_is_refused_when_any_exact_input_differs(self):
        e, a, b, _ = self.certified_pair()
        changed = e.candidate({"extra.py": "X = 2\n"})
        with self.assertRaisesRegex(StateError, "NO_REUSABLE_EVIDENCE"):
            reuse.derive(e.ws, changed)  # different source: no evidence exists for this snapshot
        orig_runner = reuse.execution.runner_digest
        reuse.execution.runner_digest = lambda: "0" * 64
        self.addCleanup(setattr, reuse.execution, "runner_digest", orig_runner)
        with self.assertRaisesRegex(StateError, "RUNNER_CHANGED"):
            reuse.derive(e.ws, b)
        reuse.execution.runner_digest = orig_runner
        orig_eval = versions.evaluator_id
        versions.evaluator_id = lambda tl: "vep-local-evaluator/9.9.9/" + tl
        self.addCleanup(setattr, versions, "evaluator_id", orig_eval)
        with self.assertRaisesRegex(StateError, "EVALUATOR_CHANGED"):
            reuse.derive(e.ws, b)

    def test_failed_evidence_is_never_reused(self):
        e = self.env()
        bad = e.candidate({"arithmetic.py": "def add(a, b):\n    return 0\n"})
        controller.enqueue(e.ws, bad)
        self.assertEqual(controller.run_one(e.ws, controller.LocalToolWorker("w", AUTH))["candidate_status"], "REJECTED")
        twin = e.candidate({"arithmetic.py": "def add(a, b):\n    return 0\n"})
        with self.assertRaisesRegex(StateError, "NO_REUSABLE_EVIDENCE"):
            reuse.derive(e.ws, twin)

    def test_tampered_chain_is_rejected_by_the_verifier(self):
        e, a, b, _ = self.certified_pair()
        snap = candidates.get_state(e.ws, b)["snapshot_id"]
        bundle = reuse.export_bundle(e.ws, b)
        other = e.candidate({"extra.py": "X = 3\n"})
        controller.enqueue(e.ws, other)
        controller.run_one(e.ws, controller.LocalToolWorker("w", AUTH))
        with e.ws.db.read() as c:
            ev2 = c.execute("SELECT envelope_digest FROM evidence WHERE candidate_id=?", (other,)).fetchone()["envelope_digest"]
        swapped = dict(bundle, evidence_envelope=json.loads(e.ws.cas.get(ev2)))  # evidence of a different tree
        self.assertEqual(trustpolicy.verify_derived_authorized(swapped, self.policy(e, snap), NOW)["code"], "EVIDENCE_DIGEST_MISMATCH")
        self.assertEqual(trustpolicy.verify_derived_authorized({**bundle, "bundle_version": 2}, self.policy(e, snap), NOW)["code"], "UNSUPPORTED_BUNDLE_VERSION")
        other_issuer = trustpolicy.make_policy("rp", [trustpolicy.issuer(b"\x02" * 32)], ["vep-local-evaluator/*"], "TRUSTED_LOCAL", snapshot_id=snap)
        self.assertEqual(trustpolicy.verify_derived_authorized(bundle, other_issuer, NOW)["code"], "UNAUTHORIZED_ISSUER")

    @unittest.skipUnless(NODE, "node not installed: independent verification NOT RUN")
    def test_node_validates_the_same_derivation_chain(self):
        e, a, b, _ = self.certified_pair()
        snap = candidates.get_state(e.ws, b)["snapshot_id"]
        (self.tmp / "b3.json").write_text(json.dumps(reuse.export_bundle(e.ws, b)))
        (self.tmp / "p.json").write_text(json.dumps(self.policy(e, snap)))
        out = json.loads(subprocess.run([NODE, str(ROOT / "conformance/node/verify.mjs"), "derived", str(self.tmp / "b3.json"), str(self.tmp / "p.json"), NOW], capture_output=True, text=True).stdout)
        self.assertEqual((out["valid"], out["assurance"]), (True, "AUTHORIZED_DERIVED"))
        self.assertEqual(out["derivation_chain"][2], a)
        (self.tmp / "p2.json").write_text(json.dumps(self.policy(e, "snap-" + "0" * 64)))
        out = json.loads(subprocess.run([NODE, str(ROOT / "conformance/node/verify.mjs"), "derived", str(self.tmp / "b3.json"), str(self.tmp / "p2.json"), NOW], capture_output=True, text=True).stdout)
        self.assertEqual(out["code"], "SNAPSHOT_MISMATCH")


class SuiteTests(unittest.TestCase):
    def test_suite_12_extends_11_verbatim_and_regenerates(self):
        old = json.loads((ROOT / "conformance/vectors/suite-1.1.json").read_text())["vectors"]
        new = json.loads((ROOT / "conformance/vectors/suite-1.2.json").read_text())
        self.assertEqual(new["vectors"][:len(old)], old)
        import sys
        self.assertEqual(subprocess.run([sys.executable, str(ROOT / "scripts/gen_conformance_vectors_12.py"), "--check"]).returncode, 0)
        seen = {v["expect"]["code"] for v in new["vectors"] if v["op"] == "verify_derived"} - {None}
        specific = set(new["derived_reason_codes"]) - {"WRONG_TYPE", "SIGNATURE_INVALID"}
        self.assertEqual(specific - seen, set())

    def test_python_and_node_agree_on_every_vector(self):
        from vep import conformance
        suite = conformance.load_suite(ROOT / "conformance/vectors/suite-1.2.json")
        self.assertEqual([v["id"] for v in suite["vectors"] if not conformance.check_vector(v, conformance.run_vector(v))], [])
        if NODE:
            r = subprocess.run([NODE, str(ROOT / "conformance/node/verify.mjs"), "suite", str(ROOT / "conformance/vectors/suite-1.2.json")], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stdout)


if __name__ == "__main__":
    unittest.main()
