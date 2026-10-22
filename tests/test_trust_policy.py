"""Authorized verification: real workspace certificates against relying-party trust policies, in Python and Node; suite 1.1 integrity."""
import json
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

from tests.helpers import AUTH, VepTestCase, src_env
from vep import conformance, controller, trustpolicy
from vep.cli import main as cli_main

ROOT = Path(__file__).resolve().parents[1]
NODE = shutil.which("node")
NOW = "2099-01-01T00:00:00Z"


class SuiteIntegrityTests(unittest.TestCase):
    def test_suite_11_carries_the_frozen_10_vectors_verbatim_and_regenerates_identically(self):
        old = json.loads((ROOT / "conformance/vectors/suite-1.0.json").read_text())["vectors"]
        new = json.loads((ROOT / "conformance/vectors/suite-1.1.json").read_text())
        self.assertEqual(new["vectors"][:len(old)], old)
        self.assertGreaterEqual(sum(1 for v in new["vectors"] if v["op"] == "verify_authorized"), 39)
        r = subprocess.run([sys.executable, str(ROOT / "scripts/gen_conformance_vectors_11.py"), "--check"], capture_output=True)
        self.assertEqual(r.returncode, 0)
        r = subprocess.run([sys.executable, str(ROOT / "scripts/gen_conformance_vectors.py"), "--check"], capture_output=True)
        self.assertEqual(r.returncode, 0)  # the 1.0 file is untouched

    def test_every_authorized_reason_code_is_exercised(self):
        new = json.loads((ROOT / "conformance/vectors/suite-1.1.json").read_text())
        seen = {v["expect"]["code"] for v in new["vectors"] if v["op"] == "verify_authorized"} - {None}
        # the shared envelope/payload codes are exercised by the 1.0 bundle vectors; the policy-specific ones must appear here
        specific = set(trustpolicy.AUTHORIZED_CODES) - {"MALFORMED_ENVELOPE", "MALFORMED_PAYLOAD", "NONCANONICAL_PAYLOAD", "WRONG_TYPE", "UNSUPPORTED_SCHEMA_VERSION", "SCHEMA_INVALID"}
        self.assertEqual(specific - seen, set())

    def test_reference_agrees_with_every_vector(self):
        suite = conformance.load_suite(ROOT / "conformance/vectors/suite-1.1.json")
        self.assertEqual([v["id"] for v in suite["vectors"] if not conformance.check_vector(v, conformance.run_vector(v))], [])

    @unittest.skipUnless(NODE, "node not installed: independent verification NOT RUN")
    def test_node_agrees_on_every_vector(self):
        r = subprocess.run([NODE, str(ROOT / "conformance/node/verify.mjs"), "suite", str(ROOT / "conformance/vectors/suite-1.1.json")], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout)
        n = len(json.loads((ROOT / "conformance/vectors/suite-1.1.json").read_text())["vectors"])
        self.assertIn(f"{n}/{n}", r.stdout)


class RealCertificateTests(VepTestCase):
    def certified(self):
        e = self.env()
        controller.enqueue(e.ws, e.candidate({"extra.py": "X = 1\n"}))
        out = controller.run_one(e.ws, controller.LocalToolWorker("w", AUTH))
        return e, out["certificate_id"], e.ws.get_object(e.ws.get_object(out["candidate_id"], "Candidate")["snapshot_id"], "Snapshot").id

    def raw_key(self, e):
        with e.ws.db.read() as c:
            return bytes.fromhex(c.execute("SELECT public_key_hex FROM trusted_keys").fetchone()["public_key_hex"])

    def policy(self, e, snap, **kw):
        return trustpolicy.make_policy("rp", [trustpolicy.issuer(self.raw_key(e))], ["vep-local-evaluator/*"], "TRUSTED_LOCAL", snapshot_id=snap, **kw)

    def test_genuine_certificate_is_authorized_only_with_the_matching_policy(self):
        e, cert, snap = self.certified()
        b2 = conformance.export_bundle(e.ws, cert, version=2)
        self.assertEqual(set(b2), {"bundle_version", "certificate_envelope", "evidence_envelope"})
        ok = trustpolicy.verify_authorized(b2, self.policy(e, snap), NOW)
        self.assertEqual((ok["valid"], ok["assurance"]), (True, "AUTHORIZED"))
        self.assertEqual(trustpolicy.verify_authorized(b2, self.policy(e, "snap-" + "0" * 64), NOW)["code"], "SNAPSHOT_MISMATCH")
        other = trustpolicy.make_policy("rp", [trustpolicy.issuer(b"\x01" * 32)], ["vep-local-evaluator/*"], "TRUSTED_LOCAL", snapshot_id=snap)
        self.assertEqual(trustpolicy.verify_authorized(b2, other, NOW)["code"], "UNAUTHORIZED_ISSUER")
        self.assertEqual(trustpolicy.verify_authorized(b2, self.policy(e, snap, objective_id="obj-" + "1" * 64), NOW)["code"], "OBJECTIVE_MISMATCH")

    def test_key_revocation_and_rotation_semantics_on_a_real_key(self):
        e, cert, snap = self.certified()
        b2 = conformance.export_bundle(e.ws, cert, version=2)
        raw = self.raw_key(e)
        mk = lambda iss: trustpolicy.make_policy("rp", iss, ["vep-local-evaluator/*"], "TRUSTED_LOCAL", snapshot_id=snap)
        self.assertEqual(trustpolicy.verify_authorized(b2, mk([trustpolicy.issuer(raw, status="compromised", status_effective_at="2099-01-01T00:00:00Z")]), NOW)["code"], "REVOKED_KEY")
        self.assertEqual(trustpolicy.verify_authorized(b2, mk([trustpolicy.issuer(raw, status="retired", status_effective_at="2000-06-01T00:00:00Z")]), NOW)["code"], "REVOKED_KEY")
        self.assertTrue(trustpolicy.verify_authorized(b2, mk([trustpolicy.issuer(raw, status="retired", status_effective_at="2098-06-01T00:00:00Z")]), NOW)["valid"])

    @unittest.skipUnless(NODE, "node not installed: independent verification NOT RUN")
    def test_node_and_cli_agree_on_a_real_bundle(self):
        e, cert, snap = self.certified()
        d = self.tmp
        (d / "b.json").write_text(json.dumps(conformance.export_bundle(e.ws, cert, version=2)))
        (d / "p.json").write_text(json.dumps(self.policy(e, snap)))
        r = subprocess.run([NODE, str(ROOT / "conformance/node/verify.mjs"), "authorized", str(d / "b.json"), str(d / "p.json"), NOW], capture_output=True, text=True)
        out = json.loads(r.stdout)
        self.assertEqual((out["valid"], out["assurance"]), (True, "AUTHORIZED"))
        self.assertEqual(out["trust_policy_id"], trustpolicy.policy_id(self.policy(e, snap)))  # identical content identity in both implementations
        base = [sys.executable, "-m", "vep", "conformance", "verify", "--bundle", str(d / "b.json")]
        env = src_env()
        no_flags = subprocess.run(base, capture_output=True, text=True, env=env)
        self.assertNotEqual(no_flags.returncode, 0)  # refuses to emit a verdict that could be misread as authorization
        ok = subprocess.run(base + ["--trust-policy", str(d / "p.json"), "--now", NOW], capture_output=True, text=True, env=env)
        self.assertEqual(ok.returncode, 0, ok.stderr)
        # a v1 bundle is internal-consistency only and says so
        (d / "b1.json").write_text(json.dumps(conformance.export_bundle(e.ws, cert, version=1)))
        io = subprocess.run([sys.executable, "-m", "vep", "conformance", "verify", "--bundle", str(d / "b1.json"), "--internal-only"], capture_output=True, text=True, env=env)
        self.assertEqual(json.loads(io.stdout)["assurance"], "INTERNAL_CONSISTENCY_ONLY")
        self.assertIn("does NOT establish", json.loads(io.stdout)["warning"])


if __name__ == "__main__":
    unittest.main()
