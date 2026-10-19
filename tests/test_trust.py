"""Trust-model regression tests (R001-R004, R012, R015, R025). All drive real behavior."""
import base64
import json
from unittest import mock

from vep import candidates, certificates, execution, isolation, trust
from vep.canonical import canonical_bytes, strict_loads
from vep.errors import AuthorizationError, IsolationUnavailable, SchemaError, StateError, VerificationFailed
from vep.evidence import load_signed, open_envelope
from vep.objects import VEPObject
from vep.policies import make_policy
from vep.objectives import create_objective
from tests.helpers import BASE_FILES, VepTestCase


def evidence_fields(**kw):
    h = lambda c: c * 64
    f = {"candidate_id": "cand-" + h("1"), "objective_id": "obj-" + h("2"), "snapshot_id": "snap-" + h("3"),
         "policy_id": "pol-" + h("4"), "action_id": "act-" + h("5"), "runner_digest": h("6"), "argv": ["x"],
         "exit_code": 0, "verdict": "PASS", "tests_discovered": 1, "tests_run": 1, "tests_passed": 1,
         "tests_failed": 0, "tests_skipped": 0, "executed_ids_digest": h("7"), "stdout_digest": h("8"),
         "stderr_digest": h("9"), "staged_tree_snapshot_id": "snap-" + h("3"), "isolation": "NONE_TRUSTED_LOCAL",
         "trust_level": "TRUSTED_LOCAL", "evaluator_id": "vep-local-evaluator/test/TRUSTED_LOCAL",
         "execution_environment": {"kind": "host-subprocess"}, "started_at": "2026-01-01T00:00:00Z",
         "finished_at": "2026-01-01T00:00:01Z", "budget_reservation": "r"}
    f.update(kw)
    return f


class TrustLabelTests(VepTestCase):
    def certified(self, **env_kw):
        e = self.env(**env_kw)
        cid = e.candidate({"extra.py": "X = 1\n"})
        e.evaluate(cid)
        return e, cid, certificates.certify(e.ws, cid)

    def test_R001_local_evidence_is_labeled_trusted_local_everywhere(self):
        e, cid, cert = self.certified()
        ev = load_signed(e.ws, cert["evidence_envelope_digest"], "Evidence")
        self.assertEqual((ev["trust_level"], ev["isolation"]), ("TRUSTED_LOCAL", "NONE_TRUSTED_LOCAL"))
        self.assertNotIn("isolation_attestation_digest", ev.fields)
        self.assertEqual(cert["trust_level"], "TRUSTED_LOCAL")
        self.assertTrue(cert["evaluator_id"].startswith("vep-local-evaluator/"))
        with e.ws.db.read() as c:
            self.assertEqual(c.execute("SELECT trust_level FROM certificates").fetchone()[0], "TRUSTED_LOCAL")
            self.assertEqual(c.execute("SELECT trust_level FROM evidence").fetchone()[0], "TRUSTED_LOCAL")

    def test_R001_trust_level_cannot_be_inconsistent_with_isolation_facts(self):
        with self.assertRaises(SchemaError):  # claims verified isolation while running locally
            VEPObject.create("Evidence", evidence_fields(trust_level="ISOLATED_VERIFIED"))
        with self.assertRaises(SchemaError):  # verified without any attestation
            VEPObject.create("Evidence", evidence_fields(trust_level="ISOLATED_VERIFIED", isolation="DOCKER_GVISOR"))
        with self.assertRaises(SchemaError):  # local run carrying an attestation
            VEPObject.create("Evidence", evidence_fields(isolation_attestation_digest="a" * 64))
        with self.assertRaises(SchemaError):  # UNVERIFIED cannot pass
            VEPObject.create("Evidence", evidence_fields(trust_level="UNVERIFIED"))
        VEPObject.create("Evidence", evidence_fields(trust_level="ISOLATED_VERIFIED", isolation="DOCKER_GVISOR",
                                                     isolation_attestation_digest="a" * 64))

    def test_R001_relabeling_signed_evidence_breaks_the_signature(self):
        e, cid, cert = self.certified()
        env = strict_loads(e.ws.cas.get(cert["evidence_envelope_digest"]))
        payload = strict_loads(base64.b64decode(env["payload"]))
        payload["fields"].update(trust_level="ISOLATED_VERIFIED", isolation="DOCKER_GVISOR",
                                 isolation_attestation_digest="b" * 64)
        env["payload"] = base64.b64encode(canonical_bytes(payload)).decode()
        with self.assertRaisesRegex(VerificationFailed, "signature invalid"):
            open_envelope(e.ws, canonical_bytes(env), "Evidence")

    def test_tampered_execution_metadata_invalidates_evidence(self):
        e, cid, cert = self.certified()
        env = strict_loads(e.ws.cas.get(cert["evidence_envelope_digest"]))
        payload = strict_loads(base64.b64decode(env["payload"]))
        payload["fields"]["execution_environment"] = {"kind": "docker-gvisor"}
        env["payload"] = base64.b64encode(canonical_bytes(payload)).decode()
        with self.assertRaises(VerificationFailed):
            open_envelope(e.ws, canonical_bytes(env), "Evidence")

    def test_verifier_can_demand_isolated_evidence_and_local_evidence_fails(self):
        e, cid, cert = self.certified()
        ok = certificates.verify_certificate(e.ws, cert.id)
        self.assertEqual((ok["trust_level"], ok["required_trust"]), ("TRUSTED_LOCAL", "TRUSTED_LOCAL"))
        with self.assertRaisesRegex(VerificationFailed, "TRUST_LEVEL_INSUFFICIENT"):
            certificates.verify_certificate(e.ws, cert.id, require_trust="ISOLATED_VERIFIED")

    def test_certificate_with_mismatched_trust_level_is_rejected(self):
        e, cid, cert = self.certified()
        bad = VEPObject.create("Certificate", {**cert.fields, "trust_level": "ISOLATED_VERIFIED"})
        digest = e.ws.cas.put(e.keystore.sign(bad))  # even a key-holder cannot make evidence say otherwise
        with e.ws.db.tx() as c:
            c.execute("DROP TRIGGER cert_immutable_u")
            c.execute("UPDATE certificates SET envelope_digest=?, id=? WHERE id=?", (digest, bad.id, cert.id))
        with self.assertRaisesRegex(VerificationFailed, "trust level"):
            certificates.verify_certificate(e.ws, bad.id)

    def test_missing_evaluator_authority_prevents_certification(self):
        e = self.env()
        cid = e.candidate()
        e.evaluate(cid)
        with e.ws.db.tx() as c:
            c.execute("UPDATE trusted_keys SET revoked=1")
        with self.assertRaises(VerificationFailed):
            certificates.certify(e.ws, cid)
        self.assertEqual(candidates.get_state(e.ws, cid)["status"], "EVIDENCE_READY")

    def test_changed_policy_invalidates_policy_bound_evidence(self):
        e, cid, cert = self.certified()
        pol2 = make_policy(e.ws, e.base, name="other")
        obj2 = create_objective(e.ws, "o", "d", e.base.id, pol2.id)
        with self.assertRaises(VerificationFailed):
            certificates.verify_certificate(e.ws, cert.id, expect_policy_id=pol2.id)
        with self.assertRaises(VerificationFailed):
            certificates.verify_certificate(e.ws, cert.id, expect_objective_id=obj2.id)


class IsolationGateTests(VepTestCase):
    def test_R002_policy_requiring_isolation_never_runs_locally(self):
        e = self.env()
        pol = make_policy(e.ws, e.base, name="strict")
        strict = VEPObject.create("ExecutionPolicy", {**pol.fields, "required_trust": "ISOLATED_VERIFIED"})
        e.ws.put_object(strict)
        obj = create_objective(e.ws, "o", "d", e.base.id, strict.id)
        from vep import budgets
        budgets.create_account(e.ws, f"objective:{obj.id}", "objective", "1")
        cid = candidates.register_candidate(e.ws, obj.id, e.ws.get_object(e.candidate(), "Candidate")["snapshot_id"], "a").id
        with mock.patch.object(execution, "_run_limited", side_effect=AssertionError("must not execute")):
            with self.assertRaisesRegex(AuthorizationError, "ISOLATED_VERIFIED"):
                e.evaluate(cid)
        self.assertEqual(candidates.get_state(e.ws, cid)["status"], "PROPOSED")

    def test_R002_isolated_mode_requires_a_real_current_attestation(self):
        e = self.env()
        cid = e.candidate()
        image = "python@sha256:" + "a" * 64
        forged = {"status": "ISOLATED_VERIFIED", "image": image, "capabilities": {"image_id": "sha256:x"},
                  "runtime_identity": {"runtime": "runsc"}}
        unverified = {"status": "ISOLATION_UNVERIFIED", "image": image, "results": {}}
        with mock.patch.object(execution, "_run_limited", side_effect=AssertionError("must not execute")), \
                mock.patch.object(execution, "_run_isolated", side_effect=AssertionError("must not execute")):
            for kw in ({}, {"image": image}, {"attestation": forged}, {"image": image, "attestation": unverified},
                       {"image": image, "attestation": forged}):
                with self.assertRaises(IsolationUnavailable, msg=str(kw)):
                    e.evaluate(cid, mode="isolated", **kw)
        self.assertEqual(candidates.get_state(e.ws, cid)["status"], "PROPOSED")
        with e.ws.db.read() as c:
            self.assertEqual(c.execute("SELECT COUNT(*) FROM evidence").fetchone()[0], 0)

    def test_failed_isolation_never_downgrades_to_trusted_local(self):
        e = self.env()
        cid = e.candidate()
        with self.assertRaises(IsolationUnavailable):
            e.evaluate(cid, mode="isolated")  # trusted-local authorization is present, and must not matter
        self.assertEqual(candidates.get_state(e.ws, cid)["status"], "PROPOSED")

    def test_unverified_evidence_can_never_satisfy_any_requirement(self):
        for req in ("TRUSTED_LOCAL", "ISOLATED_VERIFIED"):
            self.assertFalse(trust.satisfies("UNVERIFIED", req))
        with self.assertRaises(SchemaError):
            trust.satisfies("TRUSTED_LOCAL", "UNVERIFIED")
        self.assertTrue(trust.satisfies("ISOLATED_VERIFIED", "TRUSTED_LOCAL"))
        self.assertFalse(trust.satisfies("TRUSTED_LOCAL", "ISOLATED_VERIFIED"))


class ReportForgeryTests(VepTestCase):
    FORGE = ("import atexit, json, sys\ncfg = json.loads(sys.argv[1])\n"
             "def forge():\n    json.dump({'kind': 'unittest', 'discovered': 99, 'run': 99, 'passed': "
             "['test_arithmetic.T.t%d' % i for i in range(99)], 'failed': [], 'errors': [], 'skipped': [], "
             "'expected_failures': [], 'unexpected_successes': []}, open(cfg['report_path'], 'w'))\n"
             "atexit.register(forge)\n")

    def test_R003_R015_forged_report_with_wrong_counts_is_rejected(self):
        e = self.env()
        r = e.evaluate(e.candidate({"arithmetic.py": self.FORGE + BASE_FILES["arithmetic.py"]}))
        self.assertEqual(r["status"], "REJECTED"); self.assertIn("REPORT_STDERR_MISMATCH", r["reason"])
        self.assertEqual(candidates.get_state(e.ws, r["candidate_id"])["status"], "REJECTED")

    def test_R015_forged_pass_over_real_failures_is_rejected(self):
        e = self.env()
        broken = self.FORGE + "def add(a, b):\n    return 0\n"
        r = e.evaluate(e.candidate({"arithmetic.py": broken}))
        self.assertEqual(r["status"], "REJECTED")
        self.assertTrue(any(k in r["reason"] for k in ("REPORT_STDERR_MISMATCH", "EXIT_REPORT_MISMATCH")), r)

    def test_crosscheck_unit_behavior(self):
        rep = {"run": 2, "failed": [], "errors": [], "unexpected_successes": []}
        ok = b"..\nRan 2 tests in 0.001s\n\nOK\n"
        execution.crosscheck_unittest_stderr(rep, ok)
        for bad in (b"", b"Ran 3 tests in 0s\n\nOK\n", b"Ran 2 tests in 0s\n\nFAILED (failures=1)\n"):
            with self.assertRaises(Exception):
                execution.crosscheck_unittest_stderr(rep, bad)

    def test_R025_candidate_content_never_reaches_the_evaluator_command(self):
        e = self.env()
        cid = e.candidate({"Makefile": "test:\n\techo hacked\n", "vep-policy.json": '{"command": "echo hacked"}',
                           "extra.py": "X=1\n"})
        # vep-policy*.json is protected; the rest must have no effect on the command line
        v = candidates.check_policy(e.ws, cid)
        self.assertTrue(any("vep-policy.json" in x for x in v))
        pol = e.policy
        argv, _ = execution.build_argv(pol, self.tmp / "staged", self.tmp)
        self.assertEqual(argv[1], "-I")
        self.assertNotIn("hacked", " ".join(argv))
        with self.assertRaises(Exception):
            policies = __import__("vep.policies", fromlist=["x"])
            policies.validate_evaluator({"kind": "unittest", "command": "echo hacked"})


class KeyExposureTests(VepTestCase):
    def test_key_material_never_reaches_snapshots_or_staging(self):
        e = self.env()
        (e.root / "stray_signing.pem").write_text("-----BEGIN " + "PRIVATE KEY-----\nx\n")
        (e.root / "id_ed25519").write_text("k")
        cid = e.candidate()
        snap = e.ws.get_object(e.ws.get_object(cid, "Candidate")["snapshot_id"], "Snapshot")
        names = [x["path"] for x in snap["entries"]]
        self.assertFalse([n for n in names if n.endswith(".pem") or "id_" in n or ".vep" in n], names)
        from vep import snapshots
        stage = self.tmp / "stage"
        snapshots.materialize(e.ws, snap, stage)
        self.addCleanup(snapshots.make_writable, stage)
        self.assertFalse(list(stage.rglob("*.pem")) or list(stage.rglob("signing*")))
