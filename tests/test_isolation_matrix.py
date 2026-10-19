"""Decision-logic tests for the isolation adapter using a STUB docker CLI (tests/fixtures/stub_docker.py).

These do NOT demonstrate isolation. They show that: a result of ISOLATED_VERIFIED requires every matrix test
to be observed as PASS, any failed/absent observation yields ISOLATION_UNVERIFIED, and the evaluator only
produces ISOLATED_VERIFIED evidence after a current attestation. Real-runtime results are NOT_RUN on hosts
without Docker+gVisor (see docs/RELEASE_BASELINE.md and the release gate report).
"""
import json
import os
import stat
import sys
import unittest
from pathlib import Path
from unittest import mock

from vep import candidates, certificates, isolation
from vep.canonical import canonical_bytes
from vep.errors import IsolationUnavailable
from vep.evidence import load_signed
from tests.helpers import VepTestCase

STUB = Path(__file__).parent / "fixtures" / "stub_docker.py"
PIN = "python@sha256:" + "a" * 64


class StubDockerCase(VepTestCase):
    def setUp(self):
        super().setUp()
        self.bin = self.tmp / "bin"; self.bin.mkdir()
        self.log = self.tmp / "docker.log"; self.log.write_text("")
        self.cfg_path = self.tmp / "stub.json"
        shim = self.bin / "docker"
        shim.write_text(f"#!/bin/sh\nexec {sys.executable} {STUB} \"$@\"\n")
        shim.chmod(shim.stat().st_mode | stat.S_IXUSR)
        self.docker = str(shim)
        env = mock.patch.dict(os.environ, {"STUB_DOCKER_CONFIG": str(self.cfg_path), "PATH": f"{self.bin}:{os.environ['PATH']}"})
        env.start(); self.addCleanup(env.stop)
        t9 = mock.patch.object(isolation, "T9_TIMEOUT_S", 1)
        t9.start(); self.addCleanup(t9.stop)
        self.configure()

    def configure(self, **kw):
        self.cfg_path.write_text(json.dumps({"pin": PIN, "log": str(self.log), **kw}))

    def verify(self):
        return isolation.verify_runtime(PIN, docker=self.docker)

    def calls(self):
        return [json.loads(l) for l in self.log.read_text().splitlines()]


class MatrixDecisionTests(StubDockerCase):
    def test_all_observations_pass_yields_verified_with_runtime_identity(self):
        att = self.verify()
        self.assertEqual(att["status"], "ISOLATED_VERIFIED", att["reasons"])
        self.assertEqual({r["status"] for r in att["results"].values()}, {"PASS"})
        self.assertEqual(sorted(att["results"]), sorted(isolation.MATRIX))
        self.assertEqual(att["runtime_identity"]["runtime"], "runsc")
        self.assertEqual(att["runtime_identity"]["corroboration"], "docker-inspect-only")

    def test_every_run_uses_the_hardened_plan_and_cleans_up(self):
        self.verify()
        runs = [c for c in self.calls() if c[:1] == ["run"] and "-d" not in c]
        self.assertTrue(runs)
        for c in runs:
            for flag in ("--pull=never", "--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges"):
                self.assertIn(flag, c)
            self.assertNotIn("--privileged", c)
            self.assertFalse(any("docker.sock" in x or ".vep" in x for x in c))
        names = {c[c.index("--name") + 1] for c in self.calls() if c[:1] == ["run"] and "--name" in c}
        removed = {c[-1] for c in self.calls() if c[:2] == ["rm", "-f"]}
        self.assertTrue(names <= removed, "every started container is force-removed")

    def test_each_failed_observation_blocks_verification(self):
        cases = {
            "T2": {"T2_source_write": {"ok": True, "value": 1}},
            "T3": {"T3_root_write": {"ok": True, "value": 1}},
            "T4": {"T4_key_files": {"ok": True, "value": ["/x/signing.pem"]}},
            "T5": {"T5_db_files": {"ok": True, "value": ["/x/vep.db"]}},
            "T6": {"T6_network_connect": {"ok": True, "value": None}},
            "T7": {"T7_cap_eff": {"ok": True, "value": "00000000a80425fb"}},
        }
        for t, override in cases.items():
            self.configure(probe_overrides=override)
            att = self.verify()
            self.assertEqual(att["status"], isolation.UNVERIFIED, t)
            self.assertEqual(att["results"][t]["status"], "FAIL", t)

    def test_resource_limit_not_enforced_blocks_verification(self):
        self.configure(oom_rc=0)
        att = self.verify()
        self.assertEqual((att["status"], att["results"]["T8"]["status"]), (isolation.UNVERIFIED, "FAIL"))

    def test_leftover_container_after_timeout_blocks_verification(self):
        self.configure(leave_container=True)
        self.assertEqual(self.verify()["results"]["T9"]["status"], "FAIL")

    def test_wrong_runtime_recorded_blocks_verification(self):
        self.configure(inspect="runc|none|true|false|134217728|64")
        att = self.verify()
        self.assertEqual((att["status"], att["results"]["T12"]["status"]), (isolation.UNVERIFIED, "FAIL"))
        self.assertIsNone(att["runtime_identity"])

    def test_missing_runsc_marks_everything_not_run_never_pass(self):
        self.configure(runsc=False)
        att = self.verify()
        self.assertEqual(att["status"], isolation.UNVERIFIED)
        self.assertEqual({r["status"] for r in att["results"].values()}, {"NOT_RUN"})
        self.assertFalse([c for c in self.calls() if c[:1] == ["run"]], "nothing may be started without runsc")

    def test_image_substitution_blocks_verification(self):
        self.configure(digest_ok=False)
        att = self.verify()
        self.assertEqual(att["status"], isolation.UNVERIFIED)
        self.assertTrue(any("pinned digest" in r for r in att["reasons"]))

    def test_missing_image_blocks_verification_and_never_pulls(self):
        self.configure(image_present=False)
        self.assertEqual(self.verify()["status"], isolation.UNVERIFIED)
        self.assertFalse([c for c in self.calls() if c[:1] == ["pull"]])

    def test_unpinned_image_is_refused(self):
        att = isolation.verify_runtime("python:latest", docker=self.docker)
        self.assertEqual(att["status"], isolation.UNVERIFIED)

    def test_attestation_goes_stale_when_the_image_changes(self):
        att = self.verify()
        self.assertTrue(isolation.attestation_is_current(att, PIN, self.docker)[0])
        self.configure(digest_ok=False)
        self.assertFalse(isolation.attestation_is_current(att, PIN, self.docker)[0])
        self.assertFalse(isolation.attestation_is_current({**att, "status": isolation.UNVERIFIED}, PIN, self.docker)[0])
        self.assertFalse(isolation.attestation_is_current(att, "python@sha256:" + "b" * 64, self.docker)[0])

    def test_capability_detector_reports_without_side_effects(self):
        caps = isolation.detect_capabilities(PIN, self.docker)
        self.assertTrue(caps["daemon"] and caps["runsc_registered"] and caps["image_present"])
        self.assertEqual(caps["image_pinned_digest_ok"], True)
        self.assertFalse([c for c in self.calls() if c[0] in ("run", "pull", "rm")])


class IsolatedEvaluationPlumbingTests(StubDockerCase):
    def test_isolated_evidence_requires_and_records_the_attestation(self):
        e = self.env()
        att = self.verify()
        cid = e.candidate({"extra.py": "X = 1\n"})
        r = e.evaluate(cid, mode="isolated", image=PIN, attestation=att, trusted_local_authorization=None)
        self.assertEqual((r["status"], r["trust_level"]), ("EVIDENCE_READY", "ISOLATED_VERIFIED"))
        cert = certificates.certify(e.ws, cid)
        ev = load_signed(e.ws, cert["evidence_envelope_digest"], "Evidence")
        self.assertEqual((ev["trust_level"], ev["isolation"]), ("ISOLATED_VERIFIED", "DOCKER_GVISOR"))
        self.assertEqual(e.ws.cas.get(ev["isolation_attestation_digest"]), canonical_bytes(att))
        self.assertEqual(ev["execution_environment"]["runtime"]["runtime"], "runsc")
        out = certificates.verify_certificate(e.ws, cert.id, require_trust="ISOLATED_VERIFIED")
        self.assertEqual(out["trust_level"], "ISOLATED_VERIFIED")

    def test_stale_attestation_is_refused_without_fallback(self):
        e = self.env()
        att = self.verify()
        self.configure(digest_ok=False)
        cid = e.candidate()
        with self.assertRaises(IsolationUnavailable):
            e.evaluate(cid, mode="isolated", image=PIN, attestation=att)
        self.assertEqual(candidates.get_state(e.ws, cid)["status"], "PROPOSED")

    def test_pytest_policy_is_not_supported_in_isolated_mode(self):
        e = self.env(evaluator={"kind": "pytest", "targets": ["tests"], "import_roots": ["."], "min_tests": 1})
        att = self.verify()
        with self.assertRaises(IsolationUnavailable):
            e.evaluate(e.candidate(), mode="isolated", image=PIN, attestation=att)


class RealHostTests(unittest.TestCase):
    def test_real_host_capability_report_is_honest(self):
        caps = isolation.detect_capabilities()
        self.assertIn("os", caps)
        att = isolation.verify_runtime("python@sha256:" + "a" * 64)  # certainly not present locally
        self.assertEqual(att["status"], isolation.UNVERIFIED)
        self.assertNotIn("PASS", {r["status"] for r in att["results"].values()})


if __name__ == "__main__":
    unittest.main()
