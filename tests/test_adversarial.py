"""Failure-prevention matrix F01-F20. Each test drives the real pipeline against a hostile or broken input."""
import base64
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

from vep import audits, budgets, candidates, certificates, execution, isolation, snapshots
from vep.canonical import canonical_bytes, strict_loads
from vep.errors import (BudgetError, IsolationUnavailable, PolicyViolation, StateError, VerificationFailed)
from vep.evidence import load_signed
from vep.objectives import create_objective
from vep.policies import make_policy
from tests.helpers import AUTH, BASE_FILES, VepTestCase


class FailureMatrix(VepTestCase):
    def violations(self, e, changes):
        cid = e.candidate(changes)
        return cid, candidates.check_policy(e.ws, cid)

    # --- F01 / F02: false greens -------------------------------------------------
    def test_F01_exit_zero_with_no_tests(self):
        files = dict(BASE_FILES)
        files["tests/test_arithmetic.py"] = "import unittest\ndef load_tests(l, t, p):\n    return unittest.TestSuite()\n"
        e = self.env(files=files)
        r = e.evaluate(e.candidate())
        self.assertEqual(r["status"], "REJECTED"); self.assertIn("ZERO_TESTS", r["reason"])

    def test_F02_every_test_skipped(self):
        e = self.env()
        r = e.evaluate(e.candidate({"arithmetic.py": "import unittest\nraise unittest.SkipTest('x')\n"}))
        self.assertIn("ALL_SKIPPED", r["reason"])

    # --- F03 / F04: evaluator reconfiguration and runner shadowing ----------------
    def test_F03_candidate_changes_evaluation_configuration(self):
        e = self.env()
        for path, body in (("pytest.ini", "[pytest]\naddopts=-k nothing\n"), ("conftest.py", "import sys\n"),
                           ("tests/conftest.py", "x=1\n"), ("setup.cfg", "[tool:pytest]\n"), ("tox.ini", ""),
                           ("pyproject.toml", "[tool.pytest.ini_options]\n"), ("sitecustomize.py", "import os\n")):
            cid, v = self.violations(e, {path: body})
            self.assertTrue(any("PROTECTED_PATH_CHANGED" in x for x in v), path)
            self.assertEqual(candidates.get_state(e.ws, cid)["status"], "REJECTED")

    def test_F03_candidate_edits_the_required_tests(self):
        e = self.env()
        cid, v = self.violations(e, {"tests/test_arithmetic.py": "import unittest\n"})
        self.assertIn("REQUIRED_TEST_MODIFIED:tests/test_arithmetic.py", v)
        cid, v = self.violations(e, {"tests/test_arithmetic.py": None})
        self.assertIn("REQUIRED_TEST_MISSING:tests/test_arithmetic.py", v)

    def test_F04_candidate_shadows_runner_or_stdlib(self):
        e = self.env()
        for path in ("unittest/__init__.py", "unittest.py", "json.py", "os.py", "pytest.py", "_pytest/__init__.py"):
            cid, v = self.violations(e, {path: "raise SystemExit(0)\n"})
            self.assertTrue(any("RUNNER_SHADOWING" in x for x in v), path)

    def test_F04_runner_prefers_stdlib_even_if_a_shadow_slips_through(self):
        # Defense in depth: drive the runner directly with a hostile module on the import path.
        proj = self.tmp / "shadow"
        (proj / "tests").mkdir(parents=True)
        (proj / "difflib.py").write_text("raise RuntimeError('shadowed stdlib difflib')\n")
        (proj / "tests" / "test_a.py").write_text(
            "import unittest, difflib\nclass T(unittest.TestCase):\n    def test_a(self):\n"
            "        self.assertTrue(hasattr(difflib, 'SequenceMatcher'))\n")
        rep = self.tmp / "rep.json"
        cfg = json.dumps({"root": str(proj), "start_dir": "tests", "pattern": "test*.py",
                          "import_roots": ["."], "report_path": str(rep)})
        r = subprocess.run([sys.executable, "-I", str(execution.RUNNER_PATH), cfg], capture_output=True, text=True, cwd=proj)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(rep.read_text())["passed"], ["test_a.T.test_a"])

    # --- F05 / F06: mutation and VEP internal state ---------------------------------
    def test_F05_candidate_mutates_workspace_during_evaluation(self):
        e = self.env()
        evil = "import os\nos.chmod('.', 0o755)\nopen('planted.txt', 'w').write('x')\nos.chmod('.', 0o555)\n" + BASE_FILES["arithmetic.py"]
        r = e.evaluate(e.candidate({"arithmetic.py": evil}))
        self.assertEqual(r["status"], "REJECTED"); self.assertIn("WORKSPACE_MUTATED", r["reason"])

    def test_F06_staged_tree_contains_no_vep_state_and_state_is_unreachable_relatively(self):
        e = self.env()
        e.ws.state.joinpath("secret.txt").write_text("s")
        probe = ("import os\nfound=[]\np=os.getcwd()\nwhile True:\n    if os.path.exists(os.path.join(p,'.vep')): found.append(p)\n"
                 "    n=os.path.dirname(p)\n    if n==p: break\n    p=n\nif found or os.path.exists('.vep'):\n"
                 "    raise RuntimeError('VEP state reachable: %r' % found)\n") + BASE_FILES["arithmetic.py"]
        r = e.evaluate(e.candidate({"arithmetic.py": probe}))
        self.assertEqual(r["verdict"], "PASS", r)
        snap = e.ws.get_object(e.ws.get_object(r["candidate_id"], "Candidate")["snapshot_id"], "Snapshot")
        self.assertFalse(any(x["path"].startswith(".vep") for x in snap["entries"]))

    def test_F06_tampering_with_the_signing_key_is_detected(self):
        e = self.env()
        evil = f"open({str(e.keystore.path)!r}, 'ab').write(b'tamper')\n" + BASE_FILES["arithmetic.py"]
        r = e.evaluate(e.candidate({"arithmetic.py": evil}))
        self.assertEqual(r["status"], "REJECTED"); self.assertIn("VEP_STATE_TAMPERED", r["reason"])

    def test_F06_evaluation_environment_is_scrubbed(self):
        e = self.env()
        os.environ["VEP_SECRET_FOR_TEST"] = "hunter2"
        self.addCleanup(os.environ.pop, "VEP_SECRET_FOR_TEST", None)
        probe = "import os\nassert 'VEP_SECRET_FOR_TEST' not in os.environ\nassert 'PYTHONPATH' not in os.environ\n" + BASE_FILES["arithmetic.py"]
        self.assertEqual(e.evaluate(e.candidate({"arithmetic.py": probe}))["verdict"], "PASS")

    # --- F07 / F08: stale certificates and altered evidence ----------------------------
    def test_F07_certificate_for_obsolete_source(self):
        e = self.env()
        cid = e.candidate({"x.py": "A=1\n"}); e.evaluate(cid)
        cert = certificates.certify(e.ws, cid)
        (e.last_dir / "x.py").write_text("A=2\n")
        with self.assertRaises(VerificationFailed):
            certificates.verify_certificate(e.ws, cert.id, current_root=e.last_dir)

    def test_F08_evidence_altered_after_creation(self):
        e = self.env()
        cid = e.candidate(); e.evaluate(cid)
        cert = certificates.certify(e.ws, cid)
        env = strict_loads(e.ws.cas.get(cert["evidence_envelope_digest"]))
        payload = strict_loads(base64.b64decode(env["payload"]))
        payload["fields"]["tests_skipped"] = 0; payload["fields"]["exit_code"] = 0; payload["fields"]["tests_run"] = 99
        env["payload"] = base64.b64encode(canonical_bytes(payload)).decode()
        forged = e.ws.cas.put(canonical_bytes(env))
        with self.assertRaisesRegex(VerificationFailed, "signature invalid"):
            load_signed(e.ws, forged, "Evidence")

    # --- F09 / F10: budget bypass and duplicate spending ---------------------------------
    def test_F09_candidate_cannot_bypass_budget_authorization(self):
        e = self.env(budget=None)
        cid = e.candidate()
        with self.assertRaises(BudgetError):
            e.evaluate(cid)
        with e.ws.db.read() as c:
            self.assertEqual(c.execute("SELECT COUNT(*) n FROM evidence").fetchone()["n"], 0)

    def test_F10_duplicate_requests_do_not_duplicate_spending(self):
        e = self.env()
        cid = e.candidate(); e.evaluate(cid)
        for _ in range(3):
            with self.assertRaises(StateError):
                e.evaluate(cid)
        self.assertEqual(budgets.report(e.ws, f"objective:{e.objective.id}")["settled"], "0.001")
        budgets.reserve(e.ws, f"objective:{e.objective.id}", "0.01", "dup")
        budgets.reserve(e.ws, f"objective:{e.objective.id}", "0.01", "dup")
        self.assertEqual(budgets.report(e.ws, f"objective:{e.objective.id}")["reserved"], "0.01")

    # --- F11: incorrect cached results ------------------------------------------------
    def test_F11_cache_never_serves_results_for_changed_inputs_or_tampered_entries(self):
        e = self.env()
        a = e.candidate({"x.py": "A=1\n"}); e.evaluate(a)
        with e.ws.db.read() as c:
            action_id = c.execute("SELECT action_id FROM evidence WHERE candidate_id=?", (a,)).fetchone()[0]
        self.assertEqual(execution.cached_evidence(e.ws, action_id)["candidate_id"], a)
        b = e.candidate({"x.py": "A=2\n"}); e.evaluate(b)
        with e.ws.db.read() as c:
            action_b = c.execute("SELECT action_id FROM evidence WHERE candidate_id=?", (b,)).fetchone()[0]
        self.assertNotEqual(action_id, action_b)
        self.assertIsNone(execution.cached_evidence(e.ws, "act-" + "0" * 64))
        with e.ws.db.read() as c:
            dig = c.execute("SELECT envelope_digest FROM evidence WHERE candidate_id=?", (a,)).fetchone()[0]
        p = e.ws.cas._path(dig); os.chmod(p, 0o644); p.write_bytes(p.read_bytes()[:-5])
        with self.assertRaises(VerificationFailed):
            execution.cached_evidence(e.ws, action_id)

    # --- F12-F16: static audits (policy-defined; detailed cases in test_audits) ----------
    def test_F12_to_F16_are_enforced_by_policy_audits_on_the_candidate_snapshot(self):
        rules = {"id": "readiness", "file": "status.json", "rules": [
            {"type": "aggregate_all", "aggregate": "ready", "components": "components", "component_flag": "ready"},
            {"type": "require_present", "path": "credentials.present"},
            {"type": "implies", "if": {"path": "ready", "equals": True}, "then": {"path": "credentials.present", "equals": True}},
            {"type": "forbid_when", "when": {"path": "mode", "equals": "production"}, "forbidden": {"path": "backend", "in": ["fixture"]}},
            {"type": "forbid_values", "path": "public.endpoints", "values": ["/debug"]}]}
        good = {"ready": True, "mode": "production", "backend": "real", "credentials": {"present": True},
                "components": {"a": {"ready": True}}, "public": {"endpoints": ["/health"]}}
        files = {**BASE_FILES, "status.json": json.dumps(good)}
        e = self.env(files=files, audits=[rules])
        self.assertEqual(e.evaluate(e.candidate({"n.py": "x=1\n"}))["verdict"], "PASS")
        bads = [dict(good, components={"a": {"ready": True}, "b": {"ready": False}}),      # F12
                dict(good, ready=False),                                                      # F13
                dict(good, backend="fixture"),                                                # F14
                dict(good, public={"endpoints": ["/health", "/debug/state"]}),                # F15
                {k: v for k, v in good.items() if k != "credentials"},                       # F16
                dict(good, credentials={"present": False})]                                   # F16
        for doc in bads:
            cid = e.candidate({"status.json": json.dumps(doc)})
            with self.assertRaises(PolicyViolation):
                e.evaluate(cid)
            self.assertEqual(candidates.get_state(e.ws, cid)["status"], "REJECTED")

    # --- F17 / F18: isolation honesty ------------------------------------------------------
    def test_F17_local_execution_is_never_represented_as_isolated(self):
        e = self.env()
        r = e.evaluate(e.candidate())
        self.assertIn("no security isolation", r["isolation"])
        cid = r["candidate_id"]
        cert = certificates.certify(e.ws, cid)
        self.assertEqual(certificates.verify_certificate(e.ws, cert.id)["isolation_of_evidence"], "NONE_TRUSTED_LOCAL")
        ev = load_signed(e.ws, cert["evidence_envelope_digest"], "Evidence")
        self.assertEqual(ev["isolation"], "NONE_TRUSTED_LOCAL")

    def test_F18_unavailable_security_runtime_never_falls_back_to_host(self):
        e = self.env()
        cid = e.candidate()
        with mock.patch.object(execution, "probe", return_value=isolation.ProbeResult(isolation.UNVERIFIED, ["absent"])), \
                mock.patch("subprocess.Popen", side_effect=AssertionError("host execution attempted")):
            with self.assertRaises(IsolationUnavailable):
                e.evaluate(cid, mode="isolated")
        self.assertEqual(candidates.get_state(e.ws, cid)["status"], "PROPOSED")

    # --- F19: composition of independently valid changes ---------------------------------------
    def test_F19_certificates_do_not_transfer_to_a_composition(self):
        e = self.env()
        a = e.candidate({"a.py": "A=1\n"}); dir_a = e.last_dir
        b = e.candidate({"b.py": "B=1\n"}); dir_b = e.last_dir
        e.evaluate(a); cert_a = certificates.certify(e.ws, a)
        e.evaluate(b); cert_b = certificates.certify(e.ws, b)
        comp = candidates.compose(e.ws, e.base.id, a, b)
        self.assertEqual(comp["conflicts"], [])
        merged = self.tmp / "merged"; snapshots.materialize(e.ws, comp["snapshot"], merged, readonly=False)
        for cert in (cert_a, cert_b):
            with self.assertRaisesRegex(VerificationFailed, "SOURCE_CHANGED"):
                certificates.verify_certificate(e.ws, cert.id, current_root=merged)
        cc = candidates.register_candidate(e.ws, e.objective.id, comp["snapshot"].id, "merger")
        self.assertEqual(candidates.get_state(e.ws, cc.id)["status"], "PROPOSED")
        self.assertEqual(e.evaluate(cc.id)["verdict"], "PASS")  # must earn its own evidence

    def test_F19_semantic_interference_is_caught_by_the_composed_evaluation(self):
        files = {"api.py": "def f():\n    return 1\n", "use.py": "",
                 "tests/test_all.py": "import unittest, api, use\nclass T(unittest.TestCase):\n    def test_f(self):\n        self.assertEqual(api.f(), 1)\n"
                                       "    def test_use(self):\n        self.assertTrue(use.ok())\n"}
        e = self.env(files={**files, "use.py": "import api\ndef ok():\n    return api.f() == 1\n"})
        a = e.candidate({"api.py": "def f():\n    return 1\ndef g():\n    return 2\n"})   # additive, valid alone
        b = e.candidate({"use.py": "import api\ndef ok():\n    return api.f() == 1 and True\n"})  # valid alone
        c = e.candidate({"use.py": "import api\ndef ok():\n    return api.g() == 2\n"})    # needs api.g (invalid alone)
        self.assertEqual(e.evaluate(a)["verdict"], "PASS"); self.assertEqual(e.evaluate(b)["verdict"], "PASS")
        self.assertEqual(e.evaluate(c)["verdict"], "FAIL")
        comp = candidates.compose(e.ws, e.base.id, a, c)
        cc = candidates.register_candidate(e.ws, e.objective.id, comp["snapshot"].id, "merger")
        self.assertEqual(e.evaluate(cc.id)["verdict"], "PASS")

    # --- F20: changed objective or policy must not inherit evidence ---------------------------------
    def test_F20_new_policy_or_objective_does_not_inherit_old_certification(self):
        e = self.env()
        cid = e.candidate({"x.py": "A=1\n"}); e.evaluate(cid)
        cert = certificates.certify(e.ws, cid)
        pol2 = make_policy(e.ws, e.base, name="stricter", limits={"timeout_s": 7})
        obj2 = create_objective(e.ws, "obj", "desc", e.base.id, pol2.id)
        self.assertNotEqual(pol2.id, e.policy.id); self.assertNotEqual(obj2.id, e.objective.id)
        with self.assertRaises(VerificationFailed):
            certificates.verify_certificate(e.ws, cert.id, expect_objective_id=obj2.id)
        with self.assertRaises(VerificationFailed):
            certificates.verify_certificate(e.ws, cert.id, expect_policy_id=pol2.id)
        budgets.create_account(e.ws, f"objective:{obj2.id}", "objective", "1")
        snap_id = e.ws.get_object(cid, "Candidate")["snapshot_id"]
        same_code = candidates.register_candidate(e.ws, obj2.id, snap_id, "agent")
        self.assertNotEqual(same_code.id, cid)
        with e.ws.db.read() as c:
            self.assertEqual(c.execute("SELECT COUNT(*) n FROM evidence WHERE candidate_id=?", (same_code.id,)).fetchone()["n"], 0)
        with self.assertRaises(StateError):
            certificates.certify(e.ws, same_code.id)


if __name__ == "__main__":
    unittest.main()
