"""Offline regression tests for scripts/claude_live_e2e.py: classification, sanitizing, limits and the independent checks, using a fake `claude` that makes no model call.
Nothing here is evidence about Claude Code; it proves the harness will not report VERIFIED for the wrong reasons."""
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FAKE = ROOT / "tests" / "fixtures" / "fake_claude.py"
spec = importlib.util.spec_from_file_location("claude_live_e2e", ROOT / "scripts" / "claude_live_e2e.py")
H = importlib.util.module_from_spec(spec)
sys.modules["claude_live_e2e"] = H
spec.loader.exec_module(H)
NODE = shutil.which("node")


class Pure(unittest.TestCase):
    def test_refuses_without_authorization_and_over_budget(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "x.json"
            r = subprocess.run([sys.executable, str(ROOT / "scripts/claude_live_e2e.py"), "--out", str(out)], capture_output=True, text=True)
            self.assertEqual(r.returncode, 3)
            self.assertEqual(json.loads(out.with_suffix(".status.json").read_text())["CLAUDE_LIVE_E2E"], "UNVERIFIED")
            r = subprocess.run([sys.executable, str(ROOT / "scripts/claude_live_e2e.py"), "--authorize-model-run", "--max-budget-usd", "50", "--out", str(out)], capture_output=True, text=True)
            self.assertEqual(r.returncode, 2); self.assertFalse(out.exists())

    def test_sanitize_redacts_credentials_emails_and_paths_but_keeps_vep_ids(self):
        cid = "cand-" + "a" * 64
        t = H.sanitize({"cmd": "token=abcd1234efgh5678 sk-live_ABCDEFGHIJKLMNOP mail me@example.com /" + "Users" + "/alice/project/x.py " + cid,
                        "nested": [{"k": "Bearer abcdefghijklmnop12345"}], "long": "x" * 1000, "n": 3})
        s = json.dumps(t)
        for leak in ("abcd1234efgh5678", "ABCDEFGHIJKLMNOP", "me@example.com", "/" + "Users" + "/alice", "abcdefghijklmnop12345"):
            self.assertNotIn(leak, s)
        self.assertIn(cid, s); self.assertLess(len(t["long"]), 450); self.assertEqual(t["n"], 3)

    def stream(self, **kw):
        ev = [{"type": "system", "subtype": "init", "mcp_servers": [{"name": "vep", "status": kw.get("status", "connected")}],
               "tools": kw.get("tools", ["mcp__vep__vep_status"]), "skills": kw.get("skills", ["vep"])}]
        for i, (tool, err) in enumerate(kw.get("calls", [])):
            ev.append({"type": "assistant", "message": {"content": [{"type": "tool_use", "id": f"t{i}", "name": tool, "input": {}}]}})
            ev.append({"type": "user", "message": {"content": [{"type": "tool_result", "tool_use_id": f"t{i}", "content": "ok", "is_error": err}]}})
        return [json.dumps(e) for e in ev]

    def test_discovery_invocation_and_skill_activation_are_reported_separately(self):
        full = [("mcp__vep__vep_status", False), ("mcp__vep__vep_candidate_register", False), ("mcp__vep__vep_evaluate", False)]
        f = H.session_findings(H.parse_stream(self.stream(calls=full)))
        self.assertEqual((f["mcp_discovery"], f["mcp_tool_invocation"], f["skill_discovery"], f["skill_activation"]), ("VERIFIED", "VERIFIED", "VERIFIED", "NOT_OBSERVED"))
        f = H.session_findings(H.parse_stream(self.stream(calls=full + [("Skill", False)])))
        self.assertEqual(f["skill_activation"], "NOT_OBSERVED")  # a Skill call without the vep skill in its input does not count
        s = self.stream(calls=full)
        s.append(json.dumps({"type": "assistant", "message": {"content": [{"type": "tool_use", "id": "sk", "name": "Skill", "input": {"skill": "vep"}}]}}))
        self.assertEqual(H.session_findings(H.parse_stream(s))["skill_activation"], "VERIFIED")
        f = H.session_findings(H.parse_stream(self.stream(status="failed", tools=[], calls=[])))
        self.assertEqual((f["mcp_discovery"], f["mcp_tool_invocation"]), ("FAILED", "FAILED"))
        f = H.session_findings(H.parse_stream(self.stream(calls=[("mcp__vep__vep_status", True), ("mcp__vep__vep_candidate_register", False), ("mcp__vep__vep_evaluate", False)])))
        self.assertEqual(f["mcp_tool_invocation"], "FAILED")  # a tool that returned an error does not count as invoked successfully
        self.assertEqual(H.session_findings(H.parse_stream([]))["mcp_discovery"], "NOT_OBSERVED")

    def test_classify_requires_every_independent_item_and_ignores_skill_activation(self):
        good_f = {"mcp_discovery": "VERIFIED", "mcp_tool_invocation": "VERIFIED", "skill_activation": "NOT_OBSERVED"}
        keys = ["candidate_certified_by_controller", "change_present_and_executes", "evidence_matches_protected_evaluation", "ids_shown_to_model", "authorized_python",
                "authorized_node", "mutation_source_changed", "unauthorized_rejected"]
        good = {k: True for k in keys}
        self.assertEqual(H.classify(good_f, good, cut=None, exit_code=0), "VERIFIED")
        for k in keys:
            self.assertEqual(H.classify(good_f, {**good, k: False}, cut=None, exit_code=0), "FAILED", k)
            self.assertEqual(H.classify(good_f, {kk: v for kk, v in good.items() if kk != k}, cut=None, exit_code=0), "FAILED", k)  # missing is not a pass
        self.assertEqual(H.classify(good_f, good, cut="tool-call limit", exit_code=0), "FAILED")
        self.assertEqual(H.classify(good_f, good, cut=None, exit_code=1), "FAILED")
        self.assertEqual(H.classify({**good_f, "mcp_discovery": "NOT_OBSERVED"}, good, cut=None, exit_code=0), "FAILED")


class WithFakeClaude(unittest.TestCase):
    def run_mode(self, mode, **kw):
        env = dict(FAKE_CLAUDE_MODE=mode, FAKE_PY=sys.executable)
        old = {k: os.environ.get(k) for k in env}
        os.environ.update(env)
        pp = os.environ.get("PYTHONPATH")
        os.environ["PYTHONPATH"] = str(ROOT / "src") + (os.pathsep + pp if pp else "")
        try:
            return H.execute(str(FAKE), budget=1.0, timeout_s=kw.get("timeout_s", 120), max_tool_calls=kw.get("max_tool_calls", 40), model=None)
        finally:
            for k, v in old.items():
                os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)
            os.environ["PYTHONPATH"] = pp or ""
            if pp is None:
                os.environ.pop("PYTHONPATH", None)

    @unittest.skipUnless(NODE, "node not installed: the Node leg of the harness cannot pass")
    def test_a_complete_correct_session_is_verified_and_records_every_leg(self):
        o = self.run_mode("ok")
        self.assertEqual(o["CLAUDE_LIVE_E2E"], "VERIFIED", o["independent_checks"])
        self.assertEqual(o["SKILL_ACTIVATION"], "VERIFIED")
        ck = o["independent_checks"]
        for k in ("candidate_certified_by_controller", "change_present_and_executes", "evidence_matches_protected_evaluation", "ids_shown_to_model", "authorized_python",
                  "authorized_node", "mutation_source_changed", "unauthorized_rejected"):
            self.assertTrue(ck[k], k)
        self.assertNotIn("sk-abcdefghijklmnop1234", json.dumps(o))  # the fake leaked a key into a tool result; it must not reach the evidence
        self.assertIn("max_turns", o["limits"])

    @unittest.skipUnless(NODE, "node not installed")
    def test_work_done_without_activating_the_skill_is_verified_but_says_so(self):
        o = self.run_mode("no_skill")
        self.assertEqual((o["CLAUDE_LIVE_E2E"], o["SKILL_ACTIVATION"], o["session"]["skill_discovery"]), ("VERIFIED", "NOT_OBSERVED", "FAILED"))

    @unittest.skipUnless(NODE, "node not installed")
    def test_a_certified_candidate_without_the_requested_change_fails(self):
        o = self.run_mode("wrong_change")
        self.assertEqual(o["CLAUDE_LIVE_E2E"], "FAILED"); self.assertFalse(o["independent_checks"]["change_present_and_executes"])

    @unittest.skipUnless(NODE, "node not installed")
    def test_ids_the_model_was_never_shown_fail(self):
        o = self.run_mode("hidden_ids")
        self.assertEqual(o["CLAUDE_LIVE_E2E"], "FAILED"); self.assertFalse(o["independent_checks"]["ids_shown_to_model"])

    def test_no_work_and_no_server_fail(self):
        self.assertEqual(self.run_mode("no_tools")["CLAUDE_LIVE_E2E"], "FAILED")
        o = self.run_mode("mcp_not_connected")
        self.assertEqual((o["CLAUDE_LIVE_E2E"], o["session"]["mcp_discovery"]), ("FAILED", "FAILED"))

    def alive(self, pid):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        try:  # a zombie that has not been reaped yet is not running
            return subprocess.run(["ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True).stdout.strip()[:1] not in ("Z", "")
        except Exception:
            return True

    def test_limits_actively_kill_the_whole_process_group_while_it_runs(self):
        import time
        for mode, kw, expect in (("too_many_calls", dict(max_tool_calls=10), "tool-call limit"), ("hang", dict(timeout_s=3), "wall-time")):
            pidfile = Path(tempfile.mkdtemp()) / "pids.json"
            os.environ["FAKE_PIDFILE"] = str(pidfile)
            t0 = time.monotonic()
            o = self.run_mode(mode, **kw)
            elapsed = time.monotonic() - t0
            self.assertEqual(o["CLAUDE_LIVE_E2E"], "FAILED", mode); self.assertIn(expect, o["limits"]["cut_reason"])
            self.assertLess(elapsed, 60, f"{mode}: the run was cut, not waited out (the fake would have lingered 300 s)")
            pids = json.loads(pidfile.read_text())
            time.sleep(0.5)
            self.assertEqual([self.alive(p) for p in pids], [False, False], f"{mode}: parent and grandchild must be dead")

    @unittest.skipUnless(NODE, "node not installed")
    def test_a_fabricated_transcript_without_workspace_records_is_rejected(self):
        o = self.run_mode("fabricated")
        self.assertEqual(o["CLAUDE_LIVE_E2E"], "FAILED")
        self.assertEqual(o["session"]["mcp_tool_invocation"], "VERIFIED")  # the transcript alone looks like success...
        self.assertFalse(o["independent_checks"]["candidate_certified_by_controller"])  # ...but the workspace has no certificate


class MutationSpecificity(unittest.TestCase):
    def test_only_source_changed_counts(self):
        from vep.errors import VerificationFailed
        self.assertTrue(str(VerificationFailed("SOURCE_CHANGED: current tree x != certified y")).startswith("SOURCE_CHANGED"))
        self.assertFalse(str(VerificationFailed("evidence signature invalid")).startswith("SOURCE_CHANGED"))


if __name__ == "__main__":
    unittest.main()
