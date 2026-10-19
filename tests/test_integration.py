"""End-to-end: CLI via a real subprocess, demo script, benchmark script, installed entry point."""
import json
import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

from tests.helpers import BASE_FILES, VepTestCase, write_tree

ROOT = Path(__file__).resolve().parents[1]
VEP = [sys.executable, "-m", "vep"]


def run(args, cwd, ok=(0,)):
    r = subprocess.run(VEP + args, cwd=cwd, capture_output=True, text=True)
    assert r.returncode in ok, (args, r.returncode, r.stdout, r.stderr)
    return r


class CLITests(VepTestCase):
    def j(self, args, ok=(0,)):
        return json.loads(run(args + ["--json"], self.proj, ok).stdout)

    def setUp(self):
        super().setUp()
        self.proj = self.tmp / "proj"; self.proj.mkdir()
        write_tree(self.proj, BASE_FILES)

    def test_full_lifecycle_through_the_cli(self):
        init = self.j(["init"])
        self.assertNotIn("PRIVATE", json.dumps(init)); self.assertEqual(len(init["signing_key_id"]), 64)
        obj = self.j(["objective", "create", "--title", "t"])
        self.j(["budget", "create", "--account", f"objective:{obj['objective_id']}", "--kind", "objective", "--limit", "1.00"])
        self.assertEqual(self.j(["status"])["execution_mode"], "trusted-local only (no security isolation)")
        (self.proj / "extra.py").write_text("X = 1\n")
        cand = self.j(["candidate", "create", "--objective", obj["objective_id"]])
        r = run(["evaluate", "--candidate", cand["candidate_id"], "--json"], self.proj, ok=(7,))  # no authorization
        self.assertIn("AuthorizationError", r.stderr)
        ev = self.j(["evaluate", "--candidate", cand["candidate_id"], "--trusted-local-execution"])
        self.assertEqual(ev["status"], "EVIDENCE_READY")
        cert = self.j(["certify", "--candidate", cand["candidate_id"]])
        ok = self.j(["verify", "--certificate", cert["certificate_id"]])
        self.assertEqual(ok["mode"], "current-source")
        (self.proj / "extra.py").write_text("X = 2\n")
        bad = run(["verify", "--certificate", cert["certificate_id"]], self.proj, ok=(4,))
        self.assertIn("SOURCE_CHANGED", bad.stderr)
        self.j(["verify", "--certificate", cert["certificate_id"], "--historical"])
        self.assertEqual(self.j(["candidate", "show", "--id", cand["candidate_id"]])["state"]["status"], "CERTIFIED")

    def test_budget_and_tokens_commands(self):
        self.j(["init"])
        self.j(["budget", "create", "--account", "a", "--kind", "objective", "--limit", "1"])
        self.j(["budget", "reserve", "--account", "a", "--amount", "0.4", "--key", "k"])
        self.j(["budget", "reserve", "--account", "a", "--amount", "0.4", "--key", "k"])  # idempotent
        self.assertEqual(self.j(["budget", "show", "--account", "a"])["reserved"], "0.4")
        run(["budget", "reserve", "--account", "a", "--amount", "0.7", "--key", "k2"], self.proj, ok=(5,))
        self.j(["budget", "settle", "--key", "k", "--amount", "0.3"])
        self.assertEqual(self.j(["budget", "show", "--account", "a"])["settled"], "0.3")
        run(["budget", "settle", "--key", "k", "--amount", "0.31"], self.proj, ok=(5,))

    def test_tokens_command_records_receipt(self):
        self.j(["init"])
        obj = self.j(["objective", "create"])
        cand = self.j(["candidate", "create", "--objective", obj["objective_id"]])
        usage = self.tmp / "u.json"
        usage.write_text(json.dumps({"provider": "local", "model": "m", "pricing_version": "v1",
            "ordinary_input_tokens": 1000, "cached_input_tokens": 0, "cache_write_tokens": 0, "output_tokens": 500,
            "reasoning_tokens_in_output": 100, "usage_source": "simulated",
            "prices_per_million": {"input": "3", "cached_input": "0.3", "cache_write": "3.75", "output": "15"}}))
        r = self.j(["tokens", "record", "--candidate", cand["candidate_id"], "--usage-file", str(usage), "--key", "r1"])
        self.assertEqual(r["cost_usd"], "0.0105")
        self.assertTrue(self.j(["tokens", "record", "--candidate", cand["candidate_id"], "--usage-file", str(usage), "--key", "r1"])["duplicate"])

    def test_route_cache_audit_isolation_simulate(self):
        models = self.tmp / "m.json"; task = self.tmp / "t.json"
        models.write_text(json.dumps([{"name": "x", "price_in_per_m": "1", "price_out_per_m": "2", "context_capacity": 100000,
            "capabilities": ["code"], "acceptance_estimate": "0.9", "success_lower_bound": "0.95", "latency_s": "3",
            "max_risk": "high", "evidence_source": "measured"}]))
        task.write_text(json.dumps({"input_tokens": 100, "output_tokens": 100, "required_capabilities": ["code"]}))
        self.assertEqual(self.j(["route", "--models-file", str(models), "--task-file", str(task)])["selected"]["models"], ["x"])
        task.write_text(json.dumps({"input_tokens": 100, "output_tokens": 100, "required_capabilities": ["gpu"]}))
        run(["route", "--models-file", str(models), "--task-file", str(task)], self.proj, ok=(3,))
        c = self.j(["cache", "--prefix-tokens", "10000", "--input-price", "3", "--output-price", "15",
                    "--write-multiplier", "1.25", "--read-multiplier", "0.1", "--reuses", "5"])
        self.assertEqual(c["recommendation"], "USE_CACHE")
        a = self.tmp / "a.json"; target = self.tmp / "s.json"
        a.write_text(json.dumps({"id": "r", "rules": [{"type": "aggregate_all", "aggregate": "ready", "components": "c", "component_flag": "ok"}]}))
        target.write_text(json.dumps({"ready": True, "c": {"x": {"ok": False}}}))
        self.assertTrue(self.j(["audit", "--audit-file", str(a), "--target", str(target)], ok=(3,))["r"])
        target.write_text(json.dumps({"ready": True, "c": {"x": {"ok": True}}}))
        self.assertEqual(self.j(["audit", "--audit-file", str(a), "--target", str(target)])["r"], [])
        iso = json.loads(run(["isolation", "probe", "--json"], self.proj, ok=(0, 8)).stdout)
        self.assertIn(iso["status"], ("ISOLATION_UNVERIFIED", "ISOLATION_RUNTIME_PRESENT"))
        s1 = run(["simulate", "--tasks", "300", "--seed", "5", "--json"], self.proj).stdout
        s2 = run(["simulate", "--tasks", "300", "--seed", "5", "--json"], self.proj).stdout
        self.assertEqual(s1, s2)
        self.assertNotEqual(s1, run(["simulate", "--tasks", "300", "--seed", "6", "--json"], self.proj).stdout)

    def test_context_command_and_usage_errors(self):
        self.j(["init"])
        obj = self.j(["objective", "create"])
        snap = self.j(["snapshot"])["snapshot_id"]
        pol = self.j(["objective", "show", "--id", obj["objective_id"]])["policy_id"]
        m = self.j(["context", "--snapshot", snap, "--policy", pol, "--max-tokens", "1000", "--path", "arithmetic.py"])
        self.assertIn("context_id", m)
        run(["context", "--snapshot", snap, "--policy", pol, "--max-tokens", "1"], self.proj, ok=(6,))
        run(["context", "--snapshot", snap, "--policy", pol, "--max-tokens", "100", "--path", "../x"], self.proj, ok=(14,))
        r = subprocess.run(VEP + ["nonsense"], cwd=self.proj, capture_output=True, text=True)
        self.assertEqual(r.returncode, 2)

    def test_commands_outside_a_workspace_fail_cleanly(self):
        r = run(["status"], self.proj, ok=(1,))
        self.assertIn("not a VEP workspace", r.stderr)

    def test_no_secret_material_is_printed(self):
        out = run(["init", "--json"], self.proj).stdout + run(["status", "--json"], self.proj).stdout
        pem = (self.proj / ".vep" / "keys" / "signing.pem").read_text().split("\n")[1]
        self.assertNotIn(pem, out); self.assertNotIn("PRIVATE KEY", out)


class ScriptTests(unittest.TestCase):
    def test_demo_runs_the_real_implementation(self):
        r = subprocess.run([sys.executable, str(ROOT / "examples" / "run_demo.py")], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        for needle in ("refused: AuthorizationError", "'current source equals certified snapshot'", "rejected: SOURCE_CHANGED",
                       "REQUIRED_TEST_MODIFIED", "DEMO OK"):
            self.assertIn(needle, r.stdout)

    def test_benchmark_script_reports_reproducibility(self):
        d = Path(__import__("tempfile").mkdtemp()); self.addCleanup(shutil.rmtree, d, True)
        r = subprocess.run([sys.executable, str(ROOT / "benchmarks" / "run_simulation.py"), "--tasks", "400",
                            "--out-json", str(d / "r.json"), "--out-md", str(d / "r.md")], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("reproducible: yes", r.stdout)
        self.assertIn("SIMULATED", (d / "r.md").read_text())

    def test_entry_point_is_declared(self):
        self.assertIn('vep = "vep.cli:main"', (ROOT / "pyproject.toml").read_text())
        self.assertTrue((ROOT / "src" / "vep" / "_runner.py").exists())


if __name__ == "__main__":
    unittest.main()
