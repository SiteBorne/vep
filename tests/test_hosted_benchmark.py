"""Portability and guard-rail tests for the hosted-Linux benchmark qualification (no benchmark is run here)."""
import importlib.util
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
BENCH = ROOT / "benchmarks"
sys.path.insert(0, str(BENCH))
import envinfo  # noqa: E402
import wait_idle  # noqa: E402


def load(name):
    spec = importlib.util.spec_from_file_location(name, BENCH / f"{name}.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


PROC_STAT_A = "cpu  1000 10 500 8000 100 20 30 5 0 0\ncpu0 250 2 125 2000 25 5 7 1 0 0\n"
PROC_STAT_B = "cpu  1100 10 520 8800 110 20 32 5 0 0\n"
MEMINFO = "MemTotal:       16379988 kB\nMemAvailable:   15000000 kB\nSwapTotal:      4194300 kB\nSwapFree:       4194300 kB\n"
CPUINFO = "processor\t: 0\nmodel name\t: AMD EPYC 7763 64-Core Processor\nflags\t: fpu\n"
OS_RELEASE = 'NAME="Ubuntu"\nVERSION_ID="24.04"\nPRETTY_NAME="Ubuntu 24.04.5 LTS"\nHOME_URL="https://x"\n'


class LinuxParsingTests(unittest.TestCase):
    def test_proc_stat_and_idle_percentage(self):
        a = envinfo.parse_proc_stat_cpu(PROC_STAT_A.splitlines()[0])
        b = envinfo.parse_proc_stat_cpu(PROC_STAT_B.splitlines()[0])
        self.assertEqual(a, (8100, 9665))      # idle+iowait ; sum of the first 8 fields
        self.assertEqual(envinfo.idle_percent(a, b), 86.91)  # 810 idle of 932 elapsed jiffies
        self.assertIsNone(envinfo.idle_percent(a, a))  # no elapsed jiffies: unknown, never a made-up number

    def test_meminfo_cpuinfo_osrelease(self):
        m = envinfo.parse_meminfo(MEMINFO)
        self.assertEqual((m["MemTotal"], m["SwapTotal"]), (16379988, 4194300))
        self.assertEqual(envinfo.parse_cpu_model(CPUINFO), "AMD EPYC 7763 64-Core Processor")
        self.assertEqual(envinfo.parse_os_release(OS_RELEASE)["VERSION_ID"], "24.04")

    def test_linux_host_info_keeps_the_report_keys_used_by_the_renderer(self):
        files = {"/proc/meminfo": MEMINFO, "/proc/cpuinfo": CPUINFO, "/etc/os-release": OS_RELEASE}
        with mock.patch.object(envinfo.sys, "platform", "linux"), mock.patch.object(envinfo, "_read", side_effect=lambda p: files.get(p, "")), \
                mock.patch.dict("os.environ", {"ImageOS": "ubuntu24", "ImageVersion": "20261012.334.1", "GITHUB_RUN_ID": "42"}):
            h = envinfo.host_info()
        for k in ("platform", "machine", "cpus", "python", "kernel", "mem_total_mb", "swap", "power", "cpu_model", "os_release", "runner"):
            self.assertIn(k, h)
        self.assertIsInstance(h["power"], list)
        self.assertIsInstance(h["swap"], str)
        self.assertEqual(h["runner"]["ImageVersion"], "20261012.334.1")
        self.assertEqual(h["cpu_model"], "AMD EPYC 7763 64-Core Processor")

    def test_current_platform_probe_works_and_has_original_keys(self):
        p = envinfo.env_probe()
        self.assertIn("load_avg_1m", p)
        self.assertIn("cpu_idle_pct", p)
        h = envinfo.host_info()
        self.assertTrue({"power", "swap", "platform", "cpus"} <= set(h))


class IdleGuardTests(unittest.TestCase):
    def test_criterion_is_strictly_below_two_and_cannot_be_raised(self):
        self.assertTrue(wait_idle.evaluate([{"load_avg_1m": 1.99}])["achieved"])
        self.assertFalse(wait_idle.evaluate([{"load_avg_1m": 2.0}])["achieved"])
        self.assertEqual(wait_idle.main(["--max-load", "2.5", "--out", "/dev/null"]), 2)

    def test_success_and_timeout_paths_record_every_sample(self):
        out = Path(tempfile.mkdtemp()) / "idle.json"
        with mock.patch("os.getloadavg", return_value=(0.5, 0.5, 0.5)), mock.patch.object(envinfo, "cpu_idle_pct", return_value=99.0):
            self.assertEqual(wait_idle.main(["--timeout", "5", "--interval", "1", "--out", str(out)]), 0)
        self.assertTrue(json.loads(out.read_text())["result"]["achieved"])
        with mock.patch("os.getloadavg", return_value=(4.0, 4.0, 4.0)), mock.patch.object(envinfo, "cpu_idle_pct", return_value=10.0):
            self.assertEqual(wait_idle.main(["--timeout", "0", "--interval", "1", "--out", str(out)]), 3)
        r = json.loads(out.read_text())
        self.assertFalse(r["result"]["achieved"])
        self.assertEqual(r["result"]["min_load_avg_1m"], 4.0)
        self.assertGreaterEqual(len(r["samples_detail"]), 1)


class QualificationReportTests(unittest.TestCase):
    def setUp(self):
        self.q = load("qualification_report")

    def paired(self, load_avg=0.8, gate=None, blocks=10):
        return {"load_avg_1m_at_start": load_avg, "gate_failures": gate or [], "scenarios": {"S1": {"valid_blocks": blocks}, "S2": {"valid_blocks": 10}}}

    def test_declared_criteria_are_applied_unchanged(self):
        self.assertEqual(self.q.project_validity(self.paired(), None)["status"], "VALID")
        for bad in (self.paired(load_avg=2.0), self.paired(gate=["TESTMON"]), self.paired(blocks=9)):
            self.assertNotEqual(self.q.project_validity(bad, None)["status"], "VALID")
        self.assertEqual((self.q.MAX_START_LOAD, self.q.MIN_VALID_BLOCKS), (2.0, 10))

    def test_not_run_when_the_idle_criterion_was_never_met(self):
        idle = {"result": {"achieved": False}}
        v = self.q.project_validity(None, idle)
        self.assertEqual(v["status"], "NOT_RUN")
        self.assertIn("idle criterion not achieved", v["reasons"][0])


class WorkflowGuardTests(unittest.TestCase):
    text = (ROOT / ".github" / "workflows" / "benchmark-qualification.yml").read_text()

    def test_manual_read_only_no_secrets_fixed_runner(self):
        self.assertRegex(self.text, r"(?m)^on:\n  workflow_dispatch:\n")
        self.assertNotRegex(self.text, r"(?m)^\s+(push|pull_request|pull_request_target|schedule):")
        self.assertRegex(self.text, r"(?m)^permissions:\n  contents: read\n")
        self.assertNotIn("secrets.", self.text)
        self.assertIn("runs-on: ubuntu-24.04", self.text)
        self.assertNotIn("continue-on-error", self.text)

    def test_source_under_test_is_pinned_and_checked_against_the_release(self):
        self.assertIn("RELEASE_COMMIT: 578850d1245e3a2e5e282f5e9734ea7dfc0f44e6", self.text)
        self.assertIn('git diff --quiet "$RELEASE_COMMIT" HEAD -- src pyproject.toml', self.text)

    def test_every_workload_is_gated_by_the_idle_check_and_the_threshold_is_not_overridden(self):
        for proj in ("pyflakes", "more-itertools"):
            m = re.search(r"if python benchmarks/wait_idle\.py[^\n]*--label " + proj + r"[^\n]*; then\n\s+python benchmarks/paired\.py --project " + proj, self.text)
            self.assertTrue(m, proj)
        self.assertNotIn("--max-load", self.text)  # the default (the declared 2.0) is used; no override anywhere
        self.assertIn("--blocks", (BENCH / "paired.py").read_text())  # design parameters stay in the harness defaults
        self.assertNotRegex(self.text, r"paired\.py[^\n]*--(blocks|warmups|seed|batch-n|workers)")  # preregistered design not overridden in the workflow

    def test_pinned_projects_match_the_registry_and_environments_exclude_vep(self):
        specs = json.loads((BENCH / "external" / "projects.json").read_text())
        self.assertEqual(specs["pyflakes"]["commit"], "8526af8494a831803bbc1eae24b8f9d2a24aa2f7")
        self.assertEqual(specs["more-itertools"]["commit"], "4aeb4338ae1407d8da9723e86da99efeb446f719")
        self.assertIn('import vep" 2>/dev/null; then echo "::error::vep is importable', self.text)


class RendererTests(unittest.TestCase):
    def test_renderer_handles_a_linux_report(self):
        d = Path(tempfile.mkdtemp())
        cfg = {"configs": {"DIRECT": {"wall_s": {"mean": 1, "median": 1, "sd": 0.1}, "cpu_s": {"mean": 1}, "peak_child_rss_mb": {"mean": 30}}},
               "comparisons": {}}
        block = {"index": 2, "order": ["DIRECT"], "env": {"load_avg_1m": 0.5, "cpu_idle_pct": 98.0}, "runs": {"DIRECT": {"rc": 0, "wall": 1, "cpu": 1, "rss": 30}}}
        rep = {"project": "pyflakes", "pinned_commit": "a" * 40, "vep_commit": "b" * 40, "host": envinfo.host_info() | {"cpus": 4}, "load_avg_1m_at_start": 0.5,
               "gate_failures": [], "correctness_gate": {}, "scenarios": {"S1": {"valid_blocks": 1, "warmup_blocks": [], "excluded": [], "blocks": [block], "not_applicable": {},
                                                                                "analysis": cfg, "environment": {"load_avg_1m_min": 0.5, "load_avg_1m_max": 0.5, "cpu_idle_pct_min": 98.0, "direct_baseline_cv": 0.01}}}}
        (d / "paired-pyflakes.json").write_text(json.dumps(rep))
        out = d / "o.md"
        r = load("paired_report")
        with mock.patch.object(sys, "argv", ["paired_report.py", "--dir", str(d), "--out", str(out), "--title", "T"]):
            self.assertEqual(r.main(), 0)
        self.assertIn("## pyflakes", out.read_text())
        self.assertIn("NOT_RUN", out.read_text())  # more-itertools report absent: rendered as NOT_RUN, never invented


if __name__ == "__main__":
    unittest.main()
