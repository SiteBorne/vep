"""Guards for the performance-qualification workflow (a YAML mistake silently disables a workflow)."""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WF = ROOT / ".github" / "workflows" / "perf-qualification.yml"


def load_yaml(path):
    try:
        import yaml
        return yaml.safe_load(path.read_text())
    except ImportError:
        import json
        import shutil
        import subprocess
        if not shutil.which("ruby"):
            raise unittest.SkipTest("neither pyyaml nor ruby is available to parse the workflow")
        r = subprocess.run(["ruby", "-ryaml", "-rjson", "-e", "puts JSON.generate(YAML.safe_load(File.read(ARGV[0]), aliases: true))", str(path)], capture_output=True, text=True)
        assert r.returncode == 0, r.stderr
        return json.loads(r.stdout)


class PerfWorkflowTests(unittest.TestCase):
    def test_parses_is_manual_only_least_privilege_and_pinned(self):
        d = load_yaml(WF)
        trig = d.get("on") or d.get(True) or d.get("true")
        self.assertEqual(set(trig), {"workflow_dispatch", "push"})
        self.assertEqual(trig["push"]["branches"], ["perf/agent-scale"])
        self.assertEqual(trig["push"]["paths"], [".github/workflows/perf-qualification.yml"])
        self.assertEqual(d["permissions"], {"contents": "read"})
        text = WF.read_text()
        for line in re.findall(r"uses:\s*(\S+)", text):
            self.assertRegex(line, r"@[0-9a-f]{40}$", line)
        self.assertNotIn("secrets.", text)
        self.assertNotIn("pull_request", text)
        for job in d["jobs"].values():
            for step in job["steps"]:
                if "run" in step:
                    self.assertIsInstance(step["run"], str)

    def test_control_is_the_baseline_commit_and_the_idle_rule_is_never_relaxed(self):
        text = WF.read_text()
        self.assertIn("1ab17af60450c4d558bab5c1c4260024ade45355", text)
        self.assertIn("wait_idle.py", text)
        self.assertNotIn("--timeout 0", text)


if __name__ == "__main__":
    unittest.main()
