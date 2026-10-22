"""The hosted correctness gate must fail when the invariant run is skipped, partial, run under the wrong flags, or when any test fails."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "benchmarks/invariants/qualify_hosted.py"
N = len(json.loads((ROOT / "benchmarks/invariants/invariants.json").read_text())["invariants"])


def junit(failures=0, skipped=0):
    cases = "".join('<testcase classname="t.A" name="ok%d"/>' % i for i in range(3)) + "".join('<testcase classname="t.A" name="f%d"><failure/></testcase>' % i for i in range(failures)) + \
        "".join('<testcase classname="t.A" name="s%d"><skipped/></testcase>' % i for i in range(skipped))
    return f"<testsuites><testsuite>{cases}</testsuite></testsuites>"


def gate(tmp, *, junit_xml=None, inv=None, flags="staging_fast"):
    t = Path(tmp)
    if junit_xml is not None:
        (t / "junit.xml").write_text(junit_xml)
    if inv is not None:
        (t / "inv.json").write_text(json.dumps(inv))
    r = subprocess.run([sys.executable, str(GATE), "--junit", str(t / "junit.xml"), "--invariants", str(t / "inv.json"), "--flags", flags, "--out", str(t / "q.json")], capture_output=True, text=True)
    return r.returncode, json.loads((t / "q.json").read_text())


def good_inv(flags="staging_fast", n=N):
    return {"flags": flags, "executed": n, "all_passed": True, "invariants": [{"id": f"I{i}", "passed": True} for i in range(n)]}


class GateTests(unittest.TestCase):
    def test_complete_green_run_qualifies_and_records_skips(self):
        with tempfile.TemporaryDirectory() as t:
            rc, q = gate(t, junit_xml=junit(skipped=1), inv=good_inv())
            self.assertEqual((rc, q["qualified"], q["tests_skipped"]), (0, True, 1))

    def test_missing_invariant_report_is_a_failure_not_a_pass(self):
        with tempfile.TemporaryDirectory() as t:
            rc, q = gate(t, junit_xml=junit())
            self.assertEqual(rc, 1); self.assertFalse(q["qualified"]); self.assertIn("not executed", q["problems"][0])

    def test_partial_wrong_flag_or_failing_runs_fail(self):
        with tempfile.TemporaryDirectory() as t:
            self.assertEqual(gate(t, junit_xml=junit(), inv=good_inv(n=N - 1))[0], 1)
            self.assertEqual(gate(t, junit_xml=junit(), inv=good_inv(flags="none"))[0], 1)
            bad = good_inv(); bad["all_passed"] = False; bad["invariants"][0]["passed"] = False
            self.assertEqual(gate(t, junit_xml=junit(), inv=bad)[0], 1)
            self.assertEqual(gate(t, junit_xml=junit(failures=1), inv=good_inv())[0], 1)

    def test_missing_junit_fails(self):
        with tempfile.TemporaryDirectory() as t:
            (Path(t) / "inv.json").write_text(json.dumps(good_inv()))
            rc, q = gate(t, inv=good_inv())
            self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()
