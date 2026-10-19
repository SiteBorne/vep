"""VEP protected unittest runner. Executed as `python -I _runner.py <config-json>`.

It lives outside the staged tree and is identified by digest in the Action/Evidence. It appends
(never prepends) candidate import roots so standard-library modules always win name resolution.
Report integrity note: this runs in the same process as candidate test code, so a hostile candidate
could forge the report. That is why execution is only permitted in the trusted-local mode.
"""
import json
import os
import sys
import unittest


def main() -> int:
    cfg = json.loads(sys.argv[1])
    root = os.path.abspath(cfg["root"])
    for r in cfg["import_roots"]:
        p = os.path.abspath(os.path.join(root, r))
        if p not in sys.path:
            sys.path.append(p)
    start = os.path.abspath(os.path.join(root, cfg["start_dir"]))
    if start not in sys.path:
        sys.path.append(start)
    loader = unittest.TestLoader()
    suite = loader.discover(start, pattern=cfg["pattern"], top_level_dir=start)
    discovered = suite.countTestCases()
    out = {"passed": [], "failed": [], "errors": [], "skipped": [], "expected_failures": [],
           "unexpected_successes": []}

    class Rec(unittest.TextTestResult):
        def addSuccess(self, t):
            super().addSuccess(t); out["passed"].append(t.id())
        def addFailure(self, t, e):
            super().addFailure(t, e); out["failed"].append(t.id())
        def addError(self, t, e):
            super().addError(t, e); out["errors"].append(t.id())
        def addSkip(self, t, r):
            super().addSkip(t, r); out["skipped"].append(t.id())
        def addExpectedFailure(self, t, e):
            super().addExpectedFailure(t, e); out["expected_failures"].append(t.id())
        def addUnexpectedSuccess(self, t):
            super().addUnexpectedSuccess(t); out["unexpected_successes"].append(t.id())

    runner = unittest.TextTestRunner(stream=sys.stderr, verbosity=2, resultclass=Rec)
    result = runner.run(suite)
    report = {"kind": "unittest", "discovered": discovered, "run": result.testsRun, **out}
    with open(cfg["report_path"], "w", encoding="utf-8") as fh:
        json.dump(report, fh, sort_keys=True)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
