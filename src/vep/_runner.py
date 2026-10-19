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


def place_roots(paths):
    """Put the candidate's import roots after the standard library but BEFORE site-packages, so an installed
    copy of the project under test can never shadow the staged source. Standard-library names still win."""
    idx = len(sys.path)
    for i, entry in enumerate(sys.path):
        if "site-packages" in entry or "dist-packages" in entry:
            idx = i
            break
    for p in paths:
        if p not in sys.path:
            sys.path.insert(idx, p)
            idx += 1


def provided_names(roots):
    """Top-level importable names the staged tree provides (packages with __init__.py, and plain modules)."""
    names = set()
    for r in roots:
        try:
            entries = list(os.scandir(r))
        except OSError:
            continue
        for e in entries:
            if e.is_dir() and os.path.isfile(os.path.join(e.path, "__init__.py")):
                names.add(e.name)
            elif e.is_file() and e.name.endswith(".py") and e.name != "__init__.py":
                names.add(e.name[:-3])
    return names


def shadowed_modules(roots, modules):
    """Names the staged tree provides but that were imported from somewhere else (for example an installed copy).
    Order of sys.path is not trusted: this inspects what was actually loaded."""
    real_roots = [os.path.realpath(r) + os.sep for r in roots]
    out = []
    for name in sorted(provided_names(roots)):
        f = getattr(modules.get(name), "__file__", None)
        if f and not any(os.path.realpath(f).startswith(rr) for rr in real_roots):
            out.append(name)
    return out


def main() -> int:
    cfg = json.loads(sys.argv[1])
    root = os.path.abspath(cfg["root"])
    roots = [os.path.abspath(os.path.join(root, r)) for r in cfg["import_roots"]]
    place_roots(roots)
    start = os.path.abspath(os.path.join(root, cfg["start_dir"]))
    if start not in sys.path:
        sys.path.append(start)
    roots = roots + [start]
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
    report = {"kind": "unittest", "discovered": discovered, "run": result.testsRun, **out,
              "shadowed_modules": shadowed_modules(roots, sys.modules)}
    if cfg["report_path"] == "-":  # isolated mode: no writable host path; parent parses this marker line
        sys.stdout.write("\nVEP_REPORT_V1:" + json.dumps(report, sort_keys=True) + "\n")
        sys.stdout.flush()
    else:
        with open(cfg["report_path"], "w", encoding="utf-8") as fh:
            json.dump(report, fh, sort_keys=True)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
