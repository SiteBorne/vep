"""Hosted correctness gate for one flag set: a JUnit file from the whole suite plus the invariant report. A skipped or missing invariant run is a FAIL, never a pass.

    python benchmarks/invariants/qualify_hosted.py --junit junit.xml --invariants inv.json --flags <set> --out qualification.json
"""
from __future__ import annotations

import argparse
import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--junit", required=True); ap.add_argument("--invariants", required=True); ap.add_argument("--flags", required=True); ap.add_argument("--out", required=True)
    a = ap.parse_args()
    problems, skipped, n, bad = [], [], 0, []
    jp = Path(a.junit)
    if not jp.exists():
        problems.append("no JUnit file: the suite did not run")
    else:
        for tc in ET.parse(jp).getroot().iter("testcase"):
            n += 1
            if tc.find("failure") is not None or tc.find("error") is not None:
                bad.append(f"{tc.get('classname')}::{tc.get('name')}")
            if tc.find("skipped") is not None:
                skipped.append(f"{tc.get('classname')}::{tc.get('name')}")
    if bad:
        problems.append(f"{len(bad)} failing tests, e.g. {bad[:3]}")
    ip = Path(a.invariants)
    doc = json.loads(ip.read_text()) if ip.exists() else None
    expected = len(json.loads((ROOT / "benchmarks/invariants/invariants.json").read_text())["invariants"])
    if doc is None:
        problems.append("invariant suite was not executed (no report): counts as FAIL")
    else:
        if doc.get("executed") != expected:
            problems.append(f"invariants executed {doc.get('executed')} of {expected}")
        if not doc.get("all_passed"):
            problems.append("invariant failures: " + str([i["id"] for i in doc["invariants"] if not i["passed"]]))
        if (doc.get("flags") or "none") != a.flags:
            problems.append(f"invariants ran with VEP_PERF={doc.get('flags')!r}, expected {a.flags!r}")
    out = {"flags": a.flags, "tests_run": n, "tests_failed": len(bad), "tests_skipped": len(skipped), "skipped": skipped, "invariants_executed": (doc or {}).get("executed"),
           "invariants_expected": expected, "qualified": not problems, "problems": problems}
    Path(a.out).write_text(json.dumps(out, indent=1) + "\n")
    print(json.dumps(out, indent=1))
    return 0 if not problems else 1


if __name__ == "__main__":
    sys.exit(main())
