"""Verify that every invariant names real tests and (with --run) that all of them pass.

    python benchmarks/invariants/check_invariants.py [--run]
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def split(ref: str):
    parts = ref.split("::")
    return parts[0], parts[-1]


def exists(ref: str) -> bool:
    f, name = split(ref)
    p = ROOT / f
    return p.exists() and re.search(rf"def {re.escape(name)}\b", p.read_text()) is not None


def node_ids() -> dict:
    """(file, function) -> pytest node ids, from a collection run, so references need not spell class names."""
    r = subprocess.run([sys.executable, "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider"], cwd=ROOT, capture_output=True, text=True)
    out: dict = {}
    for ln in r.stdout.splitlines():
        if "::" in ln:
            f, fn = ln.split("::")[0], ln.split("::")[-1].split("[")[0]
            out.setdefault((f, fn), []).append(ln.strip())
    return out


def main() -> int:
    doc = json.loads((ROOT / "benchmarks/invariants/invariants.json").read_text())
    bad = [(i["id"], t) for i in doc["invariants"] for t in i["tests"] if not exists(t)]
    if bad:
        print("missing tests:", bad); return 1
    if "--run" not in sys.argv:
        print(f"{len(doc['invariants'])} invariants, {sum(len(i['tests']) for i in doc['invariants'])} tests named, all exist"); return 0
    status = {}
    ids = node_ids()
    for inv in doc["invariants"]:
        nodes = [n for t in inv["tests"] for n in ids.get(split(t), [])]
        if len(nodes) < len(inv["tests"]):
            print("FAIL " + inv["id"] + " test reference did not resolve to a collected test"); status[inv["id"]] = False; continue
        r = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", *nodes], cwd=ROOT, capture_output=True, text=True)
        status[inv["id"]] = r.returncode == 0
        print(("PASS " if r.returncode == 0 else "FAIL ") + inv["id"] + " " + inv["name"])
    return 0 if all(status.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
