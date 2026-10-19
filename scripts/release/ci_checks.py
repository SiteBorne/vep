"""Static release checks that need no network: secrets (tree + history), workflows, claims, artifacts.

    python scripts/release/ci_checks.py [--dist dist]

Exit 0 iff everything passes. Used by CI and the release workflow in addition to the test-suite.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import gates as G  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dist")
    a = ap.parse_args()
    pol = G.load_policy()
    problems: list[str] = []
    problems += [f"secret/tree {h['rule']} {h['file']}:{h['line']}" for h in G.scan_tree(pol)]
    problems += [f"secret/history {h['rule']} {h['file']}:{h['line']}" for h in G.scan_history(pol)]
    for wf in sorted((G.ROOT / ".github" / "workflows").glob("*.yml")):
        problems += G.lint_workflow(wf.read_text(), pol, wf.name)
    for pat in pol["claim_scan_paths"]:
        for f in sorted(G.ROOT.glob(pat)):
            problems += [f"claim {x['claim']} {x['file']}:{x['line']}" for x in
                         G.scan_claims(f.read_text(), pol, {"UNTRUSTED_EXECUTION_ISOLATION": "UNVERIFIED"}, f.name)]
    v = G.version_consistency()
    if len(set(v.values())) != 1:
        problems.append(f"version mismatch {v}")
    if a.dist:
        for f in sorted(Path(a.dist).glob("*.whl")) + sorted(Path(a.dist).glob("*.tar.gz")):
            problems += [f"artifact {f.name}: {m}" for m in G.audit_artifact(f, pol)]
    for p in problems:
        print("FAIL:", p)
    print("ci_checks:", "FAIL" if problems else "PASS")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
