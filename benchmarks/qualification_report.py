"""Build the machine-readable qualification report for a hosted benchmark run.

    python benchmarks/qualification_report.py --results DIR --release-tag v0.5.0b1 --release-commit <sha> --out DIR/qualification-report.json

It records source identities, whether the VEP implementation under test equals the release commit (evaluation-critical paths
only), pinned external revisions, per-project idle checks and the declared launch-gate criteria, hashes of every result file,
and the GitHub run identity. It never changes a criterion; it only applies the declared ones to the recorded data.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PROJECTS = json.loads((REPO / "benchmarks" / "external" / "projects.json").read_text())
EVAL_CRITICAL = ["src", "pyproject.toml"]  # code whose behaviour is measured; the benchmark harness itself lives outside these paths
MAX_START_LOAD = 2.0   # declared launch-gate criterion
MIN_VALID_BLOCKS = 10  # declared design


def sha256(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def git(*a: str) -> str:
    return subprocess.run(["git", "-C", str(REPO), *a], capture_output=True, text=True).stdout.strip()


def project_validity(paired: dict | None, idle: dict | None) -> dict:
    """The declared criteria (same as scripts/launch_check.py): start load < 2.0, no correctness-gate failure, >= 10 valid blocks per scenario."""
    if paired is None:
        return {"status": "NOT_RUN", "reasons": ["workload was not run" + (" (idle criterion not achieved within the bounded wait)" if idle and not idle["result"]["achieved"] else "")]}
    reasons = []
    if paired["load_avg_1m_at_start"] >= MAX_START_LOAD:
        reasons.append(f"load_avg_1m_at_start {paired['load_avg_1m_at_start']:.2f} >= {MAX_START_LOAD}")
    if paired["gate_failures"]:
        reasons.append(f"correctness gate failures: {paired['gate_failures']}")
    for sc, v in paired["scenarios"].items():
        if v["valid_blocks"] < MIN_VALID_BLOCKS:
            reasons.append(f"{sc}: only {v['valid_blocks']} valid blocks")
    return {"status": "VALID" if not reasons else "ENVIRONMENTALLY_OR_METHODOLOGICALLY_INVALID", "reasons": reasons}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", required=True)
    ap.add_argument("--release-tag", required=True)
    ap.add_argument("--release-commit", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    d = Path(a.results)
    head = git("rev-parse", "HEAD")
    release_resolved = git("rev-parse", f"{a.release_tag}^{{commit}}")
    changed = [x for x in git("diff", "--name-only", a.release_commit, "HEAD").splitlines() if x]
    critical_changed = [x for x in changed if any(x == c or x.startswith(c + "/") for c in EVAL_CRITICAL)]
    rep: dict = {"report_version": 1, "kind": "hosted benchmark qualification",
                 "run": {k: os.environ.get(k) for k in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_WORKFLOW", "GITHUB_REPOSITORY", "GITHUB_SHA", "GITHUB_REF", "GITHUB_SERVER_URL", "ImageOS", "ImageVersion", "RUNNER_NAME") if os.environ.get(k)},
                 "source": {"release_tag": a.release_tag, "release_commit_expected": a.release_commit, "release_commit_resolved_from_tag": release_resolved,
                            "tag_matches_expected": release_resolved == a.release_commit, "harness_commit": head,
                            "evaluation_critical_paths": EVAL_CRITICAL, "evaluation_critical_files_changed_since_release": critical_changed,
                            "vep_implementation_matches_release": release_resolved == a.release_commit and not critical_changed,
                            "files_changed_since_release_not_evaluation_critical": [x for x in changed if x not in critical_changed],
                            "portability_note": "only benchmark harness/workflow/documentation files may differ from the release commit"},
                 "criteria": {"max_load_avg_1m_at_start": MAX_START_LOAD, "min_valid_blocks_per_scenario": MIN_VALID_BLOCKS, "unchanged_from": "docs/BENCHMARK_METHODOLOGY.md and scripts/launch_check.py"},
                 "projects": {}, "files": {}}
    env = d / "environment.json"
    if env.exists():
        rep["environment_json"] = json.loads(env.read_text())
    for name, spec in PROJECTS.items():
        pj = d / f"paired-{name}.json"
        ij = d / f"idle-{name}.json"
        paired = json.loads(pj.read_text()) if pj.exists() else None
        idle = json.loads(ij.read_text()) if ij.exists() else None
        pin_actual = (d / f"pin-{name}.txt").read_text().strip() if (d / f"pin-{name}.txt").exists() else None
        rep["projects"][name] = {"pinned_commit_expected": spec["commit"], "pinned_commit_actual": pin_actual, "pin_matches": pin_actual == spec["commit"],
                                 "idle_check": None if idle is None else idle["result"], "validity": project_validity(paired, idle),
                                 "paired_report": pj.name if paired else None,
                                 "load_avg_1m_at_start": None if paired is None else round(paired["load_avg_1m_at_start"], 2)}
    for p in sorted(d.rglob("*")):
        if p.is_file() and p.name != "qualification-report.json":
            rep["files"][str(p.relative_to(d))] = {"sha256": sha256(p), "bytes": p.stat().st_size}
    valid = all(v["validity"]["status"] == "VALID" and v["pin_matches"] for v in rep["projects"].values()) and rep["source"]["vep_implementation_matches_release"]
    rep["qualification"] = "VALID" if valid else "INVALID_OR_INCOMPLETE"
    Path(a.out).write_text(json.dumps(rep, indent=1, sort_keys=True))
    print(json.dumps({"qualification": rep["qualification"], "projects": {k: v["validity"]["status"] for k, v in rep["projects"].items()},
                      "vep_implementation_matches_release": rep["source"]["vep_implementation_matches_release"]}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
