"""Machine validation of master-dataset.json: provenance hashes, completeness, internal consistency, classification and assurance hygiene.

    python benchmarks/analysis/validate.py     # exit 1 and list problems if anything is inconsistent
"""
from __future__ import annotations

import hashlib
import json
import math
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
REQUIRED = ("source_path", "source_sha256", "vep_commit", "project", "project_commit", "cohort", "host", "classification", "assurance", "metric", "units",
            "stats", "samples_n", "warmups", "correctness_gate", "cache_eligibility", "variance", "confidence_interval", "limitations", "scenario", "operation", "config")


def tracked_benchmark_files() -> set[str]:
    out = subprocess.run(["git", "-C", str(ROOT), "ls-files", "benchmarks/results", "benchmarks/results.json", "docs/BENCHMARKS.md", "docs/BENCHMARK_METHODOLOGY.md", "docs/BENCHMARK_RESULTS_PAIRED.md",
                          "docs/BENCHMARK_RESULTS_HOSTED_LINUX.md", "docs/CONTROLLER_SCALING.md", "docs/PERFORMANCE_REPORT.md"], capture_output=True, text=True).stdout.split()
    return set(out)


def validate(path: Path = HERE / "master-dataset.json") -> list[str]:
    d = json.loads(path.read_text())
    problems: list[str] = []
    srcs = {s["path"]: s for s in d["sources"]}
    for p, s in srcs.items():
        f = ROOT / p
        if not f.exists():
            problems.append(f"{p}: source missing"); continue
        if hashlib.sha256(f.read_bytes()).hexdigest() != s["sha256"]:
            problems.append(f"{p}: sha256 differs from the file on disk (stale dataset)")
        if s["classification"] not in d["classifications"]:
            problems.append(f"{p}: bad classification")
    missing = tracked_benchmark_files() - set(srcs)
    if missing:
        problems.append(f"tracked benchmark artifacts not in the inventory: {sorted(missing)[:5]}")
    for o in d["observations"]:
        for k in REQUIRED:
            if k not in o:
                problems.append(f"obs {o.get('id')}: missing field {k}")
        s = srcs.get(o["source_path"])
        if not s or s["sha256"] != o["source_sha256"]:
            problems.append(f"obs {o['id']}: source hash does not match its inventory entry")
        if o["assurance"] not in d["assurance_levels"]:
            problems.append(f"obs {o['id']}: unknown assurance")
        smp, st = o.get("samples"), o["stats"]
        if smp and "mean" in st and o["metric"] in ("wall_s", "cpu_s", "child_cpu_s", "peak_child_rss_mb", "wall_ms"):
            m = sum(smp) / len(smp)
            if not math.isclose(m, st["mean"], rel_tol=2e-3, abs_tol=2e-3):
                problems.append(f"obs {o['id']} {o['operation']} {o['metric']}: stored mean {st['mean']} != mean of samples {m:.4f}")
        ci = o.get("confidence_interval")
        if ci and "mean" in st and not (ci["lo"] <= st["mean"] + 2e-3 and st["mean"] - 2e-3 <= ci["hi"]):
            problems.append(f"obs {o['id']}: mean outside its own interval")
        if o["classification"] == "SYNTHETIC" and o["assurance"] != "SIMULATED":
            problems.append(f"obs {o['id']}: synthetic data labelled with a verification assurance")
        if o["assurance"] == "BUILD_CACHE_HIT_NO_CERTIFICATE" and o["cache_eligibility"] == "n/a":
            problems.append(f"obs {o['id']}: cache hit without stated eligibility")
    for c in d["comparisons"]:
        for key in ("welch_preregistered", "paired_bootstrap"):
            v = c.get(key)
            if v and isinstance(v.get("rel_ci95") or v.get("rel_ci95"), list):
                lo, hi = v["rel_ci95"]
                if lo > hi:
                    problems.append(f"{c['source_path']} {c['scenario']} {c['comparison']}: inverted interval")
    for key in d["aggregates_by_cohort"]:
        cohorts = {o["cohort"] for o in d["observations"] if f"{o['cohort']}|{o['project']}|{o['scenario']}" == key}
        if len(cohorts) > 1:
            problems.append(f"aggregate {key} mixes cohorts {cohorts}")
    inval = {s["path"] for s in d["sources"] if s["classification"] == "INVALID_ENVIRONMENT"}
    if any(o["source_path"] in inval and f"{o['cohort']}|{o['project']}|{o['scenario']}" in d["aggregates_by_cohort"] and o["classification"] == "MEASURED" for o in d["observations"]):
        problems.append("an INVALID_ENVIRONMENT observation is counted as MEASURED")
    return problems


if __name__ == "__main__":
    probs = validate()
    print("\n".join(probs) if probs else f"benchmark dataset: consistent ({len(json.loads((HERE / 'master-dataset.json').read_text())['observations'])} observations)")
    sys.exit(1 if probs else 0)
