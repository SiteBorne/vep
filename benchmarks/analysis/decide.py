"""Apply the PREREGISTERED adoption rules (benchmarks/analysis/PLANNED_EXPERIMENTS.json) to A/B results. The rules live here as constants and are covered by tests; they are
not parameters of the data and are never edited after results exist.

    python benchmarks/analysis/decide.py --dir benchmarks/results/hosted-linux-perf --correctness <dir with qualification-*.json> --out decisions.json

Per optimized arm, against the first arm of each A/B file (the pristine control):
  wall rule     at 1,000 AND 3,000 files: Welch verdict VEP_FASTER (whole 95% interval of the relative difference below -10% AND mean gain above 50 ms) AND paired-bootstrap VEP_FASTER
  CPU endpoint  same thresholds on CPU seconds (reported separately; it does not by itself adopt)
  cold guard    at 100 files: REJECT if the Welch interval lies wholly above +5% and the mean slowdown exceeds 50 ms
  memory        REJECT if mean peak child RSS at the largest size exceeds the control's by more than 25%
  exclusions    any excluded block (a correctness failure) in the arm's files: REJECT
  correctness   the hosted correctness gate for the arm's flag set must be qualified, else INCONCLUSIVE (never ADOPT)
  environment   every analysed block must satisfy load < 2.0 and CPU idle >= 75%, else INCONCLUSIVE
ADOPT needs all of: wall rule at both sizes, cold guard ok, memory ok, zero exclusions, correctness qualified, environment valid. REJECT when the environment is valid and
the wall rule fails at 1,000 or 3,000 files (including NO_MEASURABLE_ADVANTAGE), or the guard/memory/exclusion rule is violated. Everything else is INCONCLUSIVE.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REL, ABS_S, GUARD_REL, MEM_GROWTH = 0.10, 0.05, 0.05, 0.25
WALL_SIZES = (1000, 3000)
COLD_SIZE = 100


def env_valid(doc) -> bool:
    blocks = doc["blocks"]
    return bool(blocks) and all(b["env"].get("load_avg_1m", 99) < 2.0 and b["env"].get("cpu_idle_pct", 0) >= 75.0 for b in blocks)


def pick(doc, arm, metric):
    c = doc["comparisons"].get(f"{arm}_vs_{doc['baseline']}", {}).get(metric)
    return c


def decide_arm(arm: str, files: dict[int, dict], qualified: bool | None) -> dict:
    why, status = [], None
    missing = [n for n in (*WALL_SIZES, COLD_SIZE) if n not in files]
    if missing:
        return {"arm": arm, "decision": "INCONCLUSIVE", "reasons": [f"no A/B data for sizes {missing}"]}
    if any(arm not in d["arms"] for d in files.values()):
        return {"arm": arm, "decision": "INCONCLUSIVE", "reasons": ["arm absent from some A/B files"]}
    invalid = [n for n, d in files.items() if not env_valid(d)]
    excluded = sum(len(d["excluded"]) for d in files.values())
    detail = {}
    wall_pass = True
    wall_fail_valid = False
    for n in WALL_SIZES:
        d = files[n]; c = pick(d, arm, "wall_s")
        if not c:
            wall_pass = False; why.append(f"n={n}: too few valid blocks for a verdict"); continue
        w, b = c["welch_preregistered"], c["paired_bootstrap"]
        detail[f"wall_n{n}"] = {"welch": w, "bootstrap": b, "control_mean_s": d["summary"][d["baseline"]]["wall_s"]["mean"], "arm_mean_s": d["summary"][arm]["wall_s"]["mean"]}
        if not (w["verdict"] == "VEP_FASTER" and b["verdict"] == "VEP_FASTER"):
            wall_pass = False
            if w["verdict"] != "INCONCLUSIVE" and b["verdict"] != "INCONCLUSIVE":
                wall_fail_valid = True
            why.append(f"n={n}: wall verdict Welch={w['verdict']} bootstrap={b['verdict']} (rel diff {w['rel_diff']:+.1%}, CI {w['rel_ci95']})")
        cc = pick(d, arm, "cpu_s")
        if cc:
            detail[f"cpu_n{n}"] = {"welch": cc["welch_preregistered"], "bootstrap": cc["paired_bootstrap"]}
    cold = pick(files[COLD_SIZE], arm, "wall_s")
    guard_ok = True
    if cold:
        w = cold["welch_preregistered"]
        detail["cold_guard_n100"] = w
        if w["rel_ci95"][0] > GUARD_REL and w["diff_s"] > ABS_S:
            guard_ok = False; why.append(f"cold-path guard violated at 100 files: {w['rel_diff']:+.1%}")
    big = files[max(WALL_SIZES)]
    mem_ok = True
    cm, am = big["summary"][big["baseline"]]["rss_child_max_mb"]["mean"], big["summary"][arm]["rss_child_max_mb"]["mean"]
    detail["memory_largest"] = {"control_mb": cm, "arm_mb": am}
    if cm and am > cm * (1 + MEM_GROWTH):
        mem_ok = False; why.append(f"peak child RSS grew {am / cm - 1:+.0%}")
    if excluded:
        why.append(f"{excluded} excluded block(s): correctness failure in some arm")
    if not guard_ok or not mem_ok or excluded:
        status = "REJECT"
    elif invalid:
        status = "INCONCLUSIVE"; why.append(f"environment invalid for sizes {invalid} (load < 2.0 and idle >= 75% required)")
    elif wall_fail_valid:
        status = "REJECT"
    elif not wall_pass:
        status = "INCONCLUSIVE"
    elif qualified is not True:
        status = "INCONCLUSIVE"; why.append("hosted correctness gate for this flag set not qualified" if qualified is False else "hosted correctness gate result missing")
    else:
        status = "ADOPT"; why.append("wall rule passed at 1,000 and 3,000 files; guard, memory, exclusions, correctness and environment all satisfied")
    return {"arm": arm, "decision": status, "reasons": why, "detail": detail, "environment_valid": not invalid}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True); ap.add_argument("--correctness", help="directory containing qualification.json files (one per flag set)"); ap.add_argument("--out", required=True)
    a = ap.parse_args()
    files: dict[int, dict] = {}
    for p in sorted(Path(a.dir).glob("ab-n*-factorial.json")):
        d = json.loads(p.read_text()); files[d["n_files"]] = d
    qual: dict[str, bool] = {}
    if a.correctness:
        for p in Path(a.correctness).rglob("qualification.json"):
            q = json.loads(p.read_text()); qual[q["flags"]] = q["qualified"]
    arms = sorted({x for d in files.values() for x in d["arms"][1:]})
    out = {"rules": {"relative": REL, "absolute_s": ABS_S, "cold_guard_relative": GUARD_REL, "memory_growth": MEM_GROWTH, "wall_sizes": WALL_SIZES}, "control_arm": next(iter(files.values()))["baseline"] if files else None,
           "decisions": [decide_arm(x, files, qual.get(x)) for x in arms]}
    Path(a.out).write_text(json.dumps(out, indent=1, sort_keys=True) + "\n")
    for d in out["decisions"]:
        print(f"{d['arm']:50s} {d['decision']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
