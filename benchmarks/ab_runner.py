"""Balanced, randomized-order, paired A/B comparison of VEP configurations (VEP_PERF flag sets) on the full protected workflow. Raw observations are kept.

    python benchmarks/ab_runner.py --n 1000 --arms none staging_fast verified_handoff --blocks 10 --out benchmarks/results/ab-<tag>.json

Each block runs every arm once in a seeded random order, each in a fresh process and a fresh project; warm-up blocks are recorded but not analysed; a block is
excluded only if some arm failed correctness (not certified or not authorized-verified), and exclusions are listed. The first arm is the baseline. Verdicts use the
preregistered rule from docs/BENCHMARK_METHODOLOGY.md (Welch 95%, 10% relative and 50 ms absolute) plus a paired bootstrap; the same thresholds are applied to CPU time.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import random
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import paired as P  # noqa: E402  (statistics and verdict rule shared with the established harness)
import envinfo  # noqa: E402

RSS_DIV = P.RSS_DIV


def one(arm: str, n: int, change: str) -> dict:
    tmp = Path(tempfile.mkdtemp(prefix="vep-ab-"))
    root = tmp / "p"
    root.mkdir()
    env = dict(os.environ, VEP_PERF=arm or "none")
    t0 = time.perf_counter()
    p = subprocess.Popen([sys.executable, str(HERE / "workflow_once.py"), "--n", str(n), "--root", str(root), "--change", change], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    _, status, ru = os.wait4(p.pid, 0)
    out, err = p.stdout.read(), p.stderr.read()
    total = time.perf_counter() - t0
    subprocess.run(["chmod", "-R", "u+w", str(tmp)], capture_output=True)
    shutil.rmtree(tmp, ignore_errors=True)
    rc = os.waitstatus_to_exitcode(status)
    try:
        j = json.loads(out.strip().splitlines()[-1])
    except Exception:
        j = {"error": f"no output (rc={rc}) {err[-200:]}"}
    j.update(rc=rc, total_s=total, rss_child_max_mb=ru.ru_maxrss / (1e6 if sys.platform == "darwin" else 1024))
    return j


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, required=True)
    ap.add_argument("--arms", nargs="+", required=True)
    ap.add_argument("--blocks", type=int, default=10)
    ap.add_argument("--warmups", type=int, default=2)
    ap.add_argument("--seed", type=int, default=20261019)
    ap.add_argument("--change", default="new", choices=["new", "none"])
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    rng = random.Random(a.seed)
    blocks, warm = [], []
    for i in range(a.warmups + a.blocks):
        order = list(a.arms); rng.shuffle(order)
        env = envinfo.env_probe()
        runs = {arm: one(arm, a.n, a.change) for arm in order}
        rec = {"index": i, "order": order, "env": {k: env.get(k) for k in ("load_avg_1m", "cpu_idle_pct", "mem_available_mb") if k in env}, "runs": runs}
        (warm if i < a.warmups else blocks).append(rec)
        print(f"block {i}: " + " ".join(f"{k}={v.get('wall_s', float('nan')):.3f}" for k, v in runs.items()), flush=True)
    good = [b for b in blocks if all("error" not in r and r["rc"] == 0 for r in b["runs"].values())]
    excluded = [{"index": b["index"], "reason": {k: r.get("error") for k, r in b["runs"].items() if "error" in r or r["rc"]}} for b in blocks if b not in good]
    base = a.arms[0]
    summary, comps = {}, {}
    for arm in a.arms:
        summary[arm] = {m: P.summ([b["runs"][arm][m] for b in good]) for m in ("wall_s", "cpu_s", "materialize_s", "evaluate_s", "rss_child_max_mb")} if good else {}
    for arm in a.arms[1:]:
        comps[f"{arm}_vs_{base}"] = {}
        for m in ("wall_s", "cpu_s"):
            b_, v_ = [b["runs"][base][m] for b in good], [b["runs"][arm][m] for b in good]
            if len(good) >= 3:
                comps[f"{arm}_vs_{base}"][m] = {"welch_preregistered": P.welch_verdict(b_, v_), "paired_bootstrap": P.bootstrap_verdict(b_, v_, a.seed)}
        ms = [(b["runs"][arm]["materialize_s"] - b["runs"][base]["materialize_s"]) for b in good]
        if good:
            comps[f"{arm}_vs_{base}"]["materialize_s_mean_paired_diff"] = round(statistics.mean(ms), 4)
    doc = {"kind": "paired A/B of VEP_PERF flag sets", "n_files": a.n, "arms": a.arms, "baseline": base, "change": a.change, "seed": a.seed, "valid_blocks": len(good), "warmup_blocks": len(warm),
           "excluded": excluded, "host": {"platform": platform.platform(), "cpus": os.cpu_count(), "python": platform.python_version(), "load_avg_1m_at_start": os.getloadavg()[0]},
           "summary": summary, "comparisons": comps, "blocks": blocks, "warmups": warm,
           "rule": {"relative": P.REL, "absolute_s": P.ABS, "note": "applied to wall and to CPU seconds; adoption also needs zero correctness exclusions and no cold-path regression"}}
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
