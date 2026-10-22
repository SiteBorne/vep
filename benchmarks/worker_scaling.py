"""Experiment D: throughput, latency, CPU and memory of VEP's controller with 1, 2, 4, 8, 16 worker processes on SHORT and LONG real test workloads.

    python benchmarks/worker_scaling.py --project pyflakes --src <clone> --evalpy <py without vep> --candidates 8 --workers 1 2 4 8 16 --reps 5 --out <json>

Each repetition certifies N distinct benign candidates of a pinned project through the durable controller (real worker processes sharing one SQLite workspace) and,
as the no-VEP reference, runs the same trees with the same number of parallel direct test processes. Order of worker counts is shuffled per repetition. Reported:
jobs/s, p95 completion latency, CPU seconds, largest-child RSS, and whether all candidates were certified exactly once (stale commits / retries are read from the DB).
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
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import paired as P  # noqa: E402
import envinfo  # noqa: E402
from agent_workflow import Ctx, DRIVER  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--project", required=True); ap.add_argument("--src", required=True); ap.add_argument("--evalpy", required=True)
    ap.add_argument("--candidates", type=int, default=8); ap.add_argument("--workers", nargs="+", type=int, default=[1, 2, 4, 8, 16])
    ap.add_argument("--reps", type=int, default=5); ap.add_argument("--warmups", type=int, default=1); ap.add_argument("--opt-flags", default="staging_fast,verified_handoff")
    ap.add_argument("--seed", type=int, default=20261019); ap.add_argument("--out", required=True)
    a = ap.parse_args()
    rng = random.Random(a.seed)
    raw = []
    for rep in range(a.warmups + a.reps):
        order = list(a.workers); rng.shuffle(order)
        rec = {"rep": rep, "warmup": rep < a.warmups, "env": envinfo.env_probe(), "vep": {}, "direct": {}}
        for w in order:
            ctx = Ctx(a, a.project, a.src)
            trees = [str(ctx.tree(f"extra{i}")) for i in range(a.candidates)]
            for system, flags in (("vep", a.opt_flags),):
                ws = ctx.tmp / "ws"
                env = dict(os.environ, VEP_PERF=flags)
                base = ctx.tree("clean")
                subprocess.run([a.evalpy, str(DRIVER), "setup", "--ws", str(ws), "--tree", str(base), "--project", a.project], check=True, capture_output=True, env=env)
                sf = ctx.tmp / "steps.json"; sf.write_text(json.dumps([{"label": "batch", "kind": "batch", "trees": trees}]))
                p = subprocess.Popen([a.evalpy, str(DRIVER), "trace", "--ws", str(ws), "--steps", str(sf), "--workers", str(w), "--system", "fresh"], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                _, status, ru = os.wait4(p.pid, 0)
                out = p.stdout.read()
                try:
                    j = json.loads(out.strip().splitlines()[-1]); step = j["steps"][0]
                except Exception:
                    step = {"error": p.stderr.read()[-200:]}
                with_db = {}
                try:
                    import sqlite3
                    con = sqlite3.connect(str(ws / ".vep" / "vep.db")); con.row_factory = sqlite3.Row
                    with_db = {"jobs": con.execute("SELECT COUNT(*) n FROM jobs").fetchone()["n"], "attempts_gt1": con.execute("SELECT COUNT(*) n FROM jobs WHERE attempts<>1").fetchone()["n"],
                               "certificates": con.execute("SELECT COUNT(*) n FROM certificates").fetchone()["n"]}
                except Exception as exc:
                    with_db = {"error": repr(exc)[:100]}
                rec["vep"][str(w)] = {**step, "cpu_total_s": ru.ru_utime + ru.ru_stime, "rss_children_max_mb": ru.ru_maxrss / (1e6 if sys.platform == "darwin" else 1024), **with_db}
            t0 = time.perf_counter()
            with ThreadPoolExecutor(w) as ex:
                rs = list(ex.map(lambda t: P.run_proc([a.evalpy, *ctx.spec["direct_cmd"]], Path(t)), trees))
            wall = time.perf_counter() - t0
            rec["direct"][str(w)] = {"wall_s": wall, "jobs_per_s": len(trees) / wall, "cpu_s": sum(r[2] for r in rs), "rss_mb": max(r[3] for r in rs), "all_pass": all(r[0] == 0 for r in rs)}
            subprocess.run(["chmod", "-R", "u+w", str(ctx.tmp)], capture_output=True); shutil.rmtree(ctx.tmp, ignore_errors=True)
        raw.append(rec)
        print(f"rep {rep}: " + " ".join(f"w{w}={rec['vep'][str(w)].get('jobs_per_s', float('nan')):.2f}j/s" for w in a.workers), flush=True)
    kept = [r for r in raw if not r["warmup"]]
    summ = {}
    for w in a.workers:
        v = [r["vep"][str(w)] for r in kept if "error" not in r["vep"][str(w)]]
        d = [r["direct"][str(w)] for r in kept]
        summ[str(w)] = {"vep_jobs_per_s": P.summ([x["jobs_per_s"] for x in v]) if v else None, "vep_p95_latency_s": P.summ([x["p95_latency_s"] for x in v]) if v else None,
                        "vep_cpu_total_s": P.summ([x["cpu_total_s"] for x in v]) if v else None, "vep_rss_children_max_mb": P.summ([x["rss_children_max_mb"] for x in v]) if v else None,
                        "vep_all_certified_once": all(x.get("certified") == a.candidates and x.get("attempts_gt1") == 0 for x in v) if v else None,
                        "direct_jobs_per_s": P.summ([x["jobs_per_s"] for x in d]), "direct_cpu_s": P.summ([x["cpu_s"] for x in d])}
    doc = {"kind": "worker scaling on a real project", "project": a.project, "project_commit": P.SPECS[a.project]["commit"], "candidates_per_rep": a.candidates, "opt_flags": a.opt_flags, "reps": a.reps,
           "warmups": a.warmups, "host": {"platform": platform.platform(), "cpus": os.cpu_count(), "python": platform.python_version(), "load_avg_1m_at_start": os.getloadavg()[0]}, "summary": summ, "raw": raw}
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
