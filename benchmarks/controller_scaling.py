"""Measure the durable controller with W real worker processes on one host (spawned processes, real evaluator).

Usage: python benchmarks/controller_scaling.py [--jobs 32] [--reps 3] [--workers 1 2 4 8 16] [--out FILE]

Each rep builds a fresh workspace with `jobs` distinct candidates (each runs a real unittest evaluation and
certification). Reported per worker count: wall time, throughput, per-job latency, retries/stale commits,
child CPU time and peak child RSS. A direct sequential `evaluate+certify` run without the controller is
the baseline for controller overhead. Results are observations on this machine only.
"""
from __future__ import annotations

import argparse
import json
import multiprocessing as mp
import platform
import resource
import shutil
import statistics
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from vep import budgets, candidates, certificates, controller, execution, snapshots  # noqa: E402
from vep.evidence import KeyStore  # noqa: E402
from vep.objectives import create_objective  # noqa: E402
from vep.policies import make_policy  # noqa: E402
from vep.workspace import Workspace  # noqa: E402

BASE = {
    "calc.py": "def add(a, b):\n    return a + b\n",
    "tests/test_calc.py": "import unittest\nfrom calc import add\n\n\nclass T(unittest.TestCase):\n"
                          "    def test_add(self):\n        self.assertEqual(add(1, 2), 3)\n",
}


def make_env(tmp: Path, jobs: int):
    root = tmp / "p"
    for rel, txt in BASE.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(txt)
    ws = Workspace.init(root)
    KeyStore(ws).ensure()
    base = snapshots.take_snapshot(ws)
    pol = make_policy(ws, base)
    obj = create_objective(ws, "bench", "bench", base.id, pol.id)
    budgets.create_account(ws, f"objective:{obj.id}", "objective", "100.00")
    cids = []
    for i in range(jobs):
        d = tmp / f"v{i}"
        shutil.copytree(root, d, ignore=shutil.ignore_patterns(".vep"))
        (d / f"mod{i}.py").write_text(f"V = {i}\n")
        cids.append(candidates.register_candidate(ws, obj.id, snapshots.take_snapshot(ws, d).id, "bench").id)
    return ws, cids


def worker_proc(root: str, name: str, q) -> None:
    ws = Workspace(root)
    w = controller.LocalToolWorker(name, execution.TRUSTED_LOCAL_AUTH)
    lat, outcomes = [], []
    while True:
        t0 = time.perf_counter()
        r = controller.run_one(ws, w)
        if r is None:
            break
        lat.append(time.perf_counter() - t0)
        outcomes.append(r["outcome"])
    q.put({"latencies": lat, "outcomes": outcomes})


def run_controller(tmp: Path, jobs: int, workers: int) -> dict:
    ws, cids = make_env(tmp, jobs)
    for c in cids:
        controller.enqueue(ws, c)
    ctx = mp.get_context("spawn")
    q = ctx.Queue()
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    t0 = time.perf_counter()
    procs = [ctx.Process(target=worker_proc, args=(str(ws.root), f"w{i}", q)) for i in range(workers)]
    for p in procs:
        p.start()
    res = [q.get() for _ in procs]
    for p in procs:
        p.join()
    wall = time.perf_counter() - t0
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    lat = [x for r in res for x in r["latencies"]]
    outcomes = [o for r in res for o in r["outcomes"]]
    with ws.db.read() as c:
        certified = c.execute("SELECT COUNT(*) n FROM certificates").fetchone()["n"]
        retried = c.execute("SELECT COUNT(*) n FROM jobs WHERE attempts>1").fetchone()["n"]
    rss_div = 1 if sys.platform == "darwin" else 1024
    return {"wall_s": wall, "throughput_jobs_per_s": jobs / wall, "mean_latency_s": statistics.mean(lat),
            "max_latency_s": max(lat), "certified": certified, "retried_jobs": retried,
            "stale_commits": outcomes.count("STALE"), "failed": outcomes.count("FAILED"),
            "child_cpu_s": (after.ru_utime - before.ru_utime) + (after.ru_stime - before.ru_stime),
            "peak_single_child_rss_mb": after.ru_maxrss / rss_div / 1e6 if sys.platform == "darwin" else after.ru_maxrss / 1024}


def run_direct(tmp: Path, jobs: int) -> dict:
    """Baseline: sequential evaluate+certify with no controller."""
    ws, cids = make_env(tmp, jobs)
    t0 = time.perf_counter()
    for c in cids:
        execution.evaluate(ws, c, trusted_local_authorization=execution.TRUSTED_LOCAL_AUTH)
        certificates.certify(ws, c)
    wall = time.perf_counter() - t0
    return {"wall_s": wall, "throughput_jobs_per_s": jobs / wall}


def summarize(runs: list[dict], key: str) -> dict:
    v = [r[key] for r in runs]
    return {"mean": statistics.mean(v), "stdev": statistics.stdev(v) if len(v) > 1 else 0.0, "min": min(v), "max": max(v)}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--jobs", type=int, default=32)
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--workers", type=int, nargs="+", default=[1, 2, 4, 8, 16])
    ap.add_argument("--out", default="benchmarks/results/controller_scaling.json")
    a = ap.parse_args()
    out: dict = {"host": {"platform": platform.platform(), "cpus": mp.cpu_count(), "python": sys.version.split()[0]},
                 "jobs_per_rep": a.jobs, "reps": a.reps, "results": {}}
    tmp_root = Path(tempfile.mkdtemp(prefix="vep-bench-"))
    try:
        direct = [run_direct(tmp_root / f"d{i}", a.jobs) for i in range(a.reps)]
        out["results"]["direct_sequential_no_controller"] = {k: summarize(direct, k) for k in ("wall_s", "throughput_jobs_per_s")}
        for w in a.workers:
            runs = [run_controller(tmp_root / f"c{w}_{i}", a.jobs, w) for i in range(a.reps)]
            bad = [r for r in runs if r["certified"] != a.jobs or r["failed"] or r["stale_commits"]]
            out["results"][f"controller_{w}_workers"] = {
                "correct_all_reps": not bad,
                **{k: summarize(runs, k) for k in ("wall_s", "throughput_jobs_per_s", "mean_latency_s", "max_latency_s",
                                                   "child_cpu_s", "peak_single_child_rss_mb", "retried_jobs", "stale_commits")}}
            print(f"workers={w}: {out['results'][f'controller_{w}_workers']['throughput_jobs_per_s']['mean']:.2f} jobs/s", flush=True)
    finally:
        shutil.rmtree(tmp_root, ignore_errors=True)
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps(out, indent=1, sort_keys=True))
    print(f"wrote {a.out}")


if __name__ == "__main__":
    main()
