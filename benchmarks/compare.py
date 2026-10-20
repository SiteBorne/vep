"""Comparative benchmark following docs/BENCHMARK_METHODOLOGY.md (declared before measuring).

    python benchmarks/compare.py --project more-itertools --src <clone> --out benchmarks/results/compare-more-itertools.json \
        --evalpy <python without vep> --testmon-py <python with pytest-testmon>
"""
from __future__ import annotations

import argparse
import json
import math
import os
import platform
import resource
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SPECS = json.loads((REPO / "benchmarks" / "external" / "projects.json").read_text())
DRIVER = REPO / "benchmarks" / "compare_vep_driver.py"
T_CRIT = [(1, 12.706), (2, 4.303), (3, 3.182), (4, 2.776), (5, 2.571), (6, 2.447), (7, 2.365), (8, 2.306), (9, 2.262),
          (10, 2.228), (15, 2.131), (20, 2.086), (30, 2.042), (10**9, 1.96)]
REL, ABS = 0.10, 0.05  # declared thresholds


def tcrit(df: float) -> float:
    best = T_CRIT[0][1]
    for d, t in T_CRIT:  # conservative: use the entry at or below df
        if d <= df:
            best = t
    return best


def verdict(base: list[float], vep: list[float]) -> dict:
    mb, mv = statistics.mean(base), statistics.mean(vep)
    sb, sv = statistics.stdev(base), statistics.stdev(vep)
    nb, nv = len(base), len(vep)
    se = math.sqrt(sb ** 2 / nb + sv ** 2 / nv)
    df = (sb ** 2 / nb + sv ** 2 / nv) ** 2 / ((sb ** 2 / nb) ** 2 / (nb - 1) + (sv ** 2 / nv) ** 2 / (nv - 1)) if se > 0 else nb + nv - 2
    d = mv - mb
    lo, hi = (d - tcrit(df) * se) / mb, (d + tcrit(df) * se) / mb
    if hi < -REL and -d > ABS:
        v = "VEP_FASTER"
    elif lo > REL and d > ABS:
        v = "VEP_SLOWER"
    elif (lo >= -REL and hi <= REL) or abs(d) < ABS:
        v = "NO_MEASURABLE_ADVANTAGE"
    else:
        v = "INCONCLUSIVE"
    return {"verdict": v, "baseline_mean_s": round(mb, 4), "vep_mean_s": round(mv, 4), "diff_s": round(d, 4),
            "rel_diff": round(d / mb, 4), "rel_ci95": [round(lo, 4), round(hi, 4)], "welch_df": round(df, 1)}


def summ(xs: list[float]) -> dict:
    return {"n": len(xs), "mean": round(statistics.mean(xs), 4), "sd": round(statistics.stdev(xs), 4) if len(xs) > 1 else 0.0,
            "min": round(min(xs), 4), "max": round(max(xs), 4), "samples": [round(x, 4) for x in xs]}


def measured(fn):
    r0, t0 = resource.getrusage(resource.RUSAGE_CHILDREN), time.perf_counter()
    out = fn()
    r1 = resource.getrusage(resource.RUSAGE_CHILDREN)
    return out, time.perf_counter() - t0, (r1.ru_utime - r0.ru_utime) + (r1.ru_stime - r0.ru_stime)


class Bench:
    def __init__(self, a):
        self.a, self.name = a, a.project
        self.spec = SPECS[a.project]
        self.tmp = Path(tempfile.mkdtemp(prefix="vep-cmp-"))
        self.n = 0

    def tree(self, edit=None, mutant=False, extra_test: str | None = None) -> Path:
        self.n += 1
        d = self.tmp / f"t{self.n}"
        shutil.copytree(self.a.src, d, ignore=shutil.ignore_patterns(".git"))
        if mutant:
            m = self.spec["mutant"]
            p = d / m["path"]
            p.write_text(p.read_text().replace(m["old"], m["new"], 1))
        if edit:
            e = self.spec["edit"]
            p = d / e["path"]
            t = p.read_text()
            assert e["old"] in t
            p.write_text(t.replace(e["old"], e["new"], 1))
        if extra_test:
            (d / self.spec["benign"]["path"].replace("vep_extra", extra_test)).write_text(
                self.spec["benign"]["content"].replace("VepExtra", "V" + extra_test.replace("_", "")))
        return d

    # ---- systems; each returns (accepted: bool)
    def direct(self, tree: Path) -> bool:
        return subprocess.run([self.a.evalpy, *self.spec["direct_cmd"]], cwd=tree, capture_output=True).returncode == 0

    def testmon(self, tree: Path) -> bool:
        r = subprocess.run([self.a.testmon_py, "-m", "pytest", "--testmon", "-q", "-x", *self.spec["pytest_targets"]],
                           cwd=tree, capture_output=True)
        return r.returncode in (0, 5)  # 5 = nothing selected, i.e. nothing affected by the change

    def vep_setup(self, tree: Path) -> Path:
        ws = self.tmp / f"ws{self.n}_{time.monotonic_ns()}"
        subprocess.run([self.a.evalpy, str(DRIVER), "setup", "--ws", str(ws), "--tree", str(tree), "--project", self.name], check=True, capture_output=True)
        return ws

    def vep_single(self, ws: Path, tree: Path) -> bool:
        return subprocess.run([self.a.evalpy, str(DRIVER), "single", "--ws", str(ws), "--tree", str(tree)], capture_output=True).returncode == 0

    def vep_batch(self, ws: Path, trees: list[Path], workers: int) -> bool:
        return subprocess.run([self.a.evalpy, str(DRIVER), "batch", "--ws", str(ws), "--workers", str(workers), "--trees", *map(str, trees)],
                              capture_output=True).returncode == 0

    def vep_buildcache(self, ws: Path, tree: Path) -> bool:
        return subprocess.run([self.a.evalpy, str(DRIVER), "buildcache", "--ws", str(ws), "--tree", str(tree), "--project", self.name],
                              capture_output=True).returncode == 0

    # ---- gate
    def gate(self) -> dict:
        clean, mut = self.tree(), self.tree(mutant=True)
        ws = self.vep_setup(clean)
        ws2 = self.vep_setup(clean)
        tm_clean, tm_mut = self.tree(), self.tree(mutant=True)
        bws = self.vep_setup(clean)
        g = {"A_direct": [self.direct(clean), not self.direct(mut)],
             "B_testmon": [self.testmon(tm_clean), not self.testmon(tm_mut)],
             "E_vep": [self.vep_single(ws, clean), not self.vep_single(ws2, mut)],
             "F2_buildcache": [self.vep_buildcache(bws, clean), not self.vep_buildcache(self.vep_setup(clean), mut)]}
        return {k: {"accepts_clean": v[0], "rejects_mutant": v[1], "passed": all(v)} for k, v in g.items()}

    # ---- scenarios
    def t1(self, reps: int) -> dict:
        out = {k: [] for k in ("A", "B", "E")}
        cpu = {k: [] for k in out}
        setup = []
        for _ in range(reps):
            t = self.tree()
            _, w, c = measured(lambda: self.direct(t)); out["A"].append(w); cpu["A"].append(c)
            t = self.tree()
            _, w, c = measured(lambda: self.testmon(t)); out["B"].append(w); cpu["B"].append(c)
            t = self.tree()
            _, sw, _ = measured(lambda: self.vep_setup(t)); setup.append(sw)
            ws = self.tmp / f"ws{self.n}"  # last created workspace for this tree
            ws = max(self.tmp.glob("ws*"), key=lambda p: p.stat().st_mtime)
            t2 = self.tree()
            _, w, c = measured(lambda: self.vep_single(ws, t2)); out["E"].append(w); cpu["E"].append(c)
        return {"wall": {k: summ(v) for k, v in out.items()}, "child_cpu": {k: summ(v) for k, v in cpu.items()},
                "vep_one_time_setup_s": summ(setup),
                "verdicts": {"E_vs_A": verdict(out["A"], out["E"]), "E_vs_B": verdict(out["B"], out["E"])}}

    def t2(self, reps: int) -> dict:
        res = {k: [] for k in ("A", "B", "E", "F2")}
        first = {"B": [], "F2_miss": []}
        for _ in range(reps):
            t = self.tree(); self.direct(t)
            _, w, _ = measured(lambda: self.direct(t)); res["A"].append(w)
            t = self.tree()
            _, wf, _ = measured(lambda: self.testmon(t)); first["B"].append(wf)
            _, w, _ = measured(lambda: self.testmon(t)); res["B"].append(w)
            t = self.tree(); ws = self.vep_setup(t); self.vep_single(ws, t)
            t_again = self.tree()  # same content, new directory: a CI re-run of an unchanged tree
            _, w, _ = measured(lambda: self.vep_single(ws, t_again)); res["E"].append(w)
            t = self.tree(); ws = self.vep_setup(t)
            _, wf, _ = measured(lambda: self.vep_buildcache(ws, t)); first["F2_miss"].append(wf)
            t_again = self.tree()
            _, w, _ = measured(lambda: self.vep_buildcache(ws, t_again)); res["F2"].append(w)
        return {"wall": {k: summ(v) for k, v in res.items()}, "first_run_cost": {k: summ(v) for k, v in first.items()},
                "verdicts": {"E_vs_A": verdict(res["A"], res["E"]), "E_vs_B": verdict(res["B"], res["E"]),
                             "F2_vs_A_no_certificate": verdict(res["A"], res["F2"])}}

    def t3(self, reps: int) -> dict:
        res = {k: [] for k in ("A", "B", "E")}
        for _ in range(reps):
            base = self.tree()
            t = self.tree(edit=True)
            _, w, _ = measured(lambda: self.direct(t)); res["A"].append(w)
            tb = self.tree(); self.testmon(tb)  # populate testmon data on the unedited tree
            e = self.spec["edit"]
            p = tb / e["path"]; p.write_text(p.read_text().replace(e["old"], e["new"], 1))
            _, w, _ = measured(lambda: self.testmon(tb)); res["B"].append(w)
            ws = self.vep_setup(base)
            te = self.tree(edit=True)
            _, w, _ = measured(lambda: self.vep_single(ws, te)); res["E"].append(w)
        return {"wall": {k: summ(v) for k, v in res.items()},
                "verdicts": {"E_vs_A": verdict(res["A"], res["E"]), "E_vs_B": verdict(res["B"], res["E"])}}

    def t4(self, reps: int, n: int, workers: int) -> dict:
        res = {k: [] for k in ("C_seq_direct", "D_parallel_direct", "E_vep_1", "F_vep_parallel")}
        for _ in range(reps):
            trees = [self.tree(extra_test=f"vep_extra{i}") for i in range(n)]
            _, w, _ = measured(lambda: all([self.direct(t) for t in trees])); res["C_seq_direct"].append(w)
            trees = [self.tree(extra_test=f"vep_extra{i}") for i in range(n)]
            def par():
                with ThreadPoolExecutor(workers) as ex:
                    return all(ex.map(self.direct, trees))
            _, w, _ = measured(par); res["D_parallel_direct"].append(w)
            base = self.tree()
            for key, wk in (("E_vep_1", 1), ("F_vep_parallel", workers)):
                ws = self.vep_setup(base)
                trees = [self.tree(extra_test=f"vep_extra{i}") for i in range(n)]
                _, w, _ = measured(lambda: self.vep_batch(ws, trees, wk)); res[key].append(w)
        return {"n_candidates": n, "workers": workers, "wall": {k: summ(v) for k, v in res.items()},
                "verdicts": {"E1_vs_C": verdict(res["C_seq_direct"], res["E_vep_1"]),
                             "F_vs_D": verdict(res["D_parallel_direct"], res["F_vep_parallel"]),
                             "F_vs_C": verdict(res["C_seq_direct"], res["F_vep_parallel"])}}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--project", required=True)
    ap.add_argument("--src", required=True)
    ap.add_argument("--evalpy", required=True)
    ap.add_argument("--testmon-py", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--reps", type=int, default=10)
    ap.add_argument("--batch-reps", type=int, default=5)
    ap.add_argument("--batch-n", type=int, default=8)
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--scenarios", default="T1,T2,T3,T4")
    a = ap.parse_args()
    b = Bench(a)
    ver = subprocess.run([a.testmon_py, "-m", "pip", "list", "--format=json"], capture_output=True, text=True)
    pk = {p["name"].lower(): p["version"] for p in json.loads(ver.stdout)} if ver.returncode == 0 else {}
    report = {"methodology": "docs/BENCHMARK_METHODOLOGY.md", "project": a.project,
              "pinned_commit": subprocess.run(["git", "-C", a.src, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip(),
              "vep_commit": subprocess.run(["git", "-C", str(REPO), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip(),
              "host": {"platform": platform.platform(), "cpus": os.cpu_count(), "python": platform.python_version(),
                       "load_avg_1m_at_start": os.getloadavg()[0]},
              "testmon_env": {k: pk.get(k) for k in ("pytest", "pytest-testmon", "coverage")},
              "thresholds": {"relative": REL, "absolute_s": ABS}, "reps": a.reps, "batch_reps": a.batch_reps}
    try:
        report["correctness_gate"] = b.gate()
        failed = [k for k, v in report["correctness_gate"].items() if not v["passed"]]
        report["gate_failures"] = failed
        sc = a.scenarios.split(",")
        if "T1" in sc: report["T1_cold_verify"] = b.t1(a.reps)
        if "T2" in sc: report["T2_unchanged_rerun"] = b.t2(a.reps)
        if "T3" in sc: report["T3_small_edit"] = b.t3(a.reps)
        if "T4" in sc: report["T4_batch"] = b.t4(a.batch_reps, a.batch_n, a.workers)
    finally:
        shutil.rmtree(b.tmp, ignore_errors=True)
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps(report, indent=1, sort_keys=True) + "\n")
    print("gate failures:", report["gate_failures"])
    for k, v in report.items():
        if isinstance(v, dict) and "verdicts" in v:
            print(k, {n: x["verdict"] for n, x in v["verdicts"].items()})
    return 0


if __name__ == "__main__":
    sys.exit(main())
