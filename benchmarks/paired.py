"""Controlled, paired, order-randomized benchmark (supplements benchmarks/compare.py; does not replace its records).

    python benchmarks/paired.py --project pyflakes --src <clone> --evalpy <py without vep> --testmon-py <py with testmon> \
        --out benchmarks/results/paired-pyflakes.json [--blocks 10] [--warmups 2] [--seed 20261019] [--batch-n 4] [--workers 4]

Design (procedures added before the controlled run; the preregistered thresholds in docs/BENCHMARK_METHODOLOGY.md are unchanged):
* A block runs every configuration of a scenario once, on identical source trees, in a seeded random order. Paired
  differences are taken within a block. Warmup blocks run first and are recorded but not analysed.
* A block is excluded only if some configuration gave a wrong accept/reject outcome or hit an infrastructure error; the reason
  is recorded. Slow or noisy timings are never excluded.
* Per block, before timing: 1-minute load average and CPU idle percentage are recorded (not timed).
* Per run: wall time, child CPU time and peak child RSS from wait4 (the max over the waited-for process tree).
* Verdicts: the preregistered rule (Welch 95% interval of the difference of means; 10% relative and 50 ms absolute thresholds)
  is the headline; a paired bootstrap interval (10,000 resamples, seeded) is reported alongside.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import platform
import random
import re
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
REL, ABS = 0.10, 0.05  # preregistered
T_CRIT = [(1, 12.706), (2, 4.303), (3, 3.182), (4, 2.776), (5, 2.571), (6, 2.447), (7, 2.365), (8, 2.306), (9, 2.262),
          (10, 2.228), (15, 2.131), (20, 2.086), (30, 2.042), (10**9, 1.96)]
RSS_DIV = 1 if sys.platform == "darwin" else 1024  # ru_maxrss is bytes on macOS, KiB on Linux


def tcrit(df):
    best = T_CRIT[0][1]
    for d, t in T_CRIT:
        if d <= df:
            best = t
    return best


def classify(lo, hi, d):
    if hi < -REL and -d > ABS:
        return "VEP_FASTER"
    if lo > REL and d > ABS:
        return "VEP_SLOWER"
    if (lo >= -REL and hi <= REL) or abs(d) < ABS:
        return "NO_MEASURABLE_ADVANTAGE"
    return "INCONCLUSIVE"


def welch_verdict(base, vep):
    mb, mv = statistics.mean(base), statistics.mean(vep)
    sb, sv = statistics.stdev(base), statistics.stdev(vep)
    nb, nv = len(base), len(vep)
    se = math.sqrt(sb ** 2 / nb + sv ** 2 / nv)
    df = (sb ** 2 / nb + sv ** 2 / nv) ** 2 / ((sb ** 2 / nb) ** 2 / (nb - 1) + (sv ** 2 / nv) ** 2 / (nv - 1)) if se > 0 else nb + nv - 2
    d = mv - mb
    lo, hi = (d - tcrit(df) * se) / mb, (d + tcrit(df) * se) / mb
    return {"rule": "preregistered Welch 95%", "verdict": classify(lo, hi, d), "diff_s": round(d, 4), "rel_diff": round(d / mb, 4),
            "rel_ci95": [round(lo, 4), round(hi, 4)]}


def bootstrap_verdict(base, vep, seed, n=10000):
    rng = random.Random(seed)
    k = len(base)
    diffs = [v - b for b, v in zip(base, vep)]
    rel = [(v - b) / b for b, v in zip(base, vep)]
    md, mr = [], []
    for _ in range(n):
        idx = [rng.randrange(k) for _ in range(k)]
        md.append(statistics.mean(diffs[i] for i in idx))
        mr.append(statistics.mean(rel[i] for i in idx))
    md.sort(); mr.sort()
    lo_r, hi_r = mr[int(0.025 * n)], mr[int(0.975 * n)]
    d = statistics.mean(diffs)
    return {"rule": "paired bootstrap 95% (same thresholds)", "verdict": classify(lo_r, hi_r, d), "mean_paired_diff_s": round(d, 4),
            "median_paired_diff_s": round(statistics.median(diffs), 4), "diff_ci95_s": [round(md[int(0.025 * n)], 4), round(md[int(0.975 * n)], 4)],
            "mean_rel_diff": round(statistics.mean(rel), 4), "rel_ci95": [round(lo_r, 4), round(hi_r, 4)], "pairs": k}


def summ(xs):
    return {"n": len(xs), "mean": round(statistics.mean(xs), 4), "median": round(statistics.median(xs), 4),
            "sd": round(statistics.stdev(xs), 4) if len(xs) > 1 else 0.0, "min": round(min(xs), 4), "max": round(max(xs), 4)}


def env_probe() -> dict:
    load = os.getloadavg()[0]
    idle = None
    r = subprocess.run(["top", "-l", "2", "-n", "0", "-s", "2"], capture_output=True, text=True)
    m = re.findall(r"CPU usage:.*?([\d.]+)% idle", r.stdout)
    if m:
        idle = float(m[-1])
    return {"load_avg_1m": round(load, 2), "cpu_idle_pct": idle}


def run_proc(argv, cwd, capture=False):
    """Run one process; return (rc, wall, cpu, rss_mb, stdout)."""
    out = tempfile.TemporaryFile() if capture else subprocess.DEVNULL
    t0 = time.perf_counter()
    p = subprocess.Popen(argv, cwd=cwd, stdout=out, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
    _, status, ru = os.wait4(p.pid, 0)
    wall = time.perf_counter() - t0
    p.returncode = os.waitstatus_to_exitcode(status)
    text = ""
    if capture:
        out.seek(0)
        text = out.read().decode("utf-8", "replace")
        out.close()
    return p.returncode, wall, ru.ru_utime + ru.ru_stime, ru.ru_maxrss / RSS_DIV / (1e6 if sys.platform == "darwin" else 1), text


class Bench:
    def __init__(self, a):
        self.a, self.spec, self.name = a, SPECS[a.project], a.project
        self.tmp = Path(tempfile.mkdtemp(prefix="vep-paired-"))
        self.n = 0
        self.test_files = 0

    def tree(self, *, mutant=False, edit=False, extra: int | None = None) -> Path:
        self.n += 1
        d = self.tmp / f"t{self.n}"
        shutil.copytree(self.a.src, d, ignore=shutil.ignore_patterns(".git"))
        if mutant:
            m = self.spec["mutant"]; p = d / m["path"]; p.write_text(p.read_text().replace(m["old"], m["new"], 1))
        if edit:
            e = self.spec["edit"]; p = d / e["path"]; t = p.read_text(); assert e["old"] in t; p.write_text(t.replace(e["old"], e["new"], 1))
        if extra is not None:
            (d / self.spec["benign"]["path"].replace("vep_extra", f"vep_extra{extra}")).write_text(
                self.spec["benign"]["content"].replace("VepExtra", f"VepExtra{extra}"))
        return d

    # each returns dict(rc, wall, cpu, rss) ; success = rc == 0
    def direct(self, tree):
        rc, w, c, r, _ = run_proc([self.a.evalpy, *self.spec["direct_cmd"]], tree)
        return {"rc": rc, "wall": w, "cpu": c, "rss": r}

    def testmon(self, tree):
        rc, w, c, r, _ = run_proc([self.a.testmon_py, "-m", "pytest", "--testmon", "-q", "-x", *self.spec["pytest_targets"]], tree)
        return {"rc": 0 if rc in (0, 5) else rc, "wall": w, "cpu": c, "rss": r}

    def vep_setup(self, tree):
        ws = self.tmp / f"ws{time.monotonic_ns()}"
        subprocess.run([self.a.evalpy, str(DRIVER), "setup", "--ws", str(ws), "--tree", str(tree), "--project", self.name], check=True, capture_output=True)
        return ws

    def vep_single(self, ws, tree):
        rc, w, c, r, out = run_proc([self.a.evalpy, str(DRIVER), "single", "--ws", str(ws), "--tree", str(tree)], tree.parent, True)
        return {"rc": rc, "wall": w, "cpu": c, "rss": r}

    def vep_batch(self, ws, trees, workers):
        rc, w, c, r, out = run_proc([self.a.evalpy, str(DRIVER), "batch", "--ws", str(ws), "--workers", str(workers), "--trees", *map(str, trees)], self.tmp, True)
        return {"rc": rc, "wall": w, "cpu": c, "rss": r}

    def vep_buildcache(self, ws, tree):
        rc, w, c, r, out = run_proc([self.a.evalpy, str(DRIVER), "buildcache", "--ws", str(ws), "--tree", str(tree), "--project", self.name], tree.parent, True)
        hit = '"cache": "HIT"' in out
        return {"rc": rc, "wall": w, "cpu": c, "rss": r, "cache_hit": hit}

    # ---------------- correctness gate: every configuration accepts clean and rejects the mutant
    def gate(self):
        clean, mut = self.tree(), self.tree(mutant=True)
        g = {}
        g["DIRECT"] = [self.direct(clean)["rc"] == 0, self.direct(mut)["rc"] != 0]
        g["TESTMON"] = [self.testmon(self.tree())["rc"] == 0, self.testmon(self.tree(mutant=True))["rc"] != 0]
        g["VEP_PLAIN"] = [self.vep_single(self.vep_setup(clean), clean)["rc"] == 0, self.vep_single(self.vep_setup(clean), mut)["rc"] != 0]
        g["VEP_OPT_buildcache"] = [self.vep_buildcache(self.vep_setup(clean), clean)["rc"] == 0, self.vep_buildcache(self.vep_setup(clean), mut)["rc"] != 0]
        return {k: {"accepts_clean": v[0], "rejects_mutant": v[1], "passed": all(v)} for k, v in g.items()}

    # ---------------- scenarios: each returns a dict config -> measurement, for one block; setup is untimed
    def block_s1(self, order):  # cold verification of one tree
        fns = {"DIRECT": lambda: self.direct(self.tree()), "TESTMON": lambda: self.testmon(self.tree())}
        def vp():
            t = self.tree(); ws = self.vep_setup(self.tree()); return self.vep_single(ws, t)
        fns["VEP_PLAIN"] = vp
        return {k: fns[k]() for k in order}

    def block_s2(self, order):  # warm re-verification of an unchanged tree
        t_d = self.tree(); self.direct(t_d)
        t_t = self.tree(); self.testmon(t_t)
        t_v = self.tree(); ws_v = self.vep_setup(t_v); self.vep_single(ws_v, t_v)
        t_c = self.tree(); ws_c = self.vep_setup(t_c); self.vep_buildcache(ws_c, t_c)
        fns = {"DIRECT": lambda: self.direct(t_d), "TESTMON": lambda: self.testmon(t_t),
               "VEP_PLAIN": lambda: self.vep_single(ws_v, self.tree()),  # same content, new directory: a re-run of an unchanged tree
               "VEP_OPT": lambda: self.vep_buildcache(ws_c, self.tree())}
        return {k: fns[k]() for k in order}

    def block_s3(self, order):  # warm, after a small behaviour-preserving edit
        t_d = self.tree(edit=True)
        t_t = self.tree(); self.testmon(t_t)
        e = self.spec["edit"]; p = t_t / e["path"]; p.write_text(p.read_text().replace(e["old"], e["new"], 1))
        base = self.tree(); ws_v = self.vep_setup(base); self.vep_single(ws_v, base)
        t_v = self.tree(edit=True)
        fns = {"DIRECT": lambda: self.direct(t_d), "TESTMON": lambda: self.testmon(t_t), "VEP_PLAIN": lambda: self.vep_single(ws_v, t_v)}
        return {k: fns[k]() for k in order}

    def block_s4(self, order):  # cold batch of N distinct candidates
        n, w = self.a.batch_n, self.a.workers
        def seq():
            ts = [self.tree(extra=i) for i in range(n)]
            t0 = time.perf_counter(); rs = [self.direct(t) for t in ts]
            return {"rc": 0 if all(r["rc"] == 0 for r in rs) else 1, "wall": time.perf_counter() - t0, "cpu": sum(r["cpu"] for r in rs), "rss": max(r["rss"] for r in rs)}
        def par():
            ts = [self.tree(extra=i) for i in range(n)]
            t0 = time.perf_counter()
            with ThreadPoolExecutor(w) as ex:
                rs = list(ex.map(self.direct, ts))
            return {"rc": 0 if all(r["rc"] == 0 for r in rs) else 1, "wall": time.perf_counter() - t0, "cpu": sum(r["cpu"] for r in rs), "rss": max(r["rss"] for r in rs)}
        def vep(workers):
            def f():
                base = self.tree(); ws = self.vep_setup(base); ts = [self.tree(extra=i) for i in range(n)]
                return self.vep_batch(ws, ts, workers)
            return f
        fns = {"DIRECT_SEQ": seq, "DIRECT_PAR": par, "VEP_PLAIN": vep(1), "VEP_OPT": vep(w)}
        return {k: fns[k]() for k in order}


SCENARIOS = {
    "S1_cold_single": ("block_s1", ["DIRECT", "TESTMON", "VEP_PLAIN"], {"VEP_OPT": "no implemented optimization applies to one cold verification"}),
    "S2_warm_unchanged": ("block_s2", ["DIRECT", "TESTMON", "VEP_PLAIN", "VEP_OPT"], {}),
    "S3_warm_small_edit": ("block_s3", ["DIRECT", "TESTMON", "VEP_PLAIN"], {"VEP_OPT": "an edited tree misses the exact-snapshot cache; nothing to reuse"}),
    "S4_cold_batch": ("block_s4", ["DIRECT_SEQ", "DIRECT_PAR", "VEP_PLAIN", "VEP_OPT"], {}),
}
COMPARE = {"S1_cold_single": [("VEP_PLAIN", "DIRECT"), ("VEP_PLAIN", "TESTMON")],
           "S2_warm_unchanged": [("VEP_PLAIN", "DIRECT"), ("VEP_PLAIN", "TESTMON"), ("VEP_OPT", "DIRECT"), ("VEP_OPT", "VEP_PLAIN")],
           "S3_warm_small_edit": [("VEP_PLAIN", "DIRECT"), ("VEP_PLAIN", "TESTMON")],
           "S4_cold_batch": [("VEP_PLAIN", "DIRECT_SEQ"), ("VEP_OPT", "DIRECT_PAR"), ("VEP_OPT", "DIRECT_SEQ"), ("VEP_OPT", "VEP_PLAIN")]}


def analyse(blocks, pairs, seed):
    out = {"configs": {}, "comparisons": {}}
    cfgs = sorted({c for b in blocks for c in b["runs"]})
    for c in cfgs:
        rows = [b["runs"][c] for b in blocks if c in b["runs"]]
        out["configs"][c] = {"wall_s": summ([r["wall"] for r in rows]), "cpu_s": summ([r["cpu"] for r in rows]), "peak_child_rss_mb": summ([r["rss"] for r in rows])}
        if any("cache_hit" in r for r in rows):
            out["configs"][c]["cache_hits"] = sum(1 for r in rows if r.get("cache_hit")); out["configs"][c]["cache_misses"] = sum(1 for r in rows if "cache_hit" in r and not r["cache_hit"])
    for v, b in pairs:
        if v in cfgs and b in cfgs and len(blocks) >= 3:
            bw = [x["runs"][b]["wall"] for x in blocks]; vw = [x["runs"][v]["wall"] for x in blocks]
            out["comparisons"][f"{v}_vs_{b}"] = {"welch_preregistered": welch_verdict(bw, vw), "paired_bootstrap": bootstrap_verdict(bw, vw, seed),
                                                 "cpu_mean_ratio": round(statistics.mean(x["runs"][v]["cpu"] for x in blocks) / statistics.mean(x["runs"][b]["cpu"] for x in blocks), 3)}
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--project", required=True); ap.add_argument("--src", required=True)
    ap.add_argument("--evalpy", required=True); ap.add_argument("--testmon-py", required=True); ap.add_argument("--out", required=True)
    ap.add_argument("--blocks", type=int, default=10); ap.add_argument("--warmups", type=int, default=2)
    ap.add_argument("--seed", type=int, default=20261019); ap.add_argument("--batch-n", type=int, default=4); ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--scenarios", default=",".join(SCENARIOS))
    a = ap.parse_args()
    b = Bench(a)
    rng = random.Random(a.seed)
    report = {"methodology": "docs/BENCHMARK_METHODOLOGY.md (thresholds) + procedures in this file's docstring", "project": a.project, "seed": a.seed,
              "pinned_commit": subprocess.run(["git", "-C", a.src, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip(),
              "vep_commit": subprocess.run(["git", "-C", str(REPO), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip(),
              "host": {"platform": platform.platform(), "machine": platform.machine(), "cpus": os.cpu_count(), "python": platform.python_version(),
                       "power": subprocess.run(["pmset", "-g", "batt"], capture_output=True, text=True).stdout.splitlines()[:1],
                       "swap": subprocess.run(["sysctl", "-n", "vm.swapusage"], capture_output=True, text=True).stdout.strip()},
              "load_avg_1m_at_start": os.getloadavg()[0], "start_probe": env_probe(), "planned_valid_blocks": a.blocks, "warmups": a.warmups,
              "batch": {"n": a.batch_n, "workers": a.workers}, "scenarios": {}}
    try:
        report["correctness_gate"] = b.gate()
        report["gate_failures"] = [k for k, v in report["correctness_gate"].items() if not v["passed"]]
        for sc in a.scenarios.split(","):
            method, cfgs, na = SCENARIOS[sc]
            blocks, excluded, warm = [], [], []
            for i in range(a.warmups + a.blocks + 3):  # up to 3 replacement blocks if exclusions occur
                if len(blocks) >= a.blocks:
                    break
                order = cfgs[:]; rng.shuffle(order)
                probe = env_probe()
                try:
                    runs = getattr(b, method)(order)
                except Exception as exc:  # noqa: BLE001
                    excluded.append({"block": i, "reason": f"infrastructure error: {exc.__class__.__name__}: {exc}"[:200]}); continue
                rec = {"index": i, "order": order, "env": probe, "runs": runs}
                if i < a.warmups:
                    rec["note"] = "warmup (recorded, not analysed)"; warm.append(rec); continue
                bad = [c for c, r in runs.items() if r["rc"] != 0]
                if bad:
                    rec["excluded_reason"] = f"configuration(s) returned an incorrect/failed outcome: {bad}"; excluded.append(rec); continue
                blocks.append(rec)
            envs = [x["env"] for x in blocks]
            direct_key = "DIRECT" if "DIRECT" in cfgs else "DIRECT_SEQ"
            dw = [x["runs"][direct_key]["wall"] for x in blocks]
            cv = (statistics.stdev(dw) / statistics.mean(dw)) if len(dw) > 1 else None
            report["scenarios"][sc] = {"configs": cfgs, "not_applicable": na, "valid_blocks": len(blocks), "warmup_blocks": warm, "excluded": excluded,
                                       "blocks": blocks, "analysis": analyse(blocks, COMPARE[sc], a.seed + 1),
                                       "environment": {"load_avg_1m_min": min(e["load_avg_1m"] for e in envs), "load_avg_1m_max": max(e["load_avg_1m"] for e in envs),
                                                       "cpu_idle_pct_min": min((e["cpu_idle_pct"] or 0) for e in envs), "direct_baseline_cv": None if cv is None else round(cv, 4)}}
            print(sc, "valid blocks:", len(blocks), "excluded:", len(excluded), flush=True)
    finally:
        shutil.rmtree(b.tmp, ignore_errors=True)
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps(report, indent=1, sort_keys=True) + "\n")
    print("wrote", a.out)


if __name__ == "__main__":
    main()
