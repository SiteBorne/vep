"""Stage-level profile of VEP's complete protected workflow as the input grows (100 to 10,000+ files). No model, no network.

    python benchmarks/profile_scale.py --sizes 100 1000 3000 10000 --runs 3 --out benchmarks/results/scale-profile-<tag>.json

Workflow traced: source scan -> snapshot hashing -> CAS write -> policy check -> queue -> staging -> pre-execution integrity -> test subprocess -> report validation ->
post-execution integrity -> signing -> certification -> independent (authorized, Python) verification. Wall and CPU time are reported INCLUSIVE and EXCLUSIVE per stage
(exclusive = inclusive minus time spent in nested instrumented stages). Counters (file opens, bytes read/written/hashed, mkdir/chmod calls, CAS hits/misses, SQLite
acquire/body/commit time) are attributed to the innermost active stage. Peak RSS is the SUM over the process tree sampled every 20 ms with `ps` (a sampler can miss spikes
shorter than its interval). Allocation hotspots come from a separate tracemalloc run that is never timed. Instrumentation overhead is itself measured and reported.
Set VEP_SRC to profile another source tree (used for before/after comparisons).
"""
from __future__ import annotations

import argparse
import builtins
import hashlib
import io
import json
import os
import platform
import resource
import shutil
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import tracemalloc
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, os.environ.get("VEP_SRC") or str(Path(__file__).resolve().parents[1] / "src"))
from vep import (budgets, candidates, certificates, conformance, controller, evidence, execution, snapshots, storage, trustpolicy, versions)  # noqa: E402
from vep.database import Database  # noqa: E402
from vep.evidence import KeyStore  # noqa: E402
from vep.objectives import create_objective  # noqa: E402
from vep.policies import make_policy  # noqa: E402
from vep.workspace import Workspace  # noqa: E402

COUNTERS = ("opens", "bytes_read", "bytes_written", "bytes_hashed", "mkdirs", "chmods", "cas_hits", "cas_misses", "sqlite_acquire_s", "sqlite_body_s", "sqlite_commit_s")


class Prof:
    def __init__(self):
        self.local = threading.local()
        self.reset()

    def reset(self):
        self.incl = defaultdict(float); self.excl = defaultdict(float); self.cpu_incl = defaultdict(float); self.cpu_excl = defaultdict(float)
        self.calls = defaultdict(int); self.callers = defaultdict(lambda: defaultdict(int)); self.cnt = defaultdict(lambda: defaultdict(float)); self.tree_calls = 0

    def stack(self):
        if not hasattr(self.local, "s"):
            self.local.s = []
        return self.local.s

    def top(self):
        s = self.stack()
        return s[-1][0] if s else "(outside)"

    def add(self, key, n=1):
        self.cnt[self.top()][key] += n


P = Prof()


def stage(name):
    def deco_target(owner, attr, label=None):
        orig = getattr(owner, attr)
        lab = label or name

        def wrapper(*a, **k):
            s = P.stack()
            P.callers[lab][s[-1][0] if s else '(outside)'] += 1
            frame = [lab, time.perf_counter(), time.process_time(), 0.0, 0.0]
            s.append(frame)
            try:
                return orig(*a, **k)
            finally:
                s.pop()
                dt, dc = time.perf_counter() - frame[1], time.process_time() - frame[2]
                P.incl[lab] += dt; P.excl[lab] += dt - frame[3]; P.cpu_incl[lab] += dc; P.cpu_excl[lab] += dc - frame[4]; P.calls[lab] += 1
                if s:
                    s[-1][3] += dt; s[-1][4] += dc
        setattr(owner, attr, wrapper)
    return deco_target


class CountedHash:
    def __init__(self, h):
        self._h = h

    def update(self, data):
        P.add("bytes_hashed", len(data)); self._h.update(data)

    def hexdigest(self):
        return self._h.hexdigest()

    def digest(self):
        return self._h.digest()

    def copy(self):
        return CountedHash(self._h.copy())


def install():
    S = lambda owner, attr, label: stage(label)(owner, attr, label)
    S(snapshots, "scan_tree", "scan_tree"); S(snapshots, "read_regular_nofollow", "read_files"); S(snapshots, "take_snapshot", "take_snapshot")
    S(snapshots, "verify_snapshot", "verify_snapshot"); S(execution, "verify_snapshot", "verify_snapshot")
    S(snapshots, "materialize", "materialize"); S(execution, "materialize", "materialize")
    for mod in (snapshots, execution):
        orig = getattr(mod, "tree_snapshot_id")
        def mk(orig):
            def tsi(*a, **k):
                P.tree_calls += 1
                return orig(*a, **k)
            return tsi
        setattr(mod, "tree_snapshot_id", mk(orig))
        S(mod, "tree_snapshot_id", "tree_hash")
    S(storage.CAS, "put", "cas_put"); S(storage.CAS, "get", "cas_get"); S(storage.CAS, "verify", "cas_verify")
    S(candidates, "check_policy", "policy_check"); S(controller, "enqueue", "queue_enqueue"); S(controller, "run_one", "worker_run_one")
    S(execution, "evaluate", "evaluate"); S(execution, "_run_limited", "test_subprocess"); S(execution, "validate_report", "report_validation")
    S(KeyStore, "sign", "sign"); S(evidence, "store_signed", "store_signed"); S(certificates, "certify", "certify")
    S(conformance, "export_bundle", "export_bundle"); S(trustpolicy, "verify_authorized", "independent_verify")
    # counters
    real_sha = hashlib.sha256
    stage_put = storage.CAS.put

    def put(self, data):
        d = real_sha(bytes(data)).hexdigest()  # probe with the uninstrumented hash so bytes_hashed is not double counted
        P.cnt["cas_put"]["cas_hits" if self._path(d).exists() else "cas_misses"] += 1
        return stage_put(self, data)
    storage.CAS.put = put
    hashlib.sha256 = lambda data=b"", **kw: (P.add("bytes_hashed", len(data)), CountedHash(real_sha(data)))[1]
    oo, bo, oio = os.open, builtins.open, io.open
    os.open = lambda *a, **k: (P.add("opens"), oo(*a, **k))[1]
    builtins.open = io.open = lambda *a, **k: (P.add("opens"), bo(*a, **k))[1]
    orc, owc = Path.read_bytes, Path.write_bytes
    Path.read_bytes = lambda self: (lambda d: (P.add("bytes_read", len(d)), d)[1])(orc(self))
    Path.write_bytes = lambda self, data: (P.add("bytes_written", len(data)), owc(self, data))[1]
    omk, och = Path.mkdir, os.chmod
    Path.mkdir = lambda self, *a, **k: (P.add("mkdirs"), omk(self, *a, **k))[1]
    os.chmod = lambda *a, **k: (P.add("chmods"), och(*a, **k))[1]
    # sqlite: acquire (connect + BEGIN IMMEDIATE), body, commit
    from contextlib import contextmanager
    def tx(self):
        conn = self.connect()
        t0 = time.perf_counter()
        conn.execute("BEGIN IMMEDIATE")
        t1 = time.perf_counter()
        P.add("sqlite_acquire_s", t1 - t0)
        try:
            yield conn
        except BaseException:
            conn.execute("ROLLBACK"); raise
        else:
            t2 = time.perf_counter()
            P.add("sqlite_body_s", t2 - t1)
            conn.execute("COMMIT")
            P.add("sqlite_commit_s", time.perf_counter() - t2)
        finally:
            conn.close()
    Database.tx = contextmanager(tx)


def make_project(root: Path, n_files: int) -> None:
    tests = max(2, min(400, n_files // 5))
    (root / "pkg").mkdir(parents=True)
    (root / "tests").mkdir()
    (root / "pkg" / "__init__.py").write_text("")
    body = "".join(f"# filler line {j} to give the module a realistic size\n" for j in range(40))
    for i in range(n_files - tests - 1):
        d = root / "pkg" / f"d{i // 100}"
        d.mkdir(exist_ok=True)
        (d / f"m{i}.py").write_text(f"def f{i}(x):\n    return x + {i}\n{body}")
    for i in range(tests):
        (root / "tests" / f"test_t{i}.py").write_text(f"import unittest\n\n\nclass T(unittest.TestCase):\n    def test(self):\n        self.assertEqual({i} + 1, {i + 1})\n")


class TreeRss(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True); self.peak = 0.0; self.stop = False

    def run(self):
        me = os.getpid()
        while not self.stop:
            try:
                rows = [ln.split() for ln in subprocess.run(["ps", "-axo", "pid=,ppid=,rss="], capture_output=True, text=True).stdout.splitlines()]
                kids, tot = {me}, 0
                ch = True
                while ch:
                    ch = False
                    for pid, ppid, rss in rows:
                        if int(ppid) in kids and int(pid) not in kids:
                            kids.add(int(pid)); ch = True
                tot = sum(int(r[2]) for r in rows if int(r[0]) in kids)
                self.peak = max(self.peak, tot / 1024)
            except Exception:
                pass
            time.sleep(0.02)


def one_run(n_files: int, tmp: Path) -> dict:
    root = tmp / "p"
    make_project(root, n_files)
    ws = Workspace.init(root)
    KeyStore(ws).ensure()
    base = snapshots.take_snapshot(ws)
    pol = make_policy(ws, base, limits={"timeout_s": 600})
    obj = create_objective(ws, "o", "d", base.id, pol.id)
    budgets.create_account(ws, f"objective:{obj.id}", "objective", "1.00")
    (root / "pkg" / "new.py").write_text("def new():\n    return 1\n")
    P.reset()
    rss = TreeRss(); rss.start()
    t0, c0, r0 = time.perf_counter(), time.process_time(), resource.getrusage(resource.RUSAGE_CHILDREN)
    snap = snapshots.take_snapshot(ws)
    cid = candidates.register_candidate(ws, obj.id, snap.id, "profile").id
    controller.enqueue(ws, cid)
    out = controller.run_one(ws, controller.LocalToolWorker("prof", execution.TRUSTED_LOCAL_AUTH))
    assert out["candidate_status"] == "CERTIFIED", out
    cert = out["certificate_id"]
    with ws.db.read() as c:
        raw = bytes.fromhex(c.execute("SELECT public_key_hex FROM trusted_keys").fetchone()["public_key_hex"])
    bundle = conformance.export_bundle(ws, cert, version=2)
    pol_t = trustpolicy.make_policy("rp", [trustpolicy.issuer(raw)], ["vep-local-evaluator/*"], "TRUSTED_LOCAL", snapshot_id=snap.id)
    assert trustpolicy.verify_authorized(bundle, pol_t, "2099-01-01T00:00:00Z")["valid"]
    wall, cpu = time.perf_counter() - t0, time.process_time() - c0
    r1 = resource.getrusage(resource.RUSAGE_CHILDREN)
    rss.stop = True; rss.join(1)
    stages = {k: {"incl_s": round(P.incl[k], 5), "excl_s": round(P.excl[k], 5), "cpu_incl_s": round(P.cpu_incl[k], 5), "cpu_excl_s": round(P.cpu_excl[k], 5), "calls": P.calls[k]} for k in P.incl}
    counters = {k: {c: round(v, 5) for c, v in d.items()} for k, d in P.cnt.items()}
    child_cpu = (r1.ru_utime - r0.ru_utime) + (r1.ru_stime - r0.ru_stime)
    return {"wall_s": round(wall, 4), "parent_cpu_s": round(cpu, 4), "child_cpu_s": round(child_cpu, 4), "peak_tree_rss_mb": round(rss.peak, 1),
            "child_ru_inblock": r1.ru_inblock - r0.ru_inblock, "child_ru_oublock": r1.ru_oublock - r0.ru_oublock, "stages": stages, "counters": counters, "tree_hash_calls": P.tree_calls, "callers": {k: dict(v) for k, v in P.callers.items() if k in ("cas_verify", "cas_get", "cas_put", "verify_snapshot", "tree_hash", "read_files", "materialize")}}


def alloc_hotspots(n_files: int, tmp: Path) -> list:
    tracemalloc.start(8)
    root = tmp / "alloc"
    make_project(root, n_files)
    ws = Workspace.init(root); KeyStore(ws).ensure()
    snap = snapshots.take_snapshot(ws)
    ws.get_object(snap.id, "Snapshot")
    snapshots.verify_snapshot(ws, snap)
    d = tmp / "alloc-stage"
    snapshots.materialize(ws, snap, d)
    top = tracemalloc.take_snapshot().statistics("lineno")[:8]
    tracemalloc.stop()
    snapshots.make_writable(d)
    return [{"where": f"{Path(s.traceback[0].filename).name}:{s.traceback[0].lineno}", "kb": round(s.size / 1024, 1), "count": s.count} for s in top]


def startup_baseline() -> dict:
    xs = []
    for _ in range(15):
        t = time.perf_counter(); subprocess.run([sys.executable, "-I", "-c", "pass"]); xs.append(time.perf_counter() - t)
    return {"python_I_pass_median_ms": round(statistics.median(xs) * 1000, 1), "min_ms": round(min(xs) * 1000, 1)}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sizes", nargs="+", type=int, default=[100, 1000])
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--out", required=True)
    ap.add_argument("--no-alloc", action="store_true")
    a = ap.parse_args()
    install()
    doc = {"kind": "scale profile", "host": {"platform": platform.platform(), "cpus": os.cpu_count(), "python": platform.python_version()}, "package": versions.PACKAGE_VERSION,
           "load_avg_1m_at_start": os.getloadavg()[0], "runs_per_size": a.runs, "warmup_runs": 1, "interpreter_startup": startup_baseline(), "sizes": {}}
    for n in a.sizes:
        raw = []
        for i in range(a.runs + 1):
            tmp = Path(tempfile.mkdtemp(prefix="vep-scale-")).resolve()
            try:
                r = one_run(n, tmp); r["warmup"] = i == 0; raw.append(r)
                print(f"n={n} run {i}: wall={r['wall_s']}s child_cpu={r['child_cpu_s']}s rss={r['peak_tree_rss_mb']}MB", flush=True)
            finally:
                subprocess.run(["chmod", "-R", "u+w", str(tmp)]); shutil.rmtree(tmp, ignore_errors=True)
        kept = [r for r in raw if not r["warmup"]]
        med = lambda xs: round(statistics.median(xs), 5)
        names = sorted({k for r in kept for k in r["stages"]})
        doc["sizes"][str(n)] = {"files": n, "raw": raw,
            "summary": {"wall_s": {"median": med([r["wall_s"] for r in kept]), "min": min(r["wall_s"] for r in kept), "max": max(r["wall_s"] for r in kept)},
                        "child_cpu_s_median": med([r["child_cpu_s"] for r in kept]), "parent_cpu_s_median": med([r["parent_cpu_s"] for r in kept]), "peak_tree_rss_mb_median": med([r["peak_tree_rss_mb"] for r in kept]),
                        "stages_median": {k: {m: med([r["stages"].get(k, {}).get(m, 0) for r in kept]) for m in ("incl_s", "excl_s", "cpu_incl_s", "cpu_excl_s", "calls")} for k in names},
                        "callers_of_io_stages_run_median": {k: {p: med([r["callers"].get(k, {}).get(p, 0) for r in kept]) for p in sorted({p for r in kept for p in r["callers"].get(k, {})})}
                                                            for k in ("cas_verify", "cas_get", "cas_put", "verify_snapshot", "tree_hash", "read_files", "materialize")},
                        "counters_median_by_stage": {k: {c: med([r["counters"].get(k, {}).get(c, 0) for r in kept]) for c in COUNTERS if any(r["counters"].get(k, {}).get(c) for r in kept)}
                                                     for k in sorted({k for r in kept for k in r["counters"]})}}}
        if not a.no_alloc:
            tmp = Path(tempfile.mkdtemp(prefix="vep-alloc-")).resolve()
            try:
                doc["sizes"][str(n)]["allocation_hotspots_untimed"] = alloc_hotspots(n, tmp)
            finally:
                subprocess.run(["chmod", "-R", "u+w", str(tmp)]); shutil.rmtree(tmp, ignore_errors=True)
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
