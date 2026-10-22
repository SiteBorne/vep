"""Stage profile of VEP's real execution path on a deterministic synthetic project (no network, no model).

    python benchmarks/profile_stages.py --files 200 --runs 7 --out benchmarks/results/stage-profile.json

Wraps the real functions with wall-clock timers (inclusive times; nested stages overlap on purpose and are labelled), then runs the complete
workflow `enqueue -> controller.run_one` (policy check, budget, staging, protected test run, signing, certification) `runs` times on fresh
workspaces. Also measures exact-input evidence reuse (derive + verify) against the full evaluation it replaces. Reports medians and the observed
spread; this is a profile for choosing what to optimise, not a benchmark claim.
"""
from __future__ import annotations

import argparse
import json
import platform
import shutil
import statistics
import sys
import tempfile
import time
from collections import defaultdict
from pathlib import Path

import os  # noqa: E402
sys.path.insert(0, os.environ.get("VEP_SRC") or str(Path(__file__).resolve().parents[1] / "src"))
from vep import budgets, candidates, certificates, controller, execution, snapshots, storage, trustpolicy, versions  # noqa: E402
try:
    from vep import reuse  # noqa: E402
except ImportError:  # a pre-reuse source tree (used for before/after comparisons)
    reuse = None
from vep.database import Database  # noqa: E402
from vep.evidence import KeyStore  # noqa: E402
from vep.objectives import create_objective  # noqa: E402
from vep.policies import make_policy  # noqa: E402
from vep.workspace import Workspace  # noqa: E402

TOTALS: dict[str, float] = defaultdict(float)
COUNTS: dict[str, int] = defaultdict(int)


def timed(owner, name, stage):
    orig = getattr(owner, name)

    def wrapper(*a, **k):
        t = time.perf_counter()
        try:
            return orig(*a, **k)
        finally:
            TOTALS[stage] += time.perf_counter() - t
            COUNTS[stage] += 1
    setattr(owner, name, wrapper)


def install():
    from contextlib import contextmanager
    otx, oread = Database.tx, Database.read

    @contextmanager
    def tx(self):
        t = time.perf_counter()
        with otx(self) as c:
            TOTALS["sqlite_write_tx (incl. lock wait + body)"] += 0  # body time is attributed below
            t_body = time.perf_counter()
            yield c
        TOTALS["sqlite_write_tx (incl. lock wait + body)"] += time.perf_counter() - t
        COUNTS["sqlite_write_tx (incl. lock wait + body)"] += 1
    Database.tx = tx
    timed(snapshots, "take_snapshot", "snapshot_construction (scan+hash+CAS put)")
    timed(storage.CAS, "put", "cas_put (inclusive; nested in snapshot/evidence)")
    timed(execution, "materialize", "staging_materialize")
    timed(execution, "_run_limited", "protected_test_run (subprocess incl. worker startup)")
    timed(KeyStore, "sign", "signing")
    timed(candidates, "check_policy", "policy_validation")
    timed(certificates, "certify", "certification (inclusive of signing)")
    timed(execution, "evaluate", "evaluate_total (inclusive)")
    timed(execution, "tree_snapshot_id", "staged_tree_hash_checks (before+after run)")
    timed(execution, "verify_snapshot", "snapshot_blob_verification")


def make_project(root: Path, files: int) -> None:
    (root / "pkg").mkdir(parents=True)
    (root / "tests").mkdir()
    for i in range(files):
        (root / "pkg" / f"m{i}.py").write_text(f"def f{i}(x):\n    return x + {i}\n" + "# filler\n" * 20)
        (root / "tests" / f"test_m{i}.py").write_text(f"import unittest\nfrom pkg.m{i} import f{i}\n\n\nclass T(unittest.TestCase):\n    def test(self):\n        self.assertEqual(f{i}(1), {i + 1})\n")
    (root / "pkg" / "__init__.py").write_text("")


def one_run(tmp: Path, files: int) -> dict:
    root = tmp / "p"
    make_project(root, files)
    ws = Workspace.init(root)
    KeyStore(ws).ensure()
    base = snapshots.take_snapshot(ws)
    pol = make_policy(ws, base, limits={"timeout_s": 120})
    obj = create_objective(ws, "o", "d", base.id, pol.id)
    budgets.create_account(ws, f"objective:{obj.id}", "objective", "1.00")
    (root / "pkg" / "new.py").write_text("def new():\n    return 1\n")
    TOTALS.clear(); COUNTS.clear()
    t = time.perf_counter()
    snap = snapshots.take_snapshot(ws)
    cid = candidates.register_candidate(ws, obj.id, snap.id, "profile").id
    controller.enqueue(ws, cid)
    out = controller.run_one(ws, controller.LocalToolWorker("prof", execution.TRUSTED_LOCAL_AUTH))
    full = time.perf_counter() - t
    assert out["candidate_status"] == "CERTIFIED", out
    stages = {k: round(v * 1000, 1) for k, v in TOTALS.items()}
    if reuse is None:
        return {"full_workflow_ms": round(full * 1000, 1), "stages_ms": stages, "counts": dict(COUNTS), "reuse_derive_export_verify_ms": 0.0}
    # reuse: a second candidate with the identical tree
    snap2 = snapshots.take_snapshot(ws)
    cid2 = candidates.register_candidate(ws, obj.id, snap2.id, "second").id
    t = time.perf_counter()
    reuse.derive(ws, cid2)
    bundle = reuse.export_bundle(ws, cid2)
    with ws.db.read() as c:
        raw = bytes.fromhex(c.execute("SELECT public_key_hex FROM trusted_keys").fetchone()["public_key_hex"])
    pol_t = trustpolicy.make_policy("rp", [trustpolicy.issuer(raw)], ["vep-local-evaluator/*"], "TRUSTED_LOCAL", snapshot_id=snap2.id)
    ok = trustpolicy.verify_derived_authorized(bundle, pol_t, "2099-01-01T00:00:00Z")["valid"]
    reuse_s = time.perf_counter() - t
    assert ok
    return {"full_workflow_ms": round(full * 1000, 1), "stages_ms": stages, "counts": dict(COUNTS), "reuse_derive_export_verify_ms": round(reuse_s * 1000, 1)}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--files", type=int, default=200)
    ap.add_argument("--runs", type=int, default=7)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    install()
    runs = []
    for i in range(a.runs + 1):  # first run is a warmup and is recorded but not analysed
        tmp = Path(tempfile.mkdtemp(prefix="vep-prof-")).resolve()
        try:
            r = one_run(tmp, a.files)
            r["warmup"] = i == 0
            runs.append(r)
            print(f"run {i}: full={r['full_workflow_ms']}ms reuse={r['reuse_derive_export_verify_ms']}ms")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    kept = [r for r in runs if not r["warmup"]]
    keys = sorted({k for r in kept for k in r["stages_ms"]})
    med = lambda xs: round(statistics.median(xs), 1)
    summary = {
        "full_workflow_ms": {"median": med([r["full_workflow_ms"] for r in kept]), "min": min(r["full_workflow_ms"] for r in kept), "max": max(r["full_workflow_ms"] for r in kept)},
        "stages_median_ms": {k: med([r["stages_ms"].get(k, 0) for r in kept]) for k in keys},
        "reuse_derive_export_verify_ms": {"median": med([r["reuse_derive_export_verify_ms"] for r in kept]), "min": min(r["reuse_derive_export_verify_ms"] for r in kept), "max": max(r["reuse_derive_export_verify_ms"] for r in kept)}}
    doc = {"kind": "stage profile (inclusive wall times; stages overlap)", "project": {"files": a.files * 2 + 2, "tests": a.files}, "runs": a.runs, "warmup_runs": 1,
           "host": {"platform": platform.platform(), "python": platform.python_version()}, "package": versions.PACKAGE_VERSION, "summary": summary, "raw": runs}
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n")
    print(json.dumps(summary, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
