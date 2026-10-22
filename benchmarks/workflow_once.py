"""One timed execution of VEP's protected workflow on a generated project (called by benchmarks/ab_runner.py; setup is outside the timed region).

    VEP_PERF=<flags> python benchmarks/workflow_once.py --n 1000 --root <empty dir>

Timed region: take_snapshot -> register -> enqueue -> run_one (policy check, budget, staging, protected test run, signing, certification) -> export v2 bundle ->
independent authorized verification (Python). Prints one JSON line; exits non-zero (and prints the reason) if the result is not a certified, authorized-verified candidate.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, os.environ.get("VEP_SRC") or str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from profile_scale import make_project  # noqa: E402
from vep import budgets, candidates, conformance, controller, execution, snapshots, trustpolicy  # noqa: E402
from vep.evidence import KeyStore  # noqa: E402
from vep.objectives import create_objective  # noqa: E402
from vep.policies import make_policy  # noqa: E402
from vep.workspace import Workspace  # noqa: E402

T = {"materialize": 0.0, "evaluate": 0.0}


def timed(owner, attr, key):
    orig = getattr(owner, attr)

    def w(*a, **k):
        t = time.perf_counter()
        try:
            return orig(*a, **k)
        finally:
            T[key] += time.perf_counter() - t
    setattr(owner, attr, w)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, required=True)
    ap.add_argument("--root", required=True)
    ap.add_argument("--change", default="new", choices=["new", "none"], help="'none': register the identical tree again (same-source re-verification)")
    a = ap.parse_args()
    root = Path(a.root)
    make_project(root, a.n)
    ws = Workspace.init(root)
    KeyStore(ws).ensure()
    base = snapshots.take_snapshot(ws)
    pol = make_policy(ws, base, limits={"timeout_s": 600})
    obj = create_objective(ws, "o", "d", base.id, pol.id)
    budgets.create_account(ws, f"objective:{obj.id}", "objective", "1.00")
    if a.change == "new":
        (root / "pkg" / "new.py").write_text("def new():\n    return 1\n")
    timed(execution, "materialize", "materialize"); timed(execution, "evaluate", "evaluate")
    t0, c0 = time.perf_counter(), os.times()
    snap = snapshots.take_snapshot(ws)
    cid = candidates.register_candidate(ws, obj.id, snap.id, "bench").id
    controller.enqueue(ws, cid)
    out = controller.run_one(ws, controller.LocalToolWorker("bench", execution.TRUSTED_LOCAL_AUTH))
    if out.get("candidate_status") != "CERTIFIED":
        print(json.dumps({"error": "not certified", "out": str(out)[:300]})); return 2
    with ws.db.read() as c:
        raw = bytes.fromhex(c.execute("SELECT public_key_hex FROM trusted_keys").fetchone()["public_key_hex"])
    bundle = conformance.export_bundle(ws, out["certificate_id"], version=2)
    pol_t = trustpolicy.make_policy("rp", [trustpolicy.issuer(raw)], ["vep-local-evaluator/*"], "TRUSTED_LOCAL", snapshot_id=snap.id)
    r = trustpolicy.verify_authorized(bundle, pol_t, "2099-01-01T00:00:00Z")
    wall, c1 = time.perf_counter() - t0, os.times()
    if not r["valid"] or r["assurance"] != "AUTHORIZED":
        print(json.dumps({"error": "bundle not authorized", "r": r})); return 3
    cpu = (c1.user - c0.user) + (c1.system - c0.system) + (c1.children_user - c0.children_user) + (c1.children_system - c0.children_system)
    try:
        from vep import perf as _perf
        stats = dict(_perf.STATS)
    except ImportError:  # the pristine control tree has no perf module
        stats = None
    print(json.dumps({"activation": stats, "wall_s": wall, "cpu_s": cpu, "materialize_s": T["materialize"], "evaluate_s": T["evaluate"], "certificate_id": out["certificate_id"], "snapshot_id": snap.id}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
