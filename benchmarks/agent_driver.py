"""In-process driver for benchmarks/agent_workflow.py: runs a deterministic trace of agent steps against ONE long-lived VEP workspace (like an MCP server would)
and reports per-step timings. Honours VEP_PERF (flag set under test) and VEP_SRC. Not a user tool.

    agent_driver.py setup --ws DIR --tree DIR --project NAME
    agent_driver.py trace --ws DIR --system fresh|reuse|advisory --steps steps.json [--workers N]
"""
from __future__ import annotations

import argparse
import json
import multiprocessing as mp
import os
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, os.environ.get("VEP_SRC") or str(HERE.parent / "src"))
from vep import budgets, candidates, certificates, conformance, controller, execution, fastpath, snapshots, trustpolicy  # noqa: E402
from vep.evidence import KeyStore  # noqa: E402
from vep.objectives import create_objective  # noqa: E402
from vep.policies import make_policy  # noqa: E402
from vep.workspace import Workspace  # noqa: E402

PROJECTS = json.loads((HERE / "external" / "projects.json").read_text())
MARK: dict = {}


def mark_tests():
    orig = execution._run_limited

    def w(*a, **k):
        try:
            return orig(*a, **k)
        finally:
            MARK.setdefault("first_test_done", time.perf_counter())
    execution._run_limited = w


def setup(a):
    root = Path(a.ws); root.mkdir(parents=True)
    ws = Workspace.init(root); KeyStore(ws).ensure()
    base = snapshots.take_snapshot(ws, Path(a.tree))
    if a.project == "synthetic":
        spec = {"evaluator": {"kind": "unittest", "start_dir": "tests", "pattern": "test*.py", "import_roots": ["."], "min_tests": 2}}
    else:
        spec = PROJECTS[a.project]
    pol = make_policy(ws, base, name=a.project, evaluator=spec["evaluator"], limits={"timeout_s": 900}, required_exclude=[x["path"] for x in spec.get("required_exclude", [])])
    obj = create_objective(ws, "bench", "bench", base.id, pol.id)
    budgets.create_account(ws, f"objective:{obj.id}", "objective", "1000.00")
    (root / "bench.json").write_text(json.dumps({"objective": obj.id, "base_snapshot": base.id}))
    # the base tree's own evidence: a real session starts from verified source
    return 0


def policy_for(ws):
    return json.loads((ws.root / "bench.json").read_text())


def authorize(ws, cid, outcome, snapshot_id):
    """Independent authorized verification of whatever the fast path returned, Python implementation, against a relying-party policy."""
    with ws.db.read() as c:
        raw = bytes.fromhex(c.execute("SELECT public_key_hex FROM trusted_keys").fetchone()["public_key_hex"])
    pol = trustpolicy.make_policy("rp", [trustpolicy.issuer(raw)], ["vep-local-evaluator/*"], "TRUSTED_LOCAL", snapshot_id=snapshot_id)
    now = "2099-01-01T00:00:00Z"
    if outcome["outcome"] == "FRESH_CERTIFICATE":
        r = trustpolicy.verify_authorized(conformance.export_bundle(ws, outcome["certificate_id"], version=2), pol, now)
        return r["valid"] and r["assurance"] == "AUTHORIZED"
    if outcome["outcome"] == "DERIVED_ATTESTATION":
        from vep import reuse
        r = trustpolicy.verify_derived_authorized(reuse.export_bundle(ws, cid), pol, now)
        return r["valid"] and r["assurance"] == "AUTHORIZED_DERIVED"
    return None


def worker_proc(root, name, q):
    ws = Workspace(root)
    w = controller.LocalToolWorker(name, execution.TRUSTED_LOCAL_AUTH)
    ends = []
    while controller.run_one(ws, w) is not None:
        ends.append(time.time())
    q.put(ends)


def run_step(ws, st, system, workers, prev_snap):
    meta = policy_for(ws)
    out = {"label": st["label"], "kind": st["kind"], "expect": st.get("expect")}
    MARK.clear()
    t0 = time.perf_counter(); c0 = os.times()
    if st["kind"] == "verify":
        snap = snapshots.take_snapshot(ws, Path(st["tree"]))
        cid = candidates.register_candidate(ws, meta["objective"], snap.id, "agent").id
        fb = None
        if system == "advisory":
            adv = fastpath.verify(ws, cid, mode="advisory", root=Path(st["tree"]), previous_snapshot_id=prev_snap)
            fb = time.perf_counter() - t0
            out["advisory_pass"] = adv["advisory_pass"]
        res = fastpath.verify(ws, cid, mode="reuse_if_identical" if system == "reuse" else "fresh")
        end_verdict = time.perf_counter()
        auth = authorize(ws, cid, res, snap.id)
        end = time.perf_counter()
        out.update(outcome=res["outcome"], executed=res["executed"], certificate=bool(res.get("certificate_id")), authorized=auth,
                   feedback_s=fb if fb is not None else (MARK.get("first_test_done", end_verdict) - t0 if res["executed"] else end_verdict - t0),
                   verdict_s=end_verdict - t0, authorized_s=(end - t0) if auth else None, snapshot_id=snap.id)
        out["prev_snap"] = snap.id
    elif st["kind"] == "corrupt_then_verify":
        snap = snapshots.take_snapshot(ws, Path(st["tree"]))
        cid = candidates.register_candidate(ws, meta["objective"], snap.id, "agent").id
        digest = next(e["digest"] for e in snap["entries"] if e["path"] == st["corrupt_path"])
        p = ws.cas._path(digest); os.chmod(p, 0o644); data = p.read_bytes(); p.write_bytes(data[:-1] + (b"#" if data[-1:] != b"#" else b"@"))
        res = fastpath.verify(ws, cid, mode="fresh")
        end = time.perf_counter()
        out.update(outcome=res["outcome"], executed=res["executed"], certificate=bool(res.get("certificate_id")), authorized=None, feedback_s=end - t0, verdict_s=end - t0, authorized_s=None, snapshot_id=snap.id)
    elif st["kind"] == "cancel_retry":
        snap = snapshots.take_snapshot(ws, Path(st["tree"]))
        cid = candidates.register_candidate(ws, meta["objective"], snap.id, "agent").id
        job = controller.enqueue(ws, cid)
        controller.cancel(ws, job["id"])
        snap2 = snapshots.take_snapshot(ws, Path(st["tree"]))
        cid2 = candidates.register_candidate(ws, meta["objective"], snap2.id, "agent-retry").id
        res = fastpath.verify(ws, cid2, mode="reuse_if_identical" if system == "reuse" else "fresh")
        end_verdict = time.perf_counter()
        auth = authorize(ws, cid2, res, snap2.id)
        end = time.perf_counter()
        out.update(outcome=res["outcome"], executed=res["executed"], certificate=bool(res.get("certificate_id")), authorized=auth, feedback_s=end_verdict - t0, verdict_s=end_verdict - t0,
                   authorized_s=(end - t0) if auth else None, snapshot_id=snap2.id, cancelled_job_state=controller.get_job(ws, job["id"])["state"])
    elif st["kind"] == "batch":
        cids = []
        for tree in st["trees"]:
            snap = snapshots.take_snapshot(ws, Path(tree))
            cids.append(candidates.register_candidate(ws, meta["objective"], snap.id, "agent").id)
        for c in cids:
            controller.enqueue(ws, c)
        start_wall = time.time()
        if workers <= 1:
            w = controller.LocalToolWorker("w0", execution.TRUSTED_LOCAL_AUTH); ends = []
            while controller.run_one(ws, w) is not None:
                ends.append(time.time())
        else:
            ctx = mp.get_context("spawn"); q = ctx.Queue()
            ps = [ctx.Process(target=worker_proc, args=(str(ws.root), f"w{i}", q)) for i in range(workers)]
            [p.start() for p in ps]
            ends = sorted(sum((q.get() for _ in ps), []))
            [p.join() for p in ps]
        with ws.db.read() as c:
            certs = c.execute("SELECT COUNT(*) n FROM certificates").fetchone()["n"]
        lat = sorted(e - start_wall for e in ends)
        out.update(outcome="FRESH_CERTIFICATE" if certs >= len(cids) else "FAILED", executed=True, certificate=certs >= len(cids), authorized=None, candidates=len(cids), certified=certs,
                   feedback_s=lat[0] if lat else None, verdict_s=lat[-1] if lat else None, authorized_s=None, p95_latency_s=lat[min(len(lat) - 1, int(0.95 * len(lat)))] if lat else None,
                   jobs_per_s=len(lat) / lat[-1] if lat else 0)
    else:
        raise ValueError(st["kind"])
    c1 = os.times()
    out["cpu_s"] = (c1.user - c0.user) + (c1.system - c0.system) + (c1.children_user - c0.children_user) + (c1.children_system - c0.children_system)
    out["wall_s"] = time.perf_counter() - t0
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("mode"); ap.add_argument("--ws", required=True); ap.add_argument("--tree"); ap.add_argument("--project"); ap.add_argument("--system", default="fresh")
    ap.add_argument("--steps"); ap.add_argument("--workers", type=int, default=1)
    a = ap.parse_args()
    if a.mode == "setup":
        return setup(a)
    ws = Workspace(a.ws)
    mark_tests()
    steps = json.loads(Path(a.steps).read_text())
    prev = policy_for(ws)["base_snapshot"]
    res = []
    for st in steps:
        r = run_step(ws, st, a.system, a.workers, prev)
        prev = r.pop("prev_snap", prev)
        res.append(r)
    print(json.dumps({"steps": res, "peak_rss_children_mb": __import__("resource").getrusage(__import__("resource").RUSAGE_CHILDREN).ru_maxrss / (1e6 if sys.platform == "darwin" else 1024)}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
