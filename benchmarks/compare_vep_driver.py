"""Child-process driver for benchmarks/compare.py (so VEP's own start-up cost is included, like a CLI call).

modes:
  setup  --ws DIR --tree DIR --project NAME    create workspace, key, base snapshot, policy, objective, budget
  single --ws DIR --tree DIR                   snapshot tree, register, enqueue, evaluate, certify with one worker
  batch  --ws DIR --trees D1 D2 ... --workers N
  buildcache --ws DIR --tree DIR --project NAME   run the test suite as a cached, deterministic BuildAction
"""
from __future__ import annotations

import argparse
import json
import multiprocessing as mp
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from vep import budgets, builds, candidates, controller, execution, snapshots  # noqa: E402
from vep.evidence import KeyStore  # noqa: E402
from vep.objectives import create_objective  # noqa: E402
from vep.policies import make_policy  # noqa: E402
from vep.workspace import Workspace  # noqa: E402

PROJECTS = json.loads((REPO / "benchmarks" / "external" / "projects.json").read_text())

TEST_ACTION = (
    "import io,json,sys,unittest\n"
    "s=unittest.defaultTestLoader.discover({start!r},pattern={pat!r},top_level_dir='.')\n"
    "r=unittest.TextTestRunner(stream=io.StringIO()).run(s)\n"
    "open('result.json','w').write(json.dumps({{'run':r.testsRun,'bad':len(r.failures)+len(r.errors)}}))\n"
    "sys.exit(0 if r.wasSuccessful() else 1)\n")


def worker_proc(root: str, name: str, q) -> None:
    ws = Workspace(root)
    w = controller.LocalToolWorker(name, execution.TRUSTED_LOCAL_AUTH)
    n = 0
    while controller.run_one(ws, w) is not None:
        n += 1
    q.put(n)


def objective_of(ws: Workspace) -> str:
    return json.loads((ws.root / "bench.json").read_text())["objective"]


def add(ws: Workspace, tree: str) -> str:
    snap = snapshots.take_snapshot(ws, Path(tree))
    cid = candidates.register_candidate(ws, objective_of(ws), snap.id, "bench").id
    controller.enqueue(ws, cid)
    return cid


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("mode")
    ap.add_argument("--ws", required=True)
    ap.add_argument("--tree")
    ap.add_argument("--trees", nargs="*", default=[])
    ap.add_argument("--project")
    ap.add_argument("--workers", type=int, default=1)
    a = ap.parse_args()
    if a.mode == "setup":
        root = Path(a.ws)
        root.mkdir(parents=True)
        ws = Workspace.init(root)
        KeyStore(ws).ensure()
        base = snapshots.take_snapshot(ws, Path(a.tree))
        spec = PROJECTS[a.project]
        pol = make_policy(ws, base, name=a.project, evaluator=spec["evaluator"], limits={"timeout_s": 900},
                          required_exclude=[x["path"] for x in spec.get("required_exclude", [])])
        obj = create_objective(ws, "bench", "bench", base.id, pol.id)
        budgets.create_account(ws, f"objective:{obj.id}", "objective", "100.00")
        (root / "bench.json").write_text(json.dumps({"objective": obj.id}))
        return 0
    ws = Workspace(a.ws)
    if a.mode == "single":
        cid = add(ws, a.tree)
        r = controller.run_one(ws, controller.LocalToolWorker("bench", execution.TRUSTED_LOCAL_AUTH))
        print(json.dumps({"status": r["candidate_status"], "certified": r["candidate_status"] == "CERTIFIED"}))
        return 0 if r["candidate_status"] == "CERTIFIED" else 3
    if a.mode == "batch":
        for t in a.trees:
            add(ws, t)
        if a.workers <= 1:
            n = 0
            w = controller.LocalToolWorker("bench", execution.TRUSTED_LOCAL_AUTH)
            while controller.run_one(ws, w) is not None:
                n += 1
        else:
            ctx = mp.get_context("spawn")
            q = ctx.Queue()
            ps = [ctx.Process(target=worker_proc, args=(a.ws, f"w{i}", q)) for i in range(a.workers)]
            for p in ps:
                p.start()
            n = sum(q.get() for _ in ps)
            for p in ps:
                p.join()
        with ws.db.read() as c:
            cert = c.execute("SELECT COUNT(*) n FROM certificates").fetchone()["n"]
        print(json.dumps({"ran": n, "certified": cert}))
        return 0 if cert == len(a.trees) else 3
    if a.mode == "buildcache":
        spec = PROJECTS[a.project]["evaluator"]
        snap = snapshots.take_snapshot(ws, Path(a.tree))
        act = builds.BuildAction(("{python}", "-I", "-c", TEST_ACTION.format(start=spec["start_dir"], pat=spec["pattern"])),
                                 snap.id, outputs=("result.json",), timeout_s=900)
        r = builds.run(ws, act)
        print(json.dumps({"cache": r["cache"], "failure": r["failure"]}))
        return 0 if r["failure"] is None else 3
    return 2


if __name__ == "__main__":
    sys.exit(main())
