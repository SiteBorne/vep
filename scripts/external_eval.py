"""Evaluate an external open-source project (read-only clone at a pinned commit) through VEP, trusted-local.

    python scripts/external_eval.py --project pyflakes --src <clone dir> --report out.json

Per project: record the pinned revision and license; run the project's own tests directly (no VEP) as a
reference; freeze a policy from the upstream tests; then evaluate three candidates through the durable controller:
  upstream  - the unmodified revision                      (expected CERTIFIED)
  benign    - upstream plus one new passing test file      (expected CERTIFIED)
  mutant    - upstream with one logic inversion in source  (expected REJECTED; a surviving mutant is reported, not hidden)
then verify the upstream certificate (live tree, Python and Node bundle) and show a post-certification edit invalidates it.
Nothing is pushed anywhere; the clone is only read. The project's tests run as the invoking user (NO isolation).
Run with an interpreter that has `cryptography` (see scripts/dogfood.py for why `vep` must not be installed in it).
"""
from __future__ import annotations

import argparse
import json
import platform
import resource
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from vep import (budgets, candidates, certificates, conformance, controller, execution, snapshots, versions)  # noqa: E402
from vep.errors import VerificationFailed  # noqa: E402
from vep.evidence import KeyStore  # noqa: E402
from vep.objectives import create_objective  # noqa: E402
from vep.policies import make_policy  # noqa: E402
from vep.workspace import Workspace  # noqa: E402


def git(d: Path, *a: str) -> str:
    return subprocess.run(["git", "-C", str(d), *a], check=True, capture_output=True, text=True).stdout.strip()


def timed(fn):
    r0, t0 = resource.getrusage(resource.RUSAGE_CHILDREN), time.perf_counter()
    out = fn()
    r1 = resource.getrusage(resource.RUSAGE_CHILDREN)
    return out, {"wall_s": round(time.perf_counter() - t0, 3),
                 "child_cpu_s": round((r1.ru_utime - r0.ru_utime) + (r1.ru_stime - r0.ru_stime), 3)}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--project", required=True)
    ap.add_argument("--src", required=True)
    ap.add_argument("--report", required=True)
    ap.add_argument("--projects", default=str(REPO / "benchmarks" / "external" / "projects.json"))
    a = ap.parse_args()
    spec = json.loads(Path(a.projects).read_text())[a.project]
    src = Path(a.src).resolve()
    head = git(src, "rev-parse", "HEAD")
    if head != spec["commit"] or git(src, "status", "--porcelain", "--untracked-files=no"):
        print(f"refusing: {src} is not a clean checkout of {spec['commit']} (HEAD {head})", file=sys.stderr)
        return 2
    lic = next((p for p in sorted(src.glob("LICEN[CS]E*"))), None)
    work = Path(tempfile.mkdtemp(prefix=f"vep-ext-{a.project}-"))
    report: dict = {"report_version": 1, "kind": "external project through VEP", "classification": "LOCALLY_VERIFIED (trusted-local, one host)",
                    "project": {"name": a.project, "url": spec["url"], "tag": spec["tag"], "commit": head, "license": spec["license"],
                                "license_file": lic.name if lic else None, "kind": spec["kind"]},
                    "tool": {"vep_commit": git(REPO, "rev-parse", "HEAD"), "package": versions.PACKAGE_VERSION,
                             "python": platform.python_version(), "platform": platform.platform()},
                    "limits": ["project tests ran as the invoking user with NO isolation (explicitly authorized for these vetted projects)",
                               "no changes were pushed to the project; candidates are local and disposable",
                               "one host, one run per candidate: no statistical claim"]}
    try:
        # reference run without VEP (same interpreter, same tree)
        direct, dcost = timed(lambda: subprocess.run([sys.executable, *spec["direct_cmd"]], cwd=src, capture_output=True, text=True))
        tail = [l for l in direct.stderr.splitlines() if l.startswith(("Ran ", "OK", "FAILED"))]
        report["direct_reference"] = {"command": "python " + " ".join(spec["direct_cmd"]), "returncode": direct.returncode,
                                      "summary": tail, **dcost}
        tree = work / "upstream"
        shutil.copytree(src, tree, ignore=shutil.ignore_patterns(".git"))
        ws_root = work / "ws"
        ws_root.mkdir()
        ws = Workspace.init(ws_root)
        KeyStore(ws).ensure()
        base = snapshots.take_snapshot(ws, tree)
        policy = make_policy(ws, base, name=a.project, evaluator=spec["evaluator"], limits={"timeout_s": 900})
        obj = create_objective(ws, f"{a.project} verification", "evaluate pinned upstream revision and local variants", base.id, policy.id)
        budgets.create_account(ws, f"objective:{obj.id}", "objective", "1.00")
        report["baseline"] = {"snapshot_id": base.id, "policy_id": policy.id, "required_test_files": len(policy["required_tests"]),
                              "files_in_snapshot": len(snapshots.entries_of(base)), "min_passing_tests": spec["evaluator"]["min_tests"]}

        def variant(name: str, edit):
            d = work / name
            shutil.copytree(tree, d)
            edit(d)
            return snapshots.take_snapshot(ws, d)

        def add_benign(d: Path):
            p = d / spec["benign"]["path"]
            p.write_text(spec["benign"]["content"])

        def mutate(d: Path):
            p = d / spec["mutant"]["path"]
            text = p.read_text()
            assert spec["mutant"]["old"] in text, "mutation site not found"
            p.write_text(text.replace(spec["mutant"]["old"], spec["mutant"]["new"], 1))

        cands = {"upstream": base, "benign": variant("benign", add_benign), "mutant": variant("mutant", mutate)}
        report["candidates"] = {}
        ids = {}
        for name, snap in cands.items():
            ids[name] = candidates.register_candidate(ws, obj.id, snap.id, f"external-eval:{name}").id
        for name in ("upstream", "benign", "mutant"):
            controller.enqueue(ws, ids[name])
            res, cost = timed(lambda: controller.run_one(ws, controller.LocalToolWorker(f"ext-{name}", execution.TRUSTED_LOCAL_AUTH)))
            ev = None
            with ws.db.read() as c:
                row = c.execute("SELECT id FROM evidence WHERE candidate_id=?", (ids[name],)).fetchone()
            if row:
                e = ws.get_object(row["id"], "Evidence")
                ev = {k: e[k] for k in ("tests_discovered", "tests_run", "tests_passed", "tests_failed", "tests_skipped")}
            report["candidates"][name] = {"candidate_id": ids[name], "snapshot_id": cands[name].id, "result": res, "tests": ev, "cost": cost}
        up = report["candidates"]["upstream"]["result"]
        report["verification"] = {"upstream_certified": up.get("candidate_status") == "CERTIFIED"}
        if report["verification"]["upstream_certified"]:
            cid = up["certificate_id"]
            v = certificates.verify_certificate(ws, cid, current_root=tree)
            bundle = conformance.export_bundle(ws, cid)
            bp = work / "bundle.json"
            bp.write_text(json.dumps(bundle))
            node = shutil.which("node")
            report["verification"].update({
                "live_tree_checks": v["checks_passed"], "bundle_python_reference": conformance.verify_bundle(bundle)["valid"],
                "bundle_node_independent": (json.loads(subprocess.run([node, str(REPO / "conformance/node/verify.mjs"), "bundle", str(bp)],
                                                                      capture_output=True, text=True).stdout)["valid"] if node else "NOT_RUN")})
            ch = work / "changed"
            shutil.copytree(tree, ch)
            tp = ch / spec["invalidate"]["path"]
            tp.write_text(tp.read_text() + "\n# edit after certification\n")
            try:
                certificates.verify_certificate(ws, cid, current_root=ch)
                report["verification"]["edited_tree_rejected"] = False
            except VerificationFailed as exc:
                report["verification"]["edited_tree_rejected"] = True
                report["verification"]["edited_tree_reason"] = str(exc)[:60]
        c = report["candidates"]
        report["outcome"] = {
            "upstream_certified": c["upstream"]["result"].get("candidate_status") == "CERTIFIED",
            "benign_certified": c["benign"]["result"].get("candidate_status") == "CERTIFIED",
            "mutant_rejected": c["mutant"]["result"].get("candidate_status") == "REJECTED",
            "edited_tree_rejected": report["verification"].get("edited_tree_rejected", False)}
        report["outcome"]["all_expected"] = all(report["outcome"].values())
    finally:
        shutil.rmtree(work, ignore_errors=True)
    Path(a.report).parent.mkdir(parents=True, exist_ok=True)
    Path(a.report).write_text(json.dumps(report, indent=1, sort_keys=True, default=str) + "\n")
    print(a.project, json.dumps(report["outcome"]))
    return 0 if report["outcome"]["all_expected"] else 1


if __name__ == "__main__":
    sys.exit(main())
