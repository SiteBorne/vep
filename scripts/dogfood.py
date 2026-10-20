"""Dogfood: run VEP's own lifecycle on a real change to VEP's own repository and write a machine-readable report.

    python scripts/dogfood.py --repo . --base-commit <sha> --candidate-commit <sha> --work <dir> \
        --report docs/dogfood/vep-on-vep-run-1.json [--require-count 300]

Run it with an interpreter that has `cryptography` but does NOT have `vep` installed: the evaluator runs
`sys.executable -I`, and an editable `vep` install would shadow the candidate's source and test the wrong code.
The script refuses to start if `vep` is importable from outside this repository's src/.

Steps: attach git worktrees at fixed commits; snapshot the base; freeze a policy (existing tests protected by
digest); create an objective with a budget; register the candidate (the tree at --candidate-commit);
run it through the durable controller (real full test suite, trusted-local); verify the certificate against the
live tree, as a portable bundle (Python reference and Node, if present); run a negative control (the candidate's
new tests against the BASE implementation must be rejected); then change the source and show the certificate and
evidence no longer apply.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import platform
import resource
import shutil
import subprocess
import sys
import time
from pathlib import Path

REPO_SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(REPO_SRC))

from vep import (budgets, candidates, certificates, conformance, controller, depgraph, execution, git_adapter,  # noqa: E402
                 snapshots, tokens, versions)
from vep.errors import VerificationFailed  # noqa: E402
from vep.evidence import KeyStore  # noqa: E402
from vep.objectives import create_objective  # noqa: E402
from vep.policies import make_policy  # noqa: E402
from vep.workspace import Workspace  # noqa: E402


def git(repo: Path, *a: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *a], check=True, capture_output=True, text=True).stdout.strip()


def timed(fn):
    r0, t0 = resource.getrusage(resource.RUSAGE_CHILDREN), time.perf_counter()
    out = fn()
    r1 = resource.getrusage(resource.RUSAGE_CHILDREN)
    return out, {"wall_s": round(time.perf_counter() - t0, 3),
                 "child_cpu_s": round((r1.ru_utime - r0.ru_utime) + (r1.ru_stime - r0.ru_stime), 3),
                 "peak_child_rss_mb": round(r1.ru_maxrss / (1e6 if sys.platform == "darwin" else 1024), 1)}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True)
    ap.add_argument("--base-commit", required=True)
    ap.add_argument("--candidate-commit", required=True)
    ap.add_argument("--work", required=True)
    ap.add_argument("--report", required=True)
    ap.add_argument("--require-count", type=int, default=300, help="minimum passing tests the policy demands")
    ap.add_argument("--timeout", type=int, default=900)
    a = ap.parse_args()
    repo, work = Path(a.repo).resolve(), Path(a.work).resolve()
    spec = importlib.util.find_spec("vep")
    if spec is None or Path(spec.origin).resolve().parent.parent != REPO_SRC.resolve():
        print("refusing: `vep` resolves outside this repo's src; run with an interpreter without an editable vep", file=sys.stderr)
        return 2
    try:
        subprocess.run([sys.executable, "-I", "-c", "import vep"], check=True, capture_output=True)
        print("refusing: `vep` is importable under `python -I`; the evaluator would test the wrong code", file=sys.stderr)
        return 2
    except subprocess.CalledProcessError:
        pass
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)
    base_dir, cand_dir, ctrl_dir = work / "base", work / "candidate", work / "control"
    git(repo, "worktree", "add", "--detach", "-f", str(base_dir), a.base_commit)
    git(repo, "worktree", "add", "--detach", "-f", str(cand_dir), a.candidate_commit)
    report: dict = {"report_version": 1, "kind": "vep-on-vep dogfood", "classification": "LOCALLY_VERIFIED (trusted-local, one host)"}
    try:
        report["subject"] = {"repository": "VEP (this repository)", "base_commit": git(repo, "rev-parse", a.base_commit),
                             "candidate_commit": git(repo, "rev-parse", a.candidate_commit),
                             "candidate_subject": git(repo, "log", "-1", "--format=%s", a.candidate_commit),
                             "candidate_author_note": "change written by Claude Code in an interactive session; not an autonomous-agent run",
                             "license": "Apache-2.0"}
        report["tool"] = {"package": versions.PACKAGE_VERSION, "protocol": versions.PROTOCOL_VERSION,
                          "db_schema": versions.DB_SCHEMA_VERSION, "python": platform.python_version(),
                          "platform": platform.platform(), "evaluator_python": "<evaluator venv>/bin/" + Path(sys.executable).name,
                          "tool_commit": git(REPO_SRC.parent, "rev-parse", "HEAD"),
                          "tool_tree_dirty": bool(git(REPO_SRC.parent, "status", "--porcelain", "--untracked-files=no"))}
        ws_root = work / "vep-workspace"
        ws_root.mkdir()
        ws = Workspace.init(ws_root)
        KeyStore(ws).ensure()
        base = snapshots.take_snapshot(ws, base_dir)
        git_adapter.associate(ws, base.id, base_dir)
        policy = make_policy(ws, base, name="vep-on-vep", evaluator={
            "kind": "unittest", "start_dir": "tests", "pattern": "test*.py", "import_roots": ["src", "."],
            "min_tests": a.require_count, "allow_module_names": ["vep"]}, limits={"timeout_s": a.timeout})
        obj = create_objective(ws, "vep build CLI", "Expose build actions through `vep build run|stats` with an authorization gate and tests.",
                               base.id, policy.id, created_by="dogfood")
        budgets.create_account(ws, f"objective:{obj.id}", "objective", "1.00")
        report["baseline"] = {"base_snapshot_id": base.id, "policy_id": policy.id, "objective_id": obj.id,
                              "required_test_files": len(policy["required_tests"]), "min_passing_tests": a.require_count,
                              "protected_patterns": policy["protected_patterns"]}

        cand_snap = snapshots.take_snapshot(ws, cand_dir)
        git_adapter.associate(ws, cand_snap.id, cand_dir)
        d = snapshots.diff(base, cand_snap)
        cid = candidates.register_candidate(ws, obj.id, cand_snap.id, "claude-code").id
        report["candidate"] = {"candidate_id": cid, "snapshot_id": cand_snap.id, "diff": d}
        graph = depgraph.build_graph(ws, base.id)
        report["impact_hint"] = depgraph.impact(ws, graph, base.id, cand_snap.id)

        # ---- negative control: the new tests against the BASE implementation must be rejected
        shutil.copytree(cand_dir, ctrl_dir, ignore=shutil.ignore_patterns(".git"))
        for p in d["modified"]:
            if p.startswith("src/"):
                (ctrl_dir / p).write_text(git(repo, "show", f"{a.base_commit}:{p}") + "\n")
        ctrl_snap = snapshots.take_snapshot(ws, ctrl_dir)
        ctrl_id = candidates.register_candidate(ws, obj.id, ctrl_snap.id, "control").id
        controller.enqueue(ws, ctrl_id)
        ctrl, ctrl_cost = timed(lambda: controller.run_one(ws, controller.LocalToolWorker("dogfood-control", execution.TRUSTED_LOCAL_AUTH)))
        report["negative_control"] = {"description": "candidate's new tests with the base implementation of src files",
                                      "candidate_id": ctrl_id, "result": ctrl, "cost": ctrl_cost,
                                      "expected": "REJECTED", "as_expected": ctrl.get("candidate_status") == "REJECTED"}

        # ---- the real run through the durable controller
        controller.enqueue(ws, cid)
        run, cost = timed(lambda: controller.run_one(ws, controller.LocalToolWorker("dogfood-worker", execution.TRUSTED_LOCAL_AUTH)))
        job = controller.get_job(ws, run["job"])
        with ws.db.read() as c:
            ev = c.execute("SELECT id FROM evidence WHERE candidate_id=?", (cid,)).fetchone()
        evidence = ws.get_object(ev["id"], "Evidence") if ev else None
        report["run"] = {"controller_result": run, "job": {k: job[k] for k in ("id", "state", "attempts", "fence", "mode", "failure_class")},
                         "cost": cost, "budget": budgets.report(ws, f"objective:{obj.id}"),
                         "tests": None if evidence is None else {k: evidence[k] for k in ("tests_discovered", "tests_run", "tests_passed",
                                                                                          "tests_failed", "tests_skipped")},
                         "evidence_trust_level": None if evidence is None else evidence["trust_level"],
                         "token_usage": tokens.usage_report(ws, cid)["by_source"],
                         "note": "no model tokens were used by the evaluation; CPU/wall are measured, not monetized"}
        certified = run.get("candidate_status") == "CERTIFIED"
        report["verification"] = {"certified": certified}
        if certified:
            cert_id = run["certificate_id"]
            v_live = certificates.verify_certificate(ws, cert_id, current_root=cand_dir)
            v_hist = certificates.verify_certificate(ws, cert_id)
            bundle = conformance.export_bundle(ws, cert_id)
            bundle_path = work / "bundle.json"
            bundle_path.write_text(json.dumps(bundle, indent=1, sort_keys=True))
            node = shutil.which("node")
            node_res = None
            if node:
                r = subprocess.run([node, str(REPO_SRC.parent / "conformance" / "node" / "verify.mjs"), "bundle", str(bundle_path)],
                                   capture_output=True, text=True)
                node_res = json.loads(r.stdout)
            report["verification"].update({
                "current_source_check": v_live["checks_passed"], "historical_check": v_hist["checks_passed"],
                "bundle_python_reference": conformance.verify_bundle(bundle),
                "bundle_node_independent": node_res if node else "NOT_RUN (node missing)",
                "certificate_id": cert_id, "certified_snapshot_id": cand_snap.id})
            # ---- invalidation: change a source file after certification
            changed_dir = work / "changed"
            shutil.copytree(cand_dir, changed_dir, ignore=shutil.ignore_patterns(".git"))
            target = changed_dir / "src" / "vep" / "versions.py"
            target.write_text(target.read_text() + "\n# post-certification edit\n")
            changed_snap = snapshots.take_snapshot(ws, changed_dir)
            try:
                certificates.verify_certificate(ws, cert_id, current_root=changed_dir)
                stale_detected = None
            except VerificationFailed as exc:
                stale_detected = str(exc)[:160]
            ev_check = depgraph.evidence_validity(ws, evidence.id, snapshot_id=changed_snap.id, policy_id=policy.id)
            report["invalidation"] = {
                "edit": "appended a comment to src/vep/versions.py", "changed_snapshot_id": changed_snap.id,
                "certificate_rejected_for_changed_tree": stale_detected is not None, "reason": stale_detected,
                "evidence_reusable_for_changed_tree": ev_check["valid"], "evidence_reasons": ev_check["reasons"],
                "static_impact": depgraph.impact(ws, graph, cand_snap.id, changed_snap.id)["affected_by_static_analysis"][:12],
                "required_evaluation_after_change": "FULL"}
        ok = (certified and report["negative_control"]["as_expected"] and report["invalidation"]["certificate_rejected_for_changed_tree"]
              and report["verification"]["bundle_python_reference"]["valid"])
        report["outcome"] = "DOGFOOD_PASS" if ok else "DOGFOOD_FAIL"
        report["limits"] = ["trusted-local execution: no isolation; the evaluator ran this repository's own tests as the invoking user",
                            "tests that need tools absent from the scrubbed PATH (for example node) are skipped by the evaluator and counted as skipped",
                            "one change, one host, one run: no statistical claim"]
    finally:
        for p in (base_dir, cand_dir):
            subprocess.run(["git", "-C", str(repo), "worktree", "remove", "--force", str(p)], capture_output=True)
    Path(a.report).parent.mkdir(parents=True, exist_ok=True)
    Path(a.report).write_text(json.dumps(report, indent=1, sort_keys=True, default=str) + "\n")
    print(report["outcome"], "->", a.report)
    return 0 if report["outcome"] == "DOGFOOD_PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
