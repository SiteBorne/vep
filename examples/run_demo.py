"""End-to-end VEP demonstration using the real implementation (no mocks, no fixtures of results).

Runs in a temporary directory. The evaluation executes candidate code in a plain host subprocess,
so this demo explicitly passes the trusted-local-execution authorization for the bundled tiny project.
"""
from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path

from vep import budgets, candidates, certificates, execution, snapshots
from vep.errors import VepError
from vep.evidence import KeyStore
from vep.objectives import create_objective
from vep.policies import make_policy
from vep.snapshots import make_writable
from vep.workspace import Workspace

HERE = Path(__file__).resolve().parent


def step(title: str) -> None:
    print(f"\n== {title}")


def main() -> int:
    work = Path(tempfile.mkdtemp(prefix="vep-demo-"))
    try:
        proj = work / "project"
        shutil.copytree(HERE / "tiny_project", proj)
        make_writable(proj)  # copytree preserves modes; a read-only source checkout must not make the demo fail
        policy_cfg = json.loads((HERE / "example_policy.json").read_text())

        step("init workspace + signing key")
        ws = Workspace.init(proj)
        print("key id:", KeyStore(ws).ensure())

        step("snapshot, frozen policy, objective, budget")
        base = snapshots.take_snapshot(ws)
        pol = make_policy(ws, base, evaluator=policy_cfg["evaluator"], audits=policy_cfg["audits"])
        obj = create_objective(ws, "keep arithmetic correct", "add division", base.id, pol.id)
        budgets.create_account(ws, f"objective:{obj.id}", "objective", "1.00")
        print("snapshot", base.id[:24], "| required tests:", sorted(pol["required_tests"]))

        step("candidate: add a feature (new file, protected tests untouched)")
        cand_dir = work / "cand"
        shutil.copytree(proj, cand_dir, ignore=shutil.ignore_patterns(".vep"))
        (cand_dir / "division.py").write_text("def div(a, b):\n    return a / b\n")
        snap = snapshots.take_snapshot(ws, cand_dir)
        cand = candidates.register_candidate(ws, obj.id, snap.id, "demo-agent")
        print("candidate", cand.id[:24])

        step("evaluate WITHOUT authorization -> must refuse")
        try:
            execution.evaluate(ws, cand.id)
        except VepError as exc:
            print("refused:", exc.__class__.__name__)

        step("evaluate with trusted-local authorization (NO security isolation)")
        res = execution.evaluate(ws, cand.id, trusted_local_authorization=execution.TRUSTED_LOCAL_AUTH)
        print(json.dumps(res, indent=1))

        step("certify and verify against the exact current source")
        cert = certificates.certify(ws, cand.id)
        print(certificates.verify_certificate(ws, cert.id, current_root=cand_dir)["checks_passed"])

        step("source changes after certification -> verification must fail")
        (cand_dir / "division.py").write_text("def div(a, b):\n    return 0\n")
        try:
            certificates.verify_certificate(ws, cert.id, current_root=cand_dir)
            print("UNEXPECTED: verification passed")
            return 1
        except VepError as exc:
            print("rejected:", exc)

        step("false-green candidate: tests replaced by a no-op -> must not certify")
        bad_dir = work / "bad"
        shutil.copytree(proj, bad_dir, ignore=shutil.ignore_patterns(".vep"))
        (bad_dir / "tests" / "test_arithmetic.py").write_text("import unittest\n")
        bad = candidates.register_candidate(ws, obj.id, snapshots.take_snapshot(ws, bad_dir).id, "sneaky-agent")
        print("policy violations:", candidates.check_policy(ws, bad.id))
        print("final state:", candidates.get_state(ws, bad.id)["status"])

        step("budget report")
        print(json.dumps(budgets.report(ws, f"objective:{obj.id}"), indent=1))
        print("\nDEMO OK")
        return 0
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
