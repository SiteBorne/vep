"""End-to-end isolated evaluation on a Docker+gVisor host, for the isolation workflow.

Requires a passing attestation (from `vep isolation verify`). Builds a throwaway workspace with an EPHEMERAL signing key
(a demonstration issuer, not a trusted one), evaluates a candidate in the container, certifies it, and verifies the result
as ISOLATED_VERIFIED with the Python reference and, if present, the independent Node verifier. Also checks the fail-closed
paths. Writes a summary JSON; exits non-zero if any expectation fails.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

from vep import budgets, candidates, certificates, conformance, execution, snapshots  # noqa: E402
from vep.errors import AuthorizationError, IsolationUnavailable, VepError  # noqa: E402
from vep.evidence import KeyStore  # noqa: E402
from vep.objectives import create_objective  # noqa: E402
from vep.policies import make_policy  # noqa: E402
from vep.snapshots import make_writable  # noqa: E402
from vep.workspace import Workspace  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--image", required=True)
    ap.add_argument("--attestation", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    att = json.loads(Path(a.attestation).read_text())
    summary: dict = {"image": a.image, "attestation_status": att.get("status"), "attestation_reasons": att.get("reasons"),
                     "checks": {}}
    ok = att.get("status") == "ISOLATED_VERIFIED"
    work = Path(tempfile.mkdtemp(prefix="vep-iso-"))
    try:
        if ok:
            proj = work / "project"
            shutil.copytree(ROOT / "examples" / "tiny_project", proj)
            make_writable(proj)
            cfg = json.loads((ROOT / "examples" / "example_policy.json").read_text())
            ws = Workspace.init(proj)
            KeyStore(ws).ensure()
            base = snapshots.take_snapshot(ws)
            pol = make_policy(ws, base, evaluator=cfg["evaluator"], audits=cfg["audits"])
            obj = create_objective(ws, "isolated demo", "add division", base.id, pol.id)
            budgets.create_account(ws, f"objective:{obj.id}", "objective", "1.00")
            cand_dir = work / "cand"
            shutil.copytree(proj, cand_dir, ignore=shutil.ignore_patterns(".vep"))
            (cand_dir / "division.py").write_text("def div(a, b):\n    return a / b\n")
            cid = candidates.register_candidate(ws, obj.id, snapshots.take_snapshot(ws, cand_dir).id, "ci").id
            # fail-closed: wrong image string must not run anything
            try:
                execution.evaluate(ws, cid, mode="isolated", image=a.image.replace("3.13", "3.12"), attestation=att)
                summary["checks"]["wrong_image_refused"] = False
            except IsolationUnavailable:
                summary["checks"]["wrong_image_refused"] = True
            try:
                execution.evaluate(ws, cid)  # no authorization, no isolation requested
                summary["checks"]["unauthorized_host_run_refused"] = False
            except AuthorizationError:
                summary["checks"]["unauthorized_host_run_refused"] = True
            r = execution.evaluate(ws, cid, mode="isolated", image=a.image, attestation=att)
            summary["evaluation"] = {k: r.get(k) for k in ("status", "verdict", "trust_level", "isolation", "counts")}
            summary["checks"]["evaluated_isolated_verified"] = r.get("trust_level") == "ISOLATED_VERIFIED" and r.get("verdict") == "PASS"
            cert = certificates.certify(ws, cid)
            v = certificates.verify_certificate(ws, cert.id, require_trust="ISOLATED_VERIFIED")
            summary["checks"]["certificate_isolated_verified"] = v["trust_level"] == "ISOLATED_VERIFIED"
            bundle = conformance.export_bundle(ws, cert.id, "ISOLATED_VERIFIED")
            summary["checks"]["bundle_python_reference"] = conformance.verify_bundle(bundle)["valid"]
            node = shutil.which("node")
            if node:
                bp = work / "bundle.json"
                bp.write_text(json.dumps(bundle))
                res = subprocess.run([node, str(ROOT / "conformance/node/verify.mjs"), "bundle", str(bp)], capture_output=True, text=True)
                summary["checks"]["bundle_node_independent"] = json.loads(res.stdout).get("valid") is True
            else:
                summary["checks"]["bundle_node_independent"] = "NOT_RUN (node missing)"
            summary["demonstration_issuer_note"] = "ephemeral key generated in this job; not a trusted issuer"
        else:
            summary["note"] = "attestation not ISOLATED_VERIFIED: isolated evaluation was not attempted (no fallback)"
    except VepError as exc:
        summary["error"] = f"{exc.__class__.__name__}: {exc}"
        ok = False
    finally:
        make_writable(work)
        shutil.rmtree(work, ignore_errors=True)
    passed = ok and all(v is True for v in summary["checks"].values() if not str(v).startswith("NOT_RUN"))
    summary["result"] = "PASS" if passed else "FAIL"
    Path(a.out).write_text(json.dumps(summary, indent=1, sort_keys=True))
    print(json.dumps(summary, indent=1, sort_keys=True))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
