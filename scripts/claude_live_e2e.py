"""Bounded live Claude Code end-to-end proof for VEP. REFUSES to run without --authorize-model-run: it makes real model calls (API spend).

    python scripts/claude_live_e2e.py --authorize-model-run --max-budget-usd 1.00 --out docs/evidence/claude-code-live.json

Procedure (docs/CLAUDE_LIVE_E2E.md): disposable project with a harmless test; `vep claude install --allow-evaluate`; a real `claude -p` session loads the
project's own .mcp.json (via --mcp-config, strict) and the installed Skill, and is asked to verify a small change. Afterwards THIS script (not the model)
checks the workspace: the candidate is CERTIFIED by the controller, the exported bundle verifies under an externally built trust policy in Python and Node, a
source mutation invalidates the snapshot, and an unauthorized tool call was rejected. The tool-call transcript is stored sanitized. Untested live until authorized.
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROMPT = ("Use the vep skill. 1) Call vep_status. 2) Create a VEP objective titled 'live e2e' (vep_objective_create). 3) Add a function `triple(x)` returning 3*x to feature.py. "
          "4) Register the candidate (vep_candidate_register) and evaluate it (vep_evaluate), poll vep_job_status until it finishes. 5) Report the evidence id and certificate id exactly as returned. "
          "Then try to call vep_export_evidence only if it is available. Never claim the change is verified unless a vep tool result says so.")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--authorize-model-run", action="store_true")
    ap.add_argument("--max-budget-usd", default="1.00")
    ap.add_argument("--out", required=True)
    ap.add_argument("--model")
    a = ap.parse_args()
    if not a.authorize_model_run:
        Path(a.out).with_suffix(".status.json").write_text(json.dumps({"CLAUDE_LIVE_E2E": "UNVERIFIED", "reason": "no authorization for a real model run was given"}, indent=1) + "\n")
        print("refusing: this makes real model calls; pass --authorize-model-run to proceed. CLAUDE_LIVE_E2E=UNVERIFIED")
        return 3
    claude = shutil.which("claude")
    if not claude:
        print("claude CLI not found"); return 2
    d = Path(tempfile.mkdtemp(prefix="vep-live-"))
    (d / "tests").mkdir()
    (d / "feature.py").write_text("def double(x):\n    return 2 * x\n")
    (d / "tests/test_feature.py").write_text("import unittest\nfrom feature import double\n\nclass T(unittest.TestCase):\n    def test_double(self):\n        self.assertEqual(double(2), 4)\n")
    subprocess.run([sys.executable, "-m", "vep.cli", "init", "--root", str(d)], check=True, capture_output=True)
    subprocess.run([sys.executable, "-m", "vep.cli", "claude", "install", "--root", str(d), "--allow-evaluate"], check=True, capture_output=True)
    cmd = [claude, "-p", PROMPT, "--output-format", "stream-json", "--verbose", "--mcp-config", str(d / ".mcp.json"), "--strict-mcp-config",
           "--allowedTools", "mcp__vep__vep_status,mcp__vep__vep_objective_create,mcp__vep__vep_candidate_register,mcp__vep__vep_evaluate,mcp__vep__vep_job_status,Edit,Write,Read",
           "--max-budget-usd", a.max_budget_usd, "--no-session-persistence", "--permission-mode", "default"] + (["--model", a.model] if a.model else [])
    r = subprocess.run(cmd, cwd=d, capture_output=True, text=True, timeout=1800)
    calls = []
    for ln in r.stdout.splitlines():
        try:
            ev = json.loads(ln)
        except ValueError:
            continue
        for blk in (ev.get("message", {}) or {}).get("content", []) if isinstance(ev.get("message"), dict) else []:
            if isinstance(blk, dict) and blk.get("type") == "tool_use":
                calls.append({"tool": blk.get("name"), "input": blk.get("input")})
    out = {"CLAUDE_LIVE_E2E": "UNVERIFIED", "exit_code": r.returncode, "claude_version": subprocess.run([claude, "--version"], capture_output=True, text=True).stdout.strip(),
           "tool_calls": calls}
    # independent checks by this script, not by the model
    from vep import candidates, trustpolicy
    from vep.conformance import export_bundle
    from vep.workspace import Workspace
    ws = Workspace(d)
    with ws.db.read() as c:
        cert = c.execute("SELECT id, snapshot_id FROM certificates").fetchone()
        raw = bytes.fromhex(c.execute("SELECT public_key_hex FROM trusted_keys").fetchone()["public_key_hex"])
    checks = {"vep_tools_called": sorted({x["tool"] for x in calls if str(x["tool"]).startswith("mcp__vep__")}), "certified_by_controller": bool(cert)}
    if cert:
        pol = trustpolicy.make_policy("rp", [trustpolicy.issuer(raw)], ["vep-local-evaluator/*"], "TRUSTED_LOCAL", snapshot_id=cert["snapshot_id"])
        checks["authorized_python"] = trustpolicy.verify_authorized(export_bundle(ws, cert["id"], version=2), pol, "2099-01-01T00:00:00Z")["valid"]
        (d / "feature.py").write_text((d / "feature.py").read_text() + "\n# mutation\n")
        from vep import certificates
        try:
            certificates.verify_certificate(ws, cert["id"], current_root=d); checks["mutation_invalidates"] = False
        except Exception:
            checks["mutation_invalidates"] = True
    out["independent_checks"] = checks
    ok = r.returncode == 0 and {"mcp__vep__vep_status", "mcp__vep__vep_evaluate"} <= set(checks["vep_tools_called"]) and checks.get("authorized_python") and checks.get("mutation_invalidates")
    out["CLAUDE_LIVE_E2E"] = "VERIFIED" if ok else "FAILED"
    text = re.sub(r"/(Users|private|var)/[^\s\"']+", "<path>", json.dumps(out, indent=1, sort_keys=True))
    Path(a.out).write_text(text + "\n")
    print(out["CLAUDE_LIVE_E2E"])
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
