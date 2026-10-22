"""Bounded live Claude Code end-to-end proof for VEP. REFUSES to run without --authorize-model-run: it makes real model calls (API spend).

    python scripts/claude_live_e2e.py --authorize-model-run --max-budget-usd 1.00 --max-tool-calls 40 --timeout-s 600 --out docs/evidence/claude-code-live.json

A real `claude -p` session loads only the disposable project's own `.mcp.json` (--strict-mcp-config) and its installed Skill and is asked to verify a small change.
Afterwards THIS script (not the model) establishes, separately and independently:
  mcp_discovery        the session reported the vep server connected and exposed its tools        (from the stream's init event)
  mcp_tool_invocation  the model called vep_* tools and they returned non-error results            (from tool_use / tool_result events)
  skill_discovery      the session listed the `vep` skill                                          (init event)
  skill_activation     the model actually invoked the Skill tool for `vep`                         (tool_use event)
  protected_evaluation the candidate in the workspace is CERTIFIED by the controller after a trusted-local job, its snapshot contains the requested
                       `triple(x)` (executed: triple(2) == 6) and its evidence/certificate ids are the ones the model was shown
  authorized_python / authorized_node   the exported v2 bundle verifies under an externally built trust policy in both verifiers
  mutation             after editing the tree, certificate verification fails with SOURCE_CHANGED specifically
  unauthorized         a read-only vep-mcp server refuses a write with VEP_E_NOT_AUTHORIZED (run by this script against the same build, not through Claude)
Model execution is bounded by --max-budget-usd (CLI), --timeout-s (process group killed) and --max-tool-calls (stream cut). The installed CLI (2.1.x) has no
--max-turns option, so turns are bounded indirectly by those three. Recorded inputs are sanitized. Verdict VERIFIED needs every item except skill_activation,
which is reported on its own (a model may do the work without activating the Skill).
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIRED_TOOLS = {"mcp__vep__vep_status", "mcp__vep__vep_evaluate", "mcp__vep__vep_candidate_register"}
ALLOWED = ("mcp__vep__vep_status,mcp__vep__vep_objective_create,mcp__vep__vep_candidate_register,mcp__vep__vep_evaluate,mcp__vep__vep_job_status,"
           "mcp__vep__vep_candidate_state,Skill,Edit,Write,Read")
PROMPT = ("Use the vep skill. 1) Call vep_status. 2) Create a VEP objective titled 'live e2e' (vep_objective_create). 3) Add a function `triple(x)` returning 3*x to feature.py. "
          "4) Register the candidate (vep_candidate_register) and evaluate it (vep_evaluate), then poll vep_job_status until it finishes. 5) Report the evidence id and certificate id "
          "exactly as returned. Never claim the change is verified unless a vep tool result says so.")
MAX_BUDGET_CEILING = 5.0

SECRET_RES = [re.compile(p) for p in (r"sk-[A-Za-z0-9_\-]{12,}", r"(?i)bearer\s+[A-Za-z0-9._\-]{12,}", r"(?i)(api[_-]?key|token|secret|password)\s*[=:]\s*\S+",
                                      r"[A-Za-z0-9+/_\-]{40,}={0,2}", r"[\w.+-]+@[\w-]+\.[\w.-]+", r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----")]
PATH_RE = re.compile(r"/(?:Users|home|private|var|tmp)/[^\s\"'`]+")
ID_RE = re.compile(r"\b(?:obj|snap|cand|evd|cert|pol|act)-[0-9a-f]{64}\b|\bjob-[0-9a-f]{32}\b")


def sanitize(value, depth=0):
    """Redact credential-like strings, e-mail addresses and absolute paths; keep VEP ids (public identifiers) and truncate long text to a hash+length."""
    if isinstance(value, dict):
        return {str(k): sanitize(v, depth + 1) for k, v in list(value.items())[:50]}
    if isinstance(value, list):
        return [sanitize(v, depth + 1) for v in value[:50]]
    if not isinstance(value, str):
        return value
    keep = {m.group(0): f"\0{i}\0" for i, m in enumerate(ID_RE.finditer(value))}
    t = value
    for k, ph in keep.items():
        t = t.replace(k, ph)
    for rx in SECRET_RES:
        t = rx.sub("<redacted>", t)
    t = PATH_RE.sub("<path>", t)
    for k, ph in keep.items():
        t = t.replace(ph, k)
    return t if len(t) <= 400 else t[:400] + f"...<{len(value)} chars>"


class Session:
    """What the stream-json transcript shows. Pure data so classification can be tested offline."""
    def __init__(self):
        self.init_seen = False
        self.mcp_servers: list[dict] = []
        self.tools: list[str] = []
        self.skills: list[str] = []
        self.calls: list[dict] = []        # tool_use events in order
        self.results: dict[str, dict] = {}  # tool_use_id -> {"is_error", "text"}
        self.result_event: dict = {}
        self.cut_reason: str | None = None


def parse_stream(lines) -> Session:
    s = Session()
    for ln in lines:
        try:
            ev = json.loads(ln)
        except ValueError:
            continue
        if not isinstance(ev, dict):
            continue
        if ev.get("type") == "system" and ev.get("subtype") == "init":
            s.init_seen = True
            s.mcp_servers = [m for m in ev.get("mcp_servers", []) if isinstance(m, dict)]
            s.tools = [t for t in ev.get("tools", []) if isinstance(t, str)]
            s.skills = [x for k in ("skills", "slash_commands") for x in ev.get(k, []) if isinstance(x, str)]
        msg = ev.get("message")
        for blk in (msg.get("content", []) if isinstance(msg, dict) and isinstance(msg.get("content"), list) else []):
            if not isinstance(blk, dict):
                continue
            if blk.get("type") == "tool_use":
                s.calls.append({"id": blk.get("id"), "tool": blk.get("name"), "input": blk.get("input")})
            elif blk.get("type") == "tool_result":
                c = blk.get("content")
                text = c if isinstance(c, str) else json.dumps(c)
                s.results[blk.get("tool_use_id")] = {"is_error": bool(blk.get("is_error")), "text": text}
        if ev.get("type") == "result":
            s.result_event = ev
    return s


def session_findings(s: Session) -> dict:
    vep_calls = [c for c in s.calls if str(c["tool"]).startswith("mcp__vep__")]
    ok_results = [c for c in vep_calls if c["id"] in s.results and not s.results[c["id"]]["is_error"]]
    server = next((m for m in s.mcp_servers if m.get("name") == "vep"), None)
    skill_calls = [c for c in s.calls if c["tool"] == "Skill" and "vep" in json.dumps(c.get("input"))]
    return {
        "mcp_discovery": "VERIFIED" if server and server.get("status") == "connected" and any(t.startswith("mcp__vep__") for t in s.tools)
        else ("NOT_OBSERVED" if not s.init_seen else "FAILED"),
        "mcp_tool_invocation": "VERIFIED" if REQUIRED_TOOLS <= {c["tool"] for c in ok_results} else "FAILED",
        "skill_discovery": "VERIFIED" if "vep" in s.skills else ("NOT_OBSERVED" if not s.init_seen else "FAILED"),
        "skill_activation": "VERIFIED" if skill_calls else "NOT_OBSERVED",
        "vep_tools_called": sorted({c["tool"] for c in vep_calls}),
    }


def shown_ids(s: Session) -> set[str]:
    return set(ID_RE.findall(" ".join(r["text"] for r in s.results.values())))


def classify(findings: dict, checks: dict, *, cut: str | None, exit_code: int | None) -> str:
    """VERIFIED needs every item except skill_activation (reported separately). Any bound breach or failed item is FAILED."""
    if cut:
        return "FAILED"
    required = [findings["mcp_discovery"] == "VERIFIED", findings["mcp_tool_invocation"] == "VERIFIED", exit_code == 0,
                checks.get("candidate_certified_by_controller") is True, checks.get("change_present_and_executes") is True,
                checks.get("evidence_matches_protected_evaluation") is True, checks.get("ids_shown_to_model") is True,
                checks.get("authorized_python") is True, checks.get("authorized_node") is True, checks.get("mutation_source_changed") is True,
                checks.get("unauthorized_rejected") is True]
    return "VERIFIED" if all(required) else "FAILED"


def independent_checks(d: Path, shown: set[str], repo: Path = ROOT) -> dict:
    from vep import certificates, trustpolicy
    from vep.conformance import export_bundle
    from vep.errors import VerificationFailed
    from vep.workspace import Workspace
    ck: dict = {}
    ws = Workspace(d)
    with ws.db.read() as c:
        certs = c.execute("SELECT id, candidate_id, snapshot_id, evidence_id FROM certificates").fetchall()
        raw_row = c.execute("SELECT public_key_hex FROM trusted_keys").fetchone()
        jobs = [dict(r) for r in c.execute("SELECT candidate_id, state, mode FROM jobs").fetchall()]
    ck["candidate_certified_by_controller"] = len(certs) == 1
    if len(certs) != 1 or not raw_row:
        return ck
    cert = certs[0]
    cid = cert["candidate_id"]
    # the certified snapshot contains the requested change and it executes
    snap = ws.get_object(cert["snapshot_id"], "Snapshot")
    entry = next((e for e in snap["entries"] if e["path"] == "feature.py"), None)
    src = ws.cas.get(entry["digest"]).decode() if entry else ""
    ns: dict = {}
    try:
        exec(compile(src, "feature.py", "exec"), ns)
        ck["change_present_and_executes"] = ns["triple"](2) == 6 and ns["triple"](0) == 0 and ns["double"](2) == 4
    except Exception:
        ck["change_present_and_executes"] = False
    # the evidence is the protected evaluator's, for exactly this candidate and snapshot
    from vep.evidence import load_signed
    with ws.db.read() as c:
        row = c.execute("SELECT envelope_digest FROM evidence WHERE id=?", (cert["evidence_id"],)).fetchone()
    ev = load_signed(ws, row["envelope_digest"], "Evidence")
    ck["evidence_matches_protected_evaluation"] = (ev["candidate_id"] == cid and ev["staged_tree_snapshot_id"] == cert["snapshot_id"] and ev["trust_level"] == "TRUSTED_LOCAL"
                                                    and str(ev["evaluator_id"]).startswith("vep-local-evaluator/") and ev["verdict"] == "PASS" and ev["tests_passed"] >= 1
                                                    and any(j["candidate_id"] == cid and j["state"] == "SUCCEEDED" and j["mode"] == "trusted-local" for j in jobs))
    ck["ids_shown_to_model"] = {cert["id"], cert["evidence_id"], cid} <= shown
    # authorized verification under an externally built policy, in both implementations
    raw = bytes.fromhex(raw_row["public_key_hex"])
    pol = trustpolicy.make_policy("relying-party", [trustpolicy.issuer(raw)], ["vep-local-evaluator/*"], "TRUSTED_LOCAL", snapshot_id=cert["snapshot_id"])
    bundle = export_bundle(ws, cert["id"], version=2)
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    ck["authorized_python"] = trustpolicy.verify_authorized(bundle, pol, now).get("assurance") == "AUTHORIZED"
    node = shutil.which("node")
    if node:
        (d / "_b2.json").write_text(json.dumps(bundle)); (d / "_p.json").write_text(json.dumps(pol))
        r = subprocess.run([node, str(repo / "conformance" / "node" / "verify.mjs"), "authorized", str(d / "_b2.json"), str(d / "_p.json"), now], capture_output=True, text=True)
        try:
            ck["authorized_node"] = json.loads(r.stdout).get("assurance") == "AUTHORIZED"
        except ValueError:
            ck["authorized_node"] = False
        (d / "_b2.json").unlink(); (d / "_p.json").unlink()
    else:
        ck["authorized_node"] = False
        ck["authorized_node_note"] = "node not installed: NOT RUN"
    # mutation: the specific failure, not any exception
    (d / "feature.py").write_text((d / "feature.py").read_text() + "\n# mutation after certification\n")
    try:
        certificates.verify_certificate(ws, cert["id"], current_root=d)
        ck["mutation_source_changed"] = False
    except VerificationFailed as exc:
        ck["mutation_source_changed"] = str(exc).startswith("SOURCE_CHANGED")
    except Exception:
        ck["mutation_source_changed"] = False
    ck["unauthorized_rejected"] = unauthorized_rejected(d)
    return ck


def unauthorized_rejected(d: Path) -> bool:
    """Start a read-only vep-mcp for the same project with the official MCP client and attempt a write."""
    from mcp.client.client import Client
    from mcp.client.stdio import StdioServerParameters
    exe = shutil.which("vep-mcp")
    params = StdioServerParameters(command=exe or sys.executable, args=([] if exe else ["-m", "vep.mcp_server"]) + ["--root", str(d), "--authority", "read"],
                                   env={k: v for k, v in os.environ.items() if k in ("PATH", "HOME", "LANG", "TMPDIR", "PYTHONPATH")})

    async def go():
        async with Client(params) as c:
            r = await c.call_tool("vep_objective_create", {"title": "unauthorized probe"})
            return bool(r.is_error) and r.structured_content["error"]["code"] == "VEP_E_NOT_AUTHORIZED"
    try:
        return asyncio.run(go())
    except Exception:
        return False


def run_session(claude: str, d: Path, *, budget: float, timeout_s: int, max_tool_calls: int, model: str | None) -> tuple[Session, int | None, list[str]]:
    cmd = [claude, "-p", PROMPT, "--output-format", "stream-json", "--verbose", "--mcp-config", str(d / ".mcp.json"), "--strict-mcp-config", "--allowedTools", ALLOWED,
           "--max-budget-usd", f"{budget:.2f}", "--no-session-persistence", "--permission-mode", "default"] + (["--model", model] if model else [])
    p = subprocess.Popen(cmd, cwd=d, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, start_new_session=True)
    lines: list[str] = []
    cut = None
    deadline = time.monotonic() + timeout_s
    import threading
    def killer():
        nonlocal cut
        while p.poll() is None:
            if time.monotonic() > deadline:
                cut = f"wall-time limit {timeout_s}s exceeded"; break
            time.sleep(0.5)
        if cut:
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
    t = threading.Thread(target=killer, daemon=True); t.start()
    for ln in p.stdout:
        lines.append(ln)
        if '"tool_use"' in ln and len(parse_stream(lines).calls) > max_tool_calls:
            cut = f"tool-call limit {max_tool_calls} exceeded"
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            break
    rc = p.wait()
    s = parse_stream(lines)
    s.cut_reason = cut
    return s, rc, lines


def make_project() -> Path:
    d = Path(tempfile.mkdtemp(prefix="vep-live-"))
    (d / "tests").mkdir()
    (d / "feature.py").write_text("def double(x):\n    return 2 * x\n")
    (d / "tests/test_feature.py").write_text("import unittest\nfrom feature import double\n\n\nclass T(unittest.TestCase):\n    def test_double(self):\n        self.assertEqual(double(2), 4)\n")
    py = [sys.executable, "-m", "vep.cli"]
    subprocess.run(py + ["init", "--root", str(d)], check=True, capture_output=True)
    subprocess.run(py + ["claude", "install", "--root", str(d), "--allow-evaluate"], check=True, capture_output=True)
    return d


def execute(claude: str, *, budget: float, timeout_s: int, max_tool_calls: int, model: str | None) -> dict:
    d = make_project()
    s, rc, _ = run_session(claude, d, budget=budget, timeout_s=timeout_s, max_tool_calls=max_tool_calls, model=model)
    findings = session_findings(s)
    checks = independent_checks(d, shown_ids(s))
    verdict = classify(findings, checks, cut=s.cut_reason, exit_code=rc)
    ver = subprocess.run([claude, "--version"], capture_output=True, text=True).stdout.strip()
    return sanitize({
        "CLAUDE_LIVE_E2E": verdict, "SKILL_ACTIVATION": findings["skill_activation"], "claude_version": ver, "exit_code": rc,
        "limits": {"max_budget_usd": budget, "timeout_s": timeout_s, "max_tool_calls": max_tool_calls, "max_turns": "not supported by the installed CLI; bounded by the three limits above",
                   "cut_reason": s.cut_reason},
        "session": findings, "independent_checks": checks,
        "tool_calls": [{"tool": c["tool"], "input": c["input"], "error": s.results.get(c["id"], {}).get("is_error")} for c in s.calls],
        "reported_cost_usd": s.result_event.get("total_cost_usd"), "turns_reported": s.result_event.get("num_turns")})


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--authorize-model-run", action="store_true")
    ap.add_argument("--max-budget-usd", type=float, default=1.0)
    ap.add_argument("--max-tool-calls", type=int, default=40)
    ap.add_argument("--timeout-s", type=int, default=600)
    ap.add_argument("--out", required=True)
    ap.add_argument("--model")
    a = ap.parse_args()
    if not a.authorize_model_run:
        Path(a.out).with_suffix(".status.json").write_text(json.dumps({"CLAUDE_LIVE_E2E": "UNVERIFIED", "reason": "no authorization for a real model run was given"}, indent=1) + "\n")
        print("refusing: this makes real model calls; pass --authorize-model-run to proceed. CLAUDE_LIVE_E2E=UNVERIFIED")
        return 3
    if not 0 < a.max_budget_usd <= MAX_BUDGET_CEILING or a.max_tool_calls < 1 or a.timeout_s < 30:
        print(f"refusing: budget must be in (0, {MAX_BUDGET_CEILING}] USD, tool calls >= 1, timeout >= 30 s"); return 2
    claude = shutil.which("claude")
    if not claude:
        print("claude CLI not found"); return 2
    out = execute(claude, budget=a.max_budget_usd, timeout_s=a.timeout_s, max_tool_calls=a.max_tool_calls, model=a.model)
    Path(a.out).write_text(json.dumps(out, indent=1, sort_keys=True) + "\n")
    print(out["CLAUDE_LIVE_E2E"], "| skill activation:", out["SKILL_ACTIVATION"])
    return 0 if out["CLAUDE_LIVE_E2E"] == "VERIFIED" else 1


if __name__ == "__main__":
    sys.exit(main())
