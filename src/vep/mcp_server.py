"""VEP MCP server (local stdio). Thin adapter over `vep.services`: no domain logic lives here.

    vep-mcp --root PROJECT [--authority read,register,evaluate,export] [--trusted-local-execution]

Authority is fixed by the operator at start-up; callers cannot raise it. Default is read-only. There is no tool that accepts a verdict or
certifies anything: certification happens only inside the controller after a protected evaluation, which additionally needs both the
`evaluate` authority and --trusted-local-execution (candidate code then runs unisolated on this host). Remote HTTP is intentionally not
offered: write-capable remote access is not qualified (see docs/MCP.md). Requires the optional `mcp` extra.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ResourceError
from mcp.types import CallToolResult, TextContent, ToolAnnotations

from . import services, versions
from .services import AUTHORITIES, Context, ServiceError

INSTRUCTIONS = (
    "VEP verifies code changes with protected, evidence-carrying evaluation. Start with vep_status. Typical flow: vep_objective_create (freezes the "
    "current tree and its tests) -> make the change -> vep_candidate_register -> vep_evaluate -> vep_job_status -> vep_verify_certificate / "
    "vep_export_evidence. If something fails call vep_explain_failure. Results are compact; fetch logs with vep_read_artifact using returned handles. "
    "You cannot declare a result certified: only VEP's protected evaluation can, and only if the operator enabled it.")


def _ok(d: dict) -> dict:
    return d


def _err(e: ServiceError) -> CallToolResult:
    body = e.to_dict()
    return CallToolResult(content=[TextContent(type="text", text=json.dumps(body, sort_keys=True))], structuredContent=body, isError=True)


def build_server(ctx: Context) -> MCPServer:
    srv = MCPServer("vep", title="Verified Evolution Protocol", version=versions.PACKAGE_VERSION, instructions=INSTRUCTIONS)

    def run(fn, *a, **kw) -> Any:
        try:
            return fn(ctx, *a, **kw)
        except ServiceError as e:
            return _err(e)

    ro = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False)
    wr_idem = ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=False)

    @srv.tool(annotations=ro)
    def vep_status() -> dict[str, Any]:
        """Workspace summary: versions, counts, enabled authority, next action."""
        return run(services.status)

    @srv.tool(annotations=wr_idem)
    def vep_objective_create(title: str, description: str = "", budget: str = "1.00", idempotency_key: str | None = None) -> dict[str, Any]:
        """Freeze the current tree and its tests as the acceptance baseline and open a USD budget. Needs the 'register' authority."""
        return run(services.objective_create, title, description, budget, idempotency_key)

    @srv.tool(annotations=wr_idem)
    def vep_candidate_register(objective_id: str, author: str = "agent", idempotency_key: str | None = None) -> dict[str, Any]:
        """Register the current working tree as a candidate (stays PROPOSED; nothing is evaluated or certified). Needs 'register'."""
        return run(services.candidate_register, objective_id, author, idempotency_key)

    @srv.tool(annotations=wr_idem)
    def vep_evaluate(candidate_id: str) -> dict[str, Any]:
        """Queue the protected evaluation (idempotent per candidate). Runs candidate code unisolated on this host; needs the 'evaluate' authority AND the operator's --trusted-local-execution."""
        return run(services.evaluate, candidate_id)

    @srv.tool(annotations=ro)
    def vep_job_status(job_id: str | None = None, candidate_id: str | None = None) -> dict[str, Any]:
        """State of an evaluation job (give job_id or candidate_id): state, attempts, bounded result, next action."""
        return run(services.job_status, job_id, candidate_id)

    @srv.tool(annotations=ro)
    def vep_candidate_state(candidate_id: str) -> dict[str, Any]:
        """Candidate status with evidence and certificate ids."""
        return run(services.candidate_state, candidate_id)

    @srv.tool(annotations=ro)
    def vep_verify_certificate(certificate_id: str, require_trust: str = "TRUSTED_LOCAL", check_current_source: bool = False) -> dict[str, Any]:
        """Verify a certificate against THIS workspace's own key registry (not an external trust anchor)."""
        return run(services.verify_certificate, certificate_id, require_trust, check_current_source)

    @srv.tool(annotations=wr_idem)
    def vep_export_evidence(certificate_id: str, bundle_version: int = 2) -> dict[str, Any]:
        """Write a portable evidence bundle to .vep/exports and return its handle (path, size, sha256). Needs the 'export' authority."""
        return run(services.export_evidence, certificate_id, bundle_version)

    @srv.tool(annotations=ro)
    def vep_budget_status(objective_id: str) -> dict[str, Any]:
        """Budget for an objective: limit, reserved, settled, uncertain, available (USD)."""
        return run(services.budget_status, objective_id)

    @srv.tool(annotations=ro)
    def vep_explain_failure(candidate_id: str | None = None, job_id: str | None = None) -> dict[str, Any]:
        """Which invariant failed and why, the remedy, a bounded preview of failing tests and handles to the full output."""
        return run(services.explain_failure, candidate_id, job_id)

    @srv.tool(annotations=ro)
    def vep_read_artifact(digest: str, offset: int = 0, limit: int = services.MAX_ARTIFACT_PAGE) -> dict[str, Any]:
        """Page through a stored execution log by its handle (64 hex)."""
        return run(services.read_artifact, digest, offset, limit)

    def res(fn, *a):
        try:
            return json.dumps(fn(ctx, *a), sort_keys=True)
        except ServiceError as e:
            raise ResourceError(json.dumps(e.to_dict()["error"], sort_keys=True)) from e

    @srv.resource("vep://version", mime_type="application/json", description="Package, protocol and schema versions and enabled authority")
    def r_version() -> str:
        return res(services.status)

    @srv.resource("vep://objective/{objective_id}", mime_type="application/json", description="Objective summary")
    def r_objective(objective_id: str) -> str:
        return res(services.objective_summary, objective_id)

    @srv.resource("vep://policy/{policy_id}", mime_type="application/json", description="Frozen acceptance policy summary")
    def r_policy(policy_id: str) -> str:
        return res(services.policy_summary, policy_id)

    @srv.resource("vep://candidate/{candidate_id}", mime_type="application/json", description="Candidate state")
    def r_candidate(candidate_id: str) -> str:
        return res(services.candidate_state, candidate_id)

    @srv.resource("vep://history/{candidate_id}", mime_type="application/json", description="First page of a candidate's transition history")
    def r_history(candidate_id: str) -> str:
        return res(services.history, candidate_id)

    @srv.resource("vep://evidence/{evidence_id}", mime_type="application/json", description="Evidence summary with log handles")
    def r_evidence(evidence_id: str) -> str:
        return res(services.evidence_summary, evidence_id)

    @srv.resource("vep://certificate/{certificate_id}/verification", mime_type="application/json", description="Workspace-registry verification of a certificate")
    def r_verification(certificate_id: str) -> str:
        return res(services.verify_certificate, certificate_id)

    return srv


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="vep-mcp", description=__doc__.split("\n")[0])
    ap.add_argument("--root", default=".", help="VEP workspace (project) directory")
    ap.add_argument("--authority", default="read", help=f"comma-separated subset of {','.join(AUTHORITIES)} (default: read)")
    ap.add_argument("--trusted-local-execution", action="store_true", help="allow evaluation: candidate code runs unisolated on this host")
    ap.add_argument("--transport", default="stdio", help="only 'stdio' is supported")
    a = ap.parse_args(argv)
    if a.transport != "stdio":
        print("vep-mcp: only the local stdio transport is offered; remote HTTP write access is not qualified (docs/MCP.md)", file=sys.stderr)
        return 2
    granted = frozenset(x.strip() for x in a.authority.split(",") if x.strip())
    if not granted <= set(AUTHORITIES):
        print(f"vep-mcp: unknown authority {sorted(granted - set(AUTHORITIES))}", file=sys.stderr)
        return 2
    ctx = Context(root=Path(a.root).resolve(), authority=granted, trusted_local_execution=a.trusted_local_execution, actor="vep-mcp")
    build_server(ctx).run("stdio")
    return 0


if __name__ == "__main__":
    sys.exit(main())
