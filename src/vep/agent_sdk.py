"""Claude Agent SDK adapter: options that give an SDK-driven agent the VEP MCP tools under an operator-fixed authority, plus the guard hook.

    from vep.agent_sdk import vep_options
    options = vep_options("/path/to/project", authority=("read", "register"), max_budget_usd=1.0)
    async for msg in claude_agent_sdk.query(prompt="Verify my change with VEP", options=options): ...

This module only BUILDS configuration; it makes no model call. The agent talks to the same `vep-mcp` stdio server as Claude Code, so there is one
implementation of every operation. Authority is enforced by the server's start-up flags (not by the allow-list, which is only a second layer).
Requires the optional `claude` extra.
"""
from __future__ import annotations

import importlib.util
import sys
from importlib import resources
from pathlib import Path
from typing import Any

from claude_agent_sdk import ClaudeAgentOptions, HookMatcher

from .services import AUTHORITIES

SERVER = "vep"
# tool -> authority it needs. tests/test_agent_sdk.py asserts this equals the live server's tool list, so it cannot drift silently.
TOOL_AUTHORITY = {
    "vep_status": "read", "vep_job_status": "read", "vep_candidate_state": "read", "vep_verify_certificate": "read", "vep_budget_status": "read",
    "vep_explain_failure": "read", "vep_read_artifact": "read",
    "vep_objective_create": "register", "vep_candidate_register": "register",
    "vep_evaluate": "evaluate", "vep_export_evidence": "export",
}
GUARD_MATCHER = "Edit|Write|MultiEdit|NotebookEdit|Bash"


def _guard_module():
    spec = importlib.util.spec_from_file_location("vep_guard_asset", str(resources.files("vep") / "assets" / "claude" / "vep_guard.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


async def guard_hook(input_data: dict[str, Any], tool_use_id: str | None, context: Any) -> dict[str, Any]:
    """PreToolUse callback: same decisions as the Claude Code hook script (defense in depth, not a security boundary)."""
    reason = _guard_module().decide(input_data.get("tool_name"), input_data.get("tool_input"), input_data.get("cwd"), input_data.get("cwd"))
    if not reason:
        return {}
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": reason}}


def vep_options(root: str | Path, *, authority: tuple[str, ...] = ("read", "register"), trusted_local: bool = False, python: str | None = None,
                max_budget_usd: float | None = None, hooks: bool = True, **overrides: Any) -> ClaudeAgentOptions:
    granted = tuple(dict.fromkeys(authority))
    if not set(granted) <= set(AUTHORITIES) or "read" not in granted:
        raise ValueError(f"authority must include 'read' and be a subset of {AUTHORITIES}")
    if trusted_local and "evaluate" not in granted:
        raise ValueError("trusted_local needs the 'evaluate' authority")
    root = Path(root).resolve()
    args = ["-m", "vep.mcp_server", "--root", str(root), "--authority", ",".join(granted)] + (["--trusted-local-execution"] if trusted_local else [])
    allowed = [f"mcp__{SERVER}__{t}" for t, a in TOOL_AUTHORITY.items() if a in granted]
    denied = [f"mcp__{SERVER}__{t}" for t, a in TOOL_AUTHORITY.items() if a not in granted]
    opts: dict[str, Any] = dict(
        cwd=str(root), mcp_servers={SERVER: {"type": "stdio", "command": python or sys.executable, "args": args}},
        allowed_tools=allowed, disallowed_tools=denied, max_budget_usd=max_budget_usd,
        hooks={"PreToolUse": [HookMatcher(matcher=GUARD_MATCHER, hooks=[guard_hook])]} if hooks else None)
    opts.update(overrides)
    return ClaudeAgentOptions(**opts)
