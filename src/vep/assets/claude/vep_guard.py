#!/usr/bin/env python3
"""Claude Code PreToolUse hook installed by `vep claude install` (defense in depth, not a security boundary).

Denies tool calls that would tamper with VEP state or bypass the MCP server's operator-fixed authority:
  - Edit/Write/MultiEdit/NotebookEdit of anything under <project>/.vep/
  - Bash commands that write to .vep/ or run `vep run|evaluate|certify|build run` directly
Anything else produces no decision, so the normal permission flow applies. A hook can be bypassed by a determined
agent with shell access (for example through an interpreter); the isolation and operator authority are the real controls.
"""
import json
import os
import re
import sys

EDIT_TOOLS = {"Edit", "Write", "MultiEdit", "NotebookEdit"}
WRITE_HINT = re.compile(r"(>|>>|\brm\b|\bmv\b|\bcp\b|\bsed\s+-i|\btee\b|\bsqlite3\b|\bchmod\b|\bdd\b|\btruncate\b|\bln\b)")
DIRECT_VEP = re.compile(r"(^|[;&|(`\s])(?:\S*/)?vep\s+(?:--\S+\s+\S+\s+)*(run|evaluate|certify|build\s+run)\b")


def decide(tool, inp, cwd, project_root):
    """Return a denial reason, or None for no decision."""
    root = os.path.realpath(project_root or cwd or ".")
    state = os.path.join(root, ".vep") + os.sep
    inp = inp or {}
    if tool in EDIT_TOOLS:
        path = inp.get("file_path") or inp.get("notebook_path") or ""
        full = os.path.realpath(path if os.path.isabs(path) else os.path.join(cwd or root, path))
        if (full + os.sep).startswith(state):
            return "VEP state under .vep/ is managed by VEP and must not be edited by hand."
    elif tool == "Bash":
        cmd = str(inp.get("command") or "")
        if ".vep" in cmd and WRITE_HINT.search(cmd):
            return "This command appears to modify .vep/ state; VEP state must change only through VEP itself."
        if DIRECT_VEP.search(cmd):
            return "Run evaluation through the vep MCP tools (authority is set by the operator); direct `vep run|evaluate|certify` from the agent shell is blocked."
    return None


def main() -> None:
    try:
        data = json.load(sys.stdin)
    except Exception:
        print("vep_guard: unreadable hook input; no decision", file=sys.stderr)
        return
    reason = decide(data.get("tool_name"), data.get("tool_input"), data.get("cwd"), os.environ.get("CLAUDE_PROJECT_DIR"))
    if reason:
        json.dump({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                          "permissionDecisionReason": reason}}, sys.stdout)


if __name__ == "__main__":
    main()
