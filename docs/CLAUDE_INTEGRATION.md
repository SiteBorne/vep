# Claude Code and Claude Agent SDK integration

VEP stays the authority for source identity, protected verification, budgets and certification. Claude Code (or the Agent SDK) supplies the agent loop and talks to VEP
only through the [MCP server](MCP.md). Nothing here lets an agent certify its own work.

## Claude Code: install, inspect, remove
```bash
pip install 'vep-protocol[mcp]'
vep claude install --root .                     # read + register authority (default); --dry-run first if you like
vep claude install --root . --allow-evaluate    # also evaluate+export, and --trusted-local-execution (candidate code runs unisolated on this host)
vep claude status --root .
vep claude uninstall --root .
vep claude plugin --out ./vep-plugin            # the same skill + server + hook as a Claude Code plugin (load with --plugin-dir)
```
What `install` writes (all recorded with hashes in `.claude/vep-install.json`):
| File | Purpose |
|---|---|
| `.mcp.json` | project-scoped MCP server `vep` with the operator-chosen authority |
| `.claude/skills/vep/` | Skill `vep`: a short `SKILL.md` (workflow router and rules) plus three on-demand workflow files and an error-code reference (progressive disclosure) |
| `CLAUDE.md` (managed block) | five lines: use the skill, never claim "verified" without a tool result, never edit `.vep/` or run `vep run|evaluate|certify` from the shell |
| `.claude/hooks/vep_guard.py` + `.claude/settings.json` hook | PreToolUse guard (below) |

Conflicts and safety: an existing different `vep` server entry, a modified installed file, or an invalid JSON file is a **conflict**: nothing is written (exit 3) unless `--force`, which first copies the
originals to `.claude/vep-backups/<stamp>/`. Uninstall removes only what is still byte-identical to what was installed and reports the rest as kept. The server `command` defaults to
`vep-mcp` if on PATH, else the installing interpreter (`python -m vep.mcp_server`); override with `--mcp-command`. Claude Code asks the user to approve project-scoped servers on first use; VEP does not and cannot approve on the user's behalf.

The Skill's three workflows: **register and verify a change**, **explain a failed invariant**, **retrieve exact evidence / export a bundle**. The guard hook denies edits to `.vep/`, shell commands
that write to it, and direct `vep run|evaluate|certify`. It is **defense in depth, not a security boundary**: an agent with a shell can evade pattern matching, so the operator's authority flags
and (for hostile code) real isolation remain the controls.

## Claude Agent SDK
`vep.agent_sdk.vep_options(root, authority=..., trusted_local=..., max_budget_usd=...)` returns `ClaudeAgentOptions` with the `vep` stdio server, an allow-list and an explicit deny-list derived from the
authority, and the same guard as a `PreToolUse` callback. Permission mode is never set to bypass. It makes no model call. A drift test fails if the allow/deny table stops matching the live server's tools.

## Status of verification (what was and was not actually run)
| Item | Status |
|---|---|
| Installer/uninstaller, conflict and backup handling, guard decisions, plugin layout | tested (`tests/test_claude_code.py`) |
| `claude plugin validate` on the generated plugin | passed with the installed Claude Code 2.1.220 |
| `claude mcp get vep` in an installed project | discovers the server (scope: Project) and reports **Pending approval** |
| Live tool calls and Skill triggering inside Claude Code | **UNVERIFIED**: needs the user's approval of the server and a model run, which was not authorized |
| `${CLAUDE_PROJECT_DIR:-.}` expansion inside Claude Code's MCP launch | **UNVERIFIED** (the server itself is verified with the official MCP client) |
| Agent SDK live run | **NOT_RUN** (would spend API budget; no authorization) |
| Skill description trigger rate, token cost of the Skill | not measured |

To close the gap: approve the server in an interactive `claude` session in an installed project (or authorize a bounded `claude -p` run) and the live evidence can be recorded in `docs/evidence/claude-code-live.json`, which
`scripts/profile_check.py` then reads for `CLAUDE_INTEGRATION_READY`.
