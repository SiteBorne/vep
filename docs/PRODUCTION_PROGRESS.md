# Production protocol progress ledger

Format: `BASELINE | COMPLETED | VERIFIED | FAILED | UNVERIFIED | NEXT`. Commit ids are local until pushed.

## BASELINE
`main` at b05bafb: v0.5.0b1 published (GitHub prerelease), hosted benchmark qualification run 39457964415, launch gate on 1e1c5b1 `ANNOUNCEMENT_READY = YES` (nothing posted). Suite before this work: 407 passed.

## COMPLETED
| Item | Where |
|---|---|
| External trust-policy verification (VEP-TP1), rotation/revocation, bundle v2, v1 labelled internal-only; suites 1.1 and 1.2 | `trustpolicy.py`, `conformance.py`, `conformance/node/verify.mjs`, `conformance/vectors/` |
| Build-cache identity/assurance fixes | `builds.py`, `tests/test_cache_identity.py` |
| Shared service layer; MCP stdio server (12 tools, 7 resources) | `services.py`, `mcp_server.py`, [MCP](MCP.md) |
| Claude Code installer, Skill, CLAUDE.md block, guard hook, plugin export | `claude_code.py`, `assets/claude/`, [CLAUDE_INTEGRATION](CLAUDE_INTEGRATION.md) |
| A2A 1.0 adapter | `a2a_server.py`, [A2A](A2A.md) |
| Claude Agent SDK options builder (offline) | `agent_sdk.py` |
| Exact-input evidence reuse (DerivedAttestation, bundle v3, Python + Node verification) | `reuse.py`, [EVIDENCE_REUSE](EVIDENCE_REUSE.md) |
| Stage profile; measured optimization (one candidate rejected on its numbers); MCP context profile | `benchmarks/profile_stages.py`, `benchmarks/mcp_context_profile.py`, [PERFORMANCE_REPORT](PERFORMANCE_REPORT.md) |
| Fault-injection suite and coverage map | `tests/test_fault_injection.py`, [FAULT_INJECTION](FAULT_INJECTION.md) |
| Normative spec, machine-enforced profiles, compatibility matrix, qualification report, quickstart (executed against an installed wheel), announcement drafts | [CORE_PROTOCOL_SPEC](CORE_PROTOCOL_SPEC.md), `scripts/profile_check.py`, [PROFILES](PROFILES.md), [COMPATIBILITY_MATRIX](COMPATIBILITY_MATRIX.md), [PRODUCTION_QUALIFICATION_REPORT](PRODUCTION_QUALIFICATION_REPORT.md), [ANNOUNCEMENT_NEXT](ANNOUNCEMENT_NEXT.md) |

## VERIFIED
482 tests pass (unittest and pytest). Suites 1.0/1.1/1.2: Python and Node agree on 119/160/194. `release_check.sh --skip-matrix`: all gates pass except source integrity (uncommitted at the time) and the skipped Python matrix. Profile results: [production-profiles.json](production-profiles.json).

## FAILED / REJECTED (kept as results)
Object parse cache: about 2.7% end to end, below the preregistered threshold; reverted. Hard-linking staging and mtime-based hashing: rejected for soundness.

## UNVERIFIED
Claude Code live tool use and Skill triggering; `${CLAUDE_PROJECT_DIR:-.}` expansion in Claude Code; Agent SDK live run; hosted CI on the new commit; A2A with an external inspector; the launch gate's dogfood/external evidence is stale for the new sources and must be re-run when a release candidate is cut.

## NEXT (needs the user)
Push for hosted CI; approve the project server in Claude Code or authorize a bounded live run; set the version (proposed `0.6.0b1`) and cut a release candidate; nothing is posted.
