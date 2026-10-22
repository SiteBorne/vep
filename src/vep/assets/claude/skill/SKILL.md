---
name: vep
description: Verify a code change with VEP (Verified Evolution Protocol) through the vep MCP server - register a change against a frozen baseline, run or inspect protected evaluation, explain which invariant failed, and retrieve exact evidence or a portable bundle. Use when asked to verify, certify, or prove a change, to explain a VEP failure, or to fetch VEP evidence.
allowed-tools: mcp__vep__vep_status mcp__vep__vep_job_status mcp__vep__vep_candidate_state mcp__vep__vep_budget_status mcp__vep__vep_explain_failure mcp__vep__vep_read_artifact
---

# Using VEP

VEP records what was actually checked for a change. You cannot declare anything certified: only VEP's protected evaluation can, and only when the operator enabled it. Never claim "verified" unless a tool result says so, and say which trust level it names.

Start every task with `vep_status`. It reports the enabled authority (`read`, `register`, `evaluate`, `export`) and a next action. If a tool answers `VEP_E_NOT_AUTHORIZED`, the operator has not granted that authority: tell the user, do not look for a way around it (no editing `.vep/`, no running `vep` CLI evaluation from Bash).

Pick the workflow:

- Register and verify a change: [workflows/register-and-verify.md](workflows/register-and-verify.md)
- Explain a failed invariant: [workflows/explain-failure.md](workflows/explain-failure.md)
- Retrieve exact evidence or a portable bundle: [workflows/retrieve-evidence.md](workflows/retrieve-evidence.md)
- Error codes and what they mean: [reference/errors.md](reference/errors.md)

Rules that always apply:

1. Results are compact. Logs are fetched by handle with `vep_read_artifact` in pages; do not fetch more than you need.
2. Writing tools take an `idempotency_key`; reuse the same key when retrying so a retry cannot double-register.
3. `vep_verify_certificate` checks against this workspace's own keys. It is not an external attestation. A third party needs the exported v2 bundle and their own trust policy.
4. A passing result with trust level `TRUSTED_LOCAL` means the candidate's tests ran unisolated on the operator's host. Report that, not "secure".
