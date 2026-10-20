# VEP as an MCP server (local stdio)

`vep-mcp` exposes VEP to any MCP client over **stdio**. It is a thin adapter over `vep.services`; no verification logic lives in it. Install with
`pip install 'vep-protocol[mcp]'` (official `mcp` Python SDK ≥ 2.3; negotiated protocol revision in the tests: `2026-07-28`).

```bash
vep-mcp --root /path/to/project --authority read,register            # default is read only
vep-mcp --root /path/to/project --authority read,register,evaluate,export --trusted-local-execution
```

## Authority is the operator's, not the caller's
Authority is fixed by flags when the server starts: `read`, `register`, `evaluate`, `export`. No tool accepts an authority, a trust level, a verdict
or a "certified" flag; extra arguments are ignored or rejected, and a call without the needed authority returns `VEP_E_NOT_AUTHORIZED` and changes nothing
(`tests/test_mcp_server.py::test_authority_is_enforced_by_the_operator_not_the_caller`). `vep_evaluate` additionally needs `--trusted-local-execution`, the operator's
acknowledgement that candidate code then runs **unisolated on this host**; without it the error is `VEP_E_EVALUATION_DISABLED`. Certification happens only inside the
controller after a protected evaluation.

## Tools (12; descriptions are the schemas the model sees)
| Tool | Needs | Purpose |
|---|---|---|
| `vep_status` | read | versions, counts, enabled authority, next action |
| `vep_objective_create` | register | freeze the current tree and tests as the baseline; open a budget (idempotency key) |
| `vep_candidate_register` | register | register the working tree as a candidate (stays `PROPOSED`) |
| `vep_evaluate` | evaluate + trusted-local | queue the protected evaluation (idempotent per candidate) |
| `vep_reuse_evidence` | evaluate | exact-input evidence reuse: issue a DerivedAttestation if identical evidence exists; executes nothing ([EVIDENCE_REUSE](EVIDENCE_REUSE.md)) |
| `vep_job_status` | read | job state with a bounded result and the next action |
| `vep_candidate_state` | read | status, evidence and certificate ids |
| `vep_verify_certificate` | read | verify against **this workspace's own keys** (assurance `WORKSPACE_KEY_REGISTRY`) |
| `vep_export_evidence` | export | write a portable v2 bundle under `.vep/exports`; returns path, size, sha256 |
| `vep_budget_status` | read | limit, reserved, settled, uncertain, available |
| `vep_explain_failure` | read | failed invariant, remedy, bounded preview of failing tests, log handles |
| `vep_read_artifact` | read | page through a stored log by its 64-hex handle (only handles referenced by this workspace's evidence) |

Resources: `vep://version`, `vep://objective/{id}`, `vep://policy/{id}`, `vep://candidate/{id}`, `vep://history/{candidate_id}`, `vep://evidence/{id}`, `vep://certificate/{id}/verification`.

## Output contract
Every result is a compact object with stable ids, a `next_action` and handles for anything large. Logs, test ids and traces are fetched explicitly and paginated
(`vep_read_artifact`, `limit ≤ 4000`); lists are capped at 200. Storage is lossless; only the *presentation* is bounded. Errors are `isError` results with
`{"error": {"code", "message", ...}}` and one of `VEP_E_INVALID_ARGUMENT`, `NOT_FOUND`, `NOT_AUTHORIZED`, `EVALUATION_DISABLED`, `STATE`, `BUDGET`, `POLICY`, `VERIFICATION_FAILED`,
`ISOLATION_UNAVAILABLE`, `INTERNAL` (the last never leaks internals). Writing tools take an `idempotency_key`; the same key returns the stored result (`idempotent_replay: true`).

## Measured (stdio, this host, no model)
`tools/list` is 7,170 bytes (≈1.8k tokens by the bytes/4 *estimate* used elsewhere in VEP; **not** provider usage); `vep_status` answers in a median 40.6 ms over 60 calls
(`benchmarks/results/mcp-context-profile.json`). Tool definitions are static, so a client's prompt-cache prefix is not invalidated by VEP between calls; whether a given
provider actually reports a cache hit is not measured here.

## Transports and qualification
Only stdio is offered. `--transport http` exits 2. Remote HTTP write access would need authentication, Origin validation, request limits and OAuth handled correctly; none of that is
implemented, so none is claimed. The official MCP conformance tooling drives HTTP servers and therefore does not apply; stdio behaviour is exercised with the official MCP client
(`tests/test_mcp_server.py`, `tests/test_agent_sdk.py`).
