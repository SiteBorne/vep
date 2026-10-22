# Readiness profiles

There is **no umbrella `PRODUCTION_READY`**. Each profile below is computed by `scripts/profile_check.py` from its *own* prerequisite list; no profile inherits another's result, and a prerequisite
that could not be established (missing tool, no authorization, evidence not produced) is `UNVERIFIED` and keeps the profile at `NO`. Results for a given commit are in `docs/production-profiles.json`
and summarised in [PRODUCTION_QUALIFICATION_REPORT](PRODUCTION_QUALIFICATION_REPORT.md). `tests/test_profiles.py` tests the engine itself.

| Profile | Meaning | Prerequisites (each must PASS) |
|---|---|---|
| `CORE_PROTOCOL_CONFORMANT` | The Core Profile of [CORE_PROTOCOL_SPEC](CORE_PROTOCOL_SPEC.md) is implemented and agrees with the frozen vectors in two independent implementations | spec present and naming the protocol version; suites 1.0/1.1/1.2 regenerate byte-identically; Python agrees with every vector; Node agrees with every vector; every authorized/derived reason code has a vector |
| `CORE_PROTOCOL_PRODUCTION_READY` | The Core Profile's verification semantics meet their production criteria (scope: the specification and its verifiers, not hosting and not hostile code) | all of the above, **plus** trust-anchor/trust-policy tests (including the regression that a self-authorizing v1 bundle is never `AUTHORIZED`); derivation-chain tests; fault-injection tests and map; adversarial/hardening/execution tests; compatibility, migration, candidate and controller tests |
| `REFERENCE_IMPLEMENTATION_READY` | The Python package is releasable as software | full suite with no failures; fault injection; compatibility/migration; built wheel installs in a fresh venv with CLI, MCP, A2A entry points and packaged skill assets; **hosted CI green on the exact HEAD** |
| `MCP_INTEGRATION_READY` | Local stdio MCP server | official-client tests (tool surface, schemas, authority, idempotency, bounds, hostile arguments, full flow with independent verification); Agent SDK contract/drift test; no remote transport reachable |
| `A2A_INTEGRATION_READY` | Authenticated JSON-RPC A2A agent | tests with the official client and a raw client (card, lifecycle, malformed, wrong version, unauthorized, duplicate, expired, cancel); lost-response and unknown-capability tests |
| `CLAUDE_INTEGRATION_READY` | Claude Code installs and uses VEP | installer tests; `claude plugin validate`; client discovery; **a recorded live tool call from a real Claude Code session** |
| `ISOLATED_EXECUTION_READY` | The gated Docker+gVisor path ran on hosted infrastructure | recorded isolation evidence is current: no isolation-critical file changed since the revision it was validated on |
| `UNTRUSTED_EXECUTION_READY` | Hostile code may be evaluated (not claimed anywhere) | external security review; escape testing |
| `PUBLIC_ANNOUNCEMENT_READY` | A release exists that can be announced | candidate version set; hosted CI green on HEAD; candidate release artifacts verified; built wheel installs |

Scope notes recorded with the profiles: MCP readiness is for stdio only; A2A readiness is for authenticated loopback JSON-RPC (no public-internet qualification, no push notifications);
the Core production profile says nothing about running untrusted code. Both verifiers were written by the same author from the same text, and no external review of any kind has taken place.
