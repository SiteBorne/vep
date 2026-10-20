# Beta scope: what `0.5.0b1` claims, and what it does not

Every row is backed by an executed test, report or run listed in `launch-gate.json`; nothing here is aspirational.

## Supported claims (verified behaviour)
| Capability | Evidence | Limits stated up front |
|---|---|---|
| Durable local execution controller (leases, fencing, recovery, idempotent enqueue, budget admission) | `tests/test_controller.py` including 4 real processes; scaling record `docs/CONTROLLER_SCALING.md` | single host, SQLite; measured only up to 16 worker processes on tiny jobs; no distributed-scale claim |
| Verified candidate state transitions | state machine and SQL triggers; `tests/test_candidates.py`, adversarial tests | - |
| Tool and build execution; deterministic build-action cache | `tests/test_builds.py`, `tests/test_cli_build.py` | trusted-local; cache applies only to declared deterministic actions; a cache hit yields no certificate |
| Agent-adapter interface | `tests/test_agents.py` | adapters never certify; interface v1 |
| Local Ollama interoperability | one recorded run with `qwen2.5-coder:7b` (`docs/live_agent_run.json`) | **one run on a toy task: not a reliability or quality benchmark**; other agents and models untested |
| Bounded local concurrency | multi-process fencing tests | see controller row |
| Dependency-aware work claims and local composition | `tests/test_depgraph.py` | static Python imports and declared edges only; **path-level composition is not general semantic merge verification**; a clean merge always needs full evaluation |
| Exact-only evidence reuse | `depgraph.evidence_validity`; `EXACT_ONLY` | reuse across different candidates with identical snapshots is not implemented |
| Cryptographically verifiable evidence and certificates | Ed25519 over DSSE-style envelopes; `tests/test_certificates.py` | one local key per workspace, no rotation, no transparency log |
| Independent conformance | suite 1.0 (119 vectors), reference verifier and a Node verifier agreeing | the second implementation has the same author; exercised objects and operations only (canonicalization, identity, envelopes, Evidence/Certificate bundle verification) |
| Transactional token and budget accounting | `tests/test_budgets.py`, `tests/test_tokens.py`, `tests/test_agents.py` | usage provenance is labelled; tool-claimed usage is unauthenticated |
| Real repository dogfooding | `docs/dogfood/`, `docs/external/` | trusted-local; two small dependency-free external projects; the VEP-on-VEP change was authored interactively |
| Trust-aware evaluation | `TRUSTED_LOCAL` / `ISOLATED_VERIFIED` / `UNVERIFIED`; no automatic fallback | - |
| Offline operation | no network is needed after installation; the core never calls a model | - |
| Gated isolation path | hosted-runner matrix T1-T12 passed once (`docs/isolation/`) | not escape-tested; runtime identity from `docker inspect` only; unverified on other hosts |

## Explicitly not claimed
* Universal support for arbitrary agents, languages or build systems. Python projects with the `unittest` or `pytest` evaluators only; the isolated path supports `unittest` only and needs a Linux Docker host with gVisor.
* That one successful local model invocation measures reliability or quality.
* Distributed or "thousand-agent" scale from a 16-process test.
* Semantic correctness of composed changes from a path-level merge.
* That the offline routing and cache calculations are a deployed model-selection service. They are inputs-in, decision-out calculators with illustrative parameters; VEP never calls a model provider.
* Safe execution of untrusted or hostile code, immunity to sandbox escape, or production-grade security.
* Speed: measured results show no speed advantage over running the tests directly ([REAL_WORLD_RESULTS](REAL_WORLD_RESULTS.md)).
* Production readiness.
