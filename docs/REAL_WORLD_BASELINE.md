# Real-World Baseline (start of the v0.5.0b1 effort)

Observed on the build host (macOS, Darwin 24.6, Python 3.14.7). Everything below was executed, not assumed.

| Item | Observed |
|---|---|
| Starting commit | `551612a` on `main`, working tree clean, tag `v0.4.0a1` (unmodified) |
| Package / protocol | `0.4.0a1` / `0.3` (canonical format `VEP-C1`, evidence format 2) |
| Database schema | 2 at baseline; **3** after Phase B (adds `jobs`, `job_events`; additive, `CREATE IF NOT EXISTS`) |
| Object identity | domain-separated SHA-256 per type; 13 object types (`Evidence`, `Certificate` at schema v2, rest v1) |
| Tests at baseline | `scripts/verify.sh` passed end to end; 312 pytest tests pass in `.venv` |
| System `python3` | has no `cryptography`/`pytest`; use `.venv` (a bare `unittest discover` there errors, which is an environment fact, not a regression) |
| Hosts tools | git yes; docker CLI yes but **daemon not running** (colima context), no `runsc`; **go absent**; ollama 0.40.3 with one local model (`deepseek-r1:32b`); `claude` CLI present |

## Existing security boundaries
Trusted-local evaluator (explicit authorization string, `-I` subprocess, scrubbed env, false-green detection, key-digest and tree-mutation checks): **no isolation**. Docker+gVisor path with fail-closed attestation: decision logic tested against a stub; **never exercised against a real runtime** (`ISOLATION_UNVERIFIED`).

## Capability classification at baseline
* IMPLEMENTED + LOCALLY_VERIFIED: canonicalization, CAS, snapshots, candidate state machine, budgets, token receipts (caller-supplied usage), context manifests, protected evaluator, signed evidence/certificates, audits, routing engine, cache economics, Git inspection.
* SIMULATED only: cost/reliability simulation (`vep simulate`).
* Schema only: `Observation`, `OptimizationExperiment`; `BudgetLease`/`TokenReceipt` partially exercised.
* NOT_IMPLEMENTED: durable orchestration, agent adapters, build actions beyond the evaluator, dependency graph, REAPI, independent verifier, real benchmarks, hosted CI evidence.
* UNVERIFIED: gVisor isolation, live agent execution, hosted CI/CodeQL.

## Release blockers for the v0.5.0b1 target (at baseline)
Everything under NOT_IMPLEMENTED above. Progress is tracked in `IMPLEMENTATION_PROGRESS.md`.
