# Architecture

```
            +-------------------------------- workspace (project dir) ---------------+
            |  source tree                      .vep/  (never snapshotted/staged)    |
            |                                    cas/ objects (0444)                  |
            |                                    vep.db (SQLite WAL + triggers)       |
            |                                    keys/signing.pem (0600)              |
            +---------------------------------------------------------------------+
 snapshot ─► Snapshot(manifest)  ─► Objective(base, frozen ExecutionPolicy)
 candidate ─► Candidate(snapshot) ─► check_policy ─► reserve budget ─► EVALUATING
                                                         │
                          materialize exact snapshot read-only in temp dir (outside workspace)
                          python -I _runner.py (scrubbed env, timeout, output caps)
                                                         │
                  validate report (no false green) + tree/key integrity ─► Evidence (signed)
                                                         │
                         EVIDENCE_READY ─► Certificate (signed, exact snapshot) ─► verify
```

## Modules
| Module | Responsibility |
|---|---|
| `canonical`, `objects` | VEP-C1 serialization, domain-separated identity, 13 schemas |
| `storage` | CAS (atomic, verify-on-read) |
| `database`, `workspace` | SQLite schema + triggers; workspace layout; object index |
| `snapshots` | manifests, diff, materialization, tree hashing |
| `objectives`, `policies`, `candidates` | frozen policy, evaluator grammar, protected-path checks, state machine, claims, composition |
| `budgets`, `tokens` | hierarchical transactional budgets; provider-independent receipts |
| `context` | lossless budgeted context manifests |
| `execution`, `_runner` | protected evaluator pipeline and false-green validation |
| `evidence`, `certificates` | Ed25519 DSSE-style envelopes; certification and verification |
| `audits` | policy-defined readiness/consistency audits |
| `routing`, `cache_planner`, `simulation` | offline economics and synthetic experiments |
| `git_adapter` | read-only Git inspection |
| `isolation` | Docker+gVisor capability detector, plan, T1–T12 verification matrix, attestation; fail-closed |
| `trust`, `versions`, `migrations` | trust levels and classification; independent version axes; validated DB migration |
| `cli` | `vep` command, stable exit codes (`errors.py`) |

## Trust boundaries
1. **VEP process** (trusted): holds the key, writes state, signs.
2. **Evaluator subprocess** (candidate code): sees only the staged snapshot and a scratch dir. In trusted-local mode it is *not* sandboxed from the OS user (see `THREAT_MODEL.md`).
3. **Optional container** (planned): separate trust boundary; not implemented as an execution path.

## Design choices
* Structural enforcement: protected rules are SQL triggers/CHECKs, closed grammars, and typed validators — not prompt text (R1, R9).
* SQLite chosen for transactional local state; one connection per operation; `BEGIN IMMEDIATE` for writers.
* Money is Decimal/integers everywhere; probabilities in the *simulation* use floats because they drive RNG draws, and are never hashed or billed.
* Fail closed: missing budget, auth, isolation, policy, audit file or report all stop progress without a certificate.

## Distributed boundary
Single-host by design. Distributed analogues (leases/fencing, replicated logs, remote attested execution, global merge ordering) are documented as future work in `IMPLEMENTATION_STATUS.md`.
