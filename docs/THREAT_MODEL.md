# Threat Model

See [SECURITY_ARCHITECTURE.md](SECURITY_ARCHITECTURE.md) for the trust levels and [SECURITY_REVIEW.md](SECURITY_REVIEW.md) for findings with regression tests.

## Scope and honesty statement

VEP 0.4.0a1 is a local developer preview. **It provides no security boundary for hostile code unless an `ISOLATED_VERIFIED` result was actually produced**, and no such result exists for the development host. The default and only exercised mode is `TRUSTED_LOCAL`: the operator explicitly authorizes running *code they trust* in an ordinary subprocess with their own permissions. The Docker + gVisor adapter (capability detector, T1–T12 verification matrix, isolated evaluator path) is implemented and decision-tested with a stub, but has not been executed against a real runtime (`ISOLATION_UNVERIFIED`).

## Assets

| Asset | Where | Protection |
|---|---|---|
| Signing key | `.vep/keys/signing.pem` (0600, dir 0700) | Never staged, never printed; env scrubbed; digest re-checked after local runs. **Readable by trusted-local candidate code.** |
| Acceptance policy | CAS, bound by id into objective/evidence/certificate | Frozen by digest; protected patterns; required-test digests; `required_trust` |
| Evidence/certificates | CAS + DB | Ed25519 signatures; trust level and evaluator id inside the signed bytes |
| Budgets | SQLite | `BEGIN IMMEDIATE`; idempotency keys; append-only ledger |
| Source identity | Snapshot manifests | Content addressed; materialized from CAS; `O_NOFOLLOW` reads |

## Actors
* **Candidate author (agent)** — untrusted regarding what its change says. In trusted-local mode it is *also* trusted not to attack the host; that trust is the operator's explicit decision.
* **Operator** — configures objectives/policies, grants trusted-local authorization, chooses `--require-trust`.
* **Local attacker with state-directory access** — can read/alter the key and DB; defeats everything (out of scope; mitigated only by 0700 permissions).

## Threats

| # | Threat | Mitigation | Residual |
|---|---|---|---|
| T1 | False green (zero tests, all skipped, bad report) | `validate_report`, required-suite execution check, minimum-pass rule | none known |
| T2 | Candidate rewrites test configuration or shadows the runner | protected patterns, digest-pinned required tests, shadow-name denial, `python -I`, append-only `sys.path` | configuration channels not in the pattern list |
| T3 | Candidate mutates the tree during evaluation | read-only staging + post-run tree hash | host-wide effects in trusted-local mode |
| T4 | Candidate reads or alters VEP state | staging outside the workspace, scrubbed env, key digest check | **reads are not prevented in trusted-local mode** |
| T5 | Candidate forges the report | stderr cross-check, exit-status and digest checks | consistent double forgery in-process (why the mode is trusted-local) |
| T6 | Trust relabeling (local evidence presented as isolated) | schema-v2 consistency rules inside signed bytes; certificate must match evidence; verifier `--require-trust` | none |
| T7 | Silent downgrade when isolation is missing | `IsolationUnavailable` before any state change; no fallback path | none |
| T8 | Stale/forged/altered certificates | exact-snapshot binding, signatures, immutable rows | key compromise; no rotation |
| T9 | Budget bypass, double spend, oversubscription, overflow | mandatory account, idempotency, range limits | provider usage is caller-supplied |
| T10 | Cache poisoning | Action-id keyed, signature re-verified | non-deterministic tests |
| T11 | Readiness misrepresentation in audited products | policy audits | only what the rules express |
| T12 | Composition interference | composition = new snapshot needing its own evidence | depends on test coverage |
| T13 | Container option injection | strict mount-path allow-list (SR-03) | runtime unverified |
| T14 | Path traversal, symlink escape, TOCTOU | strict grammar, symlink rejection, `O_NOFOLLOW` | none known |
| T15 | Canonicalization ambiguity | strict parser, no floats, per-type versioned domains | none |
| T16 | Supply-chain / CI compromise | SHA-pinned actions, least privilege, artifact audit, provenance record | hosted behavior unverified |
| T17 | Secrets in repo history or artifacts | tree + history + artifact scans in the gate | pattern coverage |

## Out of scope
Network attackers, multi-tenant isolation, side channels, key lifecycle management, resource exhaustion beyond timeouts/output caps, third-party dependency internals.

## Distributed boundary
Single host by design. Leases/fencing, replicated logs and attested remote executors (cf. Bazel Remote Execution API; Google Omega's optimistic concurrency) are future work.
