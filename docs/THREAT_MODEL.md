# Threat Model

## Scope and honesty statement

VEP 0.3.0 is a local reference MVP. **It does not provide a security boundary for hostile code.** The only execution mode implemented is *trusted-local*: candidate code runs in an ordinary subprocess as the invoking OS user, behind an explicit authorization. The Docker + gVisor adapter produces a hardened *plan* and a probe; the container execution pipeline is **not implemented/not exercised** (status `ISOLATION_UNVERIFIED` on the build host).

## Assets

| Asset | Where | Protection |
|---|---|---|
| Signing key | `.vep/keys/signing.pem` (0600) | Not copied into staging; env scrubbed; digest checked after each run. **Not protected from same-user trusted-local code** (it can read the file). |
| Acceptance policy | CAS + objective binding | Frozen by digest; protected patterns; required-test digests. |
| Evidence/certificates | CAS + DB | Ed25519 signatures; chain re-verified; immutable rows. |
| Budgets | SQLite | Transactional; idempotent; triggers for append-only ledger. |
| Source identity | Snapshot manifests | Content-addressed; materialized from CAS. |

## Actors

* **Candidate author (agent)** — untrusted for *what the change says*, but in trusted-local mode trusted not to attack the host.
* **Operator** — configures the objective/policy and grants the trusted-local authorization.
* **Local attacker with DB/CAS write access** — out of scope for integrity of *state*, but certificates still verify cryptographically (the DB row alone cannot forge a signature).

## Threats and mitigations

| # | Threat | Mitigation | Residual risk |
|---|---|---|---|
| T1 | False green (no tests, all skipped, bad report) | `validate_report` + required-suite execution check (F01, F02) | Report is produced in the same process as candidate code (see T5) |
| T2 | Candidate rewrites test config / runner | Protected patterns, frozen required tests, shadow-name denial, `python -I`, append-only sys.path (F03, F04) | Novel config channels not in the pattern list |
| T3 | Candidate mutates tree during run | Read-only staging + post-run re-hash (F05) | A candidate can still escape elsewhere on the host in trusted-local mode |
| T4 | Candidate reads/alters VEP state | Staging outside workspace, scrubbed env, key digest check (F06) | **Reads are not prevented** in trusted-local mode (same OS user) |
| T5 | Candidate forges the test report | Not preventable in-process; mode requires explicit trust | **Open.** Requires a separate-process/host evaluator with attested reporting |
| T6 | Stale/forged/altered certificates | Exact-snapshot binding, signatures, immutable rows (F07, F08) | Key compromise; no rotation/transparency log |
| T7 | Budget bypass / double spend / oversubscription | Mandatory account, `BEGIN IMMEDIATE`, idempotency keys (F09, F10) | Provider usage is caller-supplied and unauthenticated |
| T8 | Cache poisoning | Action-id keyed; re-verified signatures (F11) | Non-determinism in tests can still mislead if cache reuse is enabled by callers |
| T9 | Readiness misrepresentation in audited products | Policy audits (F12–F16) | Only what the policy's rules express |
| T10 | Misrepresenting local runs as isolated | `isolation` field in evidence, `NONE_TRUSTED_LOCAL`, verify output (F17) | — |
| T11 | Silent downgrade when isolation is missing | Fail closed (F18) | Container pipeline unimplemented |
| T12 | Composition interference | Composition is a new snapshot needing its own evidence (F19) | Detection depends on test coverage |
| T13 | Objective/policy swap inheriting evidence | Ids bound in evidence + certificate (F20) | — |
| T14 | Path traversal / symlink escape | Strict path grammar, symlink rejection, CAS digest regex | — |
| T15 | Canonicalization ambiguity | Strict parser, no floats, domain separation | — |
| T16 | Git argument injection / mutation | Argument arrays, read-only subcommand whitelist, hex validation | — |

## Out of scope for 0.3.0

Network attackers, multi-tenant isolation, side channels, supply-chain attacks on dependencies (`cryptography`), key management lifecycle, denial of service beyond simple timeouts/output caps.

## Distributed boundary

Failures requiring distributed coordination (e.g. F19 across hosts) are covered by local analogues only: compare-and-swap versions, work-claim overlap detection, and re-evaluation of compositions. A real implementation needs leases/fencing tokens, a replicated log, and an attested remote executor (cf. Bazel Remote Execution API, Google Omega's optimistic concurrency); none of that exists here.
