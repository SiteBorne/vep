# Implementation Status (0.4.0a1)

Categories (RFC rule R10): **IMPLEMENTED** (code exists), **TESTED** (automated test observed passing in this build), **SIMULATED** (synthetic model, not a measurement), **DESIGNED** (specified, not built), **UNVERIFIED** (could not be exercised here).

| Capability | Status | Notes |
|---|---|---|
| Canonical serialization, domain-separated identities | IMPLEMENTED, TESTED | `canonical.py`, `objects.py` |
| 13 protocol object types | IMPLEMENTED, TESTED (construction/validation) | Not every type has a CLI producer (e.g. `OptimizationExperiment`, `Observation` are schema-only) |
| CAS | IMPLEMENTED, TESTED | |
| Snapshots, diff, materialize | IMPLEMENTED, TESTED | Files only; empty directories ignored |
| Candidate state machine | IMPLEMENTED, TESTED | SQL triggers enforce certification guards |
| Work claims / composition | IMPLEMENTED, TESTED | Path-level three-way merge only |
| Budgets (org/project/objective/candidate/operation) | IMPLEMENTED, TESTED | Single host; thread-level concurrency tested, not multi-process |
| Token accounting | IMPLEMENTED, TESTED | Usage is caller-supplied, unauthenticated |
| Context manifests | IMPLEMENTED, TESTED | Token counts approximate (bytes/4); keyword retrieval experimental |
| Protected evaluator (unittest, pytest) | IMPLEMENTED, TESTED | **Trusted-local only; no security isolation** |
| Evidence signing, certificates, verification | IMPLEMENTED, TESTED | Single local key; no rotation |
| Static readiness audits | IMPLEMENTED, TESTED | Policy-driven rule set |
| Failure matrix F01–F20 | IMPLEMENTED, TESTED | F12–F16 via audits; F17/F18 via honesty/fail-closed tests; F19/F20 local analogues |
| Routing policy engine | IMPLEMENTED, TESTED | Offline; no model calls; no commercial benchmarks |
| Cache economics | IMPLEMENTED, TESTED | |
| Math foundations (retry, Little, BH, false acceptance) | IMPLEMENTED, TESTED | |
| Synthetic simulation | IMPLEMENTED, TESTED, SIMULATED | Illustrative parameters only |
| Git inspection | IMPLEMENTED, TESTED | Read-only; needs `git` |
| Docker+gVisor plan + probe | IMPLEMENTED, TESTED (plan/probe logic with stubs and the real host probe) | |
| Trust levels (TRUSTED_LOCAL / ISOLATED_VERIFIED / UNVERIFIED), schema v2 evidence/certificates, migration | IMPLEMENTED, TESTED | `trust.py`, `migrations.py`, `tests/test_trust.py`, `tests/test_compat.py` |
| Isolation capability detector, T1–T12 matrix, attestation, isolated evaluator path | IMPLEMENTED, TESTED (decision logic with a stub docker CLI) | **UNVERIFIED against a real runtime**: macOS host, Docker daemon down, no `runsc`; matrix results are `NOT_RUN` |
| Release gate, clean-room test, secret/artifact/claim scans, workflows | IMPLEMENTED, TESTED locally | Hosted CI/CodeQL/attestation NOT_RUN |
| gVisor / container escape resistance | **UNVERIFIED** | No runtime available on the build host; no claim is made |
| Durable execution controller (leases, fencing, recovery, `vep run`/`vep jobs`) | IMPLEMENTED, TESTED (incl. 4 real processes) | Single-host SQLite; cancel is cooperative; no scale claim |
| Distributed coordination, remote execution, merge queues | DESIGNED only | |
| Live LLM / provider integration | OUT OF SCOPE | |
| Production readiness | **NOT CLAIMED** | |

## Known limitations

1. Trusted-local mode lets candidate code read anything the invoking user can read, including the signing key, and forge the test report.
2. Compute cost per evaluation is a declared flat number, not a measurement.
3. `random`-based simulation depends on CPython's documented seeding of `random.Random` for string seeds; reproducibility was verified on this platform only.
4. No key rotation, transparency log, or external signer.
5. Snapshots ignore empty directories and non-regular files by rejecting them.
6. Sources cited in `EVIDENCE.md` were not re-fetched online during this build; see its verification column.
