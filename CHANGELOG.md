# Changelog

All notable changes. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions: [PEP 440](https://peps.python.org/pep-0440/).

## [0.5.0b1] - UNRELEASED (date set when tagged)
Public beta candidate. Protocol version unchanged (0.3); database schema 2 → 3 (additive); object schemas unchanged (Evidence/Certificate 2, others 1). Scope and limits: `docs/BETA_SCOPE.md`, `docs/RELEASE_NOTES.md`.

### Added
- **Durable execution controller** (SQLite jobs, leases, fencing tokens checked inside every committing transaction, bounded retries, crash recovery, idempotent enqueue, budget admission): `vep run`, `vep jobs`.
- **Agent adapters**: versioned `AgentAdapter` interface, allowlisted structured-subprocess adapter, Ollama-compatible local adapter; usage provenance labels (`provider_reported`, `locally_measured`, `caller_supplied`, ...). Adapters never certify.
- **Build actions** with a content-addressed, verified result cache and determinism check: `vep build run|stats`.
- **Dependency graph** (static imports, declared build/contract edges), claim relations and scheduling, composite candidates, EXACT_ONLY evidence validity: `vep graph`, `vep compose`.
- **Conformance**: frozen suite 1.0 (119 vectors), portable certificate bundles, a reference verifier and an independent Node verifier: `vep conformance export|verify|vectors`, `scripts/conformance_check.sh`, `docs/CONFORMANCE.md`.
- Hosted-runner **gVisor isolation workflow** and end-to-end script; revalidation record in `docs/isolation/`.
- Launch gate (`scripts/launch_check.py`), claims traceability (`scripts/check_claims.py`), dogfood and external-project evaluation scripts, controlled benchmark harnesses, public docs (WHY_VEP, COMPARISON, SECURITY_LIMITATIONS, ROADMAP, FAQ, BETA_SCOPE).
- Policy: `evaluator.allow_module_names` (explicit, unittest only), `make_policy(required_exclude=...)`.

### Changed / compatibility notes
- **Compatibility (C22):** object id, digest, timestamp and decimal patterns now use `\Z` and ASCII digits. Values with a trailing newline or non-ASCII digits are rejected; VEP never produced such values. Found while writing the independent verifier.
- `TokenReceipt.usage_source` gained `caller_supplied` (backward-compatible enum extension).
- The protected runner's digest changed (see Security), so cached evidence from earlier builds no longer matches.

### Security
- **Fixed false green:** the unittest runner now places candidate import roots before site-packages and fails closed (`CODE_UNDER_TEST_SHADOWED`) when a module the staged tree provides was loaded from elsewhere. Previously an installed copy of the project could be tested and certified instead of the candidate.
- **Fixed:** the isolation pinned-image check now compares repository and digest (Docker's `RepoDigests` omit the tag); previously a tagged pin never matched on a real runtime (it failed closed).
- Private vulnerability reporting confirmed enabled; `SECURITY.md`/`SUPPORT.md` use verified GitHub mechanisms.

### Known limitations
See `docs/SECURITY_LIMITATIONS.md` and `docs/BETA_SCOPE.md`. Trusted-local mode is not a security boundary; isolation verified on one hosted run only; no external audit; no PyPI release.

## [0.4.0a1] - 2026-10-19
Initial public developer preview (prerelease). Protocol version unchanged (0.3); see `docs/COMPATIBILITY.md`.

### Added
- **Trust levels** `TRUSTED_LOCAL`, `ISOLATED_VERIFIED`, `UNVERIFIED` recorded in signed Evidence and Certificates (object schema v2), with cross-field consistency rules, evaluator identity and execution-environment records; `required_trust` policy field; `vep verify --require-trust`.
- Report cross-check against the runner's own output; parent-derived evidence.
- **Isolation**: `vep isolation detect|verify`, T1–T12 verification matrix and attestation, isolated evaluator path (`vep evaluate --isolated --image … --attestation-file …`). Real-runtime execution is **UNVERIFIED** (not run on the development host).
- Versioned decoding (`UNSUPPORTED_SCHEMA_VERSION`), database schema 2 with validated idempotent migration, `vep version`.
- `--field` and `--budget` conveniences; tested `docs/QUICKSTART.md`.
- Release engineering: `scripts/release_check.sh` (17 required gates → `release-gate.json`, `docs/RELEASE_GATE_REPORT.md`), clean-room installer test, secret/history/artifact scans, claim policy, local provenance record, SHA-pinned least-privilege GitHub workflows (CI, release, CodeQL), Dependabot.
- Documents: SECURITY, CONTRIBUTING, CODE_OF_CONDUCT, SUPPORT, SECURITY_ARCHITECTURE, SECURITY_REVIEW, COMPATIBILITY, MIGRATIONS, RELEASE_PROVENANCE, RELEASE_BASELINE.
- Benchmarks: cache-hit-rate and routing/budget sensitivity sweeps; measured local timing kept separate from synthetic results.

### Changed
- `certify` refuses schema-v1 evidence; v1 certificates still verify and are classified explicitly (never upgraded).
- `.vep/` is created with mode 0700.
- Evidence/Certificate identities now use schema version 2 (v1 identities are unchanged and still decodable).

### Fixed
- SR-02 state directory permissions; SR-03 docker `--mount` option injection; SR-04 snapshot symlink race (`O_NOFOLLOW`); SR-05 budget overflow traceback; SR-12 missing optional `pytest` handled before execution. See `docs/SECURITY_REVIEW.md`.

### Known limitations
Trusted-local mode is not a security boundary; isolation unverified; no PyPI release yet; hosted CI/attestations not yet executed. See `docs/RELEASE_NOTES_0.4.0a1.md`.

## [0.3.0]
Internal MVP (not publicly released). See `docs/RELEASE_BASELINE.md`.
