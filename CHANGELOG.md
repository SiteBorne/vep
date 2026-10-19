# Changelog

## Unreleased (0.5.0b1 work)

* Added: durable execution controller, agent adapters, build actions, dependency graph, usage provenance, frozen conformance suite 1.0 with an independent Node verifier.
* **Compatibility note (C22):** object id, digest, timestamp and decimal patterns now use `\Z` and ASCII digits. Previously a value with a trailing newline (e.g. a digest followed by `\n`) or non-ASCII digits in a timestamp passed validation. VEP never produced such values; objects containing them are now rejected. Found while writing the independent verifier.
* **Security fix (found by evaluating an external project):** the protected unittest runner now places candidate import roots before site-packages and fails closed (`CODE_UNDER_TEST_SHADOWED`) when a module the staged tree provides was loaded from elsewhere. Previously an installed copy of the project could be tested instead of the candidate, yielding a false green. Runner digest changed, so earlier cached evidence no longer matches.
* Policy: `evaluator.allow_module_names` (explicit, unittest only) and `make_policy(required_exclude=...)`.
* `TokenReceipt.usage_source` gained `caller_supplied` (backward-compatible enum extension). Database schema 3 adds job and build tables (additive).


All notable changes. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions: [PEP 440](https://peps.python.org/pep-0440/).

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
Trusted-local mode is not a security boundary; isolation unverified; no PyPI release yet; hosted CI/attestations not yet executed. See `docs/RELEASE_NOTES.md`.

## [0.3.0]
Internal MVP (not publicly released). See `docs/RELEASE_BASELINE.md`.
