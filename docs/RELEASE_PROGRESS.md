# Release Progress (0.4.0a1)

This file is a resumable work log, **not evidence**. Only the output of `scripts/release_check.sh` (`release-gate.json`) counts.

## COMPLETED
* Baseline observed and committed locally (`docs/RELEASE_BASELINE.md`).
* Trust levels in signed Evidence/Certificate (schema v2), legacy classification, DB schema 2 + migration, `vep version`.
* Isolation capability detector, T1–T12 matrix, attestation, isolated evaluator path (stub-tested; real runtime NOT_RUN).
* Security review with 18 findings; fixes SR-02/03/04/05/12; static guards (SR-14).
* Regression tests R001–R026 (see mapping below), compat fixtures, release/claims/secret/artifact tests.
* Docs: README, QUICKSTART (executed by tests), SECURITY*, COMPATIBILITY, MIGRATIONS, RELEASE_*, CONTRIBUTING, CODE_OF_CONDUCT, SUPPORT, CHANGELOG.
* Release tooling: gate, clean-room installer test, quickstart runner, SHA-pinned workflows (CI, release, CodeQL), Dependabot.

## CURRENT
Release candidate qualified locally (decision GO, see `release-gate.json`); local tag `v0.4.0a1` points at the gated commit. Awaiting a verified GitHub destination and explicit publication authorization.

## FAILED_GATES
Final run: none. Earlier runs failed and were fixed: PYTHON_COMPATIBILITY (a build test depended on a git checkout; scans now fall back to a directory walk), ARTIFACT_INTEGRITY precursor (generated report leaked a machine path into the sdist; paths are scrubbed and generated reports excluded from the sdist).

## NEXT_ACTION
1. Create/identify the public GitHub repository (owner/slug unknown — not guessed).
2. Enable private vulnerability reporting; fill the CONFIGURATION REQUIRED notices (SECURITY.md, CODE_OF_CONDUCT.md, SUPPORT.md).
3. Push `main`, let CI run, then push tag `v0.4.0a1` (release workflow creates the prerelease).
4. Optionally configure PyPI trusted publishing and set `PYPI_TRUSTED_PUBLISHING=true`.

## DECISIONS
* Keep distribution name `vep-protocol` (PyPI name returned HTTP 404 = unclaimed at check time; not reserved).
* Schema versions are per type (Evidence/Certificate → 2); other identities unchanged.
* `ISOLATED_VERIFIED` is attestation-gated and fail-closed; no host fallback anywhere.
* Gate outputs are committed after the tested commit; the tag points at the tested commit.
* No history rewriting; no publication without a verified destination and explicit authorization.

## UNVERIFIED
* Container isolation against a real Docker+gVisor runtime (no Linux daemon with `runsc` on the dev host).
* Hosted GitHub Actions behavior, CodeQL, build attestation, PyPI trusted publishing.
* Windows (unsupported).

## R-test mapping
R001 `tests/test_trust.py` · R002 `test_trust.py` · R003 `test_trust.py::ReportForgeryTests` · R004 `test_compat.py` · R005/R006/R026 `test_compat.py` · R007 `test_compat.py::CliContractTests` · R008/R009/R017 `test_release.py` · R010 `test_certificates.py`, `test_hardening.py` · R011 `test_trust.py`, `test_adversarial.py::F20` · R012 `test_adversarial.py::F03` · R013/R014 `test_execution.py`, `test_adversarial.py::F01/F02` · R015 `test_trust.py` · R016 `test_budgets.py` · R018 clean-room gate `scripts/release/cleanroom.py` · R019/R020 `test_hardening.py` · R021/R024 `test_release.py` · R022 `test_math.py::SimulationTests` · R023 `test_release.py::QuickstartTests` · R025 `test_trust.py::ReportForgeryTests`.
