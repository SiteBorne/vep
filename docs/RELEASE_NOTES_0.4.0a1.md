# VEP 0.4.0a1 — Initial Public Developer Preview

**Prerelease. Not production-ready. Not a sandbox.** Package `vep-protocol` 0.4.0a1 · protocol 0.3 · Python ≥ 3.11 · Linux/macOS · Apache-2.0.

## What you can do with it today
* Create exact-source **snapshots**, freeze an acceptance **policy** (digest-pinned required tests), register **candidates**, and push them through a SQLite-enforced state machine.
* **Evaluate** operator-trusted code locally (`TRUSTED_LOCAL`, explicit `--trusted-local-execution`), with false-green detection (zero tests, all skipped, malformed/forged reports, missing required suites, tree mutation, key tampering).
* Get **signed evidence and certificates** bound to snapshot, policy, objective, evaluator identity and trust level; verify them against the live source; see them fail when anything changes.
* Use transactional **budgets**, provider-independent **token receipts**, lossless **context manifests**, offline **model-routing** and **prompt-cache** economics, a seeded **simulator**, read-only **Git** inspection.

## What is new since the internal 0.3.0
Explicit **trust levels** in signed objects (no more unattested isolation strings), versioned object/database schemas with a validated migration, an isolation **capability detector and T1–T12 verification matrix**, five security fixes (SR-02…SR-05, SR-12), a tested quickstart, a one-command release gate, and public CI/release workflows. Details: [CHANGELOG](../CHANGELOG.md), [COMPATIBILITY](COMPATIBILITY.md), [MIGRATIONS](MIGRATIONS.md).

## Trust model in one paragraph
A signature proves who signed. `TRUSTED_LOCAL` evidence additionally says: the operator authorized running this code with their own permissions, with no isolation — so it is only as trustworthy as the code. `ISOLATED_VERIFIED` evidence would additionally carry an attestation that a Docker + gVisor boundary was *observed* to satisfy T1–T12; **no such evidence has been produced on the development host, and this release makes no claim about evaluating untrusted code.** See [SECURITY_ARCHITECTURE](SECURITY_ARCHITECTURE.md).

## Known limitations
1. Trusted-local code can read the signing key and influence its own test report (stderr cross-checks only catch careless forgery).
2. Container evaluation is **UNVERIFIED**: implemented, decision-tested with a stub, never executed against a real runtime (needs a Linux Docker daemon with gVisor).
3. Even inside a verified sandbox the test runner shares a process with the code under test; isolation protects the host and signer, not the truthfulness of in-sandbox outcomes.
4. Token usage is caller-supplied; compute cost per evaluation is a declared flat number.
5. Simulation results use illustrative parameters; they are not measurements of any real model or provider.
6. Single host, single key (no rotation), no Windows support, empty directories are not part of snapshots.
7. Hosted CI, CodeQL and build attestations are configured but **have not run** (the repository was not yet published when this was written). No PyPI release exists.

## Install and verify
See [README](../README.md) and [RELEASE_PROVENANCE](RELEASE_PROVENANCE.md). The release assets are `vep_protocol-0.4.0a1-py3-none-any.whl`, `vep_protocol-0.4.0a1.tar.gz` and `SHA256SUMS`.

## Qualification
The decision and per-gate results of the build that produced these artifacts are in [RELEASE_GATE_REPORT](RELEASE_GATE_REPORT.md) (`release-gate.json`).
