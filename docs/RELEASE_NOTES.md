# VEP 0.5.0b1 — Public Beta (prerelease)

**Prerelease. Not production-ready. Default execution is not isolated.** Package `vep-protocol` 0.5.0b1 · protocol 0.3 · conformance suite 1.0 · database schema 3 · object schemas Evidence/Certificate 2, others 1 · Python ≥ 3.11 · Linux/macOS · Apache-2.0. The previous prerelease, `0.4.0a1`, is unchanged; its notes are in [RELEASE_NOTES_0.4.0a1.md](RELEASE_NOTES_0.4.0a1.md).

## What is new since 0.4.0a1
* A **durable execution controller** (`vep run`, `vep jobs`): leased, fenced, idempotent jobs; crash recovery; budget admission.
* **Agent adapters** and **build actions** with a verified result cache (`vep build`); **dependency graph and composition** (`vep graph`, `vep compose`).
* **Portable certificate bundles** and a **frozen conformance suite** with an independent Node verifier (`vep conformance`, [CONFORMANCE](CONFORMANCE.md)).
* A hosted-runner **gVisor isolation workflow** ([isolation](isolation/README.md), [revalidation](isolation/REVALIDATION.md)).
* Real-world records: VEP verifying its own change, two pinned open-source projects, one local-model run, a pre-declared paired benchmark ([REAL_WORLD_RESULTS](REAL_WORLD_RESULTS.md)).

## Security-relevant fixes in this release
* A **false green**: an installed copy of a project could be tested and certified in place of the candidate. The runner now orders staged roots first and fails closed when a staged module was loaded from elsewhere.
* Strict id/digest/timestamp validation (trailing newline and non-ASCII digits rejected).
* The isolation pinned-image comparison could never match a tagged reference on a real runtime (it failed closed).

## Read before relying on it
[BETA_SCOPE](BETA_SCOPE.md) lists what is and is not claimed. In short: trusted-local execution runs code with your permissions and no isolation; isolation passed its matrix on one hosted run and is not escape-tested; VEP is not faster than running your tests directly; no external audit; one signing key per workspace; one local-model run is not a reliability measurement.

## Install and verify
See [README](../README.md) and [RELEASE_PROVENANCE](RELEASE_PROVENANCE.md). Release assets: `vep_protocol-0.5.0b1-py3-none-any.whl`, `vep_protocol-0.5.0b1.tar.gz`, `SHA256SUMS`, plus a build-provenance attestation.

## Qualification
The decision and per-category evidence for the revision that produced these artifacts are in [LAUNCH_READINESS_REPORT](LAUNCH_READINESS_REPORT.md) and `launch-gate.json`.

## History note
On 2026-10-20 the 38 commits after `551612a` were rewritten so that author and committer are the project account and the automatic co-author trailers were removed. File contents are identical (every git tree matches); only commit ids changed. The old-to-new mapping is `docs/history-correction-map.json`. Evidence records created before that date (`launch-gate.json`, `docs/dogfood/`, `docs/external/`, `benchmarks/results/`, `docs/isolation/`, `docs/launch-logs/`) cite the old commit ids. The published `v0.4.0a1` tag and the earlier commits were not changed.
