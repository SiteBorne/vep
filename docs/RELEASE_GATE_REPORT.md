# Release Gate Report

**Decision: GO**  ·  package `vep-protocol 0.4.0a1`  ·  source `1256ee6fd606a2b3733ee48d0fdc4367e2c7f51d`

Generated 2026-10-19T17:54:21Z on macOS-15.6-arm64-arm-64bit-Mach-O / Python 3.14.7. Produced by `scripts/release_check.sh`; machine-readable twin: `release-gate.json`.

## Capabilities

| Capability | Status |
|---|---|
| PUBLIC_DEVELOPER_PREVIEW | PASS |
| UNTRUSTED_EXECUTION_ISOLATION | UNVERIFIED |

## Gates

| Gate | Required | Status | Detail |
|---|---|---|---|
| SOURCE_INTEGRITY | yes | **PASS** | clean tree at 1256ee6fd606, version 0.4.0a1 |
| TEST_DISCOVERY | yes | **PASS** | unittest=312 pytest=312 |
| UNIT_TESTS | yes | **PASS** | unittest ran=312 rc=0 skipped=0; pytest passed=312 failed=0 skipped=0 |
| ADVERSARIAL_TESTS | yes | **PASS** | adversarial+trust+isolation+release regression: ran=92 rc=0 |
| INVARIANT_TESTS | yes | **PASS** | invariant suites: ran=84 rc=0 |
| DEMO | yes | **PASS** | rc=0 |
| SIMULATION_REPRODUCIBILITY | yes | **PASS** | identical=True |
| PACKAGE_BUILD | yes | **PASS** | vep_protocol-0.4.0a1-py3-none-any.whl, vep_protocol-0.4.0a1.tar.gz; twine check rc=0 Checking <repo>/dist/vep_protocol-0.4.0a1-py3-none-any.whl: [32mPASSED[0m Checking <repo>/dist/vep_protocol-0.4.0a1.tar.gz: [32mPASSED[0m  |
| PACKAGE_INSTALLATION | yes | **PASS** | wheel and sdist install cleanly; pip check ok |
| CLI_SMOKE_TEST | yes | **PASS** | 18 clean-room checks; failing: [] |
| ARTIFACT_INTEGRITY | yes | **PASS** | checksums verified; no keys/db/env/machine paths/secrets in wheel or sdist |
| SECRET_SCAN | yes | **PASS** | 0 findings; working tree, all reachable history and release artifacts scanned (values are never printed) |
| SECURITY_REVIEW | yes | **PASS** | 18 findings recorded, none open; each fixed/mitigated finding has an existing regression test |
| DOCUMENTATION | yes | **PASS** | 24 required docs present; no unsupported claims; quickstart executed against installed wheel |
| PROTOCOL_COMPATIBILITY | yes | **PASS** | frozen-fixture compatibility: ran=13 rc=0 |
| PYTHON_COMPATIBILITY | yes | **PASS** | tests run from the extracted sdist against the installed wheel on every supported interpreter |
| RELEASE_PROVENANCE | yes | **PASS** | local build record written and re-verified; workflows pass static checks (SHA-pinned, least-privilege, no pull_request_target); hosted attestation NOT_RUN |
| OPTIONAL_ISOLATION | no | **UNVERIFIED** | no VEP_ISOLATION_IMAGE configured; capability report only |
| DEPENDENCY_AUDIT | no | **PASS** | No known vulnerabilities found |
| HOSTED_CI | no | **NOT_RUN** | requires the public GitHub repository; not executed locally |
| HOSTED_ATTESTATION | no | **NOT_RUN** | requires the public GitHub repository; not executed locally |

`PASS` = executed and succeeded in this run. `UNVERIFIED`/`NOT_RUN` are never green. Optional gates never turn a NO_GO into a GO and never upgrade a capability claim.
