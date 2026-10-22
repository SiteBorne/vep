# VEP-on-VEP dogfood runs

Objective: add `vep build run|stats` (CLI over the build-action module) with an explicit authorization gate and tests.
The change (branch `dogfood/vep-build-cli`, 2 files: `src/vep/cli.py`, new `tests/test_cli_build.py`) was written by
Claude Code in an interactive session, **not** by an autonomous agent run. Each run snapshots the base commit, freezes
a policy that protects the existing test files by digest, registers the candidate, runs the full unit suite (367
tests) through the durable controller in trusted-local mode, then verifies and attacks the result. Produced by
`scripts/dogfood.py`; all runs are one machine, one run each, no statistics.

| Run | Outcome | What it found |
|---|---|---|
| `run-0-policy-blocked` | candidate rejected before execution: `RUNNER_SHADOWING:src/vep/cli.py` | VEP's own anti-shadowing rule denied the package name `vep`, so VEP could not evaluate changes to itself. Fixed with an explicit, policy-frozen `evaluator.allow_module_names` (runner-dependency names only, never stdlib, unittest evaluator only). |
| `run-1-tests-not-hermetic` | REJECTED, 16 of 365 tests failed | Tests that spawn `python -m vep` resolved the *installed* VEP, not the staged candidate, plus tests needing `pytest`/`build`. Fixed: child processes now import the source tree under test (`tests/helpers.src_env`); the evaluation interpreter is built without an editable `vep`. |
| `run-2-two-env-failures` | REJECTED, 2 of 367 failed | Demo copied a read-only staged tree and could not create `.vep`; the quickstart test needed an installed `vep` command. Fixed in the base (demo makes its copy writable; quickstart uses a shim to the source under test). |
| `run-3` | **DOGFOOD_PASS**, CERTIFIED (TRUSTED_LOCAL) | 365 passed, 0 failed, 2 skipped (Node-dependent tests; `node` is not on the evaluator's scrubbed PATH). 50.1 s wall, 25.8 s child CPU, 74 MB peak child RSS, 1 job attempt, 0.002 USD flat declared evaluation charge (a declared number, not a measurement). |

Run 3 checks, all from the report:
* **Negative control:** the candidate's new tests run against the *base* implementation of `src/` were REJECTED, so the tests do exercise the candidate's code (49.3 s).
* **Certificate:** verified against the live tree, historically, and as a portable bundle by both the Python reference and the independent Node verifier.
* **Invalidation:** appending a comment to `src/vep/versions.py` after certification made `verify` fail with `SOURCE_CHANGED`, and the evidence reported `SNAPSHOT_CHANGED` (not reusable). Required evaluation after a change stays FULL; the static impact list is a prioritisation hint only.
* Note: the report records `tool_tree_dirty: true`; at that moment the working tree contained only the pending rename of the earlier run reports. The tool commit equals the base commit.

Limits: trusted-local execution (no isolation); the base commit was advanced three times during the exercise to fix
the environment-dependence above, which is a finding about VEP's test suite, not evidence of a slower or faster
workflow; the change is small; token cost is zero because no model was involved in evaluation.

## Later runs
| Run | Outcome | Notes |
|---|---|---|
| `run-4-final-runner` | **DOGFOOD_PASS** | Re-run with the runner that fails closed on shadowed modules (365 passed, negative control rejected, edit invalidates). |
| `run-5-release-candidate` | **DOGFOOD_PASS** | Run at commit `4d0216a` (the release-candidate source, version `0.5.0b1`), same base `11391fe` and candidate `9d79210`. The report's `tool_tree_dirty: true` reflects only pending renames of earlier external reports into `docs/external/earlier/` at that moment; no source file was modified. |

Host-specific absolute paths (the scratch interpreter location and home directory) were replaced by placeholders in these records in a separate commit; no measurement or outcome value was changed.

| `run-6-0.6-candidate` | **DOGFOOD_PASS** | Re-run for the 0.6 candidate (tool commit `7071dee`, package 0.6.0b1, base/candidate are the rewritten-history equivalents of `11391fe`/`9d79210`): 365 passed, 2 skipped (Node-dependent), negative control rejected, post-certification edit invalidates; the certificate also verifies as an **authorized** v2 bundle against a trust policy in Python and Node (`AUTHORIZED`). |
