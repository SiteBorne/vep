# Production-profile qualification report

Computed by `python scripts/profile_check.py --run --run-packaging` (machine-readable result: [production-profiles.json](production-profiles.json), which records the commit it was computed on). A profile is `YES` only when **all** of
its own prerequisites pass; there is no umbrella `PRODUCTION_READY`. Definitions: [PROFILES.md](PROFILES.md). Specification: [CORE_PROTOCOL_SPEC.md](CORE_PROTOCOL_SPEC.md). Nothing in this report is an external review.

## Result
| Profile | Result | Blocking / scope |
|---|---|---|
| `CORE_PROTOCOL_CONFORMANT` | **YES** | Python and Node agree on all 119 + 160 + 194 vector evaluations (suites 1.0-1.2); suites regenerate byte-identically |
| `CORE_PROTOCOL_PRODUCTION_READY` | **YES** (scope: the Core Profile's verification semantics; not hosting, not hostile code) | trust-anchor regression, derivation-chain, fault-injection, adversarial and compatibility/migration tests all pass |
| `REFERENCE_IMPLEMENTATION_READY` | **YES** | CI and CodeQL green on `3cf2371` (hosted), full suite, fault injection, compatibility, wheel build/install/smoke |
| `MCP_INTEGRATION_READY` | **YES** (scope: local stdio only) | remote HTTP is not offered |
| `A2A_INTEGRATION_READY` | **YES** (scope: authenticated JSON-RPC, loopback default; streaming exercised, push not offered; not qualified for public exposure) | no official inspector run |
| `CLAUDE_INTEGRATION_READY` | NO | no recorded live Claude Code tool call (server approval and a model run were not authorized); installer, plugin validation and client discovery pass |
| `ISOLATED_EXECUTION_READY` | **YES** | the hosted gVisor evidence from a prior revision is still current: no isolation-critical file changed since |
| `UNTRUSTED_EXECUTION_READY` | NO | no external security review, no escape testing |
| `PUBLIC_ANNOUNCEMENT_READY` | NO | no candidate version set, no candidate release artifacts |

## What was run (after the CodeQL fix; refreshed for PR #2)
* **Security finding (PR #2, `py/clear-text-storage-sensitive-data` at `claude_code.py`).** Data flow: the flagged "secret" was the boolean `trusted_local` written to the install manifest, not a credential. The genuine risks nearby (predictable temp names, umask-dependent modes, `copy2` backups, symlink following, status echoing foreign entries) were fixed with 17 regression tests written first (12 failed before the fix). Hosted result after the fix: the PR code-scanning check passes and the alert is `fixed`; nothing was dismissed. The rescan closing the alert is not itself proof that the report was a false positive.
* **Tests:** 499 tests, 0 failing, 0 skipped locally (unittest and pytest agree; run twice more after the fix). In the second full gate run one pytest test failed once and was not reproduced (499/499 on two reruns and in the third gate run); the gate now prints failing test names. Treat that as an unexplained, unreproduced flake until it recurs.
* **Full release gate (`scripts/release_check.sh`, including the Python 3.11-3.14 matrix run from the extracted sdist against the installed wheel):** every gate passes except `SOURCE_INTEGRITY` (the `v0.5.0b1` tag does not point at HEAD and the version is not bumped, as expected). Two real bugs were found and fixed by this run: the sdist omitted binary test fixtures (`graft tests/fixtures`), and the matrix venvs lacked the optional extras. Outputs of the gate were not committed.
* **Hosted CI and CodeQL on the PR branch:** CI (Ubuntu 3.11, 3.12, 3.13, 3.14; macOS 3.13; build and install artifacts) and CodeQL passed on `2beb1ce`. CI and CodeQL were also green on the final head `3cf2371`, the commit the profiles were computed on (`docs/production-profiles.json`; the profile file itself is committed afterwards).
* **Re-run real-world evaluations (new, not inherited):** VEP-on-VEP dogfood (365 passed, 2 skipped, negative control rejected, edit invalidates), pyflakes 4.0.3 and more-itertools v11.2.1 at their pinned commits (upstream and benign CERTIFIED, mutants REJECTED, edit rejected), each now also verified as an **authorized** v2 bundle against a trust policy in Python and Node. Records: `docs/dogfood/vep-on-vep-run-6-0.6-candidate.json`, `docs/external/*-0.6-candidate.json`.
* **Conformance suites 1.0-1.2** (119/160/194), Python and Node, MCP stdio, A2A, Claude installer/plugin validation, fault injection: all inside the 499 tests and `profile_check.py`.
* **Inherited historical evidence, not recomputed:** hosted-Linux benchmark qualification (run 39457964415), the earlier macOS benchmarks, controller scaling, hosted gVisor isolation matrix. No performance-sensitive code changed in the security fix (installer file handling only), so no new before/after measurement was needed.
* `scripts/launch_check.py` was not re-run for this candidate: it is pinned to the published `0.5.0b1` and would report the new tree as a non-release.

## Not done, stated plainly
* The hosted benchmark-qualification and isolation workflows were not run on this work; nothing was tagged, released or merged.
* No live Claude Code session and no Claude Agent SDK model run (both would spend model budget; not authorized). Server approval inside Claude Code was not granted on the user's behalf.
* No external A2A inspector and no official MCP conformance run (the latter targets HTTP servers).
* No external security review; both verifiers were written by the same author.
* Optimization: one candidate (object parse cache) measured below the preregistered threshold and was reverted; others were rejected for soundness ([PERFORMANCE_REPORT.md](PERFORMANCE_REPORT.md)).

## Version decision
Proposed next version: **`0.6.0b1`** (not `1.0.0`). Reasons: new public interfaces (MCP, A2A, `vep claude`, `vep reuse`), a new bundle default (format 2) and verification semantics, a new object type and corrected cache identities, all additive or behind explicit flags, with the protocol version (`0.3`), Evidence/Certificate schemas and database schema (`3`) unchanged. It is **not set** in the repository: bumping and tagging need your decision.

## To reach the remaining profiles
1. (Done) the work is on PR #2 so hosted CI and CodeQL run on the exact commit.
2. Approve the project server in an interactive Claude Code session, or authorize one bounded `claude -p` run; record it as `docs/evidence/claude-code-live.json` (`CLAUDE_INTEGRATION_READY`).
3. Set the version, re-run the dogfood and external evaluations and the launch gate, tag and verify a release (`PUBLIC_ANNOUNCEMENT_READY`).
4. `UNTRUSTED_EXECUTION_READY` needs a separate security assessment and escape testing that this work does not attempt.
