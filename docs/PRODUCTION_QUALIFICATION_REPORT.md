# Production-profile qualification report

Computed by `python scripts/profile_check.py --run --run-packaging` (machine-readable result: [production-profiles.json](production-profiles.json), which records the commit it was computed on). A profile is `YES` only when **all** of
its own prerequisites pass; there is no umbrella `PRODUCTION_READY`. Definitions: [PROFILES.md](PROFILES.md). Specification: [CORE_PROTOCOL_SPEC.md](CORE_PROTOCOL_SPEC.md). Nothing in this report is an external review.

## Result
| Profile | Result | Blocking / scope |
|---|---|---|
| `CORE_PROTOCOL_CONFORMANT` | **YES** | Python and Node agree on all 119 + 160 + 194 vector evaluations (suites 1.0-1.2); suites regenerate byte-identically |
| `CORE_PROTOCOL_PRODUCTION_READY` | **YES** (scope: the Core Profile's verification semantics; not hosting, not hostile code) | trust-anchor regression, derivation-chain, fault-injection, adversarial and compatibility/migration tests all pass |
| `REFERENCE_IMPLEMENTATION_READY` | NO | hosted CI has not run on this commit (it is not pushed). Full suite, fault injection, compatibility, wheel build/install/smoke all pass |
| `MCP_INTEGRATION_READY` | **YES** (scope: local stdio only) | remote HTTP is not offered |
| `A2A_INTEGRATION_READY` | **YES** (scope: authenticated JSON-RPC, loopback default; streaming exercised, push not offered; not qualified for public exposure) | no official inspector run |
| `CLAUDE_INTEGRATION_READY` | NO | no recorded live Claude Code tool call (server approval and a model run were not authorized); installer, plugin validation and client discovery pass |
| `ISOLATED_EXECUTION_READY` | **YES** | the hosted gVisor evidence from a prior revision is still current: no isolation-critical file changed since |
| `UNTRUSTED_EXECUTION_READY` | NO | no external security review, no escape testing |
| `PUBLIC_ANNOUNCEMENT_READY` | NO | no candidate version set, HEAD not pushed, no hosted CI on it, no candidate release artifacts |

## What was run on this work tree
* Full test suite: 482 tests, 0 failing, 0 skipped (unittest and pytest agree; includes real subprocess/SIGKILL/contention tests and a real `vep-a2a` process).
* `scripts/conformance_check.sh`-equivalent: all three suites on both implementations; `gen_conformance_vectors*.py --check` for each.
* `scripts/release_check.sh --skip-matrix`: every gate passed (build, wheel and sdist install, clean-room CLI smoke, artifact integrity, secret scan, documentation incl. the quickstart executed against the installed wheel, protocol compatibility, dependency audit) **except** `SOURCE_INTEGRITY` (uncommitted tree at the time; the old release tag does not point at HEAD, as expected until a new version is tagged) and `PYTHON_COMPATIBILITY` (matrix skipped by flag). Its outputs were not committed.
* `scripts/launch_check.py --skip-slow` (scratch output): `ANNOUNCEMENT_READY = NO`. Besides the missing release and CI, it marks the dogfood and external-project evidence **stale** because evaluation-critical source files (`objects.py`, `conformance.py`) changed since they were produced; those runs must be repeated when a release candidate is cut. The historical benchmark was not recomputed (the evaluation path is unchanged).

## Not done, stated plainly
* Hosted CI, CodeQL, the hosted benchmark-qualification workflow and the isolation workflow were not run on this work; nothing was pushed, tagged or released.
* No live Claude Code session and no Claude Agent SDK model run (both would spend model budget; not authorized). Server approval inside Claude Code was not granted on the user's behalf.
* No external A2A inspector and no official MCP conformance run (the latter targets HTTP servers).
* No external security review; both verifiers were written by the same author.
* Optimization: one candidate (object parse cache) measured below the preregistered threshold and was reverted; others were rejected for soundness ([PERFORMANCE_REPORT.md](PERFORMANCE_REPORT.md)).

## Version decision
Proposed next version: **`0.6.0b1`** (not `1.0.0`). Reasons: new public interfaces (MCP, A2A, `vep claude`, `vep reuse`), a new bundle default (format 2) and verification semantics, a new object type and corrected cache identities, all additive or behind explicit flags, with the protocol version (`0.3`), Evidence/Certificate schemas and database schema (`3`) unchanged. It is **not set** in the repository: bumping and tagging need your decision.

## To reach the remaining profiles
1. Push the work to a branch/PR so hosted CI and CodeQL run on the exact commit (`REFERENCE_IMPLEMENTATION_READY`).
2. Approve the project server in an interactive Claude Code session, or authorize one bounded `claude -p` run; record it as `docs/evidence/claude-code-live.json` (`CLAUDE_INTEGRATION_READY`).
3. Set the version, re-run the dogfood and external evaluations and the launch gate, tag and verify a release (`PUBLIC_ANNOUNCEMENT_READY`).
4. `UNTRUSTED_EXECUTION_READY` needs a separate security assessment and escape testing that this work does not attempt.
