# Performance profile and measured optimization

Method: `benchmarks/profile_stages.py` wraps VEP's real functions with wall-clock timers and runs the complete `enqueue -> controller.run_one` workflow (policy check, budget reservation, staging, protected test run, signing, certification)
on fresh workspaces of a deterministic synthetic project. Times are **inclusive** (nested stages overlap), medians over the measured runs after one warm-up, one macOS host (not quiet, not plugged-in controlled). It is a profile for choosing
what to optimise, not a benchmark claim; the historical benchmarks ([BENCHMARKS](BENCHMARKS.md), [hosted Linux](BENCHMARK_RESULTS_HOSTED_LINUX.md)) were not re-run.

## Where the time goes (median ms; `benchmarks/results/stage-profile-200.json`, `stage-profile-1000.json`)
| Stage | 200 tests / 402 files | 1,000 tests / 2,002 files |
|---|---|---|
| Full workflow | 320.3 | 1,222.5 |
| `evaluate` (inclusive) | 263.6 | 1,013.9 |
| Protected test run (subprocess incl. interpreter start) | 130.4 | 345.0 |
| Staging (materialize the snapshot read-only) | 42.3 | 230.7 |
| Snapshot construction (scan, hash, CAS put) | 22.0 | 103.3 |
| Policy validation | 22.2 | 90.6 |
| Staged-tree hash checks (before and after the run) | 16.2 | 80.7 |
| SQLite write transactions (incl. lock wait) | 13.6 | 19.2 |
| Snapshot blob verification | 7.9 | 38.2 |
| Certification (inclusive of signing) | 7.3 | 12.7 |
| Signing (Ed25519) | 0.4 | 0.4 |
| Exact-input reuse: derive + export + verify | 22.7 | 69.4 |

Findings: the protected test run dominates only while tests are cheap; VEP's own file-proportional work (staging, hashing, verification, policy validation) is about 44% of the workflow at 1,000 modules (543 of 1,222 ms; at 200 modules 111 of 320 ms). Signing and SQLite are negligible; no
database contention was visible in a single-worker run (multi-process contention is covered by `tests/test_fault_injection.py` for correctness, and by `docs/CONTROLLER_SCALING.md` for throughput up to 16 processes on tiny jobs).
Staging cost is file-system bound: a profile of `materialize` at 1,000 modules shows ~4,000 `open` calls as the largest cost.

## Optimizations considered
| Candidate | Result | Decision |
|---|---|---|
| Cache the parsed fields of `VEPObject` (every field access re-parses the canonical bytes) | 3 interleaved before/after rounds, 5 runs each, 1,000 modules: full workflow 683.4 ms median before vs 662.7 ms after (about 20 ms, 2.7%); policy validation 49.6 -> 41.2 ms (-17%) (`benchmarks/results/paired-object-parse-cache.json`) | **Not adopted.** Below the preregistered rule (10% relative and 50 ms absolute, [BENCHMARK_METHODOLOGY](BENCHMARK_METHODOLOGY.md)); the change was reverted. Kept as a negative result. |
| Hard-link or clone CAS blobs into the staging tree instead of copying | not implemented | **Rejected for soundness.** The evaluated code runs as the same user in trusted-local mode and could chmod/modify a linked file, corrupting the content-addressed store. |
| Skip re-hashing unchanged files by mtime/size | not implemented | **Rejected for soundness.** Timestamps are attacker-controllable and not an identity; a certificate over an unverified identity would be unsound. |
| Skip unaffected tests using the dependency graph | not implemented | **Rejected.** Static analysis cannot prove behavioural independence ([BETA_SCOPE](BETA_SCOPE.md)); it is never used for certification. |
| Verified exact-input reuse of a prior evaluation | implemented ([EVIDENCE_REUSE](EVIDENCE_REUSE.md)) | **Adopted** for identical source, policy, runner, evaluator and environment only; 14x faster at 200 modules, 18x at 1,000 for the derive+verify step versus the evaluation it replaces (trivial tests). Not a certificate. |

## Context and output economics (MCP, `benchmarks/results/mcp-context-profile.json`)
12 tool definitions total 7,170 bytes (about 1.8k tokens by the bytes/4 estimate; a provider's tokenizer will differ); typical tool responses are 270-410 bytes; `vep_status` median 40.6 ms over stdio (60 calls). Large outputs are
never inlined: logs and test ids are paged by handle. No provider usage was measured, so there is **no claim** about prompt-cache hits, billed tokens or Claude-side savings; the static, versioned tool definitions are
the precondition for a stable cached prefix, not evidence of one. Usage provenance in VEP's `TokenReceipt` remains separated into ordinary, cached-read, cache-write and output tokens, with reasoning tokens recorded as included in output.
