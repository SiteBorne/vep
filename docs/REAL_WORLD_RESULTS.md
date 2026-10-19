# Real-world results (v0.5.0b1 work, locally verified only)

Everything here is an observation on one macOS machine (12 logical CPUs, Python 3.14.7), trusted-local execution,
small repetition counts. Nothing is REAL_WORLD_VALIDATED, and nothing supports a claim of production readiness.

## 1. Lifecycle on real code
| What | Result | Record |
|---|---|---|
| VEP verifying its own change (`vep build` CLI), 367-test suite through the controller | CERTIFIED (TRUSTED_LOCAL); negative control rejected; post-certification edit invalidates; Python and Node bundle verifiers agree | `docs/dogfood/` (run 3, rerun with final runner: run 4) |
| pyflakes 4.0.3 (MIT), 795 tests | upstream and benign change CERTIFIED; mutant rejected (259 failures) | `docs/external/` |
| more-itertools v11.2.1 (MIT), 930 tests | upstream and benign change CERTIFIED; mutant rejected (43 failures) | `docs/external/` |
| Local model (qwen2.5-coder:7b via Ollama) producing a change that VEP certified | 1 run, 4.1 s, runtime-reported 135/106 tokens | `docs/live_agent_run.json` |

Defects in VEP found by doing this (all fixed, with tests): the anti-shadowing rule blocked VEP's own package name; VEP's tests were
not hermetic against an installed copy; a path where an **installed copy of the project could be tested instead of the
candidate and certify (false green)**; id/digest/timestamp patterns accepting a trailing newline.

## 2. Speed comparison (`docs/BENCHMARK_METHODOLOGY.md`; raw data `benchmarks/results/compare-*.json`)
Verdicts use the pre-declared rule: 10% relative threshold, 50 ms absolute, Welch 95% interval. Times are mean seconds.
"E" = VEP with one worker producing a signed certificate; the baselines produce only an exit code.

| Scenario | pyflakes (0.45 s suite) | more-itertools (6.5 s suite) |
|---|---|---|
| T1 cold verify, VEP vs direct run | A 0.44 / E 0.68: **VEP_SLOWER** (+54%, +0.24 s) | A 6.81 / E 7.00: NO_MEASURABLE_ADVANTAGE (+2.8%, interval -4% to +10%; noisy) |
| T1 VEP vs pytest-testmon cold | B 1.02: VEP_FASTER | B 8.70: VEP_FASTER (-19%) |
| T2 unchanged re-run, VEP vs direct | VEP_SLOWER (+51%) | NO_MEASURABLE_ADVANTAGE (+3.8%) |
| T2 unchanged re-run, VEP vs testmon (warm) | B 0.21 vs E 0.70: **VEP_SLOWER** | B 0.22 vs E 6.70: **VEP_SLOWER** (about 30x) |
| T2 `BuildAction` cache hit vs direct (no certificate) | 0.08 vs 0.46: VEP_FASTER (-83%) | 0.09 vs 6.46: VEP_FASTER (-99%); the first (miss) run cost 13.4 s because determinism is verified by running twice |
| T3 small edit, VEP vs direct | VEP_SLOWER (+52%) | NO_MEASURABLE_ADVANTAGE (+3.8%) |
| T3 small edit, VEP vs testmon | B 0.28 vs E 0.70: **VEP_SLOWER** | B 0.47 vs E 6.68: **VEP_SLOWER** (about 14x) |
| T4 batch of 8, 1 worker: VEP vs sequential direct | VEP_SLOWER (+36%) | NO_MEASURABLE_ADVANTAGE (+3.2%) |
| T4 batch of 8, 4 workers: VEP vs parallel direct | VEP_SLOWER (+64%) | NO_MEASURABLE_ADVANTAGE (+5.8%, interval +3.7% to +7.9%) |
| T4 4-worker VEP vs sequential direct | VEP_FASTER (-57%) | VEP_FASTER (-73%) |

How to read this honestly:
* **VEP does not make a single verification faster.** On the 0.5 s suite its fixed cost (staging, hashing, signing, process start) is about 0.24 s per candidate; on the 6.5 s suite that cost is within noise. The prediction in the methodology (no speed advantage) held.
* **Change-based test selection (testmon) is far faster on repeated and edited runs**, by one to two orders of magnitude here. VEP deliberately re-runs the full suite after any change (evidence reuse is exact-snapshot only), so it is slower than testmon but gives an exact-snapshot guarantee that testmon's heuristic selection does not claim.
* VEP's bounded parallelism scales like plain parallel execution (4 workers: -73% against sequential, +5.8% against parallel direct runs), which is expected because the workers do the same work plus signing. The only large VEP speedup is the `BuildAction` cache hit, which applies to deterministic actions and produces no certificate. Evidence reuse across identical snapshots is NOT implemented (`cached_evidence` exists but is not called).
* What VEP adds is not speed: a signed, exact-snapshot, independently checkable record (verified by two implementations), enforced protection of required tests, false-green detection, and budget accounting. Whether that is worth the overhead is a judgement this benchmark does not make.

## 3. Limits and caveats
* **The machine was not idle during the benchmark** (other applications used several cores; see the deviations section of the methodology). Treat small differences as unreliable; the large ones (testmon, cache hit, parallel scaling vs sequential) are well outside the observed noise. Re-run on a quiet machine before quoting numbers.
* Two small dependency-free projects, one machine, 5-10 repetitions; no remote execution, no Bazel (not installed), no model cost comparison (no model involved in evaluation).
* Trusted-local only: no hostile-code isolation was tested (`ISOLATION_UNVERIFIED`).
* The VEP-on-VEP change was authored interactively by Claude Code, not by an autonomous agent run.
