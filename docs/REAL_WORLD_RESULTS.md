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

## 2a. Controlled paired benchmark (current; full tables in [BENCHMARK_RESULTS_PAIRED](BENCHMARK_RESULTS_PAIRED.md))
Procedure ([BENCHMARK_METHODOLOGY](BENCHMARK_METHODOLOGY.md), "Controlled paired run"): 10 analysed blocks per scenario after 2 warmups, every configuration once per block in a seeded random order, identical trees, no block excluded; verdicts by the **preregistered** rule (Welch 95% interval, 10% relative and 50 ms absolute thresholds) with a paired-bootstrap interval alongside (the two agreed on every comparison). Raw data: `benchmarks/results/paired-*.json`.

| Scenario (cold/warm) | pyflakes (0.46 s suite) | more-itertools (6.4 s suite) |
|---|---|---|
| S1 cold single: VEP vs direct | VEP_SLOWER, +50.5% | NO_MEASURABLE_ADVANTAGE, +3.9% |
| S1 cold single: VEP vs testmon | VEP_FASTER (testmon pays for coverage on a cold run) | VEP_FASTER, -17.4% |
| S2 warm unchanged: VEP vs direct | VEP_SLOWER, +53.9% | NO_MEASURABLE_ADVANTAGE, +3.8% |
| S2 warm unchanged: VEP vs testmon | VEP_SLOWER, +224% | VEP_SLOWER, 30.6x |
| S2 warm unchanged: **VEP build-cache hit** vs direct (no certificate) | VEP_FASTER, -82.7% (10 hits, 0 misses) | VEP_FASTER, -98.8% (10 hits, 0 misses) |
| S3 warm after edit: VEP vs direct | VEP_SLOWER, +55.7% | NO_MEASURABLE_ADVANTAGE, +3.8% |
| S3 warm after edit: VEP vs testmon | VEP_SLOWER, +158% | VEP_SLOWER, 14.5x |
| S4 cold batch of 4: VEP 4 workers vs direct parallel | VEP_SLOWER, +78.5% | NO_MEASURABLE_ADVANTAGE, +6.0% |
| S4 cold batch of 4: VEP 4 workers vs direct sequential | VEP_FASTER, -50.4% | VEP_FASTER, -73.0% |
| S4 cold batch of 4: VEP 1 worker vs direct sequential | VEP_SLOWER, +40.6% | NO_MEASURABLE_ADVANTAGE, +2.9% |

**Verdict on speed: no advantage.** VEP is slower than direct execution on the short suite, indistinguishable from it (within +/-10%) on the 6.4 s suite, and much slower than change-based test selection on repeated runs. Its parallelism matches plain parallel execution. The one large speedup is the exact-snapshot build-cache hit, which produces no certificate. CPU time follows wall time (VEP uses about 4% more CPU than a direct run on the longer suite; about 47% more on the short one).

**Environment validity: the benchmark gate stays UNVERIFIED.** The 1-minute load average at start was 5.0 (pyflakes) and 5.6 (more-itertools) against the declared criterion of < 2.0: Notes.app held a full core and several UI applications another few, and I did not terminate them. The more-itertools run happened on **battery power** (the machine was unplugged between the two projects). By the reporting-only criteria, 2 of 8 scenario-project cells were environmentally valid (more-itertools S2 and S3); the pyflakes batch scenario had a 13% coefficient of variation in its direct baseline. The first-run records (below) and this controlled run agree on every qualitative conclusion, but neither satisfies the gate's declared environment criterion. To satisfy it, re-run on a quiet, plugged-in machine:

```bash
python benchmarks/paired.py --project pyflakes --src <pinned pyflakes clone> --evalpy <python without vep> --testmon-py <python with pytest-testmon> --out benchmarks/results/paired-pyflakes.json
python benchmarks/paired.py --project more-itertools --src <pinned more-itertools clone> --evalpy <python without vep> --testmon-py <python with pytest-testmon> --out benchmarks/results/paired-more-itertools.json
python benchmarks/paired_report.py && python scripts/launch_check.py
```
Prerequisites: AC power, no other heavy applications (1-minute load average < 2.0 at start), the pinned clones from `benchmarks/external/projects.json`, and a Python with `cryptography` but without `vep` installed. An earlier controlled-run attempt was aborted after about two minutes because the starting load was inflated by my own test runs; it retained no data.

## 2b. First run (non-idle machine, unpaired; preserved as recorded)
 (`docs/BENCHMARK_METHODOLOGY.md`; raw data `benchmarks/results/compare-*.json`)
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
