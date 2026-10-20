# Benchmark methodology (declared before any result was observed)

Committed before the first measurement run. `benchmarks/compare.py` implements exactly this; `docs/REAL_WORLD_RESULTS.md`
reports what happened. If a result contradicts a prediction below, the result is reported as is.

## Question
Does VEP reduce the time or compute needed to reach a *verified* accept/reject decision on a code change, compared with
established ways of running the same tests? VEP also produces signed evidence and an exact-snapshot certificate that
the baselines do not; time is compared, and the difference in what is produced is stated next to every number.

## Systems (same trees, same interpreter, same machine)
| Id | System | Notes |
|---|---|---|
| A | Direct run: `python -I -m unittest discover` | no VEP; exit code only |
| B | `pytest --testmon` (pytest-testmon, change-based test selection, built in a throwaway venv) | established incremental tool; selection is heuristic, **not** an equivalent guarantee; its venv has pytest/coverage but not the projects under test |
| C | Sequential direct runs of N candidates | single worker |
| D | Parallel direct runs of N candidates, W workers (thread pool launching processes) | existing parallelism, no VEP |
| E | VEP, 1 worker: snapshot, register, enqueue, evaluate (full protected runner), sign, certify | equal correctness requirement |
| F | VEP with eligible optimizations: W worker processes (bounded parallelism) | the only implemented VEP optimization on the certification path |
| F2 | VEP `BuildAction` result cache hit for a deterministic test action | does **not** yield a certificate; shown only to measure the cache mechanism |

Not implemented, so not benchmarked: reuse of evidence across candidates with identical snapshots (`cached_evidence`
exists but is not wired into evaluation), cost-aware model routing in live execution, remote execution (REAPI), sound
incremental test skipping (VEP's evidence reuse rule is EXACT_ONLY by design).
Baseline "Bazel/REAPI" is NOT_RUN: not installed.

## Workloads
Pinned external projects from `benchmarks/external/projects.json`: pyflakes 4.0.3 (795 tests, ~0.5 s) and more-itertools
v11.2.1 (930 tests, ~6.4 s). Scenarios:
* **T1 cold verify:** one clean tree, first run.
* **T2 unchanged re-run:** the same tree verified again after a first run.
* **T3 small edit:** a behaviour-preserving source edit after a first run (B can select tests; VEP re-evaluates fully).
* **T4 batch:** N = 8 distinct benign candidates (each adds one new passing test file) with W = 4 workers for D and F.

## Correctness gate (before timing)
Every system must accept the clean tree and reject a mutant tree (one logic inversion, as in `docs/external`). A system
that fails the gate is reported as `FAILED_CORRECTNESS_GATE` and not compared on speed.

## Measurements
Wall-clock (monotonic), child CPU time (rusage), peak child RSS, per run. Repetitions: 10 for T1-T3, 5 for T4 (each
repetition uses a fresh tree copy and fresh state). One-time costs (VEP workspace creation, key generation, policy
creation, testmon baseline run for T2/T3) are measured separately and excluded from the per-run figure; they are reported.
Cold = first run in a fresh state; warm = repeated. The machine is otherwise idle; the 1-minute load average at start is recorded.

## Effect thresholds (declared in advance)
* Practical-significance threshold: **10%** relative difference in mean wall time, and at least 50 ms absolute.
* Interval: Welch 95% confidence interval of the difference of means (t critical value from the Welch-Satterthwaite df).
* Verdict for VEP versus a baseline:
  * `VEP_FASTER` if the whole interval of the relative difference is below -10% (and the absolute gain exceeds 50 ms);
  * `VEP_SLOWER` if the whole interval is above +10% (and exceeds 50 ms);
  * `NO_MEASURABLE_ADVANTAGE` if the whole interval lies within +-10% (or the absolute difference is under 50 ms);
  * `INCONCLUSIVE` otherwise.
  Speed is judged only for systems that passed the correctness gate. A verdict says nothing about other machines or projects.

## Predictions (written before running)
1. T1: VEP is `VEP_SLOWER` or `NO_MEASURABLE_ADVANTAGE` than A on the 6 s project and `VEP_SLOWER` on the 0.5 s project (fixed staging, hashing and signing costs dominate); no speed advantage is expected from VEP in a single cold verification.
2. T2/T3: B (testmon) is faster than VEP on T3 and on T2, because VEP re-runs the full suite. VEP has no advantage over B.
3. T4: E with 1 worker is no faster than C; F with 4 workers scales similarly to D; any F-versus-D difference is within threshold or in D's favour.
4. F2 shows a large speedup on a cache hit, which applies only to a deterministic action and gives no certificate.
5. Overall expectation: `NO_MEASURABLE_ADVANTAGE` or VEP slower on speed; VEP's value is the evidence and certificate, not wall time.

## Limits
Two projects with no third-party dependencies, one machine (12 logical CPUs), small repetition counts, wall time and CPU
only. No token or monetary cost is involved (no model is used), so no cost comparison is made. Results are observations,
not proofs, and are not extrapolated to larger repositories or remote execution.

## Deviations from this plan (added after the first measurement run)
* **The machine was not idle.** `load_avg_1m_at_start` was 9.9 (pyflakes) and 22.4 (more-itertools, inflated by the preceding run), and a process listing taken right afterwards showed other applications using several cores (`corespeechd` about 190%, Notes about 100%, a ChatGPT renderer about 100%) with the system load average staying near 10 on 12 logical CPUs. The condition "otherwise idle" was therefore NOT met. All numbers below were taken under that background load; absolute times may be inflated and parallel results (4 workers) are the most exposed. Effects reported as large are far outside the observed noise; small ones (a few percent) are not reliable. A re-run on a quiet machine is recommended before quoting any figure.
* Peak RSS is not reported (`ru_maxrss` of children is a running maximum, not a per-run figure).

## Controlled paired run: procedures added before running (thresholds above are unchanged)
Added after the non-idle first run and before any controlled measurement; `benchmarks/paired.py` implements them. The first-run
records (`benchmarks/results/compare-*.json`) are preserved untouched.
* **Paired, balanced blocks.** A block runs every configuration of a scenario once, on identical trees, in an order drawn from a seeded RNG (seed 20261019). Paired differences are taken within blocks. Target: 10 analysed blocks per scenario; 2 warmup blocks run first and are recorded but not analysed.
* **Configurations.** DIRECT (A), TESTMON (the established incremental tool), VEP_PLAIN (one worker, no optimization), VEP_OPT (only optimizations that are implemented and exercised: the `BuildAction` result cache on an unchanged tree, and 4 worker processes on a batch). VEP_OPT is NOT_APPLICABLE where nothing can be reused (one cold verification; an edited tree) and that is recorded, not filled in. Batch size is 4 candidates (the first run used 8) to bound run time.
* **Scenarios.** S1 cold single verification; S2 warm re-verification of an unchanged tree; S3 warm re-verification after a behaviour-preserving edit; S4 cold batch. Cold = fresh tree and fresh VEP workspace; warm = a prior run of the same configuration was done untimed (so file-system caches and VEP/testmon state are warm).
* **Exclusions (pre-declared).** A block is excluded only if some configuration returned a wrong accept/reject outcome or an infrastructure error; the reason is recorded and up to 3 replacement blocks are run. Slow or noisy timings are never excluded.
* **Environment record (not timed).** Before every block: 1-minute load average and CPU idle percentage; at start: power source, swap, platform. Competing user applications are not terminated.
* **Environment validity (reporting only).** Reported, not used to alter any verdict: CPU idle >= 75% in at least 90% of blocks, and a coefficient of variation of the direct baseline <= 5%. The launch gate's existing criterion (`load_avg_1m_at_start` < 2.0 and no correctness-gate failure) is unchanged and decides `BENCHMARK_REPRODUCIBILITY`.
* **Statistics.** The preregistered verdict (Welch 95% interval, 10% relative and 50 ms absolute thresholds) is the headline for each pair; a paired bootstrap interval (10,000 resamples, seeded) with the same thresholds is reported next to it. Disagreements are reported. Unlike workloads are never aggregated into one percentage.
* **Measurements.** Wall time, child CPU time and peak child RSS (maximum over the process tree waited for, via `wait4`), cache hits and misses (build cache), correctness outcome, per run.

## Hosted-Linux qualification run (added with its results; procedure = commit c130600)
To remove the dependency on an idle developer machine, the same preregistered design runs unchanged on a fresh GitHub-hosted VM via `.github/workflows/benchmark-qualification.yml` (manual trigger, read-only token, no secrets).
* **Source under test.** Fixed to release `v0.5.0b1` (commit `578850d`). The workflow checks that the tag resolves to that commit and that nothing under `src/` or `pyproject.toml` differs between it and the harness checkout; every other changed file is listed in the artifact (`files-changed-since-release.txt`). Only the benchmark harness, workflow, docs and gate script differ.
* **Portability changes only.** `benchmarks/envinfo.py` supplies Linux equivalents of the macOS-only environment probes (`/proc/stat`, `/proc/meminfo`, `/proc/cpuinfo`, `/etc/os-release`, runner environment variables); the macOS branch is unchanged. `paired.py` calls it; scenarios, configurations, block counts, warmups, seed, correctness gate, statistics and thresholds are untouched (the workflow passes none of these as overrides, and a test asserts it).
* **Idle criterion.** `benchmarks/wait_idle.py` waits up to 15 minutes, sampling the 1-minute load average, for the declared start criterion (< 2.0); it refuses a higher limit. If the criterion is not met the workload is not run and the report says `NOT_RUN` (environmentally invalid); every sample is kept. The gate then reads `load_avg_1m_at_start` from the paired report, as before.
* **Evidence sets.** The gate applies the same declared criteria to each complete evidence set (macOS records; hosted-Linux records) and passes if one complete set satisfies them. Sets are never mixed, and absolute times are never compared across machines. A hosted set must also be confirmed against its GitHub run (successful run of that workflow, recorded file hashes, VEP implementation identical to the release).
* **Environment fixed by the workflow.** `ubuntu-24.04`, Python 3.14, `cryptography==50.0.2` in the measurement interpreter and `pytest==9.1.1`, `pytest-testmon==2.2.0` in the testmon interpreter (neither has `vep` installed; the workflow fails if it is importable), pinned external commits verified after checkout.
