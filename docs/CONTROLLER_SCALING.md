# Controller scaling measurement (Phase F)

Reproduce: `python benchmarks/controller_scaling.py --jobs 32 --reps 3 --workers 1 2 4 8 16`
Raw data: `benchmarks/results/controller_scaling.json`. Classification: **locally verified observation**, one machine
(macOS 15.6 arm64, 12 logical CPUs, Python 3.14.7), idle apart from the benchmark.

Workload: 32 distinct candidates per rep, each a real unittest evaluation (one tiny test, about 65 ms) plus signed
evidence and certification, with real spawned worker processes sharing one SQLite workspace. 3 repetitions per
setting. All reps in every setting certified all 32 candidates exactly once, with 0 retries, 0 stale commits, 0 failures.

| Setting | Throughput (jobs/s, mean ± sd) | Speedup vs 1 worker | Mean job latency (s) | Child CPU per rep (s) |
|---|---|---|---|---|
| Direct sequential, no controller | 15.8 ± 0.1 | n/a | n/a | n/a |
| Controller, 1 worker | 14.6 ± 0.3 | 1.0x | 0.066 | 1.9 |
| 2 workers | 24.9 ± 1.4 | 1.7x | 0.074 | 2.1 |
| 4 workers | 42.9 ± 2.2 | 2.9x | 0.079 | 2.2 |
| 8 workers | 65.0 ± 5.3 | 4.4x | 0.089 | 2.5 |
| 16 workers | 60.5 ± 4.1 | 4.1x | 0.142 | 3.8 |

Peak single-child RSS was about 40 MB in all settings (this is the largest one process, not the total).

## What this does and does not show
* Controller overhead versus calling `evaluate`+`certify` directly was about 7% in throughput (14.6 vs 15.8 jobs/s, larger than the observed noise).
* Throughput scaled sub-linearly to 8 workers and did not improve at 16 (difference between 8 and 16 is within about one standard deviation, so no advantage is established). Latency and CPU per job rose at 16, consistent with contention for the single SQLite writer and for 12 cores; the cause was not isolated by profiling.
* Conflict rate: 0, but the jobs touched disjoint candidates by construction, so this says nothing about contended work. Contention behaviour is covered by the fencing tests, not by this benchmark.
* The jobs are tiny and CPU-bound on process start-up. Real builds and test suites will shift the balance toward the workers and may scale better; that is untested.
* Little's Law was **not** applied: runs last seconds and are not a steady state.
* No claim is made beyond 16 worker processes on one host. Nothing here supports distributed or "thousand-agent" scalability. The default scheduler remains single-worker for tightly coupled work.
