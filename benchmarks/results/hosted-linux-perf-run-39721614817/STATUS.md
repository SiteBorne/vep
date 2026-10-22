# Hosted run 39721614817 (commit 8c4a5ab) - corrected run

Preserved as downloaded; `decisions.json` is the output of `benchmarks/analysis/decide.py` (preregistered rules, unchanged).

- benchmark job: success, 0 excluded blocks, every analysed block load < 2.0 and CPU idle >= 75%.
- flag-correctness: qualified for 5 flag sets (none, staging_fast, staging_clone, verified_handoff, staging_fast+staging_clone+verified_handoff): 554 tests, 0 failed, invariants executed.
- GAP: the benchmarked arm `staging_fast,verified_handoff` had NO hosted correctness run in this matrix, so it cannot be ADOPTed from this run (decision: INCONCLUSIVE). Its wall gain here passes the wall rule (-14.4% / -109 ms at 1,000 files; -17.4% / -329 ms at 3,000 files). The matrix was extended and a replication run started on the following commit.
