# Hosted run 39755218641 (commit a521f4e) - the qualifying run

Preserved as downloaded; `decisions.json` is the mechanical output of `benchmarks/analysis/decide.py` (preregistered thresholds, unchanged).

- benchmark job: success; 0 excluded blocks; every analysed block met load < 2.0 and CPU idle >= 75%.
- flag-correctness: all six benchmarked flag sets qualified (555 tests, 0 failed, invariants executed): none, staging_fast, staging_clone, verified_handoff, staging_fast+verified_handoff, staging_fast+staging_clone+verified_handoff.
- Runner variance in this run was high (95% intervals of +/-15-20% on wall time), so wall-time rules are mostly not decidable from it alone. See docs/AGENT_SCALE_PERFORMANCE_REPORT.md for the four-run comparison.
