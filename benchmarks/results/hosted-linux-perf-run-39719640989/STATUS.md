# Historical record: hosted run 39719640989 (commit 46d1ec2)

Preserved exactly as downloaded (artifact `perf-qualification`; no file edited). Status: PROVISIONAL / HISTORICAL.

- `benchmark` job: success. All measurement steps ran; no excluded blocks.
- `flags-on-tests` job: FAILED (`tests/test_benchmark_analysis.py` -> `extract.py --check` in a depth-1 checkout; cause: commit-derived provenance). The hosted invariant step was skipped, so this run has no hosted correctness qualification for any flag set.
- Consequently no arm from this run can be ADOPTed; the measurements stand as measurements. Corrected rerun: run 39721614817 on 8c4a5ab.
- The run is NOT merged into the master dataset; it lives in this directory only.
