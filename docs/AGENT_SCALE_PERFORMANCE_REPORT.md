# Agent-scale performance qualification report

Branch `perf/agent-scale` (not merged; PR #2 and the release candidate are untouched). Control: `1ab17af60450c4d558bab5c1c4260024ade45355`, run side by side with the flagged code in the same randomized blocks. Platform: GitHub-hosted ubuntu-24.04, 4 vCPU, ext4. Linux hosted results are never combined with the local macOS results.

## 1. What happened to the first hosted run, and why it is historical

| Run | Commit | benchmark job | correctness gate | Status |
|---|---|---|---|---|
| 39719640989 | 46d1ec2 | success | `flags-on-tests` FAILED (invariant step skipped) | HISTORICAL, PROVISIONAL |
| 39721614817 | 8c4a5ab | success | 5 flag sets qualified; `staging_fast`+`verified_handoff` had no run | measurements stand; one arm unqualified |
| 39747018211 | ce6aab8 | success | all 6 FAILED (artifact-inventory defect, fixed) | HISTORICAL, PROVISIONAL |
| 39755218641 | a521f4e | success | all 6 qualified (555 tests, 0 failed, invariants run) | qualifying run |

**Root cause of the original failure.** `benchmarks/analysis/extract.py` recorded a per-file `git_commit` taken from `git log`. GitHub checks out with depth 1, where `git log` returns the one checked-out commit for every file, so `extract.py --check` regenerated different bytes. Reproduced on 46d1ec2 in a depth-1 clone: only `git_commit` differed (all 35 sources); every observation was identical. **Fix (0447cfc):** commit lineage lives in a verified ledger (`source-history.json`, path + sha256 + last commit); `--check` still compares dataset and CSV byte for byte, additionally verifies the ledger against git whenever history exists, and nothing was weakened, suppressed or removed. Regression tests run extraction, validation and rendering in a fresh depth-1 clone, from other working directories, repeatedly, and detect a forged ledger.

**Run 3's failures** were my own defect and the gate caught it: committing raw run artifacts made four tests fail (artifacts not inventoried; `/home/runner` paths tripped the sdist audit). Fixed in a521f4e by inventorying the preserved run directories (not pooled into observations) and excluding them from the sdist. The raw files were never edited.

**Gate hardening.** A skipped or missing invariant step can no longer count: `qualify_hosted.py` fails unless the JUnit file, a complete invariant report with matching flags, and zero failed tests are present. A guard test fails if any benchmarked flag arm lacks its own matrix entry (it caught the missing combined arm in run 2).

All four runs are preserved unaltered under `benchmarks/results/hosted-linux-perf-run-<id>/`.

## 2. Did each mechanism actually activate? (median per run, 3,000-file workflow, run 39755218641)

| Arm | Evidence |
|---|---|
| `none` | 3,001 blobs staged by CAS read; no optimization counters |
| `staging_fast` | 3,001 files written by the exclusive-create fast path |
| `verified_handoff` | 3,001 blobs verified once and staged from the verified bytes; verification pass run 1, skipped 1 (the redundant pass) |
| `staging_clone` | **Did not activate on this runner**: 0 clones succeeded, 3,001 fell back to write (ext4 has no reflink). Its arm therefore measures `staging_fast`+`verified_handoff` plus fallback overhead. Copy-on-write was demonstrated only on macOS APFS, where local timings are `INVALID_ENVIRONMENT`. |

## 3. Preregistered rule, applied unchanged

Wall time: 10% relative **and** 50 ms absolute with the whole 95% interval beyond the threshold (Welch) and a confirming paired bootstrap, at both 1,000 and 3,000 files; cold-path guard at 100 files; memory guard +25%; zero exclusions; hosted correctness qualified; environment valid. `decide.py` encodes this with tests for each branch; thresholds were not touched.

### Relative wall-time difference vs control (negative is faster), all four runs

| Arm | n | run 1 (prov.) | run 2 | run 3 (prov.) | run 4 (qualifying) |
|---|---|---|---|---|---|
| staging_fast | 1,000 | -6.6% (±wide) | -5.1% | -4.5% | -7.8% [-20, +4] |
| | 3,000 | -9.9% | -6.2% | -5.7% | -6.4% [-26, +13] |
| verified_handoff | 1,000 | -6.8% | -7.6% | -7.1% | +0.1% [-19, +19] |
| | 3,000 | -11.4% | -9.7% | -8.7% | -13.0% [-30, +4] |
| staging_fast + verified_handoff | 1,000 | +5.0% | -14.4% (-109 ms) | -11.5% | -1.9% [-21, +17] |
| | 3,000 | -15.5% | -17.4% (-329 ms) | -14.9% | -18.1% [-36, -1] (-262 ms) |
| | 8,000 | -20.7% | -20.2% | -18.1% | -14.3% |
| staging_fast + staging_clone + verified_handoff | 1,000 | +28.0% | -4.6% | -5.6% | -2.1% |
| | 3,000 | -7.5% | -5.3% | -7.0% | -8.2% |

CPU seconds are far steadier than wall time across runs: `staging_fast` -5 to -7%, `verified_handoff` -8 to -11%, `staging_fast`+`verified_handoff` **-12% to -20% in all four runs** (CPU: VEP_FASTER at both sizes in run 4). Peak child memory: control 54.3 MB; `staging_fast` +0.1%; arms with `verified_handoff` 59-60 MB (+10%, under the 25% guard). The 100-file cold path showed no regression in any arm.

Run 2 and run 3 were quiet (95% intervals ±0.3-1%); runs 1 and 4 were noisy (±15-20%) although every block met the preregistered start criteria (load < 2.0, idle ≥ 75%). The rule has no replicate-combination clause, and I did not invent one after seeing data.

### Decisions

| Arm | Decision | Basis |
|---|---|---|
| `none` (flags off) | REJECT as an optimization | No effect (-1% to -2%, CI spans 0); confirms the flag-off path carries no measurable overhead |
| `staging_fast` | **REJECT** | Real but small (-5% to -8% wall, -5 to -7% CPU), consistently below the 10% threshold |
| `verified_handoff` | **REJECT** | -7% to -8% at 1,000 files in the three runs with usable intervals, below 10%; 3,000-file interval straddles -10% |
| `staging_fast`+`staging_clone`+`verified_handoff` | **REJECT** | Clone never activated on the hosted filesystem; no gain over the combination without it; +10% memory |
| `staging_fast`+`verified_handoff` | **INCONCLUSIVE** | Passes the rule on the two quiet runs (run 2 had no gate for this arm; run 3 failed its gate) and shows a large, consistent CPU gain; the qualifying run (gate passed) is too noisy to confirm at 1,000 files (-1.9%, CI [-21, +17]) and its 3,000-file Welch interval reaches -0.5%. Mechanical `decide.py` output on run 4 says REJECT (mean diff 12 ms < 50 ms at 1,000 files); I treat that as under-powered rather than as evidence against, because intervals that wide cannot exclude a 10% gain. Not adopted. |
| macOS `staging_clone` | INCONCLUSIVE | Activates on APFS, but only an invalid-environment local run exists |

Nothing is ADOPTed. The only honest next experiment is a replicated hosted run of `staging_fast`+`verified_handoff` with the replicate rule declared in advance.

## 4. Agent-workflow benchmark (12 scenarios, 7 systems; pyflakes 5 reps, more-itertools 3 reps; medians, run 4)

Same-workload comparison of `VEP_BASE` and `VEP_OPT` (`staging_fast`+`verified_handoff`):
- Small tests: pyflakes -2% to -9% on re-verification-heavy scenarios (T02 -8%, T06 -8%, T08 -9%); other scenarios within ±5%.
- Long tests (more-itertools, 11 s per run): -2% to +1%. The fixed per-file work being removed is negligible next to the test runtime.
- T12 (large tree, tiny change): **-17% / -14%** (pyflakes / more-itertools), reproduced in run 2 (-19% / -18%).
- **T09 is not an optimization result.** The driver gives `VEP_BASE` one worker and every other VEP system four (`agent_workflow.py:159`), so -43% / -48% measures parallel workers, not the flags. The like-for-like comparison is `VEP_REUSE` (four workers, no flags): 2.95 s vs `VEP_OPT` 2.84 s.
- VEP protected fresh certification is not faster than running the tests directly: pyflakes cold verify 1.06 s vs 0.73 s direct (1.45×); more-itertools 11.3 s vs 11.0 s (1.03×). The value is the signed, independently verifiable certificate, not speed. Exact-input reuse (`VEP_REUSE`) turns identical re-verification into a derived attestation (T02/T08: 1.14-1.18 s vs 2.0-2.2 s), which is not a fresh certificate and is reported as such.

## 5. Worker scaling (run 4, 8 candidates per rep, 4 vCPU)

| | W=1 | W=2 | W=4 | W=8 |
|---|---|---|---|---|
| pyflakes VEP / direct jobs per s | 1.07 / 1.38 | 1.99 / 2.72 | 2.51 / 3.41 | 2.38 / 3.31 |
| more-itertools VEP / direct jobs per s | 0.09 / 0.09 | 0.17 / 0.18 | 0.23 / 0.23 | 0.23 / 0.23 |

Throughput saturates at the 4 vCPUs. VEP uses about 1.25-1.36× the CPU of a direct run on short tests and 1.00-1.02× on long tests. Every candidate was certified exactly once.

## 6. Rejected-experiment record

Reject decisions leave the code on the branch behind default-off flags for reproducibility. Reverting is only decided by whoever integrates; none of this branch is proposed for merge.
- `staging_fast` alone, `verified_handoff` alone: small real gains, below threshold.
- `staging_clone` on ext4: never activates; no measured benefit.
- Policy/metadata caching (C): analysed only, not implemented, because the remaining per-candidate cost is dominated by file I/O removed above or by test execution.

## 7. Compatibility with production evidence

The optimizations preserve every security boundary: the pre-run tree hash is retained as the integrity anchor; verified-handoff holds bytes only in memory for one `evaluate` call under a 128 MiB cap; there are no hard links; certificates, ids and bundles are byte-identical with flags on and off (invariant suite, 15 invariants, hosted on all six flag sets). The single narrow semantic difference (over-cap blobs fall back to the unoptimized path) is documented in `docs/IO_AUDIT_AND_EQUIVALENCE.md`.

## 8. Limitations

- Hosted runners are noisy; wall-time intervals of ±15-20% occurred despite valid start conditions.
- Four runs of the same commit family are replicates of one design, not independent platforms.
- No model, token, or API-cost measurement was made; nothing here supports a claim about provider usage or cost.
- Local macOS timings are `INVALID_ENVIRONMENT` (load average ~9) and are not cited.
