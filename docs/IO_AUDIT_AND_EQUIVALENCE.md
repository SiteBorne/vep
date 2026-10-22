# I/O audit: which reads serve a distinct security boundary

Profile of one fresh protected certification (`benchmarks/profile_scale.py`, caller attribution; at 300 files every blob was read and hashed about eight times). Each row is one pass over the file contents of a snapshot. **Nothing was removed because the CAS is content-addressed**: content addressing says what a blob *should* hash to; only a read-and-hash says what is on disk now. No hash is taken from file modification times or other mutable metadata.

| # | Pass (code) | Obligation it serves | Distinct boundary? | Experiment |
|---|---|---|---|---|
| R1 | `take_snapshot` -> `read_regular_nofollow` (`snapshots.build_entries`) | defines the source identity from the bytes being submitted; symlink/race checks | **yes** (identity of the submission) | kept |
| R2 | `CAS.put` of an existing blob re-verifies it (`storage.CAS.put`) | "already stored" must mean "stored correctly"; a corrupt object is repaired by a rewrite | **yes** (store integrity) | kept |
| R3 | `register_candidate` -> `verify_snapshot` (`candidates.py:30`) | a candidate is accepted into the lifecycle only if its snapshot is fully present and valid; separate call, possibly a different process | **yes** (admission) | kept |
| R4 | `check_policy` -> `verify_snapshot` (`candidates.py:106`), called from `evaluate` | integrity before policy decisions | **same call chain as R5** | B: shares R5's pass |
| R5 | `evaluate` -> `verify_snapshot` (`execution.py:296`) | pre-execution integrity, **before** the budget is reserved and state changes | **yes** (it is the gate before spending); R4 is subsumed by it within one call | B: one pass for R4+R5 |
| R6 | `materialize` -> `CAS.get` per blob (verifies) | the bytes that will actually run | **yes** (use-time verification) | B: writes the bytes R5 already verified; no extra read |
| R7 | `tree_snapshot_id(staged)` before the run | staged tree equals the snapshot (staging fault, clone/copy fault, tampering between write and run) | **yes** | kept (this is also what makes the clone variant safe) |
| R8 | `tree_snapshot_id(staged)` after the run | the tests did not modify the source | **yes** | kept |

## Replacement mechanism (experiment B, `verified_handoff`)
* **Obligation preserved.** Within one `evaluate`, the first pass (R4, or R5 when the candidate was already policy-checked) reads every blob, checks its SHA-256 and keeps the verified bytes in a `BlobScope` (bounded at 128 MiB; blobs beyond the cap are simply not kept). R5 is skipped only for a snapshot id already fully verified in that scope. R6 writes the kept bytes; a blob that was not kept is read and verified by `CAS.get` as before.
* **Exactly what is trusted.** The bytes that were hashed are the bytes that are staged. That is *stronger* than before, where the bytes staged were a second read of a file that could have changed in between.
* **Mutation/concurrency.** If a blob changes on disk after its verifying read, the plain path fails at staging (`CorruptObject`) while the handoff path stages the verified bytes and the run proceeds on the correct source; neither can certify a tree that differs from the snapshot (R7 and R8 still run). Tests: `test_cas_blob_corrupted_after_the_verifying_read_is_never_certified_wrongly`, `test_concurrent_cas_tampering_during_staging_never_yields_a_wrong_certificate`.
* **Failure/rollback and the one semantic difference.** Corruption present *before* the evaluation is detected at the first pass, before any budget is reserved (same as before). A blob corrupted *during* the window and not kept (over the cap) is detected at staging, i.e. after the reservation, and takes the existing evaluator-error path (candidate rejected, funds held as UNCERTAIN) instead of the pre-reservation refusal. That narrow difference is stated here and tested; it affects only snapshots above the cap with a fault inside a millisecond window.
* **R2, R3, R7, R8 are not touched.**

## Replacement mechanism (experiment A, staging)
* `staging_fast`: same files, bytes, modes and read-only directories; directories created once; each file created with `O_EXCL|O_NOFOLLOW` at its final mode and written through the descriptor (no per-file `mkdir` and path-based `chmod`). Equivalence test compares complete trees under three umasks.
* `staging_clone`: macOS `clonefile` / Linux `FICLONE` copy-on-write instead of reading the blob. **Never a hard link**; the staged file is a distinct inode; writing it cannot reach the CAS (`test_writing_to_a_staged_file_never_reaches_the_cas`). A clone reads no bytes, so integrity of staged content rests on R7 (which stays); on any clone failure or unsupported filesystem it falls back to a normal write (`test_unsupported_clone_falls_back_to_a_normal_write`).

## Regression evidence for the optimized paths
`tests/test_staging_equivalence.py` (8) and `tests/test_staging_adversarial.py` (7) exercise the flags ON; the whole suite (536 tests) and the 15-invariant suite pass with every flag ON on macOS (APFS, clone path active), and again on hosted Linux in the `flags-on-tests` job.
