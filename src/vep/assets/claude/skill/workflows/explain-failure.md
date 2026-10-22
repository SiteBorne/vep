# Explain a failed invariant

Read-only; works with the default authority.

1. `vep_explain_failure(candidate_id)` (or `job_id`). It returns the failed invariant, a reason, the remedy, a bounded preview of failing tests, and log handles.
2. State the invariant and reason in the user's terms. Typical ones: a protected test was changed or removed; the test count fell below the policy minimum; the evaluator timed out; the snapshot changed after evaluation.
3. Only if the preview is not enough, `vep_read_artifact(digest, offset, limit)` for the relevant log handle, one page at a time.
4. Fix the cause in the source, not by weakening tests. Then register a new candidate (see register-and-verify.md).
5. Do not retry an evaluation unchanged expecting a different result; infrastructure failures are labelled as such in the job state.
