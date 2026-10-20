# Register and verify a change

Needs `register` (and `evaluate` plus the operator's trusted-local switch to run the evaluation).

1. `vep_status` - confirm authority and that a workspace exists. If there is no objective yet, `vep_objective_create(title, description, budget, idempotency_key)`: this freezes the current tree and its existing tests as the baseline. Do this BEFORE editing code. Keep the returned `objective_id`.
2. Make the change. Add tests for new behaviour; do not edit or delete protected existing tests (the policy rejects that).
3. `vep_candidate_register(objective_id, idempotency_key)` snapshots the working tree as a candidate. It stays `PROPOSED`; nothing is certified.
4. `vep_evaluate(candidate_id)` queues the protected evaluation. If it returns `VEP_E_NOT_AUTHORIZED`, stop and tell the user the exact command the operator must enable; do not retry.
5. Poll `vep_job_status(candidate_id=...)` until the state is terminal. Do not poll faster than every few seconds.
6. If the candidate is `CERTIFIED`: `vep_verify_certificate(certificate_id)` and report the trust level, tests passed/run, and the snapshot id. If `REJECTED` or the job failed: follow [explain-failure.md](explain-failure.md).
7. Any later edit to the tree invalidates the certificate for the new tree; register a new candidate.
