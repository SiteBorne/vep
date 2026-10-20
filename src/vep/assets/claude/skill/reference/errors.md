# Stable error codes

Tool errors are `isError` results with `{"error": {"code", "message", "detail"}}`.

| Code | Meaning | What to do |
|---|---|---|
| VEP_E_NOT_AUTHORIZED | The operator did not grant this authority | Tell the user which authority is needed; do not work around it |
| VEP_E_EVALUATION_DISABLED | Evaluation runs candidate code unisolated and the operator has not enabled it | Tell the user; do not retry |
| VEP_E_NOT_FOUND | Unknown id or no workspace | Check the id with `vep_status` / `vep_candidate_state` |
| VEP_E_INVALID_ARGUMENT | Bad id format, range or value | Fix the argument |
| VEP_E_STATE | The object's state does not allow this (also a reused idempotency key with different arguments) | Read the current state; use a new key if the request really differs |
| VEP_E_BUDGET | Budget cannot cover the action | Report budget with `vep_budget_status` |
| VEP_E_POLICY | The frozen policy forbids this | Read the message; change the source, not the policy |
| VEP_E_VERIFICATION_FAILED | A certificate or evidence check failed | Run `vep_explain_failure`; never present it as verified |
| VEP_E_ISOLATION_UNAVAILABLE | Requested isolation is not available | Report it; do not fall back silently |
| VEP_E_INTERNAL | Unexpected server error | Report it; do not retry in a loop |
