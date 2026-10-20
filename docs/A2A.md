# VEP as an A2A 1.0 agent (JSON-RPC)

`vep-a2a` lets another agent submit verification work to VEP as an A2A task. It uses the official `a2a-sdk` (1.2.x); install with `pip install 'vep-protocol[a2a]'`.
It adds **no scheduling logic**: a task is mapped onto the existing durable VEP job.

```bash
export VEP_A2A_TOKEN=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')
vep-a2a --root /path/to/project --authority read,register,evaluate --trusted-local-execution --port 8421
```

* **Discovery.** Agent Card at `/.well-known/agent-card.json`: interface `JSONRPC` at `/a2a`, `protocolVersion` 1.0, bearer security scheme, three skills. Discovery does not imply permission:
  the card lists what the agent can do, the operator's flags decide what it will do.
* **Authentication.** Every JSON-RPC call needs `Authorization: Bearer <token>` (constant-time compare). The server will not start without a token of ≥ 16 characters, and refuses a
  non-loopback bind unless `--allow-nonlocal` is given (put TLS and rate limiting in front). `--token-expires` makes the token stop working at a given time (`401`, `token expired`).
* **Versioning.** Clients must send `A2A-Version: 1.0`; a missing header (interpreted by the SDK as 0.3), `0.3` or `9.0` is refused.
* **Skills** (a single JSON data part `{"skill": ..., ...}`): `vep.verify_change {objective_id, author?}`, `vep.get_status`, `vep.explain_failure {candidate_id}`. Free text is never interpreted.
  Unknown skills, extra arguments (`verdict`, `authority`, ...), invalid ids and calls beyond the operator's authority end the task `REJECTED` and change nothing.
* **Task ↔ job.** `verify_change` registers the working tree (`candidate_register`), queues the evaluation (`evaluate`), then reports the job: `WORKING` with the candidate and job ids, `COMPLETED`
  **only if VEP certified the candidate** (artifact `verification` with certificate and evidence ids), `FAILED` for a rejected or failed evaluation (artifact `failure-explanation`),
  `CANCELED` after `CancelTask` (which cancels the VEP job; the lease fence refuses the cancelled worker's later commits). A task deadline (`--task-timeout`, default 600 s) fails the task and cancels the job.
* **Idempotency.** The A2A `messageId` is the idempotency key. A duplicate or retried message (including after a lost response) reuses the same VEP candidate and job; it never registers or evaluates twice.
* **Never exposed.** Signing keys, the database and credentials do not appear in messages or artifacts; the adapter has no access path to them other than `vep.services` results.

## What is and is not qualified
Tested (`tests/test_a2a_server.py`, `tests/test_fault_injection.py`) against a real `vep-a2a` process with the **official a2a client** (streaming and non-streaming) and a hand-written JSON-RPC client:
malformed JSON/params, unknown method, wrong or missing version, missing/wrong/expired token, hostile payloads, read-only authority, full verification, failed verification, duplicate message,
lost response, cancellation, task deadline, unknown extension header. Streaming (SSE) responses were exercised on loopback only. Push notifications are not offered
(`pushNotifications: false`). Not qualified: public-internet exposure, multi-tenant use, task persistence across server restarts (A2A task state is in memory; the VEP job and candidate persist).
No official A2A inspector was run.
