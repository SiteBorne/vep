# Implementation Progress (v0.5.0b1 effort)

Resumable ledger, **not evidence**. Evidence is test output and gate results.

BASELINE_COMMIT: 551612a (v0.4.0a1)
CURRENT_COMMIT: uncommitted work on top of 551612a
COMPLETED_PHASES: A (baseline, see REAL_WORLD_BASELINE.md); B (execution controller, see below)
CURRENT_PHASE: C (agent/tool integration) not started

## Phase B: what exists
`src/vep/controller.py`: SQLite jobs with leases, per-job fencing token checked inside every committing transaction (reserve, EVALUATING, evidence, rejection, certificate), idempotent enqueue, bounded attempts, budget admission check, cooperative cancel, crash recovery (unknown-outcome work is failed and funds held UNCERTAIN, never re-run), `LocalToolWorker`, `IsolatedWorker` (fails closed). CLI: `vep run`, `vep jobs list|show|recover|cancel`.
Hooks added: `execution.evaluate(..., guard=)`, `certificates.certify(..., guard=)`, `errors.StaleLease`, DB schema v3.

VERIFIED_TESTS: `tests/test_controller.py` (14 tests incl. 4 real spawned processes certifying 8 candidates exactly once); full suite 326 passed; `gen_variables.py --check` clean; installed-CLI `vep run` end to end on a scratch project returned CERTIFIED.
FAILED_GATES: none known. The release gate (`scripts/release_check.sh`) has NOT been re-run since the changes.

## Not done (explicitly)
Phases C-L: agent adapter + usage provenance, build actions/cache, dependency graph + composition semantics, 2/4/8/16-worker measurements, independent (non-Python) verifier (no Go on host), VEP-on-VEP dogfood, extra projects, benchmarks vs baselines, public docs/announcement, launch gate, real gVisor test. Only `LocalToolWorker` and `IsolatedWorker` exist; no command or agent worker yet.

OPEN_DECISIONS: independent verifier language (Go not installed; Node/Rust availability unchecked); whether to run the live-agent test against the local `deepseek-r1:32b` model via Ollama (slow, 19 GB model).
NEXT_ACTION: Phase C: `AgentAdapter` interface + structured-subprocess adapter with allowlist and usage-provenance labels.
KNOWN_LIMITATIONS: cancellation does not kill running subprocesses; `check_policy` (PROPOSED to POLICY_CHECKED) is not fenced; single-host SQLite only; 4-process test is not a scalability result; announcement readiness: ANNOUNCEMENT_READY = NO.
