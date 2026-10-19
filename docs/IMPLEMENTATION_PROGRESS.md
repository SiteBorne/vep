# Implementation Progress (v0.5.0b1 effort)

Resumable ledger, **not evidence**. Evidence is test output and gate results.

BASELINE_COMMIT: 551612a (v0.4.0a1)
CURRENT_COMMIT: uncommitted work on top of 551612a
COMPLETED_PHASES: A, B; C partial (adapters done; live run attempted and FAILED; TokenReceipt wiring not done)
CURRENT_PHASE: D (build actions + cache done and tested; evidence-validity checks, dependency graph, CLI not done)

## Phase B: what exists
`src/vep/controller.py`: SQLite jobs with leases, per-job fencing token checked inside every committing transaction (reserve, EVALUATING, evidence, rejection, certificate), idempotent enqueue, bounded attempts, budget admission check, cooperative cancel, crash recovery (unknown-outcome work is failed and funds held UNCERTAIN, never re-run), `LocalToolWorker`, `IsolatedWorker` (fails closed). CLI: `vep run`, `vep jobs list|show|recover|cancel`.
Hooks added: `execution.evaluate(..., guard=)`, `certificates.certify(..., guard=)`, `errors.StaleLease`, DB schema v3.

VERIFIED_TESTS: `tests/test_controller.py` (14 tests incl. 4 real spawned processes certifying 8 candidates exactly once); full suite 326 passed; `gen_variables.py --check` clean; installed-CLI `vep run` end to end on a scratch project returned CERTIFIED.
FAILED_GATES: none known. The release gate (`scripts/release_check.sh`) has NOT been re-run since the changes.

## Not done (explicitly)
Phases C-L: agent adapter + usage provenance, build actions/cache, dependency graph + composition semantics, 2/4/8/16-worker measurements, independent (non-Python) verifier (no Go on host), VEP-on-VEP dogfood, extra projects, benchmarks vs baselines, public docs/announcement, launch gate, real gVisor test. Only `LocalToolWorker` and `IsolatedWorker` exist; no command or agent worker yet.

OPEN_DECISIONS: independent verifier language (Go not installed; Node/Rust availability unchecked); whether to run the live-agent test against the local `deepseek-r1:32b` model via Ollama (slow, 19 GB model).
NEXT_ACTION: finish Phase C (one bounded live Ollama run, which a prior attempt did not complete; TokenReceipt wiring: its usage_source enum lacks locally_measured/caller_supplied, so a schema decision is needed), then Phase D.
KNOWN_LIMITATIONS: cancellation does not kill running subprocesses; `check_policy` (PROPOSED to POLICY_CHECKED) is not fenced; single-host SQLite only; 4-process test is not a scalability result; announcement readiness: ANNOUNCEMENT_READY = NO.

## Phase C so far
`src/vep/agents.py`, `tests/test_agents.py` (10 tests). Full suite: 336 passed. Adapters never certify; output is registered as a PROPOSED candidate and must pass the controller/evaluator. A test confirms an agent that deletes the tests is not certified.

## Live agent attempt (recorded, negative)
`scripts/live_agent_check.py` against local Ollama `deepseek-r1:32b-qwen-distill-q4_K_M`, 900 s model timeout: **timed out with no output** (`docs/live_agent_run.json`, error_class RUNTIME_UNAVAILABLE, detail "timed out"). The test suite was also running on the same machine for part of that window, so this is not a clean measurement of the model. LIVE_AGENT_EXECUTION remains UNVERIFIED. (Superseded by attempt 2 below.)

## Phase D so far
`src/vep/builds.py`, `tests/test_builds.py` (8 tests). Full suite: 344 passed.

## Live agent attempt 2 (positive, N=1)
Model `qwen2.5-coder:7b` (pulled with user approval; the 32B model was then deleted at the user's request). `scripts/live_agent_check.py qwen2.5-coder:7b 600`: 4.1 s, runtime-reported 135 input / 106 output tokens, one file modified, candidate evaluated by the controller: PASS, CERTIFIED (TRUSTED_LOCAL). Output in `docs/live_agent_run.json`. Single run on a toy task; says nothing about reliability or the 32B model's slowness beyond the earlier timeout.
