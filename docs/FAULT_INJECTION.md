# Fault-injection and adversarial coverage map

Every row names tests that run in the normal suite. `tests/test_fault_injection.py::test_every_test_named_in_the_fault_injection_map_exists`
fails if a name here stops existing. "Real" means a real process, socket or file system fault, not a mock.

| Fault | Tests (what they prove) |
|---|---|
| Worker crash and restart | `tests/test_fault_injection.py::test_sigkill_of_a_real_worker_mid_evaluation_is_recovered_without_retry_or_false_certificate` (real SIGKILL: job FAILED with an unknown outcome, candidate REJECTED, funds UNCERTAIN, no certificate, no automatic re-run); `tests/test_controller.py::test_lease_expiry_mid_evaluation_is_not_retried_and_holds_funds` |
| Lease expiry and stale fencing | `tests/test_controller.py::test_stale_worker_is_fenced_at_commit`; `tests/test_controller.py::test_stale_worker_cannot_certify`; `tests/test_controller.py::test_attempts_are_bounded`; `tests/test_controller.py::test_four_real_processes_certify_each_candidate_exactly_once` |
| Idempotent repeated calls | `tests/test_controller.py::test_happy_path_certifies_once_and_is_idempotent`; `tests/test_controller.py::test_complete_is_idempotent_and_conflicting_replay_refused`; `tests/test_adversarial.py::test_F10_duplicate_requests_do_not_duplicate_spending`; `tests/test_execution.py::test_duplicate_evaluation_does_not_double_spend` |
| Duplicate MCP / A2A requests | `tests/test_mcp_server.py::test_idempotency_and_bounded_resources`; `tests/test_a2a_server.py::test_verify_change_end_to_end_idempotent_and_independently_checked` |
| Lost HTTP responses | `tests/test_fault_injection.py::test_a_lost_http_response_is_safely_retried_with_the_same_message_id` (the first delivery is abandoned mid-request; the retry produces one candidate and one job) |
| Revoked signers | `tests/test_trust_policy.py::test_key_revocation_and_rotation_semantics_on_a_real_key`; `tests/test_certificates.py::test_revoked_key_rejected`; suite 1.1 vectors `auth-103`..`auth-107` (Python and Node) |
| Malformed external trust policies | `tests/test_trust_policy.py::test_reference_agrees_with_every_vector`; `tests/test_trust_policy.py::test_every_authorized_reason_code_is_exercised` (suite 1.1 `MALFORMED_TRUST_POLICY`, `SUBJECT_UNSPECIFIED`) |
| Self-authorizing bundle (the original trust-anchor defect) | `tests/test_trust_anchor_risk.py::test_authorized_mode_rejects_the_same_forgery` |
| Cache corruption | `tests/test_builds.py::test_corrupted_cache_entry_is_a_miss_not_a_reuse`; `tests/test_adversarial.py::test_F11_cache_never_serves_results_for_changed_inputs_or_tampered_entries` |
| Incompatible cached action identities | `tests/test_cache_identity.py::test_every_material_input_changes_the_identity`; `tests/test_cache_identity.py::test_entries_written_by_the_old_format_are_not_reusable`; `tests/test_cache_identity.py::test_identity_domain_is_versioned_so_old_entries_cannot_be_reached` |
| Interrupted database transactions | `tests/test_fault_injection.py::test_a_process_killed_inside_a_transaction_leaves_no_partial_state`; `tests/test_fault_injection.py::test_an_exception_inside_a_transaction_rolls_back_every_statement`; `tests/test_budgets.py::test_transaction_rollback_on_failure`; `tests/test_hardening.py::test_partial_failure_in_receipt_settlement_rolls_back_everything` |
| SQLite contention | `tests/test_fault_injection.py::test_sqlite_contention_from_six_processes_loses_no_writes_and_raises_no_lock_errors` |
| Source mutation | `tests/test_adversarial.py::test_F05_candidate_mutates_workspace_during_evaluation`; `tests/test_adversarial.py::test_F07_certificate_for_obsolete_source`; `tests/test_hardening.py::test_deleted_file_changes_snapshot_identity_and_invalidates_certificate` |
| Test-runner shadowing | `tests/test_adversarial.py::test_F04_candidate_shadows_runner_or_stdlib`; `tests/test_execution.py::test_a_shadowed_report_can_never_pass` |
| Zero-test and all-skipped reports | `tests/test_adversarial.py::test_F01_exit_zero_with_no_tests`; `tests/test_adversarial.py::test_F02_every_test_skipped`; `tests/test_execution.py::test_all_skipped_candidate_cannot_certify` |
| Unauthorized tool calls | `tests/test_mcp_server.py::test_authority_is_enforced_by_the_operator_not_the_caller`; `tests/test_a2a_server.py::test_read_only_server_serves_status_and_rejects_writes` |
| Prompt-injected tool arguments | `tests/test_mcp_server.py::test_invalid_and_hostile_arguments_get_stable_codes_and_change_nothing`; `tests/test_a2a_server.py::test_hostile_inputs_are_rejected_without_state_change`; `tests/test_agents.py::test_unlisted_tool_and_option_injection_refused` |
| Candidate-provided forged reports | `tests/test_fault_injection.py::test_a_candidate_that_prints_or_writes_a_passing_report_cannot_certify`; `tests/test_execution.py::test_malformed_report_files` |
| Competing candidate composition | `tests/test_adversarial.py::test_F19_certificates_do_not_transfer_to_a_composition`; `tests/test_adversarial.py::test_F19_semantic_interference_is_caught_by_the_composed_evaluation` |
| Wrong protocol versions | `tests/test_a2a_server.py::test_unauthorized_malformed_wrong_version_and_unknown_requests`; `tests/test_compat.py::test_R007_failures_return_distinct_nonzero_exit_codes` |
| Unknown client capabilities | `tests/test_fault_injection.py::test_unknown_extensions_and_unknown_fields_are_not_silently_honoured` |
| Failed optional dependencies | `tests/test_fault_injection.py::test_missing_mcp_extra_fails_clearly_with_exit_2`; `tests/test_fault_injection.py::test_missing_a2a_extra_fails_clearly_with_exit_2`; `tests/test_fault_injection.py::test_missing_claude_extra_names_the_extra`; `tests/test_fault_injection.py::test_the_core_cli_works_without_any_optional_extra`; `tests/test_hardening.py::test_R020_missing_optional_pytest_fails_clearly_before_executing` |
| Expired token / expired task | `tests/test_a2a_server.py::test_token_expiry_is_enforced`; `tests/test_a2a_server.py::test_task_deadline_expires_and_cancels_the_job`; `tests/test_a2a_server.py::test_cancellation_cancels_the_vep_job` |
| Evidence reuse misuse | `tests/test_evidence_reuse.py::test_reuse_is_refused_when_any_exact_input_differs`; `tests/test_evidence_reuse.py::test_failed_evidence_is_never_reused`; `tests/test_evidence_reuse.py::test_tampered_chain_is_rejected_by_the_verifier` |
| Evidence transplanted to another candidate | `tests/test_hardening.py::test_evidence_cannot_be_replayed_onto_another_candidate` |

## Historical failure classes (invariant tests, not warnings)

| Past failure | Invariant test |
|---|---|
| Fixture execution represented as production | `tests/test_adversarial.py::test_F17_local_execution_is_never_represented_as_isolated`; `tests/test_migration_fixtures.py` (frozen fixtures are loaded as fixtures) |
| Aggregate readiness contradicting subsystem flags | `tests/test_launch_gate.py` (gate verdict derived from the individual gates) |
| Mutable debug/test hooks bypassing public API restrictions | `tests/test_mcp_server.py::test_authority_is_enforced_by_the_operator_not_the_caller` (no tool accepts authority, trust level or verdict) |
| Unprotected acceptance suites | `tests/test_adversarial.py::test_F03_candidate_edits_the_required_tests`; `tests/test_hardening.py::test_SR06_substituting_the_required_module_itself_is_blocked_by_its_digest` |
| Incorrectly reused source identities | `tests/test_hardening.py::test_exec_bit_change_invalidates_certificate`; `tests/test_cache_identity.py::test_every_material_input_changes_the_identity` |
| Credentials or signing material exposed to candidate execution | `tests/test_adversarial.py::test_F06_evaluation_environment_is_scrubbed`; `tests/test_adversarial.py::test_F06_tampering_with_the_signing_key_is_detected` |
| Green workflows without verified release artifacts | `tests/test_release.py::test_R021_go_only_when_every_required_gate_passes`; `tests/test_hosted_benchmark.py::test_source_under_test_is_pinned_and_checked_against_the_release` |

Not covered by an automated test (stated, not hidden): disk-full during CAS writes, clock changes during leases (leases use caller-supplied or
monotonic-free wall time), and network partitions between a remote worker and the workspace (there are no remote workers).
