# Test Priority Plan

This plan is execution-focused: each tier has release-gate intent, explicit test names, and ownership by module/file.

## Tier Definitions

- P0: Release blockers. Must pass for every release candidate.
- P1: Security/policy hardening. Must pass on main branch before feature merges.
- P2: Economic/lifecycle correctness. Required before protocol parameter changes.
- P3: Resilience and adversarial depth. Required before major network-scale rollout.

## Ownership Model

- Consensus owner: `src/consensus/*`, `src/finality/*`, `src/state/*`
- UTXO/validation owner: `src/utxo/*`, `src/privacy/*`, `src/common/address*`
- Mempool/policy owner: `src/mempool/*`, `src/consensus/policy_*`
- Networking owner: `src/p2p/*`, `src/node/*`, `src/ingress/*`
- Economics owner: `src/consensus/rewards*`, validator lifecycle paths
- Wallet/SDK owner: wallet logic and persistence paths

---

## P0: Determinism + Consensus Safety (Release Blocking)

### 1) Consensus replay equivalence
- Owner: Consensus owner
- Module/file: `tests/test_frontier_replay.cpp`, `tests/test_frontier_execution.cpp`, `tests/test_state_commitment.cpp`
- Existing:
  - `test_frontier_execution_is_deterministic_for_same_parent_and_slice`
  - `test_frontier_replay_is_deterministic_for_same_parent_and_record_sequence`
  - `test_frontier_transition_identity_matches_across_two_nodes_with_same_parent_and_ingress`
- Add next:
  - `test_frontier_replay_equivalence_across_two_nodes_with_shuffled_arrival_same_ordered_slice`
  - `test_state_commitment_identical_after_restart_at_each_epoch_boundary`
  - `test_frontier_apply_rejects_nondeterministic_transition_metadata`

### 2) Tx validity invariants (no inflation, bounded checks)
- Owner: UTXO/validation owner
- Module/file: `tests/test_protocol_scope.cpp`, `tests/test_confidential_tx.cpp`, `tests/test_privacy.cpp`
- Existing:
  - `test_protocol_scope_rejects_duplicate_inputs`
  - `test_protocol_scope_rejects_input_output_sum_mismatch`
  - `test_validate_tx_v2_rejects_commitment_balance_mismatch`
- Add next:
  - `test_protocol_scope_rejects_fee_overflow_u64_boundary`
  - `test_protocol_scope_rejects_value_overflow_total_output_sum`
  - `test_validate_tx_v2_rejects_duplicate_nullifier_like_confidential_spend_id`

### 3) Finality / fork-choice correctness
- Owner: Consensus owner
- Module/file: `tests/test_finality_certificate.cpp`, `tests/test_integration.cpp`, `tests/test_state_commitment.cpp`
- Existing:
  - `test_finality_certificate_serialize_roundtrip`
  - `test_canonical_finality_certificate_hash_is_deterministic_under_signature_reordering`
- Add next:
  - `test_finality_rejects_quorum_below_threshold_exact_boundary`
  - `test_fork_choice_prefers_highest_finalized_view_then_weight`
  - `test_equivocation_evidence_changes_fork_choice_deterministically`

---

## P1: Policy/Security Hardening

### 4) Mempool deterministic admission and eviction
- Owner: Mempool/policy owner
- Module/file: `tests/test_mempool.cpp`
- Existing:
  - `test_mempool_selection_order_fee_rate_then_absolute_fee_then_txid`
  - `test_mempool_full_rejects_equal_or_worse_and_evicts_one_better_tx`
  - `test_mempool_rejects_double_spend_across_transactions`
- Add next:
  - `test_mempool_eviction_is_stable_under_equal_fee_rate_and_equal_fee`
  - `test_mempool_reject_reason_is_deterministic_for_multi_violation_tx`
  - `test_mempool_txv2_policy_boundary_at_activation_height_exact`

### 5) Parse/serialization rejection surface
- Owner: Networking owner + UTXO/validation owner
- Module/file: `tests/test_codec.cpp`, `tests/test_p2p.cpp`, `tests/test_hardening.cpp`
- Existing:
  - `test_parse_any_tx_dispatches_v1_and_rejects_unknown_version`
  - `test_tx_message_rejects_oversized_payload`
- Add next:
  - `test_codec_rejects_nonminimal_varint_in_all_message_types`
  - `test_p2p_rejects_frame_with_valid_crc_but_truncated_body`
  - `test_tx_parser_rejects_extra_trailing_bytes_after_valid_tx`

### 6) Validation cost bounds / verify budget
- Owner: UTXO/validation owner
- Module/file: `tests/test_protocol_scope.cpp`, `tests/test_privacy.cpp`
- Existing:
  - `test_protocol_scope_rejects_tx_when_verify_budget_exceeded_by_join_request_outputs`
- Add next:
  - `test_protocol_scope_verify_budget_exact_limit_accepts_limit_plus_one_rejects`
  - `test_protocol_scope_script_size_limit_exact_boundary`
  - `test_protocol_scope_input_count_limit_exact_boundary`

---

## P2: Economic and Lifecycle Correctness

### 7) Monetary conservation and reward split
- Owner: Economics owner
- Module/file: `tests/test_monetary.cpp`
- Existing:
  - `test_reward_schedule_exact_total_supply`
  - `test_epoch_settlement_pays_exact_accrued_scores`
- Add next:
  - `test_reward_split_rounding_is_conservative_and_deterministic`
  - `test_fee_distribution_no_unit_loss_across_many_remainder_patterns`
  - `test_emission_transition_height_exact_boundary_no_double_mint`

### 8) Validator lifecycle transitions
- Owner: Economics owner + Consensus owner
- Module/file: `tests/test_validator_lifecycle.cpp`, `tests/test_validator_onboarding.cpp`, `tests/test_bonding.cpp`
- Existing:
  - `test_validator_cooldown_enforced_for_exit_rejoin`
  - `test_unbond_delay_enforced`
  - `test_slash_consumes_bond_and_bans_validator`
- Add next:
  - `test_validator_rejoin_exactly_at_cooldown_height_accepts`
  - `test_unbond_finalize_exact_boundary_height_accepts_minus_one_rejects`
  - `test_banned_validator_cannot_regain_eligibility_through_any_path`

### 9) Availability and scoring state transitions
- Owner: Consensus owner
- Module/file: `tests/test_availability.cpp`
- Existing:
  - `test_availability_score_update_is_deterministic`
  - `test_availability_lifecycle_persistence_across_restart_is_identical`
- Add next:
  - `test_availability_penalty_recovery_exact_threshold_boundaries`
  - `test_availability_score_saturation_limits_are_enforced`
  - `test_availability_checkpoint_inputs_are_order_independent`

---

## P3: Resilience and Adversarial Depth

### 10) Restart/recovery and persistence exactness
- Owner: Networking owner + Consensus owner
- Module/file: `tests/test_snapshot.cpp`, `tests/test_frontier_replay.cpp`, `tests/test_wallet_store.cpp`
- Existing:
  - `test_snapshot_import_rejects_nonempty_db`
  - `test_frontier_storage_replay_reproduces_identical_state_on_restart`
- Add next:
  - `test_restart_mid_epoch_then_finalize_matches_no_restart_state_root`
  - `test_partial_ingress_persist_crash_recovery_fails_closed`
  - `test_wallet_store_recovery_rejects_schema_version_downgrade_bytes`

### 11) Adversarial fuzz and mutation suites
- Owner: Shared (UTXO/validation + Networking)
- Module/file: `fuzz/*`, plus tests in `tests/test_hardening.cpp`
- Existing:
  - Existing fuzz targets: `fuzz_p2p_frame`, `fuzz_tx_parse`
- Add next:
  - `fuzz_tx_v2_parse_and_validate_budgeted`
  - `fuzz_script_sig_parser_and_p2pkh_decoder`
  - `fuzz_ingress_certificate_decode_and_signature_paths`

### 12) Long-horizon deterministic simulations
- Owner: Consensus owner
- Module/file: `tests/test_integration.cpp`, `tests/test_availability.cpp`
- Existing:
  - `test_availability_long_horizon_replay_equivalence_across_continuous_epoch_and_random_restart_schedules`
- Add next:
  - `test_10k_block_multi_validator_replay_equivalence_two_nodes`
  - `test_long_horizon_churn_slash_rejoin_determinism`
  - `test_long_horizon_fee_market_pressure_does_not_break_finality_progress`

---

## CI Gating Rules

- `P0` suite: required on every PR and release branch.
- `P1` suite: required on every PR touching `src/consensus`, `src/utxo`, `src/mempool`, `src/p2p`.
- `P2` suite: required on PRs touching economics parameters, lifecycle logic, reward distribution.
- `P3` suite: run nightly and before release tag.

## Execution Order (Recommended)

1. Close all missing `P0` tests.
2. Close deterministic mempool and parser-hardening gaps in `P1`.
3. Lock economic boundary tests in `P2` before any parameter updates.
4. Expand fuzz and long-horizon coverage in `P3`.

## PR Template Snippet

Every protocol PR should include:

- Tier impacted: `P0` / `P1` / `P2` / `P3`
- Invariant changed: one sentence
- Tests added/updated: exact test names
- Determinism check: pass/fail with command output summary
- Worst-case validation cost impact: bounded/unbounded + justification
