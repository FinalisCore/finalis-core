# Invariants

Rules that must never break. Each one names the code that enforces it and the test that proves it.
Change a rule only together with its test, the spec in `docs/spec/`, and the TLA+ model in `formal/` where one exists.
**No test** marks a gap: add one before changing that code.

## Finality (two-phase: prevote → polka → lock → precommit)
Spec: `docs/spec/TWO_PHASE_FINALITY.md`. Model: `formal/two_phase_finality*.tla`.

| # | Invariant | Enforced in | Test |
|---|---|---|---|
| F1 | At most one transition finalizes per height. | `src/node/node_consensus.cpp` | `test_only_one_block_can_finalize_per_height_after_vote_locking`, `test_db_rejects_conflicting_same_height_finalized_writes`, `test_conflicting_same_height_finalized_artifacts_fail_loud_on_load` |
| F2 | Lock rule: a locked node does not prevote for a conflicting value unless a newer polka moves the lock. | `Node` vote-lock logic | `test_locked_node_refuses_conflict_and_late_round0_finality_completes`, `test_newer_polka_moves_the_lock` |
| F3 | Vote-round floor: a node never votes below its highest locked or prevoted round at that height. TLC found a fork without this rule. | `Node::local_vote_round_floor_locked` | `test_no_vote_below_highest_voted_round_after_round_reset` |
| F4 | Prevotes and locks are durable before they are sent. A failed write means no precommit. | `persist_consensus_safety_state_locked` | `test_vote_lock_survives_restart_and_blocks_conflicting_vote`, `test_restart_between_prevote_and_precommit`, `test_pf_lock_write_failure_*` |
| F5 | Fail-stop: after a failed durable write, all later writes and vote rebroadcasts are blocked until reopen. | `safety_storage_failed()`, storage write fence | `test_storage_failed_durable_write_blocks_all_later_writes_until_reopen`, `test_storage_write_fence_blocks_every_write` |
| F6 | Finality needs a quorum at or above the threshold, counted exactly. | finality certificate checks | `test_finality_rejects_quorum_below_threshold_exact_boundary`, `test_exiting_validator_outflow_does_not_inflate_quorum_or_signature_count` |
| F7 | A POL must be a valid polka from a lower round for that same proposal. | proposal validation | `test_pol_must_be_a_valid_lower_round_polka_for_the_proposal` |
| F8 | A future-round message does not advance the round without valid justification. | round handling | `test_future_round_proposal_does_not_advance_round_without_valid_justification`, `test_future_round_vote_does_not_advance_round_prematurely` |
| F9 | Same-round equivocation is rejected, and both prevote and precommit equivocation are slashable. | `VoteTracker`, slash evidence | `test_vote_tracker_rejects_same_round_equivocation`, `test_slash_evidence_parsing_and_validation`, `test_prevote_slash_evidence_validation` |
| F10 | No prevote for a proposal whose next-state commitment does not match local execution. | proposal validation | `test_no_prevote_for_proposal_with_wrong_next_state_commitment` |

## Signatures and chain identity
| # | Invariant | Enforced in | Test |
|---|---|---|---|
| S1 | Every consensus signature covers `D = sha256d("SC-CHAIN-DOMAIN-V1" ‖ network_id ‖ genesis_hash)`. | `consensus_chain_domain` (`src/utxo/validate.hpp`) | `test_unbond_and_spend_signed_for_one_chain_are_invalid_on_another` |
| S2 | Slash evidence from another chain is rejected. | slash evidence validation | `test_slash_evidence_from_another_chain_is_rejected` |
| S3 | A finality certificate's canonical hash does not depend on signature order. | certificate hashing | `test_canonical_finality_certificate_hash_is_deterministic_under_signature_reordering` |

## Leader randomness (VRF)
| # | Invariant | Enforced in | Test |
|---|---|---|---|
| V1 | The VRF is RFC 9381 ECVRF-EDWARDS25519-SHA512-TAI, byte for byte. | `src/crypto/vrf.cpp` | `test_vrf_matches_rfc9381_edwards25519_tai_vectors` |
| V2 | VRF output does not depend on the libsodium version's point validation. This is a consensus risk, so never route it through `crypto_core_ed25519_is_valid_point`. | `src/crypto/vrf.cpp` | `test_vrf_proof_does_not_depend_on_libsodium_point_validation` |
| V3 | The node refuses to start if the VRF self-test fails. | `crypto::vrf_init()` in `src/node/node.cpp` | No test |
| V4 | The VRF output is the leader's only input to randomness, and the proof is checked. | frontier validation | `test_frontier_leader_vrf_is_checked_and_is_the_only_leader_input_to_randomness` |
| V5 | Small-order and non-canonical keys and points are rejected. | `src/crypto/vrf.cpp` | `test_vrf_rejects_small_order_and_non_canonical_public_keys`, `test_vrf_rejects_non_canonical_off_curve_and_small_order_encodings` |

## Confidential UTXO (enabled from genesis)
Spec: `docs/spec/CONFIDENTIAL_UTXO_SPEC.md`.

| # | Invariant | Enforced in | Test |
|---|---|---|---|
| C1 | Inputs and outputs balance homomorphically, with no hidden inflation. | `src/utxo/` validate | `test_validate_tx_v2_rejects_commitment_balance_mismatch`, `test_commitment_sum_is_homomorphic` |
| C2 | The supply audit holds, and it detects inflation. | supply audit | `test_confidential_supply_audit_invariant_holds`, `test_confidential_supply_audit_detects_inflation` |
| C3 | Range proofs and memos have the right shape and stay within bounds. | `src/utxo/` validate | `test_validate_tx_v2_rejects_confidential_range_proof_or_memo_bounds`, `test_range_proof_wrong_shape_rejected` |
| C4 | No duplicate spend IDs, and the first valid conflicting spend wins. | validate, frontier execution, mempool | `test_validate_tx_v2_rejects_duplicate_nullifier_like_confidential_spend_id`, `test_frontier_execution_first_conflicting_valid_spend_wins`, `test_mempool_rejects_double_spend_across_transactions` |
| C5 | The wallet imports a coin only if the memo's (amount, blind) opens `value_commitment`. | `src/wallet/` receive | `test_confidential_receive_rejects_memo_that_does_not_open_commitment` |
| C6 | Blind = `hash_to_scalar("FINALIS/conf-output/blind/v1", seed ‖ one_time_pubkey)`. | `src/wallet/confidential_keys.cpp` | `test_confidential_output_blind_is_derived_from_seed_and_output_key` |
| C7 | Confidential verification weight per block is capped. | frontier execution | `test_frontier_execution_rejects_slice_over_block_confidential_verify_weight`, `test_txv2_confidential_verify_weight_formula` |

## State and determinism
| # | Invariant | Enforced in | Test |
|---|---|---|---|
| D1 | The incrementally maintained UTXO root equals a full recomputation. | `check_utxo_tree_against` (`src/consensus/frontier_execution.cpp`) | Every test: `tests/test_main.cpp` enables `set_utxo_tree_crosscheck(true)` |
| D2 | Replay is deterministic for the same parent and record sequence. | frontier replay | `test_frontier_replay_is_deterministic_for_same_parent_and_record_sequence`, `test_smt_determinism_across_replay` |
| D3 | A tampered state root or decisions commitment is rejected. | frontier replay | `test_frontier_replay_rejects_tampered_next_state_root`, `test_frontier_replay_rejects_tampered_decisions_commitment` |
| D4 | Committee selection and the proposer schedule are deterministic. | `src/consensus/` | `test_committee_root_is_deterministic`, `test_proposer_schedule_is_deterministic` |
| D5 | Transition timestamps strictly increase. | frontier apply | `test_frontier_apply_requires_increasing_timestamp` |
| D6 | No prevote for a transition more than `kMaxTransitionTimestampDriftS` (60 s) in the future. | `src/node/node_consensus.cpp` | `test_validator_never_prevotes_a_transition_from_the_future` |
| D7 | Durable storage is RocksDB only. The file backend fails configure unless the build is fuzz or test only. | `CMakeLists.txt` | ctest `configure-rejects-file-backend` |
| D8 | Memoized SWE work (settlement decryption, inclusion proof) never changes a result: the memo key is sha256d of every input, a hit returns what the computation returns, and only a passing proof is remembered. | `TimedMemo` (`src/consensus/frontier_execution.cpp`) | `test_prewarmed_timed_openings_give_the_same_state_without_decrypting_again`, `test_timed_opening_jobs_include_long_locks_opened_by_the_block`, `test_timed_proof_memo_remembers_only_a_passing_proof` |
| D9 | Only the round leader can make a node decrypt: a network proposal's settlement openings are prewarmed only after its proposer signature verifies against the round leader. | `Node::prewarm_proposal_timed_openings` (`src/node/node_consensus.cpp`) | `test_proposal_prewarm_requires_the_round_leaders_signature` |
| D10 | Recorded history replays under the current code: a consensus rule change carries a per-network activation height, and heights below it validate under the old rule. v2.2.13 broke this (fresh nodes rejected testnet-3 block 37). | `NetworkConfig` activation heights (e.g. `ingress_certifier_terms_activation_height`) | CI `history-replay` (`scripts/replay_history_check.sh`: testnet-3 genesis → 5173 offline with `--no-fast-start`), `test_frontier_lane_prefix_uses_whole_epoch_terms_below_the_terms_activation_height` |

## Upgrade signals (signaled activation)
| # | Invariant | Enforced in | Test |
|---|---|---|---|
| U1 | An `SCUPGSIG` output is valid only from the network's `upgrade_signal_activation_height` (mainnet 0, testnet-3 not yet set), has zero value, appears at most once per transaction, is not part of a timed body, and carries the validator key's signature over the chain domain, the upgrade id and the key: a signal from another chain or another key is rejected. | `validate_special_script_semantics` (`src/utxo/validate.cpp`) | `test_upgrade_signal_validation_checks_value_signature_chain_and_count`, `test_upgrade_signal_script_roundtrip_and_layout` |
| U2 | Signal admission and `UPG:` state are functions of finalized state only, never of the binary's upgrade table (A1), so binaries that know an upgrade and binaries that do not derive the same state. A signal is admitted from an active validator, once per operator per id, and, unless the upgrade is locked in or active, only while the operator holds fewer than `kMaxOpenUpgradeSignalsPerOperator` open signals. The first signal creates the record with `first_signal_height`. Block derivation, the node's mempool and the lightserver pre-check use the same rule (`consensus::upgrade_signal_admission_error` against finalized state), so a proposer and a validator always agree. Admitted signals are recorded per canonical operator in `upgrade_records`. | `apply_validator_state_changes_from_txs` (`src/consensus/canonical_derivation.cpp`), `SpecialValidationContext::upgrade_signal_admission` | `test_upgrade_signal_admission_and_apply`, `test_frontier_apply_records_upgrade_signal_and_commits_it`, `test_upgrade_signal_for_unknown_upgrade_keeps_old_and_new_binaries_on_one_state` |
| U3 | `upgrade_records` is in the post-state commitment once non-empty, appended after every older field: no state below `upgrade_signal_activation_height` can hold a record, so recorded history keeps its commitments (D10). It persists as `UPG:` rows in both persist paths, loads at start, and travels in snapshots. | `consensus_post_state_preimage`, `DB::load_upgrade_records`, `storage/snapshot.cpp` | `test_frontier_apply_records_upgrade_signal_and_commits_it`, `test_upgrade_record_codec_and_commitment_root`, `test_snapshot_carries_every_row_fast_start_loads`, CI `history-replay` |
| U4 | Upgrade states change only at an epoch end L, in canonical derivation, right after committee(L+1) is derived, for every record, whether or not the binary knows the upgrade. Lock-in needs signalers >= ceil(2/3) of operators active at L+1, a quorum of committee(L+1)'s seats, and, when committee(L+1) derived NORMAL, its `availability_min_eligible_operators`. Lock-in is checked before the window end (`first_signal_height + upgrade_signal_window_blocks`); a record past it fails and is removed. Activation is the start of L+2. No record is ever created at an epoch end, so a chain without signals keeps its commitments. | `advance_upgrade_records_at_epoch_end`, `upgrade_lock_in_inputs`, `canonical_upgrade_active` (`src/consensus/canonical_derivation.cpp`) | `test_frontier_upgrade_locks_in_at_epoch_end_and_activates_two_epochs_later`, `test_upgrade_records_advance_at_epoch_end_from_checkpoint_inputs`, CI `history-replay` |
| U5 | From an upgrade's activation height on, an operator that has not signaled it is not a committee candidate in NORMAL or FALLBACK mode, is not counted in `qualified_depth` or the eligible-operator count, is not recovered by emergency prior-committee recovery and is not the empty-active-set escape member. The exclusion changes nothing else: bond, status and availability state stay as they are, and a later signal restores exactly the checkpoint an on-time signal gives. With no records derivation is unchanged. | `operator_eligible_under_upgrades` (`src/consensus/upgrade_activation.cpp`), `finalized_committee_candidates_for_height`, `count_eligible_operators_at_checkpoint`, `qualified_depth_at_checkpoint`, `emergency_fallback_committee_members`, `empty_active_set_escape_member` (`src/consensus/canonical_derivation.cpp`); CHECKPOINT_DERIVATION_SPEC §6.4 | `test_checkpoint_excludes_non_signalers_from_activation_and_late_signal_restores_eligibility`, `test_emergency_fallback_committee_skips_non_signalers_after_activation`, `test_upgrade_excludes_non_signalers_from_committees_from_activation_on`, CI `history-replay` |
| U6 | A node never proposes, prevotes, precommits or timeout-votes at a height where a locked-in upgrade it does not implement is active, and reports `upgrade_required` from that height. Its handshake fingerprint covers exactly the active upgrades it implements, so before any activation it equals the fingerprint of releases without signaled activation, and from an activation on peers that disagree on the active rules disconnect. | `Node::abstaining_at_height_locked`, `Node::local_consensus_rules_fingerprint_locked` (`src/node/`), `consensus_rules_fingerprint` (`src/common/chain_id.cpp`), `consensus::unimplemented_locked_in_upgrades` | `test_node_upgrade_activation_changes_fingerprint_and_stops_signing_when_unimplemented`, `test_rules_fingerprint_covers_active_upgrades_only_when_present`, `test_upgrade_handshake_and_required_helpers`, `test_quorum_diagnosis_reports_upgrade_required` |

## Ingress certifiers (lanes)
| # | Invariant | Enforced in | Test |
|---|---|---|---|
| I1 | An ingress certificate is valid only in its certifier term: its epoch field is the term's first height, and terms tile each committee epoch. Below `ingress_certifier_terms_activation_height` (testnet-3: 4801, else 0) a term is the whole epoch, so history from before C1 replays. | `consensus::ingress_certifier_term_start`, `ingress_certifier_term_blocks_at`, frontier lane prefix, `drop_stale_unfinalized_ingress_locked` | `test_frontier_lane_prefix_requires_the_certifier_term_of_the_block`, `test_ingress_certifier_terms_tile_each_epoch`, `test_frontier_lane_prefix_uses_whole_epoch_terms_below_the_terms_activation_height` |
| I2 | Every node names the same certifier for a (term, lane), from finalized data only (committee and the last W `prev_finality_signers`); a node without that data does not certify. | `Node::designated_ingress_certifier_locked` | `test_ingress_certifiers_agree_across_nodes_and_skip_a_stopped_validator` |
| I3 | A certifier that stops signing holds its lane for at most a liveness window plus a term. | `consensus::designated_ingress_certifier` (live members only) | `test_tx_final_within_epoch_when_designated_certifier_offline`, `test_designated_ingress_certifier_is_drawn_from_live_committee_members` |

## Monetary
| # | Invariant | Enforced in | Test |
|---|---|---|---|
| M1 | The reward schedule sums exactly to total supply. | `src/consensus/` monetary | `test_reward_schedule_exact_total_supply`, `test_reward_schedule_exact_total_supply_across_annual_budgets` |
| M2 | The turnstile pool never goes negative, and it is in the state commitment. | turnstile | `test_turnstile_rejects_negative_pool_block`, `test_turnstile_state_commitment_includes_p` |
| M3 | The base fee stays within its bounds. | fee logic | `test_base_fee_follows_block_fullness_and_never_leaves_its_bounds` |
| M4 | A slash consumes the bond and bans the validator. | slashing | `test_slash_consumes_bond_and_bans_validator` |
