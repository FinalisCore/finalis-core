// SPDX-License-Identifier: MIT

#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "common/chain_id.hpp"
#include "common/network.hpp"
#include "consensus/availability_retention.hpp"
#include "consensus/frontier_execution.hpp"
#include "consensus/validator_registry.hpp"
#include "storage/db.hpp"
#include "utxo/validate.hpp"
#include "utxo/tx.hpp"

namespace finalis::consensus {

struct CanonicalDerivationConfig {
  NetworkConfig network{};
  ChainId chain_id{};
  std::size_t max_committee{MAX_COMMITTEE};
  std::uint64_t validator_min_bond_override{BOND_AMOUNT};
  std::uint64_t validator_bond_min_amount{BOND_AMOUNT};
  std::uint64_t validator_bond_max_amount{BOND_AMOUNT};
  std::uint64_t validator_warmup_blocks{WARMUP_BLOCKS};
  std::uint64_t validator_cooldown_blocks{0};
  std::uint64_t validator_join_limit_window_blocks{0};
  std::uint32_t validator_join_limit_max_new{0};
  std::uint64_t validator_liveness_window_blocks{10'000};
  std::uint32_t validator_miss_rate_suspend_threshold_percent{30};
  std::uint32_t validator_miss_rate_exit_threshold_percent{60};
  std::uint64_t validator_suspend_duration_blocks{1'000};
  availability::AvailabilityConfig availability{};
  std::uint64_t availability_min_eligible_operators{1};
  std::uint32_t validation_rules_version{6};
  ConfidentialPolicy confidential_policy{};
  std::function<std::optional<Hash32>(std::uint64_t)> finalized_hash_at_height;
};

struct CanonicalGenesisState {
  Hash32 genesis_artifact_id{};
  std::vector<PubKey32> initial_validators;
};

struct CanonicalFrontierRecord {
  FrontierTransition transition;
  std::vector<Bytes> ordered_records;
  CertifiedIngressLaneRecords lane_records;

  CanonicalFrontierRecord() = default;
  CanonicalFrontierRecord(const FrontierTransition& transition_in, const std::vector<Bytes>& ordered_records_in)
      : transition(transition_in), ordered_records(ordered_records_in) {}
  CanonicalFrontierRecord(const FrontierTransition& transition_in, const CertifiedIngressLaneRecords& lane_records_in)
      : transition(transition_in), lane_records(lane_records_in) {}
};

struct CanonicalFinalizedMetadata {
  std::uint32_t round{0};
  std::uint32_t quorum_threshold{0};
  std::uint32_t signature_count{0};
};

enum class FinalizedIdentityKind : std::uint8_t {
  Genesis = 0,
  Transition = 1,
};

struct FinalizedIdentity {
  FinalizedIdentityKind kind{FinalizedIdentityKind::Genesis};
  Hash32 id{};

  static FinalizedIdentity genesis(const Hash32& genesis_id) {
    return FinalizedIdentity{FinalizedIdentityKind::Genesis, genesis_id};
  }

  static FinalizedIdentity transition(const Hash32& transition_id) {
    return FinalizedIdentity{FinalizedIdentityKind::Transition, transition_id};
  }

  bool is_genesis() const { return kind == FinalizedIdentityKind::Genesis; }
  bool is_transition() const { return kind == FinalizedIdentityKind::Transition; }
  const Hash32& value() const { return id; }
  std::optional<Hash32> genesis_id() const { return is_genesis() ? std::optional<Hash32>(id) : std::nullopt; }
  std::optional<Hash32> transition_id() const { return is_transition() ? std::optional<Hash32>(id) : std::nullopt; }
};

struct CanonicalDerivedState {
  std::uint64_t finalized_height{0};
  std::uint64_t finalized_frontier{0};
  FrontierVector finalized_frontier_vector{};
  FrontierLaneRoots finalized_lane_roots{};
  FinalizedIdentity finalized_identity{};
  Hash32 last_finality_certificate_hash{};
  UtxoSetV2 utxos;
  ValidatorRegistry validators;
  std::map<Hash32, ValidatorJoinRequest> validator_join_requests;
  Hash32 finalized_randomness{};
  std::map<std::uint64_t, Hash32> committee_epoch_randomness_cache;
  std::uint64_t protocol_reserve_balance_units{0};
  std::map<std::uint64_t, storage::EpochRewardSettlementState> epoch_reward_states;
  std::map<std::uint64_t, storage::FinalizedCommitteeCheckpoint> finalized_committee_checkpoints;
  std::map<std::uint64_t, CanonicalFinalizedMetadata> finalized_block_metadata;
  std::uint64_t validator_join_window_start_height{0};
  std::uint32_t validator_join_count_in_window{0};
  std::uint64_t validator_liveness_window_start_height{0};
  std::size_t last_participation_eligible_signers{0};
  availability::AvailabilityPersistentState availability_state;
  Hash32 state_commitment{};
};

struct AdaptiveCheckpointParameters {
  std::uint64_t qualified_depth{0};
  std::uint64_t target_committee_size{1};
  std::uint64_t min_eligible_operators{1};
  std::uint64_t min_bond{150ULL * BASE_UNITS_PER_COIN};
  std::uint32_t target_expand_streak{0};
  std::uint32_t target_contract_streak{0};
};

bool build_genesis_canonical_state(const CanonicalDerivationConfig& cfg, const CanonicalGenesisState& genesis,
                                   CanonicalDerivedState* out, std::string* error);
std::uint64_t genesis_validator_bond_amount();
Hash32 canonical_finality_certificate_hash(const FinalityCertificate& cert);
Hash32 frontier_finality_link_hash(const FrontierTransition& transition);
bool populate_frontier_transition_metadata(const CanonicalDerivationConfig& cfg, const CanonicalDerivedState& prev,
                                           std::uint64_t height, std::uint32_t round, const PubKey32& leader_pubkey,
                                           const std::vector<PubKey32>& observed_signers,
                                           std::uint64_t accepted_fee_units, const UtxoSetV2& post_execution_utxos,
                                           FrontierTransition* transition,
                                           std::string* error);
bool load_certified_frontier_record_from_storage(const storage::DB& db, const FrontierTransition& transition,
                                                 CanonicalFrontierRecord* out, std::string* error);
bool verify_frontier_record_against_state(const CanonicalDerivationConfig& cfg, const CanonicalDerivedState& prev,
                                          const CanonicalFrontierRecord& record, FrontierExecutionResult* recomputed,
                                          std::string* error,
                                          std::string* validation_diagnostics = nullptr);
bool verify_frontier_record_against_state_with_replay_options(
                                          const CanonicalDerivationConfig& cfg, const CanonicalDerivedState& prev,
                                          const CanonicalFrontierRecord& record,
                                          bool allow_legacy_ingress_epoch_replay,
                                          FrontierExecutionResult* recomputed, std::string* error,
                                          std::string* validation_diagnostics = nullptr);
bool apply_frontier_record(const CanonicalDerivationConfig& cfg, const CanonicalDerivedState& prev,
                           const CanonicalFrontierRecord& record, CanonicalDerivedState* out, std::string* error);
bool derive_canonical_state_from_frontier_chain(const CanonicalDerivationConfig& cfg,
                                                const CanonicalDerivedState& initial_state,
                                                const std::vector<CanonicalFrontierRecord>& chain,
                                                CanonicalDerivedState* out, std::string* error);
bool derive_canonical_state_from_frontier_storage(const CanonicalDerivationConfig& cfg,
                                                  const CanonicalDerivedState& initial_state,
                                                  const storage::DB& db,
                                                  CanonicalDerivedState* out, std::string* error);
Hash32 consensus_state_commitment(const CanonicalDerivationConfig& cfg, const CanonicalDerivedState& state);
std::uint64_t qualified_depth_at_checkpoint(const ValidatorRegistry& validators, std::uint64_t height,
                                            std::uint64_t effective_min_bond,
                                            const availability::AvailabilityPersistentState& availability_state,
                                            const availability::AvailabilityConfig& availability_cfg);
std::uint64_t derive_adaptive_committee_target(const std::optional<storage::FinalizedCommitteeCheckpoint>& previous_checkpoint,
                                               std::uint64_t qualified_depth, std::uint32_t* expand_streak,
                                               std::uint32_t* contract_streak);
std::uint64_t derive_adaptive_min_eligible(std::uint64_t target_committee_size);
std::uint64_t derive_adaptive_min_bond(std::uint64_t target_committee_size, std::uint64_t qualified_depth);
AdaptiveCheckpointParameters adaptive_checkpoint_parameters_from_metadata(
    const std::optional<storage::FinalizedCommitteeCheckpoint>& checkpoint);
AdaptiveCheckpointParameters derive_adaptive_checkpoint_parameters(
    const std::optional<storage::FinalizedCommitteeCheckpoint>& previous_checkpoint, std::uint64_t qualified_depth);
bool bootstrap_availability_grace_active(const ValidatorRegistry& validators, std::uint64_t height);
bool bootstrap_operator_grandfathered_for_availability(const ValidatorRegistry& validators, const PubKey32& operator_id,
                                                       std::uint64_t height);
std::uint64_t count_eligible_operators_at_checkpoint(const ValidatorRegistry& validators, std::uint64_t height,
                                                     const availability::AvailabilityPersistentState& availability_state,
                                                     const availability::AvailabilityConfig& availability_cfg);
availability::AvailabilityConfig availability_config_with_min_bond(const availability::AvailabilityConfig& base,
                                                                   std::uint64_t min_bond);
bool canonical_checkpoints_equal(const storage::FinalizedCommitteeCheckpoint& a,
                                 const storage::FinalizedCommitteeCheckpoint& b);
bool derive_next_epoch_checkpoint_from_state(const CanonicalDerivationConfig& cfg, const CanonicalDerivedState& state,
                                             std::uint64_t epoch_start_height,
                                             storage::FinalizedCommitteeCheckpoint* out, std::string* error);
bool validate_next_epoch_checkpoint_from_state(const CanonicalDerivationConfig& cfg, const CanonicalDerivedState& state,
                                               std::uint64_t epoch_start_height,
                                               const storage::FinalizedCommitteeCheckpoint& checkpoint,
                                               std::string* error);
bool validate_checkpoint_schedule_for_height(const CanonicalDerivationConfig& cfg, const CanonicalDerivedState& state,
                                             const storage::FinalizedCommitteeCheckpoint& checkpoint,
                                             std::uint64_t height, std::string* error);
bool bootstrap_handoff_complete(const CanonicalDerivedState& state);
std::optional<PubKey32> checkpoint_ticket_pow_fallback_member(const storage::FinalizedCommitteeCheckpoint& checkpoint);
std::optional<PubKey32> checkpoint_ticket_pow_fallback_member_for_round(
    const storage::FinalizedCommitteeCheckpoint& checkpoint, std::uint32_t round);
std::optional<PubKey32> legacy_checkpoint_ticket_pow_fallback_member_for_round(
    const storage::FinalizedCommitteeCheckpoint& checkpoint, std::uint32_t round);
std::vector<PubKey32> legacy_checkpoint_committee_for_round(const storage::FinalizedCommitteeCheckpoint& checkpoint,
                                                            std::uint32_t round);
std::vector<PubKey32> checkpoint_committee_for_round(const storage::FinalizedCommitteeCheckpoint& checkpoint,
                                                     std::uint32_t round);
std::vector<PubKey32> legacy_canonical_committee_for_height_round(const CanonicalDerivationConfig& cfg,
                                                                  const CanonicalDerivedState& state,
                                                                  std::uint64_t height, std::uint32_t round);

std::vector<PubKey32> canonical_committee_for_height_round(const CanonicalDerivationConfig& cfg,
                                                           const CanonicalDerivedState& state, std::uint64_t height,
                                                           std::uint32_t round);
std::optional<PubKey32> legacy_canonical_leader_for_height_round(const CanonicalDerivationConfig& cfg,
                                                                 const CanonicalDerivedState& state,
                                                                 std::uint64_t height, std::uint32_t round);
std::optional<PubKey32> canonical_leader_for_height_round(const CanonicalDerivationConfig& cfg,
                                                          const CanonicalDerivedState& state, std::uint64_t height,
                                                          std::uint32_t round);

}  // namespace finalis::consensus
