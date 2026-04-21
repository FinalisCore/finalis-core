#pragma once

#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "consensus/availability_retention.hpp"
#include "consensus/epoch_committee.hpp"
#include "consensus/epoch_tickets.hpp"
#include "consensus/validator_registry.hpp"
#include "utxo/validate.hpp"
#include "utxo/tx.hpp"

namespace finalis::storage {

struct TipState {
  std::uint64_t height{0};
  Hash32 hash{};
};

enum class SlashingRecordKind : std::uint8_t {
  VOTE_EQUIVOCATION = 1,
  PROPOSER_EQUIVOCATION = 2,
  ONCHAIN_SLASH = 3,
};

struct SlashingRecord {
  Hash32 record_id{};
  SlashingRecordKind kind{SlashingRecordKind::ONCHAIN_SLASH};
  PubKey32 validator_pubkey{};
  std::uint64_t height{0};
  std::uint32_t round{0};
  std::uint64_t observed_height{0};
  Hash32 object_a{};
  Hash32 object_b{};
  Hash32 txid{};
};

struct IngressEquivocationEvidence {
  Hash32 evidence_id{};
  std::uint64_t epoch{0};
  std::uint32_t lane{0};
  std::uint64_t seq{0};
  Hash32 first_cert_hash{};
  Hash32 second_cert_hash{};
  Hash32 first_txid{};
  Hash32 second_txid{};
  Hash32 first_tx_hash{};
  Hash32 second_tx_hash{};
};

enum class FinalizedCommitteeDerivationMode : std::uint8_t {
  NORMAL = 0,
  FALLBACK = 1,
};

enum class FinalizedCommitteeFallbackReason : std::uint8_t {
  NONE = 0,
  INSUFFICIENT_ELIGIBLE_OPERATORS = 1,
  HYSTERESIS_RECOVERY_PENDING = 2,
};

struct FinalizedCommitteeCheckpoint {
  std::uint64_t epoch_start_height{0};
  Hash32 epoch_seed{};
  std::uint8_t ticket_difficulty_bits{consensus::DEFAULT_TICKET_DIFFICULTY_BITS};
  FinalizedCommitteeDerivationMode derivation_mode{FinalizedCommitteeDerivationMode::NORMAL};
  FinalizedCommitteeFallbackReason fallback_reason{FinalizedCommitteeFallbackReason::NONE};
  std::uint64_t availability_eligible_operator_count{0};
  std::uint64_t availability_min_eligible_operators{0};
  std::uint64_t adaptive_target_committee_size{0};
  std::uint64_t adaptive_min_eligible{0};
  std::uint64_t adaptive_min_bond{0};
  std::uint64_t qualified_depth{0};
  std::uint32_t target_expand_streak{0};
  std::uint32_t target_contract_streak{0};
  std::vector<PubKey32> ordered_members;
  std::vector<PubKey32> ordered_operator_ids;
  std::vector<std::uint64_t> ordered_base_weights;
  std::vector<std::uint32_t> ordered_ticket_bonus_bps;
  std::vector<std::uint64_t> ordered_final_weights;
  std::vector<Hash32> ordered_ticket_hashes;
  std::vector<std::uint64_t> ordered_ticket_nonces;
};

struct EpochRewardSettlementState {
  std::uint64_t epoch_start_height{0};
  std::uint64_t total_reward_units{0};
  std::uint64_t fee_pool_units{0};
  std::uint64_t reserve_accrual_units{0};
  std::uint64_t reserve_subsidy_units{0};
  bool settled{false};
  std::map<PubKey32, std::uint64_t> reward_score_units;
  std::map<PubKey32, std::uint64_t> expected_participation_units;
  std::map<PubKey32, std::uint64_t> observed_participation_units;
  std::map<PubKey32, std::uint64_t> onboarding_score_units;
};

struct EpochCommitteeFreezeMarker {
  std::uint64_t epoch{0};
  Hash32 challenge_anchor{};
  std::uint64_t member_count{0};
};

struct NodeRuntimeStatusSnapshot {
  bool chain_id_ok{true};
  bool db_open{true};
  std::uint64_t local_finalized_height{0};
  bool observed_network_height_known{false};
  std::uint64_t observed_network_finalized_height{0};
  std::size_t healthy_peer_count{0};
  std::size_t established_peer_count{0};
  std::uint64_t finalized_lag{0};
  bool peer_height_disagreement{false};
  bool next_height_committee_available{false};
  bool next_height_proposer_available{false};
  bool bootstrap_sync_incomplete{false};
  bool registration_ready_preflight{false};
  bool registration_ready{false};
  std::uint32_t readiness_stable_samples{0};
  std::string readiness_blockers_csv;
  std::uint64_t captured_at_unix_ms{0};
  std::uint64_t mempool_tx_count{0};
  std::uint64_t mempool_bytes{0};
  bool mempool_full{false};
  std::optional<std::uint64_t> min_fee_rate_to_enter_when_full_milliunits_per_byte;
  std::uint64_t rejected_full_not_good_enough{0};
  std::uint64_t evicted_for_better_incoming{0};
  std::uint64_t min_relay_fee{0};
  std::uint64_t availability_epoch{0};
  std::uint64_t availability_retained_prefix_count{0};
  std::uint64_t availability_tracked_operator_count{0};
  std::uint64_t availability_eligible_operator_count{0};
  bool availability_below_min_eligible{false};
  std::uint64_t adaptive_target_committee_size{0};
  std::uint64_t adaptive_min_eligible{0};
  std::uint64_t adaptive_min_bond{0};
  std::uint64_t qualified_depth{0};
  std::int64_t adaptive_slack{0};
  std::uint32_t target_expand_streak{0};
  std::uint32_t target_contract_streak{0};
  std::uint8_t availability_checkpoint_derivation_mode{
      static_cast<std::uint8_t>(FinalizedCommitteeDerivationMode::NORMAL)};
  std::uint8_t availability_checkpoint_fallback_reason{
      static_cast<std::uint8_t>(FinalizedCommitteeFallbackReason::NONE)};
  bool availability_fallback_sticky{false};
  std::uint32_t adaptive_fallback_rate_bps{0};
  std::uint32_t adaptive_sticky_fallback_rate_bps{0};
  std::uint32_t adaptive_fallback_window_epochs{0};
  bool adaptive_near_threshold_operation{false};
  bool adaptive_prolonged_expand_buildup{false};
  bool adaptive_prolonged_contract_buildup{false};
  bool adaptive_repeated_sticky_fallback{false};
  bool adaptive_depth_collapse_after_bond_increase{false};
  bool availability_state_rebuild_triggered{false};
  std::string availability_state_rebuild_reason;
  bool availability_local_operator_known{false};
  PubKey32 availability_local_operator_pubkey{};
  std::uint8_t availability_local_operator_status{
      static_cast<std::uint8_t>(availability::AvailabilityOperatorStatus::WARMUP)};
  std::int64_t availability_local_service_score{0};
  std::uint64_t availability_local_warmup_epochs{0};
  std::uint64_t availability_local_successful_audits{0};
  std::uint64_t availability_local_late_audits{0};
  std::uint64_t availability_local_missed_audits{0};
  std::uint64_t availability_local_invalid_audits{0};
  std::uint64_t availability_local_retained_prefix_count{0};
  std::int64_t availability_local_eligibility_score{0};
  std::uint32_t availability_local_seat_budget{0};
};

struct AdaptiveEpochTelemetry {
  std::uint64_t epoch_start_height{0};
  std::uint64_t derivation_height{0};
  std::uint64_t qualified_depth{0};
  std::uint64_t adaptive_target_committee_size{0};
  std::uint64_t adaptive_min_eligible{0};
  std::uint64_t adaptive_min_bond{0};
  std::int64_t slack{0};
  std::uint32_t target_expand_streak{0};
  std::uint32_t target_contract_streak{0};
  FinalizedCommitteeDerivationMode derivation_mode{FinalizedCommitteeDerivationMode::NORMAL};
  FinalizedCommitteeFallbackReason fallback_reason{FinalizedCommitteeFallbackReason::NONE};
  bool fallback_sticky{false};
  std::uint64_t committee_size_selected{0};
  std::uint64_t eligible_operator_count{0};
};

struct AdaptiveTelemetrySummary {
  std::uint32_t window_epochs{0};
  std::uint32_t sample_count{0};
  std::uint32_t fallback_epochs{0};
  std::uint32_t sticky_fallback_epochs{0};
  std::uint32_t fallback_rate_bps{0};
  std::uint32_t sticky_fallback_rate_bps{0};
  bool near_threshold_operation{false};
  bool prolonged_expand_buildup{false};
  bool prolonged_contract_buildup{false};
  bool repeated_sticky_fallback{false};
  bool depth_collapse_after_bond_increase{false};
};

struct ConsensusStateCommitmentCache {
  std::uint64_t height{0};
  Hash32 hash{};
  Hash32 commitment{};
};

class DB {
 public:
  DB();
  ~DB();

  DB(const DB&) = delete;
  DB& operator=(const DB&) = delete;
  DB(DB&&) noexcept = default;
  DB& operator=(DB&&) noexcept = default;

  bool open(const std::string& path);
  bool open_readonly(const std::string& path);
  bool flush();
  void close();

  bool put(const std::string& key, const Bytes& value);
  std::optional<Bytes> get(const std::string& key) const;
  bool erase(const std::string& key);
  std::map<std::string, Bytes> scan_prefix(const std::string& prefix) const;

  bool set_tip(const TipState& tip);
  std::optional<TipState> get_tip() const;

  // Certificates are indexed both by finalized height and finalized artifact hash.
  // The height index is the primary live lookup path for finalized certificates.
  bool put_finality_certificate(const FinalityCertificate& cert);
  std::optional<FinalityCertificate> get_finality_certificate_by_height(std::uint64_t height) const;

  bool set_height_hash(std::uint64_t height, const Hash32& hash);
  std::optional<Hash32> get_height_hash(std::uint64_t height) const;

  bool put_utxo(const OutPoint& op, const TxOut& out);
  bool put_utxo_v2(const OutPoint& op, const UtxoEntryV2& entry);
  bool erase_utxo(const OutPoint& op);
  std::optional<TxOut> get_utxo(const OutPoint& op) const;
  std::optional<UtxoEntryV2> get_utxo_v2(const OutPoint& op) const;
  std::map<OutPoint, UtxoEntry> load_utxos() const;
  std::map<OutPoint, UtxoEntryV2> load_utxos_v2() const;

  bool put_validator(const PubKey32& pub, const consensus::ValidatorInfo& info);
  std::map<PubKey32, consensus::ValidatorInfo> load_validators() const;
  bool put_validator_join_request(const Hash32& request_txid, const ValidatorJoinRequest& req);
  std::map<Hash32, ValidatorJoinRequest> load_validator_join_requests() const;
  bool put_slashing_record(const SlashingRecord& rec);
  std::map<Hash32, SlashingRecord> load_slashing_records() const;
  bool put_ingress_equivocation_evidence(const IngressEquivocationEvidence& rec);
  std::optional<IngressEquivocationEvidence> get_ingress_equivocation_evidence(std::uint64_t epoch, std::uint32_t lane,
                                                                               std::uint64_t seq) const;
  std::map<Hash32, IngressEquivocationEvidence> load_ingress_equivocation_evidence() const;
  bool put_finalized_committee_checkpoint(const FinalizedCommitteeCheckpoint& checkpoint);
  std::optional<FinalizedCommitteeCheckpoint> get_finalized_committee_checkpoint(std::uint64_t epoch_start_height) const;
  std::map<std::uint64_t, FinalizedCommitteeCheckpoint> load_finalized_committee_checkpoints() const;
  bool put_epoch_reward_settlement(const EpochRewardSettlementState& state);
  std::optional<EpochRewardSettlementState> get_epoch_reward_settlement(std::uint64_t epoch_start_height) const;
  std::map<std::uint64_t, EpochRewardSettlementState> load_epoch_reward_settlements() const;
  bool put_protocol_reserve_balance(std::uint64_t balance_units);
  std::optional<std::uint64_t> get_protocol_reserve_balance() const;
  bool put_epoch_ticket(const consensus::EpochTicket& ticket);
  std::vector<consensus::EpochTicket> load_epoch_tickets(std::uint64_t epoch) const;
  std::vector<std::uint64_t> load_epoch_ticket_epochs() const;
  bool put_best_epoch_ticket(const consensus::EpochBestTicket& ticket);
  std::map<PubKey32, consensus::EpochBestTicket> load_best_epoch_tickets(std::uint64_t epoch) const;
  bool clear_best_epoch_tickets(std::uint64_t epoch);
  bool put_epoch_committee_snapshot(const consensus::EpochCommitteeSnapshot& snapshot);
  std::optional<consensus::EpochCommitteeSnapshot> get_epoch_committee_snapshot(std::uint64_t epoch) const;
  std::map<std::uint64_t, consensus::EpochCommitteeSnapshot> load_epoch_committee_snapshots() const;
  bool put_epoch_committee_freeze_marker(const EpochCommitteeFreezeMarker& marker);
  std::optional<EpochCommitteeFreezeMarker> get_epoch_committee_freeze_marker(std::uint64_t epoch) const;
  std::map<std::uint64_t, EpochCommitteeFreezeMarker> load_epoch_committee_freeze_markers() const;
  bool put_node_runtime_status_snapshot(const NodeRuntimeStatusSnapshot& snapshot);
  std::optional<NodeRuntimeStatusSnapshot> get_node_runtime_status_snapshot() const;
  bool put_adaptive_epoch_telemetry(const AdaptiveEpochTelemetry& telemetry);
  std::optional<AdaptiveEpochTelemetry> get_adaptive_epoch_telemetry(std::uint64_t epoch_start_height) const;
  std::map<std::uint64_t, AdaptiveEpochTelemetry> load_adaptive_epoch_telemetry() const;
  bool put_availability_persistent_state(const availability::AvailabilityPersistentState& state);
  std::optional<availability::AvailabilityPersistentState> get_availability_persistent_state() const;
  bool put_consensus_state_commitment_cache(const ConsensusStateCommitmentCache& cache);
  std::optional<ConsensusStateCommitmentCache> get_consensus_state_commitment_cache() const;
  bool put_validator_onboarding_record(const PubKey32& pub, const Bytes& value);
  std::optional<Bytes> get_validator_onboarding_record(const PubKey32& pub) const;
  std::map<PubKey32, Bytes> load_validator_onboarding_records() const;
  bool erase_validator_onboarding_record(const PubKey32& pub);

  struct TxLocation {
    std::uint64_t height{0};
    std::uint32_t tx_index{0};
    Bytes tx_bytes;
  };
  bool put_tx_index(const Hash32& txid, std::uint64_t height, std::uint32_t tx_index, const Bytes& tx_bytes);
  std::optional<TxLocation> get_tx_index(const Hash32& txid) const;

  bool put_ingress_record(std::uint64_t seq, const Bytes& record_bytes);
  std::optional<Bytes> get_ingress_record(std::uint64_t seq) const;
  std::vector<Bytes> load_ingress_slice(std::uint64_t from_exclusive, std::uint64_t to_inclusive) const;
  bool ingress_slice_matches(std::uint64_t from_exclusive, const std::vector<Bytes>& ordered_records) const;
  bool set_finalized_ingress_tip(std::uint64_t seq);
  std::optional<std::uint64_t> get_finalized_ingress_tip() const;
  bool put_ingress_certificate(std::uint32_t lane, std::uint64_t seq, const Bytes& cert_bytes);
  std::optional<Bytes> get_ingress_certificate(std::uint32_t lane, std::uint64_t seq) const;
  bool put_ingress_bytes(const Hash32& txid, const Bytes& tx_bytes);
  std::optional<Bytes> get_ingress_bytes(const Hash32& txid) const;
  bool put_lane_state(std::uint32_t lane, const LaneState& state);
  std::optional<LaneState> get_lane_state(std::uint32_t lane) const;
  std::vector<Bytes> load_ingress_lane_range(std::uint32_t lane, std::uint64_t from_seq, std::uint64_t to_seq) const;
  bool put_frontier_transition(const Hash32& id, const Bytes& transition_bytes);
  std::optional<Bytes> get_frontier_transition(const Hash32& id) const;
  bool set_finalized_frontier_height(std::uint64_t height);
  std::optional<std::uint64_t> get_finalized_frontier_height() const;
  bool map_height_to_frontier_transition(std::uint64_t height, const Hash32& id);
  std::optional<Hash32> get_frontier_transition_by_height(std::uint64_t height) const;

  struct ScriptUtxoEntry {
    OutPoint outpoint;
    std::uint64_t value{0};
    Bytes script_pubkey;
    std::uint64_t height{0};
  };
  bool put_script_utxo(const Hash32& scripthash, const OutPoint& op, const TxOut& out, std::uint64_t height);
  bool erase_script_utxo(const Hash32& scripthash, const OutPoint& op);
  std::vector<ScriptUtxoEntry> get_script_utxos(const Hash32& scripthash) const;

  struct ScriptHistoryEntry {
    Hash32 txid{};
    std::uint64_t height{0};
  };
  bool add_script_history(const Hash32& scripthash, std::uint64_t height, const Hash32& txid);
  std::vector<ScriptHistoryEntry> get_script_history(const Hash32& scripthash) const;

 private:
  std::string path_;
  bool readonly_{false};

#ifdef SC_HAS_ROCKSDB
  class RocksImpl;
  std::unique_ptr<RocksImpl> rocks_;
#else
  std::map<std::string, Bytes> mem_;
  bool flush_file() const;
  bool load_file();
#endif
};

std::string key_height(std::uint64_t height);
std::string key_height_prefix();
std::string key_tip();
std::string key_genesis_hash();
std::string key_genesis_artifact();
std::string key_genesis_json();
std::string key_root_index(const std::string& kind, std::uint64_t height);
std::string key_root_index_prefix();
std::string key_finality_certificate_height(std::uint64_t height);
std::string key_finality_certificate_height_prefix();
std::string key_ingress_record_prefix();
std::string key_ingress_certificate_prefix();
std::string key_ingress_bytes_prefix();
std::string key_frontier_transition(const Hash32& id);
std::string key_frontier_transition_prefix();
std::string key_finalized_frontier_height();
std::string key_frontier_height(std::uint64_t height);
std::string key_frontier_height_prefix();
std::string key_smt_leaf_prefix(const std::string& tree_id);
std::string key_smt_leaf(const std::string& tree_id, const Hash32& key);
std::string key_smt_root_prefix(const std::string& tree_id);
std::string key_smt_root(const std::string& tree_id, std::uint64_t height);
std::string key_script_utxo_prefix(const Hash32& scripthash);
std::string key_script_utxo(const Hash32& scripthash, const OutPoint& op);
std::string key_script_history_prefix(const Hash32& scripthash);
std::string key_script_history(const Hash32& scripthash, std::uint64_t height, const Hash32& txid);
std::string key_utxo_prefix();
std::string key_utxo(const OutPoint& op);
std::string key_validator_prefix();
std::string key_validator(const PubKey32& pub);
std::string key_txidx_prefix();
std::string key_lane_state_prefix();
std::string key_ingress_equivocation_prefix();
std::string key_node_runtime_status_snapshot();
std::string key_availability_persistent_state();
std::string key_consensus_state_commitment_cache();
std::string key_protocol_reserve_balance();
std::string key_adaptive_epoch_telemetry_prefix();
std::string key_validator_onboarding(const PubKey32& pub);
AdaptiveTelemetrySummary summarize_adaptive_epoch_telemetry(
    const std::map<std::uint64_t, AdaptiveEpochTelemetry>& telemetry_by_epoch, std::size_t window_epochs = 16);

}  // namespace finalis::storage
