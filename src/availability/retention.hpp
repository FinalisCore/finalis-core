#pragma once

#include <cstdint>
#include <limits>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "common/types.hpp"
#include "consensus/frontier_execution.hpp"

namespace finalis::availability {

inline constexpr std::size_t kAuditChunkSize = 4096;
inline constexpr std::size_t kReplicationFactor = 3;
inline constexpr std::size_t kAuditsPerOperatorPerEpoch = 4;
inline constexpr std::uint64_t kWarmupEpochs = 14;
inline constexpr std::uint64_t kMinWarmupAudits = 50;
inline constexpr std::uint32_t kMinWarmupSuccessRateBps = 9800;
inline constexpr std::uint32_t kScoreDecayAlphaBps = 9800;
inline constexpr std::int64_t kRetentionHistoryBonusMultiplier = 3;
inline constexpr std::int64_t kEligibilityMinScore = 10;
inline constexpr std::int64_t kProbationScore = 0;
inline constexpr std::int64_t kEjectionScore = -20;
inline constexpr std::int64_t kSeatUnit = 10;
inline constexpr std::uint32_t kMaxSeatsPerOperator = 4;
inline constexpr std::uint64_t kRetentionWindowMinEpochs = 64;
inline constexpr std::uint64_t kRetentionWindowTargetEpochs = 256;
inline constexpr std::uint64_t kAuditResponseDeadlineSlots = 4;

enum class AvailabilityOperatorStatus : std::uint8_t {
  WARMUP = 0,
  ACTIVE = 1,
  PROBATION = 2,
  EJECTED = 3,
};

struct AvailabilityConfig {
  std::size_t audit_chunk_size{kAuditChunkSize};
  std::size_t replication_factor{kReplicationFactor};
  std::size_t audits_per_operator_per_epoch{kAuditsPerOperatorPerEpoch};
  std::uint64_t warmup_epochs{kWarmupEpochs};
  std::uint64_t min_warmup_audits{kMinWarmupAudits};
  std::uint32_t min_warmup_success_rate_bps{kMinWarmupSuccessRateBps};
  std::uint32_t score_alpha_bps{kScoreDecayAlphaBps};
  std::uint64_t min_bond{BOND_AMOUNT};
  std::int64_t retention_history_bonus_multiplier{kRetentionHistoryBonusMultiplier};
  std::int64_t eligibility_min_score{kEligibilityMinScore};
  std::int64_t probation_score{kProbationScore};
  std::int64_t ejection_score{kEjectionScore};
  std::int64_t seat_unit{kSeatUnit};
  std::uint32_t max_seats_per_operator{kMaxSeatsPerOperator};
  std::uint64_t retention_window_min_epochs{kRetentionWindowMinEpochs};
  std::uint64_t retention_window_target_epochs{kRetentionWindowTargetEpochs};
  std::uint64_t audit_response_deadline_slots{kAuditResponseDeadlineSlots};
};

struct RetainedPrefix {
  std::uint32_t lane_id{0};
  std::uint64_t start_seq{0};
  std::uint64_t end_seq{0};
  Hash32 prefix_id{};
  Hash32 payload_commitment{};
  Hash32 chunk_root{};
  std::uint64_t byte_length{0};
  std::uint32_t chunk_count{0};
  std::uint64_t certified_height{0};

  bool operator==(const RetainedPrefix&) const = default;
};

struct RetainedPrefixPayload {
  RetainedPrefix prefix;
  Bytes payload_bytes;
  std::vector<Bytes> chunks;
  std::vector<Hash32> chunk_hashes;
};

struct AvailabilityMerkleProof {
  std::vector<Hash32> siblings;

  bool operator==(const AvailabilityMerkleProof&) const = default;
};

struct AvailabilityAuditChallenge {
  Hash32 challenge_id{};
  std::uint64_t epoch{0};
  PubKey32 operator_pubkey{};
  Hash32 prefix_id{};
  std::uint32_t chunk_index{0};
  std::uint64_t issued_slot{0};
  std::uint64_t deadline_slot{0};
  Hash32 nonce{};

  bool operator==(const AvailabilityAuditChallenge&) const = default;
};

struct AvailabilityAuditResponse {
  Hash32 challenge_id{};
  PubKey32 operator_pubkey{};
  Hash32 prefix_id{};
  std::uint32_t chunk_index{0};
  Bytes chunk_bytes;
  AvailabilityMerkleProof proof;
  std::uint64_t responded_slot{0};
  Sig64 operator_sig{};

  bool operator==(const AvailabilityAuditResponse&) const = default;
};

enum class AvailabilityAuditOutcome : std::uint8_t {
  VALID_TIMELY = 0,
  VALID_LATE = 1,
  NO_RESPONSE = 2,
  INVALID_RESPONSE = 3,
};

enum class InvalidAvailabilityResponseType : std::uint8_t {
  INVALID_CHUNK = 0,
  INVALID_PROOF = 1,
  WRONG_PREFIX = 2,
  MALFORMED_RESPONSE = 3,
};

struct InvalidAvailabilityServiceEvidence {
  AvailabilityAuditChallenge challenge;
  AvailabilityAuditResponse response;
  InvalidAvailabilityResponseType violation{InvalidAvailabilityResponseType::MALFORMED_RESPONSE};

  bool operator==(const InvalidAvailabilityServiceEvidence&) const = default;
};

struct AvailabilityOperatorState {
  PubKey32 operator_pubkey{};
  std::uint64_t bond{0};
  AvailabilityOperatorStatus status{AvailabilityOperatorStatus::WARMUP};
  std::int64_t service_score{0};
  std::uint64_t successful_audits{0};
  std::uint64_t late_audits{0};
  std::uint64_t missed_audits{0};
  std::uint64_t invalid_audits{0};
  std::uint64_t warmup_epochs{0};
  std::uint64_t retained_prefix_count{0};
  bool was_ever_active{false};
  std::uint32_t recovery_consecutive_success_epochs{0};

  bool operator==(const AvailabilityOperatorState&) const = default;
};

struct AvailabilitySeatTicket {
  PubKey32 operator_pubkey{};
  std::uint32_t seat_index{0};
  Hash32 ticket{};

  bool operator==(const AvailabilitySeatTicket&) const = default;
};

struct AvailabilityPersistentState {
  std::uint32_t version{2};
  std::uint64_t current_epoch{0};
  std::vector<AvailabilityOperatorState> operators;
  std::vector<RetainedPrefix> retained_prefixes;
  std::vector<InvalidAvailabilityServiceEvidence> evidence;

  // Restart contract:
  // - operator lifecycle counters and retained-prefix membership are restored
  //   exactly from disk
  // - eligibility, seat budgets, ticket ordering, and future score evolution
  //   are recomputed from that restored state and current inputs
  bool operator==(const AvailabilityPersistentState&) const = default;
  Bytes serialize() const;
  static std::optional<AvailabilityPersistentState> parse(const Bytes& b);
};

// Canonical live-state helpers:
// - normalize_availability_consensus_state canonicalizes only the
//   consensus-relevant availability fields consumed by live eligibility and
//   checkpoint derivation
// - normalize_availability_persistent_state enforces canonical ordering and
//   deduplicates exact duplicates for the full persisted object, including the
//   observability-only evidence vector
// - validate_availability_persistent_state_for_live_derivation rejects any
//   consensus-relevant persisted state that could change live eligibility under
//   restart/replay; evidence is intentionally excluded from this validation
void normalize_availability_consensus_state(AvailabilityPersistentState* state);
void normalize_availability_persistent_state(AvailabilityPersistentState* state);
bool validate_availability_persistent_state_for_live_derivation(const AvailabilityPersistentState& state,
                                                                const AvailabilityConfig& cfg = {},
                                                                std::string* error = nullptr);
AvailabilityPersistentState consensus_relevant_availability_state(const AvailabilityPersistentState& state);
std::uint64_t count_eligible_operators(const AvailabilityPersistentState& state, const AvailabilityConfig& cfg = {});
void refresh_live_availability_state(const Hash32& finalized_identity_id,
                                     const std::map<PubKey32, std::uint64_t>& operator_bonds, bool advance_epoch,
                                     AvailabilityPersistentState* state, const AvailabilityConfig& cfg = {},
                                     std::uint64_t recovery_activation_height = std::numeric_limits<std::uint64_t>::max());
void advance_live_availability_epoch(const Hash32& finalized_identity_id,
                                     const std::map<PubKey32, std::uint64_t>& operator_bonds, std::uint64_t epoch,
                                     AvailabilityPersistentState* state, const AvailabilityConfig& cfg = {},
                                     std::uint64_t recovery_activation_height = std::numeric_limits<std::uint64_t>::max());

enum class AvailabilitySimulationBehavior : std::uint8_t {
  HONEST = 0,
  INTERMITTENT = 1,
  NO_RESPONSE = 2,
  INVALID_RESPONSE = 3,
  FLAKY = 4,
  JOIN_LATE = 5,
  LEAVE_EARLY = 6,
};

struct AvailabilitySimulationOperator {
  PubKey32 operator_pubkey{};
  std::uint64_t bond{BOND_AMOUNT};
  AvailabilitySimulationBehavior behavior{AvailabilitySimulationBehavior::HONEST};
  std::uint64_t join_epoch{0};
  std::optional<std::uint64_t> leave_epoch;

  bool operator==(const AvailabilitySimulationOperator&) const = default;
};

struct AvailabilitySimulationOperatorSummary {
  PubKey32 operator_pubkey{};
  AvailabilityOperatorStatus status{AvailabilityOperatorStatus::WARMUP};
  std::int64_t service_score{0};
  std::uint64_t retained_prefix_count{0};
  std::int64_t eligibility_score{0};
  std::uint32_t seat_budget{0};

  bool operator==(const AvailabilitySimulationOperatorSummary&) const = default;
};

struct ShadowCommitteeComparison {
  std::uint64_t epoch{0};
  std::size_t real_committee_size{0};
  std::size_t passive_committee_size{0};
  std::size_t overlap_count{0};
  std::uint32_t overlap_bps{0};
  std::vector<PubKey32> only_real;
  std::vector<PubKey32> only_passive;
  std::size_t real_churn_count{0};
  std::size_t passive_churn_count{0};

  bool operator==(const ShadowCommitteeComparison&) const = default;
};

struct AvailabilitySimulationEpochSummary {
  std::uint64_t epoch{0};
  std::uint64_t retained_prefix_count{0};
  std::uint64_t tracked_operator_count{0};
  std::uint64_t eligible_operator_count{0};
  std::uint64_t warmup_count{0};
  std::uint64_t active_count{0};
  std::uint64_t probation_count{0};
  std::uint64_t ejected_count{0};
  std::vector<AvailabilitySimulationOperatorSummary> operators;
  std::vector<AvailabilitySeatTicket> passive_tickets;
  std::vector<PubKey32> passive_committee_preview;
  std::optional<ShadowCommitteeComparison> committee_comparison;

  bool operator==(const AvailabilitySimulationEpochSummary&) const = default;
};

struct AvailabilitySimulationScenario {
  Hash32 seed{};
  std::uint64_t start_epoch{0};
  std::uint64_t epochs{0};
  std::uint64_t retained_prefixes_per_epoch{1};
  std::size_t passive_committee_size{0};
  std::vector<AvailabilitySimulationOperator> operators;
  std::map<std::uint64_t, std::vector<PubKey32>> real_committees_by_epoch;
  std::vector<std::uint64_t> restart_epochs;
};

struct AvailabilitySimulationResult {
  AvailabilityPersistentState final_state;
  std::vector<AvailabilitySimulationEpochSummary> epochs;

  bool operator==(const AvailabilitySimulationResult&) const = default;
};

struct AvailabilityAnalyticsEpochSummary {
  std::uint64_t epoch{0};
  std::size_t tracked_operator_count{0};
  std::size_t eligible_operator_count{0};
  std::size_t warmup_count{0};
  std::size_t active_count{0};
  std::size_t probation_count{0};
  std::size_t ejected_count{0};
  std::size_t passive_committee_size{0};
  std::size_t real_committee_size{0};
  std::size_t overlap_count{0};
  std::uint32_t overlap_bps{0};
  std::size_t passive_churn_count{0};
  std::size_t real_churn_count{0};
  std::uint64_t passive_total_seat_budget{0};
  std::uint64_t passive_top1_seat_budget{0};
  std::uint64_t passive_top3_seat_budget{0};
  std::uint64_t passive_top5_seat_budget{0};
  std::uint32_t passive_top1_share_bps{0};
  std::uint32_t passive_top3_share_bps{0};
  std::uint32_t passive_top5_share_bps{0};
  std::uint32_t passive_max_seat_budget{0};
  std::vector<std::uint64_t> seat_budget_histogram;

  bool operator==(const AvailabilityAnalyticsEpochSummary&) const = default;
};

struct AvailabilityAnalyticsReport {
  Hash32 simulation_seed{};
  std::uint64_t epoch_count{0};
  std::vector<AvailabilityAnalyticsEpochSummary> epochs;
  std::uint64_t total_activation_events{0};
  std::uint64_t total_probation_events{0};
  std::uint64_t total_ejection_events{0};
  std::uint64_t activation_latency_count{0};
  std::uint64_t activation_latency_sum{0};
  std::uint64_t activation_latency_max{0};
  std::uint64_t never_activated_count{0};
  std::uint64_t overlap_bps_sum{0};
  std::uint32_t min_overlap_bps{0};
  std::uint32_t max_overlap_bps{0};
  std::uint64_t passive_churn_sum{0};
  std::uint64_t real_churn_sum{0};
  std::uint32_t max_top1_share_bps{0};
  std::uint32_t max_top3_share_bps{0};
  std::uint32_t max_top5_share_bps{0};
  std::uint32_t seat_budget_histogram_max_bucket{0};
  std::vector<std::uint64_t> seat_budget_histogram;

  bool operator==(const AvailabilityAnalyticsReport&) const = default;
  Bytes serialize() const;
};

enum class AvailabilitySuiteStabilityClass : std::uint8_t {
  STABLE = 0,
  BORDERLINE = 1,
  UNSTABLE = 2,
};

struct AvailabilityScenarioParameterPoint {
  std::uint32_t replication_factor{kReplicationFactor};
  std::uint32_t warmup_epochs{kWarmupEpochs};
  std::uint32_t min_warmup_audits{kMinWarmupAudits};
  std::uint32_t min_warmup_success_rate_bps{kMinWarmupSuccessRateBps};
  std::uint32_t score_alpha_bps{kScoreDecayAlphaBps};
  std::int64_t eligibility_min_score{kEligibilityMinScore};
  std::uint32_t seat_unit{kSeatUnit};
  std::uint32_t max_seats_per_operator{kMaxSeatsPerOperator};

  bool operator==(const AvailabilityScenarioParameterPoint&) const = default;
  auto operator<=>(const AvailabilityScenarioParameterPoint&) const = default;
};

struct AvailabilityScenarioSuiteConfig {
  Hash32 simulation_seed{};
  std::uint64_t horizon_epochs{0};
  AvailabilitySimulationScenario scenario;
  std::vector<std::uint32_t> replication_factors;
  std::vector<std::uint32_t> warmup_epochs_values;
  std::vector<std::uint32_t> min_warmup_audits_values;
  std::vector<std::uint32_t> min_warmup_success_rate_bps_values;
  std::vector<std::uint32_t> score_alpha_bps_values;
  std::vector<std::int64_t> eligibility_min_score_values;
  std::vector<std::uint32_t> seat_unit_values;
  std::vector<std::uint32_t> max_seats_per_operator_values;
};

struct AvailabilityScenarioSuiteEntry {
  AvailabilityScenarioParameterPoint params;
  AvailabilityAnalyticsReport report;

  bool operator==(const AvailabilityScenarioSuiteEntry&) const = default;
};

struct AvailabilityScenarioSuiteComparativeEntry {
  AvailabilityScenarioParameterPoint params;
  std::uint32_t mean_overlap_bps{0};
  std::uint32_t min_overlap_bps{0};
  std::uint32_t max_top1_share_bps{0};
  std::uint32_t max_top3_share_bps{0};
  std::uint32_t mean_passive_churn{0};
  std::uint64_t total_activation_events{0};
  std::uint64_t total_probation_events{0};
  std::uint64_t total_ejection_events{0};
  std::uint64_t activation_latency_count{0};
  std::uint64_t activation_latency_sum{0};
  std::uint64_t activation_latency_max{0};
  std::size_t final_eligible_operator_count{0};
  std::size_t final_active_count{0};
  std::size_t final_probation_count{0};
  std::size_t final_ejected_count{0};
  std::uint32_t final_top1_share_bps{0};
  std::uint32_t final_top3_share_bps{0};
  AvailabilitySuiteStabilityClass stability_class{AvailabilitySuiteStabilityClass::UNSTABLE};
  std::uint64_t ranking_key_0{0};
  std::uint64_t ranking_key_1{0};
  std::uint64_t ranking_key_2{0};
  std::uint64_t ranking_key_3{0};
  std::uint64_t ranking_key_4{0};

  bool operator==(const AvailabilityScenarioSuiteComparativeEntry&) const = default;
};

struct AvailabilityScenarioSuiteComparativeReport {
  Hash32 simulation_seed{};
  std::uint64_t horizon_epochs{0};
  std::vector<AvailabilityScenarioSuiteEntry> entries;
  std::vector<AvailabilityScenarioSuiteComparativeEntry> comparative_entries;

  bool operator==(const AvailabilityScenarioSuiteComparativeReport&) const = default;
  Bytes serialize() const;
};

enum class AvailabilityParameterDimension : std::uint8_t {
  ReplicationFactor = 0,
  WarmupEpochs = 1,
  MinWarmupAudits = 2,
  MinWarmupSuccessRateBps = 3,
  ScoreAlphaBps = 4,
  EligibilityMinScore = 5,
  SeatUnit = 6,
  MaxSeatsPerOperator = 7,
};

enum class AvailabilitySensitivityClass : std::uint8_t {
  Robust = 0,
  Sensitive = 1,
};

struct AvailabilityScenarioSuiteDeltaEntry {
  AvailabilityScenarioParameterPoint params;
  AvailabilityScenarioParameterPoint baseline_params;
  std::int64_t mean_overlap_bps_delta{0};
  std::int64_t min_overlap_bps_delta{0};
  std::int64_t max_top1_share_bps_delta{0};
  std::int64_t max_top3_share_bps_delta{0};
  std::int64_t mean_passive_churn_delta{0};
  std::int64_t total_activation_events_delta{0};
  std::int64_t total_probation_events_delta{0};
  std::int64_t total_ejection_events_delta{0};
  std::int64_t activation_latency_count_delta{0};
  std::int64_t activation_latency_sum_delta{0};
  std::int64_t activation_latency_max_delta{0};
  std::int64_t final_eligible_operator_count_delta{0};
  std::int64_t final_active_count_delta{0};
  std::int64_t final_probation_count_delta{0};
  std::int64_t final_ejected_count_delta{0};
  AvailabilitySuiteStabilityClass baseline_class{AvailabilitySuiteStabilityClass::UNSTABLE};
  AvailabilitySuiteStabilityClass current_class{AvailabilitySuiteStabilityClass::UNSTABLE};

  bool operator==(const AvailabilityScenarioSuiteDeltaEntry&) const = default;
};

struct AvailabilityScenarioSuiteDeltaReport {
  AvailabilityScenarioParameterPoint baseline_params;
  std::vector<AvailabilityScenarioSuiteDeltaEntry> entries;

  bool operator==(const AvailabilityScenarioSuiteDeltaReport&) const = default;
  Bytes serialize() const;
};

struct AvailabilityOATSensitivityEntry {
  AvailabilityParameterDimension dimension{AvailabilityParameterDimension::ReplicationFactor};
  std::int64_t parameter_value{0};
  std::int64_t mean_overlap_bps_delta{0};
  std::int64_t max_top1_share_bps_delta{0};
  std::int64_t mean_passive_churn_delta{0};
  std::int64_t activation_latency_sum_delta{0};
  std::int64_t total_probation_events_delta{0};
  std::int64_t total_ejection_events_delta{0};

  bool operator==(const AvailabilityOATSensitivityEntry&) const = default;
};

struct AvailabilityOATSensitivityReport {
  AvailabilityScenarioParameterPoint baseline_params;
  AvailabilityParameterDimension dimension{AvailabilityParameterDimension::ReplicationFactor};
  std::vector<AvailabilityOATSensitivityEntry> entries;

  bool operator==(const AvailabilityOATSensitivityReport&) const = default;
  Bytes serialize() const;
};

struct AvailabilityDominantParameterEffect {
  AvailabilityParameterDimension dimension{AvailabilityParameterDimension::ReplicationFactor};
  std::uint64_t max_abs_mean_overlap_bps_delta{0};
  std::uint64_t max_abs_max_top1_share_bps_delta{0};
  std::uint64_t max_abs_mean_passive_churn_delta{0};
  std::uint64_t max_abs_activation_latency_sum_delta{0};

  bool operator==(const AvailabilityDominantParameterEffect&) const = default;
};

struct AvailabilityDimensionSensitivitySummary {
  AvailabilityParameterDimension dimension{AvailabilityParameterDimension::ReplicationFactor};
  AvailabilitySensitivityClass sensitivity_class{AvailabilitySensitivityClass::Sensitive};
  std::uint64_t max_abs_mean_overlap_bps_delta{0};
  std::uint64_t max_abs_max_top1_share_bps_delta{0};
  std::uint64_t max_abs_mean_passive_churn_delta{0};
  std::uint64_t max_abs_activation_latency_sum_delta{0};

  bool operator==(const AvailabilityDimensionSensitivitySummary&) const = default;
};

Bytes canonical_retained_prefix_payload_bytes(const std::vector<consensus::CertifiedIngressRecord>& records);
Hash32 retained_prefix_payload_commitment(const Bytes& payload_bytes);
Hash32 retained_prefix_id(std::uint32_t lane_id, std::uint64_t start_seq, std::uint64_t end_seq,
                          const Hash32& payload_commitment, std::uint64_t certified_height);
std::vector<Bytes> split_retained_prefix_chunks(const Bytes& payload_bytes, std::size_t chunk_size = kAuditChunkSize);
std::vector<Hash32> retained_prefix_chunk_hashes(const std::vector<Bytes>& chunks);
Hash32 retained_prefix_chunk_root(const std::vector<Hash32>& chunk_hashes);
std::optional<RetainedPrefixPayload> build_retained_prefix_payload(
    std::uint32_t lane_id, const std::vector<consensus::CertifiedIngressRecord>& records, std::uint64_t certified_height,
    std::size_t chunk_size = kAuditChunkSize);
std::vector<RetainedPrefixPayload> build_retained_prefix_payloads_from_lane_records(
    const consensus::CertifiedIngressLaneRecords& lane_records, std::uint64_t certified_height,
    std::size_t chunk_size = kAuditChunkSize);

std::optional<AvailabilityMerkleProof> build_chunk_merkle_proof(const std::vector<Hash32>& chunk_hashes,
                                                                std::uint32_t chunk_index);
bool verify_chunk_merkle_proof(const Bytes& chunk_bytes, std::uint32_t chunk_index, const AvailabilityMerkleProof& proof,
                               const Hash32& chunk_root);

Hash32 availability_assignment_score(const Hash32& epoch_seed, const Hash32& prefix_id, const PubKey32& operator_pubkey);
std::vector<PubKey32> assigned_operators_for_prefix(const Hash32& epoch_seed, const RetainedPrefix& prefix,
                                                    const std::vector<PubKey32>& operators,
                                                    std::size_t replication_factor = kReplicationFactor);
bool is_operator_assigned_to_prefix(const Hash32& epoch_seed, const RetainedPrefix& prefix, const PubKey32& operator_pubkey,
                                    const std::vector<PubKey32>& operators,
                                    std::size_t replication_factor = kReplicationFactor);

Hash32 availability_audit_seed(const Hash32& finalized_transition_id, std::uint64_t epoch);
std::vector<AvailabilityAuditChallenge> build_audit_challenges_for_operator(
    const PubKey32& operator_pubkey, const std::vector<RetainedPrefix>& assigned_prefixes, const Hash32& finalized_transition_id,
    std::uint64_t epoch, std::uint64_t issued_slot, const AvailabilityConfig& cfg = {});
Hash32 availability_audit_response_signing_hash(const AvailabilityAuditResponse& response);
std::optional<AvailabilityAuditResponse> make_audit_response(const AvailabilityAuditChallenge& challenge,
                                                             const RetainedPrefixPayload& payload,
                                                             const Bytes& operator_private_key);
AvailabilityAuditOutcome verify_audit_response(const AvailabilityAuditChallenge& challenge, const RetainedPrefix& prefix,
                                               const std::optional<AvailabilityAuditResponse>& response,
                                               InvalidAvailabilityServiceEvidence* evidence = nullptr,
                                               std::string* error = nullptr);

std::int64_t audit_outcome_delta(AvailabilityAuditOutcome outcome);
void apply_epoch_audit_outcomes(AvailabilityOperatorState* state, const std::vector<AvailabilityAuditOutcome>& outcomes,
                                std::uint64_t retained_prefix_count, const AvailabilityConfig& cfg = {},
                                std::uint32_t recovery_threshold_epochs = std::numeric_limits<std::uint32_t>::max());
std::vector<AvailabilityAuditOutcome> live_epoch_audit_outcomes(std::uint64_t retained_prefix_count,
                                                                const AvailabilityConfig& cfg = {},
                                                                bool guarantee_recovery_opportunity = false);
std::int64_t operator_eligibility_score(const AvailabilityOperatorState& state, const AvailabilityConfig& cfg = {});
bool operator_is_eligible(const AvailabilityOperatorState& state, const AvailabilityConfig& cfg = {});
std::uint32_t operator_seat_budget(const AvailabilityOperatorState& state, const AvailabilityConfig& cfg = {});
Hash32 availability_ticket(const Hash32& epoch_seed, const PubKey32& operator_pubkey, std::uint32_t seat_index);
std::vector<AvailabilitySeatTicket> build_availability_tickets(const Hash32& epoch_seed,
                                                               const std::vector<AvailabilityOperatorState>& operators,
                                                               const AvailabilityConfig& cfg = {});
Hash32 availability_simulation_epoch_seed(const Hash32& simulation_seed, std::uint64_t epoch);
std::vector<PubKey32> preview_passive_committee(const Hash32& epoch_seed,
                                                const std::vector<AvailabilityOperatorState>& operators,
                                                std::size_t committee_size, const AvailabilityConfig& cfg = {});
ShadowCommitteeComparison compare_shadow_committee(std::uint64_t epoch, const std::vector<PubKey32>& real_committee,
                                                   const std::vector<PubKey32>& passive_committee,
                                                   const std::vector<PubKey32>& previous_real_committee = {},
                                                   const std::vector<PubKey32>& previous_passive_committee = {});
AvailabilitySimulationResult run_availability_shadow_simulation(const AvailabilitySimulationScenario& scenario,
                                                                const AvailabilityConfig& cfg = {});
AvailabilityAnalyticsReport analyze_availability_shadow_simulation(const AvailabilitySimulationScenario& scenario,
                                                                  const AvailabilitySimulationResult& result);
std::string render_availability_analytics_report(const AvailabilityAnalyticsReport& report);
AvailabilityConfig availability_config_from_parameter_point(const AvailabilityScenarioParameterPoint& params,
                                                            const AvailabilityConfig& base = {});
std::vector<AvailabilityScenarioParameterPoint> enumerate_availability_parameter_points(
    const AvailabilityScenarioSuiteConfig& suite);
AvailabilityScenarioSuiteComparativeReport run_availability_scenario_suite(const AvailabilityScenarioSuiteConfig& suite,
                                                                           const AvailabilityConfig& base = {});
std::string render_availability_scenario_suite_report(const AvailabilityScenarioSuiteComparativeReport& report);
std::optional<AvailabilityScenarioParameterPoint> default_availability_parameter_point(const AvailabilityConfig& cfg = {});
const AvailabilityScenarioSuiteComparativeEntry* find_availability_suite_baseline(
    const AvailabilityScenarioSuiteComparativeReport& suite_report,
    const AvailabilityScenarioParameterPoint& baseline_params);
AvailabilityScenarioSuiteDeltaReport build_availability_suite_delta_report(
    const AvailabilityScenarioSuiteComparativeReport& suite_report,
    const AvailabilityScenarioParameterPoint& baseline_params);
std::vector<AvailabilityOATSensitivityReport> build_availability_oat_sensitivity_reports(
    const AvailabilityScenarioSuiteDeltaReport& delta_report);
std::vector<AvailabilityDominantParameterEffect> build_availability_dominant_parameter_effects(
    const std::vector<AvailabilityOATSensitivityReport>& reports);
std::vector<AvailabilityDimensionSensitivitySummary> build_availability_dimension_sensitivity_summaries(
    const std::vector<AvailabilityOATSensitivityReport>& reports);
std::string render_availability_suite_delta_report(const AvailabilityScenarioSuiteDeltaReport& report);
std::string render_availability_oat_sensitivity_report(const AvailabilityOATSensitivityReport& report);

std::vector<RetainedPrefix> expire_retained_prefixes(const std::vector<RetainedPrefix>& retained_prefixes,
                                                     std::uint64_t current_epoch,
                                                     std::uint64_t retention_window_epochs = kRetentionWindowMinEpochs);
std::uint64_t floor_sqrt_u64(std::uint64_t value);

}  // namespace finalis::availability
