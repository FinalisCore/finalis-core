#include "availability/retention.hpp"

#include <algorithm>
#include <functional>
#include <limits>
#include <set>
#include <sstream>
#include <stdexcept>

#include "codec/bytes.hpp"
#include "crypto/ed25519.hpp"
#include "crypto/hash.hpp"
#include "merkle/merkle.hpp"

namespace finalis::availability {
namespace {

constexpr std::uint32_t kAvailabilityPersistentStateVersion = 1;
const Bytes kAvailabilityPersistentStateMagic{'F', 'I', 'N', 'A', 'L', 'I', 'S', '_', 'A', 'V', 'A', 'I', 'L',
                                              '_', 'S', 'T', 'A', 'T', 'E', '_', 'V', '1'};
constexpr std::uint32_t kAvailabilityAnalyticsReportVersion = 1;
const Bytes kAvailabilityAnalyticsReportMagic{'F', 'I', 'N', 'A', 'L', 'I', 'S', '_', 'A', 'V', 'A', 'I', 'L',
                                              '_', 'A', 'N', 'A', 'L', 'Y', 'T', 'I', 'C', 'S', '_', 'V', '1'};
constexpr std::uint32_t kAvailabilitySuiteReportVersion = 1;
const Bytes kAvailabilitySuiteReportMagic{'F', 'I', 'N', 'A', 'L', 'I', 'S', '_', 'A', 'V', 'A', 'I', 'L',
                                          '_', 'S', 'U', 'I', 'T', 'E', '_', 'V', '1'};
constexpr std::uint32_t kAvailabilityDeltaReportVersion = 1;
const Bytes kAvailabilityDeltaReportMagic{'F', 'I', 'N', 'A', 'L', 'I', 'S', '_', 'A', 'V', 'A', 'I', 'L',
                                          '_', 'D', 'E', 'L', 'T', 'A', '_', 'V', '1'};
constexpr std::uint32_t kAvailabilityOatReportVersion = 1;
const Bytes kAvailabilityOatReportMagic{'F', 'I', 'N', 'A', 'L', 'I', 'S', '_', 'A', 'V', 'A', 'I', 'L',
                                        '_', 'O', 'A', 'T', '_', 'V', '1'};

using finalis::codec::ByteWriter;

Hash32 domain_hash(const Bytes& tag, const std::function<void(ByteWriter&)>& append) {
  ByteWriter w;
  w.bytes(tag);
  append(w);
  return crypto::sha256d(w.data());
}

std::size_t bounded_index(const Hash32& h, std::size_t size) {
  if (size == 0) return 0;
  std::uint64_t v = 0;
  for (int i = 0; i < 8; ++i) v |= static_cast<std::uint64_t>(h[i]) << (8 * i);
  return static_cast<std::size_t>(v % size);
}

bool all_zero_sig(const Sig64& sig) {
  for (auto b : sig) {
    if (b != 0) return false;
  }
  return true;
}

std::uint64_t encode_i64(std::int64_t value) {
  return static_cast<std::uint64_t>(value) ^ 0x8000000000000000ULL;
}

std::int64_t decode_i64(std::uint64_t value) {
  return static_cast<std::int64_t>(value ^ 0x8000000000000000ULL);
}

template <typename T>
void sort_and_unique(std::vector<T>* values) {
  if (!values) return;
  std::sort(values->begin(), values->end());
  values->erase(std::unique(values->begin(), values->end()), values->end());
}

bool retained_prefix_less(const RetainedPrefix& a, const RetainedPrefix& b) {
  if (a.certified_height != b.certified_height) return a.certified_height < b.certified_height;
  if (a.lane_id != b.lane_id) return a.lane_id < b.lane_id;
  if (a.start_seq != b.start_seq) return a.start_seq < b.start_seq;
  return a.prefix_id < b.prefix_id;
}

bool invalid_evidence_less(const InvalidAvailabilityServiceEvidence& a, const InvalidAvailabilityServiceEvidence& b) {
  if (a.challenge.challenge_id != b.challenge.challenge_id) return a.challenge.challenge_id < b.challenge.challenge_id;
  if (a.challenge.operator_pubkey != b.challenge.operator_pubkey) {
    return a.challenge.operator_pubkey < b.challenge.operator_pubkey;
  }
  if (a.response.operator_pubkey != b.response.operator_pubkey) {
    return a.response.operator_pubkey < b.response.operator_pubkey;
  }
  return static_cast<std::uint8_t>(a.violation) < static_cast<std::uint8_t>(b.violation);
}

template <typename T, typename Less, typename Equivalent>
bool has_conflicting_duplicates(const std::vector<T>& values, Less&& less, Equivalent&& equivalent) {
  for (std::size_t i = 1; i < values.size(); ++i) {
    const bool same_key = !less(values[i - 1], values[i]) && !less(values[i], values[i - 1]);
    if (same_key && !equivalent(values[i - 1], values[i])) return true;
  }
  return false;
}

void update_operator_status(AvailabilityOperatorState* state, const AvailabilityConfig& cfg) {
  if (!state) return;
  if (state->invalid_audits > 0 || state->service_score <= cfg.ejection_score) {
    state->status = AvailabilityOperatorStatus::EJECTED;
    return;
  }
  const auto total_audits = state->successful_audits + state->late_audits + state->missed_audits + state->invalid_audits;
  const auto success_bps = total_audits == 0 ? 0U : static_cast<std::uint32_t>((state->successful_audits * 10'000ULL) / total_audits);
  if (state->status == AvailabilityOperatorStatus::WARMUP) {
    if (state->successful_audits >= cfg.min_warmup_audits && state->warmup_epochs >= cfg.warmup_epochs &&
        success_bps >= cfg.min_warmup_success_rate_bps && state->bond >= cfg.min_bond) {
      state->status = AvailabilityOperatorStatus::ACTIVE;
      return;
    }
  }
  if (state->service_score < cfg.probation_score) {
    state->status = AvailabilityOperatorStatus::PROBATION;
    return;
  }
  if (state->status == AvailabilityOperatorStatus::PROBATION &&
      state->service_score >= cfg.eligibility_min_score && state->bond >= cfg.min_bond) {
    state->status = AvailabilityOperatorStatus::ACTIVE;
    return;
  }
  if (state->status == AvailabilityOperatorStatus::ACTIVE && state->service_score < cfg.eligibility_min_score) {
    state->status = AvailabilityOperatorStatus::PROBATION;
  }
}

bool operator_state_status_is_idempotent(const AvailabilityOperatorState& state, const AvailabilityConfig& cfg) {
  auto copy = state;
  update_operator_status(&copy, cfg);
  return copy.status == state.status;
}

void serialize_merkle_proof(ByteWriter& w, const AvailabilityMerkleProof& proof) {
  w.varint(proof.siblings.size());
  for (const auto& sibling : proof.siblings) w.bytes_fixed(sibling);
}

std::optional<AvailabilityMerkleProof> parse_merkle_proof(codec::ByteReader& r) {
  AvailabilityMerkleProof proof;
  const auto count = r.varint();
  if (!count.has_value()) return std::nullopt;
  proof.siblings.reserve(static_cast<std::size_t>(*count));
  for (std::uint64_t i = 0; i < *count; ++i) {
    auto sibling = r.bytes_fixed<32>();
    if (!sibling.has_value()) return std::nullopt;
    proof.siblings.push_back(*sibling);
  }
  return proof;
}

void serialize_operator_state(ByteWriter& w, const AvailabilityOperatorState& state) {
  w.bytes_fixed(state.operator_pubkey);
  w.u64le(state.bond);
  w.u8(static_cast<std::uint8_t>(state.status));
  w.u64le(encode_i64(state.service_score));
  w.u64le(state.successful_audits);
  w.u64le(state.late_audits);
  w.u64le(state.missed_audits);
  w.u64le(state.invalid_audits);
  w.u64le(state.warmup_epochs);
  w.u64le(state.retained_prefix_count);
}

std::optional<AvailabilityOperatorState> parse_operator_state(codec::ByteReader& r) {
  AvailabilityOperatorState state;
  const auto pub = r.bytes_fixed<32>();
  const auto bond = r.u64le();
  const auto status = r.u8();
  const auto score = r.u64le();
  const auto successful = r.u64le();
  const auto late = r.u64le();
  const auto missed = r.u64le();
  const auto invalid = r.u64le();
  const auto warmup = r.u64le();
  const auto retained = r.u64le();
  if (!pub || !bond || !status || !score || !successful || !late || !missed || !invalid || !warmup || !retained) {
    return std::nullopt;
  }
  if (*status > static_cast<std::uint8_t>(AvailabilityOperatorStatus::EJECTED)) return std::nullopt;
  state.operator_pubkey = *pub;
  state.bond = *bond;
  state.status = static_cast<AvailabilityOperatorStatus>(*status);
  state.service_score = decode_i64(*score);
  state.successful_audits = *successful;
  state.late_audits = *late;
  state.missed_audits = *missed;
  state.invalid_audits = *invalid;
  state.warmup_epochs = *warmup;
  state.retained_prefix_count = *retained;
  return state;
}

void serialize_retained_prefix(ByteWriter& w, const RetainedPrefix& prefix) {
  w.u32le(prefix.lane_id);
  w.u64le(prefix.start_seq);
  w.u64le(prefix.end_seq);
  w.bytes_fixed(prefix.prefix_id);
  w.bytes_fixed(prefix.payload_commitment);
  w.bytes_fixed(prefix.chunk_root);
  w.u64le(prefix.byte_length);
  w.u32le(prefix.chunk_count);
  w.u64le(prefix.certified_height);
}

std::optional<RetainedPrefix> parse_retained_prefix(codec::ByteReader& r) {
  RetainedPrefix prefix;
  const auto lane = r.u32le();
  const auto start = r.u64le();
  const auto end = r.u64le();
  const auto prefix_id = r.bytes_fixed<32>();
  const auto payload = r.bytes_fixed<32>();
  const auto chunk_root = r.bytes_fixed<32>();
  const auto byte_length = r.u64le();
  const auto chunk_count = r.u32le();
  const auto certified = r.u64le();
  if (!lane || !start || !end || !prefix_id || !payload || !chunk_root || !byte_length || !chunk_count || !certified) {
    return std::nullopt;
  }
  prefix.lane_id = *lane;
  prefix.start_seq = *start;
  prefix.end_seq = *end;
  prefix.prefix_id = *prefix_id;
  prefix.payload_commitment = *payload;
  prefix.chunk_root = *chunk_root;
  prefix.byte_length = *byte_length;
  prefix.chunk_count = *chunk_count;
  prefix.certified_height = *certified;
  return prefix;
}

void serialize_audit_challenge(ByteWriter& w, const AvailabilityAuditChallenge& challenge) {
  w.bytes_fixed(challenge.challenge_id);
  w.u64le(challenge.epoch);
  w.bytes_fixed(challenge.operator_pubkey);
  w.bytes_fixed(challenge.prefix_id);
  w.u32le(challenge.chunk_index);
  w.u64le(challenge.issued_slot);
  w.u64le(challenge.deadline_slot);
  w.bytes_fixed(challenge.nonce);
}

std::optional<AvailabilityAuditChallenge> parse_audit_challenge(codec::ByteReader& r) {
  AvailabilityAuditChallenge challenge;
  const auto id = r.bytes_fixed<32>();
  const auto epoch = r.u64le();
  const auto pub = r.bytes_fixed<32>();
  const auto prefix = r.bytes_fixed<32>();
  const auto chunk = r.u32le();
  const auto issued = r.u64le();
  const auto deadline = r.u64le();
  const auto nonce = r.bytes_fixed<32>();
  if (!id || !epoch || !pub || !prefix || !chunk || !issued || !deadline || !nonce) return std::nullopt;
  challenge.challenge_id = *id;
  challenge.epoch = *epoch;
  challenge.operator_pubkey = *pub;
  challenge.prefix_id = *prefix;
  challenge.chunk_index = *chunk;
  challenge.issued_slot = *issued;
  challenge.deadline_slot = *deadline;
  challenge.nonce = *nonce;
  return challenge;
}

void serialize_audit_response(ByteWriter& w, const AvailabilityAuditResponse& response) {
  w.bytes_fixed(response.challenge_id);
  w.bytes_fixed(response.operator_pubkey);
  w.bytes_fixed(response.prefix_id);
  w.u32le(response.chunk_index);
  w.varbytes(response.chunk_bytes);
  serialize_merkle_proof(w, response.proof);
  w.u64le(response.responded_slot);
  w.bytes_fixed(response.operator_sig);
}

std::optional<AvailabilityAuditResponse> parse_audit_response(codec::ByteReader& r) {
  AvailabilityAuditResponse response;
  const auto challenge = r.bytes_fixed<32>();
  const auto pub = r.bytes_fixed<32>();
  const auto prefix = r.bytes_fixed<32>();
  const auto chunk = r.u32le();
  const auto bytes = r.varbytes();
  auto proof = parse_merkle_proof(r);
  const auto responded = r.u64le();
  const auto sig = r.bytes_fixed<64>();
  if (!challenge || !pub || !prefix || !chunk || !bytes || !proof || !responded || !sig) return std::nullopt;
  response.challenge_id = *challenge;
  response.operator_pubkey = *pub;
  response.prefix_id = *prefix;
  response.chunk_index = *chunk;
  response.chunk_bytes = *bytes;
  response.proof = *proof;
  response.responded_slot = *responded;
  response.operator_sig = *sig;
  return response;
}

void serialize_invalid_evidence(ByteWriter& w, const InvalidAvailabilityServiceEvidence& evidence) {
  serialize_audit_challenge(w, evidence.challenge);
  serialize_audit_response(w, evidence.response);
  w.u8(static_cast<std::uint8_t>(evidence.violation));
}

std::optional<InvalidAvailabilityServiceEvidence> parse_invalid_evidence(codec::ByteReader& r) {
  auto challenge = parse_audit_challenge(r);
  auto response = parse_audit_response(r);
  const auto violation = r.u8();
  if (!challenge || !response || !violation) return std::nullopt;
  if (*violation > static_cast<std::uint8_t>(InvalidAvailabilityResponseType::MALFORMED_RESPONSE)) return std::nullopt;
  return InvalidAvailabilityServiceEvidence{*challenge, *response,
                                            static_cast<InvalidAvailabilityResponseType>(*violation)};
}

std::uint64_t effective_join_epoch(const AvailabilitySimulationScenario& scenario,
                                   const AvailabilitySimulationOperator& op) {
  if (op.behavior == AvailabilitySimulationBehavior::JOIN_LATE && op.join_epoch == 0) {
    return scenario.start_epoch + (scenario.epochs / 3);
  }
  return op.join_epoch;
}

std::optional<std::uint64_t> effective_leave_epoch(const AvailabilitySimulationScenario& scenario,
                                                   const AvailabilitySimulationOperator& op) {
  if (op.behavior == AvailabilitySimulationBehavior::LEAVE_EARLY && !op.leave_epoch.has_value()) {
    return scenario.start_epoch + std::max<std::uint64_t>(1, scenario.epochs / 2);
  }
  return op.leave_epoch;
}

bool operator_present_in_epoch(const AvailabilitySimulationScenario& scenario, const AvailabilitySimulationOperator& op,
                               std::uint64_t epoch) {
  const auto join_epoch = effective_join_epoch(scenario, op);
  if (epoch < join_epoch) return false;
  if (const auto leave_epoch = effective_leave_epoch(scenario, op); leave_epoch.has_value() && epoch > *leave_epoch) return false;
  return true;
}

AvailabilityAuditOutcome simulated_audit_outcome(const Hash32& simulation_seed, const AvailabilitySimulationOperator& op,
                                                 std::uint64_t epoch, std::size_t draw_index) {
  const auto draw_hash = domain_hash(Bytes{'f', 'i', 'n', 'a', 'l', 'i', 's', '.', 'a', 'v', 'a', 'i', 'l', '.',
                                           's', 'i', 'm', '.', 'o', 'u', 't', 'c', 'o', 'm', 'e', '.', 'v', '1'},
                                     [&](ByteWriter& w) {
                                       w.bytes_fixed(simulation_seed);
                                       w.bytes_fixed(op.operator_pubkey);
                                       w.u64le(epoch);
                                       w.u64le(draw_index);
                                       w.u8(static_cast<std::uint8_t>(op.behavior));
                                     });
  const auto bucket = draw_hash[0] % 6;
  switch (op.behavior) {
    case AvailabilitySimulationBehavior::HONEST:
    case AvailabilitySimulationBehavior::JOIN_LATE:
    case AvailabilitySimulationBehavior::LEAVE_EARLY:
      return AvailabilityAuditOutcome::VALID_TIMELY;
    case AvailabilitySimulationBehavior::INTERMITTENT:
      return bucket < 3 ? AvailabilityAuditOutcome::VALID_TIMELY
                        : (bucket < 5 ? AvailabilityAuditOutcome::VALID_LATE : AvailabilityAuditOutcome::NO_RESPONSE);
    case AvailabilitySimulationBehavior::NO_RESPONSE:
      return AvailabilityAuditOutcome::NO_RESPONSE;
    case AvailabilitySimulationBehavior::INVALID_RESPONSE:
      return AvailabilityAuditOutcome::INVALID_RESPONSE;
    case AvailabilitySimulationBehavior::FLAKY:
      if (bucket < 2) return AvailabilityAuditOutcome::VALID_TIMELY;
      if (bucket < 4) return AvailabilityAuditOutcome::VALID_LATE;
      return AvailabilityAuditOutcome::NO_RESPONSE;
  }
  return AvailabilityAuditOutcome::NO_RESPONSE;
}

std::vector<RetainedPrefix> simulated_retained_prefixes(const Hash32& simulation_seed, std::uint64_t epoch,
                                                        std::uint64_t retained_prefixes_per_epoch,
                                                        std::size_t chunk_size) {
  std::vector<RetainedPrefix> out;
  out.reserve(static_cast<std::size_t>(retained_prefixes_per_epoch));
  for (std::uint64_t i = 0; i < retained_prefixes_per_epoch; ++i) {
    RetainedPrefix prefix;
    prefix.lane_id = static_cast<std::uint32_t>(i % 8);
    prefix.start_seq = epoch * 1'000 + (i * 4) + 1;
    prefix.end_seq = prefix.start_seq + 1;
    prefix.certified_height = epoch;
    prefix.payload_commitment = domain_hash(Bytes{'f', 'i', 'n', 'a', 'l', 'i', 's', '.', 'a', 'v', 'a', 'i', 'l', '.',
                                                  's', 'i', 'm', '.', 'p', 'a', 'y', 'l', 'o', 'a', 'd', '.', 'v', '1'},
                                            [&](ByteWriter& w) {
                                              w.bytes_fixed(simulation_seed);
                                              w.u64le(epoch);
                                              w.u64le(i);
                                            });
    prefix.byte_length = static_cast<std::uint64_t>(chunk_size) * 2 + (i % std::max<std::size_t>(1, chunk_size));
    prefix.chunk_count =
        static_cast<std::uint32_t>(std::max<std::uint64_t>(1, (prefix.byte_length + chunk_size - 1) / chunk_size));
    prefix.chunk_root = domain_hash(Bytes{'f', 'i', 'n', 'a', 'l', 'i', 's', '.', 'a', 'v', 'a', 'i', 'l', '.',
                                          's', 'i', 'm', '.', 'c', 'h', 'u', 'n', 'k', '.', 'v', '1'},
                                    [&](ByteWriter& w) {
                                      w.bytes_fixed(prefix.payload_commitment);
                                      w.u32le(prefix.chunk_count);
                                    });
    prefix.prefix_id = retained_prefix_id(prefix.lane_id, prefix.start_seq, prefix.end_seq, prefix.payload_commitment, epoch);
    out.push_back(prefix);
  }
  std::sort(out.begin(), out.end(), [](const RetainedPrefix& a, const RetainedPrefix& b) {
    if (a.certified_height != b.certified_height) return a.certified_height < b.certified_height;
    if (a.lane_id != b.lane_id) return a.lane_id < b.lane_id;
    if (a.start_seq != b.start_seq) return a.start_seq < b.start_seq;
    return a.prefix_id < b.prefix_id;
  });
  return out;
}

std::vector<PubKey32> normalized_committee(const std::vector<PubKey32>& committee) {
  auto out = committee;
  sort_and_unique(&out);
  return out;
}

std::size_t symmetric_difference_count(const std::vector<PubKey32>& a, const std::vector<PubKey32>& b) {
  std::vector<PubKey32> diff;
  std::set_symmetric_difference(a.begin(), a.end(), b.begin(), b.end(), std::back_inserter(diff));
  return diff.size();
}

std::uint32_t share_bps(std::uint64_t part, std::uint64_t whole) {
  if (whole == 0) return 0;
  return static_cast<std::uint32_t>((part * 10'000ULL) / whole);
}

void ensure_histogram_size(std::vector<std::uint64_t>* histogram, std::size_t size) {
  if (!histogram) return;
  if (histogram->size() < size) histogram->resize(size, 0);
}

void serialize_analytics_epoch_summary(ByteWriter& w, const AvailabilityAnalyticsEpochSummary& summary) {
  w.u64le(summary.epoch);
  w.u64le(summary.tracked_operator_count);
  w.u64le(summary.eligible_operator_count);
  w.u64le(summary.warmup_count);
  w.u64le(summary.active_count);
  w.u64le(summary.probation_count);
  w.u64le(summary.ejected_count);
  w.u64le(summary.passive_committee_size);
  w.u64le(summary.real_committee_size);
  w.u64le(summary.overlap_count);
  w.u32le(summary.overlap_bps);
  w.u64le(summary.passive_churn_count);
  w.u64le(summary.real_churn_count);
  w.u64le(summary.passive_total_seat_budget);
  w.u64le(summary.passive_top1_seat_budget);
  w.u64le(summary.passive_top3_seat_budget);
  w.u64le(summary.passive_top5_seat_budget);
  w.u32le(summary.passive_top1_share_bps);
  w.u32le(summary.passive_top3_share_bps);
  w.u32le(summary.passive_top5_share_bps);
  w.u32le(summary.passive_max_seat_budget);
  w.varint(summary.seat_budget_histogram.size());
  for (const auto bucket : summary.seat_budget_histogram) w.u64le(bucket);
}

void serialize_parameter_point(ByteWriter& w, const AvailabilityScenarioParameterPoint& point) {
  w.u32le(point.replication_factor);
  w.u32le(point.warmup_epochs);
  w.u32le(point.min_warmup_audits);
  w.u32le(point.min_warmup_success_rate_bps);
  w.u32le(point.score_alpha_bps);
  w.u64le(encode_i64(point.eligibility_min_score));
  w.u32le(point.seat_unit);
  w.u32le(point.max_seats_per_operator);
}

void serialize_suite_comparative_entry(ByteWriter& w, const AvailabilityScenarioSuiteComparativeEntry& entry) {
  serialize_parameter_point(w, entry.params);
  w.u32le(entry.mean_overlap_bps);
  w.u32le(entry.min_overlap_bps);
  w.u32le(entry.max_top1_share_bps);
  w.u32le(entry.max_top3_share_bps);
  w.u32le(entry.mean_passive_churn);
  w.u64le(entry.total_activation_events);
  w.u64le(entry.total_probation_events);
  w.u64le(entry.total_ejection_events);
  w.u64le(entry.activation_latency_count);
  w.u64le(entry.activation_latency_sum);
  w.u64le(entry.activation_latency_max);
  w.u64le(entry.final_eligible_operator_count);
  w.u64le(entry.final_active_count);
  w.u64le(entry.final_probation_count);
  w.u64le(entry.final_ejected_count);
  w.u32le(entry.final_top1_share_bps);
  w.u32le(entry.final_top3_share_bps);
  w.u8(static_cast<std::uint8_t>(entry.stability_class));
  w.u64le(entry.ranking_key_0);
  w.u64le(entry.ranking_key_1);
  w.u64le(entry.ranking_key_2);
  w.u64le(entry.ranking_key_3);
  w.u64le(entry.ranking_key_4);
}

std::int64_t parameter_dimension_value(const AvailabilityScenarioParameterPoint& point, AvailabilityParameterDimension dimension) {
  switch (dimension) {
    case AvailabilityParameterDimension::ReplicationFactor:
      return point.replication_factor;
    case AvailabilityParameterDimension::WarmupEpochs:
      return point.warmup_epochs;
    case AvailabilityParameterDimension::MinWarmupAudits:
      return point.min_warmup_audits;
    case AvailabilityParameterDimension::MinWarmupSuccessRateBps:
      return point.min_warmup_success_rate_bps;
    case AvailabilityParameterDimension::ScoreAlphaBps:
      return point.score_alpha_bps;
    case AvailabilityParameterDimension::EligibilityMinScore:
      return point.eligibility_min_score;
    case AvailabilityParameterDimension::SeatUnit:
      return point.seat_unit;
    case AvailabilityParameterDimension::MaxSeatsPerOperator:
      return point.max_seats_per_operator;
  }
  return 0;
}

std::size_t differing_parameter_dimensions(const AvailabilityScenarioParameterPoint& a,
                                           const AvailabilityScenarioParameterPoint& b,
                                           AvailabilityParameterDimension* last_difference = nullptr) {
  std::size_t count = 0;
  auto note = [&](AvailabilityParameterDimension dimension) {
    ++count;
    if (last_difference) *last_difference = dimension;
  };
  if (a.replication_factor != b.replication_factor) note(AvailabilityParameterDimension::ReplicationFactor);
  if (a.warmup_epochs != b.warmup_epochs) note(AvailabilityParameterDimension::WarmupEpochs);
  if (a.min_warmup_audits != b.min_warmup_audits) note(AvailabilityParameterDimension::MinWarmupAudits);
  if (a.min_warmup_success_rate_bps != b.min_warmup_success_rate_bps) note(AvailabilityParameterDimension::MinWarmupSuccessRateBps);
  if (a.score_alpha_bps != b.score_alpha_bps) note(AvailabilityParameterDimension::ScoreAlphaBps);
  if (a.eligibility_min_score != b.eligibility_min_score) note(AvailabilityParameterDimension::EligibilityMinScore);
  if (a.seat_unit != b.seat_unit) note(AvailabilityParameterDimension::SeatUnit);
  if (a.max_seats_per_operator != b.max_seats_per_operator) note(AvailabilityParameterDimension::MaxSeatsPerOperator);
  return count;
}

std::uint64_t abs_i64(std::int64_t value) {
  return value < 0 ? static_cast<std::uint64_t>(-value) : static_cast<std::uint64_t>(value);
}

void serialize_delta_entry(ByteWriter& w, const AvailabilityScenarioSuiteDeltaEntry& entry) {
  serialize_parameter_point(w, entry.params);
  serialize_parameter_point(w, entry.baseline_params);
  w.u64le(encode_i64(entry.mean_overlap_bps_delta));
  w.u64le(encode_i64(entry.min_overlap_bps_delta));
  w.u64le(encode_i64(entry.max_top1_share_bps_delta));
  w.u64le(encode_i64(entry.max_top3_share_bps_delta));
  w.u64le(encode_i64(entry.mean_passive_churn_delta));
  w.u64le(encode_i64(entry.total_activation_events_delta));
  w.u64le(encode_i64(entry.total_probation_events_delta));
  w.u64le(encode_i64(entry.total_ejection_events_delta));
  w.u64le(encode_i64(entry.activation_latency_count_delta));
  w.u64le(encode_i64(entry.activation_latency_sum_delta));
  w.u64le(encode_i64(entry.activation_latency_max_delta));
  w.u64le(encode_i64(entry.final_eligible_operator_count_delta));
  w.u64le(encode_i64(entry.final_active_count_delta));
  w.u64le(encode_i64(entry.final_probation_count_delta));
  w.u64le(encode_i64(entry.final_ejected_count_delta));
  w.u8(static_cast<std::uint8_t>(entry.baseline_class));
  w.u8(static_cast<std::uint8_t>(entry.current_class));
}

void serialize_oat_entry(ByteWriter& w, const AvailabilityOATSensitivityEntry& entry) {
  w.u8(static_cast<std::uint8_t>(entry.dimension));
  w.u64le(encode_i64(entry.parameter_value));
  w.u64le(encode_i64(entry.mean_overlap_bps_delta));
  w.u64le(encode_i64(entry.max_top1_share_bps_delta));
  w.u64le(encode_i64(entry.mean_passive_churn_delta));
  w.u64le(encode_i64(entry.activation_latency_sum_delta));
  w.u64le(encode_i64(entry.total_probation_events_delta));
  w.u64le(encode_i64(entry.total_ejection_events_delta));
}

AvailabilitySuiteStabilityClass classify_suite_entry(const AvailabilityScenarioSuiteComparativeEntry& entry) {
  if (entry.max_top1_share_bps <= 5'000 && entry.mean_overlap_bps >= 2'500 && entry.mean_passive_churn <= 4 &&
      entry.total_ejection_events <= 1) {
    return AvailabilitySuiteStabilityClass::STABLE;
  }
  if (entry.max_top1_share_bps <= 7'000 && entry.mean_overlap_bps >= 1'000 && entry.mean_passive_churn <= 8 &&
      entry.total_ejection_events <= 4) {
    return AvailabilitySuiteStabilityClass::BORDERLINE;
  }
  return AvailabilitySuiteStabilityClass::UNSTABLE;
}

}  // namespace

Bytes canonical_retained_prefix_payload_bytes(const std::vector<consensus::CertifiedIngressRecord>& records) {
  ByteWriter w;
  w.bytes(Bytes{'F', 'I', 'N', 'A', 'L', 'I', 'S', '_', 'R', 'E', 'T', 'A', 'I', 'N', '_', 'P', 'A', 'Y', 'L', 'O', 'A', 'D',
                '_', 'V', '1'});
  w.varint(records.size());
  for (const auto& record : records) {
    const auto cert_bytes = record.certificate.serialize();
    w.varbytes(cert_bytes);
    w.varbytes(record.tx_bytes);
  }
  return w.take();
}

Hash32 retained_prefix_payload_commitment(const Bytes& payload_bytes) { return crypto::sha256d(payload_bytes); }

Hash32 retained_prefix_id(std::uint32_t lane_id, std::uint64_t start_seq, std::uint64_t end_seq,
                          const Hash32& payload_commitment, std::uint64_t certified_height) {
  return domain_hash(Bytes{'f', 'i', 'n', 'a', 'l', 'i', 's', '.', 'p', 'r', 'e', 'f', 'i', 'x', '.', 'v', '1'},
                     [&](ByteWriter& w) {
                       w.u32le(lane_id);
                       w.u64le(start_seq);
                       w.u64le(end_seq);
                       w.bytes_fixed(payload_commitment);
                       w.u64le(certified_height);
                     });
}

std::vector<Bytes> split_retained_prefix_chunks(const Bytes& payload_bytes, std::size_t chunk_size) {
  std::vector<Bytes> chunks;
  if (chunk_size == 0) return chunks;
  for (std::size_t offset = 0; offset < payload_bytes.size(); offset += chunk_size) {
    const auto end = std::min(payload_bytes.size(), offset + chunk_size);
    chunks.emplace_back(payload_bytes.begin() + static_cast<long>(offset), payload_bytes.begin() + static_cast<long>(end));
  }
  if (chunks.empty()) chunks.push_back({});
  return chunks;
}

std::vector<Hash32> retained_prefix_chunk_hashes(const std::vector<Bytes>& chunks) {
  std::vector<Hash32> hashes;
  hashes.reserve(chunks.size());
  for (const auto& chunk : chunks) hashes.push_back(crypto::sha256d(chunk));
  return hashes;
}

Hash32 retained_prefix_chunk_root(const std::vector<Hash32>& chunk_hashes) {
  if (chunk_hashes.empty()) return zero_hash();
  return merkle::compute_merkle_root_from_leaves(chunk_hashes).value_or(zero_hash());
}

std::optional<RetainedPrefixPayload> build_retained_prefix_payload(
    std::uint32_t lane_id, const std::vector<consensus::CertifiedIngressRecord>& records, std::uint64_t certified_height,
    std::size_t chunk_size) {
  if (records.empty()) return std::nullopt;
  const auto start_seq = records.front().certificate.seq;
  const auto end_seq = records.back().certificate.seq;
  for (std::size_t i = 0; i < records.size(); ++i) {
    const auto& cert = records[i].certificate;
    if (cert.lane != lane_id) return std::nullopt;
    if (cert.seq != start_seq + i) return std::nullopt;
  }
  RetainedPrefixPayload out;
  out.payload_bytes = canonical_retained_prefix_payload_bytes(records);
  out.chunks = split_retained_prefix_chunks(out.payload_bytes, chunk_size);
  out.chunk_hashes = retained_prefix_chunk_hashes(out.chunks);
  out.prefix.lane_id = lane_id;
  out.prefix.start_seq = start_seq;
  out.prefix.end_seq = end_seq;
  out.prefix.payload_commitment = retained_prefix_payload_commitment(out.payload_bytes);
  out.prefix.chunk_root = retained_prefix_chunk_root(out.chunk_hashes);
  out.prefix.byte_length = out.payload_bytes.size();
  out.prefix.chunk_count = static_cast<std::uint32_t>(out.chunk_hashes.size());
  out.prefix.certified_height = certified_height;
  out.prefix.prefix_id = retained_prefix_id(lane_id, start_seq, end_seq, out.prefix.payload_commitment, certified_height);
  return out;
}

std::vector<RetainedPrefixPayload> build_retained_prefix_payloads_from_lane_records(
    const consensus::CertifiedIngressLaneRecords& lane_records, std::uint64_t certified_height, std::size_t chunk_size) {
  std::vector<RetainedPrefixPayload> out;
  for (std::size_t lane = 0; lane < lane_records.size(); ++lane) {
    if (lane_records[lane].empty()) continue;
    auto payload = build_retained_prefix_payload(static_cast<std::uint32_t>(lane), lane_records[lane], certified_height, chunk_size);
    if (payload.has_value()) out.push_back(*payload);
  }
  return out;
}

std::optional<AvailabilityMerkleProof> build_chunk_merkle_proof(const std::vector<Hash32>& chunk_hashes,
                                                                std::uint32_t chunk_index) {
  if (chunk_hashes.empty() || chunk_index >= chunk_hashes.size()) return std::nullopt;
  AvailabilityMerkleProof proof;
  std::vector<Hash32> level = chunk_hashes;
  std::size_t index = chunk_index;
  while (level.size() > 1) {
    if (level.size() % 2 == 1) level.push_back(level.back());
    const std::size_t sibling = (index % 2 == 0) ? (index + 1) : (index - 1);
    proof.siblings.push_back(level[sibling]);
    std::vector<Hash32> next;
    next.reserve(level.size() / 2);
    for (std::size_t i = 0; i < level.size(); i += 2) {
      Bytes cat;
      cat.insert(cat.end(), level[i].begin(), level[i].end());
      cat.insert(cat.end(), level[i + 1].begin(), level[i + 1].end());
      next.push_back(crypto::sha256d(cat));
    }
    index /= 2;
    level = std::move(next);
  }
  return proof;
}

bool verify_chunk_merkle_proof(const Bytes& chunk_bytes, std::uint32_t chunk_index, const AvailabilityMerkleProof& proof,
                               const Hash32& chunk_root) {
  Hash32 current = crypto::sha256d(chunk_bytes);
  std::size_t index = chunk_index;
  for (const auto& sibling : proof.siblings) {
    Bytes cat;
    if (index % 2 == 0) {
      cat.insert(cat.end(), current.begin(), current.end());
      cat.insert(cat.end(), sibling.begin(), sibling.end());
    } else {
      cat.insert(cat.end(), sibling.begin(), sibling.end());
      cat.insert(cat.end(), current.begin(), current.end());
    }
    current = crypto::sha256d(cat);
    index /= 2;
  }
  return current == chunk_root;
}

Hash32 availability_assignment_score(const Hash32& epoch_seed, const Hash32& prefix_id, const PubKey32& operator_pubkey) {
  return domain_hash(Bytes{'f', 'i', 'n', 'a', 'l', 'i', 's', '.', 'a', 'v', 'a', 'i', 'l', '.', 'a', 's', 's', 'i', 'g', 'n',
                           '.', 'v', '1'},
                     [&](ByteWriter& w) {
                       w.bytes_fixed(epoch_seed);
                       w.bytes_fixed(prefix_id);
                       w.bytes_fixed(operator_pubkey);
                     });
}

std::vector<PubKey32> assigned_operators_for_prefix(const Hash32& epoch_seed, const RetainedPrefix& prefix,
                                                    const std::vector<PubKey32>& operators, std::size_t replication_factor) {
  std::vector<std::pair<Hash32, PubKey32>> ranked;
  ranked.reserve(operators.size());
  for (const auto& pub : operators) ranked.push_back({availability_assignment_score(epoch_seed, prefix.prefix_id, pub), pub});
  std::sort(ranked.begin(), ranked.end(), [](const auto& a, const auto& b) {
    if (a.first != b.first) return a.first < b.first;
    return a.second < b.second;
  });
  if (replication_factor > ranked.size()) replication_factor = ranked.size();
  std::vector<PubKey32> out;
  out.reserve(replication_factor);
  for (std::size_t i = 0; i < replication_factor; ++i) out.push_back(ranked[i].second);
  return out;
}

bool is_operator_assigned_to_prefix(const Hash32& epoch_seed, const RetainedPrefix& prefix, const PubKey32& operator_pubkey,
                                    const std::vector<PubKey32>& operators, std::size_t replication_factor) {
  const auto assigned = assigned_operators_for_prefix(epoch_seed, prefix, operators, replication_factor);
  return std::find(assigned.begin(), assigned.end(), operator_pubkey) != assigned.end();
}

Hash32 availability_audit_seed(const Hash32& finalized_transition_id, std::uint64_t epoch) {
  return domain_hash(Bytes{'f', 'i', 'n', 'a', 'l', 'i', 's', '.', 'a', 'u', 'd', 'i', 't', '.', 's', 'e', 'e', 'd', '.', 'v',
                           '1'},
                     [&](ByteWriter& w) {
                       w.bytes_fixed(finalized_transition_id);
                       w.u64le(epoch);
                     });
}

std::vector<AvailabilityAuditChallenge> build_audit_challenges_for_operator(
    const PubKey32& operator_pubkey, const std::vector<RetainedPrefix>& assigned_prefixes, const Hash32& finalized_transition_id,
    std::uint64_t epoch, std::uint64_t issued_slot, const AvailabilityConfig& cfg) {
  std::vector<AvailabilityAuditChallenge> out;
  if (assigned_prefixes.empty()) return out;
  const auto seed = availability_audit_seed(finalized_transition_id, epoch);
  out.reserve(cfg.audits_per_operator_per_epoch);
  for (std::size_t draw = 0; draw < cfg.audits_per_operator_per_epoch; ++draw) {
    const auto selector = domain_hash(Bytes{'f', 'i', 'n', 'a', 'l', 'i', 's', '.', 'a', 'u', 'd', 'i', 't', '.', 'd', 'r', 'a',
                                            'w', '.', 'v', '1'},
                                      [&](ByteWriter& w) {
                                        w.bytes_fixed(seed);
                                        w.bytes_fixed(operator_pubkey);
                                        w.u64le(draw);
                                      });
    const auto prefix_index = bounded_index(selector, assigned_prefixes.size());
    const auto& prefix = assigned_prefixes[prefix_index];
    const auto chunk_selector =
        domain_hash(Bytes{'f', 'i', 'n', 'a', 'l', 'i', 's', '.', 'a', 'u', 'd', 'i', 't', '.', 'c', 'h', 'u', 'n', 'k', '.',
                          'v', '1'},
                    [&](ByteWriter& w) {
                      w.bytes_fixed(selector);
                      w.bytes_fixed(prefix.prefix_id);
                    });
    AvailabilityAuditChallenge challenge;
    challenge.epoch = epoch;
    challenge.operator_pubkey = operator_pubkey;
    challenge.prefix_id = prefix.prefix_id;
    challenge.chunk_index = static_cast<std::uint32_t>(bounded_index(chunk_selector, prefix.chunk_count));
    challenge.issued_slot = issued_slot;
    challenge.deadline_slot = issued_slot + cfg.audit_response_deadline_slots;
    challenge.nonce = selector;
    challenge.challenge_id = domain_hash(Bytes{'f', 'i', 'n', 'a', 'l', 'i', 's', '.', 'a', 'u', 'd', 'i', 't', '.', 'c', 'h',
                                               'a', 'l', 'l', 'e', 'n', 'g', 'e', '.', 'v', '1'},
                                         [&](ByteWriter& w) {
                                           w.u64le(challenge.epoch);
                                           w.bytes_fixed(challenge.operator_pubkey);
                                           w.bytes_fixed(challenge.prefix_id);
                                           w.u32le(challenge.chunk_index);
                                           w.u64le(challenge.issued_slot);
                                           w.u64le(challenge.deadline_slot);
                                           w.bytes_fixed(challenge.nonce);
                                         });
    out.push_back(challenge);
  }
  return out;
}

Hash32 availability_audit_response_signing_hash(const AvailabilityAuditResponse& response) {
  return domain_hash(Bytes{'f', 'i', 'n', 'a', 'l', 'i', 's', '.', 'a', 'u', 'd', 'i', 't', '.', 'r', 'e', 's', 'p', 'o', 'n',
                           's', 'e', '.', 'v', '1'},
                     [&](ByteWriter& w) {
                       w.bytes_fixed(response.challenge_id);
                       w.bytes_fixed(response.operator_pubkey);
                       w.bytes_fixed(response.prefix_id);
                       w.u32le(response.chunk_index);
                       w.varbytes(response.chunk_bytes);
                       w.varint(response.proof.siblings.size());
                       for (const auto& sibling : response.proof.siblings) w.bytes_fixed(sibling);
                       w.u64le(response.responded_slot);
                     });
}

std::optional<AvailabilityAuditResponse> make_audit_response(const AvailabilityAuditChallenge& challenge,
                                                             const RetainedPrefixPayload& payload,
                                                             const Bytes& operator_private_key) {
  if (challenge.prefix_id != payload.prefix.prefix_id) return std::nullopt;
  if (challenge.chunk_index >= payload.chunks.size()) return std::nullopt;
  auto proof = build_chunk_merkle_proof(payload.chunk_hashes, challenge.chunk_index);
  if (!proof.has_value()) return std::nullopt;
  AvailabilityAuditResponse response;
  response.challenge_id = challenge.challenge_id;
  response.operator_pubkey = challenge.operator_pubkey;
  response.prefix_id = challenge.prefix_id;
  response.chunk_index = challenge.chunk_index;
  response.chunk_bytes = payload.chunks[challenge.chunk_index];
  response.proof = *proof;
  response.responded_slot = challenge.issued_slot;
  const auto signing_hash = availability_audit_response_signing_hash(response);
  const Bytes signing_message(signing_hash.begin(), signing_hash.end());
  auto sig = crypto::ed25519_sign(signing_message, operator_private_key);
  if (!sig.has_value()) return std::nullopt;
  response.operator_sig = *sig;
  return response;
}

AvailabilityAuditOutcome verify_audit_response(const AvailabilityAuditChallenge& challenge, const RetainedPrefix& prefix,
                                               const std::optional<AvailabilityAuditResponse>& response,
                                               InvalidAvailabilityServiceEvidence* evidence, std::string* error) {
  if (!response.has_value()) {
    if (error) *error = "no-response";
    return AvailabilityAuditOutcome::NO_RESPONSE;
  }
  const auto& r = *response;
  auto invalid = [&](InvalidAvailabilityResponseType violation, const std::string& reason) {
    if (evidence) *evidence = InvalidAvailabilityServiceEvidence{challenge, r, violation};
    if (error) *error = reason;
    return AvailabilityAuditOutcome::INVALID_RESPONSE;
  };
  if (r.challenge_id != challenge.challenge_id || r.operator_pubkey != challenge.operator_pubkey ||
      r.prefix_id != challenge.prefix_id || r.chunk_index != challenge.chunk_index) {
    return invalid(InvalidAvailabilityResponseType::WRONG_PREFIX, "wrong-prefix");
  }
  if (all_zero_sig(r.operator_sig)) return invalid(InvalidAvailabilityResponseType::MALFORMED_RESPONSE, "missing-signature");
  const auto signing_hash = availability_audit_response_signing_hash(r);
  if (!crypto::ed25519_verify(Bytes(signing_hash.begin(), signing_hash.end()), r.operator_sig, r.operator_pubkey)) {
    return invalid(InvalidAvailabilityResponseType::MALFORMED_RESPONSE, "invalid-signature");
  }
  if (!verify_chunk_merkle_proof(r.chunk_bytes, r.chunk_index, r.proof, prefix.chunk_root)) {
    return invalid(InvalidAvailabilityResponseType::INVALID_PROOF, "invalid-proof");
  }
  if (r.responded_slot <= challenge.deadline_slot) return AvailabilityAuditOutcome::VALID_TIMELY;
  return AvailabilityAuditOutcome::VALID_LATE;
}

std::int64_t audit_outcome_delta(AvailabilityAuditOutcome outcome) {
  switch (outcome) {
    case AvailabilityAuditOutcome::VALID_TIMELY:
      return 1;
    case AvailabilityAuditOutcome::VALID_LATE:
      return 0;
    case AvailabilityAuditOutcome::NO_RESPONSE:
      return -1;
    case AvailabilityAuditOutcome::INVALID_RESPONSE:
      return -20;
  }
  return 0;
}

void apply_epoch_audit_outcomes(AvailabilityOperatorState* state, const std::vector<AvailabilityAuditOutcome>& outcomes,
                                std::uint64_t retained_prefix_count, const AvailabilityConfig& cfg) {
  if (!state) return;
  state->service_score = (state->service_score * static_cast<std::int64_t>(cfg.score_alpha_bps)) / 10'000;
  for (const auto outcome : outcomes) {
    state->service_score += audit_outcome_delta(outcome);
    switch (outcome) {
      case AvailabilityAuditOutcome::VALID_TIMELY:
        ++state->successful_audits;
        break;
      case AvailabilityAuditOutcome::VALID_LATE:
        ++state->late_audits;
        break;
      case AvailabilityAuditOutcome::NO_RESPONSE:
        ++state->missed_audits;
        break;
      case AvailabilityAuditOutcome::INVALID_RESPONSE:
        ++state->invalid_audits;
        break;
    }
  }
  ++state->warmup_epochs;
  state->retained_prefix_count = retained_prefix_count;
  update_operator_status(state, cfg);
}

std::vector<AvailabilityAuditOutcome> live_epoch_audit_outcomes(std::uint64_t retained_prefix_count,
                                                                const AvailabilityConfig& cfg) {
  std::vector<AvailabilityAuditOutcome> outcomes;
  if (retained_prefix_count == 0 || cfg.audits_per_operator_per_epoch == 0) return outcomes;
  outcomes.assign(cfg.audits_per_operator_per_epoch, AvailabilityAuditOutcome::VALID_TIMELY);
  return outcomes;
}

std::int64_t operator_eligibility_score(const AvailabilityOperatorState& state, const AvailabilityConfig& cfg) {
  return state.service_score +
         static_cast<std::int64_t>(cfg.retention_history_bonus_multiplier *
                                   static_cast<std::int64_t>(floor_sqrt_u64(state.retained_prefix_count)));
}

bool operator_is_eligible(const AvailabilityOperatorState& state, const AvailabilityConfig& cfg) {
  // Live availability eligibility is intentionally computed only from the
  // consensus-relevant operator state. Persisted invalid-response evidence is
  // observability-only and must never affect this decision.
  return state.status == AvailabilityOperatorStatus::ACTIVE && state.bond >= cfg.min_bond &&
         operator_eligibility_score(state, cfg) >= cfg.eligibility_min_score;
}

std::uint32_t operator_seat_budget(const AvailabilityOperatorState& state, const AvailabilityConfig& cfg) {
  const auto eligibility = operator_eligibility_score(state, cfg);
  if (eligibility <= 0 || cfg.seat_unit <= 0) return 0;
  const auto scaled = static_cast<std::uint64_t>(eligibility / cfg.seat_unit);
  return std::min<std::uint32_t>(cfg.max_seats_per_operator, static_cast<std::uint32_t>(floor_sqrt_u64(scaled)));
}

Hash32 availability_ticket(const Hash32& epoch_seed, const PubKey32& operator_pubkey, std::uint32_t seat_index) {
  return domain_hash(Bytes{'f', 'i', 'n', 'a', 'l', 'i', 's', '.', 'a', 'v', 'a', 'i', 'l', 'a', 'b', 'i', 'l', 'i', 't', 'y',
                           '.', 't', 'i', 'c', 'k', 'e', 't', '.', 'v', '1'},
                     [&](ByteWriter& w) {
                       w.bytes_fixed(epoch_seed);
                       w.bytes_fixed(operator_pubkey);
                       w.u32le(seat_index);
                     });
}

std::vector<AvailabilitySeatTicket> build_availability_tickets(const Hash32& epoch_seed,
                                                               const std::vector<AvailabilityOperatorState>& operators,
                                                               const AvailabilityConfig& cfg) {
  std::vector<AvailabilitySeatTicket> out;
  for (const auto& op : operators) {
    if (!operator_is_eligible(op, cfg)) continue;
    const auto budget = operator_seat_budget(op, cfg);
    for (std::uint32_t seat = 0; seat < budget; ++seat) {
      out.push_back(AvailabilitySeatTicket{op.operator_pubkey, seat, availability_ticket(epoch_seed, op.operator_pubkey, seat)});
    }
  }
  std::sort(out.begin(), out.end(), [](const AvailabilitySeatTicket& a, const AvailabilitySeatTicket& b) {
    if (a.ticket != b.ticket) return a.ticket < b.ticket;
    if (a.operator_pubkey != b.operator_pubkey) return a.operator_pubkey < b.operator_pubkey;
    return a.seat_index < b.seat_index;
  });
  return out;
}

Hash32 availability_simulation_epoch_seed(const Hash32& simulation_seed, std::uint64_t epoch) {
  return domain_hash(Bytes{'f', 'i', 'n', 'a', 'l', 'i', 's', '.', 'a', 'v', 'a', 'i', 'l', '.',
                           's', 'i', 'm', '.', 'e', 'p', 'o', 'c', 'h', '.', 'v', '1'},
                     [&](ByteWriter& w) {
                       w.bytes_fixed(simulation_seed);
                       w.u64le(epoch);
                     });
}

std::vector<PubKey32> preview_passive_committee(const Hash32& epoch_seed,
                                                const std::vector<AvailabilityOperatorState>& operators,
                                                std::size_t committee_size, const AvailabilityConfig& cfg) {
  std::vector<PubKey32> preview;
  const auto tickets = build_availability_tickets(epoch_seed, operators, cfg);
  preview.reserve(std::min<std::size_t>(committee_size, tickets.size()));
  std::set<PubKey32> seen;
  for (const auto& ticket : tickets) {
    if (!seen.insert(ticket.operator_pubkey).second) continue;
    preview.push_back(ticket.operator_pubkey);
    if (preview.size() >= committee_size) break;
  }
  return preview;
}

ShadowCommitteeComparison compare_shadow_committee(std::uint64_t epoch, const std::vector<PubKey32>& real_committee,
                                                   const std::vector<PubKey32>& passive_committee,
                                                   const std::vector<PubKey32>& previous_real_committee,
                                                   const std::vector<PubKey32>& previous_passive_committee) {
  ShadowCommitteeComparison out;
  out.epoch = epoch;
  out.real_committee_size = real_committee.size();
  out.passive_committee_size = passive_committee.size();

  const auto real = normalized_committee(real_committee);
  const auto passive = normalized_committee(passive_committee);
  const auto prev_real = normalized_committee(previous_real_committee);
  const auto prev_passive = normalized_committee(previous_passive_committee);

  std::vector<PubKey32> overlap;
  std::set_intersection(real.begin(), real.end(), passive.begin(), passive.end(), std::back_inserter(overlap));
  out.overlap_count = overlap.size();

  std::vector<PubKey32> union_members;
  std::set_union(real.begin(), real.end(), passive.begin(), passive.end(), std::back_inserter(union_members));
  out.overlap_bps =
      union_members.empty() ? 10'000U : static_cast<std::uint32_t>((out.overlap_count * 10'000ULL) / union_members.size());

  std::set_difference(real.begin(), real.end(), passive.begin(), passive.end(), std::back_inserter(out.only_real));
  std::set_difference(passive.begin(), passive.end(), real.begin(), real.end(), std::back_inserter(out.only_passive));

  out.real_churn_count = symmetric_difference_count(prev_real, real);
  out.passive_churn_count = symmetric_difference_count(prev_passive, passive);
  return out;
}

AvailabilitySimulationResult run_availability_shadow_simulation(const AvailabilitySimulationScenario& scenario,
                                                                const AvailabilityConfig& cfg) {
  AvailabilitySimulationResult result;
  auto operators = scenario.operators;
  std::sort(operators.begin(), operators.end(), [](const AvailabilitySimulationOperator& a,
                                                   const AvailabilitySimulationOperator& b) {
    return a.operator_pubkey < b.operator_pubkey;
  });
  std::map<PubKey32, AvailabilitySimulationOperator> operator_specs;
  for (const auto& op : operators) operator_specs[op.operator_pubkey] = op;

  std::set<std::uint64_t> restart_epochs(scenario.restart_epochs.begin(), scenario.restart_epochs.end());
  std::vector<PubKey32> previous_real_committee;
  std::vector<PubKey32> previous_passive_committee;

  for (std::uint64_t offset = 0; offset < scenario.epochs; ++offset) {
    const auto epoch = scenario.start_epoch + offset;
    result.final_state.current_epoch = epoch;

    auto epoch_prefixes =
        simulated_retained_prefixes(scenario.seed, epoch, scenario.retained_prefixes_per_epoch, cfg.audit_chunk_size);
    result.final_state.retained_prefixes.insert(result.final_state.retained_prefixes.end(), epoch_prefixes.begin(),
                                                epoch_prefixes.end());
    std::sort(result.final_state.retained_prefixes.begin(), result.final_state.retained_prefixes.end(),
              [](const RetainedPrefix& a, const RetainedPrefix& b) {
                if (a.certified_height != b.certified_height) return a.certified_height < b.certified_height;
                if (a.lane_id != b.lane_id) return a.lane_id < b.lane_id;
                if (a.start_seq != b.start_seq) return a.start_seq < b.start_seq;
                return a.prefix_id < b.prefix_id;
              });
    result.final_state.retained_prefixes.erase(
        std::unique(result.final_state.retained_prefixes.begin(), result.final_state.retained_prefixes.end(),
                    [](const RetainedPrefix& a, const RetainedPrefix& b) { return a.prefix_id == b.prefix_id; }),
        result.final_state.retained_prefixes.end());
    result.final_state.retained_prefixes =
        expire_retained_prefixes(result.final_state.retained_prefixes, epoch, cfg.retention_window_min_epochs);

    std::map<PubKey32, AvailabilityOperatorState> previous_states;
    for (const auto& state : result.final_state.operators) previous_states[state.operator_pubkey] = state;

    std::vector<AvailabilityOperatorState> active_states;
    active_states.reserve(operators.size());
    for (const auto& op : operators) {
      if (!operator_present_in_epoch(scenario, op, epoch)) continue;
      auto state_it = previous_states.find(op.operator_pubkey);
      AvailabilityOperatorState state;
      if (state_it != previous_states.end()) {
        state = state_it->second;
      } else {
        state.operator_pubkey = op.operator_pubkey;
        state.bond = op.bond;
      }
      state.bond = op.bond;
      active_states.push_back(state);
    }

    std::vector<PubKey32> assignment_operators;
    for (const auto& state : active_states) {
      if (state.status != AvailabilityOperatorStatus::EJECTED) assignment_operators.push_back(state.operator_pubkey);
    }
    sort_and_unique(&assignment_operators);

    const auto epoch_seed = availability_simulation_epoch_seed(scenario.seed, epoch);
    for (std::size_t i = 0; i < active_states.size(); ++i) {
      auto& state = active_states[i];
      std::uint64_t retained_count = 0;
      if (std::find(assignment_operators.begin(), assignment_operators.end(), state.operator_pubkey) != assignment_operators.end()) {
        for (const auto& prefix : result.final_state.retained_prefixes) {
          const auto assigned =
              assigned_operators_for_prefix(epoch_seed, prefix, assignment_operators, cfg.replication_factor);
          if (std::find(assigned.begin(), assigned.end(), state.operator_pubkey) != assigned.end()) ++retained_count;
        }
      }

      std::vector<AvailabilityAuditOutcome> outcomes;
      outcomes.reserve(cfg.audits_per_operator_per_epoch);
      const auto spec_it = operator_specs.find(state.operator_pubkey);
      if (spec_it == operator_specs.end()) throw std::runtime_error("availability simulation operator spec missing");
      for (std::size_t draw = 0; draw < cfg.audits_per_operator_per_epoch; ++draw) {
        outcomes.push_back(simulated_audit_outcome(scenario.seed, spec_it->second, epoch, draw));
      }
      apply_epoch_audit_outcomes(&state, outcomes, retained_count, cfg);
    }

    std::sort(active_states.begin(), active_states.end(), [](const AvailabilityOperatorState& a,
                                                             const AvailabilityOperatorState& b) {
      return a.operator_pubkey < b.operator_pubkey;
    });
    result.final_state.operators = active_states;

    AvailabilitySimulationEpochSummary summary;
    summary.epoch = epoch;
    summary.retained_prefix_count = result.final_state.retained_prefixes.size();
    summary.tracked_operator_count = result.final_state.operators.size();
    for (const auto& state : result.final_state.operators) {
      AvailabilitySimulationOperatorSummary operator_summary;
      operator_summary.operator_pubkey = state.operator_pubkey;
      operator_summary.status = state.status;
      operator_summary.service_score = state.service_score;
      operator_summary.retained_prefix_count = state.retained_prefix_count;
      operator_summary.eligibility_score = operator_eligibility_score(state, cfg);
      operator_summary.seat_budget = operator_seat_budget(state, cfg);
      summary.operators.push_back(operator_summary);
      if (operator_is_eligible(state, cfg)) ++summary.eligible_operator_count;
      switch (state.status) {
        case AvailabilityOperatorStatus::WARMUP:
          ++summary.warmup_count;
          break;
        case AvailabilityOperatorStatus::ACTIVE:
          ++summary.active_count;
          break;
        case AvailabilityOperatorStatus::PROBATION:
          ++summary.probation_count;
          break;
        case AvailabilityOperatorStatus::EJECTED:
          ++summary.ejected_count;
          break;
      }
      if (operator_summary.seat_budget <= cfg.max_seats_per_operator) continue;
      throw std::runtime_error("availability simulation seat budget overflow");
    }

    summary.passive_tickets = build_availability_tickets(epoch_seed, result.final_state.operators, cfg);
    summary.passive_committee_preview =
        preview_passive_committee(epoch_seed, result.final_state.operators, scenario.passive_committee_size, cfg);

    std::vector<PubKey32> real_committee;
    if (auto it = scenario.real_committees_by_epoch.find(epoch); it != scenario.real_committees_by_epoch.end()) {
      real_committee = it->second;
      sort_and_unique(&real_committee);
    }
    summary.committee_comparison = compare_shadow_committee(epoch, real_committee, summary.passive_committee_preview,
                                                            previous_real_committee, previous_passive_committee);
    previous_real_committee = real_committee;
    previous_passive_committee = summary.passive_committee_preview;

    result.epochs.push_back(summary);

    if (restart_epochs.find(epoch) != restart_epochs.end()) {
      const auto restored = AvailabilityPersistentState::parse(result.final_state.serialize());
      if (!restored.has_value()) throw std::runtime_error("availability simulation restart restore failed");
      result.final_state = *restored;
    }
  }
  return result;
}

AvailabilityAnalyticsReport analyze_availability_shadow_simulation(const AvailabilitySimulationScenario& scenario,
                                                                  const AvailabilitySimulationResult& result) {
  AvailabilityAnalyticsReport report;
  report.simulation_seed = scenario.seed;
  report.epoch_count = result.epochs.size();

  std::map<PubKey32, AvailabilityOperatorStatus> previous_status;
  std::map<PubKey32, std::uint64_t> first_active_epoch;

  for (const auto& op : scenario.operators) previous_status[op.operator_pubkey] = AvailabilityOperatorStatus::WARMUP;

  for (const auto& epoch_summary : result.epochs) {
    AvailabilityAnalyticsEpochSummary analytics;
    analytics.epoch = epoch_summary.epoch;
    analytics.tracked_operator_count = epoch_summary.tracked_operator_count;
    analytics.eligible_operator_count = epoch_summary.eligible_operator_count;
    analytics.warmup_count = epoch_summary.warmup_count;
    analytics.active_count = epoch_summary.active_count;
    analytics.probation_count = epoch_summary.probation_count;
    analytics.ejected_count = epoch_summary.ejected_count;

    if (epoch_summary.committee_comparison.has_value()) {
      const auto& comparison = *epoch_summary.committee_comparison;
      analytics.passive_committee_size = comparison.passive_committee_size;
      analytics.real_committee_size = comparison.real_committee_size;
      analytics.overlap_count = comparison.overlap_count;
      analytics.overlap_bps = comparison.overlap_bps;
      analytics.passive_churn_count = comparison.passive_churn_count;
      analytics.real_churn_count = comparison.real_churn_count;
    }

    std::vector<std::uint32_t> seat_budgets;
    seat_budgets.reserve(epoch_summary.operators.size());
    for (const auto& op : epoch_summary.operators) {
      analytics.passive_total_seat_budget += op.seat_budget;
      seat_budgets.push_back(op.seat_budget);
      ensure_histogram_size(&analytics.seat_budget_histogram, static_cast<std::size_t>(op.seat_budget) + 1);
      ++analytics.seat_budget_histogram[op.seat_budget];
      analytics.passive_max_seat_budget = std::max(analytics.passive_max_seat_budget, op.seat_budget);

      const auto prev = previous_status[op.operator_pubkey];
      if (op.status == AvailabilityOperatorStatus::ACTIVE && prev != AvailabilityOperatorStatus::ACTIVE) {
        ++report.total_activation_events;
        if (first_active_epoch.find(op.operator_pubkey) == first_active_epoch.end()) {
          first_active_epoch[op.operator_pubkey] = epoch_summary.epoch;
        }
      }
      if (op.status == AvailabilityOperatorStatus::PROBATION && prev != AvailabilityOperatorStatus::PROBATION) {
        ++report.total_probation_events;
      }
      if (op.status == AvailabilityOperatorStatus::EJECTED && prev != AvailabilityOperatorStatus::EJECTED) {
        ++report.total_ejection_events;
      }
      previous_status[op.operator_pubkey] = op.status;
    }

    std::sort(seat_budgets.begin(), seat_budgets.end(), std::greater<>());
    if (!seat_budgets.empty()) analytics.passive_top1_seat_budget = seat_budgets[0];
    for (std::size_t i = 0; i < std::min<std::size_t>(3, seat_budgets.size()); ++i) analytics.passive_top3_seat_budget += seat_budgets[i];
    for (std::size_t i = 0; i < std::min<std::size_t>(5, seat_budgets.size()); ++i) analytics.passive_top5_seat_budget += seat_budgets[i];
    analytics.passive_top1_share_bps = share_bps(analytics.passive_top1_seat_budget, analytics.passive_total_seat_budget);
    analytics.passive_top3_share_bps = share_bps(analytics.passive_top3_seat_budget, analytics.passive_total_seat_budget);
    analytics.passive_top5_share_bps = share_bps(analytics.passive_top5_seat_budget, analytics.passive_total_seat_budget);

    report.overlap_bps_sum += analytics.overlap_bps;
    if (report.epochs.empty()) {
      report.min_overlap_bps = analytics.overlap_bps;
      report.max_overlap_bps = analytics.overlap_bps;
    } else {
      report.min_overlap_bps = std::min(report.min_overlap_bps, analytics.overlap_bps);
      report.max_overlap_bps = std::max(report.max_overlap_bps, analytics.overlap_bps);
    }
    report.passive_churn_sum += analytics.passive_churn_count;
    report.real_churn_sum += analytics.real_churn_count;
    report.max_top1_share_bps = std::max(report.max_top1_share_bps, analytics.passive_top1_share_bps);
    report.max_top3_share_bps = std::max(report.max_top3_share_bps, analytics.passive_top3_share_bps);
    report.max_top5_share_bps = std::max(report.max_top5_share_bps, analytics.passive_top5_share_bps);
    report.seat_budget_histogram_max_bucket =
        std::max<std::uint32_t>(report.seat_budget_histogram_max_bucket, analytics.passive_max_seat_budget);
    ensure_histogram_size(&report.seat_budget_histogram, analytics.seat_budget_histogram.size());
    for (std::size_t i = 0; i < analytics.seat_budget_histogram.size(); ++i) {
      report.seat_budget_histogram[i] += analytics.seat_budget_histogram[i];
    }

    report.epochs.push_back(analytics);
  }

  for (const auto& op : scenario.operators) {
    const auto join_epoch = effective_join_epoch(scenario, op);
    if (result.epochs.empty()) continue;
    const auto last_epoch = result.epochs.back().epoch;
    if (join_epoch > last_epoch) continue;
    auto it = first_active_epoch.find(op.operator_pubkey);
    if (it == first_active_epoch.end()) {
      ++report.never_activated_count;
      continue;
    }
    const auto latency = it->second >= join_epoch ? (it->second - join_epoch) : 0;
    ++report.activation_latency_count;
    report.activation_latency_sum += latency;
    report.activation_latency_max = std::max(report.activation_latency_max, latency);
  }

  return report;
}

Bytes AvailabilityAnalyticsReport::serialize() const {
  ByteWriter w;
  w.bytes(kAvailabilityAnalyticsReportMagic);
  w.u32le(kAvailabilityAnalyticsReportVersion);
  w.bytes_fixed(simulation_seed);
  w.u64le(epoch_count);
  w.varint(epochs.size());
  for (const auto& epoch : epochs) serialize_analytics_epoch_summary(w, epoch);
  w.u64le(total_activation_events);
  w.u64le(total_probation_events);
  w.u64le(total_ejection_events);
  w.u64le(activation_latency_count);
  w.u64le(activation_latency_sum);
  w.u64le(activation_latency_max);
  w.u64le(never_activated_count);
  w.u64le(overlap_bps_sum);
  w.u32le(min_overlap_bps);
  w.u32le(max_overlap_bps);
  w.u64le(passive_churn_sum);
  w.u64le(real_churn_sum);
  w.u32le(max_top1_share_bps);
  w.u32le(max_top3_share_bps);
  w.u32le(max_top5_share_bps);
  w.u32le(seat_budget_histogram_max_bucket);
  w.varint(seat_budget_histogram.size());
  for (const auto bucket : seat_budget_histogram) w.u64le(bucket);
  return w.take();
}

std::string render_availability_analytics_report(const AvailabilityAnalyticsReport& report) {
  auto short_hex = [](const Hash32& h) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(8);
    for (std::size_t i = 0; i < 4; ++i) {
      out.push_back(kHex[(h[i] >> 4) & 0x0f]);
      out.push_back(kHex[h[i] & 0x0f]);
    }
    return out;
  };
  std::ostringstream oss;
  oss << "seed=" << short_hex(report.simulation_seed) << " epochs=" << report.epoch_count
      << " activations=" << report.total_activation_events << " probation=" << report.total_probation_events
      << " ejections=" << report.total_ejection_events << " overlap_sum_bps=" << report.overlap_bps_sum
      << " overlap_min_bps=" << report.min_overlap_bps << " overlap_max_bps=" << report.max_overlap_bps
      << " passive_churn_sum=" << report.passive_churn_sum << " real_churn_sum=" << report.real_churn_sum
      << " max_top1_share_bps=" << report.max_top1_share_bps << " max_top3_share_bps=" << report.max_top3_share_bps
      << " max_top5_share_bps=" << report.max_top5_share_bps << " never_activated=" << report.never_activated_count;
  for (const auto& epoch : report.epochs) {
    oss << "\n"
        << "epoch=" << epoch.epoch << " tracked=" << epoch.tracked_operator_count << " eligible=" << epoch.eligible_operator_count
        << " warmup=" << epoch.warmup_count << " active=" << epoch.active_count << " probation=" << epoch.probation_count
        << " ejected=" << epoch.ejected_count << " passive_committee=" << epoch.passive_committee_size
        << " real_committee=" << epoch.real_committee_size << " overlap=" << epoch.overlap_count
        << " overlap_bps=" << epoch.overlap_bps << " passive_churn=" << epoch.passive_churn_count
        << " real_churn=" << epoch.real_churn_count << " seat_total=" << epoch.passive_total_seat_budget
        << " top1=" << epoch.passive_top1_seat_budget << " top3=" << epoch.passive_top3_seat_budget
        << " top5=" << epoch.passive_top5_seat_budget << " top1_bps=" << epoch.passive_top1_share_bps
        << " top3_bps=" << epoch.passive_top3_share_bps << " top5_bps=" << epoch.passive_top5_share_bps;
  }
  return oss.str();
}

AvailabilityConfig availability_config_from_parameter_point(const AvailabilityScenarioParameterPoint& params,
                                                            const AvailabilityConfig& base) {
  auto cfg = base;
  cfg.replication_factor = params.replication_factor;
  cfg.warmup_epochs = params.warmup_epochs;
  cfg.min_warmup_audits = params.min_warmup_audits;
  cfg.min_warmup_success_rate_bps = params.min_warmup_success_rate_bps;
  cfg.score_alpha_bps = params.score_alpha_bps;
  cfg.eligibility_min_score = params.eligibility_min_score;
  cfg.seat_unit = params.seat_unit;
  cfg.max_seats_per_operator = params.max_seats_per_operator;
  return cfg;
}

std::vector<AvailabilityScenarioParameterPoint> enumerate_availability_parameter_points(
    const AvailabilityScenarioSuiteConfig& suite) {
  auto replications = suite.replication_factors;
  auto warmups = suite.warmup_epochs_values;
  auto warmup_audits = suite.min_warmup_audits_values;
  auto warmup_success = suite.min_warmup_success_rate_bps_values;
  auto score_alpha = suite.score_alpha_bps_values;
  auto eligibility = suite.eligibility_min_score_values;
  auto seat_units = suite.seat_unit_values;
  auto seat_caps = suite.max_seats_per_operator_values;

  if (replications.empty()) replications.push_back(kReplicationFactor);
  if (warmups.empty()) warmups.push_back(kWarmupEpochs);
  if (warmup_audits.empty()) warmup_audits.push_back(kMinWarmupAudits);
  if (warmup_success.empty()) warmup_success.push_back(kMinWarmupSuccessRateBps);
  if (score_alpha.empty()) score_alpha.push_back(kScoreDecayAlphaBps);
  if (eligibility.empty()) eligibility.push_back(kEligibilityMinScore);
  if (seat_units.empty()) seat_units.push_back(kSeatUnit);
  if (seat_caps.empty()) seat_caps.push_back(kMaxSeatsPerOperator);

  sort_and_unique(&replications);
  sort_and_unique(&warmups);
  sort_and_unique(&warmup_audits);
  sort_and_unique(&warmup_success);
  sort_and_unique(&score_alpha);
  sort_and_unique(&eligibility);
  sort_and_unique(&seat_units);
  sort_and_unique(&seat_caps);

  std::vector<AvailabilityScenarioParameterPoint> out;
  for (const auto replication : replications) {
    for (const auto warmup_epoch : warmups) {
      for (const auto warmup_audit : warmup_audits) {
        for (const auto success_bps : warmup_success) {
          for (const auto alpha_bps : score_alpha) {
            for (const auto eligibility_score : eligibility) {
              for (const auto seat_unit : seat_units) {
                for (const auto seat_cap : seat_caps) {
                  out.push_back(AvailabilityScenarioParameterPoint{
                      replication, warmup_epoch, warmup_audit, success_bps, alpha_bps, eligibility_score, seat_unit, seat_cap});
                }
              }
            }
          }
        }
      }
    }
  }
  std::sort(out.begin(), out.end());
  return out;
}

AvailabilityScenarioSuiteComparativeReport run_availability_scenario_suite(const AvailabilityScenarioSuiteConfig& suite,
                                                                           const AvailabilityConfig& base) {
  AvailabilityScenarioSuiteComparativeReport report;
  report.simulation_seed = suite.simulation_seed;
  report.horizon_epochs = suite.horizon_epochs;

  auto scenario = suite.scenario;
  scenario.seed = suite.simulation_seed;
  if (suite.horizon_epochs != 0) scenario.epochs = suite.horizon_epochs;

  for (const auto& point : enumerate_availability_parameter_points(suite)) {
    const auto cfg = availability_config_from_parameter_point(point, base);
    const auto result = run_availability_shadow_simulation(scenario, cfg);
    auto analytics = analyze_availability_shadow_simulation(scenario, result);
    report.entries.push_back(AvailabilityScenarioSuiteEntry{point, analytics});

    AvailabilityScenarioSuiteComparativeEntry entry;
    entry.params = point;
    entry.mean_overlap_bps =
        analytics.epoch_count == 0 ? 0 : static_cast<std::uint32_t>(analytics.overlap_bps_sum / analytics.epoch_count);
    entry.min_overlap_bps = analytics.min_overlap_bps;
    entry.max_top1_share_bps = analytics.max_top1_share_bps;
    entry.max_top3_share_bps = analytics.max_top3_share_bps;
    entry.mean_passive_churn =
        analytics.epoch_count == 0 ? 0 : static_cast<std::uint32_t>(analytics.passive_churn_sum / analytics.epoch_count);
    entry.total_activation_events = analytics.total_activation_events;
    entry.total_probation_events = analytics.total_probation_events;
    entry.total_ejection_events = analytics.total_ejection_events;
    entry.activation_latency_count = analytics.activation_latency_count;
    entry.activation_latency_sum = analytics.activation_latency_sum;
    entry.activation_latency_max = analytics.activation_latency_max;
    if (!analytics.epochs.empty()) {
      const auto& final_epoch = analytics.epochs.back();
      entry.final_eligible_operator_count = final_epoch.eligible_operator_count;
      entry.final_active_count = final_epoch.active_count;
      entry.final_probation_count = final_epoch.probation_count;
      entry.final_ejected_count = final_epoch.ejected_count;
      entry.final_top1_share_bps = final_epoch.passive_top1_share_bps;
      entry.final_top3_share_bps = final_epoch.passive_top3_share_bps;
    }
    entry.stability_class = classify_suite_entry(entry);
    entry.ranking_key_0 = entry.max_top1_share_bps;
    entry.ranking_key_1 = 10'000U - entry.mean_overlap_bps;
    entry.ranking_key_2 = entry.mean_passive_churn;
    entry.ranking_key_3 = entry.total_probation_events + entry.total_ejection_events;
    entry.ranking_key_4 =
        entry.activation_latency_count == 0 ? std::numeric_limits<std::uint64_t>::max()
                                            : (entry.activation_latency_sum / entry.activation_latency_count);
    report.comparative_entries.push_back(entry);
  }

  std::sort(report.comparative_entries.begin(), report.comparative_entries.end(),
            [](const AvailabilityScenarioSuiteComparativeEntry& a, const AvailabilityScenarioSuiteComparativeEntry& b) {
              if (a.stability_class != b.stability_class) return a.stability_class < b.stability_class;
              if (a.ranking_key_0 != b.ranking_key_0) return a.ranking_key_0 < b.ranking_key_0;
              if (a.ranking_key_1 != b.ranking_key_1) return a.ranking_key_1 < b.ranking_key_1;
              if (a.ranking_key_2 != b.ranking_key_2) return a.ranking_key_2 < b.ranking_key_2;
              if (a.ranking_key_3 != b.ranking_key_3) return a.ranking_key_3 < b.ranking_key_3;
              if (a.ranking_key_4 != b.ranking_key_4) return a.ranking_key_4 < b.ranking_key_4;
              return a.params < b.params;
            });

  return report;
}

Bytes AvailabilityScenarioSuiteComparativeReport::serialize() const {
  ByteWriter w;
  w.bytes(kAvailabilitySuiteReportMagic);
  w.u32le(kAvailabilitySuiteReportVersion);
  w.bytes_fixed(simulation_seed);
  w.u64le(horizon_epochs);
  w.varint(entries.size());
  for (const auto& entry : entries) {
    serialize_parameter_point(w, entry.params);
    w.varbytes(entry.report.serialize());
  }
  w.varint(comparative_entries.size());
  for (const auto& entry : comparative_entries) serialize_suite_comparative_entry(w, entry);
  return w.take();
}

std::string render_availability_scenario_suite_report(const AvailabilityScenarioSuiteComparativeReport& report) {
  auto short_hex = [](const Hash32& h) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(8);
    for (std::size_t i = 0; i < 4; ++i) {
      out.push_back(kHex[(h[i] >> 4) & 0x0f]);
      out.push_back(kHex[h[i] & 0x0f]);
    }
    return out;
  };
  std::ostringstream oss;
  oss << "seed=" << short_hex(report.simulation_seed) << " horizon=" << report.horizon_epochs
      << " entries=" << report.comparative_entries.size();
  for (const auto& entry : report.comparative_entries) {
    oss << "\nparams"
        << " rf=" << entry.params.replication_factor << " warmup_epochs=" << entry.params.warmup_epochs
        << " warmup_audits=" << entry.params.min_warmup_audits
        << " warmup_success_bps=" << entry.params.min_warmup_success_rate_bps
        << " alpha_bps=" << entry.params.score_alpha_bps << " elig=" << entry.params.eligibility_min_score
        << " seat_unit=" << entry.params.seat_unit << " seat_cap=" << entry.params.max_seats_per_operator
        << " class=" << static_cast<std::uint32_t>(entry.stability_class) << " mean_overlap_bps=" << entry.mean_overlap_bps
        << " min_overlap_bps=" << entry.min_overlap_bps << " max_top1_share_bps=" << entry.max_top1_share_bps
        << " max_top3_share_bps=" << entry.max_top3_share_bps << " mean_passive_churn=" << entry.mean_passive_churn
        << " activation_events=" << entry.total_activation_events << " probation_events=" << entry.total_probation_events
        << " ejection_events=" << entry.total_ejection_events << " final_eligible=" << entry.final_eligible_operator_count;
  }
  return oss.str();
}

std::optional<AvailabilityScenarioParameterPoint> default_availability_parameter_point(const AvailabilityConfig& cfg) {
  return AvailabilityScenarioParameterPoint{static_cast<std::uint32_t>(cfg.replication_factor),
                                            static_cast<std::uint32_t>(cfg.warmup_epochs),
                                            static_cast<std::uint32_t>(cfg.min_warmup_audits),
                                            static_cast<std::uint32_t>(cfg.min_warmup_success_rate_bps),
                                            static_cast<std::uint32_t>(cfg.score_alpha_bps), cfg.eligibility_min_score,
                                            static_cast<std::uint32_t>(cfg.seat_unit),
                                            static_cast<std::uint32_t>(cfg.max_seats_per_operator)};
}

const AvailabilityScenarioSuiteComparativeEntry* find_availability_suite_baseline(
    const AvailabilityScenarioSuiteComparativeReport& suite_report, const AvailabilityScenarioParameterPoint& baseline_params) {
  for (const auto& entry : suite_report.comparative_entries) {
    if (entry.params == baseline_params) return &entry;
  }
  return nullptr;
}

AvailabilityScenarioSuiteDeltaReport build_availability_suite_delta_report(
    const AvailabilityScenarioSuiteComparativeReport& suite_report, const AvailabilityScenarioParameterPoint& baseline_params) {
  AvailabilityScenarioSuiteDeltaReport report;
  report.baseline_params = baseline_params;
  const auto* baseline = find_availability_suite_baseline(suite_report, baseline_params);
  if (!baseline) throw std::runtime_error("availability suite baseline not found");

  report.entries.reserve(suite_report.comparative_entries.size());
  for (const auto& entry : suite_report.comparative_entries) {
    report.entries.push_back(AvailabilityScenarioSuiteDeltaEntry{
        .params = entry.params,
        .baseline_params = baseline_params,
        .mean_overlap_bps_delta = static_cast<std::int64_t>(entry.mean_overlap_bps) - static_cast<std::int64_t>(baseline->mean_overlap_bps),
        .min_overlap_bps_delta = static_cast<std::int64_t>(entry.min_overlap_bps) - static_cast<std::int64_t>(baseline->min_overlap_bps),
        .max_top1_share_bps_delta =
            static_cast<std::int64_t>(entry.max_top1_share_bps) - static_cast<std::int64_t>(baseline->max_top1_share_bps),
        .max_top3_share_bps_delta =
            static_cast<std::int64_t>(entry.max_top3_share_bps) - static_cast<std::int64_t>(baseline->max_top3_share_bps),
        .mean_passive_churn_delta =
            static_cast<std::int64_t>(entry.mean_passive_churn) - static_cast<std::int64_t>(baseline->mean_passive_churn),
        .total_activation_events_delta =
            static_cast<std::int64_t>(entry.total_activation_events) - static_cast<std::int64_t>(baseline->total_activation_events),
        .total_probation_events_delta =
            static_cast<std::int64_t>(entry.total_probation_events) - static_cast<std::int64_t>(baseline->total_probation_events),
        .total_ejection_events_delta =
            static_cast<std::int64_t>(entry.total_ejection_events) - static_cast<std::int64_t>(baseline->total_ejection_events),
        .activation_latency_count_delta =
            static_cast<std::int64_t>(entry.activation_latency_count) - static_cast<std::int64_t>(baseline->activation_latency_count),
        .activation_latency_sum_delta =
            static_cast<std::int64_t>(entry.activation_latency_sum) - static_cast<std::int64_t>(baseline->activation_latency_sum),
        .activation_latency_max_delta =
            static_cast<std::int64_t>(entry.activation_latency_max) - static_cast<std::int64_t>(baseline->activation_latency_max),
        .final_eligible_operator_count_delta = static_cast<std::int64_t>(entry.final_eligible_operator_count) -
                                               static_cast<std::int64_t>(baseline->final_eligible_operator_count),
        .final_active_count_delta =
            static_cast<std::int64_t>(entry.final_active_count) - static_cast<std::int64_t>(baseline->final_active_count),
        .final_probation_count_delta =
            static_cast<std::int64_t>(entry.final_probation_count) - static_cast<std::int64_t>(baseline->final_probation_count),
        .final_ejected_count_delta =
            static_cast<std::int64_t>(entry.final_ejected_count) - static_cast<std::int64_t>(baseline->final_ejected_count),
        .baseline_class = baseline->stability_class,
        .current_class = entry.stability_class,
    });
  }
  std::sort(report.entries.begin(), report.entries.end(),
            [](const AvailabilityScenarioSuiteDeltaEntry& a, const AvailabilityScenarioSuiteDeltaEntry& b) {
              return a.params < b.params;
            });
  return report;
}

Bytes AvailabilityScenarioSuiteDeltaReport::serialize() const {
  ByteWriter w;
  w.bytes(kAvailabilityDeltaReportMagic);
  w.u32le(kAvailabilityDeltaReportVersion);
  serialize_parameter_point(w, baseline_params);
  w.varint(entries.size());
  for (const auto& entry : entries) serialize_delta_entry(w, entry);
  return w.take();
}

std::vector<AvailabilityOATSensitivityReport> build_availability_oat_sensitivity_reports(
    const AvailabilityScenarioSuiteDeltaReport& delta_report) {
  std::vector<AvailabilityOATSensitivityReport> reports;
  for (std::uint8_t dim = static_cast<std::uint8_t>(AvailabilityParameterDimension::ReplicationFactor);
       dim <= static_cast<std::uint8_t>(AvailabilityParameterDimension::MaxSeatsPerOperator); ++dim) {
    AvailabilityParameterDimension dimension = static_cast<AvailabilityParameterDimension>(dim);
    AvailabilityOATSensitivityReport report;
    report.baseline_params = delta_report.baseline_params;
    report.dimension = dimension;
    for (const auto& entry : delta_report.entries) {
      AvailabilityParameterDimension differing_dimension{};
      if (differing_parameter_dimensions(entry.params, delta_report.baseline_params, &differing_dimension) != 1 ||
          differing_dimension != dimension) {
        continue;
      }
      report.entries.push_back(AvailabilityOATSensitivityEntry{
          .dimension = dimension,
          .parameter_value = parameter_dimension_value(entry.params, dimension),
          .mean_overlap_bps_delta = entry.mean_overlap_bps_delta,
          .max_top1_share_bps_delta = entry.max_top1_share_bps_delta,
          .mean_passive_churn_delta = entry.mean_passive_churn_delta,
          .activation_latency_sum_delta = entry.activation_latency_sum_delta,
          .total_probation_events_delta = entry.total_probation_events_delta,
          .total_ejection_events_delta = entry.total_ejection_events_delta,
      });
    }
    std::sort(report.entries.begin(), report.entries.end(),
              [](const AvailabilityOATSensitivityEntry& a, const AvailabilityOATSensitivityEntry& b) {
                return a.parameter_value < b.parameter_value;
              });
    reports.push_back(report);
  }
  return reports;
}

Bytes AvailabilityOATSensitivityReport::serialize() const {
  ByteWriter w;
  w.bytes(kAvailabilityOatReportMagic);
  w.u32le(kAvailabilityOatReportVersion);
  serialize_parameter_point(w, baseline_params);
  w.u8(static_cast<std::uint8_t>(dimension));
  w.varint(entries.size());
  for (const auto& entry : entries) serialize_oat_entry(w, entry);
  return w.take();
}

std::vector<AvailabilityDominantParameterEffect> build_availability_dominant_parameter_effects(
    const std::vector<AvailabilityOATSensitivityReport>& reports) {
  std::vector<AvailabilityDominantParameterEffect> effects;
  effects.reserve(reports.size());
  for (const auto& report : reports) {
    AvailabilityDominantParameterEffect effect;
    effect.dimension = report.dimension;
    for (const auto& entry : report.entries) {
      effect.max_abs_mean_overlap_bps_delta =
          std::max(effect.max_abs_mean_overlap_bps_delta, abs_i64(entry.mean_overlap_bps_delta));
      effect.max_abs_max_top1_share_bps_delta =
          std::max(effect.max_abs_max_top1_share_bps_delta, abs_i64(entry.max_top1_share_bps_delta));
      effect.max_abs_mean_passive_churn_delta =
          std::max(effect.max_abs_mean_passive_churn_delta, abs_i64(entry.mean_passive_churn_delta));
      effect.max_abs_activation_latency_sum_delta =
          std::max(effect.max_abs_activation_latency_sum_delta, abs_i64(entry.activation_latency_sum_delta));
    }
    effects.push_back(effect);
  }
  return effects;
}

std::vector<AvailabilityDimensionSensitivitySummary> build_availability_dimension_sensitivity_summaries(
    const std::vector<AvailabilityOATSensitivityReport>& reports) {
  std::vector<AvailabilityDimensionSensitivitySummary> out;
  out.reserve(reports.size());
  for (const auto& report : reports) {
    AvailabilityDimensionSensitivitySummary summary;
    summary.dimension = report.dimension;
    for (const auto& entry : report.entries) {
      summary.max_abs_mean_overlap_bps_delta =
          std::max(summary.max_abs_mean_overlap_bps_delta, abs_i64(entry.mean_overlap_bps_delta));
      summary.max_abs_max_top1_share_bps_delta =
          std::max(summary.max_abs_max_top1_share_bps_delta, abs_i64(entry.max_top1_share_bps_delta));
      summary.max_abs_mean_passive_churn_delta =
          std::max(summary.max_abs_mean_passive_churn_delta, abs_i64(entry.mean_passive_churn_delta));
      summary.max_abs_activation_latency_sum_delta =
          std::max(summary.max_abs_activation_latency_sum_delta, abs_i64(entry.activation_latency_sum_delta));
    }
    summary.sensitivity_class =
        (summary.max_abs_mean_overlap_bps_delta <= 1'000 && summary.max_abs_max_top1_share_bps_delta <= 1'000 &&
         summary.max_abs_mean_passive_churn_delta <= 2 && summary.max_abs_activation_latency_sum_delta <= 10)
            ? AvailabilitySensitivityClass::Robust
            : AvailabilitySensitivityClass::Sensitive;
    out.push_back(summary);
  }
  return out;
}

std::string render_availability_suite_delta_report(const AvailabilityScenarioSuiteDeltaReport& report) {
  std::ostringstream oss;
  oss << "baseline"
      << " rf=" << report.baseline_params.replication_factor << " warmup_epochs=" << report.baseline_params.warmup_epochs
      << " warmup_audits=" << report.baseline_params.min_warmup_audits
      << " warmup_success_bps=" << report.baseline_params.min_warmup_success_rate_bps
      << " alpha_bps=" << report.baseline_params.score_alpha_bps
      << " elig=" << report.baseline_params.eligibility_min_score << " seat_unit=" << report.baseline_params.seat_unit
      << " seat_cap=" << report.baseline_params.max_seats_per_operator;
  for (const auto& entry : report.entries) {
    oss << "\nparams"
        << " rf=" << entry.params.replication_factor << " warmup_epochs=" << entry.params.warmup_epochs
        << " warmup_audits=" << entry.params.min_warmup_audits
        << " warmup_success_bps=" << entry.params.min_warmup_success_rate_bps
        << " alpha_bps=" << entry.params.score_alpha_bps << " elig=" << entry.params.eligibility_min_score
        << " seat_unit=" << entry.params.seat_unit << " seat_cap=" << entry.params.max_seats_per_operator
        << " d_overlap=" << entry.mean_overlap_bps_delta << " d_top1=" << entry.max_top1_share_bps_delta
        << " d_churn=" << entry.mean_passive_churn_delta << " d_activation_sum=" << entry.activation_latency_sum_delta;
  }
  return oss.str();
}

std::string render_availability_oat_sensitivity_report(const AvailabilityOATSensitivityReport& report) {
  std::ostringstream oss;
  oss << "dimension=" << static_cast<std::uint32_t>(report.dimension);
  for (const auto& entry : report.entries) {
    oss << "\nvalue=" << entry.parameter_value << " d_overlap=" << entry.mean_overlap_bps_delta
        << " d_top1=" << entry.max_top1_share_bps_delta << " d_churn=" << entry.mean_passive_churn_delta
        << " d_activation_sum=" << entry.activation_latency_sum_delta << " d_probation=" << entry.total_probation_events_delta
        << " d_ejection=" << entry.total_ejection_events_delta;
  }
  return oss.str();
}

std::vector<RetainedPrefix> expire_retained_prefixes(const std::vector<RetainedPrefix>& retained_prefixes,
                                                     std::uint64_t current_epoch, std::uint64_t retention_window_epochs) {
  std::vector<RetainedPrefix> out;
  for (const auto& prefix : retained_prefixes) {
    if (current_epoch >= prefix.certified_height &&
        current_epoch - prefix.certified_height >= retention_window_epochs) {
      continue;
    }
    out.push_back(prefix);
  }
  return out;
}

void normalize_availability_consensus_state(AvailabilityPersistentState* state) {
  if (!state) return;

  std::sort(state->operators.begin(), state->operators.end(), [](const AvailabilityOperatorState& a,
                                                                 const AvailabilityOperatorState& b) {
    return a.operator_pubkey < b.operator_pubkey;
  });
  state->operators.erase(std::unique(state->operators.begin(), state->operators.end()), state->operators.end());

  std::sort(state->retained_prefixes.begin(), state->retained_prefixes.end(), retained_prefix_less);
  state->retained_prefixes.erase(std::unique(state->retained_prefixes.begin(), state->retained_prefixes.end()),
                                 state->retained_prefixes.end());
}

void normalize_availability_persistent_state(AvailabilityPersistentState* state) {
  if (!state) return;
  normalize_availability_consensus_state(state);

  std::sort(state->evidence.begin(), state->evidence.end(), invalid_evidence_less);
  state->evidence.erase(std::unique(state->evidence.begin(), state->evidence.end()), state->evidence.end());
}

bool validate_availability_persistent_state_for_live_derivation(const AvailabilityPersistentState& state,
                                                                const AvailabilityConfig& cfg, std::string* error) {
  // Live derivation intentionally validates only the consensus-relevant
  // availability fields. The persisted evidence vector is observability-only
  // and may not gate eligibility or checkpoint output.
  if (!std::is_sorted(state.operators.begin(), state.operators.end(),
                      [](const AvailabilityOperatorState& a, const AvailabilityOperatorState& b) {
                        return a.operator_pubkey < b.operator_pubkey;
                      })) {
    if (error) *error = "operators-not-canonically-sorted";
    return false;
  }
  if (has_conflicting_duplicates(
          state.operators,
          [](const AvailabilityOperatorState& a, const AvailabilityOperatorState& b) { return a.operator_pubkey < b.operator_pubkey; },
          [](const AvailabilityOperatorState& a, const AvailabilityOperatorState& b) { return a == b; })) {
    if (error) *error = "operator-state-conflicting-duplicate";
    return false;
  }
  for (std::size_t i = 1; i < state.operators.size(); ++i) {
    if (state.operators[i - 1].operator_pubkey == state.operators[i].operator_pubkey) {
      if (error) *error = "operator-state-duplicate";
      return false;
    }
  }
  for (const auto& operator_state : state.operators) {
    if (!operator_state_status_is_idempotent(operator_state, cfg)) {
      if (error) *error = "operator-state-status-not-idempotent";
      return false;
    }
  }

  if (!std::is_sorted(state.retained_prefixes.begin(), state.retained_prefixes.end(), retained_prefix_less)) {
    if (error) *error = "retained-prefixes-not-canonically-sorted";
    return false;
  }
  if (has_conflicting_duplicates(
          state.retained_prefixes, retained_prefix_less,
          [](const RetainedPrefix& a, const RetainedPrefix& b) { return a == b; })) {
    if (error) *error = "retained-prefix-conflicting-duplicate";
    return false;
  }
  std::set<Hash32> seen_prefix_ids;
  for (const auto& prefix : state.retained_prefixes) {
    if (!seen_prefix_ids.insert(prefix.prefix_id).second) {
      if (error) *error = "retained-prefix-duplicate";
      return false;
    }
  }

  return true;
}

AvailabilityPersistentState consensus_relevant_availability_state(const AvailabilityPersistentState& state) {
  auto out = state;
  out.evidence.clear();
  normalize_availability_consensus_state(&out);
  return out;
}

std::uint64_t count_eligible_operators(const AvailabilityPersistentState& state, const AvailabilityConfig& cfg) {
  std::uint64_t out = 0;
  for (const auto& operator_state : state.operators) {
    if (operator_is_eligible(operator_state, cfg)) ++out;
  }
  return out;
}

void refresh_live_availability_state(const Hash32& finalized_identity_id,
                                     const std::map<PubKey32, std::uint64_t>& operator_bonds, bool advance_epoch,
                                     AvailabilityPersistentState* state, const AvailabilityConfig& cfg) {
  if (!state) return;
  std::vector<PubKey32> operator_ids;
  operator_ids.reserve(operator_bonds.size());
  for (const auto& [operator_id, _] : operator_bonds) operator_ids.push_back(operator_id);

  const auto epoch_seed = availability_audit_seed(finalized_identity_id, state->current_epoch);
  std::map<PubKey32, std::uint64_t> assigned_prefix_counts;
  for (const auto& prefix : state->retained_prefixes) {
    for (const auto& operator_id : assigned_operators_for_prefix(epoch_seed, prefix, operator_ids, cfg.replication_factor)) {
      ++assigned_prefix_counts[operator_id];
    }
  }

  std::map<PubKey32, AvailabilityOperatorState> existing;
  for (const auto& operator_state : state->operators) existing[operator_state.operator_pubkey] = operator_state;

  std::vector<AvailabilityOperatorState> refreshed;
  refreshed.reserve(operator_ids.size());
  for (const auto& operator_id : operator_ids) {
    AvailabilityOperatorState operator_state;
    if (auto it = existing.find(operator_id); it != existing.end()) operator_state = it->second;
    operator_state.operator_pubkey = operator_id;
    operator_state.bond = operator_bonds.at(operator_id);
    const auto retained_count = assigned_prefix_counts[operator_id];
    if (advance_epoch) {
      apply_epoch_audit_outcomes(&operator_state, live_epoch_audit_outcomes(retained_count, cfg), retained_count, cfg);
    } else {
      operator_state.retained_prefix_count = retained_count;
    }
    refreshed.push_back(operator_state);
  }
  state->operators = std::move(refreshed);
  normalize_availability_persistent_state(state);
}

void advance_live_availability_epoch(const Hash32& finalized_identity_id,
                                     const std::map<PubKey32, std::uint64_t>& operator_bonds, std::uint64_t epoch,
                                     AvailabilityPersistentState* state, const AvailabilityConfig& cfg) {
  if (!state) return;
  if (epoch < state->current_epoch) return;
  if (state->current_epoch == 0 && epoch == 0) {
    refresh_live_availability_state(finalized_identity_id, operator_bonds, false, state, cfg);
    return;
  }
  while (state->current_epoch < epoch) {
    ++state->current_epoch;
    state->retained_prefixes = expire_retained_prefixes(state->retained_prefixes, state->current_epoch,
                                                        cfg.retention_window_min_epochs);
    refresh_live_availability_state(finalized_identity_id, operator_bonds, true, state, cfg);
  }
}

Bytes AvailabilityPersistentState::serialize() const {
  ByteWriter w;
  w.bytes(kAvailabilityPersistentStateMagic);
  w.u32le(version);
  w.u64le(current_epoch);

  auto normalized = *this;
  normalize_availability_persistent_state(&normalized);

  w.varint(normalized.operators.size());
  for (const auto& operator_state : normalized.operators) serialize_operator_state(w, operator_state);

  w.varint(normalized.retained_prefixes.size());
  for (const auto& prefix : normalized.retained_prefixes) serialize_retained_prefix(w, prefix);

  w.varint(normalized.evidence.size());
  for (const auto& entry : normalized.evidence) serialize_invalid_evidence(w, entry);
  return w.take();
}

std::optional<AvailabilityPersistentState> AvailabilityPersistentState::parse(const Bytes& b) {
  AvailabilityPersistentState state;
  if (!codec::parse_exact(b, [&](codec::ByteReader& r) {
        auto magic = r.bytes(kAvailabilityPersistentStateMagic.size());
        auto version = r.u32le();
        auto current_epoch = r.u64le();
        if (!magic || !version || !current_epoch) return false;
        if (*magic != kAvailabilityPersistentStateMagic) return false;
        if (*version != kAvailabilityPersistentStateVersion) return false;
        state.version = *version;
        state.current_epoch = *current_epoch;

        auto operator_count = r.varint();
        if (!operator_count) return false;
        state.operators.reserve(static_cast<std::size_t>(*operator_count));
        for (std::uint64_t i = 0; i < *operator_count; ++i) {
          auto operator_state = parse_operator_state(r);
          if (!operator_state) return false;
          state.operators.push_back(*operator_state);
        }

        auto prefix_count = r.varint();
        if (!prefix_count) return false;
        state.retained_prefixes.reserve(static_cast<std::size_t>(*prefix_count));
        for (std::uint64_t i = 0; i < *prefix_count; ++i) {
          auto prefix = parse_retained_prefix(r);
          if (!prefix) return false;
          state.retained_prefixes.push_back(*prefix);
        }

        auto evidence_count = r.varint();
        if (!evidence_count) return false;
        state.evidence.reserve(static_cast<std::size_t>(*evidence_count));
        for (std::uint64_t i = 0; i < *evidence_count; ++i) {
          auto entry = parse_invalid_evidence(r);
          if (!entry) return false;
          state.evidence.push_back(*entry);
        }
        return true;
      })) {
    return std::nullopt;
  }
  normalize_availability_persistent_state(&state);
  return state;
}

std::uint64_t floor_sqrt_u64(std::uint64_t value) {
  std::uint64_t lo = 0;
  std::uint64_t hi = (1ULL << 32);
  while (lo < hi) {
    const auto mid = lo + ((hi - lo + 1) / 2);
    const auto sq = static_cast<unsigned __int128>(mid) * static_cast<unsigned __int128>(mid);
    if (sq <= value) {
      lo = mid;
    } else {
      hi = mid - 1;
    }
  }
  return lo;
}

}  // namespace finalis::availability
