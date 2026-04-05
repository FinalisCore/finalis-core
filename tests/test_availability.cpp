#include "test_framework.hpp"

#include <array>
#include <limits>
#include <map>
#include <stdexcept>

#include "availability/retention.hpp"
#include "consensus/finalized_committee.hpp"
#include "consensus/validator_registry.hpp"
#include "crypto/ed25519.hpp"
#include "crypto/hash.hpp"

using namespace finalis;

namespace {

crypto::KeyPair key_from_byte(std::uint8_t base) {
  std::array<std::uint8_t, 32> seed{};
  seed.fill(base);
  auto kp = crypto::keypair_from_seed32(seed);
  if (!kp.has_value()) throw std::runtime_error("key derivation failed");
  return *kp;
}

consensus::CertifiedIngressRecord sample_record(std::uint32_t lane, std::uint64_t seq, std::uint8_t fill) {
  consensus::CertifiedIngressRecord record;
  record.tx_bytes.resize(3000, fill);
  record.certificate.epoch = 1;
  record.certificate.lane = lane;
  record.certificate.seq = seq;
  record.certificate.txid = crypto::sha256d(record.tx_bytes);
  record.certificate.tx_hash = crypto::sha256d(record.tx_bytes);
  record.certificate.prev_lane_root.fill(static_cast<std::uint8_t>(fill ^ 0x5a));
  return record;
}

availability::RetainedPrefixPayload sample_payload(std::uint32_t lane = 2, std::uint64_t start_seq = 7,
                                                   std::uint64_t certified_height = 11) {
  std::vector<consensus::CertifiedIngressRecord> records;
  records.push_back(sample_record(lane, start_seq, 0x31));
  records.push_back(sample_record(lane, start_seq + 1, 0x32));
  auto payload = availability::build_retained_prefix_payload(lane, records, certified_height);
  if (!payload.has_value()) throw std::runtime_error("failed to build retained prefix payload");
  return *payload;
}

availability::AvailabilitySimulationOperator simulation_operator(
    std::uint8_t base, availability::AvailabilitySimulationBehavior behavior, std::uint64_t join_epoch = 0,
    std::optional<std::uint64_t> leave_epoch = std::nullopt) {
  availability::AvailabilitySimulationOperator op;
  op.operator_pubkey = key_from_byte(base).public_key;
  op.bond = BOND_AMOUNT;
  op.behavior = behavior;
  op.join_epoch = join_epoch;
  op.leave_epoch = leave_epoch;
  return op;
}

std::map<std::uint64_t, std::vector<PubKey32>> deterministic_real_committees(
    const Hash32& seed, const std::vector<availability::AvailabilitySimulationOperator>& operators, std::uint64_t start_epoch,
    std::uint64_t epochs, std::size_t take) {
  std::map<std::uint64_t, std::vector<PubKey32>> out;
  for (std::uint64_t offset = 0; offset < epochs; ++offset) {
    const auto epoch = start_epoch + offset;
    std::vector<std::pair<Hash32, PubKey32>> scored;
    for (const auto& op : operators) {
      if (epoch < op.join_epoch) continue;
      if (op.leave_epoch.has_value() && epoch > *op.leave_epoch) continue;
      Bytes material(seed.begin(), seed.end());
      material.insert(material.end(), op.operator_pubkey.begin(), op.operator_pubkey.end());
      material.push_back(static_cast<std::uint8_t>(epoch & 0xff));
      material.push_back(static_cast<std::uint8_t>((epoch >> 8) & 0xff));
      scored.emplace_back(crypto::sha256d(material), op.operator_pubkey);
    }
    std::sort(scored.begin(), scored.end(), [](const auto& a, const auto& b) {
      if (a.first != b.first) return a.first < b.first;
      return a.second < b.second;
    });
    auto& committee = out[epoch];
    for (std::size_t i = 0; i < std::min<std::size_t>(take, scored.size()); ++i) committee.push_back(scored[i].second);
  }
  return out;
}

availability::AvailabilitySimulationScenario analytics_scenario(Hash32 seed) {
  availability::AvailabilitySimulationScenario scenario;
  scenario.start_epoch = 5;
  scenario.epochs = 96;
  scenario.retained_prefixes_per_epoch = 3;
  scenario.passive_committee_size = 4;
  scenario.seed = seed;
  scenario.operators = {
      simulation_operator(0x76, availability::AvailabilitySimulationBehavior::HONEST),
      simulation_operator(0x77, availability::AvailabilitySimulationBehavior::INTERMITTENT),
      simulation_operator(0x78, availability::AvailabilitySimulationBehavior::FLAKY),
      simulation_operator(0x79, availability::AvailabilitySimulationBehavior::JOIN_LATE, 20),
      simulation_operator(0x7a, availability::AvailabilitySimulationBehavior::NO_RESPONSE),
      simulation_operator(0x7b, availability::AvailabilitySimulationBehavior::INVALID_RESPONSE),
  };
  scenario.real_committees_by_epoch =
      deterministic_real_committees(scenario.seed, scenario.operators, scenario.start_epoch, scenario.epochs, 4);
  return scenario;
}

availability::AvailabilityScenarioSuiteConfig analytics_suite(Hash32 seed) {
  availability::AvailabilityScenarioSuiteConfig suite;
  suite.simulation_seed = seed;
  suite.horizon_epochs = 72;
  suite.scenario = analytics_scenario(seed);
  suite.replication_factors = {3, 2};
  suite.warmup_epochs_values = {14, 8};
  suite.min_warmup_audits_values = {50};
  suite.min_warmup_success_rate_bps_values = {9800};
  suite.score_alpha_bps_values = {9800, 9500};
  suite.eligibility_min_score_values = {10, 5};
  suite.seat_unit_values = {10, 20};
  suite.max_seats_per_operator_values = {4, 2};
  return suite;
}

availability::InvalidAvailabilityServiceEvidence sample_invalid_evidence(std::uint8_t base) {
  availability::InvalidAvailabilityServiceEvidence evidence;
  evidence.challenge.challenge_id.fill(base);
  evidence.challenge.epoch = 1;
  evidence.challenge.operator_pubkey = key_from_byte(base).public_key;
  evidence.challenge.prefix_id.fill(static_cast<std::uint8_t>(base + 1));
  evidence.challenge.chunk_index = static_cast<std::uint32_t>(base);
  evidence.challenge.issued_slot = 10 + base;
  evidence.challenge.deadline_slot = 20 + base;
  evidence.challenge.nonce.fill(static_cast<std::uint8_t>(base + 2));
  evidence.response.challenge_id = evidence.challenge.challenge_id;
  evidence.response.operator_pubkey = key_from_byte(static_cast<std::uint8_t>(base + 3)).public_key;
  evidence.response.prefix_id = evidence.challenge.prefix_id;
  evidence.response.chunk_index = evidence.challenge.chunk_index;
  evidence.response.chunk_bytes = Bytes{base, static_cast<std::uint8_t>(base + 4)};
  evidence.response.responded_slot = 30 + base;
  evidence.response.operator_sig.fill(static_cast<std::uint8_t>(base + 5));
  evidence.violation = availability::InvalidAvailabilityResponseType::INVALID_PROOF;
  return evidence;
}

}  // namespace

TEST(test_availability_chunk_commitment_is_deterministic_and_byte_sensitive) {
  const auto a = sample_payload();
  const auto b = sample_payload();
  ASSERT_EQ(a.prefix.chunk_root, b.prefix.chunk_root);
  ASSERT_EQ(a.prefix.payload_commitment, b.prefix.payload_commitment);

  auto changed = sample_payload();
  changed.payload_bytes[13] ^= 0x7f;
  changed.chunks = availability::split_retained_prefix_chunks(changed.payload_bytes);
  changed.chunk_hashes = availability::retained_prefix_chunk_hashes(changed.chunks);
  changed.prefix.chunk_root = availability::retained_prefix_chunk_root(changed.chunk_hashes);
  changed.prefix.payload_commitment = availability::retained_prefix_payload_commitment(changed.payload_bytes);
  ASSERT_TRUE(a.prefix.chunk_root != changed.prefix.chunk_root);
  ASSERT_TRUE(a.prefix.payload_commitment != changed.prefix.payload_commitment);
}

TEST(test_availability_audit_verification_accepts_valid_and_rejects_invalid_proofs) {
  const auto operator_key = key_from_byte(0x41);
  const auto payload = sample_payload();
  Hash32 transition_id{};
  transition_id.fill(0x77);
  const auto challenges = availability::build_audit_challenges_for_operator(operator_key.public_key, {payload.prefix}, transition_id,
                                                                            3, 100);
  ASSERT_EQ(challenges.size(), availability::kAuditsPerOperatorPerEpoch);

  const auto response = availability::make_audit_response(challenges.front(), payload, operator_key.private_key);
  ASSERT_TRUE(response.has_value());
  std::string err;
  availability::InvalidAvailabilityServiceEvidence evidence;
  ASSERT_EQ(availability::verify_audit_response(challenges.front(), payload.prefix, response, &evidence, &err),
            availability::AvailabilityAuditOutcome::VALID_TIMELY);

  auto bad_chunk = *response;
  bad_chunk.chunk_bytes[0] ^= 0x11;
  const auto bad_chunk_hash = availability::availability_audit_response_signing_hash(bad_chunk);
  auto bad_chunk_sig =
      crypto::ed25519_sign(Bytes(bad_chunk_hash.begin(), bad_chunk_hash.end()), operator_key.private_key);
  ASSERT_TRUE(bad_chunk_sig.has_value());
  bad_chunk.operator_sig = *bad_chunk_sig;
  ASSERT_EQ(availability::verify_audit_response(challenges.front(), payload.prefix, bad_chunk, &evidence, &err),
            availability::AvailabilityAuditOutcome::INVALID_RESPONSE);
  ASSERT_EQ(evidence.violation, availability::InvalidAvailabilityResponseType::INVALID_PROOF);

  auto bad_proof = *response;
  bad_proof.proof.siblings.front()[0] ^= 0x22;
  const auto bad_proof_hash = availability::availability_audit_response_signing_hash(bad_proof);
  auto bad_proof_sig =
      crypto::ed25519_sign(Bytes(bad_proof_hash.begin(), bad_proof_hash.end()), operator_key.private_key);
  ASSERT_TRUE(bad_proof_sig.has_value());
  bad_proof.operator_sig = *bad_proof_sig;
  ASSERT_EQ(availability::verify_audit_response(challenges.front(), payload.prefix, bad_proof, &evidence, &err),
            availability::AvailabilityAuditOutcome::INVALID_RESPONSE);
  ASSERT_EQ(evidence.violation, availability::InvalidAvailabilityResponseType::INVALID_PROOF);

  auto bad_prefix = *response;
  bad_prefix.prefix_id.fill(0x99);
  ASSERT_EQ(availability::verify_audit_response(challenges.front(), payload.prefix, bad_prefix, &evidence, &err),
            availability::AvailabilityAuditOutcome::INVALID_RESPONSE);
  ASSERT_EQ(evidence.violation, availability::InvalidAvailabilityResponseType::WRONG_PREFIX);
}

TEST(test_availability_score_update_is_deterministic) {
  availability::AvailabilityOperatorState state;
  state.operator_pubkey = key_from_byte(0x42).public_key;
  state.bond = BOND_AMOUNT;
  state.service_score = 10;
  availability::AvailabilityConfig cfg;
  cfg.score_alpha_bps = 9800;

  availability::apply_epoch_audit_outcomes(&state,
                                           {availability::AvailabilityAuditOutcome::VALID_TIMELY,
                                            availability::AvailabilityAuditOutcome::NO_RESPONSE,
                                            availability::AvailabilityAuditOutcome::INVALID_RESPONSE},
                                           9, cfg);
  ASSERT_EQ(state.service_score, -11);
  ASSERT_EQ(state.successful_audits, 1u);
  ASSERT_EQ(state.missed_audits, 1u);
  ASSERT_EQ(state.invalid_audits, 1u);
}

TEST(test_availability_operator_lifecycle_transitions_are_deterministic) {
  availability::AvailabilityConfig cfg;
  cfg.warmup_epochs = 2;
  cfg.min_warmup_audits = 3;
  cfg.min_warmup_success_rate_bps = 9000;
  cfg.eligibility_min_score = 2;
  cfg.probation_score = 0;
  cfg.ejection_score = -5;

  availability::AvailabilityOperatorState warmup;
  warmup.operator_pubkey = key_from_byte(0x43).public_key;
  warmup.bond = BOND_AMOUNT;
  availability::apply_epoch_audit_outcomes(&warmup,
                                           {availability::AvailabilityAuditOutcome::VALID_TIMELY,
                                            availability::AvailabilityAuditOutcome::VALID_TIMELY},
                                           4, cfg);
  ASSERT_EQ(warmup.status, availability::AvailabilityOperatorStatus::WARMUP);
  availability::apply_epoch_audit_outcomes(&warmup,
                                           {availability::AvailabilityAuditOutcome::VALID_TIMELY,
                                            availability::AvailabilityAuditOutcome::VALID_TIMELY},
                                           4, cfg);
  ASSERT_EQ(warmup.status, availability::AvailabilityOperatorStatus::ACTIVE);

  availability::AvailabilityOperatorState probation = warmup;
  availability::apply_epoch_audit_outcomes(&probation,
                                           {availability::AvailabilityAuditOutcome::NO_RESPONSE,
                                            availability::AvailabilityAuditOutcome::NO_RESPONSE,
                                            availability::AvailabilityAuditOutcome::NO_RESPONSE,
                                            availability::AvailabilityAuditOutcome::NO_RESPONSE},
                                           1, cfg);
  ASSERT_EQ(probation.status, availability::AvailabilityOperatorStatus::PROBATION);

  availability::AvailabilityOperatorState ejected = warmup;
  availability::apply_epoch_audit_outcomes(&ejected, {availability::AvailabilityAuditOutcome::INVALID_RESPONSE}, 1, cfg);
  ASSERT_EQ(ejected.status, availability::AvailabilityOperatorStatus::EJECTED);
}

TEST(test_availability_seat_budget_is_concave_and_capped) {
  availability::AvailabilityConfig cfg;
  cfg.max_seats_per_operator = 4;
  cfg.seat_unit = 10;

  availability::AvailabilityOperatorState low;
  low.operator_pubkey = key_from_byte(0x44).public_key;
  low.bond = BOND_AMOUNT;
  low.status = availability::AvailabilityOperatorStatus::ACTIVE;
  low.service_score = 100;
  low.retained_prefix_count = 4;

  availability::AvailabilityOperatorState high = low;
  high.operator_pubkey = key_from_byte(0x45).public_key;
  high.service_score = 1000;
  high.retained_prefix_count = 400;

  const auto low_budget = availability::operator_seat_budget(low, cfg);
  const auto high_budget = availability::operator_seat_budget(high, cfg);
  ASSERT_TRUE(low_budget > 0);
  ASSERT_TRUE(high_budget >= low_budget);
  ASSERT_TRUE(high_budget < low_budget * 10);
  ASSERT_TRUE(high_budget <= cfg.max_seats_per_operator);
}

TEST(test_availability_retention_window_expiry_is_deterministic) {
  std::vector<availability::RetainedPrefix> retained;
  retained.push_back(sample_payload(1, 1, 10).prefix);
  retained.push_back(sample_payload(2, 5, 80).prefix);

  const auto kept = availability::expire_retained_prefixes(retained, 100, 32);
  ASSERT_EQ(kept.size(), 1u);
  ASSERT_EQ(kept.front().lane_id, 2u);
}

TEST(test_availability_ticket_order_is_reproducible) {
  availability::AvailabilityConfig cfg;
  cfg.eligibility_min_score = 1;
  cfg.seat_unit = 10;

  availability::AvailabilityOperatorState a;
  a.operator_pubkey = key_from_byte(0x46).public_key;
  a.bond = BOND_AMOUNT;
  a.status = availability::AvailabilityOperatorStatus::ACTIVE;
  a.service_score = 200;
  a.retained_prefix_count = 9;

  availability::AvailabilityOperatorState b = a;
  b.operator_pubkey = key_from_byte(0x47).public_key;
  b.service_score = 150;

  Hash32 epoch_seed{};
  epoch_seed.fill(0x61);
  const auto tickets_a = availability::build_availability_tickets(epoch_seed, {a, b}, cfg);
  const auto tickets_b = availability::build_availability_tickets(epoch_seed, {a, b}, cfg);
  ASSERT_EQ(tickets_a, tickets_b);
  ASSERT_TRUE(!tickets_a.empty());
}

TEST(test_availability_assignment_and_prefix_materialization_are_deterministic) {
  consensus::CertifiedIngressLaneRecords lanes;
  lanes[3].push_back(sample_record(3, 9, 0x51));
  lanes[3].push_back(sample_record(3, 10, 0x52));
  lanes[6].push_back(sample_record(6, 1, 0x61));

  const auto retained = availability::build_retained_prefix_payloads_from_lane_records(lanes, 22);
  ASSERT_EQ(retained.size(), 2u);

  std::vector<PubKey32> operators{key_from_byte(0x48).public_key, key_from_byte(0x49).public_key, key_from_byte(0x4a).public_key,
                                  key_from_byte(0x4b).public_key};
  Hash32 epoch_seed{};
  epoch_seed.fill(0x33);
  const auto assigned_a = availability::assigned_operators_for_prefix(epoch_seed, retained.front().prefix, operators, 3);
  const auto assigned_b = availability::assigned_operators_for_prefix(epoch_seed, retained.front().prefix, operators, 3);
  ASSERT_EQ(assigned_a, assigned_b);
  ASSERT_EQ(assigned_a.size(), 3u);
}

TEST(test_availability_persistent_state_roundtrip_is_byte_stable) {
  availability::AvailabilityPersistentState state;
  state.current_epoch = 77;
  availability::AvailabilityOperatorState op;
  op.operator_pubkey = key_from_byte(0x51).public_key;
  op.bond = BOND_AMOUNT;
  op.status = availability::AvailabilityOperatorStatus::ACTIVE;
  op.service_score = -17;
  op.successful_audits = 12;
  op.late_audits = 1;
  op.missed_audits = 2;
  op.invalid_audits = 0;
  op.warmup_epochs = 15;
  op.retained_prefix_count = 9;
  state.operators.push_back(op);
  state.retained_prefixes.push_back(sample_payload(4, 20, 60).prefix);

  const auto bytes_a = state.serialize();
  const auto parsed = availability::AvailabilityPersistentState::parse(bytes_a);
  ASSERT_TRUE(parsed.has_value());
  const auto bytes_b = parsed->serialize();
  ASSERT_EQ(bytes_a, bytes_b);
}

TEST(test_availability_score_persistence_across_restart_is_identical) {
  availability::AvailabilityConfig cfg;
  cfg.warmup_epochs = 2;
  cfg.min_warmup_audits = 2;
  cfg.min_warmup_success_rate_bps = 9000;
  cfg.eligibility_min_score = 1;

  availability::AvailabilityOperatorState baseline;
  baseline.operator_pubkey = key_from_byte(0x52).public_key;
  baseline.bond = BOND_AMOUNT;
  baseline.service_score = 13;
  baseline.successful_audits = 5;
  baseline.warmup_epochs = 2;
  baseline.status = availability::AvailabilityOperatorStatus::ACTIVE;
  baseline.retained_prefix_count = 7;

  availability::AvailabilityPersistentState persisted;
  persisted.current_epoch = 9;
  persisted.operators.push_back(baseline);
  persisted.retained_prefixes.push_back(sample_payload(2, 9, 9).prefix);

  const auto encoded = persisted.serialize();
  const auto restored = availability::AvailabilityPersistentState::parse(encoded);
  ASSERT_TRUE(restored.has_value());
  ASSERT_EQ(restored->operators.front(), baseline);

  auto no_restart = baseline;
  auto after_restart = restored->operators.front();
  const std::vector<availability::AvailabilityAuditOutcome> outcomes{
      availability::AvailabilityAuditOutcome::VALID_TIMELY, availability::AvailabilityAuditOutcome::NO_RESPONSE,
      availability::AvailabilityAuditOutcome::VALID_LATE};
  availability::apply_epoch_audit_outcomes(&no_restart, outcomes, 11, cfg);
  availability::apply_epoch_audit_outcomes(&after_restart, outcomes, 11, cfg);
  ASSERT_EQ(after_restart, no_restart);
}

TEST(test_availability_lifecycle_persistence_across_restart_is_identical) {
  availability::AvailabilityPersistentState state;
  state.current_epoch = 12;

  availability::AvailabilityOperatorState warmup;
  warmup.operator_pubkey = key_from_byte(0x53).public_key;
  warmup.bond = BOND_AMOUNT;
  warmup.status = availability::AvailabilityOperatorStatus::WARMUP;
  warmup.successful_audits = 1;
  warmup.warmup_epochs = 1;

  availability::AvailabilityOperatorState active = warmup;
  active.operator_pubkey = key_from_byte(0x54).public_key;
  active.status = availability::AvailabilityOperatorStatus::ACTIVE;
  active.service_score = 20;
  active.successful_audits = 10;
  active.warmup_epochs = 20;

  availability::AvailabilityOperatorState probation = active;
  probation.operator_pubkey = key_from_byte(0x55).public_key;
  probation.status = availability::AvailabilityOperatorStatus::PROBATION;
  probation.service_score = -1;

  availability::AvailabilityOperatorState ejected = active;
  ejected.operator_pubkey = key_from_byte(0x56).public_key;
  ejected.status = availability::AvailabilityOperatorStatus::EJECTED;
  ejected.invalid_audits = 1;
  ejected.service_score = -20;

  state.operators = {ejected, probation, warmup, active};
  const auto parsed = availability::AvailabilityPersistentState::parse(state.serialize());
  ASSERT_TRUE(parsed.has_value());
  ASSERT_EQ(parsed->operators.size(), 4u);
  auto find_status = [&](const PubKey32& pub) {
    for (const auto& op : parsed->operators) {
      if (op.operator_pubkey == pub) return op.status;
    }
    throw std::runtime_error("missing restored operator");
  };
  ASSERT_EQ(find_status(warmup.operator_pubkey), availability::AvailabilityOperatorStatus::WARMUP);
  ASSERT_EQ(find_status(active.operator_pubkey), availability::AvailabilityOperatorStatus::ACTIVE);
  ASSERT_EQ(find_status(probation.operator_pubkey), availability::AvailabilityOperatorStatus::PROBATION);
  ASSERT_EQ(find_status(ejected.operator_pubkey), availability::AvailabilityOperatorStatus::EJECTED);

  availability::AvailabilityConfig cfg;
  cfg.warmup_epochs = 2;
  cfg.min_warmup_audits = 2;
  cfg.min_warmup_success_rate_bps = 9000;
  cfg.eligibility_min_score = 2;
  cfg.probation_score = 0;
  cfg.ejection_score = -5;
  auto restored_warmup = warmup;
  for (const auto& op : parsed->operators) {
    if (op.operator_pubkey == warmup.operator_pubkey) {
      restored_warmup = op;
      break;
    }
  }
  availability::apply_epoch_audit_outcomes(&restored_warmup,
                                           {availability::AvailabilityAuditOutcome::VALID_TIMELY,
                                            availability::AvailabilityAuditOutcome::VALID_TIMELY},
                                           3, cfg);
  ASSERT_EQ(restored_warmup.status, availability::AvailabilityOperatorStatus::ACTIVE);
}

TEST(test_availability_retention_window_expiry_matches_after_restart) {
  availability::AvailabilityPersistentState state;
  state.current_epoch = 100;
  state.retained_prefixes = {sample_payload(1, 1, 10).prefix, sample_payload(2, 5, 80).prefix};

  const auto baseline = availability::expire_retained_prefixes(state.retained_prefixes, 100, 32);
  const auto restored = availability::AvailabilityPersistentState::parse(state.serialize());
  ASSERT_TRUE(restored.has_value());
  const auto after_restart = availability::expire_retained_prefixes(restored->retained_prefixes, restored->current_epoch, 32);
  ASSERT_EQ(after_restart, baseline);
}

TEST(test_availability_retained_prefix_restoration_is_exact) {
  availability::AvailabilityPersistentState state;
  state.current_epoch = 44;
  const auto prefix_a = sample_payload(3, 9, 22).prefix;
  const auto prefix_b = sample_payload(6, 1, 23).prefix;
  state.retained_prefixes = {prefix_b, prefix_a};

  const auto restored = availability::AvailabilityPersistentState::parse(state.serialize());
  ASSERT_TRUE(restored.has_value());
  ASSERT_EQ(restored->retained_prefixes.size(), 2u);
  ASSERT_EQ(restored->retained_prefixes[0], prefix_a);
  ASSERT_EQ(restored->retained_prefixes[1], prefix_b);
}

TEST(test_availability_persistent_state_normalization_is_canonical_and_validation_is_order_independent) {
  availability::AvailabilityPersistentState state;
  state.current_epoch = 19;

  availability::AvailabilityOperatorState a;
  a.operator_pubkey = key_from_byte(0x59).public_key;
  a.bond = BOND_AMOUNT;
  a.status = availability::AvailabilityOperatorStatus::ACTIVE;
  a.service_score = 25;
  a.successful_audits = 8;
  a.warmup_epochs = 20;
  a.retained_prefix_count = 4;

  availability::AvailabilityOperatorState b = a;
  b.operator_pubkey = key_from_byte(0x5a).public_key;
  b.service_score = 40;
  b.retained_prefix_count = 9;

  state.operators = {b, a, b};
  state.retained_prefixes = {sample_payload(8, 4, 30).prefix, sample_payload(4, 2, 11).prefix, sample_payload(8, 4, 30).prefix};
  availability::normalize_availability_persistent_state(&state);

  ASSERT_EQ(state.operators.size(), 2u);
  ASSERT_TRUE(state.operators[0].operator_pubkey < state.operators[1].operator_pubkey);
  ASSERT_EQ(state.retained_prefixes.size(), 2u);
  ASSERT_TRUE(state.retained_prefixes[0].certified_height <= state.retained_prefixes[1].certified_height);
  ASSERT_TRUE(availability::validate_availability_persistent_state_for_live_derivation(state));
  ASSERT_EQ(availability::count_eligible_operators(state), 2u);
}

TEST(test_availability_persistent_state_normalization_is_idempotent) {
  availability::AvailabilityPersistentState state;
  state.current_epoch = 21;
  availability::AvailabilityOperatorState a;
  a.operator_pubkey = key_from_byte(0x67).public_key;
  a.bond = BOND_AMOUNT;
  a.status = availability::AvailabilityOperatorStatus::ACTIVE;
  a.service_score = 33;
  a.successful_audits = 5;
  a.warmup_epochs = 7;
  a.retained_prefix_count = 3;
  availability::AvailabilityOperatorState b = a;
  b.operator_pubkey = key_from_byte(0x68).public_key;
  b.service_score = 17;
  state.operators = {b, a, a};
  state.retained_prefixes = {sample_payload(5, 2, 18).prefix, sample_payload(1, 1, 11).prefix};

  auto once = state;
  availability::normalize_availability_persistent_state(&once);
  auto twice = once;
  availability::normalize_availability_persistent_state(&twice);
  ASSERT_EQ(twice, once);
}

TEST(test_availability_evidence_isolation_for_live_eligibility_and_counting) {
  availability::AvailabilityConfig cfg;
  cfg.min_bond = BOND_AMOUNT;
  cfg.eligibility_min_score = 0;

  availability::AvailabilityPersistentState base;
  base.current_epoch = 9;
  availability::AvailabilityOperatorState active;
  active.operator_pubkey = key_from_byte(0x69).public_key;
  active.bond = BOND_AMOUNT;
  active.status = availability::AvailabilityOperatorStatus::ACTIVE;
  active.service_score = 5;
  active.successful_audits = 2;
  active.warmup_epochs = 2;
  active.retained_prefix_count = 1;
  base.operators.push_back(active);
  base.retained_prefixes.push_back(sample_payload(2, 2, 9).prefix);

  auto with_evidence = base;
  with_evidence.evidence = {sample_invalid_evidence(0x31), sample_invalid_evidence(0x21), sample_invalid_evidence(0x31)};
  availability::normalize_availability_persistent_state(&base);
  availability::normalize_availability_persistent_state(&with_evidence);

  ASSERT_TRUE(availability::validate_availability_persistent_state_for_live_derivation(base, cfg));
  ASSERT_TRUE(availability::validate_availability_persistent_state_for_live_derivation(with_evidence, cfg));
  ASSERT_EQ(availability::consensus_relevant_availability_state(base),
            availability::consensus_relevant_availability_state(with_evidence));
  ASSERT_EQ(availability::operator_is_eligible(base.operators.front(), cfg),
            availability::operator_is_eligible(with_evidence.operators.front(), cfg));
  ASSERT_EQ(availability::count_eligible_operators(base, cfg), availability::count_eligible_operators(with_evidence, cfg));

  consensus::ValidatorRegistry validators;
  validators.set_rules(consensus::ValidatorRules{.min_bond = BOND_AMOUNT, .warmup_blocks = 0, .cooldown_blocks = 0});
  std::string err;
  ASSERT_TRUE(validators.register_bond(active.operator_pubkey, OutPoint{Hash32{1}, 0}, 0, BOND_AMOUNT, &err,
                                       active.operator_pubkey));
  validators.advance_height(1);
  const auto info = validators.get(active.operator_pubkey);
  ASSERT_TRUE(info.has_value());
  const auto eligibility_a =
      consensus::committee_eligibility_at_checkpoint(validators, active.operator_pubkey, *info, 1, BOND_AMOUNT,
                                                     &base.operators.front(), cfg, true);
  const auto eligibility_b =
      consensus::committee_eligibility_at_checkpoint(validators, active.operator_pubkey, *info, 1, BOND_AMOUNT,
                                                     &with_evidence.operators.front(), cfg, true);
  ASSERT_EQ(eligibility_a.eligible, eligibility_b.eligible);
  ASSERT_EQ(eligibility_a.availability_eligible, eligibility_b.availability_eligible);
}

TEST(test_availability_persistent_state_validation_rejects_conflicting_duplicates_and_non_idempotent_status) {
  availability::AvailabilityConfig cfg;
  cfg.warmup_epochs = 2;
  cfg.min_warmup_audits = 2;
  cfg.min_warmup_success_rate_bps = 9000;
  cfg.eligibility_min_score = 2;
  cfg.probation_score = 0;
  cfg.ejection_score = -5;

  availability::AvailabilityPersistentState duplicate_state;
  duplicate_state.current_epoch = 7;
  availability::AvailabilityOperatorState op;
  op.operator_pubkey = key_from_byte(0x5b).public_key;
  op.bond = BOND_AMOUNT;
  op.status = availability::AvailabilityOperatorStatus::ACTIVE;
  op.service_score = 10;
  op.successful_audits = 5;
  op.warmup_epochs = 5;
  duplicate_state.operators = {op, op};
  duplicate_state.operators.back().service_score = 11;
  availability::normalize_availability_persistent_state(&duplicate_state);
  std::string error;
  ASSERT_TRUE(!availability::validate_availability_persistent_state_for_live_derivation(duplicate_state, cfg, &error));
  ASSERT_EQ(error, "operator-state-conflicting-duplicate");

  availability::AvailabilityPersistentState status_state;
  status_state.current_epoch = 7;
  op.status = availability::AvailabilityOperatorStatus::ACTIVE;
  op.service_score = -1;
  status_state.operators = {op};
  availability::normalize_availability_persistent_state(&status_state);
  error.clear();
  ASSERT_TRUE(!availability::validate_availability_persistent_state_for_live_derivation(status_state, cfg, &error));
  ASSERT_EQ(error, "operator-state-status-not-idempotent");
}

TEST(test_availability_prefix_assignment_is_deterministic_under_shuffled_operator_input) {
  const auto prefix = sample_payload(7, 3, 40).prefix;
  Hash32 epoch_seed{};
  epoch_seed.fill(0x66);

  std::vector<PubKey32> operators{
      key_from_byte(0x71).public_key,
      key_from_byte(0x72).public_key,
      key_from_byte(0x73).public_key,
      key_from_byte(0x74).public_key,
  };
  const auto expected = availability::assigned_operators_for_prefix(epoch_seed, prefix, operators, 3);
  std::rotate(operators.begin(), operators.begin() + 2, operators.end());
  const auto shuffled = availability::assigned_operators_for_prefix(epoch_seed, prefix, operators, 3);
  ASSERT_EQ(shuffled, expected);
}

TEST(test_availability_seat_budget_and_tickets_match_after_restart) {
  availability::AvailabilityConfig cfg;
  cfg.eligibility_min_score = 1;
  cfg.seat_unit = 10;

  availability::AvailabilityPersistentState state;
  state.current_epoch = 18;

  availability::AvailabilityOperatorState a;
  a.operator_pubkey = key_from_byte(0x57).public_key;
  a.bond = BOND_AMOUNT;
  a.status = availability::AvailabilityOperatorStatus::ACTIVE;
  a.service_score = 120;
  a.retained_prefix_count = 16;

  availability::AvailabilityOperatorState b = a;
  b.operator_pubkey = key_from_byte(0x58).public_key;
  b.service_score = 70;
  b.retained_prefix_count = 4;

  state.operators = {b, a};
  Hash32 epoch_seed{};
  epoch_seed.fill(0x73);

  const auto expected_scores = std::vector<std::int64_t>{
      availability::operator_eligibility_score(a, cfg), availability::operator_eligibility_score(b, cfg)};
  const auto expected_budgets =
      std::vector<std::uint32_t>{availability::operator_seat_budget(a, cfg), availability::operator_seat_budget(b, cfg)};
  const auto expected_tickets = availability::build_availability_tickets(epoch_seed, {a, b}, cfg);

  const auto restored = availability::AvailabilityPersistentState::parse(state.serialize());
  ASSERT_TRUE(restored.has_value());
  ASSERT_EQ(restored->operators.size(), 2u);
  ASSERT_EQ(availability::operator_eligibility_score(restored->operators[0], cfg), expected_scores[0]);
  ASSERT_EQ(availability::operator_eligibility_score(restored->operators[1], cfg), expected_scores[1]);
  ASSERT_EQ(availability::operator_seat_budget(restored->operators[0], cfg), expected_budgets[0]);
  ASSERT_EQ(availability::operator_seat_budget(restored->operators[1], cfg), expected_budgets[1]);
  ASSERT_EQ(availability::build_availability_tickets(epoch_seed, restored->operators, cfg), expected_tickets);
}

TEST(test_availability_shadow_simulation_is_repeatable_over_long_horizon) {
  availability::AvailabilitySimulationScenario scenario;
  scenario.start_epoch = 1;
  scenario.epochs = 512;
  scenario.retained_prefixes_per_epoch = 3;
  scenario.passive_committee_size = 3;
  scenario.seed.fill(0x81);
  scenario.operators = {
      simulation_operator(0x61, availability::AvailabilitySimulationBehavior::HONEST),
      simulation_operator(0x62, availability::AvailabilitySimulationBehavior::INTERMITTENT),
      simulation_operator(0x63, availability::AvailabilitySimulationBehavior::FLAKY),
      simulation_operator(0x64, availability::AvailabilitySimulationBehavior::NO_RESPONSE),
  };
  scenario.real_committees_by_epoch =
      deterministic_real_committees(scenario.seed, scenario.operators, scenario.start_epoch, scenario.epochs, 3);

  const auto a = availability::run_availability_shadow_simulation(scenario);
  const auto b = availability::run_availability_shadow_simulation(scenario);
  ASSERT_EQ(a, b);
  ASSERT_EQ(a.epochs.size(), 512u);
  ASSERT_TRUE(!a.epochs.back().passive_committee_preview.empty());
}

TEST(test_availability_shadow_simulation_handles_operator_churn_deterministically) {
  availability::AvailabilitySimulationScenario scenario;
  scenario.start_epoch = 10;
  scenario.epochs = 72;
  scenario.retained_prefixes_per_epoch = 2;
  scenario.passive_committee_size = 3;
  scenario.seed.fill(0x82);
  scenario.operators = {
      simulation_operator(0x65, availability::AvailabilitySimulationBehavior::HONEST, 10),
      simulation_operator(0x66, availability::AvailabilitySimulationBehavior::JOIN_LATE, 25),
      simulation_operator(0x67, availability::AvailabilitySimulationBehavior::LEAVE_EARLY, 10, 40),
      simulation_operator(0x68, availability::AvailabilitySimulationBehavior::INTERMITTENT, 10),
  };

  const auto result = availability::run_availability_shadow_simulation(scenario);
  ASSERT_EQ(result.epochs.front().tracked_operator_count, 3u);
  ASSERT_EQ(result.epochs[20].tracked_operator_count, 4u);
  ASSERT_EQ(result.epochs.back().tracked_operator_count, 3u);

  bool saw_joined_active = false;
  bool saw_leaver_absent = true;
  for (const auto& summary : result.epochs) {
    for (const auto& op : summary.operators) {
      if (op.operator_pubkey == scenario.operators[1].operator_pubkey &&
          op.status == availability::AvailabilityOperatorStatus::ACTIVE) {
        saw_joined_active = true;
      }
      if (summary.epoch > 40 && op.operator_pubkey == scenario.operators[2].operator_pubkey) saw_leaver_absent = false;
    }
  }
  ASSERT_TRUE(saw_joined_active);
  ASSERT_TRUE(saw_leaver_absent);
}

TEST(test_availability_shadow_simulation_restart_matches_no_restart_baseline) {
  availability::AvailabilitySimulationScenario baseline;
  baseline.start_epoch = 3;
  baseline.epochs = 180;
  baseline.retained_prefixes_per_epoch = 4;
  baseline.passive_committee_size = 4;
  baseline.seed.fill(0x83);
  baseline.operators = {
      simulation_operator(0x69, availability::AvailabilitySimulationBehavior::HONEST),
      simulation_operator(0x6a, availability::AvailabilitySimulationBehavior::INTERMITTENT),
      simulation_operator(0x6b, availability::AvailabilitySimulationBehavior::FLAKY),
      simulation_operator(0x6c, availability::AvailabilitySimulationBehavior::NO_RESPONSE),
      simulation_operator(0x6d, availability::AvailabilitySimulationBehavior::JOIN_LATE, 45),
  };
  baseline.real_committees_by_epoch =
      deterministic_real_committees(baseline.seed, baseline.operators, baseline.start_epoch, baseline.epochs, 4);

  auto restarted = baseline;
  restarted.restart_epochs = {30, 90, 135};

  const auto a = availability::run_availability_shadow_simulation(baseline);
  const auto b = availability::run_availability_shadow_simulation(restarted);
  ASSERT_EQ(a, b);
}

TEST(test_availability_shadow_committee_comparison_metrics_are_consistent) {
  availability::AvailabilitySimulationScenario scenario;
  scenario.start_epoch = 7;
  scenario.epochs = 48;
  scenario.retained_prefixes_per_epoch = 3;
  scenario.passive_committee_size = 3;
  scenario.seed.fill(0x84);
  scenario.operators = {
      simulation_operator(0x6e, availability::AvailabilitySimulationBehavior::HONEST),
      simulation_operator(0x6f, availability::AvailabilitySimulationBehavior::INTERMITTENT),
      simulation_operator(0x70, availability::AvailabilitySimulationBehavior::FLAKY),
      simulation_operator(0x71, availability::AvailabilitySimulationBehavior::JOIN_LATE, 20),
  };
  scenario.real_committees_by_epoch =
      deterministic_real_committees(scenario.seed, scenario.operators, scenario.start_epoch, scenario.epochs, 3);

  const auto result = availability::run_availability_shadow_simulation(scenario);
  ASSERT_EQ(result.epochs.size(), 48u);
  for (const auto& summary : result.epochs) {
    ASSERT_TRUE(summary.committee_comparison.has_value());
    const auto& comparison = *summary.committee_comparison;
    ASSERT_EQ(comparison.overlap_count + comparison.only_real.size(), comparison.real_committee_size);
    ASSERT_EQ(comparison.overlap_count + comparison.only_passive.size(), comparison.passive_committee_size);
    ASSERT_TRUE(comparison.overlap_bps <= 10'000u);
    ASSERT_TRUE(comparison.real_churn_count <= comparison.real_committee_size * 2);
    ASSERT_TRUE(comparison.passive_churn_count <= comparison.passive_committee_size * 2);
  }
}

TEST(test_availability_shadow_simulation_remains_stable_under_bad_operators) {
  availability::AvailabilitySimulationScenario scenario;
  scenario.start_epoch = 1;
  scenario.epochs = 96;
  scenario.retained_prefixes_per_epoch = 2;
  scenario.passive_committee_size = 4;
  scenario.seed.fill(0x85);
  scenario.operators = {
      simulation_operator(0x72, availability::AvailabilitySimulationBehavior::HONEST),
      simulation_operator(0x73, availability::AvailabilitySimulationBehavior::INVALID_RESPONSE),
      simulation_operator(0x74, availability::AvailabilitySimulationBehavior::NO_RESPONSE),
      simulation_operator(0x75, availability::AvailabilitySimulationBehavior::INTERMITTENT),
  };

  const auto result = availability::run_availability_shadow_simulation(scenario);
  bool invalid_ejected = false;
  bool missed_ejected = false;
  for (const auto& summary : result.epochs) {
    for (const auto& op : summary.operators) {
      ASSERT_TRUE(op.seat_budget <= availability::kMaxSeatsPerOperator);
      if (op.operator_pubkey == scenario.operators[1].operator_pubkey &&
          op.status == availability::AvailabilityOperatorStatus::EJECTED) {
        invalid_ejected = true;
      }
      if (op.operator_pubkey == scenario.operators[2].operator_pubkey &&
          op.status == availability::AvailabilityOperatorStatus::EJECTED) {
        missed_ejected = true;
      }
    }
  }
  ASSERT_TRUE(invalid_ejected);
  ASSERT_TRUE(missed_ejected);
}

TEST(test_availability_analytics_report_is_repeatable) {
  Hash32 seed{};
  seed.fill(0x91);
  const auto scenario = analytics_scenario(seed);
  const auto sim_a = availability::run_availability_shadow_simulation(scenario);
  const auto sim_b = availability::run_availability_shadow_simulation(scenario);
  const auto report_a = availability::analyze_availability_shadow_simulation(scenario, sim_a);
  const auto report_b = availability::analyze_availability_shadow_simulation(scenario, sim_b);
  ASSERT_EQ(report_a, report_b);
  ASSERT_EQ(report_a.serialize(), report_b.serialize());
}

TEST(test_availability_analytics_report_matches_restart_equivalence) {
  Hash32 seed{};
  seed.fill(0x92);
  const auto baseline = analytics_scenario(seed);
  auto restarted = baseline;
  restarted.restart_epochs = {25, 55, 80};

  const auto report_a =
      availability::analyze_availability_shadow_simulation(baseline, availability::run_availability_shadow_simulation(baseline));
  const auto report_b =
      availability::analyze_availability_shadow_simulation(restarted, availability::run_availability_shadow_simulation(restarted));
  ASSERT_EQ(report_a, report_b);
}

TEST(test_availability_analytics_concentration_metrics_are_consistent) {
  Hash32 seed{};
  seed.fill(0x93);
  const auto scenario = analytics_scenario(seed);
  const auto report =
      availability::analyze_availability_shadow_simulation(scenario, availability::run_availability_shadow_simulation(scenario));

  ASSERT_EQ(report.epoch_count, report.epochs.size());
  for (const auto& epoch : report.epochs) {
    ASSERT_TRUE(epoch.passive_top1_seat_budget <= epoch.passive_top3_seat_budget);
    ASSERT_TRUE(epoch.passive_top3_seat_budget <= epoch.passive_top5_seat_budget);
    ASSERT_TRUE(epoch.passive_top5_seat_budget <= epoch.passive_total_seat_budget);
    ASSERT_TRUE(epoch.passive_top1_share_bps <= epoch.passive_top3_share_bps);
    ASSERT_TRUE(epoch.passive_top3_share_bps <= epoch.passive_top5_share_bps);
    ASSERT_TRUE(epoch.passive_top5_share_bps <= 10'000u);
    ASSERT_TRUE(epoch.passive_max_seat_budget <= availability::kMaxSeatsPerOperator);
  }
}

TEST(test_availability_analytics_overlap_and_churn_metrics_are_consistent) {
  Hash32 seed{};
  seed.fill(0x94);
  const auto scenario = analytics_scenario(seed);
  const auto report =
      availability::analyze_availability_shadow_simulation(scenario, availability::run_availability_shadow_simulation(scenario));

  std::uint64_t overlap_sum = 0;
  for (const auto& epoch : report.epochs) {
    ASSERT_TRUE(epoch.overlap_count <= std::min(epoch.real_committee_size, epoch.passive_committee_size));
    if (epoch.real_committee_size == 0 && epoch.passive_committee_size == 0) {
      ASSERT_EQ(epoch.overlap_bps, 10'000u);
    } else {
      ASSERT_TRUE(epoch.overlap_bps <= 10'000u);
    }
    ASSERT_TRUE(epoch.real_churn_count <= epoch.real_committee_size * 2);
    ASSERT_TRUE(epoch.passive_churn_count <= epoch.passive_committee_size * 2);
    overlap_sum += epoch.overlap_bps;
  }
  ASSERT_EQ(report.overlap_bps_sum, overlap_sum);
}

TEST(test_availability_analytics_activation_latency_is_accounted_deterministically) {
  availability::AvailabilitySimulationScenario scenario;
  scenario.start_epoch = 1;
  scenario.epochs = 80;
  scenario.retained_prefixes_per_epoch = 2;
  scenario.passive_committee_size = 3;
  scenario.seed.fill(0x95);
  scenario.operators = {
      simulation_operator(0x7c, availability::AvailabilitySimulationBehavior::HONEST),
      simulation_operator(0x7d, availability::AvailabilitySimulationBehavior::JOIN_LATE, 20),
      simulation_operator(0x7e, availability::AvailabilitySimulationBehavior::NO_RESPONSE, 10),
  };

  const auto report =
      availability::analyze_availability_shadow_simulation(scenario, availability::run_availability_shadow_simulation(scenario));
  ASSERT_TRUE(report.activation_latency_count >= 1u);
  ASSERT_TRUE(report.activation_latency_sum >= report.activation_latency_count);
  ASSERT_TRUE(report.activation_latency_max <= scenario.epochs);
  ASSERT_TRUE(report.never_activated_count >= 1u);
}

TEST(test_availability_analytics_probation_and_ejection_events_are_counted_as_transitions) {
  availability::AvailabilitySimulationScenario scenario;
  scenario.start_epoch = 1;
  scenario.epochs = 64;
  scenario.retained_prefixes_per_epoch = 2;
  scenario.passive_committee_size = 3;
  scenario.seed.fill(0x96);
  scenario.operators = {
      simulation_operator(0x7f, availability::AvailabilitySimulationBehavior::HONEST),
      simulation_operator(0x80, availability::AvailabilitySimulationBehavior::INTERMITTENT),
      simulation_operator(0x81, availability::AvailabilitySimulationBehavior::INVALID_RESPONSE),
      simulation_operator(0x82, availability::AvailabilitySimulationBehavior::NO_RESPONSE),
  };

  const auto report =
      availability::analyze_availability_shadow_simulation(scenario, availability::run_availability_shadow_simulation(scenario));
  ASSERT_TRUE(report.total_activation_events >= 1u);
  ASSERT_TRUE(report.total_probation_events >= 1u);
  ASSERT_TRUE(report.total_ejection_events >= 1u);
  ASSERT_TRUE(report.total_ejection_events <= report.epoch_count * scenario.operators.size());
}

TEST(test_availability_analytics_serialization_and_rendering_are_stable) {
  Hash32 seed{};
  seed.fill(0x97);
  const auto scenario = analytics_scenario(seed);
  const auto report =
      availability::analyze_availability_shadow_simulation(scenario, availability::run_availability_shadow_simulation(scenario));
  ASSERT_EQ(report.serialize(), report.serialize());
  ASSERT_EQ(availability::render_availability_analytics_report(report),
            availability::render_availability_analytics_report(report));
}

TEST(test_availability_suite_repeatability_is_stable) {
  Hash32 seed{};
  seed.fill(0xa1);
  const auto suite = analytics_suite(seed);
  const auto a = availability::run_availability_scenario_suite(suite);
  const auto b = availability::run_availability_scenario_suite(suite);
  ASSERT_EQ(a, b);
  ASSERT_EQ(a.serialize(), b.serialize());
}

TEST(test_availability_suite_restart_equivalence_is_stable) {
  Hash32 seed{};
  seed.fill(0xa2);
  auto suite = analytics_suite(seed);
  auto restarted = suite;
  restarted.scenario.restart_epochs = {20, 40, 60};
  const auto a = availability::run_availability_scenario_suite(suite);
  const auto b = availability::run_availability_scenario_suite(restarted);
  ASSERT_EQ(a, b);
}

TEST(test_availability_suite_parameter_ordering_is_lexicographic_and_stable) {
  Hash32 seed{};
  seed.fill(0xa3);
  const auto suite = analytics_suite(seed);
  const auto points = availability::enumerate_availability_parameter_points(suite);
  ASSERT_TRUE(!points.empty());
  for (std::size_t i = 1; i < points.size(); ++i) {
    ASSERT_TRUE(!(points[i] < points[i - 1]));
  }

  const auto report = availability::run_availability_scenario_suite(suite);
  ASSERT_EQ(report.entries.size(), points.size());
  for (std::size_t i = 0; i < points.size(); ++i) {
    ASSERT_EQ(report.entries[i].params, points[i]);
  }
}

TEST(test_availability_suite_comparative_metrics_are_consistent) {
  Hash32 seed{};
  seed.fill(0xa4);
  const auto suite = analytics_suite(seed);
  const auto report = availability::run_availability_scenario_suite(suite);
  ASSERT_EQ(report.entries.size(), report.comparative_entries.size());
  ASSERT_TRUE(!report.comparative_entries.empty());
  for (const auto& entry : report.comparative_entries) {
    ASSERT_TRUE(entry.mean_overlap_bps <= 10'000u);
    ASSERT_TRUE(entry.min_overlap_bps <= entry.mean_overlap_bps || entry.mean_overlap_bps == 0);
    ASSERT_TRUE(entry.max_top1_share_bps <= entry.max_top3_share_bps);
    ASSERT_TRUE(entry.max_top3_share_bps <= 10'000u);
    ASSERT_TRUE(entry.final_top1_share_bps <= entry.final_top3_share_bps);
    ASSERT_TRUE(entry.final_top3_share_bps <= 10'000u);
    ASSERT_TRUE(entry.stability_class == availability::AvailabilitySuiteStabilityClass::STABLE ||
                entry.stability_class == availability::AvailabilitySuiteStabilityClass::BORDERLINE ||
                entry.stability_class == availability::AvailabilitySuiteStabilityClass::UNSTABLE);
  }
}

TEST(test_availability_suite_serialization_and_rendering_are_stable) {
  Hash32 seed{};
  seed.fill(0xa5);
  const auto suite = analytics_suite(seed);
  const auto report = availability::run_availability_scenario_suite(suite);
  ASSERT_EQ(report.serialize(), report.serialize());
  ASSERT_EQ(availability::render_availability_scenario_suite_report(report),
            availability::render_availability_scenario_suite_report(report));
}

TEST(test_availability_suite_parameter_sensitivity_produces_distinct_results) {
  Hash32 seed{};
  seed.fill(0xa6);
  availability::AvailabilityScenarioSuiteConfig suite;
  suite.simulation_seed = seed;
  suite.horizon_epochs = 64;
  suite.scenario = analytics_scenario(seed);
  suite.replication_factors = {2, 3};
  suite.warmup_epochs_values = {14};
  suite.min_warmup_audits_values = {50};
  suite.min_warmup_success_rate_bps_values = {9800};
  suite.score_alpha_bps_values = {9800};
  suite.eligibility_min_score_values = {10};
  suite.seat_unit_values = {10};
  suite.max_seats_per_operator_values = {4};

  const auto report = availability::run_availability_scenario_suite(suite);
  ASSERT_EQ(report.comparative_entries.size(), 2u);
  ASSERT_TRUE(report.comparative_entries[0] != report.comparative_entries[1]);
}

TEST(test_availability_suite_delta_report_is_repeatable) {
  Hash32 seed{};
  seed.fill(0xb1);
  const auto suite = analytics_suite(seed);
  const auto report_a = availability::run_availability_scenario_suite(suite);
  const auto report_b = availability::run_availability_scenario_suite(suite);
  const auto baseline = availability::default_availability_parameter_point().value();
  const auto delta_a = availability::build_availability_suite_delta_report(report_a, baseline);
  const auto delta_b = availability::build_availability_suite_delta_report(report_b, baseline);
  ASSERT_EQ(delta_a, delta_b);
  ASSERT_EQ(delta_a.serialize(), delta_b.serialize());
}

TEST(test_availability_suite_baseline_selection_finds_default_point) {
  Hash32 seed{};
  seed.fill(0xb2);
  const auto suite = analytics_suite(seed);
  const auto report = availability::run_availability_scenario_suite(suite);
  const auto baseline = availability::default_availability_parameter_point().value();
  const auto* entry = availability::find_availability_suite_baseline(report, baseline);
  ASSERT_TRUE(entry != nullptr);
  ASSERT_EQ(entry->params, baseline);
}

TEST(test_availability_suite_delta_signs_are_current_minus_baseline) {
  Hash32 seed{};
  seed.fill(0xb3);
  const auto suite = analytics_suite(seed);
  const auto report = availability::run_availability_scenario_suite(suite);
  const auto baseline = availability::default_availability_parameter_point().value();
  const auto delta = availability::build_availability_suite_delta_report(report, baseline);
  const auto* baseline_entry = availability::find_availability_suite_baseline(report, baseline);
  ASSERT_TRUE(baseline_entry != nullptr);
  bool saw_zero = false;
  for (const auto& entry : delta.entries) {
    const auto* current = availability::find_availability_suite_baseline(report, entry.params);
    ASSERT_TRUE(current != nullptr);
    ASSERT_EQ(entry.mean_overlap_bps_delta,
              static_cast<std::int64_t>(current->mean_overlap_bps) - static_cast<std::int64_t>(baseline_entry->mean_overlap_bps));
    if (entry.params == baseline) {
      saw_zero = true;
      ASSERT_EQ(entry.mean_overlap_bps_delta, 0);
      ASSERT_EQ(entry.max_top1_share_bps_delta, 0);
      ASSERT_EQ(entry.mean_passive_churn_delta, 0);
    }
  }
  ASSERT_TRUE(saw_zero);
}

TEST(test_availability_oat_reports_only_include_single_dimension_differences) {
  Hash32 seed{};
  seed.fill(0xb4);
  const auto suite = analytics_suite(seed);
  const auto baseline = availability::default_availability_parameter_point().value();
  const auto delta = availability::build_availability_suite_delta_report(availability::run_availability_scenario_suite(suite), baseline);
  const auto reports = availability::build_availability_oat_sensitivity_reports(delta);
  ASSERT_EQ(reports.size(), 8u);
  for (const auto& report : reports) {
    std::int64_t previous = std::numeric_limits<std::int64_t>::min();
    for (const auto& entry : report.entries) {
      ASSERT_TRUE(entry.parameter_value >= previous);
      previous = entry.parameter_value;
      availability::AvailabilityParameterDimension differing{};
      std::size_t diffs = 0;
      const auto candidate = [&]() {
        availability::AvailabilityScenarioParameterPoint p = baseline;
        switch (report.dimension) {
          case availability::AvailabilityParameterDimension::ReplicationFactor:
            p.replication_factor = static_cast<std::uint32_t>(entry.parameter_value);
            break;
          case availability::AvailabilityParameterDimension::WarmupEpochs:
            p.warmup_epochs = static_cast<std::uint32_t>(entry.parameter_value);
            break;
          case availability::AvailabilityParameterDimension::MinWarmupAudits:
            p.min_warmup_audits = static_cast<std::uint32_t>(entry.parameter_value);
            break;
          case availability::AvailabilityParameterDimension::MinWarmupSuccessRateBps:
            p.min_warmup_success_rate_bps = static_cast<std::uint32_t>(entry.parameter_value);
            break;
          case availability::AvailabilityParameterDimension::ScoreAlphaBps:
            p.score_alpha_bps = static_cast<std::uint32_t>(entry.parameter_value);
            break;
          case availability::AvailabilityParameterDimension::EligibilityMinScore:
            p.eligibility_min_score = entry.parameter_value;
            break;
          case availability::AvailabilityParameterDimension::SeatUnit:
            p.seat_unit = static_cast<std::uint32_t>(entry.parameter_value);
            break;
          case availability::AvailabilityParameterDimension::MaxSeatsPerOperator:
            p.max_seats_per_operator = static_cast<std::uint32_t>(entry.parameter_value);
            break;
        }
        return p;
      }();
      diffs = 0;
      if (candidate.replication_factor != baseline.replication_factor) {
        ++diffs;
        differing = availability::AvailabilityParameterDimension::ReplicationFactor;
      }
      if (candidate.warmup_epochs != baseline.warmup_epochs) {
        ++diffs;
        differing = availability::AvailabilityParameterDimension::WarmupEpochs;
      }
      if (candidate.min_warmup_audits != baseline.min_warmup_audits) {
        ++diffs;
        differing = availability::AvailabilityParameterDimension::MinWarmupAudits;
      }
      if (candidate.min_warmup_success_rate_bps != baseline.min_warmup_success_rate_bps) {
        ++diffs;
        differing = availability::AvailabilityParameterDimension::MinWarmupSuccessRateBps;
      }
      if (candidate.score_alpha_bps != baseline.score_alpha_bps) {
        ++diffs;
        differing = availability::AvailabilityParameterDimension::ScoreAlphaBps;
      }
      if (candidate.eligibility_min_score != baseline.eligibility_min_score) {
        ++diffs;
        differing = availability::AvailabilityParameterDimension::EligibilityMinScore;
      }
      if (candidate.seat_unit != baseline.seat_unit) {
        ++diffs;
        differing = availability::AvailabilityParameterDimension::SeatUnit;
      }
      if (candidate.max_seats_per_operator != baseline.max_seats_per_operator) {
        ++diffs;
        differing = availability::AvailabilityParameterDimension::MaxSeatsPerOperator;
      }
      ASSERT_EQ(diffs, 1u);
      ASSERT_EQ(differing, report.dimension);
    }
  }
}

TEST(test_availability_dominant_parameter_effects_are_rankable_deterministically) {
  Hash32 seed{};
  seed.fill(0xb5);
  const auto suite = analytics_suite(seed);
  const auto baseline = availability::default_availability_parameter_point().value();
  const auto delta = availability::build_availability_suite_delta_report(availability::run_availability_scenario_suite(suite), baseline);
  auto reports = availability::build_availability_oat_sensitivity_reports(delta);
  auto effects = availability::build_availability_dominant_parameter_effects(reports);
  ASSERT_EQ(effects.size(), reports.size());
  std::sort(effects.begin(), effects.end(), [](const auto& a, const auto& b) {
    if (a.max_abs_max_top1_share_bps_delta != b.max_abs_max_top1_share_bps_delta) {
      return a.max_abs_max_top1_share_bps_delta > b.max_abs_max_top1_share_bps_delta;
    }
    return a.dimension < b.dimension;
  });
  for (std::size_t i = 1; i < effects.size(); ++i) {
    ASSERT_TRUE(effects[i - 1].max_abs_max_top1_share_bps_delta >= effects[i].max_abs_max_top1_share_bps_delta);
  }
}

TEST(test_availability_dimension_sensitivity_summary_matches_threshold_rule) {
  Hash32 seed{};
  seed.fill(0xb6);
  const auto suite = analytics_suite(seed);
  const auto baseline = availability::default_availability_parameter_point().value();
  const auto delta = availability::build_availability_suite_delta_report(availability::run_availability_scenario_suite(suite), baseline);
  const auto summaries =
      availability::build_availability_dimension_sensitivity_summaries(availability::build_availability_oat_sensitivity_reports(delta));
  ASSERT_EQ(summaries.size(), 8u);
  bool saw_sensitive = false;
  for (const auto& summary : summaries) {
    const auto expected = (summary.max_abs_mean_overlap_bps_delta <= 1'000 &&
                           summary.max_abs_max_top1_share_bps_delta <= 1'000 &&
                           summary.max_abs_mean_passive_churn_delta <= 2 &&
                           summary.max_abs_activation_latency_sum_delta <= 10)
                              ? availability::AvailabilitySensitivityClass::Robust
                              : availability::AvailabilitySensitivityClass::Sensitive;
    ASSERT_EQ(summary.sensitivity_class, expected);
    if (summary.sensitivity_class == availability::AvailabilitySensitivityClass::Sensitive) saw_sensitive = true;
  }
  ASSERT_TRUE(saw_sensitive);
}

TEST(test_availability_suite_delta_and_oat_reports_are_stable_across_restart_equivalence) {
  Hash32 seed{};
  seed.fill(0xb7);
  auto suite = analytics_suite(seed);
  auto restarted = suite;
  restarted.scenario.restart_epochs = {20, 40, 60};
  const auto baseline = availability::default_availability_parameter_point().value();

  const auto report_a = availability::run_availability_scenario_suite(suite);
  const auto report_b = availability::run_availability_scenario_suite(restarted);
  const auto delta_a = availability::build_availability_suite_delta_report(report_a, baseline);
  const auto delta_b = availability::build_availability_suite_delta_report(report_b, baseline);
  ASSERT_EQ(delta_a, delta_b);
  ASSERT_EQ(availability::build_availability_oat_sensitivity_reports(delta_a),
            availability::build_availability_oat_sensitivity_reports(delta_b));
}

TEST(test_availability_suite_delta_and_oat_rendering_are_stable) {
  Hash32 seed{};
  seed.fill(0xb8);
  const auto suite = analytics_suite(seed);
  const auto baseline = availability::default_availability_parameter_point().value();
  const auto delta =
      availability::build_availability_suite_delta_report(availability::run_availability_scenario_suite(suite), baseline);
  const auto oats = availability::build_availability_oat_sensitivity_reports(delta);
  ASSERT_EQ(delta.serialize(), delta.serialize());
  ASSERT_EQ(availability::render_availability_suite_delta_report(delta),
            availability::render_availability_suite_delta_report(delta));
  ASSERT_TRUE(!oats.empty());
  ASSERT_EQ(oats.front().serialize(), oats.front().serialize());
  ASSERT_EQ(availability::render_availability_oat_sensitivity_report(oats.front()),
            availability::render_availability_oat_sensitivity_report(oats.front()));
}
