#include "test_framework.hpp"

#ifndef _WIN32
#include <unistd.h>
#else
#include <process.h>
#define getpid _getpid
#endif

#include <atomic>
#include <chrono>
#include <filesystem>

#include "codec/bytes.hpp"
#include "consensus/monetary.hpp"
#include "codec/varint.hpp"
#include "storage/db.hpp"
#include "utxo/tx.hpp"

using namespace finalis;

namespace {

std::string unique_test_base(const std::string& prefix) {
  static std::atomic<std::uint64_t> seq{0};
  const auto pid = static_cast<std::uint64_t>(::getpid());
  const auto now = std::chrono::steady_clock::now().time_since_epoch().count();
  return prefix + "_" + std::to_string(pid) + "_" + std::to_string(now) + "_" + std::to_string(seq.fetch_add(1, std::memory_order_relaxed));
}

}  // namespace

TEST(test_varint_roundtrip_and_minimality) {
  const std::vector<std::uint64_t> values = {0, 1, 2, 127, 128, 255, 300, 16384, (1ULL << 32), UINT64_MAX};
  for (auto v : values) {
    auto enc = codec::encode_uleb128(v);
    ASSERT_TRUE(codec::is_minimal_uleb128_encoding(enc));
    size_t off = 0;
    auto dec = codec::decode_uleb128(enc, off, true);
    ASSERT_TRUE(dec.has_value());
    ASSERT_EQ(dec.value(), v);
    ASSERT_EQ(off, enc.size());
  }

  Bytes non_minimal = {0x80, 0x00};
  size_t off = 0;
  ASSERT_TRUE(!codec::decode_uleb128(non_minimal, off, true).has_value());
}

TEST(test_tx_and_blockheader_roundtrip) {
  Tx tx;
  tx.version = 1;
  tx.inputs.push_back(TxIn{zero_hash(), 7, Bytes{0x40}, 0xFFFFFFFF});
  tx.outputs.push_back(TxOut{123, Bytes{0x76, 0xA9, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0xAC}});

  auto ser = tx.serialize();
  auto parsed = Tx::parse(ser);
  ASSERT_TRUE(parsed.has_value());
  ASSERT_EQ(parsed->serialize(), ser);

  BlockHeader h;
  h.prev_finalized_hash = tx.txid();
  h.prev_finality_cert_hash.fill(0xAB);
  h.height = 5;
  h.timestamp = 123456;
  h.merkle_root = tx.txid();
  h.leader_pubkey.fill(9);
  h.leader_signature.fill(7);
  h.round = 3;

  auto hser = h.serialize();
  auto hparsed = BlockHeader::parse(hser);
  ASSERT_TRUE(hparsed.has_value());
  ASSERT_EQ(hparsed->serialize(), hser);
  ASSERT_EQ(hparsed->prev_finality_cert_hash, h.prev_finality_cert_hash);
}

TEST(test_blockheader_canonical_reserialization_always_includes_prev_finality_cert_hash) {
  BlockHeader h;
  h.prev_finalized_hash.fill(0x11);
  h.prev_finality_cert_hash = zero_hash();
  h.height = 7;
  h.timestamp = 123;
  h.merkle_root.fill(0x22);
  h.leader_pubkey.fill(0x33);
  h.round = 4;
  h.leader_signature.fill(0x44);

  const auto canonical = h.serialize();
  ASSERT_EQ(canonical.size(), static_cast<std::size_t>(32 + 32 + 8 + 8 + 32 + 32 + 4 + 64));
  auto parsed = BlockHeader::parse(canonical);
  ASSERT_TRUE(parsed.has_value());
  ASSERT_EQ(parsed->serialize(), canonical);

  codec::ByteWriter legacy;
  legacy.bytes_fixed(h.prev_finalized_hash);
  legacy.u64le(h.height);
  legacy.u64le(h.timestamp);
  legacy.bytes_fixed(h.merkle_root);
  legacy.bytes_fixed(h.leader_pubkey);
  legacy.u32le(h.round);
  legacy.bytes_fixed(h.leader_signature);
  const auto legacy_bytes = legacy.take();
  ASSERT_EQ(legacy_bytes.size(), static_cast<std::size_t>(32 + 8 + 8 + 32 + 32 + 4 + 64));

  auto parsed_legacy = BlockHeader::parse(legacy_bytes);
  ASSERT_TRUE(parsed_legacy.has_value());
  ASSERT_EQ(parsed_legacy->prev_finality_cert_hash, zero_hash());
  const auto reserialized = parsed_legacy->serialize();
  ASSERT_EQ(reserialized.size(), canonical.size());
  ASSERT_TRUE(reserialized != legacy_bytes);
}

TEST(test_slashing_record_db_roundtrip) {
  const std::string path = unique_test_base("/tmp/finalis_test_slashing_record_db");
  std::filesystem::remove_all(path);

  storage::DB db;
  ASSERT_TRUE(db.open(path));

  storage::SlashingRecord rec;
  rec.record_id.fill(0x11);
  rec.kind = storage::SlashingRecordKind::PROPOSER_EQUIVOCATION;
  rec.validator_pubkey.fill(0x22);
  rec.height = 55;
  rec.round = 3;
  rec.observed_height = 54;
  rec.object_a.fill(0x33);
  rec.object_b.fill(0x44);
  rec.txid.fill(0x55);

  ASSERT_TRUE(db.put_slashing_record(rec));
  const auto records = db.load_slashing_records();
  auto it = records.find(rec.record_id);
  ASSERT_TRUE(it != records.end());
  ASSERT_EQ(it->second.kind, rec.kind);
  ASSERT_EQ(it->second.validator_pubkey, rec.validator_pubkey);
  ASSERT_EQ(it->second.height, rec.height);
  ASSERT_EQ(it->second.round, rec.round);
  ASSERT_EQ(it->second.observed_height, rec.observed_height);
  ASSERT_EQ(it->second.object_a, rec.object_a);
  ASSERT_EQ(it->second.object_b, rec.object_b);
  ASSERT_EQ(it->second.txid, rec.txid);
}

TEST(test_finalized_committee_checkpoint_db_roundtrip) {
  const std::string path = unique_test_base("/tmp/finalis_test_finalized_committee_checkpoint_db");
  std::filesystem::remove_all(path);

  storage::DB db;
  ASSERT_TRUE(db.open(path));

  storage::FinalizedCommitteeCheckpoint snapshot;
  snapshot.epoch_start_height = 33;
  snapshot.epoch_seed.fill(0x44);
  snapshot.ticket_difficulty_bits = 9;
  snapshot.derivation_mode = storage::FinalizedCommitteeDerivationMode::FALLBACK;
  snapshot.fallback_reason = storage::FinalizedCommitteeFallbackReason::HYSTERESIS_RECOVERY_PENDING;
  snapshot.availability_eligible_operator_count = 2;
  snapshot.availability_min_eligible_operators = 3;
  snapshot.adaptive_target_committee_size = 24;
  snapshot.adaptive_min_eligible = 27;
  snapshot.adaptive_min_bond = 150ULL * consensus::BASE_UNITS_PER_COIN;
  snapshot.qualified_depth = 31;
  snapshot.target_expand_streak = 4;
  snapshot.target_contract_streak = 0;
  PubKey32 a{};
  PubKey32 b{};
  PubKey32 oa{};
  PubKey32 ob{};
  a.fill(0x11);
  b.fill(0x22);
  oa.fill(0x55);
  ob.fill(0x66);
  snapshot.ordered_members = {a, b};
  snapshot.ordered_operator_ids = {oa, ob};
  snapshot.ordered_base_weights = {100, 200};
  snapshot.ordered_ticket_bonus_bps = {700, 900};
  snapshot.ordered_final_weights = {1070000, 2180000};
  Hash32 ha{};
  Hash32 hb{};
  ha.fill(0x33);
  hb.fill(0x44);
  snapshot.ordered_ticket_hashes = {ha, hb};
  snapshot.ordered_ticket_nonces = {7, 9};

  ASSERT_TRUE(db.put_finalized_committee_checkpoint(snapshot));
  const auto loaded = db.get_finalized_committee_checkpoint(snapshot.epoch_start_height);
  ASSERT_TRUE(loaded.has_value());
  ASSERT_EQ(loaded->epoch_start_height, snapshot.epoch_start_height);
  ASSERT_EQ(loaded->epoch_seed, snapshot.epoch_seed);
  ASSERT_EQ(loaded->ticket_difficulty_bits, snapshot.ticket_difficulty_bits);
  ASSERT_EQ(loaded->derivation_mode, snapshot.derivation_mode);
  ASSERT_EQ(loaded->fallback_reason, snapshot.fallback_reason);
  ASSERT_EQ(loaded->availability_eligible_operator_count, snapshot.availability_eligible_operator_count);
  ASSERT_EQ(loaded->availability_min_eligible_operators, snapshot.availability_min_eligible_operators);
  ASSERT_EQ(loaded->adaptive_target_committee_size, snapshot.adaptive_target_committee_size);
  ASSERT_EQ(loaded->adaptive_min_eligible, snapshot.adaptive_min_eligible);
  ASSERT_EQ(loaded->adaptive_min_bond, snapshot.adaptive_min_bond);
  ASSERT_EQ(loaded->qualified_depth, snapshot.qualified_depth);
  ASSERT_EQ(loaded->target_expand_streak, snapshot.target_expand_streak);
  ASSERT_EQ(loaded->target_contract_streak, snapshot.target_contract_streak);
  ASSERT_EQ(loaded->ordered_members, snapshot.ordered_members);
  ASSERT_EQ(loaded->ordered_operator_ids, snapshot.ordered_operator_ids);
  ASSERT_EQ(loaded->ordered_base_weights, snapshot.ordered_base_weights);
  ASSERT_EQ(loaded->ordered_ticket_bonus_bps, snapshot.ordered_ticket_bonus_bps);
  ASSERT_EQ(loaded->ordered_final_weights, snapshot.ordered_final_weights);
  ASSERT_EQ(loaded->ordered_ticket_hashes, snapshot.ordered_ticket_hashes);
  ASSERT_EQ(loaded->ordered_ticket_nonces, snapshot.ordered_ticket_nonces);

  const auto all = db.load_finalized_committee_checkpoints();
  auto it = all.find(snapshot.epoch_start_height);
  ASSERT_TRUE(it != all.end());
  ASSERT_EQ(it->second.ordered_members, snapshot.ordered_members);
  ASSERT_EQ(it->second.ordered_operator_ids, snapshot.ordered_operator_ids);
  ASSERT_EQ(it->second.ordered_base_weights, snapshot.ordered_base_weights);
  ASSERT_EQ(it->second.ordered_ticket_bonus_bps, snapshot.ordered_ticket_bonus_bps);
  ASSERT_EQ(it->second.ordered_final_weights, snapshot.ordered_final_weights);
  ASSERT_EQ(it->second.ordered_ticket_hashes, snapshot.ordered_ticket_hashes);
  ASSERT_EQ(it->second.ordered_ticket_nonces, snapshot.ordered_ticket_nonces);
}

TEST(test_node_runtime_status_snapshot_roundtrip_preserves_availability_fallback_observability) {
  const std::string path = unique_test_base("/tmp/finalis_test_node_runtime_status_snapshot_db");
  std::filesystem::remove_all(path);

  storage::DB db;
  ASSERT_TRUE(db.open(path));

  storage::NodeRuntimeStatusSnapshot snapshot;
  snapshot.chain_id_ok = true;
  snapshot.db_open = true;
  snapshot.local_finalized_height = 12;
  snapshot.availability_epoch = 5;
  snapshot.availability_retained_prefix_count = 7;
  snapshot.availability_tracked_operator_count = 3;
  snapshot.availability_eligible_operator_count = 2;
  snapshot.availability_below_min_eligible = false;
  snapshot.adaptive_target_committee_size = 24;
  snapshot.adaptive_min_eligible = 27;
  snapshot.adaptive_min_bond = 150ULL * consensus::BASE_UNITS_PER_COIN;
  snapshot.qualified_depth = 31;
  snapshot.adaptive_slack = 4;
  snapshot.target_expand_streak = 4;
  snapshot.target_contract_streak = 0;
  snapshot.availability_checkpoint_derivation_mode =
      static_cast<std::uint8_t>(storage::FinalizedCommitteeDerivationMode::FALLBACK);
  snapshot.availability_checkpoint_fallback_reason =
      static_cast<std::uint8_t>(storage::FinalizedCommitteeFallbackReason::HYSTERESIS_RECOVERY_PENDING);
  snapshot.availability_fallback_sticky = true;
  snapshot.adaptive_fallback_rate_bps = 2500;
  snapshot.adaptive_sticky_fallback_rate_bps = 1250;
  snapshot.adaptive_fallback_window_epochs = 8;
  snapshot.adaptive_near_threshold_operation = true;
  snapshot.adaptive_prolonged_expand_buildup = true;
  snapshot.adaptive_prolonged_contract_buildup = false;
  snapshot.adaptive_repeated_sticky_fallback = true;
  snapshot.adaptive_depth_collapse_after_bond_increase = false;
  snapshot.availability_state_rebuild_triggered = true;
  snapshot.availability_state_rebuild_reason = "invalid_persisted_state";

  ASSERT_TRUE(db.put_node_runtime_status_snapshot(snapshot));
  const auto loaded = db.get_node_runtime_status_snapshot();
  ASSERT_TRUE(loaded.has_value());
  ASSERT_EQ(loaded->adaptive_target_committee_size, snapshot.adaptive_target_committee_size);
  ASSERT_EQ(loaded->adaptive_min_eligible, snapshot.adaptive_min_eligible);
  ASSERT_EQ(loaded->adaptive_min_bond, snapshot.adaptive_min_bond);
  ASSERT_EQ(loaded->qualified_depth, snapshot.qualified_depth);
  ASSERT_EQ(loaded->adaptive_slack, snapshot.adaptive_slack);
  ASSERT_EQ(loaded->target_expand_streak, snapshot.target_expand_streak);
  ASSERT_EQ(loaded->target_contract_streak, snapshot.target_contract_streak);
  ASSERT_EQ(loaded->availability_checkpoint_derivation_mode, snapshot.availability_checkpoint_derivation_mode);
  ASSERT_EQ(loaded->availability_checkpoint_fallback_reason, snapshot.availability_checkpoint_fallback_reason);
  ASSERT_EQ(loaded->availability_fallback_sticky, snapshot.availability_fallback_sticky);
  ASSERT_EQ(loaded->adaptive_fallback_rate_bps, snapshot.adaptive_fallback_rate_bps);
  ASSERT_EQ(loaded->adaptive_sticky_fallback_rate_bps, snapshot.adaptive_sticky_fallback_rate_bps);
  ASSERT_EQ(loaded->adaptive_fallback_window_epochs, snapshot.adaptive_fallback_window_epochs);
  ASSERT_EQ(loaded->adaptive_near_threshold_operation, snapshot.adaptive_near_threshold_operation);
  ASSERT_EQ(loaded->adaptive_prolonged_expand_buildup, snapshot.adaptive_prolonged_expand_buildup);
  ASSERT_EQ(loaded->adaptive_prolonged_contract_buildup, snapshot.adaptive_prolonged_contract_buildup);
  ASSERT_EQ(loaded->adaptive_repeated_sticky_fallback, snapshot.adaptive_repeated_sticky_fallback);
  ASSERT_EQ(loaded->adaptive_depth_collapse_after_bond_increase, snapshot.adaptive_depth_collapse_after_bond_increase);
  ASSERT_EQ(loaded->availability_state_rebuild_triggered, snapshot.availability_state_rebuild_triggered);
  ASSERT_EQ(loaded->availability_state_rebuild_reason, snapshot.availability_state_rebuild_reason);
}

TEST(test_adaptive_epoch_telemetry_db_roundtrip_and_summary) {
  const std::string path = unique_test_base("/tmp/finalis_test_adaptive_epoch_telemetry_db");
  std::filesystem::remove_all(path);

  storage::DB db;
  ASSERT_TRUE(db.open(path));

  storage::AdaptiveEpochTelemetry first;
  first.epoch_start_height = 100;
  first.derivation_height = 99;
  first.qualified_depth = 28;
  first.adaptive_target_committee_size = 16;
  first.adaptive_min_eligible = 19;
  first.adaptive_min_bond = 150ULL * consensus::BASE_UNITS_PER_COIN;
  first.slack = 9;
  first.target_expand_streak = 3;
  first.derivation_mode = storage::FinalizedCommitteeDerivationMode::FALLBACK;
  first.fallback_reason = storage::FinalizedCommitteeFallbackReason::HYSTERESIS_RECOVERY_PENDING;
  first.fallback_sticky = true;
  first.committee_size_selected = 16;
  first.eligible_operator_count = 19;
  ASSERT_TRUE(db.put_adaptive_epoch_telemetry(first));

  storage::AdaptiveEpochTelemetry second = first;
  second.epoch_start_height = 124;
  second.derivation_height = 123;
  second.qualified_depth = 24;
  second.adaptive_min_bond = 200ULL * consensus::BASE_UNITS_PER_COIN;
  second.slack = 5;
  second.fallback_sticky = false;
  second.fallback_reason = storage::FinalizedCommitteeFallbackReason::INSUFFICIENT_ELIGIBLE_OPERATORS;
  ASSERT_TRUE(db.put_adaptive_epoch_telemetry(second));

  const auto loaded = db.get_adaptive_epoch_telemetry(124);
  ASSERT_TRUE(loaded.has_value());
  ASSERT_EQ(loaded->adaptive_min_bond, second.adaptive_min_bond);
  ASSERT_EQ(loaded->slack, second.slack);
  ASSERT_EQ(loaded->fallback_reason, second.fallback_reason);

  const auto all = db.load_adaptive_epoch_telemetry();
  ASSERT_EQ(all.size(), 2u);
  const auto summary = storage::summarize_adaptive_epoch_telemetry(all, 16);
  ASSERT_EQ(summary.sample_count, 2u);
  ASSERT_EQ(summary.fallback_epochs, 2u);
  ASSERT_EQ(summary.sticky_fallback_epochs, 1u);
  ASSERT_TRUE(summary.prolonged_expand_buildup);
  ASSERT_TRUE(summary.depth_collapse_after_bond_increase);
}

TEST(test_finalized_committee_checkpoint_rejects_unknown_enum_values) {
  const std::string path = unique_test_base("/tmp/finalis_test_finalized_committee_checkpoint_bad_enum_db");
  std::filesystem::remove_all(path);

  storage::DB db;
  ASSERT_TRUE(db.open(path));

  storage::FinalizedCommitteeCheckpoint snapshot;
  snapshot.epoch_start_height = 65;
  snapshot.derivation_mode = storage::FinalizedCommitteeDerivationMode::NORMAL;
  snapshot.fallback_reason = storage::FinalizedCommitteeFallbackReason::NONE;
  ASSERT_TRUE(db.put_finalized_committee_checkpoint(snapshot));

  auto rows = db.scan_prefix("CE:");
  ASSERT_EQ(rows.size(), 1u);
  auto raw = rows.begin()->second;
  constexpr std::size_t kCheckpointTrailerBytes =
      1 + 1 + (6 * sizeof(std::uint64_t)) + (2 * sizeof(std::uint32_t));
  constexpr std::size_t kFallbackReasonOffsetFromEnd =
      (6 * sizeof(std::uint64_t)) + (2 * sizeof(std::uint32_t)) + 1;
  ASSERT_TRUE(raw.size() >= kCheckpointTrailerBytes);
  raw[raw.size() - kFallbackReasonOffsetFromEnd] = 0xFF;
  ASSERT_TRUE(db.put(rows.begin()->first, raw));
  ASSERT_TRUE(!db.get_finalized_committee_checkpoint(snapshot.epoch_start_height).has_value());
}

TEST(test_epoch_reward_settlement_db_roundtrip) {
  const std::string path = unique_test_base("/tmp/finalis_test_epoch_reward_settlement_db");
  std::filesystem::remove_all(path);

  storage::DB db;
  ASSERT_TRUE(db.open(path));

  storage::EpochRewardSettlementState state;
  state.epoch_start_height = 33;
  state.total_reward_units = 123456;
  state.reserve_accrual_units = 13717;
  state.settled = true;
  PubKey32 a{};
  PubKey32 b{};
  a.fill(0x11);
  b.fill(0x22);
  state.reward_score_units[a] = 7;
  state.reward_score_units[b] = 11;
  state.expected_participation_units[a] = 12;
  state.expected_participation_units[b] = 8;
  state.observed_participation_units[a] = 9;
  state.observed_participation_units[b] = 8;

  ASSERT_TRUE(db.put_epoch_reward_settlement(state));
  const auto loaded = db.get_epoch_reward_settlement(state.epoch_start_height);
  ASSERT_TRUE(loaded.has_value());
  ASSERT_EQ(loaded->epoch_start_height, state.epoch_start_height);
  ASSERT_EQ(loaded->total_reward_units, state.total_reward_units);
  ASSERT_EQ(loaded->reserve_accrual_units, state.reserve_accrual_units);
  ASSERT_EQ(loaded->settled, state.settled);
  ASSERT_EQ(loaded->reward_score_units, state.reward_score_units);
  ASSERT_EQ(loaded->expected_participation_units, state.expected_participation_units);
  ASSERT_EQ(loaded->observed_participation_units, state.observed_participation_units);

  const auto all = db.load_epoch_reward_settlements();
  auto it = all.find(state.epoch_start_height);
  ASSERT_TRUE(it != all.end());
  ASSERT_EQ(it->second.reward_score_units, state.reward_score_units);
  ASSERT_EQ(it->second.reserve_accrual_units, state.reserve_accrual_units);
  ASSERT_EQ(it->second.expected_participation_units, state.expected_participation_units);
  ASSERT_EQ(it->second.observed_participation_units, state.observed_participation_units);
}

TEST(test_validator_db_roundtrip_preserves_operator_id) {
  const std::string path = unique_test_base("/tmp/finalis_test_validator_db_operator");
  std::filesystem::remove_all(path);

  storage::DB db;
  ASSERT_TRUE(db.open(path));

  PubKey32 pub{};
  PubKey32 operator_id{};
  pub.fill(0x33);
  operator_id.fill(0x55);
  consensus::ValidatorInfo info;
  info.status = consensus::ValidatorStatus::ACTIVE;
  info.joined_height = 12;
  info.bonded_amount = 7 * consensus::BASE_UNITS_PER_COIN;
  info.operator_id = operator_id;
  info.has_bond = true;
  Hash32 bond_txid{};
  bond_txid.fill(0x01);
  info.bond_outpoint = OutPoint{bond_txid, 2};
  ASSERT_TRUE(db.put_validator(pub, info));

  const auto validators = db.load_validators();
  auto it = validators.find(pub);
  ASSERT_TRUE(it != validators.end());
  ASSERT_EQ(it->second.operator_id, operator_id);
  ASSERT_EQ(it->second.bonded_amount, info.bonded_amount);
}

TEST(test_frontier_transition_and_ingress_db_roundtrip) {
  FrontierDecision decision;
  decision.record_id.fill(0x11);
  decision.accepted = false;
  decision.reject_reason = FrontierRejectReason::CONFLICT_DOMAIN_USED;
  const auto decision_ser = decision.serialize();
  auto decision_parsed = FrontierDecision::parse(decision_ser);
  ASSERT_TRUE(decision_parsed.has_value());
  ASSERT_EQ(decision_parsed->serialize(), decision_ser);

  FrontierTransition transition;
  transition.prev_finalized_hash.fill(0x12);
  transition.prev_finality_link_hash.fill(0x13);
  transition.height = 5;
  transition.round = 2;
  transition.leader_pubkey.fill(0x14);
  transition.prev_vector.lane_max_seq[0] = 7;
  transition.next_vector.lane_max_seq[0] = 9;
  transition.ingress_commitment.fill(0x15);
  transition.prev_frontier = 7;
  transition.next_frontier = 9;
  transition.prev_state_root.fill(0x22);
  transition.next_state_root.fill(0x33);
  transition.ordered_slice_commitment.fill(0x44);
  transition.decisions_commitment.fill(0x55);
  transition.quorum_threshold = 1;
  transition.observed_signers.push_back(transition.leader_pubkey);
  transition.settlement.settlement_epoch_start = 1;
  transition.settlement.outputs.push_back({transition.leader_pubkey, 123});
  transition.settlement.total = 123;
  transition.settlement.current_fees = 23;
  transition.settlement.settled_epoch_fees = 17;
  transition.settlement.settled_epoch_rewards = 100;
  transition.settlement.reserve_subsidy_units = 6;
  transition.settlement_commitment = transition.settlement.commitment();
  const auto transition_ser = transition.serialize();
  auto transition_parsed = FrontierTransition::parse(transition_ser);
  ASSERT_TRUE(transition_parsed.has_value());
  ASSERT_EQ(transition_parsed->serialize(), transition_ser);
  const auto transition_id = transition.transition_id();

  const std::string path = unique_test_base("/tmp/finalis_test_ingress_db");
  std::filesystem::remove_all(path);
  storage::DB db;
  ASSERT_TRUE(db.open(path));

  Bytes record_a{0x01, 0x02, 0x03};
  Bytes record_b{0x04, 0x05};
  ASSERT_TRUE(db.put_ingress_record(8, record_a));
  ASSERT_TRUE(db.put_ingress_record(9, record_b));
  ASSERT_TRUE(db.put_ingress_record(8, record_a));
  ASSERT_TRUE(!db.put_ingress_record(8, record_b));

  auto loaded_a = db.get_ingress_record(8);
  auto loaded_b = db.get_ingress_record(9);
  ASSERT_TRUE(loaded_a.has_value());
  ASSERT_TRUE(loaded_b.has_value());
  ASSERT_EQ(*loaded_a, record_a);
  ASSERT_EQ(*loaded_b, record_b);

  const auto slice = db.load_ingress_slice(7, 9);
  ASSERT_EQ(slice.size(), 2u);
  ASSERT_EQ(slice[0], record_a);
  ASSERT_EQ(slice[1], record_b);
  ASSERT_TRUE(db.ingress_slice_matches(7, {record_a, record_b}));
  ASSERT_TRUE(!db.ingress_slice_matches(7, {record_b, record_a}));

  ASSERT_TRUE(db.set_finalized_ingress_tip(9));
  ASSERT_TRUE(!db.set_finalized_ingress_tip(8));
  const auto tip = db.get_finalized_ingress_tip();
  ASSERT_TRUE(tip.has_value());
  ASSERT_EQ(*tip, 9u);

  ASSERT_TRUE(db.put_frontier_transition(transition_id, transition_ser));
  ASSERT_TRUE(db.put_frontier_transition(transition_id, transition_ser));
  Bytes conflicting_transition = transition_ser;
  conflicting_transition[0] ^= 0x01;
  ASSERT_TRUE(!db.put_frontier_transition(transition_id, conflicting_transition));
  const auto loaded_transition = db.get_frontier_transition(transition_id);
  ASSERT_TRUE(loaded_transition.has_value());
  ASSERT_EQ(*loaded_transition, transition_ser);

  ASSERT_TRUE(db.map_height_to_frontier_transition(1, transition_id));
  ASSERT_TRUE(db.map_height_to_frontier_transition(1, transition_id));
  Hash32 other_id = transition_id;
  other_id[0] ^= 0x01;
  ASSERT_TRUE(!db.map_height_to_frontier_transition(1, other_id));
  const auto mapped_id = db.get_frontier_transition_by_height(1);
  ASSERT_TRUE(mapped_id.has_value());
  ASSERT_EQ(*mapped_id, transition_id);

  ASSERT_TRUE(db.set_finalized_frontier_height(1));
  ASSERT_TRUE(!db.set_finalized_frontier_height(0));
  const auto frontier_height = db.get_finalized_frontier_height();
  ASSERT_TRUE(frontier_height.has_value());
  ASSERT_EQ(*frontier_height, 1u);
}

void register_codec_tests() {}
