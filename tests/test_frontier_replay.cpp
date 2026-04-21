#include "test_framework.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <filesystem>
#include <set>
#include <stdexcept>

#include "common/address.hpp"
#include "codec/bytes.hpp"
#include "consensus/canonical_derivation.hpp"
#include "consensus/frontier_execution.hpp"
#include "consensus/ingress.hpp"
#include "consensus/randomness.hpp"
#include "crypto/ed25519.hpp"
#include "crypto/hash.hpp"
#include "storage/db.hpp"
#include "utxo/validate.hpp"
#include "utxo/signing.hpp"

using namespace finalis;

namespace {

std::string unique_test_base(const std::string& prefix) {
  static std::atomic<std::uint64_t> seq{0};
  return prefix + "_" + std::to_string(seq.fetch_add(1, std::memory_order_relaxed));
}

crypto::KeyPair key_from_byte(std::uint8_t base) {
  std::array<std::uint8_t, 32> seed{};
  seed.fill(base);
  auto kp = crypto::keypair_from_seed32(seed);
  if (!kp.has_value()) throw std::runtime_error("key derivation failed");
  return *kp;
}

TxOut p2pkh_out_for_pub(const PubKey32& pub, std::uint64_t value) {
  const auto pkh = crypto::h160(Bytes(pub.begin(), pub.end()));
  return TxOut{value, address::p2pkh_script_pubkey(pkh)};
}

Bytes raw_signed_spend(const OutPoint& op, const TxOut& prev, const crypto::KeyPair& from, const PubKey32& to_pub,
                       std::uint64_t value_out) {
  const auto to_pkh = crypto::h160(Bytes(to_pub.begin(), to_pub.end()));
  std::vector<TxOut> outputs{TxOut{value_out, address::p2pkh_script_pubkey(to_pkh)}};
  auto tx = build_signed_p2pkh_tx_single_input(op, prev, from.private_key, outputs);
  if (!tx.has_value()) throw std::runtime_error("failed to build spend");
  return tx->serialize();
}

Bytes make_p2pkh_script_sig(const Sig64& sig, const PubKey32& pub) {
  Bytes ss;
  ss.push_back(0x40);
  ss.insert(ss.end(), sig.begin(), sig.end());
  ss.push_back(0x20);
  ss.insert(ss.end(), pub.begin(), pub.end());
  return ss;
}

Bytes onboarding_registration_script(const PubKey32& validator_pub, const PubKey32& payout_pub, const Sig64& pop) {
  Bytes s{'S', 'C', 'O', 'N', 'B', 'R', 'E', 'G'};
  s.insert(s.end(), validator_pub.begin(), validator_pub.end());
  s.insert(s.end(), payout_pub.begin(), payout_pub.end());
  s.insert(s.end(), pop.begin(), pop.end());
  return s;
}

Bytes raw_signed_spend_v2_with_outputs(const OutPoint& op, const crypto::KeyPair& from,
                                       const std::vector<TxOutV2>& outputs, std::uint64_t fee) {
  TxV2 tx;
  tx.inputs.push_back(TxInV2{
      .prev_txid = op.txid,
      .prev_index = op.index,
      .sequence = 0xFFFFFFFF,
      .kind = TxInputKind::Transparent,
      .witness = TransparentInputWitnessV2{},
  });
  tx.outputs = outputs;
  tx.fee = fee;
  tx.balance_proof.excess_commitment = crypto::Commitment33{};
  tx.balance_proof.excess_pubkey.fill(0);
  tx.balance_proof.excess_sig.fill(0);
  auto msg = signing_message_for_input_v2(tx, 0);
  if (!msg.has_value()) throw std::runtime_error("failed to build v2 sighash");
  auto sig = crypto::ed25519_sign(*msg, from.private_key);
  if (!sig.has_value()) throw std::runtime_error("failed to sign v2 spend");
  std::get<TransparentInputWitnessV2>(tx.inputs[0].witness).script_sig = make_p2pkh_script_sig(*sig, from.public_key);
  return tx.serialize();
}

consensus::CanonicalDerivationConfig test_cfg() {
  consensus::CanonicalDerivationConfig cfg;
  cfg.network = mainnet_network();
  cfg.chain_id.network_name = cfg.network.name;
  cfg.chain_id.magic = cfg.network.magic;
  cfg.chain_id.network_id_hex = hex_encode(Bytes(cfg.network.network_id.begin(), cfg.network.network_id.end()));
  cfg.chain_id.protocol_version = PROTOCOL_VERSION;
  cfg.chain_id.genesis_hash_hex = "frontier-test";
  cfg.chain_id.genesis_source = "test";
  return cfg;
}

consensus::CanonicalDerivationConfig live_activation_cfg() {
  auto cfg = test_cfg();
  cfg.network.committee_epoch_blocks = 4;
  cfg.network.onboarding_admission_pow_difficulty_bits = 0;
  cfg.network.validator_join_admission_pow_difficulty_bits = 0;
  cfg.max_committee = 8;
  cfg.validator_min_bond_override = BOND_AMOUNT;
  cfg.validator_bond_min_amount = BOND_AMOUNT;
  cfg.validator_bond_max_amount = BOND_AMOUNT;
  cfg.validator_warmup_blocks = 1;
  cfg.validator_cooldown_blocks = 2;
  cfg.validator_join_limit_window_blocks = 32;
  cfg.validator_join_limit_max_new = 8;
  cfg.availability.replication_factor = 1;
  cfg.availability.warmup_epochs = 1;
  cfg.availability.min_warmup_audits = 1;
  cfg.availability.min_warmup_success_rate_bps = 10'000;
  cfg.availability.eligibility_min_score = 0;
  cfg.availability_min_eligible_operators = 1;
  return cfg;
}

std::uint64_t live_adaptive_test_bond() {
  return consensus::derive_adaptive_min_bond(16, 1);
}

storage::FinalizedCommitteeCheckpoint checkpoint_with_adaptive(
    storage::FinalizedCommitteeDerivationMode mode, const consensus::AdaptiveCheckpointParameters& adaptive) {
  storage::FinalizedCommitteeCheckpoint checkpoint;
  checkpoint.derivation_mode = mode;
  checkpoint.adaptive_target_committee_size = adaptive.target_committee_size;
  checkpoint.adaptive_min_eligible = adaptive.min_eligible_operators;
  checkpoint.adaptive_min_bond = adaptive.min_bond;
  checkpoint.qualified_depth = adaptive.qualified_depth;
  checkpoint.target_expand_streak = adaptive.target_expand_streak;
  checkpoint.target_contract_streak = adaptive.target_contract_streak;
  checkpoint.availability_min_eligible_operators = adaptive.min_eligible_operators;
  return checkpoint;
}

bool committee_eligibility_from_spec_rules(const consensus::ValidatorRegistry& validators, const PubKey32& validator_pubkey,
                                           const consensus::ValidatorInfo& info, std::uint64_t checkpoint_height,
                                           std::uint64_t effective_min_bond,
                                           const availability::AvailabilityOperatorState* availability_state,
                                           const availability::AvailabilityConfig& availability_cfg,
                                           storage::FinalizedCommitteeDerivationMode mode) {
  const bool base_eligible = validators.is_active_for_height(validator_pubkey, checkpoint_height) && info.has_bond &&
                             (info.joined_height == 0 || info.bonded_amount >= effective_min_bond);
  if (!base_eligible) return false;
  if (mode == storage::FinalizedCommitteeDerivationMode::FALLBACK) return true;
  return availability_state != nullptr && availability::operator_is_eligible(*availability_state, availability_cfg);
}

Bytes p2pkh_script_for_pub(const PubKey32& pub) {
  return address::p2pkh_script_pubkey(crypto::h160(Bytes(pub.begin(), pub.end())));
}

availability::InvalidAvailabilityServiceEvidence sample_observability_only_evidence(std::uint8_t base) {
  availability::InvalidAvailabilityServiceEvidence evidence;
  evidence.challenge.challenge_id.fill(base);
  evidence.challenge.epoch = 1;
  evidence.challenge.operator_pubkey = key_from_byte(base).public_key;
  evidence.challenge.prefix_id.fill(static_cast<std::uint8_t>(base + 1));
  evidence.challenge.chunk_index = static_cast<std::uint32_t>(base);
  evidence.challenge.issued_slot = 100 + base;
  evidence.challenge.deadline_slot = 110 + base;
  evidence.challenge.nonce.fill(static_cast<std::uint8_t>(base + 2));
  evidence.response.challenge_id = evidence.challenge.challenge_id;
  evidence.response.operator_pubkey = key_from_byte(static_cast<std::uint8_t>(base + 3)).public_key;
  evidence.response.prefix_id = evidence.challenge.prefix_id;
  evidence.response.chunk_index = evidence.challenge.chunk_index;
  evidence.response.chunk_bytes = Bytes{base, static_cast<std::uint8_t>(base + 4), static_cast<std::uint8_t>(base + 5)};
  evidence.response.responded_slot = 120 + base;
  evidence.response.operator_sig.fill(static_cast<std::uint8_t>(base + 6));
  evidence.violation = availability::InvalidAvailabilityResponseType::INVALID_PROOF;
  return evidence;
}

consensus::CanonicalDerivedState build_parent_state_with_utxo(const consensus::CanonicalDerivationConfig& cfg, std::uint64_t frontier,
                                                              const OutPoint& op, const TxOut& out) {
  consensus::CanonicalGenesisState genesis;
  genesis.genesis_artifact_id = zero_hash();
  genesis.initial_validators.push_back(key_from_byte(90).public_key);

  consensus::CanonicalDerivedState state;
  std::string err;
  if (!consensus::build_genesis_canonical_state(cfg, genesis, &state, &err)) {
    throw std::runtime_error("genesis canonical state failed: " + err);
  }
  state.utxos[op] = UtxoEntry{out};
  state.finalized_frontier = frontier;
  state.finalized_frontier_vector.lane_max_seq[0] = frontier;
  state.state_commitment = consensus::consensus_state_commitment(cfg, state);
  return state;
}

consensus::CertifiedIngressLaneRecords make_lane_records(const consensus::CanonicalDerivedState& parent_state,
                                                         const std::vector<Bytes>& ordered_records,
                                                         FrontierVector* next_vector_out = nullptr,
                                                         std::uint64_t epoch_blocks = 0) {
  consensus::CertifiedIngressLaneRecords lane_records;
  const auto signer = key_from_byte(90);
  FrontierVector next_vector = parent_state.finalized_frontier_vector;
  auto lane_roots = parent_state.finalized_lane_roots;
  const auto next_height = parent_state.finalized_height + 1;
  const std::uint64_t cert_epoch = (epoch_blocks > 0)
      ? consensus::committee_epoch_start(next_height, epoch_blocks)
      : 1;
  for (const auto& raw : ordered_records) {
    auto tx = parse_any_tx(raw);
    if (!tx.has_value()) throw std::runtime_error("failed to parse ordered test tx");
    const auto lane = consensus::assign_ingress_lane(*tx);
    IngressCertificate cert;
    cert.epoch = cert_epoch;
    cert.lane = lane;
    cert.seq = ++next_vector.lane_max_seq[lane];
    cert.txid = txid_any(*tx);
    cert.tx_hash = crypto::sha256d(raw);
    cert.prev_lane_root = lane_roots[lane];
    const auto signing_hash = cert.signing_hash();
    const auto sig = crypto::ed25519_sign(Bytes(signing_hash.begin(), signing_hash.end()), signer.private_key);
    if (!sig.has_value()) throw std::runtime_error("failed to sign ingress certificate");
    cert.sigs = {FinalitySig{signer.public_key, *sig}};
    lane_roots[lane] = consensus::compute_lane_root_append(lane_roots[lane], cert.tx_hash);
    lane_records[lane].push_back(consensus::CertifiedIngressRecord{cert, raw});
  }
  if (next_vector_out) *next_vector_out = next_vector;
  return lane_records;
}

consensus::CanonicalFrontierRecord make_frontier_record(const consensus::CanonicalDerivedState& parent_state,
                                                        const std::vector<Bytes>& ordered_records,
                                                        const consensus::CanonicalDerivationConfig& cfg = test_cfg(),
                                                        std::uint32_t round = 0,
                                                        const std::vector<PubKey32>& observed_signers = {},
                                                        const SpecialValidationContext* vctx = nullptr) {
  FrontierVector next_vector;
  auto lane_records = make_lane_records(parent_state, ordered_records, &next_vector, cfg.network.committee_epoch_blocks);
  consensus::FrontierExecutionResult result;
  std::string err;
  if (!consensus::execute_frontier_lane_prefix(parent_state.utxos, parent_state.finalized_frontier_vector, next_vector,
                                               lane_records, parent_state.finalized_lane_roots, vctx, &result, &err)) {
    throw std::runtime_error("frontier execution failed: " + err);
  }
  const auto height = parent_state.finalized_height + 1;
  const auto leader = consensus::canonical_leader_for_height_round(cfg, parent_state, height, round);
  if (!leader.has_value()) throw std::runtime_error("missing canonical leader");
  const auto signers = observed_signers.empty() ? std::vector<PubKey32>{*leader} : observed_signers;
  if (!consensus::populate_frontier_transition_metadata(cfg, parent_state, height, round, *leader, signers,
                                                        result.accepted_fee_units, result.next_utxos, &result.transition,
                                                        &err)) {
    throw std::runtime_error("frontier metadata population failed: " + err);
  }
  return consensus::CanonicalFrontierRecord{result.transition, lane_records};
}

void persist_frontier_record(storage::DB& db, std::uint64_t height, const consensus::CanonicalFrontierRecord& record) {
  ASSERT_TRUE(db.put_frontier_transition(record.transition.transition_id(), record.transition.serialize()));
  ASSERT_TRUE(db.map_height_to_frontier_transition(height, record.transition.transition_id()));
}

void persist_frontier_record_with_certificate(const consensus::CanonicalDerivationConfig& cfg,
                                              const consensus::CanonicalDerivedState& parent_state, storage::DB& db,
                                              std::uint64_t height,
                                              const consensus::CanonicalFrontierRecord& record) {
  persist_frontier_record(db, height, record);
  const auto committee =
      consensus::canonical_committee_for_height_round(cfg, parent_state, record.transition.height, record.transition.round);
  ASSERT_TRUE(!committee.empty());
  ASSERT_EQ(committee.size(), 1u);
  const auto signer = key_from_byte(90);
  ASSERT_EQ(committee.front(), signer.public_key);
  auto sig = crypto::ed25519_sign(vote_signing_message(record.transition.height, record.transition.round,
                                                       record.transition.transition_id()),
                                  signer.private_key);
  ASSERT_TRUE(sig.has_value());
  FinalityCertificate cert;
  cert.height = record.transition.height;
  cert.round = record.transition.round;
  cert.frontier_transition_id = record.transition.transition_id();
  cert.quorum_threshold = static_cast<std::uint32_t>(consensus::quorum_threshold(committee.size()));
  cert.committee_members = committee;
  cert.signatures = {FinalitySig{signer.public_key, *sig}};
  ASSERT_TRUE(db.put_finality_certificate(cert));
}

void persist_lane_state_seed(storage::DB& db, const consensus::CanonicalDerivedState& parent_state) {
  for (std::size_t lane = 0; lane < finalis::INGRESS_LANE_COUNT; ++lane) {
    const auto max_seq = parent_state.finalized_frontier_vector.lane_max_seq[lane];
    if (max_seq == 0) continue;
    LaneState state;
    state.epoch = 0;
    state.lane = static_cast<std::uint32_t>(lane);
    state.max_seq = max_seq;
    state.lane_root = parent_state.finalized_lane_roots[lane];
    ASSERT_TRUE(db.put_lane_state(static_cast<std::uint32_t>(lane), state));
  }
}

void persist_lane_records(storage::DB& db, const consensus::CanonicalFrontierRecord& record) {
  for (std::size_t lane = 0; lane < finalis::INGRESS_LANE_COUNT; ++lane) {
    for (const auto& ingress : record.lane_records[lane]) {
      ASSERT_TRUE(db.put_ingress_bytes(ingress.certificate.txid, ingress.tx_bytes));
      ASSERT_TRUE(db.put_ingress_certificate(static_cast<std::uint32_t>(lane), ingress.certificate.seq,
                                             ingress.certificate.serialize()));
      LaneState state;
      state.epoch = ingress.certificate.epoch;
      state.lane = ingress.certificate.lane;
      state.max_seq = ingress.certificate.seq;
      state.lane_root = consensus::compute_lane_root_append(ingress.certificate.prev_lane_root, ingress.certificate.tx_hash);
      ASSERT_TRUE(db.put_lane_state(state.lane, state));
    }
  }
}

consensus::CanonicalDerivedState apply_frontier_or_throw(const consensus::CanonicalDerivationConfig& cfg,
                                                         const consensus::CanonicalDerivedState& parent,
                                                         const std::vector<Bytes>& ordered_records) {
  const auto record = make_frontier_record(parent, ordered_records, cfg);
  consensus::CanonicalDerivedState out;
  std::string err;
  if (!consensus::apply_frontier_record(cfg, parent, record, &out, &err)) {
    throw std::runtime_error("apply_frontier_record failed: " + err);
  }
  return out;
}

std::map<std::string, Bytes> checkpoint_raw_rows(
    const std::map<std::uint64_t, storage::FinalizedCommitteeCheckpoint>& checkpoints) {
  const auto path = unique_test_base("/tmp/finalis_test_checkpoint_bytes_long_horizon");
  std::filesystem::remove_all(path);
  storage::DB db;
  if (!db.open(path)) throw std::runtime_error("checkpoint byte db open failed");
  for (const auto& [_, checkpoint] : checkpoints) {
    if (!db.put_finalized_committee_checkpoint(checkpoint)) {
      throw std::runtime_error("checkpoint byte db write failed");
    }
  }
  return db.scan_prefix("CE:");
}

}  // namespace

TEST(test_frontier_replay_is_deterministic_for_same_parent_and_record_sequence) {
  const auto cfg = test_cfg();
  const auto from = key_from_byte(1);
  const auto to = key_from_byte(2);

  OutPoint op{};
  op.txid.fill(0x11);
  op.index = 0;
  const auto prev = p2pkh_out_for_pub(from.public_key, 10'000);
  const auto parent = build_parent_state_with_utxo(cfg, 5, op, prev);

  const std::vector<Bytes> ordered{raw_signed_spend(op, prev, from, to.public_key, 9'800)};
  const auto record = make_frontier_record(parent, ordered);

  consensus::CanonicalDerivedState a;
  consensus::CanonicalDerivedState b;
  std::string err_a;
  std::string err_b;
  ASSERT_TRUE(consensus::derive_canonical_state_from_frontier_chain(cfg, parent, {record}, &a, &err_a));
  ASSERT_TRUE(consensus::derive_canonical_state_from_frontier_chain(cfg, parent, {record}, &b, &err_b));
  ASSERT_EQ(a.finalized_frontier, b.finalized_frontier);
  ASSERT_EQ(a.state_commitment, b.state_commitment);
  ASSERT_EQ(consensus::frontier_utxo_state_root(a.utxos), consensus::frontier_utxo_state_root(b.utxos));
}

TEST(test_frontier_transition_identity_matches_across_two_nodes_with_same_parent_and_ingress) {
  const auto cfg = test_cfg();
  const auto from = key_from_byte(17);
  const auto to = key_from_byte(18);

  OutPoint op{};
  op.txid.fill(0x19);
  op.index = 0;
  const auto prev = p2pkh_out_for_pub(from.public_key, 10'000);
  const auto parent_a = build_parent_state_with_utxo(cfg, 9, op, prev);
  const auto parent_b = build_parent_state_with_utxo(cfg, 9, op, prev);

  const std::vector<Bytes> ordered{raw_signed_spend(op, prev, from, to.public_key, 9'700)};
  const auto record_a = make_frontier_record(parent_a, ordered);
  const auto record_b = make_frontier_record(parent_b, ordered);

  ASSERT_EQ(record_a.transition.serialize(), record_b.transition.serialize());
  ASSERT_EQ(record_a.transition.transition_id(), record_b.transition.transition_id());
}

TEST(test_availability_long_horizon_replay_equivalence_across_continuous_epoch_and_random_restart_schedules) {
  const auto cfg = live_activation_cfg();
  const auto from = key_from_byte(0x80);
  const std::array<crypto::KeyPair, 12> keys = {
      key_from_byte(0x81), key_from_byte(0x82), key_from_byte(0x83), key_from_byte(0x84),
      key_from_byte(0x85), key_from_byte(0x86), key_from_byte(0x87), key_from_byte(0x88),
      key_from_byte(0x89), key_from_byte(0x8a), key_from_byte(0x8b), key_from_byte(0x8c),
  };

  consensus::CanonicalGenesisState genesis;
  genesis.genesis_artifact_id = zero_hash();
  genesis.initial_validators.push_back(key_from_byte(90).public_key);

  consensus::CanonicalDerivedState genesis_state;
  std::string err;
  ASSERT_TRUE(consensus::build_genesis_canonical_state(cfg, genesis, &genesis_state, &err));

  OutPoint op{};
  op.txid.fill(0x31);
  op.index = 0;
  const auto prev = p2pkh_out_for_pub(from.public_key, 25'000);
  genesis_state.utxos[op] = UtxoEntry{prev};
  genesis_state.state_commitment = consensus::consensus_state_commitment(cfg, genesis_state);

  std::vector<consensus::CanonicalFrontierRecord> chain;
  chain.reserve(keys.size());
  consensus::CanonicalDerivedState build_state = genesis_state;
  OutPoint current_op = op;
  TxOut current_prev = prev;
  crypto::KeyPair current_key = from;
  std::uint64_t next_value = 24'500;
  for (const auto& next_key : keys) {
    const std::vector<Bytes> ordered{raw_signed_spend(current_op, current_prev, current_key, next_key.public_key, next_value)};
    chain.push_back(make_frontier_record(build_state, ordered, cfg));
    build_state = apply_frontier_or_throw(cfg, build_state, ordered);
    auto parsed = Tx::parse(ordered.front());
    ASSERT_TRUE(parsed.has_value());
    current_op = OutPoint{parsed->txid(), 0};
    current_prev = parsed->outputs.at(0);
    current_key = next_key;
    next_value -= 250;
  }

  const auto run_schedule = [&](const std::set<std::size_t>& restart_after_steps) {
    consensus::CanonicalDerivedState state = genesis_state;
    for (std::size_t i = 0; i < chain.size(); ++i) {
      std::string local_err;
      consensus::CanonicalDerivedState next;
      if (!consensus::apply_frontier_record(cfg, state, chain[i], &next, &local_err)) {
        throw std::runtime_error("apply_frontier_record failed at step=" + std::to_string(i + 1) +
                                 " height=" + std::to_string(chain[i].transition.height) + ": " + local_err);
      }
      state = std::move(next);
      if (restart_after_steps.count(i + 1) != 0) {
        auto restored = availability::AvailabilityPersistentState::parse(state.availability_state.serialize());
        if (!restored.has_value()) throw std::runtime_error("availability state restore failed");
        state.availability_state = *restored;
      }
    }
    return state;
  };

  const auto continuous = run_schedule({});
  const auto every_epoch = run_schedule({4, 8, 12});
  const auto randomized = run_schedule({2, 5, 9, 11});

  ASSERT_EQ(every_epoch.availability_state, continuous.availability_state);
  ASSERT_EQ(randomized.availability_state, continuous.availability_state);
  ASSERT_EQ(every_epoch.state_commitment, continuous.state_commitment);
  ASSERT_EQ(randomized.state_commitment, continuous.state_commitment);

  const auto continuous_checkpoint_bytes = checkpoint_raw_rows(continuous.finalized_committee_checkpoints);
  const auto every_epoch_checkpoint_bytes = checkpoint_raw_rows(every_epoch.finalized_committee_checkpoints);
  const auto randomized_checkpoint_bytes = checkpoint_raw_rows(randomized.finalized_committee_checkpoints);
  ASSERT_EQ(every_epoch_checkpoint_bytes, continuous_checkpoint_bytes);
  ASSERT_EQ(randomized_checkpoint_bytes, continuous_checkpoint_bytes);
}

TEST(test_availability_evidence_isolation_preserves_checkpoint_output) {
  auto cfg = live_activation_cfg();
  cfg.availability_min_eligible_operators = 1;
  const auto bootstrap = key_from_byte(0x90);
  const auto second = key_from_byte(0x91);

  consensus::CanonicalGenesisState genesis;
  genesis.genesis_artifact_id = zero_hash();
  genesis.initial_validators.push_back(bootstrap.public_key);

  consensus::CanonicalDerivedState base;
  std::string err;
  ASSERT_TRUE(consensus::build_genesis_canonical_state(cfg, genesis, &base, &err));
  base.validators.set_rules(
      consensus::ValidatorRules{.min_bond = live_adaptive_test_bond(), .warmup_blocks = 0, .cooldown_blocks = 0});
  ASSERT_TRUE(base.validators.register_bond(second.public_key, OutPoint{Hash32{2}, 0}, 0, live_adaptive_test_bond(), &err,
                                            second.public_key));
  base.validators.advance_height(1);
  base.committee_epoch_randomness_cache[5] = base.finalized_randomness;
  base.availability_state.operators = {
      availability::AvailabilityOperatorState{
          .operator_pubkey = bootstrap.public_key,
          .bond = live_adaptive_test_bond(),
          .status = availability::AvailabilityOperatorStatus::ACTIVE,
          .successful_audits = 1,
          .warmup_epochs = 1,
          .retained_prefix_count = 1,
      },
      availability::AvailabilityOperatorState{
          .operator_pubkey = second.public_key,
          .bond = live_adaptive_test_bond(),
          .status = availability::AvailabilityOperatorStatus::ACTIVE,
          .successful_audits = 1,
          .warmup_epochs = 1,
          .retained_prefix_count = 1,
      },
  };
  availability::normalize_availability_persistent_state(&base.availability_state);

  auto with_evidence = base;
  with_evidence.availability_state.evidence = {
      sample_observability_only_evidence(0x11),
      sample_observability_only_evidence(0x17),
      sample_observability_only_evidence(0x11),
  };
  availability::normalize_availability_persistent_state(&with_evidence.availability_state);

  storage::FinalizedCommitteeCheckpoint checkpoint_a;
  storage::FinalizedCommitteeCheckpoint checkpoint_b;
  ASSERT_TRUE(consensus::derive_next_epoch_checkpoint_from_state(cfg, base, 5, &checkpoint_a, &err));
  ASSERT_TRUE(consensus::derive_next_epoch_checkpoint_from_state(cfg, with_evidence, 5, &checkpoint_b, &err));
  ASSERT_TRUE(consensus::canonical_checkpoints_equal(checkpoint_a, checkpoint_b));

  const auto raw_a = checkpoint_raw_rows({{checkpoint_a.epoch_start_height, checkpoint_a}});
  const auto raw_b = checkpoint_raw_rows({{checkpoint_b.epoch_start_height, checkpoint_b}});
  ASSERT_EQ(raw_a, raw_b);
  ASSERT_EQ(consensus::consensus_state_commitment(cfg, base), consensus::consensus_state_commitment(cfg, with_evidence));
}

TEST(test_availability_evidence_isolation_preserves_restart_boundary_checkpoint_output) {
  const auto cfg = live_activation_cfg();
  const auto from = key_from_byte(0xa0);
  const auto k1 = key_from_byte(0xa1);
  const auto k2 = key_from_byte(0xa2);
  const auto k3 = key_from_byte(0xa3);
  const auto k4 = key_from_byte(0xa4);

  consensus::CanonicalGenesisState genesis;
  genesis.genesis_artifact_id = zero_hash();
  genesis.initial_validators.push_back(key_from_byte(90).public_key);

  consensus::CanonicalDerivedState genesis_state;
  std::string err;
  ASSERT_TRUE(consensus::build_genesis_canonical_state(cfg, genesis, &genesis_state, &err));

  OutPoint op{};
  op.txid.fill(0x41);
  op.index = 0;
  const auto prev = p2pkh_out_for_pub(from.public_key, 10'000);
  genesis_state.utxos[op] = UtxoEntry{prev};
  genesis_state.state_commitment = consensus::consensus_state_commitment(cfg, genesis_state);

  std::vector<consensus::CanonicalFrontierRecord> chain;
  chain.reserve(4);
  consensus::CanonicalDerivedState current = genesis_state;
  OutPoint current_op = op;
  TxOut current_prev = prev;
  crypto::KeyPair current_key = from;
  const std::array<crypto::KeyPair, 4> next_keys{k1, k2, k3, k4};
  std::uint64_t next_value = 9'900;
  for (const auto& next_key : next_keys) {
    const std::vector<Bytes> ordered{raw_signed_spend(current_op, current_prev, current_key, next_key.public_key, next_value)};
    const auto record = make_frontier_record(current, ordered, cfg);
    chain.push_back(record);
    current = apply_frontier_or_throw(cfg, current, ordered);
    auto parsed = Tx::parse(ordered.front());
    ASSERT_TRUE(parsed.has_value());
    current_op = OutPoint{parsed->txid(), 0};
    current_prev = parsed->outputs.at(0);
    current_key = next_key;
    next_value -= 100;
  }

  consensus::CanonicalDerivedState pre_boundary = genesis_state;
  for (std::size_t i = 0; i < 3; ++i) {
    std::string local_err;
    consensus::CanonicalDerivedState next;
    ASSERT_TRUE(consensus::apply_frontier_record(cfg, pre_boundary, chain[i], &next, &local_err));
    pre_boundary = std::move(next);
  }

  auto with_evidence_a = pre_boundary.availability_state;
  with_evidence_a.evidence = {sample_observability_only_evidence(0x21), sample_observability_only_evidence(0x23)};
  auto with_evidence_b = pre_boundary.availability_state;
  with_evidence_b.evidence = {sample_observability_only_evidence(0x31), sample_observability_only_evidence(0x29),
                              sample_observability_only_evidence(0x33)};
  const auto restored_a = availability::AvailabilityPersistentState::parse(with_evidence_a.serialize());
  const auto restored_b = availability::AvailabilityPersistentState::parse(with_evidence_b.serialize());
  ASSERT_TRUE(restored_a.has_value());
  ASSERT_TRUE(restored_b.has_value());

  auto state_a = pre_boundary;
  auto state_b = pre_boundary;
  state_a.availability_state = *restored_a;
  state_b.availability_state = *restored_b;

  consensus::CanonicalDerivedState restarted_a;
  consensus::CanonicalDerivedState restarted_b;
  std::string restart_err;
  ASSERT_TRUE(consensus::apply_frontier_record(cfg, state_a, chain[3], &restarted_a, &restart_err));
  ASSERT_TRUE(consensus::apply_frontier_record(cfg, state_b, chain[3], &restarted_b, &restart_err));

  ASSERT_EQ(availability::consensus_relevant_availability_state(restarted_a.availability_state),
            availability::consensus_relevant_availability_state(restarted_b.availability_state));
  ASSERT_EQ(restarted_a.state_commitment, restarted_b.state_commitment);
  ASSERT_EQ(checkpoint_raw_rows(restarted_a.finalized_committee_checkpoints),
            checkpoint_raw_rows(restarted_b.finalized_committee_checkpoints));
}

TEST(test_availability_evidence_isolation_holds_across_long_horizon_restart_schedules) {
  const auto cfg = live_activation_cfg();
  const auto from = key_from_byte(0xb0);
  const std::array<crypto::KeyPair, 12> keys = {
      key_from_byte(0xb1), key_from_byte(0xb2), key_from_byte(0xb3), key_from_byte(0xb4),
      key_from_byte(0xb5), key_from_byte(0xb6), key_from_byte(0xb7), key_from_byte(0xb8),
      key_from_byte(0xb9), key_from_byte(0xba), key_from_byte(0xbb), key_from_byte(0xbc),
  };

  consensus::CanonicalGenesisState genesis;
  genesis.genesis_artifact_id = zero_hash();
  genesis.initial_validators.push_back(key_from_byte(90).public_key);

  consensus::CanonicalDerivedState genesis_state;
  std::string err;
  ASSERT_TRUE(consensus::build_genesis_canonical_state(cfg, genesis, &genesis_state, &err));

  OutPoint op{};
  op.txid.fill(0x51);
  op.index = 0;
  const auto prev = p2pkh_out_for_pub(from.public_key, 25'000);
  genesis_state.utxos[op] = UtxoEntry{prev};
  genesis_state.state_commitment = consensus::consensus_state_commitment(cfg, genesis_state);

  std::vector<consensus::CanonicalFrontierRecord> chain;
  chain.reserve(keys.size());
  consensus::CanonicalDerivedState build_state = genesis_state;
  OutPoint current_op = op;
  TxOut current_prev = prev;
  crypto::KeyPair current_key = from;
  std::uint64_t next_value = 24'500;
  for (const auto& next_key : keys) {
    const std::vector<Bytes> ordered{raw_signed_spend(current_op, current_prev, current_key, next_key.public_key, next_value)};
    chain.push_back(make_frontier_record(build_state, ordered, cfg));
    build_state = apply_frontier_or_throw(cfg, build_state, ordered);
    auto parsed = Tx::parse(ordered.front());
    ASSERT_TRUE(parsed.has_value());
    current_op = OutPoint{parsed->txid(), 0};
    current_prev = parsed->outputs.at(0);
    current_key = next_key;
    next_value -= 250;
  }

  const auto run_schedule = [&](const std::set<std::size_t>& restart_after_steps, bool mutate_evidence) {
    consensus::CanonicalDerivedState state = genesis_state;
    for (std::size_t i = 0; i < chain.size(); ++i) {
      std::string local_err;
      consensus::CanonicalDerivedState next;
      if (!consensus::apply_frontier_record(cfg, state, chain[i], &next, &local_err)) {
        throw std::runtime_error("apply_frontier_record failed at step=" + std::to_string(i + 1) +
                                 " height=" + std::to_string(chain[i].transition.height) + ": " + local_err);
      }
      state = std::move(next);
      if (mutate_evidence) {
        state.availability_state.evidence = {sample_observability_only_evidence(static_cast<std::uint8_t>(0x40 + i)),
                                             sample_observability_only_evidence(static_cast<std::uint8_t>(0x70 - i))};
        availability::normalize_availability_persistent_state(&state.availability_state);
      }
      if (restart_after_steps.count(i + 1) != 0) {
        auto restored = availability::AvailabilityPersistentState::parse(state.availability_state.serialize());
        if (!restored.has_value()) throw std::runtime_error("availability state restore failed");
        if (mutate_evidence) {
          restored->evidence = {sample_observability_only_evidence(static_cast<std::uint8_t>(0x90 + i))};
          availability::normalize_availability_persistent_state(&*restored);
        }
        state.availability_state = *restored;
      }
    }
    return state;
  };

  const auto baseline = run_schedule({}, false);
  const auto every_epoch = run_schedule({4, 8, 12}, true);
  const auto randomized = run_schedule({2, 5, 9, 11}, true);

  ASSERT_EQ(availability::consensus_relevant_availability_state(every_epoch.availability_state),
            availability::consensus_relevant_availability_state(baseline.availability_state));
  ASSERT_EQ(availability::consensus_relevant_availability_state(randomized.availability_state),
            availability::consensus_relevant_availability_state(baseline.availability_state));
  ASSERT_EQ(every_epoch.state_commitment, baseline.state_commitment);
  ASSERT_EQ(randomized.state_commitment, baseline.state_commitment);
  ASSERT_EQ(checkpoint_raw_rows(every_epoch.finalized_committee_checkpoints),
            checkpoint_raw_rows(baseline.finalized_committee_checkpoints));
  ASSERT_EQ(checkpoint_raw_rows(randomized.finalized_committee_checkpoints),
            checkpoint_raw_rows(baseline.finalized_committee_checkpoints));
}

TEST(test_availability_state_epoch_boundary_replay_matches_persisted_restore_before_checkpoint_derivation) {
  const auto cfg = live_activation_cfg();
  const auto from = key_from_byte(0x70);
  const auto k1 = key_from_byte(0x71);
  const auto k2 = key_from_byte(0x72);
  const auto k3 = key_from_byte(0x73);
  const auto k4 = key_from_byte(0x74);

  consensus::CanonicalGenesisState genesis;
  genesis.genesis_artifact_id = zero_hash();
  genesis.initial_validators.push_back(key_from_byte(90).public_key);

  consensus::CanonicalDerivedState genesis_state;
  std::string err;
  ASSERT_TRUE(consensus::build_genesis_canonical_state(cfg, genesis, &genesis_state, &err));

  OutPoint op{};
  op.txid.fill(0x21);
  op.index = 0;
  const auto prev = p2pkh_out_for_pub(from.public_key, 10'000);
  genesis_state.utxos[op] = UtxoEntry{prev};
  genesis_state.state_commitment = consensus::consensus_state_commitment(cfg, genesis_state);

  std::vector<consensus::CanonicalFrontierRecord> chain;
  chain.reserve(4);
  consensus::CanonicalDerivedState current = genesis_state;
  OutPoint current_op = op;
  TxOut current_prev = prev;
  crypto::KeyPair current_key = from;
  const std::array<crypto::KeyPair, 4> next_keys{k1, k2, k3, k4};
  std::uint64_t next_value = 9'900;
  for (const auto& next_key : next_keys) {
    const std::vector<Bytes> ordered{raw_signed_spend(current_op, current_prev, current_key, next_key.public_key, next_value)};
    const auto record = make_frontier_record(current, ordered, cfg);
    chain.push_back(record);
    current = apply_frontier_or_throw(cfg, current, ordered);
    auto parsed = Tx::parse(ordered.front());
    ASSERT_TRUE(parsed.has_value());
    current_op = OutPoint{parsed->txid(), 0};
    current_prev = parsed->outputs.at(0);
    current_key = next_key;
    next_value -= 100;
  }
  const auto uninterrupted = current;

  consensus::CanonicalDerivedState pre_boundary = genesis_state;
  for (std::size_t i = 0; i < 3; ++i) {
    std::string local_err;
    consensus::CanonicalDerivedState next;
    ASSERT_TRUE(consensus::apply_frontier_record(cfg, pre_boundary, chain[i], &next, &local_err));
    pre_boundary = std::move(next);
  }
  const auto restored_availability =
      availability::AvailabilityPersistentState::parse(pre_boundary.availability_state.serialize());
  ASSERT_TRUE(restored_availability.has_value());
  pre_boundary.availability_state = *restored_availability;

  consensus::CanonicalDerivedState restarted;
  std::string restart_err;
  ASSERT_TRUE(consensus::apply_frontier_record(cfg, pre_boundary, chain[3], &restarted, &restart_err));

  ASSERT_EQ(restarted.availability_state, uninterrupted.availability_state);
  ASSERT_EQ(restarted.state_commitment, uninterrupted.state_commitment);
  const auto cp_uninterrupted = uninterrupted.finalized_committee_checkpoints.find(5);
  const auto cp_restarted = restarted.finalized_committee_checkpoints.find(5);
  ASSERT_TRUE(cp_uninterrupted != uninterrupted.finalized_committee_checkpoints.end());
  ASSERT_TRUE(cp_restarted != restarted.finalized_committee_checkpoints.end());
  ASSERT_TRUE(consensus::canonical_checkpoints_equal(cp_uninterrupted->second, cp_restarted->second));
}

TEST(test_frontier_transition_diverges_explicitly_when_ingress_diverges) {
  const auto cfg = test_cfg();
  const auto from = key_from_byte(19);
  const auto to_a = key_from_byte(20);
  const auto to_b = key_from_byte(21);

  OutPoint op{};
  op.txid.fill(0x29);
  op.index = 0;
  const auto prev = p2pkh_out_for_pub(from.public_key, 10'000);
  const auto parent = build_parent_state_with_utxo(cfg, 4, op, prev);

  const std::vector<Bytes> ordered_a{raw_signed_spend(op, prev, from, to_a.public_key, 9'700)};
  const std::vector<Bytes> ordered_b{raw_signed_spend(op, prev, from, to_b.public_key, 9'700)};
  const auto record_a = make_frontier_record(parent, ordered_a);
  const auto record_b = make_frontier_record(parent, ordered_b);

  ASSERT_TRUE(record_a.transition.transition_id() != record_b.transition.transition_id());
  ASSERT_TRUE(record_a.transition.ingress_commitment != record_b.transition.ingress_commitment);
}

TEST(test_frontier_replay_rejects_tampered_next_state_root) {
  const auto cfg = test_cfg();
  const auto from = key_from_byte(3);
  const auto to = key_from_byte(4);

  OutPoint op{};
  op.txid.fill(0x22);
  op.index = 0;
  const auto prev = p2pkh_out_for_pub(from.public_key, 10'000);
  const auto parent = build_parent_state_with_utxo(cfg, 0, op, prev);

  auto record = make_frontier_record(parent, {raw_signed_spend(op, prev, from, to.public_key, 9'900)});
  record.transition.next_state_root[0] ^= 0x01;

  consensus::CanonicalDerivedState out;
  std::string err;
  ASSERT_TRUE(!consensus::derive_canonical_state_from_frontier_chain(cfg, parent, {record}, &out, &err));
}

TEST(test_frontier_replay_rejects_tampered_decisions_commitment) {
  const auto cfg = test_cfg();
  const auto from = key_from_byte(5);
  const auto to = key_from_byte(6);

  OutPoint op{};
  op.txid.fill(0x33);
  op.index = 0;
  const auto prev = p2pkh_out_for_pub(from.public_key, 10'000);
  const auto parent = build_parent_state_with_utxo(cfg, 2, op, prev);

  auto record = make_frontier_record(parent, {raw_signed_spend(op, prev, from, to.public_key, 9'850)});
  record.transition.decisions_commitment[0] ^= 0x01;

  consensus::CanonicalDerivedState out;
  std::string err;
  ASSERT_TRUE(!consensus::derive_canonical_state_from_frontier_chain(cfg, parent, {record}, &out, &err));
}

TEST(test_frontier_replay_rejects_tampered_ordered_slice_bytes) {
  const auto cfg = test_cfg();
  const auto from = key_from_byte(7);
  const auto to = key_from_byte(8);

  OutPoint op{};
  op.txid.fill(0x44);
  op.index = 0;
  const auto prev = p2pkh_out_for_pub(from.public_key, 10'000);
  const auto parent = build_parent_state_with_utxo(cfg, 1, op, prev);

  auto record = make_frontier_record(parent, {raw_signed_spend(op, prev, from, to.public_key, 9'850)});
  bool mutated = false;
  for (auto& lane : record.lane_records) {
    if (!lane.empty()) {
      lane[0].tx_bytes[0] ^= 0x01;
      mutated = true;
      break;
    }
  }
  ASSERT_TRUE(mutated);

  consensus::CanonicalDerivedState out;
  std::string err;
  ASSERT_TRUE(!consensus::derive_canonical_state_from_frontier_chain(cfg, parent, {record}, &out, &err));
}

TEST(test_frontier_replay_rejects_mismatched_prev_frontier) {
  const auto cfg = test_cfg();
  const auto from = key_from_byte(9);
  const auto to = key_from_byte(10);

  OutPoint op{};
  op.txid.fill(0x55);
  op.index = 0;
  const auto prev = p2pkh_out_for_pub(from.public_key, 10'000);
  const auto parent = build_parent_state_with_utxo(cfg, 4, op, prev);

  auto record = make_frontier_record(parent, {raw_signed_spend(op, prev, from, to.public_key, 9'800)});
  record.transition.prev_vector.lane_max_seq[0] += 1;
  record.transition.prev_frontier += 1;

  consensus::CanonicalDerivedState out;
  std::string err;
  ASSERT_TRUE(!consensus::derive_canonical_state_from_frontier_chain(cfg, parent, {record}, &out, &err));
}

TEST(test_frontier_replay_rejects_non_contiguous_transition_range) {
  const auto cfg = test_cfg();
  const auto from = key_from_byte(15);
  const auto to = key_from_byte(16);

  OutPoint op{};
  op.txid.fill(0x56);
  op.index = 0;
  const auto prev = p2pkh_out_for_pub(from.public_key, 10'000);
  const auto parent = build_parent_state_with_utxo(cfg, 4, op, prev);

  auto record = make_frontier_record(parent, {raw_signed_spend(op, prev, from, to.public_key, 9'800)});
  record.transition.next_vector.lane_max_seq[0] += 1;
  record.transition.next_frontier += 1;

  consensus::CanonicalDerivedState out;
  std::string err;
  ASSERT_TRUE(!consensus::derive_canonical_state_from_frontier_chain(cfg, parent, {record}, &out, &err));
}

TEST(test_frontier_replay_from_persisted_ingress_slice_is_deterministic) {
  const auto cfg = test_cfg();
  const auto from_a = key_from_byte(12);
  const auto from_b = key_from_byte(13);
  const auto to = key_from_byte(14);

  OutPoint op_a{};
  op_a.txid.fill(0x61);
  op_a.index = 0;
  OutPoint op_b{};
  op_b.txid.fill(0x62);
  op_b.index = 0;
  const auto prev_a = p2pkh_out_for_pub(from_a.public_key, 10'000);
  const auto prev_b = p2pkh_out_for_pub(from_b.public_key, 10'000);
  const auto parent = build_parent_state_with_utxo(cfg, 20, op_a, prev_a);

  consensus::CanonicalDerivedState parent_with_two = parent;
  parent_with_two.utxos[op_b] = UtxoEntry{prev_b};
  parent_with_two.state_commitment = consensus::consensus_state_commitment(cfg, parent_with_two);

  const std::string path = unique_test_base("/tmp/finalis_test_frontier_replay_ingress_db");
  std::filesystem::remove_all(path);
  storage::DB db;
  ASSERT_TRUE(db.open(path));

  const Bytes record_a = raw_signed_spend(op_a, prev_a, from_a, to.public_key, 9'900);
  const Bytes record_b = raw_signed_spend(op_b, prev_b, from_b, to.public_key, 9'850);
  const auto record = make_frontier_record(parent_with_two, {record_a, record_b});
  persist_lane_state_seed(db, parent_with_two);
  persist_lane_records(db, record);

  consensus::CanonicalDerivedState a;
  consensus::CanonicalDerivedState b;
  std::string err_a;
  std::string err_b;
  ASSERT_TRUE(consensus::derive_canonical_state_from_frontier_chain(cfg, parent_with_two, {record}, &a, &err_a));
  ASSERT_TRUE(consensus::derive_canonical_state_from_frontier_chain(cfg, parent_with_two, {record}, &b, &err_b));
  ASSERT_EQ(a.finalized_frontier, 22u);
  ASSERT_EQ(a.state_commitment, b.state_commitment);
}

TEST(test_frontier_settlement_is_deterministic_for_identical_parent_and_accepted_set) {
  const auto cfg = test_cfg();
  const auto from_a = key_from_byte(24);
  const auto from_b = key_from_byte(25);
  const auto to = key_from_byte(26);

  OutPoint op_a{};
  op_a.txid.fill(0x91);
  op_a.index = 0;
  OutPoint op_b{};
  op_b.txid.fill(0x92);
  op_b.index = 0;
  const auto prev_a = p2pkh_out_for_pub(from_a.public_key, 10'000);
  const auto prev_b = p2pkh_out_for_pub(from_b.public_key, 12'000);
  auto parent = build_parent_state_with_utxo(cfg, 60, op_a, prev_a);
  parent.utxos[op_b] = UtxoEntry{prev_b};
  parent.state_commitment = consensus::consensus_state_commitment(cfg, parent);

  const std::vector<Bytes> ordered{
      raw_signed_spend(op_a, prev_a, from_a, to.public_key, 9'900),
      raw_signed_spend(op_b, prev_b, from_b, to.public_key, 11'800),
  };

  const auto a = make_frontier_record(parent, ordered);
  const auto b = make_frontier_record(parent, ordered);
  ASSERT_EQ(a.transition.settlement.serialize(), b.transition.settlement.serialize());
  ASSERT_EQ(a.transition.settlement_commitment, b.transition.settlement_commitment);
}

TEST(test_frontier_replay_rejects_tampered_settlement_commitment) {
  const auto cfg = test_cfg();
  const auto from = key_from_byte(27);
  const auto to = key_from_byte(28);

  OutPoint op{};
  op.txid.fill(0x93);
  op.index = 0;
  const auto prev = p2pkh_out_for_pub(from.public_key, 10'000);
  const auto parent = build_parent_state_with_utxo(cfg, 61, op, prev);

  auto record = make_frontier_record(parent, {raw_signed_spend(op, prev, from, to.public_key, 9'900)});
  record.transition.settlement_commitment[0] ^= 0x01;

  consensus::CanonicalDerivedState out;
  std::string err;
  ASSERT_TRUE(!consensus::derive_canonical_state_from_frontier_chain(cfg, parent, {record}, &out, &err));
}

TEST(test_frontier_replay_rejects_tampered_ingress_commitment) {
  const auto cfg = test_cfg();
  const auto from = key_from_byte(41);
  const auto to = key_from_byte(42);

  OutPoint op{};
  op.txid.fill(0x95);
  op.index = 0;
  const auto prev = p2pkh_out_for_pub(from.public_key, 10'000);
  const auto parent = build_parent_state_with_utxo(cfg, 61, op, prev);

  auto record = make_frontier_record(parent, {raw_signed_spend(op, prev, from, to.public_key, 9'900)});
  record.transition.ingress_commitment[0] ^= 0x01;

  consensus::CanonicalDerivedState out;
  std::string err;
  ASSERT_TRUE(!consensus::derive_canonical_state_from_frontier_chain(cfg, parent, {record}, &out, &err));
}

TEST(test_frontier_replay_advances_finalized_metadata_deterministically) {
  const auto cfg = test_cfg();
  const auto from = key_from_byte(29);
  const auto to = key_from_byte(30);

  OutPoint op{};
  op.txid.fill(0x94);
  op.index = 0;
  const auto prev = p2pkh_out_for_pub(from.public_key, 10'000);
  const auto parent = build_parent_state_with_utxo(cfg, 62, op, prev);

  const auto record = make_frontier_record(parent, {raw_signed_spend(op, prev, from, to.public_key, 9'900)});
  consensus::CanonicalDerivedState out;
  std::string err;
  ASSERT_TRUE(consensus::derive_canonical_state_from_frontier_chain(cfg, parent, {record}, &out, &err));
  ASSERT_EQ(out.finalized_height, 1u);
  ASSERT_EQ(out.finalized_frontier, record.transition.next_frontier);
  ASSERT_TRUE(out.finalized_identity.is_transition());
  ASSERT_EQ(out.finalized_identity.id, record.transition.transition_id());
  ASSERT_EQ(out.last_finality_certificate_hash, consensus::frontier_finality_link_hash(record.transition));
  ASSERT_TRUE(out.finalized_randomness != parent.finalized_randomness);
  auto meta_it = out.finalized_block_metadata.find(1);
  ASSERT_TRUE(meta_it != out.finalized_block_metadata.end());
  ASSERT_EQ(meta_it->second.round, record.transition.round);
  ASSERT_EQ(meta_it->second.quorum_threshold, record.transition.quorum_threshold);
  ASSERT_EQ(meta_it->second.signature_count, record.transition.observed_signers.size());
  ASSERT_TRUE(out.epoch_reward_states.find(1) != out.epoch_reward_states.end());
}

TEST(test_frontier_replay_rejects_block_artifact_parent_kind_after_genesis) {
  const auto cfg = test_cfg();
  const auto from = key_from_byte(31);
  const auto to = key_from_byte(32);

  OutPoint op{};
  op.txid.fill(0x95);
  op.index = 0;
  const auto prev = p2pkh_out_for_pub(from.public_key, 10'000);
  auto parent = build_parent_state_with_utxo(cfg, 62, op, prev);
  parent.finalized_height = 3;
  Hash32 wrong_parent{};
  wrong_parent.fill(0x51);
  parent.finalized_identity = consensus::FinalizedIdentity::genesis(wrong_parent);
  parent.state_commitment = consensus::consensus_state_commitment(cfg, parent);

  const auto record = make_frontier_record(parent, {raw_signed_spend(op, prev, from, to.public_key, 9'900)});
  consensus::CanonicalDerivedState out;
  std::string err;
  ASSERT_TRUE(!consensus::derive_canonical_state_from_frontier_chain(cfg, parent, {record}, &out, &err));
  ASSERT_EQ(err, "frontier-parent-identity-kind-mismatch");
}

TEST(test_consensus_state_commitment_intentionally_ignores_finalized_identity_kind) {
  const auto cfg = test_cfg();
  const auto owner = key_from_byte(33);

  OutPoint op{};
  op.txid.fill(0xa1);
  op.index = 0;
  const auto prev = p2pkh_out_for_pub(owner.public_key, 10'000);
  auto state = build_parent_state_with_utxo(cfg, 0, op, prev);

  Hash32 shared_id{};
  shared_id.fill(0x5a);
  state.finalized_height = 3;
  state.finalized_identity = consensus::FinalizedIdentity::genesis(shared_id);
  const auto block_commitment = consensus::consensus_state_commitment(cfg, state);

  state.finalized_identity = consensus::FinalizedIdentity::transition(shared_id);
  const auto transition_commitment = consensus::consensus_state_commitment(cfg, state);

  ASSERT_EQ(block_commitment, transition_commitment);
}

TEST(test_frontier_storage_replay_reproduces_identical_state_on_restart) {
  const auto cfg = test_cfg();
  const auto from_a = key_from_byte(17);
  const auto from_b = key_from_byte(18);
  const auto to = key_from_byte(19);

  OutPoint op_a{};
  op_a.txid.fill(0x71);
  op_a.index = 0;
  OutPoint op_b{};
  op_b.txid.fill(0x72);
  op_b.index = 0;
  const auto prev_a = p2pkh_out_for_pub(from_a.public_key, 10'000);
  const auto prev_b = p2pkh_out_for_pub(from_b.public_key, 10'000);
  auto parent = build_parent_state_with_utxo(cfg, 30, op_a, prev_a);
  parent.utxos[op_b] = UtxoEntry{prev_b};
  parent.state_commitment = consensus::consensus_state_commitment(cfg, parent);

  const std::string path = unique_test_base("/tmp/finalis_test_frontier_storage_replay_db");
  std::filesystem::remove_all(path);
  storage::DB db;
  ASSERT_TRUE(db.open(path));

  const Bytes record_a = raw_signed_spend(op_a, prev_a, from_a, to.public_key, 9'900);
  const Bytes record_b = raw_signed_spend(op_b, prev_b, from_b, to.public_key, 9'850);
  const auto chain_record = make_frontier_record(parent, {record_a, record_b});
  persist_lane_state_seed(db, parent);
  persist_lane_records(db, chain_record);
  persist_frontier_record_with_certificate(cfg, parent, db, 1, chain_record);
  ASSERT_TRUE(db.set_finalized_frontier_height(1));

  consensus::CanonicalDerivedState from_chain;
  consensus::CanonicalDerivedState from_storage;
  std::string chain_err;
  std::string storage_err;
  ASSERT_TRUE(consensus::derive_canonical_state_from_frontier_chain(cfg, parent, {chain_record}, &from_chain, &chain_err));
  if (!consensus::derive_canonical_state_from_frontier_storage(cfg, parent, db, &from_storage, &storage_err)) {
    throw std::runtime_error("derive_canonical_state_from_frontier_storage failed: " + storage_err);
  }
  ASSERT_EQ(from_storage.finalized_frontier, from_chain.finalized_frontier);
  ASSERT_EQ(from_storage.state_commitment, from_chain.state_commitment);
  ASSERT_EQ(consensus::frontier_utxo_state_root(from_storage.utxos), consensus::frontier_utxo_state_root(from_chain.utxos));
}

TEST(test_frontier_storage_replay_is_consistent_across_two_nodes_with_same_artifacts) {
  const auto cfg = test_cfg();
  const auto from_a = key_from_byte(31);
  const auto from_b = key_from_byte(32);
  const auto to = key_from_byte(33);

  OutPoint op_a{};
  op_a.txid.fill(0xA1);
  op_a.index = 0;
  OutPoint op_b{};
  op_b.txid.fill(0xA2);
  op_b.index = 0;
  const auto prev_a = p2pkh_out_for_pub(from_a.public_key, 10'000);
  const auto prev_b = p2pkh_out_for_pub(from_b.public_key, 12'000);
  auto parent = build_parent_state_with_utxo(cfg, 70, op_a, prev_a);
  parent.utxos[op_b] = UtxoEntry{prev_b};
  parent.state_commitment = consensus::consensus_state_commitment(cfg, parent);

  const Bytes record_a = raw_signed_spend(op_a, prev_a, from_a, to.public_key, 9'900);
  const Bytes record_b = raw_signed_spend(op_b, prev_b, from_b, to.public_key, 11'750);
  const auto frontier_record = make_frontier_record(parent, {record_a, record_b});

  const std::string path_a = unique_test_base("/tmp/finalis_test_frontier_storage_node_a");
  const std::string path_b = unique_test_base("/tmp/finalis_test_frontier_storage_node_b");
  std::filesystem::remove_all(path_a);
  std::filesystem::remove_all(path_b);

  storage::DB db_a;
  storage::DB db_b;
  ASSERT_TRUE(db_a.open(path_a));
  ASSERT_TRUE(db_b.open(path_b));

  for (storage::DB* db : {&db_a, &db_b}) {
    persist_lane_state_seed(*db, parent);
    persist_lane_records(*db, frontier_record);
    persist_frontier_record_with_certificate(cfg, parent, *db, 1, frontier_record);
    ASSERT_TRUE(db->set_finalized_frontier_height(1));
  }

  consensus::CanonicalDerivedState state_a;
  consensus::CanonicalDerivedState state_b;
  std::string err_a;
  std::string err_b;
  if (!consensus::derive_canonical_state_from_frontier_storage(cfg, parent, db_a, &state_a, &err_a)) {
    throw std::runtime_error("derive_canonical_state_from_frontier_storage db_a failed: " + err_a);
  }
  if (!consensus::derive_canonical_state_from_frontier_storage(cfg, parent, db_b, &state_b, &err_b)) {
    throw std::runtime_error("derive_canonical_state_from_frontier_storage db_b failed: " + err_b);
  }
  ASSERT_EQ(state_a.finalized_identity.kind, state_b.finalized_identity.kind);
  ASSERT_EQ(state_a.finalized_identity.id, state_b.finalized_identity.id);
  ASSERT_EQ(state_a.finalized_frontier, state_b.finalized_frontier);
  ASSERT_EQ(state_a.state_commitment, state_b.state_commitment);
  ASSERT_EQ(consensus::frontier_utxo_state_root(state_a.utxos), consensus::frontier_utxo_state_root(state_b.utxos));
}

TEST(test_frontier_storage_replay_fails_closed_when_ingress_record_is_missing) {
  const auto cfg = test_cfg();
  const auto from = key_from_byte(20);
  const auto to = key_from_byte(21);

  OutPoint op{};
  op.txid.fill(0x81);
  op.index = 0;
  const auto prev = p2pkh_out_for_pub(from.public_key, 10'000);
  const auto parent = build_parent_state_with_utxo(cfg, 40, op, prev);

  const std::string path = unique_test_base("/tmp/finalis_test_frontier_storage_missing_ingress_db");
  std::filesystem::remove_all(path);
  storage::DB db;
  ASSERT_TRUE(db.open(path));

  const Bytes record = raw_signed_spend(op, prev, from, to.public_key, 9'900);
  const auto chain_record = make_frontier_record(parent, {record});
  persist_lane_state_seed(db, parent);
  persist_frontier_record(db, 1, chain_record);
  ASSERT_TRUE(db.set_finalized_frontier_height(1));

  consensus::CanonicalDerivedState out;
  std::string err;
  ASSERT_TRUE(!consensus::derive_canonical_state_from_frontier_storage(cfg, parent, db, &out, &err));
}

TEST(test_frontier_storage_replay_fails_closed_when_lane_tip_is_too_low) {
  const auto cfg = test_cfg();
  const auto from = key_from_byte(34);
  const auto to = key_from_byte(35);

  OutPoint op{};
  op.txid.fill(0x83);
  op.index = 0;
  const auto prev = p2pkh_out_for_pub(from.public_key, 10'000);
  const auto parent = build_parent_state_with_utxo(cfg, 40, op, prev);

  const std::string path = unique_test_base("/tmp/finalis_test_frontier_storage_low_ingress_tip_db");
  std::filesystem::remove_all(path);
  storage::DB db;
  ASSERT_TRUE(db.open(path));

  const Bytes record = raw_signed_spend(op, prev, from, to.public_key, 9'900);
  const auto chain_record = make_frontier_record(parent, {record});
  persist_lane_state_seed(db, parent);
  auto lane = std::find_if(chain_record.lane_records.begin(), chain_record.lane_records.end(),
                           [](const auto& records) { return !records.empty(); });
  ASSERT_TRUE(lane != chain_record.lane_records.end());
  const auto lane_index = static_cast<std::uint32_t>(std::distance(chain_record.lane_records.begin(), lane));
  LaneState low_tip;
  low_tip.epoch = 0;
  low_tip.lane = lane_index;
  low_tip.max_seq = chain_record.transition.next_vector.lane_max_seq[lane_index] - 1;
  low_tip.lane_root = parent.finalized_lane_roots[lane_index];
  ASSERT_TRUE(db.put_lane_state(lane_index, low_tip));
  persist_frontier_record(db, 1, chain_record);
  ASSERT_TRUE(db.set_finalized_frontier_height(1));

  consensus::CanonicalDerivedState out;
  std::string err;
  ASSERT_TRUE(!consensus::derive_canonical_state_from_frontier_storage(cfg, parent, db, &out, &err));
}

TEST(test_frontier_storage_replay_fails_closed_when_ingress_records_are_reordered) {
  const auto cfg = test_cfg();
  const auto from_a = key_from_byte(36);
  const auto from_b = key_from_byte(37);
  const auto to = key_from_byte(38);

  OutPoint op_a{};
  op_a.txid.fill(0x84);
  op_a.index = 0;
  OutPoint op_b{};
  op_b.txid.fill(0x85);
  op_b.index = 0;
  const auto prev_a = p2pkh_out_for_pub(from_a.public_key, 10'000);
  const auto prev_b = p2pkh_out_for_pub(from_b.public_key, 12'000);
  auto parent = build_parent_state_with_utxo(cfg, 50, op_a, prev_a);
  parent.utxos[op_b] = UtxoEntry{prev_b};
  parent.state_commitment = consensus::consensus_state_commitment(cfg, parent);

  const Bytes record_a = raw_signed_spend(op_a, prev_a, from_a, to.public_key, 9'900);
  const Bytes record_b = raw_signed_spend(op_b, prev_b, from_b, to.public_key, 11'700);
  const auto chain_record = make_frontier_record(parent, {record_a, record_b});

  const std::string path = unique_test_base("/tmp/finalis_test_frontier_storage_reordered_ingress_db");
  std::filesystem::remove_all(path);
  storage::DB db;
  ASSERT_TRUE(db.open(path));
  persist_lane_state_seed(db, parent);
  auto tampered = chain_record.lane_records;
  bool rewrote = false;
  for (auto& lane_records : tampered) {
    if (!lane_records.empty()) {
      lane_records[0].certificate.prev_lane_root[0] ^= 0x01;
      ASSERT_TRUE(db.put_ingress_bytes(lane_records[0].certificate.txid, lane_records[0].tx_bytes));
      ASSERT_TRUE(db.put_ingress_certificate(lane_records[0].certificate.lane, lane_records[0].certificate.seq,
                                             lane_records[0].certificate.serialize()));
      rewrote = true;
      break;
    }
  }
  ASSERT_TRUE(rewrote);
  persist_frontier_record(db, 1, chain_record);
  ASSERT_TRUE(db.set_finalized_frontier_height(1));

  consensus::CanonicalDerivedState out;
  std::string err;
  ASSERT_TRUE(!consensus::derive_canonical_state_from_frontier_storage(cfg, parent, db, &out, &err));
}

TEST(test_frontier_storage_replay_fails_closed_when_ingress_record_is_corrupted) {
  const auto cfg = test_cfg();
  const auto from = key_from_byte(39);
  const auto to = key_from_byte(40);

  OutPoint op{};
  op.txid.fill(0x86);
  op.index = 0;
  const auto prev = p2pkh_out_for_pub(from.public_key, 10'000);
  const auto parent = build_parent_state_with_utxo(cfg, 60, op, prev);

  const Bytes record = raw_signed_spend(op, prev, from, to.public_key, 9'900);
  const auto chain_record = make_frontier_record(parent, {record});

  const std::string path = unique_test_base("/tmp/finalis_test_frontier_storage_corrupt_ingress_db");
  std::filesystem::remove_all(path);
  storage::DB db;
  ASSERT_TRUE(db.open(path));
  persist_lane_state_seed(db, parent);
  bool corrupted = false;
  for (const auto& lane : chain_record.lane_records) {
    if (!lane.empty()) {
      Bytes corrupt = lane[0].tx_bytes;
      corrupt[0] ^= 0x01;
      ASSERT_TRUE(db.put_ingress_bytes(lane[0].certificate.txid, corrupt));
      ASSERT_TRUE(db.put_ingress_certificate(lane[0].certificate.lane, lane[0].certificate.seq,
                                             lane[0].certificate.serialize()));
      corrupted = true;
      break;
    }
  }
  ASSERT_TRUE(corrupted);
  persist_frontier_record(db, 1, chain_record);
  ASSERT_TRUE(db.set_finalized_frontier_height(1));

  consensus::CanonicalDerivedState out;
  std::string err;
  ASSERT_TRUE(!consensus::derive_canonical_state_from_frontier_storage(cfg, parent, db, &out, &err));
}

TEST(test_frontier_storage_replay_rejects_tampered_transition_bytes) {
  const auto cfg = test_cfg();
  const auto from = key_from_byte(22);
  const auto to = key_from_byte(23);

  OutPoint op{};
  op.txid.fill(0x82);
  op.index = 0;
  const auto prev = p2pkh_out_for_pub(from.public_key, 10'000);
  const auto parent = build_parent_state_with_utxo(cfg, 50, op, prev);

  const std::string path = unique_test_base("/tmp/finalis_test_frontier_storage_tampered_transition_db");
  std::filesystem::remove_all(path);
  storage::DB db;
  ASSERT_TRUE(db.open(path));

  const Bytes record = raw_signed_spend(op, prev, from, to.public_key, 9'900);
  auto chain_record = make_frontier_record(parent, {record});
  persist_lane_state_seed(db, parent);
  persist_lane_records(db, chain_record);
  auto tampered_transition = chain_record.transition;
  tampered_transition.next_state_root[0] ^= 0x01;
  ASSERT_TRUE(db.put_frontier_transition(chain_record.transition.transition_id(), tampered_transition.serialize()));
  ASSERT_TRUE(db.map_height_to_frontier_transition(1, chain_record.transition.transition_id()));
  ASSERT_TRUE(db.set_finalized_frontier_height(1));

  consensus::CanonicalDerivedState out;
  std::string err;
  ASSERT_TRUE(!consensus::derive_canonical_state_from_frontier_storage(cfg, parent, db, &out, &err));
}

TEST(test_live_validator_membership_state_mid_epoch_is_only_committee_eligible_after_next_epoch_checkpoint) {
  const auto cfg = live_activation_cfg();
  const auto bootstrap = key_from_byte(90);
  const auto joiner = key_from_byte(91);

  consensus::CanonicalGenesisState genesis;
  genesis.genesis_artifact_id = zero_hash();
  genesis.initial_validators.push_back(bootstrap.public_key);

  consensus::CanonicalDerivedState state;
  std::string err;
  ASSERT_TRUE(consensus::build_genesis_canonical_state(cfg, genesis, &state, &err));

  state.finalized_height = 2;
  state.validators.set_rules(
      consensus::ValidatorRules{.min_bond = live_adaptive_test_bond(),
                                .warmup_blocks = 1,
                                .cooldown_blocks = cfg.validator_cooldown_blocks});
  ASSERT_TRUE(state.validators.register_bond(joiner.public_key, OutPoint{Hash32{}, 7}, 2, live_adaptive_test_bond(), &err,
                                             joiner.public_key));
  state.validators.advance_height(3);
  ASSERT_TRUE(state.validators.is_active_for_height(joiner.public_key, 3));

  const auto committee_h3 = consensus::canonical_committee_for_height_round(cfg, state, 3, 0);
  ASSERT_TRUE(std::find(committee_h3.begin(), committee_h3.end(), joiner.public_key) == committee_h3.end());
  const auto committee_h4 = consensus::canonical_committee_for_height_round(cfg, state, 4, 0);
  ASSERT_TRUE(std::find(committee_h4.begin(), committee_h4.end(), joiner.public_key) == committee_h4.end());

  state.committee_epoch_randomness_cache[5] = state.finalized_randomness;
  storage::FinalizedCommitteeCheckpoint checkpoint;
  ASSERT_TRUE(consensus::derive_next_epoch_checkpoint_from_state(cfg, state, 5, &checkpoint, &err));
  state.finalized_committee_checkpoints[5] = checkpoint;

  const auto committee_h5 = consensus::canonical_committee_for_height_round(cfg, state, 5, 0);
  ASSERT_TRUE(std::find(committee_h5.begin(), committee_h5.end(), joiner.public_key) == committee_h5.end());
}

TEST(test_live_validator_membership_state_on_epoch_edge_has_single_canonical_activation_boundary) {
  const auto cfg = live_activation_cfg();
  const auto bootstrap = key_from_byte(93);
  const auto joiner = key_from_byte(94);

  consensus::CanonicalGenesisState genesis;
  genesis.genesis_artifact_id = zero_hash();
  genesis.initial_validators.push_back(bootstrap.public_key);

  consensus::CanonicalDerivedState state;
  std::string err;
  ASSERT_TRUE(consensus::build_genesis_canonical_state(cfg, genesis, &state, &err));

  state.finalized_height = 4;
  state.validators.set_rules(
      consensus::ValidatorRules{.min_bond = live_adaptive_test_bond(),
                                .warmup_blocks = 1,
                                .cooldown_blocks = cfg.validator_cooldown_blocks});
  ASSERT_TRUE(state.validators.register_bond(joiner.public_key, OutPoint{Hash32{}, 8}, 4, live_adaptive_test_bond(), &err,
                                             joiner.public_key));
  state.validators.advance_height(5);
  ASSERT_TRUE(state.validators.is_active_for_height(joiner.public_key, 5));

  state.committee_epoch_randomness_cache[5] = state.finalized_randomness;
  storage::FinalizedCommitteeCheckpoint checkpoint_a;
  ASSERT_TRUE(consensus::derive_next_epoch_checkpoint_from_state(cfg, state, 5, &checkpoint_a, &err));
  ASSERT_TRUE(std::find(checkpoint_a.ordered_members.begin(), checkpoint_a.ordered_members.end(), joiner.public_key) ==
              checkpoint_a.ordered_members.end());

  consensus::CanonicalDerivedState replayed = state;
  storage::FinalizedCommitteeCheckpoint checkpoint_b;
  ASSERT_TRUE(consensus::derive_next_epoch_checkpoint_from_state(cfg, replayed, 5, &checkpoint_b, &err));
  ASSERT_EQ(checkpoint_a.ordered_members, checkpoint_b.ordered_members);
  ASSERT_EQ(checkpoint_a.ordered_operator_ids, checkpoint_b.ordered_operator_ids);
  ASSERT_EQ(checkpoint_a.ordered_final_weights, checkpoint_b.ordered_final_weights);
}

TEST(test_frontier_lane_prefix_rejects_stale_ingress_epoch_with_context) {
  auto cfg = test_cfg();
  cfg.network.committee_epoch_blocks = 4;

  const auto from = key_from_byte(110);
  const auto to = key_from_byte(111);
  OutPoint op{};
  op.txid.fill(0xA1);
  op.index = 0;
  auto parent_state = build_parent_state_with_utxo(cfg, 0, op, p2pkh_out_for_pub(from.public_key, 10'000));
  parent_state.finalized_height = 4;

  const auto raw = raw_signed_spend(op, p2pkh_out_for_pub(from.public_key, 10'000), from, to.public_key, 9'800);
  FrontierVector next_vector;
  auto lane_records = make_lane_records(parent_state, {raw}, &next_vector);

  SpecialValidationContext ctx;
  ctx.network = &cfg.network;
  ctx.current_height = 5;

  consensus::FrontierExecutionResult result;
  std::string err;
  ASSERT_TRUE(!consensus::execute_frontier_lane_prefix(parent_state.utxos, parent_state.finalized_frontier_vector,
                                                       next_vector, lane_records, parent_state.finalized_lane_roots,
                                                       &ctx, &result, &err));
  ASSERT_TRUE(err.find("frontier-certified-ingress-epoch-mismatch") != std::string::npos);
}

TEST(test_frontier_apply_updates_validator_state_for_txv2_onboarding_output) {
  auto cfg = live_activation_cfg();
  cfg.confidential_policy.activation_height = 0;

  const auto from = key_from_byte(0xA2);
  const auto validator = key_from_byte(0xA3);
  const auto payout = key_from_byte(0xA4);

  OutPoint op{};
  op.txid.fill(0xB1);
  op.index = 0;
  auto parent_state = build_parent_state_with_utxo(cfg, 0, op, p2pkh_out_for_pub(from.public_key, 10'000));

  const auto pop = crypto::ed25519_sign(onboarding_registration_pop_message(validator.public_key, payout.public_key),
                                        validator.private_key);
  ASSERT_TRUE(pop.has_value());

  std::vector<TxOutV2> outputs;
  outputs.push_back(TxOutV2{.kind = TxOutputKind::Transparent,
                            .body = TransparentTxOutV2{0,
                                                       onboarding_registration_script(validator.public_key,
                                                                                      payout.public_key, *pop)}});
  outputs.push_back(TxOutV2{.kind = TxOutputKind::Transparent,
                            .body = TransparentTxOutV2{9'500, p2pkh_script_for_pub(payout.public_key)}});
  const auto raw = raw_signed_spend_v2_with_outputs(op, from, outputs, 500);

  SpecialValidationContext vctx;
  vctx.network = &cfg.network;
  vctx.current_height = 1;
  vctx.confidential_policy = &cfg.confidential_policy;

  const auto record = make_frontier_record(parent_state, {raw}, cfg, 0, {}, &vctx);

  consensus::CanonicalDerivedState out;
  std::string err;
  ASSERT_TRUE(consensus::apply_frontier_record(cfg, parent_state, record, &out, &err));
  const auto info = out.validators.get(validator.public_key);
  ASSERT_TRUE(info.has_value());
  ASSERT_EQ(info->status, consensus::ValidatorStatus::ONBOARDING);
}

TEST(test_checkpoint_derivation_ignores_below_difficulty_ticket_hashes) {
  auto cfg = live_activation_cfg();
  cfg.max_committee = 5;

  consensus::CanonicalGenesisState genesis;
  genesis.genesis_artifact_id = zero_hash();
  const auto v0 = key_from_byte(101);
  const auto v1 = key_from_byte(102);
  const auto v2 = key_from_byte(103);
  const auto v3 = key_from_byte(104);
  const auto v4 = key_from_byte(105);
  genesis.initial_validators = {v0.public_key, v1.public_key, v2.public_key, v3.public_key, v4.public_key};

  consensus::CanonicalDerivedState state;
  std::string err;
  ASSERT_TRUE(consensus::build_genesis_canonical_state(cfg, genesis, &state, &err));
  state.finalized_height = 4;
  state.finalized_committee_checkpoints[1].ticket_difficulty_bits = 12;

  bool found_nonqualifying_selected_member = false;
  for (std::uint8_t seed_b = 1; seed_b < 64 && !found_nonqualifying_selected_member; ++seed_b) {
    Hash32 epoch_randomness{};
    epoch_randomness.fill(seed_b);
    state.committee_epoch_randomness_cache[5] = epoch_randomness;

    storage::FinalizedCommitteeCheckpoint checkpoint;
    ASSERT_TRUE(consensus::derive_next_epoch_checkpoint_from_state(cfg, state, 5, &checkpoint, &err));
    ASSERT_EQ(checkpoint.ticket_difficulty_bits, 12u);

    for (std::size_t i = 0; i < checkpoint.ordered_members.size(); ++i) {
      const auto operator_id = i < checkpoint.ordered_operator_ids.size() ? checkpoint.ordered_operator_ids[i]
                                                                          : checkpoint.ordered_members[i];
      const auto ticket = consensus::best_epoch_ticket_for_operator_id(5, checkpoint.epoch_seed, operator_id, 5,
                                                                       consensus::EPOCH_TICKET_MAX_NONCE);
      ASSERT_TRUE(ticket.has_value());
      if (consensus::epoch_ticket_meets_difficulty(*ticket, checkpoint.ticket_difficulty_bits)) continue;

      ASSERT_EQ(checkpoint.ordered_ticket_bonus_bps[i], 0u);
      ASSERT_EQ(checkpoint.ordered_ticket_hashes[i], Hash32{});
      ASSERT_EQ(checkpoint.ordered_ticket_nonces[i], 0u);
      found_nonqualifying_selected_member = true;
      break;
    }
  }

  ASSERT_TRUE(found_nonqualifying_selected_member);
}

TEST(test_adaptive_committee_target_tracks_qualified_depth_staircase) {
  ASSERT_EQ(consensus::derive_adaptive_checkpoint_parameters(std::nullopt, 1).target_committee_size, 1u);
  ASSERT_EQ(consensus::derive_adaptive_checkpoint_parameters(std::nullopt, 2).target_committee_size, 2u);
  ASSERT_EQ(consensus::derive_adaptive_checkpoint_parameters(std::nullopt, 3).target_committee_size, 3u);
  ASSERT_EQ(consensus::derive_adaptive_checkpoint_parameters(std::nullopt, 4).target_committee_size, 4u);
  ASSERT_EQ(consensus::derive_adaptive_checkpoint_parameters(std::nullopt, 6).target_committee_size, 4u);
  ASSERT_EQ(consensus::derive_adaptive_checkpoint_parameters(std::nullopt, 7).target_committee_size, 7u);
  ASSERT_EQ(consensus::derive_adaptive_checkpoint_parameters(std::nullopt, 10).target_committee_size, 7u);
  ASSERT_EQ(consensus::derive_adaptive_checkpoint_parameters(std::nullopt, 11).target_committee_size, 10u);
  ASSERT_EQ(consensus::derive_adaptive_checkpoint_parameters(std::nullopt, 16).target_committee_size, 10u);
  ASSERT_EQ(consensus::derive_adaptive_checkpoint_parameters(std::nullopt, 17).target_committee_size, 16u);
  ASSERT_EQ(consensus::derive_adaptive_checkpoint_parameters(std::nullopt, 24).target_committee_size, 16u);
  ASSERT_EQ(consensus::derive_adaptive_checkpoint_parameters(std::nullopt, 25).target_committee_size, 24u);
  ASSERT_EQ(consensus::derive_adaptive_checkpoint_parameters(std::nullopt, 30).target_committee_size, 27u);
}

TEST(test_adaptive_committee_target_is_stateless_for_same_qualified_depth) {
  const auto baseline = consensus::derive_adaptive_checkpoint_parameters(std::nullopt, 22);
  auto previous = checkpoint_with_adaptive(storage::FinalizedCommitteeDerivationMode::NORMAL, baseline);
  for (std::size_t i = 0; i < 5; ++i) {
    const auto next = consensus::derive_adaptive_checkpoint_parameters(previous, 22);
    ASSERT_EQ(next.target_committee_size, baseline.target_committee_size);
    ASSERT_EQ(next.min_eligible_operators, baseline.min_eligible_operators);
    ASSERT_EQ(next.target_expand_streak, 0u);
    ASSERT_EQ(next.target_contract_streak, 0u);
    previous = checkpoint_with_adaptive(storage::FinalizedCommitteeDerivationMode::NORMAL, next);
  }
}

TEST(test_adaptive_committee_target_reacts_immediately_to_depth_changes) {
  const auto first = consensus::derive_adaptive_checkpoint_parameters(std::nullopt, 3);
  ASSERT_EQ(first.target_committee_size, 3u);
  auto previous = checkpoint_with_adaptive(storage::FinalizedCommitteeDerivationMode::NORMAL, first);
  const auto second = consensus::derive_adaptive_checkpoint_parameters(previous, 7);
  ASSERT_EQ(second.target_committee_size, 7u);
  previous = checkpoint_with_adaptive(storage::FinalizedCommitteeDerivationMode::NORMAL, second);
  const auto third = consensus::derive_adaptive_checkpoint_parameters(previous, 2);
  ASSERT_EQ(third.target_committee_size, 2u);
  ASSERT_EQ(third.target_expand_streak, 0u);
  ASSERT_EQ(third.target_contract_streak, 0u);
}

TEST(test_adaptive_min_eligible_and_min_bond_rules_are_deterministic) {
  ASSERT_EQ(consensus::derive_adaptive_min_eligible(1), 1u);
  ASSERT_EQ(consensus::derive_adaptive_min_eligible(3), 3u);
  ASSERT_EQ(consensus::derive_adaptive_min_eligible(16), 16u);
  ASSERT_EQ(consensus::derive_adaptive_min_bond(16, 1), 150ULL * consensus::BASE_UNITS_PER_COIN);
  ASSERT_EQ(consensus::derive_adaptive_min_bond(3, 3), 150ULL * consensus::BASE_UNITS_PER_COIN);
  ASSERT_EQ(consensus::derive_adaptive_min_bond(24, 24), 150ULL * consensus::BASE_UNITS_PER_COIN);
  ASSERT_EQ(consensus::derive_adaptive_min_bond(24, 400), 150ULL * consensus::BASE_UNITS_PER_COIN);
}

TEST(test_qualified_depth_counts_only_lifecycle_bond_and_availability_qualified_operators) {
  auto cfg = live_activation_cfg();
  auto availability_cfg = consensus::availability_config_with_min_bond(cfg.availability, live_adaptive_test_bond());
  consensus::ValidatorRegistry validators;
  validators.set_rules(
      consensus::ValidatorRules{.min_bond = live_adaptive_test_bond(), .warmup_blocks = 0, .cooldown_blocks = 0});
  const auto active = key_from_byte(0xA0);
  const auto warmup = key_from_byte(0xA1);
  const auto inactive = key_from_byte(0xA2);
  std::string err;
  ASSERT_TRUE(validators.register_bond(active.public_key, OutPoint{Hash32{1}, 0}, 0, live_adaptive_test_bond(), &err,
                                       active.public_key));
  ASSERT_TRUE(validators.register_bond(warmup.public_key, OutPoint{Hash32{2}, 0}, 0, live_adaptive_test_bond(), &err,
                                       warmup.public_key));
  ASSERT_TRUE(validators.register_bond(inactive.public_key, OutPoint{Hash32{3}, 0}, 5, live_adaptive_test_bond(), &err,
                                       inactive.public_key));
  validators.advance_height(1);

  availability::AvailabilityPersistentState availability_state;
  availability_state.operators = {
      availability::AvailabilityOperatorState{
          .operator_pubkey = active.public_key,
          .bond = live_adaptive_test_bond(),
          .status = availability::AvailabilityOperatorStatus::ACTIVE,
          .successful_audits = 1,
          .warmup_epochs = 1,
          .retained_prefix_count = 1,
      },
      availability::AvailabilityOperatorState{
          .operator_pubkey = warmup.public_key,
          .bond = live_adaptive_test_bond(),
          .status = availability::AvailabilityOperatorStatus::WARMUP,
      },
      availability::AvailabilityOperatorState{
          .operator_pubkey = inactive.public_key,
          .bond = live_adaptive_test_bond(),
          .status = availability::AvailabilityOperatorStatus::ACTIVE,
          .successful_audits = 1,
          .warmup_epochs = 1,
          .retained_prefix_count = 1,
      },
  };
  ASSERT_EQ(consensus::qualified_depth_at_checkpoint(validators, 1, live_adaptive_test_bond(), availability_state,
                                                     availability_cfg),
            1u);
}

TEST(test_adaptive_checkpoint_metadata_is_replay_equivalent) {
  auto cfg = live_activation_cfg();
  const auto bootstrap = key_from_byte(0xB0);
  const auto second = key_from_byte(0xB1);

  consensus::CanonicalGenesisState genesis;
  genesis.genesis_artifact_id = zero_hash();
  genesis.initial_validators.push_back(bootstrap.public_key);

  consensus::CanonicalDerivedState state;
  std::string err;
  ASSERT_TRUE(consensus::build_genesis_canonical_state(cfg, genesis, &state, &err));
  state.validators.set_rules(
      consensus::ValidatorRules{.min_bond = live_adaptive_test_bond(), .warmup_blocks = 0, .cooldown_blocks = 0});
  ASSERT_TRUE(state.validators.register_bond(second.public_key, OutPoint{Hash32{6}, 0}, 0, live_adaptive_test_bond(), &err,
                                             second.public_key));
  state.validators.advance_height(1);
  state.committee_epoch_randomness_cache[5] = state.finalized_randomness;
  state.availability_state.operators = {
      availability::AvailabilityOperatorState{
          .operator_pubkey = bootstrap.public_key,
          .bond = live_adaptive_test_bond(),
          .status = availability::AvailabilityOperatorStatus::ACTIVE,
          .successful_audits = 1,
          .warmup_epochs = 1,
          .retained_prefix_count = 1,
      },
      availability::AvailabilityOperatorState{
          .operator_pubkey = second.public_key,
          .bond = live_adaptive_test_bond(),
          .status = availability::AvailabilityOperatorStatus::ACTIVE,
          .successful_audits = 1,
          .warmup_epochs = 1,
          .retained_prefix_count = 1,
      },
  };

  storage::FinalizedCommitteeCheckpoint checkpoint_a;
  storage::FinalizedCommitteeCheckpoint checkpoint_b;
  ASSERT_TRUE(consensus::derive_next_epoch_checkpoint_from_state(cfg, state, 5, &checkpoint_a, &err));
  auto replayed = state;
  ASSERT_TRUE(consensus::derive_next_epoch_checkpoint_from_state(cfg, replayed, 5, &checkpoint_b, &err));
  ASSERT_EQ(checkpoint_a.adaptive_target_committee_size, checkpoint_b.adaptive_target_committee_size);
  ASSERT_EQ(checkpoint_a.adaptive_min_eligible, checkpoint_b.adaptive_min_eligible);
  ASSERT_EQ(checkpoint_a.adaptive_min_bond, checkpoint_b.adaptive_min_bond);
  ASSERT_EQ(checkpoint_a.qualified_depth, checkpoint_b.qualified_depth);
  ASSERT_EQ(checkpoint_a.target_expand_streak, checkpoint_b.target_expand_streak);
  ASSERT_EQ(checkpoint_a.target_contract_streak, checkpoint_b.target_contract_streak);
}

TEST(test_live_bporeligibility_filters_future_committee_checkpoint_membership) {
  const auto cfg = live_activation_cfg();
  const auto bootstrap = key_from_byte(96);
  const auto warmup = key_from_byte(97);
  const auto probation = key_from_byte(98);
  const auto ejected = key_from_byte(99);

  consensus::CanonicalGenesisState genesis;
  genesis.genesis_artifact_id = zero_hash();
  genesis.initial_validators.push_back(bootstrap.public_key);

  consensus::CanonicalDerivedState state;
  std::string err;
  ASSERT_TRUE(consensus::build_genesis_canonical_state(cfg, genesis, &state, &err));

  state.validators.set_rules(consensus::ValidatorRules{.min_bond = 1, .warmup_blocks = 0, .cooldown_blocks = 0});
  ASSERT_TRUE(state.validators.register_bond(warmup.public_key, OutPoint{Hash32{1}, 0}, 0, 100, &err, warmup.public_key));
  ASSERT_TRUE(state.validators.register_bond(probation.public_key, OutPoint{Hash32{2}, 0}, 0, 100, &err, probation.public_key));
  ASSERT_TRUE(state.validators.register_bond(ejected.public_key, OutPoint{Hash32{3}, 0}, 0, 100, &err, ejected.public_key));
  state.validators.advance_height(1);
  state.committee_epoch_randomness_cache[5] = state.finalized_randomness;

  state.availability_state.operators = {
      availability::AvailabilityOperatorState{
          .operator_pubkey = bootstrap.public_key,
          .bond = live_adaptive_test_bond(),
          .status = availability::AvailabilityOperatorStatus::ACTIVE,
          .successful_audits = 1,
          .warmup_epochs = 1,
          .retained_prefix_count = 1,
      },
      availability::AvailabilityOperatorState{
          .operator_pubkey = warmup.public_key,
          .bond = 100,
          .status = availability::AvailabilityOperatorStatus::WARMUP,
      },
      availability::AvailabilityOperatorState{
          .operator_pubkey = probation.public_key,
          .bond = 100,
          .status = availability::AvailabilityOperatorStatus::PROBATION,
      },
      availability::AvailabilityOperatorState{
          .operator_pubkey = ejected.public_key,
          .bond = 100,
          .status = availability::AvailabilityOperatorStatus::EJECTED,
      },
  };

  storage::FinalizedCommitteeCheckpoint checkpoint;
  ASSERT_TRUE(consensus::derive_next_epoch_checkpoint_from_state(cfg, state, 5, &checkpoint, &err));
  ASSERT_EQ(checkpoint.ordered_members.size(), 1u);
  ASSERT_TRUE(std::find(checkpoint.ordered_members.begin(), checkpoint.ordered_members.end(), bootstrap.public_key) !=
              checkpoint.ordered_members.end());
  ASSERT_TRUE(std::find(checkpoint.ordered_members.begin(), checkpoint.ordered_members.end(), warmup.public_key) ==
              checkpoint.ordered_members.end());
  ASSERT_TRUE(std::find(checkpoint.ordered_members.begin(), checkpoint.ordered_members.end(), probation.public_key) ==
              checkpoint.ordered_members.end());
  ASSERT_TRUE(std::find(checkpoint.ordered_members.begin(), checkpoint.ordered_members.end(), ejected.public_key) ==
              checkpoint.ordered_members.end());
  ASSERT_EQ(checkpoint.ordered_operator_ids.size(), 1u);
  ASSERT_EQ(checkpoint.derivation_mode, storage::FinalizedCommitteeDerivationMode::NORMAL);
  ASSERT_EQ(checkpoint.fallback_reason, storage::FinalizedCommitteeFallbackReason::NONE);
  ASSERT_EQ(checkpoint.availability_eligible_operator_count, 1u);
  ASSERT_EQ(checkpoint.availability_min_eligible_operators, 1u);
}

TEST(test_live_bpoar_checkpoint_fallback_mode_is_deterministic_and_explicit) {
  auto cfg = live_activation_cfg();
  cfg.availability_min_eligible_operators = 2;
  const auto bootstrap = key_from_byte(100);
  const auto warmup = key_from_byte(101);

  consensus::CanonicalGenesisState genesis;
  genesis.genesis_artifact_id = zero_hash();
  genesis.initial_validators.push_back(bootstrap.public_key);

  consensus::CanonicalDerivedState state;
  std::string err;
  ASSERT_TRUE(consensus::build_genesis_canonical_state(cfg, genesis, &state, &err));

  state.validators.set_rules(
      consensus::ValidatorRules{.min_bond = live_adaptive_test_bond(), .warmup_blocks = 0, .cooldown_blocks = 0});
  ASSERT_TRUE(state.validators.register_bond(warmup.public_key, OutPoint{Hash32{4}, 0}, 0, live_adaptive_test_bond(), &err,
                                             warmup.public_key));
  state.validators.advance_height(1);
  state.committee_epoch_randomness_cache[5] = state.finalized_randomness;
  state.availability_state.operators = {
      availability::AvailabilityOperatorState{
          .operator_pubkey = bootstrap.public_key,
          .bond = live_adaptive_test_bond(),
          .status = availability::AvailabilityOperatorStatus::ACTIVE,
          .successful_audits = 1,
          .warmup_epochs = 1,
          .retained_prefix_count = 1,
      },
      availability::AvailabilityOperatorState{
          .operator_pubkey = warmup.public_key,
          .bond = live_adaptive_test_bond(),
          .status = availability::AvailabilityOperatorStatus::WARMUP,
      },
  };

  storage::FinalizedCommitteeCheckpoint checkpoint_a;
  ASSERT_TRUE(consensus::derive_next_epoch_checkpoint_from_state(cfg, state, 5, &checkpoint_a, &err));
  storage::FinalizedCommitteeCheckpoint checkpoint_b;
  ASSERT_TRUE(consensus::derive_next_epoch_checkpoint_from_state(cfg, state, 5, &checkpoint_b, &err));

  ASSERT_EQ(checkpoint_a.derivation_mode, storage::FinalizedCommitteeDerivationMode::NORMAL);
  ASSERT_EQ(checkpoint_a.fallback_reason, storage::FinalizedCommitteeFallbackReason::NONE);
  ASSERT_EQ(checkpoint_a.availability_eligible_operator_count, 1u);
  ASSERT_EQ(checkpoint_a.availability_min_eligible_operators, 1u);
  ASSERT_EQ(checkpoint_a.ordered_members, checkpoint_b.ordered_members);
  ASSERT_EQ(checkpoint_a.fallback_reason, checkpoint_b.fallback_reason);
  ASSERT_TRUE(std::find(checkpoint_a.ordered_members.begin(), checkpoint_a.ordered_members.end(), warmup.public_key) ==
              checkpoint_a.ordered_members.end());
}

TEST(test_live_bpoar_checkpoint_fallback_hysteresis_is_sticky_until_recovery_threshold) {
  auto cfg = live_activation_cfg();
  const auto bootstrap = key_from_byte(110);
  std::vector<crypto::KeyPair> operators;
  operators.push_back(bootstrap);
  const auto min_required = consensus::derive_adaptive_min_eligible(4);
  for (std::uint8_t seed = 111; operators.size() < static_cast<std::size_t>(min_required + 1); ++seed) {
    operators.push_back(key_from_byte(seed));
  }

  consensus::CanonicalGenesisState genesis;
  genesis.genesis_artifact_id = zero_hash();
  genesis.initial_validators.push_back(bootstrap.public_key);

  consensus::CanonicalDerivedState state;
  std::string err;
  ASSERT_TRUE(consensus::build_genesis_canonical_state(cfg, genesis, &state, &err));
  state.validators.set_rules(
      consensus::ValidatorRules{.min_bond = live_adaptive_test_bond(), .warmup_blocks = 0, .cooldown_blocks = 0});
  for (std::size_t i = 1; i < operators.size(); ++i) {
    ASSERT_TRUE(state.validators.register_bond(operators[i].public_key, OutPoint{Hash32{static_cast<std::uint8_t>(8 + i)}, 0}, 0,
                                               live_adaptive_test_bond(), &err, operators[i].public_key));
  }
  state.validators.advance_height(1);
  state.committee_epoch_randomness_cache[5] = state.finalized_randomness;
  state.finalized_committee_checkpoints[1].epoch_start_height = 1;
  state.finalized_committee_checkpoints[1].derivation_mode = storage::FinalizedCommitteeDerivationMode::FALLBACK;

  state.availability_state.operators.clear();
  for (std::size_t i = 0; i < static_cast<std::size_t>(min_required); ++i) {
    state.availability_state.operators.push_back(availability::AvailabilityOperatorState{
        .operator_pubkey = operators[i].public_key,
        .bond = live_adaptive_test_bond(),
        .status = availability::AvailabilityOperatorStatus::ACTIVE,
        .successful_audits = 1,
        .warmup_epochs = 1,
        .retained_prefix_count = 1,
    });
  }

  storage::FinalizedCommitteeCheckpoint sticky_checkpoint;
  ASSERT_TRUE(consensus::derive_next_epoch_checkpoint_from_state(cfg, state, 5, &sticky_checkpoint, &err));
  ASSERT_EQ(sticky_checkpoint.derivation_mode, storage::FinalizedCommitteeDerivationMode::FALLBACK);
  ASSERT_EQ(sticky_checkpoint.fallback_reason, storage::FinalizedCommitteeFallbackReason::HYSTERESIS_RECOVERY_PENDING);
  ASSERT_EQ(sticky_checkpoint.availability_eligible_operator_count, min_required);

  state.finalized_committee_checkpoints[1] = sticky_checkpoint;
  state.availability_state.operators.push_back(availability::AvailabilityOperatorState{
      .operator_pubkey = operators[static_cast<std::size_t>(min_required)].public_key,
      .bond = live_adaptive_test_bond(),
      .status = availability::AvailabilityOperatorStatus::ACTIVE,
      .successful_audits = 1,
      .warmup_epochs = 1,
      .retained_prefix_count = 1,
  });
  std::sort(state.availability_state.operators.begin(), state.availability_state.operators.end(),
            [](const availability::AvailabilityOperatorState& a, const availability::AvailabilityOperatorState& b) {
              return a.operator_pubkey < b.operator_pubkey;
            });

  storage::FinalizedCommitteeCheckpoint recovered_checkpoint;
  ASSERT_TRUE(consensus::derive_next_epoch_checkpoint_from_state(cfg, state, 9, &recovered_checkpoint, &err));
  ASSERT_EQ(recovered_checkpoint.derivation_mode, storage::FinalizedCommitteeDerivationMode::NORMAL);
  ASSERT_EQ(recovered_checkpoint.fallback_reason, storage::FinalizedCommitteeFallbackReason::NONE);
  ASSERT_EQ(recovered_checkpoint.availability_eligible_operator_count, min_required + 1);
  ASSERT_EQ(recovered_checkpoint.availability_min_eligible_operators, consensus::derive_adaptive_min_eligible(4));
}

TEST(test_live_bpoar_checkpoint_cross_node_determinism_uses_canonical_operator_ordering) {
  auto cfg = live_activation_cfg();
  cfg.availability_min_eligible_operators = 1;
  const auto bootstrap = key_from_byte(120);
  const auto operator_a = key_from_byte(121);
  const auto operator_b = key_from_byte(122);

  auto build_state = [&](bool reverse_availability_order) {
    consensus::CanonicalGenesisState genesis;
    genesis.genesis_artifact_id = zero_hash();
    genesis.initial_validators.push_back(bootstrap.public_key);

    consensus::CanonicalDerivedState state;
    std::string local_err;
    if (!consensus::build_genesis_canonical_state(cfg, genesis, &state, &local_err)) {
      throw std::runtime_error("build_genesis_canonical_state failed: " + local_err);
    }
    state.validators.set_rules(
        consensus::ValidatorRules{.min_bond = live_adaptive_test_bond(), .warmup_blocks = 0, .cooldown_blocks = 0});
    if (!state.validators.register_bond(operator_a.public_key, OutPoint{Hash32{10}, 0}, 0, live_adaptive_test_bond(), &local_err,
                                        operator_a.public_key)) {
      throw std::runtime_error("register_bond operator_a failed: " + local_err);
    }
    if (!state.validators.register_bond(operator_b.public_key, OutPoint{Hash32{11}, 0}, 0, live_adaptive_test_bond(), &local_err,
                                        operator_b.public_key)) {
      throw std::runtime_error("register_bond operator_b failed: " + local_err);
    }
    state.validators.advance_height(1);
    state.committee_epoch_randomness_cache[5] = state.finalized_randomness;
    state.availability_state.operators = {
        availability::AvailabilityOperatorState{
            .operator_pubkey = operator_a.public_key,
            .bond = live_adaptive_test_bond(),
            .status = availability::AvailabilityOperatorStatus::ACTIVE,
            .successful_audits = 1,
            .warmup_epochs = 1,
            .retained_prefix_count = 1,
        },
        availability::AvailabilityOperatorState{
            .operator_pubkey = bootstrap.public_key,
            .bond = live_adaptive_test_bond(),
            .status = availability::AvailabilityOperatorStatus::ACTIVE,
            .successful_audits = 1,
            .warmup_epochs = 1,
            .retained_prefix_count = 1,
        },
        availability::AvailabilityOperatorState{
            .operator_pubkey = operator_b.public_key,
            .bond = live_adaptive_test_bond(),
            .status = availability::AvailabilityOperatorStatus::ACTIVE,
            .successful_audits = 1,
            .warmup_epochs = 1,
            .retained_prefix_count = 1,
        },
    };
    if (reverse_availability_order) {
      std::reverse(state.availability_state.operators.begin(), state.availability_state.operators.end());
    }
    return state;
  };

  auto state_a = build_state(false);
  auto state_b = build_state(true);
  std::string err_a;
  std::string err_b;
  storage::FinalizedCommitteeCheckpoint checkpoint_a;
  storage::FinalizedCommitteeCheckpoint checkpoint_b;
  ASSERT_TRUE(consensus::derive_next_epoch_checkpoint_from_state(cfg, state_a, 5, &checkpoint_a, &err_a));
  ASSERT_TRUE(consensus::derive_next_epoch_checkpoint_from_state(cfg, state_b, 5, &checkpoint_b, &err_b));
  ASSERT_EQ(checkpoint_a.derivation_mode, storage::FinalizedCommitteeDerivationMode::NORMAL);
  ASSERT_EQ(checkpoint_a.fallback_reason, storage::FinalizedCommitteeFallbackReason::NONE);
  ASSERT_EQ(checkpoint_a.ordered_members, checkpoint_b.ordered_members);
  ASSERT_EQ(checkpoint_a.ordered_operator_ids, checkpoint_b.ordered_operator_ids);
  ASSERT_EQ(checkpoint_a.ordered_base_weights, checkpoint_b.ordered_base_weights);
  ASSERT_EQ(checkpoint_a.ordered_ticket_bonus_bps, checkpoint_b.ordered_ticket_bonus_bps);
  ASSERT_EQ(checkpoint_a.ordered_ticket_hashes, checkpoint_b.ordered_ticket_hashes);
  ASSERT_EQ(checkpoint_a.ordered_ticket_nonces, checkpoint_b.ordered_ticket_nonces);

  const auto base_a = unique_test_base("/tmp/finalis_checkpoint_bytes_a");
  const auto base_b = unique_test_base("/tmp/finalis_checkpoint_bytes_b");
  storage::DB db_a;
  storage::DB db_b;
  ASSERT_TRUE(db_a.open(base_a));
  ASSERT_TRUE(db_b.open(base_b));
  ASSERT_TRUE(db_a.put_finalized_committee_checkpoint(checkpoint_a));
  ASSERT_TRUE(db_b.put_finalized_committee_checkpoint(checkpoint_b));
  const auto raw_a = db_a.scan_prefix("CE:");
  const auto raw_b = db_b.scan_prefix("CE:");
  ASSERT_EQ(raw_a.size(), 1u);
  ASSERT_EQ(raw_b.size(), 1u);
  ASSERT_EQ(raw_a.begin()->second, raw_b.begin()->second);
}

TEST(test_checkpoint_mode_reason_table_matches_normative_spec) {
  ASSERT_EQ(consensus::derive_adaptive_checkpoint_parameters(std::nullopt, 1).target_committee_size, 1u);
  ASSERT_EQ(consensus::derive_adaptive_checkpoint_parameters(std::nullopt, 3).target_committee_size, 3u);
  ASSERT_EQ(consensus::derive_adaptive_checkpoint_parameters(std::nullopt, 4).target_committee_size, 4u);
  ASSERT_EQ(consensus::derive_adaptive_min_eligible(1), 1u);
  ASSERT_EQ(consensus::derive_adaptive_min_eligible(3), 3u);
  ASSERT_EQ(consensus::derive_adaptive_min_eligible(4), 4u);
}

TEST(test_genesis_checkpoint_metadata_matches_later_checkpoint_semantics) {
  auto cfg = live_activation_cfg();
  const auto bootstrap = key_from_byte(140);

  consensus::CanonicalGenesisState genesis;
  genesis.genesis_artifact_id = zero_hash();
  genesis.initial_validators.push_back(bootstrap.public_key);

  consensus::CanonicalDerivedState state;
  std::string err;
  ASSERT_TRUE(consensus::build_genesis_canonical_state(cfg, genesis, &state, &err));
  auto it = state.finalized_committee_checkpoints.find(1);
  ASSERT_TRUE(it != state.finalized_committee_checkpoints.end());
  ASSERT_EQ(it->second.derivation_mode, storage::FinalizedCommitteeDerivationMode::NORMAL);
  ASSERT_EQ(it->second.fallback_reason, storage::FinalizedCommitteeFallbackReason::NONE);
  ASSERT_EQ(it->second.availability_min_eligible_operators, 1u);
  ASSERT_EQ(it->second.availability_eligible_operator_count, 1u);
  ASSERT_EQ(it->second.adaptive_target_committee_size, 1u);
  ASSERT_EQ(it->second.adaptive_min_eligible, 1u);
  ASSERT_EQ(it->second.adaptive_min_bond, consensus::genesis_validator_bond_amount());
}

TEST(test_bootstrap_availability_grace_does_not_relax_post_genesis_joiner_requirements) {
  auto cfg = live_activation_cfg();
  const auto bootstrap = key_from_byte(141);
  const auto joiner = key_from_byte(142);

  consensus::CanonicalGenesisState genesis;
  genesis.genesis_artifact_id = zero_hash();
  genesis.initial_validators.push_back(bootstrap.public_key);

  consensus::CanonicalDerivedState state;
  std::string err;
  ASSERT_TRUE(consensus::build_genesis_canonical_state(cfg, genesis, &state, &err));

  state.validators.set_rules(
      consensus::ValidatorRules{.min_bond = consensus::genesis_validator_bond_amount(), .warmup_blocks = 0, .cooldown_blocks = 0});
  ASSERT_TRUE(state.validators.register_bond(joiner.public_key, OutPoint{Hash32{9}, 0}, 1,
                                             consensus::genesis_validator_bond_amount(), &err, joiner.public_key));
  state.validators.advance_height(1);
  state.committee_epoch_randomness_cache[5] = state.finalized_randomness;

  storage::FinalizedCommitteeCheckpoint checkpoint;
  ASSERT_TRUE(consensus::derive_next_epoch_checkpoint_from_state(cfg, state, 5, &checkpoint, &err));
  ASSERT_EQ(checkpoint.derivation_mode, storage::FinalizedCommitteeDerivationMode::NORMAL);
  ASSERT_EQ(checkpoint.fallback_reason, storage::FinalizedCommitteeFallbackReason::NONE);
  ASSERT_EQ(checkpoint.availability_eligible_operator_count, 1u);
  ASSERT_EQ(checkpoint.availability_min_eligible_operators, 1u);
}

TEST(test_bootstrap_handoff_complete_is_purely_derived_from_finalized_state) {
  auto cfg = live_activation_cfg();
  const auto bootstrap = key_from_byte(143);
  const auto joiner = key_from_byte(144);

  consensus::CanonicalGenesisState genesis;
  genesis.genesis_artifact_id = zero_hash();
  genesis.initial_validators.push_back(bootstrap.public_key);

  consensus::CanonicalDerivedState state;
  std::string err;
  ASSERT_TRUE(consensus::build_genesis_canonical_state(cfg, genesis, &state, &err));
  ASSERT_TRUE(!consensus::bootstrap_handoff_complete(state));

  state.finalized_height = 1;
  ASSERT_TRUE(!consensus::bootstrap_handoff_complete(state));

  state.validators.set_rules(consensus::ValidatorRules{.min_bond = consensus::genesis_validator_bond_amount(),
                                                       .warmup_blocks = 0,
                                                       .cooldown_blocks = 0});
  ASSERT_TRUE(state.validators.register_bond(joiner.public_key, OutPoint{Hash32{7}, 0}, 1,
                                             consensus::genesis_validator_bond_amount(), &err, joiner.public_key));
  state.validators.advance_height(state.finalized_height + 1);
  ASSERT_TRUE(consensus::bootstrap_handoff_complete(state));
}

TEST(test_checkpoint_ticket_pow_fallback_member_uses_best_ticket_hash_and_nonce) {
  storage::FinalizedCommitteeCheckpoint checkpoint;
  const auto a = key_from_byte(145).public_key;
  const auto b = key_from_byte(146).public_key;
  const auto c = key_from_byte(147).public_key;
  checkpoint.ordered_members = {a, b, c};

  Hash32 ha{};
  ha.fill(0x40);
  Hash32 hb{};
  hb.fill(0x10);
  Hash32 hc{};
  hc.fill(0x10);
  checkpoint.ordered_ticket_hashes = {ha, hb, hc};
  checkpoint.ordered_ticket_nonces = {9, 7, 11};

  const auto fallback = consensus::checkpoint_ticket_pow_fallback_member(checkpoint);
  ASSERT_TRUE(fallback.has_value());
  ASSERT_EQ(*fallback, b);
}

TEST(test_ticket_pow_fallback_begins_after_normal_proposer_rounds_are_exhausted) {
  auto cfg = live_activation_cfg();
  const auto a = key_from_byte(148).public_key;
  const auto b = key_from_byte(149).public_key;
  const auto c = key_from_byte(150).public_key;

  consensus::CanonicalGenesisState genesis;
  genesis.genesis_artifact_id = zero_hash();
  genesis.initial_validators = {a, b, c};

  consensus::CanonicalDerivedState state;
  std::string err;
  ASSERT_TRUE(consensus::build_genesis_canonical_state(cfg, genesis, &state, &err));

  auto checkpoint = state.finalized_committee_checkpoints.at(1);
  checkpoint.ordered_members = {a, b, c};
  Hash32 ha{};
  ha.fill(0x30);
  Hash32 hb{};
  hb.fill(0x20);
  Hash32 hc{};
  hc.fill(0x10);
  checkpoint.ordered_ticket_hashes = {ha, hb, hc};
  checkpoint.ordered_ticket_nonces = {4, 3, 2};
  state.finalized_committee_checkpoints[1] = checkpoint;

  const auto round0 = consensus::canonical_committee_for_height_round(cfg, state, 1, 0);
  ASSERT_EQ(round0, checkpoint.ordered_members);

  const auto round1 = consensus::canonical_committee_for_height_round(cfg, state, 1, 1);
  ASSERT_EQ(round1, checkpoint.ordered_members);

  const auto round2 = consensus::canonical_committee_for_height_round(cfg, state, 1, 2);
  ASSERT_EQ(round2, checkpoint.ordered_members);

  const auto round3 = consensus::canonical_committee_for_height_round(cfg, state, 1, 3);
  ASSERT_EQ(round3.size(), 1u);
  ASSERT_EQ(round3.front(), c);

  const auto round4 = consensus::canonical_committee_for_height_round(cfg, state, 1, 4);
  ASSERT_EQ(round4.size(), 1u);
  ASSERT_EQ(round4.front(), b);

  ASSERT_TRUE(!consensus::checkpoint_ticket_pow_fallback_member_for_round(checkpoint, 0).has_value());
  ASSERT_TRUE(!consensus::checkpoint_ticket_pow_fallback_member_for_round(checkpoint, 1).has_value());
  ASSERT_TRUE(!consensus::checkpoint_ticket_pow_fallback_member_for_round(checkpoint, 2).has_value());
  const auto leader3 = consensus::checkpoint_ticket_pow_fallback_member_for_round(checkpoint, 3);
  ASSERT_TRUE(leader3.has_value());
  ASSERT_EQ(*leader3, c);
  const auto leader4 = consensus::checkpoint_ticket_pow_fallback_member_for_round(checkpoint, 4);
  ASSERT_TRUE(leader4.has_value());
  ASSERT_EQ(*leader4, b);
}

TEST(test_live_validator_exit_mid_epoch_is_removed_only_at_next_epoch_checkpoint) {
  const auto cfg = live_activation_cfg();
  const auto bootstrap = key_from_byte(102);
  const auto exiting = key_from_byte(103);

  consensus::CanonicalGenesisState genesis;
  genesis.genesis_artifact_id = zero_hash();
  genesis.initial_validators.push_back(bootstrap.public_key);

  consensus::CanonicalDerivedState state;
  std::string err;
  ASSERT_TRUE(consensus::build_genesis_canonical_state(cfg, genesis, &state, &err));

  state.finalized_height = 2;
  state.validators.set_rules(
      consensus::ValidatorRules{.min_bond = live_adaptive_test_bond(),
                                .warmup_blocks = 0,
                                .cooldown_blocks = cfg.validator_cooldown_blocks});
  ASSERT_TRUE(state.validators.register_bond(exiting.public_key, OutPoint{Hash32{}, 9}, 0, live_adaptive_test_bond(), &err,
                                             exiting.public_key));
  state.validators.advance_height(3);
  ASSERT_TRUE(state.validators.request_unbond(exiting.public_key, 2));
  state.validators.advance_height(3);

  const auto committee_h3 = consensus::canonical_committee_for_height_round(cfg, state, 3, 0);
  ASSERT_TRUE(std::find(committee_h3.begin(), committee_h3.end(), exiting.public_key) == committee_h3.end());
  state.committee_epoch_randomness_cache[5] = state.finalized_randomness;
  storage::FinalizedCommitteeCheckpoint checkpoint;
  ASSERT_TRUE(consensus::derive_next_epoch_checkpoint_from_state(cfg, state, 5, &checkpoint, &err));
  ASSERT_TRUE(std::find(checkpoint.ordered_members.begin(), checkpoint.ordered_members.end(), exiting.public_key) ==
              checkpoint.ordered_members.end());
}
