// SPDX-License-Identifier: MIT

#include "support/test_chain_domain.hpp"
#include "test_framework.hpp"
#include "support/test_genesis.hpp"
#include "support/test_validator_bls.hpp"
#include "support/test_leader_vrf.hpp"
#include "support/test_paths.hpp"
#include "support/storage_fault_injection.hpp"

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <cerrno>
#include <filesystem>
#include <fstream>
#include <limits>
#include <set>
#include <sstream>
#include <thread>
#include <array>
#include <atomic>
#include <iostream>

#ifdef _WIN32
#include <process.h>
#endif

#include "common/address.hpp"
#include "consensus/availability_retention.hpp"
#include "codec/bytes.hpp"
#include "consensus/canonical_derivation.hpp"
#include "consensus/frontier_execution.hpp"
#include "consensus/light_client.hpp"
#include "consensus/ingress.hpp"
#include "consensus/validator_registry.hpp"
#include "consensus/state_commitment.hpp"
#include "common/socket_compat.hpp"
#include "crypto/ed25519.hpp"
#include "crypto/hash.hpp"
#include "lightserver/server.hpp"
#include "wallet/confidential_builder.hpp"
#include "wallet/light_verifier.hpp"
#include "wallet/verified_balance.hpp"
#include "common/keystore.hpp"
#include "common/merkle.hpp"
#include "node/node.hpp"
#include "p2p/framing.hpp"
#include "p2p/messages.hpp"
#include "storage/db.hpp"
#include "consensus/monetary.hpp"
#include "genesis/genesis.hpp"
#include "utxo/signing.hpp"
#include "utxo/validate.hpp"

using namespace finalis;

namespace {

// The chain domain a node validates transaction signatures under: sign with it to submit to that node.
Hash32 node_chain_domain(const node::Node& n) { return n.consensus_domain_for_test(); }
Hash32 node_chain_domain(const std::unique_ptr<node::Node>& n) { return n->consensus_domain_for_test(); }

std::chrono::seconds ci_timeout_seconds(int base_seconds) {
  int scale = 1;
  if (const char* env = std::getenv("FINALIS_CI_TIMEOUT_SCALE")) {
    int v = std::atoi(env);
    if (v > 0) scale = v;
  }
#ifdef _WIN32
  scale *= 3;
#endif
  return std::chrono::seconds(base_seconds * scale);
}

std::optional<std::filesystem::path> find_repo_fixture(const std::filesystem::path& relative) {
  auto cur = std::filesystem::current_path();
  for (int i = 0; i < 8; ++i) {
    const auto candidate = cur / relative;
    if (std::filesystem::exists(candidate)) return candidate;
    if (!cur.has_parent_path()) break;
    cur = cur.parent_path();
  }
  return std::nullopt;
}

std::string shell_quote_path(const std::filesystem::path& path) {
  std::string s = path.string();
  std::string out;
  out.reserve(s.size() + 2);
  out.push_back('"');
  for (char ch : s) {
    if (ch == '"') out += "\\\"";
    else out.push_back(ch);
  }
  out.push_back('"');
  return out;
}

std::string python_launcher() {
#ifdef _WIN32
  return "python";
#else
  return "python3";
#endif
}

bool wait_for(const std::function<bool()>& pred, std::chrono::milliseconds timeout) {
  const auto start = std::chrono::steady_clock::now();
  while (std::chrono::steady_clock::now() - start < timeout) {
    if (pred()) return true;
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
  }
  return pred();
}

bool wait_for_tip(const node::Node& n, std::uint64_t expected_height, std::chrono::milliseconds timeout) {
  return wait_for([&]() { return n.status().height >= expected_height; }, timeout);
}

bool wait_for_peer_count(const node::Node& n, std::size_t min_peers, std::chrono::milliseconds timeout) {
  return wait_for([&]() { return n.status().peers >= min_peers; }, timeout);
}

// A local precommit is queued and recorded by whichever thread flushes next; a p2p reader or the
// event loop can take it first, so it may be recorded just after the triggering call returns.
bool wait_for_local_precommit(const node::Node& n, std::uint64_t height, std::uint32_t round,
                              const Hash32& transition_id) {
  return wait_for([&]() { return n.local_vote_recorded_for_test(height, round, transition_id); },
                  ci_timeout_seconds(5));
}

bool wait_for_same_tip(const std::vector<std::unique_ptr<node::Node>>& nodes, std::chrono::milliseconds timeout) {
  return wait_for([&]() {
    if (nodes.empty()) return true;
    const auto s0 = nodes[0]->status();
    for (size_t i = 1; i < nodes.size(); ++i) {
      const auto si = nodes[i]->status();
      if (si.height != s0.height || si.transition_hash != s0.transition_hash) return false;
    }
    return true;
  }, timeout);
}

bool wait_for_stable_same_tip(const std::vector<std::unique_ptr<node::Node>>& nodes, std::chrono::milliseconds timeout) {
  const auto start = std::chrono::steady_clock::now();
  const auto stable_window = std::chrono::milliseconds(1200);

  while (std::chrono::steady_clock::now() - start < timeout) {
    if (!wait_for_same_tip(nodes, std::chrono::milliseconds(500))) {
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
      continue;
    }

    const auto base = nodes[0]->status();
    bool all_equal = true;
    for (size_t i = 1; i < nodes.size(); ++i) {
      const auto si = nodes[i]->status();
      if (si.height != base.height || si.transition_hash != base.transition_hash) {
        all_equal = false;
        break;
      }
    }
    if (!all_equal) continue;

    const auto stable_start = std::chrono::steady_clock::now();
    bool stable = true;
    while (std::chrono::steady_clock::now() - stable_start < stable_window) {
      const auto s0 = nodes[0]->status();
      if (s0.height != base.height || s0.transition_hash != base.transition_hash) {
        stable = false;
        break;
      }
      for (size_t i = 1; i < nodes.size(); ++i) {
        const auto si = nodes[i]->status();
        if (si.height != base.height || si.transition_hash != base.transition_hash) {
          stable = false;
          break;
        }
      }
      if (!stable) break;
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    if (stable) return true;
  }
  return false;
}

std::optional<availability::AvailabilityPersistentState> load_availability_state(const std::string& db_path) {
  storage::DB db;
  if (!db.open(db_path)) return std::nullopt;
  return db.get_availability_persistent_state();
}

std::optional<storage::FinalizedCommitteeCheckpoint> load_checkpoint(const std::string& db_path,
                                                                     std::uint64_t epoch_start_height) {
  storage::DB db;
  if (!db.open(db_path)) return std::nullopt;
  return db.get_finalized_committee_checkpoint(epoch_start_height);
}

std::optional<Bytes> load_availability_state_bytes(const std::string& db_path) {
  storage::DB db;
  if (!db.open(db_path)) return std::nullopt;
  return db.get(storage::key_availability_persistent_state());
}

using finalis::test::unique_test_base;

bool same_finality_sig_vector(const std::vector<FinalitySig>& a, const std::vector<FinalitySig>& b) {
  if (a.size() != b.size()) return false;
  for (std::size_t i = 0; i < a.size(); ++i) {
    if (a[i].validator_pubkey != b[i].validator_pubkey) return false;
    if (a[i].signature != b[i].signature) return false;
  }
  return true;
}

bool same_finalized_checkpoint(const storage::FinalizedCommitteeCheckpoint& a,
                               const storage::FinalizedCommitteeCheckpoint& b) {
  return a.epoch_start_height == b.epoch_start_height && a.epoch_seed == b.epoch_seed &&
         a.ticket_difficulty_bits == b.ticket_difficulty_bits && a.derivation_mode == b.derivation_mode &&
         a.fallback_reason == b.fallback_reason &&
         a.availability_eligible_operator_count == b.availability_eligible_operator_count &&
         a.availability_min_eligible_operators == b.availability_min_eligible_operators &&
         a.adaptive_target_committee_size == b.adaptive_target_committee_size &&
         a.adaptive_min_eligible == b.adaptive_min_eligible && a.adaptive_min_bond == b.adaptive_min_bond &&
         a.qualified_depth == b.qualified_depth && a.target_expand_streak == b.target_expand_streak &&
         a.target_contract_streak == b.target_contract_streak &&
         a.ordered_members == b.ordered_members &&
         a.ordered_operator_ids == b.ordered_operator_ids && a.ordered_base_weights == b.ordered_base_weights &&
         a.ordered_ticket_bonus_bps == b.ordered_ticket_bonus_bps && a.ordered_final_weights == b.ordered_final_weights &&
         a.ordered_ticket_hashes == b.ordered_ticket_hashes && a.ordered_ticket_nonces == b.ordered_ticket_nonces;
}

bool finalized_checkpoint_matches_epoch_snapshot(const storage::FinalizedCommitteeCheckpoint& checkpoint,
                                                 const consensus::EpochCommitteeSnapshot& snapshot) {
  if (checkpoint.ordered_members != snapshot.ordered_members) return false;
  if (checkpoint.ordered_ticket_hashes.size() != snapshot.selected_winners.size()) return false;
  if (checkpoint.ordered_ticket_nonces.size() != snapshot.selected_winners.size()) return false;
  for (std::size_t i = 0; i < snapshot.selected_winners.size(); ++i) {
    if (checkpoint.ordered_members[i] != snapshot.selected_winners[i].participant_pubkey) return false;
    if (checkpoint.ordered_ticket_hashes[i] != snapshot.selected_winners[i].work_hash) return false;
    if (checkpoint.ordered_ticket_nonces[i] != snapshot.selected_winners[i].nonce) return false;
  }
  return true;
}

std::string test_key_finality_certificate_height(std::uint64_t height) {
  return storage::key_finality_certificate_height(height);
}

Bytes serialize_test_csaf(const std::optional<std::pair<Hash32, std::uint32_t>>& lock_state,
                          const std::optional<QuorumCertificate>& qc_state,
                          const std::optional<Hash32>& qc_payload_id) {
  codec::ByteWriter w;
  w.u8(lock_state.has_value() ? 1 : 0);
  if (lock_state.has_value()) {
    w.bytes_fixed(lock_state->first);
    w.u32le(lock_state->second);
  }
  w.u8(qc_state.has_value() ? 1 : 0);
  if (qc_state.has_value()) {
    w.u64le(qc_state->height);
    w.u32le(qc_state->round);
    w.bytes_fixed(qc_state->block_id);
    w.u8(qc_payload_id.has_value() ? 1 : 0);
    if (qc_payload_id.has_value()) w.bytes_fixed(*qc_payload_id);
    w.varint(qc_state->signatures.size());
    for (const auto& sig : qc_state->signatures) {
      w.bytes_fixed(sig.validator_pubkey);
      w.bytes_fixed(sig.signature);
    }
  }
  return w.take();
}

std::string epoch_db_key_suffix(std::uint64_t epoch) {
  Bytes b(8);
  for (int i = 7; i >= 0; --i) {
    b[7 - i] = static_cast<std::uint8_t>((epoch >> (i * 8)) & 0xff);
  }
  return hex_encode(b);
}

// Consensus-safety keys encode the height little-endian (node key_consensus_safety_state), unlike
// the big-endian epoch keys above.
std::string csafe_height_suffix(std::uint64_t height) {
  Bytes b(8);
  for (int i = 0; i < 8; ++i) b[static_cast<std::size_t>(i)] = static_cast<std::uint8_t>((height >> (i * 8)) & 0xff);
  return hex_encode(b);
}
std::string csafe_db_key(std::uint64_t height) { return "CSAFE:" + csafe_height_suffix(height); }
std::string csafe_mirror_db_key(std::uint64_t height) { return "CSAFE_MIRROR:" + csafe_height_suffix(height); }
std::string csafe_quarantine_db_key(std::uint64_t height) { return "CSAFE_QUARANTINE:" + csafe_height_suffix(height); }

std::array<std::uint8_t, 32> deterministic_seed_for_node_id(int node_id);
bool write_mainnet_genesis_file(const std::string& path, std::size_t n_validators = 4,
                                std::uint64_t genesis_time_unix = 1735689600ULL);

node::NodeConfig single_node_cfg(const std::string& base, std::size_t max_committee = MAX_COMMITTEE) {
  node::NodeConfig cfg;
  cfg.allow_unencrypted_keystore = true;  // test fixture: no passphrase
  cfg.disable_p2p = true;
  cfg.node_id = 0;
  cfg.max_committee = max_committee;
  cfg.network.min_block_interval_ms = 100;
  cfg.network.round_timeout_ms = 200;
  cfg.p2p_port = 0;  // disable_p2p: never bound
  cfg.db_path = base + "/node0";
  cfg.genesis_path = base + "/genesis.json";
  cfg.allow_unsafe_genesis_override = true;
  cfg.validator_key_file = cfg.db_path + "/keystore/validator.json";
  cfg.validator_passphrase = "test-pass";
  return cfg;
}

node::NodeConfig single_node_cfg_with_finality_binding(const std::string& base, std::uint64_t activation_height,
                                                       std::size_t max_committee = MAX_COMMITTEE) {
  auto cfg = single_node_cfg(base, max_committee);
  cfg.network.finality_binding_activation_height = activation_height;
  return cfg;
}

consensus::CanonicalDerivationConfig test_canonical_cfg(const node::NodeConfig& node_cfg, const storage::DB& db) {
  consensus::CanonicalDerivationConfig cfg;
  cfg.network = node_cfg.network;
  cfg.chain_id = ChainId::from_config_and_db(node_cfg.network, db, std::nullopt, "test", std::nullopt);
  cfg.max_committee = node_cfg.max_committee;
  cfg.validation_rules_version = 7;
  cfg.finalized_hash_at_height = [&db](std::uint64_t height) -> std::optional<Hash32> {
    if (height == 0) return zero_hash();
    return db.get_height_hash(height);
  };
  return cfg;
}

bool persist_test_frontier_replay_records(const node::NodeConfig& cfg, storage::DB& db, const std::vector<Bytes>& ordered_records,
                                          consensus::CanonicalDerivedState* derived_out = nullptr,
                                          bool store_legacy_zero_vectors = false) {
  const auto derivation_cfg = test_canonical_cfg(cfg, db);
  auto gj = db.get(storage::key_genesis_json());
  if (!gj.has_value()) return false;
  auto doc = genesis::parse_json(std::string(gj->begin(), gj->end()));
  if (!doc.has_value()) return false;

  consensus::CanonicalGenesisState genesis_state = consensus::canonical_genesis_state_from_document(*doc);

  consensus::CanonicalDerivedState genesis_derived;
  std::string error;
  if (!consensus::build_genesis_canonical_state(derivation_cfg, genesis_state, &genesis_derived, &error)) return false;
  consensus::CertifiedIngressLaneRecords lane_records;
  const auto signers = node::Node::deterministic_test_keypairs();
  const auto& signer = signers.front();
  FrontierVector next_vector = genesis_derived.finalized_frontier_vector;
  auto lane_roots = genesis_derived.finalized_lane_roots;
  for (const auto& raw : ordered_records) {
    auto parsed = Tx::parse(raw);
    if (!parsed.has_value()) return false;
    const auto lane = consensus::assign_ingress_lane(*parsed);
    IngressCertificate cert;
    cert.epoch = 1;
    cert.lane = lane;
    cert.seq = ++next_vector.lane_max_seq[lane];
    cert.txid = parsed->txid();
    cert.tx_hash = crypto::sha256d(raw);
    cert.prev_lane_root = lane_roots[lane];
    const auto signing_hash = cert.signing_hash();
    const Bytes msg(signing_hash.begin(), signing_hash.end());
    auto sig = crypto::ed25519_sign(msg, signer.private_key);
    if (!sig.has_value()) return false;
    cert.sigs = {FinalitySig{signer.public_key, *sig}};
    lane_roots[lane] = consensus::compute_lane_root_append(lane_roots[lane], cert.tx_hash);
    lane_records[lane].push_back(consensus::CertifiedIngressRecord{cert, raw});
  }
  consensus::FrontierExecutionResult exec_result;
  if (!consensus::execute_frontier_lane_prefix(genesis_derived.utxos, genesis_derived.confidential_pool_value, genesis_derived.finalized_frontier_vector,
                                               next_vector, lane_records, genesis_derived.finalized_lane_roots, nullptr,
                                               &exec_result, &error)) {
    return false;
  }
  const auto leader = consensus::canonical_leader_for_height_round(derivation_cfg, genesis_derived, 1, 0);
  if (!leader.has_value()) return false;
  if (!consensus::populate_frontier_transition_metadata(derivation_cfg, genesis_derived, 1, 0, *leader, 0, {},
                                                        TimeSignatureAggregate{}, exec_result.accepted_fee_units, exec_result.next_utxos,
                                                        &exec_result.transition, &error)) {
    return false;
  }
  if (!test::attach_test_leader_vrf(&exec_result.transition, genesis_derived.finalized_randomness,
                                    node::Node::deterministic_test_keypairs())) {
    return false;
  }
  {
    consensus::CanonicalFrontierRecord record{exec_result.transition, lane_records};
    if (!test::attach_test_next_state_commitment(derivation_cfg, genesis_derived, &record)) return false;
    exec_result.transition = record.transition;
  }

  for (std::size_t lane = 0; lane < finalis::INGRESS_LANE_COUNT; ++lane) {
    for (const auto& ingress : lane_records[lane]) {
      if (!db.put_ingress_bytes(ingress.certificate.txid, ingress.tx_bytes)) return false;
      if (!db.put_ingress_certificate(static_cast<std::uint32_t>(lane), ingress.certificate.seq,
                                      ingress.certificate.serialize())) {
        return false;
      }
      LaneState state;
      state.epoch = ingress.certificate.epoch;
      state.lane = ingress.certificate.lane;
      state.max_seq = ingress.certificate.seq;
      state.lane_root =
          consensus::compute_lane_root_append(ingress.certificate.prev_lane_root, ingress.certificate.tx_hash);
      if (!db.put_lane_state(state.lane, state)) return false;
    }
  }
  FrontierTransition stored_transition = exec_result.transition;
  Hash32 stored_transition_id = stored_transition.transition_id();
  if (store_legacy_zero_vectors) {
    stored_transition.prev_vector = FrontierVector{};
    stored_transition.next_vector = FrontierVector{};
    stored_transition.ingress_commitment = zero_hash();
    stored_transition_id = stored_transition.transition_id();
  }
  if (!db.put_frontier_transition(stored_transition_id, stored_transition.serialize())) return false;
  if (!db.map_height_to_frontier_transition(1, stored_transition_id)) return false;
  const auto committee = consensus::canonical_committee_for_height_round(derivation_cfg, genesis_derived, 1, 0);
  const auto quorum = consensus::quorum_threshold(committee.size());
  if (committee.size() < quorum || quorum == 0) return false;
  FinalityCertificate cert;
  cert.height = 1;
  cert.round = 0;
  cert.frontier_transition_id = stored_transition_id;
  cert.quorum_threshold = static_cast<std::uint32_t>(quorum);
  cert.committee_members = committee;
  const auto msg = vote_signing_message(consensus_chain_domain(derivation_cfg.network, derivation_cfg.chain_id), cert.height, cert.round, cert.frontier_transition_id);
  const auto keys = node::Node::deterministic_test_keypairs();
  for (std::size_t i = 0; i < quorum; ++i) {
    const auto& signer_pub = committee[i];
    const auto signer_it =
        std::find_if(keys.begin(), keys.end(), [&](const auto& kp) { return kp.public_key == signer_pub; });
    if (signer_it == keys.end()) return false;
    auto sig = crypto::ed25519_sign(msg, signer_it->private_key);
    if (!sig.has_value()) return false;
    cert.signatures.push_back(FinalitySig{signer_pub, *sig});
  }
  if (!db.put_finality_certificate(cert)) return false;
  if (!db.set_height_hash(1, stored_transition_id)) return false;
  if (!db.set_finalized_frontier_height(1)) return false;
  db.set_tip(storage::TipState{1, stored_transition_id});
  if (!db.put("REPLAY:MODE", Bytes{'f', 'r', 'o', 'n', 't', 'i', 'e', 'r'})) return false;

  if (derived_out) {
    if (!consensus::derive_canonical_state_from_frontier_storage(derivation_cfg, genesis_derived, db, derived_out, &error)) {
      return false;
    }
  }
  return true;
}

bool persist_test_frontier_replay_record(const node::NodeConfig& cfg, storage::DB& db,
                                         consensus::CanonicalDerivedState* derived_out = nullptr) {
  Tx tx;
  tx.version = 1;
  tx.lock_time = 0;
  tx.outputs.push_back(TxOut{1, Bytes{'t', 'e', 's', 't'}});
  return persist_test_frontier_replay_records(cfg, db, {tx.serialize()}, derived_out);
}

struct CertifiedIngressFixture {
  consensus::CanonicalDerivedState parent;
  FrontierVector next_vector{};
  consensus::CertifiedIngressLaneRecords lane_records;
  std::vector<Bytes> merged_records;
};

p2p::IngressRecordMsg make_signed_ingress_record_msg(const Bytes& tx_bytes, std::uint64_t epoch, std::uint64_t seq,
                                                     const Hash32& prev_lane_root,
                                                     const crypto::KeyPair* signer_override = nullptr) {
  auto tx = Tx::parse(tx_bytes);
  if (!tx.has_value()) throw std::runtime_error("invalid ingress tx bytes");
  IngressCertificate cert;
  cert.epoch = epoch;
  cert.lane = consensus::assign_ingress_lane(*tx);
  cert.seq = seq;
  cert.txid = tx->txid();
  cert.tx_hash = crypto::sha256d(tx_bytes);
  cert.prev_lane_root = prev_lane_root;
  const auto signers = node::Node::deterministic_test_keypairs();
  const crypto::KeyPair& signer = signer_override ? *signer_override : signers[0];
  const auto signing_hash = cert.signing_hash();
  const Bytes msg(signing_hash.begin(), signing_hash.end());
  auto sig = crypto::ed25519_sign(msg, signer.private_key);
  if (!sig.has_value()) throw std::runtime_error("failed to sign ingress certificate");
  cert.sigs.push_back(FinalitySig{signer.public_key, *sig});
  return p2p::IngressRecordMsg{cert, tx_bytes};
}

bool persist_certified_ingress_fixture(const node::NodeConfig& cfg, storage::DB& db, const std::vector<Bytes>& raw_records,
                                       CertifiedIngressFixture* out = nullptr) {
  const auto derivation_cfg = test_canonical_cfg(cfg, db);
  auto gj = db.get(storage::key_genesis_json());
  if (!gj.has_value()) return false;
  auto doc = genesis::parse_json(std::string(gj->begin(), gj->end()));
  if (!doc.has_value()) return false;

  consensus::CanonicalGenesisState genesis_state = consensus::canonical_genesis_state_from_document(*doc);

  consensus::CanonicalDerivedState genesis_derived;
  std::string error;
  if (!consensus::build_genesis_canonical_state(derivation_cfg, genesis_state, &genesis_derived, &error)) return false;

  FrontierVector next_vector = genesis_derived.finalized_frontier_vector;
  auto lane_roots = genesis_derived.finalized_lane_roots;
  const auto signers = node::Node::deterministic_test_keypairs();
  const auto& signer = signers.front();
  consensus::CertifiedIngressLaneRecords lane_records;
  for (const auto& raw : raw_records) {
    auto parsed = Tx::parse(raw);
    if (!parsed.has_value()) return false;
    const auto lane = consensus::assign_ingress_lane(*parsed);
    IngressCertificate cert;
    cert.epoch = 1;
    cert.lane = lane;
    cert.seq = ++next_vector.lane_max_seq[lane];
    cert.txid = parsed->txid();
    cert.tx_hash = crypto::sha256d(raw);
    cert.prev_lane_root = lane_roots[lane];
    const auto signing_hash = cert.signing_hash();
    const Bytes msg(signing_hash.begin(), signing_hash.end());
    auto sig = crypto::ed25519_sign(msg, signer.private_key);
    if (!sig.has_value()) return false;
    cert.sigs = {FinalitySig{signer.public_key, *sig}};
    lane_roots[lane] = consensus::compute_lane_root_append(lane_roots[lane], cert.tx_hash);
    lane_records[lane].push_back(consensus::CertifiedIngressRecord{cert, raw});

    if (!db.put_ingress_bytes(cert.txid, raw)) return false;
    if (!db.put_ingress_certificate(cert.lane, cert.seq, cert.serialize())) return false;
    LaneState state;
    state.epoch = cert.epoch;
    state.lane = cert.lane;
    state.max_seq = cert.seq;
    state.lane_root = lane_roots[lane];
    if (!db.put_lane_state(state.lane, state)) return false;
  }

  if (out) {
    consensus::FrontierLaneRoots recomputed_roots{};
    std::vector<Bytes> merged_records;
    if (!consensus::frontier_merge_certified_ingress(genesis_derived.finalized_frontier_vector, next_vector, lane_records,
                                                     genesis_derived.finalized_lane_roots, &recomputed_roots,
                                                     &merged_records, &error)) {
      return false;
    }
    out->parent = genesis_derived;
    out->next_vector = next_vector;
    out->lane_records = lane_records;
    out->merged_records = std::move(merged_records);
  }
  return true;
}

bool build_frontier_proposal_from_records(const node::NodeConfig& cfg, storage::DB& db,
                                          const std::vector<Bytes>& ordered_records, std::uint64_t height,
                                          std::uint32_t round, FrontierProposal* proposal_out,
                                          consensus::CanonicalDerivedState* parent_out = nullptr);

bool build_test_frontier_proposal_with_certified_ingress(const node::NodeConfig& cfg, storage::DB& db,
                                                         FrontierProposal* proposal_out,
                                                         consensus::CanonicalDerivedState* parent_out = nullptr) {
  std::vector<Bytes> ordered_records;
  Tx tx;
  tx.version = 1;
  tx.lock_time = 0;
  tx.outputs.push_back(TxOut{1, Bytes{'v', 'a', 'l', 'i', 'd'}});
  ordered_records.push_back(tx.serialize());
  return build_frontier_proposal_from_records(cfg, db, ordered_records, 1, 0, proposal_out, parent_out);
}

bool build_frontier_proposal_from_records(const node::NodeConfig& cfg, storage::DB& db, const std::vector<Bytes>& ordered_records,
                                          std::uint64_t height, std::uint32_t round, FrontierProposal* proposal_out,
                                          consensus::CanonicalDerivedState* parent_out) {
  if (!proposal_out) return false;
  const auto derivation_cfg = test_canonical_cfg(cfg, db);
  auto gj = db.get(storage::key_genesis_json());
  if (!gj.has_value()) return false;
  auto doc = genesis::parse_json(std::string(gj->begin(), gj->end()));
  if (!doc.has_value()) return false;

  consensus::CanonicalGenesisState genesis_state = consensus::canonical_genesis_state_from_document(*doc);

  CertifiedIngressFixture fixture;
  std::string error;
  if (!persist_certified_ingress_fixture(cfg, db, ordered_records, &fixture)) return false;

  consensus::FrontierExecutionResult exec_result;
  if (!consensus::execute_frontier_lane_prefix(fixture.parent.utxos, fixture.parent.confidential_pool_value, fixture.parent.finalized_frontier_vector,
                                               fixture.next_vector, fixture.lane_records,
                                               fixture.parent.finalized_lane_roots, nullptr,
                                               &exec_result, &error)) {
    return false;
  }
  const auto leader = consensus::canonical_leader_for_height_round(derivation_cfg, fixture.parent, height, round);
  if (!leader.has_value()) return false;
  // fixture.parent is the genesis-derived state, so there is no parent
  // participation to record.
  if (!consensus::populate_frontier_transition_metadata(derivation_cfg, fixture.parent, height, round, *leader, 0, {},
                                                        TimeSignatureAggregate{}, exec_result.accepted_fee_units, exec_result.next_utxos,
                                                        &exec_result.transition, &error)) {
    return false;
  }
  if (!test::attach_test_leader_vrf(&exec_result.transition, fixture.parent.finalized_randomness,
                                    node::Node::deterministic_test_keypairs())) {
    return false;
  }
  {
    consensus::CanonicalFrontierRecord record{exec_result.transition, fixture.lane_records};
    if (!test::attach_test_next_state_commitment(derivation_cfg, fixture.parent, &record)) return false;
    exec_result.transition = record.transition;
  }

  *proposal_out = FrontierProposal{exec_result.transition, ordered_records};
  if (parent_out) *parent_out = fixture.parent;
  return true;
}

std::uint16_t reserve_test_port() {
  for (int attempt = 0; attempt < 32; ++attempt) {
    if (!finalis::net::ensure_sockets()) return 0;
    auto fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (!finalis::net::valid_socket(fd)) return 0;
    (void)finalis::net::set_reuseaddr(fd);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(0);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
      finalis::net::close_socket(fd);
      continue;
    }
    sockaddr_in bound{};
    socklen_t len = sizeof(bound);
    std::uint16_t port = 0;
    if (::getsockname(fd, reinterpret_cast<sockaddr*>(&bound), &len) == 0) {
      port = ntohs(bound.sin_port);
    }
    finalis::net::close_socket(fd);
    if (port != 0) return port;
  }
  return 0;
}

std::vector<std::uint16_t> reserve_test_ports(int count) {
  std::vector<std::uint16_t> ports;
  ports.reserve(static_cast<std::size_t>(count));
  // Ports are released before use, so the OS may hand one out twice; reject duplicates.
  for (int attempt = 0; static_cast<int>(ports.size()) < count && attempt < count * 8; ++attempt) {
    const auto port = reserve_test_port();
    if (port == 0) throw std::runtime_error("reserve_test_port failed");
    if (std::find(ports.begin(), ports.end(), port) == ports.end()) ports.push_back(port);
  }
  if (static_cast<int>(ports.size()) != count) throw std::runtime_error("reserve_test_ports: no distinct ports");
  return ports;
}

bool can_open_loopback_listener_for_test() {
  if (!finalis::net::ensure_sockets()) return false;
  auto fd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (!finalis::net::valid_socket(fd)) return false;
  (void)finalis::net::set_reuseaddr(fd);
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(0);
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  const bool bound = (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0);
  const bool listening = bound && (::listen(fd, 1) == 0);
  finalis::net::close_socket(fd);
  return listening;
}

int node_for_pub(const std::vector<crypto::KeyPair>& keys, const PubKey32& pub) {
  for (size_t i = 0; i < keys.size(); ++i) {
    if (keys[i].public_key == pub) return static_cast<int>(i);
  }
  return -1;
}

crypto::KeyPair key_from_byte(std::uint8_t b) {
  std::array<std::uint8_t, 32> seed{};
  seed.fill(b);
  auto kp = crypto::keypair_from_seed32(seed);
  if (!kp.has_value()) throw std::runtime_error("key generation failed");
  return *kp;
}

std::array<std::uint8_t, 32> deterministic_seed_for_node_id(int node_id) {
  std::array<std::uint8_t, 32> seed{};
  const int i = node_id + 1;
  for (std::size_t j = 0; j < seed.size(); ++j) seed[j] = static_cast<std::uint8_t>(i * 19 + static_cast<int>(j));
  return seed;
}

bool create_test_validator_keystore(const node::NodeConfig& cfg, int node_id) {
  keystore::ValidatorKey out_key;
  std::string kerr;
  return keystore::create_validator_keystore(cfg.validator_key_file, cfg.validator_passphrase, "mainnet", "sc",
                                             deterministic_seed_for_node_id(node_id), &out_key, &kerr);
}

bool write_mainnet_genesis_file(const std::string& path, std::size_t n_validators, std::uint64_t genesis_time_unix);

std::unique_ptr<node::Node> start_single_test_node(const std::string& base, std::uint64_t activation_height,
                                                   std::size_t max_committee = 1) {
  std::error_code ec;
  std::filesystem::remove_all(base, ec);
  std::filesystem::create_directories(base);
  const auto cfg = single_node_cfg_with_finality_binding(base, activation_height, max_committee);
  if (!write_mainnet_genesis_file(cfg.genesis_path, 1)) return nullptr;
  if (!create_test_validator_keystore(cfg, 0)) return nullptr;
  auto node = std::make_unique<node::Node>(cfg);
  if (!node->init()) return nullptr;
  node->start();
  return node;
}

std::optional<Tx> create_bond_tx_from_validator0(node::Node& node0, const crypto::KeyPair& validator0,
                                                 const PubKey32& new_validator_pub) {
  const auto sender_pkh = crypto::h160(Bytes(validator0.public_key.begin(), validator0.public_key.end()));
  auto utxos = node0.find_utxos_by_pubkey_hash_for_test(sender_pkh);
  if (utxos.empty()) return std::nullopt;

  std::vector<std::pair<OutPoint, TxOut>> selected;
  std::uint64_t in_sum = 0;
  for (const auto& it : utxos) {
    selected.push_back(it);
    in_sum += it.second.value;
    if (in_sum >= BOND_AMOUNT) break;
  }
  if (in_sum < BOND_AMOUNT) return std::nullopt;

  Bytes reg_spk{'S', 'C', 'V', 'A', 'L', 'R', 'E', 'G'};
  reg_spk.insert(reg_spk.end(), new_validator_pub.begin(), new_validator_pub.end());
  std::vector<TxOut> outs{TxOut{BOND_AMOUNT, reg_spk}};
  const std::uint64_t change = in_sum - BOND_AMOUNT;
  if (change > 0) outs.push_back(TxOut{change, address::p2pkh_script_pubkey(sender_pkh)});

  Tx tx;
  tx.version = 1;
  tx.lock_time = 0;
  for (const auto& [op, _] : selected) {
    tx.inputs.push_back(TxIn{op.txid, op.index, {}, 0xFFFFFFFF});
  }
  tx.outputs = outs;

  for (std::size_t i = 0; i < selected.size(); ++i) {
    auto msg = signing_message_for_input(node_chain_domain(node0), tx, static_cast<std::uint32_t>(i));
    if (!msg.has_value()) return std::nullopt;
    auto sig = crypto::ed25519_sign(*msg, validator0.private_key);
    if (!sig.has_value()) return std::nullopt;
    Bytes script;
    script.push_back(0x40);
    script.insert(script.end(), sig->begin(), sig->end());
    script.push_back(0x20);
    script.insert(script.end(), validator0.public_key.begin(), validator0.public_key.end());
    tx.inputs[i].script_sig = std::move(script);
  }
  return tx;
}

std::optional<Tx> create_join_request_tx_from_validator0(node::Node& node0, const crypto::KeyPair& validator0,
                                                         const crypto::KeyPair& new_validator,
                                                         std::uint64_t bond_amount = BOND_AMOUNT,
                                                         std::uint64_t fee = 0) {
  const auto sender_pkh = crypto::h160(Bytes(validator0.public_key.begin(), validator0.public_key.end()));
  auto utxos = node0.find_utxos_by_pubkey_hash_for_test(sender_pkh);
  if (utxos.empty()) return std::nullopt;

  std::vector<std::pair<OutPoint, TxOut>> selected;
  std::uint64_t in_sum = 0;
  for (const auto& it : utxos) {
    selected.push_back(it);
    in_sum += it.second.value;
    if (in_sum >= bond_amount + fee) break;
  }
  if (in_sum < bond_amount + fee) return std::nullopt;

  auto pop = crypto::ed25519_sign(
      validator_join_request_pop_message(new_validator.public_key, new_validator.public_key, test::test_bls_pubkey(new_validator)),
      Bytes(new_validator.private_key.begin(), new_validator.private_key.end()));
  if (!pop.has_value()) return std::nullopt;

  Bytes reg_spk{'S', 'C', 'V', 'A', 'L', 'R', 'E', 'G'};
  reg_spk.insert(reg_spk.end(), new_validator.public_key.begin(), new_validator.public_key.end());
  ValidatorJoinRequestScriptData req{};
  req.validator_pubkey = new_validator.public_key;
  req.payout_pubkey = new_validator.public_key;
  req.pop = *pop;
  const auto bls = test::test_bls_registration(new_validator);
  req.bls_pubkey = bls.pubkey;
  req.bls_pop = bls.pop;
  const Bytes req_spk = encode_validator_join_request_script(req);

  std::vector<TxOut> outputs{TxOut{bond_amount, reg_spk}, TxOut{0, req_spk}};
  const std::uint64_t change = in_sum - bond_amount - fee;
  if (change > 0) outputs.push_back(TxOut{change, address::p2pkh_script_pubkey(sender_pkh)});

  return build_signed_p2pkh_tx_multi_input(node_chain_domain(node0), selected, Bytes(validator0.private_key.begin(), validator0.private_key.end()),
                                           outputs);
}

std::optional<Tx> create_join_request_tx_from_wallet(node::Node& node, const crypto::KeyPair& sender,
                                                     const crypto::KeyPair& new_validator,
                                                     std::uint64_t bond_amount = BOND_AMOUNT,
                                                     std::uint64_t fee = 0) {
  return create_join_request_tx_from_validator0(node, sender, new_validator, bond_amount, fee);
}

std::optional<Tx> create_onboarding_registration_tx_from_validator0(node::Node& node0, const crypto::KeyPair& validator0,
                                                                    const crypto::KeyPair& new_validator,
                                                                    const PubKey32& payout_pubkey,
                                                                    std::uint64_t fee = 1000) {
  const auto sender_pkh = crypto::h160(Bytes(validator0.public_key.begin(), validator0.public_key.end()));
  auto utxos = node0.find_utxos_by_pubkey_hash_for_test(sender_pkh);
  if (utxos.empty()) return std::nullopt;

  std::vector<std::pair<OutPoint, TxOut>> selected;
  std::uint64_t in_sum = 0;
  for (const auto& it : utxos) {
    selected.push_back(it);
    in_sum += it.second.value;
    if (in_sum >= fee) break;
  }
  if (in_sum < fee) return std::nullopt;

  return build_onboarding_registration_tx(node_chain_domain(node0), 
      selected, Bytes(validator0.private_key.begin(), validator0.private_key.end()), new_validator.public_key,
      Bytes(new_validator.private_key.begin(), new_validator.private_key.end()), payout_pubkey, fee,
      address::p2pkh_script_pubkey(sender_pkh));
}

std::optional<Tx> create_join_request_tx_from_validator0_with_payout(node::Node& node0, const crypto::KeyPair& validator0,
                                                                     const crypto::KeyPair& new_validator,
                                                                     const PubKey32& payout_pubkey,
                                                                     std::uint64_t bond_amount = BOND_AMOUNT,
                                                                     std::uint64_t fee = 0) {
  const auto sender_pkh = crypto::h160(Bytes(validator0.public_key.begin(), validator0.public_key.end()));
  auto utxos = node0.find_utxos_by_pubkey_hash_for_test(sender_pkh);
  if (utxos.empty()) return std::nullopt;

  std::vector<std::pair<OutPoint, TxOut>> selected;
  std::uint64_t in_sum = 0;
  for (const auto& it : utxos) {
    selected.push_back(it);
    in_sum += it.second.value;
    if (in_sum >= bond_amount + fee) break;
  }
  if (in_sum < bond_amount + fee) return std::nullopt;

  auto pop = crypto::ed25519_sign(
      validator_join_request_pop_message(new_validator.public_key, payout_pubkey, test::test_bls_pubkey(new_validator)),
      Bytes(new_validator.private_key.begin(), new_validator.private_key.end()));
  if (!pop.has_value()) return std::nullopt;

  Bytes reg_spk{'S', 'C', 'V', 'A', 'L', 'R', 'E', 'G'};
  reg_spk.insert(reg_spk.end(), new_validator.public_key.begin(), new_validator.public_key.end());
  ValidatorJoinRequestScriptData req{};
  req.validator_pubkey = new_validator.public_key;
  req.payout_pubkey = payout_pubkey;
  req.pop = *pop;
  const auto bls = test::test_bls_registration(new_validator);
  req.bls_pubkey = bls.pubkey;
  req.bls_pop = bls.pop;
  const Bytes req_spk = encode_validator_join_request_script(req);

  std::vector<TxOut> outputs{TxOut{bond_amount, reg_spk}, TxOut{0, req_spk}};
  const std::uint64_t change = in_sum - bond_amount - fee;
  if (change > 0) outputs.push_back(TxOut{change, address::p2pkh_script_pubkey(sender_pkh)});

  return build_signed_p2pkh_tx_multi_input(node_chain_domain(node0), selected, Bytes(validator0.private_key.begin(), validator0.private_key.end()),
                                           outputs);
}

std::optional<Tx> create_self_transfer_tx(node::Node& node, const crypto::KeyPair& sender, std::uint64_t amount,
                                          std::uint64_t fee, std::uint8_t recipient_tag) {
  const auto sender_pkh = crypto::h160(Bytes(sender.public_key.begin(), sender.public_key.end()));
  auto utxos = node.find_utxos_by_pubkey_hash_for_test(sender_pkh);
  if (utxos.empty()) return std::nullopt;

  const auto recipient = key_from_byte(recipient_tag);
  const auto recipient_pkh = crypto::h160(Bytes(recipient.public_key.begin(), recipient.public_key.end()));

  std::vector<std::pair<OutPoint, TxOut>> selected;
  std::uint64_t in_sum = 0;
  for (const auto& it : utxos) {
    selected.push_back(it);
    in_sum += it.second.value;
    if (in_sum >= amount + fee) break;
  }
  if (in_sum < amount + fee) return std::nullopt;

  std::vector<TxOut> outputs{TxOut{amount, address::p2pkh_script_pubkey(recipient_pkh)}};
  const std::uint64_t change = in_sum - amount - fee;
  if (change > 0) outputs.push_back(TxOut{change, address::p2pkh_script_pubkey(sender_pkh)});

  return build_signed_p2pkh_tx_multi_input(node_chain_domain(node), selected, Bytes(sender.private_key.begin(), sender.private_key.end()), outputs);
}

struct FundedTestWallet {
  std::size_t key_index{0};
  std::vector<std::pair<OutPoint, TxOut>> utxos;
};

struct Cluster;
bool append_live_certified_ingress_to_nodes(const std::string& db_path, const std::vector<node::Node*>& nodes,
                                            const std::vector<Bytes>& raw_records, int peer_id,
                                            std::string* error, const crypto::KeyPair* signer_override);

// Genesis has no premine, so tests that fund a validator bond from block rewards wait for the
// registration floor (~2.8k-4k coins) to accrue; under ASan that exceeds the timeouts. This floor is set
// on NetworkConfig so the node, replay and the onboarding service all apply it.
constexpr std::uint64_t kTestRegistrationBondFloor = 100ULL * consensus::BASE_UNITS_PER_COIN;

void apply_test_bond_floor(node::NodeConfig& cfg) {
  cfg.network.validator_min_bond = kTestRegistrationBondFloor;
  cfg.network.validator_bond_min_amount = kTestRegistrationBondFloor;
}

std::optional<FundedTestWallet> find_funded_test_wallet(node::Node& node, const std::vector<crypto::KeyPair>& keys,
                                                        std::uint64_t min_total, std::size_t min_utxo_count = 1) {
  for (std::size_t i = 0; i < keys.size(); ++i) {
    const auto sender_pkh = crypto::h160(Bytes(keys[i].public_key.begin(), keys[i].public_key.end()));
    auto utxos = node.find_utxos_by_pubkey_hash_for_test(sender_pkh);
    if (utxos.size() < min_utxo_count) continue;
    std::uint64_t total = 0;
    for (const auto& entry : utxos) total += entry.second.value;
    if (total < min_total) continue;
    return FundedTestWallet{i, std::move(utxos)};
  }
  return std::nullopt;
}

QuorumCertificate make_test_qc(const Hash32& chain_domain, const std::vector<crypto::KeyPair>& keys, const std::vector<PubKey32>& committee,
                               std::uint64_t height, std::uint32_t round, const Hash32& block_id,
                               std::size_t signer_count) {
  QuorumCertificate qc;
  qc.height = height;
  qc.round = round;
  qc.block_id = block_id;
  const auto msg = vote_signing_message(chain_domain, height, round, block_id);
  const std::size_t take = std::min(signer_count, committee.size());
  for (std::size_t i = 0; i < take; ++i) {
    const int signer_id = node_for_pub(keys, committee[i]);
    if (signer_id < 0) continue;
    auto sig = crypto::ed25519_sign(msg, keys[static_cast<std::size_t>(signer_id)].private_key);
    if (!sig.has_value()) continue;
    qc.signatures.push_back(FinalitySig{committee[i], *sig});
  }
  return qc;
}

std::optional<FrontierProposal> build_test_frontier_proposal(node::Node& n, std::uint64_t height, std::uint32_t round) {
  (void)n.advance_round_for_test(height, round);
  std::optional<FrontierProposal> proposal;
  const bool ready = wait_for([&]() {
    proposal = n.build_frontier_proposal_for_test(height, round);
    return proposal.has_value();
  }, std::chrono::seconds(5));
  if (!ready) return std::nullopt;
  return proposal;
}

std::optional<FrontierProposal> build_cluster_frontier_proposal(const std::vector<std::unique_ptr<node::Node>>& nodes,
                                                                const std::vector<crypto::KeyPair>& keys,
                                                                std::uint64_t height, std::uint32_t round) {
  if (nodes.empty()) return std::nullopt;
  const auto proposer = nodes[0]->proposer_for_height_round_for_test(height, round);
  if (proposer.has_value()) {
    const int proposer_id = node_for_pub(keys, *proposer);
    if (proposer_id >= 0) {
      auto proposal = build_test_frontier_proposal(*nodes[static_cast<std::size_t>(proposer_id)], height, round);
      if (proposal.has_value()) return proposal;
    }
  }
  for (const auto& node : nodes) {
    auto proposal = build_test_frontier_proposal(*node, height, round);
    if (proposal.has_value()) return proposal;
  }
  return std::nullopt;
}

Hash32 frontier_proposal_id(const FrontierProposal& proposal) { return proposal.transition.transition_id(); }

// Test validators' keys: node keys from deterministic_seed_for_node_id, extra keys from key_from_byte.
std::optional<crypto::KeyPair> test_keypair_for_pub(const PubKey32& pub) {
  static const std::map<PubKey32, crypto::KeyPair> keys = [] {
    std::map<PubKey32, crypto::KeyPair> out;
    for (int i = 0; i < 256; ++i) {
      if (auto kp = crypto::keypair_from_seed32(deterministic_seed_for_node_id(i)); kp.has_value()) {
        out.emplace(kp->public_key, *kp);
      }
      const auto kb = key_from_byte(static_cast<std::uint8_t>(i));
      out.emplace(kb.public_key, kb);
    }
    return out;
  }();
  auto it = keys.find(pub);
  if (it == keys.end()) return std::nullopt;
  return it->second;
}

// Signs the proposal as `signer` (default: the transition's leader). Pass `round` and `pol` to
// re-propose a valid value in a later round; the signer must then be that round's leader.
p2p::ProposeMsg make_test_frontier_propose_msg(const Hash32& chain_domain, const FrontierProposal& proposal,
                                               const std::optional<QuorumCertificate>& pol = std::nullopt,
                                               const std::optional<TimeoutCertificate>& justify_tc = std::nullopt,
                                               std::optional<std::uint32_t> round = std::nullopt,
                                               std::optional<PubKey32> signer = std::nullopt) {
  p2p::ProposeMsg msg;
  msg.height = proposal.transition.height;
  msg.round = round.value_or(proposal.transition.round);
  msg.prev_finalized_hash = proposal.transition.prev_finalized_hash;
  msg.frontier_proposal_bytes = proposal.serialize();
  msg.pol = pol;
  msg.justify_tc = justify_tc;
  const auto kp = test_keypair_for_pub(signer.value_or(proposal.transition.leader_pubkey));
  if (!kp.has_value()) throw std::runtime_error("unknown proposer key");
  const std::optional<std::uint32_t> pol_round =
      pol.has_value() ? std::optional<std::uint32_t>(pol->round) : std::nullopt;
  auto sig = crypto::ed25519_sign(
      propose_signing_message(chain_domain, msg.height, msg.round, proposal.transition.transition_id(), pol_round), kp->private_key);
  if (!sig.has_value()) throw std::runtime_error("failed to sign proposal");
  msg.proposer_signature = *sig;
  return msg;
}

Vote make_test_vote(const Hash32& chain_domain, const std::vector<crypto::KeyPair>& keys, std::uint64_t height, std::uint32_t round,
                    const Hash32& block_id, const PubKey32& signer_pubkey) {
  Vote vote;
  vote.height = height;
  vote.round = round;
  vote.block_id = block_id;
  vote.validator_pubkey = signer_pubkey;
  const int signer_id = node_for_pub(keys, signer_pubkey);
  if (signer_id < 0) throw std::runtime_error("unknown signer pubkey");
  auto sig = crypto::ed25519_sign(vote_signing_message(chain_domain, height, round, block_id),
                                  keys[static_cast<std::size_t>(signer_id)].private_key);
  if (!sig.has_value()) throw std::runtime_error("failed to sign vote");
  vote.signature = *sig;
  return vote;
}

Vote make_test_prevote(const Hash32& chain_domain, const std::vector<crypto::KeyPair>& keys, std::uint64_t height, std::uint32_t round,
                       const Hash32& transition_id, const PubKey32& signer_pubkey) {
  const int signer_id = node_for_pub(keys, signer_pubkey);
  if (signer_id < 0) throw std::runtime_error("unknown prevote signer pubkey");
  auto sig = crypto::ed25519_sign(prevote_signing_message(chain_domain, height, round, transition_id),
                                  keys[static_cast<std::size_t>(signer_id)].private_key);
  if (!sig.has_value()) throw std::runtime_error("failed to sign prevote");
  return Vote{height, round, transition_id, signer_pubkey, *sig};
}

// A polka: the first `signer_count` committee members' prevotes for (height, round, transition_id).
QuorumCertificate make_test_polka(const Hash32& chain_domain, const std::vector<crypto::KeyPair>& keys, const std::vector<PubKey32>& committee,
                                  std::uint64_t height, std::uint32_t round, const Hash32& transition_id,
                                  std::size_t signer_count) {
  QuorumCertificate polka;
  polka.height = height;
  polka.round = round;
  polka.frontier_transition_id = transition_id;
  for (std::size_t i = 0; i < std::min(signer_count, committee.size()); ++i) {
    const auto v = make_test_prevote(chain_domain, keys, height, round, transition_id, committee[i]);
    polka.signatures.push_back(FinalitySig{v.validator_pubkey, v.signature});
  }
  return polka;
}

// Delivers prevotes for `transition_id` from committee members other than `target` until `count` are in.
void inject_test_prevotes(node::Node& target, const std::vector<crypto::KeyPair>& keys,
                          const std::vector<PubKey32>& committee, std::uint64_t height, std::uint32_t round,
                          const Hash32& transition_id, std::size_t count) {
  std::size_t injected = 0;
  for (const auto& pub : committee) {
    if (injected == count) break;
    if (pub == target.local_validator_pubkey_for_test()) continue;
    const auto r = target.inject_network_prevote_result_for_test(make_test_prevote(target.consensus_domain_for_test(), keys, height, round, transition_id, pub));
    if (r != "accepted") throw std::runtime_error("prevote not accepted: " + r);
    ++injected;
  }
  if (injected != count) throw std::runtime_error("not enough prevoters");
}

TimeoutVote make_test_timeout_vote(const Hash32& chain_domain, const std::vector<crypto::KeyPair>& keys, std::uint64_t height, std::uint32_t round,
                                   const PubKey32& signer_pubkey) {
  TimeoutVote vote;
  vote.height = height;
  vote.round = round;
  vote.validator_pubkey = signer_pubkey;
  const int signer_id = node_for_pub(keys, signer_pubkey);
  if (signer_id < 0) throw std::runtime_error("unknown timeout signer pubkey");
  auto sig =
      crypto::ed25519_sign(timeout_vote_signing_message(chain_domain, height, round), keys[static_cast<std::size_t>(signer_id)].private_key);
  if (!sig.has_value()) throw std::runtime_error("failed to sign timeout vote");
  vote.signature = *sig;
  return vote;
}

TimeoutCertificate make_test_timeout_certificate(const Hash32& chain_domain, const std::vector<crypto::KeyPair>& keys,
                                                 const std::vector<PubKey32>& committee, std::uint64_t height,
                                                 std::uint32_t round, std::size_t signer_count) {
  TimeoutCertificate tc;
  tc.height = height;
  tc.round = round;
  const auto msg = timeout_vote_signing_message(chain_domain, height, round);
  const std::size_t take = std::min(signer_count, committee.size());
  for (std::size_t i = 0; i < take; ++i) {
    const int signer_id = node_for_pub(keys, committee[i]);
    if (signer_id < 0) continue;
    auto sig = crypto::ed25519_sign(msg, keys[static_cast<std::size_t>(signer_id)].private_key);
    if (!sig.has_value()) continue;
    tc.signatures.push_back(FinalitySig{committee[i], *sig});
  }
  return tc;
}

bool observe_test_frontier_proposal(node::Node& n, const FrontierProposal& proposal) {
  return n.observe_frontier_proposal_for_test(proposal);
}

bool inject_test_frontier_block(node::Node& n, const FrontierProposal& proposal, const std::vector<FinalitySig>& sigs) {
  return n.inject_frontier_block_for_test(proposal, sigs);
}

bool advance_test_frontier_round(node::Node& n, std::uint64_t height, std::uint32_t round) {
  return n.advance_round_for_test(height, round);
}

std::optional<FrontierProposal> build_test_frontier_proposal_at_round(node::Node& n, std::uint64_t height,
                                                                      std::uint32_t round) {
  if (!advance_test_frontier_round(n, height, round)) return std::nullopt;
  return build_test_frontier_proposal(n, height, round);
}

QuorumCertificate make_test_frontier_qc(const Hash32& chain_domain, const std::vector<crypto::KeyPair>& keys, const std::vector<PubKey32>& committee,
                                        const FrontierProposal& proposal, std::size_t signer_count) {
  return make_test_qc(chain_domain, keys, committee, proposal.transition.height, proposal.transition.round, frontier_proposal_id(proposal),
                      signer_count);
}

struct Cluster {
  std::string base;
  std::vector<node::NodeConfig> configs;
  std::vector<std::unique_ptr<node::Node>> nodes;
  // OS-assigned loopback ports, one per node; reused on restart so peers can redial.
  std::vector<std::uint16_t> ports;

  Cluster() = default;
  Cluster(const Cluster&) = delete;
  Cluster& operator=(const Cluster&) = delete;
  Cluster(Cluster&&) = default;
  Cluster& operator=(Cluster&&) = default;

  ~Cluster() {
    for (auto& n : nodes) {
      if (!n) continue;
      try {
        n->stop();
      } catch (const std::exception& e) {
        std::cerr << "cluster-stop-exception error=\"" << e.what() << "\"\n";
      } catch (...) {
        std::cerr << "cluster-stop-exception error=unknown\n";
      }
    }
  }
};

std::optional<FrontierProposal> build_live_cluster_frontier_proposal_from_records(
    Cluster& cluster, const std::vector<crypto::KeyPair>& keys, const std::vector<Bytes>& ordered_records,
    const crypto::KeyPair& ingress_signer, std::string* error = nullptr) {
  if (cluster.nodes.empty() || cluster.configs.empty()) {
    if (error) *error = "empty-cluster";
    return std::nullopt;
  }
  for (auto& n : cluster.nodes) {
    if (!n->pause_proposals_for_test(true)) {
      if (error) *error = "pause-failed";
      return std::nullopt;
    }
  }
  if (!wait_for_stable_same_tip(cluster.nodes, std::chrono::seconds(10))) {
    if (error) *error = "stable-tip-timeout";
    for (auto& n : cluster.nodes) (void)n->pause_proposals_for_test(false);
    return std::nullopt;
  }

  const auto target_height = cluster.nodes[0]->status().height + 1;
  std::vector<node::Node*> live_nodes;
  live_nodes.reserve(cluster.nodes.size());
  for (const auto& n : cluster.nodes) live_nodes.push_back(n.get());
  std::string ingress_error;
  if (!append_live_certified_ingress_to_nodes(cluster.configs.front().db_path, live_nodes, ordered_records, 7, &ingress_error,
                                              &ingress_signer)) {
    if (error) *error = ingress_error;
    for (auto& n : cluster.nodes) (void)n->pause_proposals_for_test(false);
    return std::nullopt;
  }

  auto proposal = build_cluster_frontier_proposal(cluster.nodes, keys, target_height, 0);
  if (proposal.has_value()) {
    const auto msg = make_test_frontier_propose_msg(cluster.nodes[0]->consensus_domain_for_test(), *proposal);
    for (std::size_t i = 0; i < cluster.nodes.size(); ++i) {
      const auto result = cluster.nodes[i]->inject_network_propose_result_for_test(msg);
      if (result != "accepted") {
        if (error) {
          *error = "node=" + std::to_string(i) + " propose=" + result +
                   " diagnostic=" + cluster.nodes[i]->inject_network_propose_diagnostic_for_test(msg);
        }
        proposal.reset();
        break;
      }
    }
  } else if (error) {
    *error = cluster.nodes[0]->last_test_hook_error_for_test();
  }
  return proposal;
}

std::optional<FrontierProposal> build_cluster_frontier_proposal_from_records(
    Cluster& cluster, const std::vector<crypto::KeyPair>& keys, const std::vector<Bytes>& ordered_records,
    std::uint64_t height, std::uint32_t round, const std::string& scratch_base) {
  if (cluster.nodes.empty()) return std::nullopt;
  if (!advance_test_frontier_round(*cluster.nodes[0], height, round)) return std::nullopt;
  const auto proposer = cluster.nodes[0]->proposer_for_height_round_for_test(height, round);
  if (!proposer.has_value()) return std::nullopt;
  const int proposer_id = node_for_pub(keys, *proposer);
  if (proposer_id < 0) return std::nullopt;

  FrontierProposal proposal;
  auto scratch_cfg = cluster.configs[static_cast<std::size_t>(proposer_id)];
  scratch_cfg.db_path = unique_test_base(scratch_base) + "/node" + std::to_string(proposer_id);
  // init() binds the P2P listener; the live proposer already holds this port.
  scratch_cfg.disable_p2p = true;
  scratch_cfg.listen = false;
  scratch_cfg.p2p_port = 0;
  {
    node::Node scratch_seed(scratch_cfg);
    if (!scratch_seed.init()) return std::nullopt;
    scratch_seed.stop();
  }
  storage::DB scratch_db;
  if (!scratch_db.open(scratch_cfg.db_path)) return std::nullopt;
  const bool ok = build_frontier_proposal_from_records(scratch_cfg, scratch_db, ordered_records, height, round, &proposal);
  scratch_db.close();
  if (!ok) return std::nullopt;
  return proposal;
}

struct HttpStubServer {
  finalis::net::SocketHandle fd{finalis::net::kInvalidSocket};
  std::uint16_t port{0};
  std::atomic<bool> running{false};
  std::thread th;

  bool start() {
    if (!finalis::net::ensure_sockets()) return false;
    fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (!finalis::net::valid_socket(fd)) return false;
    (void)finalis::net::set_reuseaddr(fd);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(0);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) return false;
    if (::listen(fd, 8) != 0) return false;
    sockaddr_in bound{};
    socklen_t bl = sizeof(bound);
    if (::getsockname(fd, reinterpret_cast<sockaddr*>(&bound), &bl) != 0) return false;
    port = ntohs(bound.sin_port);
    running = true;
    th = std::thread([this, lfd = fd]() {
      while (running) {
        sockaddr_in caddr{};
        socklen_t len = sizeof(caddr);
        auto cfd = ::accept(lfd, reinterpret_cast<sockaddr*>(&caddr), &len);
        if (!finalis::net::valid_socket(cfd)) continue;
        const char kResp[] = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
        (void)::send(cfd, kResp, static_cast<int>(sizeof(kResp) - 1), 0);
        finalis::net::shutdown_socket(cfd);
        finalis::net::close_socket(cfd);
      }
    });
    return true;
  }

  void stop() {
    running = false;
    if (finalis::net::valid_socket(fd)) {
      finalis::net::shutdown_socket(fd);
      finalis::net::close_socket(fd);
      fd = finalis::net::kInvalidSocket;
    }
    if (th.joinable()) th.join();
  }
};

bool write_mainnet_genesis_file(const std::string& path, std::size_t n_validators, std::uint64_t genesis_time_unix);

Cluster make_cluster(const std::string& base, int initial_active = 4, int node_count = 4,
                     std::size_t max_committee = MAX_COMMITTEE,
                     const std::function<void(node::NodeConfig&)>& configure = {}) {
  std::error_code ec;
  std::filesystem::remove_all(base, ec);
  std::filesystem::create_directories(base);
  const std::string gpath = base + "/genesis.json";
  if (!write_mainnet_genesis_file(gpath, static_cast<std::size_t>(std::max(initial_active, node_count)))) {
    throw std::runtime_error("failed to write cluster genesis");
  }
  const auto keys = node::Node::deterministic_test_keypairs();

  Cluster c;
  c.base = base;
  c.ports = reserve_test_ports(node_count);
  c.configs.reserve(node_count);
  c.nodes.reserve(node_count);
  for (int i = 0; i < node_count; ++i) {
    node::NodeConfig cfg;
    cfg.allow_unencrypted_keystore = true;  // test fixture: no passphrase
    cfg.disable_p2p = false;
    cfg.listen = true;
    cfg.bind_ip = "127.0.0.1";
    cfg.dns_seeds = false;
    cfg.network.default_seeds.clear();  // keep test nodes off the public mainnet seeds
    cfg.node_id = i;
    cfg.max_committee = max_committee;
    cfg.network.min_block_interval_ms = 100;
    cfg.network.round_timeout_ms = 200;
    cfg.p2p_port = c.ports[i];
    cfg.db_path = base + "/node" + std::to_string(i);
    cfg.genesis_path = gpath;
    cfg.allow_unsafe_genesis_override = true;
    cfg.validator_key_file = cfg.db_path + "/keystore/validator.json";
    cfg.validator_passphrase = "test-pass";
    for (int j = 0; j < i; ++j) {
      cfg.peers.push_back("127.0.0.1:" + std::to_string(c.ports[j]));
    }
    keystore::ValidatorKey out_key;
    std::string kerr;
    if (!keystore::create_validator_keystore(cfg.validator_key_file, cfg.validator_passphrase, "mainnet", "sc",
                                             deterministic_seed_for_node_id(i), &out_key, &kerr)) {
      throw std::runtime_error("failed to create validator keystore: " + kerr);
    }
    if (configure) configure(cfg);

    auto n = std::make_unique<node::Node>(cfg);
    if (!n->init()) {
      throw std::runtime_error("init failed for node " + std::to_string(i));
    }
    c.configs.push_back(cfg);
    c.nodes.push_back(std::move(n));
  }
  for (auto& n : c.nodes) n->start();
  return c;
}

Cluster make_cluster_with_timing(const std::string& base, int initial_active, int node_count, std::size_t max_committee,
                                 std::uint64_t min_block_interval_ms, std::uint64_t round_timeout_ms) {
  std::error_code ec;
  std::filesystem::remove_all(base, ec);
  std::filesystem::create_directories(base);
  const std::string gpath = base + "/genesis.json";
  if (!write_mainnet_genesis_file(gpath, static_cast<std::size_t>(std::max(initial_active, node_count)))) {
    throw std::runtime_error("failed to write cluster genesis");
  }

  Cluster c;
  c.base = base;
  c.ports = reserve_test_ports(node_count);
  c.configs.reserve(node_count);
  c.nodes.reserve(node_count);
  for (int i = 0; i < node_count; ++i) {
    node::NodeConfig cfg;
    cfg.allow_unencrypted_keystore = true;  // test fixture: no passphrase
    cfg.disable_p2p = false;
    cfg.listen = true;
    cfg.bind_ip = "127.0.0.1";
    cfg.dns_seeds = false;
    cfg.network.default_seeds.clear();  // keep test nodes off the public mainnet seeds
    cfg.node_id = i;
    cfg.max_committee = max_committee;
    cfg.network.min_block_interval_ms = min_block_interval_ms;
    cfg.network.round_timeout_ms = round_timeout_ms;
    cfg.p2p_port = c.ports[i];
    cfg.db_path = base + "/node" + std::to_string(i);
    cfg.genesis_path = gpath;
    cfg.allow_unsafe_genesis_override = true;
    cfg.validator_key_file = cfg.db_path + "/keystore/validator.json";
    cfg.validator_passphrase = "test-pass";
    for (int j = 0; j < i; ++j) {
      cfg.peers.push_back("127.0.0.1:" + std::to_string(c.ports[j]));
    }
    keystore::ValidatorKey out_key;
    std::string kerr;
    if (!keystore::create_validator_keystore(cfg.validator_key_file, cfg.validator_passphrase, "mainnet", "sc",
                                             deterministic_seed_for_node_id(i), &out_key, &kerr)) {
      throw std::runtime_error("failed to create validator keystore: " + kerr);
    }

    auto n = std::make_unique<node::Node>(cfg);
    if (!n->init()) {
      throw std::runtime_error("init failed for node " + std::to_string(i));
    }
    c.configs.push_back(cfg);
    c.nodes.push_back(std::move(n));
  }
  for (auto& n : c.nodes) n->start();
  return c;
}

Cluster make_p2p_cluster(const std::string& base, int initial_active = 2, int node_count = 2,
                         std::size_t max_committee = MAX_COMMITTEE) {
  std::error_code ec;
  std::filesystem::remove_all(base, ec);
  std::filesystem::create_directories(base);
  const std::string gpath = base + "/genesis.json";
  if (!write_mainnet_genesis_file(gpath, static_cast<std::size_t>(std::max(initial_active, node_count)))) {
    throw std::runtime_error("failed to write cluster genesis");
  }

  Cluster c;
  c.configs.reserve(static_cast<std::size_t>(node_count));
  c.nodes.reserve(static_cast<std::size_t>(node_count));
  std::vector<std::uint16_t> live_ports;
  live_ports.reserve(static_cast<std::size_t>(node_count));
  const std::size_t port_seed = std::hash<std::string>{}(base);
  for (int i = 0; i < node_count; ++i) {
    bool started = false;
    std::string last_kerr;
    for (std::uint16_t attempt = 0; attempt < 8; ++attempt) {
      node::NodeConfig cfg;
      cfg.allow_unencrypted_keystore = true;  // test fixture: no passphrase
      cfg.disable_p2p = false;
      cfg.listen = true;
      cfg.bind_ip = "127.0.0.1";
      cfg.node_id = i;
      cfg.max_committee = max_committee;
      cfg.network.min_block_interval_ms = 100;
      cfg.network.round_timeout_ms = 200;
      const std::size_t offset = port_seed + static_cast<std::size_t>(i) * 257u + static_cast<std::size_t>(attempt) * 17u;
      cfg.p2p_port = static_cast<std::uint16_t>(22000u + (offset % 20000u));
      cfg.network.default_seeds.clear();  // keep test nodes off the public mainnet seeds
      cfg.db_path = base + "/node" + std::to_string(i);
      cfg.genesis_path = gpath;
      cfg.allow_unsafe_genesis_override = true;
      cfg.validator_key_file = cfg.db_path + "/keystore/validator.json";
      cfg.validator_passphrase = "test-pass";
      for (int j = 0; j < i; ++j) {
        cfg.peers.push_back("127.0.0.1:" + std::to_string(live_ports[static_cast<std::size_t>(j)]));
      }
      keystore::ValidatorKey out_key;
      std::string kerr;
      if (!keystore::create_validator_keystore(cfg.validator_key_file, cfg.validator_passphrase, "mainnet", "sc",
                                               deterministic_seed_for_node_id(i), &out_key, &kerr)) {
        throw std::runtime_error("failed to create validator keystore: " + kerr);
      }

      auto n = std::make_unique<node::Node>(cfg);
      if (!n->init()) {
        last_kerr = "init failed for node " + std::to_string(i) + " port=" + std::to_string(cfg.p2p_port);
        continue;
      }
      n->start();
      live_ports.push_back(cfg.p2p_port);
      c.configs.push_back(cfg);
      c.nodes.push_back(std::move(n));
      started = true;
      break;
    }
    if (!started) {
      throw std::runtime_error(last_kerr.empty() ? "failed to allocate p2p port" : last_kerr);
    }
  }
  return c;
}

Tx make_fixture_ingress_tx(std::uint64_t value, std::uint8_t tag) {
  Tx tx;
  tx.version = 1;
  tx.lock_time = 0;
  tx.outputs.push_back(TxOut{value, Bytes{tag}});
  return tx;
}

// Registration floor the node enforces at its next height: same inputs as the private
// Node::effective_validator_min_bond_for_height (network bond fields overwritten by CLI overrides).
std::uint64_t live_registration_bond_amount_for_test(node::Node& node, const node::NodeConfig& cfg) {
  const auto height = node.status().height + 1;
  consensus::ValidatorRegistry registry;
  registry.set_rules(consensus::ValidatorRules{
      .warmup_blocks = cfg.validator_warmup_blocks_override.value_or(cfg.network.validator_warmup_blocks)});
  for (const auto& pub : node.active_validators_for_next_height_for_test()) {
    if (auto info = node.validator_info_for_test(pub); info.has_value()) registry.upsert(pub, *info);
  }
  return consensus::effective_validator_min_bond_for_height(
      cfg.network, cfg.validator_min_bond_override.value_or(cfg.network.validator_min_bond),
      cfg.validator_bond_min_amount_override.value_or(cfg.network.validator_bond_min_amount), registry, height);
}

bool restart_single_node_with_seeded_certified_ingress(const node::NodeConfig& cfg, const std::vector<Bytes>& raw_records,
                                                       std::unique_ptr<node::Node>* out,
                                                       CertifiedIngressFixture* fixture_out = nullptr,
                                                       bool start_node = true) {
  if (!out) return false;
  {
    node::Node seed(cfg);
    if (!seed.init()) return false;
    seed.stop();
  }
  storage::DB db;
  if (!db.open(cfg.db_path)) return false;
  if (!persist_certified_ingress_fixture(cfg, db, raw_records, fixture_out)) return false;
  db.close();

  auto node = std::make_unique<node::Node>(cfg);
  if (!node->init()) return false;
  if (start_node) node->start();
  *out = std::move(node);
  return true;
}

// One attempt: derive lane seqs from a read-only open of db_path, then inject into every node.
// *injected_any is set once any node has accepted a range.
bool append_live_certified_ingress_to_nodes_once(const std::string& db_path, const std::vector<node::Node*>& nodes,
                                                 const std::vector<Bytes>& raw_records, int peer_id, std::string* error,
                                                 const crypto::KeyPair* signer_override, bool* injected_any) {
  if (nodes.empty()) return false;
  struct PendingRange {
    std::uint32_t lane{0};
    std::uint64_t from_seq{0};
    std::uint64_t to_seq{0};
    std::vector<p2p::IngressRecordMsg> records;
  };

  std::map<std::uint32_t, PendingRange> ranges;
  std::map<std::uint32_t, std::uint64_t> next_seq;
  std::map<std::uint32_t, Hash32> prev_lane_root;
  storage::DB db;
  if (!db.open_readonly(db_path)) {
    if (error) *error = "open-db-failed";
    return false;
  }
  const auto tip = db.get_tip();
  const std::uint64_t tip_height = tip.has_value() ? tip->height : 0;
  const std::uint64_t expected_ingress_epoch =
      consensus::committee_epoch_start(tip_height + 1, node::NodeConfig{}.network.committee_epoch_blocks);

  for (const auto& raw : raw_records) {
    auto parsed = Tx::parse(raw);
    if (!parsed.has_value()) {
      if (error) *error = "tx-parse-failed";
      return false;
    }
    const auto lane = consensus::assign_ingress_lane(*parsed);
    auto& seq = next_seq[lane];
    auto& prev_root = prev_lane_root[lane];
    if (seq == 0) {
      const auto state = db.get_lane_state(lane);
      seq = state.has_value() ? (state->max_seq + 1) : 1;
      prev_root = state.has_value() ? state->lane_root : zero_hash();
    }

    auto rec = make_signed_ingress_record_msg(raw, expected_ingress_epoch, seq, prev_root, signer_override);
    prev_root = consensus::compute_lane_root_append(prev_root, rec.certificate.tx_hash);

    auto& range = ranges[lane];
    if (range.records.empty()) {
      range.lane = lane;
      range.from_seq = rec.certificate.seq;
      range.to_seq = rec.certificate.seq;
    } else {
      range.to_seq = rec.certificate.seq;
    }
    range.records.push_back(rec);
    ++seq;
  }
  db.close();

  for (auto* n : nodes) {
    if (!n) continue;
    for (const auto& [lane, range] : ranges) {
      n->set_requested_ingress_range_for_test(peer_id, p2p::GetIngressRangeMsg{lane, range.from_seq, range.to_seq});
      p2p::IngressRangeMsg msg;
      msg.lane = lane;
      msg.from_seq = range.from_seq;
      msg.to_seq = range.to_seq;
      msg.records = range.records;
      const auto ingress_error = n->inject_ingress_range_result_for_test(msg, peer_id);
      if (!ingress_error.empty()) {
        if (error) {
          *error = "node=" + std::to_string(n->p2p_port_for_test()) + " lane=" + std::to_string(lane) +
                   " range=[" + std::to_string(range.from_seq) + "," + std::to_string(range.to_seq) + "] reason=" +
                   ingress_error + " live_tips=";
          for (auto* other : nodes) {
            if (!other) continue;
            const auto st = other->lane_state_for_test(lane);
            *error += std::to_string(other->p2p_port_for_test()) + ":" + (st ? std::to_string(st->max_seq) : "none") +
                      "@h" + std::to_string(other->status().height) + " ";
          }
        }
        return false;
      }
      *injected_any = true;
    }
  }
  return true;
}

// db_path is opened read-only while its owning node is live and writing. A read-only RocksDB
// open is a point-in-time view that can miss the writer's most recent lane-state updates
// (notably when it races a memtable flush / WAL rotation), so the derived seq can lag the
// node's real lane tip and the node rejects it with ingress-seq-discontinuity. Re-derive from
// a fresh open and retry, but only while no node has accepted anything yet: once a node has
// appended, a rejection elsewhere is a real divergence and must surface.
bool append_live_certified_ingress_to_nodes(const std::string& db_path, const std::vector<node::Node*>& nodes,
                                            const std::vector<Bytes>& raw_records, int peer_id = 7,
                                            std::string* error = nullptr,
                                            const crypto::KeyPair* signer_override = nullptr) {
  constexpr int kMaxAttempts = 10;
  std::string attempt_error;
  for (int attempt = 1;; ++attempt) {
    attempt_error.clear();
    bool injected_any = false;
    if (append_live_certified_ingress_to_nodes_once(db_path, nodes, raw_records, peer_id, &attempt_error,
                                                    signer_override, &injected_any)) {
      return true;
    }
    const bool stale_seq_view = attempt_error.find("reason=ingress-seq-discontinuity") != std::string::npos ||
                                attempt_error.find("reason=ingress-prev-lane-root-mismatch") != std::string::npos;
    if (injected_any || !stale_seq_view || attempt >= kMaxAttempts) break;
    std::this_thread::sleep_for(std::chrono::milliseconds(50 * attempt));
  }
  if (error) *error = attempt_error;
  return false;
}

bool append_live_certified_ingress_to_cluster(Cluster& cluster, const std::vector<Bytes>& raw_records, int peer_id = 7,
                                              std::string* error = nullptr) {
  if (cluster.nodes.empty() || cluster.configs.empty()) {
    if (error) *error = "empty-cluster";
    return false;
  }
  std::vector<node::Node*> nodes;
  nodes.reserve(cluster.nodes.size());
  for (const auto& n : cluster.nodes) nodes.push_back(n.get());
  return append_live_certified_ingress_to_nodes(cluster.configs.front().db_path, nodes, raw_records, peer_id, error);
}

void append_live_certified_tx_or_throw(Cluster& cluster, const Tx& tx, const std::string& context) {
  std::string ingress_error;
  if (append_live_certified_ingress_to_cluster(cluster, {tx.serialize()}, 7, &ingress_error)) return;
  throw std::runtime_error(context + ": " + ingress_error);
}

// keep_validator_keys: preserve each node's keystore across the wipe so local keys stay in the
// genesis committee (otherwise init() generates fresh keys and no node can cast its own vote).
bool restart_cluster_with_seeded_certified_ingress(Cluster* cluster, const std::vector<Bytes>& raw_records,
                                                   bool start_nodes = true, bool pause_nodes = false,
                                                   bool keep_validator_keys = false,
                                                   const std::set<std::size_t>& unseeded_nodes = {}) {
  if (!cluster) return false;
  for (auto& n : cluster->nodes) {
    if (n) n->stop();
  }
  cluster->nodes.clear();

  for (std::size_t node_index = 0; node_index < cluster->configs.size(); ++node_index) {
    const auto& cfg = cluster->configs[node_index];
    std::error_code ec;
    std::string saved_key;
    if (keep_validator_keys) {
      std::ifstream in(cfg.validator_key_file, std::ios::binary);
      if (!in) return false;
      saved_key.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    }
    std::filesystem::remove_all(cfg.db_path, ec);
    if (keep_validator_keys) {
      std::filesystem::create_directories(std::filesystem::path(cfg.validator_key_file).parent_path(), ec);
      std::ofstream out(cfg.validator_key_file, std::ios::binary | std::ios::trunc);
      if (!out) return false;
      out << saved_key;
    }
    {
      node::Node seed(cfg);
      if (!seed.init()) return false;
      seed.stop();
    }
    storage::DB db;
    if (!db.open(cfg.db_path)) return false;
    if (!unseeded_nodes.contains(node_index) && !persist_certified_ingress_fixture(cfg, db, raw_records)) return false;
    db.close();

    auto node = std::make_unique<node::Node>(cfg);
    if (!node->init()) return false;
    cluster->nodes.push_back(std::move(node));
  }
  if (start_nodes) {
    if (pause_nodes) {
      for (auto& n : cluster->nodes) {
        if (!n->pause_proposals_for_test(true)) return false;
      }
    }
    for (auto& n : cluster->nodes) n->start();
    if (!wait_for_stable_same_tip(cluster->nodes, std::chrono::seconds(5))) return false;
  }
  return true;
}

bool rpc_get_status_ok(const std::string& host, std::uint16_t port) {
  if (!finalis::net::ensure_sockets()) return false;
  auto fd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (!finalis::net::valid_socket(fd)) return false;
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  if (::inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
    finalis::net::close_socket(fd);
    return false;
  }
  if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
    finalis::net::close_socket(fd);
    return false;
  }
  const std::string body = R"({"jsonrpc":"2.0","id":1,"method":"get_status","params":{}})";
  std::ostringstream req;
  req << "POST /rpc HTTP/1.1\r\n"
      << "Host: " << host << ":" << port << "\r\n"
      << "Content-Type: application/json\r\n"
      << "Content-Length: " << body.size() << "\r\n"
      << "Connection: close\r\n\r\n"
      << body;
  const auto rs = req.str();
  if (::send(fd, rs.data(), static_cast<int>(rs.size()), 0) != static_cast<int>(rs.size())) {
    finalis::net::close_socket(fd);
    return false;
  }
  std::array<char, 4096> buf{};
  std::string resp;
  while (true) {
    const ssize_t n = ::recv(fd, buf.data(), buf.size(), 0);
    if (n <= 0) break;
    resp.append(buf.data(), static_cast<std::size_t>(n));
  }
  finalis::net::close_socket(fd);
  return resp.find("\"result\"") != std::string::npos && resp.find("\"get_status\"") == std::string::npos;
}

bool send_invalid_frame(const std::string& ip, std::uint16_t port, std::uint32_t magic) {
  auto fd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (!finalis::net::valid_socket(fd)) return false;
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  if (::inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) != 1) {
    finalis::net::close_socket(fd);
    return false;
  }
  if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
    finalis::net::close_socket(fd);
    return false;
  }
  std::array<std::uint8_t, 12> hdr{};
  hdr[0] = static_cast<std::uint8_t>(magic & 0xFFu);
  hdr[1] = static_cast<std::uint8_t>((magic >> 8) & 0xFFu);
  hdr[2] = static_cast<std::uint8_t>((magic >> 16) & 0xFFu);
  hdr[3] = static_cast<std::uint8_t>((magic >> 24) & 0xFFu);
  hdr[4] = 0x01;
  hdr[5] = 0x00;
  hdr[6] = 0x09;
  hdr[7] = 0x00;
  hdr[8] = 0xFF;  // absurd payload length, guaranteed invalid by max_payload_len
  hdr[9] = 0xFF;
  hdr[10] = 0xFF;
  hdr[11] = 0x7F;
  const bool ok = ::send(fd, reinterpret_cast<const char*>(hdr.data()), static_cast<int>(hdr.size()), 0) ==
                  static_cast<int>(hdr.size());
  finalis::net::shutdown_socket(fd);
  finalis::net::close_socket(fd);
  return ok;
}

bool connect_and_check_closed(const std::string& ip, std::uint16_t port, std::chrono::milliseconds wait) {
  auto fd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (!finalis::net::valid_socket(fd)) return true;
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  if (::inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) != 1) {
    finalis::net::close_socket(fd);
    return true;
  }
  if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
    finalis::net::close_socket(fd);
    return true;
  }
  std::this_thread::sleep_for(wait);
  char c = 0;
  const ssize_t n = finalis::net::recv_nonblocking(fd, &c, 1);
#ifdef _WIN32
  const int err = finalis::net::socket_last_error();
  const bool would_block = (err == WSAEWOULDBLOCK);
#else
  const bool would_block = (errno == EAGAIN || errno == EWOULDBLOCK);
#endif
  const bool closed = (n == 0) || (n < 0 && !would_block);
  finalis::net::shutdown_socket(fd);
  finalis::net::close_socket(fd);
  return closed;
}

bool send_version_and_expect_disconnect(const std::string& ip, std::uint16_t port, const p2p::VersionMsg& v,
                                        const NetworkConfig& net_cfg, std::chrono::milliseconds wait) {
  auto fd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (!finalis::net::valid_socket(fd)) return false;
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  if (::inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) != 1) {
    finalis::net::close_socket(fd);
    return false;
  }
  if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
    finalis::net::close_socket(fd);
    return false;
  }
  if (!p2p::write_frame_fd(fd, p2p::Frame{p2p::MsgType::VERSION, p2p::ser_version(v)}, net_cfg.magic,
                           net_cfg.protocol_version)) {
    finalis::net::close_socket(fd);
    return false;
  }
  const auto deadline = std::chrono::steady_clock::now() + wait;
  bool disconnected = false;
  while (std::chrono::steady_clock::now() < deadline) {
    char buf[256];
    const ssize_t n = finalis::net::recv_nonblocking(fd, buf, sizeof(buf));
    if (n == 0) {
      disconnected = true;
      break;
    }
    if (n < 0) {
#ifdef _WIN32
      const int err = finalis::net::socket_last_error();
      if (err == WSAEWOULDBLOCK) {
#else
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
#endif
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
        continue;
      }
      disconnected = true;
      break;
    }
  }
  finalis::net::shutdown_socket(fd);
  finalis::net::close_socket(fd);
  return disconnected;
}

finalis::net::SocketHandle connect_bootstrap_joiner_without_sync(const std::string& ip, std::uint16_t port,
                                                                 const p2p::VersionMsg& v,
                                                                 const NetworkConfig& net_cfg) {
  auto fd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (!finalis::net::valid_socket(fd)) return finalis::net::kInvalidSocket;
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  if (::inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) != 1) {
    finalis::net::close_socket(fd);
    return finalis::net::kInvalidSocket;
  }
  if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
    finalis::net::close_socket(fd);
    return finalis::net::kInvalidSocket;
  }
  if (!p2p::write_frame_fd(fd, p2p::Frame{p2p::MsgType::VERSION, p2p::ser_version(v)}, net_cfg.magic,
                           net_cfg.protocol_version)) {
    finalis::net::close_socket(fd);
    return finalis::net::kInvalidSocket;
  }
  if (!p2p::write_frame_fd(fd, p2p::Frame{p2p::MsgType::VERACK, {}}, net_cfg.magic, net_cfg.protocol_version)) {
    finalis::net::close_socket(fd);
    return finalis::net::kInvalidSocket;
  }
  return fd;
}

bool request_finalized_tip_and_expect_response(finalis::net::SocketHandle fd, const NetworkConfig& net_cfg,
                                               std::uint64_t min_height = 0) {
  if (!p2p::write_frame_fd(fd, p2p::Frame{p2p::MsgType::GET_FINALIZED_TIP, p2p::ser_finalized_tip(p2p::FinalizedTipMsg{})},
                           net_cfg.magic, net_cfg.protocol_version)) {
    return false;
  }

  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
  while (std::chrono::steady_clock::now() < deadline) {
    p2p::FrameReadError ferr = p2p::FrameReadError::NONE;
    auto frame = p2p::read_frame_fd_timed(fd, net_cfg.max_payload_len, net_cfg.magic, net_cfg.protocol_version, 500, 500,
                                          &ferr);
    if (!frame.has_value()) {
      if (ferr == p2p::FrameReadError::TIMEOUT_HEADER || ferr == p2p::FrameReadError::TIMEOUT_BODY) continue;
      return false;
    }
    if (frame->msg_type != p2p::MsgType::FINALIZED_TIP) continue;
    auto tip = p2p::de_finalized_tip(frame->payload);
    if (!tip.has_value()) return false;
    if (tip->height < min_height) continue;
    return true;
  }
  return false;
}

struct StoredFrontierArtifact {
  FrontierProposal proposal;
  FinalityCertificate certificate;
};

// The bound bootstrap validator's BLS key || proof (hex) from a node's stored effective genesis, as
// that node advertises it in VERSION.
std::string bootstrap_validator_bls_hex_from_db(const std::string& db_path) {
  storage::DB db;
  if (!db.open_readonly(db_path) && !db.open(db_path)) return {};
  const auto gj = db.get(storage::key_genesis_json());
  if (!gj) return {};
  const auto doc = genesis::parse_json(std::string(gj->begin(), gj->end()));
  if (!doc || doc->initial_validator_bls.size() != 1) return {};
  Bytes kp(doc->initial_validator_bls[0].pubkey.begin(), doc->initial_validator_bls[0].pubkey.end());
  kp.insert(kp.end(), doc->initial_validator_bls[0].pop.begin(), doc->initial_validator_bls[0].pop.end());
  return hex_encode(kp);
}

std::optional<StoredFrontierArtifact> load_frontier_artifact_at_height(const std::string& db_path, std::uint64_t height) {
  storage::DB db;
  if (!db.open_readonly(db_path) && !db.open(db_path)) return std::nullopt;
  const auto transition_id = db.get_frontier_transition_by_height(height);
  if (!transition_id.has_value()) return std::nullopt;
  const auto transition_bytes = db.get_frontier_transition(*transition_id);
  if (!transition_bytes.has_value()) return std::nullopt;
  auto transition = FrontierTransition::parse(*transition_bytes);
  if (!transition.has_value()) return std::nullopt;
  auto cert = db.get_finality_certificate_by_height(height);
  if (!cert.has_value()) return std::nullopt;
  auto ordered_records = db.load_ingress_slice(transition->prev_frontier, transition->next_frontier);
  if (ordered_records.size() != static_cast<std::size_t>(transition->next_frontier - transition->prev_frontier)) {
    return std::nullopt;
  }
  return StoredFrontierArtifact{FrontierProposal{*transition, ordered_records}, *cert};
}

std::optional<StoredFrontierArtifact> find_frontier_artifact_with_tx(const std::string& db_path, const Hash32& txid,
                                                                     std::uint64_t max_h) {
  for (std::uint64_t h = 1; h <= max_h; ++h) {
    auto artifact = load_frontier_artifact_at_height(db_path, h);
    if (!artifact.has_value()) continue;
    for (const auto& raw : artifact->proposal.ordered_records) {
      auto tx = Tx::parse(raw);
      if (tx.has_value() && tx->txid() == txid) return artifact;
    }
  }
  return std::nullopt;
}

std::optional<PubKey32> pubkey_from_hex32(const std::string& hex) {
  auto b = hex_decode(hex);
  if (!b.has_value() || b->size() != 32) return std::nullopt;
  PubKey32 pub{};
  std::copy(b->begin(), b->end(), pub.begin());
  return pub;
}

struct OutOfOrderBlockSyncServer {
  finalis::net::SocketHandle fd{finalis::net::kInvalidSocket};
  std::uint16_t port{0};
  std::atomic<bool> running{false};
  std::thread th;
  NetworkConfig net{};
  std::string genesis_hash;
  Hash32 tip_hash{};
  std::uint64_t tip_height{0};
  PubKey32 bootstrap_pub{};
  std::string consensus_rules_fingerprint;  // advertised as crh=; peers reject VERSION without it
  std::string bootstrap_validator_bls_hex;  // advertised as bootstrap_validator_bls=; adoption needs it
  std::map<Hash32, p2p::TransitionMsg> transitions;
  mutable std::mutex mu;
  mutable std::mutex client_mu;
  std::set<finalis::net::SocketHandle> client_fds;
  std::vector<Hash32> requested_hashes;
  std::size_t disconnect_after_get_block_count{0};
  std::size_t total_get_block_count{0};

  std::optional<std::pair<Hash32, p2p::TransitionMsg>> transition_for_height(std::uint64_t height) const {
    for (const auto& [hash, msg] : transitions) {
      auto proposal = FrontierProposal::parse(msg.frontier_proposal_bytes);
      if (!proposal.has_value()) continue;
      if (proposal->transition.height == height) return std::make_pair(hash, msg);
    }
    return std::nullopt;
  }

  ~OutOfOrderBlockSyncServer() {
    try {
      stop();
    } catch (const std::exception& e) {
      std::cerr << "out-of-order-block-sync-server-stop-exception error=\"" << e.what() << "\"\n";
    } catch (...) {
      std::cerr << "out-of-order-block-sync-server-stop-exception error=unknown\n";
    }
  }

  bool start_transitions(const NetworkConfig& cfg, const std::string& genesis_hash_hex, const PubKey32& pub,
                         std::uint64_t height, const Hash32& hash, std::map<Hash32, p2p::TransitionMsg> send_transitions,
                         std::size_t disconnect_after = 0) {
    net = cfg;
    genesis_hash = genesis_hash_hex;
    bootstrap_pub = pub;
    tip_height = height;
    tip_hash = hash;
    transitions = std::move(send_transitions);
    disconnect_after_get_block_count = disconnect_after;
    total_get_block_count = 0;
    if (!finalis::net::ensure_sockets()) return false;
    fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (!finalis::net::valid_socket(fd)) return false;
    (void)finalis::net::set_reuseaddr(fd);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(0);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) return false;
    if (::listen(fd, 8) != 0) return false;
    sockaddr_in bound{};
    socklen_t bl = sizeof(bound);
    if (::getsockname(fd, reinterpret_cast<sockaddr*>(&bound), &bl) != 0) return false;
    port = ntohs(bound.sin_port);
    running = true;
    th = std::thread([this, lfd = fd]() { run(lfd); });
    return true;
  }

  void stop() {
    running = false;
    if (finalis::net::valid_socket(fd)) {
      finalis::net::shutdown_socket(fd);
      finalis::net::close_socket(fd);
      fd = finalis::net::kInvalidSocket;
    }
    {
      // Shutdown unblocks run()'s reads; run() closes the fd, so it is never closed twice.
      std::lock_guard<std::mutex> lk(client_mu);
      for (auto cfd : client_fds) finalis::net::shutdown_socket(cfd);
    }
    if (th.joinable()) th.join();
  }

  std::vector<Hash32> requested_hashes_snapshot() const {
    std::lock_guard<std::mutex> lk(mu);
    return requested_hashes;
  }

  void run(finalis::net::SocketHandle lfd) {
    while (running) {
      sockaddr_in caddr{};
      socklen_t len = sizeof(caddr);
      const auto cfd = ::accept(lfd, reinterpret_cast<sockaddr*>(&caddr), &len);
      if (!finalis::net::valid_socket(cfd)) return;
      {
        std::lock_guard<std::mutex> lk(client_mu);
        client_fds.insert(cfd);
      }

      bool sent_version = false;
      bool sent_verack = false;
      bool sent_tip = false;
      bool drop_connection = false;

      while (running && !drop_connection) {
        p2p::FrameReadError ferr = p2p::FrameReadError::NONE;
        auto frame = p2p::read_frame_fd_timed(cfd, net.max_payload_len, net.magic, net.protocol_version, 5000, 3000, &ferr);
        if (!frame.has_value()) break;

        switch (frame->msg_type) {
          case p2p::MsgType::VERSION: {
            auto v = p2p::de_version(frame->payload);
            if (!v.has_value()) break;
            if (!sent_version) {
              p2p::VersionMsg reply;
              reply.proto_version = static_cast<std::uint32_t>(net.protocol_version);
              reply.network_id = net.network_id;
              reply.feature_flags = net.feature_flags;
              reply.timestamp = static_cast<std::uint64_t>(::time(nullptr));
              reply.nonce = 777001;
              reply.start_height = tip_height;
              reply.start_hash = tip_hash;
              reply.node_software_version =
                  "finalis-tests/0.7;genesis=" + genesis_hash + ";network_id=" +
                  hex_encode(Bytes(net.network_id.begin(), net.network_id.end())) + ";cv=7;bootstrap_validator=" +
                  hex_encode(Bytes(bootstrap_pub.begin(), bootstrap_pub.end())) + ";validator_pubkey=" +
                  hex_encode(Bytes(bootstrap_pub.begin(), bootstrap_pub.end()));
              if (!consensus_rules_fingerprint.empty()) reply.node_software_version += ";crh=" + consensus_rules_fingerprint;
              if (!bootstrap_validator_bls_hex.empty()) {
                reply.node_software_version += ";bootstrap_validator_bls=" + bootstrap_validator_bls_hex;
              }
              (void)p2p::write_frame_fd(cfd, p2p::Frame{p2p::MsgType::VERSION, p2p::ser_version(reply)}, net.magic,
                                        net.protocol_version);
              sent_version = true;
            }
            break;
          }
          case p2p::MsgType::VERACK: {
            if (!sent_verack) {
              (void)p2p::write_frame_fd(cfd, p2p::Frame{p2p::MsgType::VERACK, {}}, net.magic, net.protocol_version);
              sent_verack = true;
            }
            if (!sent_tip) {
              p2p::FinalizedTipMsg tip{tip_height, tip_hash};
              (void)p2p::write_frame_fd(cfd, p2p::Frame{p2p::MsgType::FINALIZED_TIP, p2p::ser_finalized_tip(tip)}, net.magic,
                                        net.protocol_version);
              sent_tip = true;
            }
            break;
          }
          case p2p::MsgType::GETADDR: {
            (void)p2p::write_frame_fd(cfd, p2p::Frame{p2p::MsgType::ADDR, p2p::ser_addr(p2p::AddrMsg{})}, net.magic,
                                      net.protocol_version);
            break;
          }
          case p2p::MsgType::GET_FINALIZED_TIP: {
            p2p::FinalizedTipMsg tip{tip_height, tip_hash};
            (void)p2p::write_frame_fd(cfd, p2p::Frame{p2p::MsgType::FINALIZED_TIP, p2p::ser_finalized_tip(tip)}, net.magic,
                                      net.protocol_version);
            sent_tip = true;
            break;
          }
          case p2p::MsgType::GET_TRANSITION: {
            auto gb = p2p::de_get_transition(frame->payload);
            if (!gb.has_value()) break;
            {
              std::lock_guard<std::mutex> lk(mu);
              requested_hashes.push_back(gb->hash);
              ++total_get_block_count;
              if (disconnect_after_get_block_count != 0 && total_get_block_count == disconnect_after_get_block_count) {
                drop_connection = true;
                break;
              }
            }
            auto transition_it = transitions.find(gb->hash);
            if (transition_it == transitions.end()) break;
            (void)p2p::write_frame_fd(cfd, p2p::Frame{p2p::MsgType::TRANSITION, p2p::ser_transition(transition_it->second)},
                                      net.magic, net.protocol_version);
            break;
          }
          case p2p::MsgType::GET_TRANSITION_BY_HEIGHT: {
            auto gbh = p2p::de_get_transition_by_height(frame->payload);
            if (!gbh.has_value()) break;
            auto by_height = transition_for_height(gbh->height);
            if (!by_height.has_value()) break;
            {
              std::lock_guard<std::mutex> lk(mu);
              requested_hashes.push_back(by_height->first);
              ++total_get_block_count;
              if (disconnect_after_get_block_count != 0 && total_get_block_count == disconnect_after_get_block_count) {
                drop_connection = true;
                break;
              }
            }
            (void)p2p::write_frame_fd(cfd, p2p::Frame{p2p::MsgType::TRANSITION, p2p::ser_transition(by_height->second)},
                                      net.magic, net.protocol_version);
            break;
          }
          default:
            break;
        }
      }

      {
        std::lock_guard<std::mutex> lk(client_mu);
        client_fds.erase(cfd);
      }
      finalis::net::shutdown_socket(cfd);
      finalis::net::close_socket(cfd);
    }
  }
};

bool write_mainnet_genesis_file(const std::string& path, std::size_t n_validators, std::uint64_t genesis_time_unix) {
  const auto keys = node::Node::deterministic_test_keypairs();
  if (keys.size() < n_validators) return false;

  genesis::Document d;
  d.version = genesis::kGenesisVersion;
  d.network_name = "mainnet";
  d.protocol_version = mainnet_network().protocol_version;
  d.network_id = mainnet_network().network_id;
  d.magic = mainnet_network().magic;
  d.genesis_time_unix = genesis_time_unix;
  d.initial_height = 0;
  d.initial_active_set_size = static_cast<std::uint32_t>(n_validators);
  d.initial_committee_params.min_committee = static_cast<std::uint32_t>(n_validators);
  d.initial_committee_params.max_committee = static_cast<std::uint32_t>(mainnet_network().max_committee);
  d.initial_committee_params.sizing_rule = "min(MAX_COMMITTEE,ACTIVE_SIZE)";
  d.initial_committee_params.c = 2;
  d.monetary_params_ref = "README.md#monetary-policy-7m-hard-cap";
  d.seeds = mainnet_network().default_seeds;
  d.note = "integration-mainnet";
  d.initial_validators.clear();
  for (std::size_t i = 0; i < n_validators; ++i) d.initial_validators.push_back(keys[i].public_key);

  std::filesystem::create_directories(std::filesystem::path(path).parent_path());
  std::ofstream out(path, std::ios::trunc);
  if (!out.good()) return false;
  finalis::test::fill_test_genesis_bls(d);
  out << genesis::to_json(d);
  return out.good();
}

bool write_empty_mainnet_bootstrap_genesis_file(const std::string& path) {
  genesis::Document d;
  d.version = genesis::kGenesisVersion;
  d.network_name = "mainnet";
  d.protocol_version = mainnet_network().protocol_version;
  d.network_id = mainnet_network().network_id;
  d.magic = mainnet_network().magic;
  d.genesis_time_unix = 1735689600ULL;
  d.initial_height = 0;
  d.initial_active_set_size = 0;
  d.initial_committee_params.min_committee = 1;
  d.initial_committee_params.max_committee = static_cast<std::uint32_t>(mainnet_network().max_committee);
  d.initial_committee_params.sizing_rule = "min(MAX_COMMITTEE,ACTIVE_SIZE)";
  d.initial_committee_params.c = 1;
  d.monetary_params_ref = "README.md#monetary-policy-7m-hard-cap";
  d.seeds = {};
  d.note = "single-node-bootstrap-template";

  std::filesystem::create_directories(std::filesystem::path(path).parent_path());
  std::ofstream out(path, std::ios::trunc);
  if (!out.good()) return false;
  finalis::test::fill_test_genesis_bls(d);
  out << genesis::to_json(d);
  return out.good();
}

struct JoinedValidatorFixture {
  Cluster cluster;
  crypto::KeyPair leader_kp{};
  crypto::KeyPair joiner_kp{};
};

std::string summarize_validator_fixture_nodes(const std::vector<std::unique_ptr<node::Node>>& nodes, const PubKey32& joiner_pubkey,
                                              const std::optional<Hash32>& txid = std::nullopt,
                                              const std::vector<node::NodeConfig>* configs = nullptr) {
  std::ostringstream oss;
  for (std::size_t i = 0; i < nodes.size(); ++i) {
    const auto st = nodes[i]->status();
    const auto info = nodes[i]->validator_info_for_test(joiner_pubkey);
    oss << " node" << i << "{h=" << st.height << ",r=" << st.round
        << ",tip=" << hex_encode(Bytes(st.transition_hash.begin(), st.transition_hash.end())).substr(0, 8)
        << ",state=" << st.consensus_state
        << ",votes=" << st.votes_for_current
        << ",active_next=" << nodes[i]->active_validators_for_next_height_for_test().size()
        << ",committee_next=" << nodes[i]->committee_for_next_height_for_test().size()
        << ",err=" << nodes[i]->last_test_hook_error_for_test();
    if (info.has_value()) {
      oss << ",validator_status=" << static_cast<int>(info->status)
          << ",has_bond=" << (info->has_bond ? "yes" : "no")
          << ",bond_txid=" << hex_encode(Bytes(info->bond_outpoint.txid.begin(), info->bond_outpoint.txid.end())).substr(0, 8)
          << ",bonded=" << info->bonded_amount
          << ",unbond_height=" << info->unbond_height;
    } else {
      oss << ",validator_status=missing";
    }
    if (txid.has_value()) {
      const auto in_mempool = nodes[i]->mempool_contains_for_test(*txid);
      bool artifact = false;
      if (configs && i < configs->size()) {
        artifact = find_frontier_artifact_with_tx((*configs)[i].db_path, *txid, st.height).has_value();
      }
      oss << ",tx_mempool=" << (in_mempool ? "yes" : "no")
          << ",tx_artifact=" << (artifact ? "yes" : "no");
    }
    oss << "}";
  }
  return oss.str();
}

JoinedValidatorFixture make_joined_validator_fixture(const std::string& base, std::uint8_t joiner_seed_byte = 1) {
  (void)joiner_seed_byte;
  JoinedValidatorFixture fixture;
  fixture.cluster = make_cluster(base, 2, 2, 2);
  fixture.leader_kp = node::Node::deterministic_test_keypairs()[0];
  fixture.joiner_kp = node::Node::deterministic_test_keypairs()[1];

  auto& nodes = fixture.cluster.nodes;
  if (!wait_for([&]() {
        return nodes[0]->status().height >= 5 && nodes[1]->status().height >= 5;
      }, std::chrono::seconds(30))) {
    throw std::runtime_error("joined fixture failed to reach height 5");
  }
  if (!wait_for([&]() {
        for (const auto& n : nodes) {
          auto info = n->validator_info_for_test(fixture.joiner_kp.public_key);
          if (!info.has_value()) return false;
          if (info->status != consensus::ValidatorStatus::PENDING &&
              info->status != consensus::ValidatorStatus::ACTIVE) {
            return false;
          }
        }
        return true;
      }, std::chrono::seconds(10))) {
    throw std::runtime_error("joined fixture missing validator state");
  }
  if (!wait_for([&]() {
        return nodes[0]->active_validators_for_next_height_for_test().size() >= 2u &&
               nodes[1]->active_validators_for_next_height_for_test().size() >= 2u;
      }, std::chrono::seconds(10))) {
    throw std::runtime_error("joined fixture missing active next-height set");
  }

  return fixture;
}

JoinedValidatorFixture make_bonded_joined_validator_fixture(const std::string& base, std::uint8_t joiner_seed_byte = 1) {
  JoinedValidatorFixture fixture;
  std::error_code ec;
  std::filesystem::remove_all(base, ec);
  std::filesystem::create_directories(base);
  const std::string gpath = base + "/genesis.json";
  if (!write_mainnet_genesis_file(gpath, 2)) {
    throw std::runtime_error("bonded fixture failed to write genesis");
  }
  fixture.cluster.base = base;
  fixture.cluster.ports = reserve_test_ports(2);
  fixture.cluster.configs.reserve(2);
  fixture.cluster.nodes.reserve(2);
  fixture.leader_kp = node::Node::deterministic_test_keypairs()[0];
  fixture.joiner_kp = key_from_byte(joiner_seed_byte);
  for (int i = 0; i < 2; ++i) {
    node::NodeConfig cfg;
    cfg.allow_unencrypted_keystore = true;  // test fixture: no passphrase
    cfg.disable_p2p = false;
    cfg.listen = true;
    cfg.bind_ip = "127.0.0.1";
    cfg.dns_seeds = false;
    cfg.network.default_seeds.clear();  // keep test nodes off the public mainnet seeds
    cfg.node_id = i;
    cfg.max_committee = 3;
    cfg.network.min_block_interval_ms = 100;
    cfg.network.round_timeout_ms = 200;
    cfg.network.validator_join_admission_pow_difficulty_bits = 0;
    cfg.p2p_port = fixture.cluster.ports[i];
    cfg.db_path = base + "/node" + std::to_string(i);
    cfg.genesis_path = gpath;
    cfg.allow_unsafe_genesis_override = true;
    cfg.validator_key_file = cfg.db_path + "/keystore/validator.json";
    cfg.validator_passphrase = "test-pass";
    cfg.validator_warmup_blocks_override = 1;
    for (int j = 0; j < i; ++j) {
      cfg.peers.push_back("127.0.0.1:" + std::to_string(fixture.cluster.ports[j]));
    }
    apply_test_bond_floor(cfg);
    keystore::ValidatorKey out_key;
    std::string kerr;
    if (!keystore::create_validator_keystore(cfg.validator_key_file, cfg.validator_passphrase, "mainnet", "sc",
                                             deterministic_seed_for_node_id(i), &out_key, &kerr)) {
      throw std::runtime_error("bonded fixture keystore failed: " + kerr);
    }
    auto n = std::make_unique<node::Node>(cfg);
    if (!n->init()) throw std::runtime_error("bonded fixture init failed for node " + std::to_string(i));
    fixture.cluster.configs.push_back(cfg);
    fixture.cluster.nodes.push_back(std::move(n));
  }
  for (auto& n : fixture.cluster.nodes) n->start();
  auto& nodes = fixture.cluster.nodes;
  const auto keys = node::Node::deterministic_test_keypairs();
  if (!wait_for([&]() {
        return nodes[0]->status().height >= 5 && nodes[1]->status().height >= 5;
      }, std::chrono::seconds(30))) {
    throw std::runtime_error("bonded fixture cluster failed to reach height 5");
  }

  std::uint64_t bond_amount = 0;
  std::optional<FundedTestWallet> funded;
  // Genesis has no premine; apply_test_bond_floor keeps the bond to ~100 coins (~15s of rewards).
  if (!wait_for([&]() {
        bond_amount = live_registration_bond_amount_for_test(*nodes[0], fixture.cluster.configs[0]);
        funded = find_funded_test_wallet(*nodes[0], keys, bond_amount, 1);
        return funded.has_value();
      }, ci_timeout_seconds(600))) {
    throw std::runtime_error("bonded fixture failed to find funded wallet");
  }

  const auto& sender_kp = keys[funded->key_index];
  storage::DB db;
  if (!db.open_readonly(fixture.cluster.configs[0].db_path)) {
    throw std::runtime_error("bonded fixture failed to open db readonly");
  }
  const auto chain_id =
      ChainId::from_config_and_db(fixture.cluster.configs[0].network, db, std::nullopt, "test", std::nullopt);
  const auto sender_pkh = crypto::h160(Bytes(sender_kp.public_key.begin(), sender_kp.public_key.end()));
  ValidatorJoinAdmissionPowBuildContext pow_ctx{
      .network = &fixture.cluster.configs[0].network,
      .chain_id = &chain_id,
      .current_height = nodes[0]->status().height + 1,
      .finalized_hash_at_height = [&](std::uint64_t height) { return db.get_height_hash(height); },
  };
  auto request_tx = build_validator_join_request_tx(node_chain_domain(nodes[0]), 
      funded->utxos, Bytes(sender_kp.private_key.begin(), sender_kp.private_key.end()), fixture.joiner_kp.public_key,
      Bytes(fixture.joiner_kp.private_key.begin(), fixture.joiner_kp.private_key.end()), fixture.joiner_kp.public_key,
      bond_amount, 0, address::p2pkh_script_pubkey(sender_pkh), nullptr, &pow_ctx);
  db.close();
  if (!request_tx.has_value()) throw std::runtime_error("bonded fixture failed to build join request tx");

  std::string build_error;
  auto proposal = build_live_cluster_frontier_proposal_from_records(fixture.cluster, keys, {request_tx->serialize()},
                                                                    fixture.leader_kp, &build_error);
  if (!proposal.has_value()) {
    throw std::runtime_error("bonded fixture failed to build live join proposal: " + build_error);
  }
  const auto committee = nodes[0]->committee_for_height_round_for_test(proposal->transition.height, proposal->transition.round);
  const auto quorum = consensus::quorum_threshold(committee.size());
  std::size_t available_signers = 0;
  for (const auto& member : committee) {
    if (node_for_pub(keys, member) >= 0) ++available_signers;
  }
  if (available_signers < quorum) {
    throw std::runtime_error("bonded fixture failed to sign live join proposal");
  }
  for (const auto& member : committee) {
    const int signer_id = node_for_pub(keys, member);
    if (signer_id < 0) continue;
    const auto vote =
        make_test_vote(nodes[0]->consensus_domain_for_test(), keys, proposal->transition.height, proposal->transition.round, frontier_proposal_id(*proposal), member);
    const auto vote_result = nodes[0]->inject_network_vote_diagnostic_for_test(vote);
    if (vote_result != "accepted") {
      if (vote_result == "soft-reject:stale-finalized-height") break;
      // The live cluster's own precommit (byte-identical: Ed25519 is deterministic) got there first.
      if (vote_result == "soft-reject:duplicate") continue;
      throw std::runtime_error("bonded fixture failed to inject live join vote: " + vote_result);
    }
  }

  if (!wait_for([&]() {
        auto artifact = find_frontier_artifact_with_tx(fixture.cluster.configs[0].db_path, request_tx->txid(),
                                                       nodes[0]->status().height);
        return artifact.has_value();
      }, ci_timeout_seconds(120))) {
    throw std::runtime_error("bonded fixture join request tx did not finalize:" +
                             summarize_validator_fixture_nodes(nodes, fixture.joiner_kp.public_key, request_tx->txid(),
                                                               &fixture.cluster.configs));
  }

  if (!wait_for([&]() {
        for (const auto& n : nodes) {
          auto info = n->validator_info_for_test(fixture.joiner_kp.public_key);
          if (!info.has_value()) return false;
          if (info->status != consensus::ValidatorStatus::PENDING &&
              info->status != consensus::ValidatorStatus::ACTIVE) {
            return false;
          }
          if (!info->has_bond) return false;
          if (info->bond_outpoint.txid == zero_hash()) return false;
        }
        return true;
      }, ci_timeout_seconds(120))) {
    throw std::runtime_error("bonded fixture did not produce a real joined validator bond:" +
                             summarize_validator_fixture_nodes(nodes, fixture.joiner_kp.public_key, request_tx->txid(),
                                                               &fixture.cluster.configs));
  }
  for (auto& n : nodes) (void)n->pause_proposals_for_test(false);

  return fixture;
}

JoinedValidatorFixture make_bonded_live_joiner_fixture(const std::string& base, std::uint8_t joiner_seed_byte = 1) {
  JoinedValidatorFixture fixture;
  std::cerr << "[slash-fixture] stage=init base=" << base << std::endl;
  std::error_code ec;
  std::filesystem::remove_all(base, ec);
  std::filesystem::create_directories(base);
  const std::string gpath = base + "/genesis.json";
  if (!write_mainnet_genesis_file(gpath, 1)) {
    throw std::runtime_error("slash fixture failed to write genesis");
  }
  fixture.cluster.base = base;
  fixture.cluster.ports = reserve_test_ports(2);
  fixture.cluster.configs.reserve(2);
  fixture.cluster.nodes.reserve(2);
  fixture.leader_kp = node::Node::deterministic_test_keypairs()[0];
  fixture.joiner_kp = key_from_byte(joiner_seed_byte);
  const auto default_keys = node::Node::deterministic_test_keypairs();
  for (int i = 0; i < 2; ++i) {
    node::NodeConfig cfg;
    cfg.allow_unencrypted_keystore = true;  // test fixture: no passphrase
    cfg.disable_p2p = false;
    cfg.listen = true;
    cfg.bind_ip = "127.0.0.1";
    cfg.dns_seeds = false;
    cfg.network.default_seeds.clear();  // keep test nodes off the public mainnet seeds
    cfg.node_id = i;
    cfg.max_committee = 2;
    cfg.network.min_block_interval_ms = 100;
    cfg.network.round_timeout_ms = 200;
    cfg.network.validator_join_admission_pow_difficulty_bits = 0;
    cfg.p2p_port = fixture.cluster.ports[i];
    cfg.db_path = base + "/node" + std::to_string(i);
    cfg.genesis_path = gpath;
    cfg.allow_unsafe_genesis_override = true;
    cfg.validator_key_file = cfg.db_path + "/keystore/validator.json";
    cfg.validator_passphrase = "test-pass";
    cfg.validator_warmup_blocks_override = 1;
    for (int j = 0; j < i; ++j) {
      cfg.peers.push_back("127.0.0.1:" + std::to_string(fixture.cluster.ports[j]));
    }
    apply_test_bond_floor(cfg);
    keystore::ValidatorKey out_key;
    std::string kerr;
    std::array<std::uint8_t, 32> seed = i == 0 ? deterministic_seed_for_node_id(0) : std::array<std::uint8_t, 32>{};
    if (i == 1) seed.fill(joiner_seed_byte);
    if (!keystore::create_validator_keystore(cfg.validator_key_file, cfg.validator_passphrase, "mainnet", "sc", seed,
                                             &out_key, &kerr)) {
      throw std::runtime_error("slash fixture keystore failed: " + kerr);
    }
    auto n = std::make_unique<node::Node>(cfg);
    if (!n->init()) throw std::runtime_error("slash fixture init failed for node " + std::to_string(i));
    fixture.cluster.configs.push_back(cfg);
    fixture.cluster.nodes.push_back(std::move(n));
  }
  for (auto& n : fixture.cluster.nodes) n->start();

  auto& nodes = fixture.cluster.nodes;
  if (!wait_for([&]() { return nodes[0]->status().height >= 5 && nodes[1]->status().height >= 5; },
                std::chrono::seconds(30))) {
    throw std::runtime_error("slash fixture cluster failed to reach height 5");
  }
  std::cerr << "[slash-fixture] stage=height5" << std::endl;

  std::uint64_t bond_amount = 0;
  std::optional<FundedTestWallet> funded;
  if (!wait_for([&]() {
        bond_amount = live_registration_bond_amount_for_test(*nodes[0], fixture.cluster.configs[0]);
        funded = find_funded_test_wallet(*nodes[0], default_keys, bond_amount, 1);
        return funded.has_value();
      }, ci_timeout_seconds(300))) {
    throw std::runtime_error("slash fixture failed to find funded wallet");
  }
  std::cerr << "[slash-fixture] stage=funded-wallet bond=" << bond_amount << std::endl;

  const auto& sender_kp = default_keys[funded->key_index];
  storage::DB db;
  if (!db.open_readonly(fixture.cluster.configs[0].db_path)) {
    throw std::runtime_error("slash fixture failed to open db readonly");
  }
  const auto chain_id =
      ChainId::from_config_and_db(fixture.cluster.configs[0].network, db, std::nullopt, "test", std::nullopt);
  const auto sender_pkh = crypto::h160(Bytes(sender_kp.public_key.begin(), sender_kp.public_key.end()));
  ValidatorJoinAdmissionPowBuildContext pow_ctx{
      .network = &fixture.cluster.configs[0].network,
      .chain_id = &chain_id,
      .current_height = nodes[0]->status().height + 1,
      .finalized_hash_at_height = [&](std::uint64_t height) { return db.get_height_hash(height); },
  };
  auto request_tx = build_validator_join_request_tx(node_chain_domain(nodes[0]), 
      funded->utxos, Bytes(sender_kp.private_key.begin(), sender_kp.private_key.end()), fixture.joiner_kp.public_key,
      Bytes(fixture.joiner_kp.private_key.begin(), fixture.joiner_kp.private_key.end()), fixture.joiner_kp.public_key,
      bond_amount, 0, address::p2pkh_script_pubkey(sender_pkh), nullptr, &pow_ctx);
  db.close();
  if (!request_tx.has_value()) throw std::runtime_error("slash fixture failed to build join request tx");
  std::cerr << "[slash-fixture] stage=join-request-built txid="
            << hex_encode(Bytes(request_tx->txid().begin(), request_tx->txid().end())).substr(0, 8) << std::endl;

  std::string build_error;
  auto proposal = build_live_cluster_frontier_proposal_from_records(fixture.cluster, default_keys, {request_tx->serialize()},
                                                                    fixture.leader_kp, &build_error);
  if (!proposal.has_value()) {
    throw std::runtime_error("slash fixture failed to build live join proposal: " + build_error);
  }
  std::cerr << "[slash-fixture] stage=join-proposal-built height=" << proposal->transition.height
            << " round=" << proposal->transition.round << std::endl;
  const auto committee = nodes[0]->committee_for_height_round_for_test(proposal->transition.height, proposal->transition.round);
  for (const auto& member : committee) {
    const int signer_id = node_for_pub(default_keys, member);
    if (signer_id < 0) continue;
    const auto vote = make_test_vote(nodes[0]->consensus_domain_for_test(), default_keys, proposal->transition.height, proposal->transition.round,
                                     frontier_proposal_id(*proposal), member);
    const auto vote_result = nodes[0]->inject_network_vote_diagnostic_for_test(vote);
    if (vote_result != "accepted" && vote_result != "soft-reject:stale-finalized-height") {
      throw std::runtime_error("slash fixture failed to inject join vote: " + vote_result);
    }
  }

  if (!wait_for([&]() {
        auto artifact = find_frontier_artifact_with_tx(fixture.cluster.configs[0].db_path, request_tx->txid(),
                                                       nodes[0]->status().height);
        return artifact.has_value();
      }, ci_timeout_seconds(120))) {
    throw std::runtime_error("slash fixture join request tx did not finalize:" +
                             summarize_validator_fixture_nodes(nodes, fixture.joiner_kp.public_key, request_tx->txid(),
                                                               &fixture.cluster.configs));
  }
  std::cerr << "[slash-fixture] stage=join-finalized" << std::endl;

  for (auto& n : nodes) (void)n->pause_proposals_for_test(false);

  if (!wait_for([&]() {
        for (const auto& n : nodes) {
          auto info = n->validator_info_for_test(fixture.joiner_kp.public_key);
          if (!info.has_value()) return false;
          if (info->status != consensus::ValidatorStatus::PENDING &&
              info->status != consensus::ValidatorStatus::ACTIVE) {
            return false;
          }
        }
        return true;
      }, ci_timeout_seconds(180))) {
    throw std::runtime_error("slash fixture validator never became pending/active:" +
                             summarize_validator_fixture_nodes(nodes, fixture.joiner_kp.public_key, request_tx->txid(),
                                                               &fixture.cluster.configs));
  }
  std::cerr << "[slash-fixture] stage=pending-active" << std::endl;

  if (!wait_for([&]() {
        for (const auto& n : nodes) {
          const auto active = n->active_validators_for_next_height_for_test();
          if (std::find(active.begin(), active.end(), fixture.joiner_kp.public_key) == active.end()) return false;
        }
        return true;
      }, ci_timeout_seconds(300))) {
    throw std::runtime_error("slash fixture validator never entered active next-height set:" +
                             summarize_validator_fixture_nodes(nodes, fixture.joiner_kp.public_key, request_tx->txid(),
                                                               &fixture.cluster.configs));
  }
  std::cerr << "[slash-fixture] stage=active-next-height" << std::endl;

  return fixture;
}

std::vector<std::string> read_nonempty_lines(const std::filesystem::path& path) {
  std::vector<std::string> out;
  std::ifstream in(path);
  std::string line;
  while (std::getline(in, line)) {
    if (!line.empty()) out.push_back(line);
  }
  return out;
}

}  // namespace

TEST(test_devnet_4_nodes_finalize_and_faults) {
  const auto keys = node::Node::deterministic_test_keypairs();
  ASSERT_TRUE(keys.size() >= 4u);

  auto cluster = make_cluster(unique_test_base("/tmp/finalis_it_faults"), 4, 4, 4);
  auto& nodes = cluster.nodes;

  const bool reached_height_30 = wait_for([&]() {
    for (const auto& n : nodes) {
      if (n->status().height < 30) return false;
    }
    return true;
  }, ci_timeout_seconds(180));
  if (!reached_height_30) {
    std::ostringstream oss;
    oss << "cluster failed to reach height 30:";
    for (std::size_t i = 0; i < nodes.size(); ++i) {
      const auto st = nodes[i]->status();
      oss << " node" << i << "{h=" << st.height << ",r=" << st.round
          << ",tip=" << hex_encode(Bytes(st.transition_hash.begin(), st.transition_hash.end())).substr(0, 8) << "}";
    }
    throw std::runtime_error(oss.str());
  }

  const auto st0 = nodes[0]->status();
  int leader_id = -1;
  const auto leader = nodes[0]->proposer_for_height_round_for_test(st0.height + 1, 0);
  ASSERT_TRUE(leader.has_value());
  leader_id = node_for_pub(keys, *leader);
  ASSERT_TRUE(leader_id >= 0);

  const std::uint64_t before_pause_h = nodes[leader_id]->status().height;
  nodes[leader_id]->pause_proposals_for_test(true);
  std::this_thread::sleep_for(std::chrono::milliseconds(6500));
  nodes[leader_id]->pause_proposals_for_test(false);

  ASSERT_TRUE(wait_for([&]() {
    std::uint64_t min_h = UINT64_MAX;
    for (const auto& n : nodes) min_h = std::min(min_h, n->status().height);
    return min_h > before_pause_h;
  }, std::chrono::seconds(30)));

  // keys[0] is node0's own key, and a proposal still in flight when proposals paused may already
  // carry node0's real precommit. Move every node to a round past it: no proposal exists there.
  const auto enter_fresh_round = [&](std::uint64_t* height, std::uint32_t* round) {
    for (auto& n : nodes) ASSERT_TRUE(n->pause_proposals_for_test(true));
    ASSERT_TRUE(wait_for_stable_same_tip(nodes, ci_timeout_seconds(30)));
    ASSERT_TRUE(wait_for([&]() {
      const auto h = nodes[0]->status().height;
      std::uint32_t r = 0;
      for (const auto& n : nodes) {
        const auto si = n->status();
        if (si.height != h) return false;
        r = std::max(r, si.round);
      }
      for (auto& n : nodes) {
        if (!n->advance_round_for_test(h + 1, r + 1)) return false;
      }
      *height = h + 1;
      *round = r + 1;
      return true;
    }, ci_timeout_seconds(30)));
  };

  // Equivocation injection for validator 0.
  std::uint64_t equivocation_height = 0;
  std::uint32_t equivocation_round = 0;
  enter_fresh_round(&equivocation_height, &equivocation_round);
  const std::uint64_t min_before = equivocation_height - 1;

  for (auto& n : nodes) {
    Vote va;
    va.height = equivocation_height;
    va.round = equivocation_round;
    va.block_id.fill(0xAA);
    va.validator_pubkey = keys[0].public_key;
    auto sa = crypto::ed25519_sign(vote_signing_message(nodes[0]->consensus_domain_for_test(), va.height, va.round, va.block_id), keys[0].private_key);
    ASSERT_TRUE(sa.has_value());
    va.signature = *sa;

    Vote vb = va;
    vb.block_id.fill(0xBB);
    auto sb = crypto::ed25519_sign(vote_signing_message(nodes[0]->consensus_domain_for_test(), vb.height, vb.round, vb.block_id), keys[0].private_key);
    ASSERT_TRUE(sb.has_value());
    vb.signature = *sb;

    // va reaches later nodes by gossip from earlier ones, so "duplicate" also means it counted.
    const auto ra = n->inject_network_vote_diagnostic_for_test(va);
    if (ra != "accepted" && ra != "soft-reject:duplicate") throw std::runtime_error("va rejected: " + ra);
    ASSERT_TRUE(!n->inject_vote_for_test(vb));
  }
  for (auto& n : nodes) ASSERT_TRUE(n->pause_proposals_for_test(false));

  const bool advanced_after_equivocation = wait_for([&]() {
    for (const auto& n : nodes) {
      if (n->status().height < min_before + 2) return false;
    }
    return true;
  }, ci_timeout_seconds(240));
  if (!advanced_after_equivocation) {
    std::ostringstream oss;
    oss << "cluster failed to advance after equivocation:";
    for (std::size_t i = 0; i < nodes.size(); ++i) {
      const auto st = nodes[i]->status();
      oss << " node" << i << "{h=" << st.height << ",r=" << st.round
          << ",tip=" << hex_encode(Bytes(st.transition_hash.begin(), st.transition_hash.end())).substr(0, 8) << "}";
    }
    throw std::runtime_error(oss.str());
  }

  Vote vc;
  vc.validator_pubkey = keys[0].public_key;
  enter_fresh_round(&vc.height, &vc.round);
  vc.block_id.fill(0xCC);
  auto sc = crypto::ed25519_sign(vote_signing_message(nodes[0]->consensus_domain_for_test(), vc.height, vc.round, vc.block_id), keys[0].private_key);
  ASSERT_TRUE(sc.has_value());
  vc.signature = *sc;
  // A known equivocator's first vote per round still counts; a conflicting second one does not.
  if (const auto rc = nodes[1]->inject_network_vote_diagnostic_for_test(vc); rc != "accepted") {
    throw std::runtime_error("vc rejected: " + rc);
  }
  Vote vd = vc;
  vd.block_id.fill(0xDD);
  auto sd = crypto::ed25519_sign(vote_signing_message(nodes[0]->consensus_domain_for_test(), vd.height, vd.round, vd.block_id), keys[0].private_key);
  ASSERT_TRUE(sd.has_value());
  vd.signature = *sd;
  ASSERT_TRUE(!nodes[1]->inject_vote_for_test(vd));
}

TEST(test_primary_timeout_falls_back_to_backup_proposer) {
  if (!can_open_loopback_listener_for_test()) return;
  auto cluster = make_cluster(unique_test_base("/tmp/finalis_it_backup_proposer"), 4, 4, 4);
  auto& nodes = cluster.nodes;

  const bool reached_height_12 = wait_for([&]() {
    for (const auto& n : nodes) {
      if (n->status().height < 12) return false;
    }
    return true;
  }, ci_timeout_seconds(90));
  if (!reached_height_12) {
    std::ostringstream oss;
    oss << "cluster failed to reach height 12:";
    for (std::size_t i = 0; i < nodes.size(); ++i) {
      const auto st = nodes[i]->status();
      oss << " node" << i << "{h=" << st.height << ",r=" << st.round
          << ",tip=" << hex_encode(Bytes(st.transition_hash.begin(), st.transition_hash.end())).substr(0, 8)
          << ",committee=" << (st.next_height_committee_available ? "yes" : "no")
          << ",proposer=" << (st.next_height_proposer_available ? "yes" : "no")
          << ",leader=" << hex_encode(Bytes(st.leader.begin(), st.leader.end())).substr(0, 8) << "}";
    }
    throw std::runtime_error(oss.str());
  }

  for (const auto& n : nodes) n->pause_proposals_for_test(true);

  int primary_id = -1;
  int backup_id = -1;
  std::optional<PubKey32> primary;
  std::optional<PubKey32> backup;
  std::uint64_t frozen_height = 0;
  std::uint64_t next_height = 0;
  ASSERT_TRUE(wait_for([&]() {
    frozen_height = nodes[0]->status().height;
    next_height = frozen_height + 1;
    primary = nodes[0]->proposer_for_height_round_for_test(next_height, 0);
    backup = nodes[0]->proposer_for_height_round_for_test(next_height, 1);
    return primary.has_value() && backup.has_value();
  }, std::chrono::seconds(15)));
  for (std::size_t i = 0; i < nodes.size(); ++i) {
    if (nodes[i]->local_validator_pubkey_for_test() == *primary) primary_id = static_cast<int>(i);
    if (nodes[i]->local_validator_pubkey_for_test() == *backup) backup_id = static_cast<int>(i);
  }
  ASSERT_TRUE(primary_id >= 0);
  ASSERT_TRUE(backup_id >= 0);
  ASSERT_TRUE(primary_id != backup_id);

  const std::uint64_t before_pause_h = frozen_height;
  for (const auto& n : nodes) n->pause_proposals_for_test(false);
  nodes[primary_id]->pause_proposals_for_test(true);
  std::this_thread::sleep_for(std::chrono::milliseconds(6500));
  nodes[primary_id]->pause_proposals_for_test(false);

  const bool advanced_after_primary_pause = wait_for([&]() {
    std::uint64_t min_h = UINT64_MAX;
    for (const auto& n : nodes) min_h = std::min(min_h, n->status().height);
    return min_h > before_pause_h;
  }, std::chrono::seconds(45));
  if (!advanced_after_primary_pause) {
    std::ostringstream oss;
    oss << "cluster did not advance after pausing primary proposer:";
    for (std::size_t i = 0; i < nodes.size(); ++i) {
      const auto st = nodes[i]->status();
      oss << " node" << i << "{h=" << st.height << ",r=" << st.round
          << ",tip=" << hex_encode(Bytes(st.transition_hash.begin(), st.transition_hash.end())).substr(0, 8)
          << ",state=" << st.consensus_state
          << ",leader=" << hex_encode(Bytes(st.leader.begin(), st.leader.end())).substr(0, 8)
          << ",votes=" << st.votes_for_current << "}";
    }
    oss << " primary_node=" << primary_id << " backup_node=" << backup_id;
    throw std::runtime_error(oss.str());
  }
}

TEST(test_tx_finalized_and_visible_on_all_nodes) {
  const auto keys = node::Node::deterministic_test_keypairs();
  ASSERT_TRUE(keys.size() >= 4u);

  auto cluster = make_cluster(unique_test_base("/tmp/finalis_it_tx"));
  auto& nodes = cluster.nodes;

  ASSERT_TRUE(wait_for([&]() {
    for (const auto& n : nodes) {
      if (n->status().height < 34) return false;
    }
    return true;
  }, ci_timeout_seconds(240)));

  std::optional<FundedTestWallet> funded;
  ASSERT_TRUE(wait_for([&]() {
    funded = find_funded_test_wallet(*nodes[0], keys, 2001);
    return funded.has_value();
  }, ci_timeout_seconds(90)));
  ASSERT_TRUE(!funded->utxos.empty());
  const auto sender_index = funded->key_index;
  const auto [spend_op, spend_out] = funded->utxos.front();

  const auto recipient_index = (sender_index + 1) % keys.size();
  const auto recipient_pkh = crypto::h160(Bytes(keys[recipient_index].public_key.begin(), keys[recipient_index].public_key.end()));
  const std::uint64_t fee = 1000;
  const std::uint64_t amount = spend_out.value - fee;
  std::vector<TxOut> outputs{TxOut{amount, address::p2pkh_script_pubkey(recipient_pkh)}};

  std::string err;
  auto tx = build_signed_p2pkh_tx_single_input(node_chain_domain(nodes[0]), spend_op, spend_out, keys[sender_index].private_key, outputs, &err);
  ASSERT_TRUE(tx.has_value());
  const Hash32 txid = tx->txid();
  const auto height_before = nodes[0]->status().height;

  std::string ingress_error;
  if (!append_live_certified_ingress_to_cluster(cluster, {tx->serialize()}, 7, &ingress_error)) {
    throw std::runtime_error("append_live_certified_ingress_to_cluster failed: " + ingress_error);
  }

  OutPoint recipient_op{txid, 0};
  ASSERT_TRUE(wait_for([&]() {
    for (const auto& n : nodes) {
      TxOut out;
      if (!n->has_utxo_for_test(recipient_op, &out)) return false;
      if (out.value != amount) return false;
    }
    return true;
  }, ci_timeout_seconds(240)));
  ASSERT_TRUE(wait_for([&]() {
    for (const auto& n : nodes) {
      if (n->status().height <= height_before) return false;
    }
    return true;
  }, ci_timeout_seconds(240)));
}

TEST(test_epoch_ticket_challenge_anchor_ignores_pending_mempool_state) {
  const auto keys = node::Node::deterministic_test_keypairs();
  auto cluster = make_cluster(unique_test_base("/tmp/finalis_it_ticket_anchor_finalized_only"), 1, 1, 1);
  auto& node = cluster.nodes[0];

  ASSERT_TRUE(wait_for([&]() { return node->status().height >= 34; }, ci_timeout_seconds(120)));
  ASSERT_TRUE(node->pause_proposals_for_test(true));

  const std::uint64_t target_height = node->status().height + 1;
  const auto anchor_before = node->epoch_ticket_challenge_anchor_for_test(target_height);

  std::optional<FundedTestWallet> funded;
  ASSERT_TRUE(wait_for([&]() {
    funded = find_funded_test_wallet(*node, keys, 2001);
    return funded.has_value();
  }, ci_timeout_seconds(90)));
  ASSERT_TRUE(!funded->utxos.empty());
  const auto sender_index = funded->key_index;
  const auto [spend_op, spend_out] = funded->utxos.front();

  const auto recipient_index = (sender_index + 1) % keys.size();
  const auto recipient_pkh = crypto::h160(Bytes(keys[recipient_index].public_key.begin(), keys[recipient_index].public_key.end()));
  std::string err;
  auto tx = build_signed_p2pkh_tx_single_input(node_chain_domain(node), 
      spend_op, spend_out, keys[sender_index].private_key,
      std::vector<TxOut>{TxOut{spend_out.value - 1000, address::p2pkh_script_pubkey(recipient_pkh)}}, &err);
  ASSERT_TRUE(tx.has_value());
  ASSERT_TRUE(node->inject_tx_for_test(*tx, false));
  ASSERT_TRUE(node->mempool_contains_for_test(tx->txid()));

  const auto anchor_after = node->epoch_ticket_challenge_anchor_for_test(target_height);
  ASSERT_EQ(anchor_after, anchor_before);
}

TEST(test_restart_determinism_and_continued_finalization) {
  const auto keys = node::Node::deterministic_test_keypairs();
  ASSERT_TRUE(keys.size() >= 4u);

  const std::string base = unique_test_base("/tmp/finalis_it_restart");
  std::vector<std::uint16_t> original_ports;
  {
    auto cluster = make_cluster(base, 4, 4, MAX_COMMITTEE);
    original_ports = cluster.ports;
    auto& nodes = cluster.nodes;

    const bool node0_reached_12 = wait_for_tip(*nodes[0], 12, ci_timeout_seconds(180));
    if (!node0_reached_12) {
      std::ostringstream oss;
      oss << "pre-restart cluster failed to reach height 12:";
      for (std::size_t i = 0; i < nodes.size(); ++i) {
        const auto st = nodes[i]->status();
        oss << " node" << i << "{h=" << st.height << ",r=" << st.round
            << ",tip=" << hex_encode(Bytes(st.transition_hash.begin(), st.transition_hash.end())).substr(0, 8)
            << ",committee=" << (st.next_height_committee_available ? "yes" : "no")
            << ",proposer=" << (st.next_height_proposer_available ? "yes" : "no")
            << ",leader=" << hex_encode(Bytes(st.leader.begin(), st.leader.end())).substr(0, 8)
            << ",votes=" << st.votes_for_current << ",state=" << st.consensus_state << "}";
      }
      const auto stalled = nodes[0]->status();
      const auto next_height = stalled.height + 1;
      const auto leader = nodes[0]->proposer_for_height_round_for_test(next_height, stalled.round);
      if (leader.has_value()) {
        const int leader_id = node_for_pub(keys, *leader);
        if (leader_id >= 0) {
          auto proposal = nodes[static_cast<std::size_t>(leader_id)]->build_frontier_proposal_for_test(next_height, stalled.round);
          oss << " build_probe={leader_node=" << leader_id << ",proposal=" << (proposal.has_value() ? "yes" : "no")
              << ",error=" << nodes[static_cast<std::size_t>(leader_id)]->last_test_hook_error_for_test();
          if (proposal.has_value()) {
            auto msg = make_test_frontier_propose_msg(nodes[0]->consensus_domain_for_test(), *proposal);
            oss << ",inject=[";
            for (std::size_t i = 0; i < nodes.size(); ++i) {
              if (i) oss << ",";
              oss << nodes[i]->inject_network_propose_result_for_test(msg);
            }
            oss << "]";
          }
          oss << "}";
        }
      }
      throw std::runtime_error(oss.str());
    }
    const bool all_reached_12 = wait_for([&]() {
      for (size_t i = 1; i < nodes.size(); ++i) {
        if (nodes[i]->status().height < 12) return false;
      }
      return true;
    }, ci_timeout_seconds(180));
    if (!all_reached_12) {
      std::ostringstream oss;
      oss << "pre-restart cluster followers failed to reach height 12:";
      for (std::size_t i = 0; i < nodes.size(); ++i) {
        const auto st = nodes[i]->status();
        oss << " node" << i << "{h=" << st.height << ",r=" << st.round
            << ",tip=" << hex_encode(Bytes(st.transition_hash.begin(), st.transition_hash.end())).substr(0, 8)
            << ",committee=" << (st.next_height_committee_available ? "yes" : "no")
            << ",proposer=" << (st.next_height_proposer_available ? "yes" : "no")
            << ",leader=" << hex_encode(Bytes(st.leader.begin(), st.leader.end())).substr(0, 8)
            << ",votes=" << st.votes_for_current << ",state=" << st.consensus_state << "}";
      }
      const auto stalled = nodes[0]->status();
      const auto next_height = stalled.height + 1;
      const auto leader = nodes[0]->proposer_for_height_round_for_test(next_height, stalled.round);
      if (leader.has_value()) {
        const int leader_id = node_for_pub(keys, *leader);
        if (leader_id >= 0) {
          auto proposal = nodes[static_cast<std::size_t>(leader_id)]->build_frontier_proposal_for_test(next_height, stalled.round);
          oss << " build_probe={leader_node=" << leader_id << ",proposal=" << (proposal.has_value() ? "yes" : "no")
              << ",error=" << nodes[static_cast<std::size_t>(leader_id)]->last_test_hook_error_for_test();
          if (proposal.has_value()) {
            auto msg = make_test_frontier_propose_msg(nodes[0]->consensus_domain_for_test(), *proposal);
            oss << ",inject=[";
            for (std::size_t i = 0; i < nodes.size(); ++i) {
              if (i) oss << ",";
              oss << nodes[i]->inject_network_propose_result_for_test(msg);
            }
            oss << "]";
          }
          oss << "}";
        }
      }
      throw std::runtime_error(oss.str());
    }

    ASSERT_TRUE(wait_for_same_tip(nodes, std::chrono::seconds(20)));
    // The cluster keeps finalizing, so read every node's status in one snapshot that agrees;
    // sampling node 0 and then the others let a block land in between (seen under ASan).
    std::vector<decltype(nodes[0]->status())> snapshot;
    ASSERT_TRUE(wait_for(
        [&]() {
          snapshot.clear();
          for (const auto& n : nodes) snapshot.push_back(n->status());
          for (const auto& st : snapshot) {
            if (st.height != snapshot[0].height || st.transition_hash != snapshot[0].transition_hash) return false;
          }
          return true;
        },
        std::chrono::seconds(20)));
    const auto s0 = snapshot[0];
    const auto next_committee_before_restart = nodes[0]->committee_for_next_height_for_test();
    for (size_t i = 1; i < nodes.size(); ++i) {
      const auto& si = snapshot[i];
      ASSERT_EQ(si.height, s0.height);
      ASSERT_EQ(si.transition_hash, s0.transition_hash);
      ASSERT_EQ(nodes[i]->active_validators_for_next_height_for_test(),
                nodes[0]->active_validators_for_next_height_for_test());
      ASSERT_EQ(nodes[i]->committee_for_next_height_for_test(), next_committee_before_restart);
    }

    for (auto& n : nodes) n->pause_proposals_for_test(true);
    const bool stable_before_restart = wait_for_stable_same_tip(nodes, std::chrono::seconds(20));
    if (!stable_before_restart) {
      std::ostringstream oss;
      oss << "cluster not stable before restart while paused:";
      for (std::size_t i = 0; i < nodes.size(); ++i) {
        const auto st = nodes[i]->status();
        oss << " node" << i << "{h=" << st.height << ",r=" << st.round
            << ",tip=" << hex_encode(Bytes(st.transition_hash.begin(), st.transition_hash.end())).substr(0, 8)
            << ",committee=" << (st.next_height_committee_available ? "yes" : "no")
            << ",proposer=" << (st.next_height_proposer_available ? "yes" : "no") << "}";
      }
      throw std::runtime_error(oss.str());
    }
  }

  Cluster restarted;
  restarted.ports = original_ports;
  restarted.nodes.reserve(4);
  for (int i = 0; i < 4; ++i) {
    node::NodeConfig cfg;
    cfg.allow_unencrypted_keystore = true;  // test fixture: no passphrase
    cfg.disable_p2p = false;
    cfg.listen = true;
    cfg.bind_ip = "127.0.0.1";
    cfg.dns_seeds = false;
    cfg.network.default_seeds.clear();  // keep test nodes off the public mainnet seeds
    cfg.node_id = i;
    cfg.max_committee = MAX_COMMITTEE;
    cfg.network.min_block_interval_ms = 100;
    cfg.network.round_timeout_ms = 200;
    cfg.p2p_port = restarted.ports[i];
    cfg.db_path = base + "/node" + std::to_string(i);
    cfg.genesis_path = base + "/genesis.json";
    cfg.allow_unsafe_genesis_override = true;
    cfg.validator_key_file = cfg.db_path + "/keystore/validator.json";
    cfg.validator_passphrase = "test-pass";
    for (int j = 0; j < i; ++j) {
      cfg.peers.push_back("127.0.0.1:" + std::to_string(restarted.ports[j]));
    }

    auto n = std::make_unique<node::Node>(cfg);
    ASSERT_TRUE(n->init());
    n->pause_proposals_for_test(true);
    restarted.nodes.push_back(std::move(n));
  }
  for (auto& n : restarted.nodes) n->start();

  auto& nodes = restarted.nodes;
  const bool stable_after_restart = wait_for_stable_same_tip(nodes, std::chrono::seconds(20));
  if (!stable_after_restart) {
    std::ostringstream oss;
    oss << "cluster not stable after restart:";
    for (std::size_t i = 0; i < nodes.size(); ++i) {
      const auto st = nodes[i]->status();
      oss << " node" << i << "{h=" << st.height << ",r=" << st.round
          << ",tip=" << hex_encode(Bytes(st.transition_hash.begin(), st.transition_hash.end())).substr(0, 8)
          << ",committee=" << (st.next_height_committee_available ? "yes" : "no")
          << ",proposer=" << (st.next_height_proposer_available ? "yes" : "no") << "}";
    }
    throw std::runtime_error(oss.str());
  }
  const auto before = nodes[0]->status();
  const auto next_committee_after_restart = nodes[0]->committee_for_next_height_for_test();

  const bool stable_after_advance = wait_for_stable_same_tip(nodes, std::chrono::seconds(20));
  if (!stable_after_advance) {
    std::ostringstream oss;
    oss << "cluster not stable after restart advance:";
    for (std::size_t i = 0; i < nodes.size(); ++i) {
      const auto st = nodes[i]->status();
      oss << " node" << i << "{h=" << st.height << ",r=" << st.round
          << ",tip=" << hex_encode(Bytes(st.transition_hash.begin(), st.transition_hash.end())).substr(0, 8)
          << ",committee=" << (st.next_height_committee_available ? "yes" : "no")
          << ",proposer=" << (st.next_height_proposer_available ? "yes" : "no") << "}";
    }
    throw std::runtime_error(oss.str());
  }
  for (size_t i = 1; i < nodes.size(); ++i) {
    const auto si = nodes[i]->status();
    ASSERT_EQ(si.height, before.height);
    ASSERT_EQ(si.transition_hash, before.transition_hash);
    ASSERT_EQ(nodes[i]->active_validators_for_next_height_for_test(),
              nodes[0]->active_validators_for_next_height_for_test());
    ASSERT_EQ(nodes[i]->committee_for_next_height_for_test(), next_committee_after_restart);
  }

  for (auto& n : nodes) n->pause_proposals_for_test(false);

  const bool advanced_after_restart =
      wait_for([&]() { return nodes[0]->status().height >= before.height + 4; }, std::chrono::seconds(35));
  if (!advanced_after_restart) {
    std::ostringstream oss;
    oss << "cluster failed to advance after restart:";
    for (std::size_t i = 0; i < nodes.size(); ++i) {
      const auto st = nodes[i]->status();
      oss << " node" << i << "{h=" << st.height << ",r=" << st.round
          << ",tip=" << hex_encode(Bytes(st.transition_hash.begin(), st.transition_hash.end())).substr(0, 8)
          << ",committee=" << (st.next_height_committee_available ? "yes" : "no")
          << ",proposer=" << (st.next_height_proposer_available ? "yes" : "no") << "}";
    }
    throw std::runtime_error(oss.str());
  }
  for (auto& n : nodes) n->pause_proposals_for_test(true);
  const bool stable_after_repause = wait_for_stable_same_tip(nodes, std::chrono::seconds(10));
  if (!stable_after_repause) {
    std::ostringstream oss;
    oss << "cluster not stable after re-pause:";
    for (std::size_t i = 0; i < nodes.size(); ++i) {
      const auto st = nodes[i]->status();
      oss << " node" << i << "{h=" << st.height << ",r=" << st.round
          << ",tip=" << hex_encode(Bytes(st.transition_hash.begin(), st.transition_hash.end())).substr(0, 8)
          << ",committee=" << (st.next_height_committee_available ? "yes" : "no")
          << ",proposer=" << (st.next_height_proposer_available ? "yes" : "no") << "}";
    }
    throw std::runtime_error(oss.str());
  }
  const auto after = nodes[0]->status();
  for (size_t i = 1; i < nodes.size(); ++i) {
    const auto si = nodes[i]->status();
    ASSERT_EQ(si.height, after.height);
    ASSERT_EQ(si.transition_hash, after.transition_hash);
    ASSERT_EQ(nodes[i]->active_validators_for_next_height_for_test(),
              nodes[0]->active_validators_for_next_height_for_test());
  }
}

TEST(test_wallet_send_over_one_coin_multi_input_finalizes_and_chain_continues) {
  const auto keys = node::Node::deterministic_test_keypairs();
  ASSERT_TRUE(keys.size() >= 2u);
  auto cluster = make_cluster(unique_test_base("/tmp/finalis_it_wallet_send_multi_coin"));
  auto& n = cluster.nodes[0];

  std::optional<FundedTestWallet> funded;
  ASSERT_TRUE(wait_for([&]() {
    funded = find_funded_test_wallet(*n, keys, consensus::BASE_UNITS_PER_COIN + DEFAULT_WALLET_SEND_FEE_UNITS, 1);
    return funded.has_value();
  }, ci_timeout_seconds(300)));
  const auto sender_index = funded->key_index;
  const auto sender_pkh = crypto::h160(Bytes(keys[sender_index].public_key.begin(), keys[sender_index].public_key.end()));
  auto utxos = funded->utxos;

  if (utxos.size() < 2u) {
    const auto source = deterministic_largest_first_prevs(utxos);
    ASSERT_TRUE(!source.empty());
    const auto& [split_op, split_prev] = source.front();
    const std::uint64_t split_fee = DEFAULT_WALLET_SEND_FEE_UNITS;
    ASSERT_TRUE(split_prev.value > split_fee + 2);
    const std::uint64_t remainder = split_prev.value - split_fee;
    const std::uint64_t first_half = remainder / 2;
    const std::uint64_t second_half = remainder - first_half;
    ASSERT_TRUE(first_half > 0 && second_half > 0);
    std::string split_err;
    auto split_tx = build_signed_p2pkh_tx_single_input(node_chain_domain(n), 
        split_op, split_prev, keys[sender_index].private_key,
        std::vector<TxOut>{TxOut{first_half, address::p2pkh_script_pubkey(sender_pkh)},
                           TxOut{second_half, address::p2pkh_script_pubkey(sender_pkh)}},
        &split_err);
    ASSERT_TRUE(split_tx.has_value());
    const auto split_txid = split_tx->txid();
    const auto split_height_before = n->status().height;
    std::string split_ingress_error;
    if (!append_live_certified_ingress_to_cluster(cluster, {split_tx->serialize()}, 7, &split_ingress_error)) {
      throw std::runtime_error("append_live_certified_ingress_to_cluster split failed: " + split_ingress_error);
    }
    ASSERT_TRUE(wait_for([&]() { return n->status().height > split_height_before; }, ci_timeout_seconds(120)));
    ASSERT_TRUE(wait_for([&]() {
      TxOut out0;
      TxOut out1;
      return n->has_utxo_for_test(OutPoint{split_txid, 0}, &out0) && out0.value == first_half &&
             n->has_utxo_for_test(OutPoint{split_txid, 1}, &out1) && out1.value == second_half;
    }, ci_timeout_seconds(120)));
    ASSERT_TRUE(wait_for([&]() {
      funded = find_funded_test_wallet(*n, keys, consensus::BASE_UNITS_PER_COIN + DEFAULT_WALLET_SEND_FEE_UNITS, 2);
      return funded.has_value();
    }, ci_timeout_seconds(120)));
    utxos = funded->utxos;
  }

  const auto sorted = deterministic_largest_first_prevs(utxos);
  std::uint64_t total_available = 0;
  for (const auto& prev : sorted) total_available += prev.second.value;
  const std::uint64_t target = std::max<std::uint64_t>(consensus::BASE_UNITS_PER_COIN + DEFAULT_WALLET_SEND_FEE_UNITS,
                                                       sorted[0].second.value + 1);
  ASSERT_TRUE(total_available >= target);
  const std::uint64_t amount = target - DEFAULT_WALLET_SEND_FEE_UNITS;
  ASSERT_TRUE(amount >= consensus::BASE_UNITS_PER_COIN);

  const auto recipient_index = (sender_index + 1) % keys.size();
  const auto recipient_pkh = crypto::h160(Bytes(keys[recipient_index].public_key.begin(), keys[recipient_index].public_key.end()));
  std::string err;
  auto plan = plan_wallet_p2pkh_send(sorted, address::p2pkh_script_pubkey(recipient_pkh),
                                     address::p2pkh_script_pubkey(sender_pkh), amount,
                                     DEFAULT_WALLET_SEND_FEE_UNITS, DEFAULT_WALLET_DUST_THRESHOLD_UNITS, &err);
  ASSERT_TRUE(plan.has_value());
  ASSERT_TRUE(plan->selected_prevs.size() >= 2u);

  auto tx = build_signed_p2pkh_tx_multi_input(node_chain_domain(n), plan->selected_prevs,
                                              Bytes(keys[sender_index].private_key.begin(), keys[sender_index].private_key.end()),
                                              plan->outputs, &err);
  ASSERT_TRUE(tx.has_value());
  const Hash32 txid = tx->txid();
  const auto height_before = n->status().height;

  std::string ingress_error;
  if (!append_live_certified_ingress_to_cluster(cluster, {tx->serialize()}, 7, &ingress_error)) {
    throw std::runtime_error("append_live_certified_ingress_to_cluster send failed: " + ingress_error);
  }
  ASSERT_TRUE(wait_for([&]() { return n->status().height > height_before; }, ci_timeout_seconds(90)));

  OutPoint recipient_op{txid, 0};
  ASSERT_TRUE(wait_for([&]() {
    TxOut out;
    return n->has_utxo_for_test(recipient_op, &out) && out.value == amount;
  }, ci_timeout_seconds(120)));
}

TEST(test_single_validator_restart_recovers_missing_required_epoch_committee_state) {
  const std::string base = unique_test_base("/tmp/finalis_it_restart_missing_required_epoch");
  std::uint64_t before_height = 0;
  std::uint64_t required_epoch = 0;

  {
    auto cluster = make_cluster(base, 1, 1, MAX_COMMITTEE);
    auto& node = *cluster.nodes[0];
    ASSERT_TRUE(wait_for_tip(node, 40, ci_timeout_seconds(180)));
    ASSERT_TRUE(wait_for([&]() { return !node.committee_for_next_height_for_test().empty(); }, ci_timeout_seconds(30)));

    before_height = node.status().height;
    const std::uint64_t step = std::max<std::uint64_t>(1, node::NodeConfig{}.network.committee_epoch_blocks);
    const std::uint64_t next_epoch =
        consensus::committee_epoch_start(before_height + 1, node::NodeConfig{}.network.committee_epoch_blocks);
    ASSERT_TRUE(next_epoch > step);
    required_epoch = next_epoch - step;
  }

  storage::DB db;
  ASSERT_TRUE(db.open(base + "/node0"));
  ASSERT_TRUE(db.erase("EC:" + epoch_db_key_suffix(required_epoch)));
  ASSERT_TRUE(db.erase("ECF:" + epoch_db_key_suffix(required_epoch)));
  db.close();

  node::NodeConfig cfg;
  cfg.allow_unencrypted_keystore = true;  // test fixture: no passphrase
  cfg.disable_p2p = true;
  cfg.node_id = 0;
  cfg.max_committee = MAX_COMMITTEE;
  cfg.network.min_block_interval_ms = 100;
  cfg.network.round_timeout_ms = 200;
  cfg.p2p_port = 0;  // disable_p2p: never bound
  cfg.db_path = base + "/node0";
  cfg.genesis_path = base + "/genesis.json";
  cfg.allow_unsafe_genesis_override = true;
  cfg.validator_key_file = cfg.db_path + "/keystore/validator.json";
  cfg.validator_passphrase = "test-pass";

  node::Node restarted(cfg);
  ASSERT_TRUE(restarted.init());
  ASSERT_TRUE(!restarted.committee_for_next_height_for_test().empty());
  restarted.start();

  ASSERT_TRUE(wait_for([&]() { return restarted.status().height >= before_height + 2; }, ci_timeout_seconds(90)));
  restarted.stop();
}

TEST(test_single_validator_restart_recovers_empty_required_epoch_committee_snapshot) {
  const std::string base = unique_test_base("/tmp/finalis_it_restart_empty_required_epoch");
  std::uint64_t before_height = 0;
  std::uint64_t required_epoch = 0;

  {
    auto cluster = make_cluster(base, 1, 1, MAX_COMMITTEE);
    auto& node = *cluster.nodes[0];
    ASSERT_TRUE(wait_for_tip(node, 40, ci_timeout_seconds(180)));
    ASSERT_TRUE(wait_for([&]() { return !node.committee_for_next_height_for_test().empty(); }, ci_timeout_seconds(30)));

    before_height = node.status().height;
    const std::uint64_t step = std::max<std::uint64_t>(1, node::NodeConfig{}.network.committee_epoch_blocks);
    const std::uint64_t next_epoch =
        consensus::committee_epoch_start(before_height + 1, node::NodeConfig{}.network.committee_epoch_blocks);
    ASSERT_TRUE(next_epoch > step);
    required_epoch = next_epoch - step;
  }

  storage::DB db;
  ASSERT_TRUE(db.open(base + "/node0"));
  auto snapshot = db.get_epoch_committee_snapshot(required_epoch);
  ASSERT_TRUE(snapshot.has_value());
  snapshot->selected_winners.clear();
  snapshot->ordered_members.clear();
  ASSERT_TRUE(db.put_epoch_committee_snapshot(*snapshot));
  db.close();

  node::NodeConfig cfg;
  cfg.allow_unencrypted_keystore = true;  // test fixture: no passphrase
  cfg.disable_p2p = true;
  cfg.node_id = 0;
  cfg.max_committee = MAX_COMMITTEE;
  cfg.network.min_block_interval_ms = 100;
  cfg.network.round_timeout_ms = 200;
  cfg.p2p_port = 0;  // disable_p2p: never bound
  cfg.db_path = base + "/node0";
  cfg.genesis_path = base + "/genesis.json";
  cfg.allow_unsafe_genesis_override = true;
  cfg.validator_key_file = cfg.db_path + "/keystore/validator.json";
  cfg.validator_passphrase = "test-pass";

  node::Node restarted(cfg);
  ASSERT_TRUE(restarted.init());
  ASSERT_TRUE(!restarted.committee_for_next_height_for_test().empty());
  restarted.start();

  ASSERT_TRUE(wait_for([&]() { return restarted.status().height >= before_height + 2; }, ci_timeout_seconds(90)));
  restarted.stop();
}

TEST(test_follower_startup_repairs_missing_required_epoch_from_peer) {
  if (!can_open_loopback_listener_for_test()) return;
  const std::string base = unique_test_base("/tmp/finalis_it_required_epoch_repair_from_peer");
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);
  const std::string gpath = base + "/genesis.json";
  ASSERT_TRUE(write_mainnet_genesis_file(gpath, 2));

  node::NodeConfig bootstrap_cfg;
  bootstrap_cfg.allow_unencrypted_keystore = true;  // test fixture: no passphrase
  bootstrap_cfg.node_id = 0;
  bootstrap_cfg.dns_seeds = false;
  bootstrap_cfg.network.default_seeds.clear();  // keep test nodes off the public mainnet seeds
  bootstrap_cfg.db_path = base + "/bootstrap";
  bootstrap_cfg.p2p_port = reserve_test_port();
  if (bootstrap_cfg.p2p_port == 0) return;
  bootstrap_cfg.genesis_path = gpath;
  bootstrap_cfg.allow_unsafe_genesis_override = true;
  bootstrap_cfg.network.min_block_interval_ms = 100;
  bootstrap_cfg.network.round_timeout_ms = 200;
  bootstrap_cfg.outbound_target = 0;
  bootstrap_cfg.validator_key_file = bootstrap_cfg.db_path + "/keystore/validator.json";
  bootstrap_cfg.validator_passphrase = "test-pass";
  keystore::ValidatorKey bootstrap_key;
  std::string bootstrap_kerr;
  ASSERT_TRUE(keystore::create_validator_keystore(bootstrap_cfg.validator_key_file, bootstrap_cfg.validator_passphrase, "mainnet",
                                                  "sc", deterministic_seed_for_node_id(0), &bootstrap_key, &bootstrap_kerr));

  node::Node bootstrap(bootstrap_cfg);
  if (!bootstrap.init()) {
    return;
  }
  bootstrap.start();

  node::NodeConfig follower_cfg;
  follower_cfg.allow_unencrypted_keystore = true;  // test fixture: no passphrase
  follower_cfg.node_id = 1;
  follower_cfg.dns_seeds = false;
  follower_cfg.network.default_seeds.clear();  // keep test nodes off the public mainnet seeds
  follower_cfg.db_path = base + "/follower";
  follower_cfg.p2p_port = reserve_test_port();
  if (follower_cfg.p2p_port == 0) {
    bootstrap.stop();
    return;
  }
  follower_cfg.genesis_path = gpath;
  follower_cfg.allow_unsafe_genesis_override = true;
  follower_cfg.network.min_block_interval_ms = 100;
  follower_cfg.network.round_timeout_ms = 200;
  follower_cfg.validator_key_file = follower_cfg.db_path + "/keystore/validator.json";
  follower_cfg.validator_passphrase = "test-pass";
  keystore::ValidatorKey follower_key;
  std::string follower_kerr;
  ASSERT_TRUE(keystore::create_validator_keystore(follower_cfg.validator_key_file, follower_cfg.validator_passphrase, "mainnet",
                                                  "sc", deterministic_seed_for_node_id(1), &follower_key, &follower_kerr));
  follower_cfg.peers.push_back("127.0.0.1:" + std::to_string(bootstrap_cfg.p2p_port));

  node::Node follower(follower_cfg);
  if (!follower.init()) {
    bootstrap.stop();
    return;
  }
  follower.start();

  ASSERT_TRUE(wait_for([&]() {
    return bootstrap.status().height >= 34 && follower.status().height >= 34;
  }, ci_timeout_seconds(120)));

  const std::uint64_t before_height = follower.status().height;
  const std::uint64_t step = std::max<std::uint64_t>(1, follower_cfg.network.committee_epoch_blocks);
  const std::uint64_t next_epoch = consensus::committee_epoch_start(before_height + 1, follower_cfg.network.committee_epoch_blocks);
  ASSERT_TRUE(next_epoch > step);
  const std::uint64_t required_epoch = next_epoch - step;

  follower.stop();

  storage::DB db;
  ASSERT_TRUE(db.open(follower_cfg.db_path));
  ASSERT_TRUE(db.erase("EC:" + epoch_db_key_suffix(required_epoch)));
  ASSERT_TRUE(db.erase("ECF:" + epoch_db_key_suffix(required_epoch)));
  // Keep persisted epoch-ticket state intact. This test targets required-epoch
  // committee record repair (EC/ECF) and should not invalidate canonical
  // frontier derivation inputs.
  db.close();

  node::Node repaired_follower(follower_cfg);
  ASSERT_TRUE(repaired_follower.init());
  ASSERT_TRUE(!repaired_follower.committee_for_next_height_for_test().empty());
  repaired_follower.start();

  ASSERT_TRUE(wait_for([&]() {
    return repaired_follower.status().height >= before_height + 2;
  }, std::chrono::seconds(30)));

  repaired_follower.stop();
  bootstrap.stop();
}

TEST(test_follower_peer_loss_stalls_and_recovers_after_reconnect) {
  if (!can_open_loopback_listener_for_test()) return;
  const auto keys = node::Node::deterministic_test_keypairs();
  ASSERT_TRUE(keys.size() >= 2u);
  const std::string base = unique_test_base("/tmp/finalis_it_runtime_repair_reconnect");
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);
  const std::string gpath = base + "/genesis.json";
  ASSERT_TRUE(write_mainnet_genesis_file(gpath, 2));

  node::NodeConfig bootstrap_cfg;
  bootstrap_cfg.allow_unencrypted_keystore = true;  // test fixture: no passphrase
  bootstrap_cfg.node_id = 0;
  bootstrap_cfg.dns_seeds = false;
  bootstrap_cfg.network.default_seeds.clear();  // keep test nodes off the public mainnet seeds
  bootstrap_cfg.db_path = base + "/bootstrap";
  bootstrap_cfg.p2p_port = reserve_test_port();
  if (bootstrap_cfg.p2p_port == 0) return;
  bootstrap_cfg.genesis_path = gpath;
  bootstrap_cfg.allow_unsafe_genesis_override = true;
  bootstrap_cfg.network.min_block_interval_ms = 100;
  bootstrap_cfg.network.round_timeout_ms = 200;
  bootstrap_cfg.validator_key_file = bootstrap_cfg.db_path + "/keystore/validator.json";
  bootstrap_cfg.validator_passphrase = "test-pass";
  keystore::ValidatorKey bootstrap_key;
  std::string bootstrap_kerr;
  ASSERT_TRUE(keystore::create_validator_keystore(bootstrap_cfg.validator_key_file, bootstrap_cfg.validator_passphrase, "mainnet",
                                                  "sc", deterministic_seed_for_node_id(0), &bootstrap_key, &bootstrap_kerr));

  node::Node bootstrap(bootstrap_cfg);
  if (!bootstrap.init()) return;
  bootstrap.start();

  node::NodeConfig follower_cfg;
  follower_cfg.allow_unencrypted_keystore = true;  // test fixture: no passphrase
  follower_cfg.node_id = 1;
  follower_cfg.dns_seeds = false;
  follower_cfg.network.default_seeds.clear();  // keep test nodes off the public mainnet seeds
  follower_cfg.db_path = base + "/follower";
  follower_cfg.p2p_port = reserve_test_port();
  if (follower_cfg.p2p_port == 0) {
    bootstrap.stop();
    return;
  }
  follower_cfg.genesis_path = gpath;
  follower_cfg.allow_unsafe_genesis_override = true;
  follower_cfg.network.min_block_interval_ms = 100;
  follower_cfg.network.round_timeout_ms = 200;
  follower_cfg.validator_key_file = follower_cfg.db_path + "/keystore/validator.json";
  follower_cfg.validator_passphrase = "test-pass";
  keystore::ValidatorKey follower_key;
  std::string follower_kerr;
  ASSERT_TRUE(keystore::create_validator_keystore(follower_cfg.validator_key_file, follower_cfg.validator_passphrase, "mainnet",
                                                  "sc", deterministic_seed_for_node_id(1), &follower_key, &follower_kerr));
  follower_cfg.peers.push_back("127.0.0.1:" + std::to_string(bootstrap_cfg.p2p_port));
  follower_cfg.outbound_target = 1;

  node::Node follower(follower_cfg);
  if (!follower.init()) {
    bootstrap.stop();
    return;
  }
  follower.start();

  ASSERT_TRUE(wait_for([&]() {
    const auto s0 = bootstrap.status();
    const auto s1 = follower.status();
    return s0.height >= 5 && s1.height >= 5 && s0.transition_hash == s1.transition_hash && s1.established_peers >= 1;
  }, ci_timeout_seconds(60)));

  ASSERT_TRUE(bootstrap.pause_proposals_for_test(true));
  ASSERT_TRUE(follower.pause_proposals_for_test(true));
  ASSERT_TRUE(wait_for([&]() {
    const auto s0 = bootstrap.status();
    const auto s1 = follower.status();
    return s0.height == s1.height && s0.transition_hash == s1.transition_hash;
  }, std::chrono::seconds(5)));

  const std::uint64_t synced_height = follower.status().height;
  bootstrap.stop();

  ASSERT_TRUE(wait_for([&]() {
    const auto s = follower.status();
    return s.established_peers == 0;
  }, std::chrono::seconds(10)));

  ASSERT_TRUE(wait_for([&]() {
    const auto s = follower.status();
    return s.consensus_state == "REPAIRING" || s.consensus_state == "SYNCING";
  }, std::chrono::seconds(10)));

  {
    const auto s = follower.status();
    ASSERT_TRUE(s.consensus_state == "REPAIRING" || s.consensus_state == "SYNCING");
    ASSERT_TRUE(s.height >= synced_height);
  }

  node::Node bootstrap_restarted(bootstrap_cfg);
  if (!bootstrap_restarted.init()) {
    follower.stop();
    throw std::runtime_error("bootstrap_restarted_init_failed");
  }
  bootstrap_restarted.start();

  ASSERT_TRUE(wait_for([&]() {
    const auto s0 = bootstrap_restarted.status();
    const auto s1 = follower.status();
    return s0.established_peers >= 1 && s1.established_peers >= 1;
  }, std::chrono::seconds(10)));

  ASSERT_TRUE(bootstrap_restarted.pause_proposals_for_test(false));
  ASSERT_TRUE(follower.pause_proposals_for_test(false));

  const bool recovered = wait_for([&]() {
    const auto s = follower.status();
    return s.established_peers >= 1 && s.consensus_state != "REPAIRING" && s.height >= synced_height + 2;
  }, ci_timeout_seconds(90));
  if (!recovered) {
    const auto sb = bootstrap_restarted.status();
    const auto sf = follower.status();
    bool manual_round_advance = false;
    if (sb.height == sf.height && sb.transition_hash == sf.transition_hash) {
      const auto target_round = std::max(sb.round, sf.round) + 1;
      const auto expected_height = sb.height + 1;
      const bool advanced_bootstrap = bootstrap_restarted.advance_round_for_test(expected_height, target_round);
      const bool advanced_follower = follower.advance_round_for_test(expected_height, target_round);
      manual_round_advance = advanced_bootstrap || advanced_follower;
    }
    if (manual_round_advance) {
      const bool recovered_after_advance = wait_for([&]() {
        const auto s = follower.status();
        return s.established_peers >= 1 && s.consensus_state != "REPAIRING" && s.height >= synced_height + 2;
      }, ci_timeout_seconds(30));
      if (recovered_after_advance) {
        follower.stop();
        bootstrap_restarted.stop();
        return;
      }
    }
    bool restarted_recovery = false;
    {
      follower.stop();
      node::Node follower_restarted(follower_cfg);
      if (follower_restarted.init()) {
        follower_restarted.start();
        restarted_recovery = wait_for([&]() {
          const auto s0 = bootstrap_restarted.status();
          const auto s1 = follower_restarted.status();
          return s0.established_peers >= 1 && s1.established_peers >= 1 && s0.height >= synced_height + 2 &&
                 s1.height >= synced_height + 2 && s0.transition_hash == s1.transition_hash;
        }, ci_timeout_seconds(60));
        follower_restarted.stop();
      }
    }
    if (restarted_recovery) {
      bootstrap_restarted.stop();
      return;
    }
    const auto probe_round = std::max(sb.round, sf.round);
    const auto probe_height =
        (sb.height == sf.height && sb.transition_hash == sf.transition_hash) ? (sb.height + 1)
                                                                             : (std::max(sb.height, sf.height) + 1);
    const auto leader = bootstrap_restarted.proposer_for_height_round_for_test(probe_height, probe_round);
    int probe_leader_id = -1;
    bool probe_has_proposal = false;
    std::string probe_build_error;
    std::optional<bool> probe_leader_inject_ok;
    std::optional<std::string> probe_bootstrap_inject;
    std::optional<std::string> probe_follower_inject;
    if (leader.has_value()) {
      probe_leader_id = node_for_pub(keys, *leader);
      if (probe_leader_id >= 0) {
        node::Node* leader_node = probe_leader_id == 0 ? &bootstrap_restarted : &follower;
        auto proposal = leader_node->build_frontier_proposal_for_test(probe_height, probe_round);
        probe_has_proposal = proposal.has_value();
        probe_build_error = leader_node->last_test_hook_error_for_test();
        if (proposal.has_value()) {
          auto msg = make_test_frontier_propose_msg(bootstrap.consensus_domain_for_test(), *proposal);
          const bool leader_ok = leader_node->inject_propose_msg_for_test(msg);
          const auto bootstrap_result = bootstrap_restarted.inject_network_propose_result_for_test(msg);
          const auto follower_result = follower.inject_network_propose_result_for_test(msg);
          probe_leader_inject_ok = leader_ok;
          probe_bootstrap_inject = bootstrap_result;
          probe_follower_inject = follower_result;
          if (bootstrap_result == "accepted" || follower_result == "accepted") {
            const bool kicked = wait_for([&]() {
              const auto s0 = bootstrap_restarted.status();
              const auto s1 = follower.status();
              return s0.height >= probe_height && s1.height >= probe_height && s0.transition_hash == s1.transition_hash;
            }, std::chrono::seconds(20));
            if (kicked) {
              follower.stop();
              bootstrap_restarted.stop();
              return;
            }
          }
        }
      }
    }

    std::ostringstream oss;
    oss << "post-reconnect progress stalled:"
        << " bootstrap{h=" << sb.height << ",r=" << sb.round << ",peers=" << sb.peers << ",est=" << sb.established_peers
        << ",out=" << sb.outbound_connected << ",in=" << sb.inbound_connected << ",state=" << sb.consensus_state << "}"
        << " follower{h=" << sf.height << ",r=" << sf.round << ",peers=" << sf.peers << ",est=" << sf.established_peers
        << ",out=" << sf.outbound_connected << ",in=" << sf.inbound_connected << ",state=" << sf.consensus_state << "}";
    if (leader.has_value() && probe_leader_id >= 0) {
      oss << " build_probe={leader_node=" << probe_leader_id << ",proposal=" << (probe_has_proposal ? "yes" : "no")
          << ",error=" << probe_build_error;
      if (probe_leader_inject_ok.has_value()) {
        oss << ",leader_ok=" << (*probe_leader_inject_ok ? "yes" : "no");
      }
      if (probe_bootstrap_inject.has_value() || probe_follower_inject.has_value()) {
        oss << ",inject=[" << (probe_bootstrap_inject.has_value() ? *probe_bootstrap_inject : "?") << ","
            << (probe_follower_inject.has_value() ? *probe_follower_inject : "?") << "]";
      }
      oss << "}";
    }
    throw std::runtime_error(oss.str());
  }

  follower.stop();
  bootstrap_restarted.stop();
}

TEST(test_validator_outage_and_heal_converges) {
  const char* stage = "init";
  try {
    const std::string base = unique_test_base("/tmp/finalis_it_validator_partition_heal");
    auto cluster = make_cluster(base, 3, 3, 3);
    auto& cfgs = cluster.configs;

    stage = "initial-progress";
    ASSERT_TRUE(wait_for([&]() {
      const auto s0 = cluster.nodes[0]->status();
      const auto s1 = cluster.nodes[1]->status();
      const auto s2 = cluster.nodes[2]->status();
      return s0.height >= 5 && s1.height >= 5 && s2.height >= 5;
    }, std::chrono::seconds(120)));

    stage = "pause-majority-sync";
    for (auto& n : cluster.nodes) ASSERT_TRUE(n->pause_proposals_for_test(true));
    ASSERT_TRUE(wait_for_stable_same_tip(cluster.nodes, std::chrono::seconds(30)));

    stage = "resume-after-sync";
    for (auto& n : cluster.nodes) ASSERT_TRUE(n->pause_proposals_for_test(false));

    const auto majority_tip = cluster.nodes[0]->status();

    stage = "stop-outage-node";
    cluster.nodes[2]->stop();

    stage = "reset-outage-node";
    cluster.nodes[2].reset();

    stage = "majority-continues";
    ASSERT_TRUE(wait_for([&]() {
      const auto s0 = cluster.nodes[0]->status();
      const auto s1 = cluster.nodes[1]->status();
      return s0.height >= majority_tip.height && s1.height >= majority_tip.height &&
             s0.transition_hash == s1.transition_hash;
    }, std::chrono::seconds(30)));

    stage = "restart-construct";
    auto restarted = std::make_unique<node::Node>(cfgs[2]);

    stage = "restart-init";
    ASSERT_TRUE(restarted->init());

    stage = "restart-start";
    restarted->start();
    cluster.nodes[2] = std::move(restarted);

    stage = "heal-progress";
    ASSERT_TRUE(wait_for([&]() {
      const auto s0 = cluster.nodes[0]->status();
      const auto s1 = cluster.nodes[1]->status();
      const auto s2 = cluster.nodes[2]->status();
          return s2.height >= majority_tip.height && s0.height == s1.height &&
            s0.transition_hash == s1.transition_hash;
    }, ci_timeout_seconds(120)));

    stage = "pause-final-sync";
    for (auto& n : cluster.nodes) ASSERT_TRUE(n->pause_proposals_for_test(true));
    ASSERT_TRUE(wait_for_same_tip(cluster.nodes, ci_timeout_seconds(120)));

    stage = "final-assertions";
    const auto s0 = cluster.nodes[0]->status();
    const auto active0 = cluster.nodes[0]->active_validators_for_next_height_for_test();
    const auto committee0 = cluster.nodes[0]->committee_for_next_height_for_test();
    ASSERT_EQ(active0.size(), 3u);
    ASSERT_EQ(committee0.size(), 3u);
    for (size_t i = 1; i < cluster.nodes.size(); ++i) {
      const auto si = cluster.nodes[i]->status();
      ASSERT_EQ(si.height, s0.height);
      ASSERT_EQ(si.transition_hash, s0.transition_hash);
      ASSERT_EQ(cluster.nodes[i]->active_validators_for_next_height_for_test(), active0);
      ASSERT_EQ(cluster.nodes[i]->committee_for_next_height_for_test(), committee0);
    }
  } catch (const std::system_error& e) {
    throw std::runtime_error(std::string("validator_outage_and_heal stage=") + stage +
                             " system_error=" + e.what());
  }
}

TEST(test_permissionless_join_pending_to_active_after_warmup) {
  auto fixture = make_joined_validator_fixture(unique_test_base("/tmp/finalis_it_join"), 99);
  auto& nodes = fixture.cluster.nodes;
  ASSERT_TRUE(wait_for([&]() {
    for (const auto& n : nodes) {
      auto info = n->validator_info_for_test(fixture.joiner_kp.public_key);
      if (!info.has_value()) return false;
      if (info->status != consensus::ValidatorStatus::PENDING &&
          info->status != consensus::ValidatorStatus::ACTIVE) {
        return false;
      }
    }
    return true;
  }, std::chrono::seconds(120)));

  ASSERT_TRUE(wait_for([&]() {
    for (const auto& n : nodes) {
      auto active = n->active_validators_for_next_height_for_test();
      bool found = std::find(active.begin(), active.end(), fixture.joiner_kp.public_key) != active.end();
      if (!found) return false;
    }
    return true;
  }, std::chrono::seconds(120)));
}

// A time-locked transfer end to end on a live node: the envelope enters through the node's intake,
// a block escrows it, the committee time-signs the unlock height, and block unlock + 1 opens and
// applies the transfer first and refunds the bond. With `reveal`, the body is data only: block
// unlock + 1 publishes it ("TR:" row) and refunds the bond.
void run_timed_transfer_on_cluster(std::size_t n_nodes, const std::string& base, bool reveal = false) {
  const auto keys = node::Node::deterministic_test_keypairs();
  auto cluster = make_cluster(base, static_cast<int>(n_nodes), static_cast<int>(n_nodes), MAX_COMMITTEE);
  auto& n0 = *cluster.nodes[0];
  ASSERT_TRUE(wait_for_tip(n0, 3, ci_timeout_seconds(40)));
  const std::uint64_t bond = consensus::kTxTimedMinForfeitBond;
  const std::uint64_t prepaid = 1'000;

  std::optional<FundedTestWallet> funded;
  ASSERT_TRUE(wait_for([&]() {
    funded = find_funded_test_wallet(n0, keys, 2 * (bond + prepaid), 2);
    return funded.has_value();
  }, ci_timeout_seconds(120)));
  auto coins = funded->utxos;
  std::sort(coins.begin(), coins.end(), [](const auto& a, const auto& b) { return a.second.value > b.second.value; });
  ASSERT_TRUE(coins[0].second.value >= bond + prepaid);
  const auto& sender = keys[funded->key_index];
  const Bytes sender_priv(sender.private_key.begin(), sender.private_key.end());
  const auto sender_script = coins[0].second.script_pubkey;
  const auto recipient = crypto::keypair_from_seed32(std::array<std::uint8_t, 32>{0x5d});
  const auto recipient_pkh = crypto::h160(Bytes(recipient->public_key.begin(), recipient->public_key.end()));
  const auto domain = node_chain_domain(n0);

  const auto& epoch_blocks = cluster.configs[0].network.committee_epoch_blocks;
  const auto tip = n0.status().height;
  const auto unlock = std::min(tip + 4, consensus::committee_epoch_start(tip + 1, epoch_blocks) + epoch_blocks - 1);
  ASSERT_TRUE(unlock >= tip + 2);  // room for the envelope to be included first
  std::optional<storage::FinalizedCommitteeCheckpoint> checkpoint;
  {
    storage::DB db;
    ASSERT_TRUE(db.open_readonly(base + "/node0"));
    checkpoint = db.get_finalized_committee_checkpoint(consensus::committee_epoch_start(unlock, epoch_blocks));
  }
  ASSERT_TRUE(checkpoint.has_value() && !checkpoint->ordered_bls_keys.empty());

  const auto body = build_signed_p2pkh_tx_single_input(
      domain, coins[1].first, coins[1].second, sender_priv,
      {TxOut{coins[1].second.value - 500, address::p2pkh_script_pubkey(recipient_pkh)}});
  ASSERT_TRUE(body.has_value());
  TimedTxParams params;
  params.fee_outpoint = coins[0].first;
  params.fee_prev_out = coins[0].second;
  params.prepaid_fee = prepaid;
  params.forfeit_bond = bond;
  params.bond_refund_script = sender_script;
  if (coins[0].second.value > bond + prepaid) {
    params.fee_change = TxOut{coins[0].second.value - bond - prepaid, sender_script};
  }
  params.unlock_height = unlock;
  params.committee_epoch = consensus::committee_epoch_start(unlock, epoch_blocks);
  params.committee_root = consensus::committee_bls_key_root(checkpoint->ordered_bls_keys);
  params.committee_keys = checkpoint->ordered_bls_keys;
  params.threshold = static_cast<std::uint32_t>(consensus::time_signature_threshold(checkpoint->ordered_bls_keys.size()));
  Hash32 seed{};
  seed.fill(0x3c);
  const Bytes revealed{'s', 'e', 'a', 'l', 'e', 'd', ' ', 'b', 'i', 'd'};
  const auto timed = reveal ? build_signed_timed_tx(domain, params, TimedReveal{revealed}, sender_priv, seed)
                            : build_signed_timed_tx(domain, params, AnyTx{*body}, sender_priv, seed);
  ASSERT_TRUE(timed.has_value());
  std::string reason;
  ASSERT_TRUE(n0.inject_record_for_test(timed->serialize(), &reason));
  const auto sender_pkh = crypto::h160(Bytes(sender.public_key.begin(), sender.public_key.end()));
  const auto refunded = [&]() {
    for (const auto& [op, out] : n0.find_utxos_by_pubkey_hash_for_test(sender_pkh)) {
      const auto refund_op = consensus::timed_refund_outpoint(timed->txid());
      if (op.txid == refund_op.txid && op.index == refund_op.index && out.value == bond) return true;
    }
    return false;
  };
  if (reveal) {
    std::optional<storage::DB::TimedRevealLocation> published;
    ASSERT_TRUE(wait_for([&]() {
      storage::DB db;
      if (!db.open_readonly(base + "/node0")) return false;
      published = db.get_timed_reveal(timed->txid());
      return published.has_value();
    }, ci_timeout_seconds(120)));
    ASSERT_EQ(published->height, unlock + 1);
    ASSERT_TRUE(published->data == revealed);
    ASSERT_TRUE(refunded());
    return;
  }

  std::optional<storage::DB::TxLocation> included;
  std::optional<storage::DB::TxLocation> opened;
  ASSERT_TRUE(wait_for([&]() {
    storage::DB db;
    if (!db.open_readonly(base + "/node0")) return false;
    included = db.get_tx_index(timed->txid());
    opened = db.get_tx_index(body->txid());
    return included.has_value() && opened.has_value();
  }, ci_timeout_seconds(120)));
  ASSERT_TRUE(included->height <= unlock);
  ASSERT_EQ(opened->height, unlock + 1);
  const auto recipient_utxos = n0.find_utxos_by_pubkey_hash_for_test(recipient_pkh);
  ASSERT_EQ(recipient_utxos.size(), 1u);
  ASSERT_EQ(recipient_utxos[0].second.value, coins[1].second.value - 500);
  ASSERT_TRUE(refunded());
  // Every node settled it the same way.
  for (std::size_t i = 1; i < n_nodes; ++i) {
    ASSERT_TRUE(wait_for([&]() { return cluster.nodes[i]->find_utxos_by_pubkey_hash_for_test(recipient_pkh).size() == 1; },
                         ci_timeout_seconds(60)));
  }
}

TEST(test_timed_transfer_opens_after_its_unlock_height_on_a_live_node) {
  run_timed_transfer_on_cluster(1, unique_test_base("/tmp/finalis_it_timed_transfer"));
}

TEST(test_timed_reveal_is_published_after_its_unlock_height_on_a_live_node) {
  run_timed_transfer_on_cluster(1, unique_test_base("/tmp/finalis_it_timed_reveal"), true);
}

// Four validators: the envelope reaches its lane's certifier from another node, and the unlock
// height's time signature is aggregated from several validators' signatures.
TEST(test_timed_transfer_on_a_four_validator_cluster) {
  run_timed_transfer_on_cluster(4, unique_test_base("/tmp/finalis_it_timed_transfer4"));
}

// A long time lock end to end on four validators: encrypted to the inclusion epoch's committee and
// unlocking past that epoch; once the unlock height is final every named validator signs it, the
// signatures are relayed and accepted from the key set, and a leader carries the aggregate in
// long_time_signatures, which opens and applies the transfer and refunds the bond.
TEST(test_long_time_lock_opens_on_a_four_validator_cluster) {
  const auto base = unique_test_base("/tmp/finalis_it_long_lock");
  const auto keys = node::Node::deterministic_test_keypairs();
  auto cluster = make_cluster(base, 4, 4, MAX_COMMITTEE);
  auto& n0 = *cluster.nodes[0];
  ASSERT_TRUE(wait_for_tip(n0, 3, ci_timeout_seconds(40)));
  const std::uint64_t bond = consensus::kTxTimedMinForfeitBond;
  const auto& epoch_blocks = cluster.configs[0].network.committee_epoch_blocks;

  std::optional<FundedTestWallet> funded;
  ASSERT_TRUE(wait_for([&]() {
    funded = find_funded_test_wallet(n0, keys, 2 * (bond + 10 * consensus::kTxTimedLongFeePerEpoch), 2);
    return funded.has_value();
  }, ci_timeout_seconds(120)));
  // Early in an epoch, so the envelope is included in the epoch it names.
  ASSERT_TRUE(wait_for([&]() {
    const auto next = n0.status().height + 1;
    return consensus::committee_epoch_start(next, epoch_blocks) == consensus::committee_epoch_start(next + 10, epoch_blocks);
  }, ci_timeout_seconds(120)));
  const auto next = n0.status().height + 1;
  const auto epoch = consensus::committee_epoch_start(next, epoch_blocks);
  const auto unlock = epoch + epoch_blocks + 2;
  const auto prepaid = std::max<std::uint64_t>(1'000, *consensus::timed_long_lock_min_fee(next, unlock, epoch_blocks));

  auto coins = funded->utxos;
  std::sort(coins.begin(), coins.end(), [](const auto& a, const auto& b) { return a.second.value > b.second.value; });
  ASSERT_TRUE(coins[0].second.value >= bond + prepaid);
  const auto& sender = keys[funded->key_index];
  const Bytes sender_priv(sender.private_key.begin(), sender.private_key.end());
  const auto sender_script = coins[0].second.script_pubkey;
  const auto recipient = crypto::keypair_from_seed32(std::array<std::uint8_t, 32>{0x5e});
  const auto recipient_pkh = crypto::h160(Bytes(recipient->public_key.begin(), recipient->public_key.end()));
  const auto domain = node_chain_domain(n0);
  std::optional<storage::FinalizedCommitteeCheckpoint> checkpoint;
  {
    storage::DB db;
    ASSERT_TRUE(db.open_readonly(base + "/node0"));
    checkpoint = db.get_finalized_committee_checkpoint(epoch);
  }
  ASSERT_TRUE(checkpoint.has_value() && checkpoint->ordered_bls_keys.size() == 4);

  const auto body = build_signed_p2pkh_tx_single_input(
      domain, coins[1].first, coins[1].second, sender_priv,
      {TxOut{coins[1].second.value - 500, address::p2pkh_script_pubkey(recipient_pkh)}});
  ASSERT_TRUE(body.has_value());
  TimedTxParams params;
  params.fee_outpoint = coins[0].first;
  params.fee_prev_out = coins[0].second;
  params.prepaid_fee = prepaid;
  params.forfeit_bond = bond;
  params.bond_refund_script = sender_script;
  if (coins[0].second.value > bond + prepaid) {
    params.fee_change = TxOut{coins[0].second.value - bond - prepaid, sender_script};
  }
  params.unlock_height = unlock;
  params.committee_epoch = epoch;
  params.committee_root = consensus::committee_bls_key_root(checkpoint->ordered_bls_keys);
  params.committee_keys = checkpoint->ordered_bls_keys;
  params.threshold = static_cast<std::uint32_t>(consensus::time_signature_threshold(checkpoint->ordered_bls_keys.size()));
  Hash32 seed{};
  seed.fill(0x3d);
  const auto timed = build_signed_timed_tx(domain, params, AnyTx{*body}, sender_priv, seed);
  ASSERT_TRUE(timed.has_value());
  std::string reason;
  ASSERT_TRUE(n0.inject_record_for_test(timed->serialize(), &reason));

  std::optional<storage::DB::TxLocation> included;
  std::optional<storage::DB::TxLocation> opened;
  ASSERT_TRUE(wait_for([&]() {
    storage::DB db;
    if (!db.open_readonly(base + "/node0")) return false;
    included = db.get_tx_index(timed->txid());
    opened = db.get_tx_index(body->txid());
    return included.has_value() && opened.has_value();
  }, ci_timeout_seconds(240)));
  ASSERT_TRUE(included->height < epoch + epoch_blocks);
  ASSERT_TRUE(opened->height > unlock && opened->height <= unlock + consensus::kTimedLongGraceBlocks);
  const auto sender_pkh = crypto::h160(Bytes(sender.public_key.begin(), sender.public_key.end()));
  bool refunded = false;
  for (const auto& [op, out] : n0.find_utxos_by_pubkey_hash_for_test(sender_pkh)) {
    const auto refund_op = consensus::timed_refund_outpoint(timed->txid());
    if (op.txid == refund_op.txid && op.index == refund_op.index && out.value == bond) refunded = true;
  }
  ASSERT_TRUE(refunded);
  for (std::size_t i = 1; i < cluster.nodes.size(); ++i) {
    ASSERT_TRUE(wait_for([&]() { return cluster.nodes[i]->find_utxos_by_pubkey_hash_for_test(recipient_pkh).size() == 1; },
                         ci_timeout_seconds(60)));
  }
}

// A height-locked payment on a live node: admitted and finalized, found under the recipient's own
// address, refused before its height (mempool and block), and spent from it.
TEST(test_height_locked_payment_on_a_live_node) {
  const auto keys = node::Node::deterministic_test_keypairs();
  const auto base = unique_test_base("/tmp/finalis_it_height_lock");
  auto cluster = make_cluster(base, 1, 1, 1);
  auto& n0 = *cluster.nodes[0];
  ASSERT_TRUE(wait_for_tip(n0, 3, ci_timeout_seconds(40)));
  std::optional<FundedTestWallet> funded;
  ASSERT_TRUE(wait_for([&]() {
    funded = find_funded_test_wallet(n0, keys, 2'000'000, 1);
    return funded.has_value();
  }, ci_timeout_seconds(120)));
  const auto& sender = keys[funded->key_index];
  const auto recipient = crypto::keypair_from_seed32(std::array<std::uint8_t, 32>{0x6e});
  const auto recipient_h = crypto::h160(Bytes(recipient->public_key.begin(), recipient->public_key.end()));
  std::array<std::uint8_t, 20> recipient_pkh{};
  std::copy(recipient_h.begin(), recipient_h.end(), recipient_pkh.begin());
  const auto domain = node_chain_domain(n0);

  const auto unlock = n0.status().height + 6;
  auto coin = funded->utxos.front();
  for (const auto& c : funded->utxos) if (c.second.value > coin.second.value) coin = c;
  const auto lock_tx = build_signed_p2pkh_tx_single_input(
      domain, coin.first, coin.second, Bytes(sender.private_key.begin(), sender.private_key.end()),
      {TxOut{1'000'000, height_lock_script_pubkey(unlock, recipient_pkh)},
       TxOut{coin.second.value - 1'000'000 - 1'000, coin.second.script_pubkey}});
  ASSERT_TRUE(lock_tx.has_value());
  ASSERT_TRUE(n0.inject_tx_for_test(AnyTx{*lock_tx}, true));

  // Indexed under the recipient's plain address (what its wallet queries).
  const auto recipient_scripthash = crypto::sha256(address::p2pkh_script_pubkey(recipient_h));
  std::vector<std::pair<OutPoint, TxOut>> found;
  ASSERT_TRUE(wait_for([&]() {
    storage::DB db;
    if (!db.open_readonly(base + "/node0")) return false;
    found.clear();
    for (const auto& e : db.get_script_utxos(recipient_scripthash)) found.push_back({e.outpoint, TxOut{e.value, e.script_pubkey}});
    return found.size() == 1;
  }, ci_timeout_seconds(60)));
  ASSERT_TRUE(found[0].first.txid == lock_tx->txid());
  ASSERT_TRUE(n0.status().height + 1 < unlock);

  const auto spend = build_signed_p2pkh_tx_single_input(
      domain, found[0].first, found[0].second, Bytes(recipient->private_key.begin(), recipient->private_key.end()),
      {TxOut{1'000'000 - 1'000, address::p2pkh_script_pubkey(recipient_h)}});
  ASSERT_TRUE(spend.has_value());
  ASSERT_TRUE(!n0.inject_tx_for_test(AnyTx{*spend}, true));  // too early: refused

  ASSERT_TRUE(wait_for_tip(n0, unlock - 1, ci_timeout_seconds(90)));  // the next block is at the unlock height
  ASSERT_TRUE(n0.inject_tx_for_test(AnyTx{*spend}, true));
  ASSERT_TRUE(wait_for([&]() {
    storage::DB db;
    if (!db.open_readonly(base + "/node0")) return false;
    const auto loc = db.get_tx_index(spend->txid());
    return loc.has_value() && loc->height >= unlock;
  }, ci_timeout_seconds(60)));
}

TEST(test_onboarding_registration_tx_finalization_inserts_onboarding_validator) {
  const auto keys = node::Node::deterministic_test_keypairs();
  const auto base = unique_test_base("/tmp/finalis_it_onboarding_registration_tx");
  auto cluster = make_cluster(base, 1, 1, 1, [](node::NodeConfig& cfg) {
    // Mainnet's 20-bit onboarding PoW mines slower than the two-epoch validity window under sanitizers.
    cfg.network.onboarding_admission_pow_difficulty_bits = 8;
  });
  auto& n0 = *cluster.nodes[0];
  ASSERT_TRUE(wait_for_tip(n0, 5, ci_timeout_seconds(40)));

  std::optional<FundedTestWallet> funded;
  ASSERT_TRUE(wait_for([&]() {
    funded = find_funded_test_wallet(n0, keys, 1000, 1);
    return funded.has_value();
  }, ci_timeout_seconds(120)));

  const auto before = n0.status().height;
  const auto new_validator = crypto::keypair_from_seed32(std::array<std::uint8_t, 32>{0x91});
  ASSERT_TRUE(new_validator.has_value());
  const auto& sender = keys[funded->key_index];
  const auto sender_pkh = crypto::h160(Bytes(sender.public_key.begin(), sender.public_key.end()));
  storage::DB db0;
  ASSERT_TRUE(db0.open_readonly(base + "/node0"));
  const auto chain_id = ChainId::from_config_and_db(mainnet_network(), db0);
  ValidatorJoinAdmissionPowBuildContext pow_ctx{
      .network = &cluster.configs[0].network,
      .chain_id = &chain_id,
      .current_height = n0.status().height + 1,
      .finalized_hash_at_height = [&](std::uint64_t height) { return db0.get_height_hash(height); },
  };
  auto tx = build_onboarding_registration_tx(node_chain_domain(n0), 
      funded->utxos, Bytes(sender.private_key.begin(), sender.private_key.end()), new_validator->public_key,
      Bytes(new_validator->private_key.begin(), new_validator->private_key.end()), new_validator->public_key, 1000,
      address::p2pkh_script_pubkey(sender_pkh), nullptr, &pow_ctx);
  ASSERT_TRUE(tx.has_value());
  ASSERT_TRUE(n0.inject_tx_for_test(*tx, true));

  ASSERT_TRUE(wait_for([&]() {
    if (n0.status().height < before + 1) return false;
    storage::DB db;
    if (!db.open_readonly(base + "/node0")) return false;
    if (!db.get_tx_index(tx->txid()).has_value()) return false;
    auto validators = db.load_validators();
    auto it = validators.find(new_validator->public_key);
    return it != validators.end() && it->second.status == consensus::ValidatorStatus::ONBOARDING;
  }, ci_timeout_seconds(60)));

  auto info = n0.validator_info_for_test(new_validator->public_key);
  ASSERT_TRUE(info.has_value());
  ASSERT_EQ(info->status, consensus::ValidatorStatus::ONBOARDING);
}

TEST(test_duplicate_onboarding_registration_tx_is_rejected_after_finalization) {
  const auto keys = node::Node::deterministic_test_keypairs();
  const auto base = unique_test_base("/tmp/finalis_it_duplicate_onboarding_registration_tx");
  auto cluster = make_cluster(base, 1, 1, 1, [](node::NodeConfig& cfg) {
    // Mainnet's 20-bit onboarding PoW mines slower than the two-epoch validity window under sanitizers.
    cfg.network.onboarding_admission_pow_difficulty_bits = 8;
  });
  auto& n0 = *cluster.nodes[0];
  ASSERT_TRUE(wait_for_tip(n0, 5, ci_timeout_seconds(40)));

  std::optional<FundedTestWallet> funded0;
  ASSERT_TRUE(wait_for([&]() {
    funded0 = find_funded_test_wallet(n0, keys, 1000, 1);
    return funded0.has_value();
  }, ci_timeout_seconds(120)));

  const auto new_validator = crypto::keypair_from_seed32(std::array<std::uint8_t, 32>{0x92});
  ASSERT_TRUE(new_validator.has_value());
  const auto& sender0 = keys[funded0->key_index];
  const auto sender0_pkh = crypto::h160(Bytes(sender0.public_key.begin(), sender0.public_key.end()));
  storage::DB db0;
  ASSERT_TRUE(db0.open_readonly(base + "/node0"));
  const auto chain_id = ChainId::from_config_and_db(mainnet_network(), db0);
  ValidatorJoinAdmissionPowBuildContext pow_ctx0{
      .network = &cluster.configs[0].network,
      .chain_id = &chain_id,
      .current_height = n0.status().height + 1,
      .finalized_hash_at_height = [&](std::uint64_t height) { return db0.get_height_hash(height); },
  };
  auto tx0 = build_onboarding_registration_tx(node_chain_domain(n0), 
      funded0->utxos, Bytes(sender0.private_key.begin(), sender0.private_key.end()), new_validator->public_key,
      Bytes(new_validator->private_key.begin(), new_validator->private_key.end()), new_validator->public_key, 1000,
      address::p2pkh_script_pubkey(sender0_pkh), nullptr, &pow_ctx0);
  ASSERT_TRUE(tx0.has_value());
  ASSERT_TRUE(n0.inject_tx_for_test(*tx0, true));

  ASSERT_TRUE(wait_for([&]() {
    auto info = n0.validator_info_for_test(new_validator->public_key);
    return info.has_value() && info->status == consensus::ValidatorStatus::ONBOARDING;
  }, ci_timeout_seconds(60)));

  std::optional<FundedTestWallet> funded1;
  ASSERT_TRUE(wait_for([&]() {
    funded1 = find_funded_test_wallet(n0, keys, 1000, 1);
    return funded1.has_value();
  }, ci_timeout_seconds(120)));

  const auto& sender1 = keys[funded1->key_index];
  const auto sender1_pkh = crypto::h160(Bytes(sender1.public_key.begin(), sender1.public_key.end()));
  ValidatorJoinAdmissionPowBuildContext pow_ctx1{
      .network = &cluster.configs[0].network,
      .chain_id = &chain_id,
      .current_height = n0.status().height + 1,
      .finalized_hash_at_height = [&](std::uint64_t height) { return db0.get_height_hash(height); },
  };
  auto tx1 = build_onboarding_registration_tx(node_chain_domain(n0), 
      funded1->utxos, Bytes(sender1.private_key.begin(), sender1.private_key.end()), new_validator->public_key,
      Bytes(new_validator->private_key.begin(), new_validator->private_key.end()), new_validator->public_key, 1000,
      address::p2pkh_script_pubkey(sender1_pkh), nullptr, &pow_ctx1);
  ASSERT_TRUE(tx1.has_value());
  ASSERT_TRUE(!n0.inject_tx_for_test(*tx1, true));
}

TEST(test_onboarding_live_path_transitions_to_pending_then_active_after_bonded_join) {
  const auto keys = node::Node::deterministic_test_keypairs();
  const auto base = unique_test_base("/tmp/finalis_it_onboarding_to_active_live_path");
  // Admission PoW stays on but at 8 bits: at mainnet's 22 bits mining takes ~19s, longer than the
  // two-epoch validity window (64 blocks, ~11s at 100ms blocks), so the join raced epoch expiry.
  // PoW validity/expiry rules are covered in test_bonding.
  auto cluster = make_cluster(base, 1, 1, 1, [](node::NodeConfig& cfg) {
    apply_test_bond_floor(cfg);
    cfg.network.onboarding_admission_pow_difficulty_bits = 8;
    cfg.network.validator_join_admission_pow_difficulty_bits = 8;
  });
  auto& n0 = *cluster.nodes[0];
  ASSERT_TRUE(wait_for_tip(n0, 5, ci_timeout_seconds(40)));
  const std::uint64_t bond_amount = live_registration_bond_amount_for_test(n0, cluster.configs[0]);

  std::optional<FundedTestWallet> funded;
  // Genesis has no premine: rewards accrue ~27 coins/s; apply_test_bond_floor keeps the bond at ~100 coins.
  ASSERT_TRUE(wait_for([&]() {
    funded = find_funded_test_wallet(n0, keys, bond_amount + 1000, 1);
    return funded.has_value();
  }, ci_timeout_seconds(300)));

  const auto new_validator = crypto::keypair_from_seed32(std::array<std::uint8_t, 32>{0x93});
  ASSERT_TRUE(new_validator.has_value());
  const auto& sender = keys[funded->key_index];
  const auto sender_pkh = crypto::h160(Bytes(sender.public_key.begin(), sender.public_key.end()));

  storage::DB onboarding_db;
  ASSERT_TRUE(onboarding_db.open_readonly(base + "/node0"));
  const auto onboarding_chain_id = ChainId::from_config_and_db(mainnet_network(), onboarding_db);
  ValidatorJoinAdmissionPowBuildContext onboarding_pow_ctx{
      .network = &cluster.configs[0].network,
      .chain_id = &onboarding_chain_id,
      .current_height = n0.status().height + 1,
      .finalized_hash_at_height = [&](std::uint64_t height) { return onboarding_db.get_height_hash(height); },
  };
  auto onboarding_tx = build_onboarding_registration_tx(node_chain_domain(n0), 
      funded->utxos, Bytes(sender.private_key.begin(), sender.private_key.end()), new_validator->public_key,
      Bytes(new_validator->private_key.begin(), new_validator->private_key.end()), new_validator->public_key, 1000,
      address::p2pkh_script_pubkey(sender_pkh), nullptr, &onboarding_pow_ctx);
  ASSERT_TRUE(onboarding_tx.has_value());
  ASSERT_TRUE(n0.inject_tx_for_test(*onboarding_tx, true));

  ASSERT_TRUE(wait_for([&]() {
    auto info = n0.validator_info_for_test(new_validator->public_key);
    return info.has_value() && info->status == consensus::ValidatorStatus::ONBOARDING;
  }, ci_timeout_seconds(60)));

  const auto onboarding_info = n0.validator_info_for_test(new_validator->public_key);
  ASSERT_TRUE(onboarding_info.has_value());
  ASSERT_TRUE(!onboarding_info->has_bond);

  std::optional<FundedTestWallet> funded_after_onboarding;
  ASSERT_TRUE(wait_for([&]() {
    funded_after_onboarding = find_funded_test_wallet(n0, keys, bond_amount + 1000, 1);
    return funded_after_onboarding.has_value();
  }, ci_timeout_seconds(300)));

  storage::DB join_db;
  ASSERT_TRUE(join_db.open_readonly(base + "/node0"));
  const auto join_chain_id = ChainId::from_config_and_db(mainnet_network(), join_db);
  ValidatorJoinAdmissionPowBuildContext join_pow_ctx{
      .network = &cluster.configs[0].network,
      .chain_id = &join_chain_id,
      .current_height = n0.status().height + 1,
      .finalized_hash_at_height = [&](std::uint64_t height) { return join_db.get_height_hash(height); },
  };
  auto join_tx = build_validator_join_request_tx(node_chain_domain(n0), 
      funded_after_onboarding->utxos, Bytes(sender.private_key.begin(), sender.private_key.end()), new_validator->public_key,
      Bytes(new_validator->private_key.begin(), new_validator->private_key.end()), new_validator->public_key, bond_amount, 1000,
      address::p2pkh_script_pubkey(sender_pkh), nullptr, &join_pow_ctx);
  ASSERT_TRUE(join_tx.has_value());
  ASSERT_TRUE(n0.inject_tx_for_test(*join_tx, true));

  ASSERT_TRUE(wait_for([&]() {
    auto info = n0.validator_info_for_test(new_validator->public_key);
    return info.has_value() && info->status == consensus::ValidatorStatus::PENDING && info->has_bond;
  }, ci_timeout_seconds(60)));

  const auto pending_info = n0.validator_info_for_test(new_validator->public_key);
  ASSERT_TRUE(pending_info.has_value());
  const auto activation_height = pending_info->joined_height + mainnet_network().validator_warmup_blocks;

  ASSERT_TRUE(wait_for_tip(n0, activation_height, ci_timeout_seconds(30)));
  ASSERT_TRUE(wait_for([&]() {
    auto info = n0.validator_info_for_test(new_validator->public_key);
    if (!info.has_value() || info->status != consensus::ValidatorStatus::ACTIVE) return false;
    const auto active_next = n0.active_validators_for_next_height_for_test();
    return std::find(active_next.begin(), active_next.end(), new_validator->public_key) != active_next.end();
  }, ci_timeout_seconds(30)));
}

TEST(test_unbond_finalization_moves_validator_to_exiting) {
  // auto fixture = make_bonded_joined_validator_fixture(unique_test_base("/tmp/finalis_it_unbond_exit"), 66);
  #ifdef _WIN32
    auto temp_base = std::string(std::getenv("USERPROFILE")) + "\\AppData\\Local\\Temp\\finalis_it_unbond_exit";
  #else
      auto temp_base = "/tmp/finalis_it_unbond_exit";
  #endif
  auto fixture = make_bonded_joined_validator_fixture(
      unique_test_base(temp_base), 66);
  auto& cluster = fixture.cluster;
  auto& nodes = cluster.nodes;

  if (!wait_for([&]() {
        for (const auto& n : nodes) {
          auto info = n->validator_info_for_test(fixture.joiner_kp.public_key);
          if (!info.has_value()) return false;
          if (info->status != consensus::ValidatorStatus::PENDING &&
              info->status != consensus::ValidatorStatus::ACTIVE) {
            return false;
          }
        }
        return true;
      }, ci_timeout_seconds(120))) {
    throw std::runtime_error("bonded fixture validator never became pending/active:" +
                             summarize_validator_fixture_nodes(nodes, fixture.joiner_kp.public_key, std::nullopt,
                                                               &cluster.configs));
  }

  if (!wait_for([&]() {
        for (const auto& n : nodes) {
          const auto active = n->active_validators_for_next_height_for_test();
          if (std::find(active.begin(), active.end(), fixture.joiner_kp.public_key) == active.end()) return false;
        }
        return true;
      }, ci_timeout_seconds(300))) {
    throw std::runtime_error("bonded fixture validator never entered active next-height set:" +
                             summarize_validator_fixture_nodes(nodes, fixture.joiner_kp.public_key, std::nullopt,
                                                               &cluster.configs));
  }

  const auto before = nodes[0]->validator_info_for_test(fixture.joiner_kp.public_key);
  ASSERT_TRUE(before.has_value());
  ASSERT_TRUE(before->has_bond);
  const auto before_height = nodes[0]->status().height;

  std::string err;
  auto unbond_tx = build_unbond_tx(node_chain_domain(nodes[0]), before->bond_outpoint, fixture.joiner_kp.public_key, before->bonded_amount, 1000,
                                   fixture.joiner_kp.private_key, &err);
  ASSERT_TRUE(unbond_tx.has_value());
  const Hash32 unbond_txid = unbond_tx->txid();
  append_live_certified_tx_or_throw(cluster, *unbond_tx, "append unbond tx failed");

  const bool unbonded = wait_for([&]() {
    for (const auto& n : nodes) {
      auto info = n->validator_info_for_test(fixture.joiner_kp.public_key);
      if (!info.has_value()) return false;
      if (info->status != consensus::ValidatorStatus::EXITING) return false;
      const auto active = n->active_validators_for_next_height_for_test();
      if (std::find(active.begin(), active.end(), fixture.joiner_kp.public_key) != active.end()) return false;
    }
    return true;
  }, ci_timeout_seconds(180));
  if (!unbonded) {
    std::ostringstream oss;
    oss << "unbond did not drive validator to EXITING:";
    for (std::size_t i = 0; i < nodes.size(); ++i) {
      const auto st = nodes[i]->status();
      const auto info = nodes[i]->validator_info_for_test(fixture.joiner_kp.public_key);
      const auto artifact = find_frontier_artifact_with_tx(cluster.configs[i].db_path, unbond_txid, st.height);
      oss << " node" << i << "{h=" << st.height << ",r=" << st.round
          << ",advanced=" << (st.height > before_height ? "yes" : "no")
          << ",mempool=" << (nodes[i]->mempool_contains_for_test(unbond_txid) ? "yes" : "no")
          << ",artifact=" << (artifact.has_value() ? "yes" : "no")
          << ",err=" << nodes[i]->last_test_hook_error_for_test()
          << ",status=";
      if (!info.has_value()) {
        oss << "missing";
      } else {
        oss << static_cast<int>(info->status)
            << ",has_bond=" << (info->has_bond ? "yes" : "no")
            << ",unbond_height=" << info->unbond_height
            << ",bond_txid=" << hex_encode(Bytes(info->bond_outpoint.txid.begin(), info->bond_outpoint.txid.end())).substr(0, 8);
      }
      oss << "}";
    }
    throw std::runtime_error(oss.str());
  }
}

TEST(test_slash_consumes_bond_and_bans_validator) {
  auto cluster = make_cluster(unique_test_base("/tmp/finalis_it_slash"), 1, 1, 1);
  auto& nodes = cluster.nodes;
  const auto keys = node::Node::deterministic_test_keypairs();
  ASSERT_TRUE(wait_for([&]() { return nodes[0]->status().height >= 6; }, ci_timeout_seconds(60)));

  const auto slash_pub = keys[0].public_key;
  const std::uint64_t bond_amount = live_registration_bond_amount_for_test(*nodes[0], cluster.configs[0]);
  Hash32 bond_txid{};
  bond_txid.fill(0xA5);
  const OutPoint bond_op{bond_txid, 0};
  ASSERT_TRUE(nodes[0]->seed_bonded_validator_for_test(slash_pub, bond_op, bond_amount));

  for (auto& n : nodes) n->pause_proposals_for_test(true);
  ASSERT_TRUE(wait_for_stable_same_tip(nodes, ci_timeout_seconds(60)));

  auto info0 = nodes[0]->validator_info_for_test(slash_pub);
  ASSERT_TRUE(info0.has_value());
  ASSERT_TRUE(info0->has_bond);

  Vote a;
  a.height = nodes[0]->status().height + 1;
  a.round = 0;
  a.block_id.fill(0x31);
  a.validator_pubkey = slash_pub;
  auto sa = crypto::ed25519_sign(vote_signing_message(nodes[0]->consensus_domain_for_test(), a.height, a.round, a.block_id), keys[0].private_key);
  ASSERT_TRUE(sa.has_value());
  a.signature = *sa;

  Vote b = a;
  b.block_id.fill(0x41);
  auto sb = crypto::ed25519_sign(vote_signing_message(nodes[0]->consensus_domain_for_test(), b.height, b.round, b.block_id), keys[0].private_key);
  ASSERT_TRUE(sb.has_value());
  b.signature = *sb;

  auto slash_tx = build_slash_tx(bond_op, info0->bonded_amount, a, b);
  ASSERT_TRUE(slash_tx.has_value());
  append_live_certified_tx_or_throw(cluster, *slash_tx, "append slash tx failed");
  const Hash32 slash_txid = slash_tx->txid();
  for (auto& n : nodes) n->pause_proposals_for_test(false);

  if (!wait_for([&]() {
        for (std::size_t i = 0; i < nodes.size(); ++i) {
          const auto st = nodes[i]->status();
          const auto artifact = find_frontier_artifact_with_tx(cluster.configs[i].db_path, slash_txid, st.height);
          if (!artifact.has_value()) return false;
        }
        return true;
      }, ci_timeout_seconds(180))) {
    throw std::runtime_error("slash tx never reached frontier artifact:" +
                             summarize_validator_fixture_nodes(nodes, slash_pub, slash_txid, &cluster.configs));
  }

  if (!wait_for([&]() {
        for (const auto& n : nodes) {
          auto info = n->validator_info_for_test(slash_pub);
          if (!info.has_value()) return false;
          if (info->status != consensus::ValidatorStatus::BANNED) return false;
          if (info->has_bond) return false;
          auto active = n->active_validators_for_next_height_for_test();
          if (std::find(active.begin(), active.end(), slash_pub) != active.end()) return false;
        }
        return true;
      }, ci_timeout_seconds(300))) {
    throw std::runtime_error("slash validator did not converge to banned/no-bond state:" +
                             summarize_validator_fixture_nodes(nodes, slash_pub, slash_txid, &cluster.configs));
  }
}

// A validator's time signature on a height not yet final, carried as evidence, burns its bond and
// bans it on a live node.
TEST(test_early_time_signature_slash_bans_validator) {
  auto cluster = make_cluster(unique_test_base("/tmp/finalis_it_time_slash"), 1, 1, 1);
  auto& nodes = cluster.nodes;
  const auto keys = node::Node::deterministic_test_keypairs();
  ASSERT_TRUE(wait_for([&]() { return nodes[0]->status().height >= 6; }, ci_timeout_seconds(60)));

  const auto slash_pub = keys[0].public_key;
  const std::uint64_t bond_amount = live_registration_bond_amount_for_test(*nodes[0], cluster.configs[0]);
  Hash32 bond_txid{};
  bond_txid.fill(0xA6);
  const OutPoint bond_op{bond_txid, 0};
  ASSERT_TRUE(nodes[0]->seed_bonded_validator_for_test(slash_pub, bond_op, bond_amount));
  for (auto& n : nodes) n->pause_proposals_for_test(true);
  ASSERT_TRUE(wait_for_stable_same_tip(nodes, ci_timeout_seconds(60)));
  const auto info0 = nodes[0]->validator_info_for_test(slash_pub);
  ASSERT_TRUE(info0.has_value() && info0->has_bond);

  // Far enough ahead that the evidence is included before that height is final.
  const auto early = nodes[0]->status().height + 1'000;
  const auto sk = crypto::bls_key_from_validator_seed(Bytes(keys[0].private_key.begin(), keys[0].private_key.end()));
  ASSERT_TRUE(sk.has_value());
  const auto sig = crypto::bls_sign(*sk, time_signature_message(nodes[0]->consensus_domain_for_test(), early),
                                    crypto::kBlsTimeSignatureDst);
  ASSERT_TRUE(sig.has_value());
  const auto slash_tx = build_early_time_signature_slash_tx(bond_op, info0->bonded_amount, early, *sig);
  append_live_certified_tx_or_throw(cluster, slash_tx, "append time slash tx failed");
  for (auto& n : nodes) n->pause_proposals_for_test(false);

  if (!wait_for([&]() {
        const auto info = nodes[0]->validator_info_for_test(slash_pub);
        return info.has_value() && info->status == consensus::ValidatorStatus::BANNED && !info->has_bond;
      }, ci_timeout_seconds(300))) {
    throw std::runtime_error("time slash did not ban:" +
                             summarize_validator_fixture_nodes(nodes, slash_pub, slash_tx.txid(), &cluster.configs));
  }
}

TEST(test_banned_validator_cannot_reenter_through_onboarding_registration_tx) {
  auto cluster = make_cluster(unique_test_base("/tmp/finalis_it_banned_onboarding_reentry"), 1, 1, 1, [](node::NodeConfig& cfg) {
    // Mainnet's 20-bit onboarding PoW mines slower than the two-epoch validity window under sanitizers.
    cfg.network.onboarding_admission_pow_difficulty_bits = 8;
  });
  auto& n0 = *cluster.nodes[0];
  const auto keys = node::Node::deterministic_test_keypairs();
  ASSERT_TRUE(wait_for([&]() { return n0.status().height >= 6; }, ci_timeout_seconds(60)));

  std::optional<FundedTestWallet> funded;
  ASSERT_TRUE(wait_for([&]() {
    funded = find_funded_test_wallet(n0, keys, 1000, 1);
    return funded.has_value();
  }, ci_timeout_seconds(120)));

  const auto banned_pub = keys[0].public_key;
  const std::uint64_t bond_amount = live_registration_bond_amount_for_test(n0, cluster.configs[0]);
  Hash32 bond_txid{};
  bond_txid.fill(0xB6);
  const OutPoint bond_op{bond_txid, 0};
  ASSERT_TRUE(n0.seed_bonded_validator_for_test(banned_pub, bond_op, bond_amount));

  n0.pause_proposals_for_test(true);
  ASSERT_TRUE(wait_for_stable_same_tip(cluster.nodes, std::chrono::seconds(30)));

  auto info0 = n0.validator_info_for_test(banned_pub);
  ASSERT_TRUE(info0.has_value());
  ASSERT_TRUE(info0->has_bond);

  Vote a;
  a.height = n0.status().height + 1;
  a.round = 0;
  a.block_id.fill(0x51);
  a.validator_pubkey = banned_pub;
  auto sa = crypto::ed25519_sign(vote_signing_message(cluster.nodes[0]->consensus_domain_for_test(), a.height, a.round, a.block_id), keys[0].private_key);
  ASSERT_TRUE(sa.has_value());
  a.signature = *sa;

  Vote b = a;
  b.block_id.fill(0x61);
  auto sb = crypto::ed25519_sign(vote_signing_message(cluster.nodes[0]->consensus_domain_for_test(), b.height, b.round, b.block_id), keys[0].private_key);
  ASSERT_TRUE(sb.has_value());
  b.signature = *sb;

  auto slash_tx = build_slash_tx(bond_op, info0->bonded_amount, a, b);
  ASSERT_TRUE(slash_tx.has_value());
  append_live_certified_tx_or_throw(cluster, *slash_tx, "append slash tx failed");
  n0.pause_proposals_for_test(false);

  ASSERT_TRUE(wait_for([&]() {
    auto info = n0.validator_info_for_test(banned_pub);
    return info.has_value() && info->status == consensus::ValidatorStatus::BANNED && !info->has_bond;
  }, ci_timeout_seconds(180)));

  const auto& sender = keys[funded->key_index];
  const auto sender_pkh = crypto::h160(Bytes(sender.public_key.begin(), sender.public_key.end()));
  storage::DB db;
  ASSERT_TRUE(db.open_readonly(cluster.base + "/node0"));
  const auto chain_id = ChainId::from_config_and_db(mainnet_network(), db);
  ValidatorJoinAdmissionPowBuildContext pow_ctx{
      .network = &cluster.configs[0].network,
      .chain_id = &chain_id,
      .current_height = n0.status().height + 1,
      .finalized_hash_at_height = [&](std::uint64_t height) { return db.get_height_hash(height); },
  };
  auto onboarding_tx = build_onboarding_registration_tx(node_chain_domain(cluster.nodes[0]), 
      funded->utxos, Bytes(sender.private_key.begin(), sender.private_key.end()), banned_pub,
      Bytes(keys[0].private_key.begin(), keys[0].private_key.end()), banned_pub, 1000,
      address::p2pkh_script_pubkey(sender_pkh), nullptr, &pow_ctx);
  ASSERT_TRUE(onboarding_tx.has_value());
  ASSERT_TRUE(!n0.inject_tx_for_test(*onboarding_tx, true));
  // keys[0] is the cluster's only validator, so the chain halts once its ban applies; check the
  // rejected tx never reached the mempool instead of waiting for a block.
  ASSERT_TRUE(!n0.mempool_contains_for_test(onboarding_tx->txid()));
  {
    storage::DB verify_db;
    ASSERT_TRUE(verify_db.open_readonly(cluster.base + "/node0"));
    ASSERT_TRUE(!verify_db.get_tx_index(onboarding_tx->txid()).has_value());
  }
  auto final_info = n0.validator_info_for_test(banned_pub);
  ASSERT_TRUE(final_info.has_value());
  ASSERT_EQ(final_info->status, consensus::ValidatorStatus::BANNED);
}

TEST(test_committee_deterministic_despite_local_bans) {
  const auto keys = node::Node::deterministic_test_keypairs();
  auto cluster = make_cluster(unique_test_base("/tmp/finalis_it_proposer_equiv"), 1, 1, MAX_COMMITTEE);
  auto& nodes = cluster.nodes;

  ASSERT_TRUE(wait_for([&]() { return nodes[0]->status().height >= 6; }, std::chrono::seconds(30)));

  for (auto& n : nodes) n->pause_proposals_for_test(true);
  ASSERT_TRUE(wait_for_stable_same_tip(nodes, std::chrono::seconds(10)));

  const auto target_height = nodes[0]->status().height + 1;
  auto proposal_a = build_cluster_frontier_proposal(nodes, keys, target_height, 0);
  ASSERT_TRUE(proposal_a.has_value());

  FrontierProposal proposal_b = *proposal_a;
  proposal_b.transition.next_state_root[0] ^= 0x01;
  ASSERT_TRUE(frontier_proposal_id(proposal_b) != frontier_proposal_id(*proposal_a));

  for (auto& n : nodes) {
    ASSERT_TRUE(!observe_test_frontier_proposal(*n, *proposal_a));
    ASSERT_TRUE(observe_test_frontier_proposal(*n, proposal_b));
  }

  ASSERT_TRUE(wait_for([&]() {
    for (const auto& n : nodes) {
      auto info = n->validator_info_for_test(proposal_a->transition.leader_pubkey);
      if (!info.has_value()) return false;
      if (info->status != consensus::ValidatorStatus::ACTIVE) return false;
      auto active = n->active_validators_for_next_height_for_test();
      if (std::find(active.begin(), active.end(), proposal_a->transition.leader_pubkey) == active.end()) return false;
    }
    return true;
  }, std::chrono::seconds(10)));

  storage::DB db;
  const auto node0_db = cluster.base + "/node0";
  ASSERT_TRUE(db.open_readonly(node0_db) || db.open(node0_db));
  const auto records = db.load_slashing_records();
  bool found = false;
  for (const auto& [_, rec] : records) {
    if (rec.kind != storage::SlashingRecordKind::PROPOSER_EQUIVOCATION) continue;
    if (rec.validator_pubkey != proposal_a->transition.leader_pubkey) continue;
    if (rec.height != proposal_a->transition.height || rec.round != proposal_a->transition.round) continue;
    if (rec.object_a == frontier_proposal_id(*proposal_a) && rec.object_b == frontier_proposal_id(proposal_b)) {
      found = true;
      break;
    }
    if (rec.object_a == frontier_proposal_id(proposal_b) && rec.object_b == frontier_proposal_id(*proposal_a)) {
      found = true;
      break;
    }
  }
  ASSERT_TRUE(found);
}

TEST(test_committee_selection_and_non_member_votes_ignored) {
  const auto keys = node::Node::deterministic_test_keypairs();
  ASSERT_TRUE(keys.size() >= 12u);
  auto cluster = make_cluster(unique_test_base("/tmp/finalis_it_committee"), 12, 12, 5);
  auto& nodes = cluster.nodes;

  const auto all_nodes_reached_height_10 = [&]() {
    for (const auto& n : nodes) {
      if (n->status().height < 10) return false;
    }
    return true;
  };
  if (!wait_for(all_nodes_reached_height_10, ci_timeout_seconds(300))) {
    for (std::size_t i = 0; i < nodes.size(); ++i) {
      std::cerr << "committee-test-wait-timeout node=" << i << " height=" << nodes[i]->status().height << "\n";
    }
  }
  ASSERT_TRUE(all_nodes_reached_height_10());
  for (auto& n : nodes) n->pause_proposals_for_test(true);
  ASSERT_TRUE(wait_for_stable_same_tip(nodes, std::chrono::seconds(30)));

  const auto target_height = nodes[0]->status().height + 1;
  const auto c0 = nodes[0]->committee_for_height_round_for_test(target_height, 0);
  ASSERT_EQ(c0.size(), 5u);
  for (size_t i = 1; i < nodes.size(); ++i) {
    ASSERT_EQ(nodes[i]->committee_for_height_round_for_test(target_height, 0), c0);
  }

  PubKey32 non_member{};
  bool found_non_member = false;
  for (int i = 0; i < 12; ++i) {
    if (std::find(c0.begin(), c0.end(), keys[i].public_key) == c0.end()) {
      non_member = keys[i].public_key;
      found_non_member = true;
      break;
    }
  }
  ASSERT_TRUE(found_non_member);
  int non_member_id = node_for_pub(keys, non_member);
  ASSERT_TRUE(non_member_id >= 0);

  Vote bad_vote;
  bad_vote.height = target_height;
  bad_vote.round = 0;
  bad_vote.block_id.fill(0xA5);
  bad_vote.validator_pubkey = non_member;
  auto bad_sig =
      crypto::ed25519_sign(vote_signing_message(nodes[0]->consensus_domain_for_test(), bad_vote.height, bad_vote.round, bad_vote.block_id), keys[non_member_id].private_key);
  ASSERT_TRUE(bad_sig.has_value());
  bad_vote.signature = *bad_sig;
  ASSERT_TRUE(!nodes[0]->inject_vote_for_test(bad_vote));
  for (auto& n : nodes) n->pause_proposals_for_test(false);

  const std::uint64_t before = nodes[0]->status().height;
  ASSERT_TRUE(wait_for([&]() {
    for (const auto& n : nodes) {
      if (n->status().height < before + 2) return false;
    }
    return true;
  }, ci_timeout_seconds(120)));
}

TEST(test_mainnet_seed_bootstrap_and_catchup) {
  if (!can_open_loopback_listener_for_test()) return;
  const std::string base = unique_test_base("/tmp/finalis_it_mainnet_bootstrap_seeds");
  const std::size_t join_port_seed = std::hash<std::string>{}(base);
  auto cluster = make_p2p_cluster(base + "/validators", 2, 2, 2);
  auto& nodes = cluster.nodes;
  ASSERT_TRUE(wait_for([&]() {
    for (const auto& n : nodes) {
      if (n->status().height < 8) return false;
    }
    return true;
  }, ci_timeout_seconds(120)));
  for (auto& n : nodes) ASSERT_TRUE(n->pause_proposals_for_test(true));
  ASSERT_TRUE(wait_for_stable_same_tip(nodes, std::chrono::seconds(30)));
  const auto frozen_tip = nodes[0]->status();
  const std::uint16_t seed_port = nodes[0]->p2p_port_for_test();
  ASSERT_TRUE(seed_port != 0);

  node::NodeConfig join_cfg;
  join_cfg.allow_unencrypted_keystore = true;  // test fixture: no passphrase
  join_cfg.node_id = 7;
  join_cfg.db_path = base + "/joiner";
  join_cfg.disable_p2p = false;
  join_cfg.listen = true;
  join_cfg.bind_ip = "127.0.0.1";
  join_cfg.dns_seeds = false;
  join_cfg.network.default_seeds.clear();  // keep test nodes off the public mainnet seeds
  join_cfg.outbound_target = 1;
  join_cfg.p2p_port = static_cast<std::uint16_t>(22000u + ((join_port_seed + 4099u) % 20000u));
  join_cfg.genesis_path = base + "/validators/genesis.json";
  join_cfg.allow_unsafe_genesis_override = true;
  join_cfg.network.min_block_interval_ms = 100;
  join_cfg.network.round_timeout_ms = 200;
  join_cfg.validator_key_file = join_cfg.db_path + "/keystore/validator.json";
  join_cfg.validator_passphrase = "test-pass";
  {
    keystore::ValidatorKey out_key;
    std::string kerr;
    ASSERT_TRUE(keystore::create_validator_keystore(join_cfg.validator_key_file, join_cfg.validator_passphrase,
                                                    "mainnet", "sc", deterministic_seed_for_node_id(7), &out_key, &kerr));
  }
  join_cfg.seeds.push_back("127.0.0.1:" + std::to_string(seed_port));
  auto joiner = std::make_unique<node::Node>(join_cfg);
  ASSERT_TRUE(joiner->init() && "joiner->init() failed");
  joiner->start();
  if (!wait_for_peer_count(*joiner, 1, std::chrono::seconds(20))) {
    const auto st = joiner->status();
    std::ostringstream oss;
    oss << "joiner failed to discover seed peer:"
        << " h=" << st.height << ",r=" << st.round << ",peers=" << st.peers << ",est=" << st.established_peers
        << ",out=" << st.outbound_connected << ",in=" << st.inbound_connected << ",state=" << st.consensus_state
        << ",seed_port=" << seed_port;
    throw std::runtime_error(oss.str());
  }
  const bool joiner_caught_up = wait_for([&]() {
    const auto js = joiner->status();
    return js.height == frozen_tip.height && js.transition_hash == frozen_tip.transition_hash;
  }, std::chrono::seconds(90));
  if (!joiner_caught_up) {
    const auto js = joiner->status();
    std::ostringstream oss;
    oss << "joiner failed to catch up:";
    oss << " joiner{h=" << js.height << ",r=" << js.round << ",peers=" << js.peers << ",est=" << js.established_peers
        << ",out=" << js.outbound_connected << ",in=" << js.inbound_connected << ",state=" << js.consensus_state
        << "} frozen_tip{h=" << frozen_tip.height << ",hash="
        << hex_encode(Bytes(frozen_tip.transition_hash.begin(), frozen_tip.transition_hash.end())).substr(0, 8) << "}";
    for (std::size_t i = 0; i < nodes.size(); ++i) {
      const auto st = nodes[i]->status();
      oss << " node" << i << "{h=" << st.height << ",r=" << st.round << ",peers=" << st.peers
          << ",est=" << st.established_peers << ",out=" << st.outbound_connected << ",in=" << st.inbound_connected
          << ",state=" << st.consensus_state << "}";
    }
    throw std::runtime_error(oss.str());
  }

  joiner->stop();
}

TEST(test_observer_reports_ok_on_two_lightservers) {
  if (!can_open_loopback_listener_for_test()) return;
  const std::string base = unique_test_base("/tmp/finalis_it_observer");
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);

  auto cluster = make_cluster(base + "/cluster");
  ASSERT_TRUE(wait_for([&]() { return cluster.nodes[0]->status().height >= 10; }, std::chrono::seconds(60)));
  const std::string db_path = base + "/cluster/node0";

  lightserver::Config l1;
  l1.db_path = db_path;
  l1.bind_ip = "127.0.0.1";
  l1.port = 0;  // ephemeral
  lightserver::Server s1(l1);
  ASSERT_TRUE(s1.init());
  ASSERT_TRUE(s1.start() && "s1.start() failed");
  const std::uint16_t p1 = s1.bound_port();
  ASSERT_TRUE(p1 != 0);

  lightserver::Config l2 = l1;
  l2.port = 0;  // ephemeral
  lightserver::Server s2(l2);
  ASSERT_TRUE(s2.init());
  if (!s2.start()) {
    s1.stop();
    ASSERT_TRUE(false && "s2.start() failed");
  }
  const std::uint16_t p2 = s2.bound_port();
  ASSERT_TRUE(p2 != 0);

  ASSERT_TRUE(wait_for([&]() { return rpc_get_status_ok("127.0.0.1", p1); }, std::chrono::seconds(5)));
  ASSERT_TRUE(wait_for([&]() { return rpc_get_status_ok("127.0.0.1", p2); }, std::chrono::seconds(5)));
  const std::string out_file = base + "/observer.out";
  auto observer_script = find_repo_fixture("scripts/observe.py");
  ASSERT_TRUE(observer_script.has_value());
  ASSERT_TRUE(std::filesystem::exists(*observer_script));
  const std::string cmd = python_launcher() + " " + shell_quote_path(*observer_script) +
                          " --interval 0.2 --max-intervals 2 --mismatch-threshold 2 " +
                          std::string("http://127.0.0.1:") + std::to_string(p1) + "/rpc " +
                          "http://127.0.0.1:" + std::to_string(p2) + "/rpc > " + shell_quote_path(out_file) + " 2>&1";
  const int rc = std::system(cmd.c_str());
  s2.stop();
  s1.stop();
  ASSERT_TRUE(rc == 0);

  std::ifstream in(out_file);
  std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  ASSERT_TRUE(content.find("mismatch") == std::string::npos);
}

TEST(test_invalid_frame_spam_bans_peer_and_node_stays_alive) {
  if (!can_open_loopback_listener_for_test()) return;
  const std::string base = unique_test_base("/tmp/finalis_it_hardening_invalid_frame");
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);

  node::NodeConfig cfg;
  cfg.allow_unencrypted_keystore = true;  // test fixture: no passphrase
      cfg.node_id = 0;
  cfg.max_committee = 1;
  cfg.db_path = base + "/node0";
  cfg.bind_ip = "127.0.0.1";
  cfg.p2p_port = 0;  // ephemeral
  cfg.ban_seconds = 30;
  cfg.handshake_timeout_ms = 1000;
  cfg.frame_timeout_ms = 500;
  cfg.idle_timeout_ms = 2000;

  node::Node n(cfg);
  if (!n.init()) return;
  n.start();
  const std::uint16_t port = n.p2p_port_for_test();
  ASSERT_TRUE(port != 0);

  for (int i = 0; i < 8; ++i) {
    (void)send_invalid_frame("127.0.0.1", port, cfg.network.magic);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }

  ASSERT_TRUE(wait_for([&]() { return connect_and_check_closed("127.0.0.1", port, std::chrono::milliseconds(200)); },
                       std::chrono::seconds(5)));
  const auto st = n.status();
  ASSERT_TRUE(st.established_peers == 0);
  n.stop();
}

TEST(test_seed_http_port_preflight_does_not_break_node_progress) {
  if (!can_open_loopback_listener_for_test()) return;
  const std::string base = unique_test_base("/tmp/finalis_it_seed_http_preflight");
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);

  HttpStubServer http;
  if (!http.start()) return;

  node::NodeConfig cfg;
  cfg.allow_unencrypted_keystore = true;  // test fixture: no passphrase
      cfg.node_id = 0;
  cfg.max_committee = 1;
  cfg.db_path = base + "/node0";
  cfg.bind_ip = "127.0.0.1";
  cfg.p2p_port = 0;
  cfg.seeds.push_back("127.0.0.1:" + std::to_string(http.port));

  node::Node n(cfg);
  if (!n.init()) {
    http.stop();
    return;
  }
  n.start();
  std::this_thread::sleep_for(std::chrono::seconds(2));
  ASSERT_TRUE(n.status().peers == 0);
  n.stop();
  http.stop();
}

TEST(test_invalid_frame_ban_threshold_applies_after_strikes) {
  if (!can_open_loopback_listener_for_test()) return;
  const std::string base = unique_test_base("/tmp/finalis_it_hardening_threshold");
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);

  node::NodeConfig cfg;
  cfg.allow_unencrypted_keystore = true;  // test fixture: no passphrase
      cfg.node_id = 0;
  cfg.max_committee = 1;
  cfg.db_path = base + "/node0";
  cfg.bind_ip = "127.0.0.1";
  cfg.p2p_port = 0;
  cfg.ban_seconds = 30;
  cfg.invalid_frame_ban_threshold = 3;
  cfg.invalid_frame_window_seconds = 60;
  cfg.handshake_timeout_ms = 5000;

  node::Node n(cfg);
  if (!n.init()) return;
  n.start();
  const std::uint16_t port = n.p2p_port_for_test();
  ASSERT_TRUE(port != 0);

  ASSERT_TRUE(send_invalid_frame("127.0.0.1", port, cfg.network.magic));
  ASSERT_TRUE(send_invalid_frame("127.0.0.1", port, cfg.network.magic));
  ASSERT_TRUE(wait_for([&]() { return !connect_and_check_closed("127.0.0.1", port, std::chrono::milliseconds(100)); },
                       std::chrono::seconds(2)));

  ASSERT_TRUE(send_invalid_frame("127.0.0.1", port, cfg.network.magic));
  ASSERT_TRUE(wait_for([&]() { return connect_and_check_closed("127.0.0.1", port, std::chrono::milliseconds(150)); },
                       std::chrono::seconds(3)));
  n.stop();
}

TEST(test_epoch_reward_settlement_matches_closed_epoch_rewards) {
  const auto base = unique_test_base("/tmp/finalis_it_epoch_reward_settlement");
  auto cluster = make_cluster(base, 1, 1, 1);
  auto& n = cluster.nodes[0];
  ASSERT_TRUE(wait_for([&]() { return n->status().height >= 33; }, ci_timeout_seconds(120)));

  const auto artifact = load_frontier_artifact_at_height(base + "/node0", 33);
  ASSERT_TRUE(artifact.has_value());
  ASSERT_EQ(artifact->proposal.transition.settlement.outputs.size(), 1u);

  std::uint64_t gross_epoch_rewards = 0;
  for (std::uint64_t h = 1; h <= 32; ++h) gross_epoch_rewards += consensus::reward_units(h);
  const auto reserve_epoch_rewards = (gross_epoch_rewards * consensus::RESERVE_ACCRUAL_BPS) / 10'000ULL;
  const auto validator_epoch_rewards = gross_epoch_rewards - reserve_epoch_rewards;
  ASSERT_EQ(artifact->proposal.transition.settlement.current_fees, 0ULL);
  ASSERT_EQ(artifact->proposal.transition.settlement.settled_epoch_rewards, validator_epoch_rewards);
  ASSERT_EQ(artifact->proposal.transition.settlement.total, validator_epoch_rewards);
  ASSERT_EQ(artifact->proposal.transition.settlement.outputs[0].second, validator_epoch_rewards);

  // The reward payout is indexed under its synthetic txid and credited to the recipient's history.
  const auto settlement_txid = consensus::frontier_settlement_txid(artifact->proposal.transition);
  storage::DB db;
  ASSERT_TRUE(db.open_readonly(base + "/node0"));
  ASSERT_EQ(db.get_settlement_height(settlement_txid), std::optional<std::uint64_t>(33));
  const auto& payee = artifact->proposal.transition.settlement.outputs[0].first;
  const auto payee_scripthash =
      crypto::sha256(address::p2pkh_script_pubkey(crypto::h160(Bytes(payee.begin(), payee.end()))));
  bool credited = false;
  for (const auto& entry : db.get_script_history(payee_scripthash)) {
    if (entry.txid == settlement_txid && entry.height == 33) credited = true;
  }
  ASSERT_TRUE(credited);
}

TEST(test_epoch_reward_settlement_restart_is_deterministic) {
  const std::string base = unique_test_base("/tmp/finalis_it_epoch_reward_restart");
  {
    auto cluster = make_cluster(base, 1, 1, 1);
    ASSERT_TRUE(wait_for([&]() { return cluster.nodes[0]->status().height >= 20; }, ci_timeout_seconds(60)));
    cluster.nodes[0]->stop();
  }

  node::NodeConfig cfg;
  cfg.allow_unencrypted_keystore = true;  // test fixture: no passphrase
  cfg.disable_p2p = true;
  cfg.node_id = 0;
  cfg.max_committee = 1;
  cfg.network.min_block_interval_ms = 100;
  cfg.network.round_timeout_ms = 200;
  cfg.p2p_port = 0;
  cfg.db_path = base + "/node0";
  cfg.genesis_path = base + "/genesis.json";
  cfg.allow_unsafe_genesis_override = true;
  cfg.validator_key_file = cfg.db_path + "/keystore/validator.json";
  cfg.validator_passphrase = "test-pass";

  node::Node restarted(cfg);
  ASSERT_TRUE(restarted.init());
  restarted.start();
  ASSERT_TRUE(wait_for([&]() { return restarted.status().height >= 33; }, ci_timeout_seconds(120)));
  restarted.stop();

  storage::DB db;
  ASSERT_TRUE(db.open_readonly(base + "/node0") || db.open(base + "/node0"));
  const auto state = db.get_epoch_reward_settlement(1);
  ASSERT_TRUE(state.has_value());
  ASSERT_TRUE(state->settled);
  ASSERT_EQ(state->total_reward_units, [&]() {
    std::uint64_t gross = 0;
    for (std::uint64_t h = 1; h <= 32; ++h) gross += consensus::reward_units(h);
    return gross - ((gross * consensus::RESERVE_ACCRUAL_BPS) / 10'000ULL);
  }());
  ASSERT_EQ(state->reserve_accrual_units, [&]() {
    std::uint64_t gross = 0;
    for (std::uint64_t h = 1; h <= 32; ++h) gross += consensus::reward_units(h);
    return (gross * consensus::RESERVE_ACCRUAL_BPS) / 10'000ULL;
  }());
}

TEST(test_restart_rebuild_preserves_post_fork_checkpoint_and_settlement_across_v1_boundary) {
  const std::string base = unique_test_base("/tmp/finalis_it_restart_postfork_v1");
  {
    auto cluster = make_cluster(base, 1, 1, 1);
    const bool reached_225 =
        wait_for([&]() { return cluster.nodes[0]->status().height >= 225; }, ci_timeout_seconds(420));
    if (!reached_225) {
      std::ostringstream oss;
      const auto st = cluster.nodes[0]->status();
      oss << "postfork pre-restart node failed to reach height 225:"
          << " node0{h=" << st.height << ",r=" << st.round
          << ",tip=" << hex_encode(Bytes(st.transition_hash.begin(), st.transition_hash.end())).substr(0, 8)
          << ",committee=" << st.committee_size << ",quorum=" << st.quorum_threshold
          << ",votes=" << st.votes_for_current
          << ",timeouts=" << cluster.nodes[0]->timeout_vote_count_for_height_round_for_test(st.height + 1, st.round)
          << ",timeout_reserved="
          << (cluster.nodes[0]->local_timeout_vote_reserved_for_test(st.height + 1, st.round) ? "yes" : "no")
          << ",committee_member="
          << (cluster.nodes[0]->local_is_committee_member_for_test(st.height + 1, st.round) ? "yes" : "no")
          << ",round_age_ms=" << cluster.nodes[0]->round_age_ms_for_test()
          << ",state=" << st.consensus_state << "}";
      throw std::runtime_error(oss.str());
    }
    std::cerr << "postfork-restart-test phase=reached-height-225\n";
    for (auto& n : cluster.nodes) n->stop();
  }

  storage::DB before;
  ASSERT_TRUE(before.open(base + "/node0"));
  const auto checkpoint_before = before.get_finalized_committee_checkpoint(225);
  const auto settlement_before = before.get_epoch_reward_settlement(193);
  ASSERT_TRUE(checkpoint_before.has_value());
  ASSERT_TRUE(settlement_before.has_value());
  before.close();

  node::NodeConfig cfg;
  cfg.allow_unencrypted_keystore = true;  // test fixture: no passphrase
  cfg.disable_p2p = true;
  cfg.node_id = 0;
  cfg.max_committee = 4;
  cfg.network.min_block_interval_ms = 100;
  cfg.network.round_timeout_ms = 200;
  cfg.p2p_port = 0;
  cfg.db_path = base + "/node0";
  cfg.genesis_path = base + "/genesis.json";
  cfg.allow_unsafe_genesis_override = true;
  cfg.validator_key_file = cfg.db_path + "/keystore/validator.json";
  cfg.validator_passphrase = "test-pass";
  {
    std::cerr << "postfork-restart-test phase=restart-init-begin\n";
    node::Node restarted(cfg);
    ASSERT_TRUE(restarted.init());
    std::cerr << "postfork-restart-test phase=restart-init-ok\n";
  }

  storage::DB after;
  ASSERT_TRUE(after.open(base + "/node0"));
  const auto checkpoint_after = after.get_finalized_committee_checkpoint(225);
  const auto settlement_after = after.get_epoch_reward_settlement(193);
  ASSERT_TRUE(checkpoint_after.has_value());
  ASSERT_TRUE(settlement_after.has_value());
  ASSERT_EQ(checkpoint_after->epoch_seed, checkpoint_before->epoch_seed);
  ASSERT_EQ(checkpoint_after->ticket_difficulty_bits, checkpoint_before->ticket_difficulty_bits);
  ASSERT_EQ(checkpoint_after->ordered_members, checkpoint_before->ordered_members);
  ASSERT_EQ(checkpoint_after->ordered_operator_ids, checkpoint_before->ordered_operator_ids);
  ASSERT_EQ(checkpoint_after->ordered_base_weights, checkpoint_before->ordered_base_weights);
  ASSERT_EQ(checkpoint_after->ordered_ticket_bonus_bps, checkpoint_before->ordered_ticket_bonus_bps);
  ASSERT_EQ(checkpoint_after->ordered_final_weights, checkpoint_before->ordered_final_weights);
  ASSERT_EQ(checkpoint_after->ordered_ticket_hashes, checkpoint_before->ordered_ticket_hashes);
  ASSERT_EQ(checkpoint_after->ordered_ticket_nonces, checkpoint_before->ordered_ticket_nonces);
  ASSERT_EQ(settlement_after->settled, settlement_before->settled);
  ASSERT_EQ(settlement_after->total_reward_units, settlement_before->total_reward_units);
  ASSERT_EQ(settlement_after->reserve_accrual_units, settlement_before->reserve_accrual_units);
  ASSERT_EQ(settlement_after->reward_score_units, settlement_before->reward_score_units);
  ASSERT_EQ(settlement_after->expected_participation_units, settlement_before->expected_participation_units);
  ASSERT_EQ(settlement_after->observed_participation_units, settlement_before->observed_participation_units);

  std::vector<consensus::ValidatorBestTicket> before_winners;
  std::vector<consensus::ValidatorBestTicket> after_winners;
  for (std::size_t i = 0; i < checkpoint_before->ordered_members.size(); ++i) {
    before_winners.push_back(consensus::ValidatorBestTicket{
        checkpoint_before->ordered_members[i],
        checkpoint_before->ordered_ticket_hashes[i],
        checkpoint_before->ordered_ticket_nonces[i],
    });
    after_winners.push_back(consensus::ValidatorBestTicket{
        checkpoint_after->ordered_members[i],
        checkpoint_after->ordered_ticket_hashes[i],
        checkpoint_after->ordered_ticket_nonces[i],
    });
  }
  const auto before_seed =
      consensus::compute_proposer_seed(checkpoint_before->epoch_seed, 225, consensus::compute_committee_root(before_winners));
  const auto after_seed =
      consensus::compute_proposer_seed(checkpoint_after->epoch_seed, 225, consensus::compute_committee_root(after_winners));
  ASSERT_EQ(consensus::proposer_schedule_from_committee(before_winners, before_seed),
            consensus::proposer_schedule_from_committee(after_winners, after_seed));
  after.close();
}

TEST(test_block_path_applies_settlement_same_as_quorum_path) {
  const auto keys = node::Node::deterministic_test_keypairs();
  const std::string direct_base = unique_test_base("/tmp/finalis_it_reward_direct_path");
  const std::string quorum_base = unique_test_base("/tmp/finalis_it_reward_quorum_path");
  Tx tx = make_fixture_ingress_tx(1, 0x90);

  node::NodeConfig direct_cfg;
  direct_cfg.allow_unencrypted_keystore = true;  // test fixture: no passphrase
  direct_cfg.disable_p2p = true;
  direct_cfg.node_id = 0;
  direct_cfg.max_committee = 1;
  direct_cfg.network.min_block_interval_ms = 5000;
  direct_cfg.network.round_timeout_ms = 200;
  direct_cfg.p2p_port = 0;
  direct_cfg.db_path = direct_base + "/node0";
  direct_cfg.genesis_path = direct_base + "/genesis.json";
  direct_cfg.allow_unsafe_genesis_override = true;
  direct_cfg.validator_key_file = direct_cfg.db_path + "/keystore/validator.json";
  direct_cfg.validator_passphrase = "test-pass";
  std::filesystem::remove_all(direct_base);
  std::filesystem::create_directories(direct_base);
  ASSERT_TRUE(write_mainnet_genesis_file(direct_cfg.genesis_path, 1));
  keystore::ValidatorKey direct_key;
  std::string kerr;
  ASSERT_TRUE(keystore::create_validator_keystore(direct_cfg.validator_key_file, direct_cfg.validator_passphrase, "mainnet",
                                                  "sc", deterministic_seed_for_node_id(0), &direct_key, &kerr));
  std::unique_ptr<node::Node> direct_node;
  ASSERT_TRUE(restart_single_node_with_seeded_certified_ingress(direct_cfg, {tx.serialize()}, &direct_node));
  direct_node->pause_proposals_for_test(true);
  const auto before = direct_node->status();
  const std::uint64_t target_height = before.height + 1;
  const std::uint32_t round = before.round;
  auto proposal = direct_node->build_frontier_proposal_for_test(target_height, round);
  ASSERT_TRUE(proposal.has_value());
  auto sig = crypto::ed25519_sign(vote_signing_message(direct_node->consensus_domain_for_test(), target_height, round,
                                                       frontier_proposal_id(*proposal)),
                                  keys[0].private_key);
  ASSERT_TRUE(sig.has_value());
  FinalityCertificate cert;
  cert.height = target_height;
  cert.round = round;
  cert.frontier_transition_id = frontier_proposal_id(*proposal);
  cert.quorum_threshold = 1;
  cert.committee_members = {keys[0].public_key};
  cert.signatures = {FinalitySig{keys[0].public_key, *sig}};
  ASSERT_TRUE(direct_node->inject_frontier_transition_for_test(*proposal, cert));
  ASSERT_TRUE(wait_for([&]() { return direct_node->status().height >= target_height; }, std::chrono::seconds(10)));
  direct_node->stop();

  node::NodeConfig quorum_cfg = direct_cfg;
  quorum_cfg.db_path = quorum_base + "/node0";
  quorum_cfg.genesis_path = quorum_base + "/genesis.json";
  std::filesystem::remove_all(quorum_base);
  std::filesystem::create_directories(quorum_base);
  ASSERT_TRUE(write_mainnet_genesis_file(quorum_cfg.genesis_path, 1));
  keystore::ValidatorKey quorum_key;
  std::string quorum_kerr;
  ASSERT_TRUE(keystore::create_validator_keystore(quorum_cfg.validator_key_file, quorum_cfg.validator_passphrase, "mainnet",
                                                  "sc", deterministic_seed_for_node_id(0), &quorum_key, &quorum_kerr));
  std::unique_ptr<node::Node> quorum_node;
  ASSERT_TRUE(restart_single_node_with_seeded_certified_ingress(quorum_cfg, {tx.serialize()}, &quorum_node));
  ASSERT_TRUE(quorum_node->pause_proposals_for_test(true));
  const auto quorum_before = quorum_node->status();
  const auto quorum_target_height = quorum_before.height + 1;
  const auto quorum_round = quorum_before.round;
  auto quorum_proposal = quorum_node->build_frontier_proposal_for_test(quorum_target_height, quorum_round);
  if (!quorum_proposal.has_value()) {
    const auto proposer = quorum_node->proposer_for_height_round_for_test(quorum_target_height, quorum_round);
    const auto committee = quorum_node->committee_for_height_round_for_test(quorum_target_height, quorum_round);
    std::ostringstream oss;
    oss << "quorum proposal build failed:"
        << " h=" << quorum_before.height << ",r=" << quorum_before.round
        << ",target_h=" << quorum_target_height << ",target_r=" << quorum_round
        << ",local=" << hex_encode(Bytes(quorum_node->local_validator_pubkey_for_test().begin(),
                                         quorum_node->local_validator_pubkey_for_test().end())).substr(0, 8)
        << ",err=" << quorum_node->last_test_hook_error_for_test()
        << ",proposer=";
    if (proposer.has_value()) {
      oss << hex_encode(Bytes(proposer->begin(), proposer->end())).substr(0, 8);
    } else {
      oss << "none";
    }
    oss << ",committee_size=" << committee.size();
    throw std::runtime_error(oss.str());
  }
  auto quorum_msg = make_test_frontier_propose_msg(quorum_node->consensus_domain_for_test(), *quorum_proposal);
  ASSERT_TRUE(quorum_node->inject_propose_msg_for_test(quorum_msg));
  auto quorum_vote =
      make_test_vote(quorum_node->consensus_domain_for_test(), keys, quorum_target_height, quorum_round, frontier_proposal_id(*quorum_proposal), keys[0].public_key);
  const auto quorum_vote_result = quorum_node->inject_network_vote_diagnostic_for_test(quorum_vote);
  if (quorum_vote_result != "accepted" && quorum_vote_result != "soft-reject:stale-finalized-height") {
    throw std::runtime_error("quorum vote rejected: " + quorum_vote_result);
  }
  ASSERT_TRUE(wait_for([&]() { return quorum_node->status().height >= quorum_target_height; }, std::chrono::seconds(10)));
  quorum_node->stop();

  storage::DB db0;
  storage::DB db1;
  ASSERT_TRUE(db0.open(direct_base + "/node0"));
  ASSERT_TRUE(db1.open(quorum_base + "/node0"));
  const auto epoch_start = consensus::committee_epoch_start(target_height, node::NodeConfig{}.network.committee_epoch_blocks);
  const auto state0 = db0.get_epoch_reward_settlement(epoch_start);
  const auto state1 = db1.get_epoch_reward_settlement(epoch_start);
  ASSERT_TRUE(state0.has_value());
  ASSERT_TRUE(state1.has_value());
  ASSERT_EQ(state0->total_reward_units, state1->total_reward_units);
  ASSERT_EQ(state0->reward_score_units, state1->reward_score_units);
}

TEST(test_single_validator_respects_min_block_interval_after_finalization) {
  const std::string base = unique_test_base("/tmp/finalis_it_min_block_interval_after_finalize");

  node::NodeConfig cfg;
  cfg.allow_unencrypted_keystore = true;  // test fixture: no passphrase
  cfg.disable_p2p = true;
  cfg.node_id = 0;
  cfg.max_committee = 1;
  cfg.network.min_block_interval_ms = 1200;
  cfg.network.round_timeout_ms = 200;
  cfg.p2p_port = 0;
  cfg.db_path = base + "/node0";
  cfg.genesis_path = base + "/genesis.json";
  cfg.allow_unsafe_genesis_override = true;
  cfg.validator_key_file = cfg.db_path + "/keystore/validator.json";
  cfg.validator_passphrase = "test-pass";

  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);
  ASSERT_TRUE(write_mainnet_genesis_file(cfg.genesis_path, 1));

  keystore::ValidatorKey key;
  std::string kerr;
  ASSERT_TRUE(keystore::create_validator_keystore(cfg.validator_key_file, cfg.validator_passphrase, "mainnet", "sc",
                                                  deterministic_seed_for_node_id(0), &key, &kerr));

  std::unique_ptr<node::Node> node;
  ASSERT_TRUE(restart_single_node_with_seeded_certified_ingress(cfg, {}, &node));

  ASSERT_TRUE(wait_for([&]() { return node->status().height >= 1; }, std::chrono::seconds(10)));
  const auto first_height = node->status().height;
  ASSERT_EQ(first_height, 1u);

  std::this_thread::sleep_for(std::chrono::milliseconds(400));
  ASSERT_EQ(node->status().height, first_height);

  ASSERT_TRUE(wait_for([&]() { return node->status().height >= first_height + 1; }, std::chrono::seconds(5)));
  node->stop();
}

// A lone validator finalizes through the quorum-1 self-vote, which skips the prevote timestamp
// bound; before genesis time it must not propose at all (it would stamp genesis + 1).
TEST(test_single_validator_does_not_finalize_before_genesis_time) {
  const std::string base = unique_test_base("/tmp/finalis_it_no_finalize_before_genesis_time");

  node::NodeConfig cfg;
  cfg.allow_unencrypted_keystore = true;  // test fixture: no passphrase
  cfg.disable_p2p = true;
  cfg.node_id = 0;
  cfg.max_committee = 1;
  cfg.network.min_block_interval_ms = 200;
  cfg.network.round_timeout_ms = 200;
  cfg.p2p_port = 0;
  cfg.db_path = base + "/node0";
  cfg.genesis_path = base + "/genesis.json";
  cfg.allow_unsafe_genesis_override = true;
  cfg.validator_key_file = cfg.db_path + "/keystore/validator.json";
  cfg.validator_passphrase = "test-pass";

  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);
  const auto now = static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
  ASSERT_TRUE(write_mainnet_genesis_file(cfg.genesis_path, 1, now + 3600));

  keystore::ValidatorKey key;
  std::string kerr;
  ASSERT_TRUE(keystore::create_validator_keystore(cfg.validator_key_file, cfg.validator_passphrase, "mainnet", "sc",
                                                  deterministic_seed_for_node_id(0), &key, &kerr));

  std::unique_ptr<node::Node> node;
  ASSERT_TRUE(restart_single_node_with_seeded_certified_ingress(cfg, {}, &node));
  std::this_thread::sleep_for(std::chrono::seconds(3));
  ASSERT_EQ(node->status().height, 0u);
  // Waiting for genesis time is not a stall: no forced round advances while the clock gate holds.
  ASSERT_EQ(node->status().round, 0u);
  node->stop();
}

// Held at round 0 until genesis time, the validator proposes as soon as the clock gate opens.
TEST(test_single_validator_starts_at_round_zero_when_genesis_time_arrives) {
  const std::string base = unique_test_base("/tmp/finalis_it_start_at_genesis_time");

  node::NodeConfig cfg;
  cfg.allow_unencrypted_keystore = true;  // test fixture: no passphrase
  cfg.disable_p2p = true;
  cfg.node_id = 0;
  cfg.max_committee = 1;
  cfg.network.min_block_interval_ms = 200;
  cfg.network.round_timeout_ms = 200;
  cfg.p2p_port = 0;
  cfg.db_path = base + "/node0";
  cfg.genesis_path = base + "/genesis.json";
  cfg.allow_unsafe_genesis_override = true;
  cfg.validator_key_file = cfg.db_path + "/keystore/validator.json";
  cfg.validator_passphrase = "test-pass";

  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);
  const auto now = static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
  // The gate opens kMaxTransitionTimestampDriftS before genesis + 1. The margin outlasts keystore
  // creation and node start under sanitizers, so the pre-gate checks below run with the gate closed.
  const std::uint64_t gate_open_unix = now + 10;
  const std::uint64_t genesis_time = gate_open_unix + consensus::kMaxTransitionTimestampDriftS;
  ASSERT_TRUE(write_mainnet_genesis_file(cfg.genesis_path, 1, genesis_time));

  keystore::ValidatorKey key;
  std::string kerr;
  ASSERT_TRUE(keystore::create_validator_keystore(cfg.validator_key_file, cfg.validator_passphrase, "mainnet", "sc",
                                                  deterministic_seed_for_node_id(0), &key, &kerr));

  std::unique_ptr<node::Node> node;
  ASSERT_TRUE(restart_single_node_with_seeded_certified_ingress(cfg, {}, &node));
  std::this_thread::sleep_for(std::chrono::seconds(1));
  const auto checked_at = static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
  ASSERT_TRUE(checked_at < gate_open_unix);
  ASSERT_EQ(node->status().height, 0u);
  ASSERT_EQ(node->status().round, 0u);
  ASSERT_TRUE(wait_for_tip(*node, 1, std::chrono::seconds(25)));
  node->stop();
}

TEST(test_settled_rewards_are_visible_in_wallet_script_index) {
  const std::string base = unique_test_base("/tmp/finalis_it_wallet_script_index_rewards");

  node::NodeConfig cfg;
  cfg.allow_unencrypted_keystore = true;  // test fixture: no passphrase
  cfg.disable_p2p = true;
  cfg.node_id = 0;
  cfg.max_committee = 1;
  cfg.network.min_block_interval_ms = 100;
  cfg.network.round_timeout_ms = 200;
  cfg.p2p_port = 0;
  cfg.db_path = base + "/node0";
  cfg.genesis_path = base + "/genesis.json";
  cfg.allow_unsafe_genesis_override = true;
  cfg.validator_key_file = cfg.db_path + "/keystore/validator.json";
  cfg.validator_passphrase = "test-pass";

  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);
  ASSERT_TRUE(write_mainnet_genesis_file(cfg.genesis_path, 1));

  keystore::ValidatorKey key;
  std::string kerr;
  ASSERT_TRUE(keystore::create_validator_keystore(cfg.validator_key_file, cfg.validator_passphrase, "mainnet", "sc",
                                                  deterministic_seed_for_node_id(0), &key, &kerr));

  std::unique_ptr<node::Node> node;
  ASSERT_TRUE(restart_single_node_with_seeded_certified_ingress(cfg, {}, &node));
  ASSERT_TRUE(wait_for([&]() { return node->status().height >= 33; }, ci_timeout_seconds(120)));
  node->stop();

  storage::DB db;
  ASSERT_TRUE(db.open(cfg.db_path));
  const auto own_pkh = crypto::h160(Bytes(key.pubkey.begin(), key.pubkey.end()));
  const auto scripthash = crypto::sha256(address::p2pkh_script_pubkey(own_pkh));
  const auto entries = db.get_script_utxos(scripthash);
  ASSERT_TRUE(!entries.empty());
  std::uint64_t balance = 0;
  for (const auto& entry : entries) balance += entry.value;
  ASSERT_TRUE(balance > 0);

  const auto utxos = db.load_transparent_utxos();
  std::uint64_t direct_balance = 0;
  for (const auto& [_, entry] : utxos) {
    std::array<std::uint8_t, 20> got{};
    if (!is_p2pkh_script_pubkey(entry.out.script_pubkey, &got)) continue;
    if (got != own_pkh) continue;
    direct_balance += entry.out.value;
  }
  ASSERT_TRUE(direct_balance > 0);
}

// A finalized TxV2 (shield: transparent input -> transparent payment + confidential output) is indexed
// like a Tx: tx index, address history for the spent and paid addresses, and get_tx decodes the
// transparent output while reporting the confidential one without an amount or address. The
// confidential output and the later unshield spending it are indexed under its one-time key.
TEST(test_finalized_txv2_is_indexed_with_address_history) {
  ASSERT_TRUE(crypto::confidential_crypto_init());
  const std::string base = unique_test_base("/tmp/finalis_it_txv2_indexing");

  node::NodeConfig cfg;
  cfg.allow_unencrypted_keystore = true;  // test fixture: no passphrase
  cfg.disable_p2p = true;
  cfg.node_id = 0;
  cfg.max_committee = 1;
  cfg.network.min_block_interval_ms = 100;
  cfg.network.round_timeout_ms = 200;
  cfg.p2p_port = 0;
  cfg.db_path = base + "/node0";
  cfg.genesis_path = base + "/genesis.json";
  cfg.allow_unsafe_genesis_override = true;
  cfg.validator_key_file = cfg.db_path + "/keystore/validator.json";
  cfg.validator_passphrase = "test-pass";

  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);
  ASSERT_TRUE(write_mainnet_genesis_file(cfg.genesis_path, 1));
  keystore::ValidatorKey key;
  std::string kerr;
  ASSERT_TRUE(keystore::create_validator_keystore(cfg.validator_key_file, cfg.validator_passphrase, "mainnet", "sc",
                                                  deterministic_seed_for_node_id(0), &key, &kerr));

  std::unique_ptr<node::Node> node;
  ASSERT_TRUE(restart_single_node_with_seeded_certified_ingress(cfg, {}, &node));
  ASSERT_TRUE(wait_for([&]() { return node->status().height >= 33; }, ci_timeout_seconds(120)));

  const auto own_pkh = crypto::h160(Bytes(key.pubkey.begin(), key.pubkey.end()));
  auto spendable = node->find_utxos_by_pubkey_hash_for_test(own_pkh);
  ASSERT_TRUE(!spendable.empty());
  const auto prev = spendable.front();
  std::array<std::uint8_t, 20> recipient_pkh{};
  recipient_pkh.fill(0x45);
  constexpr std::uint64_t kConfidential = 100'000'000ULL;
  constexpr std::uint64_t kFee = 10'000ULL;
  ASSERT_TRUE(prev.second.value > kConfidential + kFee);
  const std::uint64_t transparent_out = prev.second.value - kConfidential - kFee;

  crypto::Blind32 blind{};
  blind.bytes.fill(0x5B);
  Hash32 one_time_scalar{};
  one_time_scalar.fill(0x5C);
  Hash32 ephemeral_scalar{};
  ephemeral_scalar.fill(0x5D);
  Hash32 proof_nonce{};
  proof_nonce.fill(0x5E);
  const auto one_time = crypto::secp256k1_pubkey_from_scalar(one_time_scalar);
  const auto ephemeral = crypto::secp256k1_pubkey_from_scalar(ephemeral_scalar);
  ASSERT_TRUE(one_time.has_value() && ephemeral.has_value());
  std::string err;
  const auto conf_out = wallet::build_confidential_output(
      wallet::ConfidentialRecipient{.one_time_pubkey = *one_time, .ephemeral_pubkey = *ephemeral, .scan_tag = {}, .memo = {}},
      crypto::ConfidentialOutputSecrets{.amount = kConfidential, .value_blind = blind}, proof_nonce, &err);
  ASSERT_TRUE(conf_out.has_value());
  const auto tx = wallet::build_txv2_transparent_to_confidential(node_chain_domain(node), 
      prev.first, prev.second, Bytes(key.privkey.begin(), key.privkey.end()), prev.second.value,
      TransparentTxOutV2{transparent_out, address::p2pkh_script_pubkey(recipient_pkh)}, *conf_out, blind, kConfidential,
      kFee, &err);
  if (!tx.has_value()) throw std::runtime_error("shield tx: " + err);
  ASSERT_TRUE(node->inject_tx_for_test(AnyTx{*tx}, true));

  ASSERT_TRUE(wait_for([&]() {
    storage::DB probe_db;
    if (!probe_db.open_readonly(cfg.db_path)) return false;
    return probe_db.get_tx_index(tx->txid()).has_value();
  }, ci_timeout_seconds(45)));

  // Unshield the confidential coin: the spend is indexed under the same one-time key.
  std::optional<std::uint32_t> conf_vout;
  for (std::size_t i = 0; i < tx->outputs.size(); ++i) {
    if (tx->outputs[i].kind == TxOutputKind::Confidential) conf_vout = static_cast<std::uint32_t>(i);
  }
  ASSERT_TRUE(conf_vout.has_value());
  wallet::ConfidentialOwnedCoin coin{
      .outpoint = OutPoint{tx->txid(), *conf_vout},
      .amount = kConfidential,
      .spend_secret = crypto::Blind32{one_time_scalar},
      .value_blind = blind,
      .value_commitment = conf_out->value_commitment,
      .one_time_pubkey = *one_time,
  };
  Hash32 spend_nonce{};
  spend_nonce.fill(0x5F);
  Hash32 excess_nonce{};
  excess_nonce.fill(0x60);
  const auto unshield = wallet::build_txv2_confidential_to_transparent(node_chain_domain(node), 
      coin, TransparentTxOutV2{kConfidential - kFee, address::p2pkh_script_pubkey(recipient_pkh)}, kFee, spend_nonce,
      excess_nonce, &err);
  if (!unshield.has_value()) throw std::runtime_error("unshield tx: " + err);
  ASSERT_TRUE(node->inject_tx_for_test(AnyTx{*unshield}, true));
  ASSERT_TRUE(wait_for([&]() {
    storage::DB probe_db;
    if (!probe_db.open_readonly(cfg.db_path)) return false;
    return probe_db.get_tx_index(unshield->txid()).has_value();
  }, ci_timeout_seconds(45)));
  node->stop();
  node.reset();

  const Hash32 conf_key = confidential_history_key(*one_time);
  {
    storage::DB db;
    ASSERT_TRUE(db.open(cfg.db_path));
    const auto has_txid = [&](const Hash32& scripthash, const Hash32& txid) {
      for (const auto& entry : db.get_script_history(scripthash)) {
        if (entry.txid == txid) return true;
      }
      return false;
    };
    ASSERT_TRUE(has_txid(crypto::sha256(address::p2pkh_script_pubkey(recipient_pkh)), tx->txid()));  // paid
    ASSERT_TRUE(has_txid(crypto::sha256(address::p2pkh_script_pubkey(own_pkh)), tx->txid()));        // spent
    ASSERT_TRUE(has_txid(conf_key, tx->txid()));                                                     // confidential paid
    ASSERT_TRUE(has_txid(conf_key, unshield->txid()));                                               // confidential spent
    ASSERT_EQ(db.get_script_history(conf_key).size(), 2u);
  }

  lightserver::Config lcfg;
  lcfg.db_path = cfg.db_path;
  lightserver::Server ls(lcfg);
  ASSERT_TRUE(ls.init());
  const auto status = ls.handle_rpc_for_test(std::string(R"({"jsonrpc":"2.0","id":304,"method":"get_tx_status","params":{"txid":")") +
                                             hex_encode32(tx->txid()) + R"("}})");
  ASSERT_TRUE(status.find("\"credit_safe\":true") != std::string::npos);
  const auto got = ls.handle_rpc_for_test(std::string(R"({"jsonrpc":"2.0","id":305,"method":"get_tx","params":{"txid":")") +
                                          hex_encode32(tx->txid()) + R"("}})");
  ASSERT_TRUE(got.find("\"tx_version\":2") != std::string::npos);
  ASSERT_TRUE(got.find("\"fee\":" + std::to_string(kFee)) != std::string::npos);
  ASSERT_TRUE(got.find("\"amount\":" + std::to_string(transparent_out)) != std::string::npos);
  ASSERT_TRUE(got.find("\"decoded_kind\":\"confidential\"") != std::string::npos);
  // The hidden amount is never reported as an output amount (token match: a transparent amount may
  // contain the same digits).
  ASSERT_TRUE(got.find("\"amount\":" + std::to_string(kConfidential) + ",") == std::string::npos);
  ASSERT_TRUE(got.find("\"amount\":null") != std::string::npos);

  // Detailed history shows the transparent credit to the recipient; summaries report the explicit fee,
  // not inputs minus transparent outputs (which would add the hidden shielded amount).
  const auto detailed = ls.handle_rpc_for_test(
      std::string(R"({"jsonrpc":"2.0","id":306,"method":"get_history_page_detailed","params":{"scripthash_hex":")") +
      hex_encode32(crypto::sha256(address::p2pkh_script_pubkey(recipient_pkh))) + R"(","limit":10}})");
  ASSERT_TRUE(detailed.find("\"direction\":\"received\"") != std::string::npos);
  ASSERT_TRUE(detailed.find("\"net_amount\":" + std::to_string(transparent_out)) != std::string::npos);
  const auto summaries = ls.handle_rpc_for_test(
      std::string(R"({"jsonrpc":"2.0","id":307,"method":"get_tx_summaries","params":{"txids":[")") +
      hex_encode32(tx->txid()) + R"("]}})");
  ASSERT_TRUE(summaries.find("\"fee\":" + std::to_string(kFee)) != std::string::npos);
  ASSERT_TRUE(summaries.find("\"fee\":" + std::to_string(kConfidential + kFee)) == std::string::npos);

  // A restoring wallet finds both through its derived one-time key.
  Hash32 unrelated_key{};
  unrelated_key.fill(0x61);
  const auto conf_history = ls.handle_rpc_for_test(
      std::string(R"({"jsonrpc":"2.0","id":308,"method":"get_confidential_history_page","params":{"history_keys_hex":[")") +
      hex_encode32(unrelated_key) + R"(",")" + hex_encode32(conf_key) + R"("],"limit":10}})");
  ASSERT_TRUE(conf_history.find(hex_encode32(tx->txid())) != std::string::npos);
  ASSERT_TRUE(conf_history.find(hex_encode32(unshield->txid())) != std::string::npos);
  ASSERT_TRUE(conf_history.find("\"has_more\":false") != std::string::npos);
}

TEST(test_locally_relayed_wallet_tx_enters_certified_ingress_and_finalizes) {
  const std::string base = unique_test_base("/tmp/finalis_it_local_wallet_tx_finalizes");

  node::NodeConfig cfg;
  cfg.allow_unencrypted_keystore = true;  // test fixture: no passphrase
  cfg.disable_p2p = true;
  cfg.node_id = 0;
  cfg.max_committee = 1;
  cfg.network.min_block_interval_ms = 100;
  cfg.network.round_timeout_ms = 200;
  cfg.p2p_port = 0;
  cfg.db_path = base + "/node0";
  cfg.genesis_path = base + "/genesis.json";
  cfg.allow_unsafe_genesis_override = true;
  cfg.validator_key_file = cfg.db_path + "/keystore/validator.json";
  cfg.validator_passphrase = "test-pass";

  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);
  ASSERT_TRUE(write_mainnet_genesis_file(cfg.genesis_path, 1));

  keystore::ValidatorKey key;
  std::string kerr;
  ASSERT_TRUE(keystore::create_validator_keystore(cfg.validator_key_file, cfg.validator_passphrase, "mainnet", "sc",
                                                  deterministic_seed_for_node_id(0), &key, &kerr));

  std::unique_ptr<node::Node> node;
  ASSERT_TRUE(restart_single_node_with_seeded_certified_ingress(cfg, {}, &node));
  ASSERT_TRUE(wait_for([&]() { return node->status().height >= 33; }, ci_timeout_seconds(120)));

  const auto own_pkh = crypto::h160(Bytes(key.pubkey.begin(), key.pubkey.end()));
  auto spendable = node->find_utxos_by_pubkey_hash_for_test(own_pkh);
  ASSERT_TRUE(!spendable.empty());
  const auto prev = spendable.front();

  std::array<std::uint8_t, 20> recipient_pkh{};
  recipient_pkh.fill(0x55);
  constexpr std::uint64_t kAmount = 10'000'000'000ULL;
  constexpr std::uint64_t kFee = 10'000ULL;
  ASSERT_TRUE(prev.second.value > kAmount + kFee);

  std::vector<TxOut> outputs;
  outputs.push_back(TxOut{kAmount, address::p2pkh_script_pubkey(recipient_pkh)});
  outputs.push_back(TxOut{prev.second.value - kAmount - kFee, address::p2pkh_script_pubkey(own_pkh)});

  std::string build_err;
  auto tx = build_signed_p2pkh_tx_single_input(node_chain_domain(node), prev.first, prev.second, Bytes(key.privkey.begin(), key.privkey.end()), outputs,
                                               &build_err);
  ASSERT_TRUE(tx.has_value());
  ASSERT_TRUE(node->inject_tx_for_test(*tx, true));

  ASSERT_TRUE(wait_for([&]() {
    if (node->status().height < 34) return false;
    storage::DB probe_db;
    if (!probe_db.open_readonly(cfg.db_path)) return false;
    if (!probe_db.get_tx_index(tx->txid()).has_value()) return false;
    return !node->find_utxos_by_pubkey_hash_for_test(recipient_pkh).empty();
  }, ci_timeout_seconds(45)));

  const auto recipient_utxos = node->find_utxos_by_pubkey_hash_for_test(recipient_pkh);
  ASSERT_TRUE(!recipient_utxos.empty());
  ASSERT_EQ(recipient_utxos.front().second.value, kAmount);
  node->stop();
  node.reset();

  storage::DB db;
  ASSERT_TRUE(db.open(cfg.db_path));
  const auto loc = db.get_tx_index(tx->txid());
  ASSERT_TRUE(loc.has_value());
  ASSERT_TRUE(loc->height >= 34u);
}

// The lightserver relays over a real P2P socket and reports the node's mempool verdict (TX_RESULT).
// A second spend of the same input passes the lightserver's finalized-state check but the node
// refuses it; the client must see that rejection rather than accepted_for_relay.
TEST(test_lightserver_relay_reports_node_mempool_verdict) {
  if (!can_open_loopback_listener_for_test()) return;
  const std::string base = unique_test_base("/tmp/finalis_it_relay_node_verdict");

  node::NodeConfig cfg;
  cfg.allow_unencrypted_keystore = true;  // test fixture: no passphrase
  cfg.node_id = 0;
  cfg.max_committee = 1;
  cfg.dns_seeds = false;
  cfg.network.default_seeds.clear();
  cfg.outbound_target = 0;
  cfg.network.min_block_interval_ms = 100;
  cfg.network.round_timeout_ms = 200;
  cfg.p2p_port = reserve_test_port();
  if (cfg.p2p_port == 0) return;
  cfg.db_path = base + "/node0";
  cfg.genesis_path = base + "/genesis.json";
  cfg.allow_unsafe_genesis_override = true;
  cfg.validator_key_file = cfg.db_path + "/keystore/validator.json";
  cfg.validator_passphrase = "test-pass";

  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);
  ASSERT_TRUE(write_mainnet_genesis_file(cfg.genesis_path, 1));
  keystore::ValidatorKey key;
  std::string kerr;
  ASSERT_TRUE(keystore::create_validator_keystore(cfg.validator_key_file, cfg.validator_passphrase, "mainnet", "sc",
                                                  deterministic_seed_for_node_id(0), &key, &kerr));

  std::unique_ptr<node::Node> node;
  ASSERT_TRUE(restart_single_node_with_seeded_certified_ingress(cfg, {}, &node));
  const auto own_pkh = crypto::h160(Bytes(key.pubkey.begin(), key.pubkey.end()));
  ASSERT_TRUE(wait_for([&]() {
    return node->status().height >= 33 && !node->find_utxos_by_pubkey_hash_for_test(own_pkh).empty();
  }, ci_timeout_seconds(120)));
  ASSERT_TRUE(node->pause_proposals_for_test(true));  // hold the tip: both spends meet the same state
  const auto prev = node->find_utxos_by_pubkey_hash_for_test(own_pkh).front();

  constexpr std::uint64_t kFee = 10'000ULL;
  const auto spend_to = [&](std::uint8_t fill) {
    std::array<std::uint8_t, 20> recipient_pkh{};
    recipient_pkh.fill(fill);
    std::vector<TxOut> outputs{TxOut{prev.second.value - kFee, address::p2pkh_script_pubkey(recipient_pkh)}};
    std::string err;
    auto tx = build_signed_p2pkh_tx_single_input(node_chain_domain(node), prev.first, prev.second, Bytes(key.privkey.begin(), key.privkey.end()),
                                                 outputs, &err);
    if (!tx.has_value()) throw std::runtime_error("build tx: " + err);
    return *tx;
  };
  const Tx first = spend_to(0x61);
  const Tx second = spend_to(0x62);

  lightserver::Config lcfg;
  lcfg.network = cfg.network;
  lcfg.db_path = cfg.db_path;
  lcfg.tx_relay_port = cfg.p2p_port;
  lcfg.admin_socket_path.clear();
  lightserver::Server ls(lcfg);
  ASSERT_TRUE(ls.init());
  const auto broadcast = [&](const Tx& tx) {
    return ls.handle_rpc_for_test(std::string(R"({"jsonrpc":"2.0","id":1,"method":"broadcast_tx","params":{"tx_hex":")") +
                                  hex_encode(tx.serialize()) + R"("}})");
  };

  const auto accepted = broadcast(first);
  ASSERT_TRUE(accepted.find("\"accepted\":true") != std::string::npos);
  ASSERT_TRUE(node->mempool_contains_for_test(first.txid()));

  const auto conflict = broadcast(second);
  ASSERT_TRUE(conflict.find("\"accepted\":false") != std::string::npos);
  ASSERT_TRUE(conflict.find("\"error_code\":\"tx_conflict_in_mempool\"") != std::string::npos);
  ASSERT_TRUE(!node->mempool_contains_for_test(second.txid()));

  // Resubmitting a transaction the node already holds is not a rejection.
  ASSERT_TRUE(broadcast(first).find("\"accepted\":true") != std::string::npos);

  ASSERT_TRUE(node->pause_proposals_for_test(false));
  node->stop();
}

// Three disable_p2p nodes on the in-process local bus (no sockets): node0 is the only validator, node1 and
// node2 follow it. Covers Node::for_each_local_bus_peer with multiple peers: finalized-frontier delivery,
// the designated-certifier forward (bool early exit) and the certifier's TX re-broadcast to every peer.
// (A multi-validator committee cannot finalize on the local bus: the proposal gate counts P2P sessions.)
TEST(test_local_bus_multi_node_delivers_frontiers_and_forwards_tx_to_designated_certifier) {
  const auto base = unique_test_base("/tmp/finalis_it_local_bus_multi_node");
  ASSERT_TRUE(write_mainnet_genesis_file(base + "/genesis.json", 1));
  const auto keys = node::Node::deterministic_test_keypairs();
  std::vector<std::unique_ptr<node::Node>> nodes;
  for (int i = 0; i < 3; ++i) {
    auto cfg = single_node_cfg(base, 1);
    cfg.node_id = i;
    cfg.db_path = base + "/node" + std::to_string(i);
    cfg.validator_key_file = cfg.db_path + "/keystore/validator.json";
    keystore::ValidatorKey key;
    std::string kerr;
    ASSERT_TRUE(keystore::create_validator_keystore(cfg.validator_key_file, cfg.validator_passphrase, "mainnet", "sc",
                                                    deterministic_seed_for_node_id(i), &key, &kerr));
    nodes.push_back(std::make_unique<node::Node>(cfg));
    ASSERT_TRUE(nodes.back()->init());
  }
  // Bus order is start() order: [node1, node2, node0]. Followers start first so they see every frontier.
  nodes[1]->start();
  nodes[2]->start();
  nodes[0]->start();

  // Followers can only advance if node0's TRANSITION broadcasts reach both of them over the bus.
  std::optional<FundedTestWallet> funded;
  ASSERT_TRUE(wait_for([&]() {
    for (const auto& n : nodes) {
      if (n->status().height < 3) return false;
    }
    funded = find_funded_test_wallet(*nodes[1], keys, 1'000'000, 1);
    return funded.has_value();
  }, ci_timeout_seconds(120)));

  // Freeze height so the tx stays in every mempool once delivered.
  for (auto& n : nodes) n->pause_proposals_for_test(true);
  ASSERT_TRUE(wait_for([&]() {
    const auto s0 = nodes[0]->status();
    for (const auto& n : nodes) {
      const auto s = n->status();
      if (s.height != s0.height || s.transition_hash != s0.transition_hash) return false;
    }
    return true;
  }, ci_timeout_seconds(30)));
  const auto committee = nodes[1]->committee_for_height_round_for_test(nodes[1]->status().height + 1, 0);
  ASSERT_TRUE(committee == std::vector<PubKey32>{nodes[0]->local_validator_pubkey_for_test()});

  const auto& sender = keys[funded->key_index];
  const auto sender_pkh = crypto::h160(Bytes(sender.public_key.begin(), sender.public_key.end()));
  const auto& prev = funded->utxos.front();
  std::vector<TxOut> outputs{TxOut{1'000, address::p2pkh_script_pubkey(sender_pkh)},
                             TxOut{prev.second.value - 1'000 - 10'000, address::p2pkh_script_pubkey(sender_pkh)}};
  std::string err;
  const auto tx = build_signed_p2pkh_tx_single_input(node_chain_domain(nodes[0]), 
      prev.first, prev.second, Bytes(sender.private_key.begin(), sender.private_key.end()), outputs, &err);
  ASSERT_TRUE(tx.has_value());

  // Injected locally into node1 (from_network=false: node1 never broadcasts it). node1's forward must
  // skip node2 (fn returns false) and stop at node0, the designated certifier (fn returns true). node0
  // then re-broadcasts to node1 and node2, which is node2's only way to receive it.
  ASSERT_TRUE(nodes[1]->inject_tx_for_test(*tx, true));
  ASSERT_TRUE(wait_for([&]() {
    for (const auto& n : nodes) {
      if (!n->mempool_contains_for_test(tx->txid())) return false;
    }
    return true;
  }, ci_timeout_seconds(30)));

  for (auto& n : nodes) n->stop();
}

// Line topology 0-1-2-3 over real P2P. A tx injected locally (no broadcast) at an end node that has
// no connection to the lane's designated certifier must still reach it, relayed by other validators.
TEST(test_tx_forward_relays_via_validators_when_certifier_unreachable) {
  const auto keys = node::Node::deterministic_test_keypairs();
  auto cluster = make_cluster(unique_test_base("/tmp/finalis_it_certifier_relay"), 4, 4, MAX_COMMITTEE,
                              [](node::NodeConfig& cfg) {
                                if (cfg.peers.size() > 1) cfg.peers = {cfg.peers.back()};
                              });
  auto& nodes = cluster.nodes;

  std::optional<FundedTestWallet> funded;
  ASSERT_TRUE(wait_for([&]() {
    for (const auto& n : nodes) {
      if (n->status().height < 3) return false;
    }
    funded = find_funded_test_wallet(*nodes[0], keys, 1'000'000, 1);
    return funded.has_value();
  }, ci_timeout_seconds(120)));
  for (auto& n : nodes) n->pause_proposals_for_test(true);
  ASSERT_TRUE(wait_for_stable_same_tip(nodes, ci_timeout_seconds(30)));

  const auto& sender = keys[funded->key_index];
  const auto sender_pkh = crypto::h160(Bytes(sender.public_key.begin(), sender.public_key.end()));
  const auto& prev = funded->utxos.front();
  std::vector<TxOut> outputs{TxOut{1'000, address::p2pkh_script_pubkey(sender_pkh)},
                             TxOut{prev.second.value - 1'000 - 10'000, address::p2pkh_script_pubkey(sender_pkh)}};
  std::string err;
  const auto tx = build_signed_p2pkh_tx_single_input(node_chain_domain(nodes[0]), 
      prev.first, prev.second, Bytes(sender.private_key.begin(), sender.private_key.end()), outputs, &err);
  ASSERT_TRUE(tx.has_value());

  const std::uint64_t next_height = nodes[0]->status().height + 1;
  const auto committee = nodes[0]->committee_for_height_round_for_test(next_height, 0);
  const auto certifier_pub = consensus::designated_ingress_certifier(
      committee, consensus::assign_ingress_lane(AnyTx{*tx}),
      consensus::committee_epoch_start(next_height, cluster.configs[0].network.committee_epoch_blocks));
  int certifier = -1;
  for (int i = 0; i < 4; ++i) {
    if (nodes[i]->local_validator_pubkey_for_test() == certifier_pub) certifier = i;
  }
  ASSERT_TRUE(certifier >= 0);
  // An end node two or more hops from the certifier: its only peer is not the certifier.
  const int submitter = certifier >= 2 ? 0 : 3;
  ASSERT_EQ(nodes[submitter]->status().peers, 1u);

  ASSERT_TRUE(nodes[submitter]->inject_tx_for_test(*tx, true));
  ASSERT_TRUE(wait_for([&]() { return nodes[certifier]->mempool_contains_for_test(tx->txid()); },
                       ci_timeout_seconds(30)));
}

TEST(test_tx_status_reports_certified_ingress_before_finalization) {
  const std::string base = unique_test_base("/tmp/finalis_it_tx_status_certified_ingress");

  node::NodeConfig cfg;
  cfg.allow_unencrypted_keystore = true;  // test fixture: no passphrase
  cfg.disable_p2p = true;
  cfg.node_id = 0;
  cfg.max_committee = 1;
  cfg.network.min_block_interval_ms = 100;
  cfg.network.round_timeout_ms = 200;
  cfg.p2p_port = 0;
  cfg.db_path = base + "/node0";
  cfg.genesis_path = base + "/genesis.json";
  cfg.allow_unsafe_genesis_override = true;
  cfg.validator_key_file = cfg.db_path + "/keystore/validator.json";
  cfg.validator_passphrase = "test-pass";

  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);
  ASSERT_TRUE(write_mainnet_genesis_file(cfg.genesis_path, 1));

  keystore::ValidatorKey key;
  std::string kerr;
  ASSERT_TRUE(keystore::create_validator_keystore(cfg.validator_key_file, cfg.validator_passphrase, "mainnet", "sc",
                                                  deterministic_seed_for_node_id(0), &key, &kerr));

  std::unique_ptr<node::Node> node;
  ASSERT_TRUE(restart_single_node_with_seeded_certified_ingress(cfg, {}, &node));
  ASSERT_TRUE(wait_for([&]() { return node->status().height >= 33; }, ci_timeout_seconds(120)));
  ASSERT_TRUE(node->pause_proposals_for_test(true));
  std::this_thread::sleep_for(std::chrono::milliseconds(400));

  const auto own_pkh = crypto::h160(Bytes(key.pubkey.begin(), key.pubkey.end()));
  auto spendable = node->find_utxos_by_pubkey_hash_for_test(own_pkh);
  ASSERT_TRUE(!spendable.empty());
  const auto prev = spendable.front();

  std::array<std::uint8_t, 20> recipient_pkh{};
  recipient_pkh.fill(0x44);
  constexpr std::uint64_t kAmount = 5'000'000'000ULL;
  constexpr std::uint64_t kFee = 10'000ULL;
  ASSERT_TRUE(prev.second.value > kAmount + kFee);

  std::vector<TxOut> outputs;
  outputs.push_back(TxOut{kAmount, address::p2pkh_script_pubkey(recipient_pkh)});
  outputs.push_back(TxOut{prev.second.value - kAmount - kFee, address::p2pkh_script_pubkey(own_pkh)});

  std::string build_err;
  auto tx = build_signed_p2pkh_tx_single_input(node_chain_domain(node), prev.first, prev.second, Bytes(key.privkey.begin(), key.privkey.end()), outputs,
                                               &build_err);
  ASSERT_TRUE(tx.has_value());
  ASSERT_TRUE(node->inject_tx_for_test(*tx, true));
  node->stop();
  node.reset();

  lightserver::Config lcfg;
  lcfg.db_path = cfg.db_path;
  lightserver::Server ls(lcfg);
  ASSERT_TRUE(ls.init());
  const std::string body = std::string(R"({"jsonrpc":"2.0","id":302,"method":"get_tx_status","params":{"txid":")") +
                           hex_encode32(tx->txid()) + R"("}})";
  const auto resp = ls.handle_rpc_for_test(body);
  ASSERT_TRUE(resp.find("\"status\":\"certified_ingress\"") != std::string::npos);
  ASSERT_TRUE(resp.find("\"finalized\":false") != std::string::npos);
}

TEST(test_next_height_runtime_schedule_uses_canonical_state_not_mutable_runtime_checkpoint_cache) {
  const std::string base = unique_test_base("/tmp/finalis_it_next_height_schedule_uses_canonical");

  node::NodeConfig cfg;
  cfg.allow_unencrypted_keystore = true;  // test fixture: no passphrase
  cfg.disable_p2p = true;
  cfg.node_id = 0;
  cfg.max_committee = 1;
  cfg.p2p_port = 0;
  cfg.db_path = base + "/node0";
  cfg.genesis_path = base + "/genesis.json";
  cfg.allow_unsafe_genesis_override = true;
  cfg.validator_key_file = cfg.db_path + "/keystore/validator.json";
  cfg.validator_passphrase = "test-pass";

  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);
  ASSERT_TRUE(write_mainnet_genesis_file(cfg.genesis_path, 1));

  keystore::ValidatorKey key;
  std::string kerr;
  ASSERT_TRUE(keystore::create_validator_keystore(cfg.validator_key_file, cfg.validator_passphrase, "mainnet", "sc",
                                                  deterministic_seed_for_node_id(0), &key, &kerr));

  node::Node node(cfg);
  ASSERT_TRUE(node.init());

  const auto canonical_committee = node.committee_for_height_round_for_test(1, 0);
  const auto canonical_leader = node.proposer_for_height_round_for_test(1, 0);
  ASSERT_TRUE(!canonical_committee.empty());
  ASSERT_TRUE(canonical_leader.has_value());

  const auto keys = node::Node::deterministic_test_keypairs();
  ASSERT_TRUE(keys.size() > 1u);
  storage::FinalizedCommitteeCheckpoint corrupted;
  corrupted.epoch_start_height = 1;
  corrupted.epoch_seed.fill(0x5A);
  corrupted.ticket_difficulty_bits = consensus::DEFAULT_TICKET_DIFFICULTY_BITS;
  corrupted.ordered_members.push_back(keys[1].public_key);
  corrupted.ordered_operator_ids.push_back(keys[1].public_key);
  corrupted.ordered_base_weights.push_back(1);
  corrupted.ordered_ticket_bonus_bps.push_back(0);
  corrupted.ordered_final_weights.push_back(1);
  corrupted.ordered_ticket_hashes.push_back(zero_hash());
  corrupted.ordered_ticket_nonces.push_back(0);

  ASSERT_TRUE(node.overwrite_runtime_next_height_checkpoint_for_test(corrupted));
  ASSERT_EQ(node.committee_for_height_round_for_test(1, 0), canonical_committee);
  ASSERT_EQ(node.proposer_for_height_round_for_test(1, 0), canonical_leader);

  node.stop();
}

TEST(test_frontier_build_repairs_runtime_cursor_from_frontier_storage) {
  const std::string base = unique_test_base("/tmp/finalis_it_frontier_build_repairs_runtime_cursor");
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);

  auto cfg = single_node_cfg(base, 1);
  ASSERT_TRUE(write_mainnet_genesis_file(cfg.genesis_path, 1));

  keystore::ValidatorKey key;
  std::string kerr;
  ASSERT_TRUE(keystore::create_validator_keystore(cfg.validator_key_file, cfg.validator_passphrase, "mainnet", "sc",
                                                  deterministic_seed_for_node_id(0), &key, &kerr));

  node::Node node(cfg);
  ASSERT_TRUE(node.init());

  ASSERT_TRUE(node.overwrite_runtime_frontier_cursor_for_test(1));
  auto proposal = node.build_frontier_proposal_for_test(1, 0);
  if (!proposal.has_value()) {
    throw std::runtime_error("frontier proposal repair build failed: " + node.last_test_hook_error_for_test());
  }
  ASSERT_EQ(proposal->transition.prev_frontier, 0u);
  ASSERT_EQ(proposal->transition.prev_frontier, proposal->transition.prev_vector.total_count());

  node.stop();
}

TEST(test_ingress_record_propagates_to_follower_before_finalization) {
  const std::string base = unique_test_base("/tmp/finalis_it_ingress_record_propagates");
  auto cluster = make_cluster(base, 2, 2, 2);
  auto& n0 = *cluster.nodes[0];
  auto& n1 = *cluster.nodes[1];

  ASSERT_TRUE(wait_for([&]() {
    const auto s0 = n0.status();
    const auto s1 = n1.status();
    return s0.height >= 33 && s1.height >= 33 &&
           s0.transition_hash == s1.transition_hash;
  }, ci_timeout_seconds(180)));
  ASSERT_TRUE(n0.pause_proposals_for_test(true));
  ASSERT_TRUE(n1.pause_proposals_for_test(true));
  std::this_thread::sleep_for(std::chrono::milliseconds(400));

  int sender_idx = -1;
  std::pair<OutPoint, TxOut> prev;
  std::array<std::uint8_t, 20> sender_pkh{};
  for (int i = 0; i < 2; ++i) {
    const auto kp = node::Node::deterministic_test_keypairs()[static_cast<std::size_t>(i)];
    const auto pkh = crypto::h160(Bytes(kp.public_key.begin(), kp.public_key.end()));
    auto utxos = cluster.nodes[static_cast<std::size_t>(i)]->find_utxos_by_pubkey_hash_for_test(pkh);
    if (utxos.empty()) continue;
    sender_idx = i;
    prev = utxos.front();
    sender_pkh = pkh;
    break;
  }
  ASSERT_TRUE(sender_idx >= 0);

  std::array<std::uint8_t, 20> recipient_pkh{};
  recipient_pkh.fill(0x66);
  constexpr std::uint64_t kAmount = 5'000'000'000ULL;
  constexpr std::uint64_t kFee = 10'000ULL;
  ASSERT_TRUE(prev.second.value > kAmount + kFee);

  std::vector<TxOut> outputs;
  outputs.push_back(TxOut{kAmount, address::p2pkh_script_pubkey(recipient_pkh)});
  outputs.push_back(TxOut{prev.second.value - kAmount - kFee, address::p2pkh_script_pubkey(sender_pkh)});

  const auto kp = node::Node::deterministic_test_keypairs()[static_cast<std::size_t>(sender_idx)];
  std::string build_err;
  auto tx = build_signed_p2pkh_tx_single_input(node_chain_domain(n0), prev.first, prev.second, Bytes(kp.private_key.begin(), kp.private_key.end()),
                                               outputs, &build_err);
  ASSERT_TRUE(tx.has_value());
  ASSERT_TRUE(cluster.nodes[static_cast<std::size_t>(sender_idx)]->inject_tx_for_test(*tx, true));

  ASSERT_TRUE(wait_for([&]() {
    storage::DB db0;
    storage::DB db1;
    if (!db0.open_readonly(cluster.configs[0].db_path)) return false;
    if (!db1.open_readonly(cluster.configs[1].db_path)) return false;
    return db0.get_ingress_bytes(tx->txid()).has_value() && db1.get_ingress_bytes(tx->txid()).has_value();
  }, std::chrono::seconds(10)));

  n0.stop();
  n1.stop();
}

TEST(test_synced_follower_materializes_recipient_utxos_for_finalized_transfer) {
  const std::string base = unique_test_base("/tmp/finalis_it_follower_materializes_transfer_utxos");
  auto cluster = make_cluster(base, 1, 2, 1);
  auto& leader = *cluster.nodes[0];
  auto& follower = *cluster.nodes[1];

  ASSERT_TRUE(wait_for([&]() {
    return leader.status().height >= 33 && follower.status().height >= 33;
  }, ci_timeout_seconds(240)));

  constexpr std::uint64_t kAmount = 10'000'000'000ULL;
  constexpr std::uint64_t kFee = 10'000ULL;

  const auto keys = node::Node::deterministic_test_keypairs();
  std::optional<FundedTestWallet> funded;
  ASSERT_TRUE(wait_for([&]() {
    funded = find_funded_test_wallet(leader, keys, kAmount + kFee, 1);
    if (!funded.has_value() || funded->utxos.empty()) return false;
    return true;
  }, ci_timeout_seconds(120)));
  ASSERT_TRUE(funded.has_value());

  std::array<std::uint8_t, 20> recipient_pkh{};
  recipient_pkh.fill(0x55);
  const auto sender_kp = keys[funded->key_index];
  const auto own_pkh = crypto::h160(Bytes(sender_kp.public_key.begin(), sender_kp.public_key.end()));
  const auto prev = funded->utxos.front();
  ASSERT_TRUE(prev.second.value > kAmount + kFee);

  std::vector<TxOut> outputs;
  outputs.push_back(TxOut{kAmount, address::p2pkh_script_pubkey(recipient_pkh)});
  outputs.push_back(TxOut{prev.second.value - kAmount - kFee, address::p2pkh_script_pubkey(own_pkh)});

  std::string build_err;
  auto tx = build_signed_p2pkh_tx_single_input(node_chain_domain(leader), prev.first, prev.second,
                                               Bytes(sender_kp.private_key.begin(), sender_kp.private_key.end()),
                                               outputs, &build_err);
  ASSERT_TRUE(tx.has_value());
  ASSERT_TRUE(leader.inject_tx_for_test(*tx, true));

  ASSERT_TRUE(wait_for([&]() {
    const auto leader_status = leader.status();
    const auto follower_status = follower.status();
    if (leader_status.height < 34 || follower_status.height < 34) return false;
    if (leader_status.transition_hash != follower_status.transition_hash) return false;
    return !follower.find_utxos_by_pubkey_hash_for_test(recipient_pkh).empty();
  }, ci_timeout_seconds(180)));

  const auto follower_utxos = follower.find_utxos_by_pubkey_hash_for_test(recipient_pkh);
  ASSERT_TRUE(!follower_utxos.empty());
  ASSERT_EQ(follower_utxos.front().second.value, kAmount);

  follower.stop();
  leader.stop();

  storage::DB follower_db;
  ASSERT_TRUE(follower_db.open(cluster.configs[1].db_path));
  const auto persisted_utxos = follower_db.load_transparent_utxos();
  bool found_recipient = false;
  for (const auto& [op, entry] : persisted_utxos) {
    (void)op;
    if (entry.out.value == kAmount && entry.out.script_pubkey == address::p2pkh_script_pubkey(recipient_pkh)) {
      found_recipient = true;
      break;
    }
  }
  ASSERT_TRUE(found_recipient);
  follower_db.close();

  lightserver::Config lcfg;
  lcfg.db_path = cluster.configs[1].db_path;
  lightserver::Server ls(lcfg);
  ASSERT_TRUE(ls.init());
  const auto sh = crypto::sha256(address::p2pkh_script_pubkey(recipient_pkh));
  const std::string body = std::string(R"({"jsonrpc":"2.0","id":301,"method":"get_utxos","params":{"scripthash_hex":")") +
                           hex_encode32(sh) + R"("}})";
  const auto resp = ls.handle_rpc_for_test(body);
  ASSERT_TRUE(resp.find("\"value\":10000000000") != std::string::npos);
}

TEST(test_synced_follower_restarts_from_lane_certificates_delivered_with_blocks) {
  // A follower that syncs a transfer's block without its ingress gossip gets the lane certificates
  // only with the TRANSITION, and startup replay rebuilds every block from them.
  const std::string base = unique_test_base("/tmp/finalis_it_synced_follower_restart_lane_certs");
  auto cluster = make_cluster(base, 1, 1, 1);
  auto& leader = *cluster.nodes[0];

  ASSERT_TRUE(wait_for_tip(leader, 33, ci_timeout_seconds(240)));
  constexpr std::uint64_t kAmount = 10'000'000'000ULL;
  constexpr std::uint64_t kFee = 10'000ULL;
  const auto keys = node::Node::deterministic_test_keypairs();
  std::optional<FundedTestWallet> funded;
  ASSERT_TRUE(wait_for([&]() {
    funded = find_funded_test_wallet(leader, keys, kAmount + kFee, 1);
    return funded.has_value() && !funded->utxos.empty();
  }, ci_timeout_seconds(120)));

  std::array<std::uint8_t, 20> recipient_pkh{};
  recipient_pkh.fill(0x56);
  const auto sender_kp = keys[funded->key_index];
  const auto own_pkh = crypto::h160(Bytes(sender_kp.public_key.begin(), sender_kp.public_key.end()));
  const auto prev = funded->utxos.front();
  std::vector<TxOut> outputs;
  outputs.push_back(TxOut{kAmount, address::p2pkh_script_pubkey(recipient_pkh)});
  outputs.push_back(TxOut{prev.second.value - kAmount - kFee, address::p2pkh_script_pubkey(own_pkh)});
  std::string build_err;
  auto tx = build_signed_p2pkh_tx_single_input(node_chain_domain(leader), prev.first, prev.second,
                                               Bytes(sender_kp.private_key.begin(), sender_kp.private_key.end()),
                                               outputs, &build_err);
  ASSERT_TRUE(tx.has_value());
  ASSERT_TRUE(leader.inject_tx_for_test(*tx, true));
  ASSERT_TRUE(wait_for([&]() { return !leader.find_utxos_by_pubkey_hash_for_test(recipient_pkh).empty(); },
                       ci_timeout_seconds(120)));
  const auto target = leader.status().height;

  // Blocks arrive only as TRANSITION messages: no network, so no ingress gossip or range sync.
  auto follower_cfg = cluster.configs[0];
  follower_cfg.node_id = 1;
  follower_cfg.disable_p2p = true;
  follower_cfg.db_path = base + "/follower";
  follower_cfg.validator_key_file = follower_cfg.db_path + "/keystore/validator.json";
  keystore::ValidatorKey follower_key;
  std::string key_err;
  ASSERT_TRUE(keystore::create_validator_keystore(follower_cfg.validator_key_file, follower_cfg.validator_passphrase,
                                                  "mainnet", "sc", deterministic_seed_for_node_id(1), &follower_key,
                                                  &key_err));
  auto follower = std::make_unique<node::Node>(follower_cfg);
  ASSERT_TRUE(follower->init());
  follower->start();
  for (std::uint64_t h = 1; h <= target; ++h) {
    const auto msg = leader.finalized_transition_msg_for_test(h);
    ASSERT_TRUE(msg.has_value());
    ASSERT_TRUE(follower->inject_transition_msg_for_test(*msg));
  }
  ASSERT_EQ(follower->status().height, target);
  ASSERT_TRUE(!follower->find_utxos_by_pubkey_hash_for_test(recipient_pkh).empty());
  follower->stop();
  follower.reset();

  auto restarted = std::make_unique<node::Node>(follower_cfg);
  ASSERT_TRUE(restarted->init());
  ASSERT_EQ(restarted->status().height, target);
  ASSERT_TRUE(!restarted->find_utxos_by_pubkey_hash_for_test(recipient_pkh).empty());
  restarted->stop();
}

TEST(test_restart_repairs_partial_settlement_state) {
  const std::string base = unique_test_base("/tmp/finalis_it_reward_restart_repair");
  {
    auto cluster = make_cluster(base, 1, 1, 1);
    ASSERT_TRUE(wait_for([&]() { return cluster.nodes[0]->status().height >= 33; }, ci_timeout_seconds(120)));
    cluster.nodes[0]->stop();
  }

  {
    storage::DB db;
    ASSERT_TRUE(db.open(base + "/node0"));
    ASSERT_TRUE(db.erase("ER:" + epoch_db_key_suffix(1)));
    ASSERT_TRUE(db.flush());
  }

  node::NodeConfig cfg;
  cfg.allow_unencrypted_keystore = true;  // test fixture: no passphrase
  cfg.disable_p2p = true;
  cfg.node_id = 0;
  cfg.max_committee = 1;
  cfg.network.min_block_interval_ms = 100;
  cfg.network.round_timeout_ms = 200;
  cfg.p2p_port = 0;
  cfg.db_path = base + "/node0";
  cfg.genesis_path = base + "/genesis.json";
  cfg.allow_unsafe_genesis_override = true;
  cfg.validator_key_file = cfg.db_path + "/keystore/validator.json";
  cfg.validator_passphrase = "test-pass";

  node::Node restarted(cfg);
  ASSERT_TRUE(restarted.init());
  restarted.stop();

  storage::DB repaired;
  ASSERT_TRUE(repaired.open(base + "/node0"));
  const auto state = repaired.get_epoch_reward_settlement(1);
  ASSERT_TRUE(state.has_value());
  ASSERT_TRUE(state->settled);
  std::uint64_t gross = 0;
  for (std::uint64_t h = 1; h <= 32; ++h) gross += consensus::reward_units(h);
  ASSERT_EQ(state->total_reward_units, gross - ((gross * consensus::RESERVE_ACCRUAL_BPS) / 10'000ULL));
  ASSERT_EQ(state->reserve_accrual_units, (gross * consensus::RESERVE_ACCRUAL_BPS) / 10'000ULL);
}

TEST(test_crash_between_persist_and_settlement_recovers_correctly) {
  const std::string base = unique_test_base("/tmp/finalis_it_reward_crash_repair");
  std::uint64_t finalized_height = 0;
  {
    auto cluster = make_cluster(base, 1, 1, 1);
    ASSERT_TRUE(wait_for([&]() { return cluster.nodes[0]->status().height >= 10; }, std::chrono::seconds(30)));
    cluster.nodes[0]->stop();
  }

  {
    storage::DB db;
    ASSERT_TRUE(db.open(base + "/node0"));
    // Read the tip after shutdown: a block finalized while stopping would otherwise change the epoch total.
    const auto tip = db.get_tip();
    ASSERT_TRUE(tip.has_value());
    finalized_height = tip->height;
    ASSERT_TRUE(db.erase("ER:" + epoch_db_key_suffix(1)));
    ASSERT_TRUE(db.flush());
  }

  node::NodeConfig cfg;
  cfg.allow_unencrypted_keystore = true;  // test fixture: no passphrase
  cfg.disable_p2p = true;
  cfg.node_id = 0;
  cfg.max_committee = 1;
  cfg.network.min_block_interval_ms = 100;
  cfg.network.round_timeout_ms = 200;
  cfg.p2p_port = 0;
  cfg.db_path = base + "/node0";
  cfg.genesis_path = base + "/genesis.json";
  cfg.allow_unsafe_genesis_override = true;
  cfg.validator_key_file = cfg.db_path + "/keystore/validator.json";
  cfg.validator_passphrase = "test-pass";

  node::Node restarted(cfg);
  ASSERT_TRUE(restarted.init());
  restarted.stop();

  storage::DB repaired;
  ASSERT_TRUE(repaired.open(base + "/node0"));
  const auto state = repaired.get_epoch_reward_settlement(1);
  ASSERT_TRUE(state.has_value());
  const std::uint64_t epoch_end_height = std::min<std::uint64_t>(finalized_height, 32ULL);
  std::uint64_t gross = 0;
  for (std::uint64_t h = 1; h <= epoch_end_height; ++h) gross += consensus::reward_units(h);
  ASSERT_EQ(state->total_reward_units, gross - ((gross * consensus::RESERVE_ACCRUAL_BPS) / 10'000ULL));
  ASSERT_EQ(state->reserve_accrual_units, (gross * consensus::RESERVE_ACCRUAL_BPS) / 10'000ULL);
}

TEST(test_crash_between_csaf_and_block_write_does_not_corrupt_state) {
  const std::string base = unique_test_base("/tmp/finalis_it_csaf_crash_repair");
  std::uint64_t next_height = 0;
  {
    auto cluster = make_cluster(base, 1, 1, 1);
    ASSERT_TRUE(wait_for([&]() { return cluster.nodes[0]->status().height >= 6; }, std::chrono::seconds(30)));
    cluster.nodes[0]->stop();
  }

  {
    storage::DB db;
    ASSERT_TRUE(db.open(base + "/node0"));
    // Read the tip after shutdown: a block finalized while stopping would otherwise move the target height.
    const auto tip = db.get_tip();
    ASSERT_TRUE(tip.has_value());
    next_height = tip->height + 1;
    ASSERT_TRUE(db.put(csafe_db_key(next_height), Bytes{0x01, 0x02, 0x03}));
    ASSERT_TRUE(db.flush());
  }

  node::NodeConfig cfg;
  cfg.allow_unencrypted_keystore = true;  // test fixture: no passphrase
  cfg.disable_p2p = true;
  cfg.node_id = 0;
  cfg.max_committee = 1;
  cfg.network.min_block_interval_ms = 100;
  cfg.network.round_timeout_ms = 200;
  cfg.p2p_port = 0;
  cfg.db_path = base + "/node0";
  cfg.genesis_path = base + "/genesis.json";
  cfg.allow_unsafe_genesis_override = true;
  cfg.validator_key_file = cfg.db_path + "/keystore/validator.json";
  cfg.validator_passphrase = "test-pass";

  // An unreadable row may be the only record of a broadcast vote: it is quarantined (not erased)
  // and the node abstains at that height while otherwise running normally.
  {
    node::Node restarted(cfg);
    ASSERT_TRUE(restarted.init());
    ASSERT_TRUE(restarted.abstain_heights_for_test().count(next_height) == 1);
    restarted.start();
    std::this_thread::sleep_for(std::chrono::milliseconds(1500));
    // Sole validator abstaining: nothing is signed, so the height cannot finalize.
    ASSERT_EQ(restarted.status().height + 1, next_height);
    ASSERT_TRUE(restarted.abstain_heights_for_test().count(next_height) == 1);
    restarted.stop();
  }

  storage::DB db;
  ASSERT_TRUE(db.open(base + "/node0"));
  ASSERT_TRUE(!db.get(csafe_db_key(next_height)).has_value());
  const auto quarantined = db.get(csafe_quarantine_db_key(next_height));
  ASSERT_TRUE(quarantined.has_value());
  ASSERT_TRUE(*quarantined == (Bytes{0x01, 0x02, 0x03}));
}

TEST(test_restart_with_invalid_csaf_rebuilds_correct_state) {
  const std::string base = unique_test_base("/tmp/finalis_it_invalid_csaf_rebuild");
  std::uint64_t next_height = 0;
  {
    auto cluster = make_cluster(base, 1, 1, 1);
    ASSERT_TRUE(wait_for([&]() { return cluster.nodes[0]->status().height >= 6; }, std::chrono::seconds(30)));
    next_height = cluster.nodes[0]->status().height + 1;
    cluster.nodes[0]->stop();
  }

  {
    storage::DB db;
    ASSERT_TRUE(db.open(base + "/node0"));
    QuorumCertificate bogus;
    bogus.height = next_height;
    bogus.round = 0;
    bogus.block_id.fill(0xAB);
    ASSERT_TRUE(db.put(csafe_db_key(next_height), serialize_test_csaf(std::nullopt, std::optional<QuorumCertificate>{bogus},
                                                                      std::nullopt)));
    ASSERT_TRUE(db.flush());
  }

  node::NodeConfig cfg;
  cfg.allow_unencrypted_keystore = true;  // test fixture: no passphrase
  cfg.disable_p2p = true;
  cfg.node_id = 0;
  cfg.max_committee = 1;
  cfg.network.min_block_interval_ms = 100;
  cfg.network.round_timeout_ms = 200;
  cfg.p2p_port = 0;
  cfg.db_path = base + "/node0";
  cfg.genesis_path = base + "/genesis.json";
  cfg.allow_unsafe_genesis_override = true;
  cfg.validator_key_file = cfg.db_path + "/keystore/validator.json";
  cfg.validator_passphrase = "test-pass";

  node::Node restarted(cfg);
  ASSERT_TRUE(restarted.init());
  restarted.stop();

  storage::DB db;
  ASSERT_TRUE(db.open(base + "/node0"));
  ASSERT_TRUE(!db.get(csafe_db_key(next_height)).has_value());
}

// Single validator, stopped, with an unreadable safety-state row at its next height.
// Returns the next height; fills *cfg with a restart config for the node.
std::uint64_t setup_single_validator_with_unreadable_safety_row(const std::string& base, node::NodeConfig* cfg) {
  {
    auto cluster = make_cluster(base, 1, 1, 1);
    if (!wait_for([&]() { return cluster.nodes[0]->status().height >= 4; }, std::chrono::seconds(30))) return 0;
    cluster.nodes[0]->stop();
  }
  std::uint64_t next_height = 0;
  {
    storage::DB db;
    if (!db.open(base + "/node0")) return 0;
    const auto tip = db.get_tip();
    if (!tip.has_value()) return 0;
    next_height = tip->height + 1;
    if (!db.put(csafe_db_key(next_height), Bytes{0xDE, 0xAD})) return 0;
    if (!db.flush()) return 0;
  }
  cfg->allow_unencrypted_keystore = true;  // test fixture: no passphrase
  cfg->disable_p2p = true;
  cfg->node_id = 0;
  cfg->max_committee = 1;
  cfg->network.min_block_interval_ms = 100;
  cfg->network.round_timeout_ms = 200;
  cfg->p2p_port = 0;
  cfg->db_path = base + "/node0";
  cfg->genesis_path = base + "/genesis.json";
  cfg->allow_unsafe_genesis_override = true;
  cfg->validator_key_file = cfg->db_path + "/keystore/validator.json";
  cfg->validator_passphrase = "test-pass";
  return next_height;
}

TEST(test_unreadable_safety_state_abstention_survives_second_restart) {
  const std::string base = unique_test_base("/tmp/finalis_it_csaf_abstain_two_restarts");
  node::NodeConfig cfg;
  const auto next_height = setup_single_validator_with_unreadable_safety_row(base, &cfg);
  ASSERT_TRUE(next_height > 0);
  for (int restart = 0; restart < 2; ++restart) {
    node::Node n(cfg);
    ASSERT_TRUE(n.init());
    ASSERT_EQ(n.status().height + 1, next_height);
    const auto abstain = n.abstain_heights_for_test();
    ASSERT_EQ(abstain.size(), 1u);
    ASSERT_TRUE(abstain.count(next_height) == 1);
    n.stop();
  }
  storage::DB db;
  ASSERT_TRUE(db.open(base + "/node0"));
  ASSERT_TRUE(!db.get(csafe_db_key(next_height)).has_value());
  const auto quarantined = db.get(csafe_quarantine_db_key(next_height));
  ASSERT_TRUE(quarantined.has_value());
  ASSERT_TRUE(*quarantined == (Bytes{0xDE, 0xAD}));
}

TEST(test_unsafe_discard_vote_lock_override_resumes_single_validator) {
  const std::string base = unique_test_base("/tmp/finalis_it_csaf_override");
  node::NodeConfig cfg;
  const auto next_height = setup_single_validator_with_unreadable_safety_row(base, &cfg);
  ASSERT_TRUE(next_height > 0);

  // Override naming a different height is ignored: the node still abstains.
  {
    auto wrong = cfg;
    wrong.unsafe_discard_vote_lock_height = next_height + 5;
    node::Node n(wrong);
    ASSERT_TRUE(n.init());
    ASSERT_TRUE(n.abstain_heights_for_test().count(next_height) == 1);
    n.stop();
  }

  // Override at exactly the quarantined height: abstention dropped and the chain moves again.
  {
    auto override_cfg = cfg;
    override_cfg.unsafe_discard_vote_lock_height = next_height;
    node::Node n(override_cfg);
    ASSERT_TRUE(n.init());
    ASSERT_TRUE(n.abstain_heights_for_test().empty());
    n.start();
    ASSERT_TRUE(wait_for([&]() { return n.status().height >= next_height + 1; }, std::chrono::seconds(30)));
    n.stop();
  }
  storage::DB db;
  ASSERT_TRUE(db.open(base + "/node0"));
  ASSERT_TRUE(!db.get(csafe_quarantine_db_key(next_height)).has_value());
}

TEST(test_unreadable_safety_state_abstains_and_network_finalizes_without_it) {
  auto cluster = make_cluster(unique_test_base("/tmp/finalis_it_csaf_abstain_cluster"), 4, 4, 4);
  ASSERT_TRUE(wait_for([&]() { return cluster.nodes[0]->status().height >= 2; }, ci_timeout_seconds(60)));
  for (auto& n : cluster.nodes) ASSERT_TRUE(n->pause_proposals_for_test(true));
  ASSERT_TRUE(wait_for_stable_same_tip(cluster.nodes, ci_timeout_seconds(30)));

  const std::size_t victim = 3;
  cluster.nodes[victim]->stop();
  cluster.nodes[victim].reset();
  std::uint64_t h = 0;
  {
    storage::DB db;
    ASSERT_TRUE(db.open(cluster.configs[victim].db_path));
    const auto tip = db.get_tip();
    ASSERT_TRUE(tip.has_value());
    h = tip->height + 1;
    ASSERT_TRUE(db.put(csafe_db_key(h), Bytes{0xBA, 0xD0}));
    ASSERT_TRUE(db.flush());
  }
  cluster.nodes[victim] = std::make_unique<node::Node>(cluster.configs[victim]);
  ASSERT_TRUE(cluster.nodes[victim]->init());
  ASSERT_TRUE(cluster.nodes[victim]->local_is_committee_member_for_test(h, 0));
  ASSERT_TRUE(cluster.nodes[victim]->abstain_heights_for_test().count(h) == 1);
  cluster.nodes[victim]->start();

  // The other three (a quorum of four) finalize h without the abstaining node.
  for (auto& n : cluster.nodes) ASSERT_TRUE(n->pause_proposals_for_test(false));
  ASSERT_TRUE(wait_for([&]() {
    for (const auto& n : cluster.nodes) {
      if (n->status().height < h + 2) return false;
    }
    return true;
  }, ci_timeout_seconds(120)));
  // h finalized: the abstention is released and the node votes normally again from h+1.
  ASSERT_TRUE(cluster.nodes[victim]->abstain_heights_for_test().empty());
}

// A corrupt primary row is recovered from its mirror: the lock survives and nothing is quarantined.
TEST(test_safety_state_mirror_recovers_corrupted_primary) {
  const auto keys = node::Node::deterministic_test_keypairs();
  ASSERT_TRUE(keys.size() >= 4u);
  auto cluster = make_cluster(unique_test_base("/tmp/finalis_it_csaf_mirror"), 4, 4, 4);
  Tx tx = make_fixture_ingress_tx(1, 0x8C);
  ASSERT_TRUE(restart_cluster_with_seeded_certified_ingress(&cluster, {tx.serialize()}, true, true, true));
  const std::uint64_t h = cluster.nodes[0]->status().height + 1;
  auto proposal = build_cluster_frontier_proposal_from_records(cluster, keys, {tx.serialize()}, h, 0,
                                                               "/tmp/finalis_it_csaf_mirror_a0");
  ASSERT_TRUE(proposal.has_value());
  std::size_t ti = cluster.nodes.size();
  for (std::size_t k = 0; k < cluster.nodes.size(); ++k) {
    if (cluster.nodes[k]->local_is_committee_member_for_test(h, 0)) {
      ti = k;
      break;
    }
  }
  ASSERT_TRUE(ti < cluster.nodes.size());
  ASSERT_TRUE(advance_test_frontier_round(*cluster.nodes[ti], h, 0));
  ASSERT_EQ(cluster.nodes[ti]->inject_network_propose_result_for_test(make_test_frontier_propose_msg(cluster.nodes[0]->consensus_domain_for_test(), *proposal)),
            std::string("accepted"));
  // A polka for the proposal: the node locks on it (and precommits).
  const auto committee = cluster.nodes[ti]->committee_for_height_round_for_test(h, 0);
  inject_test_prevotes(*cluster.nodes[ti], keys, committee, h, 0, frontier_proposal_id(*proposal),
                       consensus::quorum_threshold(committee.size()) - 1);
  const auto lock_before = cluster.nodes[ti]->local_vote_lock_for_test(h);
  ASSERT_TRUE(lock_before.has_value());
  ASSERT_TRUE(cluster.nodes[ti]->status().height + 1 == h);  // one precommit: not finalized

  cluster.nodes[ti]->stop();
  cluster.nodes[ti].reset();
  {
    storage::DB db;
    ASSERT_TRUE(db.open(cluster.configs[ti].db_path));
    ASSERT_TRUE(db.get(csafe_mirror_db_key(h)).has_value());
    ASSERT_TRUE(db.put(csafe_db_key(h), Bytes{0x43, 0x53, 0x46, 0x32, 0xFF}));  // magic, then garbage
    ASSERT_TRUE(db.flush());
  }
  cluster.nodes[ti] = std::make_unique<node::Node>(cluster.configs[ti]);
  ASSERT_TRUE(cluster.nodes[ti]->init());
  ASSERT_TRUE(cluster.nodes[ti]->abstain_heights_for_test().empty());
  const auto lock_after = cluster.nodes[ti]->local_vote_lock_for_test(h);
  ASSERT_TRUE(lock_after.has_value());
  ASSERT_TRUE(lock_after->first == lock_before->first);
  ASSERT_EQ(lock_after->second, lock_before->second);
}

TEST(test_db_rejects_conflicting_same_height_finalized_writes) {
  const std::string base = unique_test_base("/tmp/finalis_it_reject_conflicting_finalized_writes");
  const auto copied_path = std::filesystem::path(base) / "node0_copy";
  std::uint64_t target_height = 0;
  Hash32 original_hash{};
  FinalityCertificate original_cert;
  {
    auto cluster = make_cluster(base, 1, 1, 1);
    ASSERT_TRUE(wait_for([&]() { return cluster.nodes[0]->status().height >= 6; }, std::chrono::seconds(30)));
    target_height = cluster.nodes[0]->status().height;
    original_hash = cluster.nodes[0]->status().transition_hash;
    cluster.nodes[0]->stop();
  }

  std::filesystem::remove_all(copied_path);
  std::filesystem::copy(std::filesystem::path(base) / "node0", copied_path, std::filesystem::copy_options::recursive);

  storage::DB db;
  ASSERT_TRUE(db.open(copied_path.string()));
  auto cert = db.get_finality_certificate_by_height(target_height);
  ASSERT_TRUE(cert.has_value());
  original_cert = *cert;
  Hash32 conflicting_hash = original_hash;
  conflicting_hash[0] ^= 0xFF;
  ASSERT_TRUE(conflicting_hash != original_hash);
  ASSERT_TRUE(!db.set_height_hash(target_height, conflicting_hash));

  auto conflicting_cert = original_cert;
  conflicting_cert.block_id = conflicting_hash;
  ASSERT_TRUE(!db.put_finality_certificate(conflicting_cert));
}

TEST(test_conflicting_same_height_finalized_artifacts_fail_loud_on_load) {
  const std::string base = unique_test_base("/tmp/finalis_it_conflicting_finalized_artifacts");
  auto cluster = make_cluster(base, 1, 1, 1);
  ASSERT_TRUE(wait_for([&]() { return cluster.nodes[0]->status().height >= 6; }, std::chrono::seconds(30)));
  cluster.nodes[0]->stop();

  storage::DB db;
  ASSERT_TRUE(db.open(base + "/node0"));
  const auto target_height = db.get_tip()->height;
  auto cert = db.get_finality_certificate_by_height(target_height);
  ASSERT_TRUE(cert.has_value());
  const auto original_hash = cert->block_id;
  cert->block_id[0] ^= 0xAA;
  ASSERT_TRUE(cert->block_id != original_hash);
  ASSERT_TRUE(db.put(test_key_finality_certificate_height(target_height), cert->serialize()));
  ASSERT_TRUE(db.flush());

  node::Node restarted(single_node_cfg(base, 1));
  std::ostringstream captured;
  auto* old = std::cerr.rdbuf(captured.rdbuf());
  const bool init_ok = restarted.init();
  std::cerr.rdbuf(old);
  ASSERT_TRUE(!init_ok);
  ASSERT_TRUE(captured.str().find("db open failed:") != std::string::npos);
}

TEST(test_canonical_signature_subset_produces_identical_rewards) {
  const auto keys = node::Node::deterministic_test_keypairs();
  const std::string base = unique_test_base("/tmp/finalis_it_reward_canonical_subset");
  auto cluster = make_cluster(base, 4, 4, 4);
  auto& nodes = cluster.nodes;
  Tx tx = make_fixture_ingress_tx(1, 0xC1);
  ASSERT_TRUE(restart_cluster_with_seeded_certified_ingress(&cluster, {tx.serialize()}, true, true));

  const auto before = nodes[0]->status();
  const std::uint64_t target_height = before.height + 1;
  const std::uint32_t round = before.round;
  auto proposal = build_cluster_frontier_proposal_from_records(
      cluster, keys, {tx.serialize()}, target_height, round, "/tmp/finalis_it_reward_canonical_subset_builder");
  ASSERT_TRUE(proposal.has_value());

  const auto committee = nodes[0]->committee_for_height_round_for_test(target_height, round);
  const auto quorum = consensus::quorum_threshold(committee.size());
  auto qc = make_test_qc(nodes[0]->consensus_domain_for_test(), keys, committee, target_height, round, frontier_proposal_id(*proposal), committee.size());
  ASSERT_TRUE(qc.signatures.size() >= quorum);

  auto sigs_a = qc.signatures;
  auto sigs_b = qc.signatures;
  std::reverse(sigs_b.begin(), sigs_b.end());
  if (!sigs_b.empty()) sigs_b.push_back(sigs_b.front());

  if (!inject_test_frontier_block(*nodes[0], *proposal, sigs_a)) {
    throw std::runtime_error("frontier finalize node0 failed: " + nodes[0]->last_test_hook_error_for_test());
  }
  if (!inject_test_frontier_block(*nodes[1], *proposal, sigs_b)) {
    throw std::runtime_error("frontier finalize node1 failed: " + nodes[1]->last_test_hook_error_for_test());
  }
  ASSERT_TRUE(wait_for([&]() { return nodes[0]->status().height >= target_height; }, std::chrono::seconds(10)));
  ASSERT_TRUE(wait_for([&]() { return nodes[1]->status().height >= target_height; }, std::chrono::seconds(10)));
  for (auto& n : nodes) n->stop();

  storage::DB db0;
  storage::DB db1;
  ASSERT_TRUE(db0.open(base + "/node0"));
  ASSERT_TRUE(db1.open(base + "/node1"));
  const auto epoch_start = consensus::committee_epoch_start(target_height, node::NodeConfig{}.network.committee_epoch_blocks);
  const auto state0 = db0.get_epoch_reward_settlement(epoch_start);
  const auto state1 = db1.get_epoch_reward_settlement(epoch_start);
  ASSERT_TRUE(state0.has_value());
  ASSERT_TRUE(state1.has_value());
  ASSERT_EQ(state0->reward_score_units, state1->reward_score_units);
  const auto cert0 = db0.get_finality_certificate_by_height(target_height);
  const auto cert1 = db1.get_finality_certificate_by_height(target_height);
  ASSERT_TRUE(cert0.has_value());
  ASSERT_TRUE(cert1.has_value());
  ASSERT_EQ(cert0->signatures.size(), quorum);
  ASSERT_EQ(cert1->signatures.size(), quorum);
  ASSERT_TRUE(same_finality_sig_vector(cert0->signatures, cert1->signatures));
}

TEST(test_delayed_finalized_vote_soft_reject_keeps_peer_alive_and_chain_continues) {
  const std::string base = unique_test_base("/tmp/finalis_it_delayed_finalized_vote_soft_reject");
  auto cluster = make_cluster(base, 2, 2, 2);
  auto& nodes = cluster.nodes;

  ASSERT_TRUE(wait_for([&]() {
    for (const auto& n : nodes) {
      if (n->status().height < 6) return false;
    }
    return true;
  }, std::chrono::seconds(60)));

  const auto finalized = nodes[0]->status();
  const std::uint64_t target_height = finalized.height;
  auto finalized_artifact = load_frontier_artifact_at_height(base + "/node0", target_height);
  ASSERT_TRUE(finalized_artifact.has_value());

  const auto committee =
      nodes[0]->committee_for_height_round_for_test(target_height, finalized_artifact->proposal.transition.round);
  const auto signer = crypto::keypair_from_seed32(deterministic_seed_for_node_id(1));
  ASSERT_TRUE(signer.has_value());
  ASSERT_TRUE(std::find(committee.begin(), committee.end(), signer->public_key) != committee.end());

  Vote delayed_vote;
  delayed_vote.height = target_height;
  delayed_vote.round = finalized_artifact->proposal.transition.round;
  delayed_vote.block_id = frontier_proposal_id(finalized_artifact->proposal);
  delayed_vote.validator_pubkey = signer->public_key;
  auto sig = crypto::ed25519_sign(
      vote_signing_message(nodes[0]->consensus_domain_for_test(), delayed_vote.height, delayed_vote.round, delayed_vote.block_id), signer->private_key);
  ASSERT_TRUE(sig.has_value());
  delayed_vote.signature = *sig;

  ASSERT_EQ(nodes[0]->inject_network_vote_result_for_test(delayed_vote), std::string("soft-reject"));

  ASSERT_TRUE(wait_for([&]() {
    for (const auto& n : nodes) {
      if (n->status().height < target_height + 1) return false;
    }
    return true;
  }, std::chrono::seconds(30)));
}

TEST(test_future_height_vote_soft_rejects_without_penalizing_honest_ahead_peer) {
  const std::string base = unique_test_base("/tmp/finalis_it_future_vote_soft_reject");
  auto cluster = make_cluster(base, 2, 2, 2);
  auto& nodes = cluster.nodes;

  ASSERT_TRUE(wait_for([&]() {
    for (const auto& n : nodes) {
      if (n->status().height < 6) return false;
    }
    return true;
  }, std::chrono::seconds(60)));

  const auto live = nodes[0]->status();
  Vote future_vote;
  future_vote.height = live.height + 2;
  future_vote.round = 0;
  future_vote.block_id.fill(0xAB);
  const auto signer = crypto::keypair_from_seed32(deterministic_seed_for_node_id(1));
  ASSERT_TRUE(signer.has_value());
  future_vote.validator_pubkey = signer->public_key;
  auto sig = crypto::ed25519_sign(
      vote_signing_message(nodes[0]->consensus_domain_for_test(), future_vote.height, future_vote.round, future_vote.block_id), signer->private_key);
  ASSERT_TRUE(sig.has_value());
  future_vote.signature = *sig;

  ASSERT_EQ(nodes[0]->inject_network_vote_result_for_test(future_vote), std::string("soft-reject"));
}

TEST(test_future_height_propose_soft_rejects_without_penalizing_honest_ahead_peer) {
  auto cluster = make_cluster(unique_test_base("/tmp/finalis_it_future_propose_soft_reject"), 4, 4, 4);
  auto& nodes = cluster.nodes;

  ASSERT_TRUE(wait_for([&]() {
    for (const auto& n : nodes) {
      if (n->status().height < 6) return false;
    }
    return true;
  }, std::chrono::seconds(60)));
  for (auto& n : nodes) n->pause_proposals_for_test(true);
  ASSERT_TRUE(wait_for_stable_same_tip(nodes, std::chrono::seconds(10)));

  const auto live = nodes[0]->status();
  p2p::ProposeMsg msg;
  msg.height = live.height + 2;
  msg.round = 0;
  msg.prev_finalized_hash = live.transition_hash;

  ASSERT_EQ(nodes[0]->inject_network_propose_result_for_test(msg), std::string("soft-reject"));
}

TEST(test_inbound_ephemeral_source_port_not_persisted_to_peers_dat) {
  const std::string base = unique_test_base("/tmp/finalis_it_inbound_not_persisted");
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);
  const std::string gpath = base + "/genesis.json";
  ASSERT_TRUE(write_mainnet_genesis_file(gpath, 2));
  const std::uint16_t port0 = reserve_test_port();
  ASSERT_TRUE(port0 != 0);

  node::NodeConfig cfg0;
  cfg0.allow_unencrypted_keystore = true;  // test fixture: no passphrase
  cfg0.node_id = 0;
  cfg0.db_path = base + "/node0";
  cfg0.bind_ip = "127.0.0.1";
  cfg0.p2p_port = port0;
  cfg0.outbound_target = 0;
  cfg0.dns_seeds = false;
  cfg0.network.default_seeds.clear();  // keep test nodes off the public mainnet seeds
  cfg0.genesis_path = gpath;
  cfg0.allow_unsafe_genesis_override = true;
  cfg0.validator_key_file = cfg0.db_path + "/keystore/validator.json";
  cfg0.validator_passphrase = "test-pass";
  cfg0.network.min_block_interval_ms = 100;
  cfg0.network.round_timeout_ms = 200;
  ASSERT_TRUE(keystore::create_validator_keystore(cfg0.validator_key_file, cfg0.validator_passphrase, "mainnet", "sc",
                                                  deterministic_seed_for_node_id(0), nullptr, nullptr));

  node::NodeConfig cfg1;
  cfg1.allow_unencrypted_keystore = true;  // test fixture: no passphrase
  cfg1.node_id = 1;
  cfg1.db_path = base + "/node1";
  cfg1.bind_ip = "127.0.0.1";
  cfg1.listen = false;
  cfg1.p2p_port = 0;
  cfg1.outbound_target = 1;
  cfg1.dns_seeds = false;
  cfg1.network.default_seeds.clear();  // keep test nodes off the public mainnet seeds
  cfg1.peers = {"127.0.0.1:" + std::to_string(port0)};
  cfg1.genesis_path = gpath;
  cfg1.allow_unsafe_genesis_override = true;
  cfg1.validator_key_file = cfg1.db_path + "/keystore/validator.json";
  cfg1.validator_passphrase = "test-pass";
  cfg1.network.min_block_interval_ms = 100;
  cfg1.network.round_timeout_ms = 200;
  ASSERT_TRUE(keystore::create_validator_keystore(cfg1.validator_key_file, cfg1.validator_passphrase, "mainnet", "sc",
                                                  deterministic_seed_for_node_id(1), nullptr, nullptr));

  node::Node n0(cfg0);
  node::Node n1(cfg1);
  ASSERT_TRUE(n0.init());
  ASSERT_TRUE(n1.init());
  n0.start();
  n1.start();

  ASSERT_TRUE(wait_for_peer_count(n0, 1, std::chrono::seconds(10)));
  ASSERT_TRUE(wait_for_peer_count(n1, 1, std::chrono::seconds(10)));

  n1.stop();
  n0.stop();

  const auto persisted = read_nonempty_lines(std::filesystem::path(base) / "node0" / "peers.dat");
  ASSERT_TRUE(persisted.empty());
}

TEST(test_canonical_seed_endpoint_preserved_in_peers_dat) {
  const std::string base = unique_test_base("/tmp/finalis_it_outbound_persisted");
  auto cluster = make_p2p_cluster(base, 2, 2, 2);
  auto& nodes = cluster.nodes;

  ASSERT_TRUE(wait_for_peer_count(*nodes[0], 1, std::chrono::seconds(10)));
  ASSERT_TRUE(wait_for_peer_count(*nodes[1], 1, std::chrono::seconds(10)));

  const auto port0 = nodes[0]->p2p_port_for_test();
  nodes[0]->stop();
  nodes[1]->stop();

  const auto persisted = read_nonempty_lines(std::filesystem::path(base) / "node1" / "peers.dat");
  ASSERT_EQ(persisted.size(), 1u);
  ASSERT_EQ(persisted[0], "127.0.0.1:" + std::to_string(port0));
}

TEST(test_load_persisted_peers_splits_legacy_comma_joined_lines) {
  const std::string base = unique_test_base("/tmp/finalis_it_split_legacy_persisted_peers");
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);
  const std::string gpath = base + "/genesis.json";
  ASSERT_TRUE(write_mainnet_genesis_file(gpath, 1));

  const auto db_path = std::filesystem::path(base) / "node0";
  std::filesystem::create_directories(db_path);
  {
    std::ofstream out(db_path / "peers.dat", std::ios::trunc);
    ASSERT_TRUE(out.good());
    out << "198.51.100.20:19440\n";
    out << "203.0.113.10:19440,198.51.100.20:19440\n";
  }

  node::NodeConfig cfg;
  cfg.allow_unencrypted_keystore = true;  // test fixture: no passphrase
  cfg.disable_p2p = true;
  cfg.node_id = 0;
  cfg.db_path = db_path.string();
  cfg.genesis_path = gpath;
  cfg.allow_unsafe_genesis_override = true;
  cfg.validator_key_file = cfg.db_path + "/keystore/validator.json";
  cfg.validator_passphrase = "test-pass";
  ASSERT_TRUE(create_test_validator_keystore(cfg, cfg.node_id));

  node::Node n(cfg);
  ASSERT_TRUE(n.init());
  n.start();
  n.stop();

  const auto persisted = read_nonempty_lines(db_path / "peers.dat");
  ASSERT_EQ(persisted.size(), 2u);
  ASSERT_EQ(persisted[0], "198.51.100.20:19440");
  ASSERT_EQ(persisted[1], "203.0.113.10:19440");
}

TEST(test_same_block_different_signature_superset_same_payout) {
  const auto keys = node::Node::deterministic_test_keypairs();
  const std::string base = unique_test_base("/tmp/finalis_it_reward_signature_superset");
  auto cluster = make_cluster(base, 4, 4, 4);
  auto& nodes = cluster.nodes;
  Tx tx = make_fixture_ingress_tx(1, 0xC2);
  ASSERT_TRUE(restart_cluster_with_seeded_certified_ingress(&cluster, {tx.serialize()}, true, true));

  const auto before = nodes[0]->status();
  const std::uint64_t target_height = before.height + 1;
  const std::uint32_t round = before.round;
  auto proposal = build_cluster_frontier_proposal_from_records(
      cluster, keys, {tx.serialize()}, target_height, round, "/tmp/finalis_it_reward_signature_superset_builder");
  ASSERT_TRUE(proposal.has_value());

  auto committee = nodes[0]->committee_for_height_round_for_test(target_height, round);
  std::sort(committee.begin(), committee.end());
  const auto quorum = consensus::quorum_threshold(committee.size());
  auto quorum_qc = make_test_qc(nodes[0]->consensus_domain_for_test(), keys, committee, target_height, round, frontier_proposal_id(*proposal), quorum);
  auto full_qc = make_test_qc(nodes[0]->consensus_domain_for_test(), keys, committee, target_height, round, frontier_proposal_id(*proposal), committee.size());
  ASSERT_TRUE(quorum_qc.signatures.size() >= quorum);
  ASSERT_TRUE(full_qc.signatures.size() >= quorum);

  ASSERT_TRUE(inject_test_frontier_block(*nodes[0], *proposal, quorum_qc.signatures));
  ASSERT_TRUE(inject_test_frontier_block(*nodes[1], *proposal, full_qc.signatures));
  ASSERT_TRUE(wait_for([&]() { return nodes[0]->status().height >= target_height; }, std::chrono::seconds(10)));
  ASSERT_TRUE(wait_for([&]() { return nodes[1]->status().height >= target_height; }, std::chrono::seconds(10)));
  for (auto& n : nodes) n->stop();

  storage::DB db0;
  storage::DB db1;
  ASSERT_TRUE(db0.open(base + "/node0"));
  ASSERT_TRUE(db1.open(base + "/node1"));
  const auto epoch_start = consensus::committee_epoch_start(target_height, node::NodeConfig{}.network.committee_epoch_blocks);
  const auto state0 = db0.get_epoch_reward_settlement(epoch_start);
  const auto state1 = db1.get_epoch_reward_settlement(epoch_start);
  ASSERT_TRUE(state0.has_value());
  ASSERT_TRUE(state1.has_value());
  ASSERT_EQ(state0->reward_score_units, state1->reward_score_units);
  const auto cert0 = db0.get_finality_certificate_by_height(target_height);
  const auto cert1 = db1.get_finality_certificate_by_height(target_height);
  ASSERT_TRUE(cert0.has_value());
  ASSERT_TRUE(cert1.has_value());
  ASSERT_EQ(cert0->signatures.size(), quorum);
  ASSERT_EQ(cert1->signatures.size(), quorum);
  ASSERT_TRUE(same_finality_sig_vector(cert0->signatures, cert1->signatures));
}

TEST(test_quorum_subset_independence_for_settlement_accounting) {
  // Guards against the height-33 settlement stall where nodes finalized the
  // same block with different valid quorum subsets and diverged in
  // reward_score_units / payout construction.
  const auto keys = node::Node::deterministic_test_keypairs();
  const std::string base = unique_test_base("/tmp/finalis_it_reward_quorum_subset_independence");
  auto cluster = make_cluster(base, 4, 4, 4);
  auto& nodes = cluster.nodes;
  Tx tx = make_fixture_ingress_tx(1, 0xC3);
  ASSERT_TRUE(restart_cluster_with_seeded_certified_ingress(&cluster, {tx.serialize()}, true, true));

  const auto before = nodes[0]->status();
  const std::uint64_t target_height = before.height + 1;
  const std::uint32_t round = before.round;
  auto proposal = build_cluster_frontier_proposal_from_records(
      cluster, keys, {tx.serialize()}, target_height, round,
      "/tmp/finalis_it_reward_quorum_subset_independence_builder");
  ASSERT_TRUE(proposal.has_value());

  auto committee = nodes[0]->committee_for_height_round_for_test(target_height, round);
  std::sort(committee.begin(), committee.end());
  const auto quorum = consensus::quorum_threshold(committee.size());
  ASSERT_TRUE(committee.size() >= quorum + 1);

  auto qc_a = make_test_qc(nodes[0]->consensus_domain_for_test(), keys, committee, target_height, round, frontier_proposal_id(*proposal), quorum);
  std::vector<PubKey32> rotated_committee = committee;
  std::rotate(rotated_committee.begin(), rotated_committee.begin() + 1, rotated_committee.end());
  auto qc_b = make_test_qc(nodes[0]->consensus_domain_for_test(), keys, rotated_committee, target_height, round, frontier_proposal_id(*proposal), quorum);
  ASSERT_EQ(qc_a.signatures.size(), quorum);
  ASSERT_EQ(qc_b.signatures.size(), quorum);
  ASSERT_TRUE(!same_finality_sig_vector(qc_a.signatures, qc_b.signatures));

  ASSERT_TRUE(inject_test_frontier_block(*nodes[0], *proposal, qc_a.signatures));
  ASSERT_TRUE(inject_test_frontier_block(*nodes[1], *proposal, qc_b.signatures));
  ASSERT_TRUE(wait_for([&]() { return nodes[0]->status().height >= target_height; }, std::chrono::seconds(10)));
  ASSERT_TRUE(wait_for([&]() { return nodes[1]->status().height >= target_height; }, std::chrono::seconds(10)));
  for (auto& n : nodes) n->stop();

  storage::DB db0;
  storage::DB db1;
  ASSERT_TRUE(db0.open(base + "/node0"));
  ASSERT_TRUE(db1.open(base + "/node1"));
  const auto epoch_start = consensus::committee_epoch_start(target_height, node::NodeConfig{}.network.committee_epoch_blocks);
  const auto state0 = db0.get_epoch_reward_settlement(epoch_start);
  const auto state1 = db1.get_epoch_reward_settlement(epoch_start);
  ASSERT_TRUE(state0.has_value());
  ASSERT_TRUE(state1.has_value());
  ASSERT_EQ(state0->expected_participation_units, state1->expected_participation_units);
  ASSERT_EQ(state0->observed_participation_units, state1->observed_participation_units);
  ASSERT_EQ(state0->reward_score_units, state1->reward_score_units);

  const auto payout0 =
      consensus::compute_epoch_settlement_payout(state0->total_reward_units, state0->fee_pool_units,
                                                 state0->reserve_subsidy_units, proposal->transition.leader_pubkey,
                                                 state0->reward_score_units, {});
  const auto payout1 =
      consensus::compute_epoch_settlement_payout(state1->total_reward_units, state1->fee_pool_units,
                                                 state1->reserve_subsidy_units, proposal->transition.leader_pubkey,
                                                 state1->reward_score_units, {});
  ASSERT_EQ(payout0.total, payout1.total);
  ASSERT_EQ(payout0.outputs, payout1.outputs);
}

TEST(test_reject_cross_network_version_handshake) {
  const std::string base = unique_test_base("/tmp/finalis_it_reject_cross_network");
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);

  node::NodeConfig cfg;
  cfg.allow_unencrypted_keystore = true;  // test fixture: no passphrase
        cfg.node_id = 0;
  cfg.db_path = base + "/node0";
  cfg.genesis_path = cfg.db_path + "/genesis.json";
  cfg.allow_unsafe_genesis_override = true;
  ASSERT_TRUE(write_mainnet_genesis_file(cfg.genesis_path, 1));
  cfg.p2p_port = 0;
  cfg.network.default_seeds.clear();  // keep test nodes off the public mainnet seeds
  node::Node n(cfg);
  ASSERT_TRUE(n.init() && "n.init() failed");
  n.start();
  const std::uint16_t port = n.p2p_port_for_test();
  if (port == 0) {
    n.stop();
    ASSERT_TRUE(false && "p2p_port_for_test() returned 0");
  }

  p2p::VersionMsg v;
  v.proto_version = static_cast<std::uint32_t>(cfg.network.protocol_version);
  v.network_id = cfg.network.network_id;
  v.network_id[0] ^= 0x5A;  // mismatch
  v.feature_flags = cfg.network.feature_flags;
  v.timestamp = static_cast<std::uint64_t>(::time(nullptr));
  v.nonce = 123;
  v.node_software_version = "handshake-test/0.7;crh=" + n.consensus_rules_fingerprint_for_test();
  ASSERT_TRUE(send_version_and_expect_disconnect("127.0.0.1", port, v, cfg.network, std::chrono::milliseconds(300)));
  ASSERT_TRUE(wait_for([&]() { return n.status().rejected_network_id >= 1; }, std::chrono::seconds(2)));
  n.stop();
}

TEST(test_epoch_settlement_pays_onboarding_slice_to_onboarding_pubkey_from_finalized_ticket) {
  const auto base = unique_test_base("/tmp/finalis_it_onboarding_settlement_slice");
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);

  const auto keys = node::Node::deterministic_test_keypairs();
  const auto leader = keys[0].public_key;
  const auto validator_pub = keys[1].public_key;
  const auto onboarding_pub = keys[2].public_key;
  const std::uint64_t epoch_start = 32;
  const std::uint64_t settlement_reward_units = 10'000;
  const std::uint64_t expected_onboarding_units = consensus::onboarding_reward_units(settlement_reward_units);

  storage::DB db;
  ASSERT_TRUE(db.open(base));

  consensus::ValidatorInfo validator_info;
  validator_info.status = consensus::ValidatorStatus::ACTIVE;
  validator_info.has_bond = true;
  validator_info.bonded_amount = BOND_AMOUNT;
  ASSERT_TRUE(db.put_validator(validator_pub, validator_info));

  consensus::ValidatorInfo onboarding_info;
  onboarding_info.status = consensus::ValidatorStatus::ONBOARDING;
  onboarding_info.has_bond = false;
  onboarding_info.bonded_amount = 0;
  ASSERT_TRUE(db.put_validator(onboarding_pub, onboarding_info));

  consensus::EpochTicket ticket;
  ticket.epoch = epoch_start;
  ticket.participant_pubkey = onboarding_pub;
  ticket.challenge_anchor = Hash32{0x42};
  ticket.nonce = 1;
  ticket.work_hash = consensus::make_epoch_ticket_work_hash(ticket.epoch, ticket.challenge_anchor, ticket.participant_pubkey,
                                                            ticket.nonce);
  ticket.source_height = epoch_start;
  ticket.origin = consensus::EpochTicketOrigin::NETWORK;
  ASSERT_TRUE(db.put_epoch_ticket(ticket));

  const auto best_tickets = consensus::best_epoch_tickets_by_pubkey(db.load_epoch_tickets(epoch_start));
  auto best_it = best_tickets.find(onboarding_pub);
  ASSERT_TRUE(best_it != best_tickets.end());

  storage::EpochRewardSettlementState state;
  state.epoch_start_height = epoch_start;
  state.total_reward_units = settlement_reward_units;
  state.reward_score_units[validator_pub] = 100;
  state.onboarding_score_units[onboarding_pub] =
      static_cast<std::uint64_t>(std::max<std::uint8_t>(1, consensus::leading_zero_bits(best_it->second.work_hash)));
  ASSERT_TRUE(db.put_epoch_reward_settlement(state));

  const auto payout = consensus::compute_epoch_settlement_payout(state.total_reward_units, 0, 0, leader,
                                                                 state.reward_score_units, state.onboarding_score_units);
  ASSERT_EQ(payout.total, settlement_reward_units);

  std::uint64_t validator_units = 0;
  std::uint64_t onboarding_units = 0;
  for (const auto& [pub, units] : payout.outputs) {
    if (pub == validator_pub) validator_units += units;
    if (pub == onboarding_pub) onboarding_units += units;
  }
  ASSERT_EQ(onboarding_units, expected_onboarding_units);
  ASSERT_EQ(validator_units + onboarding_units, settlement_reward_units);
  ASSERT_EQ(validator_units, settlement_reward_units - expected_onboarding_units);
}

TEST(test_epoch_settlement_pays_onboarding_slice_to_unknown_participant_from_finalized_ticket) {
  const auto base = unique_test_base("/tmp/finalis_it_unknown_onboarding_settlement_slice");
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);

  const auto keys = node::Node::deterministic_test_keypairs();
  const auto leader = keys[0].public_key;
  const auto validator_pub = keys[1].public_key;
  const auto unknown_pub = keys[2].public_key;
  const std::uint64_t epoch_start = 32;
  const std::uint64_t settlement_reward_units = 10'000;
  const std::uint64_t expected_onboarding_units = consensus::onboarding_reward_units(settlement_reward_units);

  storage::DB db;
  ASSERT_TRUE(db.open(base));

  consensus::ValidatorInfo validator_info;
  validator_info.status = consensus::ValidatorStatus::ACTIVE;
  validator_info.has_bond = true;
  validator_info.bonded_amount = BOND_AMOUNT;
  ASSERT_TRUE(db.put_validator(validator_pub, validator_info));

  consensus::EpochTicket ticket;
  ticket.epoch = epoch_start;
  ticket.participant_pubkey = unknown_pub;
  ticket.challenge_anchor = Hash32{0x42};
  ticket.nonce = 1;
  ticket.work_hash = consensus::make_epoch_ticket_work_hash(ticket.epoch, ticket.challenge_anchor, ticket.participant_pubkey,
                                                            ticket.nonce);
  ticket.source_height = epoch_start;
  ticket.origin = consensus::EpochTicketOrigin::NETWORK;
  ASSERT_TRUE(db.put_epoch_ticket(ticket));

  const auto best_tickets = consensus::best_epoch_tickets_by_pubkey(db.load_epoch_tickets(epoch_start));
  auto best_it = best_tickets.find(unknown_pub);
  ASSERT_TRUE(best_it != best_tickets.end());

  storage::EpochRewardSettlementState state;
  state.epoch_start_height = epoch_start;
  state.total_reward_units = settlement_reward_units;
  state.reward_score_units[validator_pub] = 100;
  state.onboarding_score_units[unknown_pub] =
      static_cast<std::uint64_t>(std::max<std::uint8_t>(1, consensus::leading_zero_bits(best_it->second.work_hash)));
  ASSERT_TRUE(db.put_epoch_reward_settlement(state));

  const auto payout = consensus::compute_epoch_settlement_payout(state.total_reward_units, 0, 0, leader,
                                                                 state.reward_score_units, state.onboarding_score_units);
  ASSERT_EQ(payout.total, settlement_reward_units);

  std::uint64_t validator_units = 0;
  std::uint64_t unknown_units = 0;
  for (const auto& [pub, units] : payout.outputs) {
    if (pub == validator_pub) validator_units += units;
    if (pub == unknown_pub) unknown_units += units;
  }
  ASSERT_EQ(unknown_units, expected_onboarding_units);
  ASSERT_EQ(validator_units + unknown_units, settlement_reward_units);
  ASSERT_EQ(validator_units, settlement_reward_units - expected_onboarding_units);
}

TEST(test_skip_exact_self_endpoint_before_dial) {
  const std::string base = unique_test_base("/tmp/finalis_it_skip_exact_self");
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);

  const std::uint16_t port = reserve_test_port();
  ASSERT_TRUE(port != 0);

  node::NodeConfig cfg;
  cfg.allow_unencrypted_keystore = true;  // test fixture: no passphrase
  cfg.node_id = 0;
  cfg.db_path = base + "/node0";
  cfg.genesis_path = cfg.db_path + "/genesis.json";
  cfg.allow_unsafe_genesis_override = true;
  ASSERT_TRUE(write_mainnet_genesis_file(cfg.genesis_path, 1));
  cfg.bind_ip = "127.0.0.1";
  cfg.p2p_port = port;
  cfg.dns_seeds = false;
  cfg.network.default_seeds.clear();  // keep test nodes off the public mainnet seeds
  cfg.outbound_target = 1;
  cfg.peers.push_back("127.0.0.1:" + std::to_string(port));

  node::Node n(cfg);
  ASSERT_TRUE(n.init() && "n.init() failed");
  ASSERT_TRUE(n.endpoint_is_obvious_self_for_test("127.0.0.1", port));
  n.start();

  ASSERT_TRUE(wait_for([&]() { return n.self_endpoint_suppressed_for_test("127.0.0.1", port); },
                       std::chrono::seconds(2)));
  std::this_thread::sleep_for(std::chrono::milliseconds(500));
  ASSERT_EQ(n.status().peers, 0u);
  n.stop();
}

TEST(test_skip_resolved_localhost_self_endpoint_before_dial) {
  const std::string base = unique_test_base("/tmp/finalis_it_skip_localhost_self");
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);

  const std::uint16_t port = reserve_test_port();
  ASSERT_TRUE(port != 0);

  node::NodeConfig cfg;
  cfg.allow_unencrypted_keystore = true;  // test fixture: no passphrase
  cfg.node_id = 0;
  cfg.db_path = base + "/node0";
  cfg.genesis_path = cfg.db_path + "/genesis.json";
  cfg.allow_unsafe_genesis_override = true;
  ASSERT_TRUE(write_mainnet_genesis_file(cfg.genesis_path, 1));
  cfg.bind_ip = "127.0.0.1";
  cfg.p2p_port = port;
  cfg.dns_seeds = false;
  cfg.network.default_seeds.clear();  // keep test nodes off the public mainnet seeds
  cfg.outbound_target = 1;
  cfg.peers.push_back("localhost:" + std::to_string(port));

  node::Node n(cfg);
  ASSERT_TRUE(n.init() && "n.init() failed");
  ASSERT_TRUE(n.endpoint_is_obvious_self_for_test("localhost", port));
  n.start();

  ASSERT_TRUE(wait_for([&]() { return n.self_endpoint_suppressed_for_test("localhost", port); },
                       std::chrono::seconds(2)));
  std::this_thread::sleep_for(std::chrono::milliseconds(500));
  ASSERT_EQ(n.status().peers, 0u);
  n.stop();
}

TEST(test_reject_self_identity_in_version_handshake) {
  const std::string base = unique_test_base("/tmp/finalis_it_reject_self_identity");
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);

  node::NodeConfig cfg;
  cfg.allow_unencrypted_keystore = true;  // test fixture: no passphrase
  cfg.node_id = 0;
  cfg.db_path = base + "/node0";
  cfg.genesis_path = cfg.db_path + "/genesis.json";
  cfg.allow_unsafe_genesis_override = true;
  ASSERT_TRUE(write_mainnet_genesis_file(cfg.genesis_path, 1));
  cfg.bind_ip = "127.0.0.1";
  cfg.p2p_port = 0;
  cfg.dns_seeds = false;
  cfg.network.default_seeds.clear();  // keep test nodes off the public mainnet seeds

  node::Node n(cfg);
  ASSERT_TRUE(n.init() && "n.init() failed");
  n.start();
  const std::uint16_t port = n.p2p_port_for_test();
  if (port == 0) {
    n.stop();
    ASSERT_TRUE(false && "n.p2p_port_for_test() returned 0");
  }

  p2p::VersionMsg v;
  v.proto_version = static_cast<std::uint32_t>(cfg.network.protocol_version);
  v.network_id = cfg.network.network_id;
  v.feature_flags = cfg.network.feature_flags;
  v.timestamp = static_cast<std::uint64_t>(::time(nullptr));
  v.nonce = 777;
  const auto local_pub = n.local_validator_pubkey_for_test();
  v.node_software_version =
      "handshake-test/0.7;validator_pubkey=" +
      hex_encode(Bytes(local_pub.begin(), local_pub.end())) + ";crh=" + n.consensus_rules_fingerprint_for_test();

  ASSERT_TRUE(send_version_and_expect_disconnect("127.0.0.1", port, v, cfg.network, std::chrono::milliseconds(300)));
  ASSERT_TRUE(wait_for([&]() { return n.self_endpoint_suppressed_for_test("127.0.0.1", port); },
                       std::chrono::seconds(2)));
  n.stop();
}

TEST(test_self_endpoint_retry_suppression_persists_for_process_lifetime) {
  const std::string base = unique_test_base("/tmp/finalis_it_self_retry_suppression");
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);

  const std::uint16_t port = reserve_test_port();
  ASSERT_TRUE(port != 0);

  node::NodeConfig cfg;
  cfg.allow_unencrypted_keystore = true;  // test fixture: no passphrase
  cfg.node_id = 0;
  cfg.db_path = base + "/node0";
  cfg.genesis_path = cfg.db_path + "/genesis.json";
  cfg.allow_unsafe_genesis_override = true;
  ASSERT_TRUE(write_mainnet_genesis_file(cfg.genesis_path, 1));
  cfg.bind_ip = "127.0.0.1";
  cfg.p2p_port = port;
  cfg.dns_seeds = false;
  cfg.network.default_seeds.clear();  // keep test nodes off the public mainnet seeds
  cfg.outbound_target = 1;
  cfg.peers.push_back("127.0.0.1:" + std::to_string(port));

  node::Node n(cfg);
  ASSERT_TRUE(n.init() && "n.init() failed");
  n.start();

  ASSERT_TRUE(wait_for([&]() { return n.self_endpoint_suppressed_for_test("127.0.0.1", port); },
                       std::chrono::seconds(2)));
  const auto initial = n.status().peers;
  std::this_thread::sleep_for(std::chrono::milliseconds(1500));
  ASSERT_EQ(initial, 0u);
  ASSERT_EQ(n.status().peers, 0u);
  ASSERT_TRUE(n.self_endpoint_suppressed_for_test("127.0.0.1", port));
  n.stop();
}

TEST(test_reject_magic_mismatch_frame_before_handshake) {
  const std::string base = unique_test_base("/tmp/finalis_it_reject_magic_mismatch");
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);

  node::NodeConfig cfg;
  cfg.allow_unencrypted_keystore = true;  // test fixture: no passphrase
        cfg.node_id = 0;
  cfg.db_path = base + "/node0";
  cfg.genesis_path = cfg.db_path + "/genesis.json";
  cfg.allow_unsafe_genesis_override = true;
  ASSERT_TRUE(write_mainnet_genesis_file(cfg.genesis_path, 1));
  cfg.p2p_port = 0;
  cfg.network.default_seeds.clear();  // keep test nodes off the public mainnet seeds
  node::Node n(cfg);
  ASSERT_TRUE(n.init() && "n.init() failed");
  n.start();
  const std::uint16_t port = n.p2p_port_for_test();
  if (port == 0) {
    n.stop();
    ASSERT_TRUE(false && "p2p_port_for_test() returned 0");
  }

  p2p::VersionMsg v;
  v.proto_version = static_cast<std::uint32_t>(cfg.network.protocol_version);
  v.network_id = cfg.network.network_id;
  v.feature_flags = cfg.network.feature_flags;
  v.timestamp = static_cast<std::uint64_t>(::time(nullptr));
  v.nonce = 444;
  v.node_software_version = "magic-mismatch-test/0.7;crh=" + n.consensus_rules_fingerprint_for_test();
  NetworkConfig mismatch_net = cfg.network;
  mismatch_net.magic ^= 0x01020304u;
  ASSERT_TRUE(send_version_and_expect_disconnect("127.0.0.1", port, v, mismatch_net, std::chrono::milliseconds(300)));
  n.stop();
}

TEST(test_reject_unsupported_protocol_version_handshake) {
  const std::string base = unique_test_base("/tmp/finalis_it_reject_proto");
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);

  node::NodeConfig cfg;
  cfg.allow_unencrypted_keystore = true;  // test fixture: no passphrase
        cfg.node_id = 0;
  cfg.db_path = base + "/node0";
  cfg.genesis_path = cfg.db_path + "/genesis.json";
  cfg.allow_unsafe_genesis_override = true;
  ASSERT_TRUE(write_mainnet_genesis_file(cfg.genesis_path, 1));
  cfg.p2p_port = 0;
  cfg.network.default_seeds.clear();  // keep test nodes off the public mainnet seeds
  node::Node n(cfg);
  ASSERT_TRUE(n.init() && "n.init() failed");
  n.start();
  const std::uint16_t port = n.p2p_port_for_test();
  if (port == 0) {
    n.stop();
    ASSERT_TRUE(false && "p2p_port_for_test() returned 0");
  }

  p2p::VersionMsg v;
  v.proto_version = static_cast<std::uint32_t>(cfg.network.protocol_version + 1);  // unsupported
  v.network_id = cfg.network.network_id;
  v.feature_flags = cfg.network.feature_flags;
  v.timestamp = static_cast<std::uint64_t>(::time(nullptr));
  v.nonce = 321;
  v.node_software_version = "handshake-test/0.7;crh=" + n.consensus_rules_fingerprint_for_test();
  ASSERT_TRUE(send_version_and_expect_disconnect("127.0.0.1", port, v, cfg.network, std::chrono::milliseconds(300)));
  ASSERT_TRUE(wait_for([&]() { return n.status().rejected_protocol_version >= 1; }, ci_timeout_seconds(2)));
  n.stop();
}

TEST(test_normal_peer_connection_unaffected_by_self_peer_filtering) {
  const std::string base = unique_test_base("/tmp/finalis_it_normal_peer_unaffected");
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);

  const std::uint16_t port0 = reserve_test_port();
  const std::uint16_t port1 = reserve_test_port();
  ASSERT_TRUE(port0 != 0);
  ASSERT_TRUE(port1 != 0);

  node::NodeConfig cfg0;
  cfg0.allow_unencrypted_keystore = true;  // test fixture: no passphrase
  cfg0.node_id = 0;
  cfg0.db_path = base + "/node0";
  cfg0.genesis_path = cfg0.db_path + "/genesis.json";
  cfg0.allow_unsafe_genesis_override = true;
  ASSERT_TRUE(write_mainnet_genesis_file(cfg0.genesis_path, 1));
  cfg0.bind_ip = "127.0.0.1";
  cfg0.p2p_port = port0;
  cfg0.dns_seeds = false;
  cfg0.network.default_seeds.clear();  // keep test nodes off the public mainnet seeds

  node::NodeConfig cfg1;
  cfg1.allow_unencrypted_keystore = true;  // test fixture: no passphrase
  cfg1.node_id = 1;
  cfg1.db_path = base + "/node1";
  cfg1.genesis_path = cfg1.db_path + "/genesis.json";
  cfg1.allow_unsafe_genesis_override = true;
  ASSERT_TRUE(write_mainnet_genesis_file(cfg1.genesis_path, 1));
  cfg1.bind_ip = "127.0.0.1";
  cfg1.p2p_port = port1;
  cfg1.dns_seeds = false;
  cfg1.network.default_seeds.clear();  // keep test nodes off the public mainnet seeds
  cfg1.outbound_target = 1;
  cfg1.peers.push_back("127.0.0.1:" + std::to_string(port0));

  node::Node n0(cfg0);
  node::Node n1(cfg1);
  ASSERT_TRUE(n0.init() && "n0.init() failed");
  ASSERT_TRUE(n1.init() && "n1.init() failed");
  n0.start();
  n1.start();

  ASSERT_TRUE(wait_for_peer_count(n0, 1, std::chrono::seconds(3)));
  ASSERT_TRUE(wait_for_peer_count(n1, 1, std::chrono::seconds(3)));
  ASSERT_TRUE(!n1.self_endpoint_suppressed_for_test("127.0.0.1", port0));

  n1.stop();
  n0.stop();
}

TEST(test_mainnet_bootstrap_with_genesis) {
  auto c = make_cluster(unique_test_base("/tmp/finalis_it_mainnet_bootstrap"), 4, 4, 4);

  ASSERT_TRUE(wait_for([&]() {
    for (const auto& n : c.nodes) {
      if (n->status().height < 5) return false;
    }
    return true;
  }, std::chrono::seconds(45)));

  ASSERT_TRUE(wait_for_same_tip(c.nodes, std::chrono::seconds(10)));
}

TEST(test_single_node_custom_genesis_bootstraps_and_finalizes) {
  const std::string base = unique_test_base("/tmp/finalis_it_single_node_bootstrap");
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);
  const std::string gpath = base + "/genesis.json";
  ASSERT_TRUE(write_empty_mainnet_bootstrap_genesis_file(gpath));

  node::NodeConfig cfg;
  cfg.allow_unencrypted_keystore = true;  // test fixture: no passphrase
  cfg.node_id = 0;
  cfg.disable_p2p = true;
  cfg.dns_seeds = false;
  cfg.network.default_seeds.clear();  // keep test nodes off the public mainnet seeds
  cfg.listen = false;
  cfg.db_path = base + "/node0";
  cfg.p2p_port = 0;
  cfg.outbound_target = 0;
  cfg.genesis_path = gpath;
  cfg.allow_unsafe_genesis_override = true;
  cfg.network.min_block_interval_ms = 100;
  cfg.network.round_timeout_ms = 200;

  node::Node n(cfg);
  ASSERT_TRUE(n.init());
  n.start();

  ASSERT_TRUE(wait_for_tip(n, 1, std::chrono::seconds(20)));

  const std::string key_path = keystore::default_validator_keystore_path(cfg.db_path);
  keystore::ValidatorKey vk;
  std::string err;
  ASSERT_TRUE(keystore::load_validator_keystore(key_path, "", &vk, &err));

  const auto active = n.active_validators_for_next_height_for_test();
  ASSERT_EQ(active.size(), 1u);
  ASSERT_EQ(active[0], vk.pubkey);

  n.stop();
}

TEST(test_unseeded_bootstrap_template_ignores_default_network_seeds) {
  const std::string base = unique_test_base("/tmp/finalis_it_bootstrap_ignores_default_seeds");
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);
  const std::string gpath = base + "/genesis.json";
  ASSERT_TRUE(write_empty_mainnet_bootstrap_genesis_file(gpath));

  node::NodeConfig cfg;
  cfg.allow_unencrypted_keystore = true;  // test fixture: no passphrase
  cfg.node_id = 0;
  cfg.dns_seeds = false;
  cfg.listen = false;
  cfg.db_path = base + "/node0";
  cfg.p2p_port = 0;
  cfg.outbound_target = 0;
  cfg.genesis_path = gpath;
  cfg.allow_unsafe_genesis_override = true;
  cfg.network.min_block_interval_ms = 100;
  cfg.network.round_timeout_ms = 200;
  // Compiled-in default seeds alone must not stop a bootstrap node (unroutable test address).
  cfg.network.default_seeds = {"192.0.2.1:19440"};

  node::Node n(cfg);
  ASSERT_TRUE(n.init());
  n.start();

  ASSERT_TRUE(wait_for_tip(n, 1, std::chrono::seconds(20)));
  ASSERT_TRUE(wait_for([&]() {
    const auto s = n.status();
    return s.height >= 1 && s.consensus_state != "SYNCING" && s.consensus_state != "REPAIRING";
  }, std::chrono::seconds(5)));
  const auto s = n.status();
  ASSERT_TRUE(s.bootstrap_template_mode);
  ASSERT_TRUE(!s.bootstrap_validator_pubkey.empty());
  ASSERT_TRUE(s.consensus_state != "SYNCING");
  ASSERT_TRUE(s.consensus_state != "REPAIRING");

  n.stop();
}

TEST(test_seeded_bootstrap_template_node_does_not_self_bootstrap) {
  const std::string base = unique_test_base("/tmp/finalis_it_seeded_bootstrap_waits");
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);
  const std::string gpath = base + "/genesis.json";
  ASSERT_TRUE(write_empty_mainnet_bootstrap_genesis_file(gpath));

  node::NodeConfig cfg;
  cfg.allow_unencrypted_keystore = true;  // test fixture: no passphrase
  cfg.node_id = 0;
  cfg.dns_seeds = false;
  cfg.network.default_seeds.clear();  // keep test nodes off the public mainnet seeds
  cfg.listen = false;
  cfg.db_path = base + "/node0";
  cfg.p2p_port = 0;
  cfg.genesis_path = gpath;
  cfg.allow_unsafe_genesis_override = true;
  cfg.peers = {"127.0.0.1:1"};
  cfg.network.min_block_interval_ms = 100;
  cfg.network.round_timeout_ms = 200;

  node::Node n(cfg);
  ASSERT_TRUE(n.init());
  n.start();

  std::this_thread::sleep_for(std::chrono::seconds(8));
  const auto s = n.status();
  ASSERT_EQ(s.height, 0u);
  ASSERT_TRUE(s.bootstrap_template_mode);
  ASSERT_TRUE(s.bootstrap_validator_pubkey.empty());
  ASSERT_EQ(n.active_validators_for_next_height_for_test().size(), 0u);

  n.stop();
}

TEST(test_seeded_bootstrap_template_retries_with_inbound_noise_present) {
  const std::string base = unique_test_base("/tmp/finalis_it_seeded_retry_ignores_inbound_noise");
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);
  const std::string gpath = base + "/genesis.json";
  ASSERT_TRUE(write_empty_mainnet_bootstrap_genesis_file(gpath));

  node::NodeConfig bootstrap_cfg;
  bootstrap_cfg.allow_unencrypted_keystore = true;  // test fixture: no passphrase
  bootstrap_cfg.node_id = 0;
  bootstrap_cfg.dns_seeds = false;
  bootstrap_cfg.network.default_seeds.clear();  // keep test nodes off the public mainnet seeds
  bootstrap_cfg.db_path = base + "/bootstrap";
  bootstrap_cfg.p2p_port = reserve_test_port();
  ASSERT_TRUE(bootstrap_cfg.p2p_port != 0 && "Failed to reserve test port for bootstrap");
  bootstrap_cfg.genesis_path = gpath;
  bootstrap_cfg.allow_unsafe_genesis_override = true;
  bootstrap_cfg.network.min_block_interval_ms = 100;
  bootstrap_cfg.network.round_timeout_ms = 200;

  node::Node bootstrap(bootstrap_cfg);
  ASSERT_TRUE(bootstrap.init() && "bootstrap.init() failed");
  bootstrap.start();
  ASSERT_TRUE(wait_for_tip(bootstrap, 1, ci_timeout_seconds(12)));

  node::NodeConfig follower_cfg;
  follower_cfg.allow_unencrypted_keystore = true;  // test fixture: no passphrase
  follower_cfg.node_id = 1;
  follower_cfg.dns_seeds = false;
  follower_cfg.network.default_seeds.clear();  // keep test nodes off the public mainnet seeds
  follower_cfg.db_path = base + "/follower";
  follower_cfg.p2p_port = reserve_test_port();
  if (follower_cfg.p2p_port == 0) {
    bootstrap.stop();
    ASSERT_TRUE(false && "Failed to reserve test port for follower");
  }
  follower_cfg.genesis_path = gpath;
  follower_cfg.allow_unsafe_genesis_override = true;
  follower_cfg.seeds = {"127.0.0.1:" + std::to_string(bootstrap_cfg.p2p_port)};
  follower_cfg.outbound_target = 1;
  follower_cfg.network.min_block_interval_ms = 100;
  follower_cfg.network.round_timeout_ms = 200;

  node::Node follower(follower_cfg);
  if (!follower.init()) {
    bootstrap.stop();
    return;
  }
  follower.start();

  // Occupy the follower's inbound table with junk connections; outbound bootstrap
  // retry must still continue because it is based on outbound, not total peers.
  std::vector<finalis::net::SocketHandle> junk_fds;
  for (int i = 0; i < 3; ++i) {
    auto fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (!finalis::net::valid_socket(fd)) continue;
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(follower_cfg.p2p_port);
    ASSERT_EQ(::inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr), 1);
    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0) junk_fds.push_back(fd);
    else finalis::net::close_socket(fd);
  }

  ASSERT_TRUE(wait_for([&]() {
    const auto s = follower.status();
    return s.height >= 1 && s.established_peers >= 1;
  }, ci_timeout_seconds(20)));

  for (auto fd : junk_fds) {
    finalis::net::shutdown_socket(fd);
    finalis::net::close_socket(fd);
  }
  follower.stop();
  bootstrap.stop();
}

TEST(test_follower_connected_before_bootstrap_self_binding_adopts_and_catches_up) {
  const std::string base = unique_test_base("/tmp/finalis_it_early_follower_bootstrap");
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);
  const std::string gpath = base + "/genesis.json";
  ASSERT_TRUE(write_empty_mainnet_bootstrap_genesis_file(gpath));

  node::NodeConfig bootstrap_cfg;
  bootstrap_cfg.allow_unencrypted_keystore = true;  // test fixture: no passphrase
  bootstrap_cfg.node_id = 0;
  bootstrap_cfg.dns_seeds = false;
  bootstrap_cfg.network.default_seeds.clear();  // keep test nodes off the public mainnet seeds
  bootstrap_cfg.db_path = base + "/bootstrap";
  bootstrap_cfg.p2p_port = reserve_test_port();
  ASSERT_TRUE(bootstrap_cfg.p2p_port != 0 && "Failed to reserve test port for bootstrap");
  bootstrap_cfg.genesis_path = gpath;
  bootstrap_cfg.allow_unsafe_genesis_override = true;
  bootstrap_cfg.network.min_block_interval_ms = 100;
  bootstrap_cfg.network.round_timeout_ms = 200;
  bootstrap_cfg.network.min_block_interval_ms = 100;
  bootstrap_cfg.network.round_timeout_ms = 200;
  bootstrap_cfg.outbound_target = 0;

  node::Node bootstrap(bootstrap_cfg);
  ASSERT_TRUE(bootstrap.init() && "bootstrap.init() failed");
  bootstrap.start();
  bootstrap.pause_proposals_for_test(true);
  const auto port0 = bootstrap.p2p_port_for_test();
  if (port0 == 0) {
    bootstrap.stop();
    ASSERT_TRUE(false && "bootstrap.p2p_port_for_test() returned 0");
  }

  node::NodeConfig follower_cfg;
  follower_cfg.allow_unencrypted_keystore = true;  // test fixture: no passphrase
  follower_cfg.node_id = 1;
  follower_cfg.dns_seeds = false;
  follower_cfg.network.default_seeds.clear();  // keep test nodes off the public mainnet seeds
  follower_cfg.db_path = base + "/follower";
  follower_cfg.p2p_port = reserve_test_port();
  if (follower_cfg.p2p_port == 0) {
    bootstrap.stop();
    ASSERT_TRUE(false && "p2p_port_for_test() returned 0");
  }
  follower_cfg.genesis_path = gpath;
  follower_cfg.allow_unsafe_genesis_override = true;
  follower_cfg.network.min_block_interval_ms = 100;
  follower_cfg.network.round_timeout_ms = 200;
  follower_cfg.peers = {"127.0.0.1:" + std::to_string(port0)};
  follower_cfg.outbound_target = 1;

  node::Node follower(follower_cfg);
  if (!follower.init()) {
    bootstrap.stop();
    return;
  }
  follower.start();

  ASSERT_TRUE(wait_for([&]() {
    const auto s0 = bootstrap.status();
    const auto s1 = follower.status();
    return s0.established_peers >= 1 && s1.established_peers >= 1;
  }, std::chrono::seconds(8)));

  ASSERT_TRUE(wait_for([&]() {
    const auto s0 = bootstrap.status();
    const auto s1 = follower.status();
    return s0.height == 0 && !s0.bootstrap_validator_pubkey.empty() &&
           s1.height == 0 && s1.bootstrap_validator_pubkey == s0.bootstrap_validator_pubkey;
  }, std::chrono::seconds(10)));

  const auto active1 = follower.active_validators_for_next_height_for_test();
  ASSERT_EQ(active1.size(), 1u);

  bootstrap.pause_proposals_for_test(false);
  const bool caught_up = wait_for([&]() {
    const auto s0 = bootstrap.status();
    const auto s1 = follower.status();
    return s0.height >= 1 && s1.height >= 1 && s0.height == s1.height && s0.transition_hash == s1.transition_hash;
  }, std::chrono::seconds(40));
  if (!caught_up) {
    const auto s0 = bootstrap.status();
    const auto s1 = follower.status();
    const auto short_pub = [](const PubKey32& pub) {
      return hex_encode(Bytes(pub.begin(), pub.end())).substr(0, 8);
    };
    std::ostringstream oss;
    oss << "bootstrap/follower catch-up stalled:"
        << " bootstrap{h=" << s0.height << ",r=" << s0.round << ",peers=" << s0.peers << ",est=" << s0.established_peers
        << ",out=" << s0.outbound_connected << ",in=" << s0.inbound_connected << ",state=" << s0.consensus_state
        << ",votes=" << s0.votes_for_current << ",leader=" << short_pub(s0.leader)
        << ",bootstrap=" << s0.bootstrap_validator_pubkey << "}"
        << " follower{h=" << s1.height << ",r=" << s1.round << ",peers=" << s1.peers << ",est=" << s1.established_peers
        << ",out=" << s1.outbound_connected << ",in=" << s1.inbound_connected << ",state=" << s1.consensus_state
        << ",votes=" << s1.votes_for_current << ",leader=" << short_pub(s1.leader)
        << ",bootstrap=" << s1.bootstrap_validator_pubkey << "}";
    const auto next_height = s0.height + 1;
    const auto leader = bootstrap.proposer_for_height_round_for_test(next_height, s0.round);
    oss << " probe={next_height=" << next_height << ",round=" << s0.round
        << ",bootstrap_canonical=" << bootstrap.canonical_state_height_for_test()
        << ",follower_canonical=" << follower.canonical_state_height_for_test()
        << ",bootstrap_local=" << short_pub(bootstrap.local_validator_pubkey_for_test())
        << ",follower_local=" << short_pub(follower.local_validator_pubkey_for_test())
        << ",leader=" << (leader.has_value() ? short_pub(*leader) : std::string("none"));
    if (leader.has_value()) {
      node::Node* leader_node = nullptr;
      std::string leader_name = "unknown";
      if (*leader == bootstrap.local_validator_pubkey_for_test()) {
        leader_node = &bootstrap;
        leader_name = "bootstrap";
      } else if (*leader == follower.local_validator_pubkey_for_test()) {
        leader_node = &follower;
        leader_name = "follower";
      }
      oss << ",leader_node=" << leader_name;
      if (leader_node != nullptr) {
        auto proposal = leader_node->build_frontier_proposal_for_test(next_height, s0.round);
        oss << ",proposal=" << (proposal.has_value() ? "yes" : "no")
            << ",build_error=" << leader_node->last_test_hook_error_for_test();
        if (proposal.has_value()) {
          auto msg = make_test_frontier_propose_msg(bootstrap.consensus_domain_for_test(), *proposal);
          oss << ",inject=[" << bootstrap.inject_network_propose_result_for_test(msg) << ","
              << follower.inject_network_propose_result_for_test(msg) << "]";
        }
      }
    }
    oss << "}";
    throw std::runtime_error(oss.str());
  }

  follower.stop();
  bootstrap.stop();
}

TEST(test_adopted_bootstrap_identity_persists_across_restart_before_first_block) {
  const std::string base = unique_test_base("/tmp/finalis_it_bootstrap_identity_restart");
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);
  const std::string gpath = base + "/genesis.json";
  ASSERT_TRUE(write_empty_mainnet_bootstrap_genesis_file(gpath));

  node::NodeConfig bootstrap_cfg;
  bootstrap_cfg.allow_unencrypted_keystore = true;  // test fixture: no passphrase
  bootstrap_cfg.node_id = 0;
  bootstrap_cfg.dns_seeds = false;
  bootstrap_cfg.network.default_seeds.clear();  // keep test nodes off the public mainnet seeds
  bootstrap_cfg.db_path = base + "/bootstrap";
  bootstrap_cfg.p2p_port = reserve_test_port();
  ASSERT_TRUE(bootstrap_cfg.p2p_port != 0 && "Failed to reserve test port for bootstrap");
  bootstrap_cfg.genesis_path = gpath;
  bootstrap_cfg.allow_unsafe_genesis_override = true;

  node::Node bootstrap(bootstrap_cfg);
  ASSERT_TRUE(bootstrap.init() && "bootstrap.init() failed");
  bootstrap.start();
  bootstrap.pause_proposals_for_test(true);
  const auto port0 = bootstrap.p2p_port_for_test();
  if (port0 == 0) {
    bootstrap.stop();
    ASSERT_TRUE(false && "p2p_port_for_test() returned 0");
  }

  node::NodeConfig follower_cfg;
  follower_cfg.allow_unencrypted_keystore = true;  // test fixture: no passphrase
  follower_cfg.node_id = 1;
  follower_cfg.dns_seeds = false;
  follower_cfg.network.default_seeds.clear();  // keep test nodes off the public mainnet seeds
  follower_cfg.db_path = base + "/follower";
  follower_cfg.p2p_port = reserve_test_port();
  if (follower_cfg.p2p_port == 0) {
    bootstrap.stop();
    return;
  }
  follower_cfg.genesis_path = gpath;
  follower_cfg.allow_unsafe_genesis_override = true;
  follower_cfg.peers = {"127.0.0.1:" + std::to_string(port0)};
  follower_cfg.network.min_block_interval_ms = 100;
  follower_cfg.network.round_timeout_ms = 200;

  {
    node::Node follower(follower_cfg);
    if (!follower.init()) {
      bootstrap.stop();
      return;
    }
    follower.start();

    ASSERT_TRUE(wait_for([&]() {
      const auto s0 = bootstrap.status();
      const auto s1 = follower.status();
      return s0.established_peers >= 1 && s1.established_peers >= 1;
    }, std::chrono::seconds(8)));

    ASSERT_TRUE(wait_for([&]() {
      const auto s0 = bootstrap.status();
      const auto s1 = follower.status();
      return s0.height == 0 && !s0.bootstrap_validator_pubkey.empty() &&
             s1.height == 0 && s1.bootstrap_validator_pubkey == s0.bootstrap_validator_pubkey;
    }, std::chrono::seconds(10)));
    follower.stop();
  }

  node::Node restarted(follower_cfg);
  ASSERT_TRUE(restarted.init());
  const auto persisted = restarted.status();
  ASSERT_EQ(persisted.height, 0u);
  ASSERT_EQ(persisted.bootstrap_validator_pubkey, bootstrap.status().bootstrap_validator_pubkey);
  ASSERT_EQ(restarted.active_validators_for_next_height_for_test().size(), 1u);
  bootstrap.stop();
}

TEST(test_height_zero_bootstrap_adoption_rejects_non_explicit_fallback_path) {
  const std::string base = unique_test_base("/tmp/finalis_it_height0_fallback_rejected");
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);
  const std::string gpath = base + "/genesis.json";
  ASSERT_TRUE(write_empty_mainnet_bootstrap_genesis_file(gpath));

  node::NodeConfig bootstrap_cfg;
  bootstrap_cfg.allow_unencrypted_keystore = true;  // test fixture: no passphrase
  bootstrap_cfg.node_id = 0;
  bootstrap_cfg.dns_seeds = false;
  bootstrap_cfg.network.default_seeds.clear();  // keep test nodes off the public mainnet seeds
  bootstrap_cfg.db_path = base + "/bootstrap";
  bootstrap_cfg.p2p_port = reserve_test_port();
  ASSERT_TRUE(bootstrap_cfg.p2p_port != 0 && "Failed to reserve test port for bootstrap");
  bootstrap_cfg.genesis_path = gpath;
  bootstrap_cfg.allow_unsafe_genesis_override = true;
  bootstrap_cfg.peers = {"127.0.0.1:1"};
  bootstrap_cfg.network.min_block_interval_ms = 100;
  bootstrap_cfg.network.round_timeout_ms = 200;

  node::Node bootstrap(bootstrap_cfg);
  ASSERT_TRUE(bootstrap.init() && "bootstrap.init() failed");
  bootstrap.start();

  node::NodeConfig follower_cfg;
  follower_cfg.allow_unencrypted_keystore = true;  // test fixture: no passphrase
  follower_cfg.node_id = 1;
  follower_cfg.dns_seeds = false;
  follower_cfg.network.default_seeds.clear();  // keep test nodes off the public mainnet seeds
  follower_cfg.db_path = base + "/follower";
  follower_cfg.p2p_port = reserve_test_port();
  if (follower_cfg.p2p_port == 0) {
    bootstrap.stop();
    return;
  }
  follower_cfg.genesis_path = gpath;
  follower_cfg.allow_unsafe_genesis_override = true;
  follower_cfg.peers = {"127.0.0.1:" + std::to_string(bootstrap_cfg.p2p_port)};
  follower_cfg.network.min_block_interval_ms = 100;
  follower_cfg.network.round_timeout_ms = 200;

  node::Node follower(follower_cfg);
  if (!follower.init()) {
    bootstrap.stop();
    return;
  }
  follower.start();

  ASSERT_TRUE(wait_for([&]() {
    const auto s0 = bootstrap.status();
    const auto s1 = follower.status();
    return s0.established_peers >= 1 && s1.established_peers >= 1;
  }, std::chrono::seconds(8)));
  std::this_thread::sleep_for(std::chrono::seconds(2));

  const auto s = follower.status();
  ASSERT_TRUE(s.bootstrap_template_mode);
  ASSERT_TRUE(s.bootstrap_validator_pubkey.empty());
  ASSERT_EQ(s.height, 0u);
  ASSERT_EQ(follower.active_validators_for_next_height_for_test().size(), 0u);

  follower.stop();
  bootstrap.stop();
}

TEST(test_second_fresh_node_adopts_bootstrap_validator_and_syncs) {
  const std::string base = unique_test_base("/tmp/finalis_it_single_node_sync_join");
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);
  const std::string gpath = base + "/genesis.json";
  ASSERT_TRUE(write_empty_mainnet_bootstrap_genesis_file(gpath));

  node::NodeConfig cfg0;
  cfg0.allow_unencrypted_keystore = true;  // test fixture: no passphrase
  cfg0.node_id = 0;
  cfg0.dns_seeds = false;
  cfg0.network.default_seeds.clear();  // keep test nodes off the public mainnet seeds
  cfg0.db_path = base + "/node0";
  cfg0.p2p_port = reserve_test_port();
  if (cfg0.p2p_port == 0) return;
  cfg0.genesis_path = gpath;
  cfg0.allow_unsafe_genesis_override = true;
  cfg0.network.min_block_interval_ms = 100;
  cfg0.network.round_timeout_ms = 200;

  node::Node n0(cfg0);
  if (!n0.init()) return;
  n0.start();
  const auto port0 = n0.p2p_port_for_test();
  if (port0 == 0) {
    n0.stop();
    ASSERT_TRUE(false && "p2p_port_for_test() returned 0");
  }
  ASSERT_TRUE(wait_for_tip(n0, 5, std::chrono::seconds(20)));
  ASSERT_TRUE(wait_for_tip(n0, 1, std::chrono::seconds(12)));

  node::NodeConfig cfg1;
  cfg1.allow_unencrypted_keystore = true;  // test fixture: no passphrase
  cfg1.node_id = 1;
  cfg1.dns_seeds = false;
  cfg1.network.default_seeds.clear();  // keep test nodes off the public mainnet seeds
  cfg1.db_path = base + "/node1";
  cfg1.p2p_port = reserve_test_port();
  if (cfg1.p2p_port == 0) {
    n0.stop();
    return;
  }
  cfg1.genesis_path = gpath;
  cfg1.allow_unsafe_genesis_override = true;
  cfg1.peers = {"127.0.0.1:" + std::to_string(port0)};
  cfg1.network.min_block_interval_ms = 100;
  cfg1.network.round_timeout_ms = 200;

  node::Node n1(cfg1);
  if (!n1.init()) {
    n0.stop();
    return;
  }
  n1.start();

  ASSERT_TRUE(wait_for([&]() {
    const auto s0 = n0.status();
    const auto s1 = n1.status();
    return s0.height >= 1 && s1.height >= 1 && s0.height == s1.height && s0.transition_hash == s1.transition_hash;
  }, std::chrono::seconds(20)));

  const auto s0 = n0.status();
  const auto s1 = n1.status();
  ASSERT_TRUE(s0.bootstrap_template_mode);
  ASSERT_TRUE(s1.bootstrap_template_mode);
  ASSERT_TRUE(!s0.bootstrap_validator_pubkey.empty());
  ASSERT_EQ(s0.bootstrap_validator_pubkey, s1.bootstrap_validator_pubkey);
  ASSERT_EQ(s1.last_bootstrap_source, "seeds");
  ASSERT_TRUE(s1.established_peers >= 1u);

  const auto active1 = n1.active_validators_for_next_height_for_test();
  ASSERT_EQ(active1.size(), 1u);

  n1.stop();
  n0.stop();
}

TEST(test_explicit_join_request_auto_activates_validator_on_chain) {
  auto fixture = make_joined_validator_fixture(unique_test_base("/tmp/finalis_it_join_request_approval"), 1);
  auto& nodes = fixture.cluster.nodes;
  const auto& new_val = fixture.joiner_kp;

  for (const auto& n : nodes) {
    auto info = n->validator_info_for_test(new_val.public_key);
    ASSERT_TRUE(info.has_value());
    ASSERT_TRUE(info->status == consensus::ValidatorStatus::PENDING ||
                info->status == consensus::ValidatorStatus::ACTIVE);
  }

  for (const auto& n : nodes) {
    auto active = n->active_validators_for_next_height_for_test();
    ASSERT_TRUE(std::find(active.begin(), active.end(), new_val.public_key) != active.end());
  }
}

TEST(test_future_round_proposal_rejected_before_timeout) {
  const auto keys = node::Node::deterministic_test_keypairs();
  ASSERT_TRUE(keys.size() >= 4u);
  auto cluster = make_cluster(unique_test_base("/tmp/finalis_it_future_round_reject"), 4, 4, 4);
  auto& nodes = cluster.nodes;
  Tx tx = make_fixture_ingress_tx(1, 0x81);
  ASSERT_TRUE(restart_cluster_with_seeded_certified_ingress(&cluster, {tx.serialize()}));
  for (auto& n : nodes) n->pause_proposals_for_test(true);

  const auto target_height = nodes[0]->status().height + 1;
  const auto proposer_round1 = nodes[0]->proposer_for_height_round_for_test(target_height, 1);
  ASSERT_TRUE(proposer_round1.has_value());
  const int proposer_id = node_for_pub(keys, *proposer_round1);
  ASSERT_TRUE(proposer_id >= 0);

  auto future = build_cluster_frontier_proposal_from_records(
      cluster, keys, {tx.serialize()}, target_height, 1, "/tmp/finalis_it_future_round_reject_builder");
  ASSERT_TRUE(future.has_value());
  ASSERT_TRUE(!nodes[0]->inject_propose_msg_for_test(make_test_frontier_propose_msg(nodes[0]->consensus_domain_for_test(), *future)));
  ASSERT_EQ(nodes[0]->status().height + 1, target_height);
}

TEST(test_future_round_proposal_does_not_advance_round_without_valid_justification) {
  const auto keys = node::Node::deterministic_test_keypairs();
  ASSERT_TRUE(keys.size() >= 4u);
  auto cluster = make_cluster(unique_test_base("/tmp/finalis_it_future_round_no_advance"), 4, 4, 4);
  auto& nodes = cluster.nodes;
  Tx tx = make_fixture_ingress_tx(1, 0x82);
  ASSERT_TRUE(restart_cluster_with_seeded_certified_ingress(&cluster, {tx.serialize()}));
  for (auto& n : nodes) n->pause_proposals_for_test(true);

  const auto before = nodes[0]->status();
  const std::uint64_t target_height = before.height + 1;
  const std::uint32_t future_round = before.round + 1;
  const auto proposer = nodes[0]->proposer_for_height_round_for_test(target_height, future_round);
  ASSERT_TRUE(proposer.has_value());
  const int proposer_id = node_for_pub(keys, *proposer);
  ASSERT_TRUE(proposer_id >= 0);

  auto future = build_cluster_frontier_proposal_from_records(
      cluster, keys, {tx.serialize()}, target_height, future_round, unique_test_base("/tmp/finalis_it_future_round_no_advance_builder"));
  ASSERT_TRUE(future.has_value());

  // Signed by the round leader, but carries neither a TC nor a pol.
  const auto msg = make_test_frontier_propose_msg(nodes[0]->consensus_domain_for_test(), *future);

  ASSERT_EQ(nodes[0]->inject_network_propose_result_for_test(msg), std::string("hard-reject"));
  const auto after = nodes[0]->status();
  ASSERT_EQ(after.height, before.height);
  ASSERT_EQ(after.transition_hash, before.transition_hash);
}

TEST(test_future_round_vote_does_not_advance_round_prematurely) {
  const auto keys = node::Node::deterministic_test_keypairs();
  ASSERT_TRUE(keys.size() >= 4u);
  auto cluster = make_cluster(unique_test_base("/tmp/finalis_it_future_round_vote_no_advance"), 4, 4, 4);
  auto& nodes = cluster.nodes;

  ASSERT_TRUE(wait_for([&]() {
    for (const auto& n : nodes) {
      if (n->status().height < 6) return false;
    }
    return true;
  }, std::chrono::seconds(60)));
  for (auto& n : nodes) n->pause_proposals_for_test(true);
  ASSERT_TRUE(wait_for_stable_same_tip(nodes, std::chrono::seconds(10)));

  const auto before = nodes[0]->status();
  const std::uint64_t target_height = before.height + 1;
  const std::uint32_t future_round = before.round + 1;
  const auto committee = nodes[0]->committee_for_height_round_for_test(target_height, future_round);
  ASSERT_TRUE(!committee.empty());
  const PubKey32 signer_pub = committee.front();
  const int signer_id = node_for_pub(keys, signer_pub);
  ASSERT_TRUE(signer_id >= 0);

  Vote vote;
  vote.height = target_height;
  vote.round = future_round;
  vote.block_id.fill(0x7C);
  vote.validator_pubkey = signer_pub;
  auto sig = crypto::ed25519_sign(vote_signing_message(nodes[0]->consensus_domain_for_test(), vote.height, vote.round, vote.block_id),
                                  keys[static_cast<std::size_t>(signer_id)].private_key);
  ASSERT_TRUE(sig.has_value());
  vote.signature = *sig;

  ASSERT_EQ(nodes[0]->inject_network_vote_result_for_test(vote), std::string("soft-reject"));
  const auto after = nodes[0]->status();
  ASSERT_EQ(after.round, before.round);
  ASSERT_EQ(after.height, before.height);
  ASSERT_EQ(after.transition_hash, before.transition_hash);
}

TEST(test_only_one_block_can_finalize_per_height_after_vote_locking) {
  const auto keys = node::Node::deterministic_test_keypairs();
  ASSERT_TRUE(keys.size() >= 4u);
  auto cluster = make_cluster(unique_test_base("/tmp/finalis_it_single_finalization_lock"), 4, 4, 4);
  auto& nodes = cluster.nodes;
  Tx tx = make_fixture_ingress_tx(1, 0x89);
  ASSERT_TRUE(restart_cluster_with_seeded_certified_ingress(&cluster, {tx.serialize()}, true, true));
  auto& target = nodes[0];
  const std::uint64_t target_height = target->status().height + 1;
  const std::uint32_t round0 = 0;
  const std::uint32_t round1 = 1;
  ASSERT_TRUE(advance_test_frontier_round(*target, target_height, round0));
  const auto proposer_round0 = target->proposer_for_height_round_for_test(target_height, round0);
  const auto proposer_round1 = target->proposer_for_height_round_for_test(target_height, round1);
  ASSERT_TRUE(proposer_round0.has_value());
  ASSERT_TRUE(proposer_round1.has_value());

  const int proposer0_id = node_for_pub(keys, *proposer_round0);
  const int proposer1_id = node_for_pub(keys, *proposer_round1);
  ASSERT_TRUE(proposer0_id >= 0);
  ASSERT_TRUE(proposer1_id >= 0);

  auto proposal_a = build_cluster_frontier_proposal_from_records(
      cluster, keys, {tx.serialize()}, target_height, round0, "/tmp/finalis_it_single_finalization_lock_round0_builder");
  ASSERT_TRUE(proposal_a.has_value());
  ASSERT_EQ(target->inject_network_propose_result_for_test(make_test_frontier_propose_msg(nodes[0]->consensus_domain_for_test(), *proposal_a)),
            std::string("accepted"));

  auto proposal_b = build_cluster_frontier_proposal_from_records(
      cluster, keys, {tx.serialize()}, target_height, round1, "/tmp/finalis_it_single_finalization_lock_round1_builder");
  ASSERT_TRUE(proposal_b.has_value());

  const auto committee = target->committee_for_height_round_for_test(target_height, round0);
  ASSERT_EQ(committee.size(), 4u);

  const auto quorum = consensus::quorum_threshold(committee.size());
  std::size_t injected = 0;
  for (const auto& pub : committee) {
    if (pub == target->local_validator_pubkey_for_test()) continue;
    (void)target->inject_vote_for_test(
        make_test_vote(nodes[0]->consensus_domain_for_test(), keys, target_height, round0, frontier_proposal_id(*proposal_a), pub));
    ++injected;
    if (injected == quorum) break;
  }

  ASSERT_TRUE(wait_for([&]() { return target->status().height == target_height; }, std::chrono::seconds(5)));
  ASSERT_EQ(target->status().transition_hash, frontier_proposal_id(*proposal_a));
  ASSERT_TRUE(!target->inject_propose_msg_for_test(make_test_frontier_propose_msg(nodes[0]->consensus_domain_for_test(), *proposal_b)));
  ASSERT_EQ(target->status().transition_hash, frontier_proposal_id(*proposal_a));
}

// Regression: load_state used to drop a next-height vote lock that had no QC, so a validator that
// voted for A, crashed and restarted could then sign a conflicting payload at the same height.
// Certified-ingress records for `raw_records`, as persist_certified_ingress_fixture writes them
// (deterministic signer), built in a scratch database so a running node's records can be replayed.
std::optional<CertifiedIngressFixture> scratch_certified_ingress_fixture(const node::NodeConfig& base_cfg,
                                                                         const std::vector<Bytes>& raw_records,
                                                                         const std::string& scratch_base) {
  auto cfg = base_cfg;
  cfg.db_path = unique_test_base(scratch_base) + "/fixture";
  cfg.disable_p2p = true;
  cfg.listen = false;
  cfg.p2p_port = 0;
  {
    node::Node seed(cfg);
    if (!seed.init()) return std::nullopt;
    seed.stop();
  }
  storage::DB db;
  if (!db.open(cfg.db_path)) return std::nullopt;
  CertifiedIngressFixture fixture;
  const bool ok = persist_certified_ingress_fixture(cfg, db, raw_records, &fixture);
  db.close();
  if (!ok) return std::nullopt;
  return fixture;
}

TEST(test_validator_defers_vote_until_certified_ingress_is_held) {
  const auto keys = node::Node::deterministic_test_keypairs();
  auto cluster = make_cluster(unique_test_base("/tmp/finalis_it_vote_needs_ingress"), 4, 4, 4);
  // The target is isolated and unseeded, so it cannot hold the record when the proposal arrives.
  constexpr std::size_t ti = 3;
  cluster.configs[ti].disable_p2p = true;
  cluster.configs[ti].listen = false;
  cluster.configs[ti].p2p_port = 0;
  Tx tx = make_fixture_ingress_tx(1, 0x8C);
  ASSERT_TRUE(restart_cluster_with_seeded_certified_ingress(&cluster, {tx.serialize()}, true, true, true, {ti}));
  const std::uint64_t target_height = cluster.nodes[0]->status().height + 1;
  auto proposal = build_cluster_frontier_proposal_from_records(cluster, keys, {tx.serialize()}, target_height, 0,
                                                               "/tmp/finalis_it_vote_needs_ingress_p");
  ASSERT_TRUE(proposal.has_value());
  const auto proposal_id = frontier_proposal_id(*proposal);
  auto& target = *cluster.nodes[ti];
  ASSERT_TRUE(target.local_is_committee_member_for_test(target_height, 0));
  ASSERT_TRUE(advance_test_frontier_round(target, target_height, 0));

  // Valid proposal, but the certified record is missing locally: accepted, no vote, deferred.
  ASSERT_EQ(target.inject_network_propose_result_for_test(make_test_frontier_propose_msg(cluster.nodes[0]->consensus_domain_for_test(), *proposal)),
            std::string("accepted"));
  ASSERT_TRUE(!target.local_prevote_recorded_for_test(target_height, 0, proposal_id));
  ASSERT_EQ(target.deferred_certified_vote_count_for_test(), 1u);

  // The record arrives as a range response; the deferred proposal is re-handled and voted for.
  const auto fixture = scratch_certified_ingress_fixture(cluster.configs[ti], {tx.serialize()},
                                                         "/tmp/finalis_it_vote_needs_ingress_f");
  ASSERT_TRUE(fixture.has_value());
  const auto lane = consensus::assign_ingress_lane(tx);
  ASSERT_EQ(fixture->lane_records[lane].size(), 1u);
  const auto& record = fixture->lane_records[lane].front();
  p2p::IngressRangeMsg range;
  range.lane = lane;
  range.from_seq = 1;
  range.to_seq = 1;
  range.records.push_back(p2p::IngressRecordMsg{record.certificate, record.tx_bytes});
  target.set_requested_ingress_range_for_test(7, p2p::GetIngressRangeMsg{lane, 1, 1});
  ASSERT_TRUE(target.inject_ingress_range_for_test(range, 7));
  ASSERT_TRUE(target.local_prevote_recorded_for_test(target_height, 0, proposal_id));
  ASSERT_EQ(target.deferred_certified_vote_count_for_test(), 0u);
}

TEST(test_validator_refuses_vote_when_slice_differs_from_certified_ingress) {
  const auto keys = node::Node::deterministic_test_keypairs();
  auto cluster = make_cluster(unique_test_base("/tmp/finalis_it_vote_ingress_mismatch"), 4, 4, 4);
  Tx held = make_fixture_ingress_tx(1, 0x8D);
  const auto lane = consensus::assign_ingress_lane(held);
  // A different tx in the same lane: the proposal claims it at the seq where `held` is certified.
  std::optional<Tx> claimed;
  for (int tag = 0x90; tag <= 0xFF && !claimed.has_value(); ++tag) {
    Tx candidate = make_fixture_ingress_tx(1, static_cast<std::uint8_t>(tag));
    if (consensus::assign_ingress_lane(candidate) == lane) claimed = candidate;
  }
  ASSERT_TRUE(claimed.has_value());
  ASSERT_TRUE(restart_cluster_with_seeded_certified_ingress(&cluster, {held.serialize()}, true, true, true));
  const std::uint64_t target_height = cluster.nodes[0]->status().height + 1;
  auto proposal = build_cluster_frontier_proposal_from_records(cluster, keys, {claimed->serialize()}, target_height, 0,
                                                               "/tmp/finalis_it_vote_ingress_mismatch_p");
  ASSERT_TRUE(proposal.has_value());
  const auto proposal_id = frontier_proposal_id(*proposal);

  std::size_t ti = cluster.nodes.size();
  for (std::size_t k = 0; k < cluster.nodes.size(); ++k) {
    if (cluster.nodes[k]->local_is_committee_member_for_test(target_height, 0)) {
      ti = k;
      break;
    }
  }
  ASSERT_TRUE(ti < cluster.nodes.size());
  auto& target = *cluster.nodes[ti];
  ASSERT_TRUE(advance_test_frontier_round(target, target_height, 0));
  ASSERT_EQ(target.inject_network_propose_result_for_test(make_test_frontier_propose_msg(cluster.nodes[0]->consensus_domain_for_test(), *proposal)),
            std::string("accepted"));
  ASSERT_TRUE(!target.local_prevote_recorded_for_test(target_height, 0, proposal_id));
  ASSERT_EQ(target.deferred_certified_vote_count_for_test(), 0u);
}

// Regression for a captured fork: validators timed out of round 0, moved to round 1, then cast
// late round-0 votes that completed a QC while round 1 finalized a different transition. Two-phase
// finality removes the hazard; the rule stays (a timed-out round is never voted in).
TEST(test_validator_never_votes_in_a_round_it_timed_out_of) {
  const auto keys = node::Node::deterministic_test_keypairs();
  auto cluster = make_cluster(unique_test_base("/tmp/finalis_it_no_late_vote"), 4, 4, 4);
  Tx tx = make_fixture_ingress_tx(1, 0x8E);
  ASSERT_TRUE(restart_cluster_with_seeded_certified_ingress(&cluster, {tx.serialize()}, true, true, true));
  const std::uint64_t target_height = cluster.nodes[0]->status().height + 1;
  auto proposal = build_cluster_frontier_proposal_from_records(cluster, keys, {tx.serialize()}, target_height, 0,
                                                               "/tmp/finalis_it_no_late_vote_p");
  ASSERT_TRUE(proposal.has_value());
  const auto proposal_id = frontier_proposal_id(*proposal);

  std::vector<std::size_t> members;
  for (std::size_t k = 0; k < cluster.nodes.size(); ++k) {
    if (cluster.nodes[k]->local_is_committee_member_for_test(target_height, 0)) members.push_back(k);
  }
  ASSERT_TRUE(members.size() >= 2u);
  auto& timed_out = *cluster.nodes[members[0]];
  auto& control = *cluster.nodes[members[1]];

  // Timed out of round 0, then the late round-0 proposal arrives (same height, still round 0 here).
  ASSERT_TRUE(advance_test_frontier_round(timed_out, target_height, 0));
  timed_out.mark_local_round_timed_out_for_test(target_height, 0);
  ASSERT_EQ(timed_out.inject_network_propose_result_for_test(make_test_frontier_propose_msg(cluster.nodes[0]->consensus_domain_for_test(), *proposal)),
            std::string("accepted"));
  ASSERT_TRUE(!timed_out.local_prevote_recorded_for_test(target_height, 0, proposal_id));
  ASSERT_TRUE(!timed_out.local_vote_lock_for_test(target_height).has_value());

  // A member that did not time out still votes for the same proposal.
  ASSERT_TRUE(advance_test_frontier_round(control, target_height, 0));
  ASSERT_EQ(control.inject_network_propose_result_for_test(make_test_frontier_propose_msg(cluster.nodes[0]->consensus_domain_for_test(), *proposal)),
            std::string("accepted"));
  ASSERT_TRUE(control.local_prevote_recorded_for_test(target_height, 0, proposal_id));
}

// A committee member for every round in [0, rounds) at `height`, or nodes.size().
std::size_t test_member_for_rounds(const Cluster& cluster, std::uint64_t height, std::uint32_t rounds) {
  for (std::size_t k = 0; k < cluster.nodes.size(); ++k) {
    bool member = true;
    for (std::uint32_t r = 0; r < rounds && member; ++r) {
      member = cluster.nodes[k]->local_is_committee_member_for_test(height, r);
    }
    if (member) return k;
  }
  return cluster.nodes.size();
}

// Spec §6.6: lock, valid value and signed prevotes survive a restart; no double prevote, and the
// lock blocks a conflicting fresh proposal while the valid value's re-proposal stays votable.
TEST(test_vote_lock_survives_restart_and_blocks_conflicting_vote) {
  const auto keys = node::Node::deterministic_test_keypairs();
  ASSERT_TRUE(keys.size() >= 4u);
  auto cluster = make_cluster(unique_test_base("/tmp/finalis_it_vote_lock_restart"), 4, 4, 4);
  Tx tx = make_fixture_ingress_tx(1, 0x8B);
  ASSERT_TRUE(restart_cluster_with_seeded_certified_ingress(&cluster, {tx.serialize()}, true, true, true));
  const std::uint64_t target_height = cluster.nodes[0]->status().height + 1;
  const std::uint32_t round0 = 0;
  const std::uint32_t round1 = 1;

  // A carries the ingress record, B is empty: same height, conflicting transitions.
  auto proposal_a0 = build_cluster_frontier_proposal_from_records(
      cluster, keys, {tx.serialize()}, target_height, round0, "/tmp/finalis_it_vote_lock_restart_a0");
  auto proposal_b0 = build_cluster_frontier_proposal_from_records(
      cluster, keys, {}, target_height, round0, "/tmp/finalis_it_vote_lock_restart_b0");
  auto proposal_b1 = build_cluster_frontier_proposal_from_records(
      cluster, keys, {}, target_height, round1, "/tmp/finalis_it_vote_lock_restart_b1");
  ASSERT_TRUE(proposal_a0.has_value());
  ASSERT_TRUE(proposal_b0.has_value());
  ASSERT_TRUE(proposal_b1.has_value());
  const auto a0_id = frontier_proposal_id(*proposal_a0);
  const auto b0_id = frontier_proposal_id(*proposal_b0);
  const auto b1_id = frontier_proposal_id(*proposal_b1);
  ASSERT_TRUE(a0_id != b0_id);

  const std::size_t ti = test_member_for_rounds(cluster, target_height, 2);
  ASSERT_TRUE(ti < cluster.nodes.size());
  ASSERT_TRUE(cluster.nodes[ti]->pause_proposals_for_test(true));
  const auto committee0 = cluster.nodes[ti]->committee_for_height_round_for_test(target_height, round0);
  const auto quorum0 = consensus::quorum_threshold(committee0.size());

  // 1. Prevote A at (h, 0); a polka for A follows, so the node locks on A and precommits it.
  ASSERT_TRUE(advance_test_frontier_round(*cluster.nodes[ti], target_height, round0));
  ASSERT_EQ(cluster.nodes[ti]->inject_network_propose_result_for_test(make_test_frontier_propose_msg(cluster.nodes[0]->consensus_domain_for_test(), *proposal_a0)),
            std::string("accepted"));
  ASSERT_TRUE(cluster.nodes[ti]->local_prevote_recorded_for_test(target_height, round0, a0_id));
  inject_test_prevotes(*cluster.nodes[ti], keys, committee0, target_height, round0, a0_id, quorum0 - 1);
  ASSERT_TRUE(wait_for_local_precommit(*cluster.nodes[ti], target_height, round0, a0_id));
  ASSERT_TRUE(cluster.nodes[ti]->status().height + 1 == target_height);  // one precommit: no finality
  const auto lock_before = cluster.nodes[ti]->local_vote_lock_for_test(target_height);
  ASSERT_TRUE(lock_before.has_value());
  ASSERT_TRUE(lock_before->first == a0_id);
  ASSERT_EQ(lock_before->second, round0);
  const auto polka_before = cluster.nodes[ti]->valid_polka_for_height_for_test(target_height);
  ASSERT_TRUE(polka_before.has_value());
  ASSERT_TRUE(polka_before->frontier_transition_id == a0_id);

  // 2. Crash/restart the validator.
  cluster.nodes[ti]->stop();
  cluster.nodes[ti].reset();
  cluster.nodes[ti] = std::make_unique<node::Node>(cluster.configs[ti]);
  ASSERT_TRUE(cluster.nodes[ti]->init());
  auto& target = cluster.nodes[ti];
  ASSERT_TRUE(target->status().height + 1 == target_height);
  const auto lock_after = target->local_vote_lock_for_test(target_height);
  ASSERT_TRUE(lock_after.has_value());
  ASSERT_TRUE(lock_after->first == lock_before->first);
  ASSERT_EQ(lock_after->second, lock_before->second);
  ASSERT_TRUE(target->local_prevote_recorded_for_test(target_height, round0, a0_id));
  const auto polka_after = target->valid_polka_for_height_for_test(target_height);
  ASSERT_TRUE(polka_after.has_value());
  ASSERT_EQ(polka_after->round, round0);
  ASSERT_TRUE(target->has_candidate_frontier_proposal_for_test(a0_id));
  ASSERT_TRUE(target->pause_proposals_for_test(true));
  target->start();

  // 3a. Conflicting proposal at the same (h, 0): already prevoted there, no second prevote.
  ASSERT_TRUE(advance_test_frontier_round(*target, target_height, round0));
  (void)target->inject_network_propose_result_for_test(make_test_frontier_propose_msg(cluster.nodes[0]->consensus_domain_for_test(), *proposal_b0));
  ASSERT_TRUE(!target->local_prevote_recorded_for_test(target_height, round0, b0_id));

  // 3b. Fresh conflicting proposal at (h, 1) justified only by a TC: the lock blocks the prevote.
  const auto tc0 = make_test_timeout_certificate(cluster.nodes[0]->consensus_domain_for_test(), keys, committee0, target_height, round0, quorum0);
  ASSERT_TRUE(tc0.signatures.size() >= quorum0);
  (void)target->inject_network_propose_result_for_test(make_test_frontier_propose_msg(cluster.nodes[0]->consensus_domain_for_test(), *proposal_b1, std::nullopt, tc0));
  ASSERT_TRUE(!target->local_prevote_recorded_for_test(target_height, round1, b1_id));
  ASSERT_TRUE(target->local_vote_lock_for_test(target_height)->first == a0_id);

  // 4. Liveness: the round-1 leader re-proposes A unchanged with its round-0 polka; still votable.
  const auto leader1 = target->proposer_for_height_round_for_test(target_height, round1);
  ASSERT_TRUE(leader1.has_value());
  auto repropose = make_test_frontier_propose_msg(cluster.nodes[0]->consensus_domain_for_test(), *proposal_a0, *polka_after, tc0, round1, *leader1);
  ASSERT_EQ(target->inject_network_propose_result_for_test(repropose), std::string("accepted"));
  ASSERT_TRUE(target->local_prevote_recorded_for_test(target_height, round1, a0_id));
}

// A node far behind in rounds (a restart resets it to round 0) jumps to the round f+1 committee
// members have timed out of, however far ahead; one far-ahead voter alone (possibly Byzantine)
// moves it nowhere.
TEST(test_round_catch_up_needs_f_plus_one_timeout_votes) {
  const auto keys = node::Node::deterministic_test_keypairs();
  auto cluster = make_cluster(unique_test_base("/tmp/finalis_it_f_plus_one_round_skip"), 4, 4, 4);
  auto& nodes = cluster.nodes;
  ASSERT_TRUE(wait_for([&]() { return nodes[0]->status().height >= 2; }, ci_timeout_seconds(60)));
  for (int i = 1; i < 4; ++i) nodes[i]->stop();  // no quorum left: no finality, no TC

  auto& target = nodes[0];
  const std::uint64_t h = target->status().height + 1;
  const auto committee = target->committee_for_height_round_for_test(h, 0);
  ASSERT_EQ(committee.size(), 4u);
  std::vector<PubKey32> others;
  for (const auto& pub : committee) {
    if (pub != target->local_validator_pubkey_for_test()) others.push_back(pub);
  }
  const std::uint32_t base = target->status().round;
  const std::uint32_t far_round = base + 100;  // beyond the single-vote catch-up window (32)

  // Beyond the window the votes are not stored (soft reject), only their rounds are noted.
  (void)target->inject_timeout_vote_for_test(make_test_timeout_vote(nodes[0]->consensus_domain_for_test(), keys, h, far_round + 10, others[0]));
  ASSERT_TRUE(target->status().round < far_round);
  (void)target->inject_timeout_vote_for_test(make_test_timeout_vote(nodes[0]->consensus_domain_for_test(), keys, h, far_round, others[1]));
  ASSERT_EQ(target->status().round, far_round);  // the second-highest: f + 1 = 2 validators reached it
}

TEST(test_fork_choice_prefers_highest_finalized_view_then_weight) {
  const auto keys = node::Node::deterministic_test_keypairs();
  ASSERT_TRUE(keys.size() >= 4u);
  auto cluster = make_cluster(unique_test_base("/tmp/finalis_it_fork_choice_view_then_weight"), 4, 4, 4);
  auto& nodes = cluster.nodes;
  Tx tx = make_fixture_ingress_tx(1, 0x9A);
  ASSERT_TRUE(restart_cluster_with_seeded_certified_ingress(&cluster, {tx.serialize()}, true, true));

  auto& target = nodes[0];
  const std::uint64_t target_height = target->status().height + 1;
  const std::uint32_t round0 = 0;
  const std::uint32_t round1 = 1;

  auto proposal_round0 = build_cluster_frontier_proposal_from_records(
      cluster, keys, {tx.serialize()}, target_height, round0, "/tmp/finalis_it_fork_choice_round0_builder");
  ASSERT_TRUE(proposal_round0.has_value());
  ASSERT_EQ(target->inject_network_propose_result_for_test(make_test_frontier_propose_msg(nodes[0]->consensus_domain_for_test(), *proposal_round0)),
            std::string("accepted"));

  const auto committee0 = target->committee_for_height_round_for_test(target_height, round0);
  ASSERT_EQ(committee0.size(), 4u);
  const auto quorum0 = consensus::quorum_threshold(committee0.size());
  ASSERT_TRUE(quorum0 >= 3u);

  // Lower-view candidate gets sub-quorum support and must not finalize.
  std::size_t low_view_votes = 0;
  for (const auto& pub : committee0) {
    if (pub == target->local_validator_pubkey_for_test()) continue;
    (void)target->inject_vote_for_test(
        make_test_vote(nodes[0]->consensus_domain_for_test(), keys, target_height, round0, frontier_proposal_id(*proposal_round0), pub));
    ++low_view_votes;
    if (low_view_votes + 1 >= quorum0) break;  // keep this below quorum including local vote
  }
  ASSERT_TRUE(target->status().height + 1 == target_height);

  // Advance view with a valid timeout certificate at round0.
  for (std::size_t i = 0; i < quorum0; ++i) {
    ASSERT_TRUE(target->inject_timeout_vote_for_test(make_test_timeout_vote(nodes[0]->consensus_domain_for_test(), keys, target_height, round0, committee0[i])));
  }
  ASSERT_TRUE(wait_for([&]() { return target->status().round >= round1; }, std::chrono::seconds(5)));
  const std::uint32_t effective_round = std::max<std::uint32_t>(round1, target->status().round);

  auto proposal_round1 = build_cluster_frontier_proposal_from_records(
      cluster, keys, {tx.serialize()}, target_height, effective_round, "/tmp/finalis_it_fork_choice_round1_builder");
  ASSERT_TRUE(proposal_round1.has_value());
  auto tc0 = make_test_timeout_certificate(nodes[0]->consensus_domain_for_test(), keys, committee0, target_height, round0, quorum0);
  ASSERT_TRUE(tc0.signatures.size() >= quorum0);
  auto repropose_msg = make_test_frontier_propose_msg(nodes[0]->consensus_domain_for_test(), *proposal_round1);
  repropose_msg.justify_tc = tc0;
  ASSERT_EQ(target->inject_network_propose_result_for_test(repropose_msg), std::string("accepted"));

  const auto committee1 = target->committee_for_height_round_for_test(target_height, effective_round);
  const auto quorum1 = consensus::quorum_threshold(committee1.size());
  std::size_t high_view_votes = 0;
  for (const auto& pub : committee1) {
    if (pub == target->local_validator_pubkey_for_test()) continue;
    (void)target->inject_vote_for_test(
        make_test_vote(nodes[0]->consensus_domain_for_test(), keys, target_height, effective_round, frontier_proposal_id(*proposal_round1), pub));
    ++high_view_votes;
    if (high_view_votes >= quorum1) break;
  }

  ASSERT_TRUE(wait_for([&]() { return target->status().height == target_height; }, std::chrono::seconds(5)));
  ASSERT_EQ(target->status().transition_hash, frontier_proposal_id(*proposal_round1));
}

TEST(test_equivocation_evidence_changes_fork_choice_deterministically) {
  const auto keys = node::Node::deterministic_test_keypairs();
  ASSERT_TRUE(keys.size() >= 4u);
  auto cluster = make_cluster(unique_test_base("/tmp/finalis_it_equivocation_fork_choice_deterministic"), 4, 4, 4);
  auto& nodes = cluster.nodes;
  Tx tx = make_fixture_ingress_tx(1, 0x9C);
  ASSERT_TRUE(restart_cluster_with_seeded_certified_ingress(&cluster, {tx.serialize()}, true, true));

  for (auto& n : nodes) ASSERT_TRUE(n->pause_proposals_for_test(true));
  ASSERT_TRUE(wait_for_stable_same_tip(nodes, ci_timeout_seconds(30)));

  auto before = nodes[0]->status();
  const std::uint64_t target_height = before.height + 1;
  const std::uint32_t target_round = 0;
  auto proposal = build_cluster_frontier_proposal_from_records(
      cluster, keys, {tx.serialize()}, target_height, target_round,
      "/tmp/finalis_it_equivocation_fork_choice_deterministic_builder");
  ASSERT_TRUE(proposal.has_value());
  const auto canonical_transition_id = frontier_proposal_id(*proposal);

  // Inject an accepted proposal everywhere first so vote processing is anchored to a known candidate.
  for (auto& n : nodes) {
    ASSERT_EQ(n->inject_network_propose_result_for_test(make_test_frontier_propose_msg(nodes[0]->consensus_domain_for_test(), *proposal)), std::string("accepted"));
  }

  const auto committee = nodes[0]->committee_for_height_round_for_test(target_height, target_round);
  const auto quorum = consensus::quorum_threshold(committee.size());
  ASSERT_TRUE(quorum > 0);

  // Validator[0] equivocates: first vote accepted, conflicting vote rejected on all nodes.
  Vote equiv_a = make_test_vote(nodes[0]->consensus_domain_for_test(), keys, target_height, target_round, canonical_transition_id, keys[0].public_key);
  Vote equiv_b = equiv_a;
  equiv_b.block_id.fill(0xEE);
  auto equiv_b_sig = crypto::ed25519_sign(vote_signing_message(nodes[0]->consensus_domain_for_test(), equiv_b.height, equiv_b.round, equiv_b.block_id),
                                          keys[0].private_key);
  ASSERT_TRUE(equiv_b_sig.has_value());
  equiv_b.signature = *equiv_b_sig;
  for (auto& n : nodes) {
    ASSERT_TRUE(n->inject_vote_for_test(equiv_a));
    ASSERT_TRUE(!n->inject_vote_for_test(equiv_b));
  }

  // Complete quorum with non-equivocating committee members for the canonical proposal.
  std::size_t votes_added = 1;  // equiv_a above
  for (const auto& pub : committee) {
    if (pub == keys[0].public_key) continue;
    const auto vote = make_test_vote(nodes[0]->consensus_domain_for_test(), keys, target_height, target_round, canonical_transition_id, pub);
    for (auto& n : nodes) {
      // Nodes also gossip their own votes for the injected proposal, so one may finalize first.
      const auto res = n->inject_network_vote_diagnostic_for_test(vote);
      ASSERT_TRUE(res == "accepted" || res == "soft-reject:stale-finalized-height");
    }
    ++votes_added;
    if (votes_added >= quorum) break;
  }
  ASSERT_TRUE(votes_added >= quorum);

  for (auto& n : nodes) ASSERT_TRUE(n->pause_proposals_for_test(false));
  ASSERT_TRUE(wait_for([&]() {
    for (const auto& n : nodes) {
      if (n->status().height < target_height) return false;
    }
    return true;
  }, ci_timeout_seconds(30)));

  for (std::size_t i = 0; i < nodes.size(); ++i) {
    const auto st = nodes[i]->status();
    ASSERT_EQ(st.height, target_height);
    ASSERT_EQ(st.transition_hash, canonical_transition_id);
  }
}

// Shared setup for the two-phase scenarios: a 4-node cluster, transition A (with a record) and an
// empty transition B at round 0, and a target that is a committee member in rounds 0..2.
struct TwoPhaseFixture {
  Cluster cluster;
  std::vector<crypto::KeyPair> keys;
  std::uint64_t height{0};
  std::size_t ti{0};
  std::optional<FrontierProposal> a0;
  std::optional<FrontierProposal> b0;
  std::optional<FrontierProposal> b1;
  std::vector<PubKey32> committee;
  std::size_t quorum{0};
  node::Node& target() { return *cluster.nodes[ti]; }
};

std::unique_ptr<TwoPhaseFixture> make_two_phase_fixture(const std::string& base, std::uint8_t tx_tag) {
  auto f = std::make_unique<TwoPhaseFixture>();
  f->keys = node::Node::deterministic_test_keypairs();
  f->cluster = make_cluster(unique_test_base(base), 4, 4, 4);
  Tx tx = make_fixture_ingress_tx(1, tx_tag);
  if (!restart_cluster_with_seeded_certified_ingress(&f->cluster, {tx.serialize()}, true, true, true)) {
    throw std::runtime_error("cluster seed failed");
  }
  f->height = f->cluster.nodes[0]->status().height + 1;
  f->a0 = build_cluster_frontier_proposal_from_records(f->cluster, f->keys, {tx.serialize()}, f->height, 0, base + "_a0");
  f->b0 = build_cluster_frontier_proposal_from_records(f->cluster, f->keys, {}, f->height, 0, base + "_b0");
  f->b1 = build_cluster_frontier_proposal_from_records(f->cluster, f->keys, {}, f->height, 1, base + "_b1");
  if (!f->a0 || !f->b0 || !f->b1) throw std::runtime_error("proposal build failed");
  f->ti = test_member_for_rounds(f->cluster, f->height, 3);
  if (f->ti >= f->cluster.nodes.size()) throw std::runtime_error("no member for rounds 0..2");
  (void)f->target().pause_proposals_for_test(true);
  f->committee = f->target().committee_for_height_round_for_test(f->height, 0);
  f->quorum = consensus::quorum_threshold(f->committee.size());
  for (std::uint32_t r = 1; r < 3; ++r) {
    if (f->target().committee_for_height_round_for_test(f->height, r) != f->committee) {
      throw std::runtime_error("committee changes across rounds");
    }
  }
  return f;
}

// A pol must be a polka for the proposed transition, from a lower round, with valid prevote signatures.
TEST(test_pol_must_be_a_valid_lower_round_polka_for_the_proposal) {
  auto f = make_two_phase_fixture("/tmp/finalis_it_pol_checks", 0x8C);
  auto& target = f->target();
  const auto a_id = frontier_proposal_id(*f->a0);
  const auto leader1 = target.proposer_for_height_round_for_test(f->height, 1);
  ASSERT_TRUE(leader1.has_value());
  ASSERT_TRUE(advance_test_frontier_round(target, f->height, 1));

  // Polka for A attached to B: mismatch.
  const auto polka_a = make_test_polka(f->target().consensus_domain_for_test(), f->keys, f->committee, f->height, 0, a_id, f->quorum);
  ASSERT_EQ(target.inject_network_propose_result_for_test(
                make_test_frontier_propose_msg(f->target().consensus_domain_for_test(), *f->b0, polka_a, std::nullopt, 1, *leader1)),
            std::string("hard-reject"));
  // Precommit signatures presented as a polka (forged pol).
  auto forged = make_test_qc(f->target().consensus_domain_for_test(), f->keys, f->committee, f->height, 0, a_id, f->quorum);
  ASSERT_EQ(target.inject_network_propose_result_for_test(
                make_test_frontier_propose_msg(f->target().consensus_domain_for_test(), *f->a0, forged, std::nullopt, 1, *leader1)),
            std::string("hard-reject"));
  // Below quorum.
  const auto thin = make_test_polka(f->target().consensus_domain_for_test(), f->keys, f->committee, f->height, 0, a_id, f->quorum - 1);
  ASSERT_EQ(target.inject_network_propose_result_for_test(
                make_test_frontier_propose_msg(f->target().consensus_domain_for_test(), *f->a0, thin, std::nullopt, 1, *leader1)),
            std::string("hard-reject"));
  // Pol from the proposal's own round.
  const auto same_round = make_test_polka(f->target().consensus_domain_for_test(), f->keys, f->committee, f->height, 1, frontier_proposal_id(*f->b1), f->quorum);
  ASSERT_EQ(target.inject_network_propose_result_for_test(make_test_frontier_propose_msg(f->target().consensus_domain_for_test(), *f->b1, same_round)),
            std::string("hard-reject"));
  // Signed by someone other than the round leader.
  PubKey32 not_leader{};
  for (const auto& pub : f->committee) {
    if (pub != *leader1) not_leader = pub;
  }
  ASSERT_EQ(target.inject_network_propose_result_for_test(
                make_test_frontier_propose_msg(f->target().consensus_domain_for_test(), *f->a0, polka_a, std::nullopt, 1, not_leader)),
            std::string("hard-reject"));
  ASSERT_TRUE(!target.local_prevote_recorded_for_test(f->height, 1, a_id));
  // The well-formed re-proposal is accepted and prevoted.
  ASSERT_EQ(target.inject_network_propose_result_for_test(
                make_test_frontier_propose_msg(f->target().consensus_domain_for_test(), *f->a0, polka_a, std::nullopt, 1, *leader1)),
            std::string("accepted"));
  ASSERT_TRUE(target.local_prevote_recorded_for_test(f->height, 1, a_id));
}

// Spec §6.3 / §6.7: a polka for A at round 0 seen by a minority; round 1 re-proposes A unchanged with
// it; A finalizes with precommits from round 1 and keeps its transition id.
TEST(test_valid_value_reproposal_finalizes_same_transition_in_later_round) {
  auto f = make_two_phase_fixture("/tmp/finalis_it_valid_value_reproposal", 0x8D);
  auto& target = f->target();
  const auto a_id = frontier_proposal_id(*f->a0);
  ASSERT_TRUE(advance_test_frontier_round(target, f->height, 0));
  ASSERT_EQ(target.inject_network_propose_result_for_test(make_test_frontier_propose_msg(f->target().consensus_domain_for_test(), *f->a0)),
            std::string("accepted"));
  ASSERT_TRUE(target.local_prevote_recorded_for_test(f->height, 0, a_id));
  // No polka reaches the target in round 0: it neither locks nor precommits.
  ASSERT_TRUE(!target.local_vote_lock_for_test(f->height).has_value());

  const auto tc0 = make_test_timeout_certificate(f->target().consensus_domain_for_test(), f->keys, f->committee, f->height, 0, f->quorum);
  ASSERT_TRUE(advance_test_frontier_round(target, f->height, 1));
  const auto leader1 = target.proposer_for_height_round_for_test(f->height, 1);
  ASSERT_TRUE(leader1.has_value());
  const auto polka0 = make_test_polka(f->target().consensus_domain_for_test(), f->keys, f->committee, f->height, 0, a_id, f->quorum);
  ASSERT_EQ(target.inject_network_propose_result_for_test(
                make_test_frontier_propose_msg(f->target().consensus_domain_for_test(), *f->a0, polka0, tc0, 1, *leader1)),
            std::string("accepted"));
  ASSERT_TRUE(target.local_prevote_recorded_for_test(f->height, 1, a_id));
  ASSERT_EQ(target.valid_polka_for_height_for_test(f->height)->round, 0u);

  // Round-1 polka: lock (A, 1) and precommit at round 1.
  inject_test_prevotes(target, f->keys, f->committee, f->height, 1, a_id, f->quorum - 1);
  const auto lock = target.local_vote_lock_for_test(f->height);
  ASSERT_TRUE(lock.has_value());
  ASSERT_TRUE(lock->first == a_id);
  ASSERT_EQ(lock->second, 1u);
  ASSERT_TRUE(wait_for_local_precommit(target, f->height, 1, a_id));

  // Round-1 precommits finalize A (transition round 0, certificate round 1).
  std::size_t injected = 0;
  for (const auto& pub : f->committee) {
    if (injected + 1 == f->quorum) break;
    if (pub == target.local_validator_pubkey_for_test()) continue;
    (void)target.inject_vote_for_test(make_test_vote(f->target().consensus_domain_for_test(), f->keys, f->height, 1, a_id, pub));
    ++injected;
  }
  ASSERT_TRUE(wait_for([&]() { return target.status().height == f->height; }, std::chrono::seconds(5)));
  ASSERT_EQ(target.status().transition_hash, a_id);
}

// Spec §6.4: a lock moves forward on a newer polka. Locked on A at round 0, a polka for B at round 1
// moves the lock to (B, 1); a fresh proposal at round 2 is then refused.
TEST(test_newer_polka_moves_the_lock) {
  auto f = make_two_phase_fixture("/tmp/finalis_it_lock_moves", 0x8E);
  auto& target = f->target();
  const auto a_id = frontier_proposal_id(*f->a0);
  const auto b1_id = frontier_proposal_id(*f->b1);
  ASSERT_TRUE(advance_test_frontier_round(target, f->height, 0));
  ASSERT_EQ(target.inject_network_propose_result_for_test(make_test_frontier_propose_msg(f->target().consensus_domain_for_test(), *f->a0)),
            std::string("accepted"));
  inject_test_prevotes(target, f->keys, f->committee, f->height, 0, a_id, f->quorum - 1);
  ASSERT_TRUE(target.local_vote_lock_for_test(f->height)->first == a_id);

  // Round 1: fresh B with only a TC; locked on A, so no prevote.
  const auto tc0 = make_test_timeout_certificate(f->target().consensus_domain_for_test(), f->keys, f->committee, f->height, 0, f->quorum);
  ASSERT_TRUE(advance_test_frontier_round(target, f->height, 1));
  ASSERT_EQ(target.inject_network_propose_result_for_test(make_test_frontier_propose_msg(f->target().consensus_domain_for_test(), *f->b1, std::nullopt, tc0)),
            std::string("accepted"));
  ASSERT_TRUE(!target.local_prevote_recorded_for_test(f->height, 1, b1_id));
  // The others prevote B at round 1: a polka the target sees moves its lock and valid value.
  inject_test_prevotes(target, f->keys, f->committee, f->height, 1, b1_id, f->quorum);
  const auto lock = target.local_vote_lock_for_test(f->height);
  ASSERT_TRUE(lock.has_value());
  ASSERT_TRUE(lock->first == b1_id);
  ASSERT_EQ(lock->second, 1u);
  ASSERT_TRUE(target.valid_polka_for_height_for_test(f->height)->frontier_transition_id == b1_id);

  // Round 2: re-proposing A with its older round-0 polka cannot move the lock back.
  const auto tc1 = make_test_timeout_certificate(f->target().consensus_domain_for_test(), f->keys, f->committee, f->height, 1, f->quorum);
  ASSERT_TRUE(advance_test_frontier_round(target, f->height, 2));
  const auto leader2 = target.proposer_for_height_round_for_test(f->height, 2);
  ASSERT_TRUE(leader2.has_value());
  const auto polka_a0 = make_test_polka(f->target().consensus_domain_for_test(), f->keys, f->committee, f->height, 0, a_id, f->quorum);
  ASSERT_EQ(target.inject_network_propose_result_for_test(
                make_test_frontier_propose_msg(f->target().consensus_domain_for_test(), *f->a0, polka_a0, tc1, 2, *leader2)),
            std::string("accepted"));
  ASSERT_TRUE(!target.local_prevote_recorded_for_test(f->height, 2, a_id));
  ASSERT_TRUE(target.local_vote_lock_for_test(f->height)->first == b1_id);
}

// Spec §6.1: the captured fork. Prevotes for A complete a round-0 polka only after the target timed
// out into round 1: it records A as the valid value but never precommits at round 0.
TEST(test_late_polka_after_timeout_records_valid_value_without_precommit) {
  auto f = make_two_phase_fixture("/tmp/finalis_it_late_polka", 0x8F);
  auto& target = f->target();
  const auto a_id = frontier_proposal_id(*f->a0);
  ASSERT_TRUE(advance_test_frontier_round(target, f->height, 0));
  ASSERT_EQ(target.inject_network_propose_result_for_test(make_test_frontier_propose_msg(f->target().consensus_domain_for_test(), *f->a0)),
            std::string("accepted"));
  // The round-0 polka completes only after the target timed out of round 0.
  target.mark_local_round_timed_out_for_test(f->height, 0);
  inject_test_prevotes(target, f->keys, f->committee, f->height, 0, a_id, f->quorum - 1);
  ASSERT_TRUE(target.valid_polka_for_height_for_test(f->height).has_value());
  ASSERT_TRUE(!target.local_vote_recorded_for_test(f->height, 0, a_id));
  ASSERT_TRUE(!target.local_vote_lock_for_test(f->height).has_value());
}

// Delivers precommits for `transition_id` from committee members other than `target`.
void inject_test_precommits(node::Node& target, const std::vector<crypto::KeyPair>& keys,
                            const std::vector<PubKey32>& committee, std::uint64_t height, std::uint32_t round,
                            const Hash32& transition_id, std::size_t count) {
  std::size_t injected = 0;
  for (const auto& pub : committee) {
    if (injected == count) break;
    if (pub == target.local_validator_pubkey_for_test()) continue;
    (void)target.inject_vote_for_test(make_test_vote(target.consensus_domain_for_test(), keys, height, round, transition_id, pub));
    ++injected;
  }
  if (injected != count) throw std::runtime_error("not enough precommitters");
}

// A polka that completes before the proposal body arrives takes effect when the body does.
TEST(test_polka_before_body_locks_and_precommits_when_body_arrives) {
  auto f = make_two_phase_fixture("/tmp/finalis_it_polka_before_body", 0x90);
  auto& target = f->target();
  const auto a_id = frontier_proposal_id(*f->a0);
  ASSERT_TRUE(advance_test_frontier_round(target, f->height, 0));
  inject_test_prevotes(target, f->keys, f->committee, f->height, 0, a_id, f->quorum);
  ASSERT_TRUE(!target.local_vote_lock_for_test(f->height).has_value());
  ASSERT_EQ(target.inject_network_propose_result_for_test(make_test_frontier_propose_msg(f->target().consensus_domain_for_test(), *f->a0)),
            std::string("accepted"));
  ASSERT_TRUE(target.valid_polka_for_height_for_test(f->height).has_value());
  const auto lock = target.local_vote_lock_for_test(f->height);
  ASSERT_TRUE(lock.has_value());
  ASSERT_TRUE(lock->first == a_id);
  ASSERT_TRUE(wait_for_local_precommit(target, f->height, 0, a_id));
}

// Spec §6.2: prevotes split at round 0 (no polka, no lock); a fresh round-1 proposal finalizes.
TEST(test_split_prevotes_then_fresh_proposal_finalizes) {
  auto f = make_two_phase_fixture("/tmp/finalis_it_split_prevotes", 0x91);
  auto& target = f->target();
  const auto a_id = frontier_proposal_id(*f->a0);
  const auto b0_id = frontier_proposal_id(*f->b0);
  const auto b1_id = frontier_proposal_id(*f->b1);
  ASSERT_TRUE(advance_test_frontier_round(target, f->height, 0));
  ASSERT_EQ(target.inject_network_propose_result_for_test(make_test_frontier_propose_msg(f->target().consensus_domain_for_test(), *f->a0)),
            std::string("accepted"));
  ASSERT_TRUE(target.local_prevote_recorded_for_test(f->height, 0, a_id));
  // Others split: one prevotes A, the rest B0. Neither side reaches quorum with the target's prevote.
  std::vector<PubKey32> others;
  for (const auto& pub : f->committee) {
    if (pub != target.local_validator_pubkey_for_test()) others.push_back(pub);
  }
  ASSERT_EQ(target.inject_network_prevote_result_for_test(make_test_prevote(f->target().consensus_domain_for_test(), f->keys, f->height, 0, a_id, others[0])),
            std::string("accepted"));
  for (std::size_t i = 1; i < others.size(); ++i) {
    ASSERT_EQ(target.inject_network_prevote_result_for_test(make_test_prevote(f->target().consensus_domain_for_test(), f->keys, f->height, 0, b0_id, others[i])),
              std::string("accepted"));
  }
  ASSERT_TRUE(!target.valid_polka_for_height_for_test(f->height).has_value());
  ASSERT_TRUE(!target.local_vote_lock_for_test(f->height).has_value());

  const auto tc0 = make_test_timeout_certificate(f->target().consensus_domain_for_test(), f->keys, f->committee, f->height, 0, f->quorum);
  ASSERT_TRUE(advance_test_frontier_round(target, f->height, 1));
  ASSERT_EQ(target.inject_network_propose_result_for_test(make_test_frontier_propose_msg(f->target().consensus_domain_for_test(), *f->b1, std::nullopt, tc0)),
            std::string("accepted"));
  ASSERT_TRUE(target.local_prevote_recorded_for_test(f->height, 1, b1_id));
  inject_test_prevotes(target, f->keys, f->committee, f->height, 1, b1_id, f->quorum - 1);
  ASSERT_TRUE(wait_for_local_precommit(target, f->height, 1, b1_id));
  inject_test_precommits(target, f->keys, f->committee, f->height, 1, b1_id, f->quorum - 1);
  ASSERT_TRUE(wait_for([&]() { return target.status().height == f->height; }, std::chrono::seconds(5)));
  ASSERT_EQ(target.status().transition_hash, b1_id);
}

// Spec §6.5: A finalizes at round 0 by precommits the target has not seen yet. Locked on A, the
// target refuses a conflicting round-1 proposal, f Byzantine prevotes for it move nothing, and
// the late round-0 precommits still finalize A.
TEST(test_locked_node_refuses_conflict_and_late_round0_finality_completes) {
  auto f = make_two_phase_fixture("/tmp/finalis_it_locked_refuses_conflict", 0x92);
  auto& target = f->target();
  const auto a_id = frontier_proposal_id(*f->a0);
  const auto b1_id = frontier_proposal_id(*f->b1);
  ASSERT_TRUE(advance_test_frontier_round(target, f->height, 0));
  ASSERT_EQ(target.inject_network_propose_result_for_test(make_test_frontier_propose_msg(f->target().consensus_domain_for_test(), *f->a0)),
            std::string("accepted"));
  inject_test_prevotes(target, f->keys, f->committee, f->height, 0, a_id, f->quorum - 1);
  ASSERT_TRUE(target.local_vote_lock_for_test(f->height)->first == a_id);

  const auto tc0 = make_test_timeout_certificate(f->target().consensus_domain_for_test(), f->keys, f->committee, f->height, 0, f->quorum);
  ASSERT_TRUE(advance_test_frontier_round(target, f->height, 1));
  ASSERT_EQ(target.inject_network_propose_result_for_test(make_test_frontier_propose_msg(f->target().consensus_domain_for_test(), *f->b1, std::nullopt, tc0)),
            std::string("accepted"));
  ASSERT_TRUE(!target.local_prevote_recorded_for_test(f->height, 1, b1_id));
  const std::size_t f_faults = f->committee.size() - f->quorum;  // n - Q = f
  inject_test_prevotes(target, f->keys, f->committee, f->height, 1, b1_id, f_faults);
  ASSERT_TRUE(target.local_vote_lock_for_test(f->height)->first == a_id);
  ASSERT_TRUE(!target.local_vote_recorded_for_test(f->height, 1, b1_id));

  inject_test_precommits(target, f->keys, f->committee, f->height, 0, a_id, f->quorum - 1);
  ASSERT_TRUE(wait_for([&]() { return target.status().height == f->height; }, std::chrono::seconds(5)));
  ASSERT_EQ(target.status().transition_hash, a_id);
}

// Restart after prevoting, before the polka: the prevote record survives (no second prevote in
// the round) and the polka arriving after the restart still locks and precommits.
TEST(test_restart_between_prevote_and_precommit) {
  auto f = make_two_phase_fixture("/tmp/finalis_it_restart_mid_round", 0x93);
  const auto a_id = frontier_proposal_id(*f->a0);
  const auto b0_id = frontier_proposal_id(*f->b0);
  ASSERT_TRUE(advance_test_frontier_round(f->target(), f->height, 0));
  ASSERT_EQ(f->target().inject_network_propose_result_for_test(make_test_frontier_propose_msg(f->target().consensus_domain_for_test(), *f->a0)),
            std::string("accepted"));
  ASSERT_TRUE(f->target().local_prevote_recorded_for_test(f->height, 0, a_id));

  f->cluster.nodes[f->ti]->stop();
  f->cluster.nodes[f->ti].reset();
  // Restart isolated: a peer reconnect resets round state (received votes) and would race the test.
  f->cluster.configs[f->ti].disable_p2p = true;
  f->cluster.configs[f->ti].listen = false;
  f->cluster.configs[f->ti].p2p_port = 0;
  f->cluster.nodes[f->ti] = std::make_unique<node::Node>(f->cluster.configs[f->ti]);
  ASSERT_TRUE(f->target().init());
  ASSERT_TRUE(f->target().pause_proposals_for_test(true));
  f->target().start();
  auto& target = f->target();
  ASSERT_TRUE(target.local_prevote_recorded_for_test(f->height, 0, a_id));
  ASSERT_TRUE(advance_test_frontier_round(target, f->height, 0));

  ASSERT_EQ(target.inject_network_propose_result_for_test(make_test_frontier_propose_msg(f->target().consensus_domain_for_test(), *f->b0)),
            std::string("accepted"));
  ASSERT_TRUE(!target.local_prevote_recorded_for_test(f->height, 0, b0_id));
  ASSERT_EQ(target.inject_network_propose_result_for_test(make_test_frontier_propose_msg(f->target().consensus_domain_for_test(), *f->a0)),
            std::string("accepted"));
  inject_test_prevotes(target, f->keys, f->committee, f->height, 0, a_id, f->quorum - 1);
  ASSERT_TRUE(target.local_vote_lock_for_test(f->height)->first == a_id);
  ASSERT_TRUE(wait_for_local_precommit(target, f->height, 0, a_id));
}

// TLC counterexample (formal/two_phase_finality.tla, before the vote-round floor): a node prevotes A
// at round 0 and B at round 1, its round is reset to 0 (reconnect reset or restart), and a late
// round-0 polka for A arrives. Precommitting A at round 0 then lets A finalize at round 0 while
// B's round-1 polka (with this node's prevote) finalizes B. The node must not vote below the
// highest round it already voted in.
TEST(test_no_vote_below_highest_voted_round_after_round_reset) {
  auto f = make_two_phase_fixture("/tmp/finalis_it_vote_floor", 0x94);
  auto& target = f->target();
  const auto a_id = frontier_proposal_id(*f->a0);
  const auto b0_id = frontier_proposal_id(*f->b0);
  const auto b1_id = frontier_proposal_id(*f->b1);
  ASSERT_TRUE(advance_test_frontier_round(target, f->height, 0));
  ASSERT_EQ(target.inject_network_propose_result_for_test(make_test_frontier_propose_msg(f->target().consensus_domain_for_test(), *f->a0)),
            std::string("accepted"));
  ASSERT_TRUE(target.local_prevote_recorded_for_test(f->height, 0, a_id));
  const auto tc0 = make_test_timeout_certificate(f->target().consensus_domain_for_test(), f->keys, f->committee, f->height, 0, f->quorum);
  ASSERT_TRUE(advance_test_frontier_round(target, f->height, 1));
  ASSERT_EQ(target.inject_network_propose_result_for_test(make_test_frontier_propose_msg(f->target().consensus_domain_for_test(), *f->b1, std::nullopt, tc0)),
            std::string("accepted"));
  ASSERT_TRUE(target.local_prevote_recorded_for_test(f->height, 1, b1_id));

  // Round state reset to 0, then the late round-0 polka for A: no lock, no round-0 precommit.
  ASSERT_TRUE(advance_test_frontier_round(target, f->height, 0));
  inject_test_prevotes(target, f->keys, f->committee, f->height, 0, a_id, f->quorum - 1);
  ASSERT_TRUE(!target.local_vote_recorded_for_test(f->height, 0, a_id));
  ASSERT_TRUE(!target.local_vote_lock_for_test(f->height).has_value());
  // Round 0 stays closed to new prevotes; voting resumes once the node is back at round 1.
  (void)target.inject_network_propose_result_for_test(make_test_frontier_propose_msg(f->target().consensus_domain_for_test(), *f->b0));
  ASSERT_TRUE(!target.local_prevote_recorded_for_test(f->height, 0, b0_id));
  ASSERT_TRUE(advance_test_frontier_round(target, f->height, 1));
  inject_test_prevotes(target, f->keys, f->committee, f->height, 1, b1_id, f->quorum - 1);
  ASSERT_TRUE(wait_for_local_precommit(target, f->height, 1, b1_id));
}

TEST(test_restart_committee_deterministic_despite_epoch_ticket_order) {
  const auto keys = node::Node::deterministic_test_keypairs();
  ASSERT_TRUE(keys.size() >= 4u);
  const std::string base = unique_test_base("/tmp/finalis_it_ticket_order_determinism");
  std::uint64_t target_height = 0;
  std::uint64_t open_epoch = 0;
  storage::FinalizedCommitteeCheckpoint checkpoint;

  {
    auto cluster = make_cluster(base, 4, 4, 4);
    auto& nodes = cluster.nodes;
    ASSERT_TRUE(wait_for([&]() { return nodes[0]->status().height >= 12; }, std::chrono::seconds(120)));
    for (auto& n : nodes) n->pause_proposals_for_test(true);
    ASSERT_TRUE(wait_for_stable_same_tip(nodes, std::chrono::seconds(10)));
    target_height = nodes[0]->status().height + 1;
    open_epoch = consensus::committee_epoch_start(target_height, node::NodeConfig{}.network.committee_epoch_blocks);
  }

  const auto src = std::filesystem::path(base) / "node0";
  const auto a_path = std::filesystem::path(base) / "restart_a";
  const auto b_path = std::filesystem::path(base) / "restart_b";
  std::filesystem::remove_all(a_path);
  std::filesystem::remove_all(b_path);
  std::filesystem::copy(src, a_path, std::filesystem::copy_options::recursive);
  std::filesystem::copy(src, b_path, std::filesystem::copy_options::recursive);

  {
    storage::DB db;
    ASSERT_TRUE(db.open(a_path.string()));
    auto cp = db.get_finalized_committee_checkpoint(open_epoch);
    ASSERT_TRUE(cp.has_value());
    checkpoint = *cp;
    for (int i = 1; i <= 3; ++i) {
      consensus::EpochTicket ticket;
      ticket.epoch = open_epoch;
      ticket.participant_pubkey = keys[static_cast<std::size_t>(i)].public_key;
      ticket.challenge_anchor = checkpoint.epoch_seed;
      ticket.nonce = static_cast<std::uint64_t>(i);
      ticket.work_hash = consensus::make_epoch_ticket_work_hash(ticket.epoch, ticket.challenge_anchor,
                                                                ticket.participant_pubkey, ticket.nonce);
      ticket.source_height = target_height;
      ticket.origin = consensus::EpochTicketOrigin::NETWORK;
      ASSERT_TRUE(db.put_epoch_ticket(ticket));
    }
    db.close();
  }
  {
    storage::DB db;
    ASSERT_TRUE(db.open(b_path.string()));
    for (int i = 3; i >= 1; --i) {
      consensus::EpochTicket ticket;
      ticket.epoch = open_epoch;
      ticket.participant_pubkey = keys[static_cast<std::size_t>(i)].public_key;
      ticket.challenge_anchor = checkpoint.epoch_seed;
      ticket.nonce = static_cast<std::uint64_t>(i);
      ticket.work_hash = consensus::make_epoch_ticket_work_hash(ticket.epoch, ticket.challenge_anchor,
                                                                ticket.participant_pubkey, ticket.nonce);
      ticket.source_height = target_height;
      ticket.origin = consensus::EpochTicketOrigin::NETWORK;
      ASSERT_TRUE(db.put_epoch_ticket(ticket));
    }
    db.close();
  }

  node::NodeConfig cfg_a;
  cfg_a.allow_unencrypted_keystore = true;  // test fixture: no passphrase
  cfg_a.disable_p2p = true;
  cfg_a.node_id = 0;
  cfg_a.max_committee = 4;
  cfg_a.network.min_block_interval_ms = 100;
  cfg_a.network.round_timeout_ms = 200;
  cfg_a.db_path = a_path.string();
  cfg_a.genesis_path = base + "/genesis.json";
  cfg_a.allow_unsafe_genesis_override = true;
  cfg_a.validator_key_file = cfg_a.db_path + "/keystore/validator.json";
  cfg_a.validator_passphrase = "test-pass";

  node::NodeConfig cfg_b = cfg_a;
  cfg_b.db_path = b_path.string();
  cfg_b.validator_key_file = cfg_b.db_path + "/keystore/validator.json";

  node::Node restarted_a(cfg_a);
  node::Node restarted_b(cfg_b);
  ASSERT_TRUE(restarted_a.init());
  ASSERT_TRUE(restarted_b.init());
  ASSERT_EQ(restarted_a.committee_for_next_height_for_test(), restarted_b.committee_for_next_height_for_test());
  ASSERT_EQ(restarted_a.proposer_for_height_round_for_test(target_height, 0),
            restarted_b.proposer_for_height_round_for_test(target_height, 0));
}

TEST(test_bootstrap_join_request_auto_admits_after_finalization) {
  const std::string base = unique_test_base("/tmp/finalis_it_bootstrap_joiner_no_approval");
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);
  const std::string gpath = base + "/genesis.json";
  ASSERT_TRUE(write_empty_mainnet_bootstrap_genesis_file(gpath));

  node::NodeConfig cfg0;
  cfg0.allow_unencrypted_keystore = true;  // test fixture: no passphrase
  cfg0.node_id = 0;
  cfg0.dns_seeds = false;
  cfg0.network.default_seeds.clear();  // keep test nodes off the public mainnet seeds
  cfg0.db_path = base + "/node0";
  cfg0.p2p_port = reserve_test_port();
  if (cfg0.p2p_port == 0) return;
  cfg0.genesis_path = gpath;
  cfg0.allow_unsafe_genesis_override = true;
  cfg0.validator_min_bond_override = 1;
  cfg0.validator_bond_min_amount_override = 1;
  cfg0.validator_bond_max_amount_override = 1;
  cfg0.validator_warmup_blocks_override = 1;
  cfg0.network.min_block_interval_ms = 100;
  cfg0.network.round_timeout_ms = 200;
  cfg0.network.validator_join_admission_pow_difficulty_bits = 0;

  node::Node n0(cfg0);
  if (!n0.init()) return;
  n0.start();
  const auto port0 = n0.p2p_port_for_test();
  if (port0 == 0) {
    n0.stop();
    ASSERT_TRUE(false && "p2p_port_for_test() returned 0");
  }

  node::NodeConfig cfg1;
  cfg1.allow_unencrypted_keystore = true;  // test fixture: no passphrase
  cfg1.node_id = 1;
  cfg1.dns_seeds = false;
  cfg1.network.default_seeds.clear();  // keep test nodes off the public mainnet seeds
  cfg1.db_path = base + "/node1";
  cfg1.p2p_port = reserve_test_port();
  if (cfg1.p2p_port == 0) {
    n0.stop();
    return;
  }
  cfg1.genesis_path = gpath;
  cfg1.allow_unsafe_genesis_override = true;
  cfg1.validator_min_bond_override = 1;
  cfg1.validator_bond_min_amount_override = 1;
  cfg1.validator_bond_max_amount_override = 1;
  cfg1.validator_warmup_blocks_override = 1;
  cfg1.peers = {"127.0.0.1:" + std::to_string(port0)};
  cfg1.network.min_block_interval_ms = 100;
  cfg1.network.round_timeout_ms = 200;
  cfg1.network.validator_join_admission_pow_difficulty_bits = 0;

  node::Node n1(cfg1);
  if (!n1.init()) {
    n0.stop();
    return;
  }
  n1.start();

  ASSERT_TRUE(wait_for([&]() {
    const auto s0 = n0.status();
    const auto s1 = n1.status();
    return s0.established_peers >= 1 && s1.established_peers >= 1 && s1.height >= 5;
  }, ci_timeout_seconds(30)));

  const std::string leader_key_path = keystore::default_validator_keystore_path(cfg0.db_path);
  keystore::ValidatorKey leader_vk;
  std::string err;
  ASSERT_TRUE(keystore::load_validator_keystore(leader_key_path, "", &leader_vk, &err));

  const std::string key_path = keystore::default_validator_keystore_path(cfg1.db_path);
  keystore::ValidatorKey joiner_vk;
  ASSERT_TRUE(keystore::load_validator_keystore(key_path, "", &joiner_vk, &err));

  crypto::KeyPair leader_kp{Bytes(leader_vk.privkey.begin(), leader_vk.privkey.end()), leader_vk.pubkey};
  crypto::KeyPair joiner_kp{Bytes(joiner_vk.privkey.begin(), joiner_vk.privkey.end()), joiner_vk.pubkey};
  std::optional<Tx> request_tx;
  const auto sender_pkh = crypto::h160(Bytes(leader_kp.public_key.begin(), leader_kp.public_key.end()));
  ASSERT_TRUE(wait_for([&]() {
    storage::DB db;
    if (!db.open_readonly(cfg0.db_path)) return false;
    const auto chain_id = ChainId::from_config_and_db(cfg0.network, db, std::nullopt, "test", std::nullopt);
    ValidatorJoinAdmissionPowBuildContext pow_ctx{
        .network = &cfg0.network,
        .chain_id = &chain_id,
        .current_height = n0.status().height + 1,
        .finalized_hash_at_height = [&](std::uint64_t height) { return db.get_height_hash(height); },
    };
    request_tx = build_validator_join_request_tx(node_chain_domain(n0), 
        n0.find_utxos_by_pubkey_hash_for_test(sender_pkh), Bytes(leader_kp.private_key.begin(), leader_kp.private_key.end()),
        joiner_kp.public_key, Bytes(joiner_kp.private_key.begin(), joiner_kp.private_key.end()), joiner_kp.public_key, 1, 0,
        address::p2pkh_script_pubkey(sender_pkh), nullptr, &pow_ctx);
    db.close();
    return request_tx.has_value();
  }, ci_timeout_seconds(180)));
  const auto request_txid = request_tx->txid();
  {
    std::string ingress_error;
    std::vector<node::Node*> live_nodes{&n0, &n1};
    if (!append_live_certified_ingress_to_nodes(cfg0.db_path, live_nodes, {request_tx->serialize()}, 7, &ingress_error,
                                                &leader_kp)) {
      throw std::runtime_error("append two-node join request tx failed: " + ingress_error);
    }
  }

  bool finalized_request = wait_for([&]() {
    auto artifact = find_frontier_artifact_with_tx(base + "/node0", request_txid, n0.status().height);
    return artifact.has_value();
  }, ci_timeout_seconds(20));
  if (!finalized_request) {
    ASSERT_TRUE(n0.pause_proposals_for_test(true));
    ASSERT_TRUE(n1.pause_proposals_for_test(true));

    const auto target_height = n0.status().height + 1;
    auto proposal = build_test_frontier_proposal(n0, target_height, 0);
    ASSERT_TRUE(proposal.has_value());

    const auto committee = n0.committee_for_height_round_for_test(proposal->transition.height, proposal->transition.round);
    std::vector<FinalitySig> sigs;
    sigs.reserve(committee.size());
    for (const auto& member : committee) {
      const Bytes* private_key = nullptr;
      if (member == leader_kp.public_key) private_key = &leader_kp.private_key;
      if (member == joiner_kp.public_key) private_key = &joiner_kp.private_key;
      if (!private_key) continue;
      auto sig =
          crypto::ed25519_sign(vote_signing_message(n0.consensus_domain_for_test(), proposal->transition.height,
                                                    proposal->transition.round,
                                                    frontier_proposal_id(*proposal)),
                               *private_key);
      ASSERT_TRUE(sig.has_value());
      sigs.push_back(FinalitySig{member, *sig});
    }
    if (!inject_test_frontier_block(n0, *proposal, sigs)) {
      throw std::runtime_error("manual frontier block inject failed on leader: " + n0.last_test_hook_error_for_test());
    }
    if (!inject_test_frontier_block(n1, *proposal, sigs)) {
      throw std::runtime_error("manual frontier block inject failed on follower: " + n1.last_test_hook_error_for_test());
    }
    ASSERT_TRUE(n0.pause_proposals_for_test(false));
    ASSERT_TRUE(n1.pause_proposals_for_test(false));
    finalized_request = wait_for([&]() {
      auto artifact = find_frontier_artifact_with_tx(base + "/node0", request_txid, n0.status().height);
      return artifact.has_value();
    }, ci_timeout_seconds(40));
  }
  ASSERT_TRUE(finalized_request);
  if (!wait_for([&]() {
        auto a0 = find_frontier_artifact_with_tx(base + "/node0", request_txid, n0.status().height);
        auto a1 = find_frontier_artifact_with_tx(base + "/node1", request_txid, n1.status().height);
        return a0.has_value() && a1.has_value();
      }, ci_timeout_seconds(180))) {
    std::ostringstream oss;
    const auto s0 = n0.status();
    const auto s1 = n1.status();
    oss << "join request tx finalized on node0 but missing on node1:"
        << " n0{h=" << s0.height << ",peers=" << s0.peers << ",est=" << s0.established_peers
        << ",pending_joiners=" << s0.pending_bootstrap_joiners << "}"
        << " n1{h=" << s1.height << ",peers=" << s1.peers << ",est=" << s1.established_peers
        << ",pending_joiners=" << s1.pending_bootstrap_joiners << "}";
    throw std::runtime_error(oss.str());
  }

  if (!wait_for([&]() {
        auto info0 = n0.validator_info_for_test(joiner_vk.pubkey);
        auto info1 = n1.validator_info_for_test(joiner_vk.pubkey);
        return info0.has_value() && info1.has_value();
      }, ci_timeout_seconds(300))) {
    std::ostringstream oss;
    const auto s0 = n0.status();
    const auto s1 = n1.status();
    auto info0 = n0.validator_info_for_test(joiner_vk.pubkey);
    auto info1 = n1.validator_info_for_test(joiner_vk.pubkey);
    oss << "bootstrap joiner auto-admit missing validator record:"
        << " n0{h=" << s0.height << ",pending_joiners=" << s0.pending_bootstrap_joiners
        << ",validator_known=" << (info0.has_value() ? "yes" : "no") << "}"
        << " n1{h=" << s1.height << ",pending_joiners=" << s1.pending_bootstrap_joiners
        << ",validator_known=" << (info1.has_value() ? "yes" : "no") << "}";
    throw std::runtime_error(oss.str());
  }

  ASSERT_EQ(n0.status().pending_bootstrap_joiners, 0u);
  ASSERT_TRUE(wait_for([&]() {
    auto info0 = n0.validator_info_for_test(joiner_vk.pubkey);
    auto info1 = n1.validator_info_for_test(joiner_vk.pubkey);
    if (!info0.has_value() || !info1.has_value()) return false;
    return (info0->status == consensus::ValidatorStatus::PENDING || info0->status == consensus::ValidatorStatus::ACTIVE) &&
           (info1->status == consensus::ValidatorStatus::PENDING || info1->status == consensus::ValidatorStatus::ACTIVE);
  }, ci_timeout_seconds(30)));

  n1.stop();
  n0.stop();
}

TEST(test_late_joiner_requests_finalized_tip_and_catches_up) {
  const std::string base = unique_test_base("/tmp/finalis_it_late_joiner_catches_up");
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);
  const std::string gpath = base + "/genesis.json";
  ASSERT_TRUE(write_empty_mainnet_bootstrap_genesis_file(gpath));

  node::NodeConfig cfg0;
  cfg0.allow_unencrypted_keystore = true;  // test fixture: no passphrase
  cfg0.node_id = 0;
  cfg0.dns_seeds = false;
  cfg0.network.default_seeds.clear();  // keep test nodes off the public mainnet seeds
  cfg0.db_path = base + "/node0";
  cfg0.p2p_port = reserve_test_port();
  ASSERT_TRUE(cfg0.p2p_port != 0 && "Failed to reserve test port for cfg0");
  cfg0.genesis_path = gpath;
  cfg0.allow_unsafe_genesis_override = true;
  cfg0.network.min_block_interval_ms = 100;
  cfg0.network.round_timeout_ms = 200;

  node::Node n0(cfg0);
  ASSERT_TRUE(n0.init() && "n0.init() failed");
  n0.start();
  const auto port0 = n0.p2p_port_for_test();
  if (port0 == 0) {
    n0.stop();
    ASSERT_TRUE(false && "p2p_port_for_test() returned 0");
  }
  ASSERT_TRUE(wait_for_tip(n0, 12, std::chrono::seconds(20)));

  node::NodeConfig cfg1;
  cfg1.allow_unencrypted_keystore = true;  // test fixture: no passphrase
  cfg1.node_id = 1;
  cfg1.dns_seeds = false;
  cfg1.network.default_seeds.clear();  // keep test nodes off the public mainnet seeds
  cfg1.db_path = base + "/node1";
  cfg1.p2p_port = reserve_test_port();
  if (cfg1.p2p_port == 0) {
    n0.stop();
    return;
  }
  cfg1.genesis_path = gpath;
  cfg1.allow_unsafe_genesis_override = true;
  cfg1.peers = {"127.0.0.1:" + std::to_string(port0)};
  cfg1.network.min_block_interval_ms = 100;
  cfg1.network.round_timeout_ms = 200;

  node::Node n1(cfg1);
  if (!n1.init()) {
    n0.stop();
    return;
  }
  n1.start();

  ASSERT_TRUE(wait_for([&]() {
    const auto s0 = n0.status();
    const auto s1 = n1.status();
    return s0.height >= 12 && s1.height >= 12 && s0.height == s1.height && s0.transition_hash == s1.transition_hash;
  }, std::chrono::seconds(25)));

  const auto s0 = n0.status();
  const auto s1 = n1.status();
  ASSERT_TRUE(!s0.bootstrap_validator_pubkey.empty());
  ASSERT_EQ(s1.bootstrap_validator_pubkey, s0.bootstrap_validator_pubkey);
  ASSERT_EQ(n1.active_validators_for_next_height_for_test().size(), 1u);

  n1.stop();
  n0.stop();
}

TEST(test_late_joiner_crosses_live_handoff_and_keeps_following) {
  const std::string base = unique_test_base("/tmp/finalis_it_late_joiner_live_handoff");
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);
  const std::string gpath = base + "/genesis.json";
  ASSERT_TRUE(write_empty_mainnet_bootstrap_genesis_file(gpath));

  node::NodeConfig cfg0;
  cfg0.allow_unencrypted_keystore = true;  // test fixture: no passphrase
  cfg0.node_id = 0;
  cfg0.dns_seeds = false;
  cfg0.network.default_seeds.clear();  // keep test nodes off the public mainnet seeds
  cfg0.db_path = base + "/node0";
  cfg0.p2p_port = reserve_test_port();
  ASSERT_TRUE(cfg0.p2p_port != 0 && "Failed to reserve test port for cfg0");
  cfg0.genesis_path = gpath;
  cfg0.allow_unsafe_genesis_override = true;
  cfg0.network.min_block_interval_ms = 100;
  cfg0.network.round_timeout_ms = 200;

  node::Node n0(cfg0);
  ASSERT_TRUE(n0.init() && "n0.init() failed");
  n0.start();
  const auto port0 = n0.p2p_port_for_test();
  if (port0 == 0) {
    n0.stop();
    ASSERT_TRUE(false && "p2p_port_for_test() returned 0");
  }
  ASSERT_TRUE(wait_for_tip(n0, 24, ci_timeout_seconds(25)));

  node::NodeConfig cfg1;
  cfg1.allow_unencrypted_keystore = true;  // test fixture: no passphrase
  cfg1.node_id = 1;
  cfg1.dns_seeds = false;
  cfg1.network.default_seeds.clear();  // keep test nodes off the public mainnet seeds
  cfg1.db_path = base + "/node1";
  cfg1.p2p_port = reserve_test_port();
  if (cfg1.p2p_port == 0) {
    n0.stop();
    return;
  }
  cfg1.genesis_path = gpath;
  cfg1.allow_unsafe_genesis_override = true;
  cfg1.peers = {"127.0.0.1:" + std::to_string(port0)};
  cfg1.network.min_block_interval_ms = 100;
  cfg1.network.round_timeout_ms = 200;

  node::Node n1(cfg1);
  if (!n1.init()) {
    n0.stop();
    return;
  }
  n1.start();

  ASSERT_TRUE(wait_for([&]() {
    const auto s0 = n0.status();
    const auto s1 = n1.status();
    return s0.height >= 24 && s1.height >= 24 && s0.height == s1.height && s0.transition_hash == s1.transition_hash;
  }, ci_timeout_seconds(30)));

  const auto synced = n0.status().height;
  ASSERT_TRUE(synced >= 24);
  ASSERT_TRUE(wait_for([&]() {
    const auto s0 = n0.status();
    const auto s1 = n1.status();
    return s0.height >= synced + 4 && s1.height >= synced + 4 && s0.height == s1.height && s0.transition_hash == s1.transition_hash;
  }, ci_timeout_seconds(20)));

  n1.stop();
  n0.stop();
}

TEST(test_synced_follower_finalizes_from_propose_and_vote_without_block_redelivery) {
  const std::string base = unique_test_base("/tmp/finalis_it_propose_vote_finalize");
  const auto keys = node::Node::deterministic_test_keypairs();
  auto cluster = make_cluster(base, 2, 2, 2);
  auto& nodes = cluster.nodes;
  Tx tx = make_fixture_ingress_tx(1, 0x8F);
  ASSERT_TRUE(restart_cluster_with_seeded_certified_ingress(&cluster, {tx.serialize()}, true, true));

  auto& n0 = *nodes[0];
  auto& n1 = *nodes[1];
  const auto s0 = n0.status();
  const auto s1 = n1.status();
  ASSERT_EQ(s0.height, s1.height);
  ASSERT_EQ(s0.transition_hash, s1.transition_hash);

  const std::uint64_t next_height = s0.height + 1;
  const std::uint32_t round = 0;
  ASSERT_TRUE(advance_test_frontier_round(n0, next_height, round));
  const auto proposer = n0.proposer_for_height_round_for_test(next_height, round);
  ASSERT_TRUE(proposer.has_value());
  const int proposer_id = node_for_pub(keys, *proposer);
  ASSERT_TRUE(proposer_id >= 0);
  const int follower_id = proposer_id == 0 ? 1 : 0;
  auto& follower = *nodes[static_cast<std::size_t>(follower_id)];
  auto proposal = build_cluster_frontier_proposal_from_records(
      cluster, keys, {tx.serialize()}, next_height, round, "/tmp/finalis_it_propose_vote_finalize_builder");
  ASSERT_TRUE(proposal.has_value());
  ASSERT_TRUE(follower.inject_propose_msg_for_test(make_test_frontier_propose_msg(nodes[0]->consensus_domain_for_test(), *proposal)));

  Vote vote =
      make_test_vote(nodes[0]->consensus_domain_for_test(), keys, next_height, round, frontier_proposal_id(*proposal), keys[static_cast<std::size_t>(proposer_id)].public_key);
  Vote local_vote =
      make_test_vote(nodes[0]->consensus_domain_for_test(), keys, next_height, round, frontier_proposal_id(*proposal), keys[static_cast<std::size_t>(follower_id)].public_key);
  ASSERT_TRUE(follower.inject_vote_for_test(local_vote));
  ASSERT_TRUE(follower.inject_vote_for_test(vote));
  ASSERT_TRUE(wait_for([&]() {
    const auto follower_status = follower.status();
    return follower_status.height == next_height && follower_status.transition_hash == frontier_proposal_id(*proposal);
  }, std::chrono::seconds(5)));
}

TEST(test_redelivered_finalized_block_is_ignored) {
  const std::string base = unique_test_base("/tmp/finalis_it_finalized_redelivery");
  const auto keys = node::Node::deterministic_test_keypairs();
  auto cluster = make_cluster(base, 1, 1, MAX_COMMITTEE);
  auto& nodes = cluster.nodes;
  Tx tx = make_fixture_ingress_tx(1, 0x8E);
  ASSERT_TRUE(restart_cluster_with_seeded_certified_ingress(&cluster, {tx.serialize()}, true, true));

  const auto next_height = nodes[0]->status().height + 1;
  const std::uint32_t round = 0;
  auto proposal = build_cluster_frontier_proposal_from_records(
      cluster, keys, {tx.serialize()}, next_height, round, "/tmp/finalis_it_finalized_redelivery_builder");
  ASSERT_TRUE(proposal.has_value());

  const auto committee = nodes[0]->committee_for_height_round_for_test(next_height, round);
  const auto quorum = consensus::quorum_threshold(committee.size());
  auto qc = make_test_frontier_qc(nodes[0]->consensus_domain_for_test(), keys, committee, *proposal, quorum);
  ASSERT_TRUE(qc.signatures.size() >= quorum);
  FinalityCertificate cert;
  cert.height = next_height;
  cert.round = round;
  cert.frontier_transition_id = frontier_proposal_id(*proposal);
  cert.quorum_threshold = static_cast<std::uint32_t>(quorum);
  cert.committee_members = committee;
  cert.signatures = qc.signatures;

  ASSERT_TRUE(nodes[0]->inject_frontier_transition_for_test(*proposal, cert));
  const auto before = nodes[0]->status();
  ASSERT_EQ(before.height, next_height);
  ASSERT_EQ(before.transition_hash, frontier_proposal_id(*proposal));

  ASSERT_TRUE(nodes[0]->inject_frontier_transition_for_test(*proposal, cert));

  const auto after = nodes[0]->status();
  ASSERT_EQ(after.height, before.height);
  ASSERT_EQ(after.transition_hash, before.transition_hash);
}

TEST(test_sync_peer_rejects_tampered_finalized_block_body) {
  const std::string base = unique_test_base("/tmp/finalis_it_reject_tampered_finalized_block");
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);
  const std::string gpath = base + "/genesis.json";
  ASSERT_TRUE(write_empty_mainnet_bootstrap_genesis_file(gpath));

  node::NodeConfig bootstrap_cfg;
  bootstrap_cfg.allow_unencrypted_keystore = true;  // test fixture: no passphrase
  bootstrap_cfg.node_id = 0;
  bootstrap_cfg.dns_seeds = false;
  bootstrap_cfg.network.default_seeds.clear();  // keep test nodes off the public mainnet seeds
  bootstrap_cfg.db_path = base + "/bootstrap";
  bootstrap_cfg.p2p_port = reserve_test_port();
  ASSERT_TRUE(bootstrap_cfg.p2p_port != 0 && "Failed to reserve test port for bootstrap");
  bootstrap_cfg.genesis_path = gpath;
  bootstrap_cfg.allow_unsafe_genesis_override = true;
  bootstrap_cfg.network.min_block_interval_ms = 100;
  bootstrap_cfg.network.round_timeout_ms = 200;

  node::Node bootstrap(bootstrap_cfg);
  ASSERT_TRUE(bootstrap.init() && "bootstrap.init() failed");
  bootstrap.start();
  ASSERT_TRUE(wait_for_tip(bootstrap, 3, std::chrono::seconds(15)));

  const auto bootstrap_status = bootstrap.status();
  auto bootstrap_pub = pubkey_from_hex32(bootstrap_status.bootstrap_validator_pubkey);
  ASSERT_TRUE(bootstrap_pub.has_value());
  auto a1 = load_frontier_artifact_at_height(bootstrap_cfg.db_path, 1);
  auto a2 = load_frontier_artifact_at_height(bootstrap_cfg.db_path, 2);
  auto a3 = load_frontier_artifact_at_height(bootstrap_cfg.db_path, 3);
  ASSERT_TRUE(a1.has_value());
  ASSERT_TRUE(a2.has_value());
  ASSERT_TRUE(a3.has_value());

  FrontierProposal tampered_proposal = a3->proposal;
  tampered_proposal.transition.next_frontier += 1;
  const auto tampered_height = tampered_proposal.transition.height;

  OutOfOrderBlockSyncServer server;
  std::map<Hash32, p2p::TransitionMsg> transitions;
  transitions.emplace(frontier_proposal_id(a1->proposal),
                      p2p::TransitionMsg{a1->proposal.serialize(), a1->certificate});
  transitions.emplace(frontier_proposal_id(a2->proposal),
                      p2p::TransitionMsg{a2->proposal.serialize(), a2->certificate});
  transitions.emplace(frontier_proposal_id(a3->proposal),
                      p2p::TransitionMsg{tampered_proposal.serialize(), a3->certificate});
  server.bootstrap_validator_bls_hex = bootstrap_validator_bls_hex_from_db(bootstrap_cfg.db_path);
  ASSERT_TRUE(server.start_transitions(bootstrap_cfg.network, bootstrap_status.genesis_hash, *bootstrap_pub, tampered_height,
                                       frontier_proposal_id(a3->proposal), std::move(transitions)));

  bootstrap.stop();

  node::NodeConfig follower_cfg;
  follower_cfg.allow_unencrypted_keystore = true;  // test fixture: no passphrase
  follower_cfg.node_id = 1;
  follower_cfg.dns_seeds = false;
  follower_cfg.network.default_seeds.clear();  // keep test nodes off the public mainnet seeds
  follower_cfg.db_path = base + "/follower";
  follower_cfg.p2p_port = reserve_test_port();
  if (follower_cfg.p2p_port == 0) {
    server.stop();
    return;
  }
  follower_cfg.genesis_path = gpath;
  follower_cfg.allow_unsafe_genesis_override = true;
  follower_cfg.peers = {"127.0.0.1:" + std::to_string(server.port)};

  node::Node follower(follower_cfg);
  if (!follower.init()) {
    server.stop();
    return;
  }
  follower.start();

  std::this_thread::sleep_for(std::chrono::seconds(5));
  const auto status = follower.status();
  ASSERT_TRUE(status.height < tampered_height);
  ASSERT_TRUE(status.transition_hash != frontier_proposal_id(a3->proposal));

  follower.stop();
  server.stop();
}

TEST(test_fresh_joiner_defer_consensus_until_sync_and_still_catches_up) {
  const std::string base = unique_test_base("/tmp/finalis_it_joiner_defers_consensus_until_sync");
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);
  const std::string gpath = base + "/genesis.json";
  ASSERT_TRUE(write_empty_mainnet_bootstrap_genesis_file(gpath));

  node::NodeConfig cfg0;
  cfg0.allow_unencrypted_keystore = true;  // test fixture: no passphrase
  cfg0.node_id = 0;
  cfg0.dns_seeds = false;
  cfg0.network.default_seeds.clear();  // keep test nodes off the public mainnet seeds
  cfg0.db_path = base + "/node0";
  cfg0.p2p_port = reserve_test_port();
  ASSERT_TRUE(cfg0.p2p_port != 0 && "Failed to reserve test port for cfg0");
  cfg0.genesis_path = gpath;
  cfg0.allow_unsafe_genesis_override = true;
  cfg0.network.min_block_interval_ms = 100;
  cfg0.network.round_timeout_ms = 200;

  node::Node n0(cfg0);
  ASSERT_TRUE(n0.init() && "n0.init() failed");
  n0.start();
  const auto port0 = n0.p2p_port_for_test();
  if (port0 == 0) {
    n0.stop();
    ASSERT_TRUE(false && "p2p_port_for_test() returned 0");
  }
  ASSERT_TRUE(wait_for_tip(n0, 8, std::chrono::seconds(20)));

  node::NodeConfig cfg1;
  cfg1.allow_unencrypted_keystore = true;  // test fixture: no passphrase
  cfg1.node_id = 1;
  cfg1.dns_seeds = false;
  cfg1.network.default_seeds.clear();  // keep test nodes off the public mainnet seeds
  cfg1.db_path = base + "/node1";
  cfg1.p2p_port = reserve_test_port();
  if (cfg1.p2p_port == 0) {
    n0.stop();
    return;
  }
  cfg1.genesis_path = gpath;
  cfg1.allow_unsafe_genesis_override = true;
  cfg1.peers = {"127.0.0.1:" + std::to_string(port0)};
  cfg1.network.min_block_interval_ms = 100;
  cfg1.network.round_timeout_ms = 200;

  node::Node n1(cfg1);
  if (!n1.init()) {
    n0.stop();
    return;
  }
  n1.start();

  ASSERT_TRUE(wait_for([&]() {
    const auto s1 = n1.status();
    return !s1.bootstrap_validator_pubkey.empty();
  }, std::chrono::seconds(10)));

  ASSERT_TRUE(wait_for([&]() {
    const auto s0 = n0.status();
    const auto s1 = n1.status();
    return s0.height >= 8 && s1.height >= 8 && s0.height == s1.height && s0.transition_hash == s1.transition_hash;
  }, std::chrono::seconds(25)));

  ASSERT_EQ(n1.active_validators_for_next_height_for_test().size(), 1u);

  n1.stop();
  n0.stop();
}

TEST(test_unregistered_follower_mines_epoch_tickets_without_joining_committee) {
  const std::string base = unique_test_base("/tmp/finalis_it_unregistered_follower_epoch_tickets");
  auto cluster = make_p2p_cluster(base, 1, 1, 1);
  auto& validator = cluster.nodes[0];

  node::NodeConfig follower_cfg;
  follower_cfg.allow_unencrypted_keystore = true;  // test fixture: no passphrase
  follower_cfg.node_id = 9;
  follower_cfg.dns_seeds = false;
  follower_cfg.network.default_seeds.clear();  // keep test nodes off the public mainnet seeds
  follower_cfg.listen = true;
  follower_cfg.bind_ip = "127.0.0.1";
  follower_cfg.db_path = base + "/follower";
  follower_cfg.p2p_port = reserve_test_port();
  ASSERT_TRUE(follower_cfg.p2p_port != 0);
  follower_cfg.genesis_path = base + "/genesis.json";
  follower_cfg.allow_unsafe_genesis_override = true;
  follower_cfg.validator_key_file = follower_cfg.db_path + "/keystore/validator.json";
  follower_cfg.validator_passphrase = "test-pass";
  follower_cfg.peers = {"127.0.0.1:" + std::to_string(validator->p2p_port_for_test())};
  follower_cfg.outbound_target = 1;
  follower_cfg.network.min_block_interval_ms = 100;
  follower_cfg.network.round_timeout_ms = 200;
  follower_cfg.max_committee = 1;
  ASSERT_TRUE(create_test_validator_keystore(follower_cfg, follower_cfg.node_id));

  node::Node follower(follower_cfg);
  ASSERT_TRUE(follower.init());
  follower.start();

  ASSERT_TRUE(wait_for([&]() {
    const auto sv = validator->status();
    const auto sf = follower.status();
    return sv.height >= 65 && sf.height == sv.height && sf.transition_hash == sv.transition_hash;
  }, ci_timeout_seconds(120)));

  const auto local_pub = follower.local_validator_pubkey_for_test();
  const auto active = follower.active_validators_for_next_height_for_test();
  ASSERT_TRUE(std::find(active.begin(), active.end(), local_pub) == active.end());

  const auto required_epoch = 33ULL;

  follower.stop();
  validator->stop();

  storage::DB db;
  ASSERT_TRUE(db.open_readonly(follower_cfg.db_path));
  const auto best = db.load_best_epoch_tickets(required_epoch);
  const auto snapshot = db.get_epoch_committee_snapshot(required_epoch);
  db.close();

  ASSERT_TRUE(best.find(local_pub) != best.end());
  ASSERT_TRUE(snapshot.has_value());
  ASSERT_TRUE(std::find(snapshot->ordered_members.begin(), snapshot->ordered_members.end(), local_pub) ==
              snapshot->ordered_members.end());
}

TEST(test_unregistered_follower_open_epoch_ticket_is_rejected_by_validator_and_unpaid) {
  // Open-epoch ticket intake is validator-only (reason=non-validator-open-epoch-source).
  const std::string base = unique_test_base("/tmp/finalis_it_unknown_follower_ticket_rejected");
  auto cluster = make_p2p_cluster(base, 1, 1, 1);
  auto& validator = cluster.nodes[0];

  node::NodeConfig follower_cfg;
  follower_cfg.allow_unencrypted_keystore = true;  // test fixture: no passphrase
  follower_cfg.node_id = 9;
  follower_cfg.dns_seeds = false;
  follower_cfg.network.default_seeds.clear();  // keep test nodes off the public mainnet seeds
  follower_cfg.listen = true;
  follower_cfg.bind_ip = "127.0.0.1";
  follower_cfg.db_path = base + "/follower";
  follower_cfg.p2p_port = reserve_test_port();
  ASSERT_TRUE(follower_cfg.p2p_port != 0);
  follower_cfg.genesis_path = base + "/genesis.json";
  follower_cfg.allow_unsafe_genesis_override = true;
  follower_cfg.validator_key_file = follower_cfg.db_path + "/keystore/validator.json";
  follower_cfg.validator_passphrase = "test-pass";
  follower_cfg.peers = {"127.0.0.1:" + std::to_string(validator->p2p_port_for_test())};
  follower_cfg.network.min_block_interval_ms = 100;
  follower_cfg.network.round_timeout_ms = 200;
  follower_cfg.max_committee = 1;
  ASSERT_TRUE(create_test_validator_keystore(follower_cfg, follower_cfg.node_id));

  node::Node follower(follower_cfg);
  ASSERT_TRUE(follower.init());
  follower.start();

  ASSERT_TRUE(wait_for([&]() {
    const auto sv = validator->status();
    const auto sf = follower.status();
    return sv.height >= 65 && sf.height == sv.height && sf.transition_hash == sv.transition_hash;
  }, ci_timeout_seconds(120)));

  const auto follower_pub = follower.local_validator_pubkey_for_test();
  follower.stop();
  validator->stop();

  // Precondition: the follower did mine an epoch-33 ticket locally.
  storage::DB follower_db;
  ASSERT_TRUE(follower_db.open_readonly(follower_cfg.db_path));
  const auto follower_best = follower_db.load_best_epoch_tickets(33);
  follower_db.close();
  ASSERT_TRUE(follower_best.find(follower_pub) != follower_best.end());

  storage::DB validator_db;
  ASSERT_TRUE(validator_db.open_readonly(base + "/node0"));
  const auto best = validator_db.load_best_epoch_tickets(33);
  auto artifact = load_frontier_artifact_at_height(base + "/node0", 65);
  validator_db.close();

  ASSERT_TRUE(best.find(follower_pub) == best.end());
  ASSERT_TRUE(artifact.has_value());

  std::uint64_t follower_units = 0;
  std::uint64_t total_units = 0;
  for (const auto& [pub, units] : artifact->proposal.transition.settlement.outputs) {
    total_units += units;
    if (pub == follower_pub) follower_units += units;
  }
  ASSERT_EQ(follower_units, 0u);
  ASSERT_EQ(total_units, artifact->proposal.transition.settlement.total);
}

TEST(test_follower_sync_does_not_reject_canonical_block_due_to_local_epoch_ticket) {
  const std::string base = unique_test_base("/tmp/finalis_it_non_active_follower_sync_past_epoch_boundary");
  auto cluster = make_p2p_cluster(base, 2, 2, 2);
  auto& validators = cluster.nodes;

  ASSERT_TRUE(wait_for([&]() {
    const auto s0 = validators[0]->status();
    const auto s1 = validators[1]->status();
    return s0.height >= 18 && s1.height >= 18 && s0.height == s1.height && s0.transition_hash == s1.transition_hash;
  }, ci_timeout_seconds(35)));

  for (auto& n : validators) ASSERT_TRUE(n->pause_proposals_for_test(true));
  ASSERT_TRUE(wait_for_same_tip(validators, ci_timeout_seconds(15)));
  const auto validator_status = validators[0]->status();

  node::NodeConfig follower_cfg;
  follower_cfg.allow_unencrypted_keystore = true;  // test fixture: no passphrase
  follower_cfg.node_id = 9;
  follower_cfg.dns_seeds = false;
  follower_cfg.network.default_seeds.clear();  // keep test nodes off the public mainnet seeds
  follower_cfg.listen = true;
  follower_cfg.db_path = base + "/follower";
  follower_cfg.p2p_port = reserve_test_port();
  ASSERT_TRUE(follower_cfg.p2p_port != 0 && "Failed to reserve test port for follower");
  follower_cfg.genesis_path = base + "/genesis.json";
  follower_cfg.allow_unsafe_genesis_override = true;
  follower_cfg.validator_key_file = follower_cfg.db_path + "/keystore/validator.json";
  follower_cfg.validator_passphrase = "test-pass";
  follower_cfg.peers = {"127.0.0.1:" + std::to_string(validators[0]->p2p_port_for_test())};
  follower_cfg.outbound_target = 1;
  ASSERT_TRUE(create_test_validator_keystore(follower_cfg, follower_cfg.node_id));

  node::Node follower(follower_cfg);
  ASSERT_TRUE(follower.init());
  follower.start();

  // Pausing stops new proposals, but one already proposed can still finalize after the snapshot
  // above, so the follower is compared with the validators' live tip (never below the snapshot).
  ASSERT_TRUE(wait_for([&]() {
    const auto sf = follower.status();
    const auto sv = validators[0]->status();
    return sv.height >= validator_status.height && sf.height == sv.height && sf.transition_hash == sv.transition_hash;
  }, ci_timeout_seconds(30)));

  const auto local_pub = follower.local_validator_pubkey_for_test();
  const auto committee = follower.committee_for_next_height_for_test();
  ASSERT_TRUE(std::find(committee.begin(), committee.end(), local_pub) == committee.end());
  ASSERT_EQ(follower.active_validators_for_next_height_for_test().size(), 2u);

  for (auto& n : validators) n->stop();
  follower.stop();
}

TEST(test_syncing_follower_reconstructs_same_next_height_checkpoint_as_validator) {
  const std::string base = unique_test_base("/tmp/finalis_it_follower_checkpoint_match");
  auto cluster = make_p2p_cluster(base, 2, 2, 2);
  auto& validators = cluster.nodes;
  const auto min_height =
      std::max<std::uint64_t>(18, node::NodeConfig{}.network.committee_epoch_blocks + 2);


  for (auto& n : validators) ASSERT_TRUE(n->pause_proposals_for_test(true));
  ASSERT_TRUE(wait_for_same_tip(validators, std::chrono::seconds(5)));

  node::NodeConfig follower_cfg;
  follower_cfg.allow_unencrypted_keystore = true;  // test fixture: no passphrase
  follower_cfg.node_id = 9;
  follower_cfg.dns_seeds = false;
  follower_cfg.network.default_seeds.clear();  // keep test nodes off the public mainnet seeds
  follower_cfg.db_path = base + "/follower";
  follower_cfg.p2p_port = reserve_test_port();
  if (follower_cfg.p2p_port == 0) {
    for (auto& n : validators) n->stop();
    return;
  }
  follower_cfg.genesis_path = base + "/genesis.json";
  follower_cfg.allow_unsafe_genesis_override = true;
  follower_cfg.validator_key_file = follower_cfg.db_path + "/keystore/validator.json";
  follower_cfg.validator_passphrase = "test-pass";
  follower_cfg.peers = {"127.0.0.1:" + std::to_string(validators[0]->p2p_port_for_test())};
  ASSERT_TRUE(create_test_validator_keystore(follower_cfg, follower_cfg.node_id));

  node::Node follower(follower_cfg);
  ASSERT_TRUE(follower.init());
  follower.start();

  ASSERT_TRUE(wait_for([&]() {
    const auto s0 = validators[0]->status();
    const auto s1 = validators[1]->status();
    const auto sf = follower.status();
    return s0.height == s1.height && s0.transition_hash == s1.transition_hash && sf.height == s0.height &&
           sf.transition_hash == s0.transition_hash;
  }, std::chrono::seconds(60)));

  const auto validator_status = validators[0]->status();
  const auto target_height = validator_status.height + 1;
  const auto epoch_start = consensus::committee_epoch_start(target_height, follower_cfg.network.committee_epoch_blocks);

  follower.stop();
  for (auto& n : validators) n->stop();

  storage::DB validator_db;
  ASSERT_TRUE(validator_db.open_readonly(base + "/node0"));
  auto validator_checkpoint = validator_db.get_finalized_committee_checkpoint(epoch_start);
  validator_db.close();

  storage::DB follower_db;
  ASSERT_TRUE(follower_db.open_readonly(follower_cfg.db_path));
  auto follower_checkpoint = follower_db.get_finalized_committee_checkpoint(epoch_start);
  follower_db.close();

  ASSERT_TRUE(validator_checkpoint.has_value());
  ASSERT_TRUE(follower_checkpoint.has_value());
  ASSERT_TRUE(same_finalized_checkpoint(*validator_checkpoint, *follower_checkpoint));
}

TEST(test_finalized_checkpoint_uses_persisted_epoch_ticket_winners) {
  const std::string base = unique_test_base("/tmp/finalis_it_checkpoint_uses_persisted_ticket_winners");
  auto cluster = make_p2p_cluster(base, 2, 2, 2);
  auto& validators = cluster.nodes;
  const auto min_height =
      std::max<std::uint64_t>(18, node::NodeConfig{}.network.committee_epoch_blocks + 2);

  ASSERT_TRUE(wait_for([&]() { return validators[0]->status().height >= min_height; }, ci_timeout_seconds(180)));
  ASSERT_TRUE(wait_for_same_tip(validators, std::chrono::seconds(5)));

  for (auto& n : validators) ASSERT_TRUE(n->pause_proposals_for_test(true));
  ASSERT_TRUE(wait_for_same_tip(validators, std::chrono::seconds(5)));
  const auto validator_status = validators[0]->status();
  const auto target_height = validator_status.height + 1;
  const auto epoch_start = consensus::committee_epoch_start(target_height, node::NodeConfig{}.network.committee_epoch_blocks);

  for (auto& n : validators) n->stop();

  storage::DB db;
  ASSERT_TRUE(db.open_readonly(base + "/node0"));
  auto checkpoint = db.get_finalized_committee_checkpoint(epoch_start);
  auto snapshot = db.get_epoch_committee_snapshot(epoch_start);
  db.close();

  ASSERT_TRUE(checkpoint.has_value());
  ASSERT_TRUE(snapshot.has_value());
  ASSERT_EQ(checkpoint->ordered_members, snapshot->ordered_members);
  ASSERT_EQ(checkpoint->ordered_ticket_hashes.size(), snapshot->selected_winners.size());
  ASSERT_EQ(checkpoint->ordered_ticket_nonces.size(), snapshot->selected_winners.size());
  for (std::size_t i = 0; i < snapshot->selected_winners.size(); ++i) {
    ASSERT_EQ(checkpoint->ordered_members[i], snapshot->selected_winners[i].participant_pubkey);
    ASSERT_EQ(checkpoint->ordered_ticket_hashes[i], snapshot->selected_winners[i].work_hash);
    ASSERT_EQ(checkpoint->ordered_ticket_nonces[i], snapshot->selected_winners[i].nonce);
  }
}

TEST(test_startup_repairs_stale_checkpoint_ticket_winners) {
  const std::string base = unique_test_base("/tmp/finalis_it_repair_stale_checkpoint_ticket_winners");
  const auto min_height =
      std::max<std::uint64_t>(18, node::NodeConfig{}.network.committee_epoch_blocks + 2);
  {
    auto cluster = make_p2p_cluster(base, 2, 2, 2);
    auto& validators = cluster.nodes;
    ASSERT_TRUE(wait_for([&]() { return validators[0]->status().height >= min_height; }, ci_timeout_seconds(120)));
    ASSERT_TRUE(wait_for_same_tip(validators, std::chrono::seconds(15)));
    for (auto& n : validators) ASSERT_TRUE(n->pause_proposals_for_test(true));
    ASSERT_TRUE(wait_for_same_tip(validators, std::chrono::seconds(15)));
    const auto target_height = validators[0]->status().height + 1;
    const auto epoch_start = consensus::committee_epoch_start(target_height, node::NodeConfig{}.network.committee_epoch_blocks);
    for (auto& n : validators) n->stop();

    storage::DB db;
    ASSERT_TRUE(db.open(base + "/node0"));
    auto checkpoint = db.get_finalized_committee_checkpoint(epoch_start);
    auto snapshot = db.get_epoch_committee_snapshot(epoch_start);
    ASSERT_TRUE(checkpoint.has_value());
    ASSERT_TRUE(snapshot.has_value());
    ASSERT_TRUE(finalized_checkpoint_matches_epoch_snapshot(*checkpoint, *snapshot));
    ASSERT_TRUE(!checkpoint->ordered_ticket_hashes.empty());
    checkpoint->ordered_ticket_hashes[0] = zero_hash();
    checkpoint->ordered_ticket_nonces[0] += 1;
    ASSERT_TRUE(db.put_finalized_committee_checkpoint(*checkpoint));
    db.close();

    node::NodeConfig cfg;
    cfg.allow_unencrypted_keystore = true;  // test fixture: no passphrase
    cfg.disable_p2p = true;
    cfg.node_id = 0;
    cfg.max_committee = 2;
    cfg.network.min_block_interval_ms = 100;
    cfg.network.round_timeout_ms = 200;
    cfg.p2p_port = 0;
    cfg.db_path = base + "/node0";
    cfg.genesis_path = base + "/genesis.json";
    cfg.allow_unsafe_genesis_override = true;
    cfg.validator_key_file = cfg.db_path + "/keystore/validator.json";
    cfg.validator_passphrase = "test-pass";

    node::Node restarted(cfg);
    ASSERT_TRUE(restarted.init());
    restarted.stop();

    storage::DB repaired_db;
    ASSERT_TRUE(repaired_db.open_readonly(base + "/node0"));
    auto repaired = repaired_db.get_finalized_committee_checkpoint(epoch_start);
    auto repaired_snapshot = repaired_db.get_epoch_committee_snapshot(epoch_start);
    repaired_db.close();
    ASSERT_TRUE(repaired.has_value());
    ASSERT_TRUE(repaired_snapshot.has_value());
    ASSERT_TRUE(finalized_checkpoint_matches_epoch_snapshot(*repaired, *repaired_snapshot));
  }
}

TEST(test_reconcile_rebuild_prefers_persisted_epoch_ticket_winners) {
  const std::string base = unique_test_base("/tmp/finalis_it_reconcile_rebuild_prefers_best_tickets");
  const auto min_height =
      std::max<std::uint64_t>(18, node::NodeConfig{}.network.committee_epoch_blocks + 2);
  {
    auto cluster = make_p2p_cluster(base, 2, 2, 2);
    auto& validators = cluster.nodes;
    ASSERT_TRUE(wait_for([&]() { return validators[0]->status().height >= min_height; }, ci_timeout_seconds(90)));
    ASSERT_TRUE(wait_for_same_tip(validators, std::chrono::seconds(5)));
    for (auto& n : validators) ASSERT_TRUE(n->pause_proposals_for_test(true));
    ASSERT_TRUE(wait_for_same_tip(validators, std::chrono::seconds(5)));
    const auto target_height = validators[0]->status().height + 1;
    const auto epoch_start = consensus::committee_epoch_start(target_height, node::NodeConfig{}.network.committee_epoch_blocks);
    for (auto& n : validators) n->stop();

    storage::DB db;
    ASSERT_TRUE(db.open(base + "/node0"));
    auto checkpoint = db.get_finalized_committee_checkpoint(epoch_start);
    auto snapshot = db.get_epoch_committee_snapshot(epoch_start);
    auto best_tickets = db.load_best_epoch_tickets(epoch_start);
    ASSERT_TRUE(checkpoint.has_value());
    ASSERT_TRUE(snapshot.has_value());
    ASSERT_TRUE(!best_tickets.empty());
    checkpoint->ordered_ticket_hashes[0] = zero_hash();
    checkpoint->ordered_ticket_nonces[0] += 1;
    snapshot->selected_winners[0].work_hash = zero_hash();
    snapshot->selected_winners[0].nonce += 1;
    ASSERT_TRUE(db.put_finalized_committee_checkpoint(*checkpoint));
    ASSERT_TRUE(db.put_epoch_committee_snapshot(*snapshot));
    db.close();

    node::NodeConfig cfg;
    cfg.allow_unencrypted_keystore = true;  // test fixture: no passphrase
    cfg.disable_p2p = true;
    cfg.node_id = 0;
    cfg.max_committee = 2;
    cfg.network.min_block_interval_ms = 100;
    cfg.network.round_timeout_ms = 200;
    cfg.p2p_port = 0;
    cfg.db_path = base + "/node0";
    cfg.genesis_path = base + "/genesis.json";
    cfg.allow_unsafe_genesis_override = true;
    cfg.validator_key_file = cfg.db_path + "/keystore/validator.json";
    cfg.validator_passphrase = "test-pass";

    node::Node restarted(cfg);
    ASSERT_TRUE(restarted.init());
    restarted.stop();

    storage::DB repaired_db;
    ASSERT_TRUE(repaired_db.open_readonly(base + "/node0"));
    auto repaired = repaired_db.get_finalized_committee_checkpoint(epoch_start);
    auto repaired_snapshot = repaired_db.get_epoch_committee_snapshot(epoch_start);
    repaired_db.close();
    ASSERT_TRUE(repaired.has_value());
    ASSERT_TRUE(repaired_snapshot.has_value());
    ASSERT_TRUE(finalized_checkpoint_matches_epoch_snapshot(*repaired, *repaired_snapshot));
    ASSERT_TRUE(repaired->ordered_ticket_hashes[0] != zero_hash());
  }
}

TEST(test_syncing_follower_accepts_canonical_block_after_checkpoint_rebuild) {
  const std::string base = unique_test_base("/tmp/finalis_it_follower_accepts_canonical_after_checkpoint");
  auto cluster = make_p2p_cluster(base, 2, 2, 2);
  auto& validators = cluster.nodes;

  ASSERT_TRUE(wait_for([&]() { return validators[0]->status().height >= 32; }, ci_timeout_seconds(90)));
  ASSERT_TRUE(wait_for_same_tip(validators, std::chrono::seconds(5)));

  ASSERT_TRUE(wait_for([&]() {
    const auto s0 = validators[0]->status();
    const auto s1 = validators[1]->status();
    return s0.height >= 48 && s1.height == s0.height && s1.transition_hash == s0.transition_hash;
  }, ci_timeout_seconds(140)));

  for (auto& n : validators) ASSERT_TRUE(n->pause_proposals_for_test(true));
  ASSERT_TRUE(wait_for_same_tip(validators, std::chrono::seconds(20)));
  const auto target_tip = validators[0]->status();

  node::NodeConfig follower_cfg;
  follower_cfg.allow_unencrypted_keystore = true;  // test fixture: no passphrase
  follower_cfg.node_id = 9;
  follower_cfg.dns_seeds = false;
  follower_cfg.network.default_seeds.clear();  // keep test nodes off the public mainnet seeds
  follower_cfg.listen = false;
  follower_cfg.db_path = base + "/follower";
  follower_cfg.p2p_port = 0;
  follower_cfg.genesis_path = base + "/genesis.json";
  follower_cfg.allow_unsafe_genesis_override = true;
  follower_cfg.validator_key_file = follower_cfg.db_path + "/keystore/validator.json";
  follower_cfg.validator_passphrase = "test-pass";
  follower_cfg.peers = {"127.0.0.1:" + std::to_string(validators[0]->p2p_port_for_test()),
                        "127.0.0.1:" + std::to_string(validators[1]->p2p_port_for_test())};
  follower_cfg.outbound_target = 1;
  ASSERT_TRUE(create_test_validator_keystore(follower_cfg, 0));

  node::Node follower(follower_cfg);
  ASSERT_TRUE(follower.init());
  follower.start();
  ASSERT_TRUE(wait_for_peer_count(follower, 1, ci_timeout_seconds(120)));

  auto wait_for_follower_catchup_with_progress = [&]() {
    const auto overall_timeout = ci_timeout_seconds(240);
    const auto stall_timeout = ci_timeout_seconds(150);
    const auto start = std::chrono::steady_clock::now();
    auto last_progress = start;
    auto last = follower.status();

    while (std::chrono::steady_clock::now() - start < overall_timeout) {
      const auto s0 = validators[0]->status();
      const auto s1 = validators[1]->status();
      const auto sf = follower.status();
      const bool validators_same_tip = s0.height == s1.height && s0.transition_hash == s1.transition_hash;
      const bool follower_matches_validator_tip =
          validators_same_tip && sf.height == s0.height && sf.transition_hash == s0.transition_hash;
      if (follower_matches_validator_tip && sf.height >= target_tip.height) {
        return true;
      }

      if (sf.height > last.height || sf.transition_hash != last.transition_hash) {
        last = sf;
        last_progress = std::chrono::steady_clock::now();
      } else if (std::chrono::steady_clock::now() - last_progress > stall_timeout) {
        return false;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
    return false;
  };
  if (!wait_for_follower_catchup_with_progress()) {
    const auto sf = follower.status();
    const auto last_err = follower.last_test_hook_error_for_test();
    std::ostringstream oss;
    oss << "follower failed to catch validator tip:"
        << " follower{h=" << sf.height << ",peers=" << sf.peers << ",est=" << sf.established_peers << "}"
        << " target{h=" << target_tip.height << "}";
    if (!last_err.empty()) oss << " last_error={" << last_err << "}";
    throw std::runtime_error(oss.str());
  }

  ASSERT_TRUE(follower.pause_proposals_for_test(true));
  ASSERT_TRUE(wait_for([&]() {
    const auto s0 = validators[0]->status();
    const auto s1 = validators[1]->status();
    const auto sf = follower.status();
    return s0.height == s1.height && s0.transition_hash == s1.transition_hash && sf.height == s0.height &&
           sf.transition_hash == s0.transition_hash;
  }, std::chrono::seconds(20)));

  const auto follower_next_height = follower.status().height + 1;
  ASSERT_EQ(follower.proposer_for_height_round_for_test(follower_next_height, 0),
            validators[0]->proposer_for_height_round_for_test(follower_next_height, 0));

  follower.stop();
  for (auto& n : validators) n->stop();
}

TEST(test_synced_joiner_keeps_outbound_peer_alive_with_short_idle_timeout) {
  const std::string base = unique_test_base("/tmp/finalis_it_joiner_keepalive_short_idle");
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);
  const std::string gpath = base + "/genesis.json";
  ASSERT_TRUE(write_empty_mainnet_bootstrap_genesis_file(gpath));

  node::NodeConfig cfg0;
  cfg0.allow_unencrypted_keystore = true;  // test fixture: no passphrase
  cfg0.node_id = 0;
  cfg0.dns_seeds = false;
  cfg0.network.default_seeds.clear();  // keep test nodes off the public mainnet seeds
  cfg0.db_path = base + "/node0";
  cfg0.p2p_port = reserve_test_port();
  ASSERT_TRUE(cfg0.p2p_port != 0 && "Failed to reserve test port for cfg0");
  cfg0.genesis_path = gpath;
  cfg0.allow_unsafe_genesis_override = true;
  cfg0.idle_timeout_ms = 1200;
  cfg0.network.min_block_interval_ms = 100;
  cfg0.network.round_timeout_ms = 200;

  node::Node n0(cfg0);
  ASSERT_TRUE(n0.init() && "n0.init() failed");
  n0.start();
  const auto port0 = n0.p2p_port_for_test();
  if (port0 == 0) {
    n0.stop();
    ASSERT_TRUE(false && "p2p_port_for_test() returned 0");
  }
  ASSERT_TRUE(wait_for_tip(n0, 5, std::chrono::seconds(15)));

  node::NodeConfig cfg1;
  cfg1.allow_unencrypted_keystore = true;  // test fixture: no passphrase
  cfg1.node_id = 1;
  cfg1.dns_seeds = false;
  cfg1.network.default_seeds.clear();  // keep test nodes off the public mainnet seeds
  cfg1.db_path = base + "/node1";
  cfg1.p2p_port = reserve_test_port();
  if (cfg1.p2p_port == 0) {
    n0.stop();
    return;
  }
  cfg1.genesis_path = gpath;
  cfg1.allow_unsafe_genesis_override = true;
  cfg1.idle_timeout_ms = 1200;
  cfg1.peers = {"127.0.0.1:" + std::to_string(port0)};
  cfg1.network.min_block_interval_ms = 100;
  cfg1.network.round_timeout_ms = 200;

  node::Node n1(cfg1);
  if (!n1.init()) {
    n0.stop();
    return;
  }
  n1.start();

  ASSERT_TRUE(wait_for([&]() {
    const auto s0 = n0.status();
    const auto s1 = n1.status();
    return s0.height >= 5 && s1.height >= 5 && s0.height == s1.height && s0.transition_hash == s1.transition_hash;
  }, std::chrono::seconds(20)));

  std::this_thread::sleep_for(std::chrono::seconds(4));

  const auto s0 = n0.status();
  const auto s1 = n1.status();
  ASSERT_TRUE(s0.established_peers >= 1u);
  ASSERT_TRUE(s1.established_peers >= 1u);
  ASSERT_TRUE(s0.height >= 5u);
  ASSERT_TRUE(s1.height >= 5u);

  n1.stop();
  n0.stop();
}

TEST(test_out_of_order_block_sync_requests_parents_and_replays_buffered_descendants) {
  const std::string base = unique_test_base("/tmp/finalis_it_out_of_order_block_sync");
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);
  const std::string gpath = base + "/genesis.json";
  ASSERT_TRUE(write_empty_mainnet_bootstrap_genesis_file(gpath));

  node::NodeConfig bootstrap_cfg;
  bootstrap_cfg.allow_unencrypted_keystore = true;  // test fixture: no passphrase
  bootstrap_cfg.node_id = 0;
  bootstrap_cfg.dns_seeds = false;
  bootstrap_cfg.network.default_seeds.clear();  // keep test nodes off the public mainnet seeds
  bootstrap_cfg.db_path = base + "/bootstrap";
  bootstrap_cfg.p2p_port = reserve_test_port();
  ASSERT_TRUE(bootstrap_cfg.p2p_port != 0 && "Failed to reserve test port for bootstrap");
  bootstrap_cfg.genesis_path = gpath;
  bootstrap_cfg.allow_unsafe_genesis_override = true;
  bootstrap_cfg.network.min_block_interval_ms = 100;
  bootstrap_cfg.network.round_timeout_ms = 200;

  node::Node bootstrap(bootstrap_cfg);
  ASSERT_TRUE(bootstrap.init() && "bootstrap.init() failed");
  bootstrap.start();
  ASSERT_TRUE(wait_for_tip(bootstrap, 3, std::chrono::seconds(15)));

  const auto bootstrap_status = bootstrap.status();
  auto bootstrap_pub = pubkey_from_hex32(bootstrap_status.bootstrap_validator_pubkey);
  ASSERT_TRUE(bootstrap_pub.has_value());
  auto a1 = load_frontier_artifact_at_height(bootstrap_cfg.db_path, 1);
  auto a2 = load_frontier_artifact_at_height(bootstrap_cfg.db_path, 2);
  auto a3 = load_frontier_artifact_at_height(bootstrap_cfg.db_path, 3);
  ASSERT_TRUE(a1.has_value());
  ASSERT_TRUE(a2.has_value());
  ASSERT_TRUE(a3.has_value());

  OutOfOrderBlockSyncServer server;
  server.consensus_rules_fingerprint = bootstrap.consensus_rules_fingerprint_for_test();
  std::map<Hash32, p2p::TransitionMsg> transitions;
  transitions.emplace(frontier_proposal_id(a1->proposal),
                      p2p::TransitionMsg{a1->proposal.serialize(), a1->certificate});
  transitions.emplace(frontier_proposal_id(a2->proposal),
                      p2p::TransitionMsg{a2->proposal.serialize(), a2->certificate});
  transitions.emplace(frontier_proposal_id(a3->proposal),
                      p2p::TransitionMsg{a3->proposal.serialize(), a3->certificate});
  server.bootstrap_validator_bls_hex = bootstrap_validator_bls_hex_from_db(bootstrap_cfg.db_path);
  ASSERT_TRUE(server.start_transitions(bootstrap_cfg.network, bootstrap_status.genesis_hash, *bootstrap_pub, 3,
                                       frontier_proposal_id(a3->proposal), std::move(transitions)));

  bootstrap.stop();

  node::NodeConfig follower_cfg;
  follower_cfg.allow_unencrypted_keystore = true;  // test fixture: no passphrase
  follower_cfg.node_id = 1;
  follower_cfg.dns_seeds = false;
  follower_cfg.network.default_seeds.clear();  // keep test nodes off the public mainnet seeds
  follower_cfg.db_path = base + "/follower";
  follower_cfg.p2p_port = reserve_test_port();
  if (follower_cfg.p2p_port == 0) {
    server.stop();
    return;
  }
  follower_cfg.genesis_path = gpath;
  follower_cfg.allow_unsafe_genesis_override = true;
  follower_cfg.peers = {"127.0.0.1:" + std::to_string(server.port)};
  follower_cfg.network.min_block_interval_ms = 100;
  follower_cfg.network.round_timeout_ms = 200;

  node::Node follower(follower_cfg);
  if (!follower.init()) {
    server.stop();
    return;
  }
  follower.start();

  ASSERT_TRUE(wait_for([&]() {
    const auto s = follower.status();
    return s.height >= 3 && s.transition_hash == frontier_proposal_id(a3->proposal);
  }, std::chrono::seconds(20)));

  server.stop();
  follower.stop();

  const auto requested = server.requested_hashes_snapshot();
  ASSERT_TRUE(requested.size() >= 3u);
  ASSERT_TRUE(std::find(requested.begin(), requested.end(), frontier_proposal_id(a1->proposal)) != requested.end());
  ASSERT_TRUE(std::find(requested.begin(), requested.end(), frontier_proposal_id(a2->proposal)) != requested.end());
  ASSERT_TRUE(std::find(requested.begin(), requested.end(), frontier_proposal_id(a3->proposal)) != requested.end());
  ASSERT_EQ(follower.active_validators_for_next_height_for_test().size(), 1u);
}

TEST(test_out_of_order_block_sync_recovers_after_disconnect_and_retries_parents) {
  const std::string base = unique_test_base("/tmp/finalis_it_out_of_order_block_sync_retry");
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);
  const std::string gpath = base + "/genesis.json";
  ASSERT_TRUE(write_empty_mainnet_bootstrap_genesis_file(gpath));

  node::NodeConfig bootstrap_cfg;
  bootstrap_cfg.allow_unencrypted_keystore = true;  // test fixture: no passphrase
  bootstrap_cfg.node_id = 0;
  bootstrap_cfg.dns_seeds = false;
  bootstrap_cfg.network.default_seeds.clear();  // keep test nodes off the public mainnet seeds
  bootstrap_cfg.db_path = base + "/bootstrap";
  bootstrap_cfg.p2p_port = reserve_test_port();
  ASSERT_TRUE(bootstrap_cfg.p2p_port != 0 && "Failed to reserve test port for bootstrap");
  bootstrap_cfg.genesis_path = gpath;
  bootstrap_cfg.allow_unsafe_genesis_override = true;
  bootstrap_cfg.network.min_block_interval_ms = 100;
  bootstrap_cfg.network.round_timeout_ms = 200;

  node::Node bootstrap(bootstrap_cfg);
  ASSERT_TRUE(bootstrap.init() && "bootstrap.init() failed");
  bootstrap.start();
  ASSERT_TRUE(wait_for_tip(bootstrap, 3, std::chrono::seconds(15)));

  const auto bootstrap_status = bootstrap.status();
  auto bootstrap_pub = pubkey_from_hex32(bootstrap_status.bootstrap_validator_pubkey);
  ASSERT_TRUE(bootstrap_pub.has_value());
  auto a1 = load_frontier_artifact_at_height(bootstrap_cfg.db_path, 1);
  auto a2 = load_frontier_artifact_at_height(bootstrap_cfg.db_path, 2);
  auto a3 = load_frontier_artifact_at_height(bootstrap_cfg.db_path, 3);
  ASSERT_TRUE(a1.has_value());
  ASSERT_TRUE(a2.has_value());
  ASSERT_TRUE(a3.has_value());

  OutOfOrderBlockSyncServer server;
  std::map<Hash32, p2p::TransitionMsg> transitions;
  transitions.emplace(frontier_proposal_id(a1->proposal),
                      p2p::TransitionMsg{a1->proposal.serialize(), a1->certificate});
  transitions.emplace(frontier_proposal_id(a2->proposal),
                      p2p::TransitionMsg{a2->proposal.serialize(), a2->certificate});
  transitions.emplace(frontier_proposal_id(a3->proposal),
                      p2p::TransitionMsg{a3->proposal.serialize(), a3->certificate});
  server.bootstrap_validator_bls_hex = bootstrap_validator_bls_hex_from_db(bootstrap_cfg.db_path);
  ASSERT_TRUE(server.start_transitions(bootstrap_cfg.network, bootstrap_status.genesis_hash, *bootstrap_pub, 3,
                                       frontier_proposal_id(a3->proposal), std::move(transitions), 2));

  bootstrap.stop();

  auto connect_client = [&](const NetworkConfig& net) {
    const auto cfd = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ASSERT_TRUE(finalis::net::valid_socket(cfd));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(server.port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ASSERT_EQ(::connect(cfd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)), 0);
    return cfd;
  };
  auto handshake = [&](finalis::net::SocketHandle cfd, const NetworkConfig& net) {
    p2p::VersionMsg v;
    v.proto_version = static_cast<std::uint32_t>(net.protocol_version);
    v.network_id = net.network_id;
    v.feature_flags = net.feature_flags;
    v.timestamp = static_cast<std::uint64_t>(::time(nullptr));
    v.nonce = 9001;
    v.start_height = 0;
    v.start_hash = zero_hash();
    v.node_software_version = "finalis-tests/retry-client";
    ASSERT_TRUE(p2p::write_frame_fd(cfd, p2p::Frame{p2p::MsgType::VERSION, p2p::ser_version(v)}, net.magic, net.protocol_version));
    auto version = p2p::read_frame_fd_timed(cfd, net.max_payload_len, net.magic, net.protocol_version, 5000, 3000, nullptr, nullptr);
    ASSERT_TRUE(version.has_value());
    ASSERT_EQ(version->msg_type, p2p::MsgType::VERSION);
    ASSERT_TRUE(p2p::write_frame_fd(cfd, p2p::Frame{p2p::MsgType::VERACK, {}}, net.magic, net.protocol_version));
    bool saw_verack = false;
    bool saw_tip = false;
    ASSERT_TRUE(wait_for([&]() {
      auto frame =
          p2p::read_frame_fd_timed(cfd, net.max_payload_len, net.magic, net.protocol_version, 5000, 3000, nullptr, nullptr);
      if (!frame.has_value()) return false;
      if (frame->msg_type == p2p::MsgType::VERACK) saw_verack = true;
      if (frame->msg_type == p2p::MsgType::FINALIZED_TIP) saw_tip = true;
      return saw_verack && saw_tip;
    }, std::chrono::seconds(5)));
  };
  auto request_height_expect_transition = [&](finalis::net::SocketHandle cfd, const NetworkConfig& net, std::uint64_t height,
                                              const Hash32& expected_hash) {
    ASSERT_TRUE(p2p::write_frame_fd(cfd, p2p::Frame{p2p::MsgType::GET_TRANSITION_BY_HEIGHT,
                                                    p2p::ser_get_transition_by_height(p2p::GetTransitionByHeightMsg{height})},
                                    net.magic, net.protocol_version));
    auto frame = p2p::read_frame_fd_timed(cfd, net.max_payload_len, net.magic, net.protocol_version, 5000, 3000, nullptr, nullptr);
    ASSERT_TRUE(frame.has_value());
    ASSERT_EQ(frame->msg_type, p2p::MsgType::TRANSITION);
    auto msg = p2p::de_transition(frame->payload);
    ASSERT_TRUE(msg.has_value());
    auto proposal = FrontierProposal::parse(msg->frontier_proposal_bytes);
    ASSERT_TRUE(proposal.has_value());
    ASSERT_EQ(frontier_proposal_id(*proposal), expected_hash);
  };

  const auto a1_hash = frontier_proposal_id(a1->proposal);
  const auto a2_hash = frontier_proposal_id(a2->proposal);
  const auto a3_hash = frontier_proposal_id(a3->proposal);

  const auto first = connect_client(bootstrap_cfg.network);
  handshake(first, bootstrap_cfg.network);
  request_height_expect_transition(first, bootstrap_cfg.network, 3, a3_hash);
  ASSERT_TRUE(p2p::write_frame_fd(first, p2p::Frame{p2p::MsgType::GET_TRANSITION_BY_HEIGHT,
                                                    p2p::ser_get_transition_by_height(p2p::GetTransitionByHeightMsg{2})},
                                  bootstrap_cfg.network.magic, bootstrap_cfg.network.protocol_version));
  auto dropped =
      p2p::read_frame_fd_timed(first, bootstrap_cfg.network.max_payload_len, bootstrap_cfg.network.magic,
                               bootstrap_cfg.network.protocol_version, 2000, 1000, nullptr, nullptr);
  ASSERT_TRUE(!dropped.has_value());
  finalis::net::shutdown_socket(first);
  finalis::net::close_socket(first);

  const auto second = connect_client(bootstrap_cfg.network);
  handshake(second, bootstrap_cfg.network);
  request_height_expect_transition(second, bootstrap_cfg.network, 2, a2_hash);
  request_height_expect_transition(second, bootstrap_cfg.network, 1, a1_hash);
  finalis::net::shutdown_socket(second);
  finalis::net::close_socket(second);
  server.stop();

  const auto requested = server.requested_hashes_snapshot();
  ASSERT_TRUE(requested.size() >= 4u);
  ASSERT_TRUE(std::find(requested.begin(), requested.end(), a1_hash) != requested.end());
  ASSERT_TRUE(std::find(requested.begin(), requested.end(), a2_hash) != requested.end());
  ASSERT_TRUE(std::find(requested.begin(), requested.end(), a3_hash) != requested.end());
  ASSERT_TRUE(std::count(requested.begin(), requested.end(), a2_hash) >= 2);
}

// The node also pushes unsolicited frames (tip/ingress gossip, proposals) to a fresh peer; skip them
// and return only a TRANSITION that arrives before the deadline.
std::optional<p2p::Frame> read_transition_frame_fd(finalis::net::SocketHandle fd, const NetworkConfig& network, int timeout_ms) {
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
  while (true) {
    const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count();
    if (left <= 0) return std::nullopt;
    auto frame = p2p::read_frame_fd_timed(fd, network.max_payload_len, network.magic, network.protocol_version,
                                          static_cast<int>(left), 1000, nullptr, nullptr);
    if (!frame.has_value()) return std::nullopt;
    if (frame->msg_type == p2p::MsgType::TRANSITION) return frame;
  }
}

TEST(test_get_transition_by_height_rate_limits_same_peer_same_height) {
  const std::string base = unique_test_base("/tmp/finalis_it_get_by_height_rate_limit_same_height");
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);

  auto cfg = single_node_cfg(base, 1);
  cfg.disable_p2p = false;  // these tests talk to the node's P2P listener directly
  cfg.listen = true;
  cfg.bind_ip = "127.0.0.1";
  cfg.p2p_port = reserve_test_ports(1).at(0);
  cfg.dns_seeds = false;
  cfg.network.default_seeds.clear();  // keep test nodes off the public mainnet seeds
  cfg.network.min_block_interval_ms = 50;
  cfg.network.round_timeout_ms = 120;
  ASSERT_TRUE(write_mainnet_genesis_file(cfg.genesis_path, 1));
  ASSERT_TRUE(create_test_validator_keystore(cfg, 0));

  node::Node n(cfg);
  ASSERT_TRUE(n.init() && "n.init() failed");
  n.start();
  ASSERT_TRUE(wait_for_tip(n, 3, std::chrono::seconds(20)));
  ASSERT_TRUE(n.pause_proposals_for_test(true));  // freeze the tip so no new TRANSITIONs are pushed
  const std::uint16_t port = n.p2p_port_for_test();
  ASSERT_TRUE(port != 0);

  const auto cfd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (!finalis::net::valid_socket(cfd)) {
    n.stop();
    return;
  }
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  ASSERT_EQ(::connect(cfd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)), 0);

  p2p::VersionMsg v;
  v.proto_version = static_cast<std::uint32_t>(cfg.network.protocol_version);
  v.network_id = cfg.network.network_id;
  v.feature_flags = cfg.network.feature_flags;
  v.timestamp = static_cast<std::uint64_t>(::time(nullptr));
  v.nonce = 9010;
  v.start_height = 0;
  v.start_hash = zero_hash();
  v.node_software_version = "finalis-tests/get-by-height-rate-limit;crh=" + n.consensus_rules_fingerprint_for_test();
  ASSERT_TRUE(
      p2p::write_frame_fd(cfd, p2p::Frame{p2p::MsgType::VERSION, p2p::ser_version(v)}, cfg.network.magic, cfg.network.protocol_version));

  bool saw_version = false;
  bool saw_verack = false;
  bool saw_tip = false;
  ASSERT_TRUE(wait_for([&]() {
    auto frame = p2p::read_frame_fd_timed(cfd, cfg.network.max_payload_len, cfg.network.magic, cfg.network.protocol_version,
                                          5000, 3000, nullptr, nullptr);
    if (!frame.has_value()) return false;
    if (frame->msg_type == p2p::MsgType::VERSION) {
      saw_version = true;
      ASSERT_TRUE(
          p2p::write_frame_fd(cfd, p2p::Frame{p2p::MsgType::VERACK, {}}, cfg.network.magic, cfg.network.protocol_version));
    } else if (frame->msg_type == p2p::MsgType::VERACK) {
      saw_verack = true;
    } else if (frame->msg_type == p2p::MsgType::FINALIZED_TIP) {
      saw_tip = true;
    }
    return saw_version && saw_verack && saw_tip;
  }, std::chrono::seconds(5)));

  const auto tip_h = n.status().height;
  ASSERT_TRUE(tip_h >= 1);

  auto request_by_height = [&](std::uint64_t h, int read_timeout_ms) {
    ASSERT_TRUE(p2p::write_frame_fd(cfd, p2p::Frame{p2p::MsgType::GET_TRANSITION_BY_HEIGHT,
                                                    p2p::ser_get_transition_by_height(p2p::GetTransitionByHeightMsg{h})},
                                    cfg.network.magic, cfg.network.protocol_version));
    return read_transition_frame_fd(cfd, cfg.network, read_timeout_ms);
  };

  auto first = request_by_height(tip_h, 5000);
  ASSERT_TRUE(first.has_value());
  ASSERT_EQ(first->msg_type, p2p::MsgType::TRANSITION);

  auto second = request_by_height(tip_h, 500);
  ASSERT_TRUE(!second.has_value());

  std::this_thread::sleep_for(std::chrono::milliseconds(1600));
  auto third = request_by_height(tip_h, 5000);
  ASSERT_TRUE(third.has_value());
  ASSERT_EQ(third->msg_type, p2p::MsgType::TRANSITION);

  finalis::net::shutdown_socket(cfd);
  finalis::net::close_socket(cfd);
  n.stop();
}

TEST(test_get_transition_by_height_not_rate_limited_across_heights) {
  const std::string base = unique_test_base("/tmp/finalis_it_get_by_height_rate_limit_distinct_heights");
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);

  auto cfg = single_node_cfg(base, 1);
  cfg.disable_p2p = false;  // these tests talk to the node's P2P listener directly
  cfg.listen = true;
  cfg.bind_ip = "127.0.0.1";
  cfg.p2p_port = reserve_test_ports(1).at(0);
  cfg.dns_seeds = false;
  cfg.network.default_seeds.clear();  // keep test nodes off the public mainnet seeds
  cfg.network.min_block_interval_ms = 50;
  cfg.network.round_timeout_ms = 120;
  ASSERT_TRUE(write_mainnet_genesis_file(cfg.genesis_path, 1));
  ASSERT_TRUE(create_test_validator_keystore(cfg, 0));

  node::Node n(cfg);
  ASSERT_TRUE(n.init() && "n.init() failed");
  n.start();
  ASSERT_TRUE(wait_for_tip(n, 4, std::chrono::seconds(20)));
  ASSERT_TRUE(n.pause_proposals_for_test(true));  // freeze the tip so no new TRANSITIONs are pushed
  const std::uint16_t port = n.p2p_port_for_test();
  ASSERT_TRUE(port != 0);

  const auto cfd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (!finalis::net::valid_socket(cfd)) {
    n.stop();
    return;
  }
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  ASSERT_EQ(::connect(cfd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)), 0);

  p2p::VersionMsg v;
  v.proto_version = static_cast<std::uint32_t>(cfg.network.protocol_version);
  v.network_id = cfg.network.network_id;
  v.feature_flags = cfg.network.feature_flags;
  v.timestamp = static_cast<std::uint64_t>(::time(nullptr));
  v.nonce = 9011;
  v.start_height = 0;
  v.start_hash = zero_hash();
  v.node_software_version = "finalis-tests/get-by-height-distinct-heights;crh=" + n.consensus_rules_fingerprint_for_test();
  ASSERT_TRUE(
      p2p::write_frame_fd(cfd, p2p::Frame{p2p::MsgType::VERSION, p2p::ser_version(v)}, cfg.network.magic, cfg.network.protocol_version));

  bool saw_version = false;
  bool saw_verack = false;
  bool saw_tip = false;
  ASSERT_TRUE(wait_for([&]() {
    auto frame = p2p::read_frame_fd_timed(cfd, cfg.network.max_payload_len, cfg.network.magic, cfg.network.protocol_version,
                                          5000, 3000, nullptr, nullptr);
    if (!frame.has_value()) return false;
    if (frame->msg_type == p2p::MsgType::VERSION) {
      saw_version = true;
      ASSERT_TRUE(
          p2p::write_frame_fd(cfd, p2p::Frame{p2p::MsgType::VERACK, {}}, cfg.network.magic, cfg.network.protocol_version));
    } else if (frame->msg_type == p2p::MsgType::VERACK) {
      saw_verack = true;
    } else if (frame->msg_type == p2p::MsgType::FINALIZED_TIP) {
      saw_tip = true;
    }
    return saw_version && saw_verack && saw_tip;
  }, std::chrono::seconds(5)));

  const auto tip_h = n.status().height;
  ASSERT_TRUE(tip_h >= 2);

  ASSERT_TRUE(p2p::write_frame_fd(cfd, p2p::Frame{p2p::MsgType::GET_TRANSITION_BY_HEIGHT,
                                                  p2p::ser_get_transition_by_height(p2p::GetTransitionByHeightMsg{tip_h})},
                                  cfg.network.magic, cfg.network.protocol_version));
  auto first = read_transition_frame_fd(cfd, cfg.network, 5000);
  ASSERT_TRUE(first.has_value());
  ASSERT_EQ(first->msg_type, p2p::MsgType::TRANSITION);

  ASSERT_TRUE(p2p::write_frame_fd(cfd, p2p::Frame{p2p::MsgType::GET_TRANSITION_BY_HEIGHT,
                                                  p2p::ser_get_transition_by_height(p2p::GetTransitionByHeightMsg{tip_h - 1})},
                                  cfg.network.magic, cfg.network.protocol_version));
  auto second = read_transition_frame_fd(cfd, cfg.network, 5000);
  ASSERT_TRUE(second.has_value());
  ASSERT_EQ(second->msg_type, p2p::MsgType::TRANSITION);

  finalis::net::shutdown_socket(cfd);
  finalis::net::close_socket(cfd);
  n.stop();
}

TEST(test_get_transition_by_height_rate_limit_is_per_peer_not_global) {
  const std::string base = unique_test_base("/tmp/finalis_it_get_by_height_rate_limit_per_peer");
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);

  auto cfg = single_node_cfg(base, 1);
  cfg.disable_p2p = false;  // these tests talk to the node's P2P listener directly
  cfg.listen = true;
  cfg.bind_ip = "127.0.0.1";
  cfg.p2p_port = reserve_test_ports(1).at(0);
  cfg.dns_seeds = false;
  cfg.network.default_seeds.clear();  // keep test nodes off the public mainnet seeds
  cfg.network.min_block_interval_ms = 50;
  cfg.network.round_timeout_ms = 120;
  ASSERT_TRUE(write_mainnet_genesis_file(cfg.genesis_path, 1));
  ASSERT_TRUE(create_test_validator_keystore(cfg, 0));

  node::Node n(cfg);
  ASSERT_TRUE(n.init() && "n.init() failed");
  n.start();
  ASSERT_TRUE(wait_for_tip(n, 3, std::chrono::seconds(20)));
  ASSERT_TRUE(n.pause_proposals_for_test(true));  // freeze the tip so no new TRANSITIONs are pushed
  const std::uint16_t port = n.p2p_port_for_test();
  ASSERT_TRUE(port != 0);

  auto connect_and_handshake = [&](std::uint64_t nonce) -> finalis::net::SocketHandle {
    const auto fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (!finalis::net::valid_socket(fd)) return finalis::net::kInvalidSocket;
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ASSERT_EQ(::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)), 0);

    p2p::VersionMsg v;
    v.proto_version = static_cast<std::uint32_t>(cfg.network.protocol_version);
    v.network_id = cfg.network.network_id;
    v.feature_flags = cfg.network.feature_flags;
    v.timestamp = static_cast<std::uint64_t>(::time(nullptr));
    v.nonce = nonce;
    v.start_height = 0;
    v.start_hash = zero_hash();
    v.node_software_version = "finalis-tests/get-by-height-per-peer;crh=" + n.consensus_rules_fingerprint_for_test();
    ASSERT_TRUE(p2p::write_frame_fd(fd, p2p::Frame{p2p::MsgType::VERSION, p2p::ser_version(v)}, cfg.network.magic,
                                    cfg.network.protocol_version));
    bool saw_version = false;
    bool saw_verack = false;
    bool saw_tip = false;
    ASSERT_TRUE(wait_for([&]() {
      auto frame = p2p::read_frame_fd_timed(fd, cfg.network.max_payload_len, cfg.network.magic, cfg.network.protocol_version,
                                            5000, 3000, nullptr, nullptr);
      if (!frame.has_value()) return false;
      if (frame->msg_type == p2p::MsgType::VERSION) {
        saw_version = true;
        ASSERT_TRUE(
            p2p::write_frame_fd(fd, p2p::Frame{p2p::MsgType::VERACK, {}}, cfg.network.magic, cfg.network.protocol_version));
      } else if (frame->msg_type == p2p::MsgType::VERACK) {
        saw_verack = true;
      } else if (frame->msg_type == p2p::MsgType::FINALIZED_TIP) {
        saw_tip = true;
      }
      return saw_version && saw_verack && saw_tip;
    }, std::chrono::seconds(5)));
    return fd;
  };

  const auto tip_h = n.status().height;
  ASSERT_TRUE(tip_h >= 1);

  const auto a = connect_and_handshake(9021);
  const auto b = connect_and_handshake(9022);
  if (!finalis::net::valid_socket(a) || !finalis::net::valid_socket(b)) {
    if (finalis::net::valid_socket(a)) {
      finalis::net::shutdown_socket(a);
      finalis::net::close_socket(a);
    }
    if (finalis::net::valid_socket(b)) {
      finalis::net::shutdown_socket(b);
      finalis::net::close_socket(b);
    }
    n.stop();
    return;
  }

  ASSERT_TRUE(p2p::write_frame_fd(a, p2p::Frame{p2p::MsgType::GET_TRANSITION_BY_HEIGHT,
                                                p2p::ser_get_transition_by_height(p2p::GetTransitionByHeightMsg{tip_h})},
                                  cfg.network.magic, cfg.network.protocol_version));
  auto a_first = read_transition_frame_fd(a, cfg.network, 5000);
  ASSERT_TRUE(a_first.has_value());
  ASSERT_EQ(a_first->msg_type, p2p::MsgType::TRANSITION);

  ASSERT_TRUE(p2p::write_frame_fd(b, p2p::Frame{p2p::MsgType::GET_TRANSITION_BY_HEIGHT,
                                                p2p::ser_get_transition_by_height(p2p::GetTransitionByHeightMsg{tip_h})},
                                  cfg.network.magic, cfg.network.protocol_version));
  auto b_first = read_transition_frame_fd(b, cfg.network, 5000);
  ASSERT_TRUE(b_first.has_value());
  ASSERT_EQ(b_first->msg_type, p2p::MsgType::TRANSITION);

  finalis::net::shutdown_socket(a);
  finalis::net::close_socket(a);
  finalis::net::shutdown_socket(b);
  finalis::net::close_socket(b);
  n.stop();
}

TEST(test_reject_cross_network_mainnet_vs_testnet_handshake) {
  const std::string base = unique_test_base("/tmp/finalis_it_reject_mainnet_vs_testnet");
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);
  const std::string gpath = base + "/genesis.json";
  ASSERT_TRUE(write_mainnet_genesis_file(gpath, 4));

  node::NodeConfig cfg;
  cfg.allow_unencrypted_keystore = true;  // test fixture: no passphrase
  cfg.node_id = 0;
  cfg.db_path = base + "/node0";
  cfg.p2p_port = 0;
  cfg.genesis_path = gpath;
  cfg.allow_unsafe_genesis_override = true;
  cfg.validator_passphrase = "test-passphrase";
  cfg.validator_key_file = cfg.db_path + "/keystore/validator.json";
  {
    keystore::ValidatorKey vk;
    std::string kerr;
    ASSERT_TRUE(keystore::create_validator_keystore(cfg.validator_key_file, cfg.validator_passphrase, "mainnet", "sc",
                                                    deterministic_seed_for_node_id(0), &vk, &kerr));
  }
  node::Node n(cfg);
  ASSERT_TRUE(n.init() && "n.init() failed");
  n.start();
  const std::uint16_t port = n.p2p_port_for_test();
  if (port == 0) {
    n.stop();
    ASSERT_TRUE(false && "p2p_port_for_test() returned 0");
  }

  p2p::VersionMsg v;
  v.proto_version = static_cast<std::uint32_t>(cfg.network.protocol_version);
  v.network_id = cfg.network.network_id;
  v.network_id[0] ^= 0xFF;  // mismatch
  v.feature_flags = cfg.network.feature_flags;
  v.timestamp = static_cast<std::uint64_t>(::time(nullptr));
  v.nonce = 987;
  v.node_software_version = "handshake-test/0.7;crh=" + n.consensus_rules_fingerprint_for_test();
  ASSERT_TRUE(send_version_and_expect_disconnect("127.0.0.1", port, v, cfg.network, std::chrono::milliseconds(1000)));
  ASSERT_TRUE(wait_for([&]() { return n.status().rejected_network_id >= 1; }, std::chrono::seconds(2)));
  n.stop();
}

TEST(test_fixed_runtime_proposal_builds_frontier_payload_without_legacy_coinbase) {
  const auto base = unique_test_base("/tmp/finalis_it_no_v3_marker");
  auto cfg = single_node_cfg(base, 1);
  ASSERT_TRUE(write_mainnet_genesis_file(cfg.genesis_path, 1));
  ASSERT_TRUE(create_test_validator_keystore(cfg, 0));

  Tx tx = make_fixture_ingress_tx(1, 0xA1);
  CertifiedIngressFixture fixture;
  std::unique_ptr<node::Node> node;
  ASSERT_TRUE(restart_single_node_with_seeded_certified_ingress(cfg, {tx.serialize()}, &node, &fixture, false));
  ASSERT_TRUE(node);

  auto proposal = build_test_frontier_proposal(*node, 1, 0);
  ASSERT_TRUE(proposal.has_value());
  ASSERT_EQ(proposal->ordered_records, fixture.merged_records);
  ASSERT_EQ(proposal->transition.prev_frontier, 0u);
  ASSERT_EQ(proposal->transition.next_frontier, fixture.merged_records.size());
  for (const auto& raw : proposal->ordered_records) {
    const auto parsed = Tx::parse(raw);
    ASSERT_TRUE(parsed.has_value());
    ASSERT_TRUE(parsed->inputs.empty());
  }
}

TEST(test_single_validator_round0_uses_deterministic_proposer) {
  const std::string base = unique_test_base("/tmp/finalis_it_single_validator_round0");
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);
  const std::string gpath = base + "/genesis.json";
  ASSERT_TRUE(write_empty_mainnet_bootstrap_genesis_file(gpath));

  node::NodeConfig cfg;
  cfg.allow_unencrypted_keystore = true;  // test fixture: no passphrase
  cfg.node_id = 0;
  cfg.dns_seeds = false;
  cfg.network.default_seeds.clear();  // keep test nodes off the public mainnet seeds
  cfg.db_path = base + "/node0";
  cfg.p2p_port = reserve_test_port();
  ASSERT_TRUE(cfg.p2p_port != 0 && "Failed to reserve test port for cfg");
  cfg.genesis_path = gpath;
  cfg.allow_unsafe_genesis_override = true;
  cfg.validator_key_file = cfg.db_path + "/keystore/validator.json";
  cfg.validator_passphrase = "test-pass";
  ASSERT_TRUE(create_test_validator_keystore(cfg, 0));

  Tx tx = make_fixture_ingress_tx(1, 0xA2);
  std::unique_ptr<node::Node> node;
  ASSERT_TRUE(restart_single_node_with_seeded_certified_ingress(cfg, {tx.serialize()}, &node, nullptr, false));
  ASSERT_TRUE(node);

  auto proposal = build_test_frontier_proposal(*node, 1, 0);
  ASSERT_TRUE(proposal.has_value());
  ASSERT_EQ(proposal->transition.leader_pubkey, node->active_validators_for_next_height_for_test().front());
}

TEST(test_startup_rejects_missing_finality_certificate_for_finalized_height) {
  const auto base = unique_test_base("/tmp/finalis_it_missing_finality_cert");
  auto cluster = make_cluster(base, 1, 1, 1);
  ASSERT_TRUE(wait_for_tip(*cluster.nodes[0], 1, std::chrono::seconds(12)));
  cluster.nodes[0]->stop();
  cluster.nodes.clear();

  storage::DB db;
  ASSERT_TRUE(db.open(base + "/node0"));
  const auto tip = db.get_tip();
  ASSERT_TRUE(tip.has_value());
  ASSERT_TRUE(tip->height > 0);
  ASSERT_TRUE(db.erase(test_key_finality_certificate_height(tip->height)));
  db.close();

  node::Node n(single_node_cfg(base, 1));
  ASSERT_TRUE(!n.init());
}

TEST(test_startup_rejects_invalid_finality_certificate_signature) {
  const auto base = unique_test_base("/tmp/finalis_it_invalid_finality_cert_sig");
  auto cluster = make_cluster(base, 1, 1, 1);
  ASSERT_TRUE(wait_for_tip(*cluster.nodes[0], 1, std::chrono::seconds(12)));
  cluster.nodes[0]->stop();
  cluster.nodes.clear();

  storage::DB db;
  ASSERT_TRUE(db.open(base + "/node0"));
  const auto tip = db.get_tip();
  ASSERT_TRUE(tip.has_value());
  ASSERT_TRUE(tip->height > 0);
  auto cert = db.get_finality_certificate_by_height(tip->height);
  ASSERT_TRUE(cert.has_value());
  ASSERT_TRUE(!cert->signatures.empty());
  cert->signatures[0].signature[0] ^= 0x01;
  ASSERT_TRUE(db.put(test_key_finality_certificate_height(tip->height), cert->serialize()));
  db.close();

  node::Node n(single_node_cfg(base, 1));
  ASSERT_TRUE(!n.init());
}

TEST(test_startup_rejects_stale_persisted_validator_cache) {
  const auto base = unique_test_base("/tmp/finalis_it_validator_cache_mismatch");
  auto cluster = make_cluster(base, 1, 1, 1);
  ASSERT_TRUE(wait_for_tip(*cluster.nodes[0], 1, std::chrono::seconds(12)));
  cluster.nodes[0]->stop();
  cluster.nodes.clear();

  storage::DB db;
  ASSERT_TRUE(db.open(base + "/node0"));
  const auto keys = node::Node::deterministic_test_keypairs();
  auto info = db.load_validators();
  ASSERT_TRUE(!info.empty());
  auto it = info.find(keys[0].public_key);
  ASSERT_TRUE(it != info.end());
  it->second.operator_id = key_from_byte(0x7a).public_key;
  ASSERT_TRUE(db.put_validator(it->first, it->second));
  db.close();

  node::Node n(single_node_cfg(base, 1));
  ASSERT_TRUE(n.init());
}

TEST(test_startup_rejects_mismatching_persisted_consensus_state_commitment_cache) {
  const auto base = unique_test_base("/tmp/finalis_it_commitment_cache_mismatch");
  auto cluster = make_cluster(base, 1, 1, 1);
  ASSERT_TRUE(wait_for_tip(*cluster.nodes[0], 2, std::chrono::seconds(15)));
  cluster.nodes[0]->stop();
  cluster.nodes.clear();

  storage::DB db;
  ASSERT_TRUE(db.open(base + "/node0"));
  auto cache = db.get_consensus_state_commitment_cache();
  ASSERT_TRUE(cache.has_value());
  cache->commitment[0] ^= 0x01;
  ASSERT_TRUE(db.put_consensus_state_commitment_cache(*cache));
  db.close();

  node::Node restarted(single_node_cfg(base, 1));
  ASSERT_TRUE(restarted.init());
}

TEST(test_startup_repairs_mismatching_cached_checkpoint_material) {
  const auto base = unique_test_base("/tmp/finalis_it_checkpoint_cache_mismatch");
  auto cluster = make_cluster(base, 1, 1, 1);
  ASSERT_TRUE(wait_for_tip(*cluster.nodes[0], 2, std::chrono::seconds(15)));
  cluster.nodes[0]->stop();
  cluster.nodes.clear();

  storage::DB db;
  ASSERT_TRUE(db.open(base + "/node0"));
  auto checkpoint = db.get_finalized_committee_checkpoint(1);
  ASSERT_TRUE(checkpoint.has_value());
  ASSERT_TRUE(!checkpoint->ordered_members.empty());
  checkpoint->ordered_members[0] = key_from_byte(0x55).public_key;
  ASSERT_TRUE(db.put_finalized_committee_checkpoint(*checkpoint));
  db.close();

  node::Node restarted(single_node_cfg(base, 1));
  ASSERT_TRUE(restarted.init());
  ASSERT_TRUE(restarted.status().height >= 2);
}

TEST(test_startup_repairs_schedule_relevant_checkpoint_drift) {
  const auto base = unique_test_base("/tmp/finalis_it_checkpoint_schedule_drift");
  auto cluster = make_cluster(base, 1, 1, 1);
  ASSERT_TRUE(wait_for_tip(*cluster.nodes[0], 2, std::chrono::seconds(15)));
  cluster.nodes[0]->stop();
  cluster.nodes.clear();

  storage::DB db;
  ASSERT_TRUE(db.open(base + "/node0"));
  auto checkpoint = db.get_finalized_committee_checkpoint(1);
  ASSERT_TRUE(checkpoint.has_value());
  ASSERT_TRUE(!checkpoint->ordered_ticket_nonces.empty());
  checkpoint->ordered_ticket_nonces[0] += 1;
  ASSERT_TRUE(db.put_finalized_committee_checkpoint(*checkpoint));
  db.close();

  node::Node restarted(single_node_cfg(base, 1));
  ASSERT_TRUE(restarted.init());
  ASSERT_TRUE(restarted.status().height >= 2);
}

TEST(test_restart_replay_is_independent_of_validator_reward_and_checkpoint_caches) {
  const auto base = unique_test_base("/tmp/finalis_it_canonical_cache_independence");
  auto cluster = make_cluster(base, 1, 1, 1);
  const node::NodeConfig cfg = single_node_cfg(base, 1);
  ASSERT_TRUE(wait_for_tip(*cluster.nodes[0], 4, std::chrono::seconds(20)));
  // Read the tip after shutdown: a block finalized between reading it and stopping would otherwise
  // make the restarted node correctly report one block more.
  cluster.nodes[0]->stop();
  const auto before = cluster.nodes[0]->status();
  const auto before_commitment = cluster.nodes[0]->canonical_state_commitment_for_test();
  cluster.nodes.clear();

  storage::DB db;
  ASSERT_TRUE(db.open(cfg.db_path));
  for (const auto& [key, _] : db.scan_prefix(storage::key_validator_prefix())) ASSERT_TRUE(db.erase(key));
  for (const auto& [key, _] : db.scan_prefix("ER:")) ASSERT_TRUE(db.erase(key));
  for (const auto& [key, _] : db.scan_prefix("CE:")) ASSERT_TRUE(db.erase(key));
  ASSERT_TRUE(db.erase("PRAND:FINALIZED"));
  ASSERT_TRUE(db.erase(storage::key_consensus_state_commitment_cache()));
  db.close();

  node::Node restarted(cfg);
  ASSERT_TRUE(restarted.init());
  const auto after = restarted.status();
  ASSERT_EQ(after.height, before.height);
  ASSERT_EQ(after.transition_hash, before.transition_hash);
  ASSERT_EQ(restarted.canonical_state_commitment_for_test(), before_commitment);
}

TEST(test_fast_start_restores_state_verified_against_signed_tip) {
  const auto base = unique_test_base("/tmp/finalis_it_fast_start_verified");
  auto cluster = make_cluster(base, 1, 1, 1);
  const node::NodeConfig cfg = single_node_cfg(base, 1);
  ASSERT_TRUE(cfg.fast_start);
  ASSERT_TRUE(wait_for_tip(*cluster.nodes[0], 4, std::chrono::seconds(20)));
  // Read the tip after shutdown: a block finalized between reading it and stopping would otherwise
  // make the restarted node correctly report one block more.
  cluster.nodes[0]->stop();
  const auto before = cluster.nodes[0]->status();
  const auto before_commitment = cluster.nodes[0]->canonical_state_commitment_for_test();
  cluster.nodes.clear();

  {
    node::Node restarted(cfg);
    ASSERT_TRUE(restarted.init());
    ASSERT_EQ(restarted.fast_start_result_for_test(), std::string("ok"));
    ASSERT_EQ(restarted.status().transition_hash, before.transition_hash);
    ASSERT_EQ(restarted.canonical_state_commitment_for_test(), before_commitment);
    restarted.stop();
  }

  // A certified record beyond the finalized vector moves the stored lane tip and root ahead of the
  // finalized ones; fast start takes the finalized root from that record's prev_lane_root.
  {
    storage::DB db;
    ASSERT_TRUE(db.open(cfg.db_path));
    const std::uint32_t lane = 0;
    const auto lane_state = db.get_lane_state(lane);
    LaneState ahead = lane_state.value_or(LaneState{0, lane, 0, zero_hash()});
    IngressCertificate cert;
    cert.epoch = ahead.epoch;
    cert.lane = lane;
    cert.seq = ahead.max_seq + 1;
    cert.txid.fill(0xA1);
    cert.tx_hash.fill(0xA2);
    cert.prev_lane_root = ahead.lane_root;
    cert.sigs = {FinalitySig{node::Node::deterministic_test_keypairs()[0].public_key, Sig64{}}};
    ASSERT_TRUE(db.put_ingress_bytes(cert.txid, Bytes{0x01}));
    ASSERT_TRUE(db.put_ingress_certificate(lane, cert.seq, cert.serialize()));
    ahead.max_seq = cert.seq;
    ahead.lane_root = consensus::compute_lane_root_append(ahead.lane_root, cert.tx_hash);
    ASSERT_TRUE(db.put_lane_state(lane, ahead));
    db.close();

    node::Node restarted(cfg);
    ASSERT_TRUE(restarted.init());
    ASSERT_EQ(restarted.fast_start_result_for_test(), std::string("ok"));
    ASSERT_EQ(restarted.canonical_state_commitment_for_test(), before_commitment);
    restarted.stop();
  }

  // A stored state that no longer matches the tip's signed next_state_commitment is not trusted:
  // startup falls back to replay and rebuilds the same state.
  storage::DB db;
  ASSERT_TRUE(db.open(cfg.db_path));
  const auto validators = db.scan_prefix(storage::key_validator_prefix());
  ASSERT_TRUE(!validators.empty());
  ASSERT_TRUE(db.erase(validators.begin()->first));
  db.close();

  node::Node replayed(cfg);
  ASSERT_TRUE(replayed.init());
  ASSERT_TRUE(replayed.fast_start_result_for_test().rfind("fallback:checkpoint-post-state-commitment-mismatch", 0) == 0);
  ASSERT_EQ(replayed.status().transition_hash, before.transition_hash);
  ASSERT_EQ(replayed.canonical_state_commitment_for_test(), before_commitment);
}

TEST(test_fast_start_at_last_height_of_an_epoch_keeps_next_committee) {
  // At an epoch's last height the node re-validates the next epoch's checkpoint, which reads the
  // epoch randomness that fast start must restore. Short epochs make such stops frequent.
  const auto base = unique_test_base("/tmp/finalis_it_fast_start_epoch_boundary");
  const auto configure = [](node::NodeConfig& c) { c.network.committee_epoch_blocks = 2; };
  auto cluster = make_cluster(base, 1, 1, 1, configure);
  const node::NodeConfig cfg = cluster.configs[0];
  ASSERT_TRUE(wait_for_tip(*cluster.nodes[0], 3, std::chrono::seconds(20)));
  cluster.nodes[0]->stop();
  cluster.nodes.clear();

  bool hit_boundary = false;
  for (int attempt = 0; attempt < 12 && !hit_boundary; ++attempt) {
    node::Node n(cfg);
    ASSERT_TRUE(n.init());
    ASSERT_EQ(n.fast_start_result_for_test(), std::string("ok"));
    const auto height = n.status().height;
    ASSERT_TRUE(!n.committee_for_next_height_for_test().empty());
    hit_boundary = consensus::committee_epoch_start(height + 1, cfg.network.committee_epoch_blocks) == height + 1;
    n.start();
    ASSERT_TRUE(wait_for_tip(n, height + 1 + static_cast<std::uint64_t>(attempt % 2), std::chrono::seconds(20)));
    n.stop();
  }
  ASSERT_TRUE(hit_boundary);
}

// A light client trusts only the genesis document: it derives the epoch-1 committee, follows each
// epoch's committee through the stored handoffs, and accepts the tip on its committee's certificate.
TEST(test_light_client_follows_committees_from_genesis_and_rejects_tampering) {
  const auto base = unique_test_base("/tmp/finalis_it_light_client");
  const auto configure = [](node::NodeConfig& c) { c.network.committee_epoch_blocks = 2; };
  auto cluster = make_cluster(base, 4, 4, MAX_COMMITTEE, configure);
  const node::NodeConfig cfg = cluster.configs[0];
  ASSERT_TRUE(wait_for_tip(*cluster.nodes[0], 9, std::chrono::seconds(60)));
  for (auto& n : cluster.nodes) n->stop();
  cluster.nodes.clear();

  std::ifstream gin(base + "/genesis.json");
  const std::string gjson((std::istreambuf_iterator<char>(gin)), std::istreambuf_iterator<char>());
  const auto doc = genesis::parse_json(gjson);
  ASSERT_TRUE(doc.has_value());

  std::map<std::uint64_t, storage::FinalizedCommitteeCheckpoint> node_checkpoints;
  std::map<std::uint64_t, Bytes> handoff_bytes;
  Hash32 genesis_hash{};
  std::uint64_t tip = 0;
  std::optional<FrontierTransition> tip_transition;
  std::optional<FinalityCertificate> tip_cert;
  {
    storage::DB db;
    ASSERT_TRUE(db.open_readonly(cfg.db_path));
    const auto gh = db.get(storage::key_genesis_hash());
    ASSERT_TRUE(gh.has_value() && gh->size() == 32);
    std::copy(gh->begin(), gh->end(), genesis_hash.begin());
    node_checkpoints = db.load_finalized_committee_checkpoints();
    tip = db.get_tip()->height;
    for (std::uint64_t next = 3; next - 1 <= tip; next += 2) {
      auto b = db.get_committee_handoff(next);
      ASSERT_TRUE(b.has_value());
      handoff_bytes[next] = *b;
    }
    tip_transition = FrontierTransition::parse(*db.get_frontier_transition(*db.get_frontier_transition_by_height(tip)));
    tip_cert = db.get_finality_certificate_by_height(tip);
    ASSERT_TRUE(tip_transition.has_value() && tip_cert.has_value());
  }

  const auto genesis_checkpoint = consensus::genesis_committee_checkpoint(cfg.network, *doc, genesis_hash);
  ASSERT_TRUE(genesis_checkpoint.has_value());
  ASSERT_TRUE(consensus::checkpoint_commitment_value(*genesis_checkpoint) ==
              consensus::checkpoint_commitment_value(node_checkpoints.at(1)));
  ASSERT_EQ(genesis_checkpoint->ordered_members.size(), 4u);
  // Every committee carries each member's genesis BLS key, in member order.
  std::map<PubKey32, crypto::BlsPublicKey> genesis_bls;
  for (std::size_t i = 0; i < doc->initial_validators.size(); ++i) {
    genesis_bls[doc->initial_validators[i]] = doc->initial_validator_bls[i].pubkey;
  }
  for (const auto& [epoch, checkpoint] : node_checkpoints) {
    ASSERT_EQ(checkpoint.ordered_bls_keys.size(), checkpoint.ordered_members.size());
    for (std::size_t i = 0; i < checkpoint.ordered_members.size(); ++i) {
      ASSERT_TRUE(checkpoint.ordered_bls_keys[i] == genesis_bls.at(checkpoint.ordered_members[i]));
    }
  }

  const auto params = consensus::light_client_params(cfg.network, consensus::chain_id_for_genesis(cfg.network, genesis_hash));
  storage::FinalizedCommitteeCheckpoint current = *genesis_checkpoint;
  for (const auto& [next, bytes] : handoff_bytes) {
    const auto handoff = consensus::CommitteeHandoff::parse(bytes);
    ASSERT_TRUE(handoff.has_value());
    std::string err;
    const auto verified = consensus::verify_committee_handoff(params, current, *handoff, &err);
    ASSERT_TRUE(verified.has_value());
    ASSERT_TRUE(consensus::checkpoint_commitment_value(*verified) ==
                consensus::checkpoint_commitment_value(node_checkpoints.at(next)));
    current = *verified;
  }
  ASSERT_EQ(current.epoch_start_height, consensus::committee_epoch_start(tip, 2));
  // Every block after the first carries its parent's time signature: a threshold of the parent
  // committee's BLS keys, verifying on time_signature_message(parent height).
  {
    storage::DB tdb;
    ASSERT_TRUE(tdb.open_readonly(cfg.db_path));
    const auto domain = consensus_chain_domain(cfg.network, consensus::chain_id_for_genesis(cfg.network, genesis_hash));
    for (std::uint64_t h = 2; h <= tip; ++h) {
      const auto t = FrontierTransition::parse(*tdb.get_frontier_transition(*tdb.get_frontier_transition_by_height(h)));
      ASSERT_TRUE(t.has_value());
      const auto& checkpoint = node_checkpoints.at(consensus::committee_epoch_start(h - 1, 2));
      ASSERT_TRUE(t->prev_time_signature.signer_indices.size() >=
                  consensus::time_signature_threshold(checkpoint.ordered_bls_keys.size()));
      std::vector<crypto::BlsPublicKey> signers;
      for (const auto i : t->prev_time_signature.signer_indices) signers.push_back(checkpoint.ordered_bls_keys.at(i));
      ASSERT_TRUE(crypto::mcfly_aggregate_verify(signers, time_signature_message(domain, h - 1),
                                                 crypto::kBlsTimeSignatureDst, t->prev_time_signature.aggregate));
    }
  }
  ASSERT_TRUE(consensus::verify_light_finality(params, current, *tip_transition, *tip_cert));

  // Tampering with any link is caught.
  const auto first = *consensus::CommitteeHandoff::parse(handoff_bytes.at(3));
  ASSERT_TRUE(!consensus::verify_committee_handoff(params, node_checkpoints.at(3), first).has_value());  // wrong epoch
  auto bad_sig = first;
  bad_sig.certificate.signatures[0].signature[0] ^= 1;
  ASSERT_TRUE(!consensus::verify_committee_handoff(params, *genesis_checkpoint, bad_sig).has_value());
  auto bad_checkpoint = first;
  bad_checkpoint.next_checkpoint[bad_checkpoint.next_checkpoint.size() - 1] ^= 1;
  ASSERT_TRUE(!consensus::verify_committee_handoff(params, *genesis_checkpoint, bad_checkpoint).has_value());
  auto bad_preimage = first;
  bad_preimage.post_state_preimage[consensus::kPostStatePreimageCheckpointRootOffset] ^= 1;
  ASSERT_TRUE(!consensus::verify_committee_handoff(params, *genesis_checkpoint, bad_preimage).has_value());
  auto strangers = current;
  for (auto& member : strangers.ordered_members) member[0] ^= 0xff;
  ASSERT_TRUE(!consensus::verify_light_finality(params, strangers, *tip_transition, *tip_cert));

  // A database finalized without handoffs gets them on the next start, byte for byte.
  {
    storage::DB db;
    ASSERT_TRUE(db.open(cfg.db_path));
    for (const auto& [next, bytes] : handoff_bytes) ASSERT_TRUE(db.erase(storage::key_committee_handoff(next)));
    db.close();
  }
  {
    node::Node restarted(cfg);
    ASSERT_TRUE(restarted.init());
    restarted.stop();
  }
  storage::DB db;
  ASSERT_TRUE(db.open_readonly(cfg.db_path));
  for (const auto& [next, bytes] : handoff_bytes) ASSERT_TRUE(db.get_committee_handoff(next) == bytes);
}

// The wallet-side verifier against a real lightserver: committees from genesis over RPC, UTXO claims
// checked against the signed tip, and a server whose handoff was tampered with is refused.
TEST(test_light_verifier_checks_utxos_over_rpc_and_refuses_a_lying_server) {
  if (!can_open_loopback_listener_for_test()) return;
  const auto base = unique_test_base("/tmp/finalis_it_light_verifier");
  const auto configure = [](node::NodeConfig& c) { c.network.committee_epoch_blocks = 2; };
  auto cluster = make_cluster(base, 1, 1, MAX_COMMITTEE, configure);
  const node::NodeConfig cfg = cluster.configs[0];
  ASSERT_TRUE(wait_for_tip(*cluster.nodes[0], 12, std::chrono::seconds(60)));
  cluster.nodes[0]->stop();
  cluster.nodes.clear();

  std::ifstream gin(base + "/genesis.json");
  const auto doc = genesis::parse_json(std::string((std::istreambuf_iterator<char>(gin)), std::istreambuf_iterator<char>()));
  ASSERT_TRUE(doc.has_value());
  Hash32 genesis_hash{};
  std::uint64_t tip = 0;
  std::map<OutPoint, UtxoEntry> utxos;
  {
    storage::DB db;
    ASSERT_TRUE(db.open_readonly(cfg.db_path));
    const auto gh = db.get(storage::key_genesis_hash());
    std::copy(gh->begin(), gh->end(), genesis_hash.begin());
    tip = db.get_tip()->height;
    utxos = db.load_transparent_utxos();
  }
  ASSERT_TRUE(!utxos.empty());

  auto serve = [&]() {
    lightserver::Config lcfg;
    lcfg.db_path = cfg.db_path;
    lcfg.network = cfg.network;
    lcfg.bind_ip = "127.0.0.1";
    lcfg.port = 0;
    lcfg.admin_socket_path.clear();
    return std::make_unique<lightserver::Server>(lcfg);
  };
  auto ls = serve();
  ASSERT_TRUE(ls->init());
  ASSERT_TRUE(ls->start());
  const std::string url = "http://127.0.0.1:" + std::to_string(ls->bound_port()) + "/rpc";

  auto verifier = wallet::LightVerifier::from_genesis(cfg.network, *doc, genesis_hash);
  ASSERT_TRUE(verifier.has_value());
  const auto& [real_op, real_entry] = *utxos.begin();
  OutPoint unknown_op{};
  unknown_op.txid.fill(0x5a);
  const std::vector<std::pair<OutPoint, Bytes>> claims = {
      {real_op, wallet::transparent_utxo_leaf(real_entry.out.value, real_entry.out.script_pubkey)},
      {unknown_op, wallet::transparent_utxo_leaf(1'000, real_entry.out.script_pubkey)},
      {real_op, wallet::transparent_utxo_leaf(real_entry.out.value + 1, real_entry.out.script_pubkey)},
  };
  std::string err;
  const auto verified = verifier->verify_utxos(url, claims, &err);
  if (!verified.has_value()) throw std::runtime_error("verify_utxos: " + err);
  ASSERT_EQ(verified->height, tip);
  ASSERT_TRUE(verified->statuses == std::vector<wallet::UtxoProofStatus>({wallet::UtxoProofStatus::Unspent,
                                                                           wallet::UtxoProofStatus::Spent,
                                                                           wallet::UtxoProofStatus::Different}));
  ASSERT_EQ(verifier->trusted_epoch_start(), consensus::committee_epoch_start(tip, 2));

  // Saved progress resumes on a fresh verifier; another chain's or garbage state is refused.
  auto resumed = wallet::LightVerifier::from_genesis(cfg.network, *doc, genesis_hash);
  ASSERT_TRUE(resumed->load(verifier->save()));
  ASSERT_EQ(resumed->trusted_epoch_start(), verifier->trusted_epoch_start());
  auto other_chain = genesis_hash;
  other_chain[0] ^= 1;
  auto stranger = wallet::LightVerifier::from_genesis(cfg.network, *doc, other_chain);
  ASSERT_TRUE(!stranger->load(verifier->save()));
  ASSERT_TRUE(!resumed->load(Bytes{1, 2, 3}));
  // A verifier on another chain identity (different signing domain) rejects this chain's certificates.
  ASSERT_TRUE(!stranger->verify_utxos(url, claims).has_value());

  // Several servers' reports: coins count only when proven, and each kind of lie is attributed.
  std::vector<wallet::ClaimedUtxo> real;
  for (const auto& [op, entry] : utxos) {
    real.push_back(wallet::ClaimedUtxo{op, entry.out.value, entry.out.script_pubkey, 1});
    if (real.size() == 3) break;
  }
  ASSERT_TRUE(real.size() >= 2);
  auto inventor = real;
  inventor.push_back(wallet::ClaimedUtxo{unknown_op, 5'000'000, real[0].script_pubkey, 1});
  auto hider = std::vector<wallet::ClaimedUtxo>(real.begin() + 1, real.end());
  auto misdescriber = real;
  misdescriber[0].value += 1;
  const std::vector<wallet::EndpointClaims> reports = {
      {"honest", tip, real}, {"inventor", tip, inventor}, {"hider", tip, hider}, {"misdescriber", tip, misdescriber},
      {"behind", tip - 1, inventor}};
  const auto balance = wallet::verify_claimed_balance(&*verifier, reports, {}, {"http://127.0.0.1:1/rpc", url});
  ASSERT_TRUE(balance.verified);
  ASSERT_EQ(balance.height, tip);
  ASSERT_EQ(balance.proof_endpoint, url);
  ASSERT_EQ(balance.utxos.size(), real.size());
  std::set<std::string> caught;
  for (const auto& [endpoint, what] : balance.misbehaving) caught.insert(endpoint);
  ASSERT_TRUE(caught == std::set<std::string>({"inventor", "hider", "misdescriber"}));
  // Without a genesis to start from, the first report is passed through, marked unverified.
  const auto unverified = wallet::verify_claimed_balance(nullptr, reports, {}, {url});
  ASSERT_TRUE(!unverified.verified && unverified.utxos.size() == real.size());
  ls->stop();
  ls.reset();

  // A server whose stored handoff was altered: the client keeps what it proved before it and stops there.
  {
    storage::DB db;
    ASSERT_TRUE(db.open(cfg.db_path));
    auto bytes = db.get_committee_handoff(7);
    ASSERT_TRUE(bytes.has_value());
    auto handoff = consensus::CommitteeHandoff::parse(*bytes);
    handoff->certificate.signatures[0].signature[5] ^= 1;
    ASSERT_TRUE(db.put(storage::key_committee_handoff(7), handoff->serialize()));
    db.close();
  }
  ls = serve();
  ASSERT_TRUE(ls->init());
  ASSERT_TRUE(ls->start());
  const std::string lying_url = "http://127.0.0.1:" + std::to_string(ls->bound_port()) + "/rpc";
  auto fresh = wallet::LightVerifier::from_genesis(cfg.network, *doc, genesis_hash);
  ASSERT_TRUE(!fresh->sync_to(lying_url, tip, &err));
  ASSERT_TRUE(err.find("rejected") != std::string::npos);
  ASSERT_EQ(fresh->trusted_epoch_start(), 5u);
  ASSERT_TRUE(!fresh->verify_utxos(lying_url, claims).has_value());
  ls->stop();
}

TEST(test_consensus_history_is_pruned_and_fast_start_rebuilds_the_retained_window) {
  // 2-block epochs and a 4-block unbond delay: checkpoints keep max(2 + 2, 8) = 8 epochs, block metadata
  // 8 epochs, so both windows are passed within a few dozen heights.
  const auto base = unique_test_base("/tmp/finalis_it_history_pruning");
  const auto configure = [](node::NodeConfig& c) {
    c.network.committee_epoch_blocks = 2;
    c.network.unbond_delay_blocks = 4;
  };
  auto cluster = make_cluster(base, 1, 1, 1, configure);
  node::NodeConfig cfg = cluster.configs[0];
  ASSERT_TRUE(wait_for_tip(*cluster.nodes[0], 44, std::chrono::seconds(60)));
  cluster.nodes[0]->stop();
  const auto before_hash = cluster.nodes[0]->status().transition_hash;
  const auto before_commitment = cluster.nodes[0]->canonical_state_commitment_for_test();
  const auto sizes = cluster.nodes[0]->consensus_history_sizes_for_test();
  cluster.nodes.clear();
  // Bounded: at most 8 retained epochs (+ the next epoch's checkpoint), 8 epochs of metadata (+ the
  // tip when it opens an epoch), and reward states for the current and previous epochs only.
  ASSERT_TRUE(sizes[0] <= 9);
  ASSERT_TRUE(sizes[1] <= 17);
  ASSERT_TRUE(sizes[2] <= 3);

  {
    node::Node restarted(cfg);
    ASSERT_TRUE(restarted.init());
    ASSERT_EQ(restarted.fast_start_result_for_test(), std::string("ok"));
    ASSERT_EQ(restarted.status().transition_hash, before_hash);
    ASSERT_EQ(restarted.canonical_state_commitment_for_test(), before_commitment);
    restarted.stop();
  }
  cfg.fast_start = false;
  node::Node replayed(cfg);
  ASSERT_TRUE(replayed.init());
  ASSERT_EQ(replayed.canonical_state_commitment_for_test(), before_commitment);
  // History rows below the window stay in the database for queries.
  replayed.stop();
  storage::DB db;
  ASSERT_TRUE(db.open_readonly(cfg.db_path));
  ASSERT_TRUE(db.load_finalized_committee_checkpoints().size() > sizes[0]);
}

TEST(test_startup_can_replay_persisted_frontier_storage_when_selected) {
  const auto base = unique_test_base("/tmp/finalis_it_frontier_startup_replay");
  const node::NodeConfig legacy_cfg = single_node_cfg(base, 1);
  ASSERT_TRUE(write_mainnet_genesis_file(legacy_cfg.genesis_path, 1));
  ASSERT_TRUE(create_test_validator_keystore(legacy_cfg, 0));

  {
    node::Node n(legacy_cfg);
    ASSERT_TRUE(n.init());
    n.stop();
  }

  storage::DB db;
  ASSERT_TRUE(db.open(legacy_cfg.db_path));
  consensus::CanonicalDerivedState expected_state;
  ASSERT_TRUE(persist_test_frontier_replay_record(legacy_cfg, db, &expected_state));
  db.close();

  node::Node restarted(legacy_cfg);
  ASSERT_TRUE(restarted.init());
  ASSERT_EQ(restarted.status().height, 1u);
  ASSERT_EQ(restarted.canonical_state_commitment_for_test(), expected_state.state_commitment);
}

TEST(test_startup_rejects_invalid_frontier_storage) {
  const auto base = unique_test_base("/tmp/finalis_it_invalid_frontier_startup");
  const node::NodeConfig legacy_cfg = single_node_cfg(base, 1);
  ASSERT_TRUE(write_mainnet_genesis_file(legacy_cfg.genesis_path, 1));
  ASSERT_TRUE(create_test_validator_keystore(legacy_cfg, 0));

  {
    node::Node n(legacy_cfg);
    ASSERT_TRUE(n.init());
    n.stop();
  }

  storage::DB db;
  ASSERT_TRUE(db.open(legacy_cfg.db_path));
  ASSERT_TRUE(persist_test_frontier_replay_record(legacy_cfg, db, nullptr));
  const auto ingress_certs = db.scan_prefix(storage::key_ingress_certificate_prefix());
  ASSERT_TRUE(!ingress_certs.empty());
  ASSERT_TRUE(db.erase(ingress_certs.begin()->first));
  db.close();

  node::Node restarted(legacy_cfg);
  ASSERT_TRUE(!restarted.init());
}

TEST(test_frontier_mode_live_finalization_persists_frontier_artifacts_and_restarts) {
  const auto base = unique_test_base("/tmp/finalis_it_live_frontier_cutover_restart");
  auto cfg = single_node_cfg(base, 1);
  ASSERT_TRUE(write_mainnet_genesis_file(cfg.genesis_path, 1));
  ASSERT_TRUE(create_test_validator_keystore(cfg, 0));

  {
    node::Node seed(cfg);
    ASSERT_TRUE(seed.init());
    seed.stop();
  }
  storage::DB seeded_db;
  ASSERT_TRUE(seeded_db.open(cfg.db_path));
  ASSERT_TRUE(persist_test_frontier_replay_record(cfg, seeded_db, nullptr));
  seeded_db.close();

  storage::DB db;
  ASSERT_TRUE(db.open(cfg.db_path));
  const auto frontier_height = db.get_finalized_frontier_height();
  ASSERT_TRUE(frontier_height.has_value());
  ASSERT_TRUE(*frontier_height >= 1);
  const auto transition_id = db.get_frontier_transition_by_height(*frontier_height);
  ASSERT_TRUE(transition_id.has_value());
  db.close();

  node::Node restarted(cfg);
  ASSERT_TRUE(restarted.init());
  ASSERT_EQ(restarted.status().height, *frontier_height);
  ASSERT_EQ(restarted.status().transition_hash, *transition_id);
}

TEST(test_frontier_mode_availability_state_materializes_from_live_finalized_ingress) {
  const auto base = unique_test_base("/tmp/finalis_it_frontier_shadow_availability_live");
  auto cfg = single_node_cfg(base, 1);
  ASSERT_TRUE(write_mainnet_genesis_file(cfg.genesis_path, 1));
  ASSERT_TRUE(create_test_validator_keystore(cfg, 0));
  {
    node::Node seed(cfg);
    ASSERT_TRUE(seed.init());
    seed.stop();
  }
  storage::DB seeded_db;
  ASSERT_TRUE(seeded_db.open(cfg.db_path));
  ASSERT_TRUE(persist_test_frontier_replay_record(cfg, seeded_db, nullptr));
  seeded_db.close();

  node::Node n(cfg);
  ASSERT_TRUE(n.init());
  ASSERT_EQ(n.status().height, 1u);
  ASSERT_TRUE(n.status().availability_retained_prefix_count > 0u);

  const auto st = n.status();
  ASSERT_TRUE(st.availability_retained_prefix_count > 0u);
  ASSERT_TRUE(st.availability_tracked_operator_count > 0u);
  ASSERT_TRUE(st.availability_local_operator_known);
  ASSERT_EQ(st.availability_local_operator_status, "WARMUP");
  n.stop();

  const auto persisted = load_availability_state(cfg.db_path);
  ASSERT_TRUE(persisted.has_value());
  ASSERT_EQ(persisted->current_epoch, st.availability_epoch);
  ASSERT_EQ(persisted->retained_prefixes.size(), st.availability_retained_prefix_count);
  ASSERT_EQ(persisted->operators.size(), st.availability_tracked_operator_count);
}

TEST(test_frontier_mode_availability_state_restart_preserves_live_outputs) {
  const auto base = unique_test_base("/tmp/finalis_it_frontier_shadow_availability_restart");
  auto cfg = single_node_cfg(base, 1);
  ASSERT_TRUE(write_mainnet_genesis_file(cfg.genesis_path, 1));
  ASSERT_TRUE(create_test_validator_keystore(cfg, 0));
  {
    node::Node seed(cfg);
    ASSERT_TRUE(seed.init());
    seed.stop();
  }
  storage::DB seeded_db;
  ASSERT_TRUE(seeded_db.open(cfg.db_path));
  ASSERT_TRUE(persist_test_frontier_replay_record(cfg, seeded_db, nullptr));
  seeded_db.close();

  node::Node n(cfg);
  ASSERT_TRUE(n.init());
  ASSERT_EQ(n.status().height, 1u);
  ASSERT_TRUE(n.status().availability_retained_prefix_count > 0u);

  const auto before = n.status();
  n.stop();
  const auto before_state = load_availability_state(cfg.db_path);
  ASSERT_TRUE(before_state.has_value());
  const auto epoch_seed = availability::availability_audit_seed(before.transition_hash, before_state->current_epoch);
  const auto before_tickets = availability::build_availability_tickets(epoch_seed, before_state->operators, cfg.availability);

  node::Node restarted(cfg);
  ASSERT_TRUE(restarted.init());
  const auto after = restarted.status();
  restarted.stop();
  const auto after_state = load_availability_state(cfg.db_path);
  ASSERT_TRUE(after_state.has_value());
  const auto after_epoch_seed = availability::availability_audit_seed(after.transition_hash, after_state->current_epoch);
  const auto after_tickets = availability::build_availability_tickets(after_epoch_seed, after_state->operators, cfg.availability);

  ASSERT_EQ(after.availability_epoch, before.availability_epoch);
  ASSERT_EQ(after.availability_retained_prefix_count, before.availability_retained_prefix_count);
  ASSERT_EQ(after.availability_tracked_operator_count, before.availability_tracked_operator_count);
  ASSERT_EQ(after.availability_eligible_operator_count, before.availability_eligible_operator_count);
  ASSERT_EQ(after.availability_below_min_eligible, before.availability_below_min_eligible);
  ASSERT_EQ(after.availability_checkpoint_derivation_mode, before.availability_checkpoint_derivation_mode);
  ASSERT_EQ(after.availability_checkpoint_fallback_reason, before.availability_checkpoint_fallback_reason);
  ASSERT_EQ(after.availability_fallback_sticky, before.availability_fallback_sticky);
  ASSERT_EQ(after.availability_local_operator_known, before.availability_local_operator_known);
  ASSERT_EQ(after.availability_local_operator_status, before.availability_local_operator_status);
  ASSERT_EQ(after.availability_local_service_score, before.availability_local_service_score);
  ASSERT_EQ(after.availability_local_warmup_epochs, before.availability_local_warmup_epochs);
  ASSERT_EQ(after.availability_local_successful_audits, before.availability_local_successful_audits);
  ASSERT_EQ(after.availability_local_late_audits, before.availability_local_late_audits);
  ASSERT_EQ(after.availability_local_missed_audits, before.availability_local_missed_audits);
  ASSERT_EQ(after.availability_local_invalid_audits, before.availability_local_invalid_audits);
  ASSERT_EQ(after.availability_local_retained_prefix_count, before.availability_local_retained_prefix_count);
  ASSERT_EQ(after.availability_local_eligibility_score, before.availability_local_eligibility_score);
  ASSERT_EQ(after.availability_local_seat_budget, before.availability_local_seat_budget);
  ASSERT_EQ(after_state->current_epoch, before_state->current_epoch);
  ASSERT_EQ(after_state->operators, before_state->operators);
  ASSERT_EQ(after_state->retained_prefixes, before_state->retained_prefixes);
  ASSERT_EQ(after_state->evidence, before_state->evidence);
  ASSERT_EQ(after_tickets, before_tickets);
}

TEST(test_frontier_mode_availability_replay_and_persisted_restore_are_equivalent_for_checkpoint_inputs) {
  const auto base = unique_test_base("/tmp/finalis_it_frontier_availability_replay_equivalence");
  auto cfg = single_node_cfg(base, 1);
  ASSERT_TRUE(write_mainnet_genesis_file(cfg.genesis_path, 1));
  ASSERT_TRUE(create_test_validator_keystore(cfg, 0));
  {
    node::Node seed(cfg);
    ASSERT_TRUE(seed.init());
    seed.stop();
  }
  storage::DB seeded_db;
  ASSERT_TRUE(seeded_db.open(cfg.db_path));
  ASSERT_TRUE(persist_test_frontier_replay_record(cfg, seeded_db, nullptr));
  seeded_db.close();

  node::Node replay_built(cfg);
  ASSERT_TRUE(replay_built.init());
  const auto replay_status = replay_built.status();
  replay_built.stop();
  const auto replay_state = load_availability_state(cfg.db_path);
  const auto replay_checkpoint = load_checkpoint(cfg.db_path, 1);
  const auto replay_state_bytes = load_availability_state_bytes(cfg.db_path);
  ASSERT_TRUE(replay_state.has_value());
  ASSERT_TRUE(replay_checkpoint.has_value());
  ASSERT_TRUE(replay_state_bytes.has_value());

  node::Node persisted_restore(cfg);
  ASSERT_TRUE(persisted_restore.init());
  const auto persisted_status = persisted_restore.status();
  persisted_restore.stop();
  const auto persisted_state = load_availability_state(cfg.db_path);
  const auto persisted_checkpoint = load_checkpoint(cfg.db_path, 1);
  const auto persisted_state_bytes = load_availability_state_bytes(cfg.db_path);
  ASSERT_TRUE(persisted_state.has_value());
  ASSERT_TRUE(persisted_checkpoint.has_value());
  ASSERT_TRUE(persisted_state_bytes.has_value());

  storage::DB db;
  ASSERT_TRUE(db.open(cfg.db_path));
  ASSERT_TRUE(db.erase(storage::key_availability_persistent_state()));
  db.close();

  node::Node replay_rebuilt(cfg);
  ASSERT_TRUE(replay_rebuilt.init());
  const auto rebuilt_status = replay_rebuilt.status();
  replay_rebuilt.stop();
  const auto rebuilt_state = load_availability_state(cfg.db_path);
  const auto rebuilt_checkpoint = load_checkpoint(cfg.db_path, 1);
  const auto rebuilt_state_bytes = load_availability_state_bytes(cfg.db_path);
  ASSERT_TRUE(rebuilt_state.has_value());
  ASSERT_TRUE(rebuilt_checkpoint.has_value());
  ASSERT_TRUE(rebuilt_state_bytes.has_value());

  ASSERT_EQ(persisted_status.availability_epoch, replay_status.availability_epoch);
  ASSERT_EQ(persisted_status.availability_eligible_operator_count, replay_status.availability_eligible_operator_count);
  ASSERT_EQ(persisted_status.availability_checkpoint_derivation_mode, replay_status.availability_checkpoint_derivation_mode);
  ASSERT_EQ(persisted_status.availability_checkpoint_fallback_reason, replay_status.availability_checkpoint_fallback_reason);
  ASSERT_EQ(persisted_status.availability_fallback_sticky, replay_status.availability_fallback_sticky);

  ASSERT_EQ(*persisted_state, *replay_state);
  ASSERT_EQ(*rebuilt_state, *replay_state);
  ASSERT_EQ(*persisted_state_bytes, *replay_state_bytes);
  ASSERT_EQ(*rebuilt_state_bytes, *replay_state_bytes);
  ASSERT_TRUE(same_finalized_checkpoint(*persisted_checkpoint, *replay_checkpoint));
  ASSERT_TRUE(same_finalized_checkpoint(*rebuilt_checkpoint, *replay_checkpoint));

  ASSERT_EQ(rebuilt_status.availability_epoch, replay_status.availability_epoch);
  ASSERT_EQ(rebuilt_status.availability_eligible_operator_count, replay_status.availability_eligible_operator_count);
  ASSERT_EQ(rebuilt_status.availability_checkpoint_derivation_mode, replay_status.availability_checkpoint_derivation_mode);
  ASSERT_EQ(rebuilt_status.availability_checkpoint_fallback_reason, replay_status.availability_checkpoint_fallback_reason);
  ASSERT_EQ(rebuilt_status.availability_fallback_sticky, replay_status.availability_fallback_sticky);
}

TEST(test_frontier_mode_availability_future_expiry_is_preserved_across_restart) {
  const auto base = unique_test_base("/tmp/finalis_it_frontier_shadow_availability_future_expiry_restart");
  auto cfg = single_node_cfg(base, 1);
  cfg.availability.retention_window_min_epochs = 8;
  ASSERT_TRUE(write_mainnet_genesis_file(cfg.genesis_path, 1));
  ASSERT_TRUE(create_test_validator_keystore(cfg, 0));
  {
    node::Node seed(cfg);
    ASSERT_TRUE(seed.init());
    seed.stop();
  }
  storage::DB seeded_db;
  ASSERT_TRUE(seeded_db.open(cfg.db_path));
  ASSERT_TRUE(persist_test_frontier_replay_record(cfg, seeded_db, nullptr));
  seeded_db.close();

  node::Node n(cfg);
  ASSERT_TRUE(n.init());
  ASSERT_EQ(n.status().height, 1u);
  ASSERT_TRUE(n.status().availability_retained_prefix_count > 0u);
  n.stop();
  const auto persisted_before = load_availability_state(cfg.db_path);
  ASSERT_TRUE(persisted_before.has_value());
  ASSERT_TRUE(persisted_before->retained_prefixes.size() > 0u);
  const auto future_epoch = persisted_before->current_epoch + 3;
  const auto expected_future_expiry = availability::expire_retained_prefixes(
      persisted_before->retained_prefixes, future_epoch, cfg.availability.retention_window_min_epochs);

  node::Node restarted(cfg);
  ASSERT_TRUE(restarted.init());
  restarted.stop();
  const auto persisted_after = load_availability_state(cfg.db_path);
  ASSERT_TRUE(persisted_after.has_value());
  const auto actual_future_expiry = availability::expire_retained_prefixes(
      persisted_after->retained_prefixes, future_epoch,
      cfg.availability.retention_window_min_epochs);
  ASSERT_EQ(actual_future_expiry, expected_future_expiry);
}

TEST(test_frontier_mode_restart_fails_when_persisted_frontier_storage_is_incomplete) {
  const auto base = unique_test_base("/tmp/finalis_it_live_frontier_cutover_incomplete");
  auto cfg = single_node_cfg(base, 1);
  ASSERT_TRUE(write_mainnet_genesis_file(cfg.genesis_path, 1));
  ASSERT_TRUE(create_test_validator_keystore(cfg, 0));

  {
    node::Node seed(cfg);
    ASSERT_TRUE(seed.init());
    seed.stop();
  }
  storage::DB seeded_db;
  ASSERT_TRUE(seeded_db.open(cfg.db_path));
  ASSERT_TRUE(persist_test_frontier_replay_record(cfg, seeded_db, nullptr));
  seeded_db.close();

  storage::DB db;
  ASSERT_TRUE(db.open(cfg.db_path));
  const auto transition_id = db.get_frontier_transition_by_height(1);
  ASSERT_TRUE(transition_id.has_value());
  ASSERT_TRUE(db.erase(storage::key_frontier_transition(*transition_id)));
  db.close();

  node::Node restarted(cfg);
  ASSERT_TRUE(!restarted.init());
}

TEST(test_frontier_mode_validation_accepts_valid_proposal_against_certified_ingress) {
  const auto base = unique_test_base("/tmp/finalis_it_frontier_validate_ok");
  auto cfg = single_node_cfg(base, 1);
  ASSERT_TRUE(write_mainnet_genesis_file(cfg.genesis_path, 1));
  ASSERT_TRUE(create_test_validator_keystore(cfg, 0));

  {
    node::Node n(cfg);
    ASSERT_TRUE(n.init());
    n.stop();
  }

  storage::DB db;
  ASSERT_TRUE(db.open(cfg.db_path));
  FrontierProposal proposal;
  ASSERT_TRUE(build_test_frontier_proposal_with_certified_ingress(cfg, db, &proposal));
  db.close();

  node::Node target(cfg);
  ASSERT_TRUE(target.init());

  const auto msg = make_test_frontier_propose_msg(target.consensus_domain_for_test(), proposal);
  ASSERT_TRUE(target.inject_propose_msg_for_test(msg));
}

TEST(test_no_prevote_for_proposal_with_wrong_next_state_commitment) {
  const auto base = unique_test_base("/tmp/finalis_it_frontier_bad_post_state");
  auto cfg = single_node_cfg(base, 1);
  ASSERT_TRUE(write_mainnet_genesis_file(cfg.genesis_path, 1));
  ASSERT_TRUE(create_test_validator_keystore(cfg, 0));

  {
    node::Node n(cfg);
    ASSERT_TRUE(n.init());
    n.stop();
  }

  storage::DB db;
  ASSERT_TRUE(db.open(cfg.db_path));
  FrontierProposal good;
  ASSERT_TRUE(build_test_frontier_proposal_with_certified_ingress(cfg, db, &good));
  db.close();
  auto bad = good;
  bad.transition.next_state_commitment[7] ^= 0x40;

  node::Node target(cfg);
  ASSERT_TRUE(target.init());
  // Everything else about the proposal is valid, so it is accepted as a candidate, but not voted for.
  (void)target.inject_propose_msg_for_test(make_test_frontier_propose_msg(target.consensus_domain_for_test(), bad));
  ASSERT_TRUE(!target.local_prevote_recorded_for_test(1, 0, bad.transition.transition_id()));
  ASSERT_TRUE(target.inject_propose_msg_for_test(make_test_frontier_propose_msg(target.consensus_domain_for_test(), good)));
  ASSERT_TRUE(target.local_prevote_recorded_for_test(1, 0, good.transition.transition_id()));
}

TEST(test_frontier_mode_validation_rejects_bad_ingress_commitment) {
  const auto base = unique_test_base("/tmp/finalis_it_frontier_validate_bad_ingress");
  auto cfg = single_node_cfg(base, 1);
  ASSERT_TRUE(write_mainnet_genesis_file(cfg.genesis_path, 1));
  ASSERT_TRUE(create_test_validator_keystore(cfg, 0));
  { node::Node n(cfg); ASSERT_TRUE(n.init()); n.stop(); }
  storage::DB db;
  ASSERT_TRUE(db.open(cfg.db_path));
  FrontierProposal proposal;
  ASSERT_TRUE(build_test_frontier_proposal_with_certified_ingress(cfg, db, &proposal));
  proposal.transition.ingress_commitment[0] ^= 0x01;
  db.close();
  node::Node target(cfg);
  ASSERT_TRUE(target.init());
  const auto msg = make_test_frontier_propose_msg(target.consensus_domain_for_test(), proposal);
  ASSERT_TRUE(!target.inject_propose_msg_for_test(msg));
}

TEST(test_frontier_mode_validation_rejects_bad_decisions_commitment) {
  const auto base = unique_test_base("/tmp/finalis_it_frontier_validate_bad_decisions");
  auto cfg = single_node_cfg(base, 1);
  ASSERT_TRUE(write_mainnet_genesis_file(cfg.genesis_path, 1));
  ASSERT_TRUE(create_test_validator_keystore(cfg, 0));
  { node::Node n(cfg); ASSERT_TRUE(n.init()); n.stop(); }
  storage::DB db;
  ASSERT_TRUE(db.open(cfg.db_path));
  FrontierProposal proposal;
  ASSERT_TRUE(build_test_frontier_proposal_with_certified_ingress(cfg, db, &proposal));
  proposal.transition.decisions_commitment[0] ^= 0x01;
  db.close();
  node::Node target(cfg);
  ASSERT_TRUE(target.init());
  const auto msg = make_test_frontier_propose_msg(target.consensus_domain_for_test(), proposal);
  ASSERT_TRUE(!target.inject_propose_msg_for_test(msg));
}

TEST(test_frontier_mode_validation_rejects_bad_settlement_commitment) {
  const auto base = unique_test_base("/tmp/finalis_it_frontier_validate_bad_settlement");
  auto cfg = single_node_cfg(base, 1);
  ASSERT_TRUE(write_mainnet_genesis_file(cfg.genesis_path, 1));
  ASSERT_TRUE(create_test_validator_keystore(cfg, 0));
  { node::Node n(cfg); ASSERT_TRUE(n.init()); n.stop(); }
  storage::DB db;
  ASSERT_TRUE(db.open(cfg.db_path));
  FrontierProposal proposal;
  ASSERT_TRUE(build_test_frontier_proposal_with_certified_ingress(cfg, db, &proposal));
  proposal.transition.settlement_commitment[0] ^= 0x01;
  db.close();
  node::Node target(cfg);
  ASSERT_TRUE(target.init());
  const auto msg = make_test_frontier_propose_msg(target.consensus_domain_for_test(), proposal);
  ASSERT_TRUE(!target.inject_propose_msg_for_test(msg));
}

TEST(test_frontier_mode_validation_rejects_bad_next_state_root) {
  const auto base = unique_test_base("/tmp/finalis_it_frontier_validate_bad_root");
  auto cfg = single_node_cfg(base, 1);
  ASSERT_TRUE(write_mainnet_genesis_file(cfg.genesis_path, 1));
  ASSERT_TRUE(create_test_validator_keystore(cfg, 0));
  { node::Node n(cfg); ASSERT_TRUE(n.init()); n.stop(); }
  storage::DB db;
  ASSERT_TRUE(db.open(cfg.db_path));
  FrontierProposal proposal;
  ASSERT_TRUE(build_test_frontier_proposal_with_certified_ingress(cfg, db, &proposal));
  proposal.transition.next_state_root[0] ^= 0x01;
  db.close();
  node::Node target(cfg);
  ASSERT_TRUE(target.init());
  const auto msg = make_test_frontier_propose_msg(target.consensus_domain_for_test(), proposal);
  ASSERT_TRUE(!target.inject_propose_msg_for_test(msg));
}

TEST(test_frontier_mode_validation_accepts_proposal_without_local_certified_lane_record) {
  const auto base = unique_test_base("/tmp/finalis_it_frontier_validate_missing_cert");
  auto cfg = single_node_cfg(base, 1);
  ASSERT_TRUE(write_mainnet_genesis_file(cfg.genesis_path, 1));
  ASSERT_TRUE(create_test_validator_keystore(cfg, 0));
  { node::Node n(cfg); ASSERT_TRUE(n.init()); n.stop(); }
  storage::DB db;
  ASSERT_TRUE(db.open(cfg.db_path));
  FrontierProposal proposal;
  ASSERT_TRUE(build_test_frontier_proposal_with_certified_ingress(cfg, db, &proposal));
  const auto certs = db.scan_prefix(storage::key_ingress_certificate_prefix());
  ASSERT_TRUE(!certs.empty());
  ASSERT_TRUE(db.erase(certs.begin()->first));
  db.close();
  node::Node target(cfg);
  ASSERT_TRUE(target.init());
  const auto msg = make_test_frontier_propose_msg(target.consensus_domain_for_test(), proposal);
  ASSERT_TRUE(target.inject_propose_msg_for_test(msg));
}

TEST(test_frontier_mode_validation_accepts_proposal_without_local_ingress_bytes) {
  const auto base = unique_test_base("/tmp/finalis_it_frontier_validate_missing_bytes");
  auto cfg = single_node_cfg(base, 1);
  ASSERT_TRUE(write_mainnet_genesis_file(cfg.genesis_path, 1));
  ASSERT_TRUE(create_test_validator_keystore(cfg, 0));
  { node::Node n(cfg); ASSERT_TRUE(n.init()); n.stop(); }
  storage::DB db;
  ASSERT_TRUE(db.open(cfg.db_path));
  FrontierProposal proposal;
  ASSERT_TRUE(build_test_frontier_proposal_with_certified_ingress(cfg, db, &proposal));
  const auto bytes = db.scan_prefix(storage::key_ingress_bytes_prefix());
  ASSERT_TRUE(!bytes.empty());
  ASSERT_TRUE(db.erase(bytes.begin()->first));
  db.close();
  node::Node target(cfg);
  ASSERT_TRUE(target.init());
  const auto msg = make_test_frontier_propose_msg(target.consensus_domain_for_test(), proposal);
  ASSERT_TRUE(target.inject_propose_msg_for_test(msg));
}

TEST(test_frontier_mode_validation_rejects_non_monotone_vector) {
  const auto base = unique_test_base("/tmp/finalis_it_frontier_validate_vector_rewind");
  auto cfg = single_node_cfg(base, 1);
  ASSERT_TRUE(write_mainnet_genesis_file(cfg.genesis_path, 1));
  ASSERT_TRUE(create_test_validator_keystore(cfg, 0));
  { node::Node n(cfg); ASSERT_TRUE(n.init()); n.stop(); }
  storage::DB db;
  ASSERT_TRUE(db.open(cfg.db_path));
  FrontierProposal proposal;
  ASSERT_TRUE(build_test_frontier_proposal_with_certified_ingress(cfg, db, &proposal));
  bool rewound = false;
  for (std::size_t lane = 0; lane < finalis::INGRESS_LANE_COUNT; ++lane) {
    if (proposal.transition.next_vector.lane_max_seq[lane] > proposal.transition.prev_vector.lane_max_seq[lane]) {
      proposal.transition.next_vector.lane_max_seq[lane] = proposal.transition.prev_vector.lane_max_seq[lane] - 1;
      rewound = true;
      break;
    }
  }
  ASSERT_TRUE(rewound);
  db.close();
  node::Node target(cfg);
  ASSERT_TRUE(target.init());
  const auto msg = make_test_frontier_propose_msg(target.consensus_domain_for_test(), proposal);
  ASSERT_TRUE(!target.inject_propose_msg_for_test(msg));
}

TEST(test_frontier_mode_proposer_builds_from_certified_ingress) {
  const auto base = unique_test_base("/tmp/finalis_it_frontier_build_ok");
  auto cfg = single_node_cfg(base, 1);
  ASSERT_TRUE(write_mainnet_genesis_file(cfg.genesis_path, 1));
  ASSERT_TRUE(create_test_validator_keystore(cfg, 0));
  { node::Node n(cfg); ASSERT_TRUE(n.init()); n.stop(); }

  storage::DB db;
  ASSERT_TRUE(db.open(cfg.db_path));
  Tx tx;
  tx.version = 1;
  tx.lock_time = 0;
  tx.outputs.push_back(TxOut{1, Bytes{'b', 'u', 'i', 'l', 'd'}});
  CertifiedIngressFixture fixture;
  ASSERT_TRUE(persist_certified_ingress_fixture(cfg, db, {tx.serialize()}, &fixture));
  db.close();

  node::Node target(cfg);
  ASSERT_TRUE(target.init());
  auto proposal = build_test_frontier_proposal(target, 1, 0);
  ASSERT_TRUE(proposal.has_value());
  ASSERT_EQ(proposal->transition.next_vector, fixture.next_vector);
  ASSERT_EQ(proposal->ordered_records, fixture.merged_records);
}

TEST(test_frontier_mode_proposer_build_is_identical_across_nodes_with_same_certified_ingress) {
  const auto base_a = unique_test_base("/tmp/finalis_it_frontier_build_same_a");
  const auto base_b = unique_test_base("/tmp/finalis_it_frontier_build_same_b");
  auto cfg_a = single_node_cfg(base_a, 1);
  auto cfg_b = single_node_cfg(base_b, 1);
  ASSERT_TRUE(write_mainnet_genesis_file(cfg_a.genesis_path, 1));
  ASSERT_TRUE(write_mainnet_genesis_file(cfg_b.genesis_path, 1));
  ASSERT_TRUE(create_test_validator_keystore(cfg_a, 0));
  ASSERT_TRUE(create_test_validator_keystore(cfg_b, 0));
  { node::Node n(cfg_a); ASSERT_TRUE(n.init()); n.stop(); }
  { node::Node n(cfg_b); ASSERT_TRUE(n.init()); n.stop(); }

  Tx tx_a;
  tx_a.version = 1;
  tx_a.outputs.push_back(TxOut{1, Bytes{'x'}});
  Tx tx_b;
  tx_b.version = 1;
  tx_b.outputs.push_back(TxOut{2, Bytes{'y'}});

  storage::DB db_a;
  storage::DB db_b;
  ASSERT_TRUE(db_a.open(cfg_a.db_path));
  ASSERT_TRUE(db_b.open(cfg_b.db_path));
  ASSERT_TRUE(persist_certified_ingress_fixture(cfg_a, db_a, {tx_a.serialize(), tx_b.serialize()}));
  ASSERT_TRUE(persist_certified_ingress_fixture(cfg_b, db_b, {tx_a.serialize(), tx_b.serialize()}));
  db_a.close();
  db_b.close();

  node::Node node_a(cfg_a);
  node::Node node_b(cfg_b);
  ASSERT_TRUE(node_a.init());
  ASSERT_TRUE(node_b.init());
  auto proposal_a = build_test_frontier_proposal(node_a, 1, 0);
  auto proposal_b = build_test_frontier_proposal(node_b, 1, 0);
  ASSERT_TRUE(proposal_a.has_value());
  ASSERT_TRUE(proposal_b.has_value());
  ASSERT_EQ(proposal_a->serialize(), proposal_b->serialize());
  ASSERT_EQ(proposal_a->transition.transition_id(), proposal_b->transition.transition_id());
}

TEST(test_frontier_mode_proposer_build_does_not_depend_on_mempool_state) {
  const auto base = unique_test_base("/tmp/finalis_it_frontier_build_no_mempool");
  auto cfg = single_node_cfg(base, 1);
  ASSERT_TRUE(write_mainnet_genesis_file(cfg.genesis_path, 1));
  ASSERT_TRUE(create_test_validator_keystore(cfg, 0));
  { node::Node n(cfg); ASSERT_TRUE(n.init()); n.stop(); }

  storage::DB db;
  ASSERT_TRUE(db.open(cfg.db_path));
  Tx tx;
  tx.version = 1;
  tx.outputs.push_back(TxOut{3, Bytes{'m', 'e', 'r', 'g', 'e'}});
  CertifiedIngressFixture fixture;
  ASSERT_TRUE(persist_certified_ingress_fixture(cfg, db, {tx.serialize()}, &fixture));
  db.close();

  node::Node target(cfg);
  ASSERT_TRUE(target.init());
  auto proposal_before = build_test_frontier_proposal(target, 1, 0);
  ASSERT_TRUE(proposal_before.has_value());

  Tx unrelated;
  unrelated.version = 1;
  unrelated.outputs.push_back(TxOut{9, Bytes{'i', 'g', 'n', 'o', 'r', 'e'}});
  (void)target.inject_tx_for_test(unrelated, false);

  auto proposal_after = build_test_frontier_proposal(target, 1, 0);
  ASSERT_TRUE(proposal_after.has_value());
  ASSERT_EQ(proposal_before->serialize(), proposal_after->serialize());
  ASSERT_EQ(proposal_after->ordered_records, fixture.merged_records);
}

TEST(test_frontier_mode_proposer_build_rejects_missing_certified_lane_record) {
  const auto base = unique_test_base("/tmp/finalis_it_frontier_build_missing_cert");
  auto cfg = single_node_cfg(base, 1);
  ASSERT_TRUE(write_mainnet_genesis_file(cfg.genesis_path, 1));
  ASSERT_TRUE(create_test_validator_keystore(cfg, 0));
  { node::Node n(cfg); ASSERT_TRUE(n.init()); n.stop(); }

  storage::DB db;
  ASSERT_TRUE(db.open(cfg.db_path));
  Tx tx;
  tx.version = 1;
  tx.outputs.push_back(TxOut{1, Bytes{'c'}});
  ASSERT_TRUE(persist_certified_ingress_fixture(cfg, db, {tx.serialize()}));
  const auto certs = db.scan_prefix(storage::key_ingress_certificate_prefix());
  ASSERT_TRUE(!certs.empty());
  ASSERT_TRUE(db.erase(certs.begin()->first));
  db.close();

  node::Node target(cfg);
  ASSERT_TRUE(target.init());
  ASSERT_TRUE(!build_test_frontier_proposal(target, 1, 0).has_value());
}

TEST(test_frontier_mode_proposer_build_rejects_missing_ingress_bytes) {
  const auto base = unique_test_base("/tmp/finalis_it_frontier_build_missing_bytes");
  auto cfg = single_node_cfg(base, 1);
  ASSERT_TRUE(write_mainnet_genesis_file(cfg.genesis_path, 1));
  ASSERT_TRUE(create_test_validator_keystore(cfg, 0));
  { node::Node n(cfg); ASSERT_TRUE(n.init()); n.stop(); }

  storage::DB db;
  ASSERT_TRUE(db.open(cfg.db_path));
  Tx tx;
  tx.version = 1;
  tx.outputs.push_back(TxOut{1, Bytes{'b'}});
  ASSERT_TRUE(persist_certified_ingress_fixture(cfg, db, {tx.serialize()}));
  const auto bytes = db.scan_prefix(storage::key_ingress_bytes_prefix());
  ASSERT_TRUE(!bytes.empty());
  ASSERT_TRUE(db.erase(bytes.begin()->first));
  db.close();

  node::Node target(cfg);
  ASSERT_TRUE(target.init());
  ASSERT_TRUE(!build_test_frontier_proposal(target, 1, 0).has_value());
}

TEST(test_frontier_mode_built_proposal_is_accepted_by_existing_validation) {
  const auto base = unique_test_base("/tmp/finalis_it_frontier_build_validates");
  auto cfg = single_node_cfg(base, 1);
  ASSERT_TRUE(write_mainnet_genesis_file(cfg.genesis_path, 1));
  ASSERT_TRUE(create_test_validator_keystore(cfg, 0));
  { node::Node n(cfg); ASSERT_TRUE(n.init()); n.stop(); }

  storage::DB db;
  ASSERT_TRUE(db.open(cfg.db_path));
  Tx tx;
  tx.version = 1;
  tx.outputs.push_back(TxOut{4, Bytes{'v'}});
  ASSERT_TRUE(persist_certified_ingress_fixture(cfg, db, {tx.serialize()}));
  db.close();

  node::Node target(cfg);
  ASSERT_TRUE(target.init());
  auto proposal = build_test_frontier_proposal(target, 1, 0);
  ASSERT_TRUE(proposal.has_value());

  const auto msg = make_test_frontier_propose_msg(target.consensus_domain_for_test(), *proposal);
  ASSERT_TRUE(target.inject_propose_msg_for_test(msg));
}

TEST(test_frontier_mode_built_ordered_records_match_deterministic_certified_merge) {
  const auto base = unique_test_base("/tmp/finalis_it_frontier_build_ordered_match");
  auto cfg = single_node_cfg(base, 1);
  ASSERT_TRUE(write_mainnet_genesis_file(cfg.genesis_path, 1));
  ASSERT_TRUE(create_test_validator_keystore(cfg, 0));
  { node::Node n(cfg); ASSERT_TRUE(n.init()); n.stop(); }

  Tx tx_a;
  tx_a.version = 1;
  tx_a.outputs.push_back(TxOut{5, Bytes{'a'}});
  Tx tx_b;
  tx_b.version = 1;
  tx_b.outputs.push_back(TxOut{6, Bytes{'b'}});
  Tx tx_c;
  tx_c.version = 1;
  tx_c.outputs.push_back(TxOut{7, Bytes{'c'}});

  storage::DB db;
  ASSERT_TRUE(db.open(cfg.db_path));
  CertifiedIngressFixture fixture;
  ASSERT_TRUE(persist_certified_ingress_fixture(cfg, db, {tx_a.serialize(), tx_b.serialize(), tx_c.serialize()}, &fixture));
  db.close();

  node::Node target(cfg);
  ASSERT_TRUE(target.init());
  auto proposal = build_test_frontier_proposal(target, 1, 0);
  ASSERT_TRUE(proposal.has_value());
  ASSERT_EQ(proposal->ordered_records, fixture.merged_records);
}

TEST(test_frontier_mode_requests_and_appends_missing_certified_ingress_range_from_peer_fixture) {
  const auto base = unique_test_base("/tmp/finalis_it_ingress_sync_ok");
  auto cfg = single_node_cfg(base, 1);
  ASSERT_TRUE(write_mainnet_genesis_file(cfg.genesis_path, 1));
  ASSERT_TRUE(create_test_validator_keystore(cfg, 0));

  node::Node target(cfg);
  ASSERT_TRUE(target.init());

  Tx tx;
  tx.version = 1;
  tx.outputs.push_back(TxOut{11, Bytes{'i', 'n', 'g', 'r', 'e', 's', 's'}});
  const auto rec = make_signed_ingress_record_msg(tx.serialize(), 1, 1, zero_hash());

  p2p::IngressTipsMsg tips;
  tips.lane_tips[rec.certificate.lane] = 1;
  ASSERT_TRUE(target.inject_ingress_tips_for_test(tips, 7));
  auto req = target.requested_ingress_range_for_test(7, rec.certificate.lane);
  ASSERT_TRUE(req.has_value());
  ASSERT_EQ(req->from_seq, 1u);
  ASSERT_EQ(req->to_seq, 1u);

  p2p::IngressRangeMsg range;
  range.lane = rec.certificate.lane;
  range.from_seq = 1;
  range.to_seq = 1;
  range.records.push_back(rec);
  ASSERT_TRUE(target.inject_ingress_range_for_test(range, 7));
  target.stop();

  storage::DB db;
  ASSERT_TRUE(db.open(cfg.db_path));
  auto state = db.get_lane_state(rec.certificate.lane);
  ASSERT_TRUE(state.has_value());
  ASSERT_EQ(state->max_seq, 1u);
  auto stored = db.get_ingress_certificate(rec.certificate.lane, 1);
  ASSERT_TRUE(stored.has_value());
}

TEST(test_frontier_mode_higher_peer_lane_tip_triggers_missing_range_request) {
  const auto base = unique_test_base("/tmp/finalis_it_ingress_sync_request");
  auto cfg = single_node_cfg(base, 1);
  ASSERT_TRUE(write_mainnet_genesis_file(cfg.genesis_path, 1));
  ASSERT_TRUE(create_test_validator_keystore(cfg, 0));

  node::Node target(cfg);
  ASSERT_TRUE(target.init());

  p2p::IngressTipsMsg tips;
  tips.lane_tips[3] = 5;
  ASSERT_TRUE(target.inject_ingress_tips_for_test(tips, 9));
  auto req = target.requested_ingress_range_for_test(9, 3);
  ASSERT_TRUE(req.has_value());
  ASSERT_EQ(req->lane, 3u);
  ASSERT_EQ(req->from_seq, 1u);
  ASSERT_EQ(req->to_seq, 5u);
}

TEST(test_frontier_mode_clamps_oversized_missing_range_request) {
  const auto base = unique_test_base("/tmp/finalis_it_ingress_sync_clamp");
  auto cfg = single_node_cfg(base, 1);
  ASSERT_TRUE(write_mainnet_genesis_file(cfg.genesis_path, 1));
  ASSERT_TRUE(create_test_validator_keystore(cfg, 0));

  node::Node target(cfg);
  ASSERT_TRUE(target.init());

  p2p::IngressTipsMsg tips;
  tips.lane_tips[2] = 5000;
  ASSERT_TRUE(target.inject_ingress_tips_for_test(tips, 11));
  auto req = target.requested_ingress_range_for_test(11, 2);
  ASSERT_TRUE(req.has_value());
  ASSERT_EQ(req->from_seq, 1u);
  ASSERT_EQ(req->to_seq, 1024u);
}

TEST(test_frontier_mode_rejects_conflicting_ingress_record_from_peer_fixture) {
  const auto base = unique_test_base("/tmp/finalis_it_ingress_sync_conflict");
  auto cfg = single_node_cfg(base, 1);
  ASSERT_TRUE(write_mainnet_genesis_file(cfg.genesis_path, 1));
  ASSERT_TRUE(create_test_validator_keystore(cfg, 0));

  Tx tx_a;
  tx_a.version = 1;
  tx_a.outputs.push_back(TxOut{12, Bytes{'a'}});
  const auto rec_a = make_signed_ingress_record_msg(tx_a.serialize(), 1, 1, zero_hash());

  Tx tx_b;
  tx_b.version = 1;
  tx_b.outputs.push_back(TxOut{13, Bytes{'b'}});
  Bytes tx_b_bytes = tx_b.serialize();
  for (int i = 0; i < 256; ++i) {
    tx_b.outputs[0].script_pubkey = Bytes{static_cast<std::uint8_t>(i)};
    tx_b_bytes = tx_b.serialize();
    auto parsed = Tx::parse(tx_b_bytes);
    ASSERT_TRUE(parsed.has_value());
    if (consensus::assign_ingress_lane(*parsed) == rec_a.certificate.lane) break;
  }
  const auto rec_b = make_signed_ingress_record_msg(tx_b_bytes, 1, 1, zero_hash());
  ASSERT_EQ(rec_b.certificate.lane, rec_a.certificate.lane);

  storage::DB db;
  ASSERT_TRUE(db.open(cfg.db_path));
  ASSERT_TRUE(db.put_ingress_bytes(rec_a.certificate.txid, rec_a.tx_bytes));
  ASSERT_TRUE(db.put_ingress_certificate(rec_a.certificate.lane, rec_a.certificate.seq, rec_a.certificate.serialize()));
  ASSERT_TRUE(db.put_lane_state(rec_a.certificate.lane,
                                LaneState{rec_a.certificate.epoch, rec_a.certificate.lane, rec_a.certificate.seq,
                                          consensus::compute_lane_root_append(zero_hash(), rec_a.certificate.tx_hash)}));
  db.close();

  node::Node target(cfg);
  ASSERT_TRUE(target.init());
  target.set_requested_ingress_range_for_test(5, p2p::GetIngressRangeMsg{rec_a.certificate.lane, 1, 1});

  p2p::IngressRangeMsg range;
  range.lane = rec_b.certificate.lane;
  range.from_seq = 1;
  range.to_seq = 1;
  range.records.push_back(rec_b);
  ASSERT_TRUE(!target.inject_ingress_range_for_test(range, 5));
  target.stop();

  storage::DB db2;
  ASSERT_TRUE(db2.open(cfg.db_path));
  const auto evidence =
      db2.get_ingress_equivocation_evidence(rec_a.certificate.epoch, rec_a.certificate.lane, rec_a.certificate.seq);
  ASSERT_TRUE(evidence.has_value());
}

// A range response overlapping records the node already holds (gossip won the race) must be a
// no-op for those records, not an ingress-seq-discontinuity that scores an honest peer.
TEST(test_frontier_mode_accepts_ingress_range_overlapping_held_records) {
  const auto base = unique_test_base("/tmp/finalis_it_ingress_sync_overlap");
  auto cfg = single_node_cfg(base, 1);
  ASSERT_TRUE(write_mainnet_genesis_file(cfg.genesis_path, 1));
  ASSERT_TRUE(create_test_validator_keystore(cfg, 0));

  Tx tx_a;
  tx_a.version = 1;
  tx_a.outputs.push_back(TxOut{16, Bytes{'h'}});
  const auto rec_a = make_signed_ingress_record_msg(tx_a.serialize(), 1, 1, zero_hash());
  const auto root_a = consensus::compute_lane_root_append(zero_hash(), rec_a.certificate.tx_hash);
  Tx tx_b;
  tx_b.version = 1;
  tx_b.outputs.push_back(TxOut{17, Bytes{'n'}});
  Bytes tx_b_bytes = tx_b.serialize();
  for (int i = 0; i < 256; ++i) {
    tx_b.outputs[0].script_pubkey = Bytes{static_cast<std::uint8_t>(i)};
    tx_b_bytes = tx_b.serialize();
    auto parsed = Tx::parse(tx_b_bytes);
    ASSERT_TRUE(parsed.has_value());
    if (consensus::assign_ingress_lane(*parsed) == rec_a.certificate.lane) break;
  }
  const auto rec_b = make_signed_ingress_record_msg(tx_b_bytes, 1, 2, root_a);
  ASSERT_EQ(rec_b.certificate.lane, rec_a.certificate.lane);
  const auto lane = rec_a.certificate.lane;

  storage::DB db;
  ASSERT_TRUE(db.open(cfg.db_path));
  ASSERT_TRUE(db.put_ingress_bytes(rec_a.certificate.txid, rec_a.tx_bytes));
  ASSERT_TRUE(db.put_ingress_certificate(lane, rec_a.certificate.seq, rec_a.certificate.serialize()));
  ASSERT_TRUE(db.put_lane_state(lane, LaneState{rec_a.certificate.epoch, lane, rec_a.certificate.seq, root_a}));
  db.close();

  node::Node target(cfg);
  ASSERT_TRUE(target.init());

  // Held record with a payload that does not match its certificate is still rejected.
  auto tampered = rec_a;
  tampered.tx_bytes = tx_b_bytes;
  target.set_requested_ingress_range_for_test(5, p2p::GetIngressRangeMsg{lane, 1, 1});
  p2p::IngressRangeMsg bad;
  bad.lane = lane;
  bad.from_seq = 1;
  bad.to_seq = 1;
  bad.records.push_back(tampered);
  ASSERT_TRUE(!target.inject_ingress_range_result_for_test(bad, 5).empty());

  // Exact re-delivery of the held record.
  target.set_requested_ingress_range_for_test(5, p2p::GetIngressRangeMsg{lane, 1, 1});
  p2p::IngressRangeMsg same;
  same.lane = lane;
  same.from_seq = 1;
  same.to_seq = 1;
  same.records.push_back(rec_a);
  ASSERT_EQ(target.inject_ingress_range_result_for_test(same, 5), std::string{});
  ASSERT_EQ(target.lane_state_for_test(lane)->max_seq, 1u);

  // A reply covering only a prefix of the request (the responder caps reply bytes) is accepted; one
  // reaching past the request is not.
  target.set_requested_ingress_range_for_test(5, p2p::GetIngressRangeMsg{lane, 1, 3});
  ASSERT_EQ(target.inject_ingress_range_result_for_test(same, 5), std::string{});
  target.set_requested_ingress_range_for_test(5, p2p::GetIngressRangeMsg{lane, 1, 1});
  p2p::IngressRangeMsg past;
  past.lane = lane;
  past.from_seq = 1;
  past.to_seq = 2;
  past.records = {rec_a, rec_b};
  ASSERT_EQ(target.inject_ingress_range_result_for_test(past, 5), std::string("unexpected-range"));

  // Held prefix plus a new record: the new one appends on top of the held tip.
  target.set_requested_ingress_range_for_test(5, p2p::GetIngressRangeMsg{lane, 1, 2});
  p2p::IngressRangeMsg overlap;
  overlap.lane = lane;
  overlap.from_seq = 1;
  overlap.to_seq = 2;
  overlap.records.push_back(rec_a);
  overlap.records.push_back(rec_b);
  ASSERT_EQ(target.inject_ingress_range_result_for_test(overlap, 5), std::string{});
  const auto tip = target.lane_state_for_test(lane);
  ASSERT_TRUE(tip.has_value());
  ASSERT_EQ(tip->max_seq, 2u);
  ASSERT_EQ(tip->lane_root, consensus::compute_lane_root_append(root_a, rec_b.certificate.tx_hash));
  target.stop();
}

TEST(test_frontier_mode_rejects_incomplete_or_invalid_ingress_ranges_from_peer_fixture) {
  const auto base = unique_test_base("/tmp/finalis_it_ingress_sync_invalid");
  auto cfg = single_node_cfg(base, 1);
  ASSERT_TRUE(write_mainnet_genesis_file(cfg.genesis_path, 1));
  ASSERT_TRUE(create_test_validator_keystore(cfg, 0));

  node::Node target(cfg);
  ASSERT_TRUE(target.init());

  Tx tx_a;
  tx_a.version = 1;
  tx_a.outputs.push_back(TxOut{14, Bytes{'x'}});
  const auto rec_a = make_signed_ingress_record_msg(tx_a.serialize(), 1, 1, zero_hash());
  Tx tx_b;
  tx_b.version = 1;
  tx_b.outputs.push_back(TxOut{15, Bytes{'y'}});
  Bytes tx_b_bytes = tx_b.serialize();
  for (int i = 0; i < 256; ++i) {
    tx_b.outputs[0].script_pubkey = Bytes{static_cast<std::uint8_t>(i)};
    tx_b_bytes = tx_b.serialize();
    auto parsed = Tx::parse(tx_b_bytes);
    ASSERT_TRUE(parsed.has_value());
    if (consensus::assign_ingress_lane(*parsed) == rec_a.certificate.lane) break;
  }
  const auto rec_b = make_signed_ingress_record_msg(
      tx_b_bytes, 1, 2, consensus::compute_lane_root_append(zero_hash(), rec_a.certificate.tx_hash));
  ASSERT_EQ(rec_b.certificate.lane, rec_a.certificate.lane);

  p2p::IngressTipsMsg tips;
  tips.lane_tips[rec_a.certificate.lane] = 2;
  ASSERT_TRUE(target.inject_ingress_tips_for_test(tips, 3));

  p2p::IngressRangeMsg incomplete;
  incomplete.lane = rec_a.certificate.lane;
  incomplete.from_seq = 1;
  incomplete.to_seq = 2;
  incomplete.records.push_back(rec_a);
  ASSERT_TRUE(!target.inject_ingress_range_for_test(incomplete, 3));

  p2p::IngressRangeMsg missing_bytes = incomplete;
  missing_bytes.records.push_back(rec_b);
  missing_bytes.records[1].tx_bytes.clear();
  ASSERT_TRUE(!target.inject_ingress_range_for_test(missing_bytes, 3));

  p2p::IngressRangeMsg bad_continuity = incomplete;
  auto broken = rec_b;
  broken.certificate.prev_lane_root[0] ^= 0x01;
  bad_continuity.records.push_back(broken);
  ASSERT_TRUE(!target.inject_ingress_range_for_test(bad_continuity, 3));
  target.stop();

  storage::DB db;
  ASSERT_TRUE(db.open(cfg.db_path));
  ASSERT_TRUE(!db.get_lane_state(rec_a.certificate.lane).has_value());
}

TEST(test_frontier_mode_rejects_oversized_or_unexpected_ingress_ranges_from_peer_fixture) {
  const auto base = unique_test_base("/tmp/finalis_it_ingress_sync_bounds");
  auto cfg = single_node_cfg(base, 1);
  ASSERT_TRUE(write_mainnet_genesis_file(cfg.genesis_path, 1));
  ASSERT_TRUE(create_test_validator_keystore(cfg, 0));

  node::Node target(cfg);
  ASSERT_TRUE(target.init());

  Tx tx;
  tx.version = 1;
  tx.outputs.push_back(TxOut{16, Bytes{'z'}});
  const auto rec = make_signed_ingress_record_msg(tx.serialize(), 1, 1, zero_hash());

  target.set_requested_ingress_range_for_test(4, p2p::GetIngressRangeMsg{rec.certificate.lane, 1, 1});

  p2p::IngressRangeMsg unexpected;
  unexpected.lane = rec.certificate.lane;
  unexpected.from_seq = 2;
  unexpected.to_seq = 2;
  unexpected.records.push_back(rec);
  ASSERT_TRUE(!target.inject_ingress_range_for_test(unexpected, 4));

  target.set_requested_ingress_range_for_test(4, p2p::GetIngressRangeMsg{rec.certificate.lane, 1, 1025});
  p2p::IngressRangeMsg oversized;
  oversized.lane = rec.certificate.lane;
  oversized.from_seq = 1;
  oversized.to_seq = 1025;
  oversized.records.resize(1025, rec);
  ASSERT_TRUE(!target.inject_ingress_range_for_test(oversized, 4));
  target.stop();

  storage::DB db;
  ASSERT_TRUE(db.open(cfg.db_path));
  ASSERT_TRUE(!db.get_lane_state(rec.certificate.lane).has_value());
}

// Finalized slices can contain transactions that frontier execution rejects (here: no inputs, so the
// output is created from nothing). Such a transaction moved no funds and must not be reported as a
// finalized, credit-safe transfer, or an exchange polling get_tx_status would credit it.
TEST(test_rejected_frontier_tx_is_not_reported_credit_safe) {
  const std::string base = unique_test_base("/tmp/finalis_it_rejected_tx_not_credit_safe");
  Tx tx = make_fixture_ingress_tx(1, 0xB7);

  node::NodeConfig cfg;
  cfg.allow_unencrypted_keystore = true;  // test fixture: no passphrase
  cfg.disable_p2p = true;
  cfg.node_id = 0;
  cfg.max_committee = 1;
  cfg.network.min_block_interval_ms = 100;
  cfg.network.round_timeout_ms = 200;
  cfg.p2p_port = 0;
  cfg.db_path = base + "/node0";
  cfg.genesis_path = base + "/genesis.json";
  cfg.allow_unsafe_genesis_override = true;
  cfg.validator_key_file = cfg.db_path + "/keystore/validator.json";
  cfg.validator_passphrase = "test-pass";

  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);
  ASSERT_TRUE(write_mainnet_genesis_file(cfg.genesis_path, 1));
  keystore::ValidatorKey key;
  std::string kerr;
  ASSERT_TRUE(keystore::create_validator_keystore(cfg.validator_key_file, cfg.validator_passphrase, "mainnet", "sc",
                                                  deterministic_seed_for_node_id(0), &key, &kerr));

  std::unique_ptr<node::Node> node;
  ASSERT_TRUE(restart_single_node_with_seeded_certified_ingress(cfg, {tx.serialize()}, &node));
  ASSERT_TRUE(wait_for([&]() { return node->status().height >= 1; }, std::chrono::seconds(10)));
  node->stop();
  node.reset();

  {
    storage::DB db;
    ASSERT_TRUE(db.open(cfg.db_path));
    // Rejected by execution: its output never entered the UTXO set, and nothing is indexed.
    ASSERT_TRUE(!db.get_utxo_v2(OutPoint{tx.txid(), 0}).has_value());
    ASSERT_TRUE(!db.get_tx_index(tx.txid()).has_value());
    ASSERT_TRUE(db.get_script_history(crypto::sha256(tx.outputs[0].script_pubkey)).empty());
    ASSERT_TRUE(db.get_rejected_tx_height(tx.txid()).has_value());
  }

  lightserver::Config lcfg;
  lcfg.db_path = cfg.db_path;
  lightserver::Server ls(lcfg);
  ASSERT_TRUE(ls.init());
  const std::string body = std::string(R"({"jsonrpc":"2.0","id":303,"method":"get_tx_status","params":{"txid":")") +
                           hex_encode32(tx.txid()) + R"("}})";
  const auto resp = ls.handle_rpc_for_test(body);
  if (resp.find("\"credit_safe\":true") != std::string::npos) {
    throw std::runtime_error("rejected tx reported credit-safe: " + resp);
  }
  ASSERT_TRUE(resp.find("\"status\":\"rejected\"") != std::string::npos);
  ASSERT_TRUE(resp.find("\"finalized\":false") != std::string::npos);
}

// Precommits form a quorum per round only. In a Byzantine chaos run a round-1 quorum was cast but
// never assembled after a partition, because each node re-gossiped only its latest (lock) precommit,
// and the height took 12 rounds. Re-gossip must cover every own precommit at the height and the
// signatures of the set closest to quorum.
TEST(test_stalled_height_regossips_old_round_precommits) {
  auto f = make_two_phase_fixture("/tmp/finalis_it_regossip_old_precommits", 0x94);
  auto& target = f->target();
  const auto a_id = frontier_proposal_id(*f->a0);
  const auto me = target.local_validator_pubkey_for_test();

  // Round 0: polka, lock and precommit; one other validator's round-0 precommit arrives (2 < quorum).
  ASSERT_TRUE(advance_test_frontier_round(target, f->height, 0));
  ASSERT_EQ(target.inject_network_propose_result_for_test(make_test_frontier_propose_msg(f->target().consensus_domain_for_test(), *f->a0)),
            std::string("accepted"));
  inject_test_prevotes(target, f->keys, f->committee, f->height, 0, a_id, f->quorum - 1);
  ASSERT_TRUE(wait_for_local_precommit(target, f->height, 0, a_id));
  PubKey32 other{};
  for (const auto& pub : f->committee) {
    if (pub != me) {
      other = pub;
      break;
    }
  }
  ASSERT_TRUE(target.inject_vote_for_test(make_test_vote(f->target().consensus_domain_for_test(), f->keys, f->height, 0, a_id, other)));

  // Round 1: the same value is re-proposed with its round-0 polka; the lock moves to round 1.
  const auto tc0 = make_test_timeout_certificate(f->target().consensus_domain_for_test(), f->keys, f->committee, f->height, 0, f->quorum);
  ASSERT_TRUE(advance_test_frontier_round(target, f->height, 1));
  const auto leader1 = target.proposer_for_height_round_for_test(f->height, 1);
  ASSERT_TRUE(leader1.has_value());
  const auto polka0 = make_test_polka(f->target().consensus_domain_for_test(), f->keys, f->committee, f->height, 0, a_id, f->quorum);
  ASSERT_EQ(target.inject_network_propose_result_for_test(make_test_frontier_propose_msg(f->target().consensus_domain_for_test(), *f->a0, polka0, tc0, 1, *leader1)),
            std::string("accepted"));
  inject_test_prevotes(target, f->keys, f->committee, f->height, 1, a_id, f->quorum - 1);
  ASSERT_TRUE(wait_for_local_precommit(target, f->height, 1, a_id));
  ASSERT_EQ(target.local_vote_lock_for_test(f->height)->second, 1u);

  const auto precommits = target.precommits_for_rebroadcast_for_test(f->height);
  const auto has = [&](std::uint32_t round, const PubKey32& signer) {
    return std::any_of(precommits.begin(), precommits.end(), [&](const Vote& v) {
      return v.round == round && v.validator_pubkey == signer && v.frontier_transition_id == a_id;
    });
  };
  ASSERT_TRUE(has(1, me));     // the lock's round, as before
  ASSERT_TRUE(has(0, me));     // the older own precommit: previously dropped
  ASSERT_TRUE(has(0, other));  // round 0 is closest to quorum: its other signatures travel too
}

// A validator caught equivocating still has its votes counted, one per round. Ignoring them left
// only the honest validators to form quorums: in a Byzantine chaos run with both faulty validators
// caught, every honest validator was needed for every height and one slow node stalled a height for
// 10 rounds. Safety does not depend on ignoring them (the rules are safe for f arbitrary voters).
TEST(test_known_equivocator_votes_still_count_toward_polka) {
  auto f = make_two_phase_fixture("/tmp/finalis_it_equivocator_votes_count", 0x95);
  auto& target = f->target();
  const auto a_id = frontier_proposal_id(*f->a0);
  const auto b0_id = frontier_proposal_id(*f->b0);
  const auto b1_id = frontier_proposal_id(*f->b1);
  std::vector<PubKey32> others;
  for (const auto& pub : f->committee) {
    if (pub != target.local_validator_pubkey_for_test()) others.push_back(pub);
  }
  ASSERT_TRUE(others.size() >= 2);
  const PubKey32 equivocator = others[0];
  const PubKey32 honest = others[1];

  // Round 0: the equivocator prevotes two different values; the second is evidence, not a vote.
  ASSERT_TRUE(advance_test_frontier_round(target, f->height, 0));
  ASSERT_EQ(target.inject_network_prevote_result_for_test(make_test_prevote(f->target().consensus_domain_for_test(), f->keys, f->height, 0, a_id, equivocator)),
            std::string("accepted"));
  (void)target.inject_network_prevote_result_for_test(make_test_prevote(f->target().consensus_domain_for_test(), f->keys, f->height, 0, b0_id, equivocator));

  // Round 1: own prevote + the honest one + the equivocator's = quorum 3 -> polka.
  const auto tc0 = make_test_timeout_certificate(f->target().consensus_domain_for_test(), f->keys, f->committee, f->height, 0, f->quorum);
  ASSERT_TRUE(advance_test_frontier_round(target, f->height, 1));
  ASSERT_EQ(target.inject_network_propose_result_for_test(make_test_frontier_propose_msg(f->target().consensus_domain_for_test(), *f->b1, std::nullopt, tc0)),
            std::string("accepted"));
  ASSERT_TRUE(target.local_prevote_recorded_for_test(f->height, 1, b1_id));
  ASSERT_EQ(target.inject_network_prevote_result_for_test(make_test_prevote(f->target().consensus_domain_for_test(), f->keys, f->height, 1, b1_id, honest)),
            std::string("accepted"));
  ASSERT_EQ(target.inject_network_prevote_result_for_test(make_test_prevote(f->target().consensus_domain_for_test(), f->keys, f->height, 1, b1_id, equivocator)),
            std::string("accepted"));
  const auto polka = target.valid_polka_for_height_for_test(f->height);
  ASSERT_TRUE(polka.has_value());
  ASSERT_EQ(polka->round, 1u);
  ASSERT_TRUE(wait_for_local_precommit(target, f->height, 1, b1_id));
}


#ifdef FINALIS_STORAGE_FAULTS
// ======================================================================================
// Consensus persistence-failure tests (red-team round 2). Faults are injected only into the
// target validator's RocksDB WAL (tests/support/storage_fault_injection.cpp); src/ is unchanged.
//
// Facts these rely on (test_storage_faults.cpp): a failed durable write is invisible, every later
// write fails until the DB is reopened, a failed WAL write() loses the batch, and a failed WAL
// sync replays the batch on reopen.
//
// Tests named test_pf_*_must_* / *_does_not_* assert the spec invariant (TWO_PHASE_FINALITY.md
// §3.2: safety state is durable before the vote leaves the process). Those that fail on the
// current code are the regression tests for the defects in the audit; they are failing on purpose.
// ======================================================================================
namespace {
namespace faults = finalis::test::storage_faults;

constexpr std::array<faults::Mode, 4> kPfWalFaults = {faults::Mode::FailWalWrite, faults::Mode::FailWalWriteNoSpace,
                                                      faults::Mode::FailWalSync, faults::Mode::SyncThenFailWal};
// Gating tests: every mode. ENOSPC was left out until P5 because the system librocksdb aborted on the
// write after an auto-resume (E1, tests/KNOWN_DEFECTS.md); the storage::DB write fence closes that.
constexpr std::array<faults::Mode, 4> kPfGateFaults = kPfWalFaults;

// The disk stays failed for the whole armed window: a background write by the node's event loop may
// take the first fault, and the write under test must fail as well.
constexpr int kPfFaultCount = -1;

std::string pf_fault_name(faults::Mode m) {
  switch (m) {
    case faults::Mode::FailWalWrite:
      return "wal-write-eio";
    case faults::Mode::FailWalWriteNoSpace:
      return "wal-write-enospc";
    case faults::Mode::FailWalSync:
      return "wal-sync-eio";
    case faults::Mode::SyncThenFailWal:
      return "sync-then-eio";
    case faults::Mode::Off:
      break;
  }
  return "off";
}

void pf_require(bool ok, const std::string& what) {
  if (!ok) throw std::runtime_error("assert failed: " + what);
}

std::string pf_join(const std::vector<std::string>& items) {
  std::string out;
  for (const auto& item : items) out += (out.empty() ? "" : " | ") + item;
  return out;
}

// The three committee members other than the target, in committee order, with their cluster index.
struct PfOthers {
  std::vector<PubKey32> pubs;
  std::vector<std::size_t> nodes;
};

PfOthers pf_others(TwoPhaseFixture& f) {
  PfOthers out;
  const auto me = f.target().local_validator_pubkey_for_test();
  for (const auto& pub : f.committee) {
    if (pub == me) continue;
    std::size_t idx = f.cluster.nodes.size();
    for (std::size_t k = 0; k < f.cluster.nodes.size(); ++k) {
      if (f.cluster.nodes[k] && f.cluster.nodes[k]->local_validator_pubkey_for_test() == pub) idx = k;
    }
    out.pubs.push_back(pub);
    out.nodes.push_back(idx);
  }
  if (out.pubs.size() < 3) throw std::runtime_error("need three other committee members");
  return out;
}

const std::string& pf_db(const TwoPhaseFixture& f) { return f.cluster.configs[f.ti].db_path; }
const Hash32& pf_domain(TwoPhaseFixture& f) { return f.target().consensus_domain_for_test(); }

std::string pf_prevote(TwoPhaseFixture& f, std::uint32_t round, const Hash32& id, const PubKey32& signer) {
  return f.target().inject_network_prevote_result_for_test(make_test_prevote(pf_domain(f), f.keys, f.height, round, id, signer));
}

// Target at round 0 receives A and prevotes it (storage healthy).
void pf_prevote_a0(TwoPhaseFixture& f) {
  auto& t = f.target();
  pf_require(advance_test_frontier_round(t, f.height, 0), "advance to round 0");
  pf_require(t.inject_network_propose_result_for_test(make_test_frontier_propose_msg(pf_domain(f), *f.a0)) == "accepted",
             "A0 proposal accepted");
  pf_require(t.local_prevote_recorded_for_test(f.height, 0, frontier_proposal_id(*f.a0)), "own prevote A0 recorded");
}

// Two more A0 prevotes complete the polka (own + 2 = quorum 3). Called with a fault armed, the
// first failing write is the valid-polka batch; the lock batch then fails on RocksDB's background
// error, which is what a real failing disk does.
void pf_complete_polka_a0(TwoPhaseFixture& f, const PfOthers& o) {
  const auto a_id = frontier_proposal_id(*f.a0);
  pf_require(pf_prevote(f, 0, a_id, o.pubs[0]) == "accepted", "prevote A0 from other[0]");
  pf_require(pf_prevote(f, 0, a_id, o.pubs[1]) == "accepted", "prevote A0 from other[1]");
}

// "Must not happen" checks: a queued vote is flushed by whichever thread runs next, so give it a
// bounded window instead of checking once.
bool pf_within(const std::function<bool()>& cond, int ms = 1500) { return wait_for(cond, std::chrono::milliseconds(ms)); }

bool pf_own_precommit_in_rebroadcast(const node::Node& n, std::uint64_t h, std::uint32_t r, const Hash32& id) {
  const auto me = n.local_validator_pubkey_for_test();
  for (const auto& v : n.precommits_for_rebroadcast_for_test(h)) {
    if (v.validator_pubkey == me && v.round == r && v.frontier_transition_id == id) return true;
  }
  return false;
}

// Crash/restart of the target: a new process over the same DB directory, isolated from p2p so a
// reconnect reset cannot race the test (as test_restart_between_prevote_and_precommit does).
void pf_restart_target_isolated(TwoPhaseFixture& f) {
  f.cluster.nodes[f.ti]->stop();
  f.cluster.nodes[f.ti].reset();
  f.cluster.configs[f.ti].disable_p2p = true;
  f.cluster.configs[f.ti].listen = false;
  f.cluster.configs[f.ti].p2p_port = 0;
  f.cluster.nodes[f.ti] = std::make_unique<node::Node>(f.cluster.configs[f.ti]);
  pf_require(f.target().init(), "target re-init after restart");
  pf_require(f.target().pause_proposals_for_test(true), "pause target");
  f.target().start();
}

// Deterministic setup for the in-process paths: the target leaves p2p for the in-process local bus
// before the scenario. The other cluster validators are live (paused only from proposing): over
// p2p they would echo the relayed proposal and send their own prevotes, re-entering the target's
// polka handling at arbitrary times.
void pf_isolate_target(TwoPhaseFixture& f) { pf_restart_target_isolated(f); }

// A live validator moved onto the local bus next to the isolated target: it receives exactly what
// the target broadcasts (and nothing the test injects without relay).
node::Node& pf_bus_spy(TwoPhaseFixture& f, std::size_t idx) {
  f.cluster.nodes[idx]->stop();
  f.cluster.nodes[idx].reset();
  f.cluster.configs[idx].disable_p2p = true;
  f.cluster.configs[idx].listen = false;
  f.cluster.configs[idx].p2p_port = 0;
  f.cluster.nodes[idx] = std::make_unique<node::Node>(f.cluster.configs[idx]);
  pf_require(f.cluster.nodes[idx]->init(), "spy init");
  pf_require(f.cluster.nodes[idx]->pause_proposals_for_test(true), "pause spy");
  f.cluster.nodes[idx]->start();
  return *f.cluster.nodes[idx];
}

TimeoutCertificate pf_tc(TwoPhaseFixture& f, std::uint32_t round, const std::vector<PubKey32>& signers) {
  TimeoutCertificate tc;
  tc.height = f.height;
  tc.round = round;
  const auto msg = timeout_vote_signing_message(pf_domain(f), f.height, round);
  for (const auto& pub : signers) {
    const int id = node_for_pub(f.keys, pub);
    if (id < 0) throw std::runtime_error("unknown tc signer");
    auto sig = crypto::ed25519_sign(msg, f.keys[static_cast<std::size_t>(id)].private_key);
    if (!sig.has_value()) throw std::runtime_error("tc sign failed");
    tc.signatures.push_back(FinalitySig{pub, *sig});
  }
  return tc;
}

// Has peer `n` already received this exact vote? ed25519 is deterministic, so the test rebuilds
// the byte-identical vote; a peer that already holds it reports a duplicate. (Consumes the probe:
// a peer that did not have it accepts it now.)
bool pf_peer_had_precommit(node::Node& n, const Vote& v) {
  return n.inject_network_vote_diagnostic_for_test(v) == "soft-reject:duplicate";
}

}  // namespace

// ---------- B. Lock persistence ----------

// Invariant: when the lock write fails, the precommit that needed it is not emitted (first call).
TEST_TAGS(test_pf_lock_write_failure_first_polka_does_not_precommit, "isolate,persistence-failure");
TEST(test_pf_lock_write_failure_first_polka_does_not_precommit) {
  for (const auto mode : kPfGateFaults) {
    auto f = make_two_phase_fixture("/tmp/finalis_pf_first_" + pf_fault_name(mode), 0xA0);
    pf_isolate_target(*f);
    const auto o = pf_others(*f);
    const auto a_id = frontier_proposal_id(*f->a0);
    pf_prevote_a0(*f);
    {
      faults::Scoped fault(pf_db(*f), mode, kPfFaultCount);
      pf_complete_polka_a0(*f, o);
      pf_require(faults::injected() >= 1, pf_fault_name(mode) + ": fault injected");
    }
    auto& t = f->target();
    pf_require(!pf_within([&] { return t.local_vote_recorded_for_test(f->height, 0, a_id); }),
               pf_fault_name(mode) + ": no precommit A0 after failed lock write");
    // State left behind (documented, not a requirement): the lock stays in memory.
    const auto lock = t.local_vote_lock_for_test(f->height);
    std::cerr << "[pf] mode=" << pf_fault_name(mode) << " in-memory-lock-after-failure=" << (lock ? "yes" : "no") << "\n";
  }
}

// Invariant P1: a new prevote for the same polka after the failed lock write must not emit the
// precommit while the lock is not durable. Defect D1: lock_on_polka_locked's early return.
TEST_TAGS(test_pf_lock_write_failure_new_prevote_must_not_emit_precommit, "isolate,known-defect,persistence-failure,D1");
TEST(test_pf_lock_write_failure_new_prevote_must_not_emit_precommit) {
  std::vector<std::string> failures;  // every mode runs; all failures are reported together
  for (const auto mode : kPfWalFaults) {
    auto f = make_two_phase_fixture("/tmp/finalis_pf_reentry_" + pf_fault_name(mode), 0xA1);
    pf_isolate_target(*f);
    const auto o = pf_others(*f);
    const auto a_id = frontier_proposal_id(*f->a0);
    pf_prevote_a0(*f);
    faults::Scoped fault(pf_db(*f), mode, kPfFaultCount);
    pf_complete_polka_a0(*f, o);
    pf_require(faults::injected() >= 1, "fault injected");
    auto& t = f->target();
    pf_require(!pf_within([&] { return t.local_vote_recorded_for_test(f->height, 0, a_id); }), "no precommit before re-entry");
    pf_require(pf_prevote(*f, 0, a_id, o.pubs[2]) == "accepted", "4th prevote accepted");
    if (pf_within([&] { return t.local_vote_recorded_for_test(f->height, 0, a_id); })) {
      failures.push_back(pf_fault_name(mode) + ": precommit A0 emitted after re-entry although its lock write failed (D1)");
    }
  }
  pf_require(failures.empty(), pf_join(failures));
}

// Control for the duplicate path: a re-delivered prevote is rejected before on_prevotes_changed.
TEST_TAGS(test_pf_lock_write_failure_duplicate_prevote_does_not_emit_precommit, "isolate,persistence-failure");
TEST(test_pf_lock_write_failure_duplicate_prevote_does_not_emit_precommit) {
  auto f = make_two_phase_fixture("/tmp/finalis_pf_dup", 0xA2);
  pf_isolate_target(*f);
  const auto o = pf_others(*f);
  const auto a_id = frontier_proposal_id(*f->a0);
  pf_prevote_a0(*f);
  faults::Scoped fault(pf_db(*f), faults::Mode::FailWalWrite, kPfFaultCount);
  pf_complete_polka_a0(*f, o);
  pf_require(faults::injected() >= 1, "fault injected");
  pf_require(pf_prevote(*f, 0, a_id, o.pubs[1]) == "soft-reject", "duplicate prevote is a soft reject");
  pf_require(!pf_within([&] { return f->target().local_vote_recorded_for_test(f->height, 0, a_id); }),
             "no precommit after duplicate prevote");
}

// Invariant P6: re-delivering the proposal body (on_candidate_body_locked) after the failed lock
// write must not emit the precommit.
TEST_TAGS(test_pf_lock_write_failure_proposal_redelivery_must_not_emit_precommit, "isolate,known-defect,persistence-failure,D1");
TEST(test_pf_lock_write_failure_proposal_redelivery_must_not_emit_precommit) {
  auto f = make_two_phase_fixture("/tmp/finalis_pf_body", 0xA3);
  pf_isolate_target(*f);
  const auto o = pf_others(*f);
  const auto a_id = frontier_proposal_id(*f->a0);
  pf_prevote_a0(*f);
  faults::Scoped fault(pf_db(*f), faults::Mode::FailWalWrite, kPfFaultCount);
  pf_complete_polka_a0(*f, o);
  pf_require(faults::injected() >= 1, "fault injected");
  const auto r = f->target().inject_network_propose_result_for_test(make_test_frontier_propose_msg(pf_domain(*f), *f->a0));
  std::cerr << "[pf] proposal-redelivery result=" << r << "\n";
  pf_require(!pf_within([&] { return f->target().local_vote_recorded_for_test(f->height, 0, a_id); }),
             "precommit A0 emitted after proposal re-delivery although its lock write failed");
}

// Invariant P6: the stall rebroadcast must not sign a precommit for a lock that is not durable.
// Defect D2: local_votes_for_rebroadcast_locked signs one from the in-memory lock.
TEST_TAGS(test_pf_lock_write_failure_rebroadcast_must_not_sign_precommit, "isolate,known-defect,persistence-failure,D2");
TEST(test_pf_lock_write_failure_rebroadcast_must_not_sign_precommit) {
  auto f = make_two_phase_fixture("/tmp/finalis_pf_rebroadcast", 0xA4);
  pf_isolate_target(*f);
  const auto o = pf_others(*f);
  const auto a_id = frontier_proposal_id(*f->a0);
  pf_prevote_a0(*f);
  faults::Scoped fault(pf_db(*f), faults::Mode::FailWalWrite, kPfFaultCount);
  pf_complete_polka_a0(*f, o);
  pf_require(faults::injected() >= 1, "fault injected");
  pf_require(!pf_within([&] { return f->target().local_vote_recorded_for_test(f->height, 0, a_id); }), "no direct precommit");
  pf_require(!pf_own_precommit_in_rebroadcast(f->target(), f->height, 0, a_id),
             "stall rebroadcast set contains a precommit A0 whose lock write failed (D2)");
}

// Invariant P6 for the peer-loss round reset: reseed_local_votes_locked must not record a precommit
// for a lock that is not durable. Defect D3. The reset needs real p2p, but live validators would
// re-enter the polka path (D1) first, so the cluster is stopped and the target's only peer is a
// silent raw socket: it completes the handshake and never sends anything. Closing it is the peer
// loss. Positive control: another validator's precommit, which the reset clears from votes_.
TEST_TAGS(test_pf_lock_write_failure_peer_loss_reseed_must_not_record_precommit, "isolate,known-defect,persistence-failure,D3");
TEST(test_pf_lock_write_failure_peer_loss_reseed_must_not_record_precommit) {
  auto f = make_two_phase_fixture("/tmp/finalis_pf_reseed", 0xA5);
  const auto o = pf_others(*f);
  const auto a_id = frontier_proposal_id(*f->a0);
  auto& t = f->target();
  for (std::size_t k = 0; k < f->cluster.nodes.size(); ++k) {
    if (k != f->ti) f->cluster.nodes[k]->stop();
  }
  pf_require(wait_for([&] { return t.status().established_peers == 0; }, ci_timeout_seconds(30)), "cluster peers gone");
  const auto& net = f->cluster.configs[f->ti].network;
  p2p::VersionMsg v;
  v.proto_version = static_cast<std::uint32_t>(net.protocol_version);
  v.network_id = net.network_id;
  v.feature_flags = net.feature_flags;
  v.timestamp = static_cast<std::uint64_t>(::time(nullptr));
  v.nonce = 0x5157u;
  v.node_software_version = "pf-silent-peer/1;crh=" + t.consensus_rules_fingerprint_for_test();
  auto fd = connect_bootstrap_joiner_without_sync("127.0.0.1", t.p2p_port_for_test(), v, net);
  pf_require(finalis::net::valid_socket(fd), "silent peer connected");
  pf_require(wait_for([&] { return t.status().established_peers >= 1; }, ci_timeout_seconds(10)), "silent peer established");

  pf_prevote_a0(*f);
  faults::Scoped fault(pf_db(*f), faults::Mode::FailWalWrite, kPfFaultCount);
  pf_complete_polka_a0(*f, o);
  pf_require(faults::injected() >= 1, "fault injected");
  pf_require(!pf_within([&] { return t.local_vote_recorded_for_test(f->height, 0, a_id); }),
             "no precommit before the reset (nothing re-enters the polka path)");
  const auto marker = make_test_vote(pf_domain(*f), f->keys, f->height, 0, a_id, o.pubs[0]);
  pf_require(t.inject_vote_for_test(marker), "marker precommit accepted");
  // Probe the vote tracker directly: the stall rebroadcast set is empty once the node fail-stopped.
  const auto marker_present = [&] { return t.vote_recorded_by_for_test(f->height, 0, a_id, o.pubs[0]); };
  pf_require(marker_present(), "marker visible before reset");

  finalis::net::shutdown_socket(fd);
  finalis::net::close_socket(fd);
  pf_require(wait_for([&] { return !marker_present(); }, ci_timeout_seconds(30)), "control: peer-loss reset happened");
  pf_require(!t.local_vote_recorded_for_test(f->height, 0, a_id),
             "peer-loss reset reseeded a precommit A0 whose lock write failed (D3)");
}

// Invariant P1 on a live cluster, with no test-driven re-entry: after the failed lock write the
// precommit must not be emitted. Live peers echo the relayed proposal and send their own prevotes,
// which re-enter the polka path within milliseconds (D1 without any test help).
TEST_TAGS(test_pf_lock_write_failure_on_live_cluster_must_not_emit_precommit, "isolate,known-defect,persistence-failure,D1");
TEST(test_pf_lock_write_failure_on_live_cluster_must_not_emit_precommit) {
  auto f = make_two_phase_fixture("/tmp/finalis_pf_live", 0xAC);
  const auto o = pf_others(*f);
  const auto a_id = frontier_proposal_id(*f->a0);
  pf_prevote_a0(*f);
  faults::Scoped fault(pf_db(*f), faults::Mode::FailWalWriteNoSpace, kPfFaultCount);
  pf_complete_polka_a0(*f, o);
  pf_require(faults::injected() >= 1, "fault injected");
  pf_require(!pf_within([&] { return f->target().local_vote_recorded_for_test(f->height, 0, a_id); }, 3000),
             "live cluster: precommit A0 emitted although its lock write failed (D1 via peer echo)");
}

// Invariant P1 at the network level: no peer receives the precommit whose lock write failed.
TEST_TAGS(test_pf_lock_write_failure_precommit_must_not_reach_peer, "isolate,known-defect,persistence-failure,D1");
TEST(test_pf_lock_write_failure_precommit_must_not_reach_peer) {
  auto f = make_two_phase_fixture("/tmp/finalis_pf_peer", 0xA6);
  const auto o = pf_others(*f);
  const auto a_id = frontier_proposal_id(*f->a0);
  const auto me = f->target().local_validator_pubkey_for_test();
  pf_prevote_a0(*f);
  {
    faults::Scoped fault(pf_db(*f), faults::Mode::FailWalWrite, kPfFaultCount);
    pf_complete_polka_a0(*f, o);
    pf_require(faults::injected() >= 1, "fault injected");
    (void)pf_prevote(*f, 0, a_id, o.pubs[2]);
  }
  std::this_thread::sleep_for(std::chrono::milliseconds(1500));
  const auto own = make_test_vote(pf_domain(*f), f->keys, f->height, 0, a_id, me);
  pf_require(!pf_peer_had_precommit(*f->cluster.nodes[o.nodes[2]], own),
             "peer received precommit A0 whose lock write failed (D1 over p2p)");
}

// Control for the probe above: with healthy storage the same precommit does reach the peer.
TEST_TAGS(test_pf_control_healthy_precommit_reaches_peer, "isolate,persistence-failure");
TEST(test_pf_control_healthy_precommit_reaches_peer) {
  auto f = make_two_phase_fixture("/tmp/finalis_pf_peer_control", 0xA7);
  const auto o = pf_others(*f);
  const auto a_id = frontier_proposal_id(*f->a0);
  const auto me = f->target().local_validator_pubkey_for_test();
  pf_prevote_a0(*f);
  pf_complete_polka_a0(*f, o);
  pf_require(wait_for_local_precommit(f->target(), f->height, 0, a_id), "healthy precommit");
  std::this_thread::sleep_for(std::chrono::milliseconds(1500));
  const auto own = make_test_vote(pf_domain(*f), f->keys, f->height, 0, a_id, me);
  pf_require(pf_peer_had_precommit(*f->cluster.nodes[o.nodes[2]], own), "peer received healthy precommit");
}

// While the process keeps running, the in-memory lock still blocks conflicting votes.
TEST_TAGS(test_pf_lock_write_failure_running_node_refuses_conflicts, "isolate,persistence-failure");
TEST(test_pf_lock_write_failure_running_node_refuses_conflicts) {
  auto f = make_two_phase_fixture("/tmp/finalis_pf_running", 0xA8);
  pf_isolate_target(*f);
  const auto o = pf_others(*f);
  const auto b0_id = frontier_proposal_id(*f->b0);
  const auto b1_id = frontier_proposal_id(*f->b1);
  auto& t = f->target();
  pf_prevote_a0(*f);
  faults::Scoped fault(pf_db(*f), faults::Mode::FailWalWrite, kPfFaultCount);
  pf_complete_polka_a0(*f, o);
  pf_require(faults::injected() >= 1, "fault injected");
  (void)t.inject_network_propose_result_for_test(make_test_frontier_propose_msg(pf_domain(*f), *f->b0));
  pf_require(!t.local_prevote_recorded_for_test(f->height, 0, b0_id), "no prevote B0 in the same round");
  pf_require(advance_test_frontier_round(t, f->height, 1), "advance to round 1");
  const auto tc0 = pf_tc(*f, 0, {o.pubs[0], o.pubs[1], o.pubs[2]});
  (void)t.inject_network_propose_result_for_test(make_test_frontier_propose_msg(pf_domain(*f), *f->b1, std::nullopt, tc0));
  pf_require(!t.local_prevote_recorded_for_test(f->height, 1, b1_id), "no prevote B1 without POL while locked in memory");
}

// Invariant P3: a precommit that left the process is remembered after a restart (its lock is
// restored), for every write-failure outcome. Defect D4 (consequence of D1).
TEST_TAGS(test_pf_emitted_precommit_lock_must_survive_restart, "isolate,known-defect,persistence-failure,D4");
TEST(test_pf_emitted_precommit_lock_must_survive_restart) {
  std::vector<std::string> failures;  // every mode runs; all failures are reported together
  for (const auto mode : kPfWalFaults) {
    auto f = make_two_phase_fixture("/tmp/finalis_pf_restart_" + pf_fault_name(mode), 0xA9);
    pf_isolate_target(*f);
    const auto o = pf_others(*f);
    const auto a_id = frontier_proposal_id(*f->a0);
    pf_prevote_a0(*f);
    bool emitted = false;
    {
      faults::Scoped fault(pf_db(*f), mode, kPfFaultCount);
      pf_complete_polka_a0(*f, o);
      pf_require(faults::injected() >= 1, "fault injected");
      (void)pf_prevote(*f, 0, a_id, o.pubs[2]);
      emitted = pf_within([&] { return f->target().local_vote_recorded_for_test(f->height, 0, a_id); });
    }
    pf_restart_target_isolated(*f);
    const auto lock = f->target().local_vote_lock_for_test(f->height);
    std::cerr << "[pf] mode=" << pf_fault_name(mode) << " precommit-emitted=" << emitted
              << " lock-after-restart=" << (lock ? "yes" : "no") << "\n";
    if (emitted && !(lock.has_value() && lock->first == a_id && lock->second == 0)) {
      failures.push_back(pf_fault_name(mode) + ": precommit A0 was emitted but its lock is gone after restart (D4)");
    }
  }
  pf_require(failures.empty(), pf_join(failures));
}

// Ambiguous outcome of the lock batch itself: the valid polka is made durable first (recorded while
// the target is at round 1), so the fault hits exactly the lock write. Invariant: whatever the disk
// outcome, nothing was emitted, and after restart the node either has the lock or has not voted.
TEST_TAGS(test_pf_isolated_lock_write_fault_outcomes_after_restart, "isolate,persistence-failure");
TEST(test_pf_isolated_lock_write_fault_outcomes_after_restart) {
  for (const auto mode : kPfGateFaults) {
    auto f = make_two_phase_fixture("/tmp/finalis_pf_isolated_" + pf_fault_name(mode), 0xAA);
    pf_isolate_target(*f);
    const auto o = pf_others(*f);
    const auto a_id = frontier_proposal_id(*f->a0);
    auto& t = f->target();
    pf_prevote_a0(*f);
    pf_require(advance_test_frontier_round(t, f->height, 1), "advance to round 1");
    pf_complete_polka_a0(*f, o);  // valid polka recorded durably; no lock (not the current round)
    pf_require(t.valid_polka_for_height_for_test(f->height).has_value(), "valid polka recorded");
    pf_require(!t.local_vote_lock_for_test(f->height).has_value(), "no lock yet");
    pf_require(advance_test_frontier_round(t, f->height, 0), "back to round 0");
    {
      faults::Scoped fault(pf_db(*f), mode, kPfFaultCount);
      pf_require(pf_prevote(*f, 0, a_id, o.pubs[2]) == "accepted", "4th prevote accepted");
      pf_require(faults::injected() >= 1, "fault hit the lock write");
    }
    const bool emitted = pf_within([&] { return t.local_vote_recorded_for_test(f->height, 0, a_id); });
    pf_restart_target_isolated(*f);
    const auto lock = f->target().local_vote_lock_for_test(f->height);
    std::cerr << "[pf] isolated mode=" << pf_fault_name(mode) << " emitted=" << emitted
              << " lock-after-restart=" << (lock ? "yes" : "no") << "\n";
    pf_require(!emitted, pf_fault_name(mode) + ": no precommit after the failed lock write");
    // After restart: the lock reappears exactly when the WAL bytes reached the file.
    const bool expect_lock = mode == faults::Mode::FailWalSync || mode == faults::Mode::SyncThenFailWal;
    pf_require(lock.has_value() == expect_lock, pf_fault_name(mode) + ": lock presence after restart");
  }
}

// End-to-end safety trace. 4 validators, quorum 3: T (target, honest, lock write fails), H2 and H3
// honest (simulated by their signed votes), B (Byzantine, signs both sides). Delivery is
// asynchronous; every step is legal for its actor. Invariant (Agreement): two different transitions
// must not both gather a valid quorum certificate at the same height. Defect D5.
//
//  r0: A proposed. T, H2, B prevote A (T's prevote durable). T's lock write fails (disk error).
//      H3 prevotes A late, which re-enters T's polka handling. Before P1, T precommitted A@0 here
//      (D1) and {T, H2, B} formed a quorum for A@0. T must not precommit A@0 now.
//  T crashes and restarts: its durable state has the r0 prevote but no lock.
//  r1: B proposes B1 (no POL, justified by the round-0 TC from H2, H3, B). T (no lock) and H3
//      prevote B1, B prevotes B1 -> polka; T, H3, B precommit B1@1 -> quorum for B1@1.
//  Two observer nodes (H2's and H3's) are each handed the certificate that the signatures actually
//  produced allow: A@0 holds T's precommit only if T emitted it.
// ENOSPC included since P5 (kPfGateFaults): the storage::DB write fence closed the E1 abort here.
TEST_TAGS(test_pf_lock_write_failure_crash_must_not_allow_conflicting_finality, "isolate,known-defect,persistence-failure,D5");
TEST(test_pf_lock_write_failure_crash_must_not_allow_conflicting_finality) {
  std::vector<std::string> failures;  // every mode runs; all failures are reported together
  for (const auto mode : kPfGateFaults) {
    auto f = make_two_phase_fixture("/tmp/finalis_pf_split_" + pf_fault_name(mode), 0xAB);
    pf_isolate_target(*f);
    const auto o = pf_others(*f);
    const PubKey32 h2 = o.pubs[0], byz = o.pubs[1], h3 = o.pubs[2];
    const std::size_t h2_node = o.nodes[0], h3_node = o.nodes[2];
    const auto a_id = frontier_proposal_id(*f->a0);
    const auto b1_id = frontier_proposal_id(*f->b1);
    const auto me = f->target().local_validator_pubkey_for_test();
    const std::string m = pf_fault_name(mode);
    pf_require(f->quorum == 3 && f->committee.size() == 4, "committee 4, quorum 3");

    // r0
    pf_prevote_a0(*f);
    {
      faults::Scoped fault(pf_db(*f), mode, kPfFaultCount);
      pf_require(pf_prevote(*f, 0, a_id, h2) == "accepted", "H2 prevote A0");
      pf_require(pf_prevote(*f, 0, a_id, byz) == "accepted", "B prevote A0 (polka)");
      pf_require(faults::injected() >= 1, "fault injected");
      pf_require(pf_prevote(*f, 0, a_id, h3) == "accepted", "H3 late prevote A0 (re-entry)");
    }
    // Assertion 1: the failed lock write does not lead to a precommit for A@0, on any path.
    const bool t_precommitted_a0 =
        pf_within([&] { return f->target().local_vote_recorded_for_test(f->height, 0, a_id); }, 3000) ||
        pf_own_precommit_in_rebroadcast(f->target(), f->height, 0, a_id);
    std::cerr << "[pf-trace] mode=" << m << " T precommit A@0 emitted=" << t_precommitted_a0 << "\n";
    if (t_precommitted_a0) failures.push_back(m + ": T precommitted A@0 after its lock write failed (D1)");

    // crash + restart
    pf_restart_target_isolated(*f);
    auto& t = f->target();
    std::cerr << "[pf-trace] mode=" << m << " T lock after restart=" << (t.local_vote_lock_for_test(f->height) ? "yes" : "no") << "\n";

    // r1
    pf_require(advance_test_frontier_round(t, f->height, 1), "T to round 1");
    const auto tc0 = pf_tc(*f, 0, {h2, h3, byz});
    pf_require(t.inject_network_propose_result_for_test(make_test_frontier_propose_msg(pf_domain(*f), *f->b1, std::nullopt, tc0)) ==
                   "accepted",
               "B1 proposal accepted");
    const bool t_prevoted_b1 = t.local_prevote_recorded_for_test(f->height, 1, b1_id);
    bool t_precommitted_b1 = false;
    if (t_prevoted_b1) {
      pf_require(pf_prevote(*f, 1, b1_id, h3) == "accepted", "H3 prevote B1");
      pf_require(pf_prevote(*f, 1, b1_id, byz) == "accepted", "B prevote B1 (polka)");
      t_precommitted_b1 = wait_for_local_precommit(t, f->height, 1, b1_id);
    }
    std::cerr << "[pf-trace] mode=" << m << " T prevote B1@1=" << t_prevoted_b1 << " precommit B1@1=" << t_precommitted_b1 << "\n";

    // Certificates from the signatures that exist: T's only where T emitted the precommit (its
    // signature is deterministic, so the byte-identical copy stands for the one it sent).
    const auto sig_of = [](const Vote& v) { return FinalitySig{v.validator_pubkey, v.signature}; };
    std::vector<FinalitySig> cert_a = {sig_of(make_test_vote(pf_domain(*f), f->keys, f->height, 0, a_id, h2)),
                                       sig_of(make_test_vote(pf_domain(*f), f->keys, f->height, 0, a_id, byz))};
    if (t_precommitted_a0) cert_a.push_back(sig_of(make_test_vote(pf_domain(*f), f->keys, f->height, 0, a_id, me)));
    std::vector<FinalitySig> cert_b = {sig_of(make_test_vote(pf_domain(*f), f->keys, f->height, 1, b1_id, h3)),
                                       sig_of(make_test_vote(pf_domain(*f), f->keys, f->height, 1, b1_id, byz))};
    if (t_precommitted_b1) cert_b.push_back(sig_of(make_test_vote(pf_domain(*f), f->keys, f->height, 1, b1_id, me)));
    const bool a_final = inject_test_frontier_block(*f->cluster.nodes[h2_node], *f->a0, cert_a);
    const bool b_final = inject_test_frontier_block(*f->cluster.nodes[h3_node], *f->b1, cert_b);
    std::cerr << "[pf-trace] mode=" << m << " A@0 signatures=" << cert_a.size() << " finalized=" << a_final
              << " | B1@1 signatures=" << cert_b.size() << " finalized=" << b_final << "\n";
    // Assertion 3: no conflicting finality.
    if (a_final && b_final) failures.push_back(m + ": two transitions finalized at one height (A@0 and B1@1)");
    if (t_precommitted_a0 && t_precommitted_b1) {
      failures.push_back(m + ": T precommitted A@0 and, after restart, B1@1 without a POL (lock rule broken)");
    }
  }
  pf_require(failures.empty(), pf_join(failures));
}

// ---------- C. Prevote persistence ----------

// Invariant: a prevote whose write failed is not emitted on the direct path. Proxy: with
// quorum - 1 other prevotes no polka forms at the target, so its own prevote was never handled
// (broadcast_prevote and handle_prevote are called together, node_consensus.cpp handle_propose_result).
TEST_TAGS(test_pf_prevote_write_failure_prevote_not_emitted, "isolate,persistence-failure");
TEST(test_pf_prevote_write_failure_prevote_not_emitted) {
  for (const auto mode : kPfGateFaults) {
    auto f = make_two_phase_fixture("/tmp/finalis_pf_prevote_" + pf_fault_name(mode), 0xB0);
    pf_isolate_target(*f);
    const auto o = pf_others(*f);
    const auto a_id = frontier_proposal_id(*f->a0);
    auto& t = f->target();
    pf_require(advance_test_frontier_round(t, f->height, 0), "round 0");
    {
      faults::Scoped fault(pf_db(*f), mode, kPfFaultCount);
      // Accepted, or (P5) soft-rejected because an earlier failed write already halted signing.
      const auto r = t.inject_network_propose_result_for_test(make_test_frontier_propose_msg(pf_domain(*f), *f->a0));
      pf_require(r == "accepted" || (r == "soft-reject" && t.safety_storage_failed()), "A0 proposal accepted (got " + r + ")");
      pf_require(faults::injected() >= 1, "fault injected");
    }
    std::cerr << "[pf] prevote mode=" << pf_fault_name(mode)
              << " in-memory-prevote-record=" << t.local_prevote_recorded_for_test(f->height, 0, a_id) << "\n";
    pf_complete_polka_a0(*f, o);
    pf_require(!t.valid_polka_for_height_for_test(f->height).has_value(), "own prevote not counted locally");
  }
}

// After a failed prevote write the node does not prevote again in that round, for A or B.
TEST_TAGS(test_pf_prevote_write_failure_blocks_same_round_retry_and_conflict, "isolate,persistence-failure");
TEST(test_pf_prevote_write_failure_blocks_same_round_retry_and_conflict) {
  auto f = make_two_phase_fixture("/tmp/finalis_pf_prevote_retry", 0xB1);
  pf_isolate_target(*f);
  const auto b0_id = frontier_proposal_id(*f->b0);
  auto& t = f->target();
  pf_require(advance_test_frontier_round(t, f->height, 0), "round 0");
  faults::Scoped fault(pf_db(*f), faults::Mode::FailWalWrite, kPfFaultCount);
  // Accepted, or (P5) soft-rejected because an earlier failed write already halted signing.
  const auto r = t.inject_network_propose_result_for_test(make_test_frontier_propose_msg(pf_domain(*f), *f->a0));
  pf_require(r == "accepted" || (r == "soft-reject" && t.safety_storage_failed()), "A0 accepted (got " + r + ")");
  (void)pf_within([&] { return faults::injected() >= 1; }, 1000);
  pf_require(faults::injected() >= 1, "fault injected");
  (void)t.inject_network_propose_result_for_test(make_test_frontier_propose_msg(pf_domain(*f), *f->b0));
  pf_require(!t.local_prevote_recorded_for_test(f->height, 0, b0_id), "no prevote B0 in the same round");
}

// Invariant P6: the stall rebroadcast must not send a prevote whose write failed. Defect D6.
// Asserted twice: no in-memory prevote record survives the failed write (the rebroadcast re-sends
// that map), and the spy never received the prevote.
// Target and a spy validator share the local bus; the proposal reaches the target without relay.
// Positive control: a precommit by a validator outside the bus, held only by the target, reaches
// the spy, which proves the target's stall rebroadcast fired.
TEST_TAGS(test_pf_prevote_write_failure_rebroadcast_must_not_send_prevote, "isolate,known-defect,persistence-failure,D6");
TEST(test_pf_prevote_write_failure_rebroadcast_must_not_send_prevote) {
  auto f = make_two_phase_fixture("/tmp/finalis_pf_prevote_rebroadcast", 0xB2);
  const auto o = pf_others(*f);
  const auto a_id = frontier_proposal_id(*f->a0);
  const auto me = f->target().local_validator_pubkey_for_test();
  pf_isolate_target(*f);
  auto& spy = pf_bus_spy(*f, o.nodes[2]);
  auto& t = f->target();
  pf_require(advance_test_frontier_round(t, f->height, 0), "round 0");
  faults::Scoped fault(pf_db(*f), faults::Mode::FailWalWrite, kPfFaultCount);
  pf_require(t.inject_propose_msg_for_test(make_test_frontier_propose_msg(pf_domain(*f), *f->a0)), "A0 delivered");
  pf_require(faults::injected() >= 1, "fault injected");
  pf_require(!t.local_prevote_recorded_for_test(f->height, 0, a_id),
             "failed prevote write left a published in-memory prevote record (stall rebroadcast would send it)");
  const auto marker = make_test_vote(pf_domain(*f), f->keys, f->height, 0, a_id, o.pubs[0]);
  pf_require(t.inject_vote_for_test(marker), "marker precommit held by the target only");
  // Control, read-only on the spy (an injecting probe would itself store the marker it looks for).
  // A fail-stopped target (P2) runs no stall rebroadcast: then the control is that it has nothing
  // to rebroadcast.
  if (t.safety_storage_failed()) {
    pf_require(t.rebroadcast_sizes_for_test(f->height) == std::array<std::size_t, 3>{0, 0, 0},
               "control: fail-stopped target has nothing to rebroadcast");
  } else {
    pf_require(wait_for([&] { return spy.vote_recorded_by_for_test(f->height, 0, a_id, o.pubs[0]); }, ci_timeout_seconds(30)),
               "control: target's stall rebroadcast reached the spy");
  }
  // Bus deliveries run on separate threads, so the prevote of the same rebroadcast may still be in
  // flight; let several more rebroadcast cycles (one per round timeout) pass.
  std::this_thread::sleep_for(std::chrono::milliseconds(1500));
  const auto own = make_test_prevote(pf_domain(*f), f->keys, f->height, 0, a_id, me);
  pf_require(spy.inject_network_prevote_result_for_test(own) == "accepted",
             "spy received prevote A0 whose write failed, via stall rebroadcast (D6)");
}

namespace {
// Passive wire observer: a raw p2p peer that completes the handshake and records every PREVOTE and
// VOTE frame the node sends it (direct broadcasts and stall rebroadcasts alike). It answers PING
// with PONG to stay connected and sends nothing else: it never injects, accepts or relays a vote,
// so it cannot create the evidence it observes. Votes are kept only if their signature verifies.
class PfWireObserver {
 public:
  PfWireObserver(node::Node& n, const NetworkConfig& net, std::uint64_t nonce) : net_(net), domain_(n.consensus_domain_for_test()) {
    p2p::VersionMsg v;
    v.proto_version = static_cast<std::uint32_t>(net.protocol_version);
    v.network_id = net.network_id;
    v.feature_flags = net.feature_flags;
    v.timestamp = static_cast<std::uint64_t>(::time(nullptr));
    v.nonce = nonce;
    v.node_software_version = "pf-wire-observer/1;crh=" + n.consensus_rules_fingerprint_for_test();
    fd_ = connect_bootstrap_joiner_without_sync("127.0.0.1", n.p2p_port_for_test(), v, net);
    if (!finalis::net::valid_socket(fd_)) throw std::runtime_error("observer connect failed");
    reader_ = std::thread([this] { read_loop(); });
  }
  ~PfWireObserver() {
    stop_.store(true);
    finalis::net::shutdown_socket(fd_);
    if (reader_.joinable()) reader_.join();
    finalis::net::close_socket(fd_);
  }
  PfWireObserver(const PfWireObserver&) = delete;
  PfWireObserver& operator=(const PfWireObserver&) = delete;

  // Did the node send a validly signed prevote / precommit for (h, r, id) by `signer`?
  bool saw_prevote(std::uint64_t h, std::uint32_t r, const Hash32& id, const PubKey32& signer) const {
    return saw(prevotes_, h, r, id, signer);
  }
  bool saw_precommit(std::uint64_t h, std::uint32_t r, const Hash32& id, const PubKey32& signer) const {
    return saw(precommits_, h, r, id, signer);
  }
  bool connected() const { return !closed_.load(); }
  // PREVOTE, VOTE, TIMEOUT_VOTE and PROPOSE frames received so far, verified or not.
  int consensus_frames() const { return consensus_frames_.load(); }
  // Asks for the node's finalized tip (GET_FINALIZED_TIP); the FINALIZED_TIP replies, and any the node
  // broadcasts unasked, are collected in tips().
  bool request_tip() {
    std::lock_guard<std::mutex> wl(write_mu_);
    return p2p::write_frame_fd(fd_, p2p::Frame{p2p::MsgType::GET_FINALIZED_TIP, Bytes{}}, net_.magic, net_.protocol_version);
  }
  std::vector<std::uint64_t> tips() const {
    std::lock_guard<std::mutex> lk(mu_);
    return tips_;
  }
  // TRANSITION frames (finalized frontier + certificate broadcasts) received so far.
  int transitions() const { return transitions_.load(); }

 private:
  bool saw(const std::vector<Vote>& votes, std::uint64_t h, std::uint32_t r, const Hash32& id, const PubKey32& signer) const {
    std::lock_guard<std::mutex> lk(mu_);
    return std::any_of(votes.begin(), votes.end(), [&](const Vote& v) {
      return v.height == h && v.round == r && v.frontier_transition_id == id && v.validator_pubkey == signer;
    });
  }

  void read_loop() {
    while (!stop_.load()) {
      p2p::FrameReadError err = p2p::FrameReadError::NONE;
      auto frame = p2p::read_frame_fd_timed(fd_, net_.max_payload_len, net_.magic, net_.protocol_version, 200, 2000, &err);
      if (!frame.has_value()) {
        if (err == p2p::FrameReadError::TIMEOUT_HEADER || err == p2p::FrameReadError::TIMEOUT_BODY) continue;
        break;
      }
      if (frame->msg_type == p2p::MsgType::PING) {
        if (auto ping = p2p::de_ping(frame->payload); ping.has_value()) {
          std::lock_guard<std::mutex> wl(write_mu_);
          (void)p2p::write_frame_fd(fd_, p2p::Frame{p2p::MsgType::PONG, p2p::ser_ping(*ping)}, net_.magic, net_.protocol_version);
        }
      } else if (frame->msg_type == p2p::MsgType::FINALIZED_TIP) {
        if (auto tip = p2p::de_finalized_tip(frame->payload); tip.has_value()) {
          std::lock_guard<std::mutex> lk(mu_);
          tips_.push_back(tip->height);
        }
      } else if (frame->msg_type == p2p::MsgType::TRANSITION) {
        transitions_.fetch_add(1);
      } else if (frame->msg_type == p2p::MsgType::PREVOTE) {
        if (auto m = p2p::de_prevote(frame->payload); m.has_value() && verified(*m, false)) record(prevotes_, m->vote);
      } else if (frame->msg_type == p2p::MsgType::VOTE) {
        if (auto m = p2p::de_vote(frame->payload); m.has_value() && verified(*m, true)) record(precommits_, m->vote);
      }
      if (frame->msg_type == p2p::MsgType::PREVOTE || frame->msg_type == p2p::MsgType::VOTE ||
          frame->msg_type == p2p::MsgType::TIMEOUT_VOTE || frame->msg_type == p2p::MsgType::PROPOSE) {
        consensus_frames_.fetch_add(1);
      }
    }
    closed_.store(true);
  }

  template <typename Msg>
  bool verified(const Msg& m, bool precommit) const {
    const auto& v = m.vote;
    const Bytes msg = precommit ? vote_signing_message(domain_, v.height, v.round, v.frontier_transition_id)
                                : prevote_signing_message(domain_, v.height, v.round, v.frontier_transition_id);
    return crypto::ed25519_verify(msg, v.signature, v.validator_pubkey);
  }

  void record(std::vector<Vote>& into, const Vote& v) {
    std::lock_guard<std::mutex> lk(mu_);
    into.push_back(v);
  }

  NetworkConfig net_;
  Hash32 domain_;
  finalis::net::SocketHandle fd_{finalis::net::kInvalidSocket};
  std::thread reader_;
  std::atomic<bool> stop_{false};
  std::atomic<bool> closed_{false};
  std::atomic<int> consensus_frames_{0};
  std::atomic<int> transitions_{0};
  std::mutex write_mu_;
  std::vector<std::uint64_t> tips_;
  mutable std::mutex mu_;
  std::vector<Vote> prevotes_;
  std::vector<Vote> precommits_;
};

// Crash/restart of the target onto real p2p at its original port (its cluster peers are stopped).
void pf_restart_target_p2p_only(TwoPhaseFixture& f) {
  f.cluster.nodes[f.ti]->stop();
  f.cluster.nodes[f.ti].reset();
  f.cluster.configs[f.ti].disable_p2p = false;
  f.cluster.configs[f.ti].listen = true;
  f.cluster.configs[f.ti].p2p_port = f.cluster.ports[f.ti];
  f.cluster.nodes[f.ti] = std::make_unique<node::Node>(f.cluster.configs[f.ti]);
  pf_require(f.target().init(), "target re-init on p2p");
  pf_require(f.target().pause_proposals_for_test(true), "pause target");
  f.target().start();
}
}  // namespace

// Invariant P3 for prevotes: a prevote that reached a peer is remembered after restart, so the node
// cannot prevote a different transition in that round (on-chain slashable PREVOTE_EQUIVOCATION).
//
// Observation is passive: the target's cluster peers are stopped and its only peer is a
// PfWireObserver, which records the signed PREVOTE / VOTE frames the target actually sends and never
// injects or relays anything. One observer per target process (the connection ends with the process).
//  - Control 1: a precommit signed by another member, held only by the target, appears on the wire:
//    the target's stall rebroadcast ran (the path that re-sends in-memory prevote records).
//  - A0 emitted: the target sent a signed A0 prevote, before or after the restart.
//  - Control 2: when the restarted target records a B0 prevote, the signed B0 appears on the wire
//    before the absence of an A0/B0 pair is taken to mean anything.
// Violation: the target sent signed prevotes for both A0 and B0 at (h, 0).
// ENOSPC included since P5 (kPfGateFaults): the storage::DB write fence closed the E1 abort here.
TEST_TAGS(test_pf_rebroadcast_prevote_must_be_remembered_after_restart, "isolate,known-defect,persistence-failure,D6");
TEST(test_pf_rebroadcast_prevote_must_be_remembered_after_restart) {
  std::vector<std::string> failures;  // every mode runs; all failures are reported together
  for (const auto mode : kPfGateFaults) {
    auto f = make_two_phase_fixture("/tmp/finalis_pf_prevote_restart_" + pf_fault_name(mode), 0xB3);
    const auto o = pf_others(*f);
    const auto a_id = frontier_proposal_id(*f->a0);
    const auto b0_id = frontier_proposal_id(*f->b0);
    const auto me = f->target().local_validator_pubkey_for_test();
    const std::string m = pf_fault_name(mode);
    const auto& net = f->cluster.configs[f->ti].network;
    for (std::size_t k = 0; k < f->cluster.nodes.size(); ++k) {
      if (k != f->ti) f->cluster.nodes[k]->stop();
    }
    pf_require(wait_for([&] { return f->target().status().established_peers == 0; }, ci_timeout_seconds(30)), "cluster peers gone");

    bool a0_before = false;
    {
      PfWireObserver wire(f->target(), net, 0xD6B1);
      pf_require(wait_for([&] { return f->target().status().established_peers >= 1; }, ci_timeout_seconds(10)), "observer established");
      pf_require(advance_test_frontier_round(f->target(), f->height, 0), "round 0");
      faults::Scoped fault(pf_db(*f), mode, kPfFaultCount);
      pf_require(f->target().inject_propose_msg_for_test(make_test_frontier_propose_msg(pf_domain(*f), *f->a0)), "A0 delivered");
      pf_require(faults::injected() >= 1, "fault injected");
      const auto marker = make_test_vote(pf_domain(*f), f->keys, f->height, 0, a_id, o.pubs[0]);
      pf_require(f->target().inject_vote_for_test(marker), "marker precommit held by the target only");
      // After P2 the failed write fail-stops the node: the stall rebroadcast (the path that would
      // re-send an in-memory prevote record) is closed instead of shown to run.
      if (f->target().safety_storage_failed()) {
        pf_require(f->target().rebroadcast_sizes_for_test(f->height) == std::array<std::size_t, 3>{0, 0, 0},
                   "control 1: fail-stopped target has nothing to rebroadcast");
      } else {
        pf_require(wait_for([&] { return wire.saw_precommit(f->height, 0, a_id, o.pubs[0]); }, ci_timeout_seconds(30)),
                   "control 1: the target's stall rebroadcast reached the observer");
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(1500));  // several more rebroadcast cycles
      a0_before = wire.saw_prevote(f->height, 0, a_id, me);
      pf_require(wire.connected(), "observer stayed connected");
    }
    pf_restart_target_p2p_only(*f);
    auto& t = f->target();
    bool a0_after = false, b0_seen = false;
    bool prevoted_b0 = false;
    {
      PfWireObserver wire(t, net, 0xD6B2);
      pf_require(wait_for([&] { return t.status().established_peers >= 1; }, ci_timeout_seconds(10)), "observer established after restart");
      pf_require(advance_test_frontier_round(t, f->height, 0), "round 0 after restart");
      (void)t.inject_propose_msg_for_test(make_test_frontier_propose_msg(pf_domain(*f), *f->b0));
      prevoted_b0 = t.local_prevote_recorded_for_test(f->height, 0, b0_id);
      if (prevoted_b0) {
        b0_seen = wait_for([&] { return wire.saw_prevote(f->height, 0, b0_id, me); }, ci_timeout_seconds(10));
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(3000));  // stall rebroadcasts of any restored prevote
      a0_after = wire.saw_prevote(f->height, 0, a_id, me);
      b0_seen = b0_seen || wire.saw_prevote(f->height, 0, b0_id, me);
      pf_require(wire.connected(), "observer stayed connected after restart");
    }
    const bool a0_sent = a0_before || a0_after;
    std::cerr << "[pf] prevote-restart mode=" << m << " wire-A0-before-restart=" << a0_before << " wire-A0-after-restart=" << a0_after
              << " recorded-B0-after-restart=" << prevoted_b0 << " wire-B0=" << b0_seen << "\n";
    if (prevoted_b0 && !b0_seen) {
      failures.push_back(m + ": harness: the target recorded B0 but no B0 reached the observer, so the check is inconclusive");
    }
    if (a0_sent && b0_seen) {
      failures.push_back(m + ": honest node sent signed prevotes for A0 and B0 in the same round (PREVOTE_EQUIVOCATION)");
    }
  }
  pf_require(failures.empty(), pf_join(failures));
}

// ---------- Restart recovery matrix (safety rows edited between runs) ----------

namespace {
// Healthy run: lock + precommit on A0, then the target is stopped. Returns the target's db path.
std::string pf_locked_then_stopped(TwoPhaseFixture& f) {
  const auto o = pf_others(f);
  const auto a_id = frontier_proposal_id(*f.a0);
  pf_prevote_a0(f);
  pf_complete_polka_a0(f, o);
  pf_require(wait_for_local_precommit(f.target(), f.height, 0, a_id), "healthy precommit A0");
  f.cluster.nodes[f.ti]->stop();
  return pf_db(f);
}
}  // namespace

TEST_TAGS(test_pf_recovery_corrupt_mirror_valid_primary_keeps_lock, "isolate,persistence-failure");
TEST(test_pf_recovery_corrupt_mirror_valid_primary_keeps_lock) {
  auto f = make_two_phase_fixture("/tmp/finalis_pf_rec_mirror", 0xC0);
  const auto db_path = pf_locked_then_stopped(*f);
  {
    storage::DB db;
    pf_require(db.open(db_path), "open");
    pf_require(db.put(csafe_mirror_db_key(f->height), Bytes{0x43, 0x53, 0x46, 0x32, 0xFF}), "corrupt mirror");
    pf_require(db.flush(), "flush");
  }
  pf_restart_target_isolated(*f);
  const auto lock = f->target().local_vote_lock_for_test(f->height);
  pf_require(lock.has_value() && lock->first == frontier_proposal_id(*f->a0), "lock kept from primary");
  pf_require(f->target().abstain_heights_for_test().empty(), "no abstention");
  f->target().stop();
  storage::DB db;
  pf_require(db.open_readonly(db_path), "reopen");
  const auto mirror = db.get(csafe_mirror_db_key(f->height));
  pf_require(mirror.has_value() && *mirror != (Bytes{0x43, 0x53, 0x46, 0x32, 0xFF}), "mirror rewritten");
}

TEST_TAGS(test_pf_recovery_both_rows_corrupt_abstains_across_restarts, "isolate,persistence-failure");
TEST(test_pf_recovery_both_rows_corrupt_abstains_across_restarts) {
  auto f = make_two_phase_fixture("/tmp/finalis_pf_rec_both_corrupt", 0xC1);
  const auto db_path = pf_locked_then_stopped(*f);
  {
    storage::DB db;
    pf_require(db.open(db_path), "open");
    pf_require(db.put(csafe_db_key(f->height), Bytes{0x01}), "corrupt primary");
    pf_require(db.put(csafe_mirror_db_key(f->height), Bytes{0x02}), "corrupt mirror");
    pf_require(db.flush(), "flush");
  }
  for (int i = 0; i < 3; ++i) {
    pf_restart_target_isolated(*f);
    pf_require(f->target().abstain_heights_for_test().count(f->height) == 1, "abstains on restart " + std::to_string(i));
    pf_require(advance_test_frontier_round(f->target(), f->height, 1), "round 1");
    const auto tc0 = make_test_timeout_certificate(pf_domain(*f), f->keys, f->committee, f->height, 0, f->quorum);
    (void)f->target().inject_network_propose_result_for_test(make_test_frontier_propose_msg(pf_domain(*f), *f->b1, std::nullopt, tc0));
    pf_require(!f->target().local_prevote_recorded_for_test(f->height, 1, frontier_proposal_id(*f->b1)), "no vote while abstaining");
  }
}

// Invariant P5 (as the audit brief states it): with the vote history unavailable, the node must not
// silently resume unrestricted voting. Both rows deleted after a precommit: the node cannot tell
// this from "never voted". Expected to fail: a design limitation (missing == empty), not a code slip.
TEST_TAGS(test_pf_recovery_both_rows_missing_after_precommit_must_not_vote_freely, "isolate,known-defect,persistence-failure,G1");
TEST(test_pf_recovery_both_rows_missing_after_precommit_must_not_vote_freely) {
  auto f = make_two_phase_fixture("/tmp/finalis_pf_rec_missing", 0xC2);
  const auto db_path = pf_locked_then_stopped(*f);
  {
    storage::DB db;
    pf_require(db.open(db_path), "open");
    pf_require(db.erase(csafe_db_key(f->height)), "erase primary");
    pf_require(db.erase(csafe_mirror_db_key(f->height)), "erase mirror");
    pf_require(db.flush(), "flush");
  }
  pf_restart_target_isolated(*f);
  auto& t = f->target();
  std::cerr << "[pf] rows-missing lock=" << (t.local_vote_lock_for_test(f->height) ? "yes" : "no")
            << " abstain=" << t.abstain_heights_for_test().count(f->height) << "\n";
  pf_require(advance_test_frontier_round(t, f->height, 1), "round 1");
  const auto tc0 = make_test_timeout_certificate(pf_domain(*f), f->keys, f->committee, f->height, 0, f->quorum);
  (void)t.inject_network_propose_result_for_test(make_test_frontier_propose_msg(pf_domain(*f), *f->b1, std::nullopt, tc0));
  pf_require(!t.local_prevote_recorded_for_test(f->height, 1, frontier_proposal_id(*f->b1)),
             "rows missing after a precommit: node prevoted B1 without a POL (P5 gap)");
}

// Primary and mirror both valid but different (an older primary restored over a newer one): load
// prefers the primary without comparing. Invariant P3: the newer lock is not lost.
TEST_TAGS(test_pf_recovery_stale_primary_newer_mirror_must_keep_lock, "isolate,known-defect,persistence-failure,G2");
TEST(test_pf_recovery_stale_primary_newer_mirror_must_keep_lock) {
  auto f = make_two_phase_fixture("/tmp/finalis_pf_rec_stale_primary", 0xC3);
  const auto o = pf_others(*f);
  const auto a_id = frontier_proposal_id(*f->a0);
  pf_prevote_a0(*f);
  std::optional<Bytes> old_primary;
  {
    // Snapshot the prevote-only row from a read-only handle while the node runs.
    storage::DB ro;
    pf_require(ro.open_readonly(pf_db(*f)), "open ro");
    old_primary = ro.get(csafe_db_key(f->height));
  }
  pf_require(old_primary.has_value(), "prevote-only primary row exists");
  pf_complete_polka_a0(*f, o);
  pf_require(wait_for_local_precommit(f->target(), f->height, 0, a_id), "precommit A0");
  f->cluster.nodes[f->ti]->stop();
  {
    storage::DB db;
    pf_require(db.open(pf_db(*f)), "open");
    pf_require(db.put(csafe_db_key(f->height), *old_primary), "restore old primary");
    pf_require(db.flush(), "flush");
  }
  pf_restart_target_isolated(*f);
  const auto lock = f->target().local_vote_lock_for_test(f->height);
  pf_require(lock.has_value(), "stale-but-valid primary hid the newer mirror's lock");
}

// ---------- Round 3: recovery, controls and remaining vote paths ----------

namespace {
// Crash/restart of the target back onto real p2p (its original port), so it rejoins the cluster.
void pf_restart_target_on_p2p(TwoPhaseFixture& f) {
  f.cluster.nodes[f.ti]->stop();
  f.cluster.nodes[f.ti].reset();
  f.cluster.configs[f.ti].disable_p2p = false;
  f.cluster.configs[f.ti].listen = true;
  f.cluster.configs[f.ti].p2p_port = f.cluster.ports[f.ti];
  f.cluster.nodes[f.ti] = std::make_unique<node::Node>(f.cluster.configs[f.ti]);
  pf_require(f.target().init(), "target re-init on p2p");
  f.target().start();
}

bool pf_holds_precommit_from(const node::Node& n, std::uint64_t h, std::uint32_t r, const Hash32& id, const PubKey32& signer) {
  for (const auto& v : n.precommits_for_rebroadcast_for_test(h)) {
    if (v.validator_pubkey == signer && v.round == r && v.frontier_transition_id == id) return true;
  }
  return false;
}
}  // namespace

// Liveness control (P7): after a failed lock write that emitted nothing, a restart on a healthy disk
// lets the node rejoin and the cluster finalize the height, with one transition everywhere.
// Guards against "safe" results that only come from a node abstaining forever.
TEST_TAGS(test_pf_recovery_failed_lock_write_then_restart_cluster_finalizes, "isolate,persistence-failure");
TEST(test_pf_recovery_failed_lock_write_then_restart_cluster_finalizes) {
  auto f = make_two_phase_fixture("/tmp/finalis_pf_recovery_live", 0xD0);
  const auto o = pf_others(*f);
  const auto a_id = frontier_proposal_id(*f->a0);
  pf_isolate_target(*f);
  pf_prevote_a0(*f);
  {
    faults::Scoped fault(pf_db(*f), faults::Mode::FailWalWrite, kPfFaultCount);
    pf_complete_polka_a0(*f, o);
    pf_require(faults::injected() >= 1, "fault injected");
    pf_require(!pf_within([&] { return f->target().local_vote_recorded_for_test(f->height, 0, a_id); }), "nothing emitted");
  }
  pf_restart_target_on_p2p(*f);
  for (auto& n : f->cluster.nodes) pf_require(n->pause_proposals_for_test(false), "unpause");
  pf_require(wait_for([&] {
               for (const auto& n : f->cluster.nodes) {
                 if (n->status().height < f->height) return false;
               }
               return true;
             }, ci_timeout_seconds(120)),
             "every node finalized the height after the target's recovery");
  const auto tip = f->cluster.nodes[0]->status();
  for (const auto& n : f->cluster.nodes) {
    pf_require(n->status().height >= f->height, "height reached");
  }
  pf_require(wait_for_same_tip(f->cluster.nodes, ci_timeout_seconds(30)), "one tip everywhere");
  (void)tip;
}

// Harness control at node level: a fault armed for another node's DB leaves the target's lock path
// healthy (precommit emitted, lock durable across restart).
TEST_TAGS(test_pf_control_fault_on_other_node_leaves_target_healthy, "isolate,persistence-failure");
TEST(test_pf_control_fault_on_other_node_leaves_target_healthy) {
  auto f = make_two_phase_fixture("/tmp/finalis_pf_other_node_fault", 0xD1);
  const auto o = pf_others(*f);
  const auto a_id = frontier_proposal_id(*f->a0);
  pf_isolate_target(*f);
  pf_prevote_a0(*f);
  {
    faults::Scoped fault(f->cluster.configs[o.nodes[0]].db_path, faults::Mode::FailWalWrite, kPfFaultCount);
    pf_complete_polka_a0(*f, o);
    pf_require(wait_for_local_precommit(f->target(), f->height, 0, a_id), "target precommits normally");
  }
  pf_restart_target_isolated(*f);
  const auto lock = f->target().local_vote_lock_for_test(f->height);
  pf_require(lock.has_value() && lock->first == a_id && lock->second == 0, "target lock durable");
}

// Precommits from other validators are not a re-entry path: after a failed lock write, their
// arrival (2 of 3, below quorum) must not make the node precommit.
TEST_TAGS(test_pf_lock_write_failure_peer_precommits_do_not_emit_precommit, "isolate,persistence-failure");
TEST(test_pf_lock_write_failure_peer_precommits_do_not_emit_precommit) {
  auto f = make_two_phase_fixture("/tmp/finalis_pf_peer_precommits", 0xD2);
  const auto o = pf_others(*f);
  const auto a_id = frontier_proposal_id(*f->a0);
  auto& t = f->target();
  pf_isolate_target(*f);
  pf_prevote_a0(*f);
  faults::Scoped fault(pf_db(*f), faults::Mode::FailWalWrite, kPfFaultCount);
  pf_complete_polka_a0(*f, o);
  pf_require(faults::injected() >= 1, "fault injected");
  for (std::size_t i = 0; i < 2; ++i) {
    pf_require(t.inject_network_vote_result_for_test(make_test_vote(pf_domain(*f), f->keys, f->height, 0, a_id, o.pubs[i])) ==
                   "accepted",
               "peer precommit accepted");
  }
  pf_require(!pf_within([&] { return t.local_vote_recorded_for_test(f->height, 0, a_id); }),
             "peer precommits re-entered the polka path");
}

namespace {
// The node's own answer to GET_FINALIZED_TIP, via the passive observer.
std::optional<std::uint64_t> pf_tip_reply(PfWireObserver& wire) {
  const auto before = wire.tips().size();
  if (!wire.request_tip()) return std::nullopt;
  if (!wait_for([&] { return wire.tips().size() > before; }, std::chrono::milliseconds(5000))) return std::nullopt;
  return wire.tips().back();
}

// Target on real p2p with its cluster peers stopped and one PfWireObserver connected; it has
// prevoted A0, locked on the A0 polka and precommitted A0, all durably (storage healthy).
void pf_locked_on_a0_with_observer(TwoPhaseFixture& f, const PfOthers& o, std::unique_ptr<PfWireObserver>* wire,
                                   std::uint64_t nonce) {
  auto& t = f.target();
  for (std::size_t k = 0; k < f.cluster.nodes.size(); ++k) {
    if (k != f.ti) f.cluster.nodes[k]->stop();
  }
  pf_require(wait_for([&] { return t.status().established_peers == 0; }, ci_timeout_seconds(30)), "cluster peers gone");
  *wire = std::make_unique<PfWireObserver>(t, f.cluster.configs[f.ti].network, nonce);
  pf_require(wait_for([&] { return t.status().established_peers >= 1; }, ci_timeout_seconds(10)), "observer established");
  pf_prevote_a0(f);
  pf_complete_polka_a0(f, o);
  pf_require(wait_for_local_precommit(t, f.height, 0, frontier_proposal_id(*f.a0)), "healthy precommit A0");
}
}  // namespace

// Invariant (D7): a finalized height is reported (status, GET_FINALIZED_TIP replies, TRANSITION /
// FINALIZED_TIP broadcasts) only once its batch is durable; a failed finalization write leaves the
// previous finalized state live, enters fail-stop, and a restart never rolls back a reported height.
// The finalization batch is the first failing write: lock and precommit were written while healthy.
TEST_TAGS(test_pf_failed_disk_finalization_is_not_reported_unless_persisted, "isolate,known-defect,persistence-failure,D7");
TEST(test_pf_failed_disk_finalization_is_not_reported_unless_persisted) {
  std::vector<std::string> failures;
  for (const auto mode : kPfGateFaults) {
    const std::string m = pf_fault_name(mode);
    auto f = make_two_phase_fixture("/tmp/finalis_pf_finalize_failed_disk_" + m, 0xD3);
    const auto o = pf_others(*f);
    const auto a_id = frontier_proposal_id(*f->a0);
    auto& t = f->target();
    std::unique_ptr<PfWireObserver> wire;
    pf_locked_on_a0_with_observer(*f, o, &wire, 0xD701);
    const auto h0 = t.status().height;
    pf_require(h0 + 1 == f->height, m + ": open height is the next one");
    const auto tip0 = pf_tip_reply(*wire);
    pf_require(tip0.has_value() && *tip0 == h0, m + ": control: tip reply is the finalized height before the fault");
    const int transitions0 = wire->transitions();
    std::uint64_t max_reported = h0;
    bool halted = false;
    std::string failure;
    {
      faults::Scoped fault(pf_db(*f), mode, kPfFaultCount);
      for (std::size_t i = 0; i < 2; ++i) {  // own precommit + 2 = quorum 3: finalization runs now
        (void)t.inject_network_vote_result_for_test(make_test_vote(pf_domain(*f), f->keys, f->height, 0, a_id, o.pubs[i]));
      }
      pf_require(faults::injected() >= 1, m + ": fault injected");
      (void)pf_within([&] {
        max_reported = std::max(max_reported, t.status().height);
        return false;
      }, 1500);
      halted = t.safety_storage_failed();
      failure = t.safety_storage_failure_for_test();
      if (const auto tip = pf_tip_reply(*wire); tip.has_value()) max_reported = std::max(max_reported, *tip);
      else failures.push_back(m + ": no tip reply after the failed write");
      for (const auto h : wire->tips()) max_reported = std::max(max_reported, h);
    }
    if (!halted || failure.rfind("finalization height=" + std::to_string(f->height), 0) != 0) {
      failures.push_back(m + ": failed finalization write did not enter fail-stop as finalization (got \"" + failure + "\")");
    }
    if (max_reported != h0) {
      failures.push_back(m + ": height " + std::to_string(max_reported) + " reported although its write failed");
    }
    if (wire->transitions() != transitions0) failures.push_back(m + ": finalized frontier broadcast after a failed write");
    wire.reset();
    pf_restart_target_isolated(*f);
    const auto after = f->target().status().height;
    std::cerr << "[pf] failed-disk finalization mode=" << m << " h0=" << h0 << " max-reported=" << max_reported
              << " after-restart=" << after << " halted=" << halted << " failure=\"" << failure << "\"\n";
    // A sync-then-EIO write is durable although it failed: the restart may find the new height (disk
    // ahead of what was reported), never a lower one.
    if (after < max_reported) failures.push_back(m + ": restart rolled back reported height " + std::to_string(max_reported));
  }
  pf_require(failures.empty(), pf_join(failures));
}

// Same through the delivered path (a certified block from a peer: handle_frontier_block_locked).
TEST_TAGS(test_pf_failed_disk_delivered_finalization_is_not_reported, "isolate,known-defect,persistence-failure,D7");
TEST(test_pf_failed_disk_delivered_finalization_is_not_reported) {
  for (const auto mode : kPfGateFaults) {
    const std::string m = pf_fault_name(mode);
    auto f = make_two_phase_fixture("/tmp/finalis_pf_delivered_failed_disk_" + m, 0xD5);
    pf_isolate_target(*f);
    auto& t = f->target();
    const auto h0 = t.status().height;
    const auto quorum = consensus::quorum_threshold(f->committee.size());
    auto qc = make_test_frontier_qc(pf_domain(*f), f->keys, f->committee, *f->a0, quorum);
    FinalityCertificate cert;
    cert.height = f->height;
    cert.round = 0;
    cert.frontier_transition_id = frontier_proposal_id(*f->a0);
    cert.quorum_threshold = static_cast<std::uint32_t>(quorum);
    cert.committee_members = f->committee;
    cert.signatures = qc.signatures;
    bool accepted = false;
    {
      faults::Scoped fault(pf_db(*f), mode, kPfFaultCount);
      accepted = t.inject_frontier_transition_for_test(*f->a0, cert);
      pf_require(faults::injected() >= 1, m + ": fault injected");
    }
    pf_require(!accepted, m + ": delivery whose write failed is not accepted");
    pf_require(t.status().height == h0, m + ": status keeps the previous finalized height");
    pf_require(t.safety_storage_failed() &&
                   t.safety_storage_failure_for_test().rfind("finalization height=" + std::to_string(f->height), 0) == 0,
               m + ": fail-stop as finalization (got \"" + t.safety_storage_failure_for_test() + "\")");
    pf_restart_target_isolated(*f);
    pf_require(f->target().status().height >= h0, m + ": no rollback below the previous height");
  }
}

// Control for the above: with storage healthy the same finalization is reported at once (status, tip
// reply), and a restart finds exactly that height and transition.
TEST_TAGS(test_pf_successful_finalization_is_durable_across_restart, "isolate,persistence-failure");
TEST(test_pf_successful_finalization_is_durable_across_restart) {
  auto f = make_two_phase_fixture("/tmp/finalis_pf_finalize_durable", 0xD6);
  const auto o = pf_others(*f);
  const auto a_id = frontier_proposal_id(*f->a0);
  auto& t = f->target();
  std::unique_ptr<PfWireObserver> wire;
  pf_locked_on_a0_with_observer(*f, o, &wire, 0xD702);
  for (std::size_t i = 0; i < 2; ++i) {
    (void)t.inject_network_vote_result_for_test(make_test_vote(pf_domain(*f), f->keys, f->height, 0, a_id, o.pubs[i]));
  }
  pf_require(wait_for([&] { return t.status().height == f->height; }, ci_timeout_seconds(10)), "finalized A0");
  pf_require(t.status().transition_hash == a_id, "finalized transition is A0");
  const auto tip = pf_tip_reply(*wire);
  pf_require(tip.has_value() && *tip == f->height, "tip reply reports the new height");
  pf_require(!t.safety_storage_failed(), "healthy node not halted");
  wire.reset();
  pf_restart_target_isolated(*f);
  pf_require(f->target().status().height == f->height, "restart finds the finalized height");
  pf_require(f->target().status().transition_hash == a_id, "restart finds the finalized transition");
}

// Round advancement after a failed lock write: once the node is in round 1, a late round-0 prevote no
// longer reaches the precommit path (current-round check), but the in-memory round-0 lock is still
// in the stall rebroadcast set (D2, asserted in its own test).
TEST_TAGS(test_pf_lock_write_failure_round_advance_closes_direct_path, "isolate,persistence-failure");
TEST(test_pf_lock_write_failure_round_advance_closes_direct_path) {
  auto f = make_two_phase_fixture("/tmp/finalis_pf_round_advance", 0xD4);
  const auto o = pf_others(*f);
  const auto a_id = frontier_proposal_id(*f->a0);
  auto& t = f->target();
  pf_isolate_target(*f);
  pf_prevote_a0(*f);
  faults::Scoped fault(pf_db(*f), faults::Mode::FailWalWrite, kPfFaultCount);
  pf_complete_polka_a0(*f, o);
  pf_require(faults::injected() >= 1, "fault injected");
  pf_require(advance_test_frontier_round(t, f->height, 1), "round 1");
  pf_require(pf_prevote(*f, 0, a_id, o.pubs[2]) == "accepted", "late round-0 prevote accepted");
  pf_require(!pf_within([&] { return t.local_vote_recorded_for_test(f->height, 0, a_id); }), "no round-0 precommit from round 1");
}

// Crash between a durable precommit and its receipt: the precommit left for an empty bus, the node
// restarts, and its restored lock makes the stall rebroadcast deliver the precommit to a peer that
// joins afterwards (observed without consuming: the peer's own rebroadcast set holds it).
TEST_TAGS(test_pf_crash_after_durable_precommit_before_receipt_is_redelivered, "isolate,persistence-failure");
TEST(test_pf_crash_after_durable_precommit_before_receipt_is_redelivered) {
  auto f = make_two_phase_fixture("/tmp/finalis_pf_crash_before_receipt", 0xD5);
  const auto o = pf_others(*f);
  const auto a_id = frontier_proposal_id(*f->a0);
  const auto me = f->target().local_validator_pubkey_for_test();
  pf_isolate_target(*f);
  pf_prevote_a0(*f);
  pf_complete_polka_a0(*f, o);
  pf_require(wait_for_local_precommit(f->target(), f->height, 0, a_id), "durable precommit A0 (no one listening)");
  pf_restart_target_isolated(*f);
  pf_require(f->target().local_vote_lock_for_test(f->height).has_value(), "lock restored");
  auto& spy = pf_bus_spy(*f, o.nodes[2]);
  pf_require(wait_for([&] { return pf_holds_precommit_from(spy, f->height, 0, a_id, me); }, ci_timeout_seconds(30)),
             "restarted node re-delivered its precommit to a peer");
}

// Restart consistency: every finalized state a node accepted live must load again after a restart.
// The live finalization path accepts a quorum of precommits from a round below the transition's own
// round; the startup derivation (verify_frontier_finality_certificate_against_state) rejects that
// certificate ("certificate-round-mismatch"), so the node cannot start again. Producing such a
// certificate needs more than f signers (honest validators never vote for a transition below its
// round), so it is outside the BFT fault model; the divergence between the two checks is the defect.
// Found by fuzz_consensus_persistence (faults disabled).
TEST_TAGS(test_pf_finalized_state_must_reload_after_restart, "isolate,known-defect,beyond-fault-model,R1");
TEST(test_pf_finalized_state_must_reload_after_restart) {
  auto f = make_two_phase_fixture("/tmp/finalis_pf_reload_finalized", 0xD6);
  const auto o = pf_others(*f);
  const auto b1_id = frontier_proposal_id(*f->b1);
  auto& t = f->target();
  pf_isolate_target(*f);
  pf_require(advance_test_frontier_round(t, f->height, 1), "round 1");
  const auto tc0 = make_test_timeout_certificate(pf_domain(*f), f->keys, f->committee, f->height, 0, f->quorum);
  pf_require(t.inject_network_propose_result_for_test(make_test_frontier_propose_msg(pf_domain(*f), *f->b1, std::nullopt, tc0)) ==
                 "accepted",
             "B1 (transition round 1) body held");
  for (std::size_t i = 0; i < 3; ++i) {
    (void)t.inject_network_vote_result_for_test(make_test_vote(pf_domain(*f), f->keys, f->height, 0, b1_id, o.pubs[i]));
  }
  const bool finalized_live = wait_for([&] { return t.status().height >= f->height; }, std::chrono::milliseconds(3000));
  std::cerr << "[pf] round-0 certificate for a round-1 transition finalized live=" << finalized_live << "\n";
  pf_require(finalized_live, "precondition: the live path accepted the certificate");
  t.stop();
  f->cluster.nodes[f->ti].reset();
  f->cluster.nodes[f->ti] = std::make_unique<node::Node>(f->cluster.configs[f->ti]);
  pf_require(f->target().init(), "node cannot restart from a finalized state it accepted live (R1)");
}

// E1: an ENOSPC WAL failure on the lock path (the valid-polka write, then the lock write in the same
// on_prevotes_changed_locked call) can abort the process inside the system librocksdb
// (WritableFileWriter::Append assertion `sync_without_flush_called_`, stack:
// lock_on_polka_locked -> DB::write_batch_durable -> DBImpl::Write) instead of returning an error. The
// invariant asserted is the minimal one: a disk-full error must not kill the validator, and no
// precommit may follow the failed lock write. Intermittent (seen 4/4 times under ENOSPC only), so the
// scenario is repeated; the child-process isolation turns an abort into this test's failure.
// Mechanism (P5, test_storage_raw_rocksdb_enospc_reuses_failed_wal_writer): RocksDB auto-resumes
// after the ENOSPC and a later write reaches the failed WAL writer; the DB write fence stops that.
TEST_TAGS(test_pf_enospc_wal_failure_must_not_abort_node, "isolate,known-defect,persistence-failure,E1");
TEST(test_pf_enospc_wal_failure_must_not_abort_node) {
  for (int i = 0; i < 8; ++i) {
    auto f = make_two_phase_fixture("/tmp/finalis_pf_enospc_abort_" + std::to_string(i), 0xD7);
    const auto o = pf_others(*f);
    const auto a_id = frontier_proposal_id(*f->a0);
    pf_isolate_target(*f);
    pf_prevote_a0(*f);
    {
      faults::Scoped fault(pf_db(*f), faults::Mode::FailWalWriteNoSpace, kPfFaultCount);
      pf_complete_polka_a0(*f, o);
      pf_require(faults::injected() >= 1, "fault injected");
      pf_require(!pf_within([&] { return f->target().local_vote_recorded_for_test(f->height, 0, a_id); }),
                 "no precommit after the failed lock write");
    }
    pf_restart_target_isolated(*f);
  }
}

// ---------- P2. Fail-stop after a failed safety-critical write ----------
//
// Oracle shared by these tests: consensus_signature_count_for_test counts every validator-key
// signature (sign_consensus_locked / vrf_prove_consensus_locked, under mu_), and fail-stop entry
// snapshots it under mu_. signatures_after_fail_stop_for_test is the difference, so any signing path
// that ran after the failure was published, from any thread, shows up as a non-zero value.
namespace {
// The node fail-stopped, named for the path under test, or (P5) for an earlier failed write of the
// event loop's: the fault stays armed for every write, as a failing disk does, and whichever write
// comes first fences the DB and halts the node before the path under test signs. Either is reported.
void pf_require_halted(node::Node& t, const std::string& what, const std::string& operation_prefixes) {
  pf_require(t.safety_storage_failed(), what + ": node entered fail-stop");
  // A fence from a non-safety write is entered formally by the event loop on its next tick.
  (void)wait_for([&] { return !t.safety_storage_failure_for_test().empty(); }, std::chrono::milliseconds(3000));
  const auto failure = t.safety_storage_failure_for_test();
  bool known = false;
  std::istringstream ops(operation_prefixes);
  for (std::string op; std::getline(ops, op, ',');) known = known || failure.rfind(op, 0) == 0;
  const bool earlier_write = failure.rfind("storage-write: ", 0) == 0;
  std::cerr << "[pf] halted " << what << " on=" << (known ? "path-under-test" : earlier_write ? "earlier-write" : "unknown")
            << " failure=\"" << failure.substr(0, 120) << "\"\n";
  pf_require(known || earlier_write, what + ": failure names the operation (got \"" + failure + "\")");
  pf_require(failure.find(": ") != std::string::npos && failure.size() > failure.find(": ") + 2,
             what + ": failure carries the storage error (got \"" + failure + "\")");
}

void pf_require_no_signature_after_fail_stop(node::Node& t, const std::string& what) {
  const auto n = t.signatures_after_fail_stop_for_test();
  pf_require(n == 0, what + ": " + std::to_string(n) + " validator-key signature(s) made after fail-stop");
}

// Every in-process signing path a halted node could still be driven into, at round 0 and round 1.
void pf_drive_signing_paths_after_halt(TwoPhaseFixture& f, const PfOthers& o, const std::string& m) {
  auto& t = f.target();
  const auto a_id = frontier_proposal_id(*f.a0);
  (void)pf_prevote(f, 0, a_id, o.pubs[2]);  // re-entry (D1 path)
  (void)t.inject_network_propose_result_for_test(make_test_frontier_propose_msg(pf_domain(f), *f.a0));  // body re-delivery
  pf_require(t.rebroadcast_sizes_for_test(f.height) == std::array<std::size_t, 3>{0, 0, 0}, m + ": stall rebroadcast empty");
  t.reseed_local_votes_for_test(f.height);
  pf_require(!t.local_vote_recorded_for_test(f.height, 0, a_id), m + ": reseed recorded no own precommit");
  // A new round and a new value: the node would prevote B1 if it were healthy (no lock was published).
  pf_require(advance_test_frontier_round(t, f.height, 1), m + ": advance to round 1");
  (void)t.inject_network_propose_result_for_test(make_test_frontier_propose_msg(pf_domain(f), *f.b1));
  pf_require(!t.local_prevote_recorded_for_test(f.height, 1, frontier_proposal_id(*f.b1)), m + ": no prevote B1 after fail-stop");
  pf_require(!t.local_vote_recorded_for_test(f.height, 1, frontier_proposal_id(*f.b1)), m + ": no precommit B1 after fail-stop");
  pf_require(!pf_own_precommit_in_rebroadcast(t, f.height, 0, a_id), m + ": no precommit A0 in rebroadcast");
}
}  // namespace

// A failed lock / valid-polka write fail-stops the node before mu_ is released; afterwards no path
// (re-entry, body re-delivery, stall rebroadcast, reseed, a later round) signs anything.
TEST_TAGS(test_pf_failstop_lock_write_failure_halts_all_signing, "isolate,persistence-failure,fail-stop");
TEST(test_pf_failstop_lock_write_failure_halts_all_signing) {
  for (const auto mode : kPfGateFaults) {
    const std::string m = pf_fault_name(mode);
    auto f = make_two_phase_fixture("/tmp/finalis_pf_failstop_lock_" + m, 0xE0);
    pf_isolate_target(*f);
    const auto o = pf_others(*f);
    auto& t = f->target();
    pf_prevote_a0(*f);
    pf_require(!t.safety_storage_failed(), m + ": healthy before the fault");
    pf_require(t.consensus_signature_count_for_test() > 0, m + ": control: the A0 prevote was signed through the guard");
    faults::Scoped fault(pf_db(*f), mode, kPfFaultCount);
    pf_complete_polka_a0(*f, o);
    pf_require(faults::injected() >= 1, m + ": fault injected");
    // The polka's first durable write is the valid-polka batch; the lock write fails right after it.
    pf_require_halted(t, m, "valid-polka height=,vote-lock height=");
    pf_require_no_signature_after_fail_stop(t, m + " (at fail-stop)");
    pf_drive_signing_paths_after_halt(*f, o, m);
    pf_require_no_signature_after_fail_stop(t, m + " (after driving every path)");
  }
}

// Same for a failed prevote-record write.
TEST_TAGS(test_pf_failstop_prevote_write_failure_halts_all_signing, "isolate,persistence-failure,fail-stop");
TEST(test_pf_failstop_prevote_write_failure_halts_all_signing) {
  for (const auto mode : kPfGateFaults) {
    const std::string m = pf_fault_name(mode);
    auto f = make_two_phase_fixture("/tmp/finalis_pf_failstop_prevote_" + m, 0xE1);
    pf_isolate_target(*f);
    const auto o = pf_others(*f);
    auto& t = f->target();
    const auto a_id = frontier_proposal_id(*f->a0);
    pf_require(advance_test_frontier_round(t, f->height, 0), m + ": round 0");
    faults::Scoped fault(pf_db(*f), mode, kPfFaultCount);
    (void)t.inject_network_propose_result_for_test(make_test_frontier_propose_msg(pf_domain(*f), *f->a0));
    pf_require(faults::injected() >= 1, m + ": fault injected");
    pf_require(!t.local_prevote_recorded_for_test(f->height, 0, a_id), m + ": failed prevote not recorded");
    pf_require_halted(t, m, "prevote-record height=");
    // The prevote was signed just before its write failed (sign, then persist); that one is not
    // counted as after fail-stop and was never sent.
    pf_require_no_signature_after_fail_stop(t, m + " (at fail-stop)");
    pf_drive_signing_paths_after_halt(*f, o, m);
    pf_require_no_signature_after_fail_stop(t, m + " (after driving every path)");
  }
}

// Timeout votes: with proposals unpaused, a healthy target times out of its round and signs a
// timeout vote (control); a fail-stopped one signs none.
TEST_TAGS(test_pf_failstop_halted_node_signs_no_timeout_vote, "isolate,persistence-failure,fail-stop");
TEST(test_pf_failstop_halted_node_signs_no_timeout_vote) {
  for (const bool inject : {false, true}) {
    const std::string m = inject ? "halted" : "control";
    auto f = make_two_phase_fixture("/tmp/finalis_pf_failstop_timeout_" + m, 0xE2);
    pf_isolate_target(*f);
    auto& t = f->target();
    pf_require(advance_test_frontier_round(t, f->height, 0), m + ": round 0");
    std::optional<faults::Scoped> fault;
    if (inject) {
      fault.emplace(pf_db(*f), faults::Mode::FailWalWrite, kPfFaultCount);
      (void)t.inject_network_propose_result_for_test(make_test_frontier_propose_msg(pf_domain(*f), *f->a0));
      pf_require_halted(t, m, "prevote-record height=");
    }
    pf_require(t.pause_proposals_for_test(false), m + ": unpause");
    const bool timed_out = wait_for([&] { return t.local_timeout_vote_reserved_for_test(f->height, 0) ||
                                                 t.local_timeout_vote_reserved_for_test(f->height, 1); },
                                    inject ? std::chrono::milliseconds(3000) : std::chrono::milliseconds(ci_timeout_seconds(30)));
    if (inject) {
      pf_require(!timed_out, m + ": no timeout vote after fail-stop");
      pf_require_no_signature_after_fail_stop(t, m);
    } else {
      pf_require(timed_out, m + ": healthy target signs a timeout vote (the path is reachable)");
    }
  }
}

// Wire level: once fail-stopped, the target sends no PREVOTE, VOTE, TIMEOUT_VOTE or PROPOSE frame,
// although a stall rebroadcast ran before the fault (control). Passive observer (PfWireObserver).
TEST_TAGS(test_pf_failstop_halted_node_sends_no_consensus_frame, "isolate,persistence-failure,fail-stop");
TEST(test_pf_failstop_halted_node_sends_no_consensus_frame) {
  for (const auto mode : kPfGateFaults) {
    const std::string m = pf_fault_name(mode);
    auto f = make_two_phase_fixture("/tmp/finalis_pf_failstop_wire_" + m, 0xE3);
    const auto o = pf_others(*f);
    const auto a_id = frontier_proposal_id(*f->a0);
    auto& t = f->target();
    const auto& net = f->cluster.configs[f->ti].network;
    for (std::size_t k = 0; k < f->cluster.nodes.size(); ++k) {
      if (k != f->ti) f->cluster.nodes[k]->stop();
    }
    pf_require(wait_for([&] { return t.status().established_peers == 0; }, ci_timeout_seconds(30)), m + ": cluster peers gone");
    PfWireObserver wire(t, net, 0xFA11);
    pf_require(wait_for([&] { return t.status().established_peers >= 1; }, ci_timeout_seconds(10)), m + ": observer established");
    pf_require(advance_test_frontier_round(t, f->height, 0), m + ": round 0");
    const auto marker = make_test_vote(pf_domain(*f), f->keys, f->height, 0, a_id, o.pubs[0]);
    pf_require(t.inject_vote_for_test(marker), m + ": marker precommit held by the target only");
    pf_require(wait_for([&] { return wire.saw_precommit(f->height, 0, a_id, o.pubs[0]); }, ci_timeout_seconds(30)),
               m + ": control: the healthy target's stall rebroadcast reaches the observer");
    faults::Scoped fault(pf_db(*f), mode, kPfFaultCount);
    (void)t.inject_network_propose_result_for_test(make_test_frontier_propose_msg(pf_domain(*f), *f->a0));
    pf_require_halted(t, m, "prevote-record height=");
    // Frames queued before the flag was set may still be on the socket.
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    const int before = wire.consensus_frames();
    pf_drive_signing_paths_after_halt(*f, o, m);
    (void)t.pause_proposals_for_test(false);
    std::this_thread::sleep_for(std::chrono::milliseconds(3000));  // 15 round timeouts, several rebroadcast cycles
    const int after = wire.consensus_frames();
    std::cerr << "[pf] failstop-wire mode=" << m << " frames-at-halt=" << before << " frames-after=" << after << "\n";
    pf_require(after == before, m + ": " + std::to_string(after - before) + " consensus frame(s) sent after fail-stop");
    pf_require(!wire.saw_prevote(f->height, 0, a_id, t.local_validator_pubkey_for_test()), m + ": failed prevote A0 never sent");
    pf_require(wire.connected(), m + ": observer stayed connected (silence is not a dropped link)");
    pf_require_no_signature_after_fail_stop(t, m);
  }
}

// Quorum-1 self-vote (finalize_if_quorum): a single-validator node signs its own precommit there,
// without the lock path, as soon as the proposal body arrives. Control: a healthy node signs it and
// finalizes. Halted: fail-stop is entered through the test hook, since no safety-row write precedes
// this path (the self-vote comes before the prevote write; see KNOWN_DEFECTS.md H1, P7).
TEST_TAGS(test_pf_failstop_quorum1_self_vote_refused, "isolate,persistence-failure,fail-stop");
TEST(test_pf_failstop_quorum1_self_vote_refused) {
  for (const bool halted : {false, true}) {
    const std::string m = halted ? "halted" : "control";
    const std::string base = unique_test_base("/tmp/finalis_pf_failstop_q1_" + m);
    std::filesystem::remove_all(base);
    std::filesystem::create_directories(base);
    const std::string gpath = base + "/genesis.json";
    pf_require(write_empty_mainnet_bootstrap_genesis_file(gpath), "genesis");
    node::NodeConfig cfg;
    cfg.allow_unencrypted_keystore = true;
    cfg.node_id = 0;
    cfg.dns_seeds = false;
    cfg.network.default_seeds.clear();
    cfg.db_path = base + "/node0";
    cfg.p2p_port = reserve_test_port();
    pf_require(cfg.p2p_port != 0, "port");
    cfg.genesis_path = gpath;
    cfg.allow_unsafe_genesis_override = true;
    cfg.validator_key_file = cfg.db_path + "/keystore/validator.json";
    cfg.validator_passphrase = "test-pass";
    pf_require(create_test_validator_keystore(cfg, 0), "keystore");
    Tx tx = make_fixture_ingress_tx(1, 0xE4);
    std::unique_ptr<node::Node> n;
    // Not started (no event loop): the test drives the node.
    pf_require(restart_single_node_with_seeded_certified_ingress(cfg, {tx.serialize()}, &n, nullptr, false) && n, "single node");
    pf_require(n->committee_for_height_round_for_test(1, 0).size() == 1, "single-member committee");
    auto proposal = build_test_frontier_proposal(*n, 1, 0);
    pf_require(proposal.has_value(), m + ": proposal built");
    const auto id = frontier_proposal_id(*proposal);
    const auto msg = make_test_frontier_propose_msg(n->consensus_domain_for_test(), *proposal);
    if (halted) {
      n->enter_safety_fail_stop_for_test("simulated");
      pf_require(n->safety_storage_failed(), m + ": halted");
    }
    const auto sigs_before = n->consensus_signature_count_for_test();
    (void)n->inject_propose_msg_for_test(msg);  // body arrives: finalize_if_quorum runs
    (void)n->finalize_if_quorum_for_test(id, 1, 0);  // and once more, directly
    if (halted) {
      pf_require(n->consensus_signature_count_for_test() == sigs_before, m + ": no signature on proposal delivery or finalize");
      pf_require(!n->local_vote_recorded_for_test(1, 0, id), m + ": no quorum-1 self-vote");
      pf_require(n->status().height == 0, m + ": nothing finalized without the self-vote");
      pf_require_no_signature_after_fail_stop(*n, m);
    } else {
      pf_require(n->consensus_signature_count_for_test() > sigs_before, m + ": healthy quorum-1 path signs its self-vote");
      pf_require(n->status().height == 1, m + ": healthy single validator finalizes height 1 by the self-vote");
    }
    n->stop();
  }
}

// Concurrency: signing paths hammered from several threads while the failing write happens on
// another. Every signature is either counted before the fail-stop snapshot or refused.
TEST_TAGS(test_pf_failstop_concurrent_failure_and_signing, "isolate,persistence-failure,fail-stop");
TEST(test_pf_failstop_concurrent_failure_and_signing) {
  for (int iter = 0; iter < 3; ++iter) {
    const std::string m = "iter" + std::to_string(iter);
    auto f = make_two_phase_fixture("/tmp/finalis_pf_failstop_race_" + std::to_string(iter), 0xE5);
    pf_isolate_target(*f);
    const auto o = pf_others(*f);
    auto& t = f->target();
    const auto a_id = frontier_proposal_id(*f->a0);
    pf_prevote_a0(*f);  // a prevote record: the rebroadcast and the reseed re-sign it
    std::atomic<bool> stop{false};
    std::atomic<std::uint64_t> calls{0};
    std::vector<std::thread> hammers;
    for (int k = 0; k < 4; ++k) {
      hammers.emplace_back([&, k] {
        while (!stop.load()) {
          switch (k) {
            case 0: (void)t.rebroadcast_sizes_for_test(f->height); break;
            case 1: t.reseed_local_votes_for_test(f->height); break;
            case 2: (void)t.inject_network_propose_result_for_test(make_test_frontier_propose_msg(pf_domain(*f), *f->a0)); break;
            default: (void)t.precommits_for_rebroadcast_for_test(f->height); break;
          }
          calls.fetch_add(1);
        }
      });
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    const auto sigs_before_fault = t.consensus_signature_count_for_test();
    {
      faults::Scoped fault(pf_db(*f), faults::Mode::FailWalWrite, kPfFaultCount);
      // Third prevote completes the polka: valid-polka / lock write fails while the hammers run.
      pf_require(pf_prevote(*f, 0, a_id, o.pubs[0]) == "accepted", m + ": prevote other[0]");
      (void)pf_prevote(*f, 0, a_id, o.pubs[1]);
      pf_require(faults::injected() >= 1, m + ": fault injected");
      std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
    stop.store(true);
    for (auto& th : hammers) th.join();
    pf_require_halted(t, m, "valid-polka height=,vote-lock height=");
    std::cerr << "[pf] failstop-race " << m << " hammer-calls=" << calls.load() << " sigs-before-fault=" << sigs_before_fault
              << " sigs-total=" << t.consensus_signature_count_for_test()
              << " sigs-after-fail-stop=" << t.signatures_after_fail_stop_for_test() << "\n";
    pf_require(sigs_before_fault > 0, m + ": control: the hammers were signing before the fault");
    pf_require_no_signature_after_fail_stop(t, m);
    pf_require(!t.local_vote_recorded_for_test(f->height, 0, a_id), m + ": no precommit A0");
  }
}

// Shutdown after fail-stop: stop() returns within an explicit bound for every fault mode, ENOSPC
// included, while the disk is still failing; it rewrites neither peers.dat nor addrman.dat; the
// node restarts from disk healthy. A stop() that does not return is reported and ends this child
// process, since the blocked thread cannot be joined: bounded shutdown is then unproven.
TEST_TAGS(test_pf_failstop_shutdown_is_bounded, "isolate,persistence-failure,fail-stop");
TEST(test_pf_failstop_shutdown_is_bounded) {
  constexpr auto kBound = std::chrono::seconds(20);
  for (const auto mode : kPfWalFaults) {
    const std::string m = pf_fault_name(mode);
    auto f = make_two_phase_fixture("/tmp/finalis_pf_failstop_stop_" + m, 0xE6);
    pf_isolate_target(*f);
    const auto o = pf_others(*f);
    auto& t = f->target();
    pf_prevote_a0(*f);
    const auto dir = std::filesystem::path(pf_db(*f));
    const auto stamp = [&](const char* name) {
      std::error_code ec;
      const auto when = std::filesystem::last_write_time(dir / name, ec);
      return ec ? std::string("missing") : std::to_string(when.time_since_epoch().count());
    };
    {
      faults::Scoped fault(pf_db(*f), mode, kPfFaultCount);
      pf_complete_polka_a0(*f, o);
      pf_require(faults::injected() >= 1, m + ": fault injected");
      pf_require_halted(t, m, "valid-polka height=,vote-lock height=");
      const auto peers_before = stamp("peers.dat"), addrman_before = stamp("addrman.dat");
      std::atomic<bool> done{false};
      const auto start = std::chrono::steady_clock::now();
      std::thread stopper([&] {
        t.stop();
        done.store(true);
      });
      if (!wait_for([&] { return done.load(); }, kBound)) {
        std::cerr << "[pf] BOUNDED-SHUTDOWN-UNPROVEN mode=" << m << ": Node::stop() still blocked after " << kBound.count()
                  << "s after fail-stop\n";
        std::cerr.flush();
        std::_Exit(3);
      }
      stopper.join();
      const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();
      std::cerr << "[pf] failstop-shutdown mode=" << m << " stop_ms=" << ms << "\n";
      pf_require(stamp("peers.dat") == peers_before, m + ": peers.dat not rewritten after fail-stop");
      pf_require(stamp("addrman.dat") == addrman_before, m + ": addrman.dat not rewritten after fail-stop");
    }
    f->cluster.nodes[f->ti].reset();
    f->cluster.nodes[f->ti] = std::make_unique<node::Node>(f->cluster.configs[f->ti]);
    pf_require(f->target().init(), m + ": restart from disk after fail-stop");
    pf_require(!f->target().safety_storage_failed(), m + ": restarted node is not halted");
  }
}

// ENOSPC: after the first failed WAL write, nothing reaches the WAL again in this process (the
// observed E1 abort followed a second write). With an every-call fault, injected() counts every WAL
// write() attempt, so it must not grow after fail-stop while every path, and stop(), runs.
TEST_TAGS(test_pf_failstop_enospc_no_second_wal_write, "isolate,persistence-failure,fail-stop");
TEST(test_pf_failstop_enospc_no_second_wal_write) {
  for (int iter = 0; iter < 3; ++iter) {
    const std::string m = "enospc-iter" + std::to_string(iter);
    auto f = make_two_phase_fixture("/tmp/finalis_pf_failstop_enospc_" + std::to_string(iter), 0xE7);
    pf_isolate_target(*f);
    const auto o = pf_others(*f);
    auto& t = f->target();
    pf_prevote_a0(*f);
    faults::Scoped fault(pf_db(*f), faults::Mode::FailWalWriteNoSpace, kPfFaultCount);
    pf_complete_polka_a0(*f, o);
    pf_require_halted(t, m, "valid-polka height=,vote-lock height=");
    const int at_halt = faults::injected();
    pf_require(at_halt >= 1, m + ": fault injected");
    pf_drive_signing_paths_after_halt(*f, o, m);
    t.stop();
    std::cerr << "[pf] failstop-enospc " << m << " wal-writes-at-halt=" << at_halt << " after-stop=" << faults::injected() << "\n";
    pf_require(faults::injected() == at_halt, m + ": " + std::to_string(faults::injected() - at_halt) +
                                                  " WAL write attempt(s) after fail-stop");
  }
}

// P5: a failed write that is not consensus safety state (here the slashing record a prevote
// equivocation stores, a plain DB::put) fences the DB; the node signs nothing more, the event loop
// enters fail-stop as "storage-write", and no later write reaches the WAL. Before P5 this was the
// first failure of most campaign aborts (E1): the node kept writing after it. Write faults only: a
// non-sync put never fsyncs, so the sync modes cannot fail it.
TEST_TAGS(test_pf_failstop_non_safety_write_failure_halts_node, "isolate,persistence-failure,fail-stop");
TEST(test_pf_failstop_non_safety_write_failure_halts_node) {
  for (const auto mode : {faults::Mode::FailWalWrite, faults::Mode::FailWalWriteNoSpace}) {
    for (int iter = 0; iter < (mode == faults::Mode::FailWalWriteNoSpace ? 3 : 1); ++iter) {
      const std::string m = pf_fault_name(mode) + "#" + std::to_string(iter);
      auto f = make_two_phase_fixture("/tmp/finalis_pf_failstop_slash_" + pf_fault_name(mode), 0xE8);
      pf_isolate_target(*f);
      const auto o = pf_others(*f);
      auto& t = f->target();
      pf_prevote_a0(*f);
      pf_require(pf_prevote(*f, 0, frontier_proposal_id(*f->a0), o.pubs[0]) == "accepted", m + ": prevote A0 from other[0]");
      int at_fence = 0;
      {
        faults::Scoped fault(pf_db(*f), mode, kPfFaultCount);
        // other[0] prevotes B0 in the same round: equivocation evidence, stored by put_slashing_record.
        (void)pf_prevote(*f, 0, frontier_proposal_id(*f->b0), o.pubs[0]);
        pf_require(faults::injected() >= 1, m + ": fault injected");
        pf_require(t.safety_storage_failed(), m + ": failed slashing-record write halts signing at once");
        pf_require(wait_for([&] { return !t.safety_storage_failure_for_test().empty(); }, std::chrono::milliseconds(3000)),
                   m + ": event loop entered fail-stop");
        const auto failure = t.safety_storage_failure_for_test();
        pf_require(failure.rfind("storage-write: put[SL:", 0) == 0, m + ": fail-stop names the failed write (got \"" + failure + "\")");
        at_fence = faults::injected();
        pf_drive_signing_paths_after_halt(*f, o, m);
        pf_require_no_signature_after_fail_stop(t, m);
        t.stop();
        pf_require(faults::injected() == at_fence, m + ": " + std::to_string(faults::injected() - at_fence) +
                                                       " WAL write attempt(s) after the fence");
      }
      std::cerr << "[pf] non-safety-write mode=" << m << " wal-writes=" << at_fence << " failure=\""
                << t.safety_storage_failure_for_test() << "\"\n";
      pf_restart_target_isolated(*f);
      pf_require(!f->target().safety_storage_failed(), m + ": restart from disk is healthy");
    }
  }
}
#endif
