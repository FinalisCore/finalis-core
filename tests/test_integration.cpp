#include "test_framework.hpp"

#include <chrono>
#include <cstdlib>
#include <cerrno>
#include <filesystem>
#include <fstream>
#include <limits>
#include <sstream>
#include <thread>
#include <array>
#include <atomic>
#include <iostream>

#ifdef _WIN32
#include <process.h>
#endif

#include "address/address.hpp"
#include "availability/retention.hpp"
#include "codec/bytes.hpp"
#include "consensus/canonical_derivation.hpp"
#include "consensus/frontier_execution.hpp"
#include "consensus/ingress.hpp"
#include "consensus/validator_registry.hpp"
#include "consensus/state_commitment.hpp"
#include "common/socket_compat.hpp"
#include "crypto/ed25519.hpp"
#include "crypto/hash.hpp"
#include "lightserver/server.hpp"
#include "keystore/validator_keystore.hpp"
#include "merkle/merkle.hpp"
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

long long current_process_id() {
#ifdef _WIN32
  return static_cast<long long>(::_getpid());
#else
  return static_cast<long long>(::getpid());
#endif
}

std::chrono::seconds ci_timeout_seconds(int base_seconds) {
#ifdef _WIN32
  return std::chrono::seconds(base_seconds * 3);
#else
  return std::chrono::seconds(base_seconds);
#endif
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

std::string unique_test_base(const std::string& prefix) {
  static std::atomic<std::uint64_t> unique_counter{0};
  const auto now = std::chrono::steady_clock::now().time_since_epoch().count();
  const auto seq = unique_counter.fetch_add(1, std::memory_order_relaxed);
  return prefix + "_" + std::to_string(current_process_id()) + "_" + std::to_string(now) + "_" + std::to_string(seq);
}

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

std::string csafe_db_key(std::uint64_t height) { return "CSAFE:" + epoch_db_key_suffix(height); }

std::array<std::uint8_t, 32> deterministic_seed_for_node_id(int node_id);
bool write_mainnet_genesis_file(const std::string& path, std::size_t n_validators);

Bytes serialize_test_finalized_write_marker(std::uint64_t height, const Hash32& block_id) {
  codec::ByteWriter w;
  w.u64le(height);
  w.bytes_fixed(block_id);
  return w.take();
}

node::NodeConfig single_node_cfg(const std::string& base, std::size_t max_committee = MAX_COMMITTEE) {
  node::NodeConfig cfg;
  cfg.disable_p2p = true;
  cfg.node_id = 0;
  cfg.max_committee = max_committee;
  cfg.network.min_block_interval_ms = 100;
  cfg.network.round_timeout_ms = 200;
  cfg.p2p_port = 19040;
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

  consensus::CanonicalGenesisState genesis_state;
  genesis_state.genesis_artifact_id = genesis::block_id(*doc);
  genesis_state.initial_validators = doc->initial_validators;

  consensus::CanonicalDerivedState genesis_derived;
  std::string error;
  if (!consensus::build_genesis_canonical_state(derivation_cfg, genesis_state, &genesis_derived, &error)) return false;
  consensus::CertifiedIngressLaneRecords lane_records;
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
    lane_roots[lane] = consensus::compute_lane_root_append(lane_roots[lane], cert.tx_hash);
    lane_records[lane].push_back(consensus::CertifiedIngressRecord{cert, raw});
  }
  consensus::FrontierExecutionResult exec_result;
  if (!consensus::execute_frontier_lane_prefix(genesis_derived.utxos, genesis_derived.finalized_frontier_vector,
                                               next_vector, lane_records, genesis_derived.finalized_lane_roots, nullptr,
                                               &exec_result, &error)) {
    return false;
  }
  const auto leader = consensus::canonical_leader_for_height_round(derivation_cfg, genesis_derived, 1, 0);
  if (!leader.has_value()) return false;
  if (!consensus::populate_frontier_transition_metadata(derivation_cfg, genesis_derived, 1, 0, *leader, {*leader},
                                                        exec_result.accepted_fee_units, exec_result.next_utxos,
                                                        &exec_result.transition, &error)) {
    return false;
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
  const auto msg = vote_signing_message(cert.height, cert.round, cert.frontier_transition_id);
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

  consensus::CanonicalGenesisState genesis_state;
  genesis_state.genesis_artifact_id = genesis::block_id(*doc);
  genesis_state.initial_validators = doc->initial_validators;

  consensus::CanonicalDerivedState genesis_derived;
  std::string error;
  if (!consensus::build_genesis_canonical_state(derivation_cfg, genesis_state, &genesis_derived, &error)) return false;

  FrontierVector next_vector = genesis_derived.finalized_frontier_vector;
  auto lane_roots = genesis_derived.finalized_lane_roots;
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

  consensus::CanonicalGenesisState genesis_state;
  genesis_state.genesis_artifact_id = genesis::block_id(*doc);
  genesis_state.initial_validators = doc->initial_validators;

  CertifiedIngressFixture fixture;
  std::string error;
  if (!persist_certified_ingress_fixture(cfg, db, ordered_records, &fixture)) return false;

  consensus::FrontierExecutionResult exec_result;
  if (!consensus::execute_frontier_lane_prefix(fixture.parent.utxos, fixture.parent.finalized_frontier_vector,
                                               fixture.next_vector, fixture.lane_records,
                                               fixture.parent.finalized_lane_roots, nullptr,
                                               &exec_result, &error)) {
    return false;
  }
  const auto leader = consensus::canonical_leader_for_height_round(derivation_cfg, fixture.parent, height, round);
  if (!leader.has_value()) return false;
  if (!consensus::populate_frontier_transition_metadata(derivation_cfg, fixture.parent, height, round, *leader, {*leader},
                                                        exec_result.accepted_fee_units, exec_result.next_utxos,
                                                        &exec_result.transition, &error)) {
    return false;
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

bool write_mainnet_genesis_file(const std::string& path, std::size_t n_validators);

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
    auto msg = signing_message_for_input(tx, static_cast<std::uint32_t>(i));
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
      validator_join_request_pop_message(new_validator.public_key, new_validator.public_key),
      Bytes(new_validator.private_key.begin(), new_validator.private_key.end()));
  if (!pop.has_value()) return std::nullopt;

  Bytes reg_spk{'S', 'C', 'V', 'A', 'L', 'R', 'E', 'G'};
  reg_spk.insert(reg_spk.end(), new_validator.public_key.begin(), new_validator.public_key.end());
  Bytes req_spk{'S', 'C', 'V', 'A', 'L', 'J', 'R', 'Q'};
  req_spk.insert(req_spk.end(), new_validator.public_key.begin(), new_validator.public_key.end());
  req_spk.insert(req_spk.end(), new_validator.public_key.begin(), new_validator.public_key.end());
  req_spk.insert(req_spk.end(), pop->begin(), pop->end());

  std::vector<TxOut> outputs{TxOut{bond_amount, reg_spk}, TxOut{0, req_spk}};
  const std::uint64_t change = in_sum - bond_amount - fee;
  if (change > 0) outputs.push_back(TxOut{change, address::p2pkh_script_pubkey(sender_pkh)});

  return build_signed_p2pkh_tx_multi_input(selected, Bytes(validator0.private_key.begin(), validator0.private_key.end()),
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

  return build_onboarding_registration_tx(
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
      validator_join_request_pop_message(new_validator.public_key, payout_pubkey),
      Bytes(new_validator.private_key.begin(), new_validator.private_key.end()));
  if (!pop.has_value()) return std::nullopt;

  Bytes reg_spk{'S', 'C', 'V', 'A', 'L', 'R', 'E', 'G'};
  reg_spk.insert(reg_spk.end(), new_validator.public_key.begin(), new_validator.public_key.end());
  Bytes req_spk{'S', 'C', 'V', 'A', 'L', 'J', 'R', 'Q'};
  req_spk.insert(req_spk.end(), new_validator.public_key.begin(), new_validator.public_key.end());
  req_spk.insert(req_spk.end(), payout_pubkey.begin(), payout_pubkey.end());
  req_spk.insert(req_spk.end(), pop->begin(), pop->end());

  std::vector<TxOut> outputs{TxOut{bond_amount, reg_spk}, TxOut{0, req_spk}};
  const std::uint64_t change = in_sum - bond_amount - fee;
  if (change > 0) outputs.push_back(TxOut{change, address::p2pkh_script_pubkey(sender_pkh)});

  return build_signed_p2pkh_tx_multi_input(selected, Bytes(validator0.private_key.begin(), validator0.private_key.end()),
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

  return build_signed_p2pkh_tx_multi_input(selected, Bytes(sender.private_key.begin(), sender.private_key.end()), outputs);
}

struct FundedTestWallet {
  std::size_t key_index{0};
  std::vector<std::pair<OutPoint, TxOut>> utxos;
};

struct Cluster;
bool append_live_certified_ingress_to_nodes(const std::string& db_path, const std::vector<node::Node*>& nodes,
                                            const std::vector<Bytes>& raw_records, int peer_id,
                                            std::string* error, const crypto::KeyPair* signer_override);

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

QuorumCertificate make_test_qc(const std::vector<crypto::KeyPair>& keys, const std::vector<PubKey32>& committee,
                               std::uint64_t height, std::uint32_t round, const Hash32& block_id,
                               std::size_t signer_count) {
  QuorumCertificate qc;
  qc.height = height;
  qc.round = round;
  qc.block_id = block_id;
  const auto msg = vote_signing_message(height, round, block_id);
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

Hash32 frontier_lock_payload_id_for_test(const FrontierTransition& transition) {
  codec::ByteWriter w;
  w.bytes(Bytes{'S', 'C', '-', 'F', 'R', 'O', 'N', 'T', 'I', 'E', 'R', '-', 'L', 'O', 'C', 'K', '-', 'P', 'A', 'Y',
                'L', 'O', 'A', 'D', '-', 'V', '1'});
  w.bytes_fixed(transition.prev_finalized_hash);
  w.bytes_fixed(transition.prev_finality_link_hash);
  w.u64le(transition.height);
  w.varbytes(transition.prev_vector.serialize());
  w.varbytes(transition.next_vector.serialize());
  w.bytes_fixed(transition.ingress_commitment);
  w.u64le(transition.prev_frontier);
  w.u64le(transition.next_frontier);
  w.bytes_fixed(transition.prev_state_root);
  w.bytes_fixed(transition.next_state_root);
  w.bytes_fixed(transition.ordered_slice_commitment);
  w.bytes_fixed(transition.decisions_commitment);
  w.bytes_fixed(transition.settlement_commitment);
  return crypto::sha256d(w.data());
}

p2p::ProposeMsg make_test_frontier_propose_msg(const FrontierProposal& proposal,
                                               const std::optional<QuorumCertificate>& justify_qc = std::nullopt,
                                               const std::optional<TimeoutCertificate>& justify_tc = std::nullopt) {
  p2p::ProposeMsg msg;
  msg.height = proposal.transition.height;
  msg.round = proposal.transition.round;
  msg.prev_finalized_hash = proposal.transition.prev_finalized_hash;
  msg.frontier_proposal_bytes = proposal.serialize();
  msg.justify_qc = justify_qc;
  msg.justify_tc = justify_tc;
  return msg;
}

Vote make_test_vote(const std::vector<crypto::KeyPair>& keys, std::uint64_t height, std::uint32_t round,
                    const Hash32& block_id, const PubKey32& signer_pubkey) {
  Vote vote;
  vote.height = height;
  vote.round = round;
  vote.block_id = block_id;
  vote.validator_pubkey = signer_pubkey;
  const int signer_id = node_for_pub(keys, signer_pubkey);
  if (signer_id < 0) throw std::runtime_error("unknown signer pubkey");
  auto sig = crypto::ed25519_sign(vote_signing_message(height, round, block_id),
                                  keys[static_cast<std::size_t>(signer_id)].private_key);
  if (!sig.has_value()) throw std::runtime_error("failed to sign vote");
  vote.signature = *sig;
  return vote;
}

TimeoutVote make_test_timeout_vote(const std::vector<crypto::KeyPair>& keys, std::uint64_t height, std::uint32_t round,
                                   const PubKey32& signer_pubkey) {
  TimeoutVote vote;
  vote.height = height;
  vote.round = round;
  vote.validator_pubkey = signer_pubkey;
  const int signer_id = node_for_pub(keys, signer_pubkey);
  if (signer_id < 0) throw std::runtime_error("unknown timeout signer pubkey");
  auto sig =
      crypto::ed25519_sign(timeout_vote_signing_message(height, round), keys[static_cast<std::size_t>(signer_id)].private_key);
  if (!sig.has_value()) throw std::runtime_error("failed to sign timeout vote");
  vote.signature = *sig;
  return vote;
}

TimeoutCertificate make_test_timeout_certificate(const std::vector<crypto::KeyPair>& keys,
                                                 const std::vector<PubKey32>& committee, std::uint64_t height,
                                                 std::uint32_t round, std::size_t signer_count) {
  TimeoutCertificate tc;
  tc.height = height;
  tc.round = round;
  const auto msg = timeout_vote_signing_message(height, round);
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

QuorumCertificate make_test_frontier_qc(const std::vector<crypto::KeyPair>& keys, const std::vector<PubKey32>& committee,
                                        const FrontierProposal& proposal, std::size_t signer_count) {
  return make_test_qc(keys, committee, proposal.transition.height, proposal.transition.round, frontier_proposal_id(proposal),
                      signer_count);
}

struct Cluster {
  std::string base;
  std::vector<node::NodeConfig> configs;
  std::vector<std::unique_ptr<node::Node>> nodes;

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
    const auto msg = make_test_frontier_propose_msg(*proposal);
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
    th = std::thread([this]() {
      while (running) {
        sockaddr_in caddr{};
        socklen_t len = sizeof(caddr);
        auto cfd = ::accept(fd, reinterpret_cast<sockaddr*>(&caddr), &len);
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

bool write_mainnet_genesis_file(const std::string& path, std::size_t n_validators);

Cluster make_cluster(const std::string& base, int initial_active = 4, int node_count = 4,
                     std::size_t max_committee = MAX_COMMITTEE) {
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
  c.configs.reserve(node_count);
  c.nodes.reserve(node_count);
  for (int i = 0; i < node_count; ++i) {
    node::NodeConfig cfg;
    cfg.disable_p2p = true;
    cfg.node_id = i;
    cfg.max_committee = max_committee;
    cfg.network.min_block_interval_ms = 100;
    cfg.network.round_timeout_ms = 200;
    cfg.p2p_port = static_cast<std::uint16_t>(19040 + i);
    cfg.db_path = base + "/node" + std::to_string(i);
    cfg.genesis_path = gpath;
    cfg.allow_unsafe_genesis_override = true;
    cfg.validator_key_file = cfg.db_path + "/keystore/validator.json";
    cfg.validator_passphrase = "test-pass";
    for (int j = 0; j < i; ++j) {
      cfg.peers.push_back("127.0.0.1:" + std::to_string(19040 + j));
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
  c.configs.reserve(node_count);
  c.nodes.reserve(node_count);
  for (int i = 0; i < node_count; ++i) {
    node::NodeConfig cfg;
    cfg.disable_p2p = true;
    cfg.node_id = i;
    cfg.max_committee = max_committee;
    cfg.network.min_block_interval_ms = min_block_interval_ms;
    cfg.network.round_timeout_ms = round_timeout_ms;
    cfg.p2p_port = static_cast<std::uint16_t>(19040 + i);
    cfg.db_path = base + "/node" + std::to_string(i);
    cfg.genesis_path = gpath;
    cfg.allow_unsafe_genesis_override = true;
    cfg.validator_key_file = cfg.db_path + "/keystore/validator.json";
    cfg.validator_passphrase = "test-pass";
    for (int j = 0; j < i; ++j) {
      cfg.peers.push_back("127.0.0.1:" + std::to_string(19040 + j));
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
      cfg.disable_p2p = false;
      cfg.listen = true;
      cfg.bind_ip = "127.0.0.1";
      cfg.node_id = i;
      cfg.max_committee = max_committee;
      cfg.network.min_block_interval_ms = 100;
      cfg.network.round_timeout_ms = 200;
      const std::size_t offset = port_seed + static_cast<std::size_t>(i) * 257u + static_cast<std::size_t>(attempt) * 17u;
      cfg.p2p_port = static_cast<std::uint16_t>(22000u + (offset % 20000u));
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

std::uint64_t live_registration_bond_amount_for_test(node::Node& node) {
  const auto height = node.status().height + 1;
  const auto active = std::max<std::size_t>(1, node.active_validators_for_next_height_for_test().size());
  return consensus::validator_min_bond_units(mainnet_network(), height, active);
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

bool append_live_certified_ingress_to_nodes(const std::string& db_path, const std::vector<node::Node*>& nodes,
                                            const std::vector<Bytes>& raw_records, int peer_id = 7,
                                            std::string* error = nullptr,
                                            const crypto::KeyPair* signer_override = nullptr) {
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

    auto rec = make_signed_ingress_record_msg(raw, 1, seq, prev_root, signer_override);
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
                   ingress_error;
        }
        return false;
      }
    }
  }
  return true;
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

bool restart_cluster_with_seeded_certified_ingress(Cluster* cluster, const std::vector<Bytes>& raw_records,
                                                   bool start_nodes = true, bool pause_nodes = false) {
  if (!cluster) return false;
  for (auto& n : cluster->nodes) {
    if (n) n->stop();
  }
  cluster->nodes.clear();

  for (const auto& cfg : cluster->configs) {
    std::error_code ec;
    std::filesystem::remove_all(cfg.db_path, ec);
    {
      node::Node seed(cfg);
      if (!seed.init()) return false;
      seed.stop();
    }
    storage::DB db;
    if (!db.open(cfg.db_path)) return false;
    if (!persist_certified_ingress_fixture(cfg, db, raw_records)) return false;
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
    th = std::thread([this]() { run(); });
    return true;
  }

  void stop() {
    running = false;
    if (finalis::net::valid_socket(fd)) {
      finalis::net::shutdown_socket(fd);
      finalis::net::close_socket(fd);
      fd = finalis::net::kInvalidSocket;
    }
    std::vector<finalis::net::SocketHandle> clients;
    {
      std::lock_guard<std::mutex> lk(client_mu);
      clients.assign(client_fds.begin(), client_fds.end());
    }
    for (auto cfd : clients) {
      finalis::net::shutdown_socket(cfd);
      finalis::net::close_socket(cfd);
    }
    if (th.joinable()) th.join();
  }

  std::vector<Hash32> requested_hashes_snapshot() const {
    std::lock_guard<std::mutex> lk(mu);
    return requested_hashes;
  }

  void run() {
    while (running) {
      sockaddr_in caddr{};
      socklen_t len = sizeof(caddr);
      const auto cfd = ::accept(fd, reinterpret_cast<sockaddr*>(&caddr), &len);
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

      finalis::net::shutdown_socket(cfd);
      finalis::net::close_socket(cfd);
      {
        std::lock_guard<std::mutex> lk(client_mu);
        client_fds.erase(cfd);
      }
    }
  }
};

bool write_mainnet_genesis_file(const std::string& path, std::size_t n_validators = 4) {
  const auto keys = node::Node::deterministic_test_keypairs();
  if (keys.size() < n_validators) return false;

  genesis::Document d;
  d.version = 1;
  d.network_name = "mainnet";
  d.protocol_version = mainnet_network().protocol_version;
  d.network_id = mainnet_network().network_id;
  d.magic = mainnet_network().magic;
  d.genesis_time_unix = 1735689600ULL;
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
  out << genesis::to_json(d);
  return out.good();
}

bool write_empty_mainnet_bootstrap_genesis_file(const std::string& path) {
  genesis::Document d;
  d.version = 1;
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
  fixture.cluster.configs.reserve(2);
  fixture.cluster.nodes.reserve(2);
  fixture.leader_kp = node::Node::deterministic_test_keypairs()[0];
  fixture.joiner_kp = key_from_byte(joiner_seed_byte);
  for (int i = 0; i < 2; ++i) {
    node::NodeConfig cfg;
    cfg.disable_p2p = true;
    cfg.node_id = i;
    cfg.max_committee = 3;
    cfg.network.min_block_interval_ms = 100;
    cfg.network.round_timeout_ms = 200;
    cfg.p2p_port = static_cast<std::uint16_t>(19040 + i);
    cfg.db_path = base + "/node" + std::to_string(i);
    cfg.genesis_path = gpath;
    cfg.allow_unsafe_genesis_override = true;
    cfg.validator_key_file = cfg.db_path + "/keystore/validator.json";
    cfg.validator_passphrase = "test-pass";
    cfg.validator_warmup_blocks_override = 1;
    for (int j = 0; j < i; ++j) {
      cfg.peers.push_back("127.0.0.1:" + std::to_string(19040 + j));
    }
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
  if (!wait_for([&]() {
        bond_amount = live_registration_bond_amount_for_test(*nodes[0]);
        funded = find_funded_test_wallet(*nodes[0], keys, bond_amount, 1);
        return funded.has_value();
      }, std::chrono::seconds(240))) {
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
  auto request_tx = build_validator_join_request_tx(
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
        make_test_vote(keys, proposal->transition.height, proposal->transition.round, frontier_proposal_id(*proposal), member);
    const auto vote_result = nodes[0]->inject_network_vote_diagnostic_for_test(vote);
    if (vote_result != "accepted") {
      if (vote_result == "soft-reject:stale-finalized-height") break;
      throw std::runtime_error("bonded fixture failed to inject live join vote: " + vote_result);
    }
  }

  if (!wait_for([&]() {
        auto artifact = find_frontier_artifact_with_tx(fixture.cluster.configs[0].db_path, request_tx->txid(),
                                                       nodes[0]->status().height);
        return artifact.has_value();
      }, std::chrono::seconds(60))) {
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
      }, std::chrono::seconds(60))) {
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
  fixture.cluster.configs.reserve(2);
  fixture.cluster.nodes.reserve(2);
  fixture.leader_kp = node::Node::deterministic_test_keypairs()[0];
  fixture.joiner_kp = key_from_byte(joiner_seed_byte);
  const auto default_keys = node::Node::deterministic_test_keypairs();
  for (int i = 0; i < 2; ++i) {
    node::NodeConfig cfg;
    cfg.disable_p2p = true;
    cfg.node_id = i;
    cfg.max_committee = 2;
    cfg.network.min_block_interval_ms = 100;
    cfg.network.round_timeout_ms = 200;
    cfg.p2p_port = static_cast<std::uint16_t>(19140 + i);
    cfg.db_path = base + "/node" + std::to_string(i);
    cfg.genesis_path = gpath;
    cfg.allow_unsafe_genesis_override = true;
    cfg.validator_key_file = cfg.db_path + "/keystore/validator.json";
    cfg.validator_passphrase = "test-pass";
    cfg.validator_warmup_blocks_override = 1;
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
        bond_amount = live_registration_bond_amount_for_test(*nodes[0]);
        funded = find_funded_test_wallet(*nodes[0], default_keys, bond_amount, 1);
        return funded.has_value();
      }, std::chrono::seconds(240))) {
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
  auto request_tx = build_validator_join_request_tx(
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
    const auto vote = make_test_vote(default_keys, proposal->transition.height, proposal->transition.round,
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
      }, std::chrono::seconds(60))) {
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
      }, std::chrono::seconds(120))) {
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
      }, std::chrono::seconds(240))) {
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

  const auto unique = std::to_string(
      std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now().time_since_epoch())
          .count());
  auto cluster = make_cluster("/tmp/finalis_it_faults_" + unique, 4, 4, 4);
  auto& nodes = cluster.nodes;

  const bool reached_height_30 = wait_for([&]() {
    for (const auto& n : nodes) {
      if (n->status().height < 30) return false;
    }
    return true;
  }, std::chrono::seconds(90));
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

  // Equivocation injection for validator 0.
  std::uint64_t min_before = UINT64_MAX;
  for (const auto& n : nodes) min_before = std::min(min_before, n->status().height);

  for (auto& n : nodes) {
    const auto st = n->status();
    Vote va;
    va.height = st.height + 1;
    va.round = 0;
    va.block_id.fill(0xAA);
    va.validator_pubkey = keys[0].public_key;
    auto sa = crypto::ed25519_sign(vote_signing_message(va.height, va.round, va.block_id), keys[0].private_key);
    ASSERT_TRUE(sa.has_value());
    va.signature = *sa;

    Vote vb = va;
    vb.block_id.fill(0xBB);
    auto sb = crypto::ed25519_sign(vote_signing_message(vb.height, vb.round, vb.block_id), keys[0].private_key);
    ASSERT_TRUE(sb.has_value());
    vb.signature = *sb;

    (void)n->inject_vote_for_test(va);
    (void)n->inject_vote_for_test(vb);
  }

  const bool advanced_after_equivocation = wait_for([&]() {
    for (const auto& n : nodes) {
      if (n->status().height < min_before + 2) return false;
    }
    return true;
  }, std::chrono::seconds(90));
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
  vc.height = nodes[1]->status().height + 1;
  vc.round = 0;
  vc.block_id.fill(0xCC);
  auto sc = crypto::ed25519_sign(vote_signing_message(vc.height, vc.round, vc.block_id), keys[0].private_key);
  ASSERT_TRUE(sc.has_value());
  vc.signature = *sc;
  ASSERT_TRUE(!nodes[1]->inject_vote_for_test(vc));
}

TEST(test_primary_timeout_falls_back_to_backup_proposer) {
  const auto unique = std::to_string(
      std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now().time_since_epoch())
          .count());
  auto cluster = make_cluster("/tmp/finalis_it_backup_proposer_" + unique, 4, 4, 4);
  auto& nodes = cluster.nodes;

  const bool reached_height_20 = wait_for([&]() {
    for (const auto& n : nodes) {
      if (n->status().height < 20) return false;
    }
    return true;
  }, std::chrono::seconds(90));
  if (!reached_height_20) {
    std::ostringstream oss;
    oss << "cluster failed to reach height 20:";
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

  ASSERT_TRUE(wait_for([&]() {
    std::uint64_t min_h = UINT64_MAX;
    for (const auto& n : nodes) min_h = std::min(min_h, n->status().height);
    return min_h > before_pause_h;
  }, std::chrono::seconds(30)));
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
  }, std::chrono::seconds(120)));

  std::optional<FundedTestWallet> funded;
  ASSERT_TRUE(wait_for([&]() {
    funded = find_funded_test_wallet(*nodes[0], keys, 2001);
    return funded.has_value();
  }, std::chrono::seconds(30)));
  ASSERT_TRUE(!funded->utxos.empty());
  const auto sender_index = funded->key_index;
  const auto [spend_op, spend_out] = funded->utxos.front();

  const auto recipient_index = (sender_index + 1) % keys.size();
  const auto recipient_pkh = crypto::h160(Bytes(keys[recipient_index].public_key.begin(), keys[recipient_index].public_key.end()));
  const std::uint64_t fee = 1000;
  const std::uint64_t amount = spend_out.value - fee;
  std::vector<TxOut> outputs{TxOut{amount, address::p2pkh_script_pubkey(recipient_pkh)}};

  std::string err;
  auto tx = build_signed_p2pkh_tx_single_input(spend_op, spend_out, keys[sender_index].private_key, outputs, &err);
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
  }, std::chrono::seconds(60)));
  ASSERT_TRUE(wait_for([&]() {
    for (const auto& n : nodes) {
      if (n->status().height <= height_before) return false;
    }
    return true;
  }, std::chrono::seconds(60)));
}

TEST(test_epoch_ticket_challenge_anchor_ignores_pending_mempool_state) {
  const auto keys = node::Node::deterministic_test_keypairs();
  auto cluster = make_cluster(unique_test_base("/tmp/finalis_it_ticket_anchor_finalized_only"), 1, 1, 1);
  auto& node = cluster.nodes[0];

  ASSERT_TRUE(wait_for([&]() { return node->status().height >= 34; }, std::chrono::seconds(60)));
  ASSERT_TRUE(node->pause_proposals_for_test(true));

  const std::uint64_t target_height = node->status().height + 1;
  const auto anchor_before = node->epoch_ticket_challenge_anchor_for_test(target_height);

  std::optional<FundedTestWallet> funded;
  ASSERT_TRUE(wait_for([&]() {
    funded = find_funded_test_wallet(*node, keys, 2001);
    return funded.has_value();
  }, std::chrono::seconds(30)));
  ASSERT_TRUE(!funded->utxos.empty());
  const auto sender_index = funded->key_index;
  const auto [spend_op, spend_out] = funded->utxos.front();

  const auto recipient_index = (sender_index + 1) % keys.size();
  const auto recipient_pkh = crypto::h160(Bytes(keys[recipient_index].public_key.begin(), keys[recipient_index].public_key.end()));
  std::string err;
  auto tx = build_signed_p2pkh_tx_single_input(
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
  {
    auto cluster = make_cluster(base, 4, 4, MAX_COMMITTEE);
    auto& nodes = cluster.nodes;

    const bool node0_reached_12 = wait_for_tip(*nodes[0], 12, std::chrono::seconds(120));
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
            auto msg = make_test_frontier_propose_msg(*proposal);
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
    }, std::chrono::seconds(120));
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
            auto msg = make_test_frontier_propose_msg(*proposal);
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
    const auto s0 = nodes[0]->status();
    const auto next_committee_before_restart = nodes[0]->committee_for_next_height_for_test();
    for (size_t i = 1; i < nodes.size(); ++i) {
      const auto si = nodes[i]->status();
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
  restarted.nodes.reserve(4);
  for (int i = 0; i < 4; ++i) {
    node::NodeConfig cfg;
    cfg.disable_p2p = true;
    cfg.node_id = i;
    cfg.max_committee = MAX_COMMITTEE;
    cfg.network.min_block_interval_ms = 100;
    cfg.network.round_timeout_ms = 200;
    cfg.p2p_port = static_cast<std::uint16_t>(19040 + i);
    cfg.db_path = base + "/node" + std::to_string(i);
    cfg.genesis_path = base + "/genesis.json";
    cfg.allow_unsafe_genesis_override = true;
    cfg.validator_key_file = cfg.db_path + "/keystore/validator.json";
    cfg.validator_passphrase = "test-pass";
    for (int j = 0; j < i; ++j) {
      cfg.peers.push_back("127.0.0.1:" + std::to_string(19040 + j));
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
  }, std::chrono::seconds(180)));
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
    auto split_tx = build_signed_p2pkh_tx_single_input(
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
    ASSERT_TRUE(wait_for([&]() { return n->status().height > split_height_before; }, std::chrono::seconds(60)));
    ASSERT_TRUE(wait_for([&]() {
      TxOut out0;
      TxOut out1;
      return n->has_utxo_for_test(OutPoint{split_txid, 0}, &out0) && out0.value == first_half &&
             n->has_utxo_for_test(OutPoint{split_txid, 1}, &out1) && out1.value == second_half;
    }, std::chrono::seconds(60)));
    ASSERT_TRUE(wait_for([&]() {
      funded = find_funded_test_wallet(*n, keys, consensus::BASE_UNITS_PER_COIN + DEFAULT_WALLET_SEND_FEE_UNITS, 2);
      return funded.has_value();
    }, std::chrono::seconds(60)));
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

  auto tx = build_signed_p2pkh_tx_multi_input(plan->selected_prevs,
                                              Bytes(keys[sender_index].private_key.begin(), keys[sender_index].private_key.end()),
                                              plan->outputs, &err);
  ASSERT_TRUE(tx.has_value());
  const Hash32 txid = tx->txid();
  const auto height_before = n->status().height;

  std::string ingress_error;
  if (!append_live_certified_ingress_to_cluster(cluster, {tx->serialize()}, 7, &ingress_error)) {
    throw std::runtime_error("append_live_certified_ingress_to_cluster send failed: " + ingress_error);
  }
  ASSERT_TRUE(wait_for([&]() { return n->status().height > height_before; }, std::chrono::seconds(30)));

  OutPoint recipient_op{txid, 0};
  ASSERT_TRUE(wait_for([&]() {
    TxOut out;
    return n->has_utxo_for_test(recipient_op, &out) && out.value == amount;
  }, std::chrono::seconds(60)));
}

TEST(test_single_validator_restart_recovers_missing_required_epoch_committee_state) {
  const std::string base = unique_test_base("/tmp/finalis_it_restart_missing_required_epoch");
  std::uint64_t before_height = 0;
  std::uint64_t required_epoch = 0;

  {
    auto cluster = make_cluster(base, 1, 1, MAX_COMMITTEE);
    auto& node = *cluster.nodes[0];
    ASSERT_TRUE(wait_for_tip(node, 40, std::chrono::seconds(120)));
    ASSERT_TRUE(wait_for([&]() { return !node.committee_for_next_height_for_test().empty(); }, std::chrono::seconds(10)));

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
  cfg.disable_p2p = true;
  cfg.node_id = 0;
  cfg.max_committee = MAX_COMMITTEE;
  cfg.network.min_block_interval_ms = 100;
  cfg.network.round_timeout_ms = 200;
  cfg.p2p_port = 19040;
  cfg.db_path = base + "/node0";
  cfg.genesis_path = base + "/genesis.json";
  cfg.allow_unsafe_genesis_override = true;
  cfg.validator_key_file = cfg.db_path + "/keystore/validator.json";
  cfg.validator_passphrase = "test-pass";

  node::Node restarted(cfg);
  ASSERT_TRUE(restarted.init());
  ASSERT_TRUE(!restarted.committee_for_next_height_for_test().empty());
  restarted.start();

  ASSERT_TRUE(wait_for([&]() { return restarted.status().height >= before_height + 2; }, std::chrono::seconds(30)));
  restarted.stop();
}

TEST(test_single_validator_restart_recovers_empty_required_epoch_committee_snapshot) {
  const std::string base = unique_test_base("/tmp/finalis_it_restart_empty_required_epoch");
  std::uint64_t before_height = 0;
  std::uint64_t required_epoch = 0;

  {
    auto cluster = make_cluster(base, 1, 1, MAX_COMMITTEE);
    auto& node = *cluster.nodes[0];
    ASSERT_TRUE(wait_for_tip(node, 40, std::chrono::seconds(120)));
    ASSERT_TRUE(wait_for([&]() { return !node.committee_for_next_height_for_test().empty(); }, std::chrono::seconds(10)));

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
  cfg.disable_p2p = true;
  cfg.node_id = 0;
  cfg.max_committee = MAX_COMMITTEE;
  cfg.network.min_block_interval_ms = 100;
  cfg.network.round_timeout_ms = 200;
  cfg.p2p_port = 19040;
  cfg.db_path = base + "/node0";
  cfg.genesis_path = base + "/genesis.json";
  cfg.allow_unsafe_genesis_override = true;
  cfg.validator_key_file = cfg.db_path + "/keystore/validator.json";
  cfg.validator_passphrase = "test-pass";

  node::Node restarted(cfg);
  ASSERT_TRUE(restarted.init());
  ASSERT_TRUE(!restarted.committee_for_next_height_for_test().empty());
  restarted.start();

  ASSERT_TRUE(wait_for([&]() { return restarted.status().height >= before_height + 2; }, std::chrono::seconds(30)));
  restarted.stop();
}

TEST(test_follower_startup_repairs_missing_required_epoch_from_peer) {
  const std::string base = unique_test_base("/tmp/finalis_it_required_epoch_repair_from_peer");
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);
  const std::string gpath = base + "/genesis.json";
  ASSERT_TRUE(write_mainnet_genesis_file(gpath, 2));

  node::NodeConfig bootstrap_cfg;
  bootstrap_cfg.node_id = 0;
  bootstrap_cfg.dns_seeds = false;
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
    throw std::runtime_error("bootstrap_init_failed");
  }
  bootstrap.start();

  node::NodeConfig follower_cfg;
  follower_cfg.node_id = 1;
  follower_cfg.dns_seeds = false;
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
    throw std::runtime_error("follower_init_failed");
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
  for (const auto& [key, _] : db.scan_prefix("ET:" + epoch_db_key_suffix(required_epoch) + ":")) {
    ASSERT_TRUE(db.erase(key));
  }
  for (const auto& [key, _] : db.scan_prefix("EB:" + epoch_db_key_suffix(required_epoch) + ":")) {
    ASSERT_TRUE(db.erase(key));
  }
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
  const auto keys = node::Node::deterministic_test_keypairs();
  ASSERT_TRUE(keys.size() >= 2u);
  const std::string base = unique_test_base("/tmp/finalis_it_runtime_repair_reconnect");
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);
  const std::string gpath = base + "/genesis.json";
  ASSERT_TRUE(write_mainnet_genesis_file(gpath, 2));

  node::NodeConfig bootstrap_cfg;
  bootstrap_cfg.node_id = 0;
  bootstrap_cfg.dns_seeds = false;
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
  ASSERT_TRUE(bootstrap.init());
  bootstrap.start();

  node::NodeConfig follower_cfg;
  follower_cfg.node_id = 1;
  follower_cfg.dns_seeds = false;
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
  ASSERT_TRUE(follower.init());
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
          auto msg = make_test_frontier_propose_msg(*proposal);
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
             s0.transition_hash == s1.transition_hash && s1.height == s2.height &&
             s1.transition_hash == s2.transition_hash;
    }, std::chrono::seconds(80)));

    stage = "pause-final-sync";
    for (auto& n : cluster.nodes) ASSERT_TRUE(n->pause_proposals_for_test(true));
    ASSERT_TRUE(wait_for_stable_same_tip(cluster.nodes, std::chrono::seconds(10)));

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

TEST(test_onboarding_registration_tx_finalization_inserts_onboarding_validator) {
  const auto keys = node::Node::deterministic_test_keypairs();
  const auto base = unique_test_base("/tmp/finalis_it_onboarding_registration_tx");
  auto cluster = make_cluster(base, 1, 1, 1);
  auto& n0 = *cluster.nodes[0];
  ASSERT_TRUE(wait_for_tip(n0, 5, std::chrono::seconds(20)));

  std::optional<FundedTestWallet> funded;
  ASSERT_TRUE(wait_for([&]() {
    funded = find_funded_test_wallet(n0, keys, 1000, 1);
    return funded.has_value();
  }, std::chrono::seconds(60)));

  const auto before = n0.status().height;
  const auto new_validator = crypto::keypair_from_seed32(std::array<std::uint8_t, 32>{0x91});
  ASSERT_TRUE(new_validator.has_value());
  const auto& sender = keys[funded->key_index];
  const auto sender_pkh = crypto::h160(Bytes(sender.public_key.begin(), sender.public_key.end()));
  storage::DB db0;
  ASSERT_TRUE(db0.open_readonly(base + "/node0"));
  const auto chain_id = ChainId::from_config_and_db(mainnet_network(), db0);
  ValidatorJoinAdmissionPowBuildContext pow_ctx{
      .network = &mainnet_network(),
      .chain_id = &chain_id,
      .current_height = n0.status().height + 1,
      .finalized_hash_at_height = [&](std::uint64_t height) { return db0.get_height_hash(height); },
  };
  auto tx = build_onboarding_registration_tx(
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
  }, std::chrono::seconds(20)));

  auto info = n0.validator_info_for_test(new_validator->public_key);
  ASSERT_TRUE(info.has_value());
  ASSERT_EQ(info->status, consensus::ValidatorStatus::ONBOARDING);
}

TEST(test_duplicate_onboarding_registration_tx_is_rejected_after_finalization) {
  const auto keys = node::Node::deterministic_test_keypairs();
  const auto base = unique_test_base("/tmp/finalis_it_duplicate_onboarding_registration_tx");
  auto cluster = make_cluster(base, 1, 1, 1);
  auto& n0 = *cluster.nodes[0];
  ASSERT_TRUE(wait_for_tip(n0, 5, std::chrono::seconds(20)));

  std::optional<FundedTestWallet> funded0;
  ASSERT_TRUE(wait_for([&]() {
    funded0 = find_funded_test_wallet(n0, keys, 1000, 1);
    return funded0.has_value();
  }, std::chrono::seconds(60)));

  const auto new_validator = crypto::keypair_from_seed32(std::array<std::uint8_t, 32>{0x92});
  ASSERT_TRUE(new_validator.has_value());
  const auto& sender0 = keys[funded0->key_index];
  const auto sender0_pkh = crypto::h160(Bytes(sender0.public_key.begin(), sender0.public_key.end()));
  storage::DB db0;
  ASSERT_TRUE(db0.open_readonly(base + "/node0"));
  const auto chain_id = ChainId::from_config_and_db(mainnet_network(), db0);
  ValidatorJoinAdmissionPowBuildContext pow_ctx0{
      .network = &mainnet_network(),
      .chain_id = &chain_id,
      .current_height = n0.status().height + 1,
      .finalized_hash_at_height = [&](std::uint64_t height) { return db0.get_height_hash(height); },
  };
  auto tx0 = build_onboarding_registration_tx(
      funded0->utxos, Bytes(sender0.private_key.begin(), sender0.private_key.end()), new_validator->public_key,
      Bytes(new_validator->private_key.begin(), new_validator->private_key.end()), new_validator->public_key, 1000,
      address::p2pkh_script_pubkey(sender0_pkh), nullptr, &pow_ctx0);
  ASSERT_TRUE(tx0.has_value());
  ASSERT_TRUE(n0.inject_tx_for_test(*tx0, true));

  ASSERT_TRUE(wait_for([&]() {
    auto info = n0.validator_info_for_test(new_validator->public_key);
    return info.has_value() && info->status == consensus::ValidatorStatus::ONBOARDING;
  }, std::chrono::seconds(20)));

  std::optional<FundedTestWallet> funded1;
  ASSERT_TRUE(wait_for([&]() {
    funded1 = find_funded_test_wallet(n0, keys, 1000, 1);
    return funded1.has_value();
  }, std::chrono::seconds(60)));

  const auto& sender1 = keys[funded1->key_index];
  const auto sender1_pkh = crypto::h160(Bytes(sender1.public_key.begin(), sender1.public_key.end()));
  ValidatorJoinAdmissionPowBuildContext pow_ctx1{
      .network = &mainnet_network(),
      .chain_id = &chain_id,
      .current_height = n0.status().height + 1,
      .finalized_hash_at_height = [&](std::uint64_t height) { return db0.get_height_hash(height); },
  };
  auto tx1 = build_onboarding_registration_tx(
      funded1->utxos, Bytes(sender1.private_key.begin(), sender1.private_key.end()), new_validator->public_key,
      Bytes(new_validator->private_key.begin(), new_validator->private_key.end()), new_validator->public_key, 1000,
      address::p2pkh_script_pubkey(sender1_pkh), nullptr, &pow_ctx1);
  ASSERT_TRUE(tx1.has_value());
  ASSERT_TRUE(!n0.inject_tx_for_test(*tx1, true));
}

TEST(test_onboarding_live_path_transitions_to_pending_then_active_after_bonded_join) {
  const auto keys = node::Node::deterministic_test_keypairs();
  const auto base = unique_test_base("/tmp/finalis_it_onboarding_to_active_live_path");
  auto cluster = make_cluster(base, 1, 1, 1);
  auto& n0 = *cluster.nodes[0];
  ASSERT_TRUE(wait_for_tip(n0, 5, std::chrono::seconds(20)));
  const std::uint64_t bond_amount = live_registration_bond_amount_for_test(n0);

  std::optional<FundedTestWallet> funded;
  ASSERT_TRUE(wait_for([&]() {
    funded = find_funded_test_wallet(n0, keys, bond_amount + 1000, 1);
    return funded.has_value();
  }, std::chrono::seconds(60)));

  const auto new_validator = crypto::keypair_from_seed32(std::array<std::uint8_t, 32>{0x93});
  ASSERT_TRUE(new_validator.has_value());
  const auto& sender = keys[funded->key_index];
  const auto sender_pkh = crypto::h160(Bytes(sender.public_key.begin(), sender.public_key.end()));

  storage::DB onboarding_db;
  ASSERT_TRUE(onboarding_db.open_readonly(base + "/node0"));
  const auto onboarding_chain_id = ChainId::from_config_and_db(mainnet_network(), onboarding_db);
  ValidatorJoinAdmissionPowBuildContext onboarding_pow_ctx{
      .network = &mainnet_network(),
      .chain_id = &onboarding_chain_id,
      .current_height = n0.status().height + 1,
      .finalized_hash_at_height = [&](std::uint64_t height) { return onboarding_db.get_height_hash(height); },
  };
  auto onboarding_tx = build_onboarding_registration_tx(
      funded->utxos, Bytes(sender.private_key.begin(), sender.private_key.end()), new_validator->public_key,
      Bytes(new_validator->private_key.begin(), new_validator->private_key.end()), new_validator->public_key, 1000,
      address::p2pkh_script_pubkey(sender_pkh), nullptr, &onboarding_pow_ctx);
  ASSERT_TRUE(onboarding_tx.has_value());
  ASSERT_TRUE(n0.inject_tx_for_test(*onboarding_tx, true));

  ASSERT_TRUE(wait_for([&]() {
    auto info = n0.validator_info_for_test(new_validator->public_key);
    return info.has_value() && info->status == consensus::ValidatorStatus::ONBOARDING;
  }, std::chrono::seconds(20)));

  const auto onboarding_info = n0.validator_info_for_test(new_validator->public_key);
  ASSERT_TRUE(onboarding_info.has_value());
  ASSERT_TRUE(!onboarding_info->has_bond);

  std::optional<FundedTestWallet> funded_after_onboarding;
  ASSERT_TRUE(wait_for([&]() {
    funded_after_onboarding = find_funded_test_wallet(n0, keys, bond_amount + 1000, 1);
    return funded_after_onboarding.has_value();
  }, std::chrono::seconds(60)));

  storage::DB join_db;
  ASSERT_TRUE(join_db.open_readonly(base + "/node0"));
  const auto join_chain_id = ChainId::from_config_and_db(mainnet_network(), join_db);
  ValidatorJoinAdmissionPowBuildContext join_pow_ctx{
      .network = &mainnet_network(),
      .chain_id = &join_chain_id,
      .current_height = n0.status().height + 1,
      .finalized_hash_at_height = [&](std::uint64_t height) { return join_db.get_height_hash(height); },
  };
  auto join_tx = build_validator_join_request_tx(
      funded_after_onboarding->utxos, Bytes(sender.private_key.begin(), sender.private_key.end()), new_validator->public_key,
      Bytes(new_validator->private_key.begin(), new_validator->private_key.end()), new_validator->public_key, bond_amount, 1000,
      address::p2pkh_script_pubkey(sender_pkh), nullptr, &join_pow_ctx);
  ASSERT_TRUE(join_tx.has_value());
  ASSERT_TRUE(n0.inject_tx_for_test(*join_tx, true));

  ASSERT_TRUE(wait_for([&]() {
    auto info = n0.validator_info_for_test(new_validator->public_key);
    return info.has_value() && info->status == consensus::ValidatorStatus::PENDING && info->has_bond;
  }, std::chrono::seconds(20)));

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
      }, std::chrono::seconds(60))) {
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
      }, std::chrono::seconds(240))) {
    throw std::runtime_error("bonded fixture validator never entered active next-height set:" +
                             summarize_validator_fixture_nodes(nodes, fixture.joiner_kp.public_key, std::nullopt,
                                                               &cluster.configs));
  }

  const auto before = nodes[0]->validator_info_for_test(fixture.joiner_kp.public_key);
  ASSERT_TRUE(before.has_value());
  ASSERT_TRUE(before->has_bond);
  const auto before_height = nodes[0]->status().height;

  std::string err;
  auto unbond_tx = build_unbond_tx(before->bond_outpoint, fixture.joiner_kp.public_key, before->bonded_amount, 1000,
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
  }, std::chrono::seconds(120));
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
  ASSERT_TRUE(wait_for([&]() { return nodes[0]->status().height >= 6; }, std::chrono::seconds(30)));

  const auto slash_pub = keys[0].public_key;
  const std::uint64_t bond_amount = live_registration_bond_amount_for_test(*nodes[0]);
  Hash32 bond_txid{};
  bond_txid.fill(0xA5);
  const OutPoint bond_op{bond_txid, 0};
  ASSERT_TRUE(nodes[0]->seed_bonded_validator_for_test(slash_pub, bond_op, bond_amount));

  for (auto& n : nodes) n->pause_proposals_for_test(true);
  ASSERT_TRUE(wait_for_stable_same_tip(nodes, std::chrono::seconds(30)));

  auto info0 = nodes[0]->validator_info_for_test(slash_pub);
  ASSERT_TRUE(info0.has_value());
  ASSERT_TRUE(info0->has_bond);

  Vote a;
  a.height = nodes[0]->status().height + 1;
  a.round = 0;
  a.block_id.fill(0x31);
  a.validator_pubkey = slash_pub;
  auto sa = crypto::ed25519_sign(vote_signing_message(a.height, a.round, a.block_id), keys[0].private_key);
  ASSERT_TRUE(sa.has_value());
  a.signature = *sa;

  Vote b = a;
  b.block_id.fill(0x41);
  auto sb = crypto::ed25519_sign(vote_signing_message(b.height, b.round, b.block_id), keys[0].private_key);
  ASSERT_TRUE(sb.has_value());
  b.signature = *sb;

  auto slash_tx = build_slash_tx(bond_op, info0->bonded_amount, a, b);
  ASSERT_TRUE(slash_tx.has_value());
  append_live_certified_tx_or_throw(cluster, *slash_tx, "append slash tx failed");
  const Hash32 slash_txid = slash_tx->txid();
  for (auto& n : nodes) n->pause_proposals_for_test(false);

  ASSERT_TRUE(wait_for([&]() {
    for (const auto& n : nodes) {
      auto info = n->validator_info_for_test(slash_pub);
      if (!info.has_value()) return false;
      if (info->status != consensus::ValidatorStatus::BANNED) return false;
      if (info->has_bond) return false;
      auto active = n->active_validators_for_next_height_for_test();
      if (std::find(active.begin(), active.end(), slash_pub) != active.end()) return false;
      auto artifact = find_frontier_artifact_with_tx(cluster.configs[0].db_path, slash_txid, n->status().height);
      if (!artifact.has_value()) return false;
    }
    return true;
  }, std::chrono::seconds(60)));
}

TEST(test_banned_validator_cannot_reenter_through_onboarding_registration_tx) {
  auto cluster = make_cluster(unique_test_base("/tmp/finalis_it_banned_onboarding_reentry"), 1, 1, 1);
  auto& n0 = *cluster.nodes[0];
  const auto keys = node::Node::deterministic_test_keypairs();
  ASSERT_TRUE(wait_for([&]() { return n0.status().height >= 6; }, std::chrono::seconds(30)));

  std::optional<FundedTestWallet> funded;
  ASSERT_TRUE(wait_for([&]() {
    funded = find_funded_test_wallet(n0, keys, 1000, 1);
    return funded.has_value();
  }, std::chrono::seconds(60)));

  const auto banned_pub = keys[0].public_key;
  const std::uint64_t bond_amount = live_registration_bond_amount_for_test(n0);
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
  auto sa = crypto::ed25519_sign(vote_signing_message(a.height, a.round, a.block_id), keys[0].private_key);
  ASSERT_TRUE(sa.has_value());
  a.signature = *sa;

  Vote b = a;
  b.block_id.fill(0x61);
  auto sb = crypto::ed25519_sign(vote_signing_message(b.height, b.round, b.block_id), keys[0].private_key);
  ASSERT_TRUE(sb.has_value());
  b.signature = *sb;

  auto slash_tx = build_slash_tx(bond_op, info0->bonded_amount, a, b);
  ASSERT_TRUE(slash_tx.has_value());
  append_live_certified_tx_or_throw(cluster, *slash_tx, "append slash tx failed");
  n0.pause_proposals_for_test(false);

  ASSERT_TRUE(wait_for([&]() {
    auto info = n0.validator_info_for_test(banned_pub);
    return info.has_value() && info->status == consensus::ValidatorStatus::BANNED && !info->has_bond;
  }, std::chrono::seconds(60)));

  const auto& sender = keys[funded->key_index];
  const auto sender_pkh = crypto::h160(Bytes(sender.public_key.begin(), sender.public_key.end()));
  storage::DB db;
  ASSERT_TRUE(db.open_readonly(cluster.base + "/node0"));
  const auto chain_id = ChainId::from_config_and_db(mainnet_network(), db);
  ValidatorJoinAdmissionPowBuildContext pow_ctx{
      .network = &mainnet_network(),
      .chain_id = &chain_id,
      .current_height = n0.status().height + 1,
      .finalized_hash_at_height = [&](std::uint64_t height) { return db.get_height_hash(height); },
  };
  auto onboarding_tx = build_onboarding_registration_tx(
      funded->utxos, Bytes(sender.private_key.begin(), sender.private_key.end()), banned_pub,
      Bytes(keys[0].private_key.begin(), keys[0].private_key.end()), banned_pub, 1000,
      address::p2pkh_script_pubkey(sender_pkh), nullptr, &pow_ctx);
  ASSERT_TRUE(onboarding_tx.has_value());
  ASSERT_TRUE(!n0.inject_tx_for_test(*onboarding_tx, true));

  const auto before_height = n0.status().height;
  ASSERT_TRUE(wait_for_tip(n0, before_height + 1, std::chrono::seconds(20)));
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

  ASSERT_TRUE(wait_for([&]() {
    for (const auto& n : nodes) {
      if (n->status().height < 10) return false;
    }
    return true;
  }, ci_timeout_seconds(120)));
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
      crypto::ed25519_sign(vote_signing_message(bad_vote.height, bad_vote.round, bad_vote.block_id), keys[non_member_id].private_key);
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
  join_cfg.node_id = 7;
  join_cfg.db_path = base + "/joiner";
  join_cfg.disable_p2p = false;
  join_cfg.listen = true;
  join_cfg.bind_ip = "127.0.0.1";
  join_cfg.dns_seeds = false;
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
  if (!joiner->init()) return;
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
  if (!s1.start()) return;
  const std::uint16_t p1 = s1.bound_port();
  ASSERT_TRUE(p1 != 0);

  lightserver::Config l2 = l1;
  l2.port = 0;  // ephemeral
  lightserver::Server s2(l2);
  ASSERT_TRUE(s2.init());
  if (!s2.start()) {
    s1.stop();
    return;
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
  const std::string base = unique_test_base("/tmp/finalis_it_hardening_invalid_frame");
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);

  node::NodeConfig cfg;
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
  const std::string base = unique_test_base("/tmp/finalis_it_seed_http_preflight");
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);

  HttpStubServer http;
  if (!http.start()) return;

  node::NodeConfig cfg;
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
  const std::string base = unique_test_base("/tmp/finalis_it_hardening_threshold");
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);

  node::NodeConfig cfg;
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
  ASSERT_TRUE(!connect_and_check_closed("127.0.0.1", port, std::chrono::milliseconds(200)));

  ASSERT_TRUE(send_invalid_frame("127.0.0.1", port, cfg.network.magic));
  ASSERT_TRUE(wait_for([&]() { return connect_and_check_closed("127.0.0.1", port, std::chrono::milliseconds(150)); },
                       std::chrono::seconds(3)));
  n.stop();
}

TEST(test_epoch_reward_settlement_matches_closed_epoch_rewards) {
  const auto base = unique_test_base("/tmp/finalis_it_epoch_reward_settlement");
  auto cluster = make_cluster(base, 1, 1, 1);
  auto& n = cluster.nodes[0];
  ASSERT_TRUE(wait_for([&]() { return n->status().height >= 33; }, std::chrono::seconds(60)));

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
}

TEST(test_epoch_reward_settlement_restart_is_deterministic) {
  const std::string base = unique_test_base("/tmp/finalis_it_epoch_reward_restart");
  {
    auto cluster = make_cluster(base, 1, 1, 1);
    ASSERT_TRUE(wait_for([&]() { return cluster.nodes[0]->status().height >= 20; }, std::chrono::seconds(30)));
    cluster.nodes[0]->stop();
  }

  node::NodeConfig cfg;
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
  ASSERT_TRUE(wait_for([&]() { return restarted.status().height >= 33; }, std::chrono::seconds(60)));
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
        wait_for([&]() { return cluster.nodes[0]->status().height >= 225; }, ci_timeout_seconds(180));
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
  const std::string direct_base = "/tmp/finalis_it_reward_direct_path";
  const std::string quorum_base = "/tmp/finalis_it_reward_quorum_path";
  Tx tx = make_fixture_ingress_tx(1, 0x90);

  node::NodeConfig direct_cfg;
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
  auto sig = crypto::ed25519_sign(vote_signing_message(target_height, round, frontier_proposal_id(*proposal)),
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
  auto quorum_msg = make_test_frontier_propose_msg(*quorum_proposal);
  ASSERT_TRUE(quorum_node->inject_propose_msg_for_test(quorum_msg));
  auto quorum_vote =
      make_test_vote(keys, quorum_target_height, quorum_round, frontier_proposal_id(*quorum_proposal), keys[0].public_key);
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
  const std::string base = "/tmp/finalis_it_min_block_interval_after_finalize";

  node::NodeConfig cfg;
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

TEST(test_settled_rewards_are_visible_in_wallet_script_index) {
  const std::string base = "/tmp/finalis_it_wallet_script_index_rewards";

  node::NodeConfig cfg;
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
  ASSERT_TRUE(wait_for([&]() { return node->status().height >= 33; }, std::chrono::seconds(60)));
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

  const auto utxos = db.load_utxos();
  std::uint64_t direct_balance = 0;
  for (const auto& [_, entry] : utxos) {
    std::array<std::uint8_t, 20> got{};
    if (!is_p2pkh_script_pubkey(entry.out.script_pubkey, &got)) continue;
    if (got != own_pkh) continue;
    direct_balance += entry.out.value;
  }
  ASSERT_TRUE(direct_balance > 0);
}

TEST(test_finalized_frontier_txs_are_indexed_for_explorer_queries) {
  const std::string base = "/tmp/finalis_it_frontier_tx_indexing";
  Tx tx = make_fixture_ingress_tx(1, 0xA7);

  node::NodeConfig cfg;
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

  storage::DB db;
  ASSERT_TRUE(db.open(cfg.db_path));
  const auto loc = db.get_tx_index(tx.txid());
  ASSERT_TRUE(loc.has_value());
  ASSERT_EQ(loc->height, 1u);
  const auto sh = crypto::sha256(tx.outputs[0].script_pubkey);
  const auto history = db.get_script_history(sh);
  ASSERT_TRUE(!history.empty());
  ASSERT_EQ(history[0].txid, tx.txid());
  ASSERT_EQ(history[0].height, 1u);
}

TEST(test_locally_relayed_wallet_tx_enters_certified_ingress_and_finalizes) {
  const std::string base = "/tmp/finalis_it_local_wallet_tx_finalizes";

  node::NodeConfig cfg;
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
  ASSERT_TRUE(wait_for([&]() { return node->status().height >= 33; }, std::chrono::seconds(60)));

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
  auto tx = build_signed_p2pkh_tx_single_input(prev.first, prev.second, Bytes(key.privkey.begin(), key.privkey.end()), outputs,
                                               &build_err);
  ASSERT_TRUE(tx.has_value());
  ASSERT_TRUE(node->inject_tx_for_test(*tx, true));

  ASSERT_TRUE(wait_for([&]() {
    if (node->status().height < 34) return false;
    storage::DB probe_db;
    if (!probe_db.open_readonly(cfg.db_path)) return false;
    if (!probe_db.get_tx_index(tx->txid()).has_value()) return false;
    return !node->find_utxos_by_pubkey_hash_for_test(recipient_pkh).empty();
  }, std::chrono::seconds(20)));

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

TEST(test_tx_status_reports_certified_ingress_before_finalization) {
  const std::string base = "/tmp/finalis_it_tx_status_certified_ingress";

  node::NodeConfig cfg;
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
  ASSERT_TRUE(wait_for([&]() { return node->status().height >= 33; }, std::chrono::seconds(60)));
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
  auto tx = build_signed_p2pkh_tx_single_input(prev.first, prev.second, Bytes(key.privkey.begin(), key.privkey.end()), outputs,
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
  const std::string base = "/tmp/finalis_it_next_height_schedule_uses_canonical";

  node::NodeConfig cfg;
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
  const std::string base = "/tmp/finalis_it_frontier_build_repairs_runtime_cursor";
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
  }, std::chrono::seconds(90)));
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
  auto tx = build_signed_p2pkh_tx_single_input(prev.first, prev.second, Bytes(kp.private_key.begin(), kp.private_key.end()),
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
  }, std::chrono::seconds(120)));

  constexpr std::uint64_t kAmount = 10'000'000'000ULL;
  constexpr std::uint64_t kFee = 10'000ULL;

  const auto keys = node::Node::deterministic_test_keypairs();
  std::optional<FundedTestWallet> funded;
  ASSERT_TRUE(wait_for([&]() {
    funded = find_funded_test_wallet(leader, keys, kAmount + kFee, 1);
    if (!funded.has_value() || funded->utxos.empty()) return false;
    return true;
  }, std::chrono::seconds(60)));
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
  auto tx = build_signed_p2pkh_tx_single_input(prev.first, prev.second,
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
  }, std::chrono::seconds(90)));

  const auto follower_utxos = follower.find_utxos_by_pubkey_hash_for_test(recipient_pkh);
  ASSERT_TRUE(!follower_utxos.empty());
  ASSERT_EQ(follower_utxos.front().second.value, kAmount);

  follower.stop();
  leader.stop();

  storage::DB follower_db;
  ASSERT_TRUE(follower_db.open(cluster.configs[1].db_path));
  const auto persisted_utxos = follower_db.load_utxos();
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

TEST(test_restart_repairs_partial_settlement_state) {
  const std::string base = unique_test_base("/tmp/finalis_it_reward_restart_repair");
  {
    auto cluster = make_cluster(base, 1, 1, 1);
    ASSERT_TRUE(wait_for([&]() { return cluster.nodes[0]->status().height >= 33; }, std::chrono::seconds(60)));
    cluster.nodes[0]->stop();
  }

  {
    storage::DB db;
    ASSERT_TRUE(db.open(base + "/node0"));
    ASSERT_TRUE(db.erase("ER:" + epoch_db_key_suffix(1)));
    ASSERT_TRUE(db.flush());
  }

  node::NodeConfig cfg;
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
    finalized_height = cluster.nodes[0]->status().height;
    cluster.nodes[0]->stop();
  }

  {
    storage::DB db;
    ASSERT_TRUE(db.open(base + "/node0"));
    ASSERT_TRUE(db.erase("ER:" + epoch_db_key_suffix(1)));
    ASSERT_TRUE(db.flush());
  }

  node::NodeConfig cfg;
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
  std::uint64_t gross = 0;
  for (std::uint64_t h = 1; h <= finalized_height; ++h) gross += consensus::reward_units(h);
  ASSERT_EQ(state->total_reward_units, gross - ((gross * consensus::RESERVE_ACCRUAL_BPS) / 10'000ULL));
  ASSERT_EQ(state->reserve_accrual_units, (gross * consensus::RESERVE_ACCRUAL_BPS) / 10'000ULL);
}

TEST(test_crash_between_csaf_and_block_write_does_not_corrupt_state) {
  const std::string base = unique_test_base("/tmp/finalis_it_csaf_crash_repair");
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
    ASSERT_TRUE(db.put(csafe_db_key(next_height), Bytes{0x01, 0x02, 0x03}));
    ASSERT_TRUE(db.flush());
  }

  node::NodeConfig cfg;
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
  auto qc = make_test_qc(keys, committee, target_height, round, frontier_proposal_id(*proposal), committee.size());
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
      vote_signing_message(delayed_vote.height, delayed_vote.round, delayed_vote.block_id), signer->private_key);
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
      vote_signing_message(future_vote.height, future_vote.round, future_vote.block_id), signer->private_key);
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
  cfg0.node_id = 0;
  cfg0.db_path = base + "/node0";
  cfg0.bind_ip = "127.0.0.1";
  cfg0.p2p_port = port0;
  cfg0.outbound_target = 0;
  cfg0.dns_seeds = false;
  cfg0.genesis_path = gpath;
  cfg0.allow_unsafe_genesis_override = true;
  cfg0.validator_key_file = cfg0.db_path + "/keystore/validator.json";
  cfg0.validator_passphrase = "test-pass";
  cfg0.network.min_block_interval_ms = 100;
  cfg0.network.round_timeout_ms = 200;
  ASSERT_TRUE(keystore::create_validator_keystore(cfg0.validator_key_file, cfg0.validator_passphrase, "mainnet", "sc",
                                                  deterministic_seed_for_node_id(0), nullptr, nullptr));

  node::NodeConfig cfg1;
  cfg1.node_id = 1;
  cfg1.db_path = base + "/node1";
  cfg1.bind_ip = "127.0.0.1";
  cfg1.listen = false;
  cfg1.p2p_port = 0;
  cfg1.outbound_target = 1;
  cfg1.dns_seeds = false;
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
    out << "212.58.103.170:19440\n";
    out << "85.217.171.168:19440,212.58.103.170:19440\n";
  }

  node::NodeConfig cfg;
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
  ASSERT_EQ(persisted[0], "212.58.103.170:19440");
  ASSERT_EQ(persisted[1], "85.217.171.168:19440");
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
  auto quorum_qc = make_test_qc(keys, committee, target_height, round, frontier_proposal_id(*proposal), quorum);
  auto full_qc = make_test_qc(keys, committee, target_height, round, frontier_proposal_id(*proposal), committee.size());
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

  auto qc_a = make_test_qc(keys, committee, target_height, round, frontier_proposal_id(*proposal), quorum);
  std::vector<PubKey32> rotated_committee = committee;
  std::rotate(rotated_committee.begin(), rotated_committee.begin() + 1, rotated_committee.end());
  auto qc_b = make_test_qc(keys, rotated_committee, target_height, round, frontier_proposal_id(*proposal), quorum);
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
        cfg.node_id = 0;
  cfg.db_path = base + "/node0";
  cfg.p2p_port = 0;
  node::Node n(cfg);
  if (!n.init()) return;
  n.start();
  const std::uint16_t port = n.p2p_port_for_test();
  if (port == 0) {
    n.stop();
    return;
  }

  p2p::VersionMsg v;
  v.proto_version = static_cast<std::uint32_t>(cfg.network.protocol_version);
  v.network_id = cfg.network.network_id;
  v.network_id[0] ^= 0x5A;  // mismatch
  v.feature_flags = cfg.network.feature_flags;
  v.timestamp = static_cast<std::uint64_t>(::time(nullptr));
  v.nonce = 123;
  v.node_software_version = "handshake-test/0.7";
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

TEST(test_skip_exact_self_endpoint_before_dial) {
  const std::string base = unique_test_base("/tmp/finalis_it_skip_exact_self");
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);

  const std::uint16_t port = reserve_test_port();
  ASSERT_TRUE(port != 0);

  node::NodeConfig cfg;
  cfg.node_id = 0;
  cfg.db_path = base + "/node0";
  cfg.bind_ip = "127.0.0.1";
  cfg.p2p_port = port;
  cfg.dns_seeds = false;
  cfg.outbound_target = 1;
  cfg.peers.push_back("127.0.0.1:" + std::to_string(port));

  node::Node n(cfg);
  if (!n.init()) return;
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
  cfg.node_id = 0;
  cfg.db_path = base + "/node0";
  cfg.bind_ip = "127.0.0.1";
  cfg.p2p_port = port;
  cfg.dns_seeds = false;
  cfg.outbound_target = 1;
  cfg.peers.push_back("localhost:" + std::to_string(port));

  node::Node n(cfg);
  if (!n.init()) return;
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
  cfg.node_id = 0;
  cfg.db_path = base + "/node0";
  cfg.bind_ip = "127.0.0.1";
  cfg.p2p_port = 0;
  cfg.dns_seeds = false;

  node::Node n(cfg);
  if (!n.init()) return;
  n.start();
  const std::uint16_t port = n.p2p_port_for_test();
  if (port == 0) {
    n.stop();
    return;
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
      hex_encode(Bytes(local_pub.begin(), local_pub.end()));

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
  cfg.node_id = 0;
  cfg.db_path = base + "/node0";
  cfg.bind_ip = "127.0.0.1";
  cfg.p2p_port = port;
  cfg.dns_seeds = false;
  cfg.outbound_target = 1;
  cfg.peers.push_back("127.0.0.1:" + std::to_string(port));

  node::Node n(cfg);
  if (!n.init()) return;
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
        cfg.node_id = 0;
  cfg.db_path = base + "/node0";
  cfg.p2p_port = 0;
  node::Node n(cfg);
  if (!n.init()) return;
  n.start();
  const std::uint16_t port = n.p2p_port_for_test();
  if (port == 0) {
    n.stop();
    return;
  }

  p2p::VersionMsg v;
  v.proto_version = static_cast<std::uint32_t>(cfg.network.protocol_version);
  v.network_id = cfg.network.network_id;
  v.feature_flags = cfg.network.feature_flags;
  v.timestamp = static_cast<std::uint64_t>(::time(nullptr));
  v.nonce = 444;
  v.node_software_version = "magic-mismatch-test/0.7";
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
        cfg.node_id = 0;
  cfg.db_path = base + "/node0";
  cfg.p2p_port = 0;
  node::Node n(cfg);
  if (!n.init()) return;
  n.start();
  const std::uint16_t port = n.p2p_port_for_test();
  if (port == 0) {
    n.stop();
    return;
  }

  p2p::VersionMsg v;
  v.proto_version = static_cast<std::uint32_t>(cfg.network.protocol_version + 1);  // unsupported
  v.network_id = cfg.network.network_id;
  v.feature_flags = cfg.network.feature_flags;
  v.timestamp = static_cast<std::uint64_t>(::time(nullptr));
  v.nonce = 321;
  v.node_software_version = "handshake-test/0.7";
  ASSERT_TRUE(send_version_and_expect_disconnect("127.0.0.1", port, v, cfg.network, std::chrono::milliseconds(300)));
  ASSERT_TRUE(wait_for([&]() { return n.status().rejected_protocol_version >= 1; }, std::chrono::seconds(2)));
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
  cfg0.node_id = 0;
  cfg0.db_path = base + "/node0";
  cfg0.bind_ip = "127.0.0.1";
  cfg0.p2p_port = port0;
  cfg0.dns_seeds = false;

  node::NodeConfig cfg1;
  cfg1.node_id = 1;
  cfg1.db_path = base + "/node1";
  cfg1.bind_ip = "127.0.0.1";
  cfg1.p2p_port = port1;
  cfg1.dns_seeds = false;
  cfg1.outbound_target = 1;
  cfg1.peers.push_back("127.0.0.1:" + std::to_string(port0));

  node::Node n0(cfg0);
  node::Node n1(cfg1);
  if (!n0.init() || !n1.init()) return;
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
  cfg.node_id = 0;
  cfg.disable_p2p = true;
  cfg.dns_seeds = false;
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
  cfg.node_id = 0;
  cfg.dns_seeds = false;
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
  bootstrap_cfg.node_id = 0;
  bootstrap_cfg.dns_seeds = false;
  bootstrap_cfg.db_path = base + "/bootstrap";
  bootstrap_cfg.p2p_port = reserve_test_port();
  if (bootstrap_cfg.p2p_port == 0) return;
  bootstrap_cfg.genesis_path = gpath;
  bootstrap_cfg.allow_unsafe_genesis_override = true;
  bootstrap_cfg.network.min_block_interval_ms = 100;
  bootstrap_cfg.network.round_timeout_ms = 200;

  node::Node bootstrap(bootstrap_cfg);
  if (!bootstrap.init()) return;
  bootstrap.start();
  ASSERT_TRUE(wait_for_tip(bootstrap, 1, std::chrono::seconds(12)));

  node::NodeConfig follower_cfg;
  follower_cfg.node_id = 1;
  follower_cfg.dns_seeds = false;
  follower_cfg.db_path = base + "/follower";
  follower_cfg.p2p_port = reserve_test_port();
  if (follower_cfg.p2p_port == 0) {
    bootstrap.stop();
    return;
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
  }, std::chrono::seconds(20)));

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
  bootstrap_cfg.node_id = 0;
  bootstrap_cfg.dns_seeds = false;
  bootstrap_cfg.db_path = base + "/bootstrap";
  bootstrap_cfg.p2p_port = reserve_test_port();
  if (bootstrap_cfg.p2p_port == 0) return;
  bootstrap_cfg.genesis_path = gpath;
  bootstrap_cfg.allow_unsafe_genesis_override = true;
  bootstrap_cfg.network.min_block_interval_ms = 100;
  bootstrap_cfg.network.round_timeout_ms = 200;
  bootstrap_cfg.network.min_block_interval_ms = 100;
  bootstrap_cfg.network.round_timeout_ms = 200;
  bootstrap_cfg.outbound_target = 0;

  node::Node bootstrap(bootstrap_cfg);
  if (!bootstrap.init()) return;
  bootstrap.start();
  bootstrap.pause_proposals_for_test(true);
  const auto port0 = bootstrap.p2p_port_for_test();
  if (port0 == 0) {
    bootstrap.stop();
    return;
  }

  node::NodeConfig follower_cfg;
  follower_cfg.node_id = 1;
  follower_cfg.dns_seeds = false;
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
          auto msg = make_test_frontier_propose_msg(*proposal);
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
  bootstrap_cfg.node_id = 0;
  bootstrap_cfg.dns_seeds = false;
  bootstrap_cfg.db_path = base + "/bootstrap";
  bootstrap_cfg.p2p_port = reserve_test_port();
  if (bootstrap_cfg.p2p_port == 0) return;
  bootstrap_cfg.genesis_path = gpath;
  bootstrap_cfg.allow_unsafe_genesis_override = true;

  node::Node bootstrap(bootstrap_cfg);
  if (!bootstrap.init()) return;
  bootstrap.start();
  bootstrap.pause_proposals_for_test(true);
  const auto port0 = bootstrap.p2p_port_for_test();
  if (port0 == 0) {
    bootstrap.stop();
    return;
  }

  node::NodeConfig follower_cfg;
  follower_cfg.node_id = 1;
  follower_cfg.dns_seeds = false;
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
  bootstrap_cfg.node_id = 0;
  bootstrap_cfg.dns_seeds = false;
  bootstrap_cfg.db_path = base + "/bootstrap";
  bootstrap_cfg.p2p_port = reserve_test_port();
  if (bootstrap_cfg.p2p_port == 0) return;
  bootstrap_cfg.genesis_path = gpath;
  bootstrap_cfg.allow_unsafe_genesis_override = true;
  bootstrap_cfg.peers = {"127.0.0.1:1"};
  bootstrap_cfg.network.min_block_interval_ms = 100;
  bootstrap_cfg.network.round_timeout_ms = 200;

  node::Node bootstrap(bootstrap_cfg);
  if (!bootstrap.init()) return;
  bootstrap.start();

  node::NodeConfig follower_cfg;
  follower_cfg.node_id = 1;
  follower_cfg.dns_seeds = false;
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
  cfg0.node_id = 0;
  cfg0.dns_seeds = false;
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
    return;
  }
  ASSERT_TRUE(wait_for_tip(n0, 5, std::chrono::seconds(20)));
  ASSERT_TRUE(wait_for_tip(n0, 1, std::chrono::seconds(12)));

  node::NodeConfig cfg1;
  cfg1.node_id = 1;
  cfg1.dns_seeds = false;
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
  ASSERT_TRUE(!nodes[0]->inject_propose_msg_for_test(make_test_frontier_propose_msg(*future)));
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

  p2p::ProposeMsg msg;
  msg.height = target_height;
  msg.round = future_round;
  msg.prev_finalized_hash = future->transition.prev_finalized_hash;
  msg.frontier_proposal_bytes = future->serialize();

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
  auto sig = crypto::ed25519_sign(vote_signing_message(vote.height, vote.round, vote.block_id),
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
  ASSERT_EQ(target->inject_network_propose_result_for_test(make_test_frontier_propose_msg(*proposal_a)),
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
        make_test_vote(keys, target_height, round0, frontier_proposal_id(*proposal_a), pub));
    ++injected;
    if (injected == quorum) break;
  }

  ASSERT_TRUE(wait_for([&]() { return target->status().height == target_height; }, std::chrono::seconds(5)));
  ASSERT_EQ(target->status().transition_hash, frontier_proposal_id(*proposal_a));
  ASSERT_TRUE(!target->inject_propose_msg_for_test(make_test_frontier_propose_msg(*proposal_b)));
  ASSERT_EQ(target->status().transition_hash, frontier_proposal_id(*proposal_a));
}

TEST(test_qc_cannot_unlock_conflicting_payload) {
  const auto keys = node::Node::deterministic_test_keypairs();
  auto cluster = make_cluster(unique_test_base("/tmp/finalis_it_qc_conflicting_unlock"), 4, 4, 4);
  auto& nodes = cluster.nodes;
  Tx tx_a = make_fixture_ingress_tx(1, 0x8C);
  Tx tx_b = make_fixture_ingress_tx(1, 0x8D);
  ASSERT_TRUE(restart_cluster_with_seeded_certified_ingress(&cluster, {tx_a.serialize()}, true, true));

  auto& target = nodes[0];
  const std::uint64_t target_height = target->status().height + 1;
  const std::uint32_t round0 = 0;
  const auto proposer0 = target->proposer_for_height_round_for_test(target_height, round0);
  ASSERT_TRUE(proposer0.has_value());
  const int proposer0_id = node_for_pub(keys, *proposer0);
  ASSERT_TRUE(proposer0_id >= 0);
  auto proposal_a = build_cluster_frontier_proposal_from_records(
      cluster, keys, {tx_a.serialize()}, target_height, round0, "/tmp/finalis_it_qc_conflicting_unlock_round0_builder");
  ASSERT_TRUE(proposal_a.has_value());
  ASSERT_EQ(target->inject_network_propose_result_for_test(make_test_frontier_propose_msg(*proposal_a)),
            std::string("accepted"));

  const std::uint32_t round1 = 1;
  const auto proposer1 = target->proposer_for_height_round_for_test(target_height, round1);
  ASSERT_TRUE(proposer1.has_value());
  const int proposer1_id = node_for_pub(keys, *proposer1);
  ASSERT_TRUE(proposer1_id >= 0);
  auto proposal_b = build_cluster_frontier_proposal_from_records(
      cluster, keys, {tx_b.serialize()}, target_height, round1, "/tmp/finalis_it_qc_conflicting_unlock_round1_builder");
  ASSERT_TRUE(proposal_b.has_value());
  ASSERT_TRUE(frontier_proposal_id(*proposal_b) != frontier_proposal_id(*proposal_a));
  ASSERT_TRUE(frontier_lock_payload_id_for_test(proposal_b->transition) != frontier_lock_payload_id_for_test(proposal_a->transition));

  const auto committee0 = target->committee_for_height_round_for_test(target_height, round0);
  const auto quorum0 = target->quorum_threshold_for_next_height_for_test();
  auto qc_a = make_test_frontier_qc(keys, committee0, *proposal_a, quorum0);
  ASSERT_TRUE(qc_a.signatures.size() >= quorum0);

  auto msg = make_test_frontier_propose_msg(*proposal_b, qc_a);
  ASSERT_TRUE(!target->inject_propose_msg_for_test(msg));
  ASSERT_EQ(target->status().height + 1, target_height);
}

TEST(test_qc_allows_higher_round_reproposal_of_same_payload) {
  const auto keys = node::Node::deterministic_test_keypairs();
  auto cluster = make_cluster(unique_test_base("/tmp/finalis_it_qc_match_proposal"), 4, 4, 4);
  auto& nodes = cluster.nodes;
  Tx tx = make_fixture_ingress_tx(1, 0x8B);
  ASSERT_TRUE(restart_cluster_with_seeded_certified_ingress(&cluster, {tx.serialize()}, true, true));

  auto& target = nodes[0];
  const std::uint64_t target_height = target->status().height + 1;
  const std::uint32_t round0 = 0;
  const auto proposer0 = target->proposer_for_height_round_for_test(target_height, round0);
  ASSERT_TRUE(proposer0.has_value());
  const int proposer0_id = node_for_pub(keys, *proposer0);
  ASSERT_TRUE(proposer0_id >= 0);
  auto proposal_a = build_cluster_frontier_proposal_from_records(
      cluster, keys, {tx.serialize()}, target_height, round0, "/tmp/finalis_it_qc_match_proposal_round0_builder");
  ASSERT_TRUE(proposal_a.has_value());
  ASSERT_EQ(target->inject_network_propose_result_for_test(make_test_frontier_propose_msg(*proposal_a)),
            std::string("accepted"));

  const std::uint32_t round1 = 1;
  const auto proposer1 = target->proposer_for_height_round_for_test(target_height, round1);
  ASSERT_TRUE(proposer1.has_value());
  const int proposer1_id = node_for_pub(keys, *proposer1);
  ASSERT_TRUE(proposer1_id >= 0);
  auto proposal_b = build_cluster_frontier_proposal_from_records(
      cluster, keys, {tx.serialize()}, target_height, round1, "/tmp/finalis_it_qc_match_proposal_round1_builder");
  ASSERT_TRUE(proposal_b.has_value());
  ASSERT_EQ(frontier_lock_payload_id_for_test(proposal_a->transition), frontier_lock_payload_id_for_test(proposal_b->transition));

  const auto committee0 = target->committee_for_height_round_for_test(target_height, round0);
  const auto quorum0 = target->quorum_threshold_for_next_height_for_test();
  auto qc_a = make_test_frontier_qc(keys, committee0, *proposal_a, quorum0);
  ASSERT_TRUE(qc_a.signatures.size() >= quorum0);

  auto msg = make_test_frontier_propose_msg(*proposal_b, qc_a);
  ASSERT_TRUE(target->inject_propose_msg_for_test(msg));
}

TEST(test_qc_round_must_be_strictly_lower) {
  const auto keys = node::Node::deterministic_test_keypairs();
  auto cluster = make_cluster(unique_test_base("/tmp/finalis_it_qc_round_lower"), 4, 4, 4);
  auto& nodes = cluster.nodes;
  Tx tx = make_fixture_ingress_tx(1, 0x8A);
  ASSERT_TRUE(restart_cluster_with_seeded_certified_ingress(&cluster, {tx.serialize()}, true, true));

  auto& target = nodes[0];
  const std::uint64_t target_height = target->status().height + 1;
  const std::uint32_t round1 = 1;
  const auto proposer1 = target->proposer_for_height_round_for_test(target_height, round1);
  ASSERT_TRUE(proposer1.has_value());
  const int proposer1_id = node_for_pub(keys, *proposer1);
  ASSERT_TRUE(proposer1_id >= 0);
  auto proposal = build_cluster_frontier_proposal_from_records(
      cluster, keys, {tx.serialize()}, target_height, round1, "/tmp/finalis_it_qc_round_lower_round1_builder");
  ASSERT_TRUE(proposal.has_value());

  const auto committee1 = target->committee_for_height_round_for_test(target_height, round1);
  const auto quorum1 = consensus::quorum_threshold(committee1.size());
  auto qc_same_round = make_test_frontier_qc(keys, committee1, *proposal, quorum1);
  ASSERT_TRUE(qc_same_round.signatures.size() >= quorum1);

  auto msg = make_test_frontier_propose_msg(*proposal, qc_same_round);
  ASSERT_TRUE(!target->inject_propose_msg_for_test(msg));
}

TEST(test_timeout_certificate_reproposal_preserves_lock_payload_and_enables_revote) {
  const auto keys = node::Node::deterministic_test_keypairs();
  ASSERT_TRUE(keys.size() >= 4u);
  auto cluster = make_cluster(unique_test_base("/tmp/finalis_it_tc_reproposal_same_payload"), 4, 4, 4);
  auto& nodes = cluster.nodes;
  Tx tx = make_fixture_ingress_tx(1, 0x8D);
  ASSERT_TRUE(restart_cluster_with_seeded_certified_ingress(&cluster, {tx.serialize()}, true, true));

  auto& target = nodes[0];
  const std::uint64_t target_height = target->status().height + 1;
  const std::uint32_t round0 = 0;

  auto proposal_a = build_cluster_frontier_proposal_from_records(
      cluster, keys, {tx.serialize()}, target_height, round0, "/tmp/finalis_it_tc_reproposal_round0_builder");
  ASSERT_TRUE(proposal_a.has_value());
  ASSERT_EQ(target->inject_network_propose_result_for_test(make_test_frontier_propose_msg(*proposal_a)),
            std::string("accepted"));

  const auto committee0 = target->committee_for_height_round_for_test(target_height, round0);
  ASSERT_EQ(committee0.size(), 4u);
  const auto quorum0 = consensus::quorum_threshold(committee0.size());
  ASSERT_TRUE(quorum0 > 0);
  for (std::size_t i = 0; i < quorum0; ++i) {
    ASSERT_TRUE(target->inject_timeout_vote_for_test(make_test_timeout_vote(keys, target_height, round0, committee0[i])));
  }

  ASSERT_TRUE(wait_for([&]() { return target->status().round >= 1; }, std::chrono::seconds(5)));
  const std::uint32_t retry_round = std::max<std::uint32_t>(1, target->status().round);

  auto proposal_b = build_cluster_frontier_proposal_from_records(
      cluster, keys, {tx.serialize()}, target_height, retry_round, "/tmp/finalis_it_tc_reproposal_round1_builder");
  ASSERT_TRUE(proposal_b.has_value());
  ASSERT_EQ(proposal_a->transition.prev_finalized_hash, proposal_b->transition.prev_finalized_hash);
  ASSERT_EQ(proposal_a->transition.prev_finality_link_hash, proposal_b->transition.prev_finality_link_hash);
  ASSERT_EQ(proposal_a->transition.prev_vector, proposal_b->transition.prev_vector);
  ASSERT_EQ(proposal_a->transition.next_vector, proposal_b->transition.next_vector);
  ASSERT_EQ(proposal_a->transition.ingress_commitment, proposal_b->transition.ingress_commitment);
  ASSERT_EQ(proposal_a->transition.prev_frontier, proposal_b->transition.prev_frontier);
  ASSERT_EQ(proposal_a->transition.next_frontier, proposal_b->transition.next_frontier);
  ASSERT_EQ(proposal_a->transition.prev_state_root, proposal_b->transition.prev_state_root);
  ASSERT_EQ(proposal_a->transition.ordered_slice_commitment, proposal_b->transition.ordered_slice_commitment);
  ASSERT_EQ(proposal_a->transition.decisions_commitment, proposal_b->transition.decisions_commitment);
  ASSERT_EQ(proposal_a->transition.settlement.current_fees, proposal_b->transition.settlement.current_fees);
  ASSERT_EQ(proposal_a->transition.settlement.settled_epoch_rewards, proposal_b->transition.settlement.settled_epoch_rewards);
  ASSERT_EQ(proposal_a->transition.settlement.total, proposal_b->transition.settlement.total);
  ASSERT_EQ(proposal_a->transition.settlement.outputs, proposal_b->transition.settlement.outputs);
  ASSERT_EQ(proposal_a->transition.settlement_commitment, proposal_b->transition.settlement_commitment);
  ASSERT_EQ(proposal_a->transition.next_state_root, proposal_b->transition.next_state_root);
  ASSERT_EQ(frontier_lock_payload_id_for_test(proposal_a->transition), frontier_lock_payload_id_for_test(proposal_b->transition));

  const auto committee1 = target->committee_for_height_round_for_test(target_height, retry_round);
  const auto quorum1 = consensus::quorum_threshold(committee1.size());
  auto tc0 = make_test_timeout_certificate(keys, committee0, target_height, round0, quorum0);
  ASSERT_TRUE(tc0.signatures.size() >= quorum0);

  ASSERT_TRUE(target->advance_round_for_test(target_height, retry_round));
  auto msg = make_test_frontier_propose_msg(*proposal_b);
  msg.justify_tc = tc0;
  const auto repropose_result = target->inject_network_propose_result_for_test(msg);
  if (repropose_result != "accepted") {
    throw std::runtime_error("expected accepted TC reproposal, got: " + repropose_result);
  }

  std::size_t injected_votes = 0;
  for (const auto& pub : committee1) {
    if (pub == target->local_validator_pubkey_for_test()) continue;
    const auto vote_result = target->inject_network_vote_result_for_test(
        make_test_vote(keys, target_height, retry_round, frontier_proposal_id(*proposal_b), pub));
    if (vote_result != "accepted") {
      throw std::runtime_error("expected accepted TC re-vote from " +
                               hex_encode(Bytes(pub.begin(), pub.end())).substr(0, 8) + ", got: " + vote_result);
    }
    ++injected_votes;
    if (injected_votes >= quorum1) break;
  }
  ASSERT_TRUE(injected_votes >= quorum1);

  ASSERT_TRUE(wait_for([&]() { return target->status().height == target_height; }, std::chrono::seconds(5)));
  ASSERT_EQ(target->status().transition_hash, frontier_proposal_id(*proposal_b));
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
  cfg0.node_id = 0;
  cfg0.dns_seeds = false;
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

  node::Node n0(cfg0);
  if (!n0.init()) return;
  n0.start();
  const auto port0 = n0.p2p_port_for_test();
  if (port0 == 0) {
    n0.stop();
    return;
  }

  node::NodeConfig cfg1;
  cfg1.node_id = 1;
  cfg1.dns_seeds = false;
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
  }, std::chrono::seconds(30)));

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
    request_tx = build_validator_join_request_tx(
        n0.find_utxos_by_pubkey_hash_for_test(sender_pkh), Bytes(leader_kp.private_key.begin(), leader_kp.private_key.end()),
        joiner_kp.public_key, Bytes(joiner_kp.private_key.begin(), joiner_kp.private_key.end()), joiner_kp.public_key, 1, 0,
        address::p2pkh_script_pubkey(sender_pkh), nullptr, &pow_ctx);
    db.close();
    return request_tx.has_value();
  }, std::chrono::seconds(180)));
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
  }, std::chrono::seconds(20));
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
          crypto::ed25519_sign(vote_signing_message(proposal->transition.height, proposal->transition.round,
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
    }, std::chrono::seconds(40));
  }
  ASSERT_TRUE(finalized_request);
  ASSERT_TRUE(wait_for([&]() {
    auto info0 = n0.validator_info_for_test(joiner_vk.pubkey);
    auto info1 = n1.validator_info_for_test(joiner_vk.pubkey);
    return info0.has_value() && info1.has_value();
  }, std::chrono::seconds(20)));

  ASSERT_EQ(n0.status().pending_bootstrap_joiners, 0u);
  ASSERT_TRUE(wait_for([&]() {
    auto info0 = n0.validator_info_for_test(joiner_vk.pubkey);
    auto info1 = n1.validator_info_for_test(joiner_vk.pubkey);
    if (!info0.has_value() || !info1.has_value()) return false;
    return (info0->status == consensus::ValidatorStatus::PENDING || info0->status == consensus::ValidatorStatus::ACTIVE) &&
           (info1->status == consensus::ValidatorStatus::PENDING || info1->status == consensus::ValidatorStatus::ACTIVE);
  }, std::chrono::seconds(30)));

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
  cfg0.node_id = 0;
  cfg0.dns_seeds = false;
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
    return;
  }
  ASSERT_TRUE(wait_for_tip(n0, 12, std::chrono::seconds(20)));

  node::NodeConfig cfg1;
  cfg1.node_id = 1;
  cfg1.dns_seeds = false;
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
  cfg0.node_id = 0;
  cfg0.dns_seeds = false;
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
    return;
  }
  ASSERT_TRUE(wait_for_tip(n0, 24, ci_timeout_seconds(25)));

  node::NodeConfig cfg1;
  cfg1.node_id = 1;
  cfg1.dns_seeds = false;
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
  ASSERT_TRUE(follower.inject_propose_msg_for_test(make_test_frontier_propose_msg(*proposal)));

  Vote vote =
      make_test_vote(keys, next_height, round, frontier_proposal_id(*proposal), keys[static_cast<std::size_t>(proposer_id)].public_key);
  Vote local_vote =
      make_test_vote(keys, next_height, round, frontier_proposal_id(*proposal), keys[static_cast<std::size_t>(follower_id)].public_key);
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
  auto qc = make_test_frontier_qc(keys, committee, *proposal, quorum);
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
  bootstrap_cfg.node_id = 0;
  bootstrap_cfg.dns_seeds = false;
  bootstrap_cfg.db_path = base + "/bootstrap";
  bootstrap_cfg.p2p_port = reserve_test_port();
  if (bootstrap_cfg.p2p_port == 0) return;
  bootstrap_cfg.genesis_path = gpath;
  bootstrap_cfg.allow_unsafe_genesis_override = true;
  bootstrap_cfg.network.min_block_interval_ms = 100;
  bootstrap_cfg.network.round_timeout_ms = 200;

  node::Node bootstrap(bootstrap_cfg);
  if (!bootstrap.init()) return;
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
  ASSERT_TRUE(server.start_transitions(bootstrap_cfg.network, bootstrap_status.genesis_hash, *bootstrap_pub, tampered_height,
                                       frontier_proposal_id(a3->proposal), std::move(transitions)));

  bootstrap.stop();

  node::NodeConfig follower_cfg;
  follower_cfg.node_id = 1;
  follower_cfg.dns_seeds = false;
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
  cfg0.node_id = 0;
  cfg0.dns_seeds = false;
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
    return;
  }
  ASSERT_TRUE(wait_for_tip(n0, 8, std::chrono::seconds(20)));

  node::NodeConfig cfg1;
  cfg1.node_id = 1;
  cfg1.dns_seeds = false;
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

TEST(test_non_active_follower_does_not_mine_historical_epoch_tickets) {
  const std::string base = unique_test_base("/tmp/finalis_it_non_active_follower_no_historical_epoch_tickets");
  auto cluster = make_p2p_cluster(base, 2, 2, 2);
  auto& validators = cluster.nodes;
  const auto min_height =
      std::max<std::uint64_t>(18, node::NodeConfig{}.network.committee_epoch_blocks + 2);

  ASSERT_TRUE(wait_for([&]() { return validators[0]->status().height >= min_height; }, std::chrono::seconds(45)));
  ASSERT_TRUE(wait_for_same_tip(validators, std::chrono::seconds(15)));

  for (auto& n : validators) ASSERT_TRUE(n->pause_proposals_for_test(true));
  ASSERT_TRUE(wait_for_same_tip(validators, std::chrono::seconds(15)));
  node::NodeConfig follower_cfg;
  follower_cfg.node_id = 9;
  follower_cfg.dns_seeds = false;
  follower_cfg.listen = false;
  follower_cfg.db_path = base + "/follower";
  follower_cfg.p2p_port = 0;
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

  const auto local_pub = follower.local_validator_pubkey_for_test();
  const auto active = follower.active_validators_for_next_height_for_test();
  ASSERT_TRUE(std::find(active.begin(), active.end(), local_pub) == active.end());

  const auto validator_status = validators[0]->status();
  const auto step = std::max<std::uint64_t>(1, follower_cfg.network.committee_epoch_blocks);
  const auto next_epoch = consensus::committee_epoch_start(validator_status.height + 1, follower_cfg.network.committee_epoch_blocks);
  ASSERT_TRUE(next_epoch > step);
  const auto required_epoch = next_epoch - step;

  follower.stop();

  storage::DB db;
  ASSERT_TRUE(db.open_readonly(follower_cfg.db_path));
  const auto best = db.load_best_epoch_tickets(required_epoch);
  const auto snapshot = db.get_epoch_committee_snapshot(required_epoch);
  db.close();

  ASSERT_TRUE(best.find(local_pub) == best.end());
  ASSERT_TRUE(snapshot.has_value());
  ASSERT_TRUE(std::find(snapshot->ordered_members.begin(), snapshot->ordered_members.end(), local_pub) ==
              snapshot->ordered_members.end());

  for (auto& n : validators) n->stop();
}

TEST(test_follower_sync_does_not_reject_canonical_block_due_to_local_epoch_ticket) {
  const std::string base = unique_test_base("/tmp/finalis_it_non_active_follower_sync_past_epoch_boundary");
  auto cluster = make_p2p_cluster(base, 2, 2, 2);
  auto& validators = cluster.nodes;

  ASSERT_TRUE(wait_for([&]() {
    const auto s0 = validators[0]->status();
    const auto s1 = validators[1]->status();
    return s0.height >= 18 && s1.height >= 18 && s0.height == s1.height && s0.transition_hash == s1.transition_hash;
  }, std::chrono::seconds(35)));

  for (auto& n : validators) ASSERT_TRUE(n->pause_proposals_for_test(true));
  ASSERT_TRUE(wait_for_same_tip(validators, std::chrono::seconds(15)));
  const auto validator_status = validators[0]->status();

  node::NodeConfig follower_cfg;
  follower_cfg.node_id = 9;
  follower_cfg.dns_seeds = false;
  follower_cfg.listen = false;
  follower_cfg.db_path = base + "/follower";
  follower_cfg.p2p_port = 0;
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

  ASSERT_TRUE(wait_for([&]() {
    const auto sf = follower.status();
    return sf.height == validator_status.height && sf.transition_hash == validator_status.transition_hash;
  }, std::chrono::seconds(30)));

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

  ASSERT_TRUE(wait_for([&]() { return validators[0]->status().height >= min_height; }, ci_timeout_seconds(90)));
  ASSERT_TRUE(wait_for_same_tip(validators, std::chrono::seconds(15)));

  for (auto& n : validators) ASSERT_TRUE(n->pause_proposals_for_test(true));
  ASSERT_TRUE(wait_for_same_tip(validators, std::chrono::seconds(5)));

  node::NodeConfig follower_cfg;
  follower_cfg.node_id = 9;
  follower_cfg.dns_seeds = false;
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

  ASSERT_TRUE(wait_for([&]() { return validators[0]->status().height >= min_height; }, ci_timeout_seconds(90)));
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

  ASSERT_TRUE(wait_for([&]() { return validators[0]->status().height >= 32; }, std::chrono::seconds(50)));
  ASSERT_TRUE(wait_for_same_tip(validators, std::chrono::seconds(5)));

  node::NodeConfig follower_cfg;
  follower_cfg.node_id = 9;
  follower_cfg.dns_seeds = false;
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
  follower_cfg.outbound_target = 1;
  ASSERT_TRUE(create_test_validator_keystore(follower_cfg, follower_cfg.node_id));

  node::Node follower(follower_cfg);
  ASSERT_TRUE(follower.init());
  follower.start();

  ASSERT_TRUE(wait_for([&]() {
    const auto s0 = validators[0]->status();
    const auto s1 = validators[1]->status();
    return s0.height >= 48 && s1.height == s0.height && s1.transition_hash == s0.transition_hash;
  }, std::chrono::seconds(70)));
  for (auto& n : validators) ASSERT_TRUE(n->pause_proposals_for_test(true));
  ASSERT_TRUE(wait_for_same_tip(validators, std::chrono::seconds(15)));
  bool follower_caught_up = wait_for([&]() { return follower.status().height >= 40; }, ci_timeout_seconds(90));
  if (!follower_caught_up) {
    for (auto& n : validators) ASSERT_TRUE(n->pause_proposals_for_test(false));
    ASSERT_TRUE(wait_for([&]() { return follower.status().height >= 40; }, ci_timeout_seconds(30)));
    for (auto& n : validators) ASSERT_TRUE(n->pause_proposals_for_test(true));
  }

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
  cfg0.node_id = 0;
  cfg0.dns_seeds = false;
  cfg0.db_path = base + "/node0";
  cfg0.p2p_port = reserve_test_port();
  if (cfg0.p2p_port == 0) return;
  cfg0.genesis_path = gpath;
  cfg0.allow_unsafe_genesis_override = true;
  cfg0.idle_timeout_ms = 1200;
  cfg0.network.min_block_interval_ms = 100;
  cfg0.network.round_timeout_ms = 200;

  node::Node n0(cfg0);
  if (!n0.init()) return;
  n0.start();
  const auto port0 = n0.p2p_port_for_test();
  if (port0 == 0) {
    n0.stop();
    return;
  }
  ASSERT_TRUE(wait_for_tip(n0, 5, std::chrono::seconds(15)));

  node::NodeConfig cfg1;
  cfg1.node_id = 1;
  cfg1.dns_seeds = false;
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
  bootstrap_cfg.node_id = 0;
  bootstrap_cfg.dns_seeds = false;
  bootstrap_cfg.db_path = base + "/bootstrap";
  bootstrap_cfg.p2p_port = reserve_test_port();
  if (bootstrap_cfg.p2p_port == 0) return;
  bootstrap_cfg.genesis_path = gpath;
  bootstrap_cfg.allow_unsafe_genesis_override = true;
  bootstrap_cfg.network.min_block_interval_ms = 100;
  bootstrap_cfg.network.round_timeout_ms = 200;

  node::Node bootstrap(bootstrap_cfg);
  if (!bootstrap.init()) return;
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
  ASSERT_TRUE(server.start_transitions(bootstrap_cfg.network, bootstrap_status.genesis_hash, *bootstrap_pub, 3,
                                       frontier_proposal_id(a3->proposal), std::move(transitions)));

  bootstrap.stop();

  node::NodeConfig follower_cfg;
  follower_cfg.node_id = 1;
  follower_cfg.dns_seeds = false;
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
  bootstrap_cfg.node_id = 0;
  bootstrap_cfg.dns_seeds = false;
  bootstrap_cfg.db_path = base + "/bootstrap";
  bootstrap_cfg.p2p_port = reserve_test_port();
  if (bootstrap_cfg.p2p_port == 0) return;
  bootstrap_cfg.genesis_path = gpath;
  bootstrap_cfg.allow_unsafe_genesis_override = true;
  bootstrap_cfg.network.min_block_interval_ms = 100;
  bootstrap_cfg.network.round_timeout_ms = 200;

  node::Node bootstrap(bootstrap_cfg);
  if (!bootstrap.init()) return;
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

TEST(test_reject_cross_network_mainnet_vs_testnet_handshake) {
  const std::string base = unique_test_base("/tmp/finalis_it_reject_mainnet_vs_testnet");
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);
  const std::string gpath = base + "/genesis.json";
  ASSERT_TRUE(write_mainnet_genesis_file(gpath, 4));

  node::NodeConfig cfg;
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
  if (!n.init()) return;
  n.start();
  const std::uint16_t port = n.p2p_port_for_test();
  if (port == 0) {
    n.stop();
    return;
  }

  p2p::VersionMsg v;
  v.proto_version = static_cast<std::uint32_t>(cfg.network.protocol_version);
  v.network_id = cfg.network.network_id;
  v.network_id[0] ^= 0xFF;  // mismatch
  v.feature_flags = cfg.network.feature_flags;
  v.timestamp = static_cast<std::uint64_t>(::time(nullptr));
  v.nonce = 987;
  v.node_software_version = "handshake-test/0.7";
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
  cfg.node_id = 0;
  cfg.dns_seeds = false;
  cfg.db_path = base + "/node0";
  cfg.p2p_port = reserve_test_port();
  if (cfg.p2p_port == 0) return;
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

TEST(test_startup_rejects_incomplete_finalized_write_marker) {
  const auto base = unique_test_base("/tmp/finalis_it_partial_finalized_write");
  auto cluster = make_cluster(base, 1, 1, 1);
  ASSERT_TRUE(wait_for_tip(*cluster.nodes[0], 1, std::chrono::seconds(12)));
  cluster.nodes[0]->stop();
  cluster.nodes.clear();

  storage::DB db;
  ASSERT_TRUE(db.open(base + "/node0"));
  const auto tip = db.get_tip();
  ASSERT_TRUE(tip.has_value());
  ASSERT_TRUE(db.put("FW:PENDING", serialize_test_finalized_write_marker(tip->height, tip->hash)));
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
  const auto before = cluster.nodes[0]->status();
  const auto before_commitment = cluster.nodes[0]->canonical_state_commitment_for_test();
  cluster.nodes[0]->stop();
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

  p2p::ProposeMsg msg;
  msg.height = proposal.transition.height;
  msg.round = proposal.transition.round;
  msg.prev_finalized_hash = proposal.transition.prev_finalized_hash;
  msg.frontier_proposal_bytes = proposal.serialize();
  ASSERT_TRUE(target.inject_propose_msg_for_test(msg));
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
  p2p::ProposeMsg msg{.height = proposal.transition.height, .round = proposal.transition.round,
                      .prev_finalized_hash = proposal.transition.prev_finalized_hash,
                      .frontier_proposal_bytes = proposal.serialize()};
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
  p2p::ProposeMsg msg{.height = proposal.transition.height, .round = proposal.transition.round,
                      .prev_finalized_hash = proposal.transition.prev_finalized_hash,
                      .frontier_proposal_bytes = proposal.serialize()};
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
  p2p::ProposeMsg msg{.height = proposal.transition.height, .round = proposal.transition.round,
                      .prev_finalized_hash = proposal.transition.prev_finalized_hash,
                      .frontier_proposal_bytes = proposal.serialize()};
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
  p2p::ProposeMsg msg{.height = proposal.transition.height, .round = proposal.transition.round,
                      .prev_finalized_hash = proposal.transition.prev_finalized_hash,
                      .frontier_proposal_bytes = proposal.serialize()};
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
  p2p::ProposeMsg msg{.height = proposal.transition.height, .round = proposal.transition.round,
                      .prev_finalized_hash = proposal.transition.prev_finalized_hash,
                      .frontier_proposal_bytes = proposal.serialize()};
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
  p2p::ProposeMsg msg{.height = proposal.transition.height, .round = proposal.transition.round,
                      .prev_finalized_hash = proposal.transition.prev_finalized_hash,
                      .frontier_proposal_bytes = proposal.serialize()};
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
  p2p::ProposeMsg msg{.height = proposal.transition.height, .round = proposal.transition.round,
                      .prev_finalized_hash = proposal.transition.prev_finalized_hash,
                      .frontier_proposal_bytes = proposal.serialize()};
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

  p2p::ProposeMsg msg;
  msg.height = proposal->transition.height;
  msg.round = proposal->transition.round;
  msg.prev_finalized_hash = proposal->transition.prev_finalized_hash;
  msg.frontier_proposal_bytes = proposal->serialize();
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

void register_integration_tests() {}
