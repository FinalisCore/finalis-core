// SPDX-License-Identifier: MIT

#include "test_framework.hpp"

#include <filesystem>
#include <fstream>
#include <memory>
#include <stdexcept>

#include "consensus/ingress.hpp"
#include "crypto/ed25519.hpp"
#include "crypto/hash.hpp"
#include "genesis/genesis.hpp"
#include "common/keystore.hpp"
#include "node/node.hpp"
#include "storage/db.hpp"
#include "utxo/validate.hpp"

using namespace finalis;

namespace {

std::string unique_test_base(const std::string& prefix) {
  return prefix + "_" +
         std::to_string(std::chrono::duration_cast<std::chrono::nanoseconds>(
                            std::chrono::steady_clock::now().time_since_epoch())
                            .count());
}

std::array<std::uint8_t, 32> deterministic_seed_for_node_id(int node_id) {
  std::array<std::uint8_t, 32> seed{};
  const int i = node_id + 1;
  for (std::size_t j = 0; j < seed.size(); ++j) seed[j] = static_cast<std::uint8_t>(i * 19 + static_cast<int>(j));
  return seed;
}

Bytes valreg_script(const PubKey32& pub) {
  Bytes out{'S', 'C', 'V', 'A', 'L', 'R', 'E', 'G'};
  out.insert(out.end(), pub.begin(), pub.end());
  return out;
}

bool write_mainnet_genesis_file(const std::string& path, std::size_t n_validators) {
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
  d.note = "mainnet-characterization";
  for (std::size_t i = 0; i < n_validators; ++i) d.initial_validators.push_back(keys[i].public_key);

  std::filesystem::create_directories(std::filesystem::path(path).parent_path());
  std::ofstream out(path, std::ios::trunc);
  if (!out.good()) return false;
  out << genesis::to_json(d);
  return out.good();
}

std::unique_ptr<node::Node> make_node(const std::string& base, int node_id, std::size_t n_validators, std::size_t max_committee) {
  std::error_code ec;
  std::filesystem::remove_all(base, ec);
  std::filesystem::create_directories(base);
  const std::string gpath = base + "/genesis.json";
  if (!write_mainnet_genesis_file(gpath, n_validators)) throw std::runtime_error("failed to write genesis");

  node::NodeConfig cfg;
  cfg.disable_p2p = true;
  cfg.node_id = node_id;
  cfg.max_committee = max_committee;
  cfg.db_path = base + "/node";
  cfg.genesis_path = gpath;
  cfg.allow_unsafe_genesis_override = true;
  cfg.validator_key_file = cfg.db_path + "/keystore/validator.json";
  cfg.validator_passphrase = "test-pass";

  keystore::ValidatorKey out_key;
  std::string kerr;
  if (!keystore::create_validator_keystore(cfg.validator_key_file, cfg.validator_passphrase, "mainnet", "sc",
                                           deterministic_seed_for_node_id(node_id), &out_key, &kerr)) {
    throw std::runtime_error("failed to create validator keystore: " + kerr);
  }

  auto n = std::make_unique<node::Node>(cfg);
  if (!n->init()) throw std::runtime_error("node init failed");
  return n;
}

bool persist_certified_ingress_record(const std::string& db_path, const Bytes& tx_bytes) {
  storage::DB db;
  if (!db.open(db_path)) return false;
  auto tx = Tx::parse(tx_bytes);
  if (!tx.has_value()) return false;
  IngressCertificate cert;
  cert.epoch = 1;
  cert.lane = consensus::assign_ingress_lane(*tx);
  cert.seq = 1;
  cert.txid = tx->txid();
  cert.tx_hash = crypto::sha256d(tx_bytes);
  cert.prev_lane_root = zero_hash();
  const auto signers = node::Node::deterministic_test_keypairs();
  const auto& signer = signers.front();
  const auto signing_hash = cert.signing_hash();
  const Bytes msg(signing_hash.begin(), signing_hash.end());
  auto sig = crypto::ed25519_sign(msg, signer.private_key);
  if (!sig.has_value()) return false;
  cert.sigs = {FinalitySig{signer.public_key, *sig}};
  if (!db.put_ingress_bytes(cert.txid, tx_bytes)) return false;
  if (!db.put_ingress_certificate(cert.lane, cert.seq, cert.serialize())) return false;
  LaneState state;
  state.epoch = cert.epoch;
  state.lane = cert.lane;
  state.max_seq = cert.seq;
  state.lane_root = consensus::compute_lane_root_append(cert.prev_lane_root, cert.tx_hash);
  return db.put_lane_state(state.lane, state);
}

}  // namespace

TEST(test_characterize_mainnet_defaults_fixed_epoch_committee_runtime) {
  const auto& net = mainnet_network();
  const auto& v2 = economics_policies(net).front();
  ASSERT_EQ(net.validator_bond_min_amount, BOND_AMOUNT);
  ASSERT_EQ(net.validator_bond_max_amount, BOND_AMOUNT * 100);
  ASSERT_EQ(v2.target_validators, 16ULL);
  ASSERT_EQ(v2.min_bond_floor, BOND_AMOUNT);
  ASSERT_EQ(v2.min_bond_ceiling, BOND_AMOUNT * 10);
  ASSERT_EQ(v2.max_effective_bond_multiple, 10ULL);
  ASSERT_EQ(v2.participation_threshold_bps, 8'000U);
  ASSERT_EQ(v2.ticket_bonus_cap_bps, 1'000U);
  ASSERT_EQ(economics_policies(net).size(), 1u);
}

TEST(test_characterize_mainnet_default_node_routes_epoch_committee_paths) {
  auto n = make_node(unique_test_base("/tmp/finalis_characterize_routes"), 0, 4, 3);

  ASSERT_EQ(n->proposer_path_for_next_height_for_test(), std::string("finalized-checkpoint-proposer-schedule"));
  ASSERT_EQ(n->committee_path_for_next_height_for_test(), std::string("finalized-committee-checkpoint"));
  ASSERT_EQ(n->vote_path_for_next_height_for_test(), std::string("committee-membership"));
}

TEST(test_characterize_mainnet_default_node_builds_epoch_committee_proposal_header) {
  const auto base = unique_test_base("/tmp/finalis_characterize_propose_0");
  auto candidate = make_node(base, 0, 4, 4);
  const auto proposer = candidate->proposer_for_height_round_for_test(1, 0);
  ASSERT_TRUE(proposer.has_value());
  const auto keys = node::Node::deterministic_test_keypairs();
  auto proposer_it = std::find_if(keys.begin(), keys.end(), [&](const auto& kp) {
    return kp.public_key == *proposer;
  });
  ASSERT_TRUE(proposer_it != keys.end());
  const int proposer_id = static_cast<int>(std::distance(keys.begin(), proposer_it));
  candidate->stop();

  Tx tx;
  tx.version = 1;
  tx.outputs.push_back(TxOut{1, Bytes{'c', 'h', 'a', 'r'}});
  ASSERT_TRUE(persist_certified_ingress_record(base + "/node", tx.serialize()));

  node::NodeConfig cfg;
  cfg.disable_p2p = true;
  cfg.node_id = 0;
  cfg.max_committee = 4;
  cfg.db_path = base + "/node";
  cfg.genesis_path = base + "/genesis.json";
  cfg.allow_unsafe_genesis_override = true;
  cfg.validator_key_file = cfg.db_path + "/keystore/validator.json";
  cfg.validator_passphrase = "test-pass";
  keystore::ValidatorKey out_key;
  std::string kerr;
  ASSERT_TRUE(keystore::create_validator_keystore(cfg.validator_key_file, cfg.validator_passphrase, "mainnet", "sc",
                                                  deterministic_seed_for_node_id(proposer_id), &out_key, &kerr));
  candidate = std::make_unique<node::Node>(cfg);
  ASSERT_TRUE(candidate->init());
  auto proposal = candidate->build_frontier_proposal_for_test(1, 0);
  ASSERT_TRUE(proposal.has_value());
  ASSERT_EQ(proposal->transition.round, 0u);
}

TEST(test_characterize_mainnet_status_exposes_epoch_committee_state) {
  auto n = make_node(unique_test_base("/tmp/finalis_characterize_status_0"), 0, 4, 3);
  const auto st = n->status();
  ASSERT_EQ(st.consensus_model, std::string("finalized-checkpoint-committee-bft"));
  ASSERT_TRUE(st.current_round_slot == 0u);
  ASSERT_TRUE(st.active_epoch_committee_size <= 3u);
}

TEST(test_characterize_mainnet_runtime_is_deterministic_routing_with_current_validation_semantics) {
  Tx tx;
  tx.version = 1;
  tx.lock_time = 0;
  tx.inputs.push_back(TxIn{zero_hash(), 0, Bytes{}, 0xFFFFFFFF});
  PubKey32 pub{};
  pub[0] = 42;
  tx.outputs.push_back(TxOut{BOND_AMOUNT - 1, valreg_script(pub)});

  SpecialValidationContext ctx;
  ctx.enforce_variable_bond_range = true;
  ctx.min_bond_amount = BOND_AMOUNT;
  ctx.max_bond_amount = BOND_AMOUNT * 100;
  const auto r = validate_tx(tx, 1, UtxoSet{}, &ctx);
  ASSERT_TRUE(!r.ok);
  ASSERT_EQ(r.error, std::string("SCVALREG output out of v7 bond range"));
}

void register_mainnet_characterization_tests() {}
