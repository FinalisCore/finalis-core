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
#include <fstream>
#include <regex>
#include <set>
#include <thread>

#include "common/address.hpp"
#include "consensus/availability_retention.hpp"
#include "consensus/ingress.hpp"
#include "consensus/validator_registry.hpp"
#include "common/socket_compat.hpp"
#include "crypto/hash.hpp"
#include "genesis/genesis.hpp"
#include "common/keystore.hpp"
#include "lightserver/server.hpp"
#include "mempool/mempool.hpp"
#include "node/node.hpp"
#include "p2p/framing.hpp"
#include "storage/db.hpp"
#include "storage/snapshot.hpp"
#include "crypto/smt.hpp"
#include "utxo/signing.hpp"
#include "wallet/utxo_selection.hpp"

using namespace finalis;

namespace {

constexpr auto kClusterFinalizationTimeout = std::chrono::seconds(120);

std::string unique_test_base(const std::string& prefix) {
  static std::atomic<std::uint64_t> seq{0};
  const auto pid = static_cast<std::uint64_t>(::getpid());
  const auto now = std::chrono::steady_clock::now().time_since_epoch().count();
  return prefix + "_" + std::to_string(pid) + "_" + std::to_string(now) + "_" + std::to_string(seq.fetch_add(1, std::memory_order_relaxed));
}

std::array<std::uint8_t, 32> deterministic_seed_for_node_id(int node_id) {
  std::array<std::uint8_t, 32> seed{};
  const int i = node_id + 1;
  for (std::size_t j = 0; j < seed.size(); ++j) seed[j] = static_cast<std::uint8_t>(i * 19 + static_cast<int>(j));
  return seed;
}

bool write_mainnet_genesis_file(const std::string& path, std::size_t n_validators = 1) {
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
  d.note = "lightserver-tests";
  d.initial_validators.clear();
  for (std::size_t i = 0; i < n_validators; ++i) d.initial_validators.push_back(keys[i].public_key);

  std::filesystem::create_directories(std::filesystem::path(path).parent_path());
  std::ofstream out(path, std::ios::trunc);
  if (!out.good()) return false;
  out << genesis::to_json(d);
  return out.good();
}

struct Cluster {
  std::vector<std::unique_ptr<node::Node>> nodes;
  Cluster() = default;
  Cluster(const Cluster&) = delete;
  Cluster& operator=(const Cluster&) = delete;
  Cluster(Cluster&&) = default;
  Cluster& operator=(Cluster&&) = default;
  ~Cluster() {
    for (auto& n : nodes) {
      if (n) n->stop();
    }
  }
};

Cluster make_cluster(const std::string& base, int node_count = 4) {
  std::error_code ec;
  std::filesystem::remove_all(base, ec);
  std::filesystem::create_directories(base);
  const std::string gpath = base + "/genesis.json";
  if (!write_mainnet_genesis_file(gpath, static_cast<std::size_t>(node_count))) {
    throw std::runtime_error("failed to write genesis");
  }

  Cluster c;
  c.nodes.reserve(static_cast<std::size_t>(node_count));
  for (int i = 0; i < node_count; ++i) {
    node::NodeConfig cfg;
    cfg.node_id = i;
    cfg.disable_p2p = true;
    // Match the accelerated timing used by the integration harness. These
    // tests are asserting finalized progression inside seconds, not mainnet's
    // multi-minute production cadence.
    cfg.network.min_block_interval_ms = 100;
    cfg.network.round_timeout_ms = 200;
    cfg.p2p_port = static_cast<std::uint16_t>(19040 + i);
    cfg.db_path = base + "/node" + std::to_string(i);
    cfg.max_committee = static_cast<std::size_t>(node_count);
    cfg.genesis_path = gpath;
    cfg.allow_unsafe_genesis_override = true;
    cfg.validator_key_file = cfg.db_path + "/keystore/validator.json";
    cfg.validator_passphrase = "test-pass";
    for (int j = 0; j < i; ++j) {
      cfg.peers.push_back("127.0.0.1:" + std::to_string(19040 + j));
    }
    keystore::ValidatorKey created_key;
    std::string kerr;
    if (!keystore::create_validator_keystore(cfg.validator_key_file, cfg.validator_passphrase, "mainnet", "sc",
                                             deterministic_seed_for_node_id(i), &created_key, &kerr)) {
      throw std::runtime_error("failed to create validator keystore");
    }
    auto n = std::make_unique<node::Node>(cfg);
    if (!n->init()) throw std::runtime_error("cluster init failed");
    c.nodes.push_back(std::move(n));
  }
  for (auto& n : c.nodes) n->start();
  return c;
}

std::optional<std::string> json_string_field(const std::string& s, const std::string& key) {
  const std::regex re("\"" + key + "\"\\s*:\\s*\"([^\"]*)\"");
  std::smatch m;
  if (!std::regex_search(s, m, re) || m.size() < 2) return std::nullopt;
  return m[1].str();
}

std::vector<std::string> json_string_array_field(const std::string& s, const std::string& key) {
  std::vector<std::string> out;
  const std::regex outer_re("\"" + key + "\"\\s*:\\s*\\[(.*?)\\]");
  std::smatch outer;
  if (!std::regex_search(s, outer, outer_re) || outer.size() < 2) return out;
  const std::string body = outer[1].str();
  const std::regex item_re("\"([0-9a-fA-F]+)\"");
  for (std::sregex_iterator it(body.begin(), body.end(), item_re), end; it != end; ++it) {
    out.push_back((*it)[1].str());
  }
  return out;
}

bool wait_for(const std::function<bool()>& pred, std::chrono::milliseconds timeout) {
  const auto start = std::chrono::steady_clock::now();
  while (std::chrono::steady_clock::now() - start < timeout) {
    if (pred()) return true;
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
  }
  return pred();
}

std::optional<std::string> http_post_rpc(const std::string& host, std::uint16_t port, const std::string& body) {
  if (!finalis::net::ensure_sockets()) return std::nullopt;
  addrinfo hints{};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  addrinfo* res = nullptr;
  if (::getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res) != 0) return std::nullopt;
  auto fd = finalis::net::kInvalidSocket;
  for (addrinfo* it = res; it != nullptr; it = it->ai_next) {
    fd = ::socket(it->ai_family, it->ai_socktype, it->ai_protocol);
    if (!finalis::net::valid_socket(fd)) continue;
    (void)finalis::net::set_socket_timeouts(fd, 15'000);
    if (::connect(fd, it->ai_addr, it->ai_addrlen) == 0) break;
    finalis::net::close_socket(fd);
    fd = finalis::net::kInvalidSocket;
  }
  ::freeaddrinfo(res);
  if (!finalis::net::valid_socket(fd)) return std::nullopt;

  std::string req = "POST /rpc HTTP/1.1\r\nHost: " + host + "\r\nContent-Type: application/json\r\nContent-Length: " +
                    std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
  if (!p2p::write_all(fd, reinterpret_cast<const std::uint8_t*>(req.data()), req.size())) {
    finalis::net::close_socket(fd);
    return std::nullopt;
  }
  std::string resp;
  std::array<char, 4096> buf{};
  while (true) {
    const ssize_t n = ::recv(fd, buf.data(), buf.size(), 0);
    if (n <= 0) break;
    resp.append(buf.data(), static_cast<size_t>(n));
  }
  finalis::net::close_socket(fd);
  const auto pos = resp.find("\r\n\r\n");
  if (pos == std::string::npos) return std::nullopt;
  return resp.substr(pos + 4);
}

}  // namespace

TEST(test_lightserver_parse_args_rejects_mainnet_flag) {
  std::vector<std::string> args = {"finalis-lightserver", "--mainnet"};
  std::vector<char*> argv;
  argv.reserve(args.size());
  for (auto& s : args) argv.push_back(s.data());
  ASSERT_TRUE(!lightserver::parse_args(static_cast<int>(argv.size()), argv.data()).has_value());
}

TEST(test_lightserver_indexing_after_finalization) {
  const std::string base = unique_test_base("/tmp/finalis_light_idx");
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);

  storage::DB db;
  ASSERT_TRUE(db.open(base));

  genesis::Document d;
  d.version = 1;
  d.network_name = "mainnet";
  d.protocol_version = mainnet_network().protocol_version;
  d.network_id = mainnet_network().network_id;
  d.magic = mainnet_network().magic;
  d.genesis_time_unix = 1735689600ULL;
  d.initial_height = 0;
  d.initial_active_set_size = 1;
  d.initial_committee_params.min_committee = 1;
  d.initial_committee_params.max_committee = static_cast<std::uint32_t>(mainnet_network().max_committee);
  d.initial_committee_params.sizing_rule = "min(MAX_COMMITTEE,ACTIVE_SIZE)";
  d.initial_committee_params.c = 2;
  d.monetary_params_ref = "test";
  d.seeds = {};
  d.note = "lightserver-indexing-direct";
  d.initial_validators.push_back(node::Node::deterministic_test_keypairs()[0].public_key);
  const auto genesis_json = genesis::to_json(d);
  ASSERT_TRUE(db.put(storage::key_genesis_json(), Bytes(genesis_json.begin(), genesis_json.end())));

  Hash32 tip_hash{};
  tip_hash[31] = 0xA7;
  ASSERT_TRUE(db.set_tip(storage::TipState{7, tip_hash}));
  ASSERT_TRUE(db.set_height_hash(7, tip_hash));

  const auto keys = node::Node::deterministic_test_keypairs();
  ASSERT_TRUE(keys.size() >= 2);
  OutPoint spend_op{};
  spend_op.txid[31] = 0x11;
  spend_op.index = 0;
  const std::uint64_t fee = 1000;
  const TxOut spend_out{
      10'000, address::p2pkh_script_pubkey(crypto::h160(Bytes(keys[0].public_key.begin(), keys[0].public_key.end())))};
  const std::size_t sender_index = 0;
  const auto recipient_index = std::size_t{1};
  const auto recipient_pkh = crypto::h160(Bytes(keys[recipient_index].public_key.begin(), keys[recipient_index].public_key.end()));
  std::vector<TxOut> outs{TxOut{spend_out.value - fee, address::p2pkh_script_pubkey(recipient_pkh)}};
  auto tx = build_signed_p2pkh_tx_single_input(spend_op, spend_out, keys[sender_index].private_key, outs);
  ASSERT_TRUE(tx.has_value());
  const Hash32 txid = tx->txid();
  ASSERT_TRUE(db.put_tx_index(txid, 7, 0, tx->serialize()));
  auto loc = db.get_tx_index(txid);
  ASSERT_TRUE(loc.has_value());
  ASSERT_TRUE(loc->tx_bytes == tx->serialize());

  const Hash32 sh = crypto::sha256(address::p2pkh_script_pubkey(recipient_pkh));
  ASSERT_TRUE(db.put_script_utxo(sh, OutPoint{txid, 0}, outs[0], 7));
  ASSERT_TRUE(db.add_script_history(sh, 7, txid));
  ASSERT_TRUE(db.flush());
  auto utxos = db.get_script_utxos(sh);
  ASSERT_TRUE(!utxos.empty());
  bool found = false;
  for (const auto& u : utxos) {
    if (u.outpoint.txid == txid && u.outpoint.index == 0) found = true;
  }
  ASSERT_TRUE(found);

}

TEST(test_finality_certificate_persisted_separately) {
  const std::string base = unique_test_base("/tmp/finalis_light_cert_db");
  auto cluster = make_cluster(base);
  auto& node = *cluster.nodes[0];
  ASSERT_TRUE(wait_for([&]() { return node.status().height >= 6; }, kClusterFinalizationTimeout));

  storage::DB db;
  ASSERT_TRUE(db.open_readonly(base + "/node0"));
  auto tip = db.get_tip();
  ASSERT_TRUE(tip.has_value());

  auto cert = db.get_finality_certificate_by_height(tip->height);
  ASSERT_TRUE(cert.has_value());
  ASSERT_EQ(cert->height, tip->height);
  ASSERT_EQ(cert->block_id, tip->hash);
  ASSERT_EQ(cert->quorum_threshold, consensus::quorum_threshold(cert->committee_members.size()));
  ASSERT_TRUE(cert->signatures.size() >= cert->quorum_threshold);

  std::set<PubKey32> committee(cert->committee_members.begin(), cert->committee_members.end());
  for (const auto& sig : cert->signatures) {
    ASSERT_TRUE(committee.find(sig.validator_pubkey) != committee.end());
  }
}

TEST(test_lightserver_basic_live_rpc_surface) {
  const std::string base = unique_test_base("/tmp/finalis_light_rpc");
  auto cluster = make_cluster(base);
  auto& nodes = cluster.nodes;
  auto& node = nodes[0];
  ASSERT_TRUE(wait_for([&]() {
    for (const auto& n : nodes) {
      if (n->status().height < 6) return false;
    }
    return true;
  }, kClusterFinalizationTimeout));
  const auto pinned_tip = nodes[0]->status();
  const auto blk_height = pinned_tip.height;
  const auto blk_hash = pinned_tip.transition_hash;

  lightserver::Config lcfg;
  lcfg.db_path = base + "/node0";
  lcfg.bind_ip = "127.0.0.1";
  lcfg.max_committee = 1;
  lcfg.tx_relay_host = "127.0.0.1";
  lcfg.tx_relay_port = 29999;  // expected to be unavailable in test env
  auto ls = std::make_unique<lightserver::Server>(lcfg);
  ASSERT_TRUE(ls->init());

  auto tip_resp = ls->handle_rpc_for_test(R"({"jsonrpc":"2.0","id":1,"method":"get_tip","params":{}})");
  ASSERT_TRUE(tip_resp.find("\"height\"") != std::string::npos);
  ASSERT_TRUE(tip_resp.find("\"hash\"") != std::string::npos);
  auto status_resp = ls->handle_rpc_for_test(R"({"jsonrpc":"2.0","id":11,"method":"get_status","params":{}})");
  ASSERT_TRUE(status_resp.find("\"uptime_s\"") != std::string::npos);
  ASSERT_TRUE(status_resp.find("\"version\"") != std::string::npos);
  ASSERT_TRUE(status_resp.find("\"network_name\"") != std::string::npos);
  ASSERT_TRUE(status_resp.find("\"network_id\"") != std::string::npos);
  ASSERT_TRUE(status_resp.find("\"magic\"") != std::string::npos);
  ASSERT_TRUE(status_resp.find("\"protocol_version\"") != std::string::npos);
  ASSERT_TRUE(status_resp.find("\"feature_flags\"") != std::string::npos);
  ASSERT_TRUE(status_resp.find("\"genesis_hash\"") != std::string::npos);
  ASSERT_TRUE(status_resp.find("\"genesis_source\"") != std::string::npos);
  ASSERT_TRUE(status_resp.find("\"finalized_tip\"") != std::string::npos);
  ASSERT_TRUE(status_resp.find("\"finalized_height\"") != std::string::npos);
  ASSERT_TRUE(status_resp.find("\"finalized_transition_hash\"") != std::string::npos);
  ASSERT_TRUE(status_resp.find("\"ticket_pow\"") != std::string::npos);
  ASSERT_TRUE(status_resp.find("\"nonce_search_limit\":4096") != std::string::npos);
  ASSERT_TRUE(status_resp.find("\"sync\"") != std::string::npos);

  auto committee_resp =
      ls->handle_rpc_for_test(R"({"jsonrpc":"2.0","id":3,"method":"get_committee","params":{"height":1}})");
  ASSERT_TRUE(committee_resp.find("result") != std::string::npos);
  auto committee_verbose_resp =
      ls->handle_rpc_for_test(R"({"jsonrpc":"2.0","id":31,"method":"get_committee","params":{"height":1,"verbose":true}})");
  ASSERT_TRUE(committee_verbose_resp.find("\"members\"") != std::string::npos);
  ASSERT_TRUE(committee_verbose_resp.find("\"ticket_pow\"") != std::string::npos);
  ASSERT_TRUE(committee_verbose_resp.find("\"representative_pubkey\"") != std::string::npos);

  const std::string blk_q = std::string(R"({"jsonrpc":"2.0","id":7,"method":"get_transition","params":{"hash":")") +
                            hex_encode32(blk_hash) + R"("}})";
  auto bresp = ls->handle_rpc_for_test(blk_q);
  ASSERT_TRUE(bresp.find("transition_hex") != std::string::npos);
  ASSERT_TRUE(bresp.find("\"transition_hash\":\"" + hex_encode32(blk_hash) + "\"") != std::string::npos);

  const std::string blk_by_height_q =
      std::string(R"({"jsonrpc":"2.0","id":71,"method":"get_transition_by_height","params":{"height":)") +
      std::to_string(blk_height) + "}}";
  const auto bresp2 = ls->handle_rpc_for_test(blk_by_height_q);
  ASSERT_TRUE(bresp2.find("\"hash\":\"" + hex_encode32(blk_hash) + "\"") != std::string::npos);
  ASSERT_TRUE(bresp2.find("\"transition_hash\":\"" + hex_encode32(blk_hash) + "\"") != std::string::npos);
  ASSERT_TRUE(bresp2.find("transition_hex") != std::string::npos);
}

TEST(test_lightserver_exposes_finality_certificate_endpoint) {
  const std::string base = unique_test_base("/tmp/finalis_light_cert_rpc");
  auto cluster = make_cluster(base);
  ASSERT_TRUE(wait_for([&]() { return cluster.nodes[0]->status().height >= 6; }, kClusterFinalizationTimeout));
  const auto tip = cluster.nodes[0]->status();

  for (auto& n : cluster.nodes) {
    if (n) n->stop();
  }
  cluster.nodes.clear();

  lightserver::Config lcfg;
  lcfg.db_path = base + "/node0";
  auto ls = std::make_unique<lightserver::Server>(lcfg);
  ASSERT_TRUE(ls->init());

  const std::string by_height_q =
      std::string(R"({"jsonrpc":"2.0","id":31,"method":"get_finality_certificate","params":{"height":)") +
      std::to_string(tip.height) + "}}";
  const auto by_height = ls->handle_rpc_for_test(by_height_q);
  ASSERT_TRUE(by_height.find("\"height\":" + std::to_string(tip.height)) != std::string::npos);
  ASSERT_TRUE(by_height.find("\"transition_hash\":\"" + hex_encode32(tip.transition_hash) + "\"") != std::string::npos);
  ASSERT_TRUE(by_height.find("\"quorum_threshold\":") != std::string::npos);
  ASSERT_TRUE(by_height.find("\"committee\":[") != std::string::npos);
  ASSERT_TRUE(by_height.find("\"signatures\":[") != std::string::npos);

  const std::string by_hash_q =
      std::string(R"({"jsonrpc":"2.0","id":32,"method":"get_finality_certificate","params":{"hash":")") +
      hex_encode32(tip.transition_hash) + R"("}})";
  const auto by_hash = ls->handle_rpc_for_test(by_hash_q);
  ASSERT_TRUE(by_hash.find("\"transition_hash\":\"" + hex_encode32(tip.transition_hash) + "\"") != std::string::npos);
  ASSERT_TRUE(by_hash.find("\"signatures\":[") != std::string::npos);

  const auto by_tip_default =
      ls->handle_rpc_for_test(R"({"jsonrpc":"2.0","id":33,"method":"get_finality_certificate","params":{}})");
  ASSERT_TRUE(by_tip_default.find("\"transition_hash\":\"" + hex_encode32(tip.transition_hash) + "\"") != std::string::npos);
}

TEST(test_lightserver_exposes_script_history_endpoint_direct) {
  const std::string base = unique_test_base("/tmp/finalis_light_history_direct");
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);

  storage::DB db;
  ASSERT_TRUE(db.open(base));

  genesis::Document d;
  d.version = 1;
  d.network_name = "mainnet";
  d.protocol_version = mainnet_network().protocol_version;
  d.network_id = mainnet_network().network_id;
  d.magic = mainnet_network().magic;
  d.genesis_time_unix = 1735689600ULL;
  d.initial_height = 0;
  d.initial_active_set_size = 1;
  d.initial_committee_params.min_committee = 1;
  d.initial_committee_params.max_committee = static_cast<std::uint32_t>(mainnet_network().max_committee);
  d.initial_committee_params.sizing_rule = "min(MAX_COMMITTEE,ACTIVE_SIZE)";
  d.initial_committee_params.c = 2;
  d.monetary_params_ref = "test";
  d.seeds = {};
  d.note = "lightserver-history-direct";
  d.initial_validators.push_back(node::Node::deterministic_test_keypairs()[0].public_key);
  const auto genesis_json = genesis::to_json(d);
  ASSERT_TRUE(db.put(storage::key_genesis_json(), Bytes(genesis_json.begin(), genesis_json.end())));

  const auto kp = node::Node::deterministic_test_keypairs()[0];
  const auto pkh = crypto::h160(Bytes(kp.public_key.begin(), kp.public_key.end()));
  const Hash32 sh = crypto::sha256(address::p2pkh_script_pubkey(pkh));
  Hash32 txid{};
  txid[31] = 42;
  ASSERT_TRUE(db.add_script_history(sh, 7, txid));
  ASSERT_TRUE(db.flush());
  db.close();

  lightserver::Config lcfg;
  lcfg.db_path = base;
  auto ls = std::make_unique<lightserver::Server>(lcfg);
  ASSERT_TRUE(ls->init());

  const std::string history_q = std::string(R"({"jsonrpc":"2.0","id":91,"method":"get_history","params":{"scripthash_hex":")") +
                                hex_encode32(sh) + R"("}})";
  const auto resp = ls->handle_rpc_for_test(history_q);
  ASSERT_TRUE(resp.find(hex_encode32(txid)) != std::string::npos);
  ASSERT_TRUE(resp.find("\"height\":7") != std::string::npos);
}

TEST(test_lightserver_get_tx_status_direct) {
  const std::string base = unique_test_base("/tmp/finalis_light_tx_status_direct");
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);

  storage::DB db;
  ASSERT_TRUE(db.open(base));
  Hash32 tip_hash{};
  tip_hash[31] = 0x99;
  Hash32 block_hash{};
  block_hash[31] = 0x55;
  Hash32 txid{};
  txid[31] = 0x22;
  ASSERT_TRUE(db.set_tip(storage::TipState{9, tip_hash}));
  ASSERT_TRUE(db.set_height_hash(5, block_hash));
  ASSERT_TRUE(db.put_tx_index(txid, 5, 0, Bytes{0x01, 0x02, 0x03}));
  ASSERT_TRUE(db.flush());
  db.close();

  lightserver::Config lcfg;
  lcfg.db_path = base;
  lightserver::Server ls(lcfg);
  ASSERT_TRUE(ls.init());

  const std::string q = std::string(R"({"jsonrpc":"2.0","id":101,"method":"get_tx_status","params":{"txid":")") +
                        hex_encode32(txid) + R"("}})";
  const auto resp = ls.handle_rpc_for_test(q);
  ASSERT_TRUE(resp.find("\"status\":\"finalized\"") != std::string::npos);
  ASSERT_TRUE(resp.find("\"finalized\":true") != std::string::npos);
  ASSERT_TRUE(resp.find("\"credit_safe\":true") != std::string::npos);
  ASSERT_TRUE(resp.find("\"height\":5") != std::string::npos);
  ASSERT_TRUE(resp.find("\"transition_hash\":\"" + hex_encode32(block_hash) + "\"") != std::string::npos);
  ASSERT_TRUE(resp.find("\"finalized_depth\":5") != std::string::npos);

  Hash32 missing{};
  missing[31] = 0x33;
  const std::string q_missing =
      std::string(R"({"jsonrpc":"2.0","id":102,"method":"get_tx_status","params":{"txid":")") + hex_encode32(missing) +
      R"("}})";
  const auto missing_resp = ls.handle_rpc_for_test(q_missing);
  ASSERT_TRUE(missing_resp.find("\"status\":\"not_found\"") != std::string::npos);
  ASSERT_TRUE(missing_resp.find("\"finalized\":false") != std::string::npos);
  ASSERT_TRUE(missing_resp.find("\"credit_safe\":false") != std::string::npos);
}

TEST(test_lightserver_get_tx_decodes_onboarding_registration_output_and_pow_fields) {
  const std::string base = unique_test_base("/tmp/finalis_light_get_tx_onboarding_decode");
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);

  storage::DB db;
  ASSERT_TRUE(db.open(base));
  Hash32 tip_hash{};
  tip_hash[31] = 0x91;
  Hash32 block_hash{};
  block_hash[31] = 0x51;
  ASSERT_TRUE(db.set_tip(storage::TipState{9, tip_hash}));
  ASSERT_TRUE(db.set_height_hash(5, block_hash));

  const auto funding = node::Node::deterministic_test_keypairs()[0];
  const auto validator = node::Node::deterministic_test_keypairs()[1];
  const auto payout = node::Node::deterministic_test_keypairs()[2];
  OutPoint prev{};
  prev.txid[31] = 0x44;
  prev.index = 0;
  const auto funding_pkh = crypto::h160(Bytes(funding.public_key.begin(), funding.public_key.end()));
  const TxOut prev_out{1'000'000, address::p2pkh_script_pubkey(funding_pkh)};
  auto tx = build_onboarding_registration_tx(prev, prev_out, funding.private_key, validator.public_key, validator.private_key,
                                             payout.public_key, 1'000, prev_out.script_pubkey);
  ASSERT_TRUE(tx.has_value());
  const Hash32 txid = tx->txid();
  ASSERT_TRUE(db.put_tx_index(txid, 5, 0, tx->serialize()));
  ASSERT_TRUE(db.flush());
  db.close();

  lightserver::Config lcfg;
  lcfg.db_path = base;
  lightserver::Server ls(lcfg);
  ASSERT_TRUE(ls.init());

  const std::string q = std::string(R"({"jsonrpc":"2.0","id":103,"method":"get_tx","params":{"txid":")") + hex_encode32(txid) + R"("}})";
  const auto resp = ls.handle_rpc_for_test(q);
  ASSERT_TRUE(resp.find("\"decoded_outputs\":[") != std::string::npos);
  ASSERT_TRUE(resp.find("\"decoded_kind\":\"onboarding_registration\"") != std::string::npos);
  ASSERT_TRUE(resp.find(std::string("\"validator_pubkey_hex\":\"") +
                        hex_encode(Bytes(validator.public_key.begin(), validator.public_key.end())) + "\"") != std::string::npos);
  ASSERT_TRUE(resp.find(std::string("\"payout_pubkey_hex\":\"") +
                        hex_encode(Bytes(payout.public_key.begin(), payout.public_key.end())) + "\"") != std::string::npos);
  ASSERT_TRUE(resp.find("\"has_admission_pow\":false") != std::string::npos);
}

TEST(test_lightserver_get_utxos_uses_canonical_utxo_set_even_with_incomplete_script_index) {
  const std::string base = unique_test_base("/tmp/finalis_light_utxos_canonical_only");
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);

  storage::DB db;
  ASSERT_TRUE(db.open(base));

  genesis::Document d;
  d.version = 1;
  d.network_name = "mainnet";
  d.protocol_version = mainnet_network().protocol_version;
  d.network_id = mainnet_network().network_id;
  d.magic = mainnet_network().magic;
  d.genesis_time_unix = 1735689600ULL;
  d.initial_height = 0;
  d.initial_active_set_size = 1;
  d.initial_committee_params.min_committee = 1;
  d.initial_committee_params.max_committee = static_cast<std::uint32_t>(mainnet_network().max_committee);
  d.initial_committee_params.sizing_rule = "min(MAX_COMMITTEE,ACTIVE_SIZE)";
  d.initial_committee_params.c = 2;
  d.monetary_params_ref = "test";
  d.seeds = {};
  d.note = "lightserver-canonical-utxos";
  d.initial_validators.push_back(node::Node::deterministic_test_keypairs()[0].public_key);
  const auto genesis_json = genesis::to_json(d);
  ASSERT_TRUE(db.put(storage::key_genesis_json(), Bytes(genesis_json.begin(), genesis_json.end())));

  const auto kp = node::Node::deterministic_test_keypairs()[0];
  const auto pkh = crypto::h160(Bytes(kp.public_key.begin(), kp.public_key.end()));
  const auto script_pubkey = address::p2pkh_script_pubkey(pkh);
  const Hash32 sh = crypto::sha256(script_pubkey);

  OutPoint op1{};
  op1.txid[31] = 0x44;
  op1.index = 0;
  OutPoint op2{};
  op2.txid[31] = 0x55;
  op2.index = 1;
  ASSERT_TRUE(db.put_utxo(op1, TxOut{123456789, script_pubkey}));
  ASSERT_TRUE(db.put_utxo(op2, TxOut{222222222, script_pubkey}));
  ASSERT_TRUE(db.put_tx_index(op1.txid, 7, 0, Bytes{0x01}));
  ASSERT_TRUE(db.put_tx_index(op2.txid, 9, 0, Bytes{0x02}));
  ASSERT_TRUE(db.put_script_utxo(sh, op1, TxOut{123456789, script_pubkey}, 7));
  ASSERT_TRUE(db.flush());
  db.close();

  lightserver::Config lcfg;
  lcfg.db_path = base;
  lightserver::Server ls(lcfg);
  ASSERT_TRUE(ls.init());

  const std::string body = std::string(R"({"jsonrpc":"2.0","id":103,"method":"get_utxos","params":{"scripthash_hex":")") +
                           hex_encode32(sh) + R"("}})";
  const auto resp = ls.handle_rpc_for_test(body);
  const std::string expected =
      std::string(R"({"jsonrpc":"2.0","id":103,"result":[{"txid":")") + hex_encode32(op1.txid) +
      R"(","vout":0,"value":123456789,"height":7,"script_pubkey_hex":")" + hex_encode(script_pubkey) +
      R"("},{"txid":")" + hex_encode32(op2.txid) +
      R"(","vout":1,"value":222222222,"height":9,"script_pubkey_hex":")" + hex_encode(script_pubkey) +
      R"("}]})";
  ASSERT_EQ(resp, expected);
}

TEST(test_lightserver_get_utxos_ignores_stale_or_missing_script_index_entries) {
  const std::string base = unique_test_base("/tmp/finalis_light_utxos_stale_or_missing_su");
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);

  storage::DB db;
  ASSERT_TRUE(db.open(base));

  genesis::Document d;
  d.version = 1;
  d.network_name = "mainnet";
  d.protocol_version = mainnet_network().protocol_version;
  d.network_id = mainnet_network().network_id;
  d.magic = mainnet_network().magic;
  d.genesis_time_unix = 1735689600ULL;
  d.initial_height = 0;
  d.initial_active_set_size = 1;
  d.initial_committee_params.min_committee = 1;
  d.initial_committee_params.max_committee = static_cast<std::uint32_t>(mainnet_network().max_committee);
  d.initial_committee_params.sizing_rule = "min(MAX_COMMITTEE,ACTIVE_SIZE)";
  d.initial_committee_params.c = 2;
  d.monetary_params_ref = "test";
  d.seeds = {};
  d.note = "lightserver-stale-or-missing-su";
  d.initial_validators.push_back(node::Node::deterministic_test_keypairs()[0].public_key);
  const auto genesis_json = genesis::to_json(d);
  ASSERT_TRUE(db.put(storage::key_genesis_json(), Bytes(genesis_json.begin(), genesis_json.end())));

  const auto kp = node::Node::deterministic_test_keypairs()[0];
  const auto pkh = crypto::h160(Bytes(kp.public_key.begin(), kp.public_key.end()));
  const auto script_pubkey = address::p2pkh_script_pubkey(pkh);
  const Hash32 sh = crypto::sha256(script_pubkey);

  OutPoint canonical_op{};
  canonical_op.txid[31] = 0x66;
  canonical_op.index = 0;
  ASSERT_TRUE(db.put_utxo(canonical_op, TxOut{777777777, script_pubkey}));
  ASSERT_TRUE(db.put_tx_index(canonical_op.txid, 12, 0, Bytes{0x03}));

  OutPoint stale_op{};
  stale_op.txid[31] = 0x77;
  stale_op.index = 2;
  ASSERT_TRUE(db.put_script_utxo(sh, stale_op, TxOut{999999999, script_pubkey}, 99));
  ASSERT_TRUE(db.flush());
  db.close();

  lightserver::Config lcfg;
  lcfg.db_path = base;
  lightserver::Server ls(lcfg);
  ASSERT_TRUE(ls.init());

  const std::string body = std::string(R"({"jsonrpc":"2.0","id":104,"method":"get_utxos","params":{"scripthash_hex":")") +
                           hex_encode32(sh) + R"("}})";
  const auto resp = ls.handle_rpc_for_test(body);
  ASSERT_TRUE(resp.find(hex_encode32(canonical_op.txid)) != std::string::npos);
  ASSERT_TRUE(resp.find("\"value\":777777777") != std::string::npos);
  ASSERT_TRUE(resp.find("\"height\":12") != std::string::npos);
  ASSERT_TRUE(resp.find(hex_encode32(stale_op.txid)) == std::string::npos);
}

TEST(test_wallet_spendable_utxos_reconcile_script_index_with_canonical_set) {
  const std::string base = "/tmp/finalis_wallet_spendable_reconcile";
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);

  storage::DB db;
  ASSERT_TRUE(db.open(base));

  const auto kp = node::Node::deterministic_test_keypairs()[0];
  const auto pkh = crypto::h160(Bytes(kp.public_key.begin(), kp.public_key.end()));
  const auto script_pubkey = address::p2pkh_script_pubkey(pkh);
  const Hash32 sh = crypto::sha256(script_pubkey);

  OutPoint canonical_only{};
  canonical_only.txid[31] = 0x81;
  canonical_only.index = 0;
  ASSERT_TRUE(db.put_utxo(canonical_only, TxOut{123456789, script_pubkey}));

  OutPoint indexed_and_canonical{};
  indexed_and_canonical.txid[31] = 0x82;
  indexed_and_canonical.index = 1;
  ASSERT_TRUE(db.put_utxo(indexed_and_canonical, TxOut{222222222, script_pubkey}));
  ASSERT_TRUE(db.put_script_utxo(sh, indexed_and_canonical, TxOut{222222222, script_pubkey}, 12));

  OutPoint stale_indexed{};
  stale_indexed.txid[31] = 0x83;
  stale_indexed.index = 2;
  ASSERT_TRUE(db.put_script_utxo(sh, stale_indexed, TxOut{999999999, script_pubkey}, 99));
  ASSERT_TRUE(db.flush());

  const auto spendable = wallet::spendable_p2pkh_utxos_for_pubkey_hash(db, pkh, nullptr);
  ASSERT_EQ(spendable.size(), 2u);
  ASSERT_EQ(spendable[0].prevout.value, 222222222u);
  ASSERT_EQ(spendable[0].outpoint.txid, indexed_and_canonical.txid);
  ASSERT_EQ(spendable[0].outpoint.index, indexed_and_canonical.index);
  ASSERT_EQ(spendable[1].prevout.value, 123456789u);
  ASSERT_EQ(spendable[1].outpoint.txid, canonical_only.txid);
  ASSERT_EQ(spendable[1].outpoint.index, canonical_only.index);
}

TEST(test_wallet_spendable_utxos_history_fallback_filters_noncanonical_outputs) {
  const std::string base = unique_test_base("/tmp/finalis_wallet_spendable_history_fallback");
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);

  storage::DB db;
  ASSERT_TRUE(db.open(base));

  const auto kp = node::Node::deterministic_test_keypairs()[0];
  const auto pkh = crypto::h160(Bytes(kp.public_key.begin(), kp.public_key.end()));
  const auto script_pubkey = address::p2pkh_script_pubkey(pkh);
  const Hash32 sh = crypto::sha256(script_pubkey);

  Tx receive_tx;
  receive_tx.inputs.push_back(TxIn{zero_hash(), 0, Bytes{}, 0xFFFFFFFF});
  receive_tx.outputs.push_back(TxOut{111111111, script_pubkey});
  const Hash32 receive_txid = receive_tx.txid();
  ASSERT_TRUE(db.put_tx_index(receive_txid, 10, 0, receive_tx.serialize()));
  ASSERT_TRUE(db.add_script_history(sh, 10, receive_txid));

  OutPoint stale_indexed{receive_txid, 0};
  ASSERT_TRUE(db.put_script_utxo(sh, stale_indexed, TxOut{111111111, script_pubkey}, 10));

  OutPoint canonical_live{};
  canonical_live.txid[31] = 0x91;
  canonical_live.index = 1;
  ASSERT_TRUE(db.put_utxo(canonical_live, TxOut{222222222, script_pubkey}));
  ASSERT_TRUE(db.flush());

  const auto spendable = wallet::spendable_p2pkh_utxos_for_pubkey_hash(db, pkh, nullptr);
  ASSERT_EQ(spendable.size(), 1u);
  ASSERT_EQ(spendable[0].outpoint.txid, canonical_live.txid);
  ASSERT_EQ(spendable[0].outpoint.index, canonical_live.index);
  ASSERT_EQ(spendable[0].prevout.value, 222222222u);
}

TEST(test_lightserver_get_transition_by_height_direct) {
  const std::string base = unique_test_base("/tmp/finalis_light_block_by_height");
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);

  storage::DB db;
  ASSERT_TRUE(db.open(base));
  FrontierTransition transition;
  transition.height = 3;
  transition.round = 0;
  transition.leader_pubkey = node::Node::deterministic_test_keypairs()[0].public_key;
  transition.prev_finalized_hash[31] = 0x55;
  transition.prev_state_root[31] = 0x11;
  transition.next_state_root[31] = 0x22;
  const auto transition_hash = transition.transition_id();
  ASSERT_TRUE(db.set_tip(storage::TipState{3, transition_hash}));
  ASSERT_TRUE(db.set_height_hash(3, transition_hash));
  ASSERT_TRUE(db.put_frontier_transition(transition_hash, transition.serialize()));
  ASSERT_TRUE(db.map_height_to_frontier_transition(3, transition_hash));
  ASSERT_TRUE(db.flush());
  db.close();

  lightserver::Config lcfg;
  lcfg.db_path = base;
  lightserver::Server ls(lcfg);
  ASSERT_TRUE(ls.init());

  const auto resp =
      ls.handle_rpc_for_test(R"({"jsonrpc":"2.0","id":111,"method":"get_transition_by_height","params":{"height":3}})");
  ASSERT_TRUE(resp.find("\"height\":3") != std::string::npos);
  ASSERT_TRUE(resp.find("\"hash\":\"" + hex_encode32(transition_hash) + "\"") != std::string::npos);
  ASSERT_TRUE(resp.find("\"transition_hex\":\"" + hex_encode(transition.serialize()) + "\"") != std::string::npos);
}

TEST(test_lightserver_exposes_persisted_ingress_visibility_endpoints) {
  const std::string base = unique_test_base("/tmp/finalis_light_ingress_visibility");
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);

  const auto keys = node::Node::deterministic_test_keypairs();
  OutPoint op{};
  op.txid.fill(0x91);
  op.index = 0;
  TxOut prev{10'000, address::p2pkh_script_pubkey(crypto::h160(Bytes(keys[0].public_key.begin(), keys[0].public_key.end())))};
  auto tx = build_signed_p2pkh_tx_single_input(
      op, prev, keys[0].private_key,
      std::vector<TxOut>{TxOut{9'000, address::p2pkh_script_pubkey(crypto::h160(Bytes(keys[1].public_key.begin(), keys[1].public_key.end())))}} );
  ASSERT_TRUE(tx.has_value());
  const auto record = tx->serialize();

  storage::DB db;
  ASSERT_TRUE(db.open(base));
  ASSERT_TRUE(db.put_ingress_record(11, record));
  ASSERT_TRUE(db.set_finalized_ingress_tip(11));
  ASSERT_TRUE(db.flush());
  db.close();

  lightserver::Config lcfg;
  lcfg.db_path = base;
  lightserver::Server ls(lcfg);
  ASSERT_TRUE(ls.init());

  const auto tip_resp = ls.handle_rpc_for_test(R"({"jsonrpc":"2.0","id":201,"method":"get_ingress_tip","params":{}})");
  ASSERT_TRUE(tip_resp.find("\"ingress_tip\":11") != std::string::npos);

  const auto record_resp =
      ls.handle_rpc_for_test(R"({"jsonrpc":"2.0","id":202,"method":"get_ingress_record","params":{"seq":11}})");
  ASSERT_TRUE(record_resp.find("\"seq\":11") != std::string::npos);
  ASSERT_TRUE(record_resp.find("\"present\":true") != std::string::npos);
  ASSERT_TRUE(record_resp.find("\"txid\":\"" + hex_encode32(tx->txid()) + "\"") != std::string::npos);

  const auto missing_resp =
      ls.handle_rpc_for_test(R"({"jsonrpc":"2.0","id":203,"method":"get_ingress_record","params":{"seq":12}})");
  ASSERT_TRUE(missing_resp.find("\"seq\":12") != std::string::npos);
  ASSERT_TRUE(missing_resp.find("\"present\":false") != std::string::npos);

  const auto range_resp =
      ls.handle_rpc_for_test(R"({"jsonrpc":"2.0","id":204,"method":"get_ingress_range","params":{"start":11,"end":12}})");
  ASSERT_TRUE(range_resp.find("\"complete\":false") != std::string::npos);
  ASSERT_TRUE(range_resp.find("\"seq\":11") != std::string::npos);
  ASSERT_TRUE(range_resp.find("\"seq\":12") != std::string::npos);
}

TEST(test_lightserver_verify_ingress_slice_fails_closed_on_missing_or_corrupt_records) {
  const std::string base = unique_test_base("/tmp/finalis_light_ingress_verify");
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);

  const auto keys = node::Node::deterministic_test_keypairs();
  OutPoint op{};
  op.txid.fill(0xA1);
  op.index = 0;
  TxOut prev{10'000, address::p2pkh_script_pubkey(crypto::h160(Bytes(keys[0].public_key.begin(), keys[0].public_key.end())))};
  auto tx_a = build_signed_p2pkh_tx_single_input(
      op, prev, keys[0].private_key,
      std::vector<TxOut>{TxOut{9'000, address::p2pkh_script_pubkey(crypto::h160(Bytes(keys[1].public_key.begin(), keys[1].public_key.end())))}} );
  ASSERT_TRUE(tx_a.has_value());
  auto corrupt = tx_a->serialize();
  corrupt.push_back(0xFF);

  storage::DB db;
  ASSERT_TRUE(db.open(base));
  ASSERT_TRUE(db.put_ingress_record(21, tx_a->serialize()));
  ASSERT_TRUE(db.put_ingress_record(22, corrupt));
  ASSERT_TRUE(db.set_finalized_ingress_tip(22));
  ASSERT_TRUE(db.flush());
  db.close();

  lightserver::Config lcfg;
  lcfg.db_path = base;
  lightserver::Server ls(lcfg);
  ASSERT_TRUE(ls.init());

  const auto verify_ok =
      ls.handle_rpc_for_test(R"({"jsonrpc":"2.0","id":205,"method":"verify_ingress_slice","params":{"start":21,"end":21}})");
  ASSERT_TRUE(verify_ok.find("\"verified\":true") != std::string::npos);
  ASSERT_TRUE(verify_ok.find("\"slice_commitment\"") != std::string::npos);

  const auto verify_missing =
      ls.handle_rpc_for_test(R"({"jsonrpc":"2.0","id":206,"method":"verify_ingress_slice","params":{"start":21,"end":23}})");
  ASSERT_TRUE(verify_missing.find("\"verified\":false") != std::string::npos);
  ASSERT_TRUE(verify_missing.find("missing-seq-23") != std::string::npos);

  const auto range_corrupt =
      ls.handle_rpc_for_test(R"({"jsonrpc":"2.0","id":207,"method":"get_ingress_range","params":{"start":21,"end":22}})");
  ASSERT_TRUE(range_corrupt.find("\"complete\":true") != std::string::npos);
  ASSERT_TRUE(range_corrupt.find("\"seq\":22") != std::string::npos);
}

TEST(test_lightserver_exposes_lane_scoped_ingress_observability_endpoints) {
  const std::string base = unique_test_base("/tmp/finalis_light_ingress_lane_visibility");
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);

  Tx tx;
  tx.version = 1;
  tx.outputs.push_back(TxOut{42, Bytes{'l', 'a', 'n', 'e'}});
  const auto tx_bytes = tx.serialize();
  const auto lane = consensus::assign_ingress_lane(tx);

  IngressCertificate cert;
  cert.epoch = 1;
  cert.lane = lane;
  cert.seq = 1;
  cert.txid = tx.txid();
  cert.tx_hash = crypto::sha256d(tx_bytes);
  cert.prev_lane_root = zero_hash();

  storage::DB db;
  ASSERT_TRUE(db.open(base));
  ASSERT_TRUE(db.put_ingress_bytes(cert.txid, tx_bytes));
  ASSERT_TRUE(db.put_ingress_certificate(cert.lane, cert.seq, cert.serialize()));
  ASSERT_TRUE(db.put_lane_state(cert.lane, LaneState{cert.epoch, cert.lane, cert.seq,
                                                     consensus::compute_lane_root_append(zero_hash(), cert.tx_hash)}));
  ASSERT_TRUE(db.flush());
  db.close();

  lightserver::Config lcfg;
  lcfg.db_path = base;
  lightserver::Server ls(lcfg);
  ASSERT_TRUE(ls.init());

  const auto tip_resp = ls.handle_rpc_for_test(std::string(
      "{\"jsonrpc\":\"2.0\",\"id\":301,\"method\":\"get_ingress_lane_tip\",\"params\":{\"lane\":") +
                                               std::to_string(lane) + "}}");
  ASSERT_TRUE(tip_resp.find("\"lane\":" + std::to_string(lane)) != std::string::npos);
  ASSERT_TRUE(tip_resp.find("\"tip_seq\":1") != std::string::npos);

  const auto record_resp = ls.handle_rpc_for_test(std::string(
      "{\"jsonrpc\":\"2.0\",\"id\":302,\"method\":\"get_ingress_record\",\"params\":{\"lane\":") +
                                                  std::to_string(lane) + ",\"seq\":1}}");
  ASSERT_TRUE(record_resp.find("\"present\":true") != std::string::npos);
  ASSERT_TRUE(record_resp.find("\"txid\":\"" + hex_encode32(cert.txid) + "\"") != std::string::npos);
  ASSERT_TRUE(record_resp.find("\"bytes_present\":true") != std::string::npos);

  const auto range_resp = ls.handle_rpc_for_test(std::string(
      "{\"jsonrpc\":\"2.0\",\"id\":303,\"method\":\"get_ingress_range\",\"params\":{\"lane\":") +
                                                 std::to_string(lane) + ",\"from_seq\":1,\"to_seq\":1}}");
  ASSERT_TRUE(range_resp.find("\"complete\":true") != std::string::npos);
  ASSERT_TRUE(range_resp.find("\"seq\":1") != std::string::npos);

  const auto verify_resp = ls.handle_rpc_for_test(std::string(
      "{\"jsonrpc\":\"2.0\",\"id\":304,\"method\":\"verify_ingress_slice\",\"params\":{\"lane\":") +
                                                  std::to_string(lane) + ",\"from_seq\":1,\"to_seq\":1}}");
  ASSERT_TRUE(verify_resp.find("\"verified\":true") != std::string::npos);
}

TEST(test_lightserver_get_status_exposes_runtime_sync_summary) {
  const std::string base = unique_test_base("/tmp/finalis_light_status_direct");
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);

  storage::DB db;
  ASSERT_TRUE(db.open(base));
  Hash32 tip_hash{};
  tip_hash[31] = 0x44;
  ASSERT_TRUE(db.set_tip(storage::TipState{12, tip_hash}));
  storage::NodeRuntimeStatusSnapshot snapshot;
  snapshot.chain_id_ok = true;
  snapshot.db_open = true;
  snapshot.local_finalized_height = 12;
  snapshot.observed_network_height_known = true;
  snapshot.observed_network_finalized_height = 15;
  snapshot.healthy_peer_count = 2;
  snapshot.established_peer_count = 3;
  snapshot.finalized_lag = 3;
  snapshot.peer_height_disagreement = false;
  snapshot.next_height_committee_available = true;
  snapshot.next_height_proposer_available = true;
  snapshot.bootstrap_sync_incomplete = true;
  snapshot.mempool_tx_count = 42;
  snapshot.mempool_bytes = 8192;
  snapshot.mempool_full = true;
  snapshot.min_fee_rate_to_enter_when_full_milliunits_per_byte = 1500;
  snapshot.rejected_full_not_good_enough = 7;
  snapshot.evicted_for_better_incoming = 3;
  snapshot.min_relay_fee = 1000;
  snapshot.availability_epoch = 9;
  snapshot.availability_retained_prefix_count = 5;
  snapshot.availability_tracked_operator_count = 2;
  snapshot.availability_eligible_operator_count = 1;
  snapshot.availability_below_min_eligible = true;
  snapshot.adaptive_target_committee_size = 24;
  snapshot.adaptive_min_eligible = 27;
  snapshot.adaptive_min_bond = 150ULL * consensus::BASE_UNITS_PER_COIN;
  snapshot.qualified_depth = 26;
  snapshot.adaptive_slack = -1;
  snapshot.target_expand_streak = 3;
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
  snapshot.availability_local_operator_known = true;
  snapshot.availability_local_operator_pubkey.fill(0x21);
  snapshot.availability_local_operator_status =
      static_cast<std::uint8_t>(availability::AvailabilityOperatorStatus::WARMUP);
  snapshot.availability_local_service_score = 7;
  snapshot.availability_local_warmup_epochs = 3;
  snapshot.availability_local_successful_audits = 4;
  snapshot.availability_local_late_audits = 1;
  snapshot.availability_local_missed_audits = 2;
  snapshot.availability_local_invalid_audits = 0;
  snapshot.availability_local_retained_prefix_count = 5;
  snapshot.availability_local_eligibility_score = 13;
  snapshot.availability_local_seat_budget = 1;
  ASSERT_TRUE(db.put_node_runtime_status_snapshot(snapshot));
  storage::AdaptiveEpochTelemetry telemetry;
  telemetry.epoch_start_height = 1;
  telemetry.derivation_height = 0;
  telemetry.qualified_depth = 26;
  telemetry.adaptive_target_committee_size = 24;
  telemetry.adaptive_min_eligible = 27;
  telemetry.adaptive_min_bond = 150ULL * consensus::BASE_UNITS_PER_COIN;
  telemetry.slack = -1;
  telemetry.target_expand_streak = 3;
  telemetry.target_contract_streak = 0;
  telemetry.derivation_mode = storage::FinalizedCommitteeDerivationMode::FALLBACK;
  telemetry.fallback_reason = storage::FinalizedCommitteeFallbackReason::HYSTERESIS_RECOVERY_PENDING;
  telemetry.fallback_sticky = true;
  telemetry.committee_size_selected = 16;
  telemetry.eligible_operator_count = 1;
  ASSERT_TRUE(db.put_adaptive_epoch_telemetry(telemetry));
  ASSERT_TRUE(db.flush());
  db.close();

  lightserver::Config lcfg;
  lcfg.db_path = base;
  lightserver::Server ls(lcfg);
  ASSERT_TRUE(ls.init());

  const auto resp = ls.handle_rpc_for_test(R"({"jsonrpc":"2.0","id":121,"method":"get_status","params":{}})");
  ASSERT_TRUE(resp.find("\"finalized_tip\"") != std::string::npos);
  ASSERT_TRUE(resp.find("\"finalized_height\":12") != std::string::npos);
  ASSERT_TRUE(resp.find("\"finalized_transition_hash\":\"" + hex_encode32(tip_hash) + "\"") != std::string::npos);
  ASSERT_TRUE(resp.find("\"healthy_peer_count\":2") != std::string::npos);
  ASSERT_TRUE(resp.find("\"established_peer_count\":3") != std::string::npos);
  ASSERT_TRUE(resp.find("\"binary\":\"finalis-lightserver\"") != std::string::npos);
  ASSERT_TRUE(resp.find("\"binary_version\":\"finalis-lightserver/0.7\"") != std::string::npos);
  ASSERT_TRUE(resp.find("\"release\":\"0.7\"") != std::string::npos);
  ASSERT_TRUE(resp.find("\"wallet_api_version\":\"FINALIS_WALLET_API_V1\"") != std::string::npos);
  ASSERT_TRUE(resp.find("\"snapshot_present\":true") != std::string::npos);
  ASSERT_TRUE(resp.find("\"observed_network_finalized_height\":15") != std::string::npos);
  ASSERT_TRUE(resp.find("\"finalized_lag\":3") != std::string::npos);
  ASSERT_TRUE(resp.find("\"bootstrap_sync_incomplete\":true") != std::string::npos);
  ASSERT_TRUE(resp.find("\"mempool_size\":42") != std::string::npos);
  ASSERT_TRUE(resp.find("\"mempool\":{\"tx_count\":42") != std::string::npos);
  ASSERT_TRUE(resp.find("\"bytes\":8192") != std::string::npos);
  ASSERT_TRUE(resp.find("\"full\":true") != std::string::npos);
  ASSERT_TRUE(resp.find("\"min_fee_rate_to_enter_when_full\":1500") != std::string::npos);
  ASSERT_TRUE(resp.find("\"rejected_full_not_good_enough\":7") != std::string::npos);
  ASSERT_TRUE(resp.find("\"evicted_for_better_incoming\":3") != std::string::npos);
  ASSERT_TRUE(resp.find("\"min_relay_fee\":1000") != std::string::npos);
  ASSERT_TRUE(resp.find("\"availability\":{\"epoch\":9") != std::string::npos);
  ASSERT_TRUE(resp.find("\"retained_prefix_count\":5") != std::string::npos);
  ASSERT_TRUE(resp.find("\"tracked_operator_count\":2") != std::string::npos);
  ASSERT_TRUE(resp.find("\"eligible_operator_count\":1") != std::string::npos);
  ASSERT_TRUE(resp.find("\"below_min_eligible\":true") != std::string::npos);
  ASSERT_TRUE(resp.find("\"checkpoint_derivation_mode\":\"fallback\"") != std::string::npos);
  ASSERT_TRUE(resp.find("\"checkpoint_fallback_reason\":\"hysteresis_recovery_pending\"") != std::string::npos);
  ASSERT_TRUE(resp.find("\"fallback_sticky\":true") != std::string::npos);
  ASSERT_TRUE(resp.find("\"adaptive_target_committee_size\":24") != std::string::npos);
  ASSERT_TRUE(resp.find("\"adaptive_min_eligible\":27") != std::string::npos);
  ASSERT_TRUE(resp.find("\"adaptive_min_bond\":15000000000") != std::string::npos);
  ASSERT_TRUE(resp.find("\"qualified_depth\":26") != std::string::npos);
  ASSERT_TRUE(resp.find("\"slack\":-1") != std::string::npos);
  ASSERT_TRUE(resp.find("\"target_expand_streak\":3") != std::string::npos);
  ASSERT_TRUE(resp.find("\"fallback_rate_bps\":2500") != std::string::npos);
  ASSERT_TRUE(resp.find("\"sticky_fallback_rate_bps\":1250") != std::string::npos);
  ASSERT_TRUE(resp.find("\"near_threshold_operation\":true") != std::string::npos);
  ASSERT_TRUE(resp.find("\"repeated_sticky_fallback\":true") != std::string::npos);
  ASSERT_TRUE(resp.find("\"state_rebuild_triggered\":true") != std::string::npos);
  ASSERT_TRUE(resp.find("\"state_rebuild_reason\":\"invalid_persisted_state\"") != std::string::npos);
  ASSERT_TRUE(resp.find("\"status\":\"WARMUP\"") != std::string::npos);
  ASSERT_TRUE(resp.find("\"service_score\":7") != std::string::npos);
  ASSERT_TRUE(resp.find("\"seat_budget\":1") != std::string::npos);
}

TEST(test_lightserver_get_adaptive_telemetry_exposes_persisted_snapshots) {
  const std::string base = unique_test_base("/tmp/finalis_light_adaptive_telemetry");
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);

  storage::DB db;
  ASSERT_TRUE(db.open(base));
  Hash32 tip_hash{};
  tip_hash[31] = 0x71;
  ASSERT_TRUE(db.set_tip(storage::TipState{64, tip_hash}));
  storage::AdaptiveEpochTelemetry telemetry;
  telemetry.epoch_start_height = 48;
  telemetry.derivation_height = 47;
  telemetry.qualified_depth = 30;
  telemetry.adaptive_target_committee_size = 24;
  telemetry.adaptive_min_eligible = 27;
  telemetry.adaptive_min_bond = 150ULL * consensus::BASE_UNITS_PER_COIN;
  telemetry.slack = 3;
  telemetry.target_expand_streak = 4;
  telemetry.derivation_mode = storage::FinalizedCommitteeDerivationMode::NORMAL;
  telemetry.fallback_reason = storage::FinalizedCommitteeFallbackReason::NONE;
  telemetry.committee_size_selected = 24;
  telemetry.eligible_operator_count = 30;
  ASSERT_TRUE(db.put_adaptive_epoch_telemetry(telemetry));
  ASSERT_TRUE(db.flush());
  db.close();

  lightserver::Config lcfg;
  lcfg.db_path = base;
  lightserver::Server ls(lcfg);
  ASSERT_TRUE(ls.init());

  const auto resp =
      ls.handle_rpc_for_test(R"({"jsonrpc":"2.0","id":122,"method":"get_adaptive_telemetry","params":{"limit":4}})");
  ASSERT_TRUE(resp.find("\"window_epochs\":4") != std::string::npos);
  ASSERT_TRUE(resp.find("\"epoch_start_height\":48") != std::string::npos);
  ASSERT_TRUE(resp.find("\"qualified_depth\":30") != std::string::npos);
  ASSERT_TRUE(resp.find("\"adaptive_target_committee_size\":24") != std::string::npos);
  ASSERT_TRUE(resp.find("\"checkpoint_derivation_mode\":\"normal\"") != std::string::npos);
}

TEST(test_lightserver_broadcast_returns_structured_duplicate_code_for_finalized_tx) {
  const std::string base = unique_test_base("/tmp/finalis_light_broadcast_duplicate");
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);

  const auto keys = node::Node::deterministic_test_keypairs();
  storage::DB db;
  ASSERT_TRUE(db.open(base));
  Hash32 tip_hash{};
  tip_hash[31] = 0x91;
  ASSERT_TRUE(db.set_tip(storage::TipState{5, tip_hash}));

  OutPoint op{};
  op.txid.fill(0x55);
  op.index = 0;
  TxOut prev{10'000, address::p2pkh_script_pubkey(crypto::h160(Bytes(keys[0].public_key.begin(), keys[0].public_key.end())))};
  ASSERT_TRUE(db.put_utxo(op, prev));
  auto tx = build_signed_p2pkh_tx_single_input(
      op, prev, keys[0].private_key,
      std::vector<TxOut>{TxOut{9'000, address::p2pkh_script_pubkey(crypto::h160(Bytes(keys[1].public_key.begin(), keys[1].public_key.end())))}} );
  ASSERT_TRUE(tx.has_value());
  ASSERT_TRUE(db.put_tx_index(tx->txid(), 4, 1, tx->serialize()));
  ASSERT_TRUE(db.flush());
  db.close();

  lightserver::Config lcfg;
  lcfg.db_path = base;
  lightserver::Server ls(lcfg);
  ASSERT_TRUE(ls.init());

  const std::string body = std::string(R"({"jsonrpc":"2.0","id":401,"method":"broadcast_tx","params":{"tx_hex":")") +
                           hex_encode(tx->serialize()) + R"("}})";
  const auto resp = ls.handle_rpc_for_test(body);
  ASSERT_TRUE(resp.find("\"accepted\":false") != std::string::npos);
  ASSERT_TRUE(resp.find("\"error_code\":\"tx_duplicate\"") != std::string::npos);
  ASSERT_TRUE(resp.find("\"retryable\":false") != std::string::npos);
  ASSERT_TRUE(resp.find("\"retry_class\":\"none\"") != std::string::npos);
}

TEST(test_lightserver_broadcast_returns_structured_invalid_code) {
  const std::string base = unique_test_base("/tmp/finalis_light_broadcast_invalid");
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);

  storage::DB db;
  ASSERT_TRUE(db.open(base));
  Hash32 tip_hash{};
  tip_hash[31] = 0x92;
  ASSERT_TRUE(db.set_tip(storage::TipState{5, tip_hash}));
  ASSERT_TRUE(db.flush());
  db.close();

  Tx invalid;
  invalid.version = 1;
  invalid.lock_time = 0;
  invalid.inputs.push_back(TxIn{zero_hash(), 0, Bytes{}, 0xFFFFFFFF});

  lightserver::Config lcfg;
  lcfg.db_path = base;
  lightserver::Server ls(lcfg);
  ASSERT_TRUE(ls.init());

  const std::string body = std::string(R"({"jsonrpc":"2.0","id":402,"method":"broadcast_tx","params":{"tx_hex":")") +
                           hex_encode(invalid.serialize()) + R"("}})";
  const auto resp = ls.handle_rpc_for_test(body);
  ASSERT_TRUE(resp.find("\"accepted\":false") != std::string::npos);
  ASSERT_TRUE(resp.find("\"error_code\":\"tx_invalid\"") != std::string::npos);
  ASSERT_TRUE(resp.find("\"retryable\":false") != std::string::npos);
  ASSERT_TRUE(resp.find("\"retry_class\":\"none\"") != std::string::npos);
}

TEST(test_lightserver_broadcast_returns_mempool_pressure_rejection_from_runtime_snapshot) {
  const std::string base = unique_test_base("/tmp/finalis_light_broadcast_pressure");
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);

  const auto keys = node::Node::deterministic_test_keypairs();
  storage::DB db;
  ASSERT_TRUE(db.open(base));
  Hash32 tip_hash{};
  tip_hash[31] = 0x93;
  ASSERT_TRUE(db.set_tip(storage::TipState{8, tip_hash}));

  storage::NodeRuntimeStatusSnapshot snapshot;
  snapshot.chain_id_ok = true;
  snapshot.db_open = true;
  snapshot.local_finalized_height = 8;
  snapshot.mempool_tx_count = mempool::Mempool::kMaxTxCount;
  snapshot.mempool_bytes = 1024;
  snapshot.mempool_full = true;
  snapshot.min_fee_rate_to_enter_when_full_milliunits_per_byte = 10000;
  snapshot.min_relay_fee = 1000;
  ASSERT_TRUE(db.put_node_runtime_status_snapshot(snapshot));

  OutPoint op{};
  op.txid.fill(0x56);
  op.index = 0;
  TxOut prev{10'000, address::p2pkh_script_pubkey(crypto::h160(Bytes(keys[0].public_key.begin(), keys[0].public_key.end())))};
  ASSERT_TRUE(db.put_utxo(op, prev));
  ASSERT_TRUE(db.flush());
  db.close();

  auto tx = build_signed_p2pkh_tx_single_input(
      op, prev, keys[0].private_key,
      std::vector<TxOut>{TxOut{9'000, address::p2pkh_script_pubkey(crypto::h160(Bytes(keys[1].public_key.begin(), keys[1].public_key.end())))}} );
  ASSERT_TRUE(tx.has_value());

  lightserver::Config lcfg;
  lcfg.db_path = base;
  lightserver::Server ls(lcfg);
  ASSERT_TRUE(ls.init());

  const std::string body = std::string(R"({"jsonrpc":"2.0","id":403,"method":"broadcast_tx","params":{"tx_hex":")") +
                           hex_encode(tx->serialize()) + R"("}})";
  const auto resp = ls.handle_rpc_for_test(body);
  ASSERT_TRUE(resp.find("\"accepted\":false") != std::string::npos);
  ASSERT_TRUE(resp.find("\"error_code\":\"mempool_full_not_good_enough\"") != std::string::npos);
  ASSERT_TRUE(resp.find("\"retryable\":true") != std::string::npos);
  ASSERT_TRUE(resp.find("\"retry_class\":\"after_fee_bump\"") != std::string::npos);
  ASSERT_TRUE(resp.find("\"mempool_full\":true") != std::string::npos);
  ASSERT_TRUE(resp.find("\"min_fee_rate_to_enter_when_full\":10000") != std::string::npos);
}

TEST(test_lightserver_broadcast_returns_relay_unavailable_code_when_relay_path_fails) {
  const std::string base = unique_test_base("/tmp/finalis_light_broadcast_relay_unavailable");
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);

  const auto keys = node::Node::deterministic_test_keypairs();
  storage::DB db;
  ASSERT_TRUE(db.open(base));
  Hash32 tip_hash{};
  tip_hash[31] = 0x95;
  ASSERT_TRUE(db.set_tip(storage::TipState{8, tip_hash}));

  OutPoint op{};
  op.txid.fill(0x58);
  op.index = 0;
  TxOut prev{10'000, address::p2pkh_script_pubkey(crypto::h160(Bytes(keys[0].public_key.begin(), keys[0].public_key.end())))};
  ASSERT_TRUE(db.put_utxo(op, prev));
  ASSERT_TRUE(db.flush());
  db.close();

  auto tx = build_signed_p2pkh_tx_single_input(
      op, prev, keys[0].private_key,
      std::vector<TxOut>{TxOut{9'000, address::p2pkh_script_pubkey(crypto::h160(Bytes(keys[1].public_key.begin(), keys[1].public_key.end())))}} );
  ASSERT_TRUE(tx.has_value());

  lightserver::Config lcfg;
  lcfg.db_path = base;
  lcfg.tx_relay_override = [](const Bytes&, std::string* err) {
    if (err) *err = "connect relay peer failed";
    return false;
  };
  lightserver::Server ls(lcfg);
  ASSERT_TRUE(ls.init());

  const std::string body = std::string(R"({"jsonrpc":"2.0","id":404,"method":"broadcast_tx","params":{"tx_hex":")") +
                           hex_encode(tx->serialize()) + R"("}})";
  const auto resp = ls.handle_rpc_for_test(body);
  ASSERT_TRUE(resp.find("\"accepted\":false") != std::string::npos);
  ASSERT_TRUE(resp.find("\"error_code\":\"relay_unavailable\"") != std::string::npos);
  ASSERT_TRUE(resp.find("\"retryable\":true") != std::string::npos);
  ASSERT_TRUE(resp.find("\"retry_class\":\"transport\"") != std::string::npos);
}

TEST(test_lightserver_broadcast_returns_structured_success_when_relaying_to_live_node) {
  const std::string base = unique_test_base("/tmp/finalis_light_broadcast_success");
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);

  const auto keys = node::Node::deterministic_test_keypairs();
  storage::DB db;
  ASSERT_TRUE(db.open(base));
  Hash32 tip_hash{};
  tip_hash[31] = 0x94;
  ASSERT_TRUE(db.set_tip(storage::TipState{8, tip_hash}));

  OutPoint op{};
  op.txid.fill(0x57);
  op.index = 0;
  TxOut prev{10'000, address::p2pkh_script_pubkey(crypto::h160(Bytes(keys[0].public_key.begin(), keys[0].public_key.end())))};
  ASSERT_TRUE(db.put_utxo(op, prev));
  ASSERT_TRUE(db.flush());
  db.close();

  auto tx = build_signed_p2pkh_tx_single_input(
      op, prev, keys[0].private_key,
      std::vector<TxOut>{TxOut{9'000, address::p2pkh_script_pubkey(crypto::h160(Bytes(keys[1].public_key.begin(), keys[1].public_key.end())))}} );
  ASSERT_TRUE(tx.has_value());

  lightserver::Config lcfg;
  lcfg.db_path = base;
  lcfg.tx_relay_override = [](const Bytes&, std::string*) { return true; };
  lightserver::Server ls(lcfg);
  ASSERT_TRUE(ls.init());

  const std::string body = std::string(R"({"jsonrpc":"2.0","id":404,"method":"broadcast_tx","params":{"tx_hex":")") +
                           hex_encode(tx->serialize()) + R"("}})";
  const auto resp = ls.handle_rpc_for_test(body);
  ASSERT_TRUE(resp.find("\"accepted\":true") != std::string::npos);
  ASSERT_TRUE(resp.find("\"status\":\"accepted_for_relay\"") != std::string::npos);
  ASSERT_TRUE(resp.find("\"txid\":\"" + hex_encode32(tx->txid()) + "\"") != std::string::npos);
  ASSERT_TRUE(resp.find("\"message\":\"accepted_for_relay\"") != std::string::npos);
  ASSERT_TRUE(resp.find("\"retry_class\":\"none\"") != std::string::npos);
}

TEST(test_lightserver_verbose_committee_uses_checkpoint_operator_metadata_when_present) {
  const std::string base = unique_test_base("/tmp/finalis_light_checkpoint_committee_verbose");
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);

  storage::DB db;
  ASSERT_TRUE(db.open(base));

  Hash32 tip_hash{};
  tip_hash[31] = 0x25;
  ASSERT_TRUE(db.set_tip(storage::TipState{1025, tip_hash}));

  storage::FinalizedCommitteeCheckpoint checkpoint;
  checkpoint.epoch_start_height = 1025;
  checkpoint.ticket_difficulty_bits = 10;
  checkpoint.derivation_mode = storage::FinalizedCommitteeDerivationMode::FALLBACK;
  checkpoint.fallback_reason = storage::FinalizedCommitteeFallbackReason::INSUFFICIENT_ELIGIBLE_OPERATORS;
  checkpoint.availability_eligible_operator_count = 1;
  checkpoint.availability_min_eligible_operators = 2;
  PubKey32 rep{};
  rep[31] = 0x01;
  PubKey32 op{};
  op[31] = 0x02;
  Hash32 ticket_hash{};
  ticket_hash[31] = 0x03;
  checkpoint.ordered_members.push_back(rep);
  checkpoint.ordered_operator_ids.push_back(op);
  checkpoint.ordered_base_weights.push_back(100);
  checkpoint.ordered_ticket_bonus_bps.push_back(1000);
  checkpoint.ordered_final_weights.push_back(1010000);
  checkpoint.ordered_ticket_hashes.push_back(ticket_hash);
  checkpoint.ordered_ticket_nonces.push_back(12);
  ASSERT_TRUE(db.put_finalized_committee_checkpoint(checkpoint));
  ASSERT_TRUE(db.flush());
  db.close();

  lightserver::Config cfg;
  cfg.db_path = base;
  lightserver::Server ls(cfg);
  ASSERT_TRUE(ls.init());

  const auto resp =
      ls.handle_rpc_for_test(R"({"jsonrpc":"2.0","id":160,"method":"get_committee","params":{"height":1025,"verbose":true}})");
  ASSERT_TRUE(resp.find("\"members\"") != std::string::npos);
  ASSERT_TRUE(resp.find("\"operator_id\":\"0000000000000000000000000000000000000000000000000000000000000002\"") != std::string::npos);
  ASSERT_TRUE(resp.find("\"representative_pubkey\":\"0000000000000000000000000000000000000000000000000000000000000001\"") != std::string::npos);
  ASSERT_TRUE(resp.find("\"checkpoint_derivation_mode\":\"fallback\"") != std::string::npos);
  ASSERT_TRUE(resp.find("\"checkpoint_fallback_reason\":\"insufficient_eligible_operators\"") != std::string::npos);
  ASSERT_TRUE(resp.find("\"fallback_sticky\":false") != std::string::npos);
  ASSERT_TRUE(resp.find("\"availability_eligible_operator_count\":1") != std::string::npos);
  ASSERT_TRUE(resp.find("\"availability_min_eligible_operators\":2") != std::string::npos);
  ASSERT_TRUE(resp.find("\"base_weight\":100") != std::string::npos);
  ASSERT_TRUE(resp.find("\"ticket_bonus_bps\":1000") != std::string::npos);
  ASSERT_TRUE(resp.find("\"final_weight\":1010000") != std::string::npos);
}

TEST(test_lightserver_validate_address_reports_network_and_error_reason) {
  const std::string base = unique_test_base("/tmp/finalis_light_validate_address");
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);

  storage::DB db;
  ASSERT_TRUE(db.open(base));
  genesis::Document d;
  d.version = 1;
  d.network_name = "mainnet";
  d.protocol_version = mainnet_network().protocol_version;
  d.network_id = mainnet_network().network_id;
  d.magic = mainnet_network().magic;
  d.genesis_time_unix = 1735689600ULL;
  d.initial_height = 0;
  d.initial_active_set_size = 1;
  d.initial_committee_params.min_committee = 1;
  d.initial_committee_params.max_committee = static_cast<std::uint32_t>(mainnet_network().max_committee);
  d.initial_committee_params.sizing_rule = "min(MAX_COMMITTEE,ACTIVE_SIZE)";
  d.initial_committee_params.c = 2;
  d.monetary_params_ref = "test";
  d.seeds = {};
  d.note = "lightserver-validate-address";
  d.initial_validators.push_back(node::Node::deterministic_test_keypairs()[0].public_key);
  const auto genesis_json = genesis::to_json(d);
  ASSERT_TRUE(db.put(storage::key_genesis_json(), Bytes(genesis_json.begin(), genesis_json.end())));
  ASSERT_TRUE(db.flush());
  db.close();

  const auto kp = node::Node::deterministic_test_keypairs()[0];
  const auto pkh = crypto::h160(Bytes(kp.public_key.begin(), kp.public_key.end()));
  const auto mainnet_address = address::encode_p2pkh("sc", pkh);
  const auto testnet_address = address::encode_p2pkh("tsc", pkh);
  ASSERT_TRUE(mainnet_address.has_value());
  ASSERT_TRUE(testnet_address.has_value());

  lightserver::Config lcfg;
  lcfg.db_path = base;
  lightserver::Server ls(lcfg);
  ASSERT_TRUE(ls.init());

  const std::string valid_q =
      std::string(R"({"jsonrpc":"2.0","id":126,"method":"validate_address","params":{"address":")") +
      *mainnet_address + R"("}})";
  const auto valid_resp = ls.handle_rpc_for_test(valid_q);
  ASSERT_TRUE(valid_resp.find("\"valid\":true") != std::string::npos);
  ASSERT_TRUE(valid_resp.find("\"normalized_address\":\"" + *mainnet_address + "\"") != std::string::npos);
  ASSERT_TRUE(valid_resp.find("\"network_hint\":\"mainnet\"") != std::string::npos);
  ASSERT_TRUE(valid_resp.find("\"server_network_hrp\":\"sc\"") != std::string::npos);
  ASSERT_TRUE(valid_resp.find("\"server_network_match\":true") != std::string::npos);
  ASSERT_TRUE(valid_resp.find("\"addr_type\":\"p2pkh\"") != std::string::npos);
  ASSERT_TRUE(valid_resp.find("\"scripthash_hex\":\"") != std::string::npos);

  const std::string wrong_network_q =
      std::string(R"({"jsonrpc":"2.0","id":127,"method":"validate_address","params":{"address":")") +
      *testnet_address + R"("}})";
  const auto wrong_network_resp = ls.handle_rpc_for_test(wrong_network_q);
  ASSERT_TRUE(wrong_network_resp.find("\"valid\":true") != std::string::npos);
  ASSERT_TRUE(wrong_network_resp.find("\"server_network_match\":false") != std::string::npos);
  ASSERT_TRUE(wrong_network_resp.find("\"network_hint\":\"test_or_dev\"") != std::string::npos);

  std::string bad_checksum = *mainnet_address;
  bad_checksum.back() = (bad_checksum.back() == 'a') ? 'b' : 'a';
  const std::string invalid_q =
      std::string(R"({"jsonrpc":"2.0","id":128,"method":"validate_address","params":{"address":")") +
      bad_checksum + R"("}})";
  const auto invalid_resp = ls.handle_rpc_for_test(invalid_q);
  ASSERT_TRUE(invalid_resp.find("\"valid\":false") != std::string::npos);
  ASSERT_TRUE(invalid_resp.find("\"error\":\"checksum mismatch\"") != std::string::npos);
  ASSERT_TRUE(invalid_resp.find("\"server_network_hrp\":\"sc\"") != std::string::npos);
}

TEST(test_lightserver_history_page_is_deterministic) {
  const std::string base = unique_test_base("/tmp/finalis_light_history_page");
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);

  storage::DB db;
  ASSERT_TRUE(db.open(base));
  genesis::Document d;
  d.version = 1;
  d.network_name = "mainnet";
  d.protocol_version = mainnet_network().protocol_version;
  d.network_id = mainnet_network().network_id;
  d.magic = mainnet_network().magic;
  d.genesis_time_unix = 1735689600ULL;
  d.initial_height = 0;
  d.initial_active_set_size = 1;
  d.initial_committee_params.min_committee = 1;
  d.initial_committee_params.max_committee = static_cast<std::uint32_t>(mainnet_network().max_committee);
  d.initial_committee_params.sizing_rule = "min(MAX_COMMITTEE,ACTIVE_SIZE)";
  d.initial_committee_params.c = 2;
  d.monetary_params_ref = "test";
  d.seeds = {};
  d.note = "lightserver-history-page";
  d.initial_validators.push_back(node::Node::deterministic_test_keypairs()[0].public_key);
  const auto genesis_json = genesis::to_json(d);
  ASSERT_TRUE(db.put(storage::key_genesis_json(), Bytes(genesis_json.begin(), genesis_json.end())));

  const auto kp = node::Node::deterministic_test_keypairs()[0];
  const auto pkh = crypto::h160(Bytes(kp.public_key.begin(), kp.public_key.end()));
  const Hash32 sh = crypto::sha256(address::p2pkh_script_pubkey(pkh));
  Hash32 txid1{};
  Hash32 txid2{};
  Hash32 txid3{};
  txid1[31] = 0x01;
  txid2[31] = 0x02;
  txid3[31] = 0x03;
  ASSERT_TRUE(db.add_script_history(sh, 7, txid2));
  ASSERT_TRUE(db.add_script_history(sh, 7, txid1));
  ASSERT_TRUE(db.add_script_history(sh, 8, txid3));
  ASSERT_TRUE(db.flush());
  db.close();

  lightserver::Config lcfg;
  lcfg.db_path = base;
  lightserver::Server ls(lcfg);
  ASSERT_TRUE(ls.init());

  const std::string page1 =
      std::string(R"({"jsonrpc":"2.0","id":131,"method":"get_history_page","params":{"scripthash_hex":")") +
      hex_encode32(sh) + R"(","limit":2}})";
  const auto resp1 = ls.handle_rpc_for_test(page1);
  const auto txid1_hex = hex_encode32(txid1);
  const auto txid2_hex = hex_encode32(txid2);
  const auto txid3_hex = hex_encode32(txid3);
  ASSERT_TRUE(resp1.find("\"has_more\":true") != std::string::npos);
  ASSERT_TRUE(resp1.find("\"ordering\":\"height_asc_txid_asc\"") != std::string::npos);
  ASSERT_TRUE(resp1.find(txid1_hex) != std::string::npos);
  ASSERT_TRUE(resp1.find(txid2_hex) != std::string::npos);
  ASSERT_TRUE(resp1.find(txid3_hex) == std::string::npos);
  ASSERT_TRUE(resp1.find(txid1_hex) < resp1.find(txid2_hex));
  ASSERT_TRUE(resp1.find("\"next_start_after\":{\"height\":7,\"txid\":\"" + txid2_hex + "\"}") != std::string::npos);

  const std::string page2 =
      std::string(R"({"jsonrpc":"2.0","id":132,"method":"get_history_page","params":{"scripthash_hex":")") +
      hex_encode32(sh) + R"(","limit":2,"start_after":{"height":7,"txid":")" + txid2_hex + R"("}}})";
  const auto resp2 = ls.handle_rpc_for_test(page2);
  ASSERT_TRUE(resp2.find("\"has_more\":false") != std::string::npos);
  ASSERT_TRUE(resp2.find(txid1_hex) == std::string::npos);
  ASSERT_TRUE(resp2.find(txid2_hex) == std::string::npos);
  ASSERT_TRUE(resp2.find(txid3_hex) != std::string::npos);
}

TEST(test_lightserver_get_utxos_supports_paged_response) {
  const std::string base = unique_test_base("/tmp/finalis_light_utxos_paged");
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);

  storage::DB db;
  ASSERT_TRUE(db.open(base));

  genesis::Document d;
  d.version = 1;
  d.network_name = "mainnet";
  d.protocol_version = mainnet_network().protocol_version;
  d.network_id = mainnet_network().network_id;
  d.magic = mainnet_network().magic;
  d.genesis_time_unix = 1735689600ULL;
  d.initial_height = 0;
  d.initial_active_set_size = 1;
  d.initial_committee_params.min_committee = 1;
  d.initial_committee_params.max_committee = static_cast<std::uint32_t>(mainnet_network().max_committee);
  d.initial_committee_params.sizing_rule = "min(MAX_COMMITTEE,ACTIVE_SIZE)";
  d.initial_committee_params.c = 2;
  d.monetary_params_ref = "test";
  d.seeds = {};
  d.note = "lightserver-utxos-page";
  d.initial_validators.push_back(node::Node::deterministic_test_keypairs()[0].public_key);
  const auto genesis_json = genesis::to_json(d);
  ASSERT_TRUE(db.put(storage::key_genesis_json(), Bytes(genesis_json.begin(), genesis_json.end())));

  const auto kp = node::Node::deterministic_test_keypairs()[0];
  const auto pkh = crypto::h160(Bytes(kp.public_key.begin(), kp.public_key.end()));
  const auto script_pubkey = address::p2pkh_script_pubkey(pkh);
  const Hash32 sh = crypto::sha256(script_pubkey);

  OutPoint op1{};
  op1.txid[31] = 0x11;
  op1.index = 0;
  OutPoint op2{};
  op2.txid[31] = 0x22;
  op2.index = 1;
  OutPoint op3{};
  op3.txid[31] = 0x33;
  op3.index = 0;
  ASSERT_TRUE(db.put_utxo(op1, TxOut{11, script_pubkey}));
  ASSERT_TRUE(db.put_utxo(op2, TxOut{22, script_pubkey}));
  ASSERT_TRUE(db.put_utxo(op3, TxOut{33, script_pubkey}));
  ASSERT_TRUE(db.put_tx_index(op1.txid, 7, 0, Bytes{0x01}));
  ASSERT_TRUE(db.put_tx_index(op2.txid, 7, 0, Bytes{0x02}));
  ASSERT_TRUE(db.put_tx_index(op3.txid, 8, 0, Bytes{0x03}));
  ASSERT_TRUE(db.put_script_utxo(sh, op1, TxOut{11, script_pubkey}, 7));
  ASSERT_TRUE(db.put_script_utxo(sh, op2, TxOut{22, script_pubkey}, 7));
  ASSERT_TRUE(db.put_script_utxo(sh, op3, TxOut{33, script_pubkey}, 8));
  ASSERT_TRUE(db.flush());
  db.close();

  lightserver::Config lcfg;
  lcfg.db_path = base;
  lightserver::Server ls(lcfg);
  ASSERT_TRUE(ls.init());

  const std::string page1 =
      std::string(R"({"jsonrpc":"2.0","id":171,"method":"get_utxos","params":{"scripthash_hex":")") + hex_encode32(sh) +
      R"(","limit":2}})";
  const auto resp1 = ls.handle_rpc_for_test(page1);
  ASSERT_TRUE(resp1.find("\"has_more\":true") != std::string::npos);
  ASSERT_TRUE(resp1.find("\"ordering\":\"height_asc_txid_asc_vout_asc\"") != std::string::npos);
  ASSERT_TRUE(resp1.find(hex_encode32(op1.txid)) != std::string::npos);
  ASSERT_TRUE(resp1.find(hex_encode32(op2.txid)) != std::string::npos);
  ASSERT_TRUE(resp1.find(hex_encode32(op3.txid)) == std::string::npos);
  ASSERT_TRUE(resp1.find("\"next_start_after\":{\"height\":7,\"txid\":\"" + hex_encode32(op2.txid) + "\",\"vout\":1}") !=
              std::string::npos);

  const std::string page2 =
      std::string(R"({"jsonrpc":"2.0","id":172,"method":"get_utxos","params":{"scripthash_hex":")") + hex_encode32(sh) +
      R"(","limit":2,"start_after":{"height":7,"txid":")" + hex_encode32(op2.txid) + R"(","vout":1}}})";
  const auto resp2 = ls.handle_rpc_for_test(page2);
  ASSERT_TRUE(resp2.find("\"has_more\":false") != std::string::npos);
  ASSERT_TRUE(resp2.find(hex_encode32(op1.txid)) == std::string::npos);
  ASSERT_TRUE(resp2.find(hex_encode32(op2.txid)) == std::string::npos);
  ASSERT_TRUE(resp2.find(hex_encode32(op3.txid)) != std::string::npos);
}

TEST(test_lightserver_get_history_page_detailed_classifies_address_relative_flow) {
  const std::string base = unique_test_base("/tmp/finalis_light_history_page_detailed");
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);

  storage::DB db;
  ASSERT_TRUE(db.open(base));

  genesis::Document d;
  d.version = 1;
  d.network_name = "mainnet";
  d.protocol_version = mainnet_network().protocol_version;
  d.network_id = mainnet_network().network_id;
  d.magic = mainnet_network().magic;
  d.genesis_time_unix = 1735689600ULL;
  d.initial_height = 0;
  d.initial_active_set_size = 1;
  d.initial_committee_params.min_committee = 1;
  d.initial_committee_params.max_committee = static_cast<std::uint32_t>(mainnet_network().max_committee);
  d.initial_committee_params.sizing_rule = "min(MAX_COMMITTEE,ACTIVE_SIZE)";
  d.initial_committee_params.c = 2;
  d.monetary_params_ref = "test";
  d.seeds = {};
  d.note = "lightserver-history-detailed";
  d.initial_validators.push_back(node::Node::deterministic_test_keypairs()[0].public_key);
  const auto genesis_json = genesis::to_json(d);
  ASSERT_TRUE(db.put(storage::key_genesis_json(), Bytes(genesis_json.begin(), genesis_json.end())));

  const auto sender_kp = node::Node::deterministic_test_keypairs()[0];
  const auto recipient_kp = node::Node::deterministic_test_keypairs()[1];
  const auto sender_pkh = crypto::h160(Bytes(sender_kp.public_key.begin(), sender_kp.public_key.end()));
  const auto recipient_pkh = crypto::h160(Bytes(recipient_kp.public_key.begin(), recipient_kp.public_key.end()));
  const auto sender_spk = address::p2pkh_script_pubkey(sender_pkh);
  const auto recipient_spk = address::p2pkh_script_pubkey(recipient_pkh);
  const Hash32 recipient_sh = crypto::sha256(recipient_spk);

  Tx prev;
  prev.version = 1;
  prev.outputs.push_back(TxOut{500, sender_spk});
  const auto prev_bytes = prev.serialize();
  const auto prev_txid = prev.txid();
  ASSERT_TRUE(db.put_tx_index(prev_txid, 7, 0, prev_bytes));

  Tx tx;
  tx.version = 1;
  tx.inputs.push_back(TxIn{prev_txid, 0, Bytes{}});
  tx.outputs.push_back(TxOut{200, recipient_spk});
  tx.outputs.push_back(TxOut{299, sender_spk});
  const auto tx_bytes = tx.serialize();
  const auto txid = tx.txid();
  ASSERT_TRUE(db.put_tx_index(txid, 8, 0, tx_bytes));
  ASSERT_TRUE(db.add_script_history(recipient_sh, 8, txid));
  ASSERT_TRUE(db.flush());
  db.close();

  lightserver::Config lcfg;
  lcfg.db_path = base;
  lightserver::Server ls(lcfg);
  ASSERT_TRUE(ls.init());

  const std::string body =
      std::string(R"({"jsonrpc":"2.0","id":173,"method":"get_history_page_detailed","params":{"scripthash_hex":")") +
      hex_encode32(recipient_sh) + R"(","limit":10}})";
  const auto resp = ls.handle_rpc_for_test(body);
  ASSERT_TRUE(resp.find("\"direction\":\"received\"") != std::string::npos);
  ASSERT_TRUE(resp.find("\"net_amount\":200") != std::string::npos);
  ASSERT_TRUE(resp.find("\"detail\":\"Finalized credit to this address\"") != std::string::npos);
}

TEST(test_lightserver_get_tx_summaries_returns_batched_finalized_tx_view) {
  const std::string base = unique_test_base("/tmp/finalis_light_tx_summaries");
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);

  storage::DB db;
  ASSERT_TRUE(db.open(base));

  genesis::Document d;
  d.version = 1;
  d.network_name = "mainnet";
  d.protocol_version = mainnet_network().protocol_version;
  d.network_id = mainnet_network().network_id;
  d.magic = mainnet_network().magic;
  d.genesis_time_unix = 1735689600ULL;
  d.initial_height = 0;
  d.initial_active_set_size = 1;
  d.initial_committee_params.min_committee = 1;
  d.initial_committee_params.max_committee = static_cast<std::uint32_t>(mainnet_network().max_committee);
  d.initial_committee_params.sizing_rule = "min(MAX_COMMITTEE,ACTIVE_SIZE)";
  d.initial_committee_params.c = 2;
  d.monetary_params_ref = "test";
  d.seeds = {};
  d.note = "lightserver-tx-summaries";
  d.initial_validators.push_back(node::Node::deterministic_test_keypairs()[0].public_key);
  const auto genesis_json = genesis::to_json(d);
  ASSERT_TRUE(db.put(storage::key_genesis_json(), Bytes(genesis_json.begin(), genesis_json.end())));

  const auto sender_kp = node::Node::deterministic_test_keypairs()[0];
  const auto recipient_kp = node::Node::deterministic_test_keypairs()[1];
  const auto sender_pkh = crypto::h160(Bytes(sender_kp.public_key.begin(), sender_kp.public_key.end()));
  const auto recipient_pkh = crypto::h160(Bytes(recipient_kp.public_key.begin(), recipient_kp.public_key.end()));
  const auto sender_spk = address::p2pkh_script_pubkey(sender_pkh);
  const auto recipient_spk = address::p2pkh_script_pubkey(recipient_pkh);

  Tx prev;
  prev.version = 1;
  prev.outputs.push_back(TxOut{500, sender_spk});
  const auto prev_bytes = prev.serialize();
  const auto prev_txid = prev.txid();
  ASSERT_TRUE(db.put_tx_index(prev_txid, 7, 0, prev_bytes));

  Tx tx;
  tx.version = 1;
  tx.inputs.push_back(TxIn{prev_txid, 0, Bytes{}});
  tx.outputs.push_back(TxOut{200, recipient_spk});
  tx.outputs.push_back(TxOut{299, sender_spk});
  const auto tx_bytes = tx.serialize();
  const auto txid = tx.txid();
  ASSERT_TRUE(db.put_tx_index(txid, 8, 0, tx_bytes));
  ASSERT_TRUE(db.set_tip(storage::TipState{8, txid}));
  ASSERT_TRUE(db.flush());
  db.close();

  lightserver::Config lcfg;
  lcfg.db_path = base;
  lightserver::Server ls(lcfg);
  ASSERT_TRUE(ls.init());

  const std::string body = std::string(R"({"jsonrpc":"2.0","id":174,"method":"get_tx_summaries","params":{"txids":[")") +
                           hex_encode32(txid) + R"("]}})";
  const auto resp = ls.handle_rpc_for_test(body);
  ASSERT_TRUE(resp.find("\"txid\":\"" + hex_encode32(txid) + "\"") != std::string::npos);
  ASSERT_TRUE(resp.find("\"finalized_out\":499") != std::string::npos);
  ASSERT_TRUE(resp.find("\"fee\":1") != std::string::npos);
  ASSERT_TRUE(resp.find("\"flow_kind\":\"transfer-with-change\"") != std::string::npos);
}

TEST(test_lightserver_get_history_supports_paged_response) {
  const std::string base = unique_test_base("/tmp/finalis_light_history_paged");
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);

  storage::DB db;
  ASSERT_TRUE(db.open(base));
  genesis::Document d;
  d.version = 1;
  d.network_name = "mainnet";
  d.protocol_version = mainnet_network().protocol_version;
  d.network_id = mainnet_network().network_id;
  d.magic = mainnet_network().magic;
  d.genesis_time_unix = 1735689600ULL;
  d.initial_height = 0;
  d.initial_active_set_size = 1;
  d.initial_committee_params.min_committee = 1;
  d.initial_committee_params.max_committee = static_cast<std::uint32_t>(mainnet_network().max_committee);
  d.initial_committee_params.sizing_rule = "min(MAX_COMMITTEE,ACTIVE_SIZE)";
  d.initial_committee_params.c = 2;
  d.monetary_params_ref = "test";
  d.seeds = {};
  d.note = "lightserver-history-page-support";
  d.initial_validators.push_back(node::Node::deterministic_test_keypairs()[0].public_key);
  const auto genesis_json = genesis::to_json(d);
  ASSERT_TRUE(db.put(storage::key_genesis_json(), Bytes(genesis_json.begin(), genesis_json.end())));

  const auto kp = node::Node::deterministic_test_keypairs()[0];
  const auto pkh = crypto::h160(Bytes(kp.public_key.begin(), kp.public_key.end()));
  const Hash32 sh = crypto::sha256(address::p2pkh_script_pubkey(pkh));
  Hash32 txid1{};
  Hash32 txid2{};
  Hash32 txid3{};
  txid1[31] = 0x01;
  txid2[31] = 0x02;
  txid3[31] = 0x03;
  ASSERT_TRUE(db.add_script_history(sh, 7, txid2));
  ASSERT_TRUE(db.add_script_history(sh, 7, txid1));
  ASSERT_TRUE(db.add_script_history(sh, 8, txid3));
  ASSERT_TRUE(db.flush());
  db.close();

  lightserver::Config lcfg;
  lcfg.db_path = base;
  lightserver::Server ls(lcfg);
  ASSERT_TRUE(ls.init());

  const std::string page1 =
      std::string(R"({"jsonrpc":"2.0","id":173,"method":"get_history","params":{"scripthash_hex":")") + hex_encode32(sh) +
      R"(","limit":2}})";
  const auto resp1 = ls.handle_rpc_for_test(page1);
  const auto txid1_hex = hex_encode32(txid1);
  const auto txid2_hex = hex_encode32(txid2);
  const auto txid3_hex = hex_encode32(txid3);
  ASSERT_TRUE(resp1.find("\"has_more\":true") != std::string::npos);
  ASSERT_TRUE(resp1.find(txid1_hex) != std::string::npos);
  ASSERT_TRUE(resp1.find(txid2_hex) != std::string::npos);
  ASSERT_TRUE(resp1.find(txid3_hex) == std::string::npos);

  const std::string page2 =
      std::string(R"({"jsonrpc":"2.0","id":174,"method":"get_history","params":{"scripthash_hex":")") + hex_encode32(sh) +
      R"(","limit":2,"start_after":{"height":7,"txid":")" + txid2_hex + R"("}}})";
  const auto resp2 = ls.handle_rpc_for_test(page2);
  ASSERT_TRUE(resp2.find("\"has_more\":false") != std::string::npos);
  ASSERT_TRUE(resp2.find(txid1_hex) == std::string::npos);
  ASSERT_TRUE(resp2.find(txid2_hex) == std::string::npos);
  ASSERT_TRUE(resp2.find(txid3_hex) != std::string::npos);
}

TEST(test_snapshot_export_import_bootstraps_imported_db) {
  const std::string base = unique_test_base("/tmp/finalis_light_snapshot");
  auto cluster = make_cluster(base);
  auto& node = *cluster.nodes[0];
  ASSERT_TRUE(wait_for([&]() { return node.status().height >= 6; }, kClusterFinalizationTimeout));

  for (auto& n : cluster.nodes) {
    if (n) n->stop();
  }
  cluster.nodes.clear();

  const std::string snapshot_path = base + "/finalized.snapshot";
  const std::string imported_db_path = base + "/imported-node";

  storage::SnapshotManifest exported;
  std::string err;
  storage::SnapshotManifest imported;
  {
    storage::DB src;
    ASSERT_TRUE(src.open_readonly(base + "/node0") || src.open(base + "/node0"));
    ASSERT_TRUE(storage::export_snapshot_bundle(src, snapshot_path, &exported, &err));
  }
  {
    storage::DB dst;
    ASSERT_TRUE(dst.open(imported_db_path));
    ASSERT_TRUE(storage::import_snapshot_bundle(dst, snapshot_path, &imported, &err));
  }
  ASSERT_EQ(imported.finalized_height, exported.finalized_height);
  ASSERT_EQ(imported.finalized_hash, exported.finalized_hash);
  ASSERT_EQ(imported.utxo_root, exported.utxo_root);
  ASSERT_EQ(imported.validators_root, exported.validators_root);

  node::NodeConfig cfg;
  cfg.node_id = 9;
  cfg.disable_p2p = true;
  cfg.db_path = imported_db_path;
  cfg.max_committee = 4;
  cfg.genesis_path = base + "/genesis.json";
  cfg.allow_unsafe_genesis_override = true;
  cfg.validator_key_file = imported_db_path + "/keystore/validator.json";
  cfg.validator_passphrase = "test-pass";
  keystore::ValidatorKey created_key;
  std::string kerr;
  ASSERT_TRUE(keystore::create_validator_keystore(cfg.validator_key_file, cfg.validator_passphrase, "mainnet", "sc",
                                                  deterministic_seed_for_node_id(cfg.node_id), &created_key, &kerr));

  node::Node imported_node(cfg);
  ASSERT_TRUE(imported_node.init());
  const auto status = imported_node.status();
  ASSERT_EQ(status.height, exported.finalized_height);
  ASSERT_EQ(status.transition_hash, exported.finalized_hash);
  imported_node.stop();
}

TEST(test_lightserver_rejects_oversized_request_body_for_test_api) {
  const std::string base = unique_test_base("/tmp/finalis_light_oversized_body");
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);
  storage::DB db;
  ASSERT_TRUE(db.open(base));
  Hash32 tip_hash{};
  tip_hash.fill(0x42);
  ASSERT_TRUE(db.set_tip(storage::TipState{1, tip_hash}));
  db.close();

  lightserver::Config lcfg;
  lcfg.db_path = base;
  lightserver::Server ls(lcfg);
  ASSERT_TRUE(ls.init());

  std::string body = R"({"jsonrpc":"2.0","id":1,"method":"get_status","pad":")";
  body.append(300 * 1024, 'x');
  body += "\"}";
  const auto resp = ls.handle_rpc_for_test(body);
  ASSERT_TRUE(resp.find("request too large") != std::string::npos);
}

TEST(test_lightserver_roots_endpoints_unavailable_away_from_finalized_tip) {
  const std::string base = unique_test_base("/tmp/finalis_light_v3_proofs");
  auto cluster = make_cluster(base, 4);
  auto& node = *cluster.nodes[0];

  lightserver::Config lcfg;
  lcfg.db_path = base + "/node0";
  lcfg.bind_ip = "127.0.0.1";
  lcfg.max_committee = 4;
  auto ls = std::make_unique<lightserver::Server>(lcfg);
  ASSERT_TRUE(ls->init());

  const auto tip = node.status();
  const std::uint64_t h = tip.height;

  const std::string roots_q =
      std::string(R"({"jsonrpc":"2.0","id":21,"method":"get_roots","params":{"height":)") + std::to_string(h) + "}}";
  const auto roots = ls->handle_rpc_for_test(roots_q);
  const bool roots_available = roots.find("utxo_root") != std::string::npos;
  const bool roots_unavailable = roots.find("roots unavailable") != std::string::npos;
  ASSERT_TRUE(roots_available || roots_unavailable);

  OutPoint op{};
  op.txid.fill(0x42);
  op.index = 0;

  const std::string up_q = std::string(R"({"jsonrpc":"2.0","id":22,"method":"get_utxo_proof","params":{"txid":")") +
                           hex_encode32(op.txid) + R"(","vout":)" + std::to_string(op.index) + R"(,"height":)" +
                           std::to_string(h) + "}}";
  const auto up = ls->handle_rpc_for_test(up_q);
  if (roots_available) {
    ASSERT_TRUE(up.find("proof_format") != std::string::npos);
  } else {
    const bool utxo_root_unavailable = up.find("utxo_root unavailable") != std::string::npos;
    const bool non_tip_height_rejected = up.find("proofs only supported at finalized tip") != std::string::npos;
    ASSERT_TRUE(utxo_root_unavailable || non_tip_height_rejected);
  }

  const std::string vp_q =
      [&]() {
        const auto keys = node::Node::deterministic_test_keypairs();
        return std::string(R"({"jsonrpc":"2.0","id":23,"method":"get_validator_proof","params":{"pubkey_hex":")") +
               hex_encode(Bytes(keys[0].public_key.begin(), keys[0].public_key.end())) + R"(","height":)" +
               std::to_string(h) + "}}";
      }();
  const auto vp = ls->handle_rpc_for_test(vp_q);
  if (roots_available) {
    ASSERT_TRUE(vp.find("proof_format") != std::string::npos);
  } else {
    const bool validators_root_unavailable = vp.find("validators_root unavailable") != std::string::npos;
    const bool non_tip_height_rejected = vp.find("proofs only supported at finalized tip") != std::string::npos;
    ASSERT_TRUE(validators_root_unavailable || non_tip_height_rejected);
  }
}

TEST(test_lightserver_validator_onboarding_rpc_start_and_status_support_live_registration) {
  const std::string base = unique_test_base("/tmp/finalis_light_onboarding_rpc");
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);

  const auto seed = deterministic_seed_for_node_id(17);
  const std::string key_file = base + "/keystore/validator.json";
  const std::string passphrase = "test-pass";
  keystore::ValidatorKey validator_key;
  std::string key_err;
  ASSERT_TRUE(keystore::create_validator_keystore(key_file, passphrase, "mainnet", "sc", seed, &validator_key, &key_err));

  storage::DB db;
  ASSERT_TRUE(db.open(base));
  Hash32 tip_hash{};
  tip_hash[31] = 0xA4;
  ASSERT_TRUE(db.set_tip(storage::TipState{25, tip_hash}));
  storage::NodeRuntimeStatusSnapshot snapshot;
  snapshot.chain_id_ok = true;
  snapshot.db_open = true;
  snapshot.local_finalized_height = 25;
  snapshot.observed_network_height_known = true;
  snapshot.observed_network_finalized_height = 25;
  snapshot.healthy_peer_count = 2;
  snapshot.established_peer_count = 2;
  snapshot.finalized_lag = 0;
  snapshot.next_height_committee_available = true;
  snapshot.next_height_proposer_available = true;
  snapshot.registration_ready_preflight = true;
  snapshot.readiness_stable_samples = 8;
  snapshot.registration_ready = true;
  snapshot.availability_local_operator_known = true;
  snapshot.availability_local_operator_pubkey = validator_key.pubkey;
  snapshot.captured_at_unix_ms = static_cast<std::uint64_t>(std::time(nullptr)) * 1000ULL;
  ASSERT_TRUE(db.put_node_runtime_status_snapshot(snapshot));

  lightserver::Config cfg;
  cfg.db_path = base;
  cfg.network.onboarding_admission_pow_difficulty_bits = 0;
  cfg.network.validator_join_admission_pow_difficulty_bits = 0;
  cfg.tx_relay_override = [](const Bytes&, std::string*) { return true; };

  storage::EpochRewardSettlementState settlement;
  settlement.epoch_start_height =
      consensus::committee_epoch_start(snapshot.local_finalized_height, cfg.network.committee_epoch_blocks);
  settlement.onboarding_score_units[validator_key.pubkey] = 7;
  ASSERT_TRUE(db.put_epoch_reward_settlement(settlement));

  OutPoint op{};
  op.txid.fill(0x6A);
  op.index = 0;
  const auto own_pkh = crypto::h160(Bytes(validator_key.pubkey.begin(), validator_key.pubkey.end()));
  const TxOut spendable{50'000'000'000, address::p2pkh_script_pubkey(own_pkh)};
  ASSERT_TRUE(db.put_utxo(op, spendable));
  ASSERT_TRUE(db.put_script_utxo(crypto::sha256(spendable.script_pubkey), op, spendable, 1));
  ASSERT_TRUE(db.flush());
  db.close();

  lightserver::Server ls(cfg);
  ASSERT_TRUE(ls.init());

  const std::string start_body =
      std::string(R"({"jsonrpc":"2.0","id":501,"method":"validator_onboarding_start","params":{"key_file":")") + key_file +
      R"(","passphrase":")" + passphrase + R"(","fee":10000,"wait_for_sync":true}})";
  const auto start_resp = ls.handle_rpc_for_test(start_body);
  ASSERT_TRUE(start_resp.find("\"state\":\"waiting_for_finalization\"") != std::string::npos);
  ASSERT_TRUE(start_resp.find("\"onboarding_id\":\"rpc\"") != std::string::npos);
  ASSERT_TRUE(start_resp.find("\"wait_for_sync\":true") != std::string::npos);
  ASSERT_TRUE(start_resp.find("\"broadcast_outcome\":\"sent\"") != std::string::npos);
  ASSERT_TRUE(start_resp.find("\"selected_input_count\":1") != std::string::npos);
  const auto tracked_txid = json_string_field(start_resp, "txid_hex");
  ASSERT_TRUE(tracked_txid.has_value());
  ASSERT_TRUE(!tracked_txid->empty());

  const std::string status_body =
      std::string(R"({"jsonrpc":"2.0","id":502,"method":"validator_onboarding_status","params":{"key_file":")") + key_file +
      R"(","passphrase":")" + passphrase + R"(","fee":10000,"wait_for_sync":true,"txid_hex":")" + *tracked_txid +
      R"("}})";
  const auto status_resp = ls.handle_rpc_for_test(status_body);
  ASSERT_TRUE(status_resp.find("\"state\":\"waiting_for_finalization\"") != std::string::npos);
  ASSERT_TRUE(status_resp.find(std::string("\"txid_hex\":\"") + *tracked_txid + "\"") != std::string::npos);
  ASSERT_TRUE(status_resp.find("\"broadcast_outcome\":\"sent\"") != std::string::npos);
  ASSERT_TRUE(status_resp.find("\"onboarding_reward_pool_bps\":300") != std::string::npos);
  ASSERT_TRUE(status_resp.find("\"onboarding_admission_pow_difficulty_bits\":0") != std::string::npos);
  ASSERT_TRUE(status_resp.find("\"validator_join_admission_pow_difficulty_bits\":0") != std::string::npos);
  ASSERT_TRUE(status_resp.find("\"onboarding_reward_eligible\":false") != std::string::npos);

  const auto get_status_resp = ls.handle_rpc_for_test(R"({"jsonrpc":"2.0","id":503,"method":"get_status","params":{}})");
  ASSERT_TRUE(get_status_resp.find("\"validator_registry_status\":\"NOT_REGISTERED\"") != std::string::npos);
  ASSERT_TRUE(get_status_resp.find("\"onboarding_reward_eligible\":true") != std::string::npos);
  ASSERT_TRUE(get_status_resp.find("\"onboarding_reward_score_units\":7") != std::string::npos);
}

void register_lightserver_tests() {}
