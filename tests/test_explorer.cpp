// SPDX-License-Identifier: MIT

#include "test_framework.hpp"

#ifndef _WIN32
#include <unistd.h>
#else
#include <process.h>
#define getpid _getpid
#endif

#include <array>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <functional>
#include <optional>
#include <sstream>
#include <string>

#include "common/address.hpp"
#include "crypto/hash.hpp"
#include "node/node.hpp"
#include "utxo/signing.hpp"
#include "utxo/tx.hpp"

#define main finalis_explorer_program_main
#include "../apps/finalis-explorer/main.cpp"
#undef main

using namespace finalis;

namespace {

std::filesystem::path unique_test_cache_path(const char* stem) {
  static std::atomic<std::uint64_t> seq{0};
  const auto pid = static_cast<std::uint64_t>(::getpid());
  const auto now = std::chrono::steady_clock::now().time_since_epoch().count();
  const auto name = std::string(stem) + "_" + std::to_string(pid) + "_" + std::to_string(now) + "_" + std::to_string(seq.fetch_add(1, std::memory_order_relaxed)) + ".json";
  return std::filesystem::temp_directory_path() / name;
}

std::string make_http_get(const std::string& path) {
  return "GET " + path + " HTTP/1.1\r\nHost: explorer.test\r\nConnection: close\r\n\r\n";
}

std::string make_http_request(const std::string& method, const std::string& path,
                              const std::vector<std::pair<std::string, std::string>>& headers = {},
                              const std::string& body = {}) {
  std::ostringstream oss;
  oss << method << " " << path << " HTTP/1.1\r\nHost: explorer.test\r\nConnection: close\r\n";
  for (const auto& [k, v] : headers) oss << k << ": " << v << "\r\n";
  if (!body.empty()) oss << "Content-Length: " << body.size() << "\r\n";
  oss << "\r\n" << body;
  return oss.str();
}

std::string rpc_result(const std::string& result_json) {
  return std::string("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":") + result_json + "}";
}

std::string rpc_error(int code, const std::string& message) {
  return std::string("{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":") + std::to_string(code) +
         ",\"message\":\"" + message + "\"}}";
}

std::string make_address(std::uint8_t seed) {
  std::array<std::uint8_t, 20> pkh{};
  for (std::size_t i = 0; i < pkh.size(); ++i) pkh[i] = static_cast<std::uint8_t>(seed + i);
  const auto addr = address::encode_p2pkh("sc", pkh);
  ASSERT_TRUE(addr.has_value());
  return *addr;
}

Hash32 scripthash_for_address(const std::string& addr) {
  const auto decoded = address::decode(addr);
  ASSERT_TRUE(decoded.has_value());
  return crypto::sha256(address::p2pkh_script_pubkey(decoded->pubkey_hash));
}

Tx make_test_tx(const std::string& addr) {
  const auto decoded = address::decode(addr);
  ASSERT_TRUE(decoded.has_value());
  Tx tx;
  tx.version = 1;
  tx.inputs.push_back(TxIn{zero_hash(), 0xFFFFFFFFu, Bytes{0x01, 0x02, 0x03}, 0xFFFFFFFFu});
  tx.outputs.push_back(TxOut{123456789u, address::p2pkh_script_pubkey(decoded->pubkey_hash)});
  tx.lock_time = 0;
  return tx;
}

FrontierTransition make_test_transition(std::uint64_t height) {
  FrontierTransition transition;
  transition.prev_finalized_hash = zero_hash();
  transition.height = height;
  transition.round = 0;
  transition.leader_pubkey.fill(0x11);
  transition.prev_frontier = 0;
  transition.next_frontier = 1;
  transition.prev_state_root.fill(0x22);
  transition.next_state_root.fill(0x33);
  transition.ordered_slice_commitment.fill(0x44);
  transition.decisions_commitment.fill(0x55);
  transition.quorum_threshold = 1;
  transition.observed_signers.push_back(transition.leader_pubkey);
  return transition;
}

class ScopedRpcHook {
 public:
  using Handler = std::function<std::string(const std::string&)>;

  explicit ScopedRpcHook(Handler handler) : prev_(g_http_post_json_raw) {
    clear_runtime_caches();
    g_http_post_json_raw = [handler = std::move(handler)](const std::string&, const std::string& body, std::string*) {
      return std::optional<std::string>(handler(body));
    };
  }

  ~ScopedRpcHook() {
    g_http_post_json_raw = prev_;
    clear_runtime_caches();
  }

 private:
  HttpPostJsonRawFn prev_;
};

class ScopedUtxoHook {
 public:
  using Handler =
      std::function<std::optional<std::vector<finalis::lightserver::UtxoView>>(const Hash32&, std::string*)>;

  explicit ScopedUtxoHook(Handler handler) : prev_(g_rpc_get_utxos) {
    clear_runtime_caches();
    g_rpc_get_utxos = [handler = std::move(handler)](const std::string&, const Hash32& scripthash, std::string* err) {
      return handler(scripthash, err);
    };
  }

  ~ScopedUtxoHook() {
    g_rpc_get_utxos = prev_;
    clear_runtime_caches();
  }

 private:
  RpcGetUtxosFn prev_;
};

struct ExplorerFixture {
  std::string known_address = make_address(0x10);
  std::string empty_address = make_address(0x40);
  Hash32 known_scripthash = scripthash_for_address(known_address);
  Hash32 empty_scripthash = scripthash_for_address(empty_address);
  Tx tx = make_test_tx(known_address);
  FrontierTransition transition = make_test_transition(7);
  std::string txid = hex_encode32(tx.txid());
  std::string transition_hash = hex_encode32(transition.transition_id());
  std::string known_scripthash_hex = hex_encode32(known_scripthash);
  std::string empty_scripthash_hex = hex_encode32(empty_scripthash);
  std::string unknown_txid = std::string(63, '0') + "1";
  std::string unknown_transition_hash = std::string(63, 'a') + "b";
};

Config test_config() {
  Config cfg;
  cfg.rpc_url = "http://test.invalid/rpc";
  return cfg;
}

std::string default_rpc_handler(const ExplorerFixture& fx, const std::string& body) {
  if (body.find("\"method\":\"get_status\"") != std::string::npos) {
    return rpc_result(std::string("{\"network_name\":\"mainnet\",\"finalized_height\":10,\"finalized_transition_hash\":\"") +
                      fx.transition_hash + "\",\"version\":\"fake-lightserver\",\"protocol_reserve_balance\":4200000000,"
                      "\"availability\":{\"epoch\":9,"
                      "\"retained_prefix_count\":5,\"tracked_operator_count\":28,\"eligible_operator_count\":26,"
                      "\"below_min_eligible\":true,\"checkpoint_derivation_mode\":\"fallback\","
                      "\"checkpoint_fallback_reason\":\"hysteresis_recovery_pending\",\"fallback_sticky\":true,"
                      "\"adaptive_regime\":{\"qualified_depth\":26,\"adaptive_target_committee_size\":24,"
                      "\"adaptive_min_eligible\":27,\"adaptive_min_bond\":15000000000,\"slack\":-1,"
                      "\"target_expand_streak\":3,\"target_contract_streak\":0,\"fallback_rate_bps\":2500,"
                      "\"sticky_fallback_rate_bps\":1250,\"fallback_rate_window_epochs\":8,"
                      "\"near_threshold_operation\":true,\"prolonged_expand_buildup\":true,"
                      "\"prolonged_contract_buildup\":false,\"repeated_sticky_fallback\":true,"
                      "\"depth_collapse_after_bond_increase\":false},"
                      "\"adaptive_telemetry_summary\":{\"window_epochs\":8,\"sample_count\":8,"
                      "\"fallback_epochs\":2,\"sticky_fallback_epochs\":1},"
                      "\"local_operator\":{\"known\":true,"
                      "\"pubkey\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\","
                      "\"status\":\"ACTIVE\",\"seat_budget\":1}},\"ticket_pow\":{\"difficulty\":10,"
                      "\"difficulty_min\":8,\"difficulty_max\":12,\"epoch_health\":\"healthy\","
                      "\"streak_up\":1,\"streak_down\":0,\"nonce_search_limit\":4096,\"bonus_cap_bps\":1000}}");
  }
  if (body.find("\"method\":\"get_committee\"") != std::string::npos) {
    return rpc_result(std::string("{\"height\":10,\"epoch_start_height\":1,")
                      + "\"checkpoint_derivation_mode\":\"fallback\",\"checkpoint_fallback_reason\":\"hysteresis_recovery_pending\","
                        "\"fallback_sticky\":true,\"availability_eligible_operator_count\":26,"
                        "\"availability_min_eligible_operators\":27,\"adaptive_target_committee_size\":24,"
                        "\"adaptive_min_eligible\":27,\"adaptive_min_bond\":15000000000,\"qualified_depth\":26,"
                        "\"slack\":-1,\"target_expand_streak\":3,\"target_contract_streak\":0,"
                      + "\"ticket_pow\":{\"difficulty\":10,\"difficulty_min\":8,"
                        "\"difficulty_max\":12,\"epoch_health\":\"healthy\",\"streak_up\":1,\"streak_down\":0,"
                        "\"nonce_search_limit\":4096,\"bonus_cap_bps\":1000},"
                        "\"members\":[{\"operator_id\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\","
                        "\"representative_pubkey\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\","
                        "\"base_weight\":100,\"ticket_bonus_bps\":1000,\"final_weight\":1010000,"
                        "\"ticket_hash\":\"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\","
                        "\"ticket_nonce\":12}]}");
  }
  if (body.find("\"method\":\"get_tx_status\"") != std::string::npos) {
    if (body.find(fx.txid) != std::string::npos) {
      return rpc_result(std::string("{\"status\":\"finalized\",\"finalized\":true,\"height\":7,\"finalized_depth\":4,") +
                        "\"credit_safe\":true,\"transition_hash\":\"" + fx.transition_hash + "\"}");
    }
    return rpc_result(R"({"status":"not_found","finalized":false,"credit_safe":false})");
  }
  if (body.find("\"method\":\"get_tx\"") != std::string::npos) {
    if (body.find(fx.txid) != std::string::npos) {
      return rpc_result(std::string("{\"tx_hex\":\"") + hex_encode(fx.tx.serialize()) + "\"}");
    }
    return rpc_error(-32001, "tx not found");
  }
  if (body.find("\"method\":\"get_transition_by_height\"") != std::string::npos) {
    if (body.find("\"height\":7") != std::string::npos) {
      return rpc_result(std::string("{\"height\":7,\"hash\":\"") + fx.transition_hash + "\",\"transition_hash\":\"" +
                        fx.transition_hash + "\",\"transition_hex\":\"" + hex_encode(fx.transition.serialize()) + "\"}");
    }
    return rpc_error(-32001, "transition not found");
  }
  if (body.find("\"method\":\"get_transition\"") != std::string::npos) {
    if (body.find(fx.transition_hash) != std::string::npos) {
      return rpc_result(std::string("{\"hash\":\"") + fx.transition_hash + "\",\"transition_hash\":\"" + fx.transition_hash +
                        "\",\"transition_hex\":\"" + hex_encode(fx.transition.serialize()) + "\"}");
    }
    return rpc_error(-32001, "transition not found");
  }
  if (body.find("\"method\":\"get_ingress_record\"") != std::string::npos) {
    if (body.find("\"seq\":1") != std::string::npos) {
      return rpc_result(std::string("{\"seq\":1,\"present\":true,\"txid\":\"") + fx.txid +
                        "\",\"tx_hash\":\"" + fx.txid + "\",\"bytes_present\":true}");
    }
    return rpc_result("{\"seq\":999,\"present\":false}");
  }
  if (body.find("\"method\":\"get_utxos\"") != std::string::npos) {
    if (body.find(fx.known_scripthash_hex) != std::string::npos) {
      return rpc_result(std::string("[{\"txid\":\"") + fx.txid + "\",\"vout\":0,\"value\":123456789,\"height\":7}]");
    }
    return rpc_result("[]");
  }
  if (body.find("\"method\":\"get_history_page\"") != std::string::npos) {
    if (body.find(fx.known_scripthash_hex) != std::string::npos) {
      return rpc_result(std::string("{\"items\":[{\"txid\":\"") + fx.txid + "\",\"height\":7}],\"has_more\":false,"
                        "\"next_start_after\":{\"height\":99,\"txid\":\"" + fx.txid + "\"}}");
    }
    return rpc_result("{\"items\":[],\"has_more\":false,\"next_start_after\":{\"height\":99,\"txid\":\"deadbeef\"}}");
  }
  if (body.find("\"method\":\"get_recent_tx_summaries\"") != std::string::npos) {
    return rpc_result(std::string("{\"items\":[{\"txid\":\"") + fx.txid +
                      "\",\"height\":7,\"status_label\":\"FINALIZED (CREDIT SAFE)\",\"credit_safe\":true,"
                      "\"finalized_depth\":4,\"finalized_out\":123456789,\"total_out\":123456789,\"fee\":0,"
                      "\"input_count\":1,\"output_count\":1,\"primary_sender\":null,"
                      "\"primary_recipient\":\"" + fx.known_address +
                      "\",\"recipient_count\":1,\"recipients\":[\"" + fx.known_address +
                      "\"],\"flow_kind\":\"issuance\",\"flow_summary\":\"Protocol or settlement issuance\"}]}");
  }
  return rpc_error(-32601, "unknown method");
}

std::string future_policy_rpc_handler(const ExplorerFixture& fx, const std::string& body) {
  if (body.find("\"method\":\"get_status\"") != std::string::npos) {
    return rpc_result(std::string("{\"network_name\":\"mainnet\",\"finalized_height\":240001,\"finalized_transition_hash\":\"") +
                      fx.transition_hash + "\",\"version\":\"fake-lightserver\",\"protocol_reserve_balance\":8400000000,"
                      "\"availability\":{\"epoch\":7500,"
                      "\"retained_prefix_count\":7,\"tracked_operator_count\":31,\"eligible_operator_count\":30,"
                      "\"below_min_eligible\":false,\"checkpoint_derivation_mode\":\"normal\","
                      "\"checkpoint_fallback_reason\":\"none\",\"fallback_sticky\":false,"
                      "\"adaptive_regime\":{\"qualified_depth\":30,\"adaptive_target_committee_size\":24,"
                      "\"adaptive_min_eligible\":27,\"adaptive_min_bond\":15000000000,\"slack\":3,"
                      "\"target_expand_streak\":4,\"target_contract_streak\":0,\"fallback_rate_bps\":0,"
                      "\"sticky_fallback_rate_bps\":0,\"fallback_rate_window_epochs\":8,"
                      "\"near_threshold_operation\":false,\"prolonged_expand_buildup\":false,"
                      "\"prolonged_contract_buildup\":false,\"repeated_sticky_fallback\":false,"
                      "\"depth_collapse_after_bond_increase\":false},"
                      "\"adaptive_telemetry_summary\":{\"window_epochs\":8,\"sample_count\":8,"
                      "\"fallback_epochs\":0,\"sticky_fallback_epochs\":0},"
                      "\"local_operator\":{\"known\":true,"
                      "\"pubkey\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\","
                      "\"status\":\"ACTIVE\",\"seat_budget\":1}},\"ticket_pow\":{\"difficulty\":10,"
                      "\"difficulty_min\":8,\"difficulty_max\":12,\"epoch_health\":\"healthy\","
                      "\"streak_up\":2,\"streak_down\":0,\"nonce_search_limit\":4096,\"bonus_cap_bps\":500}}");
  }
  if (body.find("\"method\":\"get_committee\"") != std::string::npos) {
    return rpc_result(std::string("{\"height\":240001,\"epoch_start_height\":240001,")
                      + "\"checkpoint_derivation_mode\":\"normal\",\"checkpoint_fallback_reason\":\"none\","
                        "\"fallback_sticky\":false,\"availability_eligible_operator_count\":30,"
                        "\"availability_min_eligible_operators\":27,\"adaptive_target_committee_size\":24,"
                        "\"adaptive_min_eligible\":27,\"adaptive_min_bond\":15000000000,\"qualified_depth\":30,"
                        "\"slack\":3,\"target_expand_streak\":4,\"target_contract_streak\":0,"
                      + "\"ticket_pow\":{\"difficulty\":10,\"difficulty_min\":8,"
                        "\"difficulty_max\":12,\"epoch_health\":\"healthy\",\"streak_up\":2,\"streak_down\":0,"
                        "\"nonce_search_limit\":4096,\"bonus_cap_bps\":500},"
                        "\"members\":[{\"operator_id\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\","
                        "\"representative_pubkey\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\","
                        "\"base_weight\":100,\"ticket_bonus_bps\":500,\"final_weight\":1005000,"
                        "\"ticket_hash\":\"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\","
                        "\"ticket_nonce\":12}]}");
  }
  return default_rpc_handler(fx, body);
}

std::string no_recent_tx_rpc_handler(const ExplorerFixture& fx, const std::string& body) {
  if (body.find("\"method\":\"get_status\"") != std::string::npos) {
    return rpc_result(std::string("{\"network_name\":\"mainnet\",\"finalized_height\":10,\"finalized_transition_hash\":\"") +
                      fx.transition_hash + "\",\"version\":\"fake-lightserver\",\"protocol_reserve_balance\":4200000000,"
                      "\"ticket_pow\":{\"difficulty\":10,"
                      "\"difficulty_min\":8,\"difficulty_max\":12,\"epoch_health\":\"healthy\","
                      "\"streak_up\":1,\"streak_down\":0,\"nonce_search_limit\":4096,\"bonus_cap_bps\":1000}}");
  }
  if (body.find("\"method\":\"get_transition_by_height\"") != std::string::npos) {
    return rpc_error(-32001, "transition not found");
  }
  if (body.find("\"method\":\"get_recent_tx_summaries\"") != std::string::npos) {
    return rpc_result("{\"items\":[]}");
  }
  return default_rpc_handler(fx, body);
}

std::string empty_committee_rpc_handler(const ExplorerFixture& fx, const std::string& body) {
  if (body.find("\"method\":\"get_committee\"") != std::string::npos) {
    return rpc_result(std::string("{\"height\":10,\"epoch_start_height\":1,")
                      + "\"ticket_pow\":{\"difficulty\":10,\"difficulty_min\":8,"
                        "\"difficulty_max\":12,\"epoch_health\":\"healthy\",\"streak_up\":1,\"streak_down\":0,"
                        "\"nonce_search_limit\":4096,\"bonus_cap_bps\":1000},"
                        "\"members\":[]}");
  }
  return default_rpc_handler(fx, body);
}

TEST(test_explorer_api_status_and_tx_contract) {
  ExplorerFixture fx;
  ScopedRpcHook hook([&](const std::string& body) { return default_rpc_handler(fx, body); });
  const Config cfg = test_config();

  const auto status = handle_request(cfg, make_http_get("/api/status"));
  ASSERT_EQ(status.status, 200);
  ASSERT_TRUE(status.body.find("\"finalized_only\":true") != std::string::npos);
  ASSERT_TRUE(status.body.find("\"committee_snapshot\"") != std::string::npos);
  ASSERT_TRUE(status.body.find("\"finalized_height\":10") != std::string::npos);
  ASSERT_TRUE(status.body.find("\"finalized_transition_hash\":\"" + fx.transition_hash + "\"") != std::string::npos);
  ASSERT_TRUE(status.body.find("\"protocol_reserve_balance\":4200000000") != std::string::npos);
  ASSERT_TRUE(status.body.find("\"snapshot_refreshed_unix_ms\":") != std::string::npos);

  const auto tx_ok = handle_request(cfg, make_http_get("/api/tx/" + fx.txid));
  ASSERT_EQ(tx_ok.status, 200);
  ASSERT_TRUE(tx_ok.body.find("\"txid\":\"" + fx.txid + "\"") != std::string::npos);
  ASSERT_TRUE(tx_ok.body.find("\"finalized\":true") != std::string::npos);
  ASSERT_TRUE(tx_ok.body.find("\"credit_safe\":true") != std::string::npos);
  ASSERT_TRUE(tx_ok.body.find("\"height\":7") != std::string::npos);
  ASSERT_TRUE(tx_ok.body.find("\"transition_hash\":\"" + fx.transition_hash + "\"") != std::string::npos);
  ASSERT_TRUE(tx_ok.body.find("\"input_count\":1") != std::string::npos);
  ASSERT_TRUE(tx_ok.body.find("\"output_count\":1") != std::string::npos);
  ASSERT_TRUE(tx_ok.body.find("\"decoded_output_count\":1") != std::string::npos);
  ASSERT_TRUE(tx_ok.body.find("\"data_source\":\"rpc_live_finalized\"") != std::string::npos);
  ASSERT_TRUE(tx_ok.body.find("\"finalized_only\":true") != std::string::npos);

  const auto tx_bad = handle_request(cfg, make_http_get("/api/tx/not-a-txid"));
  ASSERT_EQ(tx_bad.status, 400);
  ASSERT_TRUE(tx_bad.body.find("\"code\":\"invalid_txid\"") != std::string::npos);

  const auto tx_missing = handle_request(cfg, make_http_get("/api/tx/" + fx.unknown_txid));
  ASSERT_EQ(tx_missing.status, 404);
  ASSERT_TRUE(tx_missing.body.find("\"code\":\"not_found\"") != std::string::npos);
}

TEST(test_explorer_tx_page_makes_credit_decision_explicit) {
  ExplorerFixture fx;
  ScopedRpcHook hook([&](const std::string& body) { return default_rpc_handler(fx, body); });
  const Config cfg = test_config();

  const auto tx_page = handle_request(cfg, make_http_get("/tx/" + fx.txid));
  ASSERT_EQ(tx_page.status, 200);
  ASSERT_TRUE(tx_page.body.find("FINALIZED") != std::string::npos);
  ASSERT_TRUE(tx_page.body.find("CREDIT SAFE") != std::string::npos);
  ASSERT_TRUE(tx_page.body.find("Safe to credit") != std::string::npos);
  ASSERT_TRUE(tx_page.body.find("FINALIZED (CREDIT SAFE)") != std::string::npos);
  ASSERT_TRUE(tx_page.body.find("Credit Safe</div><div>YES") != std::string::npos);
  ASSERT_TRUE(tx_page.body.find("Explorer data source: <strong>fresh finalized RPC</strong>") != std::string::npos);
  ASSERT_TRUE(tx_page.body.find("confirm") == std::string::npos);
}

TEST(test_explorer_api_v1_alias_and_batch_status_contract) {
  ExplorerFixture fx;
  ScopedRpcHook hook([&](const std::string& body) { return default_rpc_handler(fx, body); });
  Config cfg = test_config();

  const auto status = handle_request(cfg, make_http_get("/api/v1/status"));
  ASSERT_EQ(status.status, 200);
  ASSERT_TRUE(status.body.find("\"api_version\":\"v1\"") != std::string::npos);
  ASSERT_TRUE(status.body.find("\"finalized_only\":true") != std::string::npos);

  const std::string batch_body = std::string("{\"txids\":[\"") + fx.txid + "\"]}";
  const auto batch = handle_request(cfg, make_http_request("POST", "/api/v1/transactions/status:batch", {}, batch_body));
  ASSERT_EQ(batch.status, 200);
  ASSERT_TRUE(batch.body.find("\"api_version\":\"v1\"") != std::string::npos);
  ASSERT_TRUE(batch.body.find("\"txid\":\"" + fx.txid + "\"") != std::string::npos);
  ASSERT_TRUE(batch.body.find("\"finalized\":true") != std::string::npos);
}

TEST(test_explorer_partner_auth_and_idempotent_withdrawal_contract) {
  ExplorerFixture fx;
  ScopedRpcHook hook([&](const std::string& body) {
    if (body.find("\"method\":\"broadcast_tx\"") != std::string::npos) {
      return rpc_result(std::string("{\"ok\":true,\"accepted\":true,\"status\":\"accepted_for_relay\",\"finalized\":false,")
                        + "\"txid\":\"" + fx.txid + "\",\"message\":\"accepted_for_relay\",\"retryable\":false,\"retry_class\":\"none\"}");
    }
    return default_rpc_handler(fx, body);
  });
  Config cfg = test_config();
  cfg.partner_auth_required = true;
  cfg.partner_api_key = "partner-key";
  cfg.partner_api_secret = "partner-secret";

  const std::string body = std::string("{\"client_withdrawal_id\":\"w1\",\"tx_hex\":\"") + finalis::hex_encode(fx.tx.serialize()) + "\"}";

  const auto missing_auth = handle_request(cfg, make_http_request("POST", "/api/v1/withdrawals", {{"Idempotency-Key", "idem-1"}}, body));
  ASSERT_EQ(missing_auth.status, 401);
  ASSERT_TRUE(missing_auth.body.find("\"code\":\"auth_missing\"") != std::string::npos);

  const std::string ts = std::to_string(static_cast<std::uint64_t>(std::time(nullptr)));
  const std::string nonce = "n1";
  const std::string canonical = std::string("POST\n/api/v1/withdrawals\n") + ts + "\n" + nonce + "\n" + sha256_hex_text(body);
  const auto sig = hmac_sha256_hex(cfg.partner_api_secret, canonical);
  ASSERT_TRUE(sig.has_value());
  const std::vector<std::pair<std::string, std::string>> headers{
      {"Idempotency-Key", "idem-1"},
      {"X-Finalis-Api-Key", cfg.partner_api_key},
      {"X-Finalis-Timestamp", ts},
      {"X-Finalis-Nonce", nonce},
      {"X-Finalis-Signature", *sig},
  };

  const auto created = handle_request(cfg, make_http_request("POST", "/api/v1/withdrawals", headers, body));
  ASSERT_TRUE(created.status == 201 || created.status == 200 || created.status == 202);
  ASSERT_TRUE(created.body.find("\"client_withdrawal_id\":\"w1\"") != std::string::npos);
  ASSERT_TRUE(created.body.find("\"api_version\":\"v1\"") != std::string::npos);

  const std::string nonce2 = "n2";
  const std::string canonical2 = std::string("POST\n/api/v1/withdrawals\n") + ts + "\n" + nonce2 + "\n" + sha256_hex_text(body);
  const auto sig2 = hmac_sha256_hex(cfg.partner_api_secret, canonical2);
  ASSERT_TRUE(sig2.has_value());
  const std::vector<std::pair<std::string, std::string>> headers2{
      {"Idempotency-Key", "idem-1"},
      {"X-Finalis-Api-Key", cfg.partner_api_key},
      {"X-Finalis-Timestamp", ts},
      {"X-Finalis-Nonce", nonce2},
      {"X-Finalis-Signature", *sig2},
  };
  const auto replayed = handle_request(cfg, make_http_request("POST", "/api/v1/withdrawals", headers2, body));
  ASSERT_EQ(replayed.status, 200);
  ASSERT_TRUE(replayed.body.find("\"client_withdrawal_id\":\"w1\"") != std::string::npos);
}

TEST(test_explorer_partner_events_finalized_feed_contract) {
  ExplorerFixture fx;
  ScopedRpcHook hook([&](const std::string& body) {
    if (body.find("\"method\":\"broadcast_tx\"") != std::string::npos) {
      return rpc_result(std::string("{\"ok\":true,\"accepted\":true,\"status\":\"accepted_for_relay\",\"finalized\":false,")
                        + "\"txid\":\"" + fx.txid + "\",\"message\":\"accepted_for_relay\",\"retryable\":false,\"retry_class\":\"none\"}");
    }
    return default_rpc_handler(fx, body);
  });
  Config cfg = test_config();
  cfg.partner_auth_required = false;

  const std::string body = std::string("{\"client_withdrawal_id\":\"w2\",\"tx_hex\":\"") + finalis::hex_encode(fx.tx.serialize()) + "\"}";
  const auto created = handle_request(cfg, make_http_request("POST", "/api/v1/withdrawals", {{"Idempotency-Key", "idem-2"}}, body));
  ASSERT_TRUE(created.status == 201 || created.status == 200 || created.status == 202);

  const auto fetched = handle_request(cfg, make_http_get("/api/v1/withdrawals/w2"));
  ASSERT_EQ(fetched.status, 200);
  ASSERT_TRUE(fetched.body.find("\"state\":\"finalized\"") != std::string::npos);

  const auto events = handle_request(cfg, make_http_get("/api/v1/events/finalized?from_sequence=1"));
  ASSERT_EQ(events.status, 200);
  ASSERT_TRUE(events.body.find("\"items\":[") != std::string::npos);
  ASSERT_TRUE(events.body.find("\"state\":\"finalized\"") != std::string::npos);
  ASSERT_TRUE(events.body.find("\"api_version\":\"v1\"") != std::string::npos);
}

TEST(test_explorer_partner_registry_supports_next_secret_rotation) {
  ExplorerFixture fx;
  ScopedRpcHook hook([&](const std::string& body) {
    if (body.find("\"method\":\"broadcast_tx\"") != std::string::npos) {
      return rpc_result(std::string("{\"ok\":true,\"accepted\":true,\"status\":\"accepted_for_relay\",\"finalized\":false,")
                        + "\"txid\":\"" + fx.txid + "\",\"message\":\"accepted_for_relay\",\"retryable\":false,\"retry_class\":\"none\"}");
    }
    return default_rpc_handler(fx, body);
  });
  Config cfg = test_config();
  cfg.partner_auth_required = true;

  const auto registry_path = unique_test_cache_path("finalis-partner-registry");
  {
    std::ofstream out(registry_path);
    out << "{"
           "\"partners\":[{"
           "\"partner_id\":\"p1\","
           "\"api_key\":\"k1\","
           "\"active_secret\":\"old-secret\","
           "\"next_secret\":\"new-secret\","
           "\"enabled\":true"
           "}]"
           "}";
  }
  cfg.partner_registry_path = registry_path.string();
  std::string reg_err;
  ASSERT_TRUE(load_partner_registry(cfg, &reg_err));

  const std::string body = std::string("{\"client_withdrawal_id\":\"r1\",\"tx_hex\":\"") + finalis::hex_encode(fx.tx.serialize()) + "\"}";
  const std::string ts = std::to_string(static_cast<std::uint64_t>(std::time(nullptr)));
  const std::string nonce = "rot-n1";
  const std::string canonical = std::string("POST\n/api/v1/withdrawals\n") + ts + "\n" + nonce + "\n" + sha256_hex_text(body);
  const auto sig = hmac_sha256_hex("new-secret", canonical);
  ASSERT_TRUE(sig.has_value());
  const std::vector<std::pair<std::string, std::string>> headers{
      {"Idempotency-Key", "rid-1"},
      {"X-Finalis-Api-Key", "k1"},
      {"X-Finalis-Timestamp", ts},
      {"X-Finalis-Nonce", nonce},
      {"X-Finalis-Signature", *sig},
  };
  const auto resp = handle_request(cfg, make_http_request("POST", "/api/v1/withdrawals", headers, body));
  ASSERT_TRUE(resp.status == 200 || resp.status == 201 || resp.status == 202);
  ASSERT_TRUE(resp.body.find("\"partner_id\":\"p1\"") != std::string::npos);

  std::error_code ec;
  std::filesystem::remove(registry_path, ec);
}

TEST(test_explorer_partner_webhook_retries_until_success) {
  ExplorerFixture fx;
  ScopedRpcHook hook([&](const std::string& body) {
    if (body.find("\"method\":\"broadcast_tx\"") != std::string::npos) {
      return rpc_result(std::string("{\"ok\":true,\"accepted\":true,\"status\":\"accepted_for_relay\",\"finalized\":false,")
                        + "\"txid\":\"" + fx.txid + "\",\"message\":\"accepted_for_relay\",\"retryable\":false,\"retry_class\":\"none\"}");
    }
    return default_rpc_handler(fx, body);
  });
  Config cfg = test_config();
  cfg.partner_auth_required = true;
  cfg.partner_webhook_max_attempts = 3;
  cfg.partner_webhook_initial_backoff_ms = 10;
  cfg.partner_webhook_max_backoff_ms = 20;

  const auto registry_path = unique_test_cache_path("finalis-partner-webhook-registry");
  {
    std::ofstream out(registry_path);
    out << "{"
           "\"partners\":[{"
           "\"partner_id\":\"pwh\","
           "\"api_key\":\"kwh\","
           "\"active_secret\":\"awh\","
           "\"webhook_url\":\"http://webhook.invalid/partner\","
           "\"webhook_secret\":\"whsec\","
           "\"enabled\":true"
           "}]"
           "}";
  }
  cfg.partner_registry_path = registry_path.string();
  std::string reg_err;
  ASSERT_TRUE(load_partner_registry(cfg, &reg_err));

  int webhook_calls = 0;
  const auto prev_post = g_partner_webhook_post_json;
  g_partner_webhook_post_json = [&](const std::string&, const std::string&, std::string*) -> std::optional<std::string> {
    ++webhook_calls;
    if (webhook_calls == 1) return std::nullopt;
    return std::optional<std::string>("{}");
  };

  g_partner_webhook_stop.store(false);
  std::thread worker([cfg]() { partner_webhook_worker(cfg); });

  const std::string body = std::string("{\"client_withdrawal_id\":\"whr1\",\"tx_hex\":\"") + finalis::hex_encode(fx.tx.serialize()) + "\"}";
  const std::string ts = std::to_string(static_cast<std::uint64_t>(std::time(nullptr)));
  const std::string nonce = "wh-n1";
  const std::string canonical = std::string("POST\n/api/v1/withdrawals\n") + ts + "\n" + nonce + "\n" + sha256_hex_text(body);
  const auto sig = hmac_sha256_hex("awh", canonical);
  ASSERT_TRUE(sig.has_value());
  const std::vector<std::pair<std::string, std::string>> headers{
      {"Idempotency-Key", "wh-idem-1"},
      {"X-Finalis-Api-Key", "kwh"},
      {"X-Finalis-Timestamp", ts},
      {"X-Finalis-Nonce", nonce},
      {"X-Finalis-Signature", *sig},
  };
  const auto created = handle_request(cfg, make_http_request("POST", "/api/v1/withdrawals", headers, body));
  ASSERT_TRUE(created.status == 200 || created.status == 201 || created.status == 202);

  const std::string nonce2 = "wh-n2";
  const std::string canonical2 = std::string("GET\n/api/v1/withdrawals/whr1\n") + ts + "\n" + nonce2 + "\n" + sha256_hex_text("");
  const auto sig2 = hmac_sha256_hex("awh", canonical2);
  ASSERT_TRUE(sig2.has_value());
  const auto get_req = make_http_request(
      "GET", "/api/v1/withdrawals/whr1",
      {{"X-Finalis-Api-Key", "kwh"}, {"X-Finalis-Timestamp", ts}, {"X-Finalis-Nonce", nonce2}, {"X-Finalis-Signature", *sig2}}, "");
  const auto finalized = handle_request(cfg, get_req);
  ASSERT_EQ(finalized.status, 200);
  ASSERT_TRUE(finalized.body.find("\"state\":\"finalized\"") != std::string::npos);

  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
  while (webhook_calls < 2 && std::chrono::steady_clock::now() < deadline) {
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  ASSERT_TRUE(webhook_calls >= 2);

  g_partner_webhook_stop.store(true);
  g_partner_webhook_cv.notify_all();
  worker.join();
  g_partner_webhook_post_json = prev_post;

  std::error_code ec;
  std::filesystem::remove(registry_path, ec);
}

TEST(test_explorer_partner_state_persists_across_restart) {
  ExplorerFixture fx;
  int broadcast_calls = 0;
  ScopedRpcHook hook([&](const std::string& body) {
    if (body.find("\"method\":\"broadcast_tx\"") != std::string::npos) {
      ++broadcast_calls;
      return rpc_result(std::string("{\"ok\":true,\"accepted\":true,\"status\":\"accepted_for_relay\",\"finalized\":false,")
                        + "\"txid\":\"" + fx.txid + "\",\"message\":\"accepted_for_relay\",\"retryable\":false,\"retry_class\":\"none\"}");
    }
    return default_rpc_handler(fx, body);
  });

  Config cfg = test_config();
  cfg.partner_auth_required = true;
  const auto cache_path = unique_test_cache_path("finalis-partner-state-cache");
  const auto registry_path = unique_test_cache_path("finalis-partner-state-registry");
  cfg.cache_path = cache_path.string();
  cfg.partner_registry_path = registry_path.string();
  {
    std::ofstream out(registry_path);
    out << "{"
           "\"partners\":[{"
           "\"partner_id\":\"pdur\","
           "\"api_key\":\"kdur\","
           "\"active_secret\":\"sdur\","
           "\"webhook_url\":\"http://webhook.invalid/pdur\","
           "\"webhook_secret\":\"whdur\","
           "\"enabled\":true"
           "}]"
           "}";
  }
  std::string reg_err;
  ASSERT_TRUE(load_partner_registry(cfg, &reg_err));

  const std::string body = std::string("{\"client_withdrawal_id\":\"w-dur-1\",\"tx_hex\":\"") + finalis::hex_encode(fx.tx.serialize()) + "\"}";
  const std::string ts = std::to_string(static_cast<std::uint64_t>(std::time(nullptr)));
  const std::string nonce = "dur-n1";
  const std::string canonical = std::string("POST\n/api/v1/withdrawals\n") + ts + "\n" + nonce + "\n" + sha256_hex_text(body);
  const auto sig = hmac_sha256_hex("sdur", canonical);
  ASSERT_TRUE(sig.has_value());
  const auto created = handle_request(
      cfg, make_http_request("POST", "/api/v1/withdrawals",
                             {{"Idempotency-Key", "idem-dur-1"},
                              {"X-Finalis-Api-Key", "kdur"},
                              {"X-Finalis-Timestamp", ts},
                              {"X-Finalis-Nonce", nonce},
                              {"X-Finalis-Signature", *sig}},
                             body));
  ASSERT_TRUE(created.status == 200 || created.status == 201 || created.status == 202);
  ASSERT_EQ(broadcast_calls, 1);

  const std::string nonce2 = "dur-n2";
  const std::string canonical2 = std::string("GET\n/api/v1/withdrawals/w-dur-1\n") + ts + "\n" + nonce2 + "\n" + sha256_hex_text("");
  const auto sig2 = hmac_sha256_hex("sdur", canonical2);
  ASSERT_TRUE(sig2.has_value());
  const auto finalized = handle_request(
      cfg, make_http_request("GET", "/api/v1/withdrawals/w-dur-1",
                             {{"X-Finalis-Api-Key", "kdur"},
                              {"X-Finalis-Timestamp", ts},
                              {"X-Finalis-Nonce", nonce2},
                              {"X-Finalis-Signature", *sig2}},
                             ""));
  ASSERT_EQ(finalized.status, 200);
  ASSERT_TRUE(finalized.body.find("\"state\":\"finalized\"") != std::string::npos);

  clear_runtime_caches();
  ASSERT_TRUE(load_partner_registry(cfg, &reg_err));
  load_persisted_explorer_snapshot(cfg);

  const std::string ts3 = std::to_string(static_cast<std::uint64_t>(std::time(nullptr)));
  const std::string nonce3 = "dur-n3";
  const std::string canonical3 = std::string("POST\n/api/v1/withdrawals\n") + ts3 + "\n" + nonce3 + "\n" + sha256_hex_text(body);
  const auto sig3 = hmac_sha256_hex("sdur", canonical3);
  ASSERT_TRUE(sig3.has_value());
  const auto replay = handle_request(
      cfg, make_http_request("POST", "/api/v1/withdrawals",
                             {{"Idempotency-Key", "idem-dur-1"},
                              {"X-Finalis-Api-Key", "kdur"},
                              {"X-Finalis-Timestamp", ts3},
                              {"X-Finalis-Nonce", nonce3},
                              {"X-Finalis-Signature", *sig3}},
                             body));
  ASSERT_EQ(replay.status, 200);
  ASSERT_EQ(broadcast_calls, 1);
  ASSERT_TRUE(replay.body.find("\"state\":\"finalized\"") != std::string::npos);

  const std::string nonce4 = "dur-n4";
  const std::string canonical4 = std::string("GET\n/api/v1/events/finalized\n") + ts3 + "\n" + nonce4 + "\n" + sha256_hex_text("");
  const auto sig4 = hmac_sha256_hex("sdur", canonical4);
  ASSERT_TRUE(sig4.has_value());
  const auto events = handle_request(
      cfg, make_http_request("GET", "/api/v1/events/finalized?from_sequence=1",
                             {{"X-Finalis-Api-Key", "kdur"},
                              {"X-Finalis-Timestamp", ts3},
                              {"X-Finalis-Nonce", nonce4},
                              {"X-Finalis-Signature", *sig4}},
                             ""));
  ASSERT_EQ(events.status, 200);
  ASSERT_TRUE(events.body.find("\"object_id\":\"w-dur-1\"") != std::string::npos);
  ASSERT_TRUE(events.body.find("\"state\":\"finalized\"") != std::string::npos);

  {
    std::lock_guard<std::mutex> guard(g_partner_mu);
    ASSERT_TRUE(!g_partner_webhook_queue.empty());
    ASSERT_EQ(g_partner_webhook_queue.front().partner_id, "pdur");
  }

  std::error_code ec;
  std::filesystem::remove(cache_path, ec);
  std::filesystem::remove(registry_path, ec);
}

TEST(test_explorer_partner_state_gc_prunes_stale_entries_and_dedupes_queue) {
  ExplorerFixture fx;
  ScopedRpcHook hook([&](const std::string& body) {
    if (body.find("\"method\":\"broadcast_tx\"") != std::string::npos) {
      return rpc_result(std::string("{\"ok\":true,\"accepted\":true,\"status\":\"accepted_for_relay\",\"finalized\":false,")
                        + "\"txid\":\"" + fx.txid + "\",\"message\":\"accepted_for_relay\",\"retryable\":false,\"retry_class\":\"none\"}");
    }
    return default_rpc_handler(fx, body);
  });

  Config cfg = test_config();
  cfg.partner_auth_required = true;
  cfg.partner_auth_max_skew_seconds = 1;
  cfg.partner_idempotency_ttl_seconds = 1;
  cfg.partner_events_ttl_seconds = 1;
  cfg.partner_webhook_queue_ttl_seconds = 1;
  const auto cache_path = unique_test_cache_path("finalis-partner-gc-cache");
  const auto registry_path = unique_test_cache_path("finalis-partner-gc-registry");
  cfg.cache_path = cache_path.string();
  cfg.partner_registry_path = registry_path.string();
  {
    std::ofstream out(registry_path);
    out << "{"
           "\"partners\":[{"
           "\"partner_id\":\"pgc\","
           "\"api_key\":\"kgc\","
           "\"active_secret\":\"sgc\","
           "\"webhook_url\":\"http://webhook.invalid/pgc\","
           "\"webhook_secret\":\"whgc\","
           "\"enabled\":true"
           "}]"
           "}";
  }
  std::string reg_err;
  ASSERT_TRUE(load_partner_registry(cfg, &reg_err));

  const std::string body = std::string("{\"client_withdrawal_id\":\"w-gc-1\",\"tx_hex\":\"") + finalis::hex_encode(fx.tx.serialize()) + "\"}";
  const std::string ts = std::to_string(static_cast<std::uint64_t>(std::time(nullptr)));
  const std::string nonce = "gc-n1";
  const std::string canonical = std::string("POST\n/api/v1/withdrawals\n") + ts + "\n" + nonce + "\n" + sha256_hex_text(body);
  const auto sig = hmac_sha256_hex("sgc", canonical);
  ASSERT_TRUE(sig.has_value());
  const auto created = handle_request(
      cfg, make_http_request("POST", "/api/v1/withdrawals",
                             {{"Idempotency-Key", "idem-gc-1"},
                              {"X-Finalis-Api-Key", "kgc"},
                              {"X-Finalis-Timestamp", ts},
                              {"X-Finalis-Nonce", nonce},
                              {"X-Finalis-Signature", *sig}},
                             body));
  ASSERT_TRUE(created.status == 200 || created.status == 201 || created.status == 202);

  const std::string nonce2 = "gc-n2";
  const std::string canonical2 = std::string("GET\n/api/v1/withdrawals/w-gc-1\n") + ts + "\n" + nonce2 + "\n" + sha256_hex_text("");
  const auto sig2 = hmac_sha256_hex("sgc", canonical2);
  ASSERT_TRUE(sig2.has_value());
  const auto finalized = handle_request(
      cfg, make_http_request("GET", "/api/v1/withdrawals/w-gc-1",
                             {{"X-Finalis-Api-Key", "kgc"},
                              {"X-Finalis-Timestamp", ts},
                              {"X-Finalis-Nonce", nonce2},
                              {"X-Finalis-Signature", *sig2}},
                             ""));
  ASSERT_EQ(finalized.status, 200);
  ASSERT_TRUE(finalized.body.find("\"state\":\"finalized\"") != std::string::npos);

  {
    std::lock_guard<std::mutex> guard(g_partner_mu);
    ASSERT_TRUE(!g_partner_events.empty());
    ASSERT_TRUE(!g_partner_webhook_queue.empty());
    const auto stale_ms = now_unix_ms() - 120000;
    for (auto& [_, ts_ms] : g_partner_idempotency_unix_ms) ts_ms = stale_ms;
    for (auto& evt : g_partner_events) evt.emitted_unix_ms = stale_ms;
    for (auto& q : g_partner_webhook_queue) {
      q.enqueued_unix_ms = stale_ms;
      q.next_attempt_unix_ms = stale_ms;
    }
    for (auto& [_, seen_sec] : g_seen_partner_nonce_unix_ms) seen_sec = (stale_ms / 1000) - 120;
    PartnerWebhookDelivery dup = g_partner_webhook_queue.front();
    dup.attempt += 1;
    g_partner_webhook_queue.push_back(dup);
  }

  persist_explorer_snapshot(cfg);

  {
    std::lock_guard<std::mutex> guard(g_partner_mu);
    ASSERT_TRUE(g_partner_idempotency_hash.empty());
    ASSERT_TRUE(g_partner_idempotency_client_id.empty());
    ASSERT_TRUE(g_partner_idempotency_unix_ms.empty());
    ASSERT_TRUE(g_partner_events.empty());
    ASSERT_TRUE(g_partner_webhook_queue.empty());
    ASSERT_TRUE(g_seen_partner_nonce_unix_ms.empty());
    ASSERT_TRUE(g_partner_next_sequence >= 1u);
  }

  std::error_code ec;
  std::filesystem::remove(cache_path, ec);
  std::filesystem::remove(registry_path, ec);
}

TEST(test_explorer_status_and_committee_surface_show_bounded_ticket_pow) {
  ExplorerFixture fx;
  ScopedRpcHook hook([&](const std::string& body) { return default_rpc_handler(fx, body); });
  const Config cfg = test_config();

  const auto status = handle_request(cfg, make_http_get("/api/status"));
  ASSERT_EQ(status.status, 200);
  ASSERT_TRUE(status.body.find("\"ticket_pow\"") != std::string::npos);
  ASSERT_TRUE(status.body.find("\"difficulty\":10") != std::string::npos);
  ASSERT_TRUE(status.body.find("\"operator_native\":") == std::string::npos);
  ASSERT_TRUE(status.body.find("\"economics_version\":") == std::string::npos);
  ASSERT_TRUE(status.body.find("\"adaptive_target_committee_size\":24") != std::string::npos);
  ASSERT_TRUE(status.body.find("\"qualified_depth\":26") != std::string::npos);
  ASSERT_TRUE(status.body.find("\"slack\":-1") != std::string::npos);
  ASSERT_TRUE(status.body.find("\"fallback_rate_bps\":2500") != std::string::npos);

  const auto committee = handle_request(cfg, make_http_get("/api/committee"));
  ASSERT_EQ(committee.status, 200);
  ASSERT_TRUE(committee.body.find("\"members\"") != std::string::npos);
  ASSERT_TRUE(committee.body.find("\"member_count\":1") != std::string::npos);
  ASSERT_TRUE(committee.body.find("\"resolved_operator_id\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"") !=
              std::string::npos);
  ASSERT_TRUE(committee.body.find("\"operator_id_source\":\"operator_id\"") != std::string::npos);
  ASSERT_TRUE(committee.body.find("\"base_weight\":100") != std::string::npos);
  ASSERT_TRUE(committee.body.find("\"ticket_bonus_bps\":1000") != std::string::npos);
  ASSERT_TRUE(committee.body.find("\"final_weight\":1010000") != std::string::npos);
  ASSERT_TRUE(committee.body.find("\"checkpoint_derivation_mode\":\"fallback\"") != std::string::npos);
  ASSERT_TRUE(committee.body.find("\"adaptive_min_eligible\":27") != std::string::npos);
  ASSERT_TRUE(committee.body.find("\"target_expand_streak\":3") != std::string::npos);

  const auto home = handle_request(cfg, make_http_get("/"));
  ASSERT_EQ(home.status, 200);
  ASSERT_TRUE(home.body.find("Operator View") != std::string::npos);
  ASSERT_TRUE(home.body.find("Operator-Native") == std::string::npos);
  ASSERT_TRUE(home.body.find("Open Committee View") != std::string::npos);
  ASSERT_TRUE(home.body.find("Protocol Reserve") != std::string::npos);
  ASSERT_TRUE(home.body.find("42.00000000 FLS") != std::string::npos);

  const auto committee_page = handle_request(cfg, make_http_get("/committee"));
  ASSERT_EQ(committee_page.status, 200);
  ASSERT_TRUE(committee_page.body.find("Selected Operators") != std::string::npos);
  ASSERT_TRUE(committee_page.body.find("ID Source") != std::string::npos);
  ASSERT_TRUE(committee_page.body.find("nonce 12") != std::string::npos);
  ASSERT_TRUE(committee_page.body.find("Checkpoint Mode") != std::string::npos);
  ASSERT_TRUE(committee_page.body.find("Qualified Operator Depth") != std::string::npos);
}

TEST(test_explorer_api_recent_tx_summary_contract) {
  ExplorerFixture fx;
  ScopedRpcHook hook([&](const std::string& body) { return default_rpc_handler(fx, body); });
  const Config cfg = test_config();

  const auto recent = handle_request(cfg, make_http_get("/api/recent-tx"));
  ASSERT_EQ(recent.status, 200);
  ASSERT_TRUE(recent.body.find("\"snapshot_kind\":\"recent_finalized_transactions\"") != std::string::npos);
  ASSERT_TRUE(recent.body.find("\"items\"") != std::string::npos);
  ASSERT_TRUE(recent.body.find("\"txid\":\"" + fx.txid + "\"") != std::string::npos);
  ASSERT_TRUE(recent.body.find("\"status_label\":\"FINALIZED (CREDIT SAFE)\"") != std::string::npos);
}

TEST(test_explorer_api_recent_tx_empty_state_contract) {
  ExplorerFixture fx;
  ScopedRpcHook hook([&](const std::string& body) { return no_recent_tx_rpc_handler(fx, body); });
  const Config cfg = test_config();

  const auto recent = handle_request(cfg, make_http_get("/api/recent-tx"));
  ASSERT_EQ(recent.status, 200);
  ASSERT_TRUE(recent.body.find("\"snapshot_kind\":\"recent_finalized_transactions\"") != std::string::npos);
  ASSERT_TRUE(recent.body.find("\"items\":[]") != std::string::npos);
}

TEST(test_explorer_root_page_recent_tx_empty_state_is_explicit) {
  ExplorerFixture fx;
  ScopedRpcHook hook([&](const std::string& body) { return no_recent_tx_rpc_handler(fx, body); });
  const Config cfg = test_config();

  const auto home = handle_request(cfg, make_http_get("/"));
  ASSERT_EQ(home.status, 200);
  ASSERT_TRUE(home.body.find("Finalized Transactions") != std::string::npos);
  ASSERT_TRUE(home.body.find("No finalized transactions were found in the recent finalized-height scan window.") != std::string::npos);
}

TEST(test_explorer_root_page_committee_empty_state_is_explicit) {
  ExplorerFixture fx;
  ScopedRpcHook hook([&](const std::string& body) { return empty_committee_rpc_handler(fx, body); });
  const Config cfg = test_config();

  const auto home = handle_request(cfg, make_http_get("/"));
  ASSERT_EQ(home.status, 200);
  ASSERT_TRUE(home.body.find("Operator View") != std::string::npos);
  ASSERT_TRUE(home.body.find("Open Committee View") != std::string::npos);

  const auto committee = handle_request(cfg, make_http_get("/committee"));
  ASSERT_EQ(committee.status, 200);
  ASSERT_TRUE(committee.body.find("No finalized committee members available.") != std::string::npos);
}

TEST(test_explorer_root_page_availability_enforcement_empty_state_is_explicit) {
  ExplorerFixture fx;
  ScopedRpcHook hook([&](const std::string& body) { return default_rpc_handler(fx, body); });
  const Config cfg = test_config();

  const auto home = handle_request(cfg, make_http_get("/"));
  ASSERT_EQ(home.status, 200);
  ASSERT_TRUE(home.body.find("Operator View") != std::string::npos);
  ASSERT_TRUE(home.body.find("Committee composition, Ticket PoW, and availability mechanics live on the dedicated committee page.") !=
              std::string::npos);

  const auto committee = handle_request(cfg, make_http_get("/committee"));
  ASSERT_EQ(committee.status, 200);
  ASSERT_TRUE(committee.body.find("Checkpoint Mode") != std::string::npos);
  ASSERT_TRUE(committee.body.find("Adaptive Committee Target") != std::string::npos);
}

TEST(test_explorer_root_page_surfaces_summary_sections_consistently) {
  ExplorerFixture fx;
  ScopedRpcHook hook([&](const std::string& body) { return default_rpc_handler(fx, body); });
  const Config cfg = test_config();

  const auto home = handle_request(cfg, make_http_get("/"));
  ASSERT_EQ(home.status, 200);
  ASSERT_TRUE(home.body.find("Finalized Transactions") != std::string::npos);
  ASSERT_TRUE(home.body.find("Operator View") != std::string::npos);
  ASSERT_TRUE(home.body.find("Finality Committee") != std::string::npos);
  ASSERT_TRUE(home.body.find("Network ID") != std::string::npos);
  ASSERT_TRUE(home.body.find("Genesis Hash") != std::string::npos);
  ASSERT_TRUE(home.body.find("Wallet API") != std::string::npos);
  ASSERT_TRUE(home.body.find("Protocol Reserve") != std::string::npos);
  ASSERT_TRUE(home.body.find("42.00000000 FLS") != std::string::npos);
  ASSERT_TRUE(home.body.find("Reserved by protocol issuance for long-horizon monetary rules.") != std::string::npos);
  ASSERT_TRUE(home.body.find("Copy Status API Path") != std::string::npos);
}

TEST(test_explorer_status_surface_remains_truthful_for_single_live_ticket_policy) {
  ExplorerFixture fx;
  ScopedRpcHook hook([&](const std::string& body) { return future_policy_rpc_handler(fx, body); });
  const Config cfg = test_config();

  const auto status = handle_request(cfg, make_http_get("/api/status"));
  ASSERT_EQ(status.status, 200);
  ASSERT_TRUE(status.body.find("\"economics_version\":") == std::string::npos);
  ASSERT_TRUE(status.body.find("\"operator_native\":") == std::string::npos);
  ASSERT_TRUE(status.body.find("\"bonus_cap_bps\":500") != std::string::npos);

  const auto home = handle_request(cfg, make_http_get("/"));
  ASSERT_EQ(home.status, 200);
  ASSERT_TRUE(home.body.find("Operator View") != std::string::npos);
  ASSERT_TRUE(home.body.find("Legacy adjustment policy") == std::string::npos);
}

TEST(test_explorer_api_transition_contract) {
  ExplorerFixture fx;
  ScopedRpcHook hook([&](const std::string& body) { return default_rpc_handler(fx, body); });
  const Config cfg = test_config();

  const auto by_height = handle_request(cfg, make_http_get("/api/transition/7"));
  ASSERT_EQ(by_height.status, 200);
  ASSERT_TRUE(by_height.body.find("\"height\":7") != std::string::npos);

  const auto missing_height = handle_request(cfg, make_http_get("/api/transition/999"));
  ASSERT_EQ(missing_height.status, 404);
  ASSERT_TRUE(missing_height.body.find("\"code\":\"not_found\"") != std::string::npos);

  const auto by_hash = handle_request(cfg, make_http_get("/api/transition/" + fx.transition_hash));
  ASSERT_EQ(by_hash.status, 200);
  ASSERT_TRUE(by_hash.body.find("\"hash\":\"" + fx.transition_hash + "\"") != std::string::npos);
  ASSERT_TRUE(by_hash.body.find("\"data_source\":\"") != std::string::npos);

  const auto malformed = handle_request(cfg, make_http_get("/api/transition/not-hex!"));
  ASSERT_EQ(malformed.status, 400);
  ASSERT_TRUE(malformed.body.find("\"code\":\"invalid_transition_id\"") != std::string::npos);

  const auto missing_hash = handle_request(cfg, make_http_get("/api/transition/" + fx.unknown_transition_hash));
  ASSERT_EQ(missing_hash.status, 404);
  ASSERT_TRUE(missing_hash.body.find("\"code\":\"not_found\"") != std::string::npos);

  const auto committee = handle_request(cfg, make_http_get("/api/committee"));
  ASSERT_EQ(committee.status, 200);
  ASSERT_TRUE(committee.body.find("\"snapshot_refreshed_unix_ms\":") != std::string::npos);

  const auto recent = handle_request(cfg, make_http_get("/api/recent-tx"));
  ASSERT_EQ(recent.status, 200);
  ASSERT_TRUE(recent.body.find("\"snapshot_refreshed_unix_ms\":") != std::string::npos);
}

TEST(test_explorer_api_address_contract_and_empty_state) {
  ExplorerFixture fx;
  ScopedRpcHook hook([&](const std::string& body) { return default_rpc_handler(fx, body); });
  ScopedUtxoHook utxo_hook([&](const Hash32& scripthash, std::string*) -> std::optional<std::vector<finalis::lightserver::UtxoView>> {
    if (scripthash == fx.known_scripthash) {
      finalis::lightserver::UtxoView utxo;
      utxo.txid = fx.tx.txid();
      utxo.vout = 0;
      utxo.value = 123456789u;
      utxo.height = 7;
      utxo.script_pubkey = fx.tx.outputs[0].script_pubkey;
      return std::vector<finalis::lightserver::UtxoView>{utxo};
    }
    return std::vector<finalis::lightserver::UtxoView>{};
  });
  const Config cfg = test_config();

  const auto known = handle_request(cfg, make_http_get("/api/address/" + fx.known_address));
  ASSERT_EQ(known.status, 200);
  ASSERT_TRUE(known.body.find("\"address\":\"" + fx.known_address + "\"") != std::string::npos);
  ASSERT_TRUE(known.body.find("\"found\":true") != std::string::npos);

  const auto empty = handle_request(cfg, make_http_get("/api/address/" + fx.empty_address));
  ASSERT_EQ(empty.status, 200);
  ASSERT_TRUE(empty.body.find("\"found\":false") != std::string::npos);
  ASSERT_TRUE(empty.body.find("\"utxos\":[]") != std::string::npos);
  ASSERT_TRUE(empty.body.find("\"items\":[]") != std::string::npos);
  ASSERT_TRUE(empty.body.find("\"has_more\":false") != std::string::npos);
  ASSERT_TRUE(empty.body.find("\"next_cursor\":null") != std::string::npos);

  const auto invalid = handle_request(cfg, make_http_get("/api/address/not-an-address"));
  ASSERT_EQ(invalid.status, 400);
  ASSERT_TRUE(invalid.body.find("\"code\":\"invalid_address\"") != std::string::npos);
}

TEST(test_explorer_api_search_contract) {
  ExplorerFixture fx;
  ScopedRpcHook hook([&](const std::string& body) { return default_rpc_handler(fx, body); });
  ScopedUtxoHook utxo_hook([&](const Hash32& scripthash, std::string*) -> std::optional<std::vector<finalis::lightserver::UtxoView>> {
    if (scripthash == fx.known_scripthash) {
      finalis::lightserver::UtxoView utxo;
      utxo.txid = fx.tx.txid();
      utxo.vout = 0;
      utxo.value = 123456789u;
      utxo.height = 7;
      utxo.script_pubkey = fx.tx.outputs[0].script_pubkey;
      return std::vector<finalis::lightserver::UtxoView>{utxo};
    }
    return std::vector<finalis::lightserver::UtxoView>{};
  });
  const Config cfg = test_config();

  const auto numeric = handle_request(cfg, make_http_get("/api/search?q=7"));
  ASSERT_EQ(numeric.status, 200);
  ASSERT_TRUE(numeric.body.find("\"classification\":\"transition_height\"") != std::string::npos);
  ASSERT_TRUE(numeric.body.find("\"target\":\"/transition/7\"") != std::string::npos);

  const auto tx = handle_request(cfg, make_http_get("/api/search?q=" + fx.txid));
  ASSERT_EQ(tx.status, 200);
  ASSERT_TRUE(tx.body.find("\"classification\":\"txid\"") != std::string::npos);
  ASSERT_TRUE(tx.body.find("\"target\":\"/tx/" + fx.txid + "\"") != std::string::npos);

  const auto transition = handle_request(cfg, make_http_get("/api/search?q=" + fx.transition_hash));
  ASSERT_EQ(transition.status, 200);
  ASSERT_TRUE(transition.body.find("\"classification\":\"transition_hash\"") != std::string::npos);
  ASSERT_TRUE(transition.body.find("\"target\":\"/transition/" + fx.transition_hash + "\"") != std::string::npos);

  const auto unknown_hex = handle_request(cfg, make_http_get("/api/search?q=" + fx.unknown_transition_hash));
  ASSERT_EQ(unknown_hex.status, 200);
  ASSERT_TRUE(unknown_hex.body.find("\"classification\":\"not_found\"") != std::string::npos);
  ASSERT_TRUE(unknown_hex.body.find("\"found\":false") != std::string::npos);
  ASSERT_TRUE(unknown_hex.body.find("\"target\":null") != std::string::npos);

  const auto active_addr = handle_request(cfg, make_http_get("/api/search?q=" + fx.known_address));
  ASSERT_EQ(active_addr.status, 200);
  ASSERT_TRUE(active_addr.body.find("\"classification\":\"address\"") != std::string::npos);
  ASSERT_TRUE(active_addr.body.find("\"target\":\"/address/" + fx.known_address + "\"") != std::string::npos);

  const auto empty_addr = handle_request(cfg, make_http_get("/api/search?q=" + fx.empty_address));
  ASSERT_EQ(empty_addr.status, 200);
  ASSERT_TRUE(empty_addr.body.find("\"classification\":\"address\"") != std::string::npos);
  ASSERT_TRUE(empty_addr.body.find("\"found\":false") != std::string::npos);
  ASSERT_TRUE(empty_addr.body.find("\"target\":null") != std::string::npos);

  const auto invalid = handle_request(cfg, make_http_get("/api/search?q=hello"));
  ASSERT_EQ(invalid.status, 400);
  ASSERT_TRUE(invalid.body.find("\"code\":\"invalid_query\"") != std::string::npos);
}

TEST(test_explorer_redirect_sanitizes_location_header) {
  const auto resp = redirect_response("/tx/abc\r\nX-Evil: yes");
  const auto wire = http_response(resp);
  ASSERT_TRUE(wire.find("Location: /\r\n") != std::string::npos);
  ASSERT_TRUE(wire.find("X-Evil: yes") == std::string::npos);
}

TEST(test_explorer_address_pagination_contract) {
  ExplorerFixture fx;

  ScopedRpcHook last_page_hook([&](const std::string& body) {
    if (body.find("\"method\":\"get_status\"") != std::string::npos) {
      return rpc_result(std::string("{\"network_name\":\"mainnet\",\"finalized_height\":10,\"finalized_transition_hash\":\"") +
                        fx.transition_hash + "\",\"version\":\"fake-lightserver\"}");
    }
    if (body.find("\"method\":\"get_utxos\"") != std::string::npos) return rpc_result("[]");
    if (body.find("\"method\":\"get_history_page\"") != std::string::npos) {
      return rpc_result("{\"items\":[],\"has_more\":false,\"next_start_after\":{\"height\":123,\"txid\":\"abcd\"}}");
    }
    return rpc_error(-32601, "unknown method");
  });
  ScopedUtxoHook last_page_utxo_hook([&](const Hash32&, std::string*) -> std::optional<std::vector<finalis::lightserver::UtxoView>> {
    return std::vector<finalis::lightserver::UtxoView>{};
  });
  auto last_page = handle_request(test_config(), make_http_get("/api/address/" + fx.empty_address));
  ASSERT_EQ(last_page.status, 200);
  ASSERT_TRUE(last_page.body.find("\"has_more\":false") != std::string::npos);
  ASSERT_TRUE(last_page.body.find("\"next_cursor\":null") != std::string::npos);

  int page_calls = 0;
  ScopedRpcHook more_pages_hook([&](const std::string& body) {
    if (body.find("\"method\":\"get_status\"") != std::string::npos) {
      return rpc_result(std::string("{\"network_name\":\"mainnet\",\"finalized_height\":10,\"finalized_transition_hash\":\"") +
                        fx.transition_hash + "\",\"version\":\"fake-lightserver\"}");
    }
    if (body.find("\"method\":\"get_utxos\"") != std::string::npos) return rpc_result("[]");
    if (body.find("\"method\":\"get_history_page\"") != std::string::npos) {
      ++page_calls;
      return rpc_result(std::string("{\"items\":[{\"txid\":\"") + fx.txid + "\",\"height\":7}],\"has_more\":true,"
                        "\"next_start_after\":{\"height\":" + std::to_string(100 + page_calls) + ",\"txid\":\"" + fx.txid + "\"}}");
    }
    return rpc_error(-32601, "unknown method");
  });
  ScopedUtxoHook more_pages_utxo_hook([&](const Hash32&, std::string*) -> std::optional<std::vector<finalis::lightserver::UtxoView>> {
    return std::vector<finalis::lightserver::UtxoView>{};
  });
  auto paged = handle_request(test_config(), make_http_get("/api/address/" + fx.empty_address));
  ASSERT_EQ(paged.status, 200);
  ASSERT_TRUE(paged.body.find("\"has_more\":true") != std::string::npos);
  ASSERT_TRUE(paged.body.find("\"next_cursor\":\"") != std::string::npos);

  ScopedRpcHook malformed_cursor_hook([&](const std::string& body) {
    if (body.find("\"method\":\"get_status\"") != std::string::npos) {
      return rpc_result(std::string("{\"network_name\":\"mainnet\",\"finalized_height\":10,\"finalized_transition_hash\":\"") +
                        fx.transition_hash + "\",\"version\":\"fake-lightserver\"}");
    }
    if (body.find("\"method\":\"get_utxos\"") != std::string::npos) return rpc_result("[]");
    if (body.find("\"method\":\"get_history_page\"") != std::string::npos) {
      return rpc_result("{\"items\":[],\"has_more\":true}");
    }
    return rpc_error(-32601, "unknown method");
  });
  ScopedUtxoHook malformed_cursor_utxo_hook([&](const Hash32&, std::string*) -> std::optional<std::vector<finalis::lightserver::UtxoView>> {
    return std::vector<finalis::lightserver::UtxoView>{};
  });
  auto malformed = handle_request(test_config(), make_http_get("/api/address/" + fx.empty_address));
  ASSERT_EQ(malformed.status, 502);
  ASSERT_TRUE(malformed.body.find("\"code\":\"upstream_error\"") != std::string::npos);
}

TEST(test_explorer_upstream_failure_returns_consistent_json_error) {
  ScopedRpcHook hook([&](const std::string& body) -> std::string {
    if (body.find("\"method\":\"get_status\"") != std::string::npos) return "not-json";
    return rpc_error(-32601, "unknown method");
  });
  const auto resp = handle_request(test_config(), make_http_get("/api/status"));
  ASSERT_EQ(resp.status, 502);
  ASSERT_TRUE(resp.body.find("\"error\":{\"code\":\"upstream_error\"") != std::string::npos);
  ASSERT_TRUE(resp.body.find("\"message\":\"invalid rpc response\"") != std::string::npos);
}

TEST(test_explorer_healthz_reports_upstream_health) {
  ExplorerFixture fx;
  ScopedRpcHook ok_hook([&](const std::string& body) {
    if (body.find("\"method\":\"get_status\"") != std::string::npos) {
      return rpc_result(std::string("{\"network_name\":\"mainnet\",\"finalized_height\":10,\"finalized_transition_hash\":\"") +
                        fx.transition_hash + "\",\"version\":\"fake-lightserver\"}");
    }
    return rpc_error(-32601, "unknown method");
  });
  const auto ok = handle_request(test_config(), make_http_get("/healthz"));
  ASSERT_EQ(ok.status, 200);
  ASSERT_TRUE(ok.body.find("\"ok\":true") != std::string::npos);
  ASSERT_TRUE(ok.body.find("\"finalized_only\":true") != std::string::npos);
  ASSERT_TRUE(ok.body.find("\"upstream_ok\":true") != std::string::npos);

  ScopedRpcHook fail_hook([&](const std::string& body) -> std::string {
    if (body.find("\"method\":\"get_status\"") != std::string::npos) return "not-json";
    return rpc_error(-32601, "unknown method");
  });
  const auto failed = handle_request(test_config(), make_http_get("/healthz"));
  ASSERT_EQ(failed.status, 502);
  ASSERT_TRUE(failed.body.find("\"ok\":false") != std::string::npos);
  ASSERT_TRUE(failed.body.find("\"finalized_only\":true") != std::string::npos);
  ASSERT_TRUE(failed.body.find("\"upstream_ok\":false") != std::string::npos);
  ASSERT_TRUE(failed.body.find("\"error\":{\"code\":\"upstream_error\"") != std::string::npos);
}

TEST(test_explorer_hydrates_startup_cache_from_disk_without_live_rpc) {
  ExplorerFixture fx;
  Config cfg = test_config();
  const auto temp_path = unique_test_cache_path("finalis-explorer-cache-test");
  cfg.cache_path = temp_path.string();
  std::error_code ec;
  std::filesystem::remove(temp_path, ec);

  {
    ScopedRpcHook rpc([&](const std::string& body) { return default_rpc_handler(fx, body); });
    auto status = fetch_status_result(cfg);
    ASSERT_TRUE(status.value.has_value());
    auto committee = fetch_committee_result(cfg, status.value->finalized_height);
    ASSERT_TRUE(committee.value.has_value());
    const auto recent = fetch_recent_tx_results(cfg, kPersistedRecentLimit);
    ASSERT_TRUE(!recent.empty());
  }

  clear_runtime_caches();
  int rpc_calls = 0;
  {
    ScopedRpcHook rpc([&](const std::string&) {
      ++rpc_calls;
      return rpc_error(-32000, "rpc should not be used");
    });
    load_persisted_explorer_snapshot(cfg);
    auto status = fetch_status_result(cfg);
    ASSERT_TRUE(status.value.has_value());
    ASSERT_EQ(status.value->finalized_height, 10u);
    auto committee = fetch_committee_result(cfg, status.value->finalized_height);
    ASSERT_TRUE(committee.value.has_value());
    ASSERT_EQ(committee.value->members.size(), 1u);
    const auto recent = fetch_recent_tx_results(cfg, kPersistedRecentLimit);
    ASSERT_TRUE(!recent.empty());
    ASSERT_EQ(recent.front().txid, fx.txid);
    ASSERT_EQ(rpc_calls, 0);
  }

  std::filesystem::remove(temp_path, ec);
}

TEST(test_explorer_hydrates_tx_and_transition_index_from_disk_without_live_rpc) {
  ExplorerFixture fx;
  Config cfg = test_config();
  const auto temp_path = unique_test_cache_path("finalis-explorer-index-cache-test");
  cfg.cache_path = temp_path.string();
  std::error_code ec;
  std::filesystem::remove(temp_path, ec);

  {
    ScopedRpcHook rpc([&](const std::string& body) { return default_rpc_handler(fx, body); });
    auto tx = fetch_tx_result(cfg, fx.txid);
    ASSERT_TRUE(tx.value.has_value());
    auto transition = fetch_transition_result(cfg, fx.transition_hash);
    ASSERT_TRUE(transition.value.has_value());
    ASSERT_TRUE(transition.value->summary_cached);
  }

  clear_runtime_caches();
  int rpc_calls = 0;
  {
    ScopedRpcHook rpc([&](const std::string&) {
      ++rpc_calls;
      return rpc_error(-32000, "rpc should not be used");
    });
    load_persisted_explorer_snapshot(cfg);
    auto tx = fetch_tx_result(cfg, fx.txid);
    ASSERT_TRUE(tx.value.has_value());
    ASSERT_EQ(tx.value->txid, fx.txid);
    ASSERT_EQ(tx.value->data_source, "cache_finalized_snapshot");
    ASSERT_TRUE(tx.value->data_refreshed_unix_ms.has_value());
    auto transition = fetch_transition_result(cfg, fx.transition_hash);
    ASSERT_TRUE(transition.value.has_value());
    ASSERT_EQ(transition.value->hash, fx.transition_hash);
    ASSERT_TRUE(transition.value->summary_cached);
    ASSERT_EQ(transition.value->data_source, "cache_finalized_snapshot");
    ASSERT_TRUE(transition.value->data_refreshed_unix_ms.has_value());
    ASSERT_EQ(rpc_calls, 0);
  }

  std::filesystem::remove(temp_path, ec);
}

TEST(test_explorer_tx_and_transition_pages_surface_cached_data_source) {
  ExplorerFixture fx;
  Config cfg = test_config();
  const auto temp_path = unique_test_cache_path("finalis-explorer-provenance-cache-test");
  cfg.cache_path = temp_path.string();
  std::error_code ec;
  std::filesystem::remove(temp_path, ec);

  {
    ScopedRpcHook rpc([&](const std::string& body) { return default_rpc_handler(fx, body); });
    auto tx = fetch_tx_result(cfg, fx.txid);
    ASSERT_TRUE(tx.value.has_value());
    auto transition = fetch_transition_result(cfg, fx.transition_hash);
    ASSERT_TRUE(transition.value.has_value());
  }

  clear_runtime_caches();
  {
    ScopedRpcHook rpc([&](const std::string&) { return rpc_error(-32000, "rpc should not be used"); });
    load_persisted_explorer_snapshot(cfg);
    const auto tx_json = render_tx_json(*fetch_tx_result(cfg, fx.txid).value);
    ASSERT_TRUE(tx_json.find("\"data_refreshed_unix_ms\":") != std::string::npos);
    const auto tx_page = render_tx(cfg, fx.txid);
    ASSERT_TRUE(tx_page.find("Explorer data source: <strong>cached finalized snapshot</strong>") != std::string::npos);
    ASSERT_TRUE(tx_page.find("<div>Data Source</div><div>cached finalized snapshot</div>") != std::string::npos);
    ASSERT_TRUE(tx_page.find("Last refreshed from RPC: ") != std::string::npos);
    ASSERT_TRUE(tx_page.find("<div>Snapshot Refreshed</div><div>") != std::string::npos);
    const auto transition_json = render_transition_json(cfg, *fetch_transition_result(cfg, fx.transition_hash).value);
    ASSERT_TRUE(transition_json.find("\"data_refreshed_unix_ms\":") != std::string::npos);
    const auto transition_page = render_transition(cfg, fx.transition_hash);
    ASSERT_TRUE(transition_page.find("Explorer data source: <strong>cached finalized snapshot</strong>") != std::string::npos);
    ASSERT_TRUE(transition_page.find("<div>Data Source</div><div>cached finalized snapshot</div>") != std::string::npos);
    ASSERT_TRUE(transition_page.find("Last refreshed from RPC: ") != std::string::npos);
    ASSERT_TRUE(transition_page.find("<div>Snapshot Refreshed</div><div>") != std::string::npos);
  }

  std::filesystem::remove(temp_path, ec);
}

TEST(test_explorer_tx_page_and_json_surface_decoded_onboarding_registration_fields) {
  Config cfg = test_config();
  const auto funding = node::Node::deterministic_test_keypairs()[0];
  const auto validator = node::Node::deterministic_test_keypairs()[1];
  const auto payout = node::Node::deterministic_test_keypairs()[2];
  const auto payout_addr = make_address(0x33);
  const auto decoded = address::decode(payout_addr);
  ASSERT_TRUE(decoded.has_value());
  OutPoint prev{};
  prev.txid[31] = 0x71;
  prev.index = 0;
  const auto funding_pkh = crypto::h160(Bytes(funding.public_key.begin(), funding.public_key.end()));
  const TxOut prev_out{1'000'000, address::p2pkh_script_pubkey(funding_pkh)};
  auto tx = build_onboarding_registration_tx(prev, prev_out, funding.private_key, validator.public_key, validator.private_key,
                                             payout.public_key, 1'000, prev_out.script_pubkey);
  ASSERT_TRUE(tx.has_value());
  FrontierTransition transition = make_test_transition(7);
  const auto txid = hex_encode32(tx->txid());
  const auto transition_hash = hex_encode32(transition.transition_id());

  ScopedRpcHook rpc([&](const std::string& body) {
    if (body.find("\"method\":\"get_status\"") != std::string::npos) {
      return rpc_result(std::string("{\"network_name\":\"mainnet\",\"finalized_height\":10,\"finalized_transition_hash\":\"") +
                        transition_hash + "\",\"version\":\"fake-lightserver\",\"protocol_reserve_balance\":4200000000,"
                        "\"availability\":{\"local_operator\":{\"known\":false,\"pubkey\":null,\"status\":null,\"seat_budget\":null,"
                        "\"validator_registry_status\":null,\"onboarding_reward_eligible\":null,"
                        "\"onboarding_reward_score_units\":null}},"
                        "\"onboarding\":{\"reward_pool_bps\":300,\"admission_pow_difficulty_bits\":20,"
                        "\"validator_join_admission_pow_difficulty_bits\":22},"
                        "\"ticket_pow\":{\"difficulty\":10,\"difficulty_min\":8,\"difficulty_max\":12,"
                        "\"epoch_health\":\"healthy\",\"streak_up\":1,\"streak_down\":0,"
                        "\"nonce_search_limit\":4096,\"bonus_cap_bps\":1000}}");
    }
    if (body.find("\"method\":\"get_tx_status\"") != std::string::npos) {
      return rpc_result(std::string("{\"status\":\"finalized\",\"finalized\":true,\"height\":7,\"finalized_depth\":4,") +
                        "\"credit_safe\":true,\"transition_hash\":\"" + transition_hash + "\"}");
    }
    if (body.find("\"method\":\"get_tx\"") != std::string::npos) {
      return rpc_result(std::string("{\"tx_hex\":\"") + hex_encode(tx->serialize()) +
                        "\",\"decoded_outputs\":[{\"amount\":0,\"address\":null,\"script_hex\":\"" +
                        hex_encode(tx->outputs[0].script_pubkey) +
                        "\",\"decoded_kind\":\"onboarding_registration\",\"validator_pubkey_hex\":\"" +
                        hex_encode(Bytes(validator.public_key.begin(), validator.public_key.end())) +
                        "\",\"payout_pubkey_hex\":\"" + hex_encode(Bytes(payout.public_key.begin(), payout.public_key.end())) +
                        "\",\"has_admission_pow\":false,\"admission_pow_epoch\":null,\"admission_pow_nonce\":null},"
                        "{\"amount\":999000,\"address\":\"" + payout_addr + "\",\"script_hex\":\"" +
                        hex_encode(tx->outputs[1].script_pubkey) +
                        "\",\"decoded_kind\":null,\"validator_pubkey_hex\":null,\"payout_pubkey_hex\":null,"
                        "\"has_admission_pow\":false,\"admission_pow_epoch\":null,\"admission_pow_nonce\":null}]}");
    }
    if (body.find("\"method\":\"get_transition_by_height\"") != std::string::npos || body.find("\"method\":\"get_transition\"") != std::string::npos) {
      return rpc_result(std::string("{\"height\":7,\"hash\":\"") + transition_hash + "\",\"transition_hash\":\"" + transition_hash +
                        "\",\"transition_hex\":\"" + hex_encode(transition.serialize()) + "\"}");
    }
    return rpc_error(-32601, "unknown method");
  });

  const auto tx_json = render_tx_json(*fetch_tx_result(cfg, txid).value);
  ASSERT_TRUE(tx_json.find("\"decoded_kind\":\"onboarding_registration\"") != std::string::npos);
  ASSERT_TRUE(tx_json.find("\"validator_pubkey_hex\":\"" + hex_encode(Bytes(validator.public_key.begin(), validator.public_key.end())) + "\"") !=
              std::string::npos);
  const auto tx_page = render_tx(cfg, txid);
  ASSERT_TRUE(tx_page.find("SCONBREG onboarding registration") != std::string::npos);
  ASSERT_TRUE(tx_page.find("admission PoW") == std::string::npos);
  ASSERT_TRUE(tx_page.find(short_hex(hex_encode(Bytes(validator.public_key.begin(), validator.public_key.end())))) != std::string::npos);
}

TEST(test_explorer_home_and_committee_surface_per_section_refresh_times) {
  ExplorerFixture fx;
  Config cfg = test_config();
  const auto temp_path = unique_test_cache_path("finalis-explorer-section-refresh-cache-test");
  cfg.cache_path = temp_path.string();
  std::error_code ec;
  std::filesystem::remove(temp_path, ec);

  {
    ScopedRpcHook rpc([&](const std::string& body) { return default_rpc_handler(fx, body); });
    ASSERT_TRUE(fetch_status_result(cfg).value.has_value());
    ASSERT_TRUE(fetch_committee_result(cfg, 10).value.has_value());
    (void)fetch_recent_tx_results(cfg, 8);
  }

  clear_runtime_caches();
  {
    ScopedRpcHook rpc([&](const std::string&) { return rpc_error(-32000, "rpc should not be used"); });
    load_persisted_explorer_snapshot(cfg);
    const auto home = render_root(cfg);
    ASSERT_TRUE(home.find("Status Snapshot Refreshed") != std::string::npos);
    ASSERT_TRUE(home.find("Recent transactions snapshot refreshed from RPC: ") != std::string::npos);
    const auto committee = render_committee(cfg);
    ASSERT_TRUE(committee.find("Committee snapshot refreshed from RPC: ") != std::string::npos);
  }

  std::filesystem::remove(temp_path, ec);
}

TEST(test_explorer_homepage_shows_stale_banner_when_cached_surfaces_fallback_after_rpc_failure) {
  ExplorerFixture fx;
  Config cfg = test_config();
  const auto temp_path = unique_test_cache_path("finalis-explorer-stale-banner-cache-test");
  cfg.cache_path = temp_path.string();
  std::error_code ec;
  std::filesystem::remove(temp_path, ec);

  {
    ScopedRpcHook rpc([&](const std::string& body) { return default_rpc_handler(fx, body); });
    ASSERT_TRUE(fetch_status_result(cfg).value.has_value());
    ASSERT_TRUE(fetch_committee_result(cfg, 10).value.has_value());
    (void)fetch_recent_tx_results(cfg, 8);
  }

  clear_runtime_caches();
  load_persisted_explorer_snapshot(cfg);
  {
    std::lock_guard<std::mutex> guard(g_status_cache_mu);
    g_status_cache.stored_at = std::chrono::steady_clock::now() - std::chrono::seconds(10);
  }
  {
    std::lock_guard<std::mutex> guard(g_recent_tx_cache_mu);
    g_recent_tx_cache.stored_at = std::chrono::steady_clock::now() - std::chrono::seconds(10);
  }
  {
    std::lock_guard<std::mutex> guard(g_committee_cache_mu);
    g_committee_cache.stored_at = std::chrono::steady_clock::now() - std::chrono::seconds(10);
  }

  {
    const auto prev = g_http_post_json_raw;
    g_http_post_json_raw = [&](const std::string&, const std::string&, std::string*) {
      return std::optional<std::string>(rpc_error(-32000, "upstream down"));
    };
    const auto home = render_root(cfg);
    ASSERT_TRUE(home.find("Snapshot Freshness Warning") != std::string::npos);
    ASSERT_TRUE(home.find("because live RPC refresh failed") != std::string::npos);
    ASSERT_TRUE(home.find("status error=") != std::string::npos);
    g_http_post_json_raw = prev;
  }

  std::filesystem::remove(temp_path, ec);
}

}  // namespace
