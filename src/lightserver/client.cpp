#include "lightserver/client.hpp"

#include <array>
#include <cctype>
#include <limits>
#include <sstream>

#include "codec/bytes.hpp"
#include "common/minijson.hpp"
#include "common/socket_compat.hpp"

namespace finalis::lightserver {
namespace {

struct ParsedHttpUrl {
  std::string host;
  std::uint16_t port{0};
  std::string path;
};

struct UtxoCursor {
  std::uint64_t height{0};
  Hash32 txid{};
  std::uint32_t vout{0};
};

struct UtxoPageView {
  std::vector<UtxoView> items;
  bool has_more{false};
  std::optional<UtxoCursor> next_start_after;
};

std::optional<net::SocketHandle> connect_tcp(const std::string& host, std::uint16_t port) {
  if (!net::ensure_sockets()) return std::nullopt;
  addrinfo hints{};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  addrinfo* res = nullptr;
  if (::getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res) != 0) return std::nullopt;
  net::SocketHandle fd = net::kInvalidSocket;
  for (addrinfo* it = res; it != nullptr; it = it->ai_next) {
    fd = ::socket(it->ai_family, it->ai_socktype, it->ai_protocol);
    if (!net::valid_socket(fd)) continue;
    (void)net::set_socket_timeouts(fd, 15'000);
    if (::connect(fd, it->ai_addr, it->ai_addrlen) == 0) break;
    net::close_socket(fd);
    fd = net::kInvalidSocket;
  }
  ::freeaddrinfo(res);
  if (!net::valid_socket(fd)) return std::nullopt;
  return fd;
}

std::optional<ParsedHttpUrl> parse_http_url(const std::string& url) {
  const std::string prefix = "http://";
  if (url.rfind(prefix, 0) != 0) return std::nullopt;
  const std::string rest = url.substr(prefix.size());
  const auto slash = rest.find('/');
  const std::string hostport = (slash == std::string::npos) ? rest : rest.substr(0, slash);
  const std::string path = (slash == std::string::npos) ? "/" : rest.substr(slash);
  const auto colon = hostport.rfind(':');
  if (colon == std::string::npos) return std::nullopt;
  ParsedHttpUrl parsed;
  parsed.host = hostport.substr(0, colon);
  parsed.port = static_cast<std::uint16_t>(std::stoi(hostport.substr(colon + 1)));
  parsed.path = path;
  return parsed;
}

bool write_all(net::SocketHandle fd, const std::string& data) {
  size_t off = 0;
  while (off < data.size()) {
    ssize_t n = ::send(fd, data.data() + off, data.size() - off, 0);
    if (n <= 0) return false;
    off += static_cast<size_t>(n);
  }
  return true;
}

std::optional<std::string> read_all(net::SocketHandle fd) {
  std::string out;
  std::array<char, 4096> buf{};
  while (true) {
    ssize_t n = ::recv(fd, buf.data(), buf.size(), 0);
    if (n < 0) return std::nullopt;
    if (n == 0) break;
    out.append(buf.data(), static_cast<size_t>(n));
  }
  return out;
}

std::optional<std::string> http_post_json(const std::string& url, const std::string& body, std::string* err) {
  auto parsed = parse_http_url(url);
  if (!parsed) {
    if (err) *err = "invalid http url";
    return std::nullopt;
  }
  auto fd_opt = connect_tcp(parsed->host, parsed->port);
  if (!fd_opt) {
    if (err) *err = "connect failed";
    return std::nullopt;
  }
  const auto fd = *fd_opt;
  std::ostringstream req;
  req << "POST " << parsed->path << " HTTP/1.1\r\n"
      << "Host: " << parsed->host << ":" << parsed->port << "\r\n"
      << "Content-Type: application/json\r\n"
      << "Content-Length: " << body.size() << "\r\n"
      << "Connection: close\r\n\r\n"
      << body;
  if (!write_all(fd, req.str())) {
    net::close_socket(fd);
    if (err) *err = "send failed";
    return std::nullopt;
  }
  auto resp = read_all(fd);
  net::close_socket(fd);
  if (!resp) {
    if (err) *err = "read failed";
    return std::nullopt;
  }
  const auto body_pos = resp->find("\r\n\r\n");
  if (body_pos == std::string::npos) {
    if (err) *err = "invalid http response";
    return std::nullopt;
  }
  return resp->substr(body_pos + 4);
}

const minijson::Value* result_value(const minijson::Value& root, std::string* err) {
  if (!root.is_object()) {
    if (err) *err = "invalid rpc response";
    return nullptr;
  }
  if (const auto* error = root.get("error"); error && !error->is_null()) {
    if (err) *err = "rpc returned error";
    return nullptr;
  }
  const auto* result = root.get("result");
  if (!result) {
    if (err) *err = "missing rpc result";
    return nullptr;
  }
  return result;
}

std::optional<std::string> object_string(const minijson::Value* obj, const char* key) {
  if (!obj || !obj->is_object()) return std::nullopt;
  const auto* value = obj->get(key);
  if (!value) return std::nullopt;
  return value->as_string();
}

std::optional<std::uint64_t> object_u64(const minijson::Value* obj, const char* key);
std::optional<bool> object_bool(const minijson::Value* obj, const char* key);
std::optional<Hash32> parse_hex32_field(const std::string& hex);

std::optional<UtxoView> parse_utxo_entry(const minijson::Value& entry) {
  auto txid_hex = object_string(&entry, "txid");
  auto vout = object_u64(&entry, "vout");
  auto value = object_u64(&entry, "value");
  auto height = object_u64(&entry, "height");
  auto spk_hex = object_string(&entry, "script_pubkey_hex");
  if (!txid_hex || !vout || !value || !height || !spk_hex) return std::nullopt;
  auto txid = parse_hex32_field(*txid_hex);
  auto spk = hex_decode(*spk_hex);
  if (!txid || !spk || *vout > std::numeric_limits<std::uint32_t>::max()) return std::nullopt;
  return UtxoView{*txid, static_cast<std::uint32_t>(*vout), *value, *height, *spk};
}

std::optional<UtxoPageView> parse_utxo_page_result(const minijson::Value* result, std::string* err) {
  if (!result) return std::nullopt;
  UtxoPageView out;
  if (result->is_array()) {
    for (const auto& entry : result->array_value) {
      auto utxo = parse_utxo_entry(entry);
      if (utxo.has_value()) out.items.push_back(std::move(*utxo));
    }
    return out;
  }
  if (!result->is_object()) return std::nullopt;
  out.has_more = object_bool(result, "has_more").value_or(false);
  const auto* items = result->get("items");
  if (!items || !items->is_array()) {
    if (err) *err = "missing utxo page items";
    return std::nullopt;
  }
  for (const auto& entry : items->array_value) {
    auto utxo = parse_utxo_entry(entry);
    if (utxo.has_value()) out.items.push_back(std::move(*utxo));
  }
  const auto* next = result->get("next_start_after");
  if (!next || next->is_null()) return out;
  auto next_height = object_u64(next, "height");
  auto next_txid_hex = object_string(next, "txid");
  auto next_vout = object_u64(next, "vout");
  if (!next_height || !next_txid_hex || !next_vout || *next_vout > std::numeric_limits<std::uint32_t>::max()) {
    if (err) *err = "malformed utxo page cursor";
    return std::nullopt;
  }
  auto next_txid = parse_hex32_field(*next_txid_hex);
  if (!next_txid) {
    if (err) *err = "malformed utxo page cursor";
    return std::nullopt;
  }
  out.next_start_after = UtxoCursor{*next_height, *next_txid, static_cast<std::uint32_t>(*next_vout)};
  return out;
}

std::optional<std::uint64_t> object_u64(const minijson::Value* obj, const char* key) {
  if (!obj || !obj->is_object()) return std::nullopt;
  const auto* value = obj->get(key);
  if (!value) return std::nullopt;
  return value->as_u64();
}

std::optional<bool> object_bool(const minijson::Value* obj, const char* key) {
  if (!obj || !obj->is_object()) return std::nullopt;
  const auto* value = obj->get(key);
  if (!value) return std::nullopt;
  return value->as_bool();
}

std::optional<std::int64_t> object_i64(const minijson::Value* obj, const char* key) {
  if (!obj || !obj->is_object()) return std::nullopt;
  const auto* value = obj->get(key);
  if (!value || !value->is_number()) return std::nullopt;
  try {
    return std::stoll(value->string_value);
  } catch (...) {
    return std::nullopt;
  }
}

std::optional<Hash32> parse_hex32_field(const std::string& hex) {
  auto bytes = hex_decode(hex);
  if (!bytes || bytes->size() != 32) return std::nullopt;
  Hash32 out{};
  std::copy(bytes->begin(), bytes->end(), out.begin());
  return out;
}

std::string json_escape(const std::string& in) {
  std::string out;
  out.reserve(in.size() + 8);
  for (char c : in) {
    if (c == '"' || c == '\\') {
      out.push_back('\\');
      out.push_back(c);
    } else if (c == '\n') {
      out += "\\n";
    } else {
      out.push_back(c);
    }
  }
  return out;
}

std::optional<onboarding::ValidatorOnboardingState> parse_onboarding_state(const std::string& state) {
  using onboarding::ValidatorOnboardingState;
  if (state == "idle") return ValidatorOnboardingState::IDLE;
  if (state == "checking_prereqs") return ValidatorOnboardingState::CHECKING_PREREQS;
  if (state == "waiting_for_sync") return ValidatorOnboardingState::WAITING_FOR_SYNC;
  if (state == "waiting_for_funds") return ValidatorOnboardingState::WAITING_FOR_FUNDS;
  if (state == "selecting_utxos") return ValidatorOnboardingState::SELECTING_UTXOS;
  if (state == "building_join_tx") return ValidatorOnboardingState::BUILDING_JOIN_TX;
  if (state == "broadcasting_join_tx") return ValidatorOnboardingState::BROADCASTING_JOIN_TX;
  if (state == "waiting_for_finalization") return ValidatorOnboardingState::WAITING_FOR_FINALIZATION;
  if (state == "pending_activation") return ValidatorOnboardingState::PENDING_ACTIVATION;
  if (state == "active") return ValidatorOnboardingState::ACTIVE;
  if (state == "failed") return ValidatorOnboardingState::FAILED;
  if (state == "cancelled") return ValidatorOnboardingState::CANCELLED;
  return std::nullopt;
}

std::optional<onboarding::ValidatorOnboardingRecord> parse_onboarding_record_result(const minijson::Value* result,
                                                                                    std::string* err) {
  if (!result || !result->is_object()) {
    if (err) *err = "missing onboarding result";
    return std::nullopt;
  }
  onboarding::ValidatorOnboardingRecord record;
  auto pubkey_hex = object_string(result, "validator_pubkey_hex");
  auto state_name = object_string(result, "state");
  if (!pubkey_hex || !state_name) {
    if (err) *err = "missing onboarding fields";
    return std::nullopt;
  }
  auto pubkey = parse_hex32_field(*pubkey_hex);
  auto state = parse_onboarding_state(*state_name);
  if (!pubkey || !state) {
    if (err) *err = "invalid onboarding fields";
    return std::nullopt;
  }
  record.validator_pubkey = *pubkey;
  record.wallet_address = object_string(result, "wallet_address").value_or("");
  record.wallet_pubkey_hex = object_string(result, "wallet_pubkey_hex").value_or("");
  record.state = *state;
  record.fee = object_u64(result, "fee").value_or(0);
  record.bond_amount = object_u64(result, "bond_amount").value_or(0);
  record.eligibility_bond_amount = object_u64(result, "eligibility_bond_amount").value_or(record.bond_amount);
  record.required_amount = object_u64(result, "required_amount").value_or(0);
  record.last_spendable_balance = object_u64(result, "last_spendable_balance").value_or(0);
  record.last_deficit = object_u64(result, "last_deficit").value_or(0);
  record.txid_hex = object_string(result, "txid_hex").value_or("");
  record.finalized_height = object_u64(result, "finalized_height").value_or(0);
  record.validator_status = object_string(result, "validator_status").value_or("");
  record.activation_height = object_u64(result, "activation_height").value_or(0);
  record.last_error_code = object_string(result, "last_error_code").value_or("");
  record.last_error_message = object_string(result, "last_error_message").value_or("");
  if (const auto* readiness = result->get("readiness"); readiness && readiness->is_object()) {
    record.readiness.chain_id_ok = object_bool(readiness, "chain_id_ok").value_or(true);
    record.readiness.db_open = object_bool(readiness, "db_open").value_or(true);
    record.readiness.local_finalized_height = object_u64(readiness, "local_finalized_height").value_or(0);
    record.readiness.observed_network_height_known = object_bool(readiness, "observed_network_height_known").value_or(false);
    record.readiness.observed_network_finalized_height = object_u64(readiness, "observed_network_finalized_height").value_or(0);
    record.readiness.healthy_peer_count = static_cast<std::size_t>(object_u64(readiness, "healthy_peer_count").value_or(0));
    record.readiness.established_peer_count = static_cast<std::size_t>(object_u64(readiness, "established_peer_count").value_or(0));
    record.readiness.finalized_lag = object_u64(readiness, "finalized_lag").value_or(0);
    record.readiness.peer_height_disagreement = object_bool(readiness, "peer_height_disagreement").value_or(false);
    record.readiness.next_height_committee_available = object_bool(readiness, "next_height_committee_available").value_or(false);
    record.readiness.next_height_proposer_available = object_bool(readiness, "next_height_proposer_available").value_or(false);
    record.readiness.bootstrap_sync_incomplete = object_bool(readiness, "bootstrap_sync_incomplete").value_or(false);
    record.readiness.registration_ready_preflight = object_bool(readiness, "registration_ready_preflight").value_or(false);
    record.readiness.registration_ready = object_bool(readiness, "registration_ready").value_or(false);
    record.readiness.readiness_stable_samples = static_cast<std::uint32_t>(object_u64(readiness, "readiness_stable_samples").value_or(0));
    record.readiness.readiness_blockers_csv = object_string(readiness, "readiness_blockers_csv").value_or("");
    record.readiness.captured_at_unix_ms = object_u64(readiness, "captured_at_unix_ms").value_or(0);
  }
  return record;
}

}  // namespace

std::optional<RpcStatusView> rpc_get_status(const std::string& rpc_url, std::string* err) {
  auto body = http_post_json(rpc_url, R"({"jsonrpc":"2.0","id":1,"method":"get_status","params":{}})", err);
  if (!body) return std::nullopt;
  auto root = minijson::parse(*body);
  if (!root.has_value()) {
    if (err) *err = "invalid rpc response";
    return std::nullopt;
  }
  const auto* result = result_value(*root, err);
  if (!result || !result->is_object()) return std::nullopt;

  RpcStatusView out;
  auto network_name = object_string(result, "network_name");
  auto network_id = object_string(result, "network_id");
  auto genesis_hash = object_string(result, "genesis_hash");
  auto genesis_source = object_string(result, "genesis_source");
  auto proto = object_u64(result, "protocol_version");
  auto magic = object_u64(result, "magic");
  auto chain_id_ok = object_bool(result, "chain_id_ok");
  auto version = object_string(result, "version");
  auto binary_version = object_string(result, "binary_version");
  auto wallet_api_version = object_string(result, "wallet_api_version");
  auto healthy_peer_count = object_u64(result, "healthy_peer_count");
  auto established_peer_count = object_u64(result, "established_peer_count");
  const auto* tip = result->get("tip");
  auto tip_height = object_u64(tip, "height");
  auto transition_hash = object_string(tip, "transition_hash");
  const auto* sync = result->get("sync");
  if (!network_name || !network_id || !genesis_hash || !genesis_source || !proto || !magic || !tip_height ||
      !transition_hash) {
    if (err) *err = "missing status fields";
    return std::nullopt;
  }
  out.chain.network_name = *network_name;
  out.chain.network_id_hex = *network_id;
  out.chain.genesis_hash_hex = *genesis_hash;
  out.chain.genesis_source = *genesis_source;
  out.chain.protocol_version = static_cast<std::uint32_t>(*proto);
  out.chain.magic = static_cast<std::uint32_t>(*magic);
  out.tip_height = *tip_height;
  out.transition_hash = *transition_hash;
  out.version = version.value_or("");
  out.binary_version = binary_version.value_or("");
  out.wallet_api_version = wallet_api_version.value_or("");
  out.healthy_peer_count = healthy_peer_count;
  out.established_peer_count = established_peer_count;
  out.chain_id_ok = chain_id_ok.value_or(true);
  if (sync && sync->is_object()) {
    out.observed_network_height_known = object_bool(sync, "observed_network_height_known").value_or(false);
    out.peer_height_disagreement = object_bool(sync, "peer_height_disagreement").value_or(false);
    out.bootstrap_sync_incomplete = object_bool(sync, "bootstrap_sync_incomplete").value_or(false);
    out.finalized_lag = object_u64(sync, "finalized_lag");
    if (out.observed_network_height_known) {
      out.observed_network_finalized_height = object_u64(sync, "observed_network_finalized_height");
    }
  }
  const auto* availability = result->get("availability");
  if (availability && availability->is_object()) {
    out.checkpoint_derivation_mode = object_string(availability, "checkpoint_derivation_mode");
    out.checkpoint_fallback_reason = object_string(availability, "checkpoint_fallback_reason");
    out.fallback_sticky = object_bool(availability, "fallback_sticky");
    if (const auto* adaptive = availability->get("adaptive_regime"); adaptive && adaptive->is_object()) {
      out.qualified_depth = object_u64(adaptive, "qualified_depth");
      out.adaptive_target_committee_size = object_u64(adaptive, "adaptive_target_committee_size");
      out.adaptive_min_eligible = object_u64(adaptive, "adaptive_min_eligible");
      out.adaptive_min_bond = object_u64(adaptive, "adaptive_min_bond");
      out.adaptive_slack = object_i64(adaptive, "slack");
      out.target_expand_streak = object_u64(adaptive, "target_expand_streak");
      out.target_contract_streak = object_u64(adaptive, "target_contract_streak");
      out.fallback_rate_bps = object_u64(adaptive, "fallback_rate_bps");
      out.sticky_fallback_rate_bps = object_u64(adaptive, "sticky_fallback_rate_bps");
      out.fallback_rate_window_epochs = object_u64(adaptive, "fallback_rate_window_epochs");
      out.near_threshold_operation = object_bool(adaptive, "near_threshold_operation");
      out.prolonged_expand_buildup = object_bool(adaptive, "prolonged_expand_buildup");
      out.prolonged_contract_buildup = object_bool(adaptive, "prolonged_contract_buildup");
      out.repeated_sticky_fallback = object_bool(adaptive, "repeated_sticky_fallback");
      out.depth_collapse_after_bond_increase = object_bool(adaptive, "depth_collapse_after_bond_increase");
    }
  }
  return out;
}

std::optional<AddressValidationView> rpc_validate_address(const std::string& rpc_url, const std::string& address,
                                                          std::string* err) {
  const std::string body_json =
      std::string(R"({"jsonrpc":"2.0","id":41,"method":"validate_address","params":{"address":")") +
      json_escape(address) + R"("}})";
  auto body = http_post_json(rpc_url, body_json, err);
  if (!body) return std::nullopt;
  auto root = minijson::parse(*body);
  if (!root.has_value()) {
    if (err) *err = "invalid rpc response";
    return std::nullopt;
  }
  const auto* result = result_value(*root, err);
  if (!result || !result->is_object()) return std::nullopt;

  AddressValidationView out;
  out.valid = object_bool(result, "valid").value_or(false);
  out.server_network_match = object_bool(result, "server_network_match").value_or(false);
  out.normalized_address = object_string(result, "normalized_address").value_or("");
  out.network_hint = object_string(result, "network_hint").value_or("");
  out.server_network_hrp = object_string(result, "server_network_hrp").value_or("");
  out.addr_type = object_string(result, "addr_type").value_or("");
  out.pubkey_hash_hex = object_string(result, "pubkey_hash_hex").value_or("");
  out.script_pubkey_hex = object_string(result, "script_pubkey_hex").value_or("");
  out.error = object_string(result, "error").value_or("");
  if (auto scripthash_hex = object_string(result, "scripthash_hex"); scripthash_hex.has_value()) {
    auto parsed = parse_hex32_field(*scripthash_hex);
    if (parsed.has_value()) {
      out.scripthash = *parsed;
      out.has_scripthash = true;
    }
  }
  return out;
}

std::optional<std::vector<UtxoView>> rpc_get_utxos(const std::string& rpc_url, const Hash32& scripthash, std::string* err) {
  std::vector<UtxoView> out;
  std::optional<UtxoCursor> cursor;
  constexpr std::uint64_t kPageLimit = 200;
  while (true) {
    std::ostringstream body_json;
    body_json << R"({"jsonrpc":"2.0","id":2,"method":"get_utxos","params":{"scripthash_hex":")" << hex_encode32(scripthash)
              << R"(","limit":)" << kPageLimit;
    if (cursor.has_value()) {
      body_json << R"(,"start_after":{"height":)" << cursor->height << R"(,"txid":")" << hex_encode32(cursor->txid)
                << R"(","vout":)" << cursor->vout << "}";
    }
    body_json << "}}";
    auto body = http_post_json(rpc_url, body_json.str(), err);
    if (!body) return std::nullopt;
    auto root = minijson::parse(*body);
    if (!root.has_value()) {
      if (err) *err = "invalid rpc response";
      return std::nullopt;
    }
    const auto* result = result_value(*root, err);
    auto page = parse_utxo_page_result(result, err);
    if (!page) return std::nullopt;
    out.insert(out.end(), page->items.begin(), page->items.end());
    if (!page->has_more || !page->next_start_after.has_value()) break;
    cursor = page->next_start_after;
  }
  return out;
}

std::optional<std::vector<HistoryEntry>> rpc_get_history(const std::string& rpc_url, const Hash32& scripthash,
                                                         std::string* err) {
  std::vector<HistoryEntry> out;
  std::optional<HistoryCursor> cursor;
  constexpr std::uint64_t kPageLimit = 200;
  while (true) {
    std::ostringstream body_json;
    body_json << R"({"jsonrpc":"2.0","id":3,"method":"get_history","params":{"scripthash_hex":")" << hex_encode32(scripthash)
              << R"(","limit":)" << kPageLimit;
    if (cursor.has_value()) {
      body_json << R"(,"start_after":{"height":)" << cursor->height << R"(,"txid":")" << hex_encode32(cursor->txid)
                << R"("})";
    }
    body_json << "}}";
    auto body = http_post_json(rpc_url, body_json.str(), err);
    if (!body) return std::nullopt;
    auto root = minijson::parse(*body);
    if (!root.has_value()) {
      if (err) *err = "invalid rpc response";
      return std::nullopt;
    }
    const auto* result = result_value(*root, err);
    if (!result) return std::nullopt;
    if (result->is_array()) {
      for (const auto& entry : result->array_value) {
        auto txid_hex = object_string(&entry, "txid");
        auto height = object_u64(&entry, "height");
        if (!txid_hex || !height) continue;
        auto txid = parse_hex32_field(*txid_hex);
        if (!txid) continue;
        out.push_back(HistoryEntry{*txid, *height});
      }
      break;
    }
    if (!result->is_object()) return std::nullopt;
    const auto* items = result->get("items");
    if (!items || !items->is_array()) {
      if (err) *err = "missing history page items";
      return std::nullopt;
    }
    for (const auto& entry : items->array_value) {
      auto txid_hex = object_string(&entry, "txid");
      auto height = object_u64(&entry, "height");
      if (!txid_hex || !height) continue;
      auto txid = parse_hex32_field(*txid_hex);
      if (!txid) continue;
      out.push_back(HistoryEntry{*txid, *height});
    }
    const bool has_more = object_bool(result, "has_more").value_or(false);
    if (!has_more) break;
    const auto* next = result->get("next_start_after");
    if (!next || next->is_null()) break;
    auto next_height = object_u64(next, "height");
    auto next_txid_hex = object_string(next, "txid");
    if (!next_height || !next_txid_hex) {
      if (err) *err = "malformed history page cursor";
      return std::nullopt;
    }
    auto next_txid = parse_hex32_field(*next_txid_hex);
    if (!next_txid) {
      if (err) *err = "malformed history page cursor";
      return std::nullopt;
    }
    cursor = HistoryCursor{*next_height, *next_txid};
  }
  return out;
}

std::optional<HistoryPageView> rpc_get_history_page(const std::string& rpc_url, const Hash32& scripthash, std::uint64_t limit,
                                                    const std::optional<HistoryCursor>& start_after, std::string* err) {
  std::ostringstream body_json;
  body_json << R"({"jsonrpc":"2.0","id":33,"method":"get_history_page","params":{"scripthash_hex":")"
            << hex_encode32(scripthash) << R"(","limit":)" << limit;
  if (start_after.has_value()) {
    body_json << R"(,"start_after":{"height":)" << start_after->height << R"(,"txid":")" << hex_encode32(start_after->txid)
              << R"("})";
  }
  body_json << "}}";
  auto body = http_post_json(rpc_url, body_json.str(), err);
  if (!body) return std::nullopt;
  auto root = minijson::parse(*body);
  if (!root.has_value()) {
    if (err) *err = "invalid rpc response";
    return std::nullopt;
  }
  const auto* result = result_value(*root, err);
  if (!result || !result->is_object()) return std::nullopt;

  HistoryPageView out;
  out.has_more = object_bool(result, "has_more").value_or(false);
  const auto* items = result->get("items");
  if (!items || !items->is_array()) {
    if (err) *err = "missing history page items";
    return std::nullopt;
  }
  for (const auto& entry : items->array_value) {
    auto txid_hex = object_string(&entry, "txid");
    auto height = object_u64(&entry, "height");
    if (!txid_hex || !height) continue;
    auto txid = parse_hex32_field(*txid_hex);
    if (!txid) continue;
    out.items.push_back(HistoryEntry{*txid, *height});
  }
  const auto* next = result->get("next_start_after");
  if (!next || next->is_null()) {
    out.next_start_after.reset();
    return out;
  }
  auto next_height = object_u64(next, "height");
  auto next_txid_hex = object_string(next, "txid");
  if (!next_height || !next_txid_hex) {
    if (err) *err = "malformed history page cursor";
    return std::nullopt;
  }
  auto next_txid = parse_hex32_field(*next_txid_hex);
  if (!next_txid) {
    if (err) *err = "malformed history page cursor";
    return std::nullopt;
  }
  out.next_start_after = HistoryCursor{*next_height, *next_txid};
  return out;
}

std::optional<DetailedHistoryPageView> rpc_get_history_page_detailed(const std::string& rpc_url, const Hash32& scripthash,
                                                                     std::uint64_t limit,
                                                                     const std::optional<HistoryCursor>& start_after,
                                                                     std::string* err) {
  std::ostringstream body_json;
  body_json << R"({"jsonrpc":"2.0","id":35,"method":"get_history_page_detailed","params":{"scripthash_hex":")"
            << hex_encode32(scripthash) << R"(","limit":)" << limit;
  if (start_after.has_value()) {
    body_json << R"(,"start_after":{"height":)" << start_after->height << R"(,"txid":")" << hex_encode32(start_after->txid)
              << R"("})";
  }
  body_json << "}}";
  auto body = http_post_json(rpc_url, body_json.str(), err);
  if (!body) return std::nullopt;
  auto root = minijson::parse(*body);
  if (!root.has_value()) {
    if (err) *err = "invalid rpc response";
    return std::nullopt;
  }
  const auto* result = result_value(*root, err);
  if (!result || !result->is_object()) return std::nullopt;

  DetailedHistoryPageView out;
  out.has_more = object_bool(result, "has_more").value_or(false);
  const auto* items = result->get("items");
  if (!items || !items->is_array()) {
    if (err) *err = "missing detailed history page items";
    return std::nullopt;
  }
  for (const auto& entry : items->array_value) {
    auto txid_hex = object_string(&entry, "txid");
    auto height = object_u64(&entry, "height");
    auto direction = object_string(&entry, "direction");
    auto net_amount = object_i64(&entry, "net_amount");
    auto detail = object_string(&entry, "detail");
    if (!txid_hex || !height || !direction || !net_amount || !detail) continue;
    auto txid = parse_hex32_field(*txid_hex);
    if (!txid) continue;
    out.items.push_back(DetailedHistoryEntry{*txid, *height, *direction, *net_amount, *detail});
  }
  const auto* next = result->get("next_start_after");
  if (!next || next->is_null()) {
    out.next_start_after.reset();
    return out;
  }
  auto next_height = object_u64(next, "height");
  auto next_txid_hex = object_string(next, "txid");
  if (!next_height || !next_txid_hex) {
    if (err) *err = "malformed detailed history page cursor";
    return std::nullopt;
  }
  auto next_txid = parse_hex32_field(*next_txid_hex);
  if (!next_txid) {
    if (err) *err = "malformed detailed history page cursor";
    return std::nullopt;
  }
  out.next_start_after = HistoryCursor{*next_height, *next_txid};
  return out;
}

std::optional<TxView> rpc_get_tx(const std::string& rpc_url, const Hash32& txid, std::string* err) {
  const std::string body_json = std::string(R"({"jsonrpc":"2.0","id":4,"method":"get_tx","params":{"txid":")") +
                                hex_encode32(txid) + R"("}})";
  auto body = http_post_json(rpc_url, body_json, err);
  if (!body) return std::nullopt;
  auto root = minijson::parse(*body);
  if (!root.has_value()) {
    if (err) *err = "invalid rpc response";
    return std::nullopt;
  }
  const auto* result = result_value(*root, err);
  if (!result || !result->is_object()) return std::nullopt;
  auto height = object_u64(result, "height");
  auto tx_hex = object_string(result, "tx_hex");
  if (!height || !tx_hex) {
    if (err) *err = "missing tx fields";
    return std::nullopt;
  }
  auto tx_bytes = hex_decode(*tx_hex);
  if (!tx_bytes) {
    if (err) *err = "invalid tx hex";
    return std::nullopt;
  }
  return TxView{*height, *tx_bytes};
}

std::optional<TxStatusView> rpc_get_tx_status(const std::string& rpc_url, const Hash32& txid, std::string* err) {
  const std::string body_json = std::string(R"({"jsonrpc":"2.0","id":34,"method":"get_tx_status","params":{"txid":")") +
                                hex_encode32(txid) + R"("}})";
  auto body = http_post_json(rpc_url, body_json, err);
  if (!body) return std::nullopt;
  auto root = minijson::parse(*body);
  if (!root.has_value()) {
    if (err) *err = "invalid rpc response";
    return std::nullopt;
  }
  const auto* result = result_value(*root, err);
  if (!result || !result->is_object()) return std::nullopt;

  auto txid_hex = object_string(result, "txid");
  auto status = object_string(result, "status");
  auto finalized = object_bool(result, "finalized");
  auto finalized_depth = object_u64(result, "finalized_depth");
  auto credit_safe = object_bool(result, "credit_safe");
  if (!txid_hex || !status || !finalized || !finalized_depth || !credit_safe) {
    if (err) *err = "missing tx status fields";
    return std::nullopt;
  }

  TxStatusView out;
  out.txid_hex = *txid_hex;
  out.status = *status;
  out.finalized = *finalized;
  out.finalized_depth = *finalized_depth;
  out.credit_safe = *credit_safe;
  out.height = object_u64(result, "height").value_or(0);
  out.transition_hash = object_string(result, "transition_hash").value_or("");
  return out;
}

BroadcastResult rpc_broadcast_tx(const std::string& rpc_url, const Bytes& tx_bytes, std::string* err) {
  const std::string body_json = std::string(R"({"jsonrpc":"2.0","id":5,"method":"broadcast_tx","params":{"tx_hex":")") +
                                hex_encode(tx_bytes) + R"("}})";
  BroadcastResult out;
  auto body = http_post_json(rpc_url, body_json, err);
  if (!body) {
    out.outcome = BroadcastOutcome::Ambiguous;
    if (err && !err->empty()) out.error = *err;
    return out;
  }
  auto root = minijson::parse(*body);
  if (!root.has_value()) {
    out.outcome = BroadcastOutcome::Ambiguous;
    if (err) *err = "invalid rpc response";
    out.error = "invalid rpc response";
    return out;
  }
  const auto* result = result_value(*root, err);
  if (!result || !result->is_object()) {
    out.outcome = BroadcastOutcome::Ambiguous;
    if (out.error.empty() && err) out.error = *err;
    return out;
  }
  const auto accepted = result->get("accepted");
  const auto accepted_bool = accepted ? accepted->as_bool() : std::nullopt;
  out.outcome = accepted_bool.value_or(false) ? BroadcastOutcome::Sent : BroadcastOutcome::Rejected;
  if (auto txid_hex = object_string(result, "txid"); txid_hex) out.txid_hex = *txid_hex;
  if (auto error_str = object_string(result, "error"); error_str) out.error = *error_str;
  if (auto error_code = object_string(result, "error_code"); error_code) out.error_code = *error_code;
  if (auto error_message = object_string(result, "error_message"); error_message) out.error_message = *error_message;
  if (auto message = object_string(result, "message"); message) out.message = *message;
  if (auto retryable = object_bool(result, "retryable"); retryable) out.retryable = *retryable;
  if (auto retry_class = object_string(result, "retry_class"); retry_class) out.retry_class = *retry_class;
  if (auto mempool_full = object_bool(result, "mempool_full"); mempool_full) out.mempool_full = *mempool_full;
  if (auto min_rate = object_u64(result, "min_fee_rate_to_enter_when_full"); min_rate) {
    out.min_fee_rate_to_enter_when_full = *min_rate;
  }
  if (out.error.empty() && !out.error_message.empty()) out.error = out.error_message;
  return out;
}

std::optional<onboarding::ValidatorOnboardingRecord> rpc_validator_onboarding_status(
    const std::string& rpc_url, const onboarding::ValidatorOnboardingOptions& options, const std::string& tracked_txid_hex,
    std::string* err) {
  std::ostringstream body_json;
  body_json << R"({"jsonrpc":"2.0","id":6,"method":"validator_onboarding_status","params":{"key_file":")"
            << json_escape(options.key_file) << R"(","passphrase":")" << json_escape(options.passphrase) << R"(","fee":)" << options.fee
            << R"(,"wait_for_sync":)" << (options.wait_for_sync ? "true" : "false");
  if (!tracked_txid_hex.empty()) body_json << R"(,"txid_hex":")" << json_escape(tracked_txid_hex) << "\"";
  body_json << "}}";
  auto body = http_post_json(rpc_url, body_json.str(), err);
  if (!body) return std::nullopt;
  auto root = minijson::parse(*body);
  if (!root.has_value()) {
    if (err) *err = "invalid rpc response";
    return std::nullopt;
  }
  const auto* result = result_value(*root, err);
  return parse_onboarding_record_result(result, err);
}

std::optional<onboarding::ValidatorOnboardingRecord> rpc_validator_onboarding_start(
    const std::string& rpc_url, const onboarding::ValidatorOnboardingOptions& options, std::string* err) {
  std::ostringstream body_json;
  body_json << R"({"jsonrpc":"2.0","id":7,"method":"validator_onboarding_start","params":{"key_file":")"
            << json_escape(options.key_file) << R"(","passphrase":")" << json_escape(options.passphrase) << R"(","fee":)" << options.fee
            << R"(,"wait_for_sync":)" << (options.wait_for_sync ? "true" : "false") << "}}";
  auto body = http_post_json(rpc_url, body_json.str(), err);
  if (!body) return std::nullopt;
  auto root = minijson::parse(*body);
  if (!root.has_value()) {
    if (err) *err = "invalid rpc response";
    return std::nullopt;
  }
  const auto* result = result_value(*root, err);
  return parse_onboarding_record_result(result, err);
}

std::optional<std::string> http_post_json_raw(const std::string& url, const std::string& body, std::string* err) {
  return http_post_json(url, body, err);
}

}  // namespace finalis::lightserver
