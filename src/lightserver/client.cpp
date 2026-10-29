// SPDX-License-Identifier: MIT

#include "lightserver/client.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <limits>
#include <sstream>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <cstdlib>
#include <memory>

#include "codec/bytes.hpp"
#include "common/minijson.hpp"
#include "common/paths.hpp"
#include "common/socket_compat.hpp"
#ifdef _WIN32
#include <wincrypt.h>
#endif
#include "utxo/validate.hpp"

#ifndef _WIN32
#include <sys/un.h>
#endif

namespace finalis::lightserver {
namespace {

struct ParsedHttpUrl {
  std::string host;  // without IPv6 brackets
  std::uint16_t port{0};
  std::string path;
  bool tls{false};
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
  hints.ai_family = AF_UNSPEC;
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

// unix://<absolute socket path> -> the lightserver admin surface.
std::optional<std::string> parse_unix_socket_url(const std::string& url) {
  const std::string prefix = "unix://";
  if (url.rfind(prefix, 0) != 0) return std::nullopt;
  const std::string path = url.substr(prefix.size());
  if (path.empty() || path.front() != '/') return std::nullopt;
  return path;
}

std::optional<net::SocketHandle> connect_unix(const std::string& path) {
#ifdef _WIN32
  (void)path;
  return std::nullopt;
#else
  sockaddr_un addr{};
  if (path.size() >= sizeof(addr.sun_path)) return std::nullopt;
  const int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) return std::nullopt;
  (void)net::set_socket_timeouts(fd, 15'000);
  addr.sun_family = AF_UNIX;
  std::memcpy(addr.sun_path, path.c_str(), path.size() + 1);
  if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
    ::close(fd);
    return std::nullopt;
  }
  return fd;
#endif
}

// http://host[:port][/path] or https://...; host may be a bracketed IPv6 literal. Default ports 80/443.
std::optional<ParsedHttpUrl> parse_http_url(const std::string& url) {
  ParsedHttpUrl parsed;
  std::string rest;
  if (url.rfind("http://", 0) == 0) {
    rest = url.substr(7);
  } else if (url.rfind("https://", 0) == 0) {
    rest = url.substr(8);
    parsed.tls = true;
  } else {
    return std::nullopt;
  }
  const auto slash = rest.find('/');
  const std::string hostport = (slash == std::string::npos) ? rest : rest.substr(0, slash);
  parsed.path = (slash == std::string::npos) ? "/" : rest.substr(slash);
  std::string port;
  if (!hostport.empty() && hostport.front() == '[') {
    const auto close = hostport.find(']');
    if (close == std::string::npos) return std::nullopt;
    parsed.host = hostport.substr(1, close - 1);
    const std::string after = hostport.substr(close + 1);
    if (!after.empty()) {
      if (after.front() != ':') return std::nullopt;
      port = after.substr(1);
    }
  } else {
    const auto colon = hostport.rfind(':');
    parsed.host = hostport.substr(0, colon);
    if (colon != std::string::npos) {
      port = hostport.substr(colon + 1);
      if (port.empty()) return std::nullopt;
    }
  }
  if (parsed.host.empty()) return std::nullopt;
  if (port.empty()) {
    parsed.port = parsed.tls ? 443 : 80;
  } else {
    if (port.size() > 5 || !std::all_of(port.begin(), port.end(), [](char c) { return c >= '0' && c <= '9'; })) {
      return std::nullopt;
    }
    const auto p = std::stoul(port);
    if (p == 0 || p > 65535) return std::nullopt;
    parsed.port = static_cast<std::uint16_t>(p);
  }
  return parsed;
}

#ifdef _WIN32
// OpenSSL's default verify paths are usually empty on Windows: trust what Windows trusts, the
// certificates of the system "ROOT" store. False if none could be loaded.
bool load_windows_root_store(SSL_CTX* ctx) {
  HCERTSTORE store = CertOpenSystemStoreW(0, L"ROOT");
  if (!store) return false;
  X509_STORE* x509_store = SSL_CTX_get_cert_store(ctx);
  int added = 0;
  PCCERT_CONTEXT cert = nullptr;
  while ((cert = CertEnumCertificatesInStore(store, cert)) != nullptr) {
    const unsigned char* der = cert->pbCertEncoded;
    X509* x509 = d2i_X509(nullptr, &der, static_cast<long>(cert->cbCertEncoded));
    if (!x509) continue;
    if (X509_STORE_add_cert(x509_store, x509) == 1) ++added;
    X509_free(x509);
  }
  CertCloseStore(store, 0);
  ERR_clear_error();  // duplicates in the store are reported as errors; they are harmless
  return added > 0;
}
#endif

// One TLS client session over a connected socket: certificate chain checked against the system trust
// store (or FINALIS_CA_FILE), and the certificate must name the host (DNS name or IP address).
class TlsSession {
 public:
  static std::unique_ptr<TlsSession> open(net::SocketHandle fd, const std::string& host, std::string* err) {
    auto out = std::unique_ptr<TlsSession>(new TlsSession());
    out->ctx_ = SSL_CTX_new(TLS_client_method());
    if (!out->ctx_) return fail(err, "tls init failed");
    (void)SSL_CTX_set_min_proto_version(out->ctx_, TLS1_2_VERSION);
    SSL_CTX_set_verify(out->ctx_, SSL_VERIFY_PEER, nullptr);
#ifdef SSL_OP_IGNORE_UNEXPECTED_EOF
    SSL_CTX_set_options(out->ctx_, SSL_OP_IGNORE_UNEXPECTED_EOF);
#endif
    const char* ca_file = std::getenv("FINALIS_CA_FILE");
    if (ca_file && *ca_file) {
      if (SSL_CTX_load_verify_locations(out->ctx_, ca_file, nullptr) != 1) return fail(err, "cannot load FINALIS_CA_FILE");
    } else {
#ifdef _WIN32
      if (!load_windows_root_store(out->ctx_)) return fail(err, "no system trust store (Windows ROOT store empty)");
#else
      if (SSL_CTX_set_default_verify_paths(out->ctx_) != 1) return fail(err, "no system trust store");
#endif
    }
    out->ssl_ = SSL_new(out->ctx_);
    if (!out->ssl_) return fail(err, "tls init failed");
    in6_addr a6{};
    in_addr a4{};
    const bool is_ip = ::inet_pton(AF_INET, host.c_str(), &a4) == 1 || ::inet_pton(AF_INET6, host.c_str(), &a6) == 1;
    if (is_ip) {
      if (X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(out->ssl_), host.c_str()) != 1) return fail(err, "tls ip check setup failed");
    } else {
      if (SSL_set_tlsext_host_name(out->ssl_, host.c_str()) != 1 || SSL_set1_host(out->ssl_, host.c_str()) != 1) {
        return fail(err, "tls host check setup failed");
      }
    }
    if (SSL_set_fd(out->ssl_, static_cast<int>(fd)) != 1) return fail(err, "tls init failed");
    if (SSL_connect(out->ssl_) != 1) {
      const long verify = SSL_get_verify_result(out->ssl_);
      return fail(err, verify != X509_V_OK ? std::string("tls certificate rejected: ") + X509_verify_cert_error_string(verify)
                                           : std::string("tls handshake failed"));
    }
    return out;
  }
  ~TlsSession() {
    if (ssl_) {
      (void)SSL_shutdown(ssl_);
      SSL_free(ssl_);
    }
    if (ctx_) SSL_CTX_free(ctx_);
  }
  bool write_all(const std::string& data) {
    std::size_t off = 0;
    while (off < data.size()) {
      const int n = SSL_write(ssl_, data.data() + off, static_cast<int>(std::min<std::size_t>(data.size() - off, 1 << 20)));
      if (n <= 0) return false;
      off += static_cast<std::size_t>(n);
    }
    return true;
  }
  std::optional<std::string> read_all(std::size_t max_bytes) {
    std::string out;
    std::array<char, 4096> buf{};
    while (true) {
      const int n = SSL_read(ssl_, buf.data(), static_cast<int>(buf.size()));
      if (n > 0) {
        out.append(buf.data(), static_cast<std::size_t>(n));
        if (out.size() > max_bytes) return std::nullopt;
        continue;
      }
      const int e = SSL_get_error(ssl_, n);
      if (e == SSL_ERROR_ZERO_RETURN) break;
      // A server closing without close_notify after a full response (Connection: close).
      if (e == SSL_ERROR_SYSCALL && !out.empty()) break;
#ifdef SSL_R_UNEXPECTED_EOF_WHILE_READING  // OpenSSL 3; 1.1 reports it as SSL_ERROR_SYSCALL above
      if (e == SSL_ERROR_SSL && !out.empty() && ERR_GET_REASON(ERR_peek_last_error()) == SSL_R_UNEXPECTED_EOF_WHILE_READING) break;
#endif
      return std::nullopt;
    }
    return out;
  }

 private:
  TlsSession() = default;
  static std::unique_ptr<TlsSession> fail(std::string* err, const std::string& what) {
    if (err) *err = what;
    ERR_clear_error();
    return nullptr;
  }
  SSL_CTX* ctx_{nullptr};
  SSL* ssl_{nullptr};
};

bool write_all(net::SocketHandle fd, const std::string& data) {
  size_t off = 0;
  while (off < data.size()) {
    ssize_t n = ::send(fd, data.data() + off, data.size() - off, 0);
    if (n <= 0) return false;
    off += static_cast<size_t>(n);
  }
  return true;
}

// Servers are untrusted (a wallet may use anyone's): a response may not grow without bound.
constexpr std::size_t kMaxRpcResponseBytes = 16 * 1024 * 1024;

std::optional<std::string> read_all(net::SocketHandle fd) {
  std::string out;
  std::array<char, 4096> buf{};
  while (true) {
    ssize_t n = ::recv(fd, buf.data(), buf.size(), 0);
    if (n < 0) return std::nullopt;
    if (n == 0) break;
    out.append(buf.data(), static_cast<size_t>(n));
    if (out.size() > kMaxRpcResponseBytes) return std::nullopt;
  }
  return out;
}

std::optional<std::string> http_post_json(const std::string& url, const std::string& body,
                                          const std::vector<std::pair<std::string, std::string>>& headers,
                                          std::string* err) {
  for (const auto& [k, v] : headers) {
    if (k.find_first_of("\r\n:") != std::string::npos || v.find_first_of("\r\n") != std::string::npos) {
      if (err) *err = "invalid header";
      return std::nullopt;
    }
  }
  std::optional<net::SocketHandle> fd_opt;
  std::string path = "/rpc";
  std::string host_header = "localhost";
  std::optional<std::string> tls_host;
  if (const auto socket_path = parse_unix_socket_url(url); socket_path.has_value()) {
    fd_opt = connect_unix(*socket_path);
  } else {
    auto parsed = parse_http_url(url);
    if (!parsed) {
      if (err) *err = "invalid http url";
      return std::nullopt;
    }
    fd_opt = connect_tcp(parsed->host, parsed->port);
    path = parsed->path;
    const bool v6 = parsed->host.find(':') != std::string::npos;
    host_header = (v6 ? "[" + parsed->host + "]" : parsed->host) + ":" + std::to_string(parsed->port);
    tls_host = parsed->tls ? std::optional<std::string>(parsed->host) : std::nullopt;
  }
  if (!fd_opt) {
    if (err) *err = "connect failed";
    return std::nullopt;
  }
  const auto fd = *fd_opt;
  std::ostringstream req;
  req << "POST " << path << " HTTP/1.1\r\n"
      << "Host: " << host_header << "\r\n"
      << "Content-Type: application/json\r\n";
  for (const auto& [k, v] : headers) req << k << ": " << v << "\r\n";
  req << "Content-Length: " << body.size() << "\r\n"
      << "Connection: close\r\n\r\n"
      << body;
  std::optional<std::string> resp;
  if (tls_host.has_value()) {
    std::string tls_err;
    auto tls = TlsSession::open(fd, *tls_host, &tls_err);
    if (!tls) {
      net::close_socket(fd);
      if (err) *err = tls_err;
      return std::nullopt;
    }
    if (!tls->write_all(req.str())) {
      tls.reset();
      net::close_socket(fd);
      if (err) *err = "send failed";
      return std::nullopt;
    }
    resp = tls->read_all(kMaxRpcResponseBytes);
    tls.reset();
  } else {
    if (!write_all(fd, req.str())) {
      net::close_socket(fd);
      if (err) *err = "send failed";
      return std::nullopt;
    }
    resp = read_all(fd);
  }
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

std::optional<std::string> http_post_json(const std::string& url, const std::string& body, std::string* err) {
  return http_post_json(url, body, {}, err);
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
  if (!txid || !spk || *vout > (std::numeric_limits<std::uint32_t>::max)()) return std::nullopt;
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
  if (!next_height || !next_txid_hex || !next_vout || *next_vout > (std::numeric_limits<std::uint32_t>::max)()) {
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

std::optional<onboarding::ValidatorOnboardingBroadcastOutcome> parse_onboarding_broadcast_outcome(const std::string& outcome) {
  using onboarding::ValidatorOnboardingBroadcastOutcome;
  if (outcome == "none") return ValidatorOnboardingBroadcastOutcome::NONE;
  if (outcome == "sent") return ValidatorOnboardingBroadcastOutcome::SENT;
  if (outcome == "rejected") return ValidatorOnboardingBroadcastOutcome::REJECTED;
  if (outcome == "ambiguous") return ValidatorOnboardingBroadcastOutcome::AMBIGUOUS;
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
    // A server-side failure before the key is resolved carries only state and last_error_message.
    auto server_error = object_string(result, "last_error_message");
    if (err) *err = server_error ? *server_error : "missing onboarding fields";
    return std::nullopt;
  }
  auto pubkey = parse_hex32_field(*pubkey_hex);
  auto state = parse_onboarding_state(*state_name);
  if (!pubkey || !state) {
    if (err) *err = "invalid onboarding fields";
    return std::nullopt;
  }
  record.validator_pubkey = *pubkey;
  record.onboarding_id = object_string(result, "onboarding_id").value_or("");
  record.wallet_address = object_string(result, "wallet_address").value_or("");
  record.wallet_pubkey_hex = object_string(result, "wallet_pubkey_hex").value_or("");
  record.state = *state;
  record.wait_for_sync = object_bool(result, "wait_for_sync").value_or(false);
  record.fee = object_u64(result, "fee").value_or(0);
  record.bond_amount = object_u64(result, "bond_amount").value_or(0);
  record.eligibility_bond_amount = object_u64(result, "eligibility_bond_amount").value_or(record.bond_amount);
  record.required_amount = object_u64(result, "required_amount").value_or(0);
  record.last_spendable_balance = object_u64(result, "last_spendable_balance").value_or(0);
  record.last_deficit = object_u64(result, "last_deficit").value_or(0);
  if (auto selected_input_count = object_u64(result, "selected_input_count"); selected_input_count) {
    record.selected_inputs.resize(static_cast<std::size_t>(*selected_input_count));
  }
  record.selected_inputs_reserved = object_bool(result, "selected_inputs_reserved").value_or(false);
  record.txid_hex = object_string(result, "txid_hex").value_or("");
  if (auto outcome_name = object_string(result, "broadcast_outcome"); outcome_name) {
    if (auto outcome = parse_onboarding_broadcast_outcome(*outcome_name); outcome) record.broadcast_outcome = *outcome;
  }
  record.rpc_endpoint = object_string(result, "rpc_endpoint").value_or("");
  record.finalized_height = object_u64(result, "finalized_height").value_or(0);
  record.validator_status = object_string(result, "validator_status").value_or("");
  record.activation_height = object_u64(result, "activation_height").value_or(0);
  record.rejoin_eligible_height = object_u64(result, "rejoin_eligible_height").value_or(0);
  record.rejoin_blocked_reason = object_string(result, "rejoin_blocked_reason").value_or("");
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
    record.readiness.inbound_connected = static_cast<std::size_t>(object_u64(readiness, "inbound_connected").value_or(0));
    record.readiness.outbound_connected = static_cast<std::size_t>(object_u64(readiness, "outbound_connected").value_or(0));
    record.readiness.addrman_size = static_cast<std::size_t>(object_u64(readiness, "addrman_size").value_or(0));
    record.readiness.outbound_target = static_cast<std::size_t>(object_u64(readiness, "outbound_target").value_or(0));
    record.readiness.advertised_endpoint_present = object_bool(readiness, "advertised_endpoint_present").value_or(false);
    record.readiness.advertised_endpoint_likely_public =
        object_bool(readiness, "advertised_endpoint_likely_public").value_or(false);
    record.readiness.advertised_endpoint = object_string(readiness, "advertised_endpoint").value_or("");
    record.readiness.stun_enabled = object_bool(readiness, "stun_enabled").value_or(false);
    record.readiness.stun_last_success = object_bool(readiness, "stun_last_success").value_or(false);
    record.readiness.stun_last_attempt_unix_ms = object_u64(readiness, "stun_last_attempt_unix_ms").value_or(0);
    record.readiness.stun_last_success_unix_ms = object_u64(readiness, "stun_last_success_unix_ms").value_or(0);
    record.readiness.stun_last_server = object_string(readiness, "stun_last_server").value_or("");
    record.readiness.stun_last_error_code = object_string(readiness, "stun_last_error_code").value_or("");
    record.readiness.stun_backoff_until_unix_ms = object_u64(readiness, "stun_backoff_until_unix_ms").value_or(0);
    record.readiness.stun_endpoint_change_pending = object_bool(readiness, "stun_endpoint_change_pending").value_or(false);
    record.readiness.stun_endpoint_change_hits =
        static_cast<std::uint32_t>(object_u64(readiness, "stun_endpoint_change_hits").value_or(0));
    record.readiness.stun_endpoint_change_required_hits =
        static_cast<std::uint32_t>(object_u64(readiness, "stun_endpoint_change_required_hits").value_or(0));
    record.readiness.stun_endpoint_candidate = object_string(readiness, "stun_endpoint_candidate").value_or("");
    record.readiness.finalized_lag = object_u64(readiness, "finalized_lag").value_or(0);
    record.readiness.peer_height_disagreement = object_bool(readiness, "peer_height_disagreement").value_or(false);
    record.readiness.next_height_committee_available = object_bool(readiness, "next_height_committee_available").value_or(false);
    record.readiness.next_height_proposer_available = object_bool(readiness, "next_height_proposer_available").value_or(false);
    record.readiness.bootstrap_sync_incomplete = object_bool(readiness, "bootstrap_sync_incomplete").value_or(false);
    record.readiness.registration_ready_preflight = object_bool(readiness, "registration_ready_preflight").value_or(false);
    record.readiness.registration_ready = object_bool(readiness, "registration_ready").value_or(false);
    record.readiness.readiness_stable_samples = static_cast<std::uint32_t>(object_u64(readiness, "readiness_stable_samples").value_or(0));
    record.readiness.readiness_blockers_csv = object_string(readiness, "readiness_blockers_csv").value_or("");
    record.readiness.readiness_failure_codes_csv = object_string(readiness, "readiness_failure_codes_csv").value_or("");
    record.readiness.captured_at_unix_ms = object_u64(readiness, "captured_at_unix_ms").value_or(0);
  }
  return record;
}

}  // namespace

std::optional<CommitteeBlsKeysView> rpc_get_committee_bls_keys(const std::string& rpc_url, std::uint64_t height,
                                                               std::string* err) {
  std::ostringstream req;
  req << R"({"jsonrpc":"2.0","id":1,"method":"get_committee","params":{"height":)" << height << R"(,"verbose":true}})";
  auto body = http_post_json(rpc_url, req.str(), err);
  if (!body) return std::nullopt;
  auto root = minijson::parse(*body);
  if (!root.has_value()) {
    if (err) *err = "invalid rpc response";
    return std::nullopt;
  }
  const auto* result = result_value(*root, err);
  const auto root_bytes = hex_decode(object_string(result, "committee_bls_key_root").value_or(""));
  const auto* members = result ? result->get("members") : nullptr;
  if (!root_bytes || root_bytes->size() != 32 || !members || !members->is_array()) {
    if (err && err->empty()) *err = "committee keys unavailable for height " + std::to_string(height);
    return std::nullopt;
  }
  CommitteeBlsKeysView out;
  std::copy(root_bytes->begin(), root_bytes->end(), out.root.begin());
  for (const auto& member : members->array_value) {
    const auto key = hex_decode(object_string(&member, "bls_pubkey").value_or(""));
    if (!key || key->size() != crypto::kBlsPublicKeyBytes) {
      if (err) *err = "invalid committee member bls key";
      return std::nullopt;
    }
    crypto::BlsPublicKey k{};
    std::copy(key->begin(), key->end(), k.begin());
    out.keys.push_back(k);
  }
  return out;
}

std::optional<CommitteeHandoffsView> rpc_get_committee_handoffs(const std::string& rpc_url, std::uint64_t from_epoch_start,
                                                                std::uint64_t limit, std::string* err) {
  std::ostringstream req;
  req << R"({"jsonrpc":"2.0","id":1,"method":"get_committee_handoffs","params":{"from_epoch_start":)" << from_epoch_start
      << ",\"limit\":" << limit << "}}";
  auto body = http_post_json(rpc_url, req.str(), err);
  if (!body) return std::nullopt;
  auto root = minijson::parse(*body);
  if (!root.has_value()) {
    if (err) *err = "invalid rpc response";
    return std::nullopt;
  }
  const auto* result = result_value(*root, err);
  const auto epoch_blocks = object_u64(result, "epoch_blocks");
  const auto* list = result ? result->get("handoffs") : nullptr;
  if (!epoch_blocks || !list || !list->is_array()) {
    if (err && err->empty()) *err = "invalid get_committee_handoffs response";
    return std::nullopt;
  }
  CommitteeHandoffsView out;
  out.epoch_blocks = *epoch_blocks;
  for (const auto& item : list->array_value) {
    const auto next = object_u64(&item, "next_epoch_start");
    const auto bytes = hex_decode(object_string(&item, "handoff_hex").value_or(""));
    if (!next || !bytes) {
      if (err) *err = "invalid committee handoff";
      return std::nullopt;
    }
    out.handoffs.push_back({*next, std::move(*bytes)});
  }
  return out;
}

std::optional<UtxoProofsView> rpc_get_utxo_proofs(const std::string& rpc_url, const std::vector<OutPoint>& outpoints,
                                                  std::string* err) {
  std::ostringstream req;
  req << R"({"jsonrpc":"2.0","id":1,"method":"get_utxo_proofs","params":{"outpoints":[)";
  for (std::size_t i = 0; i < outpoints.size(); ++i) {
    if (i) req << ",";
    req << "{\"txid\":\"" << hex_encode32(outpoints[i].txid) << "\",\"vout\":" << outpoints[i].index << "}";
  }
  req << "]}}";
  auto body = http_post_json(rpc_url, req.str(), err);
  if (!body) return std::nullopt;
  auto root = minijson::parse(*body);
  if (!root.has_value()) {
    if (err) *err = "invalid rpc response";
    return std::nullopt;
  }
  const auto* result = result_value(*root, err);
  const auto height = object_u64(result, "height");
  const auto transition = hex_decode(object_string(result, "transition_hex").value_or(""));
  const auto certificate = hex_decode(object_string(result, "certificate_hex").value_or(""));
  const auto* list = result ? result->get("proofs") : nullptr;
  if (!height || !transition || !certificate || !list || !list->is_array()) {
    if (err && err->empty()) *err = "invalid get_utxo_proofs response";
    return std::nullopt;
  }
  UtxoProofsView out;
  out.height = *height;
  out.transition = std::move(*transition);
  out.certificate = std::move(*certificate);
  for (const auto& item : list->array_value) {
    const auto txid = hex_decode(object_string(&item, "txid").value_or(""));
    const auto vout = object_u64(&item, "vout");
    const auto proof = hex_decode(object_string(&item, "proof_hex").value_or(""));
    const auto* value = item.get("value_hex");
    if (!txid || txid->size() != 32 || !vout || *vout > (std::numeric_limits<std::uint32_t>::max)() || !proof || !value) {
      if (err) *err = "invalid utxo proof";
      return std::nullopt;
    }
    UtxoProofView p;
    std::copy(txid->begin(), txid->end(), p.outpoint.txid.begin());
    p.outpoint.index = static_cast<std::uint32_t>(*vout);
    p.compact_proof = std::move(*proof);
    if (!value->is_null()) {
      auto v = hex_decode(value->as_string().value_or(""));
      if (!v) {
        if (err) *err = "invalid utxo proof value";
        return std::nullopt;
      }
      p.value = std::move(*v);
    }
    out.proofs.push_back(std::move(p));
  }
  return out;
}

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
  out.endpoint_pubkey_hex = object_string(result, "endpoint_pubkey").value_or("");
  out.base_fee_per_kib = object_u64(result, "base_fee_per_kib").value_or(1);
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
      minijson::escape(address) + R"("}})";
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

namespace {

void append_history_page_params(std::ostringstream& body_json, std::uint64_t limit,
                                const std::optional<HistoryCursor>& start_after) {
  body_json << R"(,"limit":)" << limit;
  if (start_after.has_value()) {
    body_json << R"(,"start_after":{"height":)" << start_after->height << R"(,"txid":")" << hex_encode32(start_after->txid)
              << R"("})";
  }
  body_json << "}}";
}

std::optional<HistoryPageView> post_history_page(const std::string& rpc_url, const std::string& body_json, std::string* err) {
  auto body = http_post_json(rpc_url, body_json, err);
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

}  // namespace

std::optional<HistoryPageView> rpc_get_history_page(const std::string& rpc_url, const Hash32& scripthash, std::uint64_t limit,
                                                    const std::optional<HistoryCursor>& start_after, std::string* err) {
  std::ostringstream body_json;
  body_json << R"({"jsonrpc":"2.0","id":33,"method":"get_history_page","params":{"scripthash_hex":")"
            << hex_encode32(scripthash) << R"(")";
  append_history_page_params(body_json, limit, start_after);
  return post_history_page(rpc_url, body_json.str(), err);
}

std::optional<HistoryPageView> rpc_get_confidential_history_page(const std::string& rpc_url,
                                                                 const std::vector<Hash32>& history_keys, std::uint64_t limit,
                                                                 const std::optional<HistoryCursor>& start_after,
                                                                 std::string* err) {
  std::ostringstream body_json;
  body_json << R"({"jsonrpc":"2.0","id":37,"method":"get_confidential_history_page","params":{"history_keys_hex":[)";
  for (std::size_t i = 0; i < history_keys.size(); ++i) {
    if (i) body_json << ",";
    body_json << "\"" << hex_encode32(history_keys[i]) << "\"";
  }
  body_json << "]";
  append_history_page_params(body_json, limit, start_after);
  return post_history_page(rpc_url, body_json.str(), err);
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

std::optional<std::vector<p2p::EndpointAnnouncement>> rpc_get_lightserver_endpoints(const std::string& rpc_url,
                                                                                     std::string* err) {
  auto body = http_post_json(rpc_url, R"({"jsonrpc":"2.0","id":36,"method":"get_lightserver_endpoints","params":{}})", err);
  if (!body) return std::nullopt;
  auto root = minijson::parse(*body);
  if (!root.has_value()) {
    if (err) *err = "invalid rpc response";
    return std::nullopt;
  }
  const auto* result = result_value(*root, err);
  const auto* list = result && result->is_object() ? result->get("endpoints") : nullptr;
  if (!list || !list->is_array()) {
    if (err && err->empty()) *err = "missing endpoints";
    return std::nullopt;
  }
  std::vector<p2p::EndpointAnnouncement> out;
  for (const auto& item : list->array_value) {
    if (out.size() >= p2p::kEndpointTableCapacity) break;
    const auto pub = hex_decode(object_string(&item, "pubkey").value_or(""));
    const auto sig = hex_decode(object_string(&item, "signature").value_or(""));
    const auto url = object_string(&item, "url");
    const auto issued = object_u64(&item, "issued_unix");
    if (!pub || pub->size() != 32 || !sig || sig->size() != 64 || !url || url->size() > p2p::kMaxEndpointUrlBytes ||
        !issued) {
      continue;
    }
    p2p::EndpointAnnouncement a;
    std::copy(pub->begin(), pub->end(), a.pubkey.begin());
    std::copy(sig->begin(), sig->end(), a.signature.begin());
    a.url = *url;
    a.issued_unix = *issued;
    out.push_back(std::move(a));
  }
  return out;
}

bool probe_announced_endpoint(const p2p::EndpointAnnouncement& a, const Hash32& chain_domain, bool allow_private,
                              std::uint64_t now_unix, std::string* why) {
  const auto fail = [&](const std::string& reason) {
    if (why) *why = reason;
    return false;
  };
  if (!p2p::verify_endpoint_announcement(chain_domain, a, now_unix, allow_private)) return fail("bad announcement");
  std::string err;
  const auto status = rpc_get_status(a.url, &err);
  if (!status) return fail("unreachable: " + err);
  const auto domain = chain_domain_from_hex(status->chain.network_id_hex, status->chain.genesis_hash_hex);
  if (!domain || *domain != chain_domain) return fail("serves another chain");
  if (status->endpoint_pubkey_hex != hex_encode(Bytes(a.pubkey.begin(), a.pubkey.end()))) {
    return fail("server does not report the announced key");
  }
  return true;
}

std::optional<TimedRevealView> rpc_get_timed_reveal(const std::string& rpc_url, const Hash32& timed_txid, std::string* err) {
  const std::string body_json = std::string(R"({"jsonrpc":"2.0","id":35,"method":"get_timed_reveal","params":{"txid":")") +
                                hex_encode32(timed_txid) + R"("}})";
  auto body = http_post_json(rpc_url, body_json, err);
  if (!body) return std::nullopt;
  auto root = minijson::parse(*body);
  if (!root.has_value()) {
    if (err) *err = "invalid rpc response";
    return std::nullopt;
  }
  const auto* result = result_value(*root, err);
  if (!result || !result->is_object()) return std::nullopt;
  const auto revealed = object_bool(result, "revealed");
  if (!revealed) {
    if (err) *err = "missing timed reveal fields";
    return std::nullopt;
  }
  TimedRevealView out;
  out.revealed = *revealed;
  if (!out.revealed) return out;
  const auto height = object_u64(result, "height");
  const auto data_hex = object_string(result, "data_hex");
  auto data = data_hex ? hex_decode(*data_hex) : std::nullopt;
  if (!height || !data) {
    if (err) *err = "missing timed reveal fields";
    return std::nullopt;
  }
  out.height = *height;
  out.data = std::move(*data);
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

std::string default_admin_rpc_url(const std::string& network_name) {
  return "unix://" + default_admin_socket_path(network_name);
}

std::optional<onboarding::ValidatorOnboardingRecord> rpc_validator_onboarding_status(
    const std::string& rpc_url, const onboarding::ValidatorOnboardingOptions& options, const std::string& tracked_txid_hex,
    std::string* err) {
  std::ostringstream body_json;
  body_json << R"({"jsonrpc":"2.0","id":6,"method":"validator_onboarding_status","params":{"key_file":")"
            << minijson::escape(options.key_file) << R"(","passphrase":")" << minijson::escape(options.passphrase) << R"(","fee":)" << options.fee
            << R"(,"wait_for_sync":)" << (options.wait_for_sync ? "true" : "false");
  if (!tracked_txid_hex.empty()) body_json << R"(,"txid_hex":")" << minijson::escape(tracked_txid_hex) << "\"";
  body_json << "}}";
  auto body = http_post_json(rpc_url, body_json.str(), err);
  if (!body) return std::nullopt;
  auto root = minijson::parse(*body);
  if (!root.has_value()) {
    if (err) *err = "invalid rpc response";
    return std::nullopt;
  }
  const auto* result = result_value(*root, err);
  auto record = parse_onboarding_record_result(result, err);
  if (record) record->rpc_endpoint = rpc_url;
  return record;
}

std::optional<onboarding::ValidatorOnboardingRecord> rpc_validator_onboarding_start(
    const std::string& rpc_url, const onboarding::ValidatorOnboardingOptions& options, std::string* err) {
  std::ostringstream body_json;
  body_json << R"({"jsonrpc":"2.0","id":7,"method":"validator_onboarding_start","params":{"key_file":")"
            << minijson::escape(options.key_file) << R"(","passphrase":")" << minijson::escape(options.passphrase) << R"(","fee":)" << options.fee
            << R"(,"wait_for_sync":)" << (options.wait_for_sync ? "true" : "false") << "}}";
  auto body = http_post_json(rpc_url, body_json.str(), err);
  if (!body) return std::nullopt;
  auto root = minijson::parse(*body);
  if (!root.has_value()) {
    if (err) *err = "invalid rpc response";
    return std::nullopt;
  }
  const auto* result = result_value(*root, err);
  auto record = parse_onboarding_record_result(result, err);
  if (record) record->rpc_endpoint = rpc_url;
  return record;
}

std::optional<std::string> http_post_json_raw(const std::string& url, const std::string& body, std::string* err) {
  return http_post_json(url, body, err);
}

std::optional<std::string> http_post_json_raw(const std::string& url, const std::string& body,
                                              const std::vector<std::pair<std::string, std::string>>& headers,
                                              std::string* err) {
  return http_post_json(url, body, headers, err);
}

}  // namespace finalis::lightserver
