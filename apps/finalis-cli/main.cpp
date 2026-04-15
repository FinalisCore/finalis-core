#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <array>
#include <chrono>
#include <thread>
#include <ctime>
#include <regex>
#include <fstream>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <optional>
#include <random>
#include <set>
#include <string>
#include <algorithm>
#include <vector>
#include <filesystem>
#include <cstdio>

#include "address/address.hpp"
#include "common/chain_id.hpp"
#include "common/network.hpp"
#include "common/paths.hpp"
#include "common/socket_compat.hpp"
#include "common/wide_arith.hpp"
#include "common/version.hpp"
#include "consensus/monetary.hpp"
#include "consensus/epoch_committee.hpp"
#include "consensus/epoch_tickets.hpp"
#include "consensus/randomness.hpp"
#include "crypto/ed25519.hpp"
#include "crypto/hash.hpp"
#include "genesis/embedded_mainnet.hpp"
#include "genesis/genesis.hpp"
#include "keystore/validator_keystore.hpp"
#include "lightserver/client.hpp"
#include "onboarding/validator_onboarding.hpp"
#include "p2p/framing.hpp"
#include "p2p/messages.hpp"
#include "policy/hashcash.hpp"
#include "privacy/mint_client.hpp"
#include "privacy/mint_scripts.hpp"
#include "storage/db.hpp"
#include "storage/snapshot.hpp"
#include "utxo/signing.hpp"
#include "wallet/utxo_selection.hpp"

namespace {

std::string short_pub_hex(const finalis::PubKey32& pub) {
  return finalis::hex_encode(finalis::Bytes(pub.begin(), pub.begin() + 4));
}

std::string short_hash_hex(const finalis::Hash32& hash) {
  return finalis::hex_encode(finalis::Bytes(hash.begin(), hash.begin() + 6));
}

std::string json_escape(const std::string& in) {
  std::ostringstream oss;
  for (unsigned char c : in) {
    switch (c) {
      case '\\':
        oss << "\\\\";
        break;
      case '"':
        oss << "\\\"";
        break;
      case '\b':
        oss << "\\b";
        break;
      case '\f':
        oss << "\\f";
        break;
      case '\n':
        oss << "\\n";
        break;
      case '\r':
        oss << "\\r";
        break;
      case '\t':
        oss << "\\t";
        break;
      default:
        if (c < 0x20) {
          oss << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(c) << std::dec
              << std::setfill(' ');
        } else {
          oss << static_cast<char>(c);
        }
        break;
    }
  }
  return oss.str();
}

const char* epoch_ticket_origin_name(finalis::consensus::EpochTicketOrigin origin) {
  switch (origin) {
    case finalis::consensus::EpochTicketOrigin::LOCAL:
      return "LOCAL";
    case finalis::consensus::EpochTicketOrigin::NETWORK:
      return "NETWORK";
    default:
      return "UNKNOWN";
  }
}

std::optional<finalis::net::SocketHandle> connect_tcp(const std::string& host, std::uint16_t port) {
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
  return fd;
}

bool do_handshake_v0(finalis::net::SocketHandle fd) {
  finalis::p2p::VersionMsg v;
  v.timestamp = static_cast<std::uint64_t>(std::time(nullptr));
  v.nonce = 0xC011CAFE;
  v.start_height = 0;
  v.start_hash = finalis::zero_hash();

  if (!finalis::p2p::write_frame_fd(fd, finalis::p2p::Frame{finalis::p2p::MsgType::VERSION, finalis::p2p::ser_version(v)})) {
    return false;
  }

  bool got_version = false;
  bool got_verack = false;
  bool sent_verack = false;

  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
  while (std::chrono::steady_clock::now() < deadline && (!got_version || !got_verack)) {
    auto f = finalis::p2p::read_frame_fd(fd);
    if (!f.has_value()) return false;
    if (f->msg_type == finalis::p2p::MsgType::VERSION) {
      auto pv = finalis::p2p::de_version(f->payload);
      if (!pv.has_value()) return false;
      got_version = true;
      if (!sent_verack) {
        if (!finalis::p2p::write_frame_fd(fd, finalis::p2p::Frame{finalis::p2p::MsgType::VERACK, {}})) {
          return false;
        }
        sent_verack = true;
      }
    } else if (f->msg_type == finalis::p2p::MsgType::VERACK) {
      got_verack = true;
    }
  }

  return got_version && got_verack;
}

std::optional<std::array<std::uint8_t, 32>> decode_hex32(const std::string& hex) {
  auto b = finalis::hex_decode(hex);
  if (!b.has_value() || b->size() != 32) return std::nullopt;
  std::array<std::uint8_t, 32> out{};
  std::copy(b->begin(), b->end(), out.begin());
  return out;
}

std::optional<std::array<std::uint8_t, 64>> decode_hex64(const std::string& hex) {
  auto b = finalis::hex_decode(hex);
  if (!b.has_value() || b->size() != 64) return std::nullopt;
  std::array<std::uint8_t, 64> out{};
  std::copy(b->begin(), b->end(), out.begin());
  return out;
}

struct ParsedHttpUrl {
  std::string host;
  std::uint16_t port{0};
  std::string path;
};

std::optional<ParsedHttpUrl> parse_http_url(const std::string& url) {
  std::regex re(R"(^http://([^/:]+):([0-9]+)(/[^ ]*)$)");
  std::smatch m;
  if (!std::regex_match(url, m, re)) return std::nullopt;
  ParsedHttpUrl out;
  out.host = m[1].str();
  out.port = static_cast<std::uint16_t>(std::stoul(m[2].str()));
  out.path = m[3].str();
  return out;
}

std::optional<std::string> http_post_json(const std::string& url, const std::string& body,
                                          const std::string& bearer_token, std::string* err);
std::optional<std::string> http_post_json(const std::string& url, const std::string& body, std::string* err);
std::optional<std::string> http_get_json(const std::string& url, const std::string& bearer_token, std::string* err);
std::optional<std::string> http_get_json(const std::string& url, std::string* err);
std::optional<std::string> http_get_text(const std::string& url, std::string* err);
using HttpHeaders = std::vector<std::pair<std::string, std::string>>;
std::optional<std::string> http_post_json_with_headers(const std::string& url, const std::string& body,
                                                       const HttpHeaders& headers, std::string* err);
std::optional<std::string> http_get_json_with_headers(const std::string& url, const HttpHeaders& headers,
                                                      std::string* err);

std::string sha256_hex_string(const std::string& data) {
  finalis::Bytes b(data.begin(), data.end());
  const auto h = finalis::crypto::sha256(b);
  return finalis::hex_encode(finalis::Bytes(h.begin(), h.end()));
}

std::optional<std::uint64_t> parse_coin_amount_text(const std::string& text) {
  auto trim_local = [](const std::string& in) {
    const auto first = in.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return std::string{};
    const auto last = in.find_last_not_of(" \t\r\n");
    return in.substr(first, last - first + 1);
  };
  const std::string trimmed = trim_local(text);
  if (trimmed.empty()) return std::nullopt;
  const auto dot = trimmed.find('.');
  if (dot != std::string::npos && trimmed.find('.', dot + 1) != std::string::npos) return std::nullopt;

  const std::string whole_part = dot == std::string::npos ? trimmed : trimmed.substr(0, dot);
  const std::string frac_part = dot == std::string::npos ? std::string{} : trimmed.substr(dot + 1);
  if (!whole_part.empty() &&
      !std::all_of(whole_part.begin(), whole_part.end(), [](unsigned char c) { return std::isdigit(c) != 0; })) {
    return std::nullopt;
  }
  if (!frac_part.empty() &&
      !std::all_of(frac_part.begin(), frac_part.end(), [](unsigned char c) { return std::isdigit(c) != 0; })) {
    return std::nullopt;
  }
  if (frac_part.size() > 8) return std::nullopt;

  std::uint64_t units = 0;
  if (!whole_part.empty()) {
    try {
      const std::uint64_t whole = std::stoull(whole_part);
      units = whole * finalis::consensus::BASE_UNITS_PER_COIN;
    } catch (...) {
      return std::nullopt;
    }
  }
  if (!frac_part.empty()) {
    std::string padded = frac_part;
    padded.append(8 - padded.size(), '0');
    try {
      units += std::stoull(padded);
    } catch (...) {
      return std::nullopt;
    }
  }
  return units;
}

std::optional<std::string> hmac_sha256_hex(const finalis::Bytes& key, const std::string& data) {
  unsigned int out_len = 0;
  unsigned char out[EVP_MAX_MD_SIZE];
  if (!HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
            reinterpret_cast<const unsigned char*>(data.data()), data.size(), out, &out_len)) {
    return std::nullopt;
  }
  return finalis::hex_encode(finalis::Bytes(out, out + out_len));
}

std::optional<HttpHeaders> operator_signed_headers_for_url(const std::string& method, const std::string& url,
                                                           const std::string& body, const std::string& key_id,
                                                           const std::string& secret_hex, std::string* err) {
  if (key_id.empty() || secret_hex.empty()) {
    if (err) *err = "operator auth requires key id and secret";
    return std::nullopt;
  }
  auto parsed = parse_http_url(url);
  if (!parsed) {
    if (err) *err = "url must be http://host:port/path";
    return std::nullopt;
  }
  auto secret_opt = finalis::hex_decode(secret_hex);
  if (!secret_opt || secret_opt->size() < 16) {
    if (err) *err = "operator secret must be at least 16 bytes of hex";
    return std::nullopt;
  }
  const auto timestamp = std::to_string(static_cast<std::uint64_t>(std::time(nullptr)));
  const auto body_hash = sha256_hex_string(body);
  const auto payload = method + "\n" + parsed->path + "\n" + timestamp + "\n" + body_hash;
  auto sig = hmac_sha256_hex(*secret_opt, payload);
  if (!sig) {
    if (err) *err = "failed to sign operator request";
    return std::nullopt;
  }
  return HttpHeaders{
      {"X-Finalis-Operator-Key", key_id},
      {"X-Finalis-Timestamp", timestamp},
      {"X-Finalis-Signature", *sig},
  };
}

std::optional<std::string> http_post_json_with_headers(const std::string& url, const std::string& body,
                                                       const HttpHeaders& headers, std::string* err) {
  auto parsed = parse_http_url(url);
  if (!parsed) {
    if (err) *err = "url must be http://host:port/path";
    return std::nullopt;
  }
  auto fd_opt = connect_tcp(parsed->host, parsed->port);
  if (!fd_opt.has_value()) {
    if (err) *err = "connect failed";
    return std::nullopt;
  }
  const auto fd = *fd_opt;
  std::ostringstream req;
  req << "POST " << parsed->path << " HTTP/1.1\r\nHost: " << parsed->host << ":" << parsed->port
      << "\r\nContent-Type: application/json\r\n";
  for (const auto& [k, v] : headers) {
    req << k << ": " << v << "\r\n";
  }
  req << "Content-Length: " << body.size()
      << "\r\nConnection: close\r\n\r\n" << body;
  const auto req_s = req.str();
  if (!finalis::p2p::write_all(fd, reinterpret_cast<const std::uint8_t*>(req_s.data()), req_s.size())) {
    finalis::net::close_socket(fd);
    if (err) *err = "send failed";
    return std::nullopt;
  }
  std::string resp;
  std::array<char, 4096> buf{};
  while (true) {
    const ssize_t n = ::recv(fd, buf.data(), buf.size(), 0);
    if (n <= 0) break;
    resp.append(buf.data(), static_cast<std::size_t>(n));
  }
  finalis::net::close_socket(fd);
  const auto pos = resp.find("\r\n\r\n");
  if (pos == std::string::npos) {
    if (err) *err = "bad http response";
    return std::nullopt;
  }
  return resp.substr(pos + 4);
}

std::optional<std::string> http_post_json(const std::string& url, const std::string& body,
                                          const std::string& bearer_token, std::string* err) {
  HttpHeaders headers;
  if (!bearer_token.empty()) headers.push_back({"Authorization", "Bearer " + bearer_token});
  return http_post_json_with_headers(url, body, headers, err);
}

std::optional<std::string> http_post_json(const std::string& url, const std::string& body, std::string* err) {
  return http_post_json(url, body, "", err);
}

std::optional<std::string> http_get_json_with_headers(const std::string& url, const HttpHeaders& headers,
                                                      std::string* err) {
  auto parsed = parse_http_url(url);
  if (!parsed) {
    if (err) *err = "url must be http://host:port/path";
    return std::nullopt;
  }
  auto fd_opt = connect_tcp(parsed->host, parsed->port);
  if (!fd_opt.has_value()) {
    if (err) *err = "connect failed";
    return std::nullopt;
  }
  const auto fd = *fd_opt;
  std::ostringstream req;
  req << "GET " << parsed->path << " HTTP/1.1\r\nHost: " << parsed->host << ":" << parsed->port << "\r\n";
  for (const auto& [k, v] : headers) {
    req << k << ": " << v << "\r\n";
  }
  req << "Connection: close\r\n\r\n";
  const auto req_s = req.str();
  if (!finalis::p2p::write_all(fd, reinterpret_cast<const std::uint8_t*>(req_s.data()), req_s.size())) {
    finalis::net::close_socket(fd);
    if (err) *err = "send failed";
    return std::nullopt;
  }
  std::string resp;
  std::array<char, 4096> buf{};
  while (true) {
    const ssize_t n = ::recv(fd, buf.data(), buf.size(), 0);
    if (n <= 0) break;
    resp.append(buf.data(), static_cast<std::size_t>(n));
  }
  finalis::net::close_socket(fd);
  const auto pos = resp.find("\r\n\r\n");
  if (pos == std::string::npos) {
    if (err) *err = "bad http response";
    return std::nullopt;
  }
  return resp.substr(pos + 4);
}

std::optional<std::string> http_get_json(const std::string& url, const std::string& bearer_token, std::string* err) {
  HttpHeaders headers;
  if (!bearer_token.empty()) headers.push_back({"Authorization", "Bearer " + bearer_token});
  return http_get_json_with_headers(url, headers, err);
}

std::optional<std::string> http_get_json(const std::string& url, std::string* err) {
  return http_get_json(url, "", err);
}

std::optional<std::string> http_get_text(const std::string& url, std::string* err) {
  return http_get_json_with_headers(url, HttpHeaders{}, err);
}

std::optional<std::string> rpc_http_post(const std::string& url, const std::string& body, std::string* err) {
  auto parsed = parse_http_url(url);
  if (!parsed || parsed->path != "/rpc") {
    if (err) *err = "url must be http://host:port/rpc";
    return std::nullopt;
  }
  return http_post_json(url, body, err);
}

std::optional<std::string> find_json_string(const std::string& json, const std::string& key) {
  std::regex re("\"" + key + "\"\\s*:\\s*\"([^\"]*)\"");
  std::smatch m;
  if (!std::regex_search(json, m, re)) return std::nullopt;
  return m[1].str();
}

std::optional<std::uint64_t> find_json_u64(const std::string& json, const std::string& key) {
  std::regex re("\"" + key + "\"\\s*:\\s*([0-9]+)");
  std::smatch m;
  if (!std::regex_search(json, m, re)) return std::nullopt;
  return static_cast<std::uint64_t>(std::stoull(m[1].str()));
}

struct RpcStatusView {
  finalis::ChainId chain;
  std::uint64_t tip_height{0};
  std::string transition_hash;
  std::string version;
  std::string binary;
  std::string binary_version;
  std::string release;
  std::string wallet_api_version;
};

std::optional<RpcStatusView> parse_get_status_result(const std::string& body, std::string* err) {
  if (body.find("\"error\"") != std::string::npos) {
    if (err) *err = "rpc returned error";
    return std::nullopt;
  }
  RpcStatusView out;
  auto network_name = find_json_string(body, "network_name");
  auto network_id = find_json_string(body, "network_id");
  auto genesis_hash = find_json_string(body, "genesis_hash");
  auto genesis_source = find_json_string(body, "genesis_source");
  auto proto = find_json_u64(body, "protocol_version");
  auto magic = find_json_u64(body, "magic");
  auto tip_height = find_json_u64(body, "height");
  auto transition_hash = find_json_string(body, "transition_hash");
  auto version = find_json_string(body, "version");
  auto binary = find_json_string(body, "binary");
  auto binary_version = find_json_string(body, "binary_version");
  auto release = find_json_string(body, "release");
  auto wallet_api_version = find_json_string(body, "wallet_api_version");
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
  if (version) out.version = *version;
  if (binary) out.binary = *binary;
  if (binary_version) out.binary_version = *binary_version;
  if (release) out.release = *release;
  if (wallet_api_version) out.wallet_api_version = *wallet_api_version;
  return out;
}

std::string expand_user(const std::string& path) {
  return finalis::expand_user_home(path);
}

std::vector<std::string> read_lines(const std::string& path) {
  std::ifstream in(path);
  std::vector<std::string> out;
  std::string line;
  while (std::getline(in, line)) out.push_back(line);
  return out;
}

std::vector<std::string> tail_lines(const std::string& path, std::size_t count) {
  auto lines = read_lines(path);
  if (lines.size() <= count) return lines;
  return std::vector<std::string>(lines.end() - static_cast<std::ptrdiff_t>(count), lines.end());
}

std::string trim_copy(std::string s) {
  while (!s.empty() && (s.back() == '\n' || s.back() == '\r' || s.back() == ' ' || s.back() == '\t')) s.pop_back();
  std::size_t start = 0;
  while (start < s.size() && (s[start] == ' ' || s[start] == '\t')) ++start;
  return s.substr(start);
}

std::string slashing_kind_name(finalis::storage::SlashingRecordKind kind) {
  switch (kind) {
    case finalis::storage::SlashingRecordKind::VOTE_EQUIVOCATION:
      return "vote-equivocation";
    case finalis::storage::SlashingRecordKind::PROPOSER_EQUIVOCATION:
      return "proposer-equivocation";
    case finalis::storage::SlashingRecordKind::ONCHAIN_SLASH:
      return "onchain-slash";
  }
  return "unknown";
}

std::string validator_status_name(finalis::consensus::ValidatorStatus status) {
  switch (status) {
    case finalis::consensus::ValidatorStatus::ONBOARDING:
      return "ONBOARDING";
    case finalis::consensus::ValidatorStatus::PENDING:
      return "PENDING";
    case finalis::consensus::ValidatorStatus::ACTIVE:
      return "ACTIVE";
    case finalis::consensus::ValidatorStatus::EXITING:
      return "EXITING";
    case finalis::consensus::ValidatorStatus::BANNED:
      return "BANNED";
    case finalis::consensus::ValidatorStatus::SUSPENDED:
      return "SUSPENDED";
  }
  return "UNKNOWN";
}

std::string validator_onboarding_broadcast_outcome_name(
    finalis::onboarding::ValidatorOnboardingBroadcastOutcome outcome) {
  switch (outcome) {
    case finalis::onboarding::ValidatorOnboardingBroadcastOutcome::NONE:
      return "none";
    case finalis::onboarding::ValidatorOnboardingBroadcastOutcome::SENT:
      return "sent";
    case finalis::onboarding::ValidatorOnboardingBroadcastOutcome::REJECTED:
      return "rejected";
    case finalis::onboarding::ValidatorOnboardingBroadcastOutcome::AMBIGUOUS:
      return "ambiguous";
  }
  return "unknown";
}

void print_onboarding_record(const finalis::onboarding::ValidatorOnboardingRecord& record, bool as_json) {
  if (as_json) {
    std::cout << "{"
              << "\"onboarding_id\":\"" << record.onboarding_id << "\","
              << "\"state\":\"" << finalis::onboarding::validator_onboarding_state_name(record.state) << "\","
              << "\"validator_pubkey\":\""
              << finalis::hex_encode(finalis::Bytes(record.validator_pubkey.begin(), record.validator_pubkey.end())) << "\","
              << "\"wallet_address\":\"" << record.wallet_address << "\","
              << "\"wait_for_sync\":" << (record.wait_for_sync ? "true" : "false") << ","
              << "\"fee\":" << record.fee << ","
              << "\"bond_amount\":" << record.bond_amount << ","
              << "\"eligibility_bond_amount\":" << record.eligibility_bond_amount << ","
              << "\"required_amount\":" << record.required_amount << ","
              << "\"last_spendable_balance\":" << record.last_spendable_balance << ","
              << "\"last_deficit\":" << record.last_deficit << ","
              << "\"registration_ready\":" << (record.readiness.registration_ready ? "true" : "false") << ","
              << "\"readiness_blockers\":\"" << record.readiness.readiness_blockers_csv << "\","
              << "\"txid\":\"" << record.txid_hex << "\","
              << "\"broadcast_outcome\":\"" << validator_onboarding_broadcast_outcome_name(record.broadcast_outcome)
              << "\","
              << "\"validator_status\":\"" << record.validator_status << "\","
              << "\"finalized_height\":" << record.finalized_height << ","
              << "\"activation_height\":" << record.activation_height << ","
              << "\"last_error_code\":\"" << record.last_error_code << "\","
              << "\"last_error_message\":\"" << record.last_error_message << "\""
              << "}\n";
    return;
  }
  std::cout << "onboarding_id=" << record.onboarding_id << "\n";
  std::cout << "state=" << finalis::onboarding::validator_onboarding_state_name(record.state) << "\n";
  std::cout << "validator_pubkey="
            << finalis::hex_encode(finalis::Bytes(record.validator_pubkey.begin(), record.validator_pubkey.end())) << "\n";
  std::cout << "wallet_address=" << record.wallet_address << "\n";
  std::cout << "wait_for_sync=" << (record.wait_for_sync ? "yes" : "no") << "\n";
  std::cout << "fee=" << record.fee << "\n";
  std::cout << "bond_amount=" << record.bond_amount << "\n";
  std::cout << "eligibility_bond_amount=" << record.eligibility_bond_amount << "\n";
  std::cout << "required_amount=" << record.required_amount << "\n";
  std::cout << "last_spendable_balance=" << record.last_spendable_balance << "\n";
  std::cout << "last_deficit=" << record.last_deficit << "\n";
  std::cout << "registration_ready=" << (record.readiness.registration_ready ? "yes" : "no") << "\n";
  std::cout << "readiness_stable_samples=" << record.readiness.readiness_stable_samples << "\n";
  std::cout << "readiness_blockers=" << record.readiness.readiness_blockers_csv << "\n";
  std::cout << "healthy_peer_count=" << record.readiness.healthy_peer_count << "\n";
  std::cout << "observed_network_height_known=" << (record.readiness.observed_network_height_known ? "yes" : "no")
            << "\n";
  std::cout << "observed_network_finalized_height=" << record.readiness.observed_network_finalized_height << "\n";
  std::cout << "finalized_lag=" << record.readiness.finalized_lag << "\n";
  std::cout << "selected_inputs=" << record.selected_inputs.size() << "\n";
  if (!record.txid_hex.empty()) std::cout << "txid=" << record.txid_hex << "\n";
  std::cout << "broadcast_outcome=" << validator_onboarding_broadcast_outcome_name(record.broadcast_outcome) << "\n";
  if (!record.rpc_endpoint.empty()) std::cout << "rpc_endpoint=" << record.rpc_endpoint << "\n";
  std::cout << "validator_status=" << record.validator_status << "\n";
  if (record.finalized_height != 0) std::cout << "finalized_height=" << record.finalized_height << "\n";
  if (record.activation_height != 0) std::cout << "activation_height=" << record.activation_height << "\n";
  std::cout << "last_error_code=" << record.last_error_code << "\n";
  std::cout << "last_error_message=" << record.last_error_message << "\n";
}

std::string local_tracked_onboarding_txid(const finalis::onboarding::ValidatorOnboardingOptions& options) {
  finalis::onboarding::ValidatorOnboardingService service;
  std::string err;
  auto record = service.status(options, &err);
  if (!record.has_value()) return {};
  if (record->tracking_detached || record->txid_hex.empty()) return {};
  if (record->state != finalis::onboarding::ValidatorOnboardingState::WAITING_FOR_FINALIZATION &&
      record->state != finalis::onboarding::ValidatorOnboardingState::PENDING_ACTIVATION) {
    return {};
  }
  return record->txid_hex;
}

std::optional<finalis::onboarding::ValidatorOnboardingRecord> rpc_onboarding_status_with_local_tracking(
    const std::string& rpc_url, const finalis::onboarding::ValidatorOnboardingOptions& options, std::string* err) {
  const std::string tracked_txid = local_tracked_onboarding_txid(options);
  return finalis::lightserver::rpc_validator_onboarding_status(rpc_url, options, tracked_txid, err);
}

bool db_lock_error(const std::string& err) {
  return err.find("database is locked") != std::string::npos || err.find("locked by the running finalis-node process") != std::string::npos;
}

std::string format_outpoint(const finalis::OutPoint& op) {
  return finalis::hex_encode32(op.txid) + ":" + std::to_string(op.index);
}

const char* availability_status_name_for_cli(finalis::availability::AvailabilityOperatorStatus status) {
  switch (status) {
    case finalis::availability::AvailabilityOperatorStatus::WARMUP:
      return "WARMUP";
    case finalis::availability::AvailabilityOperatorStatus::ACTIVE:
      return "ACTIVE";
    case finalis::availability::AvailabilityOperatorStatus::PROBATION:
      return "PROBATION";
    case finalis::availability::AvailabilityOperatorStatus::EJECTED:
      return "EJECTED";
  }
  return "UNKNOWN";
}

struct SpendableView {
  std::uint64_t total{0};
  std::uint64_t largest{0};
  std::size_t count{0};
  std::optional<finalis::OutPoint> largest_outpoint;
};

constexpr const char* kDefaultMainnetDbPath = "~/.finalis/mainnet";
constexpr const char* kDefaultMainnetValidatorKeyPath = "~/.finalis/mainnet/keystore/validator.json";

std::vector<std::pair<finalis::OutPoint, finalis::TxOut>> spendable_utxos_for_pubkey_hash(
    const finalis::storage::DB& db, const std::array<std::uint8_t, 20>& pkh) {
  std::vector<std::pair<finalis::OutPoint, finalis::TxOut>> out;
  const auto spendable = finalis::wallet::spendable_p2pkh_utxos_for_pubkey_hash(db, pkh, nullptr);
  out.reserve(spendable.size());
  for (const auto& utxo : spendable) out.push_back({utxo.outpoint, utxo.prevout});
  std::sort(out.begin(), out.end(), [](const auto& a, const auto& b) {
    if (a.second.value != b.second.value) return a.second.value > b.second.value;
    if (a.first.txid != b.first.txid) return a.first.txid < b.first.txid;
    return a.first.index < b.first.index;
  });
  return out;
}

std::optional<std::array<std::uint8_t, 20>> decode_wallet_pubkey_hash(const std::string& address, std::string* err) {
  auto decoded = finalis::address::decode(address);
  if (!decoded.has_value()) {
    if (err) *err = "invalid wallet address in keystore";
    return std::nullopt;
  }
  return decoded->pubkey_hash;
}

std::vector<std::pair<finalis::OutPoint, finalis::TxOut>> spendable_utxos_for_wallet_address(
    const finalis::storage::DB& db, const std::string& address, std::string* err) {
  auto pkh = decode_wallet_pubkey_hash(address, err);
  if (!pkh.has_value()) return {};
  std::vector<std::pair<finalis::OutPoint, finalis::TxOut>> out;
  const auto utxos = spendable_utxos_for_pubkey_hash(db, *pkh);
  out.reserve(utxos.size());
  for (const auto& [op, txout] : utxos) out.push_back({op, txout});
  return out;
}

std::vector<std::pair<finalis::OutPoint, finalis::TxOut>> positive_value_utxos(
    const std::vector<std::pair<finalis::OutPoint, finalis::TxOut>>& utxos) {
  std::vector<std::pair<finalis::OutPoint, finalis::TxOut>> out;
  out.reserve(utxos.size());
  for (const auto& entry : utxos) {
    if (entry.second.value == 0) continue;
    out.push_back(entry);
  }
  return out;
}

SpendableView spendable_for_pubkey_hash(const finalis::storage::DB& db, const std::array<std::uint8_t, 20>& pkh) {
  SpendableView out;
  const auto utxos = spendable_utxos_for_pubkey_hash(db, pkh);
  for (const auto& [op, txout] : utxos) {
    if (txout.value == 0) continue;
    out.total += txout.value;
    ++out.count;
    if (txout.value > out.largest) {
      out.largest = txout.value;
      out.largest_outpoint = op;
    }
  }
  return out;
}

std::optional<SpendableView> spendable_for_wallet_address(const finalis::storage::DB& db, const std::string& address, std::string* err) {
  auto pkh = decode_wallet_pubkey_hash(address, err);
  if (!pkh.has_value()) return std::nullopt;
  return spendable_for_pubkey_hash(db, *pkh);
}

std::optional<std::uint64_t> settlement_epoch_start_for_height(const finalis::NetworkConfig& net, std::uint64_t height) {
  const auto epoch_blocks = std::max<std::uint64_t>(1, net.committee_epoch_blocks);
  const auto epoch_start = finalis::consensus::committee_epoch_start(height, epoch_blocks);
  if (height != epoch_start || epoch_start <= 1 || epoch_start <= epoch_blocks) return std::nullopt;
  return epoch_start - epoch_blocks;
}

std::optional<finalis::ValidatorJoinRequest> find_join_request_for_pubkey(
    const std::map<finalis::Hash32, finalis::ValidatorJoinRequest>& reqs, const finalis::PubKey32& pub) {
  for (const auto& [_, req] : reqs) {
    if (req.validator_pubkey == pub) return req;
  }
  return std::nullopt;
}

finalis::consensus::ValidatorRegistry build_registry_for_cli(
    const finalis::NetworkConfig& net, const std::map<finalis::PubKey32, finalis::consensus::ValidatorInfo>& validators,
    std::uint64_t height) {
  finalis::consensus::ValidatorRegistry registry;
  registry.set_rules(finalis::consensus::ValidatorRules{
      .min_bond = finalis::consensus::validator_min_bond_units(net, height, validators.size()),
      .warmup_blocks = net.validator_warmup_blocks,
      .cooldown_blocks = net.validator_cooldown_blocks,
  });
  for (const auto& [pub, info] : validators) registry.upsert(pub, info);
  return registry;
}

std::size_t active_operator_count_for_cli(
    const finalis::consensus::ValidatorRegistry& registry,
    const std::map<finalis::PubKey32, finalis::consensus::ValidatorInfo>& validators, std::uint64_t height) {
  std::set<finalis::PubKey32> operators;
  for (const auto& [pub, info] : validators) {
    if (!registry.is_active_for_height(pub, height)) continue;
    operators.insert(info.operator_id == finalis::PubKey32{} ? pub : info.operator_id);
  }
  return operators.size();
}

std::vector<std::string> run_command_lines(const std::string& cmd) {
  std::vector<std::string> out;
#ifdef _WIN32
  FILE* fp = ::_popen(cmd.c_str(), "r");
#else
  FILE* fp = ::popen(cmd.c_str(), "r");
#endif
  if (!fp) return out;
  char buf[4096];
  while (std::fgets(buf, sizeof(buf), fp)) out.push_back(trim_copy(buf));
#ifdef _WIN32
  (void)::_pclose(fp);
#else
  (void)::pclose(fp);
#endif
  return out;
}

bool contains_any(const std::string& s, const std::vector<std::string>& needles) {
  for (const auto& n : needles) {
    if (s.find(n) != std::string::npos) return true;
  }
  return false;
}

void print_section(const std::string& title) {
  std::cout << "\n== " << title << " ==\n";
}

std::string default_mainnet_db_path() { return expand_user(kDefaultMainnetDbPath); }

std::string default_mainnet_validator_key_path() { return expand_user(kDefaultMainnetValidatorKeyPath); }

void print_user_cli_help(std::ostream& os) {
  os << "finalis-cli user/validator commands:\n"
     << "  finalis-cli help [user|dev|all]\n"
     << "  finalis-cli --version\n"
     << "  finalis-cli getWallet [--file ~/.finalis/mainnet/keystore/validator.json] [--pass <pass>]\n"
     << "  finalis-cli getBalance [--db ~/.finalis/mainnet] [--file ~/.finalis/mainnet/keystore/validator.json] [--pass <pass>]\n"
     << "  finalis-cli getUTXO [--db ~/.finalis/mainnet] [--file ~/.finalis/mainnet/keystore/validator.json] [--pass <pass>]\n"
     << "  finalis-cli send --to <addr> (--amount <coins> | --amount-units <u64> | --max) [--fee <u64>] [--rpc <url>] [--db ~/.finalis/mainnet] [--file ~/.finalis/mainnet/keystore/validator.json] [--pass <pass>]\n"
     << "  finalis-cli onboarding-register [--db ~/.finalis/mainnet] [--file ~/.finalis/mainnet/keystore/validator.json] [--validator-file <path>] [--rpc <url>] [--pass <pass>] [--fee <u64>]\n"
     << "  finalis-cli validator_status [--db ~/.finalis/mainnet] [--file ~/.finalis/mainnet/keystore/validator.json] [--pass <pass>]\n"
     << "  finalis-cli economics_status [--db ~/.finalis/mainnet] [--file ~/.finalis/mainnet/keystore/validator.json] [--pass <pass>] [--height <n>] [--settlement-epoch-start <n>] [--json]\n"
     << "  finalis-cli validator-register [--db ~/.finalis/mainnet] [--file ~/.finalis/mainnet/keystore/validator.json] [--rpc <url>] [--pass <pass>] [--fee <u64>] [--timeout-seconds <n>] [--json] [--no-watch] [--no-wait-for-sync]\n"
     << "  finalis-cli validator-register-status [--db ~/.finalis/mainnet] [--file ~/.finalis/mainnet/keystore/validator.json] [--rpc <url>] [--pass <pass>] [--json]\n"
     << "  finalis-cli validator-register-cancel [--db ~/.finalis/mainnet] [--file ~/.finalis/mainnet/keystore/validator.json] [--rpc <url>] [--pass <pass>]  # cancel attempt before broadcast; detach local tracking after broadcast\n"
     << "  finalis-cli wallet_create --out <path> [--pass <pass>] [--network mainnet] [--seed-hex <32b-hex>]\n"
     << "  finalis-cli wallet_import --out <path> --privkey <hex32> [--pass <pass>] [--network mainnet]\n"
     << "  finalis-cli wallet_address --file <path> [--pass <pass>]\n"
     << "  finalis-cli wallet_export --file <path> [--pass <pass>]\n"
     << "  finalis-cli address_from_pubkey --hrp <sc> --pubkey <hex32>\n"
     << "  finalis-cli build_p2pkh_tx --prev-txid <hex32> --prev-index <u32> --prev-value <u64> --from-privkey <hex32> --to-address <addr> --amount <u64> --fee <u64> [--change-address <addr>]\n"
     << "  finalis-cli build_p2pkh_multi_tx --prev-txid <hex32> --prev-index <u32> --prev-value <u64> [--prev-txid ...] --from-privkey <hex32> --to-address <addr> --amount <u64> --fee <u64> [--change-address <addr>]\n"
     << "\nUse `finalis-cli help dev` for protocol/admin commands.\n";
}

void print_dev_cli_help(std::ostream& os) {
  os << "finalis-cli developer/protocol commands:\n"
     << "  finalis-cli tip --db <dir>\n"
     << "  finalis-cli reindex [--db <dir>] [--file <path>]  # clear consensus cache so startup can rebuild\n"
     << "  finalis-cli --print-logs [--db <dir>] [--service <name>] [--tail <n>]\n"
     << "  finalis-cli print_logs [--db <dir>] [--service <name>] [--tail <n>]\n"
     << "  finalis-cli snapshot_export --db <dir> --out <snapshot.bin>\n"
     << "  finalis-cli snapshot_import --db <dir> --in <snapshot.bin>\n"
     << "  finalis-cli create_keypair [--seed-hex <32b-hex>] [--hrp sc]\n"
     << "  finalis-cli mint_deposit_create --prev-txid <hex32> --prev-index <u32> --prev-value <u64> --from-privkey <hex32> --mint-id <hex32> --recipient-address <addr> --amount <u64> [--fee <u64>] [--change-address <addr>]\n"
     << "  finalis-cli mint_deposit_status [--db <dir>] [--mint-id <hex32>] [--recipient-address <addr>] [--tail <n>]\n"
     << "  finalis-cli mint_deposit_register --url http://host:port/path --deposit-txid <hex32> --deposit-vout <u32> --mint-id <hex32> --recipient-address <addr> --amount <u64> [--chain mainnet]\n"
     << "  finalis-cli mint_issue_blinds --url http://host:port/path --mint-deposit-ref <id> --blind <msg> --note-amount <u64> [--blind <msg> --note-amount <u64> ...]\n"
     << "  finalis-cli mint_redeem_create --url http://host:port/path --redeem-address <addr> --amount <u64> --note <opaque> [--note <opaque> ...]\n"
     << "  finalis-cli mint_redeem_approve_broadcast --url http://host:port/path --batch-id <id> --operator-key-id <id> --operator-secret-hex <hex>\n"
     << "  finalis-cli mint_redeem_status --url http://host:port/path --batch-id <id>\n"
     << "  finalis-cli mint_redeem_update --url http://host:port/path --batch-id <id> --state <broadcast|rejected> [--l1-txid <hex32>] --operator-key-id <id> --operator-secret-hex <hex>\n"
     << "  finalis-cli mint_reserves --url http://host:port/path\n"
     << "  finalis-cli mint_reserve_alerts --url http://host:port/path\n"
     << "  finalis-cli mint_reserve_health --url http://host:port/path\n"
     << "  finalis-cli mint_reserve_metrics --url http://host:port/path\n"
     << "  finalis-cli mint_worker_status --url http://host:port/path\n"
     << "  finalis-cli mint_alert_history --url http://host:port/path\n"
     << "  finalis-cli mint_alert_ack --url http://host:port/path --event-id <id> --operator-key-id <id> --operator-secret-hex <hex> [--note <text>]\n"
     << "  finalis-cli mint_alert_silence --url http://host:port/path --event-type <type> --until <unix> --operator-key-id <id> --operator-secret-hex <hex> [--reason <text>]\n"
     << "  finalis-cli mint_alert_silences --url http://host:port/path\n"
     << "  finalis-cli mint_event_policy --url http://host:port/path\n"
     << "  finalis-cli mint_event_policy_update --url http://host:port/path --operator-key-id <id> --operator-secret-hex <hex> [--retention-limit <n>] [--export-include-acknowledged true|false]\n"
     << "  finalis-cli mint_notifier_list --url http://host:port/path\n"
     << "  finalis-cli mint_notifier_upsert --url http://host:port/path --operator-key-id <id> --operator-secret-hex <hex> --notifier-id <id> --kind webhook|alertmanager|email_spool --target <value> [--enabled true|false] [--retry-max-attempts <n>] [--retry-backoff-seconds <n>] [--auth-type none|bearer|basic] [--auth-token-secret-ref <ref>] [--auth-user-secret-ref <ref>] [--auth-pass-secret-ref <ref>] [--tls-verify true|false] [--tls-ca-file <path>] [--tls-client-cert-file <path>] [--tls-client-key-file <path>] [--email-to <addr>] [--email-from <addr>]\n"
     << "  finalis-cli mint_dead_letters --url http://host:port/path\n"
     << "  finalis-cli mint_dead_letter_replay --url http://host:port/path --dead-letter-id <id> --operator-key-id <id> --operator-secret-hex <hex>\n"
     << "  finalis-cli mint_incident_timeline_export --url http://host:port/path\n"
     << "  finalis-cli mint_reserve_consolidation_plan --url http://host:port/path --operator-key-id <id> --operator-secret-hex <hex>\n"
     << "  finalis-cli mint_reserve_consolidate --url http://host:port/path --operator-key-id <id> --operator-secret-hex <hex>\n"
     << "  finalis-cli mint_redemptions_pause --url http://host:port/path --operator-key-id <id> --operator-secret-hex <hex> [--reason <text>]\n"
     << "  finalis-cli mint_redemptions_resume --url http://host:port/path --operator-key-id <id> --operator-secret-hex <hex>\n"
     << "  finalis-cli mint_redemptions_auto_pause_enable --url http://host:port/path --operator-key-id <id> --operator-secret-hex <hex>\n"
     << "  finalis-cli mint_redemptions_auto_pause_disable --url http://host:port/path --operator-key-id <id> --operator-secret-hex <hex>\n"
     << "  finalis-cli mint_redemptions_policy --url http://host:port/path\n"
     << "  finalis-cli mint_accounting_summary --url http://host:port/path\n"
     << "  finalis-cli mint_attest_reserves --url http://host:port/path\n"
     << "  finalis-cli mint_audit_export --url http://host:port/path --operator-key-id <id> --operator-secret-hex <hex>\n"
     << "  finalis-cli mint_api_example\n"
     << "  finalis-cli hashcash_stamp_tx --tx-hex <hex> [--bits <n>] [--network mainnet] [--epoch-seconds <n>] [--now <unix>] [--max-nonce <n>]\n"
     << "  finalis-cli create_unbond_tx --bond-txid <hex32> --bond-index <u32> --bond-value <u64> --validator-pubkey <hex32> --validator-privkey <hex32> [--fee <u64>]\n"
     << "  finalis-cli create_slash_tx --bond-txid <hex32> --bond-index <u32> --bond-value <u64> --a-height <u64> --a-round <u32> --a-transition <hex32> --a-pub <hex32> --a-sig <hex64> --b-height <u64> --b-round <u32> --b-transition <hex32> --b-pub <hex32> --b-sig <hex64> [--fee <u64>]\n"
     << "  finalis-cli slash_records [--db <dir>] [--tail <n>]\n"
     << "  finalis-cli epoch_tickets [--db <dir>] --epoch <n>\n"
     << "  finalis-cli epoch_best [--db <dir>] --epoch <n>\n"
     << "  finalis-cli epoch_committee [--db <dir>] --epoch <n>\n"
     << "  finalis-cli epoch_state [--db <dir>] --epoch <n>\n"
     << "  finalis-cli genesis_build --in <genesis.json> --out <genesis.bin>\n"
     << "  finalis-cli genesis_hash --in <genesis.bin>\n"
     << "  finalis-cli genesis_verify --json <genesis.json> --bin <genesis.bin>\n"
     << "  finalis-cli genesis_print_embedded\n"
     << "  finalis-cli rpc_status --url http://host:port/rpc\n"
     << "  finalis-cli rpc_transition --url http://host:port/rpc (--height <n> | --hash <hex32>)\n"
     << "  finalis-cli show_ingress_tip --url http://host:port/rpc\n"
     << "  finalis-cli show_ingress_record --url http://host:port/rpc --seq <n>\n"
     << "  finalis-cli show_ingress_range --url http://host:port/rpc --start <n> --end <n>\n"
     << "  finalis-cli verify_ingress_slice --url http://host:port/rpc --start <n> --end <n>\n"
     << "  finalis-cli ingress_lane_tip --url http://host:port/rpc --lane <n>\n"
     << "  finalis-cli ingress_record --url http://host:port/rpc --lane <n> --seq <n>\n"
     << "  finalis-cli ingress_range --url http://host:port/rpc --lane <n> --from <n> --to <n>\n"
     << "  finalis-cli ingress_verify_range --url http://host:port/rpc --lane <n> --from <n> --to <n>\n"
     << "  finalis-cli rpc_compare --urls http://a:19444/rpc,http://b:19444/rpc\n"
     << "  finalis-cli broadcast_tx [--url http://host:port/rpc | --host <ip> --port <p>] --tx-hex <hex>\n";
}

void print_cli_help(std::ostream& os, const std::string& mode) {
  if (mode == "dev") {
    print_dev_cli_help(os);
    return;
  }
  if (mode == "all") {
    print_user_cli_help(os);
    os << "\n";
    print_dev_cli_help(os);
    return;
  }
  print_user_cli_help(os);
}

}  // namespace

int main(int argc, char** argv) {
  if (argc >= 2) {
    const std::string arg1 = argv[1];
    if (arg1 == "--version" || arg1 == "version") {
      std::cout << finalis::cli_software_version() << "\n";
      return 0;
    }
  }

  if (argc < 2) {
    print_cli_help(std::cerr, "user");
    return 1;
  }

  std::string cmd = argv[1];
  if (cmd == "help" || cmd == "--help") {
    std::string mode = "user";
    if (argc >= 3) mode = argv[2];
    print_cli_help(std::cout, mode);
    return 0;
  }
  if (cmd == "--print-logs" || cmd == "print_logs") {
    std::string db_path = default_mainnet_db_path();
    std::string service_name = "finalis";
    std::size_t tail = 20;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--db" && i + 1 < argc) db_path = argv[++i];
      else if (a == "--service" && i + 1 < argc) service_name = argv[++i];
      else if (a == "--tail" && i + 1 < argc) tail = static_cast<std::size_t>(std::stoull(argv[++i]));
    }

    db_path = expand_user(db_path);
    const auto db_dir = std::filesystem::path(db_path);
    const auto mining_log = (db_dir / "MiningLOG").string();
    const auto peers_path = (db_dir / "peers.dat").string();
    const auto addrman_path = (db_dir / "addrman.dat").string();
    const auto key_path = (db_dir / "keystore" / "validator.json").string();

    finalis::storage::DB db;
    const bool opened = db.open_readonly(db_path) || db.open(db_path);

    print_section("Node");
    std::cout << "db=" << db_path << "\n";
    std::cout << "service=" << service_name << "\n";
    std::cout << "opened_db=" << (opened ? "yes" : "no") << "\n";

    if (opened) {
      const auto tip = db.get_tip();
      if (tip) {
        std::cout << "height=" << tip->height << "\n";
        std::cout << "transition_hash=" << finalis::hex_encode32(tip->hash) << "\n";
        const auto cert = db.get_finality_certificate_by_height(tip->height);
        if (cert) {
          std::cout << "finality_quorum=" << cert->quorum_threshold << "\n";
          std::cout << "finality_signatures=" << cert->signatures.size() << "\n";
          std::cout << "committee_members=" << cert->committee_members.size() << "\n";
        }
        const auto net = finalis::mainnet_network();
        const auto epoch_start =
            finalis::consensus::committee_epoch_start(tip->height + 1, net.committee_epoch_blocks);
        const auto checkpoint = db.get_finalized_committee_checkpoint(epoch_start);
        if (checkpoint) {
          std::cout << "committee_epoch_start=" << checkpoint->epoch_start_height << "\n";
          std::cout << "committee_epoch_seed=" << finalis::hex_encode32(checkpoint->epoch_seed) << "\n";
          std::cout << "committee_epoch_ordered_members=" << checkpoint->ordered_members.size() << "\n";
          std::ostringstream members;
          for (std::size_t i = 0; i < checkpoint->ordered_members.size(); ++i) {
            if (i) members << ",";
            members << short_pub_hex(checkpoint->ordered_members[i]);
          }
          std::cout << "committee_epoch_members_short=" << members.str() << "\n";
        }
      } else {
        std::cout << "height=unknown\n";
      }

      const auto validators = db.load_validators();
      std::size_t active = 0;
      std::size_t pending = 0;
      std::size_t exiting = 0;
      std::size_t suspended = 0;
      std::size_t banned = 0;
      for (const auto& [_, info] : validators) {
        switch (info.status) {
          case finalis::consensus::ValidatorStatus::ACTIVE: ++active; break;
          case finalis::consensus::ValidatorStatus::PENDING: ++pending; break;
          case finalis::consensus::ValidatorStatus::EXITING: ++exiting; break;
          case finalis::consensus::ValidatorStatus::SUSPENDED: ++suspended; break;
          case finalis::consensus::ValidatorStatus::BANNED: ++banned; break;
        }
      }
      std::cout << "validators_total=" << validators.size() << "\n";
      std::cout << "validators_active=" << active << "\n";
      std::cout << "validators_pending=" << pending << "\n";
      std::cout << "validators_exiting=" << exiting << "\n";
      std::cout << "validators_suspended=" << suspended << "\n";
      std::cout << "validators_banned=" << banned << "\n";
    }

    std::string kerr;
    finalis::keystore::ValidatorKey vk;
    if (finalis::keystore::keystore_exists(key_path) &&
        finalis::keystore::load_validator_keystore(key_path, "", &vk, &kerr)) {
      std::cout << "local_validator_pubkey=" << finalis::hex_encode(finalis::Bytes(vk.pubkey.begin(), vk.pubkey.end()))
                << "\n";
      std::cout << "local_validator_address=" << vk.address << "\n";
    }

    print_section("Peers");
    if (std::filesystem::exists(peers_path)) {
      const auto peers = tail_lines(peers_path, tail);
      std::cout << "persisted_peers=" << peers.size() << "\n";
      for (const auto& line : peers) std::cout << line << "\n";
    } else {
      std::cout << "persisted_peers=0\n";
    }
    if (std::filesystem::exists(addrman_path)) {
      const auto addrman = tail_lines(addrman_path, tail);
      std::cout << "addrman_entries=" << addrman.size() << "\n";
      for (const auto& line : addrman) std::cout << line << "\n";
    } else {
      std::cout << "addrman_entries=0\n";
    }

    print_section("Mining");
    if (std::filesystem::exists(mining_log)) {
      const auto mining = tail_lines(mining_log, tail);
      std::cout << "mined_blocks_logged=" << mining.size() << "\n";
      for (const auto& line : mining) std::cout << line << "\n";
    } else {
      std::cout << "MiningLOG not found\n";
    }

    print_section("Security");
    const std::string journal_cmd =
        "journalctl -u " + service_name + " -n " + std::to_string(tail * 10) + " --no-pager -l -q 2>/dev/null";
    const auto journal_lines = run_command_lines(journal_cmd);
    const std::vector<std::string> security_needles = {
        "peer-banned", "peer-soft-muted", "reject-version", "drop-addr", "pre-handshake", "timeout",
        "adopted bootstrap validator", "bootstrap single-node genesis", "pending_joiners"};
    std::size_t emitted = 0;
    for (const auto& line : journal_lines) {
      if (!contains_any(line, security_needles)) continue;
      std::cout << line << "\n";
      ++emitted;
      if (emitted >= tail) break;
    }
    if (emitted == 0) {
      std::cout << "no recent security/runtime events found via journalctl\n";
    }

    print_section("Slashing");
    if (opened) {
      auto records = db.load_slashing_records();
      std::cout << "slashing_records=" << records.size() << "\n";
      std::vector<finalis::storage::SlashingRecord> ordered;
      ordered.reserve(records.size());
      for (const auto& [_, rec] : records) ordered.push_back(rec);
      std::sort(ordered.begin(), ordered.end(), [](const auto& a, const auto& b) {
        if (a.observed_height != b.observed_height) return a.observed_height > b.observed_height;
        return a.record_id > b.record_id;
      });
      const std::size_t limit = std::min<std::size_t>(tail, ordered.size());
      for (std::size_t i = 0; i < limit; ++i) {
        const auto& rec = ordered[i];
        std::cout << slashing_kind_name(rec.kind)
                  << " validator=" << finalis::hex_encode(finalis::Bytes(rec.validator_pubkey.begin(), rec.validator_pubkey.end()))
                  << " height=" << rec.height
                  << " round=" << rec.round
                  << " observed_height=" << rec.observed_height
                  << " a=" << finalis::hex_encode32(rec.object_a)
                  << " b=" << finalis::hex_encode32(rec.object_b);
        if (rec.txid != finalis::zero_hash()) {
          std::cout << " txid=" << finalis::hex_encode32(rec.txid);
        }
        std::cout << "\n";
      }
    } else {
      std::cout << "slashing_records=unknown\n";
    }
    return 0;
  }

  if (cmd == "--reindex" || cmd == "reindex") {
    std::string db_path = default_mainnet_db_path();
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--db" && i + 1 < argc) db_path = argv[++i];
      else if (a == "--file" && i + 1 < argc) (void)argv[++i];
    }
    db_path = expand_user(db_path);
    finalis::storage::DB db;
    if (!db.open(db_path)) {
      std::cerr << "failed to open db\n";
      return 1;
    }
    const bool erased = db.erase(finalis::storage::key_consensus_state_commitment_cache());
    std::cout << "reindex_erased=" << (erased ? "yes" : "no") << "\n";
    return 0;
  }

  if (cmd == "slash_records") {
    std::string db_path = default_mainnet_db_path();
    std::size_t tail = 20;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--db" && i + 1 < argc) db_path = argv[++i];
      else if (a == "--tail" && i + 1 < argc) tail = static_cast<std::size_t>(std::stoull(argv[++i]));
    }
    finalis::storage::DB db;
    if (!db.open_readonly(db_path) && !db.open(db_path)) {
      std::cerr << "failed to open db\n";
      return 1;
    }
    auto records = db.load_slashing_records();
    std::vector<finalis::storage::SlashingRecord> ordered;
    ordered.reserve(records.size());
    for (const auto& [_, rec] : records) ordered.push_back(rec);
    std::sort(ordered.begin(), ordered.end(), [](const auto& a, const auto& b) {
      if (a.observed_height != b.observed_height) return a.observed_height > b.observed_height;
      return a.record_id > b.record_id;
    });
    std::cout << "slashing_records=" << ordered.size() << "\n";
    const std::size_t limit = std::min<std::size_t>(tail, ordered.size());
    for (std::size_t i = 0; i < limit; ++i) {
      const auto& rec = ordered[i];
      std::cout << slashing_kind_name(rec.kind)
                << " validator=" << finalis::hex_encode(finalis::Bytes(rec.validator_pubkey.begin(), rec.validator_pubkey.end()))
                << " height=" << rec.height
                << " round=" << rec.round
                << " observed_height=" << rec.observed_height
                << " a=" << finalis::hex_encode32(rec.object_a)
                << " b=" << finalis::hex_encode32(rec.object_b);
      if (rec.txid != finalis::zero_hash()) {
        std::cout << " txid=" << finalis::hex_encode32(rec.txid);
      }
      std::cout << "\n";
    }
    return 0;
  }

  if (cmd == "epoch_tickets" || cmd == "epoch_best" || cmd == "epoch_committee" || cmd == "epoch_state") {
    std::string db_path = default_mainnet_db_path();
    std::optional<std::uint64_t> epoch;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--db" && i + 1 < argc) db_path = argv[++i];
      else if (a == "--epoch" && i + 1 < argc) epoch = static_cast<std::uint64_t>(std::stoull(argv[++i]));
    }
    if (!epoch.has_value()) {
      std::cerr << cmd << " requires --epoch\n";
      return 1;
    }

    finalis::storage::DB db;
    if (!db.open_readonly(db_path) && !db.open(db_path)) {
      std::cerr << "failed to open db\n";
      return 1;
    }

    const bool cmd_epoch_tickets = (cmd == "epoch_tickets");
    const bool cmd_epoch_best = (cmd == "epoch_best");
    const bool cmd_epoch_state = (cmd == "epoch_state");

    if (cmd_epoch_tickets) {
      const auto tickets = db.load_epoch_tickets(*epoch);
      std::cout << "epoch=" << *epoch << "\n";
      std::cout << "tickets=" << tickets.size() << "\n";
      for (const auto& ticket : tickets) {
        std::cout << "pubkey=" << finalis::hex_encode(finalis::Bytes(ticket.participant_pubkey.begin(), ticket.participant_pubkey.end()))
                  << " origin=" << epoch_ticket_origin_name(ticket.origin)
                  << " nonce=" << ticket.nonce
                  << " source_height=" << ticket.source_height
                  << " anchor=" << finalis::hex_encode32(ticket.challenge_anchor)
                  << " work=" << finalis::hex_encode32(ticket.work_hash)
                  << " work_short=" << short_hash_hex(ticket.work_hash) << "\n";
      }
      return 0;
    }

    if (cmd_epoch_best) {
      const auto best = db.load_best_epoch_tickets(*epoch);
      std::cout << "epoch=" << *epoch << "\n";
      std::cout << "best_tickets=" << best.size() << "\n";
      for (const auto& [pub, ticket] : best) {
        std::cout << "pubkey=" << finalis::hex_encode(finalis::Bytes(pub.begin(), pub.end()))
                  << " origin=" << epoch_ticket_origin_name(ticket.origin)
                  << " nonce=" << ticket.nonce
                  << " source_height=" << ticket.source_height
                  << " anchor=" << finalis::hex_encode32(ticket.challenge_anchor)
                  << " work=" << finalis::hex_encode32(ticket.work_hash)
                  << " work_short=" << short_hash_hex(ticket.work_hash) << "\n";
      }
      return 0;
    }

    if (cmd_epoch_state) {
      const auto tickets = db.load_epoch_tickets(*epoch);
      const auto best = db.load_best_epoch_tickets(*epoch);
      const auto snapshot = db.get_epoch_committee_snapshot(*epoch);
      std::uint64_t current_epoch = 0;
      bool closed = false;
      if (auto tip = db.get_tip(); tip.has_value()) {
        const auto net = finalis::mainnet_network();
        current_epoch = finalis::consensus::committee_epoch_start(tip->height + 1, net.committee_epoch_blocks);
        closed = (*epoch < current_epoch);
      }
      std::cout << "epoch=" << *epoch << "\n";
      std::cout << "current_epoch=" << current_epoch << "\n";
      std::cout << "closed=" << (closed ? "yes" : "no") << "\n";
      std::cout << "tickets=" << tickets.size() << "\n";
      std::cout << "best_tickets=" << best.size() << "\n";
      std::cout << "snapshot_present=" << (snapshot.has_value() ? "yes" : "no") << "\n";
      if (snapshot.has_value()) {
        std::cout << "challenge_anchor=" << finalis::hex_encode32(snapshot->challenge_anchor) << "\n";
        std::cout << "committee=" << snapshot->ordered_members.size() << "\n";
      }
      return 0;
    }

    auto snapshot = db.get_epoch_committee_snapshot(*epoch);
    if (!snapshot.has_value()) {
      const auto best = db.load_best_epoch_tickets(*epoch);
      if (!best.empty()) {
        finalis::Hash32 anchor = best.begin()->second.challenge_anchor;
        const auto net = finalis::mainnet_network();
        snapshot = finalis::consensus::derive_epoch_committee_snapshot(*epoch, anchor, best, finalis::MAX_COMMITTEE,
                                                                       nullptr, false);
      }
    }
    if (!snapshot.has_value()) {
      std::cout << "epoch=" << *epoch << "\n";
      std::cout << "committee=0\n";
      return 0;
    }

    std::cout << "epoch=" << snapshot->epoch << "\n";
    std::cout << "challenge_anchor=" << finalis::hex_encode32(snapshot->challenge_anchor) << "\n";
    if (auto tip = db.get_tip(); tip.has_value()) {
      const auto net = finalis::mainnet_network();
      const auto current_epoch = finalis::consensus::committee_epoch_start(tip->height + 1, net.committee_epoch_blocks);
      std::cout << "closed=" << (snapshot->epoch < current_epoch ? "yes" : "no") << "\n";
    }
    std::cout << "committee=" << snapshot->ordered_members.size() << "\n";
    for (std::size_t i = 0; i < snapshot->selected_winners.size(); ++i) {
      const auto& winner = snapshot->selected_winners[i];
      std::cout << "slot=" << i
                << " pubkey=" << finalis::hex_encode(finalis::Bytes(winner.participant_pubkey.begin(), winner.participant_pubkey.end()))
                << " nonce=" << winner.nonce
                << " source_height=" << winner.source_height
                << " work=" << finalis::hex_encode32(winner.work_hash)
                << " work_short=" << short_hash_hex(winner.work_hash) << "\n";
    }
    return 0;
  }

  if (cmd == "tip") {
    std::string db_path = default_mainnet_db_path();
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--db" && i + 1 < argc) db_path = argv[++i];
    }

    finalis::storage::DB db;
    if (!db.open(db_path)) {
      std::cerr << "failed to open db\n";
      return 1;
    }
    auto tip = db.get_tip();
    if (!tip) {
      std::cout << "no tip\n";
      return 0;
    }
    std::cout << "height=" << tip->height << " hash=" << finalis::hex_encode32(tip->hash) << "\n";
    return 0;
  }

  if (cmd == "snapshot_export") {
    std::string db_path = default_mainnet_db_path();
    std::string out_path;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--db" && i + 1 < argc) db_path = argv[++i];
      else if (a == "--out" && i + 1 < argc) out_path = argv[++i];
    }
    if (out_path.empty()) {
      std::cerr << "snapshot_export requires --out\n";
      return 1;
    }
    finalis::storage::DB db;
    if (!db.open_readonly(db_path) && !db.open(db_path)) {
      std::cerr << "failed to open db\n";
      return 1;
    }
    finalis::storage::SnapshotManifest manifest;
    std::string err;
    if (!finalis::storage::export_snapshot_bundle(db, out_path, &manifest, &err)) {
      std::cerr << "snapshot_export failed: " << err << "\n";
      return 1;
    }
    std::cout << "snapshot=" << out_path << "\n";
    std::cout << "finalized_height=" << manifest.finalized_height << "\n";
    std::cout << "finalized_transition_hash=" << finalis::hex_encode32(manifest.finalized_hash) << "\n";
    std::cout << "utxo_root=" << finalis::hex_encode32(manifest.utxo_root) << "\n";
    std::cout << "validators_root=" << finalis::hex_encode32(manifest.validators_root) << "\n";
    std::cout << "entry_count=" << manifest.entry_count << "\n";
    return 0;
  }

  if (cmd == "snapshot_import") {
    std::string db_path = default_mainnet_db_path();
    std::string in_path;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--db" && i + 1 < argc) db_path = argv[++i];
      else if (a == "--in" && i + 1 < argc) in_path = argv[++i];
    }
    if (in_path.empty()) {
      std::cerr << "snapshot_import requires --in\n";
      return 1;
    }
    finalis::storage::DB db;
    if (!db.open(db_path)) {
      std::cerr << "failed to open db\n";
      return 1;
    }
    finalis::storage::SnapshotManifest manifest;
    std::string err;
    if (!finalis::storage::import_snapshot_bundle(db, in_path, &manifest, &err)) {
      std::cerr << "snapshot_import failed: " << err << "\n";
      return 1;
    }
    std::cout << "db=" << db_path << "\n";
    std::cout << "finalized_height=" << manifest.finalized_height << "\n";
    std::cout << "finalized_transition_hash=" << finalis::hex_encode32(manifest.finalized_hash) << "\n";
    std::cout << "entry_count=" << manifest.entry_count << "\n";
    return 0;
  }

  if (cmd == "genesis_build") {
    std::string in_path;
    std::string out_path;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--in" && i + 1 < argc) in_path = argv[++i];
      else if (a == "--out" && i + 1 < argc) out_path = argv[++i];
    }
    if (in_path.empty() || out_path.empty()) {
      std::cerr << "genesis_build requires --in and --out\n";
      return 1;
    }
    std::string err;
    auto doc = finalis::genesis::load_from_path(in_path, &err);
    if (!doc) {
      std::cerr << "failed to load genesis json: " << err << "\n";
      return 1;
    }
    if (!finalis::genesis::validate_document(*doc, finalis::mainnet_network(), &err, 0)) {
      std::cerr << "genesis validation failed: " << err << "\n";
      return 1;
    }
    const auto bin = finalis::genesis::encode_bin(*doc);
    if (!finalis::genesis::write_bin_to_path(out_path, bin, &err)) {
      std::cerr << "failed to write genesis bin: " << err << "\n";
      return 1;
    }
    const auto ghash = finalis::genesis::hash_bin(bin);
    const auto gbid = finalis::genesis::block_id(*doc);
    std::cout << "network_id=" << finalis::hex_encode(finalis::Bytes(doc->network_id.begin(), doc->network_id.end())) << "\n";
    std::cout << "magic=" << doc->magic << "\n";
    std::cout << "validator_count=" << doc->initial_validators.size() << "\n";
    std::cout << "genesis_hash=" << finalis::hex_encode32(ghash) << "\n";
    std::cout << "genesis_transition_id=" << finalis::hex_encode32(gbid) << "\n";
    return 0;
  }

  if (cmd == "genesis_hash") {
    std::string in_path;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--in" && i + 1 < argc) in_path = argv[++i];
    }
    if (in_path.empty()) {
      std::cerr << "genesis_hash requires --in\n";
      return 1;
    }
    std::string err;
    auto bin = finalis::genesis::load_bin_from_path(in_path, &err);
    if (!bin) {
      std::cerr << "failed to load genesis bin: " << err << "\n";
      return 1;
    }
    auto doc = finalis::genesis::decode_bin(*bin, &err);
    if (!doc) {
      std::cerr << "failed to decode genesis bin: " << err << "\n";
      return 1;
    }
    const auto ghash = finalis::genesis::hash_bin(*bin);
    const auto gbid = finalis::genesis::block_id(*doc);
    std::cout << "network_id=" << finalis::hex_encode(finalis::Bytes(doc->network_id.begin(), doc->network_id.end())) << "\n";
    std::cout << "magic=" << doc->magic << "\n";
    std::cout << "validator_count=" << doc->initial_validators.size() << "\n";
    std::cout << "genesis_hash=" << finalis::hex_encode32(ghash) << "\n";
    std::cout << "genesis_transition_id=" << finalis::hex_encode32(gbid) << "\n";
    return 0;
  }

  if (cmd == "genesis_verify") {
    std::string json_path;
    std::string bin_path;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--json" && i + 1 < argc) json_path = argv[++i];
      else if (a == "--bin" && i + 1 < argc) bin_path = argv[++i];
    }
    if (json_path.empty() || bin_path.empty()) {
      std::cerr << "genesis_verify requires --json and --bin\n";
      return 1;
    }
    std::string err;
    auto doc = finalis::genesis::load_from_path(json_path, &err);
    if (!doc) {
      std::cerr << "failed to load genesis json: " << err << "\n";
      return 1;
    }
    if (!finalis::genesis::validate_document(*doc, finalis::mainnet_network(), &err, 0)) {
      std::cerr << "genesis validation failed: " << err << "\n";
      return 1;
    }
    auto existing = finalis::genesis::load_bin_from_path(bin_path, &err);
    if (!existing) {
      std::cerr << "failed to read genesis bin: " << err << "\n";
      return 1;
    }
    const auto rebuilt = finalis::genesis::encode_bin(*doc);
    if (*existing != rebuilt) {
      std::cerr << "genesis verify failed: binary mismatch\n";
      return 1;
    }
    const auto ghash = finalis::genesis::hash_bin(rebuilt);
    const auto gbid = finalis::genesis::block_id(*doc);
    std::cout << "verified=1\n";
    std::cout << "genesis_hash=" << finalis::hex_encode32(ghash) << "\n";
    std::cout << "genesis_transition_id=" << finalis::hex_encode32(gbid) << "\n";
    return 0;
  }

  if (cmd == "genesis_print_embedded") {
    std::cout << "embedded_mainnet_genesis_len=" << finalis::genesis::MAINNET_GENESIS_BIN_LEN << "\n";
    std::cout << "embedded_mainnet_genesis_hash=" << finalis::hex_encode32(finalis::genesis::MAINNET_GENESIS_HASH)
              << "\n";
    return 0;
  }

  if (cmd == "rpc_status") {
    std::string url;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--url" && i + 1 < argc) url = argv[++i];
    }
    if (url.empty()) {
      std::cerr << "rpc_status requires --url\n";
      return 1;
    }
    std::string err;
    auto body = rpc_http_post(url, R"({"jsonrpc":"2.0","id":1,"method":"get_status","params":{}})", &err);
    if (!body.has_value()) {
      std::cerr << "rpc_status failed: " << err << "\n";
      return 1;
    }
    auto status = parse_get_status_result(*body, &err);
    if (!status.has_value()) {
      std::cerr << "rpc_status parse failed: " << err << "\n";
      return 1;
    }
    std::cout << "url=" << url << "\n";
    std::cout << "network_name=" << status->chain.network_name << "\n";
    std::cout << "network_id=" << status->chain.network_id_hex << "\n";
    std::cout << "protocol_version=" << status->chain.protocol_version << "\n";
    std::cout << "magic=" << status->chain.magic << "\n";
    std::cout << "genesis_hash=" << status->chain.genesis_hash_hex << "\n";
    std::cout << "genesis_source=" << status->chain.genesis_source << "\n";
    if (!status->version.empty()) std::cout << "status_version=" << status->version << "\n";
    if (!status->binary.empty()) std::cout << "binary=" << status->binary << "\n";
    if (!status->binary_version.empty()) std::cout << "binary_version=" << status->binary_version << "\n";
    if (!status->release.empty()) std::cout << "release=" << status->release << "\n";
    if (!status->wallet_api_version.empty()) std::cout << "wallet_api_version=" << status->wallet_api_version << "\n";
    std::cout << "tip_height=" << status->tip_height << "\n";
    std::cout << "transition_hash=" << status->transition_hash << "\n";
    return 0;
  }

  if (cmd == "rpc_transition") {
    std::string url;
    std::string hash_hex;
    std::string height_text;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--url" && i + 1 < argc) url = argv[++i];
      else if (a == "--hash" && i + 1 < argc) hash_hex = argv[++i];
      else if (a == "--height" && i + 1 < argc) height_text = argv[++i];
    }
    if (url.empty() || (hash_hex.empty() == height_text.empty())) {
      std::cerr << "rpc_transition requires --url and exactly one of --height/--hash\n";
      return 1;
    }
    std::string method;
    std::string params;
    if (!height_text.empty()) {
      method = "get_transition_by_height";
      params = std::string("{\"height\":") + height_text + "}";
    } else {
      method = "get_transition";
      params = std::string("{\"hash\":\"") + hash_hex + "\"}";
    }
    std::string err;
    auto body = rpc_http_post(
        url, std::string("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"") + method + "\",\"params\":" + params + "}", &err);
    if (!body.has_value()) {
      std::cerr << "rpc_transition failed: " << err << "\n";
      return 1;
    }
    auto transition_hash = find_json_string(*body, "transition_hash");
    auto transition_hex = find_json_string(*body, "transition_hex");
    if (!transition_hash || !transition_hex) {
      std::cerr << "rpc_transition parse failed: missing transition fields\n";
      return 1;
    }
    auto decoded = finalis::hex_decode(*transition_hex);
    if (!decoded.has_value()) {
      std::cerr << "rpc_transition parse failed: bad transition hex\n";
      return 1;
    }
    auto transition = finalis::FrontierTransition::parse(*decoded);
    if (!transition.has_value()) {
      std::cerr << "rpc_transition parse failed: transition parse failed\n";
      return 1;
    }
    std::cout << "transition_hash=" << *transition_hash << "\n";
    std::cout << "height=" << transition->height << "\n";
    std::cout << "round=" << transition->round << "\n";
    std::cout << "prev_frontier=" << transition->prev_frontier << "\n";
    std::cout << "next_frontier=" << transition->next_frontier << "\n";
    std::cout << "ingress_range=(" << (transition->prev_frontier + 1) << "," << transition->next_frontier << "]\n";
    std::cout << "prev_finalized_hash=" << finalis::hex_encode32(transition->prev_finalized_hash) << "\n";
    std::cout << "next_state_root=" << finalis::hex_encode32(transition->next_state_root) << "\n";
    std::cout << "decisions_commitment=" << finalis::hex_encode32(transition->decisions_commitment) << "\n";
    std::cout << "settlement_commitment=" << finalis::hex_encode32(transition->settlement_commitment) << "\n";
    std::cout << "settlement_total=" << transition->settlement.total << "\n";
    std::cout << "settlement_current_fees=" << transition->settlement.current_fees << "\n";
    std::cout << "settled_epoch_rewards=" << transition->settlement.settled_epoch_rewards << "\n";
    return 0;
  }

  if (cmd == "show_ingress_tip") {
    std::string url;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--url" && i + 1 < argc) url = argv[++i];
    }
    if (url.empty()) {
      std::cerr << "show_ingress_tip requires --url\n";
      return 1;
    }
    std::string err;
    auto body = rpc_http_post(url, R"({"jsonrpc":"2.0","id":1,"method":"get_ingress_tip","params":{}})", &err);
    if (!body.has_value()) {
      std::cerr << "show_ingress_tip failed: " << err << "\n";
      return 1;
    }
    auto tip = find_json_u64(*body, "ingress_tip");
    if (!tip.has_value()) {
      std::cerr << "show_ingress_tip parse failed: missing ingress_tip\n";
      return 1;
    }
    std::cout << "ingress_tip=" << *tip << "\n";
    return 0;
  }

  if (cmd == "ingress_lane_tip") {
    std::string url;
    std::string lane_text;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--url" && i + 1 < argc) url = argv[++i];
      else if (a == "--lane" && i + 1 < argc) lane_text = argv[++i];
    }
    if (url.empty() || lane_text.empty()) {
      std::cerr << "ingress_lane_tip requires --url and --lane\n";
      return 1;
    }
    std::string err;
    auto body = rpc_http_post(
        url, std::string("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"get_ingress_lane_tip\",\"params\":{\"lane\":") +
                 lane_text + "}}",
        &err);
    if (!body.has_value()) {
      std::cerr << "ingress_lane_tip failed: " << err << "\n";
      return 1;
    }
    auto lane = find_json_u64(*body, "lane");
    auto tip_seq = find_json_u64(*body, "tip_seq");
    if (!lane.has_value() || !tip_seq.has_value()) {
      std::cerr << "ingress_lane_tip parse failed: missing lane/tip_seq\n";
      return 1;
    }
    const bool present = body->find("\"present\":true") != std::string::npos;
    std::cout << "lane=" << *lane << "\n";
    std::cout << "present=" << (present ? "true" : "false") << "\n";
    std::cout << "tip_seq=" << *tip_seq << "\n";
    if (auto epoch = find_json_u64(*body, "epoch"); epoch.has_value()) std::cout << "epoch=" << *epoch << "\n";
    if (auto lane_root = find_json_string(*body, "lane_root"); lane_root.has_value()) {
      std::cout << "lane_root=" << *lane_root << "\n";
    }
    return 0;
  }

  if (cmd == "show_ingress_record") {
    std::string url;
    std::string seq_text;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--url" && i + 1 < argc) url = argv[++i];
      else if (a == "--seq" && i + 1 < argc) seq_text = argv[++i];
    }
    if (url.empty() || seq_text.empty()) {
      std::cerr << "show_ingress_record requires --url and --seq\n";
      return 1;
    }
    std::string err;
    auto body = rpc_http_post(
        url, std::string("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"get_ingress_record\",\"params\":{\"seq\":") +
                 seq_text + "}}",
        &err);
    if (!body.has_value()) {
      std::cerr << "show_ingress_record failed: " << err << "\n";
      return 1;
    }
    const auto seq = find_json_u64(*body, "seq");
    const auto txid = find_json_string(*body, "txid");
    const auto hash = find_json_string(*body, "hash");
    if (!seq.has_value()) {
      std::cerr << "show_ingress_record parse failed: missing seq\n";
      return 1;
    }
    const bool is_present = body->find("\"present\":true") != std::string::npos;
    std::cout << "seq=" << *seq << "\n";
    std::cout << "present=" << (is_present ? "true" : "false") << "\n";
    if (txid.has_value()) std::cout << "txid=" << *txid << "\n";
    if (hash.has_value()) std::cout << "hash=" << *hash << "\n";
    return 0;
  }

  if (cmd == "ingress_record") {
    std::string url;
    std::string lane_text;
    std::string seq_text;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--url" && i + 1 < argc) url = argv[++i];
      else if (a == "--lane" && i + 1 < argc) lane_text = argv[++i];
      else if (a == "--seq" && i + 1 < argc) seq_text = argv[++i];
    }
    if (url.empty() || lane_text.empty() || seq_text.empty()) {
      std::cerr << "ingress_record requires --url --lane --seq\n";
      return 1;
    }
    std::string err;
    auto body = rpc_http_post(
        url, std::string("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"get_ingress_record\",\"params\":{\"lane\":") +
                 lane_text + ",\"seq\":" + seq_text + "}}",
        &err);
    if (!body.has_value()) {
      std::cerr << "ingress_record failed: " << err << "\n";
      return 1;
    }
    auto lane = find_json_u64(*body, "lane");
    auto seq = find_json_u64(*body, "seq");
    if (!lane.has_value() || !seq.has_value()) {
      std::cerr << "ingress_record parse failed: missing lane/seq\n";
      return 1;
    }
    const bool present = body->find("\"present\":true") != std::string::npos;
    std::cout << "lane=" << *lane << "\n";
    std::cout << "seq=" << *seq << "\n";
    std::cout << "present=" << (present ? "true" : "false") << "\n";
    if (auto txid = find_json_string(*body, "txid"); txid.has_value()) std::cout << "txid=" << *txid << "\n";
    if (auto tx_hash = find_json_string(*body, "tx_hash"); tx_hash.has_value()) std::cout << "tx_hash=" << *tx_hash << "\n";
    if (auto cert_hash = find_json_string(*body, "cert_hash"); cert_hash.has_value()) {
      std::cout << "cert_hash=" << *cert_hash << "\n";
    }
    if (auto signer_count = find_json_u64(*body, "signer_count"); signer_count.has_value()) {
      std::cout << "signer_count=" << *signer_count << "\n";
    }
    const bool bytes_present = body->find("\"bytes_present\":true") != std::string::npos;
    if (present) std::cout << "bytes_present=" << (bytes_present ? "true" : "false") << "\n";
    return 0;
  }

  if (cmd == "show_ingress_range" || cmd == "verify_ingress_slice") {
    std::string url;
    std::string start_text;
    std::string end_text;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--url" && i + 1 < argc) url = argv[++i];
      else if (a == "--start" && i + 1 < argc) start_text = argv[++i];
      else if (a == "--end" && i + 1 < argc) end_text = argv[++i];
    }
    if (url.empty() || start_text.empty() || end_text.empty()) {
      std::cerr << cmd << " requires --url --start --end\n";
      return 1;
    }
    const std::string method = (cmd == "show_ingress_range") ? "get_ingress_range" : "verify_ingress_slice";
    std::string err;
    auto body = rpc_http_post(
        url, std::string("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"") + method +
                 "\",\"params\":{\"start\":" + start_text + ",\"end\":" + end_text + "}}",
        &err);
    if (!body.has_value()) {
      std::cerr << cmd << " failed: " << err << "\n";
      return 1;
    }
    auto start = find_json_u64(*body, "start");
    auto end = find_json_u64(*body, "end");
    if (!start.has_value() || !end.has_value()) {
      std::cerr << cmd << " parse failed: missing start/end\n";
      return 1;
    }
    std::cout << "start=" << *start << "\n";
    std::cout << "end=" << *end << "\n";
    if (cmd == "show_ingress_range") {
      const bool complete = body->find("\"complete\":true") != std::string::npos;
      std::cout << "complete=" << (complete ? "true" : "false") << "\n";
    } else {
      const bool verified = body->find("\"verified\":true") != std::string::npos;
      std::cout << "verified=" << (verified ? "true" : "false") << "\n";
      auto failure = find_json_string(*body, "failure");
      if (failure.has_value()) std::cout << "failure=" << *failure << "\n";
    }
    auto commitment = find_json_string(*body, "slice_commitment");
    if (commitment.has_value()) std::cout << "slice_commitment=" << *commitment << "\n";
    std::regex record_re(
        R"INGRESS(\{"seq":([0-9]+),"present":(true|false)(?:,"hash":"([0-9a-f]+)")?(?:,"txid":"([0-9a-f]+)")?\})INGRESS");
    for (std::sregex_iterator it(body->begin(), body->end(), record_re), end_it; it != end_it; ++it) {
      std::cout << "record seq=" << (*it)[1].str() << " present=" << (*it)[2].str();
      if ((*it)[4].matched) std::cout << " txid=" << (*it)[4].str();
      if ((*it)[3].matched) std::cout << " hash=" << (*it)[3].str();
      std::cout << "\n";
    }
    return 0;
  }

  if (cmd == "ingress_range" || cmd == "ingress_verify_range") {
    std::string url;
    std::string lane_text;
    std::string from_text;
    std::string to_text;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--url" && i + 1 < argc) url = argv[++i];
      else if (a == "--lane" && i + 1 < argc) lane_text = argv[++i];
      else if (a == "--from" && i + 1 < argc) from_text = argv[++i];
      else if (a == "--to" && i + 1 < argc) to_text = argv[++i];
    }
    if (url.empty() || lane_text.empty() || from_text.empty() || to_text.empty()) {
      std::cerr << cmd << " requires --url --lane --from --to\n";
      return 1;
    }
    const std::string method = (cmd == "ingress_range") ? "get_ingress_range" : "verify_ingress_slice";
    std::string err;
    auto body = rpc_http_post(
        url, std::string("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"") + method +
                 "\",\"params\":{\"lane\":" + lane_text + ",\"from_seq\":" + from_text + ",\"to_seq\":" + to_text + "}}",
        &err);
    if (!body.has_value()) {
      std::cerr << cmd << " failed: " << err << "\n";
      return 1;
    }
    auto lane = find_json_u64(*body, "lane");
    if (!lane.has_value()) {
      std::cerr << cmd << " parse failed: missing lane\n";
      return 1;
    }
    std::cout << "lane=" << *lane << "\n";
    std::cout << "from_seq=" << from_text << "\n";
    std::cout << "to_seq=" << to_text << "\n";
    if (cmd == "ingress_range") {
      const bool complete = body->find("\"complete\":true") != std::string::npos;
      std::cout << "complete=" << (complete ? "true" : "false") << "\n";
    } else {
      const bool verified = body->find("\"verified\":true") != std::string::npos;
      std::cout << "verified=" << (verified ? "true" : "false") << "\n";
      if (auto failure = find_json_string(*body, "failure"); failure.has_value()) std::cout << "failure=" << *failure << "\n";
    }
    std::regex record_re(
        R"INGRESS(\{"lane":[0-9]+,"seq":([0-9]+),"present":(true|false)(?:,"txid":"([0-9a-f]+)")?(?:,"tx_hash":"([0-9a-f]+)")?.*?\})INGRESS");
    for (std::sregex_iterator it(body->begin(), body->end(), record_re), end_it; it != end_it; ++it) {
      std::cout << "record seq=" << (*it)[1].str() << " present=" << (*it)[2].str();
      if ((*it)[3].matched) std::cout << " txid=" << (*it)[3].str();
      if ((*it)[4].matched) std::cout << " tx_hash=" << (*it)[4].str();
      std::cout << "\n";
    }
    return 0;
  }

  if (cmd == "rpc_compare") {
    std::string urls_csv;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--urls" && i + 1 < argc) urls_csv = argv[++i];
    }
    if (urls_csv.empty()) {
      std::cerr << "rpc_compare requires --urls\n";
      return 1;
    }
    std::vector<std::string> urls;
    {
      std::stringstream ss(urls_csv);
      std::string item;
      while (std::getline(ss, item, ',')) {
        if (!item.empty()) urls.push_back(item);
      }
    }
    if (urls.size() < 2) {
      std::cerr << "rpc_compare requires at least 2 urls\n";
      return 1;
    }

    std::vector<RpcStatusView> statuses;
    statuses.reserve(urls.size());
    bool had_error = false;

    std::cout << "url\tnetwork_id\tgenesis_hash\tproto\tmagic\theight\ttip\n";
    for (const auto& url : urls) {
      std::string err;
      auto body = rpc_http_post(url, R"({"jsonrpc":"2.0","id":1,"method":"get_status","params":{}})", &err);
      if (!body.has_value()) {
        std::cout << url << "\tERR\tERR\tERR\tERR\tERR\t" << err << "\n";
        had_error = true;
        continue;
      }
      auto st = parse_get_status_result(*body, &err);
      if (!st.has_value()) {
        std::cout << url << "\tERR\tERR\tERR\tERR\tERR\t" << err << "\n";
        had_error = true;
        continue;
      }
      statuses.push_back(*st);
      std::cout << url << "\t" << st->chain.network_id_hex.substr(0, 8) << "...\t" << st->chain.genesis_hash_hex.substr(0, 8)
                << "...\t" << st->chain.protocol_version << "\t" << st->chain.magic << "\t" << st->tip_height << "\t"
                << st->transition_hash.substr(0, 8) << "...\n";
    }

    if (had_error || statuses.size() < 2) return 2;

    bool mismatch = false;
    const auto& ref = statuses.front().chain;
    for (std::size_t i = 1; i < statuses.size(); ++i) {
      const auto mm = finalis::compare_chain_identity(ref, statuses[i].chain);
      if (!mm.match) {
        mismatch = true;
        std::cout << "MISMATCH[" << i << "]:";
        if (mm.network_id_differs) std::cout << " network_id";
        if (mm.genesis_hash_differs) std::cout << " genesis_hash";
        if (mm.protocol_version_differs) std::cout << " protocol_version";
        if (mm.magic_differs) std::cout << " magic";
        std::cout << "\n";
      }
    }
    if (mismatch) return 2;
    std::cout << "all chain identities match\n";
    return 0;
  }

  if (cmd == "create_keypair") {
    std::string seed_hex;
    std::string hrp = "sc";
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--seed-hex" && i + 1 < argc) seed_hex = argv[++i];
      if (a == "--hrp" && i + 1 < argc) hrp = argv[++i];
    }

    std::array<std::uint8_t, 32> seed{};
    if (!seed_hex.empty()) {
      auto s = decode_hex32(seed_hex);
      if (!s.has_value()) {
        std::cerr << "--seed-hex must be 32 bytes hex\n";
        return 1;
      }
      seed = *s;
    } else {
      std::random_device rd;
      for (auto& b : seed) b = static_cast<std::uint8_t>(rd());
    }

    auto kp = finalis::crypto::keypair_from_seed32(seed);
    if (!kp.has_value()) {
      std::cerr << "failed to create keypair\n";
      return 1;
    }
    auto pkh = finalis::crypto::h160(finalis::Bytes(kp->public_key.begin(), kp->public_key.end()));
    auto addr = finalis::address::encode_p2pkh(hrp, pkh);

    std::cout << "privkey_hex=" << finalis::hex_encode(finalis::Bytes(seed.begin(), seed.end())) << "\n";
    std::cout << "pubkey_hex=" << finalis::hex_encode(finalis::Bytes(kp->public_key.begin(), kp->public_key.end())) << "\n";
    if (addr.has_value()) std::cout << "address=" << *addr << "\n";
    return 0;
  }

  if (cmd == "wallet_create") {
    std::string out_path;
    std::string passphrase;
    std::string network_name = "mainnet";
    std::string seed_hex;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--out" && i + 1 < argc) out_path = argv[++i];
      else if (a == "--pass" && i + 1 < argc) passphrase = argv[++i];
      else if (a == "--network" && i + 1 < argc) network_name = argv[++i];
      else if (a == "--seed-hex" && i + 1 < argc) seed_hex = argv[++i];
    }
    if (out_path.empty()) {
      std::cerr << "--out is required\n";
      return 1;
    }
    if (network_name != "mainnet") {
      std::cerr << "only --network mainnet is supported\n";
      return 1;
    }
    std::optional<std::array<std::uint8_t, 32>> seed_override;
    if (!seed_hex.empty()) {
      seed_override = decode_hex32(seed_hex);
      if (!seed_override) {
        std::cerr << "--seed-hex must be 32-byte hex\n";
        return 1;
      }
    }
    finalis::keystore::ValidatorKey vk;
    std::string err;
    if (!finalis::keystore::create_validator_keystore(out_path, passphrase, network_name,
                                                        finalis::keystore::hrp_for_network(network_name),
                                                        seed_override, &vk, &err)) {
      std::cerr << "wallet_create failed: " << err << "\n";
      return 1;
    }
    std::cout << "file=" << out_path << "\n";
    std::cout << "network=" << vk.network_name << "\n";
    std::cout << "pubkey_hex=" << finalis::hex_encode(finalis::Bytes(vk.pubkey.begin(), vk.pubkey.end())) << "\n";
    std::cout << "address=" << vk.address << "\n";
    return 0;
  }

  if (cmd == "wallet_address") {
    std::string file_path;
    std::string passphrase;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--file" && i + 1 < argc) file_path = argv[++i];
      else if (a == "--pass" && i + 1 < argc) passphrase = argv[++i];
    }
    if (file_path.empty()) {
      std::cerr << "--file is required\n";
      return 1;
    }
    finalis::keystore::ValidatorKey vk;
    std::string err;
    if (!finalis::keystore::load_validator_keystore(file_path, passphrase, &vk, &err)) {
      std::cerr << "wallet_address failed: " << err << "\n";
      return 1;
    }
    std::cout << vk.address << "\n";
    return 0;
  }

  if (cmd == "wallet_export") {
    std::string file_path;
    std::string passphrase;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--file" && i + 1 < argc) file_path = argv[++i];
      else if (a == "--pass" && i + 1 < argc) passphrase = argv[++i];
    }
    if (file_path.empty()) {
      std::cerr << "--file is required\n";
      return 1;
    }
    finalis::keystore::ValidatorKey vk;
    std::string err;
    if (!finalis::keystore::load_validator_keystore(file_path, passphrase, &vk, &err)) {
      std::cerr << "wallet_export failed: " << err << "\n";
      return 1;
    }
    std::cout << "network=" << vk.network_name << "\n";
    std::cout << "privkey_hex=" << finalis::hex_encode(finalis::Bytes(vk.privkey.begin(), vk.privkey.end())) << "\n";
    std::cout << "pubkey_hex=" << finalis::hex_encode(finalis::Bytes(vk.pubkey.begin(), vk.pubkey.end())) << "\n";
    std::cout << "address=" << vk.address << "\n";
    return 0;
  }

  if (cmd == "getWallet") {
    std::string file_path;
    std::string passphrase;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--file" && i + 1 < argc) file_path = argv[++i];
      else if (a == "--pass" && i + 1 < argc) passphrase = argv[++i];
    }
    if (file_path.empty()) file_path = default_mainnet_validator_key_path();
    finalis::keystore::ValidatorKey vk;
    std::string err;
    if (!finalis::keystore::load_validator_keystore(file_path, passphrase, &vk, &err)) {
      std::cerr << "getWallet failed: " << err << "\n";
      return 1;
    }
    std::cout << "file=" << file_path << "\n";
    std::cout << "network=" << vk.network_name << "\n";
    std::cout << "pubkey_hex=" << finalis::hex_encode(finalis::Bytes(vk.pubkey.begin(), vk.pubkey.end())) << "\n";
    std::cout << "address=" << vk.address << "\n";
    return 0;
  }

  if (cmd == "validator_status") {
    std::string db_path = default_mainnet_db_path();
    std::string file_path = default_mainnet_validator_key_path();
    std::string passphrase;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--db" && i + 1 < argc) db_path = argv[++i];
      else if (a == "--file" && i + 1 < argc) file_path = argv[++i];
      else if (a == "--pass" && i + 1 < argc) passphrase = argv[++i];
    }
    db_path = expand_user(db_path);
    file_path = expand_user(file_path);
    finalis::storage::DB db;
    if (!db.open_readonly(db_path) && !db.open(db_path)) {
      std::cerr << "failed to open db\n";
      return 1;
    }
    finalis::keystore::ValidatorKey vk;
    std::string err;
    if (!finalis::keystore::load_validator_keystore(file_path, passphrase, &vk, &err)) {
      std::cerr << "validator_status failed to load key: " << err << "\n";
      return 1;
    }

    const auto tip = db.get_tip();
    const auto validators = db.load_validators();
    const auto reqs = db.load_validator_join_requests();
    std::string spendable_err;
    const auto spendable = spendable_for_wallet_address(db, vk.address, &spendable_err);
    if (!spendable.has_value()) {
      std::cerr << "validator_status failed to resolve wallet address: " << spendable_err << "\n";
      return 1;
    }
    const auto it = validators.find(vk.pubkey);
    const auto join_req = find_join_request_for_pubkey(reqs, vk.pubkey);
    const auto& net = finalis::mainnet_network();
    const std::uint64_t finalized_height = tip ? tip->height : 0;
    const auto runtime = db.get_node_runtime_status_snapshot();

    std::cout << "db=" << db_path << "\n";
    std::cout << "key_file=" << file_path << "\n";
    std::cout << "finalized_height=" << finalized_height << "\n";
    std::cout << "validator_pubkey=" << finalis::hex_encode(finalis::Bytes(vk.pubkey.begin(), vk.pubkey.end())) << "\n";
    std::cout << "validator_address=" << vk.address << "\n";
    if (it == validators.end()) {
      std::cout << "validator_registered=no\n";
      std::cout << "validator_status=NOT_REGISTERED\n";
    } else {
      const auto& info = it->second;
      std::cout << "validator_registered=yes\n";
      std::cout << "validator_status=" << validator_status_name(info.status) << "\n";
      std::cout << "bonded_amount=" << info.bonded_amount << "\n";
      std::cout << "has_bond=" << (info.has_bond ? "yes" : "no") << "\n";
      if (info.has_bond) std::cout << "bond_outpoint=" << format_outpoint(info.bond_outpoint) << "\n";
      std::cout << "joined_height=" << info.joined_height << "\n";
      std::cout << "last_join_height=" << info.last_join_height << "\n";
      std::cout << "last_exit_height=" << info.last_exit_height << "\n";
      std::cout << "penalty_strikes=" << info.penalty_strikes << "\n";
      if (info.status == finalis::consensus::ValidatorStatus::PENDING) {
        const std::uint64_t activation_height = info.joined_height + net.validator_warmup_blocks;
        const std::uint64_t remaining = activation_height > (finalized_height + 1) ? activation_height - (finalized_height + 1) : 0;
        std::cout << "activation_height=" << activation_height << "\n";
        std::cout << "warmup_blocks_remaining=" << remaining << "\n";
      }
      if (info.status == finalis::consensus::ValidatorStatus::SUSPENDED) {
        std::cout << "suspended_until_height=" << info.suspended_until_height << "\n";
      }
      if (info.status == finalis::consensus::ValidatorStatus::EXITING) {
        const std::uint64_t withdraw_height = info.unbond_height + net.unbond_delay_blocks;
        const std::uint64_t remaining = withdraw_height > (finalized_height + 1) ? withdraw_height - (finalized_height + 1) : 0;
        std::cout << "unbond_height=" << info.unbond_height << "\n";
        std::cout << "withdraw_height=" << withdraw_height << "\n";
        std::cout << "unbond_blocks_remaining=" << remaining << "\n";
      }
    }
    if (join_req.has_value()) {
      std::cout << "join_request_present=yes\n";
      std::cout << "join_request_txid=" << finalis::hex_encode32(join_req->request_txid) << "\n";
      std::cout << "join_request_bond_outpoint=" << format_outpoint(join_req->bond_outpoint) << "\n";
      std::cout << "join_request_bond_amount=" << join_req->bond_amount << "\n";
      std::cout << "join_request_requested_height=" << join_req->requested_height << "\n";
    } else {
      std::cout << "join_request_present=no\n";
    }
    if (runtime.has_value() && runtime->availability_local_operator_known) {
      std::cout << "local_operator_known=yes\n";
      std::cout << "local_operator_status="
                << availability_status_name_for_cli(static_cast<finalis::availability::AvailabilityOperatorStatus>(
                       runtime->availability_local_operator_status))
                << "\n";
      std::cout << "local_operator_warmup_epochs=" << runtime->availability_local_warmup_epochs << "\n";
      std::cout << "local_operator_service_score=" << runtime->availability_local_service_score << "\n";
    } else {
      std::cout << "local_operator_known=no\n";
    }
    std::cout << "spendable_utxos=" << spendable->count << "\n";
    std::cout << "spendable_balance=" << spendable->total << "\n";
    std::cout << "largest_spendable_utxo=" << spendable->largest << "\n";
    if (spendable->largest_outpoint.has_value()) {
      std::cout << "largest_spendable_outpoint=" << format_outpoint(*spendable->largest_outpoint) << "\n";
    }
    return 0;
  }

  if (cmd == "getBalance") {
    std::string db_path = default_mainnet_db_path();
    std::string file_path = default_mainnet_validator_key_path();
    std::string passphrase;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--db" && i + 1 < argc) db_path = argv[++i];
      else if (a == "--file" && i + 1 < argc) file_path = argv[++i];
      else if (a == "--pass" && i + 1 < argc) passphrase = argv[++i];
    }
    db_path = expand_user(db_path);
    file_path = expand_user(file_path);
    finalis::storage::DB db;
    if (!db.open_readonly(db_path) && !db.open(db_path)) {
      std::cerr << "failed to open db\n";
      return 1;
    }
    finalis::keystore::ValidatorKey vk;
    std::string err;
    if (!finalis::keystore::load_validator_keystore(file_path, passphrase, &vk, &err)) {
      std::cerr << "getBalance failed to load key: " << err << "\n";
      return 1;
    }
    std::string spendable_err;
    const auto spendable = spendable_for_wallet_address(db, vk.address, &spendable_err);
    if (!spendable.has_value()) {
      std::cerr << "getBalance failed to resolve wallet address: " << spendable_err << "\n";
      return 1;
    }
    std::cout << "db=" << db_path << "\n";
    std::cout << "key_file=" << file_path << "\n";
    std::cout << "address=" << vk.address << "\n";
    std::cout << "balance=" << spendable->total << "\n";
    std::cout << "spendable_utxos=" << spendable->count << "\n";
    return 0;
  }

  if (cmd == "economics_status") {
    std::string db_path = default_mainnet_db_path();
    std::string file_path = default_mainnet_validator_key_path();
    std::string passphrase;
    bool as_json = false;
    std::optional<std::uint64_t> inspect_height;
    std::optional<std::uint64_t> inspect_settlement_epoch_start;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--db" && i + 1 < argc) db_path = argv[++i];
      else if (a == "--file" && i + 1 < argc) file_path = argv[++i];
      else if (a == "--pass" && i + 1 < argc) passphrase = argv[++i];
      else if (a == "--json") as_json = true;
      else if (a == "--height" && i + 1 < argc) inspect_height = static_cast<std::uint64_t>(std::stoull(argv[++i]));
      else if (a == "--settlement-epoch-start" && i + 1 < argc) {
        inspect_settlement_epoch_start = static_cast<std::uint64_t>(std::stoull(argv[++i]));
      }
    }
    db_path = expand_user(db_path);
    file_path = expand_user(file_path);

    finalis::storage::DB db;
    if (!db.open_readonly(db_path) && !db.open(db_path)) {
      std::cerr << "failed to open db\n";
      return 1;
    }

    const auto& net = finalis::mainnet_network();
    const auto tip = db.get_tip();
    const auto validators = db.load_validators();
    const std::uint64_t finalized_height = tip ? tip->height : 0;
    if (inspect_height.has_value() && *inspect_height > finalized_height) {
      std::cerr << "--height exceeds finalized tip\n";
      return 1;
    }
    const std::uint64_t inspected_finalized_height = inspect_height.value_or(finalized_height);
    const std::uint64_t economics_height = inspected_finalized_height + 1;
    auto registry = build_registry_for_cli(net, validators, economics_height);
    const auto active_validators = registry.active_sorted(economics_height);
    const auto active_operator_count = active_operator_count_for_cli(registry, validators, economics_height);
    const auto& econ = finalis::active_economics_policy(net, economics_height);
    const auto min_bond = finalis::consensus::validator_min_bond_units(net, economics_height, active_operator_count);
    const auto max_effective_bond =
        finalis::consensus::validator_max_effective_bond_units(net, economics_height, active_operator_count);
    const auto current_epoch_start = finalis::consensus::committee_epoch_start(
        std::max<std::uint64_t>(1, inspected_finalized_height), net.committee_epoch_blocks);
    const auto current_epoch_state = db.get_epoch_reward_settlement(current_epoch_start);
    const auto settlement_epoch_start =
        inspect_settlement_epoch_start.has_value() ? inspect_settlement_epoch_start : settlement_epoch_start_for_height(net, economics_height);
    const auto settlement_epoch_state =
        settlement_epoch_start.has_value() ? db.get_epoch_reward_settlement(*settlement_epoch_start) : std::nullopt;
    const auto last_finalized_settlement_epoch_start = settlement_epoch_start;
    const auto last_finalized_settlement_epoch_state = settlement_epoch_state;

    if (!as_json) {
      std::cout << "db=" << db_path << "\n";
      std::cout << "finalized_height=" << finalized_height << "\n";
      std::cout << "inspected_finalized_height=" << inspected_finalized_height << "\n";
      std::cout << "economics_height=" << economics_height << "\n";
      std::cout << "ticket_policy=bounded_operator_search\n";
      std::cout << "economics_activation_height=" << econ.activation_height << "\n";
      std::cout << "target_validators=" << econ.target_validators << "\n";
      std::cout << "base_min_bond=" << econ.base_min_bond << "\n";
      std::cout << "min_bond_floor=" << econ.min_bond_floor << "\n";
      std::cout << "min_bond_ceiling=" << econ.min_bond_ceiling << "\n";
      std::cout << "max_effective_bond_multiple=" << econ.max_effective_bond_multiple << "\n";
      std::cout << "active_validators=" << active_validators.size() << "\n";
      std::cout << "active_operators=" << active_operator_count << "\n";
      std::cout << "min_bond=" << min_bond << "\n";
      std::cout << "max_effective_bond=" << max_effective_bond << "\n";
      std::cout << "participation_threshold_bps=" << econ.participation_threshold_bps << "\n";
      std::cout << "ticket_bonus_cap_bps=" << econ.ticket_bonus_cap_bps << "\n";
      std::cout << "current_epoch_start=" << current_epoch_start << "\n";
      if (settlement_epoch_start.has_value()) {
        std::cout << "settlement_epoch_start=" << *settlement_epoch_start << "\n";
      } else {
        std::cout << "settlement_epoch_start=none\n";
      }
    }

    finalis::keystore::ValidatorKey vk;
    std::string err;
    const bool have_local_validator = finalis::keystore::keystore_exists(file_path) &&
                                      finalis::keystore::load_validator_keystore(file_path, passphrase, &vk, &err);
    if (!have_local_validator) {
      if (as_json) {
        std::cout << "{"
                  << "\"db\":\"" << json_escape(db_path) << "\","
                  << "\"finalized_height\":" << finalized_height << ","
                  << "\"inspected_finalized_height\":" << inspected_finalized_height << ","
                  << "\"economics_height\":" << economics_height << ","
                  << "\"current_epoch_start\":" << current_epoch_start << ","
                  << "\"settlement_epoch_start\":"
                  << (settlement_epoch_start.has_value() ? std::to_string(*settlement_epoch_start) : "null") << ","
                  << "\"local_validator_present\":false"
                  << "}\n";
      }
      return 0;
    }

    const auto it = validators.find(vk.pubkey);
    const auto actual_bond = it != validators.end() ? it->second.bonded_amount : 0;
    const auto capped_bond =
        it != validators.end()
            ? finalis::consensus::capped_effective_bond_units(net, economics_height, active_operator_count, actual_bond)
            : 0;
    const auto effective_weight =
        it != validators.end()
            ? finalis::consensus::effective_weight(net, economics_height, active_operator_count, actual_bond)
            : 0;
    const auto reward_weight =
        it != validators.end()
            ? finalis::consensus::reward_weight(net, economics_height, active_operator_count, actual_bond)
            : 0;
    const auto current_expected = current_epoch_state && current_epoch_state->expected_participation_units.count(vk.pubkey)
                                      ? current_epoch_state->expected_participation_units.at(vk.pubkey)
                                      : 0;
    const auto current_observed = current_epoch_state && current_epoch_state->observed_participation_units.count(vk.pubkey)
                                      ? current_epoch_state->observed_participation_units.at(vk.pubkey)
                                      : 0;
    const auto current_participation_bps =
        current_expected == 0
            ? 10'000U
            : static_cast<std::uint32_t>(finalis::wide::mul_div_u64(std::min(current_observed, current_expected),
                                                                    10'000ULL, current_expected));
    const auto settlement_expected =
        settlement_epoch_state && settlement_epoch_state->expected_participation_units.count(vk.pubkey)
            ? settlement_epoch_state->expected_participation_units.at(vk.pubkey)
            : 0;
    const auto settlement_observed =
        settlement_epoch_state && settlement_epoch_state->observed_participation_units.count(vk.pubkey)
            ? settlement_epoch_state->observed_participation_units.at(vk.pubkey)
            : 0;
    const auto settlement_reward_score =
        settlement_epoch_state && settlement_epoch_state->reward_score_units.count(vk.pubkey)
            ? settlement_epoch_state->reward_score_units.at(vk.pubkey)
            : 0;
    const auto settlement_participation_bps =
        settlement_expected == 0
            ? 10'000U
            : static_cast<std::uint32_t>(finalis::wide::mul_div_u64(std::min(settlement_observed, settlement_expected),
                                                                    10'000ULL, settlement_expected));
    std::uint64_t settlement_reward_score_total = 0;
    if (settlement_epoch_state.has_value()) {
      for (const auto& [_, score] : settlement_epoch_state->reward_score_units) settlement_reward_score_total += score;
    }

    std::uint64_t local_theoretical_reward_units = 0;
    if (settlement_epoch_state.has_value() && settlement_reward_score_total != 0 && settlement_reward_score != 0) {
      local_theoretical_reward_units = finalis::wide::mul_div_u64(settlement_epoch_state->total_reward_units,
                                                                  settlement_reward_score,
                                                                  settlement_reward_score_total);
    }

    bool finalized_settlement_block_present = false;
    std::uint64_t finalized_settlement_height = 0;
    std::uint64_t finalized_settlement_fees_units = 0;
    std::uint64_t local_actual_reward_units = 0;
    bool payout_utxo_found = false;
    finalis::OutPoint payout_outpoint{};
    finalis::PubKey32 payout_leader_pubkey{};
    std::string settlement_reason = "no_settlement_due_at_current_height";

    const auto local_reward_pkh = finalis::crypto::h160(finalis::Bytes(vk.pubkey.begin(), vk.pubkey.end()));
    const auto local_reward_spk = finalis::address::p2pkh_script_pubkey(local_reward_pkh);

    if (last_finalized_settlement_epoch_start.has_value()) {
      finalized_settlement_height = *last_finalized_settlement_epoch_start + std::max<std::uint64_t>(1, net.committee_epoch_blocks);
      if (finalized_settlement_height > finalized_height) {
        finalized_settlement_height = 0;
      }
      auto transition_id = finalized_settlement_height != 0 ? db.get_frontier_transition_by_height(finalized_settlement_height)
                                                            : std::nullopt;
      auto transition_bytes = transition_id.has_value() ? db.get_frontier_transition(*transition_id) : std::nullopt;
      auto transition = transition_bytes.has_value() ? finalis::FrontierTransition::parse(*transition_bytes) : std::nullopt;
      if (transition.has_value()) {
        finalized_settlement_block_present = true;
        payout_leader_pubkey = transition->leader_pubkey;
        finalized_settlement_fees_units = transition->settlement.settled_epoch_fees;

        if (last_finalized_settlement_epoch_state.has_value()) {
          const auto payout = finalis::consensus::compute_epoch_settlement_payout(
              last_finalized_settlement_epoch_state->total_reward_units, finalized_settlement_fees_units,
              transition->settlement.reserve_subsidy_units, transition->leader_pubkey,
              last_finalized_settlement_epoch_state->reward_score_units,
              last_finalized_settlement_epoch_state->onboarding_score_units);
          for (const auto& [pub, units] : payout.outputs) {
            if (pub != vk.pubkey) continue;
            local_actual_reward_units = units;
            break;
          }
        }

        for (const auto& [pub, units] : transition->settlement.outputs) {
          if (pub != vk.pubkey) continue;
          payout_utxo_found = true;
          if (units > local_actual_reward_units) local_actual_reward_units = units;
          break;
        }
      }

      if (!last_finalized_settlement_epoch_state.has_value()) {
        settlement_reason = "settlement_epoch_state_missing";
      } else if (!finalized_settlement_block_present) {
        settlement_reason = "finalized_settlement_block_missing";
      } else if (last_finalized_settlement_epoch_state->total_reward_units == 0) {
        settlement_reason = "zero_settlement_reward_units";
      } else {
        std::uint64_t last_settlement_reward_score = 0;
        for (const auto& [pub, score] : last_finalized_settlement_epoch_state->reward_score_units) {
          if (pub == vk.pubkey) last_settlement_reward_score = score;
        }
        if (last_settlement_reward_score == 0) {
          settlement_reason = "zero_reward_score";
        } else if (local_actual_reward_units == 0 && !payout_utxo_found) {
          settlement_reason = "no_matching_payout_output";
        } else {
          settlement_reason = "payout_utxo_present";
        }
      }
    }

    if (as_json) {
      std::cout << "{"
                << "\"db\":\"" << json_escape(db_path) << "\","
                << "\"finalized_height\":" << finalized_height << ","
                << "\"inspected_finalized_height\":" << inspected_finalized_height << ","
                << "\"economics_height\":" << economics_height << ","
                << "\"ticket_policy\":\"bounded_operator_search\","
                << "\"economics_activation_height\":" << econ.activation_height << ","
                << "\"target_validators\":" << econ.target_validators << ","
                << "\"base_min_bond\":" << econ.base_min_bond << ","
                << "\"min_bond_floor\":" << econ.min_bond_floor << ","
                << "\"min_bond_ceiling\":" << econ.min_bond_ceiling << ","
                << "\"max_effective_bond_multiple\":" << econ.max_effective_bond_multiple << ","
                << "\"active_validators\":" << active_validators.size() << ","
                << "\"active_operators\":" << active_operator_count << ","
                << "\"min_bond\":" << min_bond << ","
                << "\"max_effective_bond\":" << max_effective_bond << ","
                << "\"participation_threshold_bps\":" << econ.participation_threshold_bps << ","
                << "\"ticket_bonus_cap_bps\":" << econ.ticket_bonus_cap_bps << ","
                << "\"current_epoch_start\":" << current_epoch_start << ","
                << "\"settlement_epoch_start\":"
                << (settlement_epoch_start.has_value() ? std::to_string(*settlement_epoch_start) : "null") << ","
                << "\"last_finalized_settlement_epoch_start\":"
                << (last_finalized_settlement_epoch_start.has_value() ? std::to_string(*last_finalized_settlement_epoch_start) : "null")
                << ","
                << "\"local_validator_present\":true,"
                << "\"local_validator_pubkey\":\"" << finalis::hex_encode(finalis::Bytes(vk.pubkey.begin(), vk.pubkey.end())) << "\","
                << "\"local_validator_address\":\"" << json_escape(vk.address) << "\","
                << "\"local_validator_registered\":" << (it != validators.end() ? "true" : "false");
      if (it != validators.end()) {
        std::cout << ",\"local_validator_status\":\"" << validator_status_name(it->second.status) << "\""
                  << ",\"local_validator_actual_bond\":" << actual_bond
                  << ",\"local_validator_capped_effective_bond\":" << capped_bond
                  << ",\"local_validator_effective_weight\":" << effective_weight
                  << ",\"local_validator_reward_weight\":" << reward_weight
                  << ",\"local_validator_current_expected_participation\":" << current_expected
                  << ",\"local_validator_current_observed_participation\":" << current_observed
                  << ",\"local_validator_current_participation_bps\":" << current_participation_bps
                  << ",\"local_validator_settlement_expected_participation\":" << settlement_expected
                  << ",\"local_validator_settlement_observed_participation\":" << settlement_observed
                  << ",\"local_validator_settlement_participation_bps\":" << settlement_participation_bps
                  << ",\"local_validator_settlement_reward_score\":" << settlement_reward_score
                  << ",\"settlement_epoch_reward_score_total\":" << settlement_reward_score_total
                  << ",\"local_validator_settlement_theoretical_reward_units\":" << local_theoretical_reward_units
                  << ",\"local_validator_settlement_actual_reward_units\":" << local_actual_reward_units
                  << ",\"finalized_settlement_block_present\":" << (finalized_settlement_block_present ? "true" : "false")
                  << ",\"finalized_settlement_height\":" << finalized_settlement_height
                  << ",\"finalized_settlement_fees_units\":" << finalized_settlement_fees_units
                  << ",\"payout_utxo_found\":" << (payout_utxo_found ? "true" : "false");
        if (payout_utxo_found) {
          std::cout << ",\"payout_outpoint\":\"" << finalis::hex_encode32(payout_outpoint.txid) << ":" << payout_outpoint.index << "\"";
        } else {
          std::cout << ",\"payout_outpoint\":null";
        }
        if (settlement_epoch_state.has_value()) {
          std::cout << ",\"settlement_epoch_total_reward_units\":" << settlement_epoch_state->total_reward_units
                    << ",\"settlement_epoch_settled\":" << (settlement_epoch_state->settled ? "true" : "false");
        } else {
          std::cout << ",\"settlement_epoch_total_reward_units\":null"
                    << ",\"settlement_epoch_settled\":null";
        }
        std::cout << ",\"local_validator_settlement_reason\":\"" << json_escape(settlement_reason) << "\"";
      }
      std::cout << "}\n";
      return 0;
    }

    std::cout << "local_validator_pubkey="
              << finalis::hex_encode(finalis::Bytes(vk.pubkey.begin(), vk.pubkey.end())) << "\n";
    std::cout << "local_validator_address=" << vk.address << "\n";
    if (it == validators.end()) {
      std::cout << "local_validator_registered=no\n";
      return 0;
    }

    std::cout << "local_validator_registered=yes\n";
    std::cout << "local_validator_status=" << validator_status_name(it->second.status) << "\n";
    std::cout << "local_validator_actual_bond=" << actual_bond << "\n";
    std::cout << "local_validator_capped_effective_bond=" << capped_bond << "\n";
    std::cout << "local_validator_effective_weight=" << effective_weight << "\n";
    std::cout << "local_validator_reward_weight=" << reward_weight << "\n";
    std::cout << "local_validator_current_expected_participation=" << current_expected << "\n";
    std::cout << "local_validator_current_observed_participation=" << current_observed << "\n";
    std::cout << "local_validator_current_participation_bps=" << current_participation_bps << "\n";
    std::cout << "local_validator_settlement_expected_participation=" << settlement_expected << "\n";
    std::cout << "local_validator_settlement_observed_participation=" << settlement_observed << "\n";
    std::cout << "local_validator_settlement_participation_bps=" << settlement_participation_bps << "\n";
    std::cout << "local_validator_settlement_reward_score=" << settlement_reward_score << "\n";
    std::cout << "settlement_epoch_reward_score_total=" << settlement_reward_score_total << "\n";
    std::cout << "local_validator_settlement_theoretical_reward_units=" << local_theoretical_reward_units << "\n";
    std::cout << "local_validator_settlement_actual_reward_units=" << local_actual_reward_units << "\n";
    std::cout << "finalized_settlement_block_present=" << (finalized_settlement_block_present ? "yes" : "no") << "\n";
    std::cout << "finalized_settlement_height=" << finalized_settlement_height << "\n";
    std::cout << "finalized_settlement_fees_units=" << finalized_settlement_fees_units << "\n";
    std::cout << "payout_utxo_found=" << (payout_utxo_found ? "yes" : "no") << "\n";
    if (payout_utxo_found) {
      std::cout << "payout_outpoint=" << format_outpoint(payout_outpoint) << "\n";
    }
    if (settlement_epoch_state.has_value()) {
      std::cout << "settlement_epoch_total_reward_units=" << settlement_epoch_state->total_reward_units << "\n";
      std::cout << "settlement_epoch_settled=" << (settlement_epoch_state->settled ? "yes" : "no") << "\n";
    }
    std::cout << "local_validator_settlement_reason=" << settlement_reason << "\n";
    return 0;
  }

  if (cmd == "validator-register" || cmd == "validator-register-status" || cmd == "validator-register-cancel") {
    std::string db_path = default_mainnet_db_path();
    std::string file_path = default_mainnet_validator_key_path();
    std::string passphrase;
    std::string rpc_url = "http://127.0.0.1:19444/rpc";
    std::uint64_t fee = 10'000;
    bool wait_for_sync = true;
    bool watch = true;
    bool as_json = false;
    std::uint64_t timeout_seconds = 600;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--db" && i + 1 < argc) db_path = argv[++i];
      else if (a == "--file" && i + 1 < argc) file_path = argv[++i];
      else if (a == "--pass" && i + 1 < argc) passphrase = argv[++i];
      else if (a == "--rpc" && i + 1 < argc) rpc_url = argv[++i];
      else if (a == "--fee" && i + 1 < argc) fee = static_cast<std::uint64_t>(std::stoull(argv[++i]));
      else if (a == "--wait-for-sync") wait_for_sync = true;
      else if (a == "--no-wait-for-sync") wait_for_sync = false;
      else if (a == "--watch") watch = true;
      else if (a == "--no-watch") watch = false;
      else if (a == "--json") as_json = true;
      else if (a == "--timeout-seconds" && i + 1 < argc) timeout_seconds = static_cast<std::uint64_t>(std::stoull(argv[++i]));
      else if (a == "--resume") {
      }
    }
    db_path = expand_user(db_path);
    file_path = expand_user(file_path);
    finalis::onboarding::ValidatorOnboardingOptions options{
        .db_path = db_path,
        .key_file = file_path,
        .passphrase = passphrase,
        .rpc_url = rpc_url,
        .fee = fee,
        .wait_for_sync = wait_for_sync,
    };
    finalis::onboarding::ValidatorOnboardingService service;
    std::string err;
    if (cmd == "validator-register-status") {
      auto record = rpc_onboarding_status_with_local_tracking(rpc_url, options, &err);
      if (!record) {
        std::string local_err;
        record = service.status(options, &local_err);
        if (!record) {
          std::cerr << "validator-register-status failed: "
                    << (err.empty() ? local_err : ("rpc status failed: " + err + "; local status failed: " + local_err)) << "\n";
          return 1;
        }
      }
      print_onboarding_record(*record, as_json);
      return 0;
    }
    if (cmd == "validator-register-cancel") {
      if (!service.cancel(options, &err)) {
        if (db_lock_error(err)) {
          std::string status_err;
          auto local_status = service.status(options, &status_err);
          if (local_status) {
            print_onboarding_record(*local_status, as_json);
            const bool pre_broadcast_cancel =
                finalis::onboarding::validator_onboarding_state_pre_broadcast(local_status->state) ||
                (local_status->state == finalis::onboarding::ValidatorOnboardingState::BROADCASTING_JOIN_TX &&
                 local_status->broadcast_outcome == finalis::onboarding::ValidatorOnboardingBroadcastOutcome::NONE);
            if (pre_broadcast_cancel) {
              std::cerr
                  << "validator-register-cancel requires exclusive local DB access to release reserved inputs or cancel the pre-broadcast attempt. "
                  << "Stop finalis-node and rerun this command.\n";
            } else {
              std::cerr
                  << "validator-register-cancel could not detach local tracking while finalis-node owns the DB. "
                  << "The join attempt is already post-broadcast or on-chain tracked; use validator-register-status to monitor it, or stop finalis-node and rerun this command if you explicitly want to detach local tracking.\n";
            }
            return 1;
          }
          auto rpc_status = rpc_onboarding_status_with_local_tracking(rpc_url, options, &status_err);
          if (rpc_status) {
            print_onboarding_record(*rpc_status, as_json);
            std::cerr
                << "validator-register-cancel could not detach local tracking while finalis-node owns the DB. "
                << "Stop finalis-node and rerun this command if you need to detach the local record.\n";
            return 1;
          }
        }
        std::cerr << "validator-register-cancel failed: " << err << "\n";
        return 1;
      }
      auto record = service.status(options, &err);
      if (!record) {
        std::cerr << "validator-register-cancel status failed: " << err << "\n";
        return 1;
      }
      print_onboarding_record(*record, as_json);
      if (record->state == finalis::onboarding::ValidatorOnboardingState::CANCELLED) {
        std::cerr << "validator-register-cancel: pre-broadcast attempt cancelled.\n";
      } else if (record->tracking_detached) {
        std::cerr << "validator-register-cancel: local tracking detached for a post-broadcast attempt.\n";
      }
      return 0;
    }

    bool using_rpc = true;
    auto record = finalis::lightserver::rpc_validator_onboarding_start(rpc_url, options, &err);
    if (!record) {
      std::string local_err;
      record = service.start_or_resume(options, &local_err);
      using_rpc = false;
      if (!record) {
        std::cerr << "validator-register failed: "
                  << (err.empty() ? local_err : ("rpc start failed: " + err + "; local start failed: " + local_err)) << "\n";
        return 1;
      }
    }
    print_onboarding_record(*record, as_json);
    if (!watch || finalis::onboarding::validator_onboarding_state_terminal(record->state)) return 0;

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(timeout_seconds);
    std::string last_state = finalis::onboarding::validator_onboarding_state_name(record->state);
    std::string tracked_txid = record->txid_hex;
    while (std::chrono::steady_clock::now() < deadline) {
      std::this_thread::sleep_for(std::chrono::seconds(1));
      std::optional<finalis::onboarding::ValidatorOnboardingRecord> updated;
      if (using_rpc) {
        updated = finalis::lightserver::rpc_validator_onboarding_status(rpc_url, options, tracked_txid, &err);
      } else {
        updated = service.poll(options, &err);
      }
      if (!updated) {
        std::cerr << "validator-register watch failed: " << err << "\n";
        return 1;
      }
      const auto current_state = finalis::onboarding::validator_onboarding_state_name(updated->state);
      const bool changed = current_state != last_state || updated->txid_hex != record->txid_hex ||
                           updated->validator_status != record->validator_status ||
                           updated->last_error_code != record->last_error_code ||
                           updated->readiness.registration_ready != record->readiness.registration_ready ||
                           updated->last_spendable_balance != record->last_spendable_balance;
      if (changed) {
        print_onboarding_record(*updated, as_json);
        last_state = current_state;
      }
      if (!updated->txid_hex.empty()) tracked_txid = updated->txid_hex;
      record = updated;
      if (finalis::onboarding::validator_onboarding_state_terminal(updated->state)) return 0;
      if (updated->state == finalis::onboarding::ValidatorOnboardingState::WAITING_FOR_FUNDS ||
          updated->state == finalis::onboarding::ValidatorOnboardingState::WAITING_FOR_SYNC ||
          updated->state == finalis::onboarding::ValidatorOnboardingState::WAITING_FOR_FINALIZATION ||
          updated->state == finalis::onboarding::ValidatorOnboardingState::PENDING_ACTIVATION) {
        continue;
      }
    }
    return 0;
  }

  if (cmd == "getUTXO") {
    std::string db_path = default_mainnet_db_path();
    std::string file_path = default_mainnet_validator_key_path();
    std::string passphrase;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--db" && i + 1 < argc) db_path = argv[++i];
      else if (a == "--file" && i + 1 < argc) file_path = argv[++i];
      else if (a == "--pass" && i + 1 < argc) passphrase = argv[++i];
    }
    db_path = expand_user(db_path);
    file_path = expand_user(file_path);
    finalis::storage::DB db;
    if (!db.open_readonly(db_path) && !db.open(db_path)) {
      std::cerr << "failed to open db\n";
      return 1;
    }
    finalis::keystore::ValidatorKey vk;
    std::string err;
    if (!finalis::keystore::load_validator_keystore(file_path, passphrase, &vk, &err)) {
      std::cerr << "getUTXO failed to load key: " << err << "\n";
      return 1;
    }
    std::string spendable_err;
    const auto utxos = positive_value_utxos(spendable_utxos_for_wallet_address(db, vk.address, &spendable_err));
    if (!spendable_err.empty()) {
      std::cerr << "getUTXO failed to resolve wallet address: " << spendable_err << "\n";
      return 1;
    }
    std::uint64_t total = 0;
    std::cout << "db=" << db_path << "\n";
    std::cout << "key_file=" << file_path << "\n";
    std::cout << "address=" << vk.address << "\n";
    std::cout << "utxo_count=" << utxos.size() << "\n";
    for (std::size_t i = 0; i < utxos.size(); ++i) {
      total += utxos[i].second.value;
      std::cout << "utxo[" << i << "].outpoint=" << format_outpoint(utxos[i].first) << "\n";
      std::cout << "utxo[" << i << "].value=" << utxos[i].second.value << "\n";
    }
    std::cout << "balance=" << total << "\n";
    return 0;
  }

  if (cmd == "send") {
    std::string db_path = default_mainnet_db_path();
    std::string file_path = default_mainnet_validator_key_path();
    std::string passphrase;
    std::string rpc_url = "http://127.0.0.1:19444/rpc";
    std::string to_addr;
    std::string amount_text;
    std::uint64_t amount_units = 0;
    std::uint64_t fee = finalis::DEFAULT_WALLET_SEND_FEE_UNITS;
    bool amount_units_set = false;
    bool send_max = false;

    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--db" && i + 1 < argc) db_path = argv[++i];
      else if (a == "--file" && i + 1 < argc) file_path = argv[++i];
      else if (a == "--pass" && i + 1 < argc) passphrase = argv[++i];
      else if (a == "--rpc" && i + 1 < argc) rpc_url = argv[++i];
      else if (a == "--to" && i + 1 < argc) to_addr = argv[++i];
      else if (a == "--amount" && i + 1 < argc) amount_text = argv[++i];
      else if (a == "--amount-units" && i + 1 < argc) {
        amount_units = static_cast<std::uint64_t>(std::stoull(argv[++i]));
        amount_units_set = true;
      } else if (a == "--fee" && i + 1 < argc) {
        fee = static_cast<std::uint64_t>(std::stoull(argv[++i]));
      } else if (a == "--max") {
        send_max = true;
      }
    }

    if (to_addr.empty()) {
      std::cerr << "--to is required\n";
      return 1;
    }
    if (!finalis::address::decode(to_addr).has_value()) {
      std::cerr << "invalid --to address\n";
      return 1;
    }
    const int amount_modes = (!amount_text.empty() ? 1 : 0) + (amount_units_set ? 1 : 0) + (send_max ? 1 : 0);
    if (amount_modes != 1) {
      std::cerr << "choose exactly one of --amount, --amount-units, or --max\n";
      return 1;
    }
    if (!amount_text.empty()) {
      auto parsed = parse_coin_amount_text(amount_text);
      if (!parsed.has_value()) {
        std::cerr << "invalid --amount (use whole coins or up to 8 decimals)\n";
        return 1;
      }
      amount_units = *parsed;
    }
    if (!send_max && amount_units == 0) {
      std::cerr << "amount must be positive\n";
      return 1;
    }

    db_path = expand_user(db_path);
    file_path = expand_user(file_path);
    finalis::storage::DB db;
    if (!db.open_readonly(db_path) && !db.open(db_path)) {
      std::cerr << "failed to open db\n";
      return 1;
    }
    finalis::keystore::ValidatorKey vk;
    std::string err;
    if (!finalis::keystore::load_validator_keystore(file_path, passphrase, &vk, &err)) {
      std::cerr << "send failed to load key: " << err << "\n";
      return 1;
    }

    std::string utxo_err;
    const auto available_prevs =
        positive_value_utxos(spendable_utxos_for_wallet_address(db, vk.address, &utxo_err));
    if (!utxo_err.empty()) {
      std::cerr << "send failed to resolve wallet address: " << utxo_err << "\n";
      return 1;
    }
    if (available_prevs.empty()) {
      std::cerr << "send failed: no spendable finalized inputs are currently available\n";
      return 1;
    }

    auto decoded_to = finalis::address::decode(to_addr);
    auto own_decoded = finalis::address::decode(vk.address);
    if (!decoded_to.has_value() || !own_decoded.has_value()) {
      std::cerr << "send failed: invalid wallet or recipient address\n";
      return 1;
    }

    std::uint64_t total_available = 0;
    for (const auto& [_, prevout] : available_prevs) total_available += prevout.value;
    if (send_max) {
      if (total_available <= fee) {
        std::cerr << "send failed: available finalized balance is too small to cover fee\n";
        return 1;
      }
      amount_units = total_available - fee;
    }

    auto plan = finalis::plan_wallet_p2pkh_send(
        available_prevs, finalis::address::p2pkh_script_pubkey(decoded_to->pubkey_hash),
        finalis::address::p2pkh_script_pubkey(own_decoded->pubkey_hash), amount_units, fee,
        finalis::DEFAULT_WALLET_DUST_THRESHOLD_UNITS, &err);
    if (!plan.has_value()) {
      std::cerr << "send planning failed: " << err << "\n";
      return 1;
    }

    auto tx = finalis::build_signed_p2pkh_tx_multi_input(
        plan->selected_prevs, finalis::Bytes(vk.privkey.begin(), vk.privkey.end()), plan->outputs, &err);
    if (!tx.has_value()) {
      std::cerr << "send build failed: " << err << "\n";
      return 1;
    }

    auto result = finalis::lightserver::rpc_broadcast_tx(rpc_url, tx->serialize(), &err);
    std::cout << "db=" << db_path << "\n";
    std::cout << "key_file=" << file_path << "\n";
    std::cout << "address=" << vk.address << "\n";
    std::cout << "recipient=" << to_addr << "\n";
    std::cout << "amount=" << amount_units << "\n";
    std::cout << "fee=" << plan->applied_fee_units << "\n";
    std::cout << "change=" << plan->change_units << "\n";
    std::cout << "inputs_selected=" << plan->selected_prevs.size() << "\n";
    std::cout << "rpc_url=" << rpc_url << "\n";
    std::cout << "txid=" << finalis::hex_encode32(tx->txid()) << "\n";

    if (!err.empty() && result.outcome == finalis::lightserver::BroadcastOutcome::Ambiguous) {
      std::cout << "accepted=unknown\n";
      std::cout << "error_message=" << err << "\n";
      return 1;
    }
    if (result.outcome != finalis::lightserver::BroadcastOutcome::Sent) {
      std::cout << "accepted=no\n";
      if (!result.error_code.empty()) std::cout << "error_code=" << result.error_code << "\n";
      if (!result.error_message.empty()) std::cout << "error_message=" << result.error_message << "\n";
      else if (!result.error.empty()) std::cout << "error_message=" << result.error << "\n";
      std::cout << "retryable=" << (result.retryable ? "yes" : "no") << "\n";
      std::cout << "retry_class=" << result.retry_class << "\n";
      return 1;
    }

    std::cout << "accepted=yes\n";
    std::cout << "status=accepted_for_relay\n";
    return 0;
  }

  if (cmd == "onboarding-register") {
    std::string db_path = default_mainnet_db_path();
    std::string file_path = default_mainnet_validator_key_path();
    std::string validator_file_path;
    std::string passphrase;
    std::string rpc_url = "http://127.0.0.1:19444/rpc";
    std::uint64_t fee = finalis::DEFAULT_WALLET_SEND_FEE_UNITS;

    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--db" && i + 1 < argc) db_path = argv[++i];
      else if (a == "--file" && i + 1 < argc) file_path = argv[++i];
      else if (a == "--validator-file" && i + 1 < argc) validator_file_path = argv[++i];
      else if (a == "--pass" && i + 1 < argc) passphrase = argv[++i];
      else if (a == "--rpc" && i + 1 < argc) rpc_url = argv[++i];
      else if (a == "--fee" && i + 1 < argc) fee = static_cast<std::uint64_t>(std::stoull(argv[++i]));
    }

    db_path = expand_user(db_path);
    file_path = expand_user(file_path);
    if (validator_file_path.empty()) validator_file_path = file_path;
    validator_file_path = expand_user(validator_file_path);

    finalis::storage::DB db;
    if (!db.open_readonly(db_path) && !db.open(db_path)) {
      std::cerr << "failed to open db\n";
      return 1;
    }

    finalis::keystore::ValidatorKey funding_key;
    std::string err;
    if (!finalis::keystore::load_validator_keystore(file_path, passphrase, &funding_key, &err)) {
      std::cerr << "onboarding-register failed to load funding key: " << err << "\n";
      return 1;
    }

    finalis::keystore::ValidatorKey validator_key;
    if (!finalis::keystore::load_validator_keystore(validator_file_path, passphrase, &validator_key, &err)) {
      std::cerr << "onboarding-register failed to load validator key: " << err << "\n";
      return 1;
    }
    if (funding_key.network_name != validator_key.network_name) {
      std::cerr << "onboarding-register failed: funding wallet targets " << funding_key.network_name
                << " but validator key targets " << validator_key.network_name << "\n";
      return 1;
    }
    const auto& network = finalis::network_by_name(funding_key.network_name);
    const auto chain_id = finalis::ChainId::from_config_and_db(network, db);
    std::string status_err;
    const auto status = finalis::lightserver::rpc_get_status(rpc_url, &status_err);
    if (!status.has_value()) {
      std::cerr << "onboarding-register failed to load rpc status: "
                << (status_err.empty() ? "rpc status unavailable" : status_err) << "\n";
      return 1;
    }
    finalis::ValidatorJoinAdmissionPowBuildContext pow_ctx{
        .network = &network,
        .chain_id = &chain_id,
        .current_height = status->tip_height + 1,
        .finalized_hash_at_height = [&db](std::uint64_t anchor_height) -> std::optional<finalis::Hash32> {
          return db.get_height_hash(anchor_height);
        },
    };

    std::string utxo_err;
    const auto available_prevs =
        positive_value_utxos(spendable_utxos_for_wallet_address(db, funding_key.address, &utxo_err));
    if (!utxo_err.empty()) {
      std::cerr << "onboarding-register failed to resolve funding wallet address: " << utxo_err << "\n";
      return 1;
    }
    if (available_prevs.empty()) {
      std::cerr << "onboarding-register failed: no spendable finalized inputs are currently available\n";
      return 1;
    }

    const auto ordered_prevs = finalis::deterministic_largest_first_prevs(available_prevs);
    std::vector<std::pair<finalis::OutPoint, finalis::TxOut>> selected_prevs;
    std::uint64_t selected_units = 0;
    for (const auto& prev : ordered_prevs) {
      selected_prevs.push_back(prev);
      selected_units += prev.second.value;
      if (selected_units >= fee) break;
    }
    if (selected_units < fee) {
      std::cerr << "onboarding-register failed: available finalized balance is too small to cover fee\n";
      return 1;
    }

    auto own_decoded = finalis::address::decode(funding_key.address);
    if (!own_decoded.has_value()) {
      std::cerr << "onboarding-register failed: invalid funding wallet address\n";
      return 1;
    }

    auto tx = finalis::build_onboarding_registration_tx(
        selected_prevs, finalis::Bytes(funding_key.privkey.begin(), funding_key.privkey.end()),
        validator_key.pubkey, finalis::Bytes(validator_key.privkey.begin(), validator_key.privkey.end()),
        funding_key.pubkey, fee, finalis::address::p2pkh_script_pubkey(own_decoded->pubkey_hash), &err, &pow_ctx);
    if (!tx.has_value()) {
      std::cerr << "onboarding-register build failed: " << err << "\n";
      return 1;
    }

    const std::uint64_t change_units = selected_units - fee;
    auto result = finalis::lightserver::rpc_broadcast_tx(rpc_url, tx->serialize(), &err);
    std::cout << "db=" << db_path << "\n";
    std::cout << "funding_key_file=" << file_path << "\n";
    std::cout << "validator_key_file=" << validator_file_path << "\n";
    std::cout << "funding_address=" << funding_key.address << "\n";
    std::cout << "validator_address=" << validator_key.address << "\n";
    std::cout << "payout_address=" << funding_key.address << "\n";
    std::cout << "fee=" << fee << "\n";
    std::cout << "change=" << change_units << "\n";
    std::cout << "inputs_selected=" << selected_prevs.size() << "\n";
    std::cout << "rpc_url=" << rpc_url << "\n";
    std::cout << "txid=" << finalis::hex_encode32(tx->txid()) << "\n";

    if (!err.empty() && result.outcome == finalis::lightserver::BroadcastOutcome::Ambiguous) {
      std::cout << "accepted=unknown\n";
      std::cout << "error_message=" << err << "\n";
      return 1;
    }
    if (result.outcome != finalis::lightserver::BroadcastOutcome::Sent) {
      std::cout << "accepted=no\n";
      if (!result.error_code.empty()) std::cout << "error_code=" << result.error_code << "\n";
      if (!result.error_message.empty()) std::cout << "error_message=" << result.error_message << "\n";
      else if (!result.error.empty()) std::cout << "error_message=" << result.error << "\n";
      std::cout << "retryable=" << (result.retryable ? "yes" : "no") << "\n";
      std::cout << "retry_class=" << result.retry_class << "\n";
      return 1;
    }

    std::cout << "accepted=yes\n";
    std::cout << "status=accepted_for_relay\n";
    return 0;
  }

  if (cmd == "wallet_import") {
    std::string out_path;
    std::string passphrase;
    std::string network_name = "mainnet";
    std::string privkey_hex;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--out" && i + 1 < argc) out_path = argv[++i];
      else if (a == "--pass" && i + 1 < argc) passphrase = argv[++i];
      else if (a == "--network" && i + 1 < argc) network_name = argv[++i];
      else if (a == "--privkey" && i + 1 < argc) privkey_hex = argv[++i];
    }
    auto priv = decode_hex32(privkey_hex);
    if (out_path.empty() || !priv) {
      std::cerr << "--out and --privkey(32-byte hex) are required\n";
      return 1;
    }
    if (network_name != "mainnet") {
      std::cerr << "only --network mainnet is supported\n";
      return 1;
    }
    finalis::keystore::ValidatorKey vk;
    std::string err;
    const std::optional<std::array<std::uint8_t, 32>> seed_override = *priv;
    if (!finalis::keystore::create_validator_keystore(out_path, passphrase, network_name,
                                                        finalis::keystore::hrp_for_network(network_name),
                                                        seed_override, &vk, &err)) {
      std::cerr << "wallet_import failed: " << err << "\n";
      return 1;
    }
    std::cout << "file=" << out_path << "\n";
    std::cout << "network=" << vk.network_name << "\n";
    std::cout << "pubkey_hex=" << finalis::hex_encode(finalis::Bytes(vk.pubkey.begin(), vk.pubkey.end())) << "\n";
    std::cout << "address=" << vk.address << "\n";
    return 0;
  }

  if (cmd == "address_from_pubkey" || cmd == "addr") {
    std::string hrp = "sc";
    std::string pub_hex;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--hrp" && i + 1 < argc) hrp = argv[++i];
      if (a == "--pubkey" && i + 1 < argc) pub_hex = argv[++i];
    }
    if (pub_hex.empty()) {
      std::cerr << "--pubkey is required\n";
      return 1;
    }

    auto b = finalis::hex_decode(pub_hex);
    if (!b || b->size() != 32) {
      std::cerr << "pubkey must be 32 bytes hex\n";
      return 1;
    }
    auto pkh = finalis::crypto::h160(*b);
    auto addr = finalis::address::encode_p2pkh(hrp, pkh);
    if (!addr) {
      std::cerr << "address encoding failed\n";
      return 1;
    }
    std::cout << *addr << "\n";
    return 0;
  }

  if (cmd == "build_p2pkh_tx") {
    std::string prev_txid_hex;
    std::uint32_t prev_index = 0;
    std::uint64_t prev_value = 0;
    std::string from_priv_hex;
    std::string to_addr;
    std::string change_addr;
    std::uint64_t amount = 0;
    std::uint64_t fee = 0;

    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--prev-txid" && i + 1 < argc) prev_txid_hex = argv[++i];
      else if (a == "--prev-index" && i + 1 < argc) prev_index = static_cast<std::uint32_t>(std::stoul(argv[++i]));
      else if (a == "--prev-value" && i + 1 < argc) prev_value = static_cast<std::uint64_t>(std::stoull(argv[++i]));
      else if (a == "--from-privkey" && i + 1 < argc) from_priv_hex = argv[++i];
      else if (a == "--to-address" && i + 1 < argc) to_addr = argv[++i];
      else if (a == "--change-address" && i + 1 < argc) change_addr = argv[++i];
      else if (a == "--amount" && i + 1 < argc) amount = static_cast<std::uint64_t>(std::stoull(argv[++i]));
      else if (a == "--fee" && i + 1 < argc) fee = static_cast<std::uint64_t>(std::stoull(argv[++i]));
    }

    auto prev_txid = decode_hex32(prev_txid_hex);
    auto priv = decode_hex32(from_priv_hex);
    auto to = finalis::address::decode(to_addr);
    if (!prev_txid.has_value() || !priv.has_value() || !to.has_value()) {
      std::cerr << "invalid required args\n";
      return 1;
    }
    if (prev_value < amount + fee) {
      std::cerr << "insufficient prev output value\n";
      return 1;
    }

    finalis::OutPoint op{*prev_txid, prev_index};

    auto kp = finalis::crypto::keypair_from_seed32(*priv);
    if (!kp.has_value()) {
      std::cerr << "invalid private key\n";
      return 1;
    }
    auto from_pkh = finalis::crypto::h160(finalis::Bytes(kp->public_key.begin(), kp->public_key.end()));
    finalis::TxOut prev_out{prev_value, finalis::address::p2pkh_script_pubkey(from_pkh)};

    std::vector<finalis::TxOut> outputs;
    outputs.push_back(finalis::TxOut{amount, finalis::address::p2pkh_script_pubkey(to->pubkey_hash)});

    const std::uint64_t change = prev_value - amount - fee;
    if (change > 0) {
      if (!change_addr.empty()) {
        auto ch = finalis::address::decode(change_addr);
        if (!ch.has_value()) {
          std::cerr << "invalid --change-address\n";
          return 1;
        }
        outputs.push_back(finalis::TxOut{change, finalis::address::p2pkh_script_pubkey(ch->pubkey_hash)});
      } else {
        outputs.push_back(finalis::TxOut{change, finalis::address::p2pkh_script_pubkey(from_pkh)});
      }
    }

    std::string err;
    auto tx = finalis::build_signed_p2pkh_tx_single_input(op, prev_out, finalis::Bytes(priv->begin(), priv->end()), outputs, &err);
    if (!tx.has_value()) {
      std::cerr << "build tx failed: " << err << "\n";
      return 1;
    }

    std::cout << "txid=" << finalis::hex_encode32(tx->txid()) << "\n";
    std::cout << "tx_hex=" << finalis::hex_encode(tx->serialize()) << "\n";
    return 0;
  }

  if (cmd == "build_p2pkh_multi_tx") {
    std::vector<std::string> prev_txid_hexes;
    std::vector<std::uint32_t> prev_indexes;
    std::vector<std::uint64_t> prev_values;
    std::string from_priv_hex;
    std::string to_addr;
    std::string change_addr;
    std::uint64_t amount = 0;
    std::uint64_t fee = 0;

    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--prev-txid" && i + 1 < argc) prev_txid_hexes.push_back(argv[++i]);
      else if (a == "--prev-index" && i + 1 < argc) prev_indexes.push_back(static_cast<std::uint32_t>(std::stoul(argv[++i])));
      else if (a == "--prev-value" && i + 1 < argc) prev_values.push_back(static_cast<std::uint64_t>(std::stoull(argv[++i])));
      else if (a == "--from-privkey" && i + 1 < argc) from_priv_hex = argv[++i];
      else if (a == "--to-address" && i + 1 < argc) to_addr = argv[++i];
      else if (a == "--change-address" && i + 1 < argc) change_addr = argv[++i];
      else if (a == "--amount" && i + 1 < argc) amount = static_cast<std::uint64_t>(std::stoull(argv[++i]));
      else if (a == "--fee" && i + 1 < argc) fee = static_cast<std::uint64_t>(std::stoull(argv[++i]));
    }

    if (prev_txid_hexes.empty() || prev_txid_hexes.size() != prev_indexes.size() || prev_txid_hexes.size() != prev_values.size()) {
      std::cerr << "prev inputs must provide matching --prev-txid/--prev-index/--prev-value groups\n";
      return 1;
    }
    auto priv = decode_hex32(from_priv_hex);
    auto to = finalis::address::decode(to_addr);
    if (!priv.has_value() || !to.has_value()) {
      std::cerr << "invalid required args\n";
      return 1;
    }

    auto kp = finalis::crypto::keypair_from_seed32(*priv);
    if (!kp.has_value()) {
      std::cerr << "invalid private key\n";
      return 1;
    }
    auto from_pkh = finalis::crypto::h160(finalis::Bytes(kp->public_key.begin(), kp->public_key.end()));

    std::vector<std::pair<finalis::OutPoint, finalis::TxOut>> prevs;
    std::uint64_t total_prev_value = 0;
    prevs.reserve(prev_txid_hexes.size());
    for (size_t i = 0; i < prev_txid_hexes.size(); ++i) {
      auto prev_txid = decode_hex32(prev_txid_hexes[i]);
      if (!prev_txid.has_value()) {
        std::cerr << "invalid --prev-txid\n";
        return 1;
      }
      prevs.push_back({
          finalis::OutPoint{*prev_txid, prev_indexes[i]},
          finalis::TxOut{prev_values[i], finalis::address::p2pkh_script_pubkey(from_pkh)},
      });
      total_prev_value += prev_values[i];
    }
    if (total_prev_value < amount + fee) {
      std::cerr << "insufficient prev output value\n";
      return 1;
    }

    std::vector<finalis::TxOut> outputs;
    outputs.push_back(finalis::TxOut{amount, finalis::address::p2pkh_script_pubkey(to->pubkey_hash)});
    const std::uint64_t change = total_prev_value - amount - fee;
    if (change > 0) {
      if (!change_addr.empty()) {
        auto ch = finalis::address::decode(change_addr);
        if (!ch.has_value()) {
          std::cerr << "invalid --change-address\n";
          return 1;
        }
        outputs.push_back(finalis::TxOut{change, finalis::address::p2pkh_script_pubkey(ch->pubkey_hash)});
      } else {
        outputs.push_back(finalis::TxOut{change, finalis::address::p2pkh_script_pubkey(from_pkh)});
      }
    }

    std::string err;
    auto tx = finalis::build_signed_p2pkh_tx_multi_input(prevs, finalis::Bytes(priv->begin(), priv->end()), outputs, &err);
    if (!tx.has_value()) {
      std::cerr << "build tx failed: " << err << "\n";
      return 1;
    }

    std::cout << "txid=" << finalis::hex_encode32(tx->txid()) << "\n";
    std::cout << "tx_hex=" << finalis::hex_encode(tx->serialize()) << "\n";
    return 0;
  }

  if (cmd == "mint_deposit_create") {
    std::string prev_txid_hex;
    std::uint32_t prev_index = 0;
    std::uint64_t prev_value = 0;
    std::string from_priv_hex;
    std::string mint_id_hex;
    std::string recipient_addr;
    std::string change_addr;
    std::uint64_t amount = 0;
    std::uint64_t fee = 0;

    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--prev-txid" && i + 1 < argc) prev_txid_hex = argv[++i];
      else if (a == "--prev-index" && i + 1 < argc) prev_index = static_cast<std::uint32_t>(std::stoul(argv[++i]));
      else if (a == "--prev-value" && i + 1 < argc) prev_value = static_cast<std::uint64_t>(std::stoull(argv[++i]));
      else if (a == "--from-privkey" && i + 1 < argc) from_priv_hex = argv[++i];
      else if (a == "--mint-id" && i + 1 < argc) mint_id_hex = argv[++i];
      else if (a == "--recipient-address" && i + 1 < argc) recipient_addr = argv[++i];
      else if (a == "--change-address" && i + 1 < argc) change_addr = argv[++i];
      else if (a == "--amount" && i + 1 < argc) amount = static_cast<std::uint64_t>(std::stoull(argv[++i]));
      else if (a == "--fee" && i + 1 < argc) fee = static_cast<std::uint64_t>(std::stoull(argv[++i]));
    }

    auto prev_txid = decode_hex32(prev_txid_hex);
    auto priv = decode_hex32(from_priv_hex);
    auto mint_id = decode_hex32(mint_id_hex);
    auto recipient = finalis::address::decode(recipient_addr);
    if (!prev_txid.has_value() || !priv.has_value() || !mint_id.has_value() || !recipient.has_value()) {
      std::cerr << "invalid required args\n";
      return 1;
    }
    if (prev_value < amount + fee) {
      std::cerr << "insufficient prev output value\n";
      return 1;
    }

    auto kp = finalis::crypto::keypair_from_seed32(*priv);
    if (!kp.has_value()) {
      std::cerr << "invalid private key\n";
      return 1;
    }
    auto from_pkh = finalis::crypto::h160(finalis::Bytes(kp->public_key.begin(), kp->public_key.end()));
    finalis::OutPoint op{*prev_txid, prev_index};
    finalis::TxOut prev_out{prev_value, finalis::address::p2pkh_script_pubkey(from_pkh)};

    std::vector<finalis::TxOut> outputs;
    outputs.push_back(finalis::TxOut{
        amount, finalis::privacy::mint_deposit_script_pubkey(*mint_id, recipient->pubkey_hash)});

    const std::uint64_t change = prev_value - amount - fee;
    if (change > 0) {
      if (!change_addr.empty()) {
        auto ch = finalis::address::decode(change_addr);
        if (!ch.has_value()) {
          std::cerr << "invalid --change-address\n";
          return 1;
        }
        outputs.push_back(finalis::TxOut{change, finalis::address::p2pkh_script_pubkey(ch->pubkey_hash)});
      } else {
        outputs.push_back(finalis::TxOut{change, finalis::address::p2pkh_script_pubkey(from_pkh)});
      }
    }

    std::string err;
    auto tx = finalis::build_signed_p2pkh_tx_single_input(op, prev_out, finalis::Bytes(priv->begin(), priv->end()), outputs, &err);
    if (!tx.has_value()) {
      std::cerr << "mint deposit tx build failed: " << err << "\n";
      return 1;
    }
    std::cout << "txid=" << finalis::hex_encode32(tx->txid()) << "\n";
    std::cout << "tx_hex=" << finalis::hex_encode(tx->serialize()) << "\n";
    return 0;
  }

  if (cmd == "mint_deposit_status") {
    std::string db_path = default_mainnet_db_path();
    std::string mint_id_hex;
    std::string recipient_addr;
    std::size_t tail = 20;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--db" && i + 1 < argc) db_path = argv[++i];
      else if (a == "--mint-id" && i + 1 < argc) mint_id_hex = argv[++i];
      else if (a == "--recipient-address" && i + 1 < argc) recipient_addr = argv[++i];
      else if (a == "--tail" && i + 1 < argc) tail = static_cast<std::size_t>(std::stoull(argv[++i]));
    }

    std::optional<finalis::Hash32> mint_filter;
    if (!mint_id_hex.empty()) {
      auto id = decode_hex32(mint_id_hex);
      if (!id) {
        std::cerr << "invalid --mint-id\n";
        return 1;
      }
      mint_filter = *id;
    }
    std::optional<std::array<std::uint8_t, 20>> recipient_filter;
    if (!recipient_addr.empty()) {
      auto addr = finalis::address::decode(recipient_addr);
      if (!addr) {
        std::cerr << "invalid --recipient-address\n";
        return 1;
      }
      recipient_filter = addr->pubkey_hash;
    }

    finalis::storage::DB db;
    if (!db.open_readonly(db_path) && !db.open(db_path)) {
      std::cerr << "failed to open db\n";
      return 1;
    }

    struct MintDepositRow {
      finalis::OutPoint outpoint;
      finalis::Hash32 mint_id{};
      std::array<std::uint8_t, 20> recipient{};
      std::uint64_t value{0};
      std::uint64_t height{0};
      finalis::Hash32 txid{};
    };

    std::vector<MintDepositRow> rows;
    const auto utxos = db.load_utxos();
    for (const auto& [op, entry] : utxos) {
      finalis::Hash32 mint_id{};
      std::array<std::uint8_t, 20> recipient{};
      if (!finalis::privacy::is_mint_deposit_script(entry.out.script_pubkey, &mint_id, &recipient)) continue;
      if (mint_filter.has_value() && mint_id != *mint_filter) continue;
      if (recipient_filter.has_value() && recipient != *recipient_filter) continue;
      MintDepositRow row;
      row.outpoint = op;
      row.mint_id = mint_id;
      row.recipient = recipient;
      row.value = entry.out.value;
      row.txid = op.txid;
      auto loc = db.get_tx_index(op.txid);
      if (loc) row.height = loc->height;
      rows.push_back(row);
    }

    std::sort(rows.begin(), rows.end(), [](const auto& a, const auto& b) {
      if (a.height != b.height) return a.height > b.height;
      return a.outpoint.index < b.outpoint.index;
    });

    std::cout << "mint_deposits=" << rows.size() << "\n";
    const std::size_t limit = std::min<std::size_t>(tail, rows.size());
    for (std::size_t i = 0; i < limit; ++i) {
      const auto& row = rows[i];
      std::cout << "txid=" << finalis::hex_encode32(row.txid)
                << " vout=" << row.outpoint.index
                << " value=" << row.value
                << " height=" << row.height
                << " mint_id=" << finalis::hex_encode32(row.mint_id)
                << " recipient_pkh=" << finalis::hex_encode(finalis::Bytes(row.recipient.begin(), row.recipient.end()))
                << "\n";
    }
    return 0;
  }

  if (cmd == "mint_deposit_register") {
    std::string url;
    std::string chain = "mainnet";
    std::string deposit_txid_hex;
    std::uint32_t deposit_vout = 0;
    std::string mint_id_hex;
    std::string recipient_addr;
    std::uint64_t amount = 0;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--url" && i + 1 < argc) url = argv[++i];
      else if (a == "--chain" && i + 1 < argc) chain = argv[++i];
      else if (a == "--deposit-txid" && i + 1 < argc) deposit_txid_hex = argv[++i];
      else if (a == "--deposit-vout" && i + 1 < argc) deposit_vout = static_cast<std::uint32_t>(std::stoul(argv[++i]));
      else if (a == "--mint-id" && i + 1 < argc) mint_id_hex = argv[++i];
      else if (a == "--recipient-address" && i + 1 < argc) recipient_addr = argv[++i];
      else if (a == "--amount" && i + 1 < argc) amount = static_cast<std::uint64_t>(std::stoull(argv[++i]));
    }

    auto deposit_txid = decode_hex32(deposit_txid_hex);
    auto mint_id = decode_hex32(mint_id_hex);
    auto recipient = finalis::address::decode(recipient_addr);
    if (url.empty() || !deposit_txid || !mint_id || !recipient) {
      std::cerr << "invalid required args\n";
      return 1;
    }

    finalis::privacy::MintDepositRegistrationRequest req;
    req.chain = chain;
    req.deposit_txid = *deposit_txid;
    req.deposit_vout = deposit_vout;
    req.mint_id = *mint_id;
    req.recipient_pubkey_hash = recipient->pubkey_hash;
    req.amount = amount;

    std::string err;
    auto body = http_post_json(url, finalis::privacy::to_json(req), &err);
    if (!body) {
      std::cerr << "mint_deposit_register failed: " << err << "\n";
      return 1;
    }
    auto resp = finalis::privacy::parse_mint_deposit_registration_response(*body);
    if (!resp) {
      std::cerr << "mint_deposit_register parse failed\n";
      return 1;
    }
    auto finalization_depth_required = find_json_u64(*body, "finalization_depth_required");
    std::cout << "accepted=" << (resp->accepted ? "true" : "false") << "\n";
    if (finalization_depth_required.has_value()) {
      std::cout << "finalization_depth_required=" << *finalization_depth_required << "\n";
    }
    std::cout << "mint_deposit_ref=" << resp->mint_deposit_ref << "\n";
    return 0;
  }

  if (cmd == "mint_issue_blinds") {
    std::string url;
    std::string mint_deposit_ref;
    std::vector<std::string> blinds;
    std::vector<std::uint64_t> note_amounts;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--url" && i + 1 < argc) url = argv[++i];
      else if (a == "--mint-deposit-ref" && i + 1 < argc) mint_deposit_ref = argv[++i];
      else if (a == "--blind" && i + 1 < argc) blinds.push_back(argv[++i]);
      else if (a == "--note-amount" && i + 1 < argc) {
        note_amounts.push_back(static_cast<std::uint64_t>(std::stoull(argv[++i])));
      }
    }
    if (url.empty() || mint_deposit_ref.empty() || blinds.empty() || blinds.size() != note_amounts.size()) {
      std::cerr << "mint_issue_blinds requires --url, --mint-deposit-ref, and matching --blind/--note-amount pairs\n";
      return 1;
    }
    finalis::privacy::MintBlindIssueRequest req;
    req.mint_deposit_ref = mint_deposit_ref;
    req.blinded_messages = blinds;
    req.note_amounts = note_amounts;

    std::string err;
    auto body = http_post_json(url, finalis::privacy::to_json(req), &err);
    if (!body) {
      std::cerr << "mint_issue_blinds failed: " << err << "\n";
      return 1;
    }
    auto resp = finalis::privacy::parse_mint_blind_issue_response(*body);
    if (!resp) {
      std::cerr << "mint_issue_blinds parse failed\n";
      return 1;
    }
    std::cout << "issuance_id=" << resp->issuance_id << "\n";
    std::cout << "mint_epoch=" << resp->mint_epoch << "\n";
    std::cout << "signed_blinds=" << resp->signed_blinds.size() << "\n";
    for (std::size_t i = 0; i < resp->signed_blinds.size(); ++i) {
      std::cout << "signed_blind[" << i << "]=" << resp->signed_blinds[i] << "\n";
      if (i < resp->note_refs.size()) {
        std::cout << "note_ref[" << i << "]=" << resp->note_refs[i] << "\n";
      }
      if (i < resp->note_amounts.size()) {
        std::cout << "note_amount[" << i << "]=" << resp->note_amounts[i] << "\n";
      }
    }
    return 0;
  }

  if (cmd == "mint_redeem_create") {
    std::string url;
    std::string redeem_address;
    std::vector<std::string> notes;
    std::uint64_t amount = 0;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--url" && i + 1 < argc) url = argv[++i];
      else if (a == "--redeem-address" && i + 1 < argc) redeem_address = argv[++i];
      else if (a == "--amount" && i + 1 < argc) amount = static_cast<std::uint64_t>(std::stoull(argv[++i]));
      else if (a == "--note" && i + 1 < argc) notes.push_back(argv[++i]);
    }
    if (url.empty() || redeem_address.empty() || amount == 0 || notes.empty()) {
      std::cerr << "mint_redeem_create requires --url, --redeem-address, --amount, and at least one --note\n";
      return 1;
    }
    finalis::privacy::MintRedemptionRequest req;
    req.notes = notes;
    req.redeem_address = redeem_address;
    req.amount = amount;

    std::string err;
    auto body = http_post_json(url, finalis::privacy::to_json(req), &err);
    if (!body) {
      std::cerr << "mint_redeem_create failed: " << err << "\n";
      return 1;
    }
    auto resp = finalis::privacy::parse_mint_redemption_response(*body);
    if (!resp) {
      std::cerr << "mint_redeem_create parse failed\n";
      return 1;
    }
    std::cout << "accepted=" << (resp->accepted ? "true" : "false") << "\n";
    std::cout << "redemption_batch_id=" << resp->redemption_batch_id << "\n";
    return 0;
  }

  if (cmd == "mint_redeem_approve_broadcast") {
    std::string url;
    std::string batch_id;
    std::string operator_key_id;
    std::string operator_secret_hex;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--url" && i + 1 < argc) url = argv[++i];
      else if (a == "--batch-id" && i + 1 < argc) batch_id = argv[++i];
      else if (a == "--operator-key-id" && i + 1 < argc) operator_key_id = argv[++i];
      else if (a == "--operator-secret-hex" && i + 1 < argc) operator_secret_hex = argv[++i];
    }
    if (url.empty() || batch_id.empty() || operator_key_id.empty() || operator_secret_hex.empty()) {
      std::cerr << "mint_redeem_approve_broadcast requires --url, --batch-id, --operator-key-id, and --operator-secret-hex\n";
      return 1;
    }
    std::ostringstream body_json;
    body_json << "{\"redemption_batch_id\":\"" << batch_id << "\"}";
    std::string err;
    auto headers = operator_signed_headers_for_url("POST", url, body_json.str(), operator_key_id, operator_secret_hex, &err);
    if (!headers) {
      std::cerr << "mint_redeem_approve_broadcast failed: " << err << "\n";
      return 1;
    }
    auto body = http_post_json_with_headers(url, body_json.str(), *headers, &err);
    if (!body) {
      std::cerr << "mint_redeem_approve_broadcast failed: " << err << "\n";
      return 1;
    }
    std::cout << *body << "\n";
    return 0;
  }

  if (cmd == "mint_redeem_status") {
    std::string url;
    std::string batch_id;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--url" && i + 1 < argc) url = argv[++i];
      else if (a == "--batch-id" && i + 1 < argc) batch_id = argv[++i];
    }
    if (url.empty() || batch_id.empty()) {
      std::cerr << "mint_redeem_status requires --url and --batch-id\n";
      return 1;
    }

    std::ostringstream body_json;
    body_json << "{\"redemption_batch_id\":\"" << batch_id << "\"}";

    std::string err;
    auto body = http_post_json(url, body_json.str(), &err);
    if (!body) {
      std::cerr << "mint_redeem_status failed: " << err << "\n";
      return 1;
    }
    auto resp = finalis::privacy::parse_mint_redemption_status_response(*body);
    if (!resp) {
      std::cerr << "mint_redeem_status parse failed\n";
      return 1;
    }
    auto finalization_depth = find_json_u64(*body, "finalization_depth");
    std::cout << "state=" << resp->state << "\n";
    std::cout << "l1_txid=" << resp->l1_txid << "\n";
    std::cout << "amount=" << resp->amount << "\n";
    if (finalization_depth.has_value()) {
      std::cout << "finalization_depth=" << *finalization_depth << "\n";
    }
    return 0;
  }

  if (cmd == "mint_redeem_update") {
    std::string url;
    std::string batch_id;
    std::string state;
    std::string l1_txid;
    std::string operator_key_id;
    std::string operator_secret_hex;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--url" && i + 1 < argc) url = argv[++i];
      else if (a == "--batch-id" && i + 1 < argc) batch_id = argv[++i];
      else if (a == "--state" && i + 1 < argc) state = argv[++i];
      else if (a == "--l1-txid" && i + 1 < argc) l1_txid = argv[++i];
      else if (a == "--operator-key-id" && i + 1 < argc) operator_key_id = argv[++i];
      else if (a == "--operator-secret-hex" && i + 1 < argc) operator_secret_hex = argv[++i];
    }
    if (url.empty() || batch_id.empty() || state.empty() || operator_key_id.empty() || operator_secret_hex.empty()) {
      std::cerr << "mint_redeem_update requires --url, --batch-id, --state, --operator-key-id, and --operator-secret-hex\n";
      return 1;
    }
    std::ostringstream body_json;
    body_json << "{\"redemption_batch_id\":\"" << batch_id << "\",\"state\":\"" << state << "\"";
    if (!l1_txid.empty()) body_json << ",\"l1_txid\":\"" << l1_txid << "\"";
    body_json << "}";
    std::string err;
    auto headers = operator_signed_headers_for_url("POST", url, body_json.str(), operator_key_id, operator_secret_hex, &err);
    if (!headers) {
      std::cerr << "mint_redeem_update failed: " << err << "\n";
      return 1;
    }
    auto body = http_post_json_with_headers(url, body_json.str(), *headers, &err);
    if (!body) {
      std::cerr << "mint_redeem_update failed: " << err << "\n";
      return 1;
    }
    std::cout << *body << "\n";
    return 0;
  }

  if (cmd == "mint_reserves") {
    std::string url;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--url" && i + 1 < argc) url = argv[++i];
    }
    if (url.empty()) {
      std::cerr << "mint_reserves requires --url\n";
      return 1;
    }
    std::string err;
    auto body = http_get_json(url, &err);
    if (!body) {
      std::cerr << "mint_reserves failed: " << err << "\n";
      return 1;
    }
    std::cout << *body << "\n";
    return 0;
  }

  if (cmd == "mint_reserve_alerts") {
    std::string url;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--url" && i + 1 < argc) url = argv[++i];
    }
    if (url.empty()) {
      std::cerr << "mint_reserve_alerts requires --url\n";
      return 1;
    }
    std::string err;
    auto body = http_get_json(url, &err);
    if (!body) {
      std::cerr << "mint_reserve_alerts failed: " << err << "\n";
      return 1;
    }
    std::cout << *body << "\n";
    return 0;
  }

  if (cmd == "mint_reserve_health") {
    std::string url;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--url" && i + 1 < argc) url = argv[++i];
    }
    if (url.empty()) {
      std::cerr << "mint_reserve_health requires --url\n";
      return 1;
    }
    std::string err;
    auto body = http_get_json(url, &err);
    if (!body) {
      std::cerr << "mint_reserve_health failed: " << err << "\n";
      return 1;
    }
    std::cout << *body << "\n";
    return 0;
  }

  if (cmd == "mint_reserve_metrics") {
    std::string url;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--url" && i + 1 < argc) url = argv[++i];
    }
    if (url.empty()) {
      std::cerr << "mint_reserve_metrics requires --url\n";
      return 1;
    }
    std::string err;
    auto body = http_get_text(url, &err);
    if (!body) {
      std::cerr << "mint_reserve_metrics failed: " << err << "\n";
      return 1;
    }
    std::cout << *body;
    return 0;
  }

  if (cmd == "mint_alert_history") {
    std::string url;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--url" && i + 1 < argc) url = argv[++i];
    }
    if (url.empty()) {
      std::cerr << "mint_alert_history requires --url\n";
      return 1;
    }
    std::string err;
    auto body = http_get_json(url, &err);
    if (!body) {
      std::cerr << "mint_alert_history failed: " << err << "\n";
      return 1;
    }
    std::cout << *body << "\n";
    return 0;
  }

  if (cmd == "mint_alert_ack") {
    std::string url, event_id, operator_key_id, operator_secret_hex, note;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--url" && i + 1 < argc) url = argv[++i];
      else if (a == "--event-id" && i + 1 < argc) event_id = argv[++i];
      else if (a == "--operator-key-id" && i + 1 < argc) operator_key_id = argv[++i];
      else if (a == "--operator-secret-hex" && i + 1 < argc) operator_secret_hex = argv[++i];
      else if (a == "--note" && i + 1 < argc) note = argv[++i];
    }
    if (url.empty() || event_id.empty() || operator_key_id.empty() || operator_secret_hex.empty()) {
      std::cerr << "mint_alert_ack requires --url, --event-id, --operator-key-id, and --operator-secret-hex\n";
      return 1;
    }
    const std::string body_json = std::string("{\"event_id\":\"") + event_id + "\",\"note\":\"" + note + "\"}";
    std::string err;
    auto headers = operator_signed_headers_for_url("POST", url, body_json, operator_key_id, operator_secret_hex, &err);
    if (!headers) {
      std::cerr << "mint_alert_ack failed: " << err << "\n";
      return 1;
    }
    auto body = http_post_json_with_headers(url, body_json, *headers, &err);
    if (!body) {
      std::cerr << "mint_alert_ack failed: " << err << "\n";
      return 1;
    }
    std::cout << *body << "\n";
    return 0;
  }

  if (cmd == "mint_alert_silence") {
    std::string url, event_type, operator_key_id, operator_secret_hex, reason;
    std::string until;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--url" && i + 1 < argc) url = argv[++i];
      else if (a == "--event-type" && i + 1 < argc) event_type = argv[++i];
      else if (a == "--until" && i + 1 < argc) until = argv[++i];
      else if (a == "--operator-key-id" && i + 1 < argc) operator_key_id = argv[++i];
      else if (a == "--operator-secret-hex" && i + 1 < argc) operator_secret_hex = argv[++i];
      else if (a == "--reason" && i + 1 < argc) reason = argv[++i];
    }
    if (url.empty() || event_type.empty() || until.empty() || operator_key_id.empty() || operator_secret_hex.empty()) {
      std::cerr << "mint_alert_silence requires --url, --event-type, --until, --operator-key-id, and --operator-secret-hex\n";
      return 1;
    }
    const std::string body_json = std::string("{\"event_type\":\"") + event_type + "\",\"until_ts\":" + until + ",\"reason\":\"" + reason + "\"}";
    std::string err;
    auto headers = operator_signed_headers_for_url("POST", url, body_json, operator_key_id, operator_secret_hex, &err);
    if (!headers) {
      std::cerr << "mint_alert_silence failed: " << err << "\n";
      return 1;
    }
    auto body = http_post_json_with_headers(url, body_json, *headers, &err);
    if (!body) {
      std::cerr << "mint_alert_silence failed: " << err << "\n";
      return 1;
    }
    std::cout << *body << "\n";
    return 0;
  }

  if (cmd == "mint_alert_silences" || cmd == "mint_event_policy" || cmd == "mint_notifier_list" ||
      cmd == "mint_dead_letters" || cmd == "mint_incident_timeline_export" || cmd == "mint_worker_status") {
    std::string url;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--url" && i + 1 < argc) url = argv[++i];
    }
    if (url.empty()) {
      std::cerr << cmd << " requires --url\n";
      return 1;
    }
    std::string err;
    auto body = http_get_json(url, &err);
    if (!body) {
      std::cerr << cmd << " failed: " << err << "\n";
      return 1;
    }
    std::cout << *body << "\n";
    return 0;
  }

  if (cmd == "mint_event_policy_update") {
    std::string url, operator_key_id, operator_secret_hex, retention_limit, export_ack;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--url" && i + 1 < argc) url = argv[++i];
      else if (a == "--operator-key-id" && i + 1 < argc) operator_key_id = argv[++i];
      else if (a == "--operator-secret-hex" && i + 1 < argc) operator_secret_hex = argv[++i];
      else if (a == "--retention-limit" && i + 1 < argc) retention_limit = argv[++i];
      else if (a == "--export-include-acknowledged" && i + 1 < argc) export_ack = argv[++i];
    }
    if (url.empty() || operator_key_id.empty() || operator_secret_hex.empty()) {
      std::cerr << "mint_event_policy_update requires --url, --operator-key-id, and --operator-secret-hex\n";
      return 1;
    }
    std::ostringstream body_json;
    body_json << "{";
    bool first = true;
    if (!retention_limit.empty()) {
      body_json << "\"event_retention_limit\":" << retention_limit;
      first = false;
    }
    if (!export_ack.empty()) {
      if (!first) body_json << ",";
      body_json << "\"export_include_acknowledged\":" << ((export_ack == "true" || export_ack == "1") ? "true" : "false");
    }
    body_json << "}";
    std::string err;
    auto headers = operator_signed_headers_for_url("POST", url, body_json.str(), operator_key_id, operator_secret_hex, &err);
    if (!headers) {
      std::cerr << "mint_event_policy_update failed: " << err << "\n";
      return 1;
    }
    auto body = http_post_json_with_headers(url, body_json.str(), *headers, &err);
    if (!body) {
      std::cerr << "mint_event_policy_update failed: " << err << "\n";
      return 1;
    }
    std::cout << *body << "\n";
    return 0;
  }

  if (cmd == "mint_notifier_upsert") {
    std::string url, operator_key_id, operator_secret_hex, notifier_id, kind, target, enabled, email_to, email_from, retry_max_attempts, retry_backoff_seconds, auth_type, auth_token_secret_ref, auth_user_secret_ref, auth_pass_secret_ref, tls_verify, tls_ca_file, tls_client_cert_file, tls_client_key_file;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--url" && i + 1 < argc) url = argv[++i];
      else if (a == "--operator-key-id" && i + 1 < argc) operator_key_id = argv[++i];
      else if (a == "--operator-secret-hex" && i + 1 < argc) operator_secret_hex = argv[++i];
      else if (a == "--notifier-id" && i + 1 < argc) notifier_id = argv[++i];
      else if (a == "--kind" && i + 1 < argc) kind = argv[++i];
      else if (a == "--target" && i + 1 < argc) target = argv[++i];
      else if (a == "--enabled" && i + 1 < argc) enabled = argv[++i];
      else if (a == "--retry-max-attempts" && i + 1 < argc) retry_max_attempts = argv[++i];
      else if (a == "--retry-backoff-seconds" && i + 1 < argc) retry_backoff_seconds = argv[++i];
      else if (a == "--auth-type" && i + 1 < argc) auth_type = argv[++i];
      else if (a == "--auth-token-secret-ref" && i + 1 < argc) auth_token_secret_ref = argv[++i];
      else if (a == "--auth-user-secret-ref" && i + 1 < argc) auth_user_secret_ref = argv[++i];
      else if (a == "--auth-pass-secret-ref" && i + 1 < argc) auth_pass_secret_ref = argv[++i];
      else if (a == "--tls-verify" && i + 1 < argc) tls_verify = argv[++i];
      else if (a == "--tls-ca-file" && i + 1 < argc) tls_ca_file = argv[++i];
      else if (a == "--tls-client-cert-file" && i + 1 < argc) tls_client_cert_file = argv[++i];
      else if (a == "--tls-client-key-file" && i + 1 < argc) tls_client_key_file = argv[++i];
      else if (a == "--email-to" && i + 1 < argc) email_to = argv[++i];
      else if (a == "--email-from" && i + 1 < argc) email_from = argv[++i];
    }
    if (url.empty() || operator_key_id.empty() || operator_secret_hex.empty() || notifier_id.empty() || kind.empty() || target.empty()) {
      std::cerr << "mint_notifier_upsert requires --url, --operator-key-id, --operator-secret-hex, --notifier-id, --kind, and --target\n";
      return 1;
    }
    const bool enabled_value = !(enabled == "false" || enabled == "0");
    std::ostringstream body_json;
    body_json << "{\"notifier_id\":\"" << notifier_id << "\",\"kind\":\"" << kind
              << "\",\"target\":\"" << target << "\",\"enabled\":" << (enabled_value ? "true" : "false");
    if (!retry_max_attempts.empty()) body_json << ",\"retry_max_attempts\":" << retry_max_attempts;
    if (!retry_backoff_seconds.empty()) body_json << ",\"retry_backoff_seconds\":" << retry_backoff_seconds;
    if (!auth_type.empty()) body_json << ",\"auth_type\":\"" << auth_type << "\"";
    if (!auth_token_secret_ref.empty()) body_json << ",\"auth_token_secret_ref\":\"" << auth_token_secret_ref << "\"";
    if (!auth_user_secret_ref.empty()) body_json << ",\"auth_user_secret_ref\":\"" << auth_user_secret_ref << "\"";
    if (!auth_pass_secret_ref.empty()) body_json << ",\"auth_pass_secret_ref\":\"" << auth_pass_secret_ref << "\"";
    if (!tls_verify.empty()) body_json << ",\"tls_verify\":" << ((tls_verify == "true" || tls_verify == "1") ? "true" : "false");
    if (!tls_ca_file.empty()) body_json << ",\"tls_ca_file\":\"" << tls_ca_file << "\"";
    if (!tls_client_cert_file.empty()) body_json << ",\"tls_client_cert_file\":\"" << tls_client_cert_file << "\"";
    if (!tls_client_key_file.empty()) body_json << ",\"tls_client_key_file\":\"" << tls_client_key_file << "\"";
    if (!email_to.empty()) body_json << ",\"email_to\":\"" << email_to << "\"";
    if (!email_from.empty()) body_json << ",\"email_from\":\"" << email_from << "\"";
    body_json << "}";
    std::string err;
    auto headers = operator_signed_headers_for_url("POST", url, body_json.str(), operator_key_id, operator_secret_hex, &err);
    if (!headers) {
      std::cerr << "mint_notifier_upsert failed: " << err << "\n";
      return 1;
    }
    auto body = http_post_json_with_headers(url, body_json.str(), *headers, &err);
    if (!body) {
      std::cerr << "mint_notifier_upsert failed: " << err << "\n";
      return 1;
    }
    std::cout << *body << "\n";
    return 0;
  }

  if (cmd == "mint_dead_letter_replay") {
    std::string url, operator_key_id, operator_secret_hex, dead_letter_id;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--url" && i + 1 < argc) url = argv[++i];
      else if (a == "--operator-key-id" && i + 1 < argc) operator_key_id = argv[++i];
      else if (a == "--operator-secret-hex" && i + 1 < argc) operator_secret_hex = argv[++i];
      else if (a == "--dead-letter-id" && i + 1 < argc) dead_letter_id = argv[++i];
    }
    if (url.empty() || operator_key_id.empty() || operator_secret_hex.empty() || dead_letter_id.empty()) {
      std::cerr << "mint_dead_letter_replay requires --url, --dead-letter-id, --operator-key-id, and --operator-secret-hex\n";
      return 1;
    }
    const std::string body_json = std::string("{\"dead_letter_id\":\"") + dead_letter_id + "\"}";
    std::string err;
    auto headers = operator_signed_headers_for_url("POST", url, body_json, operator_key_id, operator_secret_hex, &err);
    if (!headers) {
      std::cerr << "mint_dead_letter_replay failed: " << err << "\n";
      return 1;
    }
    auto body = http_post_json_with_headers(url, body_json, *headers, &err);
    if (!body) {
      std::cerr << "mint_dead_letter_replay failed: " << err << "\n";
      return 1;
    }
    std::cout << *body << "\n";
    return 0;
  }

  if (cmd == "mint_reserve_consolidate") {
    std::string url;
    std::string operator_key_id;
    std::string operator_secret_hex;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--url" && i + 1 < argc) url = argv[++i];
      else if (a == "--operator-key-id" && i + 1 < argc) operator_key_id = argv[++i];
      else if (a == "--operator-secret-hex" && i + 1 < argc) operator_secret_hex = argv[++i];
    }
    if (url.empty() || operator_key_id.empty() || operator_secret_hex.empty()) {
      std::cerr << "mint_reserve_consolidate requires --url, --operator-key-id, and --operator-secret-hex\n";
      return 1;
    }
    const std::string body_json = "{}";
    std::string err;
    auto headers = operator_signed_headers_for_url("POST", url, body_json, operator_key_id, operator_secret_hex, &err);
    if (!headers) {
      std::cerr << "mint_reserve_consolidate failed: " << err << "\n";
      return 1;
    }
    auto body = http_post_json_with_headers(url, body_json, *headers, &err);
    if (!body) {
      std::cerr << "mint_reserve_consolidate failed: " << err << "\n";
      return 1;
    }
    std::cout << *body << "\n";
    return 0;
  }

  if (cmd == "mint_reserve_consolidation_plan") {
    std::string url;
    std::string operator_key_id;
    std::string operator_secret_hex;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--url" && i + 1 < argc) url = argv[++i];
      else if (a == "--operator-key-id" && i + 1 < argc) operator_key_id = argv[++i];
      else if (a == "--operator-secret-hex" && i + 1 < argc) operator_secret_hex = argv[++i];
    }
    if (url.empty() || operator_key_id.empty() || operator_secret_hex.empty()) {
      std::cerr << "mint_reserve_consolidation_plan requires --url, --operator-key-id, and --operator-secret-hex\n";
      return 1;
    }
    std::string err;
    auto headers = operator_signed_headers_for_url("GET", url, "", operator_key_id, operator_secret_hex, &err);
    if (!headers) {
      std::cerr << "mint_reserve_consolidation_plan failed: " << err << "\n";
      return 1;
    }
    auto body = http_get_json_with_headers(url, *headers, &err);
    if (!body) {
      std::cerr << "mint_reserve_consolidation_plan failed: " << err << "\n";
      return 1;
    }
    std::cout << *body << "\n";
    return 0;
  }

  if (cmd == "mint_redemptions_pause" || cmd == "mint_redemptions_resume" ||
      cmd == "mint_redemptions_auto_pause_enable" || cmd == "mint_redemptions_auto_pause_disable") {
    std::string url;
    std::string operator_key_id;
    std::string operator_secret_hex;
    std::string reason;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--url" && i + 1 < argc) url = argv[++i];
      else if (a == "--operator-key-id" && i + 1 < argc) operator_key_id = argv[++i];
      else if (a == "--operator-secret-hex" && i + 1 < argc) operator_secret_hex = argv[++i];
      else if (a == "--reason" && i + 1 < argc) reason = argv[++i];
    }
    if (url.empty() || operator_key_id.empty() || operator_secret_hex.empty()) {
      std::cerr << cmd << " requires --url, --operator-key-id, and --operator-secret-hex\n";
      return 1;
    }
    const bool paused = (cmd == "mint_redemptions_pause");
    const bool auto_pause_enabled =
        (cmd == "mint_redemptions_auto_pause_enable") ? true :
        (cmd == "mint_redemptions_auto_pause_disable") ? false : false;
    std::ostringstream body_json;
    body_json << "{\"redemptions_paused\":" << (paused ? "true" : "false")
              << ",\"pause_reason\":\"" << reason << "\"";
    if (cmd == "mint_redemptions_auto_pause_enable" || cmd == "mint_redemptions_auto_pause_disable") {
      body_json << ",\"auto_pause_enabled\":" << (auto_pause_enabled ? "true" : "false");
    }
    body_json << "}";
    std::string err;
    auto headers = operator_signed_headers_for_url("POST", url, body_json.str(), operator_key_id, operator_secret_hex, &err);
    if (!headers) {
      std::cerr << cmd << " failed: " << err << "\n";
      return 1;
    }
    auto body = http_post_json_with_headers(url, body_json.str(), *headers, &err);
    if (!body) {
      std::cerr << cmd << " failed: " << err << "\n";
      return 1;
    }
    std::cout << *body << "\n";
    return 0;
  }

  if (cmd == "mint_redemptions_policy") {
    std::string url;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--url" && i + 1 < argc) url = argv[++i];
    }
    if (url.empty()) {
      std::cerr << "mint_redemptions_policy requires --url\n";
      return 1;
    }
    std::string err;
    auto body = http_get_json(url, &err);
    if (!body) {
      std::cerr << "mint_redemptions_policy failed: " << err << "\n";
      return 1;
    }
    std::cout << *body << "\n";
    return 0;
  }

  if (cmd == "mint_accounting_summary") {
    std::string url;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--url" && i + 1 < argc) url = argv[++i];
    }
    if (url.empty()) {
      std::cerr << "mint_accounting_summary requires --url\n";
      return 1;
    }
    std::string err;
    auto body = http_get_json(url, &err);
    if (!body) {
      std::cerr << "mint_accounting_summary failed: " << err << "\n";
      return 1;
    }
    std::cout << *body << "\n";
    return 0;
  }

  if (cmd == "mint_attest_reserves") {
    std::string url;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--url" && i + 1 < argc) url = argv[++i];
    }
    if (url.empty()) {
      std::cerr << "mint_attest_reserves requires --url\n";
      return 1;
    }
    std::string err;
    auto body = http_get_json(url, &err);
    if (!body) {
      std::cerr << "mint_attest_reserves failed: " << err << "\n";
      return 1;
    }
    std::cout << *body << "\n";
    return 0;
  }

  if (cmd == "mint_audit_export") {
    std::string url;
    std::string operator_key_id;
    std::string operator_secret_hex;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--url" && i + 1 < argc) url = argv[++i];
      else if (a == "--operator-key-id" && i + 1 < argc) operator_key_id = argv[++i];
      else if (a == "--operator-secret-hex" && i + 1 < argc) operator_secret_hex = argv[++i];
    }
    if (url.empty() || operator_key_id.empty() || operator_secret_hex.empty()) {
      std::cerr << "mint_audit_export requires --url, --operator-key-id, and --operator-secret-hex\n";
      return 1;
    }
    std::string err;
    auto headers = operator_signed_headers_for_url("GET", url, "", operator_key_id, operator_secret_hex, &err);
    if (!headers) {
      std::cerr << "mint_audit_export failed: " << err << "\n";
      return 1;
    }
    auto body = http_get_json_with_headers(url, *headers, &err);
    if (!body) {
      std::cerr << "mint_audit_export failed: " << err << "\n";
      return 1;
    }
    std::cout << *body << "\n";
    return 0;
  }

  if (cmd == "mint_api_example") {
    finalis::privacy::MintDepositRegistrationRequest deposit_req;
    deposit_req.chain = "mainnet";
    deposit_req.deposit_txid.fill(0x11);
    deposit_req.deposit_vout = 0;
    deposit_req.mint_id.fill(0x22);
    deposit_req.recipient_pubkey_hash.fill(0x33);
    deposit_req.amount = 100000;

    finalis::privacy::MintBlindIssueRequest issue_req;
    issue_req.mint_deposit_ref = "example-ref";
    issue_req.blinded_messages = {"blind-msg-1", "blind-msg-2"};
    issue_req.note_amounts = {40000, 60000};

    finalis::privacy::MintRedemptionRequest redeem_req;
    redeem_req.notes = {"note-1", "note-2"};
    redeem_req.redeem_address = "sc1example";
    redeem_req.amount = 100000;

    std::cout << "deposit_registration=" << finalis::privacy::to_json(deposit_req) << "\n";
    std::cout << "blind_issue=" << finalis::privacy::to_json(issue_req) << "\n";
    std::cout << "redemption=" << finalis::privacy::to_json(redeem_req) << "\n";
    return 0;
  }

  if (cmd == "hashcash_stamp_tx") {
    std::string tx_hex;
    std::string network_name = "mainnet";
    std::uint32_t bits = 18;
    std::uint64_t epoch_seconds = 60;
    std::uint64_t now_unix = static_cast<std::uint64_t>(std::time(nullptr));
    std::uint64_t max_nonce = 0;
    for (int i = 2; i < argc; ++i) {
      const std::string a = argv[i];
      if (a == "--tx-hex" && i + 1 < argc) tx_hex = argv[++i];
      else if (a == "--bits" && i + 1 < argc) bits = static_cast<std::uint32_t>(std::stoul(argv[++i]));
      else if (a == "--network" && i + 1 < argc) network_name = argv[++i];
      else if (a == "--epoch-seconds" && i + 1 < argc) epoch_seconds = static_cast<std::uint64_t>(std::stoull(argv[++i]));
      else if (a == "--now" && i + 1 < argc) now_unix = static_cast<std::uint64_t>(std::stoull(argv[++i]));
      else if (a == "--max-nonce" && i + 1 < argc) max_nonce = static_cast<std::uint64_t>(std::stoull(argv[++i]));
    }
    if (tx_hex.empty()) {
      std::cerr << "hashcash_stamp_tx requires --tx-hex\n";
      return 1;
    }
    if (network_name != "mainnet") {
      std::cerr << "only mainnet network is currently supported\n";
      return 1;
    }
    auto raw = finalis::hex_decode(tx_hex);
    if (!raw.has_value()) {
      std::cerr << "invalid tx hex\n";
      return 1;
    }
    auto tx = finalis::Tx::parse(*raw);
    if (!tx.has_value()) {
      std::cerr << "invalid tx bytes\n";
      return 1;
    }
    finalis::policy::HashcashConfig cfg;
    cfg.enabled = true;
    cfg.base_bits = bits;
    cfg.max_bits = bits;
    cfg.epoch_seconds = std::max<std::uint64_t>(1, epoch_seconds);
    std::string err;
    if (!finalis::policy::apply_hashcash_stamp(&*tx, finalis::mainnet_network(), cfg, bits, now_unix, max_nonce, &err)) {
      std::cerr << "hashcash stamping failed: " << err << "\n";
      return 1;
    }
    std::cout << "bits=" << bits << "\n";
    std::cout << "epoch_bucket=" << tx->hashcash->epoch_bucket << "\n";
    std::cout << "nonce=" << tx->hashcash->nonce << "\n";
    std::cout << "txid=" << finalis::hex_encode32(tx->txid()) << "\n";
    std::cout << "tx_hex=" << finalis::hex_encode(tx->serialize()) << "\n";
    return 0;
  }

  if (cmd == "create_unbond_tx") {
    std::string bond_txid_hex;
    std::uint32_t bond_index = 0;
    std::uint64_t bond_value = finalis::BOND_AMOUNT;
    std::string validator_pub_hex;
    std::string validator_priv_hex;
    std::uint64_t fee = 0;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--bond-txid" && i + 1 < argc) bond_txid_hex = argv[++i];
      else if (a == "--bond-index" && i + 1 < argc) bond_index = static_cast<std::uint32_t>(std::stoul(argv[++i]));
      else if (a == "--bond-value" && i + 1 < argc) bond_value = static_cast<std::uint64_t>(std::stoull(argv[++i]));
      else if (a == "--validator-pubkey" && i + 1 < argc) validator_pub_hex = argv[++i];
      else if (a == "--validator-privkey" && i + 1 < argc) validator_priv_hex = argv[++i];
      else if (a == "--fee" && i + 1 < argc) fee = static_cast<std::uint64_t>(std::stoull(argv[++i]));
    }
    auto bond_txid = decode_hex32(bond_txid_hex);
    auto pub = decode_hex32(validator_pub_hex);
    auto priv = decode_hex32(validator_priv_hex);
    if (!bond_txid || !pub || !priv) {
      std::cerr << "invalid args\n";
      return 1;
    }

    finalis::OutPoint op{*bond_txid, bond_index};
    std::string err;
    auto tx = finalis::build_unbond_tx(op, *pub, bond_value, fee, finalis::Bytes(priv->begin(), priv->end()), &err);
    if (!tx) {
      std::cerr << "create unbond tx failed: " << err << "\n";
      return 1;
    }
    std::cout << "txid=" << finalis::hex_encode32(tx->txid()) << "\n";
    std::cout << "tx_hex=" << finalis::hex_encode(tx->serialize()) << "\n";
    return 0;
  }

  if (cmd == "create_slash_tx") {
    std::string bond_txid_hex;
    std::uint32_t bond_index = 0;
    std::uint64_t bond_value = finalis::BOND_AMOUNT;
    finalis::Vote a, b;
    std::string a_transition_hex, a_pub_hex, a_sig_hex, b_transition_hex, b_pub_hex, b_sig_hex;
    std::uint64_t fee = 0;

    for (int i = 2; i < argc; ++i) {
      std::string k = argv[i];
      if (k == "--bond-txid" && i + 1 < argc) bond_txid_hex = argv[++i];
      else if (k == "--bond-index" && i + 1 < argc) bond_index = static_cast<std::uint32_t>(std::stoul(argv[++i]));
      else if (k == "--bond-value" && i + 1 < argc) bond_value = static_cast<std::uint64_t>(std::stoull(argv[++i]));
      else if (k == "--a-height" && i + 1 < argc) a.height = static_cast<std::uint64_t>(std::stoull(argv[++i]));
      else if (k == "--a-round" && i + 1 < argc) a.round = static_cast<std::uint32_t>(std::stoul(argv[++i]));
      else if ((k == "--a-transition" || k == "--a-block") && i + 1 < argc) a_transition_hex = argv[++i];
      else if (k == "--a-pub" && i + 1 < argc) a_pub_hex = argv[++i];
      else if (k == "--a-sig" && i + 1 < argc) a_sig_hex = argv[++i];
      else if (k == "--b-height" && i + 1 < argc) b.height = static_cast<std::uint64_t>(std::stoull(argv[++i]));
      else if (k == "--b-round" && i + 1 < argc) b.round = static_cast<std::uint32_t>(std::stoul(argv[++i]));
      else if ((k == "--b-transition" || k == "--b-block") && i + 1 < argc) b_transition_hex = argv[++i];
      else if (k == "--b-pub" && i + 1 < argc) b_pub_hex = argv[++i];
      else if (k == "--b-sig" && i + 1 < argc) b_sig_hex = argv[++i];
      else if (k == "--fee" && i + 1 < argc) fee = static_cast<std::uint64_t>(std::stoull(argv[++i]));
    }

    auto bond_txid = decode_hex32(bond_txid_hex);
    auto a_transition = decode_hex32(a_transition_hex);
    auto a_pub = decode_hex32(a_pub_hex);
    auto a_sig = decode_hex64(a_sig_hex);
    auto b_transition = decode_hex32(b_transition_hex);
    auto b_pub = decode_hex32(b_pub_hex);
    auto b_sig = decode_hex64(b_sig_hex);
    if (!bond_txid || !a_transition || !a_pub || !a_sig || !b_transition || !b_pub || !b_sig) {
      std::cerr << "invalid slash args\n";
      return 1;
    }
    a.block_id = *a_transition;
    a.validator_pubkey = *a_pub;
    a.signature = *a_sig;
    b.block_id = *b_transition;
    b.validator_pubkey = *b_pub;
    b.signature = *b_sig;

    finalis::OutPoint op{*bond_txid, bond_index};
    std::string err;
    auto tx = finalis::build_slash_tx(op, bond_value, a, b, fee, &err);
    if (!tx) {
      std::cerr << "create slash tx failed: " << err << "\n";
      return 1;
    }
    std::cout << "txid=" << finalis::hex_encode32(tx->txid()) << "\n";
    std::cout << "tx_hex=" << finalis::hex_encode(tx->serialize()) << "\n";
    return 0;
  }

  if (cmd == "broadcast_tx") {
    std::string rpc_url;
    std::string host = "127.0.0.1";
    std::uint16_t port = 19444;
    std::string tx_hex;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--url" && i + 1 < argc) rpc_url = argv[++i];
      else if (a == "--host" && i + 1 < argc) host = argv[++i];
      else if (a == "--port" && i + 1 < argc) port = static_cast<std::uint16_t>(std::stoi(argv[++i]));
      else if (a == "--tx-hex" && i + 1 < argc) tx_hex = argv[++i];
    }
    if (tx_hex.empty()) {
      std::cerr << "--tx-hex is required\n";
      return 1;
    }

    auto raw = finalis::hex_decode(tx_hex);
    if (!raw.has_value() || !finalis::Tx::parse(*raw).has_value()) {
      std::cerr << "invalid tx hex\n";
      return 1;
    }
    if (rpc_url.empty()) rpc_url = "http://" + host + ":" + std::to_string(port) + "/rpc";

    std::string err;
    const auto result = finalis::lightserver::rpc_broadcast_tx(rpc_url, *raw, &err);
    std::cout << "rpc_url=" << rpc_url << "\n";
    std::cout << "accepted=" << ((result.outcome == finalis::lightserver::BroadcastOutcome::Sent) ? "yes" : "no") << "\n";
    if (!result.txid_hex.empty()) std::cout << "txid=" << result.txid_hex << "\n";
    if (!result.message.empty()) std::cout << "message=" << result.message << "\n";
    if (!result.error_code.empty()) std::cout << "error_code=" << result.error_code << "\n";
    if (!result.error_message.empty()) std::cout << "error_message=" << result.error_message << "\n";
    else if (!result.error.empty()) std::cout << "error=" << result.error << "\n";
    std::cout << "retryable=" << (result.retryable ? "yes" : "no") << "\n";
    std::cout << "retry_class=" << result.retry_class << "\n";
    if (result.min_fee_rate_to_enter_when_full.has_value()) {
      std::cout << "min_fee_rate_to_enter_when_full=" << *result.min_fee_rate_to_enter_when_full << "\n";
    }
    if (!err.empty()) std::cout << "rpc_error=" << err << "\n";
    return result.outcome == finalis::lightserver::BroadcastOutcome::Sent ? 0 : 1;
  }

  std::cerr << "unknown command\n";
  return 1;
}
