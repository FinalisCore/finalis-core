// SPDX-License-Identifier: MIT

// P2P: message dispatch, handshake, peer events, broadcasts, sync requests, peer persistence and
// addrman, seeds and dialing, advertised endpoint and NAT refresh, peer scoring and rate limits.

#include "node.hpp"
#include "node_internal.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <limits>
#include <random>
#include <set>
#include <sstream>

#ifndef _WIN32
#include <ifaddrs.h>
#include <sys/types.h>
#endif

#include "consensus/validator_registry.hpp"
#include "common/socket_compat.hpp"
#include "common/version.hpp"
#include "crypto/hash.hpp"
#include "utxo/confidential_tx.hpp"

namespace finalis::node {
using namespace detail;

namespace {

constexpr std::uint64_t kForwardSyncWindow = 64;

constexpr std::uint64_t kTxRelayPeerBackoffMs = 60'000;

constexpr std::uint64_t kValidatorsAddrmanEntryTtlSeconds = 7 * 24 * 60 * 60;

bool is_loopback_seed_host(const std::string& host) {
  if (host == "localhost") return true;
  if (host == "::1") return true;
  return host == "127.0.0.1" || host.rfind("127.", 0) == 0;
}

bool is_wildcard_bind(const std::string& host) {
  return host == "0.0.0.0" || host == "::";
}

std::optional<p2p::NetAddress> advertised_endpoint_from_config(const NodeConfig& cfg) {
  if (!cfg.external_endpoint.empty()) {
    if (!endpoint_fingerprint_safe(cfg.external_endpoint)) return std::nullopt;
    auto parsed = p2p::parse_endpoint(cfg.external_endpoint);
    if (!parsed.has_value() || parsed->port == 0 || parsed->ip.empty()) return std::nullopt;
    return parsed;
  }
  if (!cfg.listen || !cfg.public_mode || is_local_only_bind(cfg.bind_ip) || is_wildcard_bind(cfg.bind_ip)) {
    return std::nullopt;
  }
  return p2p::NetAddress{cfg.bind_ip, cfg.p2p_port};
}

std::array<std::uint8_t, 12> make_stun_transaction_id() {
  std::array<std::uint8_t, 12> txid{};
  std::random_device rd;
  for (auto& b : txid) b = static_cast<std::uint8_t>(rd());
  return txid;
}

std::optional<p2p::NetAddress> parse_stun_binding_response(const Bytes& msg, const std::array<std::uint8_t, 12>& txid,
                                                            std::string* err) {
  constexpr std::uint16_t kBindingResponse = 0x0101;
  constexpr std::uint32_t kMagicCookie = 0x2112A442;
  if (msg.size() < 20) {
    if (err) *err = "stun_short_response";
    return std::nullopt;
  }
  const auto be16 = [&](std::size_t off) -> std::uint16_t {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(msg[off]) << 8) | msg[off + 1]);
  };
  const auto be32 = [&](std::size_t off) -> std::uint32_t {
    return (static_cast<std::uint32_t>(msg[off]) << 24) | (static_cast<std::uint32_t>(msg[off + 1]) << 16) |
           (static_cast<std::uint32_t>(msg[off + 2]) << 8) | static_cast<std::uint32_t>(msg[off + 3]);
  };
  const std::uint16_t type = be16(0);
  const std::uint16_t length = be16(2);
  const std::uint32_t cookie = be32(4);
  if (type != kBindingResponse) {
    if (err) *err = "stun_not_binding_response";
    return std::nullopt;
  }
  if (cookie != kMagicCookie) {
    if (err) *err = "stun_bad_magic_cookie";
    return std::nullopt;
  }
  for (std::size_t i = 0; i < txid.size(); ++i) {
    if (msg[8 + i] != txid[i]) {
      if (err) *err = "stun_transaction_mismatch";
      return std::nullopt;
    }
  }
  if (20 + length > msg.size()) {
    if (err) *err = "stun_bad_length";
    return std::nullopt;
  }

  std::optional<p2p::NetAddress> mapped;
  std::size_t pos = 20;
  const std::size_t end = 20 + length;
  while (pos + 4 <= end) {
    const std::uint16_t attr_type = be16(pos);
    const std::uint16_t attr_len = be16(pos + 2);
    pos += 4;
    if (pos + attr_len > end) break;
    const std::size_t attr = pos;

    if (attr_type == 0x0020 && attr_len >= 8) {  // XOR-MAPPED-ADDRESS
      const std::uint8_t family = msg[attr + 1];
      if (family == 0x01) {
        const std::uint16_t xport = be16(attr + 2);
        const std::uint32_t xip = be32(attr + 4);
        const std::uint16_t port = static_cast<std::uint16_t>(xport ^ static_cast<std::uint16_t>(kMagicCookie >> 16));
        const std::uint32_t ip_host = xip ^ kMagicCookie;
        in_addr addr{};
        addr.s_addr = htonl(ip_host);
        char buf[INET_ADDRSTRLEN] = {};
        if (::inet_ntop(AF_INET, &addr, buf, sizeof(buf)) != nullptr && port != 0) {
          mapped = p2p::NetAddress{std::string(buf), port};
          break;
        }
      }
    } else if (attr_type == 0x0001 && attr_len >= 8 && !mapped.has_value()) {  // MAPPED-ADDRESS fallback
      const std::uint8_t family = msg[attr + 1];
      if (family == 0x01) {
        const std::uint16_t port = be16(attr + 2);
        const std::uint32_t ip_host = be32(attr + 4);
        in_addr addr{};
        addr.s_addr = htonl(ip_host);
        char buf[INET_ADDRSTRLEN] = {};
        if (::inet_ntop(AF_INET, &addr, buf, sizeof(buf)) != nullptr && port != 0) {
          mapped = p2p::NetAddress{std::string(buf), port};
        }
      }
    }

    const std::size_t padded = (static_cast<std::size_t>(attr_len) + 3U) & ~static_cast<std::size_t>(3U);
    pos += padded;
  }

  if (!mapped.has_value()) {
    if (err) *err = "stun_no_mapped_address";
    return std::nullopt;
  }
  return mapped;
}

std::optional<p2p::NetAddress> stun_query_external_endpoint(const std::string& stun_server, std::uint16_t local_port,
                                                            std::uint32_t timeout_ms, std::string* err) {
  if (!net::ensure_sockets()) {
    if (err) *err = "stun_socket_init_failed";
    return std::nullopt;
  }
  const auto endpoint = p2p::parse_endpoint(stun_server);
  if (!endpoint.has_value() || endpoint->ip.empty() || endpoint->port == 0) {
    if (err) *err = "stun_server_invalid";
    return std::nullopt;
  }

  addrinfo hints{};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_protocol = IPPROTO_UDP;
  addrinfo* res = nullptr;
  if (::getaddrinfo(endpoint->ip.c_str(), std::to_string(endpoint->port).c_str(), &hints, &res) != 0 || !res) {
    if (err) *err = "stun_dns_resolve_failed";
    return std::nullopt;
  }

  net::SocketHandle fd = net::kInvalidSocket;
  for (addrinfo* it = res; it != nullptr; it = it->ai_next) {
    fd = ::socket(it->ai_family, it->ai_socktype, it->ai_protocol);
    if (net::valid_socket(fd)) break;
  }
  if (!net::valid_socket(fd)) {
    freeaddrinfo(res);
    if (err) *err = "stun_socket_create_failed";
    return std::nullopt;
  }
  net::set_close_on_exec(fd);
  (void)net::set_nonblocking(fd, true);
  (void)net::set_reuseaddr(fd);

  if (local_port != 0) {
    sockaddr_in local{};
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    local.sin_port = htons(local_port);
    if (::bind(fd, reinterpret_cast<const sockaddr*>(&local), sizeof(local)) != 0) {
      freeaddrinfo(res);
      net::close_socket(fd);
      if (err) *err = "stun_bind_failed";
      return std::nullopt;
    }
  }

  const auto txid = make_stun_transaction_id();
  Bytes req(20, 0);
  req[0] = 0x00;  // Binding Request
  req[1] = 0x01;
  req[2] = 0x00;
  req[3] = 0x00;
  req[4] = 0x21;
  req[5] = 0x12;
  req[6] = 0xA4;
  req[7] = 0x42;
  for (std::size_t i = 0; i < txid.size(); ++i) req[8 + i] = txid[i];

  bool sent = false;
  for (addrinfo* it = res; it != nullptr; it = it->ai_next) {
    const auto n = ::sendto(fd, reinterpret_cast<const char*>(req.data()), static_cast<int>(req.size()), 0, it->ai_addr,
                            static_cast<socklen_t>(it->ai_addrlen));
    if (n == static_cast<int>(req.size())) {
      sent = true;
      break;
    }
  }
  freeaddrinfo(res);
  if (!sent) {
    net::close_socket(fd);
    if (err) *err = "stun_send_failed";
    return std::nullopt;
  }

  if (!net::wait_readable(fd, std::max<std::uint32_t>(100, timeout_ms))) {
    net::close_socket(fd);
    if (err) *err = "stun_timeout";
    return std::nullopt;
  }

  std::array<std::uint8_t, 1024> buf{};
  sockaddr_storage from{};
  socklen_t from_len = sizeof(from);
  const int n =
      ::recvfrom(fd, reinterpret_cast<char*>(buf.data()), static_cast<int>(buf.size()), 0, reinterpret_cast<sockaddr*>(&from),
                 &from_len);
  net::close_socket(fd);
  if (n <= 0) {
    if (err) *err = "stun_recv_failed";
    return std::nullopt;
  }
  Bytes resp(buf.begin(), buf.begin() + n);
  return parse_stun_binding_response(resp, txid, err);
}

std::uint64_t stun_backoff_delay_ms(std::uint32_t fail_count, std::uint32_t base_ms, std::uint32_t max_backoff_ms) {
  const std::uint32_t capped_fail = std::min<std::uint32_t>(fail_count, 8);
  const std::uint64_t shift = (1ULL << capped_fail);
  const std::uint64_t raw = static_cast<std::uint64_t>(std::max<std::uint32_t>(1, base_ms)) * shift;
  return std::min<std::uint64_t>(raw, std::max<std::uint32_t>(base_ms, max_backoff_ms));
}

std::optional<std::string> linux_default_gateway_ipv4() {
#ifdef _WIN32
  return std::nullopt;
#else
  std::ifstream in("/proc/net/route");
  if (!in.good()) return std::nullopt;
  std::string line;
  std::getline(in, line);  // header
  while (std::getline(in, line)) {
    std::istringstream iss(line);
    std::string iface;
    std::string dest_hex;
    std::string gateway_hex;
    if (!(iss >> iface >> dest_hex >> gateway_hex)) continue;
    if (dest_hex != "00000000") continue;
    std::uint32_t gw_le = 0;
    try {
      gw_le = static_cast<std::uint32_t>(std::stoul(gateway_hex, nullptr, 16));
    } catch (...) {
      continue;
    }
    in_addr gw{};
    gw.s_addr = gw_le;  // /proc/net/route stores gateway in little-endian host order
    char buf[INET_ADDRSTRLEN] = {};
    if (::inet_ntop(AF_INET, &gw, buf, sizeof(buf)) != nullptr) return std::string(buf);
  }
  return std::nullopt;
#endif
}

std::optional<p2p::NetAddress> nat_pmp_map_tcp_endpoint(const std::string& gateway_ip, std::uint16_t private_port,
                                                         std::uint16_t requested_public_port, std::uint32_t lifetime_secs,
                                                         std::uint32_t timeout_ms, std::string* err) {
  if (!net::ensure_sockets()) {
    if (err) *err = "nat_pmp_socket_init_failed";
    return std::nullopt;
  }
  net::SocketHandle fd = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (!net::valid_socket(fd)) {
    if (err) *err = "nat_pmp_socket_create_failed";
    return std::nullopt;
  }
  net::set_close_on_exec(fd);
  (void)net::set_nonblocking(fd, true);

  sockaddr_in gw{};
  gw.sin_family = AF_INET;
  gw.sin_port = htons(5351);
  if (::inet_pton(AF_INET, gateway_ip.c_str(), &gw.sin_addr) != 1) {
    net::close_socket(fd);
    if (err) *err = "nat_pmp_gateway_invalid";
    return std::nullopt;
  }

  auto send_and_wait = [&](const Bytes& req, Bytes* resp) -> bool {
    const int sent = ::sendto(fd, reinterpret_cast<const char*>(req.data()), static_cast<int>(req.size()), 0,
                              reinterpret_cast<const sockaddr*>(&gw), sizeof(gw));
    if (sent != static_cast<int>(req.size())) return false;
    if (!net::wait_readable(fd, std::max<std::uint32_t>(100, timeout_ms))) return false;
    std::array<std::uint8_t, 256> buf{};
    sockaddr_storage from{};
    socklen_t from_len = sizeof(from);
    const int n = ::recvfrom(fd, reinterpret_cast<char*>(buf.data()), static_cast<int>(buf.size()), 0,
                             reinterpret_cast<sockaddr*>(&from), &from_len);
    if (n <= 0) return false;
    resp->assign(buf.begin(), buf.begin() + n);
    return true;
  };

  // Step 1: external address request (opcode 0).
  Bytes ext_req(2, 0);
  ext_req[0] = 0;
  ext_req[1] = 0;
  Bytes ext_resp;
  if (!send_and_wait(ext_req, &ext_resp) || ext_resp.size() < 12) {
    net::close_socket(fd);
    if (err) *err = "nat_pmp_external_addr_timeout";
    return std::nullopt;
  }
  if (ext_resp[1] != 128 || ext_resp[0] != 0) {
    net::close_socket(fd);
    if (err) *err = "nat_pmp_external_addr_bad_response";
    return std::nullopt;
  }
  const std::uint16_t ext_result = static_cast<std::uint16_t>((ext_resp[2] << 8) | ext_resp[3]);
  if (ext_result != 0) {
    net::close_socket(fd);
    if (err) *err = "nat_pmp_external_addr_error_" + std::to_string(ext_result);
    return std::nullopt;
  }
  in_addr ext_ip{};
  std::memcpy(&ext_ip.s_addr, &ext_resp[8], sizeof(ext_ip.s_addr));
  char ext_ip_buf[INET_ADDRSTRLEN] = {};
  if (::inet_ntop(AF_INET, &ext_ip, ext_ip_buf, sizeof(ext_ip_buf)) == nullptr) {
    net::close_socket(fd);
    if (err) *err = "nat_pmp_external_addr_parse_failed";
    return std::nullopt;
  }

  // Step 2: TCP mapping request (opcode 2).
  Bytes map_req(12, 0);
  map_req[0] = 0;
  map_req[1] = 2;
  map_req[4] = static_cast<std::uint8_t>((private_port >> 8) & 0xFF);
  map_req[5] = static_cast<std::uint8_t>(private_port & 0xFF);
  map_req[6] = static_cast<std::uint8_t>((requested_public_port >> 8) & 0xFF);
  map_req[7] = static_cast<std::uint8_t>(requested_public_port & 0xFF);
  map_req[8] = static_cast<std::uint8_t>((lifetime_secs >> 24) & 0xFF);
  map_req[9] = static_cast<std::uint8_t>((lifetime_secs >> 16) & 0xFF);
  map_req[10] = static_cast<std::uint8_t>((lifetime_secs >> 8) & 0xFF);
  map_req[11] = static_cast<std::uint8_t>(lifetime_secs & 0xFF);

  Bytes map_resp;
  if (!send_and_wait(map_req, &map_resp) || map_resp.size() < 16) {
    net::close_socket(fd);
    if (err) *err = "nat_pmp_map_timeout";
    return std::nullopt;
  }
  net::close_socket(fd);
  if (map_resp[0] != 0 || map_resp[1] != 130) {
    if (err) *err = "nat_pmp_map_bad_response";
    return std::nullopt;
  }
  const std::uint16_t map_result = static_cast<std::uint16_t>((map_resp[2] << 8) | map_resp[3]);
  if (map_result != 0) {
    if (err) *err = "nat_pmp_map_error_" + std::to_string(map_result);
    return std::nullopt;
  }
  const std::uint16_t mapped_public_port = static_cast<std::uint16_t>((map_resp[10] << 8) | map_resp[11]);
  if (mapped_public_port == 0) {
    if (err) *err = "nat_pmp_map_zero_public_port";
    return std::nullopt;
  }
  return p2p::NetAddress{ext_ip_buf, mapped_public_port};
}

std::optional<std::string> parse_http_url_host_port_path(const std::string& url, std::uint16_t* port, std::string* host,
                                                         std::string* path) {
  constexpr const char* kHttp = "http://";
  if (url.rfind(kHttp, 0) != 0) return std::nullopt;
  const std::string rest = url.substr(std::strlen(kHttp));
  const auto slash = rest.find('/');
  const std::string host_port = slash == std::string::npos ? rest : rest.substr(0, slash);
  *path = slash == std::string::npos ? "/" : rest.substr(slash);
  const auto colon = host_port.rfind(':');
  if (colon == std::string::npos) {
    *host = host_port;
    *port = 80;
  } else {
    *host = host_port.substr(0, colon);
    try {
      *port = static_cast<std::uint16_t>(std::stoul(host_port.substr(colon + 1)));
    } catch (...) {
      return std::nullopt;
    }
  }
  if (host->empty() || *port == 0 || path->empty()) return std::nullopt;
  return std::string{};
}

std::optional<std::string> http_request_ipv4(const std::string& host, std::uint16_t port, const std::string& request,
                                             std::uint32_t timeout_ms) {
  if (!net::ensure_sockets()) return std::nullopt;
  addrinfo hints{};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  addrinfo* res = nullptr;
  if (::getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res) != 0 || !res) return std::nullopt;

  net::SocketHandle fd = net::kInvalidSocket;
  for (addrinfo* it = res; it != nullptr; it = it->ai_next) {
    fd = ::socket(it->ai_family, it->ai_socktype, it->ai_protocol);
    if (!net::valid_socket(fd)) continue;
    net::set_close_on_exec(fd);
    (void)net::set_socket_timeouts(fd, timeout_ms);
    if (::connect(fd, it->ai_addr, it->ai_addrlen) == 0) break;
    net::close_socket(fd);
    fd = net::kInvalidSocket;
  }
  freeaddrinfo(res);
  if (!net::valid_socket(fd)) return std::nullopt;

  std::size_t sent = 0;
  while (sent < request.size()) {
    const int n = ::send(fd, request.data() + sent, static_cast<int>(request.size() - sent), 0);
    if (n <= 0) {
      net::close_socket(fd);
      return std::nullopt;
    }
    sent += static_cast<std::size_t>(n);
  }

  std::string out;
  std::array<char, 4096> buf{};
  while (true) {
    const int n = ::recv(fd, buf.data(), static_cast<int>(buf.size()), 0);
    if (n <= 0) break;
    out.append(buf.data(), buf.data() + n);
    if (out.size() > (2 * 1024 * 1024)) break;
  }
  net::close_socket(fd);
  if (out.empty()) return std::nullopt;
  return out;
}

std::optional<std::string> http_body_from_response(const std::string& resp) {
  const auto pos = resp.find("\r\n\r\n");
  if (pos == std::string::npos) return std::nullopt;
  return resp.substr(pos + 4);
}

std::optional<std::string> xml_tag_value(const std::string& xml, const std::string& tag) {
  const std::string open = "<" + tag + ">";
  const std::string close = "</" + tag + ">";
  const auto s = xml.find(open);
  if (s == std::string::npos) return std::nullopt;
  const auto e = xml.find(close, s + open.size());
  if (e == std::string::npos) return std::nullopt;
  return xml.substr(s + open.size(), e - (s + open.size()));
}

std::optional<std::string> upnp_igd_discover_location(std::uint32_t timeout_ms) {
  if (!net::ensure_sockets()) return std::nullopt;
  net::SocketHandle fd = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (!net::valid_socket(fd)) return std::nullopt;
  net::set_close_on_exec(fd);
  (void)net::set_nonblocking(fd, true);

  const std::string req =
      "M-SEARCH * HTTP/1.1\r\n"
      "HOST: 239.255.255.250:1900\r\n"
      "MAN: \"ssdp:discover\"\r\n"
      "MX: 1\r\n"
      "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n";
  sockaddr_in mcast{};
  mcast.sin_family = AF_INET;
  mcast.sin_port = htons(1900);
  if (::inet_pton(AF_INET, "239.255.255.250", &mcast.sin_addr) != 1) {
    net::close_socket(fd);
    return std::nullopt;
  }
  const int sent = ::sendto(fd, req.data(), static_cast<int>(req.size()), 0, reinterpret_cast<sockaddr*>(&mcast), sizeof(mcast));
  if (sent <= 0) {
    net::close_socket(fd);
    return std::nullopt;
  }

  const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(std::max<std::uint32_t>(200, timeout_ms));
  std::array<char, 4096> buf{};
  while (std::chrono::steady_clock::now() < deadline) {
    if (!net::wait_readable(fd, 100)) continue;
    sockaddr_storage from{};
    socklen_t from_len = sizeof(from);
    const int n = ::recvfrom(fd, buf.data(), static_cast<int>(buf.size()), 0, reinterpret_cast<sockaddr*>(&from), &from_len);
    if (n <= 0) continue;
    std::string s(buf.data(), buf.data() + n);
    std::string lower = s;
    std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    const auto lp = lower.find("\nlocation:");
    if (lp == std::string::npos) continue;
    const auto start = s.find(':', lp) + 1;
    const auto end = s.find('\n', start);
    if (start == std::string::npos || end == std::string::npos) continue;
    std::string loc = s.substr(start, end - start);
    while (!loc.empty() && (loc.front() == ' ' || loc.front() == '\t' || loc.front() == '\r')) loc.erase(loc.begin());
    while (!loc.empty() && (loc.back() == '\r' || loc.back() == ' ' || loc.back() == '\t')) loc.pop_back();
    net::close_socket(fd);
    if (!loc.empty()) return loc;
  }
  net::close_socket(fd);
  return std::nullopt;
}

std::optional<p2p::NetAddress> upnp_igd_map_tcp_endpoint(std::uint16_t private_port, std::uint16_t requested_public_port,
                                                          std::uint32_t lease_secs, std::uint32_t timeout_ms,
                                                          std::string* err) {
  auto location = upnp_igd_discover_location(timeout_ms);
  if (!location.has_value()) {
    if (err) *err = "upnp_discovery_failed";
    return std::nullopt;
  }

  std::uint16_t loc_port = 0;
  std::string loc_host;
  std::string loc_path;
  if (!parse_http_url_host_port_path(*location, &loc_port, &loc_host, &loc_path).has_value()) {
    if (err) *err = "upnp_location_invalid";
    return std::nullopt;
  }
  std::ostringstream get_req;
  get_req << "GET " << loc_path << " HTTP/1.1\r\nHost: " << loc_host << ":" << loc_port
          << "\r\nConnection: close\r\n\r\n";
  auto desc_resp = http_request_ipv4(loc_host, loc_port, get_req.str(), timeout_ms);
  if (!desc_resp.has_value()) {
    if (err) *err = "upnp_desc_fetch_failed";
    return std::nullopt;
  }
  auto desc_body = http_body_from_response(*desc_resp);
  if (!desc_body.has_value()) {
    if (err) *err = "upnp_desc_bad_http";
    return std::nullopt;
  }

  std::string service_type;
  std::size_t st_pos = desc_body->find("urn:schemas-upnp-org:service:WANIPConnection:");
  if (st_pos != std::string::npos) {
    const auto end = desc_body->find('<', st_pos);
    service_type = desc_body->substr(st_pos, end == std::string::npos ? std::string::npos : end - st_pos);
  } else {
    st_pos = desc_body->find("urn:schemas-upnp-org:service:WANPPPConnection:");
    if (st_pos != std::string::npos) {
      const auto end = desc_body->find('<', st_pos);
      service_type = desc_body->substr(st_pos, end == std::string::npos ? std::string::npos : end - st_pos);
    }
  }
  auto control_url = xml_tag_value(*desc_body, "controlURL");
  if (service_type.empty() || !control_url.has_value()) {
    if (err) *err = "upnp_igd_service_not_found";
    return std::nullopt;
  }
  std::string ctrl_path = *control_url;
  if (ctrl_path.rfind("http://", 0) == 0) {
    std::uint16_t cport = 0;
    std::string chost;
    std::string cpath;
    if (!parse_http_url_host_port_path(ctrl_path, &cport, &chost, &cpath).has_value()) {
      if (err) *err = "upnp_control_url_invalid";
      return std::nullopt;
    }
    loc_host = chost;
    loc_port = cport;
    ctrl_path = cpath;
  } else if (ctrl_path.empty() || ctrl_path[0] != '/') {
    ctrl_path = "/" + ctrl_path;
  }

  std::ostringstream add_body;
  add_body << "<?xml version=\"1.0\"?>"
           << "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" "
           << "s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">"
           << "<s:Body><u:AddPortMapping xmlns:u=\"" << service_type << "\">"
           << "<NewRemoteHost></NewRemoteHost>"
           << "<NewExternalPort>" << requested_public_port << "</NewExternalPort>"
           << "<NewProtocol>TCP</NewProtocol>"
           << "<NewInternalPort>" << private_port << "</NewInternalPort>"
           << "<NewInternalClient>0.0.0.0</NewInternalClient>"
           << "<NewEnabled>1</NewEnabled>"
           << "<NewPortMappingDescription>finalis-node</NewPortMappingDescription>"
           << "<NewLeaseDuration>" << lease_secs << "</NewLeaseDuration>"
           << "</u:AddPortMapping></s:Body></s:Envelope>";
  const std::string add_xml = add_body.str();
  std::ostringstream add_req;
  add_req << "POST " << ctrl_path << " HTTP/1.1\r\n"
          << "Host: " << loc_host << ":" << loc_port << "\r\n"
          << "Content-Type: text/xml; charset=\"utf-8\"\r\n"
          << "SOAPAction: \"" << service_type << "#AddPortMapping\"\r\n"
          << "Content-Length: " << add_xml.size() << "\r\n"
          << "Connection: close\r\n\r\n"
          << add_xml;
  auto add_resp = http_request_ipv4(loc_host, loc_port, add_req.str(), timeout_ms);
  if (!add_resp.has_value() || add_resp->find(" 200 ") == std::string::npos) {
    if (err) *err = "upnp_add_port_mapping_failed";
    return std::nullopt;
  }

  std::ostringstream ip_body;
  ip_body << "<?xml version=\"1.0\"?>"
          << "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" "
          << "s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">"
          << "<s:Body><u:GetExternalIPAddress xmlns:u=\"" << service_type
          << "\"></u:GetExternalIPAddress></s:Body></s:Envelope>";
  const std::string ip_xml = ip_body.str();
  std::ostringstream ip_req;
  ip_req << "POST " << ctrl_path << " HTTP/1.1\r\n"
         << "Host: " << loc_host << ":" << loc_port << "\r\n"
         << "Content-Type: text/xml; charset=\"utf-8\"\r\n"
         << "SOAPAction: \"" << service_type << "#GetExternalIPAddress\"\r\n"
         << "Content-Length: " << ip_xml.size() << "\r\n"
         << "Connection: close\r\n\r\n"
         << ip_xml;
  auto ip_resp = http_request_ipv4(loc_host, loc_port, ip_req.str(), timeout_ms);
  if (!ip_resp.has_value()) {
    if (err) *err = "upnp_get_external_ip_failed";
    return std::nullopt;
  }
  auto ip_resp_body = http_body_from_response(*ip_resp);
  if (!ip_resp_body.has_value()) {
    if (err) *err = "upnp_get_external_ip_bad_http";
    return std::nullopt;
  }
  auto external_ip = xml_tag_value(*ip_resp_body, "NewExternalIPAddress");
  if (!external_ip.has_value() || external_ip->empty()) {
    if (err) *err = "upnp_external_ip_missing";
    return std::nullopt;
  }
  return p2p::NetAddress{*external_ip, requested_public_port};
}

std::vector<std::string> resolve_ipv4_addresses(const std::string& host) {
  addrinfo hints{};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  addrinfo* res = nullptr;
  if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0 || res == nullptr) return {};

  std::set<std::string> unique;
  for (addrinfo* it = res; it != nullptr; it = it->ai_next) {
    if (!it->ai_addr || it->ai_family != AF_INET) continue;
    char buf[INET_ADDRSTRLEN] = {};
    const auto* sin = reinterpret_cast<const sockaddr_in*>(it->ai_addr);
    if (::inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf)) != nullptr) unique.insert(buf);
  }
  freeaddrinfo(res);
  return std::vector<std::string>(unique.begin(), unique.end());
}

std::set<std::string> local_ipv4_addresses() {
  std::set<std::string> ips;
#ifdef _WIN32
  char hostname[256] = {};
  if (::gethostname(hostname, sizeof(hostname) - 1) == 0) {
    for (const auto& ip : resolve_ipv4_addresses(hostname)) ips.insert(ip);
  }
#else
  ifaddrs* ifaddr = nullptr;
  if (::getifaddrs(&ifaddr) == 0 && ifaddr != nullptr) {
    for (ifaddrs* it = ifaddr; it != nullptr; it = it->ifa_next) {
      if (!it->ifa_addr || it->ifa_addr->sa_family != AF_INET) continue;
      char buf[INET_ADDRSTRLEN] = {};
      const auto* sin = reinterpret_cast<const sockaddr_in*>(it->ifa_addr);
      if (::inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf)) != nullptr) ips.insert(buf);
    }
    freeifaddrs(ifaddr);
  }
#endif
  ips.insert("127.0.0.1");
  return ips;
}

std::string local_software_version_fingerprint(const NetworkConfig& cfg, const ChainId& chain_id, std::uint32_t cv) {
  std::ostringstream oss;
  oss << finalis::node_software_version()
      << ";genesis=" << chain_id.genesis_hash_hex << ";network_id=" << network_id_hex(cfg) << ";cv=" << cv
      << ";crh=" << consensus_rules_fingerprint(cfg, chain_id, cv);
  return oss.str();
}

std::optional<std::string> software_fingerprint_value(const std::string& ua, const std::string& key) {
  const std::string needle = key + "=";
  std::size_t start = 0;
  while (start <= ua.size()) {
    std::size_t end = ua.find(';', start);
    if (end == std::string::npos) end = ua.size();
    const std::string part = ua.substr(start, end - start);
    if (part.rfind(needle, 0) == 0) return part.substr(needle.size());
    if (end == ua.size()) break;
    start = end + 1;
  }
  return std::nullopt;
}

Hash32 message_payload_id(const Bytes& payload) { return crypto::sha256(payload); }

}  // namespace

void Node::on_peer_event(int peer_id, p2p::PeerManager::PeerEventType type, const std::string& detail) {
  if (type == p2p::PeerManager::PeerEventType::CONNECTED) {
    {
      std::lock_guard<std::mutex> lk(mu_);
      peer_ip_cache_[peer_id] = endpoint_to_ip(detail);
      peer_inbound_cache_[peer_id] = p2p_.get_peer_info(peer_id).inbound;
      peer_keepalive_ms_[peer_id] = now_ms();
    }
    const auto info = p2p_.get_peer_info(peer_id);
    log_line("peer-connected peer_id=" + std::to_string(peer_id) + " dir=" + (info.inbound ? "inbound" : "outbound") +
             " endpoint=" + detail);
    const std::string ip = endpoint_to_ip(detail);
    if (!is_bootstrap_peer_ip(ip) && discipline_.is_banned(ip, now_unix())) {
      p2p_.disconnect_peer(peer_id);
      return;
    }
    if (!info.version_tx) send_version(peer_id);
    return;
  }
  if (type == p2p::PeerManager::PeerEventType::DISCONNECTED) {
    std::lock_guard<std::mutex> lk(mu_);
    const bool inbound = [&]() {
      auto it = peer_inbound_cache_.find(peer_id);
      if (it != peer_inbound_cache_.end()) return it->second;
      return false;
    }();
    log_line("peer-disconnected peer_id=" + std::to_string(peer_id) + " dir=" + (inbound ? "inbound" : "outbound") +
             " detail=" + detail);
    const bool had_round_activity =
        proposed_in_round_.find(std::make_pair(finalized_height_ + 1, current_round_)) != proposed_in_round_.end() ||
        local_vote_reservations_.find(std::make_pair(finalized_height_ + 1, current_round_)) !=
            local_vote_reservations_.end() ||
        local_timeout_vote_reservations_.find(std::make_pair(finalized_height_ + 1, current_round_)) !=
            local_timeout_vote_reservations_.end() ||
        !votes_.participants_for(finalized_height_ + 1, current_round_).empty() ||
        !timeout_votes_.signatures_for(finalized_height_ + 1, current_round_).empty();
    peer_ip_cache_.erase(peer_id);
    peer_inbound_cache_.erase(peer_id);
    peer_keepalive_ms_.erase(peer_id);
    peer_last_finalized_tip_request_ms_.erase(peer_id);
    peer_validator_pubkeys_.erase(peer_id);
    peer_finalized_tips_.erase(peer_id);
    peer_finalized_tip_seen_ms_.erase(peer_id);
    peer_ingress_tips_.erase(peer_id);
    getaddr_requested_peers_.erase(peer_id);
    msg_rate_buckets_.erase(peer_id);
    vote_verify_buckets_.erase(peer_id);
    tx_verify_buckets_.erase(peer_id);
    for (auto it = requested_ingress_ranges_.begin(); it != requested_ingress_ranges_.end();) {
      if (it->first.first == peer_id) {
        requested_ingress_range_sent_ms_.erase(it->first);
        it = requested_ingress_ranges_.erase(it);
      } else {
        ++it;
      }
    }
    for (auto it = requested_sync_height_peers_.begin(); it != requested_sync_height_peers_.end();) {
      if (it->first.second == peer_id) {
        it = requested_sync_height_peers_.erase(it);
      } else {
        ++it;
      }
    }
    for (auto it = requested_sync_heights_.begin(); it != requested_sync_heights_.end();) {
      const auto height = it->first;
      bool still_requested = false;
      for (const auto& [key, _when] : requested_sync_height_peers_) {
        if (key.first == height) {
          still_requested = true;
          break;
        }
      }
      if (!still_requested) {
        it = requested_sync_heights_.erase(it);
      } else {
        ++it;
      }
    }
    const auto current_height = finalized_height_ + 1;
    if (established_peer_count() == 0 && !single_node_bootstrap_active_locked(current_height)) {
      reconnect_round_reset_pending_ = true;
    }
    const bool should_reset_round_state =
        established_peer_count() == 0 && !single_node_bootstrap_active_locked(current_height) &&
        (current_round_ > 0 || had_round_activity);
    if (should_reset_round_state) {
      current_round_ = 0;
      proposed_in_round_.clear();
      local_vote_reservations_.clear();
      local_timeout_vote_reservations_.clear();
      votes_.clear_height(current_height);
      prevotes_.clear_height(current_height);
      timeout_votes_.clear_height(current_height);
      reseed_local_votes_locked(current_height);
      round_started_ms_ = now_ms();
      arm_round0_deadline_locked(round_started_ms_);
      log_line("peer-loss-reset height=" + std::to_string(current_height) + " reason=no-established-peers");
    }
    return;
  }
  if (type == p2p::PeerManager::PeerEventType::FRAME_INVALID) {
    const auto pi = p2p_.get_peer_info(peer_id);
    const std::string ip = pi.ip.empty() ? endpoint_to_ip(pi.endpoint) : pi.ip;
    const std::uint64_t tms = now_ms();
    bool should_log = false;
    {
      std::lock_guard<std::mutex> lk(mu_);
      auto& last = invalid_frame_log_ms_[ip];
      if (tms > last + 10'000) {
        should_log = true;
        last = tms;
      }
    }
    const std::string klass = token_value(detail, "class");
    if (should_log) {
      std::ostringstream oss;
      oss << "frame-parse-fail peer_id=" << peer_id << " dir=" << (pi.inbound ? "inbound" : "outbound")
          << " endpoint=" << pi.endpoint << " " << detail;
      log_line(oss.str());
      if (klass == "HTTP" || klass == "JSON") {
        log_line("peer sent HTTP/JSON bytes; likely dialing lightserver port (19444) instead of P2P");
      } else if (klass == "TLS") {
        log_line("peer sent TLS handshake bytes; do not place TLS/proxy in front of P2P port");
      } else if (token_value(detail, "reason") == "MAGIC_MISMATCH") {
        log_line("magic mismatch: peer is likely on a different network");
      }
    }
    score_peer(peer_id, p2p::MisbehaviorReason::INVALID_FRAME, "invalid-frame");
  } else if (type == p2p::PeerManager::PeerEventType::FRAME_TIMEOUT ||
             type == p2p::PeerManager::PeerEventType::HANDSHAKE_TIMEOUT) {
    const auto pi = p2p_.get_peer_info(peer_id);
    const std::string ip = pi.ip.empty() ? endpoint_to_ip(pi.endpoint) : pi.ip;
    log_line("peer-timeout peer_id=" + std::to_string(peer_id) + " dir=" + (pi.inbound ? "inbound" : "outbound") +
             " endpoint=" + pi.endpoint + " detail=" + detail + " stage=" +
             (type == p2p::PeerManager::PeerEventType::HANDSHAKE_TIMEOUT ? "handshake" : "frame"));
    if (!pi.inbound) {
      std::lock_guard<std::mutex> lk(mu_);
      peer_tx_relay_backoff_until_ms_[peer_id] = now_ms() + kTxRelayPeerBackoffMs;
    }
    if (bootstrap_template_mode_ && !bootstrap_validator_pubkey_.has_value() && is_bootstrap_peer_ip(ip)) {
      log_line("bootstrap-timeout peer_id=" + std::to_string(peer_id) + " ip=" + ip + " note=timeout");
      return;
    }
    score_peer(peer_id, type == p2p::PeerManager::PeerEventType::HANDSHAKE_TIMEOUT
                            ? p2p::MisbehaviorReason::HANDSHAKE_TIMEOUT
                            : p2p::MisbehaviorReason::INVALID_FRAME,
               type == p2p::PeerManager::PeerEventType::HANDSHAKE_TIMEOUT ? "handshake-timeout" : "timeout");
  } else if (type == p2p::PeerManager::PeerEventType::QUEUE_OVERFLOW) {
    score_peer(peer_id, p2p::MisbehaviorReason::RATE_LIMIT, "queue-overflow");
  } else if (type == p2p::PeerManager::PeerEventType::MESSAGE_RX) {
    log_line("peer-message-rx peer_id=" + std::to_string(peer_id) + " " + detail);
  }
}

std::optional<std::string> Node::detect_possible_public_ip() const {
  char hostname[256] = {};
  if (::gethostname(hostname, sizeof(hostname) - 1) != 0) return std::nullopt;
  addrinfo hints{};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  addrinfo* result = nullptr;
  if (::getaddrinfo(hostname, nullptr, &hints, &result) != 0) return std::nullopt;
  std::optional<std::string> out;
  for (addrinfo* it = result; it != nullptr; it = it->ai_next) {
    auto* sin = reinterpret_cast<sockaddr_in*>(it->ai_addr);
    char buf[INET_ADDRSTRLEN] = {};
    if (!::inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf))) continue;
    const std::string ip(buf);
    if (is_local_only_bind(ip) || ip.rfind("127.", 0) == 0) continue;
    out = ip;
    break;
  }
  ::freeaddrinfo(result);
  return out;
}

void Node::send_version(int peer_id) {
  auto tip = db_.get_tip();
  p2p::VersionMsg v;
  v.timestamp = now_unix();
  v.proto_version = static_cast<std::uint32_t>(cfg_.network.protocol_version);
  v.network_id = cfg_.network.network_id;
  v.feature_flags = cfg_.network.feature_flags;
  v.nonce = static_cast<std::uint32_t>(cfg_.node_id + 1000);
  v.start_height = tip ? tip->height : 0;
  v.start_hash = tip ? tip->hash : zero_hash();
  v.node_software_version = local_software_version_fingerprint(cfg_.network, chain_id_, kFixedValidationRulesVersion);
  if (bootstrap_validator_pubkey_.has_value()) {
    v.node_software_version +=
        ";bootstrap_validator=" + hex_encode(Bytes(bootstrap_validator_pubkey_->begin(), bootstrap_validator_pubkey_->end()));
  }
  if (auto advertised = current_advertised_endpoint(); advertised.has_value()) {
    v.node_software_version += ";external_endpoint=" + advertised->key();
  }
  v.node_software_version +=
      ";validator_pubkey=" + hex_encode(Bytes(local_key_.public_key.begin(), local_key_.public_key.end()));

  const bool ok = p2p_.send_to(peer_id, p2p::MsgType::VERSION, p2p::ser_version(v));
  log_line(std::string("send ") + msg_type_name(p2p::MsgType::VERSION) + " peer_id=" + std::to_string(peer_id) +
           " start_height=" + std::to_string(v.start_height) + " start_hash=" + short_hash_hex(v.start_hash) +
           " status=" + (ok ? "ok" : "failed"));
  if (ok) p2p_.mark_handshake_tx(peer_id, true, false);
}

void Node::maybe_send_verack(int peer_id) {
  const bool ok = p2p_.send_to(peer_id, p2p::MsgType::VERACK, {});
  log_line(std::string("send ") + msg_type_name(p2p::MsgType::VERACK) + " peer_id=" + std::to_string(peer_id) +
           " status=" + (ok ? "ok" : "failed"));
  if (ok) p2p_.mark_handshake_tx(peer_id, false, true);
}

void Node::send_ping(int peer_id) {
  const p2p::PingMsg ping{now_ms()};
  const bool ok = p2p_.send_to(peer_id, p2p::MsgType::PING, p2p::ser_ping(ping), true);
  log_line(std::string("send ") + msg_type_name(p2p::MsgType::PING) + " peer_id=" + std::to_string(peer_id) +
           " nonce=" + std::to_string(ping.nonce) + " status=" + (ok ? "ok" : "failed"));
}

void Node::request_epoch_tickets(int peer_id, std::uint64_t epoch, std::uint32_t max_tickets) {
  const bool ok =
      p2p_.send_to(peer_id, p2p::MsgType::GET_EPOCH_TICKETS, p2p::ser_get_epoch_tickets(p2p::GetEpochTicketsMsg{epoch, max_tickets}));
  log_line("epoch-reconcile-request peer_id=" + std::to_string(peer_id) + " epoch=" + std::to_string(epoch) +
           " max_tickets=" + std::to_string(max_tickets) + " status=" + (ok ? "ok" : "failed"));
}

void Node::handle_message(int peer_id, std::uint16_t msg_type, const Bytes& payload) {
  const FinalizedBroadcastFlushGuard flush_guard{this};  // destroyed last, after any mu_ scope
  if (!p2p::is_known_message_type(msg_type)) {
    score_peer(peer_id, p2p::MisbehaviorReason::INVALID_PAYLOAD, "unknown-msg-type");
    return;
  }

  const Hash32 payload_id = message_payload_id(payload);
  if (msg_type == p2p::MsgType::TRANSITION) {
    log_line("sync-recv-entry peer_id=" + std::to_string(peer_id) + " type=TRANSITION payload_id=" +
             short_hash_hex(payload_id) + " payload_size=" + std::to_string(payload.size()));
  }
  bool known_invalid = false;
  bool rate_limited = false;
  {
    std::lock_guard<std::mutex> lk(mu_);
    if (invalid_message_payloads_.contains(payload_id)) {
      known_invalid = true;
    } else {
      bool bypass_rate_limit = false;
      if (msg_type == p2p::MsgType::TRANSITION) {
        const bool sync_backlog = !requested_sync_heights_.empty() || !requested_sync_artifacts_.empty();
        bool peer_is_ahead = false;
        if (auto it = peer_finalized_tips_.find(peer_id); it != peer_finalized_tips_.end()) {
          peer_is_ahead = it->second.height > finalized_height_;
        }
        // During forward sync, dropping TRANSITION frames via generic msg-rate
        // control can deadlock catch-up at next_height. peer_is_ahead rests on an
        // unverified FINALIZED_TIP claim, so sync uses a larger but still bounded bucket.
        if (sync_backlog || peer_is_ahead) bypass_rate_limit = true;
      }
      rate_limited = bypass_rate_limit ? !check_sync_transition_rate_limit_locked(peer_id)
                                       : !check_rate_limit_locked(peer_id, msg_type);
    }
  }
  if (known_invalid) {
    log_line("sync-recv-drop peer_id=" + std::to_string(peer_id) + " type=" +
             std::string(msg_type_name(msg_type)) + " reason=known-invalid-payload payload_id=" +
             short_hash_hex(payload_id) + " payload_size=" + std::to_string(payload.size()));
    score_peer(peer_id, p2p::MisbehaviorReason::DUPLICATE_SPAM, "known-invalid-payload");
    return;
  }
  if (rate_limited) {
    log_line("sync-recv-drop peer_id=" + std::to_string(peer_id) + " type=" + std::string(msg_type_name(msg_type)) +
             " reason=rate-limited payload_size=" + std::to_string(payload.size()));
    score_peer(peer_id, p2p::MisbehaviorReason::RATE_LIMIT, "msg-rate");
    return;
  }

  if (msg_type == p2p::MsgType::VERSION) return on_version(peer_id, payload);

  if (msg_type == p2p::MsgType::VERACK) return on_verack(peer_id, payload);

  const auto info = p2p_.get_peer_info(peer_id);
  if (!info.established()) {
    const bool bootstrap_sync_msg =
        msg_type == p2p::MsgType::GET_FINALIZED_TIP || msg_type == p2p::MsgType::FINALIZED_TIP ||
        msg_type == p2p::MsgType::GET_TRANSITION || msg_type == p2p::MsgType::TRANSITION ||
        msg_type == p2p::MsgType::GET_INGRESS_TIPS || msg_type == p2p::MsgType::INGRESS_TIPS ||
        msg_type == p2p::MsgType::GET_INGRESS_RANGE || msg_type == p2p::MsgType::INGRESS_RANGE;
    // After VERSION exchange and our VERACK transmit, the peer may already start
    // sync bootstrap traffic before we have observed its VERACK locally. Allow
    // these messages through instead of misclassifying them as pre-handshake
    // consensus traffic and dropping the first finalized-tip/block sync step.
    if (bootstrap_sync_msg && info.version_rx && info.version_tx && info.verack_tx) {
      // fall through
    } else {
      log_line("recv-drop peer_id=" + std::to_string(peer_id) + " type=" + msg_type_name(msg_type) +
               " reason=pre-handshake version_rx=" + std::to_string(info.version_rx) +
               " verack_rx=" + std::to_string(info.verack_rx) + " version_tx=" + std::to_string(info.version_tx) +
               " verack_tx=" + std::to_string(info.verack_tx));
      {
        std::lock_guard<std::mutex> lk(mu_);
        ++rejected_pre_handshake_;
      }
      score_peer(peer_id, p2p::MisbehaviorReason::PRE_HANDSHAKE_CONSENSUS, "pre-handshake-msg");
      return;
    }
  }

  switch (msg_type) {
    case p2p::MsgType::GET_FINALIZED_TIP:
      return on_get_finalized_tip(peer_id, payload);
    case p2p::MsgType::FINALIZED_TIP:
      return on_finalized_tip(peer_id, payload);
    case p2p::MsgType::GET_INGRESS_TIPS:
      return on_get_ingress_tips(peer_id, payload);
    case p2p::MsgType::INGRESS_TIPS:
      return on_ingress_tips(peer_id, payload);
    case p2p::MsgType::GET_INGRESS_RANGE:
      return on_get_ingress_range(peer_id, payload);
    case p2p::MsgType::INGRESS_RANGE:
      return on_ingress_range(peer_id, payload);
    case p2p::MsgType::INGRESS_RECORD:
      return on_ingress_record(peer_id, payload);
    case p2p::MsgType::GET_TRANSITION:
      return on_get_transition(peer_id, payload);
    case p2p::MsgType::GET_TRANSITION_BY_HEIGHT:
      return on_get_transition_by_height(peer_id, payload);
    case p2p::MsgType::EPOCH_TICKET:
      return on_epoch_ticket(peer_id, payload);
    case p2p::MsgType::GET_EPOCH_TICKETS:
      return on_get_epoch_tickets(peer_id, payload);
    case p2p::MsgType::EPOCH_TICKETS:
      return on_epoch_tickets(peer_id, payload);
    case p2p::MsgType::TRANSITION:
      return on_transition(peer_id, payload, payload_id);
    case p2p::MsgType::PROPOSE:
      return on_propose(peer_id, payload, payload_id);
    case p2p::MsgType::VOTE:
      return on_vote(peer_id, payload, payload_id);
    case p2p::MsgType::PREVOTE:
      return on_prevote(peer_id, payload, payload_id);
    case p2p::MsgType::TIMEOUT_VOTE:
      return on_timeout_vote(peer_id, payload, payload_id);
    case p2p::MsgType::TX:
      return on_tx(peer_id, payload, payload_id);
    case p2p::MsgType::GETADDR:
      return on_getaddr(peer_id, payload);
    case p2p::MsgType::ADDR:
      return on_addr(peer_id, payload);
    case p2p::MsgType::PING:
      return on_ping(peer_id, payload);
    case p2p::MsgType::PONG:
      return on_pong(peer_id, payload);
    default:
      break;
  }
}

void Node::on_version(int peer_id, const Bytes& payload) {
  constexpr std::uint16_t msg_type = p2p::MsgType::VERSION;
  auto v = p2p::de_version(payload);
  if (!v.has_value()) {
    score_peer(peer_id, p2p::MisbehaviorReason::INVALID_PAYLOAD, "bad-version");
    return;
  }
  // Duplicate VERSION on an established connection is intentional in bootstrap-template
  // mode: after self-bootstrap, the node refreshes peer metadata with the bound
  // bootstrap validator identity. This handler keeps VERSION processing idempotent.
  log_line("recv " + std::string(msg_type_name(msg_type)) + " peer_id=" + std::to_string(peer_id) +
           " start_height=" + std::to_string(v->start_height) + " start_hash=" + short_hash_hex(v->start_hash));
  if (v->network_id != cfg_.network.network_id) {
    {
      std::lock_guard<std::mutex> lk(mu_);
      ++rejected_network_id_;
    }
    log_line("reject-version peer_id=" + std::to_string(peer_id) + " reason=network-id-mismatch");
    score_peer(peer_id, p2p::MisbehaviorReason::INVALID_PAYLOAD, "network-id-mismatch");
    p2p_.disconnect_peer(peer_id);
    return;
  }
  if (v->proto_version != static_cast<std::uint32_t>(cfg_.network.protocol_version)) {
    {
      std::lock_guard<std::mutex> lk(mu_);
      ++rejected_protocol_version_;
    }
    log_line("reject-version peer_id=" + std::to_string(peer_id) + " reason=unsupported-protocol peer_proto=" +
             std::to_string(v->proto_version) + " local_proto=" + std::to_string(cfg_.network.protocol_version));
    p2p_.disconnect_peer(peer_id);
    return;
  }
  const std::string local_genesis = ascii_lower(chain_id_.genesis_hash_hex);
  const std::string local_nid = ascii_lower(network_id_hex(cfg_.network));
  const std::string local_crh = ascii_lower(consensus_rules_fingerprint(cfg_.network, chain_id_, kFixedValidationRulesVersion));
  const auto peer_genesis = software_fingerprint_value(v->node_software_version, "genesis");
  const auto peer_nid = software_fingerprint_value(v->node_software_version, "network_id");
  const auto peer_crh = software_fingerprint_value(v->node_software_version, "crh");
  const auto peer_bootstrap = software_fingerprint_value(v->node_software_version, "bootstrap_validator");
  const auto peer_validator = software_fingerprint_value(v->node_software_version, "validator_pubkey");
  const auto peer_external_endpoint = software_fingerprint_value(v->node_software_version, "external_endpoint");
  if (peer_genesis.has_value() && ascii_lower(*peer_genesis) != local_genesis) {
    log_line("reject-version peer_id=" + std::to_string(peer_id) + " reason=genesis-fingerprint-mismatch");
    p2p_.disconnect_peer(peer_id);
    return;
  }
  if (peer_nid.has_value() && ascii_lower(*peer_nid) != local_nid) {
    log_line("reject-version peer_id=" + std::to_string(peer_id) + " reason=network-id-fingerprint-mismatch");
    p2p_.disconnect_peer(peer_id);
    return;
  }
  if (!peer_crh.has_value()) {
    log_line("reject-version peer_id=" + std::to_string(peer_id) + " reason=missing-consensus-rules-fingerprint");
    p2p_.disconnect_peer(peer_id);
    return;
  }
  if (ascii_lower(*peer_crh) != local_crh) {
    log_line("reject-version peer_id=" + std::to_string(peer_id) + " reason=consensus-rules-fingerprint-mismatch peer_crh=" +
             ascii_lower(*peer_crh) + " local_crh=" + local_crh);
    p2p_.disconnect_peer(peer_id);
    return;
  }
  // Self-connection check, independent of whether this VERSION carries a
  // validator_pubkey fingerprint. endpoint_matches_local_listener compares
  // the ACTUAL observed connection endpoint (inbound or outbound) against
  // this node's own listener address, so a non-validator peer that happens
  // to be ourselves (e.g. a NAT-hairpinned self-dial via our own
  // externally-advertised endpoint) is still caught here, even though it
  // has no validator_pubkey for the identity-based check further below to
  // compare against. This runs in addition to, not instead of, that pubkey
  // check -- the two catch different self-connection shapes.
  // Only outbound endpoints carry the peer's listener port (the port we dialed);
  // an inbound source port is ephemeral, so inbound self-dials are left to the
  // identity check below.
  {
    const auto info = p2p_.get_peer_info(peer_id);
    const auto remote = info.inbound ? std::nullopt : p2p::parse_endpoint(info.endpoint);
    if (remote.has_value() && endpoint_matches_local_listener(info.ip, remote->port)) {
      bool should_log = false;
      {
        std::lock_guard<std::mutex> lk(mu_);
        should_log = suppress_self_endpoint_locked(info.endpoint);
        if (!info.ip.empty()) {
          should_log = suppress_self_endpoint_locked(info.ip + ":" + std::to_string(cfg_.p2p_port)) || should_log;
        }
      }
      if (should_log) {
        log_line("self-peer-rejected endpoint=" + info.endpoint + " reason=local-endpoint-match");
      }
      p2p_.disconnect_peer(peer_id);
      return;
    }
  }
  if (peer_bootstrap.has_value()) {
    auto b = hex_decode(*peer_bootstrap);
    if (b && b->size() == 32) {
      PubKey32 pub{};
      std::copy(b->begin(), b->end(), pub.begin());
      (void)maybe_adopt_bootstrap_validator_from_peer(peer_id, pub, v->start_height, "version-bootstrap");
    }
  }
  if (peer_validator.has_value()) {
    auto b = hex_decode(*peer_validator);
    if (b && b->size() == 32) {
      PubKey32 pub{};
      std::copy(b->begin(), b->end(), pub.begin());
      {
        std::lock_guard<std::mutex> lk(mu_);
        peer_validator_pubkeys_[peer_id] = pub;
      }
      if (!peer_bootstrap.has_value()) {
        (void)maybe_adopt_bootstrap_validator_from_peer(peer_id, pub, v->start_height, "version-validator-fallback");
      }
      if (pub == local_key_.public_key) {
        const auto info = p2p_.get_peer_info(peer_id);
        bool should_log = false;
        std::string display_endpoint = info.endpoint;
        {
          std::lock_guard<std::mutex> lk(mu_);
          peer_validator_pubkeys_.erase(peer_id);
          should_log = suppress_self_endpoint_locked(info.endpoint);
          if (!info.ip.empty()) {
            should_log = suppress_self_endpoint_locked(info.ip + ":" + std::to_string(cfg_.p2p_port)) || should_log;
            if (display_endpoint.empty()) display_endpoint = info.ip + ":" + std::to_string(cfg_.p2p_port);
          }
        }
        if (should_log) {
          log_line("self-peer-rejected endpoint=" + display_endpoint + " reason=identity-match");
        }
        p2p_.disconnect_peer(peer_id);
        return;
      }
    }
  }
  if (peer_external_endpoint.has_value() && endpoint_fingerprint_safe(*peer_external_endpoint)) {
    const auto advertised = p2p::parse_endpoint(*peer_external_endpoint);
    if (advertised.has_value() && advertised->port != 0 && !advertised->ip.empty()) {
      const auto info = p2p_.get_peer_info(peer_id);
      const std::string remote_ip = info.ip.empty() ? endpoint_to_ip(info.endpoint) : info.ip;
      if (!remote_ip.empty() && advertised->ip == remote_ip) {
        std::lock_guard<std::mutex> lk(mu_);
        addrman_.add_or_update(*advertised, now_unix());
      } else {
        log_line("ignore-peer-external-endpoint peer_id=" + std::to_string(peer_id) + " advertised=" +
                 advertised->key() + " reason=ip-mismatch");
      }
    }
  }
  p2p_.set_peer_handshake_meta(peer_id, v->proto_version, v->network_id, v->feature_flags);
  p2p_.mark_handshake_rx(peer_id, true, false);

  auto info = p2p_.get_peer_info(peer_id);
  if (!info.version_tx) send_version(peer_id);

  {
    auto i = p2p_.get_peer_info(peer_id);
    (void)i;
  }

  maybe_send_verack(peer_id);
  return;
}

void Node::on_verack(int peer_id, const Bytes& /*payload*/) {
  constexpr std::uint16_t msg_type = p2p::MsgType::VERACK;
  log_line("recv " + std::string(msg_type_name(msg_type)) + " peer_id=" + std::to_string(peer_id));
  p2p_.mark_handshake_rx(peer_id, false, true);
  maybe_request_getaddr(peer_id);
  send_finalized_tip(peer_id);
  request_finalized_tip(peer_id);
  send_ingress_tips(peer_id);
  request_ingress_tips(peer_id);
  {
    std::lock_guard<std::mutex> lk(mu_);
    const auto current_height = finalized_height_ + 1;
    if (reconnect_round_reset_pending_ && !single_node_bootstrap_active_locked(current_height)) {
      reconnect_round_reset_pending_ = false;
      current_round_ = 0;
      proposed_in_round_.clear();
      local_vote_reservations_.clear();
      local_timeout_vote_reservations_.clear();
      votes_.clear_height(current_height);
      prevotes_.clear_height(current_height);
      timeout_votes_.clear_height(current_height);
      reseed_local_votes_locked(current_height);
      round_started_ms_ = now_ms();
      arm_round0_deadline_locked(round_started_ms_);
      log_line("peer-reconnect-reset height=" + std::to_string(current_height) + " reason=peers-restored");
    }
  }
  auto pi = p2p_.get_peer_info(peer_id);
  auto na = addrman_address_for_peer(pi);
  if (na.has_value()) {
    std::lock_guard<std::mutex> lk(mu_);
    addrman_.mark_success(*na, now_unix());
  }
  return;
}

void Node::on_get_finalized_tip(int peer_id, const Bytes& /*payload*/) {
  constexpr std::uint16_t msg_type = p2p::MsgType::GET_FINALIZED_TIP;
  log_line("recv " + std::string(msg_type_name(msg_type)) + " peer_id=" + std::to_string(peer_id));
  send_finalized_tip(peer_id);
  return;
}

void Node::on_finalized_tip(int peer_id, const Bytes& payload) {
  constexpr std::uint16_t msg_type = p2p::MsgType::FINALIZED_TIP;
  auto tip = p2p::de_finalized_tip(payload);
  if (!tip.has_value()) {
    score_peer(peer_id, p2p::MisbehaviorReason::INVALID_PAYLOAD, "bad-finalized-tip");
    return;
  }
  log_line("recv " + std::string(msg_type_name(msg_type)) + " peer_id=" + std::to_string(peer_id) +
           " height=" + std::to_string(tip->height) + " hash=" + short_hash_hex(tip->hash));
  {
    std::lock_guard<std::mutex> lk(mu_);
    peer_finalized_tips_[peer_id] = *tip;
    peer_finalized_tip_seen_ms_[peer_id] = now_ms();
  }
  {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = peer_validator_pubkeys_.find(peer_id);
    if (it != peer_validator_pubkeys_.end()) {
      (void)maybe_adopt_bootstrap_validator_from_peer(peer_id, it->second, tip->height, "finalized-tip-fallback");
    }
    (void)maybe_request_forward_sync_block_locked(peer_id);
    const std::uint64_t retry_ms =
        std::max<std::uint64_t>(3000, static_cast<std::uint64_t>(cfg_.network.round_timeout_ms));
    const std::uint64_t tms = now_ms();
    auto req_it = requested_sync_artifacts_.find(tip->hash);
    const bool request_stale = req_it == requested_sync_artifacts_.end() || tms >= req_it->second + retry_ms;
    const bool have_tip_artifact = db_.get_frontier_transition(tip->hash).has_value();
    if (tip->height > finalized_height_ && !have_tip_artifact && request_stale) {
      log_line("request-sync-tip-transition peer_id=" + std::to_string(peer_id) + " remote_height=" +
               std::to_string(tip->height) + " remote_hash=" + short_hash_hex(tip->hash));
      requested_sync_artifacts_[tip->hash] = tms;
      auto req = p2p::GetTransitionMsg{tip->hash};
      (void)p2p_.send_to(peer_id, p2p::MsgType::GET_TRANSITION, p2p::ser_get_transition(req));
    }
  }
  request_ingress_tips(peer_id);
  return;
}

void Node::on_getaddr(int peer_id, const Bytes& payload) {
  auto req = p2p::de_getaddr(payload);
  if (!req.has_value()) {
    score_peer(peer_id, p2p::MisbehaviorReason::INVALID_PAYLOAD, "bad-getaddr");
    return;
  }
  p2p::AddrMsg msg;
  {
    std::lock_guard<std::mutex> lk(mu_);
    const auto addrs = addrman_.select_candidates(256, now_unix());
    msg.entries.reserve(addrs.size());
    for (const auto& a : addrs) {
      p2p::AddrEntryMsg e;
      std::array<std::uint8_t, 16> bin{};
      if (inet_pton(AF_INET, a.ip.c_str(), bin.data()) == 1) {
        e.ip_version = 4;
      } else if (inet_pton(AF_INET6, a.ip.c_str(), bin.data()) == 1) {
        e.ip_version = 6;
      } else {
        continue;
      }
      e.ip = bin;
      e.port = a.port;
      e.last_seen_unix = now_unix();
      msg.entries.push_back(e);
    }
  }
  (void)p2p_.send_to(peer_id, p2p::MsgType::ADDR, p2p::ser_addr(msg), true);
  return;
}

void Node::on_addr(int peer_id, const Bytes& payload) {
  auto msg = p2p::de_addr(payload);
  if (!msg.has_value()) {
    score_peer(peer_id, p2p::MisbehaviorReason::INVALID_PAYLOAD, "bad-addr");
    return;
  }
  std::lock_guard<std::mutex> lk(mu_);
  for (const auto& e : msg->entries) {
    char ipbuf[INET6_ADDRSTRLEN]{};
    const char* s = nullptr;
    if (e.ip_version == 4) {
      s = inet_ntop(AF_INET, e.ip.data(), ipbuf, sizeof(ipbuf));
    } else if (e.ip_version == 6) {
      s = inet_ntop(AF_INET6, e.ip.data(), ipbuf, sizeof(ipbuf));
    }
    if (!s || e.port == 0) continue;
    const p2p::NetAddress na{std::string(ipbuf), e.port};
    const auto reject = addrman_.validate(na);
    if (reject != p2p::AddrRejectReason::NONE) {
      const std::string reason = (reject == p2p::AddrRejectReason::PORT_MISMATCH)   ? "port"
                                 : (reject == p2p::AddrRejectReason::UNROUTABLE_IP) ? "unroutable"
                                                                                     : "invalid";
      const std::string log_key = reason + ":" + na.ip;
      auto& last = addr_drop_log_ms_[log_key];
      const std::uint64_t now = now_ms();
      if (now > last + 10'000) {
        last = now;
        log_line("drop-addr peer_id=" + std::to_string(peer_id) + " ip=" + na.ip + ":" + std::to_string(na.port) +
                 " reason=" + reason);
      }
      continue;
    }
    addrman_.add_or_update(na, e.last_seen_unix);
  }
  return;
}

void Node::on_ping(int peer_id, const Bytes& payload) {
  constexpr std::uint16_t msg_type = p2p::MsgType::PING;
  auto ping = p2p::de_ping(payload);
  if (!ping.has_value()) {
    score_peer(peer_id, p2p::MisbehaviorReason::INVALID_PAYLOAD, "bad-ping");
    return;
  }
  log_line("recv " + std::string(msg_type_name(msg_type)) + " peer_id=" + std::to_string(peer_id) +
           " nonce=" + std::to_string(ping->nonce));
  const bool ok = p2p_.send_to(peer_id, p2p::MsgType::PONG, p2p::ser_ping(*ping), true);
  log_line(std::string("send ") + msg_type_name(p2p::MsgType::PONG) + " peer_id=" + std::to_string(peer_id) +
           " nonce=" + std::to_string(ping->nonce) + " status=" + (ok ? "ok" : "failed"));
  return;
}

void Node::on_pong(int peer_id, const Bytes& payload) {
  constexpr std::uint16_t msg_type = p2p::MsgType::PONG;
  auto pong = p2p::de_ping(payload);
  if (!pong.has_value()) {
    score_peer(peer_id, p2p::MisbehaviorReason::INVALID_PAYLOAD, "bad-pong");
    return;
  }
  log_line("recv " + std::string(msg_type_name(msg_type)) + " peer_id=" + std::to_string(peer_id) +
           " nonce=" + std::to_string(pong->nonce));
  return;
}

void Node::broadcast_propose(const p2p::ProposeMsg& p) {
  if (cfg_.disable_p2p) {
    for_each_local_bus_peer([&](Node* peer) { spawn_local_bus_task([peer, p]() { peer->handle_propose(p, true); }); });
  } else {
    p2p_.broadcast(p2p::MsgType::PROPOSE, p2p::ser_propose(p));
  }
}

void Node::broadcast_epoch_ticket(const consensus::EpochTicket& ticket) {
  if (cfg_.disable_p2p) {
    for_each_local_bus_peer([&](Node* peer) {
      spawn_local_bus_task([peer, ticket]() { (void)peer->handle_epoch_ticket(ticket, true, 0); });
    });
  } else {
    p2p_.broadcast(p2p::MsgType::EPOCH_TICKET, p2p::ser_epoch_ticket(p2p::EpochTicketMsg{ticket}));
  }
}

void Node::broadcast_vote(const Vote& vote) {
  p2p::VoteMsg vm;
  vm.vote = vote;
  if (cfg_.disable_p2p) {
    for_each_local_bus_peer([&](Node* peer) {
      spawn_local_bus_task([peer, vm]() { (void)peer->handle_vote(vm.vote, true, 0); });
    });
  } else {
    p2p_.broadcast(p2p::MsgType::VOTE, p2p::ser_vote(vm));
  }
}

void Node::broadcast_prevote(const Vote& vote) {
  p2p::PrevoteMsg vm;
  vm.vote = vote;
  if (cfg_.disable_p2p) {
    for_each_local_bus_peer([&](Node* peer) {
      spawn_local_bus_task([peer, vm]() { (void)peer->handle_prevote(vm.vote, true, 0); });
    });
  } else {
    p2p_.broadcast(p2p::MsgType::PREVOTE, p2p::ser_prevote(vm));
  }
}

void Node::broadcast_timeout_vote(const TimeoutVote& vote) {
  p2p::TimeoutVoteMsg vm;
  vm.vote = vote;
  if (cfg_.disable_p2p) {
    for_each_local_bus_peer([&](Node* peer) {
      spawn_local_bus_task([peer, vm]() { (void)peer->handle_timeout_vote(vm.vote, true, 0); });
    });
  } else {
    p2p_.broadcast(p2p::MsgType::TIMEOUT_VOTE, p2p::ser_timeout_vote(vm));
  }
}

void Node::flush_pending_finalized_broadcasts() {
  std::vector<std::pair<FrontierProposal, FinalityCertificate>> frontiers;
  std::optional<p2p::FinalizedTipMsg> tip;
  std::vector<Vote> precommits;
  {
    std::lock_guard<std::mutex> lk(mu_);
    frontiers.swap(pending_finalized_broadcasts_);
    precommits.swap(pending_local_precommits_);
    if (pending_finalized_tip_broadcast_) tip = p2p::FinalizedTipMsg{finalized_height_, finalized_identity_.id};
    pending_finalized_tip_broadcast_ = false;
  }
  for (const auto& vote : precommits) {
    broadcast_vote(vote);
    (void)handle_vote(vote, false, 0);
  }
  for (const auto& [proposal, certificate] : frontiers) broadcast_finalized_frontier(proposal, certificate);
  if (tip.has_value() && !cfg_.disable_p2p) {
    const Bytes payload = p2p::ser_finalized_tip(*tip);
    for (int peer_id : p2p_.peer_ids()) {
      if (!p2p_.get_peer_info(peer_id).established()) continue;
      (void)p2p_.send_to(peer_id, p2p::MsgType::FINALIZED_TIP, payload, true);
    }
  }
}

void Node::broadcast_finalized_frontier(const FrontierProposal& proposal, const FinalityCertificate& certificate) {
  const auto lane_certificates = load_finalized_lane_certificates(proposal.transition);
  if (cfg_.disable_p2p) {
    for_each_local_bus_peer([&](Node* peer) {
      spawn_local_bus_task([peer, proposal, certificate, lane_certificates]() {
        // Same hoist-before-lock shape as the live TRANSITION path in handle_message:
        // this local-bus simulation is itself running on its own task per peer, so
        // precheck_finality_certificate here is both correct and exercises the same
        // parallel-verify behavior multi-node tests rely on to look like real peers.
        const auto cert_check = peer->precheck_finality_certificate(certificate, proposal.transition);
        {
          std::lock_guard<std::mutex> lk(peer->mu_);
          (void)peer->handle_frontier_block_locked(proposal, certificate, lane_certificates, 0, true, cert_check);
        }
        peer->flush_pending_finalized_broadcasts();
      });
    });
  } else {
    p2p::TransitionMsg msg;
    msg.frontier_proposal_bytes = proposal.serialize();
    msg.certificate = certificate;
    msg.lane_certificates = lane_certificates;
    p2p_.broadcast(p2p::MsgType::TRANSITION, p2p::ser_transition(msg));
  }
}

void Node::broadcast_tx(const AnyTx& tx, int skip_peer_id) {
  if (cfg_.disable_p2p) {
    for_each_local_bus_peer([&](Node* peer) { spawn_local_bus_task([peer, tx]() { peer->handle_tx(tx, true); }); });
  } else {
    const auto payload = p2p::ser_tx(p2p::TxMsg{serialize_any_tx(tx)});
    const std::uint64_t now = now_ms();
    for (int id : p2p_.peer_ids()) {
      if (id == skip_peer_id) continue;
      if (should_mute_peer(id)) continue;
      {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = peer_tx_relay_backoff_until_ms_.find(id);
        if (it != peer_tx_relay_backoff_until_ms_.end() && now < it->second) continue;
      }
      (void)p2p_.send_to(id, p2p::MsgType::TX, payload, true);
    }
  }
}

void Node::broadcast_ingress_record(const IngressCertificate& cert, const Bytes& tx_bytes, int skip_peer_id) {
  if (cfg_.disable_p2p) {
    const p2p::IngressRecordMsg msg{cert, tx_bytes};
    for_each_local_bus_peer([&](Node* peer) {
      spawn_local_bus_task([peer, msg]() {
        std::lock_guard<std::mutex> lk(peer->mu_);
        bool appended = false;
        std::string ingress_error;
        if (!peer->handle_ingress_record_locked(0, msg, &appended, &ingress_error)) return;
        if (appended) peer->broadcast_ingress_record(msg.certificate, msg.tx_bytes);
      });
    });
  } else {
    const auto payload = p2p::ser_ingress_record(p2p::IngressRecordMsg{cert, tx_bytes});
    for (int id : p2p_.peer_ids()) {
      if (id == skip_peer_id) continue;
      (void)p2p_.send_to(id, p2p::MsgType::INGRESS_RECORD, payload, true);
    }
  }
}

void Node::load_persisted_peers() {
  if (bootstrap_template_mode_ && !bootstrap_validator_pubkey_.has_value()) return;
  const std::filesystem::path p = std::filesystem::path(cfg_.db_path) / "peers.dat";
  std::ifstream in(p);
  if (!in.good()) return;
  std::string line;
  while (std::getline(in, line)) {
    if (line.empty()) continue;
    for (const auto& ep : parse_endpoint_list(line)) {
      if (!ep.empty()) cfg_.peers.push_back(ep);
    }
  }
}

void Node::persist_peers() const {
  std::vector<p2p::PeerInfo> peers;
  peers.reserve(p2p_.peer_ids().size());
  for (int id : p2p_.peer_ids()) peers.push_back(p2p_.get_peer_info(id));
  persist_peers(peers);
}

void Node::persist_peers(const std::vector<p2p::PeerInfo>& peers) const {
  const std::filesystem::path p = std::filesystem::path(cfg_.db_path) / "peers.dat";
  std::ofstream out(p, std::ios::trunc);
  if (!out.good()) return;

  std::set<std::string> seen;
  for (const auto& ep : cfg_.peers) seen.insert(ep);
  for (const auto& ep : cfg_.seeds) seen.insert(ep);
  for (const auto& pi : peers) {
    if (auto na = addrman_address_for_peer(pi); na.has_value()) {
      seen.insert(na->key());
    }
  }
  for (const auto& ep : seen) out << ep << "\n";
}

void Node::load_addrman() {
  if (bootstrap_template_mode_ && !bootstrap_validator_pubkey_.has_value()) return;
  const std::filesystem::path p = std::filesystem::path(cfg_.db_path) / "addrman.dat";
  (void)addrman_.load(p.string());
}

void Node::persist_addrman() const {
  const std::filesystem::path p = std::filesystem::path(cfg_.db_path) / "addrman.dat";
  (void)addrman_.save(p.string());
}

void Node::load_validators_addrman() {
  if (bootstrap_template_mode_ && !bootstrap_validator_pubkey_.has_value()) return;
  const std::filesystem::path p = std::filesystem::path(cfg_.db_path) / "validators-addrman.dat";
  std::ifstream in(p);
  if (!in.good()) return;

  std::set<std::string> seen;
  std::size_t added = 0;
  std::string line;
  while (std::getline(in, line)) {
    if (line.empty() || line[0] == '#') continue;
    for (const auto& ep : parse_endpoint_list(line)) {
      if (ep.empty() || seen.find(ep) != seen.end()) continue;
      const auto parsed = p2p::parse_endpoint(ep);
      if (!parsed.has_value() || parsed->port == 0) continue;

      bool skip = false;
      {
        std::lock_guard<std::mutex> lk(mu_);
        skip = is_self_endpoint_suppressed_locked(ep);
      }
      if (skip) continue;
      if (endpoint_matches_local_listener(parsed->ip, parsed->port)) continue;

      addrman_.add_or_update(*parsed, now_unix());
      seen.insert(ep);
      ++added;
    }
  }
  {
    std::lock_guard<std::mutex> lk(mu_);
    validators_bootstrap_peers_.assign(seen.begin(), seen.end());
    prefer_validators_addrman_ = !validators_bootstrap_peers_.empty();
  }
  if (added > 0) {
    log_line("validators-addrman-load status=ok file=" + p.string() + " loaded=" + std::to_string(added));
    log_line("validators-addrman-overlay mode=enabled endpoints=" + std::to_string(added));
  }
}

void Node::persist_validators_addrman(const std::vector<p2p::PeerInfo>& peers) const {
  const std::filesystem::path p = std::filesystem::path(cfg_.db_path) / "validators-addrman.dat";
  std::set<std::string> merged_endpoints;
  const auto now = now_unix();
  const std::uint64_t ttl_cutoff = now > kValidatorsAddrmanEntryTtlSeconds ? now - kValidatorsAddrmanEntryTtlSeconds : 0;
  std::map<std::string, std::uint64_t> addrman_last_seen;
  for (const auto& entry : addrman_.all()) {
    addrman_last_seen[entry.addr.key()] = entry.last_seen;
  }

  std::ifstream in(p);
  if (in.good()) {
    std::string line;
    while (std::getline(in, line)) {
      if (line.empty() || line[0] == '#') continue;
      for (const auto& ep : parse_endpoint_list(line)) {
        if (ep.empty()) continue;
        const auto parsed = p2p::parse_endpoint(ep);
        if (!parsed.has_value() || parsed->port == 0) continue;
        if (endpoint_matches_local_listener(parsed->ip, parsed->port)) continue;
        const auto seen_it = addrman_last_seen.find(ep);
        if (seen_it != addrman_last_seen.end() && seen_it->second < ttl_cutoff) continue;
        merged_endpoints.insert(ep);
      }
    }
  }

  std::set<int> validator_peer_ids;
  {
    std::lock_guard<std::mutex> lk(mu_);
    const auto active_height = finalized_height_ + 1;
    for (const auto& [peer_id, pub] : peer_validator_pubkeys_) {
      if (!validators_.is_active_for_height(pub, active_height)) continue;
      validator_peer_ids.insert(peer_id);
    }
  }
  for (const auto& info : peers) {
    if (!info.established()) continue;
    if (validator_peer_ids.find(info.id) == validator_peer_ids.end()) continue;
    if (auto na = addrman_address_for_peer(info); na.has_value()) {
      merged_endpoints.insert(na->key());
    }
  }

  std::ofstream out(p, std::ios::trunc);
  if (!out.good()) return;
  out << "# finalis validators-addrman v1\n";
  for (const auto& ep : merged_endpoints) {
    const auto parsed = p2p::parse_endpoint(ep);
    if (!parsed.has_value() || parsed->port == 0) continue;
    if (endpoint_matches_local_listener(parsed->ip, parsed->port)) continue;
    out << ep << "\n";
  }
}

std::vector<std::string> Node::resolve_dns_seeds_once() const {
  std::vector<std::string> out;
  std::set<std::string> dedup;
  for (const auto& ep : cfg_.network.default_seeds) {
    const auto pos = ep.rfind(':');
    if (pos == std::string::npos) continue;
    const std::string host = ep.substr(0, pos);
    const std::string port = ep.substr(pos + 1);
    if (host.empty() || port.empty()) continue;
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    if (getaddrinfo(host.c_str(), port.c_str(), &hints, &res) != 0) continue;
    for (addrinfo* it = res; it != nullptr; it = it->ai_next) {
      char ipbuf[INET6_ADDRSTRLEN]{};
      if (it->ai_family == AF_INET) {
        auto* sa = reinterpret_cast<sockaddr_in*>(it->ai_addr);
        if (!inet_ntop(AF_INET, &sa->sin_addr, ipbuf, sizeof(ipbuf))) continue;
      } else if (it->ai_family == AF_INET6) {
        auto* sa = reinterpret_cast<sockaddr_in6*>(it->ai_addr);
        if (!inet_ntop(AF_INET6, &sa->sin6_addr, ipbuf, sizeof(ipbuf))) continue;
      } else {
        continue;
      }
      dedup.insert(std::string(ipbuf) + ":" + port);
    }
    freeaddrinfo(res);
  }
  out.assign(dedup.begin(), dedup.end());
  return out;
}

void Node::maybe_request_getaddr(int peer_id) {
  std::lock_guard<std::mutex> lk(mu_);
  if (!getaddr_requested_peers_.insert(peer_id).second) return;
  (void)p2p_.send_to(peer_id, p2p::MsgType::GETADDR, p2p::ser_getaddr(p2p::GetAddrMsg{}), true);
}

void Node::request_ingress_tips(int peer_id) {
  log_line("request-ingress-tips peer_id=" + std::to_string(peer_id));
  (void)p2p_.send_to(peer_id, p2p::MsgType::GET_INGRESS_TIPS, p2p::ser_get_ingress_tips(p2p::GetIngressTipsMsg{}), true);
}

void Node::send_ingress_tips(int peer_id) {
  p2p::IngressTipsMsg msg;
  {
    std::lock_guard<std::mutex> lk(mu_);
    msg.lane_tips = local_ingress_lane_tips_locked();
  }
  const bool ok = p2p_.send_to(peer_id, p2p::MsgType::INGRESS_TIPS, p2p::ser_ingress_tips(msg), true);
  std::ostringstream oss;
  oss << "send-ingress-tips peer_id=" << peer_id << " status=" << (ok ? "ok" : "failed") << " tips=";
  for (std::size_t lane = 0; lane < msg.lane_tips.size(); ++lane) {
    if (lane) oss << ",";
    oss << lane << ":" << msg.lane_tips[lane];
  }
  log_line(oss.str());
}

void Node::request_finalized_tip(int peer_id) {
  {
    std::lock_guard<std::mutex> lk(mu_);
    const std::uint64_t now = now_ms();
    constexpr std::uint64_t kFinalizedTipRequestCooldownMs = 1500;
    if (auto it = peer_last_finalized_tip_request_ms_.find(peer_id);
        it != peer_last_finalized_tip_request_ms_.end() && now < it->second + kFinalizedTipRequestCooldownMs) {
      return;
    }
    peer_last_finalized_tip_request_ms_[peer_id] = now;
  }
  log_line("request-finalized-tip peer_id=" + std::to_string(peer_id) + " local_height=" + std::to_string(finalized_height_) +
           " local_transition=" + short_hash_hex(finalized_identity_.id));
  (void)p2p_.send_to(peer_id, p2p::MsgType::GET_FINALIZED_TIP, Bytes{}, true);
}

void Node::send_finalized_tip(int peer_id) {
  // FINALIZED_TIP stays type-erased on the wire for compatibility; peers
  // exchange only the finalized identity value and reconstruct semantics
  // from mode/context locally.
  p2p::FinalizedTipMsg tip{finalized_height_, finalized_identity_.id};
  const bool ok = p2p_.send_to(peer_id, p2p::MsgType::FINALIZED_TIP, p2p::ser_finalized_tip(tip));
  log_line("send-finalized-tip peer_id=" + std::to_string(peer_id) + " height=" + std::to_string(tip.height) +
           " transition=" + short_hash_hex(tip.hash) + " status=" + (ok ? "ok" : "failed"));
}

bool Node::peer_is_fresh_for_epoch_reconcile_locked(int peer_id, std::uint64_t* peer_height,
                                                    std::uint64_t* max_peer_height) const {
  const auto info = p2p_.get_peer_info(peer_id);
  if (!info.established()) return false;
  const auto it = peer_finalized_tips_.find(peer_id);
  if (it == peer_finalized_tips_.end()) return false;
  const std::uint64_t local_peer_height = it->second.height;
  std::uint64_t observed_max_height = local_peer_height;
  bool observed_any = false;
  for (const auto& [id, tip] : peer_finalized_tips_) {
    const auto peer_info = p2p_.get_peer_info(id);
    if (!peer_info.established()) continue;
    observed_any = true;
    observed_max_height = std::max(observed_max_height, tip.height);
  }
  if (peer_height) *peer_height = local_peer_height;
  if (max_peer_height) *max_peer_height = observed_max_height;
  if (!observed_any) return false;
  // Ignore stale peers for historical epoch-ticket reconciliation; these
  // responses can diverge settlement replay inputs during bootstrap.
  if (observed_max_height > local_peer_height && (observed_max_height - local_peer_height) > 2) return false;
  return true;
}

bool Node::maybe_request_forward_sync_block_locked(int preferred_peer_id) {
  const std::uint64_t next_height = finalized_height_ + 1;
  std::uint64_t retry_ms =
      std::max<std::uint64_t>(3000, static_cast<std::uint64_t>(cfg_.network.round_timeout_ms));
  const std::uint64_t tms = now_ms();
  const std::uint64_t sync_gap = tms >= last_finalized_progress_ms_ ? (tms - last_finalized_progress_ms_) : 0;
  const auto status_snapshot = build_runtime_status_snapshot_locked(tms);
  const std::uint64_t finalized_lag = status_snapshot.finalized_lag;
  const std::uint64_t tip_freshness_ms =
      std::max<std::uint64_t>(kFinalizedTipFreshnessFloorMs, static_cast<std::uint64_t>(cfg_.network.round_timeout_ms) * 3);
  for (auto it = sync_height_rr_cursor_.begin(); it != sync_height_rr_cursor_.end();) {
    if (it->first < next_height) {
      it = sync_height_rr_cursor_.erase(it);
    } else {
      ++it;
    }
  }

  // If we have requested blocks but nothing has been finalized in a long time,
  // become more aggressive about retrying to unstick sync
  if (!requested_sync_heights_.empty()) {
    auto oldest_it = std::min_element(requested_sync_heights_.begin(), requested_sync_heights_.end(),
                                       [](const auto& a, const auto& b) { return a.second < b.second; });
    if (oldest_it != requested_sync_heights_.end()) {
      const std::uint64_t age_ms = tms - oldest_it->second;
      if (age_ms > 10000) {  // If oldest request is > 10s old, use shorter retry window
        retry_ms = 1000;
      } else if (age_ms > 5000) {  // If > 5s old, moderate retry
        retry_ms = std::min(retry_ms, static_cast<std::uint64_t>(2000));
      }
    }
  }

  if (sync_gap > 15'000) {
    retry_ms = std::min<std::uint64_t>(retry_ms, 1000);
  }
  if (finalized_lag > 16) {
    retry_ms = std::min<std::uint64_t>(retry_ms, 750);
  }

  auto eligible_peer = [&](int peer_id) {
    const auto info = p2p_.get_peer_info(peer_id);
    if (!info.established()) return false;
    auto tip_it = peer_finalized_tips_.find(peer_id);
    if (tip_it == peer_finalized_tips_.end()) return false;
    return tip_it->second.height >= next_height;
  };

  struct SyncPeerCandidate {
    int peer_id{0};
    std::uint64_t tip_height{0};
    bool fresh{false};
    bool active_validator{false};
  };

  std::vector<SyncPeerCandidate> eligible_peers;
  eligible_peers.reserve(peer_finalized_tips_.size());
  for (const auto& [peer_id, tip] : peer_finalized_tips_) {
    if (!eligible_peer(peer_id)) continue;
    bool active_validator = false;
    if (auto validator_it = peer_validator_pubkeys_.find(peer_id); validator_it != peer_validator_pubkeys_.end()) {
      active_validator = validators_.is_active_for_height(validator_it->second, finalized_height_ + 1);
    }
    bool fresh = false;
    if (auto seen_it = peer_finalized_tip_seen_ms_.find(peer_id); seen_it != peer_finalized_tip_seen_ms_.end()) {
      const std::uint64_t age_ms = tms >= seen_it->second ? (tms - seen_it->second) : 0;
      fresh = age_ms <= tip_freshness_ms;
    }
    eligible_peers.push_back(SyncPeerCandidate{
        .peer_id = peer_id,
        .tip_height = tip.height,
        .fresh = fresh,
        .active_validator = active_validator,
    });
  }
  if (eligible_peers.empty()) return false;

  const bool have_fresh_validator_peer = std::any_of(eligible_peers.begin(), eligible_peers.end(), [](const auto& c) {
    return c.active_validator && c.fresh;
  });
  const bool have_fresh_peer = std::any_of(eligible_peers.begin(), eligible_peers.end(), [](const auto& c) {
    return c.fresh;
  });
  bool strict_sync_sources = false;
  constexpr std::size_t kMinStrictValidatorPeers = 2;
  const bool high_lag_mode = finalized_lag >= 32 || sync_gap > 20'000;
  if (have_fresh_validator_peer) {
    std::vector<SyncPeerCandidate> tier1_only;
    tier1_only.reserve(eligible_peers.size());
    for (const auto& c : eligible_peers) {
      if (c.active_validator && c.fresh) tier1_only.push_back(c);
    }
    if (!tier1_only.empty() && (!high_lag_mode || tier1_only.size() >= kMinStrictValidatorPeers)) {
      eligible_peers.swap(tier1_only);
      strict_sync_sources = true;
    }
  } else if (have_fresh_peer) {
    std::vector<SyncPeerCandidate> fresh_only;
    fresh_only.reserve(eligible_peers.size());
    for (const auto& c : eligible_peers) {
      if (c.fresh) fresh_only.push_back(c);
    }
    if (!fresh_only.empty()) {
      eligible_peers.swap(fresh_only);
      strict_sync_sources = true;
    }
  }

  std::sort(eligible_peers.begin(), eligible_peers.end(), [](const auto& a, const auto& b) {
    if (a.active_validator != b.active_validator) return a.active_validator > b.active_validator;
    if (a.fresh != b.fresh) return a.fresh > b.fresh;
    if (a.tip_height != b.tip_height) return a.tip_height > b.tip_height;
    return a.peer_id < b.peer_id;
  });
  if (preferred_peer_id != 0) {
    auto it = std::find_if(eligible_peers.begin(), eligible_peers.end(),
                           [&](const auto& item) { return item.peer_id == preferred_peer_id; });
    if (it != eligible_peers.end() && it != eligible_peers.begin()) {
      std::rotate(eligible_peers.begin(), it, it + 1);
    }
  }
  const int target_peer = eligible_peers.front().peer_id;
  const std::uint64_t target_peer_height = eligible_peers.front().tip_height;

  if (target_peer_height > finalized_height_ &&
      !db_.get_finality_certificate_by_height(next_height).has_value()) {
    const auto outstanding = requested_sync_heights_.find(next_height);
    if (outstanding != requested_sync_heights_.end()) {
      const std::uint64_t age_ms = tms >= outstanding->second ? (tms - outstanding->second) : 0;
      const std::uint64_t no_progress_ms =
          tms >= last_finalized_progress_ms_ ? (tms - last_finalized_progress_ms_) : 0;
      const bool stale_enough = no_progress_ms >= 60'000;
      const bool age_enough = age_ms > std::max<std::uint64_t>(3000, retry_ms * 2);
      const bool cooldown_elapsed =
          (last_missing_next_cert_stall_log_ms_ == 0) || (tms >= last_missing_next_cert_stall_log_ms_ + 10'000);
      if (stale_enough && age_enough && cooldown_elapsed) {
        log_line("sync-stall reason=missing-certificate-for-next-height next_height=" + std::to_string(next_height) +
                 " local_height=" + std::to_string(finalized_height_) + " target_peer_id=" +
                 std::to_string(target_peer) + " target_peer_height=" + std::to_string(target_peer_height) +
                 " request_age_ms=" + std::to_string(age_ms) +
                 " no_progress_ms=" + std::to_string(no_progress_ms));
        last_missing_next_cert_stall_log_ms_ = tms;
      }
    }
  }

  const std::uint64_t dynamic_window =
      finalized_lag >= 256 ? 512 : finalized_lag >= 128 ? 256 : finalized_lag >= 32 ? 128 : kForwardSyncWindow;
  const std::uint64_t window_end = std::min(target_peer_height, finalized_height_ + dynamic_window);
  constexpr std::size_t kMaxSyncRequestsPerPeerPerSweep = kForwardSyncWindow;
  const std::size_t max_per_peer_per_sweep =
      strict_sync_sources ? std::min<std::size_t>(16u, eligible_peers.size() * 2) : kMaxSyncRequestsPerPeerPerSweep;
  std::unordered_map<int, std::size_t> sent_per_peer;
  sent_per_peer.reserve(eligible_peers.size());
  bool requested_any = false;
  for (std::uint64_t height = next_height; height <= window_end; ++height) {
    if (db_.get_height_hash(height).has_value()) continue;
    const auto outstanding = requested_sync_heights_.find(height);
    const std::uint64_t first_request_ms = (outstanding == requested_sync_heights_.end()) ? tms : outstanding->second;
    const std::uint64_t age_ms = tms >= first_request_ms ? (tms - first_request_ms) : 0;
    std::size_t fanout = sync_gap > 15'000
                             ? ((age_ms > retry_ms * 2) ? 3u : 2u)
                             : ((age_ms > retry_ms * 4) ? 3u : (age_ms > retry_ms * 2 ? 2u : 1u));
    if (high_lag_mode) fanout = std::max<std::size_t>(fanout, 2u);
    if (finalized_lag >= 128) fanout = std::max<std::size_t>(fanout, 3u);
    fanout = std::min<std::size_t>(fanout, eligible_peers.size());

    std::size_t sent_for_height = 0;
    const std::size_t candidate_count = eligible_peers.size();
    if (candidate_count == 0) break;
    auto& rr_cursor = sync_height_rr_cursor_[height];
    rr_cursor %= candidate_count;
    for (std::size_t step = 0; step < candidate_count; ++step) {
      const auto& candidate = eligible_peers[(rr_cursor + step) % candidate_count];
      const int peer_id = candidate.peer_id;
      if (sent_for_height >= fanout) break;
      auto sent_it = sent_per_peer.find(peer_id);
      if (sent_it != sent_per_peer.end() && sent_it->second >= max_per_peer_per_sweep) continue;
      auto req_it = requested_sync_height_peers_.find({height, peer_id});
      if (req_it != requested_sync_height_peers_.end() && tms < req_it->second + retry_ms) continue;

      if (outstanding == requested_sync_heights_.end()) requested_sync_heights_[height] = tms;
      requested_sync_height_peers_[{height, peer_id}] = tms;
      log_line("request-sync-next-height peer_id=" + std::to_string(peer_id) + " next_height=" +
               std::to_string(height) + " fanout=" + std::to_string(fanout));
      (void)p2p_.send_to(peer_id, p2p::MsgType::GET_TRANSITION_BY_HEIGHT,
                         p2p::ser_get_transition_by_height(p2p::GetTransitionByHeightMsg{height}), true);
      ++sent_per_peer[peer_id];
      requested_any = true;
      ++sent_for_height;
    }
    rr_cursor = (rr_cursor + std::max<std::size_t>(1, sent_for_height)) % candidate_count;
  }
  return requested_any;
}

bool Node::maybe_request_candidate_transition_locked(int peer_id, const Hash32& transition_id) {
  if (peer_id == 0 || cfg_.disable_p2p) return false;
  if (db_.get_frontier_transition(transition_id).has_value()) return false;
  if (candidate_frontier_proposals_.find(transition_id) != candidate_frontier_proposals_.end()) return false;

  const std::uint64_t retry_ms =
      std::max<std::uint64_t>(3000, static_cast<std::uint64_t>(cfg_.network.round_timeout_ms));
  const std::uint64_t tms = now_ms();
  if (auto it = requested_sync_artifacts_.find(transition_id); it != requested_sync_artifacts_.end() && tms < it->second + retry_ms) {
    return false;
  }

  requested_sync_artifacts_[transition_id] = tms;
  const bool ok = p2p_.send_to(peer_id, p2p::MsgType::GET_TRANSITION,
                               p2p::ser_get_transition(p2p::GetTransitionMsg{transition_id}), true);
  log_line("request-candidate-transition peer_id=" + std::to_string(peer_id) +
           " transition=" + short_hash_hex(transition_id) + " status=" + (ok ? "ok" : "failed"));
  return ok;
}

bool Node::seed_preflight_ok(const std::string& host, std::uint16_t port) {
  const std::string key = host + ":" + std::to_string(port);
  {
    std::lock_guard<std::mutex> lk(mu_);
    if (preflight_checked_seeds_.find(key) != preflight_checked_seeds_.end()) return true;
    preflight_checked_seeds_.insert(key);
  }

  // Avoid sacrificial TCP probes against public seeds. They look like real
  // inbound peers to a bootstrap node, trigger VERSION sends, and then close
  // before the actual handshake connection is attempted.
  if (!is_loopback_seed_host(host)) return true;

  addrinfo hints{};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  addrinfo* res = nullptr;
  if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res) != 0) return true;
  auto fd = net::kInvalidSocket;
  for (addrinfo* it = res; it != nullptr; it = it->ai_next) {
    fd = ::socket(it->ai_family, it->ai_socktype, it->ai_protocol);
    if (!net::valid_socket(fd)) continue;
    (void)net::set_socket_timeouts(fd, 1'000);
    if (::connect(fd, it->ai_addr, it->ai_addrlen) == 0) break;
    net::close_socket(fd);
    fd = net::kInvalidSocket;
  }
  freeaddrinfo(res);
  if (!net::valid_socket(fd)) return true;

  Bytes prefix;
  if (net::wait_readable(fd, 200)) {
    std::array<std::uint8_t, 16> tmp{};
    const ssize_t n = net::recv_nonblocking(fd, tmp.data(), tmp.size());
    if (n > 0) prefix.assign(tmp.begin(), tmp.begin() + n);
  }
  net::shutdown_socket(fd);
  net::close_socket(fd);

  if (prefix.empty()) return true;
  const auto kind = p2p::classify_prefix(prefix);
  if (kind == p2p::PrefixKind::HTTP || kind == p2p::PrefixKind::JSON) {
    log_line("seed preflight warning " + key + " appears HTTP/JSON; likely lightserver port");
    return false;
  }
  if (kind == p2p::PrefixKind::TLS) {
    log_line("seed preflight warning " + key + " appears TLS; do not put TLS/proxy in front of P2P");
    return false;
  }
  return true;
}

bool Node::endpoint_matches_local_listener(const std::string& host, std::uint16_t port,
                                           std::vector<std::string>* resolved_endpoints) const {
  if (!cfg_.listen || port != cfg_.p2p_port) return false;

  const auto resolved_ips = resolve_ipv4_addresses(host);
  if (resolved_ips.empty()) return false;

  auto local_ips = local_ipv4_addresses();
  const auto bind_ips = resolve_ipv4_addresses(cfg_.bind_ip);
  local_ips.insert(bind_ips.begin(), bind_ips.end());

  bool matched = false;
  for (const auto& ip : resolved_ips) {
    if (resolved_endpoints) resolved_endpoints->push_back(ip + ":" + std::to_string(port));
    if (local_ips.find(ip) != local_ips.end()) matched = true;
  }
  return matched;
}

void Node::try_connect_bootstrap_peers() {
  constexpr std::uint64_t kSyncBootstrapLagThreshold = 128;
  constexpr std::size_t kSyncBootstrapHealthyPeerThreshold = 2;

  struct Candidate {
    std::string peer;
    const char* source;
  };
  std::vector<Candidate> static_candidates;
  std::vector<Candidate> validator_candidates;
  std::vector<Candidate> addrman_candidates;
  std::set<std::string> seen;
  bool sync_bootstrap_mode = false;
  bool validator_overlay_mode = false;
  {
    std::lock_guard<std::mutex> lk(mu_);
    std::size_t healthy_established_peers = 0;
    std::uint64_t best_peer_height = finalized_height_;
    for (const auto& [peer_id, tip] : peer_finalized_tips_) {
      const auto info = p2p_.get_peer_info(peer_id);
      if (!info.established()) continue;
      ++healthy_established_peers;
      if (tip.height > best_peer_height) best_peer_height = tip.height;
    }
    const std::uint64_t finalized_lag = best_peer_height > finalized_height_ ? (best_peer_height - finalized_height_) : 0;
    sync_bootstrap_mode =
        finalized_lag > kSyncBootstrapLagThreshold || healthy_established_peers < kSyncBootstrapHealthyPeerThreshold;
    validator_overlay_mode = prefer_validators_addrman_ && !validators_bootstrap_peers_.empty();

    for (const auto& p : validators_bootstrap_peers_) {
      if (seen.insert(p).second) validator_candidates.push_back({p, "validators-addrman"});
    }
    if (!validator_overlay_mode) {
      for (const auto& p : bootstrap_peers_) {
        if (seen.insert(p).second) static_candidates.push_back({p, "seeds"});
      }
      for (const auto& p : dns_seed_peers_) {
        if (seen.insert(p).second) static_candidates.push_back({p, "dns"});
      }
    }
    if (!bootstrap_template_mode_ || bootstrap_validator_pubkey_.has_value()) {
      for (const auto& a : addrman_.select_candidates(cfg_.outbound_target * 2, now_unix())) {
        if (seen.insert(a.key()).second) addrman_candidates.push_back({a.key(), "addrman"});
      }
    }
  }

  auto attempt_candidates = [&](const std::vector<Candidate>& candidates) {
    for (const auto& candidate : candidates) {
      const auto& peer = candidate.peer;
      const auto pos = peer.find(':');
      if (pos == std::string::npos) continue;
      const std::string host = peer.substr(0, pos);
      std::uint16_t port = 0;
      try {
        port = static_cast<std::uint16_t>(std::stoi(peer.substr(pos + 1)));
      } catch (...) {
        continue;
      }
      std::vector<std::string> resolved_self_endpoints;
      if (endpoint_matches_local_listener(host, port, &resolved_self_endpoints)) {
        bool should_log = false;
        {
          std::lock_guard<std::mutex> lk(mu_);
          should_log = suppress_self_endpoint_locked(peer);
          for (const auto& endpoint : resolved_self_endpoints) {
            should_log = suppress_self_endpoint_locked(endpoint) || should_log;
          }
        }
        if (should_log) {
          log_line("self-peer-skip endpoint=" + peer + " reason=local-endpoint-match");
        }
        continue;
      }
      {
        std::lock_guard<std::mutex> lk(mu_);
        if (is_self_endpoint_suppressed_locked(peer)) continue;
      }
      if (has_peer_endpoint(host, port)) continue;
      if (!is_bootstrap_peer_ip(host) && discipline_.is_banned(host, now_unix())) continue;
      if (!seed_preflight_ok(host, port)) continue;
      log_line("peer-connect-attempt endpoint=" + peer + " source=" + candidate.source);
      {
        std::lock_guard<std::mutex> lk(mu_);
        addrman_.mark_attempt(p2p::NetAddress{host, port}, now_unix());
      }
      if (!p2p_.connect_to(host, port)) {
        log_line("peer-connect-failed endpoint=" + peer + " source=" + candidate.source + " reason=tcp-connect-failed");
        continue;
      }
      {
        std::lock_guard<std::mutex> lk(mu_);
        last_bootstrap_source_ = candidate.source;
        addrman_.mark_success(p2p::NetAddress{host, port}, now_unix());
      }
    }
  };

  auto established_active_validator_peers = [&]() -> std::size_t {
    std::lock_guard<std::mutex> lk(mu_);
    const std::uint64_t active_height = finalized_height_ + 1;
    std::size_t count = 0;
    for (const auto& [peer_id, pub] : peer_validator_pubkeys_) {
      if (!validators_.is_active_for_height(pub, active_height)) continue;
      const auto info = p2p_.get_peer_info(peer_id);
      if (!info.established()) continue;
      ++count;
    }
    return count;
  };

  attempt_candidates(validator_candidates);
  attempt_candidates(static_candidates);
  if (sync_bootstrap_mode && outbound_peer_count() >= cfg_.outbound_target) return;
  if (sync_bootstrap_mode && outbound_peer_count() > 0 && established_active_validator_peers() > 0) return;

  // In validator overlay mode, never fan out into generic addrman; keep
  // consensus connectivity pinned to validator-advertised endpoints.
  if (validator_overlay_mode) return;

  // In normal mode we blend in addrman for broader discovery.
  // In sync bootstrap mode we spill to addrman only when static/dns could not
  // establish any outbound path.
  attempt_candidates(addrman_candidates);
}

std::optional<p2p::NetAddress> Node::advertised_endpoint_locked() const {
  if (auto configured = advertised_endpoint_from_config(cfg_); configured.has_value()) return configured;
  if (!cfg_.listen || !cfg_.public_mode || cfg_.disable_p2p) return std::nullopt;
  if (nat_pmp_external_endpoint_.has_value()) return nat_pmp_external_endpoint_;
  if (upnp_igd_external_endpoint_.has_value()) return upnp_igd_external_endpoint_;
  if (stun_external_endpoint_.has_value()) return stun_external_endpoint_;
  return std::nullopt;
}

std::optional<p2p::NetAddress> Node::current_advertised_endpoint() const {
  std::lock_guard<std::mutex> lk(mu_);
  return advertised_endpoint_locked();
}

void Node::maybe_refresh_nat_pmp_external_endpoint(std::uint64_t now_ms) {
  if (cfg_.disable_p2p || !cfg_.listen || !cfg_.public_mode) return;
  if (!cfg_.nat_pmp_enabled) return;
  if (!cfg_.external_endpoint.empty()) return;
  if (cfg_.p2p_port == 0) return;

  {
    std::lock_guard<std::mutex> lk(mu_);
    if (nat_pmp_external_endpoint_.has_value() && nat_pmp_mapping_expires_ms_ != 0 &&
        now_ms > nat_pmp_mapping_expires_ms_ + std::max<std::uint32_t>(5'000, cfg_.nat_pmp_timeout_ms)) {
      nat_pmp_external_endpoint_.reset();
    }
    if (nat_pmp_next_refresh_ms_ != 0 && now_ms < nat_pmp_next_refresh_ms_) return;
  }

  auto gateway = linux_default_gateway_ipv4();
  if (!gateway.has_value()) {
    std::lock_guard<std::mutex> lk(mu_);
    nat_pmp_last_attempt_ms_ = now_ms;
    nat_pmp_last_success_ = false;
    nat_pmp_last_error_code_ = "nat_pmp_gateway_not_found";
    nat_pmp_next_refresh_ms_ = now_ms + std::max<std::uint32_t>(10'000, cfg_.stun_refresh_interval_ms);
    log_line("nat-pmp-refresh status=failed reason=gateway-not-found");
    return;
  }

  std::string error;
  const std::uint32_t lease_secs = std::max<std::uint32_t>(120, cfg_.stun_refresh_interval_ms / 1000U);
  auto mapped = nat_pmp_map_tcp_endpoint(*gateway, cfg_.p2p_port, cfg_.p2p_port, lease_secs, cfg_.nat_pmp_timeout_ms, &error);
  std::lock_guard<std::mutex> lk(mu_);
  nat_pmp_last_attempt_ms_ = now_ms;
  if (!mapped.has_value()) {
    nat_pmp_last_success_ = false;
    nat_pmp_last_error_code_ = error.empty() ? "nat_pmp_map_failed" : error;
    nat_pmp_next_refresh_ms_ = now_ms + std::max<std::uint32_t>(10'000, cfg_.stun_refresh_interval_ms);
    log_line("nat-pmp-refresh status=failed gateway=" + *gateway + " reason=" + nat_pmp_last_error_code_);
    return;
  }
  nat_pmp_external_endpoint_ = *mapped;
  nat_pmp_last_success_ = true;
  nat_pmp_last_error_code_.clear();
  nat_pmp_last_success_ms_ = now_ms;
  nat_pmp_mapping_expires_ms_ = now_ms + static_cast<std::uint64_t>(lease_secs) * 1000ULL;
  const std::uint64_t margin_ms = std::min<std::uint64_t>(
      std::max<std::uint32_t>(1'000, cfg_.nat_pmp_refresh_margin_ms), static_cast<std::uint64_t>(lease_secs) * 500ULL);
  nat_pmp_next_refresh_ms_ = nat_pmp_mapping_expires_ms_ > margin_ms ? nat_pmp_mapping_expires_ms_ - margin_ms : now_ms + 1'000;
  log_line("nat-pmp-refresh status=ok gateway=" + *gateway + " endpoint=" + nat_pmp_external_endpoint_->key());
}

void Node::maybe_refresh_upnp_igd_external_endpoint(std::uint64_t now_ms) {
  if (cfg_.disable_p2p || !cfg_.listen || !cfg_.public_mode) return;
  if (!cfg_.upnp_igd_enabled) return;
  if (!cfg_.external_endpoint.empty()) return;
  if (cfg_.p2p_port == 0) return;

  {
    std::lock_guard<std::mutex> lk(mu_);
    if (upnp_igd_external_endpoint_.has_value() && upnp_igd_mapping_expires_ms_ != 0 &&
        now_ms > upnp_igd_mapping_expires_ms_ + std::max<std::uint32_t>(5'000, cfg_.upnp_igd_timeout_ms)) {
      upnp_igd_external_endpoint_.reset();
    }
    if (upnp_igd_next_refresh_ms_ != 0 && now_ms < upnp_igd_next_refresh_ms_) return;
  }

  std::string error;
  const std::uint32_t lease_secs = std::max<std::uint32_t>(120, cfg_.upnp_igd_lease_seconds);
  auto mapped = upnp_igd_map_tcp_endpoint(cfg_.p2p_port, cfg_.p2p_port, lease_secs, cfg_.upnp_igd_timeout_ms, &error);
  std::lock_guard<std::mutex> lk(mu_);
  upnp_igd_last_attempt_ms_ = now_ms;
  if (!mapped.has_value()) {
    upnp_igd_last_success_ = false;
    upnp_igd_last_error_code_ = error.empty() ? "upnp_igd_map_failed" : error;
    upnp_igd_next_refresh_ms_ = now_ms + std::max<std::uint32_t>(10'000, cfg_.stun_refresh_interval_ms);
    log_line("upnp-igd-refresh status=failed reason=" + upnp_igd_last_error_code_);
    return;
  }
  upnp_igd_external_endpoint_ = *mapped;
  upnp_igd_last_success_ = true;
  upnp_igd_last_error_code_.clear();
  upnp_igd_last_success_ms_ = now_ms;
  upnp_igd_mapping_expires_ms_ = now_ms + static_cast<std::uint64_t>(lease_secs) * 1000ULL;
  const std::uint64_t margin_ms = std::min<std::uint64_t>(
      std::max<std::uint32_t>(1'000, cfg_.upnp_igd_refresh_margin_ms), static_cast<std::uint64_t>(lease_secs) * 500ULL);
  upnp_igd_next_refresh_ms_ =
      upnp_igd_mapping_expires_ms_ > margin_ms ? upnp_igd_mapping_expires_ms_ - margin_ms : now_ms + 1'000;
  log_line("upnp-igd-refresh status=ok endpoint=" + upnp_igd_external_endpoint_->key());
}

void Node::maybe_refresh_stun_external_endpoint(std::uint64_t now_ms) {
  if (cfg_.disable_p2p || !cfg_.listen || !cfg_.public_mode) return;
  if (!cfg_.external_endpoint.empty()) return;
  if (cfg_.stun_servers.empty()) return;
  const std::uint64_t refresh_ms = std::max<std::uint32_t>(5'000, cfg_.stun_refresh_interval_ms);
  const std::uint64_t max_backoff_ms = std::max<std::uint32_t>(refresh_ms, cfg_.stun_max_backoff_ms);

  {
    std::lock_guard<std::mutex> lk(mu_);
    if (stun_last_attempt_ms_ != 0 && now_ms < stun_last_attempt_ms_ + refresh_ms) return;
    for (auto it = stun_server_backoff_.begin(); it != stun_server_backoff_.end();) {
      if (std::find(cfg_.stun_servers.begin(), cfg_.stun_servers.end(), it->first) == cfg_.stun_servers.end()) {
        it = stun_server_backoff_.erase(it);
      } else {
        ++it;
      }
    }
  }

  std::string last_error = "stun_all_servers_failed";
  std::string used_server;
  std::uint64_t earliest_next_allowed = 0;
  bool attempted_any = false;

  for (const auto& server : cfg_.stun_servers) {
    {
      std::lock_guard<std::mutex> lk(mu_);
      auto& st = stun_server_backoff_[server];
      if (st.next_allowed_ms != 0 && now_ms < st.next_allowed_ms) {
        if (earliest_next_allowed == 0 || st.next_allowed_ms < earliest_next_allowed) {
          earliest_next_allowed = st.next_allowed_ms;
        }
        continue;
      }
      st.last_attempt_ms = now_ms;
    }

    attempted_any = true;
    used_server = server;
    std::string err;
    auto mapped = stun_query_external_endpoint(server, cfg_.p2p_port, cfg_.stun_timeout_ms, &err);
    if (mapped.has_value()) {
      std::lock_guard<std::mutex> lk(mu_);
      auto& st = stun_server_backoff_[server];
      st.fail_count = 0;
      st.next_allowed_ms = now_ms + refresh_ms;
      st.last_error_code.clear();

      stun_last_attempt_ms_ = now_ms;
      stun_last_server_ = server;
      stun_last_error_code_.clear();
      stun_last_success_ = true;
      stun_last_success_ms_ = now_ms;
      stun_backoff_until_ms_ = now_ms + refresh_ms;

      const std::string discovered = mapped->key();
      if (!stun_external_endpoint_.has_value()) {
        stun_external_endpoint_ = *mapped;
        stun_candidate_endpoint_.reset();
        stun_candidate_hits_ = 0;
        stun_candidate_since_ms_ = 0;
        stun_endpoint_change_pending_ = false;
        return;
      }

      const std::string current = stun_external_endpoint_->key();
      if (current == discovered) {
        stun_candidate_endpoint_.reset();
        stun_candidate_hits_ = 0;
        stun_candidate_since_ms_ = 0;
        stun_endpoint_change_pending_ = false;
        return;
      }

      if (!stun_candidate_endpoint_.has_value() || stun_candidate_endpoint_->key() != discovered) {
        stun_candidate_endpoint_ = *mapped;
        stun_candidate_hits_ = 1;
        stun_candidate_since_ms_ = now_ms;
      } else if (stun_candidate_hits_ < std::numeric_limits<std::uint32_t>::max()) {
        ++stun_candidate_hits_;
      }

      stun_endpoint_change_pending_ = true;
      const std::uint32_t required_hits = std::max<std::uint32_t>(2, cfg_.stun_hysteresis_samples);
      const bool enough_hits = stun_candidate_hits_ >= required_hits;
      const bool enough_time = cfg_.stun_hysteresis_min_ms != 0 &&
                               now_ms >= stun_candidate_since_ms_ + cfg_.stun_hysteresis_min_ms &&
                               stun_candidate_hits_ >= 2;
      if (enough_hits || enough_time) {
        stun_external_endpoint_ = *stun_candidate_endpoint_;
        stun_candidate_endpoint_.reset();
        stun_candidate_hits_ = 0;
        stun_candidate_since_ms_ = 0;
        stun_endpoint_change_pending_ = false;
      }
      return;
    }

    {
      std::lock_guard<std::mutex> lk(mu_);
      auto& st = stun_server_backoff_[server];
      st.fail_count = std::min<std::uint32_t>(st.fail_count + 1, 16);
      st.last_error_code = err.empty() ? "stun_query_failed" : err;
      const std::uint64_t delay = stun_backoff_delay_ms(st.fail_count, static_cast<std::uint32_t>(refresh_ms),
                                                         static_cast<std::uint32_t>(max_backoff_ms));
      st.next_allowed_ms = now_ms + delay;
      if (earliest_next_allowed == 0 || st.next_allowed_ms < earliest_next_allowed) {
        earliest_next_allowed = st.next_allowed_ms;
      }
    }
    if (!err.empty()) last_error = err;
  }

  std::lock_guard<std::mutex> lk(mu_);
  stun_last_attempt_ms_ = now_ms;
  stun_last_success_ = false;
  if (!used_server.empty()) stun_last_server_ = used_server;
  if (!attempted_any) {
    stun_last_error_code_ = "stun_all_servers_in_backoff";
  } else {
    stun_last_error_code_ = last_error;
  }
  stun_backoff_until_ms_ = earliest_next_allowed;
}

bool Node::has_peer_endpoint(const std::string& host, std::uint16_t port) const {
  const std::string endpoint = host + ":" + std::to_string(port);
  for (int pid : p2p_.peer_ids()) {
    const auto info = p2p_.get_peer_info(pid);
    if (info.endpoint == endpoint) return true;
    if (!info.inbound && info.ip == host) {
      const auto parsed = p2p::parse_endpoint(info.endpoint);
      if (parsed.has_value() && parsed->port == port) return true;
    }
  }
  return false;
}

std::size_t Node::peer_count() const { return static_cast<std::size_t>(p2p_.peer_ids().size()); }

std::size_t Node::established_peer_count() const {
  std::size_t n = 0;
  for (int id : p2p_.peer_ids()) {
    if (p2p_.get_peer_info(id).established()) ++n;
  }
  return n;
}

std::size_t Node::outbound_peer_count() const {
  if (cfg_.disable_p2p) return peer_count();
  return p2p_.outbound_count();
}

std::string Node::peer_ip_for_locked(int peer_id) const {
  auto it = peer_ip_cache_.find(peer_id);
  if (it != peer_ip_cache_.end()) return it->second;
  const auto pi = p2p_.get_peer_info(peer_id);
  if (!pi.ip.empty()) return pi.ip;
  return endpoint_to_ip(pi.endpoint);
}

bool Node::suppress_self_endpoint_locked(const std::string& endpoint) {
  if (endpoint.empty()) return false;
  return self_peer_endpoints_.insert(endpoint).second;
}

bool Node::is_self_endpoint_suppressed_locked(const std::string& endpoint) const {
  return !endpoint.empty() && self_peer_endpoints_.find(endpoint) != self_peer_endpoints_.end();
}

bool Node::is_bootstrap_peer_ip(const std::string& ip) const {
  if (ip.empty()) return false;
  auto matches_host = [&](const std::string& peer) {
    const auto pos = peer.find(':');
    const std::string host = (pos == std::string::npos) ? peer : peer.substr(0, pos);
    return host == ip;
  };
  for (const auto& peer : cfg_.peers) {
    if (matches_host(peer)) return true;
  }
  for (const auto& seed : cfg_.seeds) {
    if (matches_host(seed)) return true;
  }
  for (const auto& peer : bootstrap_peers_) {
    // SECURITY: DNS answers are not operator-vetted; they must not grant ban/rate-limit immunity.
    if (std::find(dns_seed_peers_.begin(), dns_seed_peers_.end(), peer) != dns_seed_peers_.end()) continue;
    if (matches_host(peer)) return true;
  }
  for (const auto& peer : validators_bootstrap_peers_) {
    if (matches_host(peer)) return true;
  }
  return false;
}

std::optional<p2p::NetAddress> Node::addrman_address_for_peer(const p2p::PeerInfo& info) const {
  if (info.ip.empty()) return std::nullopt;
  if (info.inbound) return std::nullopt;
  if (!info.inbound) {
    auto parsed = p2p::parse_endpoint(info.endpoint);
    if (parsed.has_value()) return *parsed;
  }
  return std::nullopt;
}

void Node::score_peer(int peer_id, p2p::MisbehaviorReason reason, const std::string& note) {
  std::lock_guard<std::mutex> lk(mu_);
  score_peer_locked(peer_id, reason, note);
}

void Node::score_peer_locked(int peer_id, p2p::MisbehaviorReason reason, const std::string& note) {
  const std::string ip = peer_ip_for_locked(peer_id);
  if (ip.empty()) return;
  if (reason == p2p::MisbehaviorReason::RATE_LIMIT && is_bootstrap_peer_ip(ip)) {
    log_line("peer-rate-limit-ignored ip=" + ip + " note=" + note + " reason=bootstrap-peer");
    return;
  }
  const p2p::PeerScoreStatus st = discipline_.add_score(ip, reason, now_unix());
  if (st.banned) {
    log_line("peer-banned ip=" + ip + " score=" + std::to_string(st.score) + " note=" + note);
    p2p_.disconnect_peer(peer_id);
  } else if (st.soft_muted) {
    log_line("peer-soft-muted ip=" + ip + " score=" + std::to_string(st.score) + " note=" + note);
  }
}

bool Node::should_mute_peer(int peer_id) const {
  if (peer_id <= 0) return false;
  std::lock_guard<std::mutex> lk(mu_);
  return should_mute_peer_locked(peer_id);
}

bool Node::should_mute_peer_locked(int peer_id) const {
  if (peer_id <= 0) return false;
  const std::string ip = peer_ip_for_locked(peer_id);
  if (ip.empty()) return false;
  return discipline_.status(ip, now_unix()).soft_muted;
}

bool Node::check_rate_limit_locked(int peer_id, std::uint16_t msg_type) {
  if (peer_id <= 0) return true;
  auto& buckets = msg_rate_buckets_[peer_id];
  auto get = [&](std::uint16_t type, double cap, double refill) -> p2p::TokenBucket& {
    auto it = buckets.find(type);
    if (it == buckets.end()) {
      it = buckets.emplace(type, p2p::TokenBucket(cap, refill)).first;
    }
    return it->second;
  };

  const auto nms = now_ms();
  switch (msg_type) {
    case p2p::MsgType::TX:
      return get(msg_type, cfg_.tx_rate_capacity, cfg_.tx_rate_refill).consume(1.0, nms);
    case p2p::MsgType::PROPOSE:
      return get(msg_type, cfg_.propose_rate_capacity, cfg_.propose_rate_refill).consume(1.0, nms);
    case p2p::MsgType::VOTE:
      return get(msg_type, cfg_.vote_rate_capacity, cfg_.vote_rate_refill).consume(1.0, nms);
    case p2p::MsgType::PREVOTE:
      return get(msg_type, cfg_.vote_rate_capacity, cfg_.vote_rate_refill).consume(1.0, nms);
    case p2p::MsgType::TIMEOUT_VOTE:
      return get(msg_type, cfg_.vote_rate_capacity, cfg_.vote_rate_refill).consume(1.0, nms);
    case p2p::MsgType::TRANSITION:
      return get(msg_type, cfg_.block_rate_capacity, cfg_.block_rate_refill).consume(1.0, nms);
    case p2p::MsgType::GET_TRANSITION:
      return get(msg_type, 120.0, 60.0).consume(1.0, nms);
    case p2p::MsgType::GET_FINALIZED_TIP:
      return get(msg_type, 20.0, 10.0).consume(1.0, nms);
    case p2p::MsgType::GET_INGRESS_TIPS:
      return get(msg_type, 20.0, 10.0).consume(1.0, nms);
    case p2p::MsgType::INGRESS_TIPS:
      return get(msg_type, 20.0, 10.0).consume(1.0, nms);
    case p2p::MsgType::GET_INGRESS_RANGE:
      return get(msg_type, 15.0, 8.0).consume(1.0, nms);
    case p2p::MsgType::INGRESS_RANGE:
      return get(msg_type, 15.0, 8.0).consume(1.0, nms);
    case p2p::MsgType::GETADDR:
      return get(msg_type, 4.0, 1.0).consume(1.0, nms);
    case p2p::MsgType::ADDR:
      return get(msg_type, 8.0, 2.0).consume(1.0, nms);
    case p2p::MsgType::PING:
      return get(msg_type, 20.0, 10.0).consume(1.0, nms);
    case p2p::MsgType::PONG:
      return get(msg_type, 20.0, 10.0).consume(1.0, nms);
    case p2p::MsgType::INGRESS_RECORD:
      return get(msg_type, 20.0, 10.0).consume(1.0, nms);
    case p2p::MsgType::EPOCH_TICKET:
      return get(msg_type, 20.0, 10.0).consume(1.0, nms);
    case p2p::MsgType::GET_TRANSITION_BY_HEIGHT:
      return get(msg_type, 120.0, 60.0).consume(1.0, nms);
    case p2p::MsgType::GET_EPOCH_TICKETS:
      return get(msg_type, 10.0, 5.0).consume(1.0, nms);
    case p2p::MsgType::EPOCH_TICKETS:
      return get(msg_type, 10.0, 5.0).consume(1.0, nms);
    default:
      return true;
  }
}

bool Node::check_sync_transition_rate_limit_locked(int peer_id) {
  if (peer_id <= 0) return true;
  // Synthetic bucket key: not a wire message type.
  constexpr std::uint16_t kSyncTransitionBucket = 0xFFFF;
  auto& buckets = msg_rate_buckets_[peer_id];
  auto it = buckets.find(kSyncTransitionBucket);
  if (it == buckets.end()) it = buckets.emplace(kSyncTransitionBucket, p2p::TokenBucket(512.0, 256.0)).first;
  return it->second.consume(1.0, now_ms());
}

}  // namespace finalis::node
