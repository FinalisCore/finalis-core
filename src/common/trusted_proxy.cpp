// SPDX-License-Identifier: MIT

#include "common/trusted_proxy.hpp"

#include <array>
#include <cctype>
#include <cstring>
#include <sstream>

#include "common/socket_compat.hpp"

namespace finalis::net {
namespace {

bool iequals(std::string_view a, std::string_view b) {
  if (a.size() != b.size()) return false;
  for (std::size_t i = 0; i < a.size(); ++i) {
    if (std::tolower(static_cast<unsigned char>(a[i])) != std::tolower(static_cast<unsigned char>(b[i]))) return false;
  }
  return true;
}

std::string_view trim(std::string_view s) {
  while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1);
  while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) s.remove_suffix(1);
  return s;
}

}  // namespace

std::optional<Ipv4Cidr> parse_ipv4_cidr(const std::string& raw) {
  const auto slash = raw.find('/');
  const std::string ip = slash == std::string::npos ? raw : raw.substr(0, slash);
  std::uint32_t prefix = 32;
  if (slash != std::string::npos) {
    const std::string p = raw.substr(slash + 1);
    if (p.empty() || p.size() > 2) return std::nullopt;
    for (char c : p) {
      if (!std::isdigit(static_cast<unsigned char>(c))) return std::nullopt;
    }
    prefix = static_cast<std::uint32_t>(std::stoul(p));
    if (prefix > 32) return std::nullopt;
  }
  in_addr addr{};
  if (::inet_pton(AF_INET, ip.c_str(), &addr) != 1) return std::nullopt;
  const std::uint32_t mask = prefix == 0 ? 0 : (0xFFFFFFFFu << (32 - prefix));
  return Ipv4Cidr{ntohl(addr.s_addr) & mask, mask};
}

std::optional<std::vector<Ipv4Cidr>> parse_ipv4_cidr_list(const std::string& csv) {
  std::vector<Ipv4Cidr> out;
  std::stringstream ss(csv);
  std::string item;
  while (std::getline(ss, item, ',')) {
    const auto parsed = parse_ipv4_cidr(std::string(trim(item)));
    if (!parsed.has_value()) return std::nullopt;
    out.push_back(*parsed);
  }
  if (out.empty()) return std::nullopt;
  return out;
}

bool ipv4_in_cidrs(const std::string& ip, const std::vector<Ipv4Cidr>& cidrs) {
  in_addr addr{};
  if (::inet_pton(AF_INET, ip.c_str(), &addr) != 1) return false;
  const std::uint32_t host = ntohl(addr.s_addr);
  for (const auto& c : cidrs) {
    if ((host & c.mask) == c.network) return true;
  }
  return false;
}

std::optional<std::string> http_header_value(std::string_view request, std::string_view name) {
  const auto head_end = request.find("\r\n\r\n");
  std::string_view head = request.substr(0, head_end);
  const auto first_eol = head.find("\r\n");
  if (first_eol == std::string_view::npos) return std::nullopt;
  head.remove_prefix(first_eol + 2);
  std::optional<std::string> found;
  while (!head.empty()) {
    const auto eol = head.find("\r\n");
    const std::string_view line = head.substr(0, eol);
    head.remove_prefix(eol == std::string_view::npos ? head.size() : eol + 2);
    const auto colon = line.find(':');
    if (colon == std::string_view::npos || !iequals(trim(line.substr(0, colon)), name)) continue;
    if (found.has_value()) return std::nullopt;  // a repeated header has no single meaning
    found = std::string(trim(line.substr(colon + 1)));
  }
  return found;
}

std::optional<std::string> parse_client_ip_literal(const std::string& raw) {
  in_addr v4{};
  if (::inet_pton(AF_INET, raw.c_str(), &v4) == 1) {
    std::array<char, INET_ADDRSTRLEN> buf{};
    if (::inet_ntop(AF_INET, &v4, buf.data(), buf.size()) != nullptr) return std::string(buf.data());
    return std::nullopt;
  }
  in6_addr v6{};
  if (::inet_pton(AF_INET6, raw.c_str(), &v6) == 1) {
    std::array<char, INET6_ADDRSTRLEN> buf{};
    if (::inet_ntop(AF_INET6, &v6, buf.data(), buf.size()) != nullptr) return std::string(buf.data());
  }
  return std::nullopt;
}

std::optional<std::string> forwarded_client_ip(const std::string& peer_ip, const std::vector<Ipv4Cidr>& trusted_proxies,
                                               const std::optional<std::string>& x_real_ip) {
  if (!x_real_ip.has_value() || !ipv4_in_cidrs(peer_ip, trusted_proxies)) return std::nullopt;
  return parse_client_ip_literal(*x_real_ip);
}

std::string rate_limit_key(const std::string& client_ip) {
  in6_addr v6{};
  if (::inet_pton(AF_INET6, client_ip.c_str(), &v6) != 1) return client_ip;
  std::memset(reinterpret_cast<unsigned char*>(&v6) + 8, 0, 8);
  std::array<char, INET6_ADDRSTRLEN> buf{};
  if (::inet_ntop(AF_INET6, &v6, buf.data(), buf.size()) == nullptr) return client_ip;
  return std::string(buf.data()) + "/64";
}

}  // namespace finalis::net
