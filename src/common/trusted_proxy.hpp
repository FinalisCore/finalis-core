// SPDX-License-Identifier: MIT

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace finalis::net {

// Behind a same-host reverse proxy every connection comes from the proxy's address. Rate limits,
// allowlists and audit logs need the real client, which only a trusted proxy may name.

struct Ipv4Cidr {
  std::uint32_t network{0};
  std::uint32_t mask{0};
};

std::optional<Ipv4Cidr> parse_ipv4_cidr(const std::string& raw);
// Comma-separated CIDRs (a bare address means /32). nullopt if empty or any entry is malformed.
std::optional<std::vector<Ipv4Cidr>> parse_ipv4_cidr_list(const std::string& csv);
bool ipv4_in_cidrs(const std::string& ip, const std::vector<Ipv4Cidr>& cidrs);

// Value of header `name` (case-insensitive) in a raw HTTP request head. nullopt if absent or repeated.
std::optional<std::string> http_header_value(std::string_view request, std::string_view name);

// Header in which the trusted proxy names the client. nginx sets X-Real-IP; a Cloudflare tunnel passes
// client headers through unchanged and names the client in CF-Connecting-IP, which the edge overwrites.
inline constexpr const char* kDefaultClientIpHeader = "X-Real-IP";
// An RFC 9110 field-name token (the value of --client-ip-header).
bool is_http_header_name(std::string_view name);

// X-Real-IP as an IPv4 or IPv6 literal in canonical form; nullopt for anything else.
std::optional<std::string> parse_client_ip_literal(const std::string& raw);

// The proxy-reported client address (X-Real-IP) when `peer_ip` is inside `trusted_proxies`, else
// nullopt: the peer is then itself the client, and anything it says about another client is ignored.
std::optional<std::string> forwarded_client_ip(const std::string& peer_ip, const std::vector<Ipv4Cidr>& trusted_proxies,
                                               const std::optional<std::string>& x_real_ip);

// Rate-limit identity of a client address: an IPv6 client is its /64 (one subscriber typically holds
// a whole /64 and could otherwise rotate through it for fresh limits); anything else is unchanged.
std::string rate_limit_key(const std::string& client_ip);

}  // namespace finalis::net
