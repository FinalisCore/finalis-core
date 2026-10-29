// SPDX-License-Identifier: MIT

#include "p2p/endpoints.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdio>
#include <cstring>

#include "codec/bytes.hpp"
#include "common/socket_compat.hpp"
#include "crypto/hash.hpp"

namespace finalis::p2p {
namespace {

struct ParsedUrl {
  std::string host;  // without brackets
  bool ipv6{false};
};

std::optional<ParsedUrl> parse_url(const std::string& url) {
  if (url.empty() || url.size() > kMaxEndpointUrlBytes) return std::nullopt;
  std::string rest;
  if (url.rfind("https://", 0) == 0) {
    rest = url.substr(8);
  } else if (url.rfind("http://", 0) == 0) {
    rest = url.substr(7);
  } else {
    return std::nullopt;
  }
  const auto slash = rest.find('/');
  if (slash == std::string::npos) return std::nullopt;
  std::string authority = rest.substr(0, slash);
  const std::string path = rest.substr(slash);
  // A path of plain segments ending in /rpc: no query, fragment or userinfo to smuggle anything in.
  if (path.size() < 4 || path.compare(path.size() - 4, 4, "/rpc") != 0) return std::nullopt;
  for (const char c : path) {
    const auto u = static_cast<unsigned char>(c);
    if (std::isalnum(u) == 0 && std::strchr("/._~-", c) == nullptr) return std::nullopt;
  }
  if (path.find("//") != std::string::npos || path.find("/./") != std::string::npos ||
      path.find("/../") != std::string::npos) {
    return std::nullopt;
  }
  ParsedUrl out;
  std::string port;
  if (!authority.empty() && authority.front() == '[') {
    const auto close = authority.find(']');
    if (close == std::string::npos) return std::nullopt;
    out.host = authority.substr(1, close - 1);
    out.ipv6 = true;
    const std::string after = authority.substr(close + 1);
    if (!after.empty()) {
      if (after.front() != ':') return std::nullopt;
      port = after.substr(1);
    }
    in6_addr a6{};
    if (::inet_pton(AF_INET6, out.host.c_str(), &a6) != 1) return std::nullopt;
  } else {
    const auto colon = authority.find(':');
    out.host = authority.substr(0, colon);
    if (colon != std::string::npos) port = authority.substr(colon + 1);
    if (out.host.empty() || out.host.size() > 253) return std::nullopt;
    for (const char c : out.host) {
      const auto u = static_cast<unsigned char>(c);
      if (std::isalnum(u) == 0 && c != '.' && c != '-') return std::nullopt;
    }
    if (out.host.front() == '.' || out.host.back() == '.' || out.host.find("..") != std::string::npos) {
      return std::nullopt;
    }
  }
  if (authority.find(':') != std::string::npos && !out.ipv6 && port.empty()) return std::nullopt;
  if (!port.empty()) {
    if (port.size() > 5 || !std::all_of(port.begin(), port.end(), [](char c) { return c >= '0' && c <= '9'; })) {
      return std::nullopt;
    }
    const auto p = std::stoul(port);
    if (p == 0 || p > 65535) return std::nullopt;
  }
  return out;
}

std::string lower(std::string s) {
  for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return s;
}

bool private_ipv4(const in_addr& a) {
  const std::uint32_t h = ntohl(a.s_addr);
  const auto in = [&](std::uint32_t net, int bits) { return (h >> (32 - bits)) == (net >> (32 - bits)); };
  return in(0x00000000, 8) || in(0x0A000000, 8) || in(0x7F000000, 8) || in(0xA9FE0000, 16) || in(0xAC100000, 12) ||
         in(0xC0A80000, 16) || in(0x64400000, 10) || h >= 0xE0000000;
}

bool private_ipv6(const in6_addr& a) {
  const auto* b = reinterpret_cast<const std::uint8_t*>(&a);
  static const std::array<std::uint8_t, 16> loopback = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
  static const std::array<std::uint8_t, 16> any{};
  if (std::memcmp(b, loopback.data(), 16) == 0 || std::memcmp(b, any.data(), 16) == 0) return true;
  if ((b[0] & 0xFE) == 0xFC) return true;                  // fc00::/7 unique local
  if (b[0] == 0xFE && (b[1] & 0xC0) == 0x80) return true;  // fe80::/10 link local
  if (b[0] == 0xFF) return true;                           // multicast
  return false;
}

}  // namespace

Bytes ser_endpoint_announcement(const EndpointAnnouncement& a) {
  codec::ByteWriter w;
  w.bytes_fixed(a.pubkey);
  w.varbytes(Bytes(a.url.begin(), a.url.end()));
  w.u64le(a.issued_unix);
  w.bytes_fixed(a.signature);
  return w.take();
}

namespace {
bool read_announcement(codec::ByteReader& r, EndpointAnnouncement* out) {
  auto pub = r.bytes_fixed<32>();
  auto url = r.varbytes();
  auto issued = r.u64le();
  auto sig = r.bytes_fixed<64>();
  if (!pub || !url || !issued || !sig || url->empty() || url->size() > kMaxEndpointUrlBytes) return false;
  out->pubkey = *pub;
  out->url.assign(url->begin(), url->end());
  out->issued_unix = *issued;
  out->signature = *sig;
  return true;
}
}  // namespace

std::optional<EndpointAnnouncement> de_endpoint_announcement(const Bytes& b) {
  EndpointAnnouncement a;
  if (!codec::parse_exact(b, [&](codec::ByteReader& r) { return read_announcement(r, &a); })) return std::nullopt;
  return a;
}

Bytes ser_get_endpoints(const GetEndpointsMsg&) { return {}; }

std::optional<GetEndpointsMsg> de_get_endpoints(const Bytes& b) {
  if (!b.empty()) return std::nullopt;
  return GetEndpointsMsg{};
}

Bytes ser_endpoints(const EndpointsMsg& m) {
  codec::ByteWriter w;
  w.varint(m.entries.size());
  for (const auto& a : m.entries) w.bytes(ser_endpoint_announcement(a));
  return w.take();
}

std::optional<EndpointsMsg> de_endpoints(const Bytes& b) {
  EndpointsMsg m;
  if (!codec::parse_exact(b, [&](codec::ByteReader& r) {
        auto n = r.varint();
        if (!n || *n > kMaxEndpointsPerMsg) return false;
        m.entries.resize(static_cast<std::size_t>(*n));
        for (auto& a : m.entries) {
          if (!read_announcement(r, &a)) return false;
        }
        return true;
      })) {
    return std::nullopt;
  }
  return m;
}

std::optional<crypto::KeyPair> derive_endpoint_keypair(const Bytes& node_private_key) {
  if (node_private_key.size() != 32) return std::nullopt;
  const std::string tag = "FINALIS-ENDPOINT-KEY-V1";
  Bytes pre(tag.begin(), tag.end());
  pre.insert(pre.end(), node_private_key.begin(), node_private_key.end());
  const Hash32 seed = crypto::sha256(pre);
  crypto::secure_wipe(pre);
  return crypto::keypair_from_seed32(seed);
}

Bytes endpoint_signing_message(const Hash32& chain_domain, const PubKey32& pubkey, const std::string& url,
                               std::uint64_t issued_unix) {
  codec::ByteWriter w;
  w.bytes(Bytes{'F', 'I', 'N', 'A', 'L', 'I', 'S', '-', 'E', 'N', 'D', 'P', 'O', 'I', 'N', 'T', '-', 'V', '1'});
  w.bytes_fixed(chain_domain);
  w.bytes_fixed(pubkey);
  w.varbytes(Bytes(url.begin(), url.end()));
  w.u64le(issued_unix);
  const Hash32 h = crypto::sha256d(w.data());
  return Bytes(h.begin(), h.end());
}

std::optional<EndpointAnnouncement> sign_endpoint_announcement(const Hash32& chain_domain, const crypto::KeyPair& key,
                                                               const std::string& url, std::uint64_t issued_unix) {
  EndpointAnnouncement a;
  a.pubkey = key.public_key;
  a.url = url;
  a.issued_unix = issued_unix;
  const auto sig = crypto::ed25519_sign(endpoint_signing_message(chain_domain, a.pubkey, url, issued_unix), key.private_key);
  if (!sig) return std::nullopt;
  a.signature = *sig;
  return a;
}

bool valid_endpoint_url(const std::string& url, bool allow_private) {
  const auto parsed = parse_url(url);
  if (!parsed) return false;
  if (allow_private) return true;
  if (parsed->ipv6) {
    in6_addr a6{};
    (void)::inet_pton(AF_INET6, parsed->host.c_str(), &a6);
    return !private_ipv6(a6);
  }
  in_addr a4{};
  if (::inet_pton(AF_INET, parsed->host.c_str(), &a4) == 1) return !private_ipv4(a4);
  const std::string host = lower(parsed->host);
  if (host == "localhost" || (host.size() > 10 && host.compare(host.size() - 10, 10, ".localhost") == 0)) return false;
  // A bare label (no dot) only resolves on a local network.
  return host.find('.') != std::string::npos;
}

std::string endpoint_group(const std::string& url) {
  const auto parsed = parse_url(url);
  if (!parsed) return {};
  if (parsed->ipv6) {
    in6_addr a6{};
    if (::inet_pton(AF_INET6, parsed->host.c_str(), &a6) != 1) return {};
    const auto* b = reinterpret_cast<const std::uint8_t*>(&a6);
    char buf[24];
    std::snprintf(buf, sizeof(buf), "v6:%02x%02x:%02x%02x", b[0], b[1], b[2], b[3]);
    return buf;
  }
  in_addr a4{};
  if (::inet_pton(AF_INET, parsed->host.c_str(), &a4) == 1) {
    const std::uint32_t h = ntohl(a4.s_addr);
    return "v4:" + std::to_string(h >> 24) + "." + std::to_string((h >> 16) & 0xFF);
  }
  const std::string host = lower(parsed->host);
  const auto last = host.rfind('.');
  if (last == std::string::npos) return "dns:" + host;
  const auto second = host.rfind('.', last - 1);
  return "dns:" + (second == std::string::npos ? host : host.substr(second + 1));
}

bool verify_endpoint_announcement(const Hash32& chain_domain, const EndpointAnnouncement& a, std::uint64_t now_unix,
                                  bool allow_private) {
  if (a.issued_unix > now_unix + kEndpointMaxFutureSkewSeconds) return false;
  if (a.issued_unix + kEndpointTtlSeconds < now_unix) return false;
  if (!valid_endpoint_url(a.url, allow_private)) return false;
  return crypto::ed25519_verify(endpoint_signing_message(chain_domain, a.pubkey, a.url, a.issued_unix), a.signature,
                                a.pubkey);
}

void EndpointTable::erase(const PubKey32& key) {
  const auto it = by_key_.find(key);
  if (it == by_key_.end()) return;
  const auto g = group_count_.find(endpoint_group(it->second.url));
  if (g != group_count_.end() && --g->second == 0) group_count_.erase(g);
  by_key_.erase(it);
}

EndpointTable::InsertResult EndpointTable::insert(const EndpointAnnouncement& a, std::uint64_t now_unix) {
  if (a.issued_unix + kEndpointTtlSeconds < now_unix) return InsertResult::Stale;
  const std::string group = endpoint_group(a.url);
  if (group.empty()) return InsertResult::Stale;
  if (const auto it = by_key_.find(a.pubkey); it != by_key_.end()) {
    if (it->second.issued_unix >= a.issued_unix) return InsertResult::Stale;
    const bool same_group = endpoint_group(it->second.url) == group;
    if (!same_group && group_count_[group] >= kMaxEndpointsPerGroup) return InsertResult::GroupFull;
    erase(a.pubkey);
    by_key_[a.pubkey] = a;
    ++group_count_[group];
    return InsertResult::Updated;
  }
  if (group_count_[group] >= kMaxEndpointsPerGroup) return InsertResult::GroupFull;
  if (by_key_.size() >= kEndpointTableCapacity) {
    // Make room in the most crowded group (oldest announcement there); a full table of distinct groups
    // keeps what it has.
    const auto crowded = std::max_element(group_count_.begin(), group_count_.end(),
                                          [](const auto& x, const auto& y) { return x.second < y.second; });
    if (crowded == group_count_.end() || crowded->second <= 1) return InsertResult::TableFull;
    const std::string victim_group = crowded->first;
    const EndpointAnnouncement* victim = nullptr;
    for (const auto& [_, e] : by_key_) {
      if (endpoint_group(e.url) == victim_group && (victim == nullptr || e.issued_unix < victim->issued_unix)) victim = &e;
    }
    if (victim == nullptr) return InsertResult::TableFull;
    const PubKey32 victim_key = victim->pubkey;
    erase(victim_key);
  }
  by_key_[a.pubkey] = a;
  ++group_count_[group];
  return InsertResult::Added;
}

void EndpointTable::expire(std::uint64_t now_unix) {
  std::vector<PubKey32> old;
  for (const auto& [key, e] : by_key_) {
    if (e.issued_unix + kEndpointTtlSeconds < now_unix) old.push_back(key);
  }
  for (const auto& key : old) erase(key);
}

std::vector<EndpointAnnouncement> EndpointTable::sample(std::size_t n, std::mt19937_64& rng) const {
  auto out = all();
  std::shuffle(out.begin(), out.end(), rng);
  if (out.size() > n) out.resize(n);
  return out;
}

std::vector<EndpointAnnouncement> EndpointTable::all() const {
  std::vector<EndpointAnnouncement> out;
  out.reserve(by_key_.size());
  for (const auto& [_, e] : by_key_) out.push_back(e);
  return out;
}

}  // namespace finalis::p2p
