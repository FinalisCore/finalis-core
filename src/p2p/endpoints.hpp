// SPDX-License-Identifier: MIT

#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <random>
#include <string>
#include <vector>

#include "common/types.hpp"
#include "crypto/ed25519.hpp"

namespace finalis::p2p {

// Public lightserver discovery. A node that serves a public lightserver signs "my RPC is at <url>"
// and the announcement spreads node to node (GET_ENDPOINTS / ENDPOINTS), so wallets and apps can
// find servers beyond the few in SEEDS.json. Nothing here is consensus.
//
// The signature proves who announced, not that the announcer runs the URL: a client keeps an
// endpoint only when that server's own get_status reports the same endpoint_pubkey (see
// lightserver/client.hpp). The key is derived from the node key one way, so an endpoint is not
// linkable to a validator identity.

inline constexpr std::size_t kMaxEndpointUrlBytes = 200;
inline constexpr std::size_t kMaxEndpointsPerMsg = 64;
inline constexpr std::size_t kEndpointTableCapacity = 1024;
inline constexpr std::size_t kMaxEndpointsPerGroup = 4;
inline constexpr std::uint64_t kEndpointTtlSeconds = 48 * 3600;
inline constexpr std::uint64_t kEndpointMaxFutureSkewSeconds = 600;
inline constexpr std::uint64_t kEndpointReannounceSeconds = 6 * 3600;

struct EndpointAnnouncement {
  PubKey32 pubkey{};
  std::string url;
  std::uint64_t issued_unix{0};
  Sig64 signature{};

  bool operator==(const EndpointAnnouncement&) const = default;
};

struct GetEndpointsMsg {};
struct EndpointsMsg {
  std::vector<EndpointAnnouncement> entries;
};

Bytes ser_endpoint_announcement(const EndpointAnnouncement& a);
std::optional<EndpointAnnouncement> de_endpoint_announcement(const Bytes& b);
Bytes ser_get_endpoints(const GetEndpointsMsg&);
std::optional<GetEndpointsMsg> de_get_endpoints(const Bytes& b);
Bytes ser_endpoints(const EndpointsMsg& m);
std::optional<EndpointsMsg> de_endpoints(const Bytes& b);

// The endpoint key: sha256("FINALIS-ENDPOINT-KEY-V1" || node private key) as an Ed25519 seed.
std::optional<crypto::KeyPair> derive_endpoint_keypair(const Bytes& node_private_key);

Bytes endpoint_signing_message(const Hash32& chain_domain, const PubKey32& pubkey, const std::string& url,
                               std::uint64_t issued_unix);
std::optional<EndpointAnnouncement> sign_endpoint_announcement(const Hash32& chain_domain, const crypto::KeyPair& key,
                                                               const std::string& url, std::uint64_t issued_unix);

// http(s)://host[:port]/...rpc with host a DNS name, an IPv4 literal or a bracketed IPv6 literal.
// Without allow_private, loopback, private, link-local and "localhost" hosts are refused (mainnet).
bool valid_endpoint_url(const std::string& url, bool allow_private);
// The flood-control group of an endpoint: /16 of an IPv4 host, /32 of an IPv6 host, else the last two
// labels of the host name. Empty for an invalid URL.
std::string endpoint_group(const std::string& url);

// Signature, URL and time window.
bool verify_endpoint_announcement(const Hash32& chain_domain, const EndpointAnnouncement& a, std::uint64_t now_unix,
                                  bool allow_private);

// Known endpoints: one announcement per key (the newest), at most kMaxEndpointsPerGroup per group,
// kEndpointTableCapacity in all, none older than kEndpointTtlSeconds. Holds verified entries only.
class EndpointTable {
 public:
  enum class InsertResult { Added, Updated, Stale, GroupFull, TableFull };
  InsertResult insert(const EndpointAnnouncement& a, std::uint64_t now_unix);
  void expire(std::uint64_t now_unix);
  // Up to `n` entries in random order.
  std::vector<EndpointAnnouncement> sample(std::size_t n, std::mt19937_64& rng) const;
  std::vector<EndpointAnnouncement> all() const;
  std::size_t size() const { return by_key_.size(); }

 private:
  void erase(const PubKey32& key);

  std::map<PubKey32, EndpointAnnouncement> by_key_;
  std::map<std::string, std::size_t> group_count_;
};

}  // namespace finalis::p2p
