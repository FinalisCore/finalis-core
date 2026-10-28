// SPDX-License-Identifier: MIT

#include "test_framework.hpp"

#include <random>

#include "p2p/endpoints.hpp"

using namespace finalis;
using namespace finalis::p2p;

namespace {

Hash32 domain(std::uint8_t b) {
  Hash32 h{};
  h.fill(b);
  return h;
}

crypto::KeyPair key(std::uint8_t b) {
  std::array<std::uint8_t, 32> seed{};
  seed.fill(b);
  return *crypto::keypair_from_seed32(seed);
}

EndpointAnnouncement signed_at(std::uint8_t k, const std::string& url, std::uint64_t t) {
  return *sign_endpoint_announcement(domain(1), key(k), url, t);
}

}  // namespace

TEST(test_endpoint_url_rules) {
  ASSERT_TRUE(valid_endpoint_url("https://rpc.example.org/rpc", false));
  ASSERT_TRUE(valid_endpoint_url("http://203.0.113.5:19444/rpc", false));
  ASSERT_TRUE(valid_endpoint_url("https://[2001:db8::1]:443/api/rpc", false));
  // Not an RPC path, odd schemes and smuggling characters.
  for (const char* bad : {"https://rpc.example.org/", "ftp://rpc.example.org/rpc", "https://rpc.example.org/rpc?x=1",
                          "https://user@rpc.example.org/rpc", "https://rpc.example.org/../rpc", "https:///rpc",
                          "https://rpc.example.org:0/rpc", "https://rpc.example.org:99999/rpc",
                          "https://rpc.example.org:/rpc", "https://[::1/rpc", "https://a..b/rpc"}) {
    ASSERT_TRUE(!valid_endpoint_url(bad, true));
  }
  ASSERT_TRUE(!valid_endpoint_url("https://" + std::string(200, 'a') + ".org/rpc", true));
  // Private hosts only off mainnet.
  for (const char* priv : {"http://127.0.0.1:19444/rpc", "http://10.1.2.3/rpc", "http://192.168.1.4/rpc",
                           "http://172.16.0.1/rpc", "http://169.254.1.1/rpc", "http://[::1]/rpc", "http://[fd00::1]/rpc",
                           "http://localhost/rpc", "http://node.localhost/rpc", "http://intranet/rpc"}) {
    ASSERT_TRUE(!valid_endpoint_url(priv, false));
    ASSERT_TRUE(valid_endpoint_url(priv, true));
  }
}

TEST(test_endpoint_groups) {
  ASSERT_EQ(endpoint_group("http://203.0.113.5:19444/rpc"), "v4:203.0");
  ASSERT_EQ(endpoint_group("http://203.0.200.9/rpc"), "v4:203.0");
  ASSERT_EQ(endpoint_group("https://[2001:db8:aa::1]/rpc"), "v6:2001:0db8");
  ASSERT_EQ(endpoint_group("https://a.b.Example.org/rpc"), "dns:example.org");
  ASSERT_EQ(endpoint_group("https://example.org/rpc"), "dns:example.org");
  ASSERT_EQ(endpoint_group("nonsense"), "");
}

TEST(test_endpoint_announcement_signature_and_codec) {
  const std::uint64_t now = 1'800'000'000;
  const auto a = signed_at(7, "https://rpc.example.org/rpc", now);
  ASSERT_TRUE(verify_endpoint_announcement(domain(1), a, now, false));
  // Another chain, a changed URL or time, a forged key: all refused.
  ASSERT_TRUE(!verify_endpoint_announcement(domain(2), a, now, false));
  auto moved = a;
  moved.url = "https://evil.example.org/rpc";
  ASSERT_TRUE(!verify_endpoint_announcement(domain(1), moved, now, false));
  auto retimed = a;
  retimed.issued_unix += 1;
  ASSERT_TRUE(!verify_endpoint_announcement(domain(1), retimed, now, false));
  auto stolen = a;
  stolen.pubkey = key(8).public_key;
  ASSERT_TRUE(!verify_endpoint_announcement(domain(1), stolen, now, false));
  // Expired, and too far in the future.
  ASSERT_TRUE(!verify_endpoint_announcement(domain(1), a, now + kEndpointTtlSeconds + 1, false));
  ASSERT_TRUE(!verify_endpoint_announcement(domain(1), signed_at(7, a.url, now + kEndpointMaxFutureSkewSeconds + 1), now, false));

  const auto round = de_endpoint_announcement(ser_endpoint_announcement(a));
  ASSERT_TRUE(round.has_value() && *round == a);
  EndpointsMsg msg;
  msg.entries = {a, signed_at(9, "http://198.51.100.1/rpc", now)};
  const auto parsed = de_endpoints(ser_endpoints(msg));
  ASSERT_TRUE(parsed.has_value() && parsed->entries == msg.entries);
  auto bytes = ser_endpoints(msg);
  bytes.push_back(0);
  ASSERT_TRUE(!de_endpoints(bytes).has_value());
  EndpointsMsg too_many;
  too_many.entries.assign(kMaxEndpointsPerMsg + 1, a);
  ASSERT_TRUE(!de_endpoints(ser_endpoints(too_many)).has_value());
  ASSERT_TRUE(de_get_endpoints({}).has_value() && !de_get_endpoints({1}).has_value());
}

TEST(test_endpoint_key_is_derived_and_unlinkable) {
  const auto node = key(3);
  const auto e1 = derive_endpoint_keypair(node.private_key);
  const auto e2 = derive_endpoint_keypair(node.private_key);
  ASSERT_TRUE(e1.has_value() && e2.has_value());
  ASSERT_TRUE(e1->public_key == e2->public_key);  // stable across restarts
  ASSERT_TRUE(e1->public_key != node.public_key);
  ASSERT_TRUE(!derive_endpoint_keypair(Bytes(31, 0)).has_value());
}

TEST(test_endpoint_table_limits) {
  const std::uint64_t now = 1'800'000'000;
  EndpointTable t;
  ASSERT_TRUE(t.insert(signed_at(1, "http://203.0.113.1/rpc", now), now) == EndpointTable::InsertResult::Added);
  // Newest per key wins; an older or equal one is stale.
  ASSERT_TRUE(t.insert(signed_at(1, "http://203.0.113.1/rpc", now - 5), now) == EndpointTable::InsertResult::Stale);
  ASSERT_TRUE(t.insert(signed_at(1, "http://198.51.100.1/rpc", now + 1), now) == EndpointTable::InsertResult::Updated);
  ASSERT_EQ(t.size(), 1u);
  ASSERT_EQ(t.all()[0].url, "http://198.51.100.1/rpc");

  // Four per group: a fifth key in 198.51/16 is refused, another group is fine.
  for (std::uint8_t k = 2; k <= 4; ++k) {
    ASSERT_TRUE(t.insert(signed_at(k, "http://198.51.100." + std::to_string(k) + "/rpc", now), now) ==
                EndpointTable::InsertResult::Added);
  }
  ASSERT_TRUE(t.insert(signed_at(5, "http://198.51.7.7/rpc", now), now) == EndpointTable::InsertResult::GroupFull);
  ASSERT_TRUE(t.insert(signed_at(5, "https://a.example.org/rpc", now), now) == EndpointTable::InsertResult::Added);
  ASSERT_EQ(t.size(), 5u);

  // Expiry.
  ASSERT_TRUE(t.insert(signed_at(6, "https://old.example.net/rpc", now - kEndpointTtlSeconds + 10), now) ==
              EndpointTable::InsertResult::Added);
  t.expire(now + 20);
  ASSERT_EQ(t.size(), 5u);
  std::mt19937_64 rng(1);
  ASSERT_EQ(t.sample(3, rng).size(), 3u);
  ASSERT_EQ(t.sample(100, rng).size(), 5u);
}

TEST(test_endpoint_table_flood_cannot_evict_distinct_groups) {
  const std::uint64_t now = 1'800'000'000;
  EndpointTable t;
  // Fill the table: kEndpointTableCapacity / 4 groups of 4.
  std::size_t k = 0;
  for (std::size_t g = 0; g < kEndpointTableCapacity / kMaxEndpointsPerGroup; ++g) {
    for (std::size_t i = 0; i < kMaxEndpointsPerGroup; ++i, ++k) {
      std::array<std::uint8_t, 32> seed{};
      seed[0] = static_cast<std::uint8_t>(k);
      seed[1] = static_cast<std::uint8_t>(k >> 8);
      seed[2] = 1;
      const auto kp = *crypto::keypair_from_seed32(seed);
      const std::string url = "http://" + std::to_string(10 + g / 200) + "." + std::to_string(g % 200) + ".0." +
                              std::to_string(i + 1) + "/rpc";
      ASSERT_TRUE(t.insert(*sign_endpoint_announcement(domain(1), kp, url, now), now) == EndpointTable::InsertResult::Added);
    }
  }
  ASSERT_EQ(t.size(), kEndpointTableCapacity);
  // A newcomer from a new group takes the place of the oldest entry in a crowded group.
  const auto fresh = signed_at(200, "https://newcomer.example.org/rpc", now + 1);
  ASSERT_TRUE(t.insert(fresh, now) == EndpointTable::InsertResult::Added);
  ASSERT_EQ(t.size(), kEndpointTableCapacity);
}
