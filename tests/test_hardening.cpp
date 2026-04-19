#include "test_framework.hpp"

#include <atomic>
#include <chrono>
#include <filesystem>

#ifndef _WIN32
#include <unistd.h>
#else
#include <process.h>
#define getpid _getpid
#endif

#include "consensus/validator_registry.hpp"
#include "crypto/ed25519.hpp"
#include "p2p/hardening.hpp"
#include "storage/db.hpp"

using namespace finalis;

namespace {
std::string unique_test_path(const char* prefix) {
  static std::atomic<std::uint64_t> counter{0};
  const auto pid = static_cast<std::uint64_t>(::getpid());
  const auto now = std::chrono::steady_clock::now().time_since_epoch().count();
  const auto seq = counter.fetch_add(1, std::memory_order_relaxed);
  return std::string(prefix) + "_" + std::to_string(pid) + "_" + std::to_string(now) + "_" + std::to_string(seq);
}
}  // namespace

TEST(test_token_bucket_refill_and_consume) {
  p2p::TokenBucket b(10.0, 5.0);
  ASSERT_TRUE(b.consume(8.0, 1000));
  ASSERT_TRUE(!b.consume(3.0, 1000));
  ASSERT_TRUE(b.consume(2.0, 1400));  // +2 tokens after 400ms
  ASSERT_TRUE(!b.consume(5.0, 1400));
  ASSERT_TRUE(b.consume(4.0, 2000));  // enough refill by now
}

TEST(test_peer_discipline_soft_mute_and_ban) {
  p2p::PeerDiscipline d(30, 100, 60);
  const std::string ip = "203.0.113.5";
  auto s1 = d.add_score(ip, p2p::MisbehaviorReason::INVALID_PAYLOAD, 100);
  ASSERT_TRUE(!s1.soft_muted);
  d.add_score(ip, p2p::MisbehaviorReason::INVALID_FRAME, 101);
  d.add_score(ip, p2p::MisbehaviorReason::INVALID_FRAME, 102);
  auto s2 = d.status(ip, 103);
  ASSERT_TRUE(!s2.soft_muted);  // first two invalid frames are strikes only
  d.add_score(ip, p2p::MisbehaviorReason::INVALID_FRAME, 103);  // threshold reached, accumulated score applied
  auto s3 = d.status(ip, 104);
  ASSERT_TRUE(s3.soft_muted);
  ASSERT_TRUE(s3.banned);
  ASSERT_TRUE(d.is_banned(ip, 120));
  ASSERT_TRUE(!d.is_banned(ip, 1000));
}

TEST(test_peer_discipline_handshake_timeouts_do_not_trigger_invalid_frame_ban_window) {
  p2p::PeerDiscipline d(30, 100, 60);
  const std::string ip = "203.0.113.9";
  for (std::uint64_t t = 100; t < 110; ++t) {
    d.add_score(ip, p2p::MisbehaviorReason::HANDSHAKE_TIMEOUT, t);
  }
  const auto status = d.status(ip, 110);
  ASSERT_TRUE(!status.soft_muted);
  ASSERT_TRUE(!status.banned);
  ASSERT_TRUE(status.score < 30);
}

TEST(test_recent_hash_cache_bounded_and_deduplicated) {
  p2p::RecentHashCache c(2);
  Hash32 a{};
  Hash32 b{};
  Hash32 d{};
  a[0] = 1;
  b[0] = 2;
  d[0] = 3;
  c.insert(a);
  c.insert(a);
  c.insert(b);
  ASSERT_TRUE(c.contains(a));
  ASSERT_TRUE(c.contains(b));
  c.insert(d);
  ASSERT_TRUE(!c.contains(a));
  ASSERT_TRUE(c.contains(b));
  ASSERT_TRUE(c.contains(d));
}

TEST(test_operator_id_from_payout_pubkey_persists_through_registry_and_db) {
  auto validator = crypto::keypair_from_seed32(std::array<std::uint8_t, 32>{1});
  auto payout = crypto::keypair_from_seed32(std::array<std::uint8_t, 32>{2});
  ASSERT_TRUE(validator.has_value());
  ASSERT_TRUE(payout.has_value());

  consensus::ValidatorRegistry registry;
  std::string err;
  ASSERT_TRUE(registry.register_bond(validator->public_key, OutPoint{zero_hash(), 7}, 5, BOND_AMOUNT, &err, payout->public_key));
  const auto info = registry.get(validator->public_key);
  ASSERT_TRUE(info.has_value());
  ASSERT_EQ(info->operator_id, payout->public_key);

  const std::string path = unique_test_path("/tmp/finalis_test_operator_id_db");
  std::filesystem::create_directories(path);
  storage::DB db;
  ASSERT_TRUE(db.open(path));
  ASSERT_TRUE(db.put_validator(validator->public_key, *info));
  const auto loaded = db.load_validators();
  auto it = loaded.find(validator->public_key);
  ASSERT_TRUE(it != loaded.end());
  ASSERT_EQ(it->second.operator_id, payout->public_key);
  db.close();
}

void register_hardening_tests() {}
