// SPDX-License-Identifier: MIT

#include "test_framework.hpp"

#include <atomic>
#include <chrono>
#include <ctime>
#include <filesystem>
#include <string>

#ifndef _WIN32
#include <unistd.h>
#else
#include <process.h>
#define getpid _getpid
#endif

#include "node/node.hpp"

using namespace finalis;

namespace {

std::string unique_test_path(const char* prefix) {
  static std::atomic<std::uint64_t> counter{0};
  const auto pid = static_cast<std::uint64_t>(::getpid());
  const auto now = std::chrono::steady_clock::now().time_since_epoch().count();
  const auto seq = counter.fetch_add(1, std::memory_order_relaxed);
  return std::string(prefix) + "_" + std::to_string(pid) + "_" + std::to_string(now) + "_" + std::to_string(seq);
}

node::NodeConfig make_cfg(const std::string& db_path) {
  node::NodeConfig cfg;
  cfg.disable_p2p = true;
  cfg.dns_seeds = false;
  cfg.db_path = db_path;
  cfg.validator_passphrase = "test-pass";
  return cfg;
}

}  // namespace

TEST(test_node_rate_limit_does_not_score_single_bootstrap_peer_during_sync) {
  auto cfg = make_cfg(unique_test_path("/tmp/finalis_test_node_rate_limit_bootstrap_guard"));
  cfg.seeds = {"64.23.244.126:19440"};
  node::Node n(cfg);
  ASSERT_TRUE(n.init());

  const std::string ip = "64.23.244.126";
  n.set_peer_ip_for_test(7, ip);
  for (int i = 0; i < 25; ++i) {
    n.score_peer_for_test(7, p2p::MisbehaviorReason::RATE_LIMIT, "msg-rate");
  }
  const auto st = n.peer_score_status_for_test(ip);
  ASSERT_EQ(st.score, 0);
  ASSERT_TRUE(!st.soft_muted);
  ASSERT_TRUE(!st.banned);

  n.score_peer_for_test(7, p2p::MisbehaviorReason::INVALID_PAYLOAD, "bad-payload");
  const auto invalid_st = n.peer_score_status_for_test(ip);
  ASSERT_EQ(invalid_st.score, 15);
  ASSERT_TRUE(!invalid_st.banned);

  n.stop();
}

TEST(test_node_rate_limit_still_scores_non_bootstrap_peer) {
  auto cfg = make_cfg(unique_test_path("/tmp/finalis_test_node_rate_limit_non_bootstrap"));
  node::Node n(cfg);
  ASSERT_TRUE(n.init());

  const std::string ip = "203.0.113.55";
  n.set_peer_ip_for_test(9, ip);
  for (int i = 0; i < 20; ++i) {
    n.score_peer_for_test(9, p2p::MisbehaviorReason::RATE_LIMIT, "msg-rate");
  }
  const auto st = n.peer_score_status_for_test(ip);
  ASSERT_EQ(st.score, 100);
  ASSERT_TRUE(st.soft_muted);
  ASSERT_TRUE(st.banned);

  n.stop();
}

TEST(test_node_peer_discipline_decay_hook_reduces_score) {
  auto cfg = make_cfg(unique_test_path("/tmp/finalis_test_node_peer_decay"));
  node::Node n(cfg);
  ASSERT_TRUE(n.init());

  const std::string ip = "198.51.100.77";
  n.set_peer_ip_for_test(11, ip);
  n.score_peer_for_test(11, p2p::MisbehaviorReason::INVALID_PAYLOAD, "bad-1");
  n.score_peer_for_test(11, p2p::MisbehaviorReason::INVALID_PAYLOAD, "bad-2");
  const auto before = n.peer_score_status_for_test(ip);
  ASSERT_TRUE(before.score >= 30);

  const auto future_unix = static_cast<std::uint64_t>(std::time(nullptr) + 120);
  n.decay_peer_discipline_for_test(future_unix);
  const auto after = n.peer_score_status_for_test(ip, future_unix);
  ASSERT_TRUE(after.score < before.score);

  n.stop();
}

void register_node_hardening_tests() {}
