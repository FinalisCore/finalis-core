// SPDX-License-Identifier: MIT

#include "test_framework.hpp"
#include "support/test_genesis.hpp"
#include "support/test_paths.hpp"

#include <atomic>
#include <chrono>
#include <ctime>
#include <filesystem>
#include <set>
#include <string>

#ifndef _WIN32
#include <unistd.h>
#else
#include <process.h>
#define getpid _getpid
#endif

#include "node/node.hpp"
#include "node/node_internal.hpp"

using namespace finalis;

namespace {

using finalis::test::unique_test_base;

node::NodeConfig make_cfg(const std::string& db_path) {
  node::NodeConfig cfg;
  cfg.allow_unencrypted_keystore = true;  // test fixture: no passphrase
  cfg.disable_p2p = true;
  cfg.dns_seeds = false;
  cfg.db_path = db_path;
  cfg.genesis_path = db_path + ".genesis.json";
  (void)finalis::test::write_test_genesis_file(cfg.genesis_path);
  cfg.validator_passphrase = "test-pass";
  return cfg;
}

}  // namespace

TEST(test_node_rate_limit_does_not_score_single_bootstrap_peer_during_sync) {
  auto cfg = make_cfg(unique_test_base("/tmp/finalis_test_node_rate_limit_bootstrap_guard"));
  cfg.seeds = {"192.0.2.30:19440"};
  node::Node n(cfg);
  ASSERT_TRUE(n.init());

  const std::string ip = "192.0.2.30";
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
  auto cfg = make_cfg(unique_test_base("/tmp/finalis_test_node_rate_limit_non_bootstrap"));
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

TEST(test_rate_limit_drop_scores_only_what_a_peer_produces_itself) {
  using node::detail::rate_limit_drop_is_scored;
  // Relayed for others: a burst from anyone reaches an honest peer's neighbours through it.
  for (const std::uint16_t type :
       {p2p::MsgType::TX, p2p::MsgType::SUBMIT_TX, p2p::MsgType::INGRESS_RECORD, p2p::MsgType::VOTE,
        p2p::MsgType::PREVOTE, p2p::MsgType::TIMEOUT_VOTE, p2p::MsgType::TIME_SIGNATURE, p2p::MsgType::PROPOSE,
        p2p::MsgType::TRANSITION, p2p::MsgType::EPOCH_TICKET}) {
    ASSERT_TRUE(!rate_limit_drop_is_scored(type));
  }
  // Sync traffic stays unscored: requests are retried, replies follow our own request rate.
  for (const std::uint16_t type :
       {p2p::MsgType::GET_TRANSITION_BY_HEIGHT, p2p::MsgType::GET_TRANSITION, p2p::MsgType::GET_INGRESS_TIPS,
        p2p::MsgType::INGRESS_TIPS, p2p::MsgType::INGRESS_RANGE, p2p::MsgType::EPOCH_TICKETS}) {
    ASSERT_TRUE(!rate_limit_drop_is_scored(type));
  }
  for (const std::uint16_t type : {p2p::MsgType::PING, p2p::MsgType::PONG, p2p::MsgType::GETADDR, p2p::MsgType::ADDR,
                                   p2p::MsgType::GET_FINALIZED_TIP, p2p::MsgType::GET_ENDPOINTS}) {
    ASSERT_TRUE(rate_limit_drop_is_scored(type));
  }
}

TEST(test_reforward_window_is_bounded_and_reaches_every_item) {
  using node::detail::next_reforward_window;
  std::size_t cursor = 0;
  ASSERT_TRUE(next_reforward_window(0, 128, &cursor).empty());
  ASSERT_EQ(cursor, 0U);

  // The 259 stuck transactions of the live incident: no pass exceeds the cap, all get their turn.
  std::set<std::size_t> seen;
  for (int pass = 0; pass < 3; ++pass) {
    const auto window = next_reforward_window(259, 128, &cursor);
    ASSERT_TRUE(window.size() <= 128);
    seen.insert(window.begin(), window.end());
  }
  ASSERT_EQ(seen.size(), 259U);

  // The set shrinking under the cursor neither skips a pass nor reads out of range.
  cursor = 200;
  const auto after_shrink = next_reforward_window(10, 128, &cursor);
  ASSERT_EQ(after_shrink.size(), 10U);
  for (const auto index : after_shrink) ASSERT_TRUE(index < 10);
}

TEST(test_node_peer_discipline_decay_hook_reduces_score) {
  auto cfg = make_cfg(unique_test_base("/tmp/finalis_test_node_peer_decay"));
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
