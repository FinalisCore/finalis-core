// SPDX-License-Identifier: MIT

#include "test_framework.hpp"
#include "support/test_genesis.hpp"
#include "support/test_paths.hpp"

#ifdef __linux__
#include <csignal>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>
#endif
#include <atomic>
#include <chrono>
#include <ctime>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <set>
#include <string>
#include <thread>

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

TEST(test_timed_settlement_row_keeps_outcome_and_only_a_real_body) {
  consensus::TimedSettlementRecord record;
  record.timed_txid.fill(0x11);

  // Forfeited: the opened body has a txid, but it moved nothing.
  Hash32 failed_body{};
  failed_body.fill(0x22);
  record.body_txid = failed_body;
  auto row = node::detail::timed_settlement_row(record);
  ASSERT_TRUE(row.timed_txid == record.timed_txid);
  ASSERT_TRUE(row.outcome == storage::TimedSettlementOutcome::Forfeited);
  ASSERT_TRUE(!row.body_txid.has_value());

  Tx body;
  body.outputs.push_back(TxOut{1, Bytes{0x51}});
  record.body_applied = true;
  record.applied_body = AnyTx{body};
  row = node::detail::timed_settlement_row(record);
  ASSERT_TRUE(row.outcome == storage::TimedSettlementOutcome::Applied);
  ASSERT_EQ(row.body_txid, std::optional<Hash32>(body.txid()));

  record.applied_body.reset();
  record.revealed_data = Bytes{0x01};
  ASSERT_TRUE(node::detail::timed_settlement_row(record).outcome == storage::TimedSettlementOutcome::Revealed);

  record.revealed_data.reset();
  record.body_applied = false;
  record.expired = true;
  ASSERT_TRUE(node::detail::timed_settlement_row(record).outcome == storage::TimedSettlementOutcome::Expired);
}

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

// Broadcasts send while holding the node lock, and PeerManager::send_to raises this event on the
// same thread. Scoring the peer here took that lock again and froze the validator for good.
TEST(test_node_freeze_watchdog_exits_when_the_lock_never_frees) {
  auto cfg = make_cfg(unique_test_base("/tmp/finalis_test_node_freeze_watchdog"));
  cfg.freeze_exit_seconds = 1;
  node::Node n(cfg);
  ASSERT_TRUE(n.init());
  std::atomic<int> reports{0};
  std::mutex detail_mu;
  std::string detail;
  n.set_freeze_handler_for_test([&](const std::string& d) {
    std::lock_guard<std::mutex> lk(detail_mu);
    detail = d;
    ++reports;
  });
  n.start();

  // A healthy node takes no action, however long it runs past the limit.
  std::this_thread::sleep_for(std::chrono::milliseconds(1'500));
  ASSERT_EQ(reports.load(), 0);
  // A hold shorter than the limit is not a freeze.
  n.hold_node_lock_for_test(500);
  std::this_thread::sleep_for(std::chrono::milliseconds(200));
  ASSERT_EQ(reports.load(), 0);

  n.hold_node_lock_for_test(1'500);
  std::this_thread::sleep_for(std::chrono::milliseconds(300));
  n.stop();
  ASSERT_EQ(reports.load(), 1);
  std::lock_guard<std::mutex> lk(detail_mu);
  ASSERT_TRUE(detail.find("lock_idle_s=1") != std::string::npos);
}

#ifdef __linux__
// The real exit needs a process of its own, and a fresh one: fork() here could copy a held lock.
TEST(test_node_freeze_watchdog_child) {
  const char* base = std::getenv("FINALIS_FREEZE_CHILD_BASE");
  if (base == nullptr) return;
  auto cfg = make_cfg(base);
  cfg.freeze_exit_seconds = 1;
  node::Node n(cfg);
  if (!n.init()) std::_Exit(1);
  n.start();
  n.hold_node_lock_for_test(30'000);
  std::_Exit(2);
}

TEST(test_node_freeze_watchdog_ends_the_process_with_the_restartable_code) {
  std::string base_env = "FINALIS_FREEZE_CHILD_BASE=" + unique_test_base("/tmp/finalis_test_node_freeze_exit");
  std::vector<std::string> env_storage{base_env, "FINALIS_TEST_QUIET_LOGS=1"};
  std::vector<char*> envp;
  for (auto& e : env_storage) envp.push_back(e.data());
  envp.push_back(nullptr);
  std::string self = "/proc/self/exe", arg0 = "finalis-tests", run = "--run", test = "test_node_freeze_watchdog_child";
  char* argv[] = {arg0.data(), run.data(), test.data(), nullptr};
  pid_t child = 0;
  ASSERT_TRUE(posix_spawn(&child, self.c_str(), nullptr, nullptr, argv, envp.data()) == 0);
  int status = 0;
  bool exited = false;
  for (int i = 0; i < 2'000 && !exited; ++i) {
    exited = waitpid(child, &status, WNOHANG) == child;
    if (!exited) std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  if (!exited) {
    kill(child, SIGKILL);
    waitpid(child, &status, 0);
  }
  ASSERT_TRUE(exited);
  ASSERT_TRUE(WIFEXITED(status));
  ASSERT_EQ(WEXITSTATUS(status), node::kFreezeExitCode);
}
#endif

TEST(test_node_freeze_exit_is_restartable_and_on_by_default) {
  // 78 and SIGABRT are in the units' RestartPreventExitStatus: they keep a node down on purpose.
  ASSERT_TRUE(node::kFreezeExitCode != 0 && node::kFreezeExitCode != 78);
  std::vector<std::string> args{"finalis-node"};
  std::vector<char*> argv;
  for (auto& a : args) argv.push_back(a.data());
  const auto cfg = node::parse_args(static_cast<int>(argv.size()), argv.data());
  ASSERT_TRUE(cfg.has_value());
  ASSERT_EQ(cfg->freeze_exit_seconds, 300U);
  ASSERT_EQ(node::NodeConfig{}.freeze_exit_seconds, 0U);
}

TEST(test_node_queue_overflow_while_locked_neither_deadlocks_nor_scores) {
  auto cfg = make_cfg(unique_test_base("/tmp/finalis_test_node_queue_overflow_locked"));
  node::Node n(cfg);
  ASSERT_TRUE(n.init());

  const std::string ip = "203.0.113.56";
  n.set_peer_ip_for_test(11, ip);
  std::atomic<bool> done{false};
  std::thread sender([&]() {
    for (int i = 0; i < 25; ++i) n.queue_overflow_while_locked_for_test(11);
    done.store(true);
  });
  for (int i = 0; i < 500 && !done.load(); ++i) std::this_thread::sleep_for(std::chrono::milliseconds(10));
  if (!done.load()) {
    // The sender holds the lock n.stop() needs, so a clean failure is impossible.
    std::cerr << "deadlock: queue overflow event blocked on the node lock\n";
    std::_Exit(1);
  }
  sender.join();
  const auto st = n.peer_score_status_for_test(ip);
  ASSERT_EQ(st.score, 0);
  ASSERT_TRUE(!st.banned);

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
