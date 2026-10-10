// SPDX-License-Identifier: MIT

#include "node.hpp"
#include "node_internal.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <limits>
#include <cerrno>
#include <random>
#include <signal.h>
#include <cstdlib>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string_view>

#ifndef _WIN32
#include <ifaddrs.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#include "common/address.hpp"
#include "codec/bytes.hpp"
#include "consensus/canonical_derivation.hpp"
#include "consensus/randomness.hpp"
#include "consensus/state_commitment.hpp"
#include "consensus/finalized_committee.hpp"
#include "consensus/ingress.hpp"
#include "consensus/validator_registry.hpp"
#include "consensus/monetary.hpp"
#include "common/paths.hpp"
#include "common/socket_compat.hpp"
#include "common/wide_arith.hpp"
#include "common/version.hpp"
#include "crypto/ed25519.hpp"
#include "crypto/hash.hpp"
#include "crypto/secure_memory.hpp"
#include "crypto/smt.hpp"
#include "genesis/embedded_mainnet.hpp"
#include "genesis/genesis.hpp"
#include "lightserver/server.hpp"
#include "common/keystore.hpp"
#include "common/merkle.hpp"
#include "utxo/confidential_tx.hpp"
#include "utxo/signing.hpp"

namespace finalis::node {
using namespace detail;

namespace {

constexpr std::size_t kAdaptiveTelemetryWindowEpochs = 16;

constexpr std::uint64_t kValidatorsAddrmanPersistIntervalBlocks = 3;

bool restart_debug_enabled() {
  const char* v = std::getenv("FINALIS_RESTART_DEBUG");
  if (!v) return false;
  return std::string(v) == "1" || std::string(v) == "true" || std::string(v) == "yes";
}

// Mirrors apps/finalis-cli/main.cpp's is_dangerous_root_path(): the destructive
// CLI maintenance commands (repair_state/full_reindex/fast_sync) already guard
// against an empty or filesystem-root --db path before touching it. The
// everyday node boot path had no equivalent, even though it also creates
// directories (ensure_private_dir) and opens/writes a real DB at whatever
// path is given.
bool is_dangerous_db_root_path(const std::filesystem::path& p) {
  std::error_code ec;
  const auto norm = std::filesystem::weakly_canonical(p, ec);
  if (ec) return false;
  if (norm.empty()) return true;
  if (norm == norm.root_path()) return true;
  return false;
}

constexpr std::uint64_t kStartupCheckpointFallbackMaxRewindBlocks = 128;

std::string launch_mode_name(LightserverLaunchMode mode) {
  switch (mode) {
    case LightserverLaunchMode::Explicit:
      return "explicit";
    default:
      return "disabled";
  }
}

bool runtime_logs_enabled() {
  if (debug_economics_logs_enabled() || debug_finality_logs_enabled()) return true;
  const char* quiet = std::getenv("FINALIS_TEST_QUIET_LOGS");
  return !(quiet && std::string_view(quiet) == "1");
}

}  // namespace

Node::Node(NodeConfig cfg) : cfg_(std::move(cfg)) {
  finalized_identity_ = finalized_identity_for_runtime_tip(0, zero_hash());
  finalized_randomness_ = zero_hash();
  restart_debug_ = restart_debug_enabled();
}

Node::~Node() noexcept {
  try {
    stop();
  } catch (const std::exception& e) {
    try {
      log_line(std::string("node-destructor-stop-exception error=\"") + e.what() + "\"");
    } catch (...) {
    }
  } catch (...) {
    try {
      log_line("node-destructor-stop-exception error=unknown");
    } catch (...) {
    }
  }
}

bool Node::init() {
  // Previously: std::cout.setf(std::ios::unitbuf) here, to make systemd/
  // journald followers see live log output instead of it sitting in a
  // block-buffer until exit. That turned every Node::log_line call -- most of
  // them made with mu_ held on the consensus/handshake hot path -- into a
  // synchronous flush syscall. log_line now does the same job with a
  // throttled, at-most-once-per-interval flush instead (see its definition),
  // so live-log visibility is kept without paying a syscall per log line.
  if (cfg_.max_committee == 0) cfg_.max_committee = cfg_.network.max_committee;
  genesis_source_hint_ = cfg_.genesis_path.empty() ? "embedded" : "file";
  cfg_.db_path = expand_user_home(cfg_.db_path);
  if (is_dangerous_db_root_path(cfg_.db_path)) {
    std::cerr << "refusing to use --db path that resolves to empty or filesystem root: " << cfg_.db_path << "\n";
    return false;
  }
  const std::filesystem::path dbp(cfg_.db_path);
  const auto parent = dbp.parent_path();
  if (!parent.empty()) (void)ensure_private_dir(parent.string());
  (void)ensure_private_dir(cfg_.db_path);
  mining_log_path_ = (dbp / "MiningLOG").string();
  startup_ms_ = now_ms();
  if (runtime_logs_enabled()) {
    std::cout << "[node " << cfg_.node_id << "] db-dir=" << cfg_.db_path << "\n";
    std::cout << "[node " << cfg_.node_id << "] mining-log=" << mining_log_path_ << "\n";
  }
  if (cfg_.public_mode && runtime_logs_enabled()) {
    std::cout << "[node " << cfg_.node_id
              << "] warning: public mode enabled (listening for inbound peers on " << cfg_.bind_ip << ":"
              << cfg_.p2p_port << ")\n";
  }
  discipline_ = p2p::PeerDiscipline(30, 100, cfg_.ban_seconds, cfg_.invalid_frame_ban_threshold,
                                    cfg_.invalid_frame_window_seconds);
  validator_min_bond_ = cfg_.network.validator_min_bond;
  validator_bond_min_amount_ = cfg_.network.validator_bond_min_amount;
  validator_bond_max_amount_ = cfg_.network.validator_bond_max_amount;
  validator_warmup_blocks_ = cfg_.network.validator_warmup_blocks;
  validator_cooldown_blocks_ = cfg_.network.validator_cooldown_blocks;
  validator_join_limit_window_blocks_ = cfg_.network.validator_join_limit_window_blocks;
  validator_join_limit_max_new_ = cfg_.network.validator_join_limit_max_new;
  validator_liveness_window_blocks_ = cfg_.network.liveness_window_blocks;
  validator_miss_rate_suspend_threshold_percent_ = cfg_.network.miss_rate_suspend_threshold_percent;
  validator_miss_rate_exit_threshold_percent_ = cfg_.network.miss_rate_exit_threshold_percent;
  validator_suspend_duration_blocks_ = cfg_.network.suspend_duration_blocks;
  if (cfg_.validator_min_bond_override.has_value()) validator_min_bond_ = *cfg_.validator_min_bond_override;
  if (cfg_.validator_bond_min_amount_override.has_value())
    validator_bond_min_amount_ = *cfg_.validator_bond_min_amount_override;
  if (cfg_.validator_bond_max_amount_override.has_value())
    validator_bond_max_amount_ = *cfg_.validator_bond_max_amount_override;
  if (validator_bond_max_amount_ < validator_bond_min_amount_) validator_bond_max_amount_ = validator_bond_min_amount_;
  if (cfg_.validator_warmup_blocks_override.has_value()) validator_warmup_blocks_ = *cfg_.validator_warmup_blocks_override;
  if (cfg_.validator_cooldown_blocks_override.has_value()) validator_cooldown_blocks_ = *cfg_.validator_cooldown_blocks_override;
  if (cfg_.validator_join_limit_window_blocks_override.has_value())
    validator_join_limit_window_blocks_ = *cfg_.validator_join_limit_window_blocks_override;
  if (cfg_.validator_join_limit_max_new_override.has_value())
    validator_join_limit_max_new_ = *cfg_.validator_join_limit_max_new_override;
  if (cfg_.liveness_window_blocks_override.has_value())
    validator_liveness_window_blocks_ = *cfg_.liveness_window_blocks_override;
  if (cfg_.miss_rate_suspend_threshold_percent_override.has_value())
    validator_miss_rate_suspend_threshold_percent_ = *cfg_.miss_rate_suspend_threshold_percent_override;
  if (cfg_.miss_rate_exit_threshold_percent_override.has_value())
    validator_miss_rate_exit_threshold_percent_ = *cfg_.miss_rate_exit_threshold_percent_override;
  if (cfg_.suspend_duration_blocks_override.has_value())
    validator_suspend_duration_blocks_ = *cfg_.suspend_duration_blocks_override;
  if (cfg_.deferred_exit_activation_height_override.has_value()) {
    cfg_.network.deferred_exit_activation_height = *cfg_.deferred_exit_activation_height_override;
  }
  if (runtime_logs_enabled()) {
    std::cout << "[node " << cfg_.node_id
              << "] deferred-exit-activation-height=" << cfg_.network.deferred_exit_activation_height << "\n";
  }
  mempool_.set_network(cfg_.network);
  mempool_.set_hashcash_config(policy::HashcashConfig{
      .enabled = cfg_.hashcash_enabled,
      .base_bits = cfg_.hashcash_base_bits,
      .max_bits = cfg_.hashcash_max_bits,
      .epoch_seconds = cfg_.hashcash_epoch_seconds,
      .fee_exempt_min = cfg_.hashcash_fee_exempt_min,
      .pressure_tx_threshold = cfg_.hashcash_pressure_tx_threshold,
      .pressure_step_txs = cfg_.hashcash_pressure_step_txs,
      .pressure_bits_per_step = cfg_.hashcash_pressure_bits_per_step,
      .large_tx_bytes = cfg_.hashcash_large_tx_bytes,
      .large_tx_extra_bits = cfg_.hashcash_large_tx_extra_bits,
  });

  validators_.set_rules(consensus::ValidatorRules{
      .min_bond = effective_validator_min_bond_for_height(0),
      .warmup_blocks = validator_warmup_blocks_,
      .cooldown_blocks = validator_cooldown_blocks_,
  });
  if (!init_local_validator_key()) return false;
  p2p::AddrPolicy addr_policy;
  // Tighten addrman to the network's canonical P2P port to reduce noisy
  // endpoint gossip and keep outbound discovery focused on reachable peers.
  addr_policy.required_port = cfg_.network.p2p_default_port;
  addr_policy.reject_unroutable = true;
  addrman_.set_policy(addr_policy);
  {
    std::string db_open_error;
    if (!db_.open(cfg_.db_path, &db_open_error)) {
      std::cerr << "db open failed: " << cfg_.db_path
                << (db_open_error.empty() ? "" : (" reason=\"" + db_open_error + "\"")) << "\n";
      return false;
    }
  }
  if (cfg_.reindex_on_start) {
    const bool erased = db_.erase(storage::key_consensus_state_commitment_cache());
    if (erased) log_line("startup-reindex cleared=consensus-state-commitment-cache");
  }
  if (!init_mainnet_genesis()) {
    std::cerr << "mainnet genesis init failed\n";
    return false;
  }
  if (auto tip = db_.get_tip(); tip.has_value() && tip->height == 0) {
    std::size_t erased_epoch_tickets = 0;
    std::size_t erased_best_epoch_tickets = 0;
    std::size_t erased_epoch_reward_settlements = 0;
    auto purge_prefix = [this](const char* prefix, std::size_t* erased) {
      const auto rows = db_.scan_prefix(prefix);
      for (const auto& [key, _] : rows) {
        if (!db_.erase(key)) return false;
        ++(*erased);
      }
      return true;
    };
    if (!purge_prefix("ET:", &erased_epoch_tickets) || !purge_prefix("EB:", &erased_best_epoch_tickets) ||
        !purge_prefix("ER:", &erased_epoch_reward_settlements)) {
      std::cerr << "startup hardening purge failed at genesis tip\n";
      return false;
    }
    if (erased_epoch_tickets != 0 || erased_best_epoch_tickets != 0 || erased_epoch_reward_settlements != 0) {
      log_line("startup-hardening genesis-tip-purge height=0 erased_epoch_tickets=" +
               std::to_string(erased_epoch_tickets) + " erased_best_epoch_tickets=" +
               std::to_string(erased_best_epoch_tickets) + " erased_epoch_reward_settlements=" +
               std::to_string(erased_epoch_reward_settlements));
    }
  }
  chain_id_ =
      ChainId::from_config_and_db(cfg_.network, db_, std::nullopt, genesis_source_hint_, expected_genesis_hash_);
  if (!load_state()) {
    std::cerr << "load_state failed\n";
    return false;
  }
  {
    std::ostringstream oss;
    oss << "chain-id network=" << chain_id_.network_name << " proto=" << chain_id_.protocol_version
        << " network_id=" << chain_id_.network_id_hex << " magic=" << chain_id_.magic
        << " genesis_hash=" << chain_id_.genesis_hash_hex << " genesis_source=" << chain_id_.genesis_source
        << " chain_id_ok=" << (chain_id_.chain_id_ok ? 1 : 0) << " db_dir=" << cfg_.db_path;
    log_line(oss.str());
  }
  log_line("consensus-path mode=finalized-checkpoint-committee");
  if (auto checkpoint = finalized_committee_checkpoint_for_height_locked(finalized_height_ + 1); checkpoint.has_value()) {
    log_line("epoch-committee-startup next_height=" + std::to_string(finalized_height_ + 1) +
             " source=finalized-checkpoint committee=" + std::to_string(checkpoint->ordered_members.size()));
    if (checkpoint->fallback_reason == storage::FinalizedCommitteeFallbackReason::EMERGENCY_PRIOR_COMMITTEE) {
      log_line("CRITICAL emergency-fallback-committee-active next_height=" + std::to_string(finalized_height_ + 1) +
               " committee=" + std::to_string(checkpoint->ordered_members.size()) +
               " acknowledged=" + (cfg_.acknowledge_emergency_fallback ? "true" : "false"));
      if (!cfg_.acknowledge_emergency_fallback) {
        std::cerr << "CRITICAL: committee for height " << (finalized_height_ + 1)
                  << " was derived by the emergency prior-committee rule (no eligible operators).\n"
                  << "Restart with --acknowledge-emergency-fallback to run in this state.\n";
        init_requires_operator_action_ = true;
        return false;
      }
    }
  } else {
    log_line("epoch-committee-startup next_height=" + std::to_string(finalized_height_ + 1) +
             " reason=missing-finalized-committee-checkpoint");
  }

  {
    std::lock_guard<std::mutex> lk(mu_);
    // Ensure no stale in-memory state survives re-init.
    current_round_ = 0;
    round_started_ms_ = now_ms();
    arm_round0_deadline_locked(round_started_ms_);
    candidate_block_sizes_.clear();
    proposed_in_round_.clear();
    logged_committee_rounds_.clear();
    votes_.clear_height(finalized_height_ + 1);
    prevotes_.clear_height(finalized_height_ + 1);
    timeout_votes_.clear_height(finalized_height_ + 1);
    highest_tc_by_height_.erase(finalized_height_ + 1);
    local_timeout_vote_reservations_.clear();
    reseed_local_votes_locked(finalized_height_ + 1);
    drop_stale_unfinalized_ingress_locked();
  }
  if (restart_debug_) {
    log_line("restart-debug startup-state height=" + std::to_string(finalized_height_) + " round=" +
             std::to_string(current_round_) + " transition=" + hex_encode32(finalized_identity_.id));
  }

  is_validator_ = validators_.is_active_for_height(local_key_.public_key, finalized_height_ + 1);

  round_started_ms_ = now_ms();
  last_finalized_progress_ms_ = now_ms();
#ifdef FINALIS_CHAOS_BYZANTINE
  if (const char* v = std::getenv("FINALIS_CHAOS_BYZANTINE"); v && std::string_view(v) == "1") {
    chaos_byzantine_ = true;
    log_line("CHAOS-BYZANTINE enabled: this validator violates the consensus rules on purpose");
  }
#endif
  {
    std::lock_guard<std::mutex> lk(mu_);
    arm_round0_deadline_locked(round_started_ms_);
  }
  last_finalized_tip_poll_ms_ = 0;
  {
    std::lock_guard<std::mutex> lk(mu_);
    (void)db_.put_node_runtime_status_snapshot(build_runtime_status_snapshot_locked(now_unix() * 1000));
  }

  load_persisted_peers();
  load_addrman();
  load_validators_addrman();
  for (const auto& p : cfg_.peers) bootstrap_peers_.push_back(p);
  for (const auto& s : cfg_.seeds) bootstrap_peers_.push_back(s);
  const bool allow_default_seed_fallback = !bootstrap_template_mode_;
  if (cfg_.seeds.empty() && allow_default_seed_fallback) {
    for (const auto& s : cfg_.network.default_seeds) bootstrap_peers_.push_back(s);
  }
  if (cfg_.dns_seeds) {
    dns_seed_peers_ = resolve_dns_seeds_once();
    for (const auto& d : dns_seed_peers_) bootstrap_peers_.push_back(d);
  }

  if (!cfg_.disable_p2p) {
    p2p_.configure_network(cfg_.network.magic, cfg_.network.protocol_version, cfg_.network.max_payload_len);
    p2p_.configure_limits(
        p2p::PeerManager::Limits{cfg_.handshake_timeout_ms, cfg_.frame_timeout_ms, cfg_.idle_timeout_ms,
                                 cfg_.peer_queue_max_bytes, cfg_.peer_queue_max_msgs, cfg_.max_inbound});
    p2p_.set_on_message([this](int peer_id, std::uint16_t msg_type, const Bytes& payload) {
      handle_message(peer_id, msg_type, payload);
    });
    p2p_.set_accept_filter([this](const std::string& ip) {
      if (is_bootstrap_peer_ip(ip)) return true;
      return !discipline_.is_banned(ip, now_unix());
    });
    p2p_.set_read_timeout_override([this](int peer_id, const p2p::PeerInfo& info) -> std::optional<std::uint32_t> {
      if (!info.established()) return std::nullopt;
      std::lock_guard<std::mutex> lk(mu_);
      bool sync_incomplete = bootstrap_sync_incomplete_locked(peer_id);
      bool local_sync_backlog = !requested_sync_artifacts_.empty() || !requested_sync_heights_.empty();
      bool peer_tip_diverged = false;
      if (auto it = peer_finalized_tips_.find(peer_id); it != peer_finalized_tips_.end()) {
        peer_tip_diverged = it->second.height != finalized_height_ || it->second.hash != finalized_identity_.id;
      }
      if (!sync_incomplete && !local_sync_backlog && !peer_tip_diverged) return std::nullopt;
      return std::max<std::uint32_t>(cfg_.idle_timeout_ms, 600'000u);
    });
    p2p_.set_on_event([this](int peer_id, p2p::PeerManager::PeerEventType type, const std::string& detail) {
      on_peer_event(peer_id, type, detail);
    });
    if (cfg_.listen) {
      if (!p2p_.start_listener(cfg_.bind_ip, cfg_.p2p_port)) {
        const int err = errno;
        std::cerr << "listener start failed " << cfg_.bind_ip << ":" << cfg_.p2p_port << " errno=" << err
                  << " err=\"" << std::strerror(err) << "\"\n";
        return false;
      }
      cfg_.p2p_port = p2p_.listener_port();
    }
    try_connect_bootstrap_peers();
  }

  if (bootstrap_template_mode_ && !bootstrap_validator_pubkey_.has_value() && finalized_height_ == 0 &&
      validators_.active_sorted(1).empty()) {
    const bool has_bootstrap_sources = !cfg_.disable_p2p && (!bootstrap_peers_.empty() || !dns_seed_peers_.empty());
    if (!has_bootstrap_sources && bootstrap_template_bind_validator(local_key_.public_key, true)) {
      log_line("bootstrap single-node genesis from local validator pubkey=" +
               hex_encode(Bytes(local_key_.public_key.begin(), local_key_.public_key.end())) + " action=init-self-bind");
    }
  }

  if (!ensure_required_epoch_committee_state_startup()) {
    std::cerr << "required epoch committee state repair failed db=" << cfg_.db_path
              << " finalized_height=" << finalized_height_
              << " bootstrap_template=" << (bootstrap_template_mode_ ? "yes" : "no")
              << " bootstrap_bound=" << (bootstrap_validator_pubkey_.has_value() ? "yes" : "no") << "\n";
    return false;
  }

  return true;
}

void Node::start() {
  if (running_.exchange(true)) return;
  {
    std::lock_guard<std::mutex> lk(mu_);
    const auto now = now_ms();
    round_started_ms_ = now;
    last_finalized_progress_ms_ = now;
    last_finalized_tip_poll_ms_ = 0;
  }
  if (cfg_.disable_p2p) {
    std::lock_guard<std::mutex> lk(g_local_bus_mu);
    g_local_bus_nodes.push_back(this);
  }
  loop_thread_ = std::thread([this]() { event_loop(); });
  if (!start_lightserver_child()) {
    log_line("lightserver not running mode=" + lightserver_mode_name() + " reason=start-failed");
  }
}

void Node::stop() {
  if (restart_debug_) {
    std::lock_guard<std::mutex> lk(mu_);
    log_line("restart-debug shutdown-begin height=" + std::to_string(finalized_height_) + " round=" +
             std::to_string(current_round_) + " transition=" + hex_encode32(finalized_identity_.id));
  }
  const bool was_running = running_.exchange(false);
  stop_lightserver_child();
  if (!was_running) {
    join_local_bus_tasks();
    persist_peers();
    persist_addrman();
    persist_validators_addrman({});
    p2p_.stop();
    db_.close();
    return;
  }
  if (cfg_.disable_p2p) {
    std::lock_guard<std::mutex> lk(g_local_bus_mu);
    g_local_bus_nodes.erase(std::remove(g_local_bus_nodes.begin(), g_local_bus_nodes.end(), this), g_local_bus_nodes.end());
  }
  if (loop_thread_.joinable()) {
    try {
      loop_thread_.join();
    } catch (const std::system_error& e) {
      log_line(std::string("shutdown-join-exception source=event-loop error=\"") + e.what() + "\"");
    }
  }
  if (restart_debug_) log_line("restart-debug event-loop-joined");
  if (restart_debug_) log_line("restart-debug round-timer-cancelled");
  join_local_bus_tasks();
  if (restart_debug_) log_line("restart-debug local-bus-tasks-joined");
  std::vector<p2p::PeerInfo> persisted_peers;
  persisted_peers.reserve(p2p_.peer_ids().size());
  for (int id : p2p_.peer_ids()) persisted_peers.push_back(p2p_.get_peer_info(id));
  p2p_.stop();
  if (restart_debug_) log_line("restart-debug p2p-stopped");
  persist_peers(persisted_peers);
  persist_addrman();
  persist_validators_addrman(persisted_peers);
  if (restart_debug_) log_line("restart-debug peers-persisted");
  {
    std::lock_guard<std::mutex> lk(mu_);
    (void)db_.flush();
    if (restart_debug_) log_line("restart-debug db-flushed");
    db_.close();
    if (restart_debug_) log_line("restart-debug db-closed");
  }
}

bool Node::start_lightserver_child() {
  if (cfg_.lightserver_mode == LightserverLaunchMode::Disabled) {
    log_line("lightserver disabled mode=disabled");
    return true;
  }

  {
    std::lock_guard<std::mutex> lk(lightserver_mu_);
    if (lightserver_pid_ > 0) {
      log_line("lightserver startup skipped reason=already-running pid=" + std::to_string(lightserver_pid_));
      return true;
    }
  }

  const std::string mode = lightserver_mode_name();
  const bool public_lightserver = lightserver_is_public();
  const std::string exposure = public_lightserver ? "public" : "local-only";
  bool sibling_found = false;
  const std::string binary = lightserver_binary_path(&sibling_found);
  {
    std::lock_guard<std::mutex> lk(lightserver_mu_);
    lightserver_exec_path_ = binary;
  }
  log_line("lightserver enabled mode=" + mode + " exec=" + binary +
           " exec_source=" + (sibling_found ? "sibling" : "PATH") + " bind=" + cfg_.lightserver_bind +
           " port=" + std::to_string(cfg_.lightserver_port) + " exposure=" + exposure);

  if (!public_lightserver) {
    if (auto detected_ip = detect_possible_public_ip(); detected_ip.has_value()) {
      log_line("detected possible public IP: " + *detected_ip);
      log_line("lightserver is bound to " + cfg_.lightserver_bind +
               "; to expose publicly use: --public --lightserver-bind 0.0.0.0");
    }
  }

  std::string bind_error;
  if (!preflight_lightserver_bind(&bind_error)) {
    log_line("lightserver startup failed mode=" + mode + " reason=" + bind_error);
    return false;
  }

#ifdef _WIN32
  log_line("lightserver child launch unsupported on windows; start finalis-lightserver.exe separately");
  return true;
#else

  std::vector<std::string> args{
      binary,
      "--db",
      cfg_.db_path,
      "--bind",
      cfg_.lightserver_bind,
      "--port",
      std::to_string(cfg_.lightserver_port),
      "--relay-host",
      "127.0.0.1",
      "--relay-port",
      std::to_string(cfg_.p2p_port),
      // Pin the child's admin socket to the path clients (CLI/wallet kDefaultAdminRpcUrl) dial.
      // Two args: the lightserver parser does not accept --admin-socket=<path>.
      "--admin-socket",
      lightserver::kDefaultAdminSocketPath,
  };

  std::vector<char*> argv;
  argv.reserve(args.size() + 1);
  for (auto& arg : args) argv.push_back(arg.data());
  argv.push_back(nullptr);

  const pid_t pid = fork();
  if (pid < 0) {
    log_line("lightserver startup failed mode=" + mode + " reason=fork");
    return false;
  }
  if (pid == 0) {
    execv(binary.c_str(), argv.data());
    argv[0] = const_cast<char*>("finalis-lightserver");
    execvp("finalis-lightserver", argv.data());
    std::perror("finalis-lightserver exec");
    _exit(127);
  }

  {
    std::lock_guard<std::mutex> lk(lightserver_mu_);
    lightserver_pid_ = static_cast<int>(pid);
  }
  ::usleep(200 * 1000);
  int status = 0;
  const pid_t waited = ::waitpid(pid, &status, WNOHANG);
  if (waited == pid) {
    std::lock_guard<std::mutex> lk(lightserver_mu_);
    lightserver_pid_ = -1;
    std::ostringstream oss;
    oss << "lightserver startup failed mode=" << mode << " pid=" << pid;
    if (WIFEXITED(status)) {
      const int code = WEXITSTATUS(status);
      oss << " exit_code=" << code;
      if (code == 1) oss << " note=check bind/db/init in child";
    } else if (WIFSIGNALED(status)) {
      oss << " signal=" << WTERMSIG(status);
    }
    log_line(oss.str());
    return false;
  }
  log_line("lightserver startup success mode=" + mode + " pid=" + std::to_string(pid));
  if (!cfg_.listen || cfg_.disable_p2p) {
    log_line("lightserver note: node listener is disabled; read RPC works, but tx relay to the node may fail");
  }
  return true;
#endif
}

void Node::stop_lightserver_child() {
#ifdef _WIN32
  std::lock_guard<std::mutex> lk(lightserver_mu_);
  lightserver_pid_ = -1;
  return;
#else
  constexpr int kTermWaitIterations = 20;   // 2s total (20 * 100ms)
  constexpr int kKillWaitIterations = 50;   // 5s total (50 * 100ms)
  pid_t pid = -1;
  {
    std::lock_guard<std::mutex> lk(lightserver_mu_);
    if (lightserver_pid_ <= 0) return;
    pid = static_cast<pid_t>(lightserver_pid_);
    lightserver_pid_ = -1;
  }
  int status = 0;
  const pid_t already = ::waitpid(pid, &status, WNOHANG);
  if (already == pid) {
    log_line("lightserver exit observed during stop pid=" + std::to_string(pid));
    return;
  }
  log_line("stopping lightserver pid=" + std::to_string(pid));
  if (::kill(pid, SIGTERM) != 0 && errno == ESRCH) {
    (void)::waitpid(pid, &status, WNOHANG);
    return;
  }
  for (int i = 0; i < kTermWaitIterations; ++i) {
    const pid_t waited = ::waitpid(pid, &status, WNOHANG);
    if (waited == pid) return;
    ::usleep(100 * 1000);
  }
  log_line("lightserver stop escalation pid=" + std::to_string(pid) + " signal=SIGKILL");
  if (::kill(pid, SIGKILL) != 0 && errno == ESRCH) {
    (void)::waitpid(pid, &status, WNOHANG);
    return;
  }
  for (int i = 0; i < kKillWaitIterations; ++i) {
    const pid_t waited = ::waitpid(pid, &status, WNOHANG);
    if (waited == pid) return;
    ::usleep(100 * 1000);
  }
  // Avoid blocking shutdown indefinitely on a wedged child process.
  log_line("lightserver stop timed out pid=" + std::to_string(pid) + " status=detached");
#endif
}

bool Node::reap_lightserver_child(bool verbose) {
#ifdef _WIN32
  (void)verbose;
  return false;
#else
  pid_t pid = -1;
  {
    std::lock_guard<std::mutex> lk(lightserver_mu_);
    if (lightserver_pid_ <= 0) return false;
    pid = static_cast<pid_t>(lightserver_pid_);
  }
  int status = 0;
  const pid_t waited = ::waitpid(pid, &status, WNOHANG);
  if (waited == 0) return false;
  if (waited < 0) {
    if (errno == ECHILD) {
      std::lock_guard<std::mutex> lk(lightserver_mu_);
      if (lightserver_pid_ == pid) lightserver_pid_ = -1;
    }
    return false;
  }
  {
    std::lock_guard<std::mutex> lk(lightserver_mu_);
    if (lightserver_pid_ == pid) lightserver_pid_ = -1;
  }
  if (verbose) {
    std::ostringstream oss;
    oss << "lightserver exited pid=" << pid;
    if (WIFEXITED(status)) {
      oss << " exit_code=" << WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
      oss << " signal=" << WTERMSIG(status);
    }
    log_line(oss.str());
  }
  return true;
#endif
}

bool Node::preflight_lightserver_bind(std::string* err) const {
  if (!net::ensure_sockets()) {
    if (err) *err = "socket-init";
    return false;
  }
  const auto fd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (!net::valid_socket(fd)) {
    if (err) *err = "socket-open";
    return false;
  }
  (void)net::set_reuseaddr(fd);
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(cfg_.lightserver_port);
  if (::inet_pton(AF_INET, cfg_.lightserver_bind.c_str(), &addr.sin_addr) != 1) {
    if (err) *err = "invalid-bind-address";
    net::close_socket(fd);
    return false;
  }
  if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
    if (err) {
      std::ostringstream oss;
      const int code = net::socket_last_error();
      oss << "bind-failed errno=" << code << " (" << net::socket_error_string(code) << ")";
      *err = oss.str();
    }
    net::close_socket(fd);
    return false;
  }
  net::close_socket(fd);
  return true;
}

std::string Node::lightserver_mode_name() const {
  return launch_mode_name(cfg_.lightserver_mode);
}

std::string Node::lightserver_binary_path(bool* sibling_found) const {
  if (sibling_found) *sibling_found = false;
#ifdef _WIN32
  return "finalis-lightserver.exe";
#else
  char exe_path[4096] = {};
  const ssize_t n = ::readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
  if (n > 0) {
    exe_path[n] = '\0';
    std::filesystem::path p(exe_path);
    const std::filesystem::path sibling = p.parent_path() / "finalis-lightserver";
    std::error_code ec;
    if (std::filesystem::exists(sibling, ec) && !ec) {
      if (sibling_found) *sibling_found = true;
      return sibling.string();
    }
  }
  return "finalis-lightserver";
#endif
}

bool Node::lightserver_is_public() const {
  return !is_local_only_bind(cfg_.lightserver_bind) && cfg_.lightserver_bind != "127.0.0.1";
}

NodeStatus Node::status() const {
  std::lock_guard<std::mutex> lk(mu_);
  NodeStatus s;
  s.network_name = cfg_.network.name;
  s.protocol_version = cfg_.network.protocol_version;
  s.magic = cfg_.network.magic;
  s.genesis_hash = chain_id_.genesis_hash_hex;
  s.genesis_source = chain_id_.genesis_source;
  s.chain_id_ok = chain_id_.chain_id_ok;
  s.db_dir = cfg_.db_path;
  s.network_id_short = hex_encode(Bytes(cfg_.network.network_id.begin(), cfg_.network.network_id.begin() + 4));
  s.height = finalized_height_;
  s.round = current_round_;
  s.transition_hash = finalized_identity_.id;
  s.transition_hash_short = short_hash_hex(finalized_identity_.id);
  auto leader = leader_for_height_round(finalized_height_ + 1, current_round_);
  if (leader.has_value()) s.leader = *leader;
  s.votes_for_current = 0;
  s.peers = peer_count();
  s.established_peers = established_peer_count();
  s.mempool_size = mempool_.size();
  const auto committee = committee_for_height_round(finalized_height_ + 1, current_round_);
  s.committee_size = committee.size();
  s.quorum_threshold = consensus::quorum_threshold(committee.size());
  s.addrman_size = addrman_.size();
  s.inbound_connected = cfg_.disable_p2p ? 0 : p2p_.inbound_count();
  s.outbound_connected = cfg_.disable_p2p ? peer_count() : p2p_.outbound_count();
  s.consensus_state = consensus_state_locked(now_ms(), &s.observed_signers, &s.quorum_threshold);
  s.last_bootstrap_source = last_bootstrap_source_;
  s.rejected_network_id = rejected_network_id_;
  s.rejected_protocol_version = rejected_protocol_version_;
  s.rejected_pre_handshake = rejected_pre_handshake_;
  s.consensus_version = kFixedValidationRulesVersion;
  s.participation_eligible_signers = static_cast<std::uint64_t>(last_participation_eligible_signers_);
  s.bootstrap_template_mode = bootstrap_template_mode_;
  if (bootstrap_validator_pubkey_.has_value()) {
    s.bootstrap_validator_pubkey =
        hex_encode(Bytes(bootstrap_validator_pubkey_->begin(), bootstrap_validator_pubkey_->end()));
  }
  s.pending_bootstrap_joiners = pending_join_request_count_locked();
  s.consensus_model = "finalized-checkpoint-committee-bft";
  s.current_round_slot = current_round_;
  if (auto checkpoint = finalized_committee_checkpoint_for_height_locked(finalized_height_ + 1); checkpoint.has_value()) {
    s.active_epoch_committee_size = checkpoint->ordered_members.size();
    s.availability_checkpoint_derivation_mode = checkpoint_derivation_mode_name(checkpoint->derivation_mode);
    s.availability_checkpoint_fallback_reason = checkpoint_fallback_reason_name(checkpoint->fallback_reason);
    s.availability_fallback_sticky =
        checkpoint->fallback_reason == storage::FinalizedCommitteeFallbackReason::HYSTERESIS_RECOVERY_PENDING;
    s.adaptive_target_committee_size = checkpoint->adaptive_target_committee_size;
    s.adaptive_min_eligible = checkpoint->adaptive_min_eligible;
    s.adaptive_min_bond = checkpoint->adaptive_min_bond;
    s.qualified_depth = checkpoint->qualified_depth;
    s.adaptive_slack = static_cast<std::int64_t>(checkpoint->qualified_depth) -
                       static_cast<std::int64_t>(checkpoint->adaptive_min_eligible);
    s.target_expand_streak = checkpoint->target_expand_streak;
    s.target_contract_streak = checkpoint->target_contract_streak;
    std::ostringstream committee;
    for (std::size_t i = 0; i < checkpoint->ordered_members.size(); ++i) {
      if (i) committee << ",";
      committee << short_pub_hex(checkpoint->ordered_members[i]);
    }
    s.active_epoch_committee_members_short = committee.str();
  }
  s.availability_epoch = availability_state_.current_epoch;
  s.availability_retained_prefix_count = availability_state_.retained_prefixes.size();
  s.availability_tracked_operator_count = availability_state_.operators.size();
  auto status_availability_cfg = cfg_.availability;
  if (auto checkpoint = finalized_committee_checkpoint_for_height_locked(finalized_height_ + 1); checkpoint.has_value()) {
    status_availability_cfg = consensus::availability_config_with_min_bond(cfg_.availability, checkpoint->adaptive_min_bond);
    s.availability_eligible_operator_count = consensus::count_eligible_operators_at_checkpoint(
        validators_, finalized_height_ + 1, availability_state_, status_availability_cfg);
    s.availability_below_min_eligible =
        s.adaptive_min_eligible != 0 && s.availability_eligible_operator_count < s.adaptive_min_eligible;
  } else {
    s.availability_eligible_operator_count =
        consensus::count_eligible_operators_at_checkpoint(validators_, finalized_height_ + 1, availability_state_,
                                                          status_availability_cfg);
    s.availability_below_min_eligible = false;
  }
  s.availability_state_rebuild_triggered = availability_state_rebuild_triggered_;
  s.availability_state_rebuild_reason = availability_state_rebuild_reason_;
  if (auto local_operator = local_operator_pubkey_locked(); local_operator.has_value()) {
    for (const auto& operator_state : availability_state_.operators) {
      if (operator_state.operator_pubkey != *local_operator) continue;
      s.availability_local_operator_known = true;
      s.availability_local_operator_pubkey =
          hex_encode(Bytes(operator_state.operator_pubkey.begin(), operator_state.operator_pubkey.end()));
      s.availability_local_operator_status = availability_status_name(operator_state.status);
      s.availability_local_service_score = operator_state.service_score;
      s.availability_local_warmup_epochs = operator_state.warmup_epochs;
      s.availability_local_successful_audits = operator_state.successful_audits;
      s.availability_local_late_audits = operator_state.late_audits;
      s.availability_local_missed_audits = operator_state.missed_audits;
      s.availability_local_invalid_audits = operator_state.invalid_audits;
      s.availability_local_retained_prefix_count = operator_state.retained_prefix_count;
      s.availability_local_eligibility_score =
          availability::operator_eligibility_score(operator_state, cfg_.availability);
      s.availability_local_seat_budget = availability::operator_seat_budget(operator_state, cfg_.availability);
      break;
    }
  }
  const auto adaptive_telemetry = db_.load_adaptive_epoch_telemetry();
  const auto adaptive_summary =
      storage::summarize_adaptive_epoch_telemetry(adaptive_telemetry, kAdaptiveTelemetryWindowEpochs);
  s.adaptive_fallback_rate_bps = adaptive_summary.fallback_rate_bps;
  s.adaptive_sticky_fallback_rate_bps = adaptive_summary.sticky_fallback_rate_bps;
  s.adaptive_fallback_window_epochs = adaptive_summary.sample_count;
  s.adaptive_near_threshold_operation = adaptive_summary.near_threshold_operation;
  s.adaptive_prolonged_expand_buildup = adaptive_summary.prolonged_expand_buildup;
  s.adaptive_prolonged_contract_buildup = adaptive_summary.prolonged_contract_buildup;
  s.adaptive_repeated_sticky_fallback = adaptive_summary.repeated_sticky_fallback;
  s.adaptive_depth_collapse_after_bond_increase = adaptive_summary.depth_collapse_after_bond_increase;
  if (auto runtime = db_.get_node_runtime_status_snapshot(); runtime.has_value()) {
    s.healthy_peer_count = runtime->healthy_peer_count;
    s.observed_network_height_known = runtime->observed_network_height_known;
    s.observed_network_finalized_height = runtime->observed_network_finalized_height;
    s.finalized_lag = runtime->finalized_lag;
    s.peer_height_disagreement = runtime->peer_height_disagreement;
    s.next_height_committee_available = runtime->next_height_committee_available;
    s.next_height_proposer_available = runtime->next_height_proposer_available;
    s.registration_ready = runtime->registration_ready;
    s.registration_readiness_stable_samples = runtime->readiness_stable_samples;
    s.registration_readiness_blockers = runtime->readiness_blockers_csv;
  }
  return s;
}

storage::NodeRuntimeStatusSnapshot Node::build_runtime_status_snapshot_locked(std::uint64_t now_ms) {
  storage::NodeRuntimeStatusSnapshot snapshot;
  snapshot.chain_id_ok = chain_id_.chain_id_ok;
  snapshot.db_open = true;
  snapshot.local_finalized_height = finalized_height_;
  snapshot.established_peer_count = established_peer_count();
  snapshot.inbound_connected = cfg_.disable_p2p ? 0 : p2p_.inbound_count();
  snapshot.outbound_connected = cfg_.disable_p2p ? peer_count() : p2p_.outbound_count();
  snapshot.addrman_size = addrman_.size();
  snapshot.outbound_target = cfg_.outbound_target;
  if (auto advertised = advertised_endpoint_locked(); advertised.has_value()) {
    snapshot.advertised_endpoint_present = true;
    snapshot.advertised_endpoint = advertised->key();
    snapshot.advertised_endpoint_likely_public = advertised_endpoint_likely_public(*advertised);
  }
  snapshot.stun_enabled = cfg_.listen && cfg_.public_mode && !cfg_.disable_p2p && cfg_.external_endpoint.empty() &&
                          !cfg_.stun_servers.empty();
  snapshot.stun_last_success = stun_last_success_;
  snapshot.stun_last_attempt_unix_ms = stun_last_attempt_ms_;
  snapshot.stun_last_success_unix_ms = stun_last_success_ms_;
  snapshot.stun_last_server = stun_last_server_;
  snapshot.stun_last_error_code = stun_last_error_code_;
  snapshot.stun_backoff_until_unix_ms = stun_backoff_until_ms_;
  snapshot.stun_endpoint_change_pending = stun_endpoint_change_pending_;
  snapshot.stun_endpoint_change_hits = stun_candidate_hits_;
  snapshot.stun_endpoint_change_required_hits = std::max<std::uint32_t>(2, cfg_.stun_hysteresis_samples);
  if (stun_candidate_endpoint_.has_value()) {
    snapshot.stun_endpoint_candidate = stun_candidate_endpoint_->key();
  }
  snapshot.abstaining_heights.assign(abstain_heights_.begin(), abstain_heights_.end());

  snapshot.next_height_committee_available = !committee_for_height_round(finalized_height_ + 1, current_round_).empty();
  snapshot.next_height_proposer_available = leader_for_height_round(finalized_height_ + 1, current_round_).has_value();
  snapshot.captured_at_unix_ms = now_ms;
  snapshot.mempool_tx_count = static_cast<std::uint64_t>(mempool_.size());
  snapshot.mempool_bytes = static_cast<std::uint64_t>(mempool_.total_bytes());
  const auto mempool_stats = mempool_.policy_stats();
  snapshot.mempool_full =
      snapshot.mempool_tx_count >= mempool::Mempool::kMaxTxCount || snapshot.mempool_bytes >= mempool::Mempool::kMaxPoolBytes;
  if (mempool_stats.min_fee_rate_to_enter_when_full.has_value()) {
    snapshot.min_fee_rate_to_enter_when_full_milliunits_per_byte =
        static_cast<std::uint64_t>((*mempool_stats.min_fee_rate_to_enter_when_full * 1000.0) + 0.5);
  }
  snapshot.rejected_full_not_good_enough = static_cast<std::uint64_t>(mempool_stats.rejected_full_not_good_enough);
  snapshot.evicted_for_better_incoming = static_cast<std::uint64_t>(mempool_stats.evicted_for_better_incoming);
  snapshot.min_relay_fee = effective_min_relay_fee_for_height(finalized_height_ + 1);
  snapshot.availability_epoch = availability_state_.current_epoch;
  snapshot.availability_retained_prefix_count =
      static_cast<std::uint64_t>(availability_state_.retained_prefixes.size());
  snapshot.availability_tracked_operator_count = static_cast<std::uint64_t>(availability_state_.operators.size());
  snapshot.availability_state_rebuild_triggered = availability_state_rebuild_triggered_;
  snapshot.availability_state_rebuild_reason = availability_state_rebuild_reason_;
  if (auto checkpoint = finalized_committee_checkpoint_for_height_locked(finalized_height_ + 1); checkpoint.has_value()) {
    const auto adaptive_availability_cfg =
        consensus::availability_config_with_min_bond(cfg_.availability, checkpoint->adaptive_min_bond);
    snapshot.adaptive_target_committee_size = checkpoint->adaptive_target_committee_size;
    snapshot.adaptive_min_eligible = checkpoint->adaptive_min_eligible;
    snapshot.adaptive_min_bond = checkpoint->adaptive_min_bond;
    snapshot.qualified_depth = checkpoint->qualified_depth;
    snapshot.adaptive_slack = static_cast<std::int64_t>(checkpoint->qualified_depth) -
                              static_cast<std::int64_t>(checkpoint->adaptive_min_eligible);
    snapshot.target_expand_streak = checkpoint->target_expand_streak;
    snapshot.target_contract_streak = checkpoint->target_contract_streak;
    snapshot.availability_eligible_operator_count = consensus::count_eligible_operators_at_checkpoint(
        validators_, finalized_height_ + 1, availability_state_, adaptive_availability_cfg);
    snapshot.availability_below_min_eligible =
        snapshot.availability_eligible_operator_count < checkpoint->adaptive_min_eligible;
    snapshot.availability_checkpoint_derivation_mode = static_cast<std::uint8_t>(checkpoint->derivation_mode);
    snapshot.availability_checkpoint_fallback_reason = static_cast<std::uint8_t>(checkpoint->fallback_reason);
    snapshot.availability_fallback_sticky =
        checkpoint->fallback_reason == storage::FinalizedCommitteeFallbackReason::HYSTERESIS_RECOVERY_PENDING;
  } else {
    snapshot.availability_eligible_operator_count =
        consensus::count_eligible_operators_at_checkpoint(validators_, finalized_height_ + 1, availability_state_,
                                                          cfg_.availability);
    snapshot.availability_below_min_eligible = false;
  }
  const auto adaptive_summary =
      storage::summarize_adaptive_epoch_telemetry(db_.load_adaptive_epoch_telemetry(), kAdaptiveTelemetryWindowEpochs);
  snapshot.adaptive_fallback_rate_bps = adaptive_summary.fallback_rate_bps;
  snapshot.adaptive_sticky_fallback_rate_bps = adaptive_summary.sticky_fallback_rate_bps;
  snapshot.adaptive_fallback_window_epochs = adaptive_summary.sample_count;
  snapshot.adaptive_near_threshold_operation = adaptive_summary.near_threshold_operation;
  snapshot.adaptive_prolonged_expand_buildup = adaptive_summary.prolonged_expand_buildup;
  snapshot.adaptive_prolonged_contract_buildup = adaptive_summary.prolonged_contract_buildup;
  snapshot.adaptive_repeated_sticky_fallback = adaptive_summary.repeated_sticky_fallback;
  snapshot.adaptive_depth_collapse_after_bond_increase = adaptive_summary.depth_collapse_after_bond_increase;
  if (auto local_operator = local_operator_pubkey_locked(); local_operator.has_value()) {
    for (const auto& operator_state : availability_state_.operators) {
      if (operator_state.operator_pubkey != *local_operator) continue;
      snapshot.availability_local_operator_known = true;
      snapshot.availability_local_operator_pubkey = operator_state.operator_pubkey;
      snapshot.availability_local_operator_status = static_cast<std::uint8_t>(operator_state.status);
      snapshot.availability_local_service_score = operator_state.service_score;
      snapshot.availability_local_warmup_epochs = operator_state.warmup_epochs;
      snapshot.availability_local_successful_audits = operator_state.successful_audits;
      snapshot.availability_local_late_audits = operator_state.late_audits;
      snapshot.availability_local_missed_audits = operator_state.missed_audits;
      snapshot.availability_local_invalid_audits = operator_state.invalid_audits;
      snapshot.availability_local_retained_prefix_count = operator_state.retained_prefix_count;
      snapshot.availability_local_eligibility_score =
          availability::operator_eligibility_score(operator_state, cfg_.availability);
      snapshot.availability_local_seat_budget = availability::operator_seat_budget(operator_state, cfg_.availability);
      break;
    }
  }

  const bool isolated_mode = cfg_.disable_p2p;
  std::vector<std::uint64_t> healthy_peer_heights;
  std::vector<std::uint64_t> healthy_peer_heights_observed;
  std::vector<std::uint64_t> fresh_peer_heights;
  std::vector<std::uint64_t> fresh_peer_heights_with_floor;
  std::vector<std::uint64_t> validator_fresh_peer_heights;
  bool bootstrap_sync_incomplete = false;
  constexpr std::uint64_t kObservedHeightExtremeLagBlocks = 64;
  const std::uint64_t tip_freshness_ms =
      std::max<std::uint64_t>(kFinalizedTipFreshnessFloorMs, static_cast<std::uint64_t>(cfg_.network.round_timeout_ms) * 3);
  for (const auto& [peer_id, tip] : peer_finalized_tips_) {
    if (!p2p_.get_peer_info(peer_id).established()) continue;
    healthy_peer_heights.push_back(tip.height);
    const bool extreme_lag =
        finalized_height_ > tip.height && (finalized_height_ - tip.height) > kObservedHeightExtremeLagBlocks;
    if (!extreme_lag) healthy_peer_heights_observed.push_back(tip.height);
    bool active_validator_peer = false;
    if (auto validator_it = peer_validator_pubkeys_.find(peer_id); validator_it != peer_validator_pubkeys_.end()) {
      active_validator_peer = validators_.is_active_for_height(validator_it->second, finalized_height_ + 1);
    }
    if (auto seen_it = peer_finalized_tip_seen_ms_.find(peer_id); seen_it != peer_finalized_tip_seen_ms_.end()) {
      const std::uint64_t age_ms = now_ms >= seen_it->second ? (now_ms - seen_it->second) : 0;
      if (age_ms <= tip_freshness_ms && !extreme_lag) {
        fresh_peer_heights.push_back(tip.height);
        if (tip.height + 2 >= finalized_height_) fresh_peer_heights_with_floor.push_back(tip.height);
        if (active_validator_peer) validator_fresh_peer_heights.push_back(tip.height);
      }
    }
    if (bootstrap_sync_incomplete_locked(peer_id)) bootstrap_sync_incomplete = true;
  }
  snapshot.bootstrap_sync_incomplete = bootstrap_sync_incomplete;
  snapshot.healthy_peer_count = healthy_peer_heights.size();
  if (isolated_mode) {
    snapshot.observed_network_height_known = true;
    snapshot.observed_network_finalized_height = finalized_height_;
  } else if (!healthy_peer_heights_observed.empty()) {
    std::sort(healthy_peer_heights_observed.begin(), healthy_peer_heights_observed.end());
    if (!fresh_peer_heights.empty()) std::sort(fresh_peer_heights.begin(), fresh_peer_heights.end());
    if (!fresh_peer_heights_with_floor.empty()) std::sort(fresh_peer_heights_with_floor.begin(), fresh_peer_heights_with_floor.end());
    if (!validator_fresh_peer_heights.empty()) {
      std::sort(validator_fresh_peer_heights.begin(), validator_fresh_peer_heights.end());
    }
    const auto* observed_source = &healthy_peer_heights_observed;
    if (!validator_fresh_peer_heights.empty()) {
      observed_source = &validator_fresh_peer_heights;
    } else if (!fresh_peer_heights_with_floor.empty()) {
      observed_source = &fresh_peer_heights_with_floor;
    } else if (!fresh_peer_heights.empty()) {
      observed_source = &fresh_peer_heights;
    }
    const auto& disagreement_heights = *observed_source;
    if (!disagreement_heights.empty()) {
      const auto min_height = disagreement_heights.front();
      const auto max_height = disagreement_heights.back();
      snapshot.peer_height_disagreement =
          disagreement_heights.size() > 1 && max_height > min_height && (max_height - min_height) > 2;
    }
    snapshot.observed_network_height_known = true;
    const auto& observed_heights = *observed_source;
    snapshot.observed_network_finalized_height = observed_heights[observed_heights.size() / 2];
  }
  if (snapshot.observed_network_height_known && snapshot.observed_network_finalized_height > finalized_height_) {
    snapshot.finalized_lag = snapshot.observed_network_finalized_height - finalized_height_;
  }

  std::vector<std::string> blockers;
  if (!snapshot.chain_id_ok) blockers.push_back("chain_id_mismatch");
  if (!isolated_mode && snapshot.healthy_peer_count == 0) blockers.push_back("no_healthy_peers");
  if (!isolated_mode && !snapshot.observed_network_height_known) blockers.push_back("observed_height_unknown");
  if (snapshot.peer_height_disagreement) blockers.push_back("peer_height_disagreement");
  if (snapshot.finalized_lag > 2) blockers.push_back("lag_exceeds_threshold");
  if (!snapshot.next_height_committee_available) blockers.push_back("next_height_committee_unavailable");
  if (!snapshot.next_height_proposer_available) blockers.push_back("next_height_proposer_unavailable");
  if (snapshot.bootstrap_sync_incomplete) blockers.push_back("bootstrap_sync_incomplete");
  if (!isolated_mode && snapshot.established_peer_count == 0) blockers.push_back("no_established_peers");
  if (!isolated_mode && snapshot.outbound_connected == 0) blockers.push_back("no_outbound_peers");
  // Inbound reachability is important for network health, but not required for
  // safe local registration gating. Many operators run behind strict NAT/ACLs.
  // Keep as telemetry/warning only, not a hard readiness blocker.
  if (!isolated_mode && cfg_.listen && cfg_.public_mode && !snapshot.advertised_endpoint_present) {
    blockers.push_back("no_advertised_endpoint");
  }
  if (!isolated_mode && cfg_.listen && cfg_.public_mode && snapshot.advertised_endpoint_present &&
      !snapshot.advertised_endpoint_likely_public) {
    blockers.push_back("advertised_endpoint_not_public");
  }
  if (!isolated_mode && snapshot.stun_enabled && !snapshot.stun_last_success &&
      !snapshot.advertised_endpoint_present) {
    blockers.push_back("stun_discovery_failed");
  }
  // Addrman fullness against outbound_target is an operator quality signal, not
  // a correctness/safety precondition for registration.

  snapshot.registration_ready_preflight = blockers.empty();
  if (snapshot.registration_ready_preflight) {
    ++registration_ready_streak_;
  } else {
    registration_ready_streak_ = 0;
  }
  snapshot.readiness_stable_samples = registration_ready_streak_;
  snapshot.registration_ready = snapshot.registration_ready_preflight && registration_ready_streak_ >= 2;
  for (std::size_t i = 0; i < blockers.size(); ++i) {
    if (i) snapshot.readiness_blockers_csv += ",";
    snapshot.readiness_blockers_csv += blockers[i];
  }
  snapshot.readiness_failure_codes_csv = snapshot.readiness_blockers_csv;
  return snapshot;
}

void Node::event_loop() {
  while (running_) {
    (void)reap_lightserver_child(true);
    std::optional<p2p::ProposeMsg> propose_to_send;
    std::optional<TimeoutVote> timeout_vote_to_broadcast;
    LocalVoteRebroadcast votes_to_rebroadcast;
    std::vector<int> keepalive_peers;
    std::vector<int> finalized_tip_poll_peers;
    bool should_build_proposal = false;
    bool should_persist_validators_addrman = false;
    bool force_validator_redial = false;
    std::uint64_t build_height = 0;
    std::uint32_t build_round = 0;
    {
      std::lock_guard<std::mutex> lk(mu_);
      const std::uint64_t h = finalized_height_ + 1;
      validators_.advance_height(h);
      const std::uint32_t cv = kFixedValidationRulesVersion;
      mempool_.set_validation_context(special_validation_context_locked(h));
      const std::uint64_t now_ms = this->now_ms();
      const std::uint64_t now_unix_ms = now_unix() * 1000;
      if (now_ms >= last_runtime_status_persist_ms_ + 1000) {
        auto runtime = build_runtime_status_snapshot_locked(now_unix_ms);
        (void)db_.put_node_runtime_status_snapshot(runtime);
        last_runtime_status_persist_ms_ = now_ms;
      }
      if (!cfg_.disable_p2p && finalized_height_ >= last_validators_addrman_persist_height_ + kValidatorsAddrmanPersistIntervalBlocks) {
        should_persist_validators_addrman = true;
        last_validators_addrman_persist_height_ = finalized_height_;
      }
      const std::uint64_t min_block_interval_ms = static_cast<std::uint64_t>(cfg_.network.min_block_interval_ms);
      const std::uint64_t ticket_window_floor_ms = std::min<std::uint64_t>(1000, min_block_interval_ms);
      const std::uint64_t ticket_window_ms =
          std::max<std::uint64_t>(ticket_window_floor_ms, min_block_interval_ms / 2);
      const bool ticket_window_elapsed = now_ms >= last_finalized_progress_ms_ + ticket_window_ms;
      const bool block_interval_elapsed =
          now_ms >= last_finalized_progress_ms_ + min_block_interval_ms;
      // Round 0 cannot use the TC bypass, so its leader may only propose once
      // both the ticket window and the block interval have elapsed. Start the
      // round-0 timer (and its timeout-vote grace) at that point, so round 0
      // gets its full timeout after proposing becomes legal instead of timing
      // out while still gated.
      if (current_round_ == 0) {
        const std::uint64_t round0_start =
            last_finalized_progress_ms_ + std::max<std::uint64_t>(ticket_window_ms, min_block_interval_ms);
        if (round_started_ms_ < round0_start) {
          round_started_ms_ = round0_start;
          arm_round0_deadline_locked(round0_start);
        }
      }
      maybe_self_bootstrap_template(now_ms);
      std::string repair_reason;
      (void)maybe_repair_next_height_locked(now_ms, &repair_reason);

      if (now_ms > last_summary_log_ms_ + 30'000) {
        const auto committee = committee_for_height_round(h, current_round_);
        const std::size_t quorum = consensus::quorum_threshold(committee.size());
        std::size_t observed = 0;
        std::size_t q = quorum;
        const auto state = consensus_state_locked(now_ms, &observed, &q);
      if (!runtime_logs_enabled()) {
        last_summary_log_ms_ = now_ms;
      } else if (cfg_.log_json) {
        std::ostringstream j;
          j << "{\"type\":\"summary\",\"network\":\"" << cfg_.network.name << "\",\"protocol_version\":"
            << cfg_.network.protocol_version << ",\"network_id\":\""
            << hex_encode(Bytes(cfg_.network.network_id.begin(), cfg_.network.network_id.begin() + 4)) << "\",\"magic\":"
            << cfg_.network.magic << ",\"db_dir\":\"" << cfg_.db_path << "\",\"height\":" << finalized_height_
            << ",\"transition\":\"" << short_hash_hex(finalized_identity_.id) << "\",\"genesis_hash\":\""
            << chain_id_.genesis_hash_hex << "\",\"genesis_source\":\"" << chain_id_.genesis_source
            << "\",\"chain_id_ok\":" << (chain_id_.chain_id_ok ? "true" : "false") << ",\"peers\":" << peer_count()
            << ",\"established_peers\":" << established_peer_count()
            << ",\"outbound_connected\":" << (cfg_.disable_p2p ? peer_count() : p2p_.outbound_count())
            << ",\"inbound_connected\":" << (cfg_.disable_p2p ? 0 : p2p_.inbound_count())
            << ",\"outbound_target\":" << cfg_.outbound_target << ",\"addrman_size\":" << addrman_.size()
            << ",\"bootstrap_source_last\":\"" << last_bootstrap_source_ << "\",\"committee_size\":" << committee.size()
            << ",\"quorum_threshold\":" << q << ",\"observed_signers\":" << observed
            << ",\"consensus_state\":\"" << state << "\",\"consensus_version\":" << kFixedValidationRulesVersion
            << ",\"bootstrap_template_mode\":" << (bootstrap_template_mode_ ? "true" : "false")
            << ",\"pending_bootstrap_joiners\":" << pending_join_request_count_locked();
          if (bootstrap_validator_pubkey_.has_value()) {
            j << ",\"bootstrap_validator_pubkey\":\""
              << hex_encode(Bytes(bootstrap_validator_pubkey_->begin(), bootstrap_validator_pubkey_->end())) << "\"";
          }
          j << "}";
          std::cout << j.str() << "\n";
        } else {
          std::cout << cfg_.network.name << " h=" << finalized_height_ << " transition=" << short_hash_hex(finalized_identity_.id)
                    << " gen=" << chain_id_.genesis_hash_hex.substr(0, 8) << " peers=" << peer_count()
                    << " outbound=" << (cfg_.disable_p2p ? peer_count() : p2p_.outbound_count()) << "/"
                    << cfg_.outbound_target << " inbound=" << (cfg_.disable_p2p ? 0 : p2p_.inbound_count())
                    << " established=" << established_peer_count() << " addrman=" << addrman_.size()
                    << " cv=" << kFixedValidationRulesVersion << " state=" << state;
          if (bootstrap_template_mode_) {
            std::cout << " bootstrap=template";
            if (bootstrap_validator_pubkey_.has_value()) {
              std::cout << " validator=" << short_pub_hex(*bootstrap_validator_pubkey_);
            }
            if (!last_bootstrap_source_.empty()) {
              std::cout << " source=" << last_bootstrap_source_;
            }
            const auto pending_joiners = pending_join_request_count_locked();
            if (pending_joiners != 0) {
              std::cout << " pending_joiners=" << pending_joiners;
            }
          }
          std::cout << "\n";
        }
        last_summary_log_ms_ = now_ms;
      }

      const std::uint64_t keepalive_interval_ms =
          std::max<std::uint64_t>(200, static_cast<std::uint64_t>(cfg_.idle_timeout_ms) / 3);
      const std::uint64_t sync_poll_interval_ms =
          std::max<std::uint64_t>(3000, static_cast<std::uint64_t>(cfg_.network.round_timeout_ms));
      const bool sync_requests_pending = !requested_sync_heights_.empty() || !requested_sync_artifacts_.empty();
      const bool sync_progress_stalled = now_ms >= last_finalized_progress_ms_ + sync_poll_interval_ms;
      for (int peer_id : p2p_.peer_ids()) {
        const auto info = p2p_.get_peer_info(peer_id);
        if (!info.established()) continue;
        auto& last = peer_keepalive_ms_[peer_id];
        if (now_ms >= last + keepalive_interval_ms) {
          keepalive_peers.push_back(peer_id);
          last = now_ms;
        }
      }

      if (!cfg_.disable_p2p && established_peer_count() > 0 &&
          (sync_progress_stalled || sync_requests_pending) &&
          now_ms >= last_finalized_tip_poll_ms_ + sync_poll_interval_ms) {
        struct TipPollCandidate {
          int peer_id{0};
          std::uint64_t tip_height{0};
          bool fresh{false};
          bool active_validator{false};
        };
        std::vector<TipPollCandidate> tip_candidates;
        tip_candidates.reserve(peer_finalized_tips_.size());
        const std::uint64_t tip_freshness_ms = std::max<std::uint64_t>(
            kFinalizedTipFreshnessFloorMs, static_cast<std::uint64_t>(cfg_.network.round_timeout_ms) * 3);
        for (const auto& [peer_id, tip] : peer_finalized_tips_) {
          const auto info = p2p_.get_peer_info(peer_id);
          if (!info.established()) continue;
          bool active_validator = false;
          if (auto validator_it = peer_validator_pubkeys_.find(peer_id); validator_it != peer_validator_pubkeys_.end()) {
            active_validator = validators_.is_active_for_height(validator_it->second, finalized_height_ + 1);
          }
          bool fresh = false;
          if (auto seen_it = peer_finalized_tip_seen_ms_.find(peer_id); seen_it != peer_finalized_tip_seen_ms_.end()) {
            const std::uint64_t age_ms = now_ms >= seen_it->second ? (now_ms - seen_it->second) : 0;
            fresh = age_ms <= tip_freshness_ms;
          }
          tip_candidates.push_back(TipPollCandidate{
              .peer_id = peer_id,
              .tip_height = tip.height,
              .fresh = fresh,
              .active_validator = active_validator,
          });
        }
        std::sort(tip_candidates.begin(), tip_candidates.end(), [](const auto& a, const auto& b) {
          if (a.active_validator != b.active_validator) return a.active_validator > b.active_validator;
          if (a.fresh != b.fresh) return a.fresh > b.fresh;
          if (a.tip_height != b.tip_height) return a.tip_height > b.tip_height;
          return a.peer_id < b.peer_id;
        });
        if (!tip_candidates.empty()) {
          const std::size_t batch = std::min<std::size_t>(8, tip_candidates.size());
          finalized_tip_poll_cursor_ %= tip_candidates.size();
          for (std::size_t i = 0; i < batch; ++i) {
            const auto& c = tip_candidates[(finalized_tip_poll_cursor_ + i) % tip_candidates.size()];
            finalized_tip_poll_peers.push_back(c.peer_id);
          }
          finalized_tip_poll_cursor_ = (finalized_tip_poll_cursor_ + batch) % tip_candidates.size();
        }
        last_finalized_tip_poll_ms_ = now_ms;
      }

      if (!repair_mode_) {
        maybe_finalize_epoch_committees_locked();
        if (!cfg_.disable_p2p) maybe_request_epoch_ticket_reconciliation_locked(now_ms);
      }

      if (!repair_mode_) {
        if (auto epoch_ticket = mine_local_epoch_ticket_locked(h); epoch_ticket.has_value()) {
        auto it = local_epoch_tickets_.find(epoch_ticket->epoch);
        const bool improved = it == local_epoch_tickets_.end() || consensus::epoch_ticket_better(*epoch_ticket, it->second);
        if (improved) {
          const bool accepted = handle_epoch_ticket_locked(*epoch_ticket, false, 0);
          if (accepted) {
            log_line("epoch-ticket-local-mined epoch=" + std::to_string(epoch_ticket->epoch) +
                     " participant=" + short_pub_hex(epoch_ticket->participant_pubkey) +
                     " work=" + short_hash_hex(epoch_ticket->work_hash));
            broadcast_epoch_ticket(*epoch_ticket);
          }
        }
      }
      }

      const auto committee = committee_for_height_round(h, current_round_);
      const bool committee_ready = !committee.empty();
      const std::size_t quorum = consensus::quorum_threshold(committee.size());
      const auto hr = std::make_pair(h, current_round_);
      prune_caches_locked(h, current_round_);
      if (committee_ready && logged_committee_rounds_.insert(hr).second) {
        std::ostringstream coss;
        coss << "committee height=" << h << " round=" << current_round_ << " size=" << committee.size()
             << " quorum=" << quorum << " members=";
        for (std::size_t i = 0; i < committee.size(); ++i) {
          if (i) coss << ",";
          coss << short_pub_hex(committee[i]);
        }
        log_line(coss.str());
        if (cfg_.log_json) {
          std::ostringstream j;
          j << "{\"type\":\"status\",\"network\":\"" << cfg_.network.name << "\",\"height\":" << finalized_height_
            << ",\"transition_hash\":\"" << hex_encode32(finalized_identity_.id) << "\",\"round\":" << current_round_
            << ",\"peers\":" << peer_count() << ",\"established_peers\":" << established_peer_count()
            << ",\"mempool_size\":" << mempool_.size()
            << ",\"committee_size\":" << committee.size() << ",\"addrman_size\":" << addrman_.size()
            << ",\"consensus_version\":" << kFixedValidationRulesVersion
            << ",\"genesis_hash\":\"" << chain_id_.genesis_hash_hex << "\""
            << ",\"genesis_source\":\"" << chain_id_.genesis_source << "\""
            << ",\"chain_id_ok\":" << (chain_id_.chain_id_ok ? "true" : "false")
            << ",\"outbound_connected\":" << (cfg_.disable_p2p ? peer_count() : p2p_.outbound_count())
            << ",\"inbound_connected\":" << (cfg_.disable_p2p ? 0 : p2p_.inbound_count())
            << ",\"last_bootstrap_source\":\"" << last_bootstrap_source_ << "\""
            << ",\"bootstrap_template_mode\":" << (bootstrap_template_mode_ ? "true" : "false")
            << ",\"pending_bootstrap_joiners\":" << pending_join_request_count_locked();
          if (bootstrap_validator_pubkey_.has_value()) {
            j << ",\"bootstrap_validator_pubkey\":\""
              << hex_encode(Bytes(bootstrap_validator_pubkey_->begin(), bootstrap_validator_pubkey_->end())) << "\"";
          }
          j << ",\"rejected_network_id\":" << rejected_network_id_
            << ",\"rejected_protocol_version\":" << rejected_protocol_version_
            << ",\"rejected_pre_handshake\":" << rejected_pre_handshake_ << "}";
          std::cout << j.str() << "\n";
        }
      }

      bool can_propose = false;
      const auto leader = leader_for_height_round(h, current_round_);
      const auto valid_polka = valid_polka_for_height_locked(h);
      const auto highest_tc = highest_tc_for_height_locked(h);
      std::set<PubKey32> established_active_validator_pubkeys;
      for (const auto& [peer_id, pub] : peer_validator_pubkeys_) {
        if (!validators_.is_active_for_height(pub, h)) continue;
        if (std::find(committee.begin(), committee.end(), pub) == committee.end()) continue;
        const auto info = p2p_.get_peer_info(peer_id);
        if (!info.established()) continue;
        established_active_validator_pubkeys.insert(pub);
      }
      const std::size_t established_active_validators = established_active_validator_pubkeys.size();
      const std::size_t required_active_validators = quorum > 0 ? quorum - 1 : 0;
      const bool quorum_validator_connectivity_ready = established_active_validators >= required_active_validators;
      const bool ticket_pow_fallback_round = current_round_ > 0 && committee.size() == 1;
      const bool tc_driven_round = highest_tc.has_value() && highest_tc->round < current_round_;
      const bool round_justification_ready =
          ticket_pow_fallback_round || valid_polka.has_value() ||
          (highest_tc.has_value() && highest_tc->round < current_round_) || current_round_ == 0;
      can_propose = leader.has_value() && *leader == local_key_.public_key;
      if (highest_tc.has_value() && !valid_polka.has_value()) {
        if (tc_no_qc_height_ != h) {
          tc_no_qc_height_ = h;
          tc_no_qc_last_round_ = current_round_;
          tc_no_qc_round_streak_ = 1;
        } else if (current_round_ != tc_no_qc_last_round_) {
          tc_no_qc_last_round_ = current_round_;
          ++tc_no_qc_round_streak_;
        }
        if (tc_no_qc_round_streak_ >= 3 && now_ms >= last_tc_no_qc_log_ms_ + 5000) {
          log_line("deadlock-break-debug height=" + std::to_string(h) +
                   " round=" + std::to_string(current_round_) +
                   " reason=tc-progress-without-qc streak=" + std::to_string(tc_no_qc_round_streak_) +
                   " has_lock=" + std::string(local_vote_locks_.find(h) != local_vote_locks_.end() ? "yes" : "no") +
                   " can_propose=" + std::string(can_propose ? "yes" : "no") +
                   " leader=" + (leader.has_value() ? short_pub_hex(*leader) : std::string("none")));
          last_tc_no_qc_log_ms_ = now_ms;
        }
      } else {
        tc_no_qc_height_ = h;
        tc_no_qc_last_round_ = current_round_;
        tc_no_qc_round_streak_ = 0;
      }
      const std::uint64_t stale_ms = cfg_.network.round_timeout_ms * 2ULL;
      const bool consensus_stalled = now_ms > last_finalized_progress_ms_ + stale_ms;
      // LIVENESS: a vote is otherwise sent once. Votes lost while peers were unreachable (partition,
      // reconnect) are never retransmitted, and a TC missing one side's timeout votes never forms, so
      // a healed partition could halt the height for good. While stalled, re-gossip this node's own
      // votes at h.
      if (now_ms >= last_tx_reforward_ms_ + 5000) {
        last_tx_reforward_ms_ = now_ms;
        reforward_uncertified_mempool_txs_locked();
      }
      if (consensus_stalled && now_ms >= last_consensus_rebroadcast_ms_ + cfg_.network.round_timeout_ms) {
        last_consensus_rebroadcast_ms_ = now_ms;
        votes_to_rebroadcast = local_votes_for_rebroadcast_locked(h);
      }
      const std::uint64_t current_round_timeout_ms = round_timeout_ms_for_round(cfg_.network, current_round_);
      const bool emit_liveness_debug = debug_liveness_logs_enabled() || consensus_stalled;
      if (emit_liveness_debug && now_ms >= last_liveness_log_ms_ + 5000) {
        const bool local_active = validators_.is_active_for_height(local_key_.public_key, h);
        const bool local_in_committee =
            std::find(committee.begin(), committee.end(), local_key_.public_key) != committee.end();
        const bool timeout_elapsed = now_ms > round_started_ms_ + current_round_timeout_ms;
        std::ostringstream lss;
        lss << "liveness-debug"
            << " next_height=" << h
            << " round=" << current_round_
            << " round_timeout_ms=" << current_round_timeout_ms
            << " finalized_height=" << finalized_height_
            << " committee_size=" << committee.size()
            << " quorum=" << quorum
            << " local_active=" << (local_active ? "yes" : "no")
            << " local_in_committee=" << (local_in_committee ? "yes" : "no")
            << " leader=" << (leader.has_value() ? short_pub_hex(*leader) : std::string("none"))
            << " local_pub=" << short_pub_hex(local_key_.public_key)
            << " can_propose=" << (can_propose ? "yes" : "no")
            << " block_interval_elapsed=" << (block_interval_elapsed ? "yes" : "no")
            << " ticket_window_elapsed=" << (ticket_window_elapsed ? "yes" : "no")
            << " round_timeout_elapsed=" << (timeout_elapsed ? "yes" : "no")
            << " round_justification_ready=" << (round_justification_ready ? "yes" : "no")
            << " has_qc=" << (valid_polka.has_value() ? "yes" : "no")
            << " has_tc=" << (highest_tc.has_value() ? "yes" : "no")
            << " established_active_validators=" << established_active_validators
            << " required_active_validators=" << required_active_validators
            << " paused=" << (pause_proposals_.load() ? "yes" : "no")
            << " repair_mode=" << (repair_mode_ ? "yes" : "no")
            << " stalled=" << (consensus_stalled ? "yes" : "no")
            << " peers_established=" << established_peer_count();
        log_line(lss.str());
        last_liveness_log_ms_ = now_ms;
      }
      const bool round_timeout_elapsed = now_ms > round_started_ms_ + current_round_timeout_ms;
      if (!repair_mode_ && !pause_proposals_.load() && current_round_ == 0 && can_propose && committee_ready &&
          block_interval_elapsed && ticket_window_elapsed && round_timeout_elapsed && !valid_polka.has_value() &&
          !highest_tc.has_value() && !quorum_validator_connectivity_ready &&
          now_ms >= last_round0_no_quorum_log_ms_ + 5000) {
        log_line("deadlock-break-debug height=" + std::to_string(h) + " round=0" +
                 " reason=round0-missing-established-active-validator-sessions" +
                 " established_active_validators=" + std::to_string(established_active_validators) +
                 " required_active_validators=" + std::to_string(required_active_validators) +
                 " peers_established=" + std::to_string(established_peer_count()) +
                 " leader=" + (leader.has_value() ? short_pub_hex(*leader) : std::string("none")));
        last_round0_no_quorum_log_ms_ = now_ms;
        force_validator_redial = true;
      }
      const bool proposal_block_interval_ready = block_interval_elapsed || tc_driven_round;
      // SAFETY: an abstaining node may already have proposed at this height before losing its
      // safety state; proposing again could be a different payload (proposer equivocation).
      if (!repair_mode_ && !pause_proposals_.load() && can_propose && committee_ready && proposal_block_interval_ready && ticket_window_elapsed &&
          !committee.empty() && round_justification_ready && quorum_validator_connectivity_ready &&
          !abstaining_at_height_locked(h)) {
        auto key = std::make_pair(h, current_round_);
        if (proposed_in_round_.find(key) == proposed_in_round_.end()) {
          should_build_proposal = true;
          build_height = h;
          build_round = current_round_;
          if (!block_interval_elapsed && tc_driven_round) {
            log_line("proposal-build-tc-bypass-block-interval height=" + std::to_string(h) +
                     " round=" + std::to_string(current_round_) +
                     " tc_round=" + std::to_string(highest_tc->round));
          }
        }
      } else if (!repair_mode_ && !pause_proposals_.load() && can_propose && committee_ready && proposal_block_interval_ready &&
                 ticket_window_elapsed && !committee.empty() && round_justification_ready &&
                 !quorum_validator_connectivity_ready && now_ms >= last_round0_no_quorum_log_ms_ + 5000) {
        log_line("proposal-build-skip height=" + std::to_string(h) + " round=" + std::to_string(current_round_) +
                 " reason=missing-established-active-validator-sessions established_active_validators=" +
                 std::to_string(established_active_validators) + " required_active_validators=" +
                 std::to_string(required_active_validators));
        last_round0_no_quorum_log_ms_ = now_ms;
      }
      const bool round0_grace_elapsed = current_round_ > 0 || now_ms >= round0_deadline_ms_;
      bool advanced_round_this_tick = false;
      if (!repair_mode_ && !pause_proposals_.load() && !should_build_proposal && round_timeout_elapsed &&
          round0_grace_elapsed && consensus_stalled && can_propose && !valid_polka.has_value() && !highest_tc.has_value() &&
          committee.size() == 1) {
        const auto old_round = current_round_;
        current_round_ = old_round + 1;
        round_started_ms_ = now_ms;
        advanced_round_this_tick = true;
        const auto forced_leader = leader_for_height_round(h, current_round_);
        log_line("round-catchup height=" + std::to_string(h) + " old_round=" + std::to_string(old_round) +
                 " new_round=" + std::to_string(current_round_) +
                 " reason=stalled-no-qc-tc-force-advance leader=" +
                 (forced_leader.has_value() ? short_pub_hex(*forced_leader) : std::string("none")));
      }
      if (!advanced_round_this_tick && !repair_mode_ && !pause_proposals_.load() && !should_build_proposal && round_timeout_elapsed &&
          round0_grace_elapsed) {
        const auto timeout_round = current_round_;
        const auto timeout_committee = committee_for_height_round(h, timeout_round);
        const auto timeout_vote_key = std::make_pair(h, timeout_round);
        const bool local_timeout_reserved =
            local_timeout_vote_reservations_.find(timeout_vote_key) != local_timeout_vote_reservations_.end();
        const bool local_timeout_member =
            std::find(timeout_committee.begin(), timeout_committee.end(), local_key_.public_key) != timeout_committee.end();
        bool timeout_evidence_progressed = local_timeout_reserved;
        // Timeout votes are blocked too while abstaining (conservative: no signatures at all at h).
        const bool abstaining = abstaining_at_height_locked(h);
        if (local_timeout_member && !local_timeout_reserved && !abstaining) {
          if (auto sig = crypto::ed25519_sign(timeout_vote_signing_message(h, timeout_round), local_key_.private_key);
              sig.has_value()) {
            local_timeout_vote_reservations_.insert(timeout_vote_key);
            local_timed_out_rounds_.insert(timeout_vote_key);
            timeout_vote_to_broadcast = TimeoutVote{h, timeout_round, local_key_.public_key, *sig};
            timeout_evidence_progressed = true;
            log_line("round-timeout-vote height=" + std::to_string(h) + " round=" + std::to_string(timeout_round));
          } else {
            log_line("round-timeout-vote-skip height=" + std::to_string(h) + " round=" + std::to_string(timeout_round) +
                     " reason=sign-failed");
          }
        } else if (!local_timeout_member) {
          log_line("round-timeout-vote-skip height=" + std::to_string(h) + " round=" + std::to_string(timeout_round) +
                   " reason=not-committee-member");
        } else if (abstaining) {
          log_line("round-timeout-vote-skip height=" + std::to_string(h) + " round=" + std::to_string(timeout_round) +
                   " reason=abstain-corrupt-safety-state");
        }
        const bool allow_timeout_round_advance =
            !timeout_committee.empty() &&
            (timeout_committee.size() == 1 ||
             (highest_tc.has_value() && highest_tc->round < timeout_round));
        if (allow_timeout_round_advance) {
          const auto old_round = current_round_;
          current_round_ = timeout_round + 1;
          round_started_ms_ = now_ms;
          const auto new_leader = leader_for_height_round(h, current_round_);
          const std::string reason = timeout_committee.size() == 1
                                         ? "ticket-pow-fallback-timeout"
                                         : "tc-driven-timeout-advance";
          log_line("round-catchup height=" + std::to_string(h) + " old_round=" + std::to_string(old_round) +
                   " new_round=" + std::to_string(current_round_) + " reason=" + reason +
                   " leader=" + (new_leader.has_value() ? short_pub_hex(*new_leader) : std::string("none")));
        } else if (timeout_evidence_progressed) {
          // Round advancement remains TC-driven outside the deterministic
          // deterministic ticket-pow fallback path.
          if (timeout_evidence_progressed) round_started_ms_ = now_ms;
        }
      }
    }

    if (should_build_proposal) {
      std::optional<FrontierProposal> built;
      std::optional<FrontierProposal> reproposal;
      std::optional<QuorumCertificate> reproposal_pol;
      std::string build_error;
      {
        std::lock_guard<std::mutex> lk(mu_);
        // Tendermint: re-propose the valid value unchanged, with its polka; otherwise build fresh.
        if (auto polka = valid_polka_for_height_locked(build_height); polka.has_value() && polka->round < build_round) {
          if (auto it = candidate_frontier_proposals_.find(polka->frontier_transition_id);
              it != candidate_frontier_proposals_.end()) {
            reproposal = it->second;
            reproposal_pol = std::move(polka);
            log_line("proposal-valid-value-reproposal height=" + std::to_string(build_height) +
                     " round=" + std::to_string(build_round) + " transition=" +
                     short_hash_hex(reproposal_pol->frontier_transition_id) +
                     " pol_round=" + std::to_string(reproposal_pol->round));
          } else {
            log_line("proposal-valid-value-missing height=" + std::to_string(build_height) +
                     " round=" + std::to_string(build_round) + " transition=" +
                     short_hash_hex(polka->frontier_transition_id) + " fallback=fresh-build");
          }
        }
        if (!reproposal.has_value()) {
          built = build_frontier_transition_locked(build_height, build_round);
          build_error = last_test_hook_error_;
        }
      }
      const auto& selected = reproposal.has_value() ? reproposal : built;
      if (selected.has_value()) {
        std::lock_guard<std::mutex> lk(mu_);
        const auto key = std::make_pair(build_height, build_round);
        const auto transition_id = selected->transition.transition_id();
        const std::optional<std::uint32_t> pol_round =
            reproposal_pol.has_value() ? std::optional<std::uint32_t>(reproposal_pol->round) : std::nullopt;
        auto sig = crypto::ed25519_sign(propose_signing_message(build_height, build_round, transition_id, pol_round),
                                        local_key_.private_key);
        if (finalized_height_ + 1 == build_height && current_round_ == build_round && sig.has_value() &&
            proposed_in_round_.find(key) == proposed_in_round_.end()) {
          proposed_in_round_[key] = true;
          candidate_frontier_proposals_[transition_id] = *selected;
          candidate_block_sizes_[transition_id] = selected->serialize().size();
          p2p::ProposeMsg msg;
          msg.height = build_height;
          msg.round = build_round;
          msg.prev_finalized_hash = selected->transition.prev_finalized_hash;
          msg.frontier_proposal_bytes = selected->serialize();
          msg.pol = reproposal_pol;
          if (build_round > 0) msg.justify_tc = highest_tc_for_height_locked(build_height);
          msg.proposer_signature = *sig;
          propose_to_send = std::move(msg);
        }
      } else {
        log_line("proposal-build-skip height=" + std::to_string(build_height) + " round=" + std::to_string(build_round) +
                 " reason=" + (build_error.empty() ? std::string("unknown") : build_error));
      }
    }

    if (propose_to_send.has_value()) {
#ifdef FINALIS_CHAOS_BYZANTINE
      if (chaos_byzantine_ && !cfg_.disable_p2p) {
        // Equivocate: a second valid proposal for the same round (different timestamp, so a
        // different transition id), each sent to half of the peers.
        auto proposal = FrontierProposal::parse(propose_to_send->frontier_proposal_bytes);
        if (proposal.has_value()) {
          p2p::ProposeMsg alt = *propose_to_send;
          // Still valid: later than the parent and within the honest prevoters' drift bound.
          proposal->transition.timestamp += 1 + (++chaos_equivocation_nonce_ % 30);
          alt.frontier_proposal_bytes = proposal->serialize();
          const std::optional<std::uint32_t> pol_round =
              alt.pol.has_value() ? std::optional<std::uint32_t>(alt.pol->round) : std::nullopt;
          if (auto sig = crypto::ed25519_sign(
                  propose_signing_message(alt.height, alt.round, proposal->transition.transition_id(), pol_round),
                  local_key_.private_key)) {
            alt.proposer_signature = *sig;
            bool flip = false;
            for (int peer_id : p2p_.peer_ids()) {
              const auto& m = flip ? alt : *propose_to_send;
              (void)p2p_.send_to(peer_id, p2p::MsgType::PROPOSE, p2p::ser_propose(m), true);
              flip = !flip;
            }
            log_line("CHAOS-BYZANTINE equivocating-propose height=" + std::to_string(alt.height) +
                     " round=" + std::to_string(alt.round));
            handle_propose(*propose_to_send, false);
            handle_propose(alt, false);
            propose_to_send.reset();
          }
        }
      }
#endif
      if (propose_to_send.has_value()) {
        broadcast_propose(*propose_to_send);
        handle_propose(*propose_to_send, false);
      }
    }

    // Backstop for finalizations reached from event-loop paths (sync, repair).
    flush_pending_finalized_broadcasts();

    for (const auto& v : votes_to_rebroadcast.timeouts) broadcast_timeout_vote(v);
    for (const auto& v : votes_to_rebroadcast.prevotes) broadcast_prevote(v);
    for (const auto& v : votes_to_rebroadcast.precommits) broadcast_vote(v);
    if (!votes_to_rebroadcast.timeouts.empty() || !votes_to_rebroadcast.prevotes.empty() ||
        !votes_to_rebroadcast.precommits.empty()) {
      log_line("consensus-rebroadcast timeouts=" + std::to_string(votes_to_rebroadcast.timeouts.size()) +
               " prevotes=" + std::to_string(votes_to_rebroadcast.prevotes.size()) +
               " precommits=" + std::to_string(votes_to_rebroadcast.precommits.size()));
    }
    if (timeout_vote_to_broadcast.has_value()) {
      broadcast_timeout_vote(*timeout_vote_to_broadcast);
      const bool ok = handle_timeout_vote(*timeout_vote_to_broadcast, false, 0);
      (void)ok;
    }

    {
      std::sort(keepalive_peers.begin(), keepalive_peers.end());
      keepalive_peers.erase(std::unique(keepalive_peers.begin(), keepalive_peers.end()), keepalive_peers.end());
    }
    for (int peer_id : keepalive_peers) {
      send_ping(peer_id);
    }
    for (int peer_id : finalized_tip_poll_peers) request_finalized_tip(peer_id);
    if (!cfg_.disable_p2p && force_validator_redial) {
      try_connect_bootstrap_peers();
      last_seed_attempt_ms_ = now_ms();
    }
    if (should_persist_validators_addrman) {
      std::vector<p2p::PeerInfo> persisted_peers;
      persisted_peers.reserve(p2p_.peer_ids().size());
      for (int id : p2p_.peer_ids()) persisted_peers.push_back(p2p_.get_peer_info(id));
      persist_validators_addrman(persisted_peers);
    }
    {
      std::lock_guard<std::mutex> lk(mu_);
      const auto now = now_unix();
      if (last_peer_discipline_decay_unix_ == 0 || now > last_peer_discipline_decay_unix_) {
        discipline_.decay(now);
        last_peer_discipline_decay_unix_ = now;
      }
    }

    if (cfg_.disable_p2p) join_local_bus_tasks();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    (void)reap_lightserver_child(true);
    if (!cfg_.disable_p2p) {
      const std::uint64_t now_ms = this->now_ms();
      maybe_refresh_upnp_igd_external_endpoint(now_ms);
      maybe_refresh_nat_pmp_external_endpoint(now_ms);
      maybe_refresh_stun_external_endpoint(now_ms);
      if (outbound_peer_count() < cfg_.outbound_target && now_ms > last_seed_attempt_ms_ + 3000) {
        try_connect_bootstrap_peers();
        last_seed_attempt_ms_ = now_ms;
      }
      if (now_ms > last_addrman_save_ms_ + 10'000) {
        persist_addrman();
        last_addrman_save_ms_ = now_ms;
      }
    }
  }
}

consensus::CanonicalDerivationConfig Node::canonical_derivation_config_locked() const {
  consensus::CanonicalDerivationConfig cfg;
  cfg.network = cfg_.network;
  cfg.chain_id = chain_id_;
  cfg.max_committee = cfg_.max_committee;
  cfg.validator_min_bond_override = validator_min_bond_;
  cfg.validator_bond_min_amount = validator_bond_min_amount_;
  cfg.validator_bond_max_amount = validator_bond_max_amount_;
  cfg.validator_warmup_blocks = validator_warmup_blocks_;
  cfg.validator_cooldown_blocks = validator_cooldown_blocks_;
  cfg.validator_join_limit_window_blocks = validator_join_limit_window_blocks_;
  cfg.validator_join_limit_max_new = validator_join_limit_max_new_;
  cfg.validator_liveness_window_blocks = validator_liveness_window_blocks_;
  cfg.validator_miss_rate_suspend_threshold_percent = validator_miss_rate_suspend_threshold_percent_;
  cfg.validator_miss_rate_exit_threshold_percent = validator_miss_rate_exit_threshold_percent_;
  cfg.validator_suspend_duration_blocks = validator_suspend_duration_blocks_;
  cfg.availability = cfg_.availability;
  cfg.availability_min_eligible_operators = cfg_.availability_min_eligible_operators;
  cfg.validation_rules_version = kFixedValidationRulesVersion;
  cfg.confidential_policy = confidential_policy_;
  cfg.finalized_hash_at_height = [this](std::uint64_t height) -> std::optional<Hash32> {
    if (height == 0) return zero_hash();
    return db_.get_height_hash(height);
  };
  return cfg;
}

bool Node::verify_and_persist_consensus_state_commitment_locked(const consensus::CanonicalDerivedState& state,
                                                                storage::DB::Batch& batch) {
  const auto commitment = consensus::consensus_state_commitment(canonical_derivation_config_locked(), state);
  if (commitment != state.state_commitment) {
    std::cerr << "consensus state commitment recomputation mismatch\n";
    return false;
  }
  auto persisted = db_.get_consensus_state_commitment_cache();
  // This cache intentionally commits only the finalized identity value. The
  // DB boundary remains kind-erased for compatibility.
  if (persisted.has_value() && persisted->height == state.finalized_height &&
      persisted->hash == state.finalized_identity.id &&
      persisted->commitment != commitment) {
    std::cerr << "persisted consensus state commitment mismatch at height " << state.finalized_height << "\n";
    return false;
  }
  batch.put_consensus_state_commitment_cache(
      storage::ConsensusStateCommitmentCache{state.finalized_height, state.finalized_identity.id, commitment});
  return true;
}

bool Node::verify_and_persist_consensus_state_commitment_locked(const consensus::CanonicalDerivedState& state) {
  storage::DB::Batch batch(db_);
  if (!verify_and_persist_consensus_state_commitment_locked(state, batch)) return false;
  return db_.write_batch(batch);
}

std::uint64_t Node::effective_validator_min_bond_for_height(std::uint64_t height) const {
  // Must be the replay rule: canonical_derivation_config_locked() feeds these same values to replay.
  return consensus::effective_validator_min_bond_for_height(cfg_.network, validator_min_bond_, validator_bond_min_amount_,
                                                            validators_, height);
}

std::uint64_t Node::effective_validator_bond_max_for_height(std::uint64_t height) const {
  return std::max<std::uint64_t>(validator_bond_max_amount_, effective_validator_min_bond_for_height(height));
}

SpecialValidationContext Node::special_validation_context_locked(std::uint64_t height) const {
  return SpecialValidationContext{
      .network = &cfg_.network,
      .chain_id = &chain_id_,
      .validators = &validators_,
      .current_height = height,
      .enforce_variable_bond_range = true,
      .min_bond_amount = effective_validator_min_bond_for_height(height),
      .max_bond_amount = effective_validator_bond_max_for_height(height),
      .unbond_delay_blocks = cfg_.network.unbond_delay_blocks,
      .is_committee_member = [this](const PubKey32& pub, std::uint64_t h, std::uint32_t round) {
        return is_committee_member_for(pub, h, round);
      },
      .finalized_hash_at_height = [this](std::uint64_t anchor_height) -> std::optional<Hash32> {
        if (anchor_height == 0) return zero_hash();
        return db_.get_height_hash(anchor_height);
      },
      .confidential_policy = &confidential_policy_};
}

std::uint64_t Node::now_unix() const {
  using namespace std::chrono;
  return duration_cast<seconds>(system_clock::now().time_since_epoch()).count();
}

std::uint64_t Node::now_ms() const {
  using namespace std::chrono;
  return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

void Node::log_line(const std::string& s) const {
  if (!runtime_logs_enabled()) return;
  if (cfg_.log_json) {
    std::cout << "{\"type\":\"log\",\"node_id\":" << cfg_.node_id << ",\"network\":\"" << cfg_.network.name
              << "\",\"msg\":\"" << s << "\"}\n";
  } else {
    std::cout << "[node " << cfg_.node_id << "] " << s << "\n";
  }
  // Throttled flush instead of std::ios::unitbuf's per-call flush (removed
  // from Node::init()): most log_line calls happen with mu_ held on the
  // consensus/handshake hot path, so flushing every single one turned each
  // call into a potential blocking syscall under lock contention. Flushing
  // at most once per kLogFlushIntervalMs keeps systemd/journald followers
  // seeing output live without paying that cost on every line. The atomic
  // timestamp is safe across the many threads that call log_line
  // concurrently without mu_ protecting this particular piece of state.
  constexpr std::uint64_t kLogFlushIntervalMs = 200;
  const auto now = now_ms();
  auto last = last_log_flush_ms_.load(std::memory_order_relaxed);
  if (now >= last + kLogFlushIntervalMs &&
      last_log_flush_ms_.compare_exchange_strong(last, now, std::memory_order_relaxed)) {
    std::cout.flush();
  }
}

std::vector<Node*> Node::local_bus_peers() const {
  std::vector<Node*> peers;
  {
    std::lock_guard<std::mutex> lk(g_local_bus_mu);
    peers = g_local_bus_nodes;
  }
  peers.erase(std::remove(peers.begin(), peers.end(), this), peers.end());
  return peers;
}

void Node::spawn_local_bus_task(std::function<void()> fn) {
  std::lock_guard<std::mutex> lk(local_bus_tasks_mu_);
  local_bus_tasks_.emplace_back([f = std::move(fn)]() { f(); });
}

void Node::join_local_bus_tasks() {
  std::vector<std::thread> tasks;
  {
    std::lock_guard<std::mutex> lk(local_bus_tasks_mu_);
    tasks.swap(local_bus_tasks_);
  }
  for (auto& t : tasks) {
    if (!t.joinable()) continue;
    try {
      t.join();
    } catch (const std::system_error& e) {
      log_line(std::string("shutdown-join-exception source=local-bus error=\"") + e.what() + "\"");
    }
  }
}

}  // namespace finalis::node
