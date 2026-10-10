// SPDX-License-Identifier: MIT

// Command-line parsing for finalis-node: parse_args() (declared in node.hpp) and its helpers.

#include <algorithm>
#include <iostream>
#include <stdexcept>
#include <string>

#include "common/paths.hpp"
#include "node.hpp"
#include "node_internal.hpp"

namespace finalis::node {
using namespace detail;

// Strict TCP port parse: whole string must be a number in [1, 65535].
static std::uint16_t parse_port_arg(const std::string& s) {
  std::size_t pos = 0;
  const unsigned long v = std::stoul(s, &pos);
  if (pos != s.size()) throw std::invalid_argument("trailing characters");
  if (v == 0 || v > 65535) throw std::out_of_range("port must be in [1, 65535]");
  return static_cast<std::uint16_t>(v);
}

// Numeric conversions below throw std::invalid_argument / std::out_of_range;
// parse_args() catches them and reports the offending flag.
static std::optional<NodeConfig> parse_args_unchecked(int argc, char** argv, std::string* current_flag) {
  NodeConfig cfg;
  cfg.listen = false;  // safe CLI default: outbound-only unless --listen is set
  cfg.network = mainnet_network();
  cfg.p2p_port = cfg.network.p2p_default_port;
  cfg.lightserver_port = cfg.network.lightserver_default_port;
  cfg.max_committee = cfg.network.max_committee;
  cfg.db_path = default_db_dir_for_network(cfg.network.name);
  bool bind_explicit = false;
  bool db_explicit = false;
  std::string validator_passphrase_env;
  // Flags that change consensus-derived state or validator rules. Every mainnet
  // node must use the canonical NetworkConfig values, so these are rejected there.
  static constexpr std::array<std::string_view, 11> kMainnetLockedConsensusFlags{
      "--max-committee",
      "--validator-min-bond",
      "--validator-warmup-blocks",
      "--validator-cooldown-blocks",
      "--validator-join-limit-window-blocks",
      "--validator-join-limit-max-new",
      "--liveness-window-blocks",
      "--miss-rate-suspend-threshold-percent",
      "--miss-rate-exit-threshold-percent",
      "--suspend-duration-blocks",
      "--deferred-exit-activation-height",
  };
  const bool mainnet_consensus_locked = cfg.network.name == "mainnet";

  for (int i = 1; i < argc; ++i) {
    std::string a = argv[i];
    *current_flag = a;
    if (mainnet_consensus_locked &&
        (a == "--deferred-exit-activation-epoch-start" ||
         std::find(kMainnetLockedConsensusFlags.begin(), kMainnetLockedConsensusFlags.end(), a) !=
             kMainnetLockedConsensusFlags.end())) {
      std::cerr << "error: " << a
                << " overrides a consensus parameter and is not allowed on mainnet; "
                   "all mainnet nodes must use the canonical network values\n";
      return std::nullopt;
    }
    auto next = [&](const std::string& name) -> std::optional<std::string> {
      if (i + 1 >= argc) {
        std::cerr << "missing value for " << name << "\n";
        return std::nullopt;
      }
      return std::string(argv[++i]);
    };

    if (a == "--mainnet") {
      std::cerr << "--mainnet is not needed in mainnet-only build; remove this flag\n";
      return std::nullopt;
    } else if (a == "--node-id") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.node_id = std::stoi(*v);
    } else if (a == "--port") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.p2p_port = parse_port_arg(*v);
    } else if (a == "--external-endpoint") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.external_endpoint = *v;
    } else if (a == "--stun-servers") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.stun_servers.clear();
      for (const auto& item : parse_endpoint_list(*v)) {
        if (!item.empty()) cfg.stun_servers.push_back(item);
      }
    } else if (a == "--stun-refresh-ms") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.stun_refresh_interval_ms = std::max<std::uint32_t>(5'000, static_cast<std::uint32_t>(std::stoul(*v)));
    } else if (a == "--stun-timeout-ms") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.stun_timeout_ms = std::max<std::uint32_t>(100, static_cast<std::uint32_t>(std::stoul(*v)));
    } else if (a == "--stun-max-backoff-ms") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.stun_max_backoff_ms = std::max<std::uint32_t>(cfg.stun_refresh_interval_ms,
                                                         static_cast<std::uint32_t>(std::stoul(*v)));
    } else if (a == "--stun-hysteresis-samples") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.stun_hysteresis_samples = std::max<std::uint32_t>(2, static_cast<std::uint32_t>(std::stoul(*v)));
    } else if (a == "--stun-hysteresis-min-ms") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.stun_hysteresis_min_ms = static_cast<std::uint32_t>(std::stoul(*v));
    } else if (a == "--no-stun") {
      cfg.stun_servers.clear();
    } else if (a == "--nat-pmp") {
      cfg.nat_pmp_enabled = true;
    } else if (a == "--no-nat-pmp") {
      cfg.nat_pmp_enabled = false;
    } else if (a == "--nat-pmp-timeout-ms") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.nat_pmp_timeout_ms = std::max<std::uint32_t>(100, static_cast<std::uint32_t>(std::stoul(*v)));
    } else if (a == "--nat-pmp-refresh-margin-ms") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.nat_pmp_refresh_margin_ms = std::max<std::uint32_t>(1'000, static_cast<std::uint32_t>(std::stoul(*v)));
    } else if (a == "--upnp-igd") {
      cfg.upnp_igd_enabled = true;
    } else if (a == "--no-upnp-igd") {
      cfg.upnp_igd_enabled = false;
    } else if (a == "--upnp-igd-timeout-ms") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.upnp_igd_timeout_ms = std::max<std::uint32_t>(200, static_cast<std::uint32_t>(std::stoul(*v)));
    } else if (a == "--upnp-igd-refresh-margin-ms") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.upnp_igd_refresh_margin_ms = std::max<std::uint32_t>(1'000, static_cast<std::uint32_t>(std::stoul(*v)));
    } else if (a == "--upnp-igd-lease-seconds") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.upnp_igd_lease_seconds = std::max<std::uint32_t>(120, static_cast<std::uint32_t>(std::stoul(*v)));
    } else if (a == "--startup-frontier-repair-max-rollback") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.startup_frontier_repair_max_rollback = std::max<std::uint64_t>(1, std::stoull(*v));
    } else if (a == "--startup-frontier-repair-adaptive-percent") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.startup_frontier_repair_adaptive_percent = static_cast<std::uint32_t>(std::stoul(*v));
    } else if (a == "--startup-frontier-repair-absolute-max-rollback") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.startup_frontier_repair_absolute_max_rollback = std::max<std::uint64_t>(1, std::stoull(*v));
    } else if (a == "--listen") {
      cfg.listen = true;
    } else if (a == "--with-lightserver") {
      cfg.lightserver_mode = LightserverLaunchMode::Explicit;
    } else if (a == "--lightserver-bind") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.lightserver_bind = *v;
    } else if (a == "--lightserver-port") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.lightserver_port = parse_port_arg(*v);
    } else if (a == "--bind") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.bind_ip = *v;
      bind_explicit = true;
    } else if (a == "--db") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.db_path = *v;
      db_explicit = true;
    } else if (a == "--validator-key-file") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.validator_key_file = *v;
    } else if (a == "--validator-passphrase") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.validator_passphrase = *v;
      crypto::secure_wipe(*v);
      // SECURITY: argv is world-readable via /proc/<pid>/cmdline and ps; blank it in place.
      crypto::secure_wipe(argv[i], std::strlen(argv[i]));
      std::cerr << "warning: --validator-passphrase exposes the secret to other local users at startup; "
                   "prefer --validator-passphrase-env\n";
    } else if (a == "--allow-unencrypted-keystore") {
      cfg.allow_unencrypted_keystore = true;
    } else if (a == "--validator-passphrase-env") {
      auto v = next(a);
      if (!v) return std::nullopt;
      validator_passphrase_env = *v;
    } else if (a == "--genesis") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.genesis_path = *v;
    } else if (a == "--peers") {
      auto v = next(a);
      if (!v) return std::nullopt;
      for (const auto& item : parse_endpoint_list(*v)) cfg.peers.push_back(item);
    } else if (a == "--disable-p2p") {
      cfg.disable_p2p = true;
    } else if (a == "--acknowledge-emergency-fallback") {
      cfg.acknowledge_emergency_fallback = true;
    } else if (a == "--fast-start") {
      cfg.fast_start = true;
    } else if (a == "--no-reindex") {
      cfg.reindex_on_start = false;
    } else if (a == "--seeds") {
      auto v = next(a);
      if (!v) return std::nullopt;
      for (const auto& item : parse_endpoint_list(*v)) cfg.seeds.push_back(item);
    } else if (a == "--allow-unsafe-genesis-override") {
      cfg.allow_unsafe_genesis_override = true;
    } else if (a == "--unsafe-discard-vote-lock-at-height" ||
               a.rfind("--unsafe-discard-vote-lock-at-height=", 0) == 0) {
      // Emergency recovery only; see Node::load_state. Accepts "--flag N" and "--flag=N".
      std::optional<std::string> v;
      if (const auto eq = a.find('='); eq != std::string::npos) {
        v = a.substr(eq + 1);
      } else {
        v = next(a);
      }
      if (!v) return std::nullopt;
      cfg.unsafe_discard_vote_lock_height = std::stoull(*v);
    } else if (a == "--outbound-target") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.outbound_target = static_cast<std::size_t>(std::stoull(*v));
    } else if (a == "--dns-seeds") {
      cfg.dns_seeds = true;
    } else if (a == "--no-dns-seeds") {
      cfg.dns_seeds = false;
    } else if (a == "--public") {
      cfg.public_mode = true;
      cfg.listen = true;
    } else if (a == "--max-committee") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.max_committee = static_cast<std::size_t>(std::stoull(*v));
    } else if (a == "--min-block-interval-ms") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.network.min_block_interval_ms = static_cast<std::uint32_t>(std::stoul(*v));
    } else if (a == "--round-timeout-ms") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.network.round_timeout_ms = static_cast<std::uint32_t>(std::stoul(*v));
    } else if (a == "--max-round-timeout-ms") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.network.max_round_timeout_ms = static_cast<std::uint32_t>(std::stoul(*v));
    } else if (a == "--log-json") {
      cfg.log_json = true;
    } else if (a == "--handshake-timeout-ms") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.handshake_timeout_ms = static_cast<std::uint32_t>(std::stoul(*v));
    } else if (a == "--frame-timeout-ms") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.frame_timeout_ms = static_cast<std::uint32_t>(std::stoul(*v));
    } else if (a == "--idle-timeout-ms") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.idle_timeout_ms = static_cast<std::uint32_t>(std::stoul(*v));
    } else if (a == "--peer-queue-max-bytes") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.peer_queue_max_bytes = static_cast<std::size_t>(std::stoull(*v));
    } else if (a == "--peer-queue-max-msgs") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.peer_queue_max_msgs = static_cast<std::size_t>(std::stoull(*v));
    } else if (a == "--max-inbound") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.max_inbound = static_cast<std::size_t>(std::stoull(*v));
    } else if (a == "--ban-seconds") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.ban_seconds = static_cast<std::uint64_t>(std::stoull(*v));
    } else if (a == "--invalid-frame-ban-threshold") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.invalid_frame_ban_threshold = std::max(1, std::stoi(*v));
    } else if (a == "--invalid-frame-window-seconds") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.invalid_frame_window_seconds = std::max<std::uint64_t>(1, std::stoull(*v));
      } else if (a == "--min-relay-fee") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.min_relay_fee = static_cast<std::uint64_t>(std::stoull(*v));
      cfg.min_relay_fee_explicit = true;
    } else if (a == "--hashcash-enabled") {
      cfg.hashcash_enabled = true;
    } else if (a == "--hashcash-base-bits") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.hashcash_base_bits = static_cast<std::uint32_t>(std::stoul(*v));
      cfg.hashcash_enabled = (cfg.hashcash_base_bits != 0);
    } else if (a == "--hashcash-max-bits") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.hashcash_max_bits = static_cast<std::uint32_t>(std::stoul(*v));
    } else if (a == "--hashcash-epoch-seconds") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.hashcash_epoch_seconds = std::max<std::uint64_t>(1, std::stoull(*v));
    } else if (a == "--hashcash-fee-exempt-min") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.hashcash_fee_exempt_min = static_cast<std::uint64_t>(std::stoull(*v));
    } else if (a == "--hashcash-pressure-tx-threshold") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.hashcash_pressure_tx_threshold = static_cast<std::size_t>(std::stoull(*v));
    } else if (a == "--hashcash-pressure-step-txs") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.hashcash_pressure_step_txs = std::max<std::size_t>(1, static_cast<std::size_t>(std::stoull(*v)));
    } else if (a == "--hashcash-pressure-bits-per-step") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.hashcash_pressure_bits_per_step = static_cast<std::uint32_t>(std::stoul(*v));
    } else if (a == "--hashcash-large-tx-bytes") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.hashcash_large_tx_bytes = static_cast<std::size_t>(std::stoull(*v));
    } else if (a == "--hashcash-large-tx-extra-bits") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.hashcash_large_tx_extra_bits = static_cast<std::uint32_t>(std::stoul(*v));
    } else if (a == "--activation-enabled" || a == "--activation-max-version" || a == "--activation-window-blocks" ||
               a == "--activation-threshold-percent" || a == "--activation-delay-blocks") {
      std::cerr << "activation flags are not supported in fixed-cv7 mode\n";
      return std::nullopt;
    } else if (a == "--validator-min-bond") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.validator_min_bond_override = static_cast<std::uint64_t>(std::stoull(*v));
    } else if (a == "--validator-warmup-blocks") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.validator_warmup_blocks_override = static_cast<std::uint64_t>(std::stoull(*v));
    } else if (a == "--validator-cooldown-blocks") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.validator_cooldown_blocks_override = static_cast<std::uint64_t>(std::stoull(*v));
    } else if (a == "--validator-join-limit-window-blocks") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.validator_join_limit_window_blocks_override = static_cast<std::uint64_t>(std::stoull(*v));
    } else if (a == "--validator-join-limit-max-new") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.validator_join_limit_max_new_override = static_cast<std::uint32_t>(std::stoul(*v));
    } else if (a == "--liveness-window-blocks") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.liveness_window_blocks_override = static_cast<std::uint64_t>(std::stoull(*v));
    } else if (a == "--miss-rate-suspend-threshold-percent") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.miss_rate_suspend_threshold_percent_override = static_cast<std::uint32_t>(std::stoul(*v));
    } else if (a == "--miss-rate-exit-threshold-percent") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.miss_rate_exit_threshold_percent_override = static_cast<std::uint32_t>(std::stoul(*v));
    } else if (a == "--suspend-duration-blocks") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.suspend_duration_blocks_override = static_cast<std::uint64_t>(std::stoull(*v));
    } else if (a == "--deferred-exit-activation-height") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.deferred_exit_activation_height_override = static_cast<std::uint64_t>(std::stoull(*v));
    } else if (a == "--deferred-exit-activation-epoch-start") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.deferred_exit_activation_height_override = static_cast<std::uint64_t>(std::stoull(*v));
    } else {
      std::cerr << "unknown arg: " << a << "\n";
      return std::nullopt;
    }
  }

  if (!cfg.genesis_path.empty() && !cfg.allow_unsafe_genesis_override) {
    std::cerr << "--genesis override on mainnet requires --allow-unsafe-genesis-override\n";
    return std::nullopt;
  }
  if (!cfg.external_endpoint.empty()) {
    if (!endpoint_fingerprint_safe(cfg.external_endpoint)) {
      std::cerr << "--external-endpoint must not contain ';'\n";
      return std::nullopt;
    }
    const auto parsed = p2p::parse_endpoint(cfg.external_endpoint);
    if (!parsed.has_value() || parsed->ip.empty() || parsed->port == 0) {
      std::cerr << "--external-endpoint must be in host:port format with non-zero port\n";
      return std::nullopt;
    }
  }
  for (const auto& server : cfg.stun_servers) {
    if (!endpoint_fingerprint_safe(server)) {
      std::cerr << "--stun-servers entries must not contain ';'\n";
      return std::nullopt;
    }
    const auto parsed = p2p::parse_endpoint(server);
    if (!parsed.has_value() || parsed->ip.empty() || parsed->port == 0) {
      std::cerr << "--stun-servers requires host:port entries\n";
      return std::nullopt;
    }
  }
  cfg.stun_max_backoff_ms = std::max<std::uint32_t>(cfg.stun_refresh_interval_ms, cfg.stun_max_backoff_ms);
  cfg.stun_hysteresis_samples = std::max<std::uint32_t>(2, cfg.stun_hysteresis_samples);
  if (cfg.validator_passphrase.empty() && !validator_passphrase_env.empty()) {
    char* pv = std::getenv(validator_passphrase_env.c_str());
    if (pv) {
      cfg.validator_passphrase = pv;
      // Remove the secret from the process environment (inherited by children, visible in
      // /proc/<pid>/environ for the initial block).
      crypto::secure_wipe(pv, std::strlen(pv));
#ifdef _WIN32
      _putenv_s(validator_passphrase_env.c_str(), "");
#else
      ::unsetenv(validator_passphrase_env.c_str());
#endif
    }
  }
  if (!db_explicit) cfg.db_path = default_db_dir_for_network(cfg.network.name);
  if (cfg.public_mode && !bind_explicit) cfg.bind_ip = "0.0.0.0";
  return cfg;
}

std::optional<NodeConfig> parse_args(int argc, char** argv) {
  std::string current_flag;
  try {
    return parse_args_unchecked(argc, argv, &current_flag);
  } catch (const std::invalid_argument&) {
    std::cerr << "error: invalid numeric value for " << current_flag << "\n";
  } catch (const std::out_of_range& e) {
    std::cerr << "error: value out of range for " << current_flag << " (" << e.what() << ")\n";
  }
  return std::nullopt;
}

}  // namespace finalis::node
