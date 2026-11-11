// SPDX-License-Identifier: MIT

#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <vector>
#include <array>

#include "common/types.hpp"

namespace finalis {

struct EconomicsConfig {
  std::uint64_t activation_height{0};
  std::uint64_t target_validators{16};
  std::uint64_t base_min_bond{BOND_AMOUNT};
  std::uint64_t min_bond_floor{BOND_AMOUNT};
  std::uint64_t min_bond_ceiling{BOND_AMOUNT * 10};
  std::uint64_t max_effective_bond_multiple{10};
  std::uint32_t participation_threshold_bps{8'000};
  std::uint32_t ticket_bonus_cap_bps{1'000};
};

struct NetworkConfig {
  std::string name;
  std::array<std::uint8_t, 16> network_id{};
  std::uint32_t magic{MAGIC};
  std::uint16_t protocol_version{PROTOCOL_VERSION};
  std::uint64_t feature_flags{0};
  std::uint16_t p2p_default_port{19440};
  std::uint16_t lightserver_default_port{19444};
  std::size_t max_committee{MAX_COMMITTEE};
  // Finalized-state metadata persists committee snapshots in deterministic
  // epochs for historical replay and inspection.
  std::uint64_t committee_epoch_blocks{32};
  // Ingress certifier terms (C1): each lane has one certifier per term of this many blocks, and an
  // IngressCertificate's epoch field is its term's first height. Must divide committee_epoch_blocks;
  // otherwise a term is the whole epoch (consensus::ingress_certifier_term_start). Consensus-critical.
  std::uint64_t ingress_certifier_term_blocks{2};
  // First height certified under C1 terms; below it a term is the whole epoch (the rule before
  // v2.2.13), so a node replaying testnet-3 from genesis accepts its pre-flag-day certificates.
  // 0 everywhere except testnet-3 (flag day: last old block 4800). Consensus-critical.
  std::uint64_t ingress_certifier_terms_activation_height{0};
  // First height that accepts SCUPGSIG upgrade signals (docs/spec/SIGNALED_ACTIVATION.md). 0 on mainnet
  // (from genesis); testnet-3 never until its flag day height is set. Below it an SCUPGSIG output is
  // rejected, as releases without signaled activation reject it. Consensus-critical.
  std::uint64_t upgrade_signal_activation_height{0};
  // An upgrade not locked in this many blocks after its first signal fails (its record is removed).
  // ~30 days at the 180 s minimum block interval; testnet ~3 days. Consensus-critical.
  std::uint64_t upgrade_signal_window_blocks{14'400};
  // A term's certifier is drawn from the committee members that signed at least one of the last this
  // many finalized parents (prev_finality_signers), so an offline validator stops holding lanes.
  // Routing only, but every node must use the same value (it is in the handshake fingerprint).
  std::uint64_t ingress_certifier_liveness_blocks{2};
  // Round pacing (local, not consensus-critical): round r times out after
  // min(round_timeout_ms * (num/den)^r, max_round_timeout_ms). The growing
  // timeout lets rounds outlast any bounded message delay (partial synchrony).
  // num <= den disables the backoff.
  std::uint32_t round_timeout_ms{30'000};
  std::uint32_t max_round_timeout_ms{300'000};
  std::uint32_t round_timeout_backoff_num{3};
  std::uint32_t round_timeout_backoff_den{2};
  std::uint32_t min_block_interval_ms{180'000};
  std::size_t max_payload_len{8 * 1024 * 1024};
  std::uint64_t bond_amount{BOND_AMOUNT};
  std::uint64_t warmup_blocks{WARMUP_BLOCKS};
  std::uint64_t unbond_delay_blocks{UNBOND_DELAY_BLOCKS};
  std::uint64_t validator_min_bond{BOND_AMOUNT};
  std::uint64_t validator_bond_min_amount{BOND_AMOUNT};
  std::uint64_t validator_bond_max_amount{BOND_AMOUNT * 100};
  std::uint64_t validator_warmup_blocks{WARMUP_BLOCKS};
  std::uint64_t validator_cooldown_blocks{100};
  std::uint64_t validator_join_limit_window_blocks{1'000};
  std::uint32_t validator_join_limit_max_new{64};
  std::uint64_t liveness_window_blocks{10'000};
  std::uint32_t miss_rate_suspend_threshold_percent{30};
  std::uint32_t miss_rate_exit_threshold_percent{60};
  std::uint64_t suspend_duration_blocks{1'000};
  std::uint32_t onboarding_admission_pow_difficulty_bits{0};
  std::uint32_t validator_join_admission_pow_difficulty_bits{0};
  // CLEANSLATE: Finality binding, availability recovery and confidential UTXOs (TxV2) are live from
  // genesis; TxV2 has no activation height.
  std::uint64_t finality_binding_activation_height{0};
  std::uint64_t availability_recovery_activation_height{0};
  std::uint64_t deferred_exit_activation_height{std::numeric_limits<std::uint64_t>::max()};
  std::uint64_t bootstrap_penalty_exit_protection_activation_height{std::numeric_limits<std::uint64_t>::max()};
  std::uint64_t empty_active_set_epoch_escape_activation_height{std::numeric_limits<std::uint64_t>::max()};
  std::vector<std::string> default_seeds;
  std::vector<EconomicsConfig> economics_policies;
};

const NetworkConfig& mainnet_network();
const NetworkConfig& testnet_network();
bool is_testnet_name(const std::string& name);  // "testnet" or its address prefix "tsc"
std::uint64_t round_timeout_ms_for_round(const NetworkConfig& network, std::uint32_t round);
const NetworkConfig& network_by_name(const std::string& name);  // testnet for "testnet"/"tsc", else mainnet
const std::vector<EconomicsConfig>& economics_policies(const NetworkConfig& network);
const EconomicsConfig& active_economics_policy(const NetworkConfig& network, std::uint64_t height);
bool finality_binding_active_at_height(const NetworkConfig& network, std::uint64_t height);
bool availability_recovery_active_at_height(const NetworkConfig& network, std::uint64_t height);
bool bootstrap_penalty_exit_protection_active_at_height(const NetworkConfig& network, std::uint64_t height);
bool empty_active_set_epoch_escape_active_at_height(const NetworkConfig& network, std::uint64_t height);
// The ingress certifier term length in force at `height`: ingress_certifier_term_blocks from
// ingress_certifier_terms_activation_height on, the whole epoch before it.
std::uint64_t ingress_certifier_term_blocks_at(const NetworkConfig& network, std::uint64_t height);
bool onboarding_admission_pow_enabled(const NetworkConfig& network);
bool validator_join_admission_pow_enabled(const NetworkConfig& network);

}  // namespace finalis
