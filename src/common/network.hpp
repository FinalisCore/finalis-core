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
  std::uint32_t round_timeout_ms{30'000};
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
  std::uint64_t finality_binding_activation_height{std::numeric_limits<std::uint64_t>::max()};
  std::uint64_t availability_recovery_activation_height{std::numeric_limits<std::uint64_t>::max()};
  std::uint64_t confidential_utxo_activation_height{std::numeric_limits<std::uint64_t>::max()};
  std::vector<std::string> default_seeds;
  std::vector<EconomicsConfig> economics_policies;
};

const NetworkConfig& mainnet_network();
const NetworkConfig& network_by_name(const std::string& name);  // mainnet only
const std::vector<EconomicsConfig>& economics_policies(const NetworkConfig& network);
const EconomicsConfig& active_economics_policy(const NetworkConfig& network, std::uint64_t height);
bool finality_binding_active_at_height(const NetworkConfig& network, std::uint64_t height);
bool availability_recovery_active_at_height(const NetworkConfig& network, std::uint64_t height);
bool confidential_utxo_active_at_height(const NetworkConfig& network, std::uint64_t height);
bool onboarding_admission_pow_enabled(const NetworkConfig& network);
bool validator_join_admission_pow_enabled(const NetworkConfig& network);

}  // namespace finalis
