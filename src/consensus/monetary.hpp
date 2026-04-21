// SPDX-License-Identifier: MIT

#pragma once

#include <cstdint>
#include <map>
#include <utility>
#include <vector>

#include "common/network.hpp"
#include "common/types.hpp"

namespace finalis::consensus {

constexpr std::uint64_t BASE_UNITS_PER_COIN = 100'000'000ULL;
constexpr std::uint64_t TOTAL_SUPPLY_COINS = 7'000'000ULL;
constexpr std::uint64_t TOTAL_SUPPLY_UNITS = TOTAL_SUPPLY_COINS * BASE_UNITS_PER_COIN;
constexpr std::uint64_t BLOCK_TIME_TARGET_SECONDS = 180ULL;
constexpr std::uint64_t BLOCKS_PER_YEAR_365 = 175'200ULL;
constexpr std::uint64_t EMISSION_YEARS = 12ULL;
constexpr std::uint64_t EMISSION_BLOCKS = EMISSION_YEARS * BLOCKS_PER_YEAR_365;
constexpr std::uint64_t EMISSION_DECAY_NUM = 4ULL;
constexpr std::uint64_t EMISSION_DECAY_DEN = 5ULL;
constexpr std::uint32_t RESERVE_ACCRUAL_BPS = 1'000U;
constexpr std::uint64_t EPOCHS_PER_YEAR_365 = BLOCKS_PER_YEAR_365 / 32ULL;
constexpr std::uint64_t POST_CAP_SUPPORT_UNITS_PER_ELIGIBLE_VALIDATOR_PER_EPOCH = 5'000'000ULL;
constexpr std::uint64_t POST_CAP_MIN_RESERVE_RUNWAY_EPOCHS = 10ULL * EPOCHS_PER_YEAR_365;
constexpr std::uint64_t POST_CAP_RESERVE_FLOOR_UNITS =
    ((TOTAL_SUPPLY_UNITS * RESERVE_ACCRUAL_BPS) / 10'000ULL) / 5ULL;
constexpr std::uint64_t ONBOARDING_REWARD_BPS = 300ULL;
// Fixed activation height for the validator economics fork. Historical validation
// below this height must remain unchanged.
constexpr std::uint64_t ECONOMICS_FORK_HEIGHT = 100'000ULL;
// New validator registrations must meet this minimum once the economics fork is active.
constexpr std::uint64_t POST_FORK_VALIDATOR_MIN_BOND_UNITS = 1'000ULL * BASE_UNITS_PER_COIN;

struct Payout {
  std::uint64_t leader{0};
  std::vector<std::pair<PubKey32, std::uint64_t>> signers;  // sorted signer pubkey order
  std::uint64_t total{0};
};

struct WeightedParticipant {
  PubKey32 pubkey{};
  std::uint64_t bonded_amount{0};
  std::uint64_t effective_weight{0};
  std::uint32_t participation_bps{10'000};
};

struct DeterministicCoinbasePayout {
  std::vector<std::pair<PubKey32, std::uint64_t>> outputs;  // sorted recipient pubkey order
  std::uint64_t total{0};
  std::uint64_t settled_epoch_fees{0};
  std::uint64_t settled_epoch_rewards{0};
  std::uint64_t reserve_subsidy_units{0};
};

std::uint64_t reward_units(std::uint64_t height);
std::uint64_t reward_units(std::uint64_t height, std::uint64_t economics_fork_height);
std::uint64_t validator_reward_units(std::uint64_t height);
std::uint64_t validator_reward_units(std::uint64_t height, std::uint64_t economics_fork_height);
std::uint64_t reserve_reward_units(std::uint64_t height);
std::uint64_t reserve_reward_units(std::uint64_t height, std::uint64_t economics_fork_height);
std::uint64_t emission_year_budget_units(std::uint64_t year_index);
std::uint64_t post_cap_support_target_units(std::size_t eligible_validator_count);
std::uint64_t post_cap_reserve_subsidy_units(std::size_t eligible_validator_count, std::uint64_t settled_epoch_fee_units,
                                             std::uint64_t reserve_balance_units);
std::uint64_t onboarding_reward_units(std::uint64_t settlement_reward_units);
bool economics_fork_active(std::uint64_t height);
bool economics_fork_active(std::uint64_t height, std::uint64_t economics_fork_height);
std::uint64_t validator_min_bond_units(std::uint64_t height);
std::uint64_t validator_min_bond_units(std::uint64_t height, std::uint64_t economics_fork_height);
std::uint64_t integer_sqrt(std::uint64_t value);
std::uint64_t effective_weight(std::uint64_t bonded_amount);
std::uint64_t validator_min_bond_units(const NetworkConfig& network, std::uint64_t height,
                                       std::size_t finalized_active_validators);
std::uint64_t validator_min_bond_units(const EconomicsConfig& economics, std::size_t finalized_active_validators);
std::uint64_t validator_max_effective_bond_units(const NetworkConfig& network, std::uint64_t height,
                                                 std::size_t finalized_active_validators);
std::uint64_t validator_max_effective_bond_units(const EconomicsConfig& economics, std::size_t finalized_active_validators);
std::uint64_t capped_effective_bond_units(const NetworkConfig& network, std::uint64_t height,
                                          std::size_t finalized_active_validators, std::uint64_t actual_bond);
std::uint64_t capped_effective_bond_units(const EconomicsConfig& economics, std::size_t finalized_active_validators,
                                          std::uint64_t actual_bond);
std::uint64_t effective_weight(const NetworkConfig& network, std::uint64_t height,
                               std::size_t finalized_active_validators, std::uint64_t actual_bond);
std::uint64_t effective_weight(const EconomicsConfig& economics, std::size_t finalized_active_validators,
                               std::uint64_t actual_bond);
std::uint64_t reward_weight(const NetworkConfig& network, std::uint64_t height,
                            std::size_t finalized_active_validators, std::uint64_t actual_bond);
std::uint64_t apply_participation_penalty_bps(std::uint64_t reward_weight_units, std::uint32_t participation_bps,
                                              std::uint32_t threshold_bps);
Payout compute_payout(std::uint64_t height, std::uint64_t fees_units, const PubKey32& leader_pubkey,
                      std::vector<PubKey32> signer_pubkeys);
Payout compute_payout(std::uint64_t height, std::uint64_t fees_units, const PubKey32& leader_pubkey,
                      std::vector<PubKey32> signer_pubkeys, std::uint64_t economics_fork_height);
Payout compute_weighted_payout(std::uint64_t height, std::uint64_t fees_units, const PubKey32& leader_pubkey,
                               std::vector<WeightedParticipant> participants);
Payout compute_weighted_payout(std::uint64_t height, std::uint64_t fees_units, const PubKey32& leader_pubkey,
                               std::vector<WeightedParticipant> participants,
                               std::uint64_t economics_fork_height);
DeterministicCoinbasePayout compute_epoch_settlement_payout(
    std::uint64_t settlement_reward_units, std::uint64_t settled_epoch_fee_units, std::uint64_t reserve_subsidy_units,
    const PubKey32& current_leader_pubkey,
    const std::map<PubKey32, std::uint64_t>& reward_score_units,
    const std::map<PubKey32, std::uint64_t>& onboarding_score_units);

}  // namespace finalis::consensus
