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
// The supply is fixed at TOTAL_SUPPLY_UNITS, emitted over EMISSION_YEARS. Validators are paid for
// ever without new coins from a protocol reserve that is never emptied:
// - RESERVE_ACCRUAL_BPS of every block's emission is saved into it;
// - FEE_RESERVE_BPS of the fees, every slashed bond and every burn go back into it (fees, bonds and
//   burns move coins, they never create them);
// - after emission ends it pays out RESERVE_PAYOUT_BPS_PER_YEAR of its balance per year, a fixed
//   fraction per epoch, so it can never run dry.
constexpr std::uint32_t RESERVE_ACCRUAL_BPS = 3'000U;
constexpr std::uint32_t FEE_RESERVE_BPS = 5'000U;
constexpr std::uint32_t RESERVE_PAYOUT_BPS_PER_YEAR = 500U;
constexpr std::uint64_t EPOCHS_PER_YEAR_365 = BLOCKS_PER_YEAR_365 / 32ULL;
constexpr std::uint64_t ONBOARDING_REWARD_BPS = 300ULL;
// Minimum validator bond (validator_min_bond_units): max(floor, (B_N + 2 * B_S) / 3) with
// B_N = base * sqrt(min(N, cap) / target) and B_S = emitted supply / MIN_BOND_SUPPLY_DIVISOR, so that
// 128 minimum bonds lock 1 % of the supply; computed from finalized state only.
constexpr std::uint64_t MIN_BOND_SUPPLY_DIVISOR = 12'800ULL;
constexpr std::uint64_t MIN_BOND_VALIDATOR_COUNT_CAP = 512ULL;
// Automatic base fee: every transaction pays at least base_fee_per_kib per started KiB of its size.
// After each block it moves towards keeping blocks half full (fullness = the larger of the byte and
// record shares of the block limits), by at most 1/8 per block (at least 1 unit when above target),
// and never below the minimum. It follows demand alone: no price, no setting.
// Zero at rest: while blocks are less than half full no fee is required (as before the base fee).
constexpr std::uint64_t BASE_FEE_MIN_PER_KIB = 0ULL;
constexpr std::uint64_t BASE_FEE_MAX_PER_KIB = 1'000'000'000'000ULL;
constexpr std::uint64_t BASE_FEE_TARGET_FULLNESS_PPM = 500'000ULL;

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
std::uint64_t validator_reward_units(std::uint64_t height);
std::uint64_t reserve_reward_units(std::uint64_t height);
std::uint64_t emission_year_budget_units(std::uint64_t year_index);
// Coins emitted by heights 1..height (the circulating supply plus the reserve).
std::uint64_t emitted_supply_units(std::uint64_t height);
// The reserve's payout for one epoch settled at `height`: zero while emission runs, then
// RESERVE_PAYOUT_BPS_PER_YEAR / EPOCHS_PER_YEAR_365 of the balance.
std::uint64_t reserve_payout_units(std::uint64_t height, std::uint64_t reserve_balance_units);
// The base fee after a block that was `fullness_ppm` full (0..1,000,000).
std::uint64_t next_base_fee_per_kib(std::uint64_t base_fee_per_kib, std::uint64_t fullness_ppm);
// The least fee a transaction of `serialized_size` bytes pays under `base_fee_per_kib`.
std::uint64_t required_base_fee_units(std::uint64_t base_fee_per_kib, std::uint64_t serialized_size);
// The reserve's share of an epoch's fees; validators are paid the rest.
std::uint64_t fee_reserve_share_units(std::uint64_t fee_pool_units);
std::uint64_t onboarding_reward_units(std::uint64_t settlement_reward_units);
std::uint64_t validator_min_bond_units(std::uint64_t height);
std::uint64_t integer_sqrt(std::uint64_t value);
std::uint64_t effective_weight(std::uint64_t bonded_amount);
std::uint64_t validator_min_bond_units(const NetworkConfig& network, std::uint64_t height,
                                       std::size_t finalized_active_validators);
std::uint64_t validator_min_bond_units(const EconomicsConfig& economics, std::uint64_t height,
                                       std::size_t finalized_active_validators);
std::uint64_t validator_max_effective_bond_units(const NetworkConfig& network, std::uint64_t height,
                                                 std::size_t finalized_active_validators);
std::uint64_t validator_max_effective_bond_units(const EconomicsConfig& economics, std::uint64_t height,
                                                 std::size_t finalized_active_validators);
std::uint64_t capped_effective_bond_units(const NetworkConfig& network, std::uint64_t height,
                                          std::size_t finalized_active_validators, std::uint64_t actual_bond);
std::uint64_t capped_effective_bond_units(const EconomicsConfig& economics, std::uint64_t height,
                                          std::size_t finalized_active_validators, std::uint64_t actual_bond);
std::uint64_t effective_weight(const NetworkConfig& network, std::uint64_t height,
                               std::size_t finalized_active_validators, std::uint64_t actual_bond);
std::uint64_t effective_weight(const EconomicsConfig& economics, std::uint64_t height,
                               std::size_t finalized_active_validators, std::uint64_t actual_bond);
std::uint64_t reward_weight(const NetworkConfig& network, std::uint64_t height,
                            std::size_t finalized_active_validators, std::uint64_t actual_bond);
std::uint64_t apply_participation_penalty_bps(std::uint64_t reward_weight_units, std::uint32_t participation_bps,
                                              std::uint32_t threshold_bps);
Payout compute_payout(std::uint64_t height, std::uint64_t fees_units, const PubKey32& leader_pubkey,
                      std::vector<PubKey32> signer_pubkeys);
Payout compute_weighted_payout(std::uint64_t height, std::uint64_t fees_units, const PubKey32& leader_pubkey,
                               std::vector<WeightedParticipant> participants);
DeterministicCoinbasePayout compute_epoch_settlement_payout(
    std::uint64_t settlement_reward_units, std::uint64_t settled_epoch_fee_units, std::uint64_t reserve_subsidy_units,
    const PubKey32& current_leader_pubkey,
    const std::map<PubKey32, std::uint64_t>& reward_score_units,
    const std::map<PubKey32, std::uint64_t>& onboarding_score_units);

}  // namespace finalis::consensus
