#include "consensus/monetary.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <map>

#include "common/wide_arith.hpp"

namespace finalis::consensus {

namespace {

constexpr std::uint32_t kLeaderParticipationBps = 20'000;

std::uint64_t clamp_u64(std::uint64_t value, std::uint64_t lo, std::uint64_t hi) {
  return std::min<std::uint64_t>(hi, std::max<std::uint64_t>(lo, value));
}

std::uint64_t participant_score(const WeightedParticipant& participant, const PubKey32& leader_pubkey) {
  const std::uint64_t base_weight =
      participant.effective_weight != 0 ? participant.effective_weight : effective_weight(participant.bonded_amount);
  if (participant.participation_bps == 0 || base_weight == 0) return 0;
  const std::uint64_t participation = participant.participation_bps;
  std::uint64_t score = (base_weight * participation) / 10'000ULL;
  if (score == 0 && base_weight != 0) score = 1;
  if (participant.pubkey == leader_pubkey) {
    score = (score * static_cast<std::uint64_t>(kLeaderParticipationBps)) / 10'000ULL;
    if (score == 0 && base_weight != 0) score = 1;
  }
  return score;
}

std::uint64_t reserve_share_of_gross(std::uint64_t gross_units) {
  return wide::mul_div_u64(gross_units, static_cast<std::uint64_t>(RESERVE_ACCRUAL_BPS), 10'000ULL);
}

const std::array<std::uint64_t, EMISSION_YEARS>& emission_year_budgets() {
  static const std::array<std::uint64_t, EMISSION_YEARS> budgets = []() {
    std::array<std::uint64_t, EMISSION_YEARS> weights{};
    std::array<std::uint64_t, EMISSION_YEARS> year_budgets{};

    std::uint64_t weight = 1;
    for (std::uint64_t i = 1; i < EMISSION_YEARS; ++i) weight *= EMISSION_DECAY_DEN;
    std::uint64_t total_weight = 0;
    for (std::uint64_t year = 0; year < EMISSION_YEARS; ++year) {
      weights[year] = weight;
      total_weight += weight;
      if (year + 1 < EMISSION_YEARS) weight = (weight / EMISSION_DECAY_DEN) * EMISSION_DECAY_NUM;
    }

    std::uint64_t allocated = 0;
    for (std::uint64_t year = 0; year + 1 < EMISSION_YEARS; ++year) {
      const auto budget = wide::mul_div_u64(TOTAL_SUPPLY_UNITS, weights[year], total_weight);
      year_budgets[year] = budget;
      allocated += budget;
    }
    year_budgets[EMISSION_YEARS - 1] = TOTAL_SUPPLY_UNITS - allocated;
    return year_budgets;
  }();
  return budgets;
}

std::uint64_t gross_reward_units_for_height(std::uint64_t height) {
  if (height >= EMISSION_BLOCKS) return 0;
  const auto year = std::min<std::uint64_t>(EMISSION_YEARS - 1, height / BLOCKS_PER_YEAR_365);
  const auto offset = height % BLOCKS_PER_YEAR_365;
  const auto annual_budget = emission_year_budgets()[static_cast<std::size_t>(year)];
  const auto base = annual_budget / BLOCKS_PER_YEAR_365;
  const auto rem = annual_budget % BLOCKS_PER_YEAR_365;
  return base + ((offset < rem) ? 1ULL : 0ULL);
}

}  // namespace

std::uint64_t reward_units(std::uint64_t height) {
  return reward_units(height, ECONOMICS_FORK_HEIGHT);
}

std::uint64_t reward_units(std::uint64_t height, std::uint64_t economics_fork_height) {
  (void)economics_fork_height;
  return gross_reward_units_for_height(height);
}

std::uint64_t validator_reward_units(std::uint64_t height) {
  return validator_reward_units(height, ECONOMICS_FORK_HEIGHT);
}

std::uint64_t validator_reward_units(std::uint64_t height, std::uint64_t economics_fork_height) {
  const auto gross = reward_units(height, economics_fork_height);
  return gross - reserve_share_of_gross(gross);
}

std::uint64_t reserve_reward_units(std::uint64_t height) {
  return reserve_reward_units(height, ECONOMICS_FORK_HEIGHT);
}

std::uint64_t reserve_reward_units(std::uint64_t height, std::uint64_t economics_fork_height) {
  return reward_units(height, economics_fork_height) - validator_reward_units(height, economics_fork_height);
}

std::uint64_t emission_year_budget_units(std::uint64_t year_index) {
  if (year_index >= EMISSION_YEARS) return 0;
  return emission_year_budgets()[static_cast<std::size_t>(year_index)];
}

std::uint64_t post_cap_support_target_units(std::size_t eligible_validator_count) {
  return static_cast<std::uint64_t>(eligible_validator_count) * POST_CAP_SUPPORT_UNITS_PER_ELIGIBLE_VALIDATOR_PER_EPOCH;
}

std::uint64_t post_cap_reserve_subsidy_units(std::size_t eligible_validator_count, std::uint64_t settled_epoch_fee_units,
                                             std::uint64_t reserve_balance_units) {
  if (eligible_validator_count == 0) return 0;
  const auto target_support = post_cap_support_target_units(eligible_validator_count);
  if (settled_epoch_fee_units >= target_support) return 0;
  if (reserve_balance_units <= POST_CAP_RESERVE_FLOOR_UNITS) return 0;
  const auto support_gap = target_support - settled_epoch_fee_units;
  const auto spendable_reserve = reserve_balance_units - POST_CAP_RESERVE_FLOOR_UNITS;
  const auto runway_cap = reserve_balance_units / std::max<std::uint64_t>(1, POST_CAP_MIN_RESERVE_RUNWAY_EPOCHS);
  return std::min({support_gap, spendable_reserve, runway_cap});
}

std::uint64_t onboarding_reward_units(std::uint64_t settlement_reward_units) {
  return wide::mul_div_u64(settlement_reward_units, ONBOARDING_REWARD_BPS, 10'000ULL);
}

bool economics_fork_active(std::uint64_t height) {
  return economics_fork_active(height, ECONOMICS_FORK_HEIGHT);
}

bool economics_fork_active(std::uint64_t height, std::uint64_t economics_fork_height) {
  return height >= economics_fork_height;
}

std::uint64_t validator_min_bond_units(std::uint64_t height) {
  return validator_min_bond_units(height, ECONOMICS_FORK_HEIGHT);
}

std::uint64_t validator_min_bond_units(std::uint64_t height, std::uint64_t economics_fork_height) {
  if (!economics_fork_active(height, economics_fork_height)) return BOND_AMOUNT;
  return POST_FORK_VALIDATOR_MIN_BOND_UNITS;
}

std::uint64_t integer_sqrt(std::uint64_t value) {
  std::uint64_t lo = 0;
  std::uint64_t hi = std::min<std::uint64_t>(value, 0xFFFFFFFFULL) + 1;
  while (lo + 1 < hi) {
    const std::uint64_t mid = lo + ((hi - lo) / 2);
    if (mid == 0 || mid <= (value / mid)) {
      lo = mid;
    } else {
      hi = mid;
    }
  }
  return lo;
}

std::uint64_t effective_weight(std::uint64_t bonded_amount) { return std::max<std::uint64_t>(1, integer_sqrt(bonded_amount)); }

std::uint64_t validator_min_bond_units(const NetworkConfig& network, std::uint64_t height,
                                       std::size_t finalized_active_validators) {
  const auto& cfg = active_economics_policy(network, height);
  return validator_min_bond_units(cfg, finalized_active_validators);
}

std::uint64_t validator_min_bond_units(const EconomicsConfig& cfg, std::size_t finalized_active_validators) {
  const std::uint64_t active = std::max<std::uint64_t>(1, static_cast<std::uint64_t>(finalized_active_validators));
  constexpr std::uint64_t kScale = 100'000'000ULL;
  constexpr std::uint64_t kScaleSqrt = 10'000ULL;
  const std::uint64_t scaled_ratio = wide::mul_div_u64(cfg.target_validators, kScale, active);
  const std::uint64_t multiplier = integer_sqrt(scaled_ratio);
  const std::uint64_t scaled = wide::mul_div_u64(cfg.base_min_bond, multiplier, kScaleSqrt);
  return clamp_u64(scaled, cfg.min_bond_floor, cfg.min_bond_ceiling);
}

std::uint64_t validator_max_effective_bond_units(const NetworkConfig& network, std::uint64_t height,
                                                 std::size_t finalized_active_validators) {
  const auto& cfg = active_economics_policy(network, height);
  return validator_max_effective_bond_units(cfg, finalized_active_validators);
}

std::uint64_t validator_max_effective_bond_units(const EconomicsConfig& cfg, std::size_t finalized_active_validators) {
  const auto min_bond = validator_min_bond_units(cfg, finalized_active_validators);
  const auto multiple = cfg.max_effective_bond_multiple;
  return wide::mul_u64_exceeds_u64(min_bond, multiple) ? std::numeric_limits<std::uint64_t>::max()
                                                       : (min_bond * multiple);
}

std::uint64_t capped_effective_bond_units(const NetworkConfig& network, std::uint64_t height,
                                          std::size_t finalized_active_validators, std::uint64_t actual_bond) {
  return std::min(actual_bond, validator_max_effective_bond_units(network, height, finalized_active_validators));
}

std::uint64_t capped_effective_bond_units(const EconomicsConfig& economics, std::size_t finalized_active_validators,
                                          std::uint64_t actual_bond) {
  return std::min(actual_bond, validator_max_effective_bond_units(economics, finalized_active_validators));
}

std::uint64_t effective_weight(const NetworkConfig& network, std::uint64_t height,
                               std::size_t finalized_active_validators, std::uint64_t actual_bond) {
  return effective_weight(capped_effective_bond_units(network, height, finalized_active_validators, actual_bond));
}

std::uint64_t effective_weight(const EconomicsConfig& economics, std::size_t finalized_active_validators,
                               std::uint64_t actual_bond) {
  return effective_weight(capped_effective_bond_units(economics, finalized_active_validators, actual_bond));
}

std::uint64_t reward_weight(const NetworkConfig& network, std::uint64_t height,
                            std::size_t finalized_active_validators, std::uint64_t actual_bond) {
  return effective_weight(network, height, finalized_active_validators, actual_bond);
}

std::uint64_t apply_participation_penalty_bps(std::uint64_t reward_weight_units, std::uint32_t participation_bps,
                                              std::uint32_t threshold_bps) {
  if (reward_weight_units == 0 || threshold_bps == 0) return reward_weight_units;
  if (participation_bps >= threshold_bps) return reward_weight_units;
  return wide::mul_div_u64(reward_weight_units, static_cast<std::uint64_t>(participation_bps),
                           static_cast<std::uint64_t>(threshold_bps));
}

Payout compute_payout(std::uint64_t height, std::uint64_t fees_units, const PubKey32& leader_pubkey,
                      std::vector<PubKey32> signer_pubkeys) {
  return compute_payout(height, fees_units, leader_pubkey, std::move(signer_pubkeys), ECONOMICS_FORK_HEIGHT);
}

Payout compute_payout(std::uint64_t height, std::uint64_t fees_units, const PubKey32& leader_pubkey,
                      std::vector<PubKey32> signer_pubkeys, std::uint64_t economics_fork_height) {
  std::sort(signer_pubkeys.begin(), signer_pubkeys.end());
  signer_pubkeys.erase(std::unique(signer_pubkeys.begin(), signer_pubkeys.end()), signer_pubkeys.end());
  std::vector<WeightedParticipant> participants;
  participants.reserve(signer_pubkeys.size());
  for (const auto& pub : signer_pubkeys) {
    participants.push_back(WeightedParticipant{pub, BOND_AMOUNT, effective_weight(BOND_AMOUNT), 10'000});
  }
  return compute_weighted_payout(height, fees_units, leader_pubkey, std::move(participants), economics_fork_height);
}

Payout compute_weighted_payout(std::uint64_t height, std::uint64_t fees_units, const PubKey32& leader_pubkey,
                               std::vector<WeightedParticipant> participants) {
  return compute_weighted_payout(height, fees_units, leader_pubkey, std::move(participants), ECONOMICS_FORK_HEIGHT);
}

Payout compute_weighted_payout(std::uint64_t height, std::uint64_t fees_units, const PubKey32& leader_pubkey,
                               std::vector<WeightedParticipant> participants,
                               std::uint64_t economics_fork_height) {
  Payout out;
  const std::uint64_t reward = validator_reward_units(height, economics_fork_height);
  out.total = reward + fees_units;

  std::sort(participants.begin(), participants.end(), [](const WeightedParticipant& a, const WeightedParticipant& b) {
    return a.pubkey < b.pubkey;
  });
  participants.erase(std::unique(participants.begin(), participants.end(),
                                 [](const WeightedParticipant& a, const WeightedParticipant& b) {
                                   return a.pubkey == b.pubkey;
                                 }),
                     participants.end());

  std::map<PubKey32, std::uint64_t> scores;
  std::uint64_t total_score = 0;
  for (const auto& participant : participants) {
    const auto score = participant_score(participant, leader_pubkey);
    if (score == 0) continue;
    scores[participant.pubkey] = score;
    total_score += score;
  }
  if (scores.empty()) {
    out.leader = out.total;
    return out;
  }

  std::uint64_t distributed = 0;
  for (const auto& [pub, score] : scores) {
    const auto share = wide::mul_div_u64(out.total, score, total_score);
    distributed += share;
    if (pub == leader_pubkey) {
      out.leader += share;
    } else {
      out.signers.push_back({pub, share});
    }
  }
  std::uint64_t remainder = out.total - distributed;
  if (remainder > 0) out.leader += remainder;
  return out;
}

DeterministicCoinbasePayout compute_epoch_settlement_payout(
    std::uint64_t settlement_reward_units, std::uint64_t settled_epoch_fee_units, std::uint64_t reserve_subsidy_units,
    const PubKey32& current_leader_pubkey,
    const std::map<PubKey32, std::uint64_t>& reward_score_units,
    const std::map<PubKey32, std::uint64_t>& onboarding_score_units) {
  DeterministicCoinbasePayout out;
  out.settled_epoch_fees = settled_epoch_fee_units;
  out.settled_epoch_rewards = settlement_reward_units;
  out.reserve_subsidy_units = reserve_subsidy_units;
  out.total = settlement_reward_units + settled_epoch_fee_units + reserve_subsidy_units;

  std::map<PubKey32, std::uint64_t> merged;
  auto distribute_pool = [&](std::uint64_t pool, const std::map<PubKey32, std::uint64_t>& score_units,
                             bool fallback_to_leader) {
    if (pool == 0) return;
    std::uint64_t total_score = 0;
    for (const auto& [pub, score] : score_units) {
      (void)pub;
      if (score == 0) continue;
      total_score += score;
    }
    if (total_score == 0) {
      if (fallback_to_leader) merged[current_leader_pubkey] += pool;
      return;
    }

    std::uint64_t distributed = 0;
    std::optional<PubKey32> last_pub;
    for (const auto& [pub, score] : score_units) {
      if (score == 0) continue;
      const auto share = wide::mul_div_u64(pool, score, total_score);
      merged[pub] += share;
      distributed += share;
      last_pub = pub;
    }
    const auto remainder = pool - distributed;
    if (remainder > 0) {
      if (last_pub.has_value()) {
        merged[*last_pub] += remainder;
      } else if (fallback_to_leader) {
        merged[current_leader_pubkey] += remainder;
      }
    }
  };

  const auto raw_onboarding_units = onboarding_reward_units(settlement_reward_units);
  const auto onboarding_units = onboarding_score_units.empty() ? 0ULL : raw_onboarding_units;
  const auto validator_units = settlement_reward_units - onboarding_units;

  distribute_pool(validator_units + settled_epoch_fee_units + reserve_subsidy_units, reward_score_units, true);
  distribute_pool(onboarding_units, onboarding_score_units, false);

  out.outputs.reserve(merged.size());
  for (const auto& [pub, units] : merged) {
    if (units == 0) continue;
    out.outputs.push_back({pub, units});
  }
  return out;
}

}  // namespace finalis::consensus
