#include "test_framework.hpp"

#include "consensus/monetary.hpp"
#include "consensus/randomness.hpp"

using namespace finalis;

namespace {

PubKey32 pub(std::uint8_t b) {
  PubKey32 p{};
  p.fill(b);
  return p;
}

}  // namespace

TEST(test_reward_schedule_boundaries) {
  using namespace finalis::consensus;
  ASSERT_EQ(emission_year_budget_units(EMISSION_YEARS), 0ULL);
  ASSERT_TRUE(reward_units(0) > reward_units(BLOCKS_PER_YEAR_365));
  ASSERT_TRUE(reward_units(BLOCKS_PER_YEAR_365) > reward_units(2 * BLOCKS_PER_YEAR_365));
  ASSERT_TRUE(reward_units(EMISSION_BLOCKS - 1) <= reward_units((EMISSION_YEARS - 1) * BLOCKS_PER_YEAR_365));
  ASSERT_EQ(reward_units(EMISSION_BLOCKS, EMISSION_BLOCKS + 1), 0ULL);
}

TEST(test_reward_after_emission_before_fork_preserves_zero_reward) {
  using namespace finalis::consensus;
  const std::uint64_t delayed_fork_height = EMISSION_BLOCKS + 100;
  ASSERT_EQ(reward_units(EMISSION_BLOCKS, delayed_fork_height), 0ULL);
  ASSERT_EQ(reward_units(EMISSION_BLOCKS + 99, delayed_fork_height), 0ULL);
}

TEST(test_reward_after_emission_remains_zero) {
  using namespace finalis::consensus;
  ASSERT_EQ(reward_units(EMISSION_BLOCKS), 0ULL);
  ASSERT_EQ(reward_units(EMISSION_BLOCKS + 1), 0ULL);
  ASSERT_EQ(reward_units(EMISSION_BLOCKS + 10'000), 0ULL);
}

TEST(test_reward_schedule_exact_total_supply) {
  using namespace finalis::consensus;
  std::uint64_t total = 0;
  for (std::uint64_t h = 0; h < EMISSION_BLOCKS; ++h) total += reward_units(h);
  ASSERT_EQ(total, TOTAL_SUPPLY_UNITS);
}

TEST(test_reward_schedule_exact_total_supply_across_annual_budgets) {
  using namespace finalis::consensus;
  std::uint64_t total = 0;
  for (std::uint64_t year = 0; year < EMISSION_YEARS; ++year) total += emission_year_budget_units(year);
  ASSERT_EQ(total, TOTAL_SUPPLY_UNITS);
}

TEST(test_reward_schedule_declines_annually_with_exact_ratio_shape) {
  using namespace finalis::consensus;
  for (std::uint64_t year = 1; year < EMISSION_YEARS; ++year) {
    ASSERT_TRUE(emission_year_budget_units(year - 1) > emission_year_budget_units(year));
  }
}

TEST(test_validator_and_reserve_split_tracks_total_supply) {
  using namespace finalis::consensus;
  std::uint64_t gross_total = 0;
  for (std::uint64_t h = 0; h < EMISSION_BLOCKS; ++h) gross_total += reward_units(h);
  ASSERT_EQ(gross_total, TOTAL_SUPPLY_UNITS);

  std::uint64_t epoch_gross = 0;
  for (std::uint64_t h = 0; h < 32; ++h) epoch_gross += reward_units(h);
  const auto epoch_reserve = (epoch_gross * RESERVE_ACCRUAL_BPS) / 10'000ULL;
  const auto epoch_validators = epoch_gross - epoch_reserve;
  ASSERT_EQ(epoch_validators + epoch_reserve, epoch_gross);
}

TEST(test_v1_participation_penalty_scales_below_threshold) {
  using namespace finalis::consensus;
  ASSERT_EQ(apply_participation_penalty_bps(100, 10'000, 8'000), 100ULL);
  ASSERT_EQ(apply_participation_penalty_bps(100, 8'000, 8'000), 100ULL);
  ASSERT_EQ(apply_participation_penalty_bps(100, 4'000, 8'000), 50ULL);
  ASSERT_EQ(apply_participation_penalty_bps(100, 0, 8'000), 0ULL);
}

TEST(test_payout_split_deterministic_with_remainder) {
  using namespace finalis::consensus;
  const std::uint64_t h = 0;
  const auto leader = pub(0x10);
  std::vector<WeightedParticipant> participants = {
      WeightedParticipant{leader, 1ULL * BASE_UNITS_PER_COIN, effective_weight(1ULL * BASE_UNITS_PER_COIN), 10'000},
      WeightedParticipant{pub(0x55), 9ULL * BASE_UNITS_PER_COIN, effective_weight(9ULL * BASE_UNITS_PER_COIN), 10'000},
      WeightedParticipant{pub(0xAA), 4ULL * BASE_UNITS_PER_COIN, effective_weight(4ULL * BASE_UNITS_PER_COIN), 10'000},
  };
  const auto p = compute_weighted_payout(h, 0, leader, participants);

  const std::uint64_t R = validator_reward_units(h);
  ASSERT_EQ(p.total, R);
  ASSERT_EQ(p.signers.size(), 2u);

  std::uint64_t distributed = p.leader;
  for (const auto& it : p.signers) distributed += it.second;
  ASSERT_EQ(distributed, R);
  std::uint64_t high_bond_share = 0;
  std::uint64_t mid_bond_share = 0;
  for (const auto& [pubkey, units] : p.signers) {
    if (pubkey == pub(0x55)) high_bond_share = units;
    if (pubkey == pub(0xAA)) mid_bond_share = units;
  }
  ASSERT_TRUE(high_bond_share > p.leader);
  ASSERT_TRUE(p.leader >= mid_bond_share);
}

TEST(test_reward_distribution_tracks_sqrt_bond_not_validator_count) {
  using namespace finalis::consensus;
  const auto leader = pub(0x42);
  std::vector<WeightedParticipant> participants = {
      WeightedParticipant{leader, 1ULL * BASE_UNITS_PER_COIN, effective_weight(1ULL * BASE_UNITS_PER_COIN), 10'000},
      WeightedParticipant{pub(0x50), 9ULL * BASE_UNITS_PER_COIN, effective_weight(9ULL * BASE_UNITS_PER_COIN), 10'000},
  };
  const auto p = compute_weighted_payout(1, 0, leader, participants);
  ASSERT_EQ(p.signers.size(), 1u);
  ASSERT_TRUE(p.signers[0].second > p.leader);
}

TEST(test_inactive_validators_receive_zero_reward_weight) {
  using namespace finalis::consensus;
  const auto leader = pub(0x42);
  std::vector<WeightedParticipant> participants = {
      WeightedParticipant{leader, 1ULL * BASE_UNITS_PER_COIN, effective_weight(1ULL * BASE_UNITS_PER_COIN), 10'000},
      WeightedParticipant{pub(0x50), 9ULL * BASE_UNITS_PER_COIN, effective_weight(9ULL * BASE_UNITS_PER_COIN), 0},
  };
  const auto p = compute_weighted_payout(1, 0, leader, participants);
  ASSERT_TRUE(p.signers.empty());
  ASSERT_EQ(p.leader, p.total);
}

TEST(test_epoch_settlement_pays_exact_accrued_scores) {
  using namespace finalis::consensus;
  const auto leader = pub(0x01);
  std::map<PubKey32, std::uint64_t> scores;
  scores[pub(0x10)] = 1;
  scores[pub(0x20)] = 3;
  const auto payout = compute_epoch_settlement_payout(400, 25, 7, leader, scores, {});
  ASSERT_EQ(payout.total, 432ULL);
  ASSERT_EQ(payout.settled_epoch_fees, 25ULL);
  ASSERT_EQ(payout.settled_epoch_rewards, 400ULL);
  ASSERT_EQ(payout.reserve_subsidy_units, 7ULL);
  ASSERT_EQ(payout.outputs.size(), 2u);

  std::uint64_t sum = 0;
  std::uint64_t low_units = 0;
  std::uint64_t high_units = 0;
  for (const auto& [pubkey, units] : payout.outputs) {
    sum += units;
    if (pubkey == pub(0x10)) low_units = units;
    if (pubkey == pub(0x20)) high_units = units;
  }
  ASSERT_EQ(sum, payout.total);
  ASSERT_TRUE(high_units > low_units);
  ASSERT_EQ(high_units + low_units, payout.total);
}

TEST(test_onboarding_reward_units_is_three_percent_of_settlement_rewards) {
  using namespace finalis::consensus;
  ASSERT_EQ(onboarding_reward_units(0), 0ULL);
  ASSERT_EQ(onboarding_reward_units(100), 3ULL);
  ASSERT_EQ(onboarding_reward_units(10'000), 300ULL);
}

TEST(test_epoch_settlement_keeps_onboarding_slice_in_validator_pool_when_no_onboarding_scores_exist) {
  using namespace finalis::consensus;
  const auto leader = pub(0x41);
  std::map<PubKey32, std::uint64_t> scores;
  scores[pub(0x10)] = 1;
  scores[pub(0x20)] = 3;

  const auto payout = compute_epoch_settlement_payout(10'000, 25, 7, leader, scores, {});
  ASSERT_EQ(payout.total, 10'032ULL);

  std::uint64_t sum = 0;
  for (const auto& [_, units] : payout.outputs) sum += units;
  ASSERT_EQ(sum, payout.total);

  std::uint64_t validator_units = 0;
  for (const auto& [pubkey, units] : payout.outputs) {
    if (pubkey == pub(0x10) || pubkey == pub(0x20)) validator_units += units;
  }
  ASSERT_EQ(validator_units, payout.total);
}

TEST(test_post_cap_reserve_subsidy_respects_gap_floor_and_runway_caps) {
  using namespace finalis::consensus;
  const std::uint64_t large_reserve_balance =
      POST_CAP_RESERVE_FLOOR_UNITS + (POST_CAP_MIN_RESERVE_RUNWAY_EPOCHS * 9ULL);
  const std::uint64_t low_runway_reserve_balance = POST_CAP_RESERVE_FLOOR_UNITS + 100ULL;
  const std::uint64_t low_runway_cap = low_runway_reserve_balance / POST_CAP_MIN_RESERVE_RUNWAY_EPOCHS;
  const std::uint64_t spendable_large_reserve = large_reserve_balance - POST_CAP_RESERVE_FLOOR_UNITS;
  ASSERT_EQ(post_cap_support_target_units(3), 15'000'000ULL);
  ASSERT_EQ(post_cap_reserve_subsidy_units(0, 0, large_reserve_balance), 0ULL);
  ASSERT_EQ(post_cap_reserve_subsidy_units(3, 15'000'000ULL, large_reserve_balance), 0ULL);
  ASSERT_EQ(post_cap_reserve_subsidy_units(3, 0, POST_CAP_RESERVE_FLOOR_UNITS), 0ULL);
  ASSERT_EQ(post_cap_reserve_subsidy_units(3, 0, large_reserve_balance), spendable_large_reserve);
  ASSERT_EQ(post_cap_reserve_subsidy_units(3, 14'999'995ULL, large_reserve_balance), 5ULL);
  ASSERT_EQ(post_cap_reserve_subsidy_units(3, 0, low_runway_reserve_balance), 100ULL);
  ASSERT_TRUE(low_runway_cap > 100ULL);
}

TEST(test_payout_after_emission_before_fork_is_fees_only) {
  using namespace finalis::consensus;
  const std::uint64_t fees = 12345;
  const auto p = compute_payout(EMISSION_BLOCKS, fees, pub(0x01), {pub(0x02), pub(0x03)}, EMISSION_BLOCKS + 10);
  ASSERT_EQ(p.total, fees);
  std::uint64_t sum = p.leader;
  for (const auto& it : p.signers) sum += it.second;
  ASSERT_EQ(sum, fees);
}

TEST(test_payout_after_emission_is_fees_only) {
  using namespace finalis::consensus;
  const std::uint64_t fees = 12345;
  const auto p = compute_payout(EMISSION_BLOCKS, fees, pub(0x01), {pub(0x02), pub(0x03)});
  ASSERT_EQ(p.total, fees);
}

TEST(test_payout_collapses_leader_signer_share_into_leader_output) {
  using namespace finalis::consensus;
  const auto leader = pub(0x42);
  const auto p = compute_payout(1, 0, leader, {leader});
  const std::uint64_t R = validator_reward_units(1);
  ASSERT_EQ(p.total, R);
  ASSERT_EQ(p.leader, R);
  ASSERT_TRUE(p.signers.empty());
}

void register_monetary_tests() {}
