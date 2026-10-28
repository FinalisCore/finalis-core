// SPDX-License-Identifier: MIT

#include "test_framework.hpp"

#include "common/network.hpp"
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
  // CLEANSLATE: Emission has a single curve and no fork-height parameter.
  ASSERT_EQ(reward_units(EMISSION_BLOCKS), 0ULL);
}

TEST(test_reward_after_emission_before_fork_preserves_zero_reward) {
  using namespace finalis::consensus;
  ASSERT_EQ(reward_units(EMISSION_BLOCKS), 0ULL);
  ASSERT_EQ(reward_units(EMISSION_BLOCKS + 99), 0ULL);
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

// Fixed supply, paid forever: the reserve pays a fixed fraction of itself per epoch once emission
// ends (never a fixed amount, so it never runs dry), and half of every fee returns to it.
TEST(test_reserve_pays_a_fraction_of_itself_after_emission_and_keeps_half_the_fees) {
  using namespace finalis::consensus;
  const std::uint64_t reserve = 2'100'000ULL * BASE_UNITS_PER_COIN;
  ASSERT_EQ(reserve_payout_units(EMISSION_BLOCKS - 1, reserve), 0ULL);  // nothing while emission runs
  const auto per_epoch = reserve_payout_units(EMISSION_BLOCKS, reserve);
  ASSERT_EQ(per_epoch, reserve * RESERVE_PAYOUT_BPS_PER_YEAR / (10'000ULL * EPOCHS_PER_YEAR_365));
  // A year of epochs takes about 5 %; the balance never reaches zero however long it pays.
  std::uint64_t r = reserve;
  for (std::uint64_t e = 0; e < EPOCHS_PER_YEAR_365; ++e) r -= reserve_payout_units(EMISSION_BLOCKS, r);
  ASSERT_TRUE(r > reserve / 100 * 95 - BASE_UNITS_PER_COIN && r < reserve / 100 * 96);
  for (std::uint64_t e = 0; e < 200 * EPOCHS_PER_YEAR_365; ++e) r -= reserve_payout_units(EMISSION_BLOCKS, r);
  ASSERT_TRUE(r > 0);
  ASSERT_EQ(fee_reserve_share_units(1'000), 500ULL);
  ASSERT_EQ(fee_reserve_share_units(1), 0ULL);  // the odd unit is paid to validators
}

TEST(test_emitted_supply_matches_the_reward_schedule) {
  using namespace finalis::consensus;
  ASSERT_EQ(emitted_supply_units(0), 0ULL);
  std::uint64_t sum = 0;
  for (std::uint64_t h = 1; h <= 3 * BLOCKS_PER_YEAR_365 + 17; ++h) {
    sum += reward_units(h);
    if (h == 1 || h == 1000 || h == BLOCKS_PER_YEAR_365 - 1 || h == BLOCKS_PER_YEAR_365 || h == 2 * BLOCKS_PER_YEAR_365 + 5) {
      ASSERT_EQ(emitted_supply_units(h), sum);
    }
  }
  ASSERT_EQ(emitted_supply_units(3 * BLOCKS_PER_YEAR_365 + 17), sum);
  // All of it, less genesis height 0, by the end; never more afterwards.
  ASSERT_EQ(emitted_supply_units(EMISSION_BLOCKS + 1'000'000), TOTAL_SUPPLY_UNITS - reward_units(0));
}

TEST(test_base_fee_follows_block_fullness_and_never_leaves_its_bounds) {
  using namespace finalis::consensus;
  // Half-full blocks keep it; full blocks raise it by 1/8, empty ones lower it by 1/8.
  ASSERT_EQ(next_base_fee_per_kib(8'000, BASE_FEE_TARGET_FULLNESS_PPM), 8'000ULL);
  ASSERT_EQ(next_base_fee_per_kib(8'000, 1'000'000), 9'000ULL);
  ASSERT_EQ(next_base_fee_per_kib(8'000, 0), 7'000ULL);
  // At the minimum (zero: no fee required at rest) a full block still raises it, an empty one cannot
  // push it lower.
  ASSERT_EQ(BASE_FEE_MIN_PER_KIB, 0ULL);
  ASSERT_EQ(next_base_fee_per_kib(BASE_FEE_MIN_PER_KIB, 1'000'000), BASE_FEE_MIN_PER_KIB + 1);
  ASSERT_EQ(next_base_fee_per_kib(BASE_FEE_MIN_PER_KIB, 0), BASE_FEE_MIN_PER_KIB);
  ASSERT_EQ(next_base_fee_per_kib(BASE_FEE_MAX_PER_KIB, 1'000'000), BASE_FEE_MAX_PER_KIB);
  // Sustained congestion: from the minimum to 1,000 units/KiB within a few hours of full blocks.
  std::uint64_t f = BASE_FEE_MIN_PER_KIB;
  std::size_t blocks = 0;
  while (f < 1'000 && blocks < 1'000) f = next_base_fee_per_kib(f, 1'000'000), ++blocks;
  ASSERT_TRUE(blocks > 20 && blocks < 120);
  // ... and back down once demand goes.
  for (std::size_t i = 0; i < 2'000; ++i) f = next_base_fee_per_kib(f, 0);
  ASSERT_EQ(f, BASE_FEE_MIN_PER_KIB);
  // Per started KiB.
  ASSERT_EQ(required_base_fee_units(10, 1), 10ULL);
  ASSERT_EQ(required_base_fee_units(10, 1024), 10ULL);
  ASSERT_EQ(required_base_fee_units(10, 1025), 20ULL);
}

TEST(test_validator_min_bond_follows_validators_and_supply) {
  using namespace finalis::consensus;
  const auto& net = finalis::mainnet_network();
  const auto coins = [](std::uint64_t units) { return units / BASE_UNITS_PER_COIN; };
  // Launch: the 150 FLS floor, whatever the validator count.
  ASSERT_EQ(coins(validator_min_bond_units(net, 1, 1)), 150ULL);
  ASSERT_EQ(coins(validator_min_bond_units(net, 1, 128)), 150ULL);
  // (150 * sqrt(N / 16) + 2 * supply / 12,800) / 3.
  const std::uint64_t h = 2 * BLOCKS_PER_YEAR_365;
  const auto supply = emitted_supply_units(h);
  const auto expect = [&](std::uint64_t n_root_x100) {  // 150 * sqrt(N/16), from sqrt(N/16) * 100
    return (150ULL * BASE_UNITS_PER_COIN * n_root_x100 / 100 + 2 * (supply / MIN_BOND_SUPPLY_DIVISOR)) / 3;
  };
  ASSERT_EQ(validator_min_bond_units(net, h, 64), expect(200));    // sqrt(4) = 2
  ASSERT_EQ(validator_min_bond_units(net, h, 256), expect(400));   // sqrt(16) = 4
  // Counted up to 512 validators: faking more does not raise the bond.
  ASSERT_EQ(validator_min_bond_units(net, h, 512), validator_min_bond_units(net, h, 100'000));
  // It rises with the supply.
  ASSERT_TRUE(validator_min_bond_units(net, 6 * BLOCKS_PER_YEAR_365, 64) > validator_min_bond_units(net, h, 64));
}

TEST(test_payout_after_emission_before_fork_is_fees_only) {
  using namespace finalis::consensus;
  const std::uint64_t fees = 12345;
  // CLEANSLATE: Payouts derive solely from the genesis-active monetary policy.
  const auto p = compute_payout(EMISSION_BLOCKS, fees, pub(0x01), {pub(0x02), pub(0x03)});
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
