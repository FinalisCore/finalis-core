#include "test_framework.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <map>

#include "codec/bytes.hpp"
#include "common/wide_arith.hpp"
#include "consensus/committee_schedule.hpp"
#include "consensus/epoch_tickets.hpp"
#include "consensus/finalized_committee.hpp"
#include "consensus/monetary.hpp"
#include "consensus/validator_registry.hpp"
#include "crypto/hash.hpp"

using namespace finalis;

namespace {

PubKey32 schedule_pub(std::uint8_t b) {
  PubKey32 p{};
  p.fill(b);
  return p;
}

Hash32 schedule_hash(std::uint8_t b) {
  Hash32 h{};
  h.fill(b);
  return h;
}

std::uint64_t schedule_hash64_prefix(const Hash32& hash) {
  std::uint64_t out = 0;
  for (std::size_t i = 0; i < 8; ++i) out = (out << 8) | static_cast<std::uint64_t>(hash[i]);
  return out;
}

Hash32 schedule_candidate_hash(const Hash32& seed, const PubKey32& selection_id) {
  codec::ByteWriter sw;
  sw.bytes(Bytes{'S', 'C', '-', 'C', 'O', 'M', 'M', 'I', 'T', 'T', 'E', 'E', '-', 'V', '3'});
  sw.bytes_fixed(seed);
  sw.bytes_fixed(selection_id);
  return crypto::sha256d(sw.data());
}

std::uint64_t schedule_candidate_strength(const consensus::FinalizedCommitteeCandidate& candidate) {
  const auto base_weight =
      candidate.effective_weight != 0 ? candidate.effective_weight : consensus::effective_weight(candidate.bonded_amount);
  const auto bounded_bonus = std::min<std::uint32_t>(candidate.ticket_bonus_bps, candidate.ticket_bonus_cap_bps);
  const auto bonded_coins =
      std::max<std::uint64_t>(1, candidate.bonded_amount / consensus::BASE_UNITS_PER_COIN);
  const auto bonus_scale = 1ULL + consensus::integer_sqrt(bonded_coins);
  const auto adjusted_bonus = static_cast<std::uint64_t>(bounded_bonus) / bonus_scale;
  return std::max<std::uint64_t>(1, base_weight * static_cast<std::uint64_t>(10'000U + adjusted_bonus));
}

bool spec_candidate_outranks(const consensus::FinalizedCommitteeCandidate& a,
                             const consensus::FinalizedCommitteeCandidate& b, const Hash32& seed) {
  const auto a_selection_id = a.selection_id == PubKey32{} ? a.pubkey : a.selection_id;
  const auto b_selection_id = b.selection_id == PubKey32{} ? b.pubkey : b.selection_id;
  const auto a_hash = schedule_candidate_hash(seed, a_selection_id);
  const auto b_hash = schedule_candidate_hash(seed, b_selection_id);
  const auto a_hash64 = schedule_hash64_prefix(a_hash);
  const auto b_hash64 = schedule_hash64_prefix(b_hash);
  const auto a_strength = schedule_candidate_strength(a);
  const auto b_strength = schedule_candidate_strength(b);
  if (const int rank_cmp = wide::compare_mul_u64(a_hash64, b_strength, b_hash64, a_strength); rank_cmp != 0) {
    return rank_cmp < 0;
  }
  if (a_hash != b_hash) return a_hash < b_hash;
  if (a_selection_id != b_selection_id) return a_selection_id < b_selection_id;
  if (a.pubkey != b.pubkey) return a.pubkey < b.pubkey;
  if (a.effective_weight != b.effective_weight) return a.effective_weight > b.effective_weight;
  if (a.capped_bonded_amount != b.capped_bonded_amount) return a.capped_bonded_amount > b.capped_bonded_amount;
  if (a.bonded_amount != b.bonded_amount) return a.bonded_amount > b.bonded_amount;
  if (a.ticket_bonus_bps != b.ticket_bonus_bps) return a.ticket_bonus_bps > b.ticket_bonus_bps;
  if (a.ticket_work_hash != b.ticket_work_hash) return a.ticket_work_hash < b.ticket_work_hash;
  if (a.ticket_nonce != b.ticket_nonce) return a.ticket_nonce < b.ticket_nonce;
  return a.ticket_bonus_cap_bps < b.ticket_bonus_cap_bps;
}

std::vector<PubKey32> spec_select_finalized_committee(std::vector<consensus::FinalizedCommitteeCandidate> candidates,
                                                      const Hash32& seed, std::size_t committee_size) {
  std::sort(candidates.begin(), candidates.end(),
            [&](const consensus::FinalizedCommitteeCandidate& a, const consensus::FinalizedCommitteeCandidate& b) {
              return spec_candidate_outranks(a, b, seed);
            });
  std::vector<PubKey32> out;
  const auto take = std::min<std::size_t>(committee_size, candidates.size());
  out.reserve(take);
  for (std::size_t i = 0; i < take; ++i) out.push_back(candidates[i].pubkey);
  return out;
}

}  // namespace

TEST(test_committee_root_is_deterministic) {
  using namespace finalis::consensus;
  std::vector<ValidatorBestTicket> committee = {
      {schedule_pub(0x01), schedule_hash(0x10), 0},
      {schedule_pub(0x02), schedule_hash(0x20), 1},
      {schedule_pub(0x03), schedule_hash(0x30), 2},
  };
  ASSERT_EQ(compute_committee_root(committee), compute_committee_root(committee));
}

TEST(test_proposer_schedule_is_deterministic) {
  using namespace finalis::consensus;
  std::vector<ValidatorBestTicket> committee = {
      {schedule_pub(0x01), schedule_hash(0x10), 0},
      {schedule_pub(0x02), schedule_hash(0x20), 0},
      {schedule_pub(0x03), schedule_hash(0x30), 0},
  };
  const Hash32 seed = compute_proposer_seed(schedule_hash(0x55), 88, compute_committee_root(committee));
  const auto a = proposer_schedule_from_committee(committee, seed);
  const auto b = proposer_schedule_from_committee(committee, seed);
  ASSERT_EQ(a, b);
  ASSERT_EQ(a.size(), 3u);
}

TEST(test_proposer_schedule_contains_all_committee_members) {
  using namespace finalis::consensus;
  std::vector<ValidatorBestTicket> committee = {
      {schedule_pub(0x01), schedule_hash(0x10), 0},
      {schedule_pub(0x02), schedule_hash(0x20), 0},
      {schedule_pub(0x03), schedule_hash(0x30), 0},
  };
  const auto schedule =
      proposer_schedule_from_committee(committee, compute_proposer_seed(schedule_hash(0x66), 12, compute_committee_root(committee)));
  ASSERT_EQ(schedule.size(), committee.size());
  ASSERT_TRUE(std::find(schedule.begin(), schedule.end(), schedule_pub(0x01)) != schedule.end());
  ASSERT_TRUE(std::find(schedule.begin(), schedule.end(), schedule_pub(0x02)) != schedule.end());
  ASSERT_TRUE(std::find(schedule.begin(), schedule.end(), schedule_pub(0x03)) != schedule.end());
}

TEST(test_committee_selection_prefers_higher_sqrt_bond) {
  using namespace finalis::consensus;
  FinalizedCommitteeCandidate low{.pubkey = schedule_pub(0x01),
                                  .bonded_amount = 1ULL * BASE_UNITS_PER_COIN,
                                  .effective_weight = effective_weight(1ULL * BASE_UNITS_PER_COIN)};
  FinalizedCommitteeCandidate high{.pubkey = schedule_pub(0x02),
                                   .bonded_amount = 9ULL * BASE_UNITS_PER_COIN,
                                   .effective_weight = effective_weight(9ULL * BASE_UNITS_PER_COIN)};
  std::size_t low_wins = 0;
  std::size_t high_wins = 0;
  for (std::uint16_t i = 0; i < 256; ++i) {
    Hash32 seed{};
    seed.fill(static_cast<std::uint8_t>(i));
    const auto selected = select_finalized_committee({low, high}, seed, 1);
    ASSERT_EQ(selected.size(), 1u);
    if (selected.front() == low.pubkey) ++low_wins;
    if (selected.front() == high.pubkey) ++high_wins;
  }
  ASSERT_TRUE(high_wins > low_wins);
}

TEST(test_split_identity_does_not_linearly_increase_committee_share) {
  using namespace finalis::consensus;
  FinalizedCommitteeCandidate single{.pubkey = schedule_pub(0x10),
                                     .bonded_amount = 16ULL * BASE_UNITS_PER_COIN,
                                     .effective_weight = effective_weight(16ULL * BASE_UNITS_PER_COIN)};
  FinalizedCommitteeCandidate split_a{.pubkey = schedule_pub(0x11),
                                      .bonded_amount = 4ULL * BASE_UNITS_PER_COIN,
                                      .effective_weight = effective_weight(4ULL * BASE_UNITS_PER_COIN)};
  FinalizedCommitteeCandidate split_b{.pubkey = schedule_pub(0x12),
                                      .bonded_amount = 4ULL * BASE_UNITS_PER_COIN,
                                      .effective_weight = effective_weight(4ULL * BASE_UNITS_PER_COIN)};
  FinalizedCommitteeCandidate split_c{.pubkey = schedule_pub(0x13),
                                      .bonded_amount = 4ULL * BASE_UNITS_PER_COIN,
                                      .effective_weight = effective_weight(4ULL * BASE_UNITS_PER_COIN)};
  FinalizedCommitteeCandidate split_d{.pubkey = schedule_pub(0x14),
                                      .bonded_amount = 4ULL * BASE_UNITS_PER_COIN,
                                      .effective_weight = effective_weight(4ULL * BASE_UNITS_PER_COIN)};
  FinalizedCommitteeCandidate rival{.pubkey = schedule_pub(0x20),
                                    .bonded_amount = 16ULL * BASE_UNITS_PER_COIN,
                                    .effective_weight = effective_weight(16ULL * BASE_UNITS_PER_COIN)};

  std::size_t single_selected = 0;
  std::size_t split_selected = 0;
  for (std::uint16_t i = 0; i < 256; ++i) {
    Hash32 seed{};
    seed.fill(static_cast<std::uint8_t>(i));
    const auto single_committee = select_finalized_committee({single, rival}, seed, 1);
    const auto split_committee = select_finalized_committee({split_a, split_b, split_c, split_d, rival}, seed, 1);
    if (!single_committee.empty() && single_committee.front() == single.pubkey) ++single_selected;
    if (!split_committee.empty() && split_committee.front() != rival.pubkey) ++split_selected;
  }
  ASSERT_TRUE(split_selected < single_selected * 4);
}

TEST(test_validator_with_same_total_bond_but_more_identities_does_not_gain_linear_total_influence) {
  using namespace finalis::consensus;
  FinalizedCommitteeCandidate single{.pubkey = schedule_pub(0x41),
                                     .bonded_amount = 25ULL * BASE_UNITS_PER_COIN,
                                     .effective_weight = effective_weight(25ULL * BASE_UNITS_PER_COIN)};
  FinalizedCommitteeCandidate split_a{.pubkey = schedule_pub(0x42),
                                      .bonded_amount = 5ULL * BASE_UNITS_PER_COIN,
                                      .effective_weight = effective_weight(5ULL * BASE_UNITS_PER_COIN)};
  FinalizedCommitteeCandidate split_b{.pubkey = schedule_pub(0x43),
                                      .bonded_amount = 5ULL * BASE_UNITS_PER_COIN,
                                      .effective_weight = effective_weight(5ULL * BASE_UNITS_PER_COIN)};
  FinalizedCommitteeCandidate split_c{.pubkey = schedule_pub(0x44),
                                      .bonded_amount = 5ULL * BASE_UNITS_PER_COIN,
                                      .effective_weight = effective_weight(5ULL * BASE_UNITS_PER_COIN)};
  FinalizedCommitteeCandidate split_d{.pubkey = schedule_pub(0x45),
                                      .bonded_amount = 5ULL * BASE_UNITS_PER_COIN,
                                      .effective_weight = effective_weight(5ULL * BASE_UNITS_PER_COIN)};
  FinalizedCommitteeCandidate split_e{.pubkey = schedule_pub(0x46),
                                      .bonded_amount = 5ULL * BASE_UNITS_PER_COIN,
                                      .effective_weight = effective_weight(5ULL * BASE_UNITS_PER_COIN)};
  FinalizedCommitteeCandidate rival{.pubkey = schedule_pub(0x47),
                                    .bonded_amount = 25ULL * BASE_UNITS_PER_COIN,
                                    .effective_weight = effective_weight(25ULL * BASE_UNITS_PER_COIN)};

  std::size_t single_selected = 0;
  std::size_t split_selected = 0;
  for (std::uint16_t i = 0; i < 256; ++i) {
    Hash32 seed{};
    seed.fill(static_cast<std::uint8_t>(i));
    const auto single_committee = select_finalized_committee({single, rival}, seed, 1);
    const auto split_committee = select_finalized_committee({split_a, split_b, split_c, split_d, split_e, rival}, seed, 1);
    if (!single_committee.empty() && single_committee.front() == single.pubkey) ++single_selected;
    if (!split_committee.empty() && split_committee.front() != rival.pubkey) ++split_selected;
  }
  ASSERT_TRUE(split_selected < single_selected * 5);
}

TEST(test_pow_modifier_cannot_overpower_bond_weight) {
  using namespace finalis::consensus;
  FinalizedCommitteeCandidate high_bond{.pubkey = schedule_pub(0x31),
                                        .bonded_amount = 16ULL * BASE_UNITS_PER_COIN,
                                        .effective_weight = effective_weight(16ULL * BASE_UNITS_PER_COIN)};
  FinalizedCommitteeCandidate low_bond{.pubkey = schedule_pub(0x32),
                                       .bonded_amount = 1ULL * BASE_UNITS_PER_COIN,
                                       .effective_weight = effective_weight(1ULL * BASE_UNITS_PER_COIN)};
  low_bond.ticket_bonus_bps = 2'500;
  std::size_t high_wins = 0;
  for (std::uint16_t i = 0; i < 256; ++i) {
    Hash32 seed{};
    seed.fill(static_cast<std::uint8_t>(i));
    const auto selected = select_finalized_committee({high_bond, low_bond}, seed, 1);
    if (!selected.empty() && selected.front() == high_bond.pubkey) ++high_wins;
  }
  ASSERT_TRUE(high_wins > 128);
}

TEST(test_bounded_ticket_difficulty_sustained_elevated_rounds_alone_do_not_reduce_difficulty) {
  using namespace finalis::consensus;
  ASSERT_TRUE(!ticket_difficulty_epoch_is_unhealthy(2'500, 10'000));
  std::uint8_t bits = 10;
  for (int i = 0; i < 4; ++i) {
    bits = adjust_bounded_ticket_difficulty_bits(bits, 64, 16, 0, 0);
  }
  ASSERT_EQ(bits, 10U);
}

TEST(test_bounded_ticket_difficulty_reduces_only_after_three_consecutive_unhealthy_epochs) {
  using namespace finalis::consensus;
  ASSERT_TRUE(ticket_difficulty_epoch_is_unhealthy(2'500, 8'400));
  ASSERT_EQ(adjust_bounded_ticket_difficulty_bits(10, 64, 16, 0, 1), 10U);
  ASSERT_EQ(adjust_bounded_ticket_difficulty_bits(10, 64, 16, 0, 2), 10U);
  ASSERT_EQ(adjust_bounded_ticket_difficulty_bits(10, 64, 16, 0, 3), 9U);
}

TEST(test_bounded_ticket_difficulty_increases_only_after_two_consecutive_healthy_epochs) {
  using namespace finalis::consensus;
  ASSERT_TRUE(ticket_difficulty_epoch_is_healthy(64, 16, 1'250, 9'500));
  ASSERT_EQ(adjust_bounded_ticket_difficulty_bits(8, 64, 16, 1, 0), 8U);
  ASSERT_EQ(adjust_bounded_ticket_difficulty_bits(8, 64, 16, 2, 0), 9U);
}

TEST(test_bounded_ticket_difficulty_holds_on_mixed_signals) {
  using namespace finalis::consensus;
  ASSERT_TRUE(!ticket_difficulty_epoch_is_healthy(64, 16, 1'000, 9'000));
  ASSERT_TRUE(!ticket_difficulty_epoch_is_unhealthy(1'000, 8'400));
  ASSERT_EQ(adjust_bounded_ticket_difficulty_bits(9, 64, 16, 0, 0), 9U);
}

TEST(test_bounded_ticket_difficulty_clamp_matches_nonce_budget) {
  using namespace finalis::consensus;
  ASSERT_EQ(adjust_bounded_ticket_difficulty_bits(MIN_BOUNDED_TICKET_DIFFICULTY_BITS, 8, 16, 0, 3),
            MIN_BOUNDED_TICKET_DIFFICULTY_BITS);
  ASSERT_EQ(adjust_bounded_ticket_difficulty_bits(MAX_BOUNDED_TICKET_DIFFICULTY_BITS, 64, 16, 2, 0),
            MAX_BOUNDED_TICKET_DIFFICULTY_BITS);
}

TEST(test_ticket_bonus_curve_is_diminishing) {
  using namespace finalis::consensus;
  EpochTicket t{};
  t.work_hash.fill(0xFF);
  t.work_hash[0] = 0x00;
  t.work_hash[1] = 0x00;
  const auto b1 = ticket_pow_bonus_bps(t, 8);
  t.work_hash[2] = 0x00;
  const auto b2 = ticket_pow_bonus_bps(t, 8);
  t.work_hash[3] = 0x00;
  const auto b3 = ticket_pow_bonus_bps(t, 8);
  ASSERT_TRUE(b1 <= b2);
  ASSERT_TRUE(b2 <= b3);
  ASSERT_TRUE((b2 - b1) >= (b3 - b2));
}

TEST(test_identical_finalized_history_yields_identical_selection) {
  using namespace finalis::consensus;
  FinalizedCommitteeCandidate x{.pubkey = schedule_pub(0x51),
                                .bonded_amount = 4ULL * BASE_UNITS_PER_COIN,
                                .effective_weight = effective_weight(4ULL * BASE_UNITS_PER_COIN)};
  FinalizedCommitteeCandidate y{.pubkey = schedule_pub(0x52),
                                .bonded_amount = 9ULL * BASE_UNITS_PER_COIN,
                                .effective_weight = effective_weight(9ULL * BASE_UNITS_PER_COIN)};
  x.ticket_bonus_bps = 500;
  y.ticket_bonus_bps = 500;
  Hash32 seed{};
  seed.fill(0x77);
  ASSERT_EQ(select_finalized_committee({x, y}, seed, 1), select_finalized_committee({x, y}, seed, 1));
}

TEST(test_committee_selection_total_order_breaks_exact_ties_by_selection_id_then_pubkey) {
  using namespace finalis::consensus;
  const PubKey32 shared_selection = schedule_pub(0x90);
  FinalizedCommitteeCandidate lower{.pubkey = schedule_pub(0x21),
                                    .selection_id = shared_selection,
                                    .bonded_amount = 4ULL * BASE_UNITS_PER_COIN,
                                    .capped_bonded_amount = 4ULL * BASE_UNITS_PER_COIN,
                                    .effective_weight = effective_weight(4ULL * BASE_UNITS_PER_COIN)};
  FinalizedCommitteeCandidate higher = lower;
  higher.pubkey = schedule_pub(0x22);
  Hash32 seed{};
  seed.fill(0x42);
  const auto forward = select_finalized_committee({higher, lower}, seed, 1);
  const auto reverse = select_finalized_committee({lower, higher}, seed, 1);
  ASSERT_EQ(forward, reverse);
  ASSERT_EQ(forward.size(), 1u);
  ASSERT_EQ(forward.front(), lower.pubkey);
}

TEST(test_committee_selection_matches_spec_comparator_under_shuffled_inputs) {
  using namespace finalis::consensus;
  Hash32 seed{};
  seed.fill(0x5A);
  std::vector<FinalizedCommitteeCandidate> candidates{
      {.pubkey = schedule_pub(0x51),
       .selection_id = schedule_pub(0xA1),
       .bonded_amount = 16ULL * BASE_UNITS_PER_COIN,
       .capped_bonded_amount = 16ULL * BASE_UNITS_PER_COIN,
       .effective_weight = effective_weight(16ULL * BASE_UNITS_PER_COIN),
       .ticket_work_hash = schedule_hash(0x11),
       .ticket_nonce = 3,
       .ticket_bonus_bps = 500,
       .ticket_bonus_cap_bps = 1000},
      {.pubkey = schedule_pub(0x52),
       .selection_id = schedule_pub(0xA2),
       .bonded_amount = 16ULL * BASE_UNITS_PER_COIN,
       .capped_bonded_amount = 16ULL * BASE_UNITS_PER_COIN,
       .effective_weight = effective_weight(16ULL * BASE_UNITS_PER_COIN),
       .ticket_work_hash = schedule_hash(0x12),
       .ticket_nonce = 2,
       .ticket_bonus_bps = 500,
       .ticket_bonus_cap_bps = 1000},
      {.pubkey = schedule_pub(0x53),
       .selection_id = schedule_pub(0xA3),
       .bonded_amount = 9ULL * BASE_UNITS_PER_COIN,
       .capped_bonded_amount = 9ULL * BASE_UNITS_PER_COIN,
       .effective_weight = effective_weight(9ULL * BASE_UNITS_PER_COIN),
       .ticket_work_hash = schedule_hash(0x13),
       .ticket_nonce = 1,
       .ticket_bonus_bps = 700,
       .ticket_bonus_cap_bps = 1000},
  };
  const auto expected = spec_select_finalized_committee(candidates, seed, 3);
  for (std::size_t i = 0; i < candidates.size(); ++i) {
    std::rotate(candidates.begin(), candidates.begin() + 1, candidates.end());
    ASSERT_EQ(select_finalized_committee(candidates, seed, 3), expected);
  }
}

TEST(test_committee_selection_cross_multiplication_handles_extreme_hash64_values_deterministically) {
  ASSERT_TRUE(wide::compare_mul_u64(std::numeric_limits<std::uint64_t>::max(), std::numeric_limits<std::uint64_t>::max(),
                                    std::numeric_limits<std::uint64_t>::max() - 1ULL,
                                    std::numeric_limits<std::uint64_t>::max()) > 0);
}

TEST(test_committee_eligibility_at_checkpoint_centralizes_lifecycle_bond_and_availability_gating) {
  using namespace finalis::consensus;
  ValidatorRegistry validators;
  validators.set_rules(ValidatorRules{.min_bond = BOND_AMOUNT, .warmup_blocks = 0, .cooldown_blocks = 0});
  const auto active_pub = schedule_pub(0x31);
  const auto inactive_pub = schedule_pub(0x32);
  const auto operator_id = schedule_pub(0x71);
  std::string err;
  ASSERT_TRUE(validators.register_bond(active_pub, OutPoint{schedule_hash(0x10), 0}, 0, BOND_AMOUNT, &err, operator_id));
  ASSERT_TRUE(validators.register_bond(inactive_pub, OutPoint{schedule_hash(0x11), 0}, 10, BOND_AMOUNT, &err, operator_id));
  validators.advance_height(1);

  auto active_info = validators.get(active_pub);
  auto inactive_info = validators.get(inactive_pub);
  ASSERT_TRUE(active_info.has_value());
  ASSERT_TRUE(inactive_info.has_value());

  availability::AvailabilityConfig availability_cfg;
  availability_cfg.min_bond = BOND_AMOUNT;
  availability_cfg.eligibility_min_score = 0;
  availability::AvailabilityOperatorState active_operator{
      .operator_pubkey = operator_id,
      .bond = BOND_AMOUNT,
      .status = availability::AvailabilityOperatorStatus::ACTIVE,
      .successful_audits = 1,
      .warmup_epochs = 1,
      .retained_prefix_count = 1,
  };
  availability::AvailabilityOperatorState warmup_operator = active_operator;
  warmup_operator.status = availability::AvailabilityOperatorStatus::WARMUP;

  const auto active_active = committee_eligibility_at_checkpoint(validators, active_pub, *active_info, 1, BOND_AMOUNT,
                                                                 &active_operator, availability_cfg, true);
  ASSERT_TRUE(active_active.eligible);

  const auto active_non_active = committee_eligibility_at_checkpoint(validators, active_pub, *active_info, 1, BOND_AMOUNT,
                                                                     &warmup_operator, availability_cfg, true);
  ASSERT_TRUE(!active_non_active.eligible);

  const auto inactive_active = committee_eligibility_at_checkpoint(validators, inactive_pub, *inactive_info, 1, BOND_AMOUNT,
                                                                   &active_operator, availability_cfg, true);
  ASSERT_TRUE(!inactive_active.eligible);
}

TEST(test_v2_operator_ticket_search_checks_full_nonce_range_and_selects_best_not_first_qualifying) {
  using namespace finalis::consensus;
  std::optional<Hash32> chosen_anchor;
  std::optional<PubKey32> chosen_operator;
  std::optional<std::uint64_t> first_qualifying_nonce;
  std::optional<std::uint64_t> best_nonce;
  for (std::uint8_t seed_b = 1; seed_b < 64 && !chosen_anchor.has_value(); ++seed_b) {
    for (std::uint8_t op_b = 1; op_b < 64 && !chosen_anchor.has_value(); ++op_b) {
      const auto anchor = schedule_hash(seed_b);
      const auto operator_id = schedule_pub(op_b);
      std::optional<std::uint64_t> local_first;
      std::optional<std::uint64_t> local_best;
      EpochTicket best_ticket{};
      bool have_best = false;
      for (std::uint64_t nonce = 0; nonce <= EPOCH_TICKET_MAX_NONCE; ++nonce) {
        EpochTicket ticket;
        ticket.epoch = 1;
        ticket.participant_pubkey = operator_id;
        ticket.challenge_anchor = anchor;
        ticket.nonce = nonce;
        ticket.work_hash = make_epoch_ticket_work_hash(ticket.epoch, ticket.challenge_anchor, ticket.participant_pubkey, nonce);
        if (epoch_ticket_meets_difficulty(ticket, DEFAULT_TICKET_DIFFICULTY_BITS) && !local_first.has_value()) {
          local_first = nonce;
        }
        if (!have_best || epoch_ticket_better(ticket, best_ticket)) {
          best_ticket = ticket;
          local_best = nonce;
          have_best = true;
        }
      }
      if (local_first.has_value() && local_best.has_value() && *local_first != *local_best) {
        chosen_anchor = anchor;
        chosen_operator = operator_id;
        first_qualifying_nonce = local_first;
        best_nonce = local_best;
      }
    }
  }
  ASSERT_TRUE(chosen_anchor.has_value());
  ASSERT_TRUE(chosen_operator.has_value());
  const auto best = best_epoch_ticket_for_operator_id(1, *chosen_anchor, *chosen_operator, 1, EPOCH_TICKET_MAX_NONCE);
  ASSERT_TRUE(best.has_value());
  ASSERT_EQ(best->nonce, *best_nonce);
  ASSERT_TRUE(*first_qualifying_nonce != *best_nonce);
}

TEST(test_epoch_ticket_better_ignores_source_height_and_uses_only_canonical_fields) {
  using namespace finalis::consensus;
  EpochTicket a;
  EpochTicket b;
  a.epoch = 1;
  b.epoch = 1;
  a.participant_pubkey = schedule_pub(0x21);
  b.participant_pubkey = schedule_pub(0x21);
  a.challenge_anchor = schedule_hash(0x55);
  b.challenge_anchor = a.challenge_anchor;
  a.nonce = 9;
  b.nonce = 9;
  a.work_hash = schedule_hash(0x11);
  b.work_hash = a.work_hash;
  a.source_height = 1;
  b.source_height = 999;

  ASSERT_TRUE(!epoch_ticket_better(a, b));
  ASSERT_TRUE(!epoch_ticket_better(b, a));
}

void register_committee_schedule_tests() {}
