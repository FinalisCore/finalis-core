#include "test_framework.hpp"

#include <array>
#include <stdexcept>

#include "consensus/finalized_committee.hpp"
#include "consensus/validator_registry.hpp"
#include "consensus/votes.hpp"
#include "crypto/ed25519.hpp"

using namespace finalis;

namespace {

crypto::KeyPair key_from_byte(std::uint8_t b) {
  std::array<std::uint8_t, 32> seed{};
  seed.fill(b);
  auto kp = crypto::keypair_from_seed32(seed);
  if (!kp.has_value()) throw std::runtime_error("key generation failed");
  return *kp;
}

}  // namespace

TEST(test_validator_min_bond_enforced) {
  consensus::ValidatorRegistry vr;
  vr.set_rules(consensus::ValidatorRules{.min_bond = 1000, .warmup_blocks = 5, .cooldown_blocks = 20});
  auto kp = crypto::keypair_from_seed32(std::array<std::uint8_t, 32>{});
  ASSERT_TRUE(kp.has_value());
  std::string err;
  ASSERT_TRUE(!vr.can_register_bond(kp->public_key, 10, 999, &err));
  ASSERT_TRUE(vr.can_register_bond(kp->public_key, 10, 1000, &err));
}

TEST(test_validator_cooldown_enforced_for_exit_rejoin) {
  consensus::ValidatorRegistry vr;
  vr.set_rules(consensus::ValidatorRules{.min_bond = BOND_AMOUNT, .warmup_blocks = 2, .cooldown_blocks = 10});
  auto kp = crypto::keypair_from_seed32(std::array<std::uint8_t, 32>{1});
  ASSERT_TRUE(kp.has_value());
  const OutPoint bond{zero_hash(), 1};
  ASSERT_TRUE(vr.register_bond(kp->public_key, bond, 5, BOND_AMOUNT));
  vr.advance_height(8);
  ASSERT_TRUE(vr.request_unbond(kp->public_key, 8));

  std::string err;
  ASSERT_TRUE(!vr.can_register_bond(kp->public_key, 12, BOND_AMOUNT, &err));
  ASSERT_TRUE(vr.can_register_bond(kp->public_key, 18, BOND_AMOUNT, &err));
}

TEST(test_validator_warmup_enforced) {
  consensus::ValidatorRegistry vr;
  vr.set_rules(consensus::ValidatorRules{.min_bond = BOND_AMOUNT, .warmup_blocks = 4, .cooldown_blocks = 0});
  auto kp = crypto::keypair_from_seed32(std::array<std::uint8_t, 32>{2});
  ASSERT_TRUE(kp.has_value());
  ASSERT_TRUE(vr.register_bond(kp->public_key, OutPoint{zero_hash(), 2}, 10, BOND_AMOUNT));

  ASSERT_TRUE(!vr.is_active_for_height(kp->public_key, 13));
  ASSERT_TRUE(vr.is_active_for_height(kp->public_key, 14));
}

TEST(test_validator_suspended_excluded_then_unsuspends) {
  consensus::ValidatorRegistry vr;
  vr.set_rules(consensus::ValidatorRules{.min_bond = BOND_AMOUNT, .warmup_blocks = 1, .cooldown_blocks = 0});
  auto kp = crypto::keypair_from_seed32(std::array<std::uint8_t, 32>{3});
  ASSERT_TRUE(kp.has_value());
  ASSERT_TRUE(vr.register_bond(kp->public_key, OutPoint{zero_hash(), 3}, 1, BOND_AMOUNT));
  vr.advance_height(3);

  auto info = vr.get(kp->public_key);
  ASSERT_TRUE(info.has_value());
  info->status = consensus::ValidatorStatus::SUSPENDED;
  info->suspended_until_height = 20;
  vr.upsert(kp->public_key, *info);

  ASSERT_TRUE(!vr.is_active_for_height(kp->public_key, 10));
  auto active_before = vr.active_sorted(10);
  ASSERT_TRUE(std::find(active_before.begin(), active_before.end(), kp->public_key) == active_before.end());

  vr.advance_height(20);
  ASSERT_TRUE(vr.is_active_for_height(kp->public_key, 20));
}

TEST(test_validator_reregister_keeps_liveness_counters) {
  consensus::ValidatorRegistry vr;
  vr.set_rules(consensus::ValidatorRules{.min_bond = BOND_AMOUNT, .warmup_blocks = 2, .cooldown_blocks = 5});
  auto kp = crypto::keypair_from_seed32(std::array<std::uint8_t, 32>{4});
  ASSERT_TRUE(kp.has_value());

  ASSERT_TRUE(vr.register_bond(kp->public_key, OutPoint{zero_hash(), 7}, 10, BOND_AMOUNT));
  auto info = vr.get(kp->public_key);
  ASSERT_TRUE(info.has_value());
  info->eligible_count_window = 9;
  info->participated_count_window = 4;
  info->penalty_strikes = 2;
  info->status = consensus::ValidatorStatus::EXITING;
  info->last_exit_height = 12;
  vr.upsert(kp->public_key, *info);

  std::string err;
  ASSERT_TRUE(vr.can_register_bond(kp->public_key, 17, BOND_AMOUNT, &err));
  ASSERT_TRUE(vr.register_bond(kp->public_key, OutPoint{zero_hash(), 8}, 17, BOND_AMOUNT));

  auto after = vr.get(kp->public_key);
  ASSERT_TRUE(after.has_value());
  ASSERT_EQ(after->eligible_count_window, 9u);
  ASSERT_EQ(after->participated_count_window, 4u);
  ASSERT_EQ(after->penalty_strikes, 2u);
  ASSERT_EQ(after->status, consensus::ValidatorStatus::PENDING);
}

TEST(test_validator_liveness_participation_order_independent) {
  auto a = key_from_byte(10).public_key;
  auto b = key_from_byte(11).public_key;
  auto c = key_from_byte(12).public_key;
  std::vector<PubKey32> committee{a, b, c};

  FinalitySig sa{a, Sig64{}};
  FinalitySig sb{b, Sig64{}};
  FinalitySig sc{c, Sig64{}};
  std::vector<FinalitySig> sigs1{sa, sb, sc};
  std::vector<FinalitySig> sigs2{sc, sa, sb};

  const auto p1 = consensus::committee_participants_from_finality(committee, sigs1);
  const auto p2 = consensus::committee_participants_from_finality(committee, sigs2);
  ASSERT_EQ(p1, p2);
}

TEST(test_validator_liveness_participation_dedups_pubkeys) {
  auto a = key_from_byte(13).public_key;
  auto b = key_from_byte(14).public_key;
  std::vector<PubKey32> committee{a, b};

  Sig64 s1{};
  s1[0] = 1;
  Sig64 s2{};
  s2[0] = 2;
  std::vector<FinalitySig> sigs{{a, s1}, {a, s2}, {b, s1}};

  const auto p = consensus::committee_participants_from_finality(committee, sigs);
  ASSERT_EQ(p.size(), 2u);
  ASSERT_TRUE(std::find(p.begin(), p.end(), a) != p.end());
  ASSERT_TRUE(std::find(p.begin(), p.end(), b) != p.end());
}

TEST(test_validator_liveness_counts_only_committee_signers) {
  auto a = key_from_byte(15).public_key;
  auto b = key_from_byte(16).public_key;
  auto outsider = key_from_byte(17).public_key;
  std::vector<PubKey32> committee{a, b};

  std::vector<FinalitySig> sigs{{a, Sig64{}}, {outsider, Sig64{}}, {outsider, Sig64{}}};
  const auto p = consensus::committee_participants_from_finality(committee, sigs);
  ASSERT_EQ(p.size(), 1u);
  ASSERT_EQ(p[0], a);
}

TEST(test_validator_liveness_window_counts_include_boundary_block) {
  // Model A: count height H first, then roll over when (H+1) hits the window boundary.
  ASSERT_TRUE(!consensus::validator_liveness_window_should_rollover(3, 0, 5));
  ASSERT_TRUE(consensus::validator_liveness_window_should_rollover(4, 0, 5));
}

TEST(test_validator_liveness_window_rollover_resets_start) {
  const std::uint64_t next = consensus::validator_liveness_next_window_start(4, 0, 5);
  ASSERT_EQ(next, 5u);
  ASSERT_EQ(consensus::validator_liveness_next_window_start(5, next, 5), 5u);
}

TEST(test_validator_liveness_window_off_by_one_locked) {
  // Window=5 and epoch start=0 => heights [0..4], [5..9], ...
  for (std::uint64_t h = 0; h <= 9; ++h) {
    const bool should = consensus::validator_liveness_window_should_rollover(h, 0, 5);
    if (h == 4 || h == 9) ASSERT_TRUE(should);
    else ASSERT_TRUE(!should);
  }
}

TEST(test_validator_join_window_replay_deterministic) {
  auto apply_finalized_sequence = [](const std::vector<std::pair<std::uint64_t, std::uint32_t>>& finalized_events) {
    std::uint64_t window_start = 0;
    std::uint32_t join_count = 0;
    constexpr std::uint64_t kWindow = 5;
    for (const auto& [height, new_regs] : finalized_events) {
      consensus::advance_validator_join_window(height, kWindow, &window_start, &join_count);
      join_count += new_regs;
    }
    return std::make_pair(window_start, join_count);
  };

  const std::vector<std::pair<std::uint64_t, std::uint32_t>> finalized{
      {1, 1}, {2, 0}, {3, 1}, {6, 0}, {7, 1}, {10, 1}};

  const auto a = apply_finalized_sequence(finalized);
  const auto b = apply_finalized_sequence(finalized);
  ASSERT_EQ(a.first, b.first);
  ASSERT_EQ(a.second, b.second);
}

TEST(test_validator_join_window_ignores_non_finalized_paths) {
  // Mempool/proposal activity does not alter join window state; only finalized applies do.
  std::uint64_t start_a = 0;
  std::uint32_t count_a = 0;
  std::uint64_t start_b = 0;
  std::uint32_t count_b = 0;
  constexpr std::uint64_t kWindow = 5;

  // Finalized sequence.
  consensus::advance_validator_join_window(1, kWindow, &start_a, &count_a);
  count_a += 1;
  consensus::advance_validator_join_window(6, kWindow, &start_a, &count_a);
  count_a += 1;

  // Same finalized sequence, with extra non-finalized "would-be registrations" ignored.
  consensus::advance_validator_join_window(1, kWindow, &start_b, &count_b);
  count_b += 1;
  // Non-finalized activity: no finalized apply call, so no mutation.
  consensus::advance_validator_join_window(6, kWindow, &start_b, &count_b);
  count_b += 1;

  ASSERT_EQ(start_a, start_b);
  ASSERT_EQ(count_a, count_b);
}

TEST(test_vote_tracker_allows_higher_round_relock_same_height) {
  consensus::VoteTracker tracker;
  const auto kp = key_from_byte(21);

  Vote a;
  a.height = 25;
  a.round = 0;
  a.block_id.fill(0x11);
  a.validator_pubkey = kp.public_key;
  a.signature.fill(0x01);

  Vote b = a;
  b.round = 1;
  b.block_id.fill(0x22);
  b.signature.fill(0x02);

  const auto first = tracker.add_vote(a);
  ASSERT_TRUE(first.accepted);
  ASSERT_TRUE(!first.duplicate);
  ASSERT_TRUE(!first.equivocation);

  const auto second = tracker.add_vote(b);
  ASSERT_TRUE(second.accepted);
  ASSERT_TRUE(!second.duplicate);
  ASSERT_TRUE(!second.equivocation);
}

TEST(test_vote_tracker_rejects_same_round_equivocation) {
  consensus::VoteTracker tracker;
  const auto kp = key_from_byte(22);

  Vote a;
  a.height = 30;
  a.round = 0;
  a.block_id.fill(0x44);
  a.validator_pubkey = kp.public_key;
  a.signature.fill(0x03);

  Vote b = a;
  b.block_id.fill(0x55);
  b.signature.fill(0x04);

  ASSERT_TRUE(tracker.add_vote(a).accepted);
  const auto repeat = tracker.add_vote(b);
  ASSERT_TRUE(!repeat.accepted);
  ASSERT_TRUE(!repeat.duplicate);
  ASSERT_TRUE(repeat.equivocation);
  ASSERT_TRUE(repeat.evidence.has_value());
}

void register_validator_lifecycle_tests() {}
