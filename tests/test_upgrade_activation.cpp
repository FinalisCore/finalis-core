// SPDX-License-Identifier: MIT

#include "test_framework.hpp"

#include <limits>
#include <set>
#include <vector>

#include "common/chain_id.hpp"
#include "consensus/canonical_derivation.hpp"
#include "consensus/upgrade_activation.hpp"
#include "consensus/validator_registry.hpp"

using namespace finalis;
using namespace finalis::consensus;

namespace {

constexpr std::uint64_t kB = 32;

PubKey32 op(std::uint8_t i) {
  PubKey32 p{};
  p.fill(i);
  return p;
}

std::set<PubKey32> ops(std::uint8_t n) {
  std::set<PubKey32> out;
  for (std::uint8_t i = 1; i <= n; ++i) out.insert(op(i));
  return out;
}

constexpr std::uint64_t kWindow = 10 * kB;

UpgradeDef def() {
  Hash32 fp{};
  fp.fill(0xAB);
  return UpgradeDef{upgrade_id("test-upgrade", fp), "test-upgrade", 33};
}

// 9 active operators, committee(L+1) = operators 1..7 (quorum 5).
UpgradeLockInInputs inputs() {
  UpgradeLockInInputs in;
  in.active_operators = ops(9);
  for (std::uint8_t i = 1; i <= 7; ++i) in.next_committee_operators.push_back(op(i));
  in.min_eligible_operators = 4;
  return in;
}

void signal(UpgradeRecord* rec, std::initializer_list<std::uint8_t> ids) {
  for (auto i : ids) rec->signalers.insert(op(i));
}

}  // namespace

TEST(test_upgrade_id_binds_name_and_rules_fingerprint) {
  Hash32 a{}, b{};
  a.fill(1);
  b.fill(2);
  ASSERT_TRUE(upgrade_id("x", a) == upgrade_id("x", a));
  ASSERT_TRUE(upgrade_id("x", a) != upgrade_id("y", a));
  ASSERT_TRUE(upgrade_id("x", a) != upgrade_id("x", b));
}

TEST(test_upgrade_operator_threshold_is_ceil_two_thirds) {
  ASSERT_EQ(upgrade_operator_threshold(0), 0u);
  ASSERT_EQ(upgrade_operator_threshold(1), 1u);
  ASSERT_EQ(upgrade_operator_threshold(3), 2u);
  ASSERT_EQ(upgrade_operator_threshold(4), 3u);
  ASSERT_EQ(upgrade_operator_threshold(9), 6u);
  ASSERT_EQ(upgrade_operator_threshold(10), 7u);
}

TEST(test_upgrade_signal_admissibility) {
  // No record yet: the first signal opens one.
  ASSERT_TRUE(check_upgrade_signal(nullptr, op(1), true, 0) == UpgradeSignalReject::None);
  ASSERT_TRUE(check_upgrade_signal(nullptr, op(1), false, 0) == UpgradeSignalReject::NotActiveOperator);
  ASSERT_TRUE(check_upgrade_signal(nullptr, op(1), true, kMaxOpenUpgradeSignalsPerOperator) ==
              UpgradeSignalReject::TooManyOpen);
  UpgradeRecord rec;
  rec.state = UpgradeState::Signaling;
  signal(&rec, {1});
  ASSERT_TRUE(check_upgrade_signal(&rec, op(1), true, 1) == UpgradeSignalReject::Duplicate);
  ASSERT_TRUE(check_upgrade_signal(&rec, op(2), true, kMaxOpenUpgradeSignalsPerOperator) ==
              UpgradeSignalReject::TooManyOpen);
  // After lock-in a late operator may always signal: it is how it regains committee eligibility.
  rec.state = UpgradeState::LockedIn;
  ASSERT_TRUE(check_upgrade_signal(&rec, op(2), true, kMaxOpenUpgradeSignalsPerOperator) == UpgradeSignalReject::None);
  rec.state = UpgradeState::Active;
  ASSERT_TRUE(check_upgrade_signal(&rec, op(2), true, kMaxOpenUpgradeSignalsPerOperator) == UpgradeSignalReject::None);
}

TEST(test_upgrade_lock_in_needs_operator_and_committee_thresholds) {
  auto in = inputs();
  UpgradeRecord rec;
  // 6 of 9 operators (= ceil 2/3) but only 4 of 7 committee seats (< quorum 5): no lock-in.
  signal(&rec, {1, 2, 3, 4, 8, 9});
  ASSERT_TRUE(!upgrade_lock_in_reached(rec, in));
  // 5 of 7 seats, but now only 5 of 9 operators: no lock-in.
  rec.signalers.clear();
  signal(&rec, {1, 2, 3, 4, 5});
  ASSERT_TRUE(!upgrade_lock_in_reached(rec, in));
  // 6 of 9 operators and 5 of 7 seats: lock-in.
  signal(&rec, {9});
  ASSERT_TRUE(upgrade_lock_in_reached(rec, in));
  // Signalers that are no longer active operators do not count.
  rec.signalers.clear();
  signal(&rec, {1, 2, 3, 4, 5, 42});
  ASSERT_TRUE(!upgrade_lock_in_reached(rec, in));
  // Signalers must also reach the minimum eligible operator count.
  rec.signalers.clear();
  signal(&rec, {1, 2, 3, 4, 5, 9});
  in.min_eligible_operators = 7;
  ASSERT_TRUE(!upgrade_lock_in_reached(rec, in));
  // No operators or no committee: never.
  ASSERT_TRUE(!upgrade_lock_in_reached(rec, UpgradeLockInInputs{}));
}

TEST(test_upgrade_lifecycle_locks_in_and_activates_two_epochs_later) {
  const auto in = inputs();
  UpgradeRecord rec;
  rec.first_signal_height = kB - 3;
  signal(&rec, {1});
  advance_upgrade_at_epoch_end(&rec, kB, kB, kWindow, in);  // first epoch end after the first signal
  ASSERT_TRUE(rec.state == UpgradeState::Signaling);

  signal(&rec, {2, 3, 4, 5, 9});
  const std::uint64_t lock_end = 3 * kB;  // end of epoch L
  advance_upgrade_at_epoch_end(&rec, lock_end, kB, kWindow, in);
  ASSERT_TRUE(rec.state == UpgradeState::LockedIn);
  ASSERT_EQ(rec.lock_in_height, lock_end);
  ASSERT_EQ(rec.activation_height, lock_end + 1 + kB);  // start of epoch L+2
  ASSERT_TRUE(!upgrade_active(rec, lock_end + kB));
  ASSERT_TRUE(upgrade_active(rec, lock_end + kB + 1));  // already true while LockedIn

  advance_upgrade_at_epoch_end(&rec, lock_end + kB, kB, kWindow, in);  // end of L+1
  ASSERT_TRUE(rec.state == UpgradeState::Active);
  const auto active = rec;
  advance_upgrade_at_epoch_end(&rec, lock_end + 2 * kB + 5 * kWindow, kB, kWindow, UpgradeLockInInputs{});
  ASSERT_TRUE(rec == active);  // terminal
}

TEST(test_upgrade_fails_at_window_end_and_lock_in_wins_on_the_same_boundary) {
  const auto in = inputs();
  UpgradeRecord rec;
  rec.state = UpgradeState::Signaling;
  rec.first_signal_height = kB + 1;
  signal(&rec, {1, 2, 3});
  const std::uint64_t last_end = rec.first_signal_height + kWindow - 1;  // next height == window end
  advance_upgrade_at_epoch_end(&rec, last_end - kB, kB, kWindow, in);
  ASSERT_TRUE(rec.state == UpgradeState::Signaling);
  advance_upgrade_at_epoch_end(&rec, last_end, kB, kWindow, in);
  ASSERT_TRUE(rec.state == UpgradeState::Failed);
  ASSERT_TRUE(!upgrade_active(rec, last_end + 10 * kB));

  UpgradeRecord late = rec;
  late.state = UpgradeState::Signaling;
  signal(&late, {4, 5, 9});
  advance_upgrade_at_epoch_end(&late, last_end, kB, kWindow, in);
  ASSERT_TRUE(late.state == UpgradeState::LockedIn);

  // The window end never overflows.
  UpgradeRecord far;
  far.state = UpgradeState::Signaling;
  far.first_signal_height = std::numeric_limits<std::uint64_t>::max() - 1;
  advance_upgrade_at_epoch_end(&far, 5 * kB, kB, kWindow, in);
  ASSERT_TRUE(far.state == UpgradeState::Signaling);
}

TEST(test_upgrade_excludes_non_signalers_from_committees_from_activation_on) {
  UpgradeRecord rec;
  rec.state = UpgradeState::LockedIn;
  rec.activation_height = 4 * kB + 1;
  signal(&rec, {1, 2});
  const std::vector<UpgradeRecord> records{rec};
  // Before activation everyone stays eligible.
  ASSERT_TRUE(operator_eligible_under_upgrades(records, op(3), 3 * kB + 1));
  // From the activation epoch on, only signalers.
  ASSERT_TRUE(operator_eligible_under_upgrades(records, op(1), 4 * kB + 1));
  ASSERT_TRUE(!operator_eligible_under_upgrades(records, op(3), 4 * kB + 1));
  // A late signal restores eligibility.
  auto later = records;
  later[0].signalers.insert(op(3));
  ASSERT_TRUE(operator_eligible_under_upgrades(later, op(3), 5 * kB + 1));
  // Failed upgrades never restrict anyone.
  auto failed = records;
  failed[0].state = UpgradeState::Failed;
  ASSERT_TRUE(operator_eligible_under_upgrades(failed, op(3), 9 * kB + 1));
}

namespace {
consensus::ValidatorRegistry registry_with_active(const std::vector<PubKey32>& active, const PubKey32& pending) {
  consensus::ValidatorRegistry vr;
  for (const auto& pub : active) {
    consensus::ValidatorInfo info;
    info.status = consensus::ValidatorStatus::ACTIVE;
    info.has_bond = true;
    info.bonded_amount = 150;
    vr.upsert(pub, info);
  }
  consensus::ValidatorInfo info;
  info.status = consensus::ValidatorStatus::ONBOARDING;
  vr.upsert(pending, info);
  return vr;
}
}  // namespace

// Step 2b + A1: signals are admitted against finalized upgrade state only, whatever upgrades the
// binary knows, and recorded per operator; the first one opens the record and its window.
TEST(test_upgrade_signal_admission_and_apply) {
  const auto d = def();
  const auto vr = registry_with_active({op(1), op(2)}, op(9));
  UpgradeRecords records;
  ASSERT_EQ(upgrade_signal_admission_error(records, vr, 40, op(9), d.id), std::string("not-active-operator"));
  ASSERT_EQ(upgrade_signal_admission_error(records, vr, 40, op(7), d.id), std::string("not-active-operator"));
  ASSERT_TRUE(upgrade_signal_admission_error(records, vr, 10, op(1), d.id).empty());  // no binary-side window

  ASSERT_TRUE(apply_upgrade_signal(vr, 40, op(1), d.id, &records));
  const auto operator1 = canonical_operator_id(op(1), *vr.get(op(1)));
  ASSERT_TRUE(records.at(d.id).signalers.count(operator1) == 1);
  ASSERT_EQ(records.at(d.id).first_signal_height, 40u);
  ASSERT_EQ(upgrade_signal_admission_error(records, vr, 41, op(1), d.id), std::string("duplicate-signal"));
  ASSERT_TRUE(!apply_upgrade_signal(vr, 41, op(1), d.id, &records));  // a duplicate changes nothing
  ASSERT_TRUE(!apply_upgrade_signal(vr, 41, op(9), d.id, &records));  // nor a non-operator
  ASSERT_TRUE(apply_upgrade_signal(vr, 45, op(2), d.id, &records));
  ASSERT_EQ(records.at(d.id).first_signal_height, 40u);  // a later signal keeps the window
  ASSERT_EQ(records.at(d.id).signalers.size(), 2u);

  // Any id is admissible, but an operator holds at most kMaxOpenUpgradeSignalsPerOperator open ones.
  Hash32 other{};
  other.fill(0xEE);
  ASSERT_TRUE(apply_upgrade_signal(vr, 46, op(1), other, &records));
  Hash32 third{};
  third.fill(0xEF);
  ASSERT_EQ(upgrade_signal_admission_error(records, vr, 47, op(1), third), std::string("too-many-open-signals"));
  ASSERT_TRUE(!apply_upgrade_signal(vr, 47, op(1), third, &records));
  ASSERT_TRUE(upgrade_signal_admission_error(records, vr, 47, op(2), third).empty());  // per operator
  // Once one of them locks in, it no longer counts as open.
  records.at(d.id).state = UpgradeState::LockedIn;
  ASSERT_TRUE(upgrade_signal_admission_error(records, vr, 48, op(1), third).empty());
  ASSERT_EQ(records.size(), 2u);
}

TEST(test_upgrade_record_codec_and_commitment_root) {
  UpgradeRecord rec;
  rec.state = UpgradeState::LockedIn;
  rec.first_signal_height = 40;
  rec.lock_in_height = 96;
  rec.activation_height = 129;
  rec.signalers = {op(3), op(1), op(2)};
  const auto bytes = serialize_upgrade_record(rec);
  const auto back = parse_upgrade_record(bytes);
  ASSERT_TRUE(back.has_value() && *back == rec);
  auto bad_state = bytes;
  bad_state[0] = 9;
  ASSERT_TRUE(!parse_upgrade_record(bad_state).has_value());
  bad_state[0] = static_cast<std::uint8_t>(UpgradeState::Failed);  // never stored
  ASSERT_TRUE(!parse_upgrade_record(bad_state).has_value());
  auto trailing = bytes;
  trailing.push_back(0);
  ASSERT_TRUE(!parse_upgrade_record(trailing).has_value());
  auto unsorted = bytes;  // swap the first two signalers: not canonical
  std::swap_ranges(unsorted.end() - 96, unsorted.end() - 64, unsorted.end() - 64);
  ASSERT_TRUE(!parse_upgrade_record(unsorted).has_value());

  const Hash32 id = def().id;
  UpgradeRecords a{{id, rec}};
  UpgradeRecords b = a;
  ASSERT_TRUE(upgrade_records_commitment_root(a) == upgrade_records_commitment_root(b));
  b[id].signalers.insert(op(4));
  ASSERT_TRUE(upgrade_records_commitment_root(a) != upgrade_records_commitment_root(b));
  ASSERT_TRUE(known_upgrades(mainnet_network()).empty());  // nothing ships signaled yet
}

// Step 3: the epoch-end inputs come from the registry and the checkpoint just derived for L+1. Every
// record advances (A1: no binary upgrade table is consulted); a failed one is removed.
TEST(test_upgrade_records_advance_at_epoch_end_from_checkpoint_inputs) {
  CanonicalDerivationConfig cfg;
  cfg.network.committee_epoch_blocks = kB;
  cfg.network.upgrade_signal_window_blocks = kWindow;
  const auto d = def();
  const auto vr = registry_with_active({op(1), op(2), op(3), op(4), op(5), op(6)}, op(9));
  const auto id_of = [&](std::uint8_t i) { return canonical_operator_id(op(i), *vr.get(op(i))); };

  storage::FinalizedCommitteeCheckpoint cp;
  cp.epoch_start_height = 2 * kB + 1;  // judged at the end of epoch [33, 64]
  for (std::uint8_t i = 1; i <= 4; ++i) cp.ordered_operator_ids.push_back(id_of(i));
  cp.derivation_mode = storage::FinalizedCommitteeDerivationMode::NORMAL;
  cp.availability_min_eligible_operators = 7;

  const auto in = upgrade_lock_in_inputs(vr, cp);
  ASSERT_EQ(in.active_operators.size(), 6u);  // the ONBOARDING validator is not an active operator
  ASSERT_EQ(in.next_committee_operators.size(), 4u);
  ASSERT_EQ(in.min_eligible_operators, 7u);
  auto fallback_cp = cp;
  fallback_cp.derivation_mode = storage::FinalizedCommitteeDerivationMode::FALLBACK;
  ASSERT_EQ(upgrade_lock_in_inputs(vr, fallback_cp).min_eligible_operators, 0u);

  UpgradeRecord four;
  four.state = UpgradeState::Signaling;
  four.first_signal_height = 33;  // window ends at 353
  for (std::uint8_t i = 1; i <= 4; ++i) four.signalers.insert(id_of(i));

  // 4 of 6 operators and 4 of 4 seats, but NORMAL needs 7 eligible: not yet.
  UpgradeRecords records{{d.id, four}};
  advance_upgrade_records_at_epoch_end(cfg, vr, cp, &records);
  ASSERT_TRUE(records.at(d.id).state == UpgradeState::Signaling);
  // FALLBACK has no availability minimum: locks in at 64, active from 97.
  advance_upgrade_records_at_epoch_end(cfg, vr, fallback_cp, &records);
  ASSERT_TRUE(records.at(d.id).state == UpgradeState::LockedIn);
  ASSERT_EQ(records.at(d.id).lock_in_height, 2 * kB);
  ASSERT_EQ(records.at(d.id).activation_height, 3 * kB + 1);
  ASSERT_TRUE(!upgrade_active(records.at(d.id), 3 * kB));
  ASSERT_TRUE(upgrade_active(records.at(d.id), 3 * kB + 1));

  // 3 of 6 operators is below ceil(2/3 * 6) = 4: stays SIGNALING, then fails at the window end and
  // its record is removed, so a later signal opens a new window.
  UpgradeRecord three = four;
  three.signalers.erase(id_of(4));
  UpgradeRecords short_records{{d.id, three}};
  advance_upgrade_records_at_epoch_end(cfg, vr, fallback_cp, &short_records);
  ASSERT_TRUE(short_records.at(d.id).state == UpgradeState::Signaling);
  auto at_timeout = fallback_cp;
  at_timeout.epoch_start_height = 10 * kB + 1;  // 321 < 353
  advance_upgrade_records_at_epoch_end(cfg, vr, at_timeout, &short_records);
  ASSERT_TRUE(short_records.at(d.id).state == UpgradeState::Signaling);
  at_timeout.epoch_start_height = 11 * kB + 1;  // 353: window over
  advance_upgrade_records_at_epoch_end(cfg, vr, at_timeout, &short_records);
  ASSERT_TRUE(short_records.empty());

  // No record is ever created at an epoch end.
  UpgradeRecords none;
  advance_upgrade_records_at_epoch_end(cfg, vr, fallback_cp, &none);
  ASSERT_TRUE(none.empty());
}

// Step 5 (§3.5-3.6): what the handshake fingerprint covers, and what a binary must report as required.
TEST(test_upgrade_handshake_and_required_helpers) {
  Hash32 known_id{}, unknown_id{}, later_id{};
  known_id.fill(0x01);
  unknown_id.fill(0x02);
  later_id.fill(0x03);
  const std::vector<UpgradeDef> known{UpgradeDef{known_id, "known", 0}};
  UpgradeRecord active;
  active.state = UpgradeState::Active;
  active.activation_height = 100;
  UpgradeRecord locked;
  locked.state = UpgradeState::LockedIn;
  locked.activation_height = 200;
  UpgradeRecord signaling;
  signaling.state = UpgradeState::Signaling;
  UpgradeRecords records{{known_id, active}, {later_id, locked}, {unknown_id, signaling}};

  ASSERT_TRUE(implemented_active_upgrades(records, known, 99).empty());
  ASSERT_TRUE(implemented_active_upgrades(records, known, 100) == std::vector<Hash32>{known_id});
  ASSERT_TRUE(implemented_active_upgrades(records, {}, 100).empty());  // not implemented: not covered
  // Only locked-in or active upgrades the binary lacks are required; a signaling one is not yet.
  const auto required = unimplemented_locked_in_upgrades(records, known);
  ASSERT_EQ(required.size(), 1u);
  ASSERT_TRUE(required[0].id == later_id && required[0].activation_height == 200);
  ASSERT_TRUE(upgrade_required_from_height(records, known) == std::optional<std::uint64_t>(200));
  // Without any table both are required, earliest activation first.
  const auto all = unimplemented_locked_in_upgrades(records, {});
  ASSERT_EQ(all.size(), 2u);
  ASSERT_TRUE(all[0].id == known_id && all[1].id == later_id);
  ASSERT_TRUE(upgrade_required_from_height(records, {}) == std::optional<std::uint64_t>(100));
  records.erase(later_id);
  ASSERT_TRUE(!upgrade_required_from_height(records, known).has_value());
}

// §3.5: with no active upgrade the fingerprint is the one releases without signaled activation
// advertise, so they keep connecting; an active upgrade changes it, in any order.
TEST(test_rules_fingerprint_covers_active_upgrades_only_when_present) {
  const auto& net = mainnet_network();
  ChainId chain;
  chain.genesis_hash_hex = std::string(64, 'a');
  Hash32 a{}, b{};
  a.fill(0x0A);
  b.fill(0x0B);
  const auto base = consensus_rules_fingerprint(net, chain, 7);
  ASSERT_EQ(consensus_rules_fingerprint(net, chain, 7, {}), base);
  ASSERT_TRUE(consensus_rules_fingerprint(net, chain, 7, {a}) != base);
  ASSERT_TRUE(consensus_rules_fingerprint(net, chain, 7, {a}) != consensus_rules_fingerprint(net, chain, 7, {b}));
  ASSERT_EQ(consensus_rules_fingerprint(net, chain, 7, {a, b}), consensus_rules_fingerprint(net, chain, 7, {b, a}));
  ASSERT_EQ(consensus_rules_fingerprint(net, chain, 7, {a, a}), consensus_rules_fingerprint(net, chain, 7, {a}));
}
