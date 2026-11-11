// SPDX-License-Identifier: MIT

#include "test_framework.hpp"

#include <set>
#include <vector>

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

UpgradeDef def() {
  Hash32 fp{};
  fp.fill(0xAB);
  return UpgradeDef{upgrade_id("test-upgrade", fp), "test-upgrade", 33, 33 + 10 * kB};
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
  const auto d = def();
  UpgradeRecord rec;
  ASSERT_TRUE(check_upgrade_signal(d, rec, op(1), true, 32) == UpgradeSignalReject::BeforeWindow);
  ASSERT_TRUE(check_upgrade_signal(d, rec, op(1), true, 33) == UpgradeSignalReject::None);
  ASSERT_TRUE(check_upgrade_signal(d, rec, op(1), false, 40) == UpgradeSignalReject::NotActiveOperator);
  ASSERT_TRUE(check_upgrade_signal(d, rec, op(1), true, d.signal_timeout) == UpgradeSignalReject::AfterTimeout);
  signal(&rec, {1});
  ASSERT_TRUE(check_upgrade_signal(d, rec, op(1), true, 40) == UpgradeSignalReject::Duplicate);
  // After lock-in a late operator may still signal, with no deadline.
  rec.state = UpgradeState::Active;
  ASSERT_TRUE(check_upgrade_signal(d, rec, op(2), true, d.signal_timeout + 1000) == UpgradeSignalReject::None);
  rec.state = UpgradeState::Failed;
  ASSERT_TRUE(check_upgrade_signal(d, rec, op(2), true, 40) == UpgradeSignalReject::Failed);
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
  const auto d = def();
  const auto in = inputs();
  UpgradeRecord rec;
  advance_upgrade_at_epoch_end(d, &rec, 0, kB, in);  // genesis boundary, before the window
  ASSERT_TRUE(rec.state == UpgradeState::Defined);
  advance_upgrade_at_epoch_end(d, &rec, kB, kB, in);  // next height 33 = signal_start
  ASSERT_TRUE(rec.state == UpgradeState::Signaling);

  signal(&rec, {1, 2, 3, 4, 5, 9});
  const std::uint64_t lock_end = 3 * kB;  // end of epoch L
  advance_upgrade_at_epoch_end(d, &rec, lock_end, kB, in);
  ASSERT_TRUE(rec.state == UpgradeState::LockedIn);
  ASSERT_EQ(rec.lock_in_height, lock_end);
  ASSERT_EQ(rec.activation_height, lock_end + 1 + kB);  // start of epoch L+2
  ASSERT_TRUE(!upgrade_active(rec, lock_end + kB));
  ASSERT_TRUE(upgrade_active(rec, lock_end + kB + 1));  // already true while LockedIn

  advance_upgrade_at_epoch_end(d, &rec, lock_end + kB, kB, in);  // end of L+1
  ASSERT_TRUE(rec.state == UpgradeState::Active);
  const auto active = rec;
  advance_upgrade_at_epoch_end(d, &rec, lock_end + 2 * kB, kB, UpgradeLockInInputs{});
  ASSERT_TRUE(rec == active);  // terminal
}

TEST(test_upgrade_fails_at_timeout_and_lock_in_wins_on_the_same_boundary) {
  const auto d = def();
  const auto in = inputs();
  UpgradeRecord rec;
  rec.state = UpgradeState::Signaling;
  signal(&rec, {1, 2, 3});
  const std::uint64_t last_end = d.signal_timeout - 1;  // next height == signal_timeout
  advance_upgrade_at_epoch_end(d, &rec, last_end - kB, kB, in);
  ASSERT_TRUE(rec.state == UpgradeState::Signaling);
  advance_upgrade_at_epoch_end(d, &rec, last_end, kB, in);
  ASSERT_TRUE(rec.state == UpgradeState::Failed);
  ASSERT_TRUE(!upgrade_active(rec, last_end + 10 * kB));

  UpgradeRecord late;
  late.state = UpgradeState::Signaling;
  signal(&late, {1, 2, 3, 4, 5, 9});
  advance_upgrade_at_epoch_end(d, &late, last_end, kB, in);
  ASSERT_TRUE(late.state == UpgradeState::LockedIn);
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

// Step 2b: finalized signals are admitted against upgrade state and recorded per operator.
TEST(test_upgrade_signal_admission_and_apply) {
  const auto d = def();
  const std::vector<UpgradeDef> defs{d};
  const auto vr = registry_with_active({op(1), op(2)}, op(9));
  UpgradeRecords records;
  Hash32 unknown{};
  unknown.fill(0xEE);
  ASSERT_EQ(upgrade_signal_admission_error(defs, records, vr, 40, op(1), unknown), std::string("unknown-upgrade"));
  ASSERT_EQ(upgrade_signal_admission_error({}, records, vr, 40, op(1), d.id), std::string("unknown-upgrade"));
  ASSERT_EQ(upgrade_signal_admission_error(defs, records, vr, 40, op(9), d.id), std::string("not-active-operator"));
  ASSERT_EQ(upgrade_signal_admission_error(defs, records, vr, 40, op(7), d.id), std::string("not-active-operator"));
  ASSERT_EQ(upgrade_signal_admission_error(defs, records, vr, 10, op(1), d.id), std::string("before-signal-window"));
  ASSERT_TRUE(upgrade_signal_admission_error(defs, records, vr, 40, op(1), d.id).empty());

  ASSERT_TRUE(apply_upgrade_signal(defs, vr, 40, op(1), d.id, &records));
  const auto operator1 = canonical_operator_id(op(1), *vr.get(op(1)));
  ASSERT_TRUE(records.at(d.id).signalers.count(operator1) == 1);
  ASSERT_EQ(upgrade_signal_admission_error(defs, records, vr, 41, op(1), d.id), std::string("duplicate-signal"));
  ASSERT_TRUE(!apply_upgrade_signal(defs, vr, 41, op(1), d.id, &records));  // a duplicate changes nothing
  ASSERT_TRUE(!apply_upgrade_signal(defs, vr, 41, op(9), d.id, &records));  // nor a non-operator
  ASSERT_EQ(records.at(d.id).signalers.size(), 1u);
}

TEST(test_upgrade_record_codec_and_commitment_root) {
  UpgradeRecord rec;
  rec.state = UpgradeState::LockedIn;
  rec.lock_in_height = 96;
  rec.activation_height = 129;
  rec.signalers = {op(3), op(1), op(2)};
  const auto bytes = serialize_upgrade_record(rec);
  const auto back = parse_upgrade_record(bytes);
  ASSERT_TRUE(back.has_value() && *back == rec);
  auto bad_state = bytes;
  bad_state[0] = 9;
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

// Step 3: the epoch-end inputs come from the registry and the checkpoint just derived for L+1, and
// only recorded upgrades the binary knows are advanced.
TEST(test_upgrade_records_advance_at_epoch_end_from_checkpoint_inputs) {
  CanonicalDerivationConfig cfg;
  cfg.network.committee_epoch_blocks = kB;
  const auto d = def();  // window [33, 353)
  cfg.upgrade_defs = {d};
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

  // 3 of 6 operators is below ceil(2/3 * 6) = 4: stays SIGNALING, then FAILED at the timeout.
  UpgradeRecord three = four;
  three.signalers.erase(id_of(4));
  UpgradeRecords short_records{{d.id, three}};
  advance_upgrade_records_at_epoch_end(cfg, vr, fallback_cp, &short_records);
  ASSERT_TRUE(short_records.at(d.id).state == UpgradeState::Signaling);
  auto at_timeout = fallback_cp;
  at_timeout.epoch_start_height = 11 * kB + 1;  // 353 >= signal_timeout
  advance_upgrade_records_at_epoch_end(cfg, vr, at_timeout, &short_records);
  ASSERT_TRUE(short_records.at(d.id).state == UpgradeState::Failed);

  // A record for an upgrade this binary does not know is left as is; none is ever created.
  auto unknown_cfg = cfg;
  unknown_cfg.upgrade_defs.clear();
  UpgradeRecords untouched{{d.id, four}};
  advance_upgrade_records_at_epoch_end(unknown_cfg, vr, fallback_cp, &untouched);
  ASSERT_TRUE(untouched.at(d.id) == four);
  UpgradeRecords none;
  advance_upgrade_records_at_epoch_end(cfg, vr, fallback_cp, &none);
  ASSERT_TRUE(none.empty());
}
