// SPDX-License-Identifier: MIT

#pragma once

// Signaled activation of consensus upgrades (docs/spec/SIGNALED_ACTIVATION.md).
// Pure functions over finalized inputs: no storage, clocks or peer state.

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "common/network.hpp"
#include "common/types.hpp"
#include "consensus/validator_registry.hpp"

namespace finalis::consensus {

// Lock-in at the end of epoch L activates the upgrade at the start of epoch L + this.
inline constexpr std::uint64_t kUpgradeActivationDelayEpochs = 2;

// Known to the binary. Signals count only inside [signal_start, signal_timeout) until lock-in.
struct UpgradeDef {
  Hash32 id{};
  std::string name;
  std::uint64_t signal_start{0};
  std::uint64_t signal_timeout{0};
};

enum class UpgradeState : std::uint8_t {
  Defined = 0,
  Signaling = 1,
  LockedIn = 2,
  Active = 3,
  Failed = 4,
};

// Finalized per-upgrade state (UPG: rows). signalers are operator ids.
struct UpgradeRecord {
  UpgradeState state{UpgradeState::Defined};
  std::set<PubKey32> signalers;
  std::uint64_t lock_in_height{0};     // epoch end height L at which it locked in
  std::uint64_t activation_height{0};  // first height under the new rules
  bool operator==(const UpgradeRecord&) const = default;
};

// H("FINALIS-UPGRADE-V1" || name || new_rules_fingerprint).
Hash32 upgrade_id(const std::string& name, const Hash32& new_rules_fingerprint);

enum class UpgradeSignalReject : std::uint8_t {
  None = 0,
  Failed,            // upgrade timed out
  BeforeWindow,      // height < signal_start
  AfterTimeout,      // not locked in and height >= signal_timeout
  NotActiveOperator,
  Duplicate,
};
const char* upgrade_signal_reject_name(UpgradeSignalReject r);

// Admissibility of a signal at `height`, signature already checked. After lock-in signals stay
// valid with no deadline: a late operator signals to become committee-eligible again.
UpgradeSignalReject check_upgrade_signal(const UpgradeDef& def, const UpgradeRecord& rec, const PubKey32& operator_id,
                                         bool is_active_operator, std::uint64_t height);

// ceil(2n/3); 0 for n = 0.
std::size_t upgrade_operator_threshold(std::size_t active_operators);

struct UpgradeLockInInputs {
  std::set<PubKey32> active_operators;
  // Operator ids of committee(L+1), derived at the same epoch boundary; one entry per seat.
  std::vector<PubKey32> next_committee_operators;
  // Minimum eligible operators committee derivation needs; signalers must reach it too.
  std::size_t min_eligible_operators{0};
};

bool upgrade_lock_in_reached(const UpgradeRecord& rec, const UpgradeLockInInputs& in);

// Advances `rec` at the end of an epoch (epoch_end_height is a multiple of epoch_blocks). Lock-in is
// checked before timeout at the same boundary.
void advance_upgrade_at_epoch_end(const UpgradeDef& def, UpgradeRecord* rec, std::uint64_t epoch_end_height,
                                  std::uint64_t epoch_blocks, const UpgradeLockInInputs& in);

// True from activation_height on, once locked in.
bool upgrade_active(const UpgradeRecord& rec, std::uint64_t height);

// Committee eligibility for the epoch starting at epoch_start_height: an operator must have signaled
// every upgrade active at that height.
bool operator_eligible_under_upgrades(const std::vector<UpgradeRecord>& records, const PubKey32& operator_id,
                                      std::uint64_t epoch_start_height);

using UpgradeRecords = std::map<Hash32, UpgradeRecord>;
// Same rule over the recorded state. Null means no upgrade state (always eligible).
bool operator_eligible_under_upgrades(const UpgradeRecords* records, const PubKey32& operator_id,
                                      std::uint64_t epoch_start_height);

// Upgrades this binary knows for `network`. Empty until the first consensus change ships signaled.
std::vector<UpgradeDef> known_upgrades(const NetworkConfig& network);

// Empty when the SCUPGSIG of `validator_pubkey` for `upgrade_id` is admissible at `height`, else why
// not: unknown upgrade, not an active validator, or a check_upgrade_signal reject. The signal counts
// for the validator's canonical operator.
std::string upgrade_signal_admission_error(const std::vector<UpgradeDef>& defs, const UpgradeRecords& records,
                                           const ValidatorRegistry& validators, std::uint64_t height,
                                           const PubKey32& validator_pubkey, const Hash32& upgrade_id);
// Records an admissible signal; returns whether it changed `records`.
bool apply_upgrade_signal(const std::vector<UpgradeDef>& defs, const ValidatorRegistry& validators, std::uint64_t height,
                          const PubKey32& validator_pubkey, const Hash32& upgrade_id, UpgradeRecords* records);

// Committed root over all records (sorted by id).
Hash32 upgrade_records_commitment_root(const UpgradeRecords& records);
Bytes serialize_upgrade_record(const UpgradeRecord& record);
std::optional<UpgradeRecord> parse_upgrade_record(const Bytes& bytes);

}  // namespace finalis::consensus
