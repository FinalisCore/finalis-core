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

// At most this many upgrades an operator may be signaling that are not yet locked in. Bounds UPG:
// state at this many records per operator whatever ids are signaled.
inline constexpr std::size_t kMaxOpenUpgradeSignalsPerOperator = 2;

// Known to the binary: which rules it implements and, from signal_start on, signals for (policy, not
// consensus). Consensus never reads this table: every binary, whether it knows an upgrade or not,
// derives the same UPG: state (SIGNALED_ACTIVATION §3.6).
struct UpgradeDef {
  Hash32 id{};
  std::string name;
  std::uint64_t signal_start{0};
};

enum class UpgradeState : std::uint8_t {
  Defined = 0,
  Signaling = 1,
  LockedIn = 2,
  Active = 3,
  Failed = 4,
};

// Finalized per-upgrade state (UPG: rows), created by the first signal for an id. signalers are
// operator ids. Not locked in by first_signal_height + upgrade_signal_window_blocks: FAILED, and the
// record is removed at that epoch end (a later signal opens a new window).
struct UpgradeRecord {
  UpgradeState state{UpgradeState::Defined};
  std::uint64_t first_signal_height{0};
  std::set<PubKey32> signalers;
  std::uint64_t lock_in_height{0};     // epoch end height L at which it locked in
  std::uint64_t activation_height{0};  // first height under the new rules
  bool operator==(const UpgradeRecord&) const = default;
};

// H("FINALIS-UPGRADE-V1" || name || new_rules_fingerprint).
Hash32 upgrade_id(const std::string& name, const Hash32& new_rules_fingerprint);

enum class UpgradeSignalReject : std::uint8_t {
  None = 0,
  NotActiveOperator,
  Duplicate,
  TooManyOpen,  // the operator already signals kMaxOpenUpgradeSignalsPerOperator open upgrades
};
const char* upgrade_signal_reject_name(UpgradeSignalReject r);

// Admissibility of a signal, signature already checked. `rec` is the id's record, null if none yet;
// `open_signals` counts the operator's signals on records not locked in. A signal for a locked-in or
// active upgrade is always admissible: a late operator signals to become committee-eligible again.
UpgradeSignalReject check_upgrade_signal(const UpgradeRecord* rec, const PubKey32& operator_id, bool is_active_operator,
                                         std::size_t open_signals);

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
// checked before the window's end at the same boundary.
void advance_upgrade_at_epoch_end(UpgradeRecord* rec, std::uint64_t epoch_end_height, std::uint64_t epoch_blocks,
                                  std::uint64_t window_blocks, const UpgradeLockInInputs& in);

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
// Append-only: an id stays here for good once released. A binary missing a locked-in id reports
// upgrade_required and stops signing at its activation (unimplemented_locked_in_upgrades).
std::vector<UpgradeDef> known_upgrades(const NetworkConfig& network);

// Empty when the SCUPGSIG of `validator_pubkey` for `upgrade_id` is admissible at `height`, else the
// check_upgrade_signal reject. A function of finalized state only, never of the binary's upgrade table.
// The signal counts for the validator's canonical operator.
std::string upgrade_signal_admission_error(const UpgradeRecords& records, const ValidatorRegistry& validators,
                                           std::uint64_t height, const PubKey32& validator_pubkey,
                                           const Hash32& upgrade_id);
// Records an admissible signal (the first one for an id creates its record at `height`); returns
// whether it changed `records`.
bool apply_upgrade_signal(const ValidatorRegistry& validators, std::uint64_t height, const PubKey32& validator_pubkey,
                          const Hash32& upgrade_id, UpgradeRecords* records);

// Ids of the upgrades active at `height` that `known` implements, sorted: what this binary's
// handshake fingerprint covers (SIGNALED_ACTIVATION §3.5).
std::vector<Hash32> implemented_active_upgrades(const UpgradeRecords& records, const std::vector<UpgradeDef>& known,
                                                std::uint64_t height);

// A locked-in or active upgrade this binary does not implement (§3.6).
struct RequiredUpgrade {
  Hash32 id{};
  std::uint64_t activation_height{0};
};
// Earliest activation first; empty when the binary implements every locked-in upgrade.
std::vector<RequiredUpgrade> unimplemented_locked_in_upgrades(const UpgradeRecords& records,
                                                              const std::vector<UpgradeDef>& known);
// First height this binary cannot validate, if any: the earliest activation it does not implement.
std::optional<std::uint64_t> upgrade_required_from_height(const UpgradeRecords& records,
                                                          const std::vector<UpgradeDef>& known);

// Committed root over all records (sorted by id).
Hash32 upgrade_records_commitment_root(const UpgradeRecords& records);
Bytes serialize_upgrade_record(const UpgradeRecord& record);
std::optional<UpgradeRecord> parse_upgrade_record(const Bytes& bytes);

}  // namespace finalis::consensus
