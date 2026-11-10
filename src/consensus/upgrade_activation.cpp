// SPDX-License-Identifier: MIT

#include "consensus/upgrade_activation.hpp"

#include "codec/bytes.hpp"
#include "consensus/validator_registry.hpp"
#include "crypto/hash.hpp"

namespace finalis::consensus {

Hash32 upgrade_id(const std::string& name, const Hash32& new_rules_fingerprint) {
  codec::ByteWriter w;
  const std::string tag = "FINALIS-UPGRADE-V1";
  w.varbytes(Bytes(tag.begin(), tag.end()));
  w.varbytes(Bytes(name.begin(), name.end()));
  w.bytes_fixed(new_rules_fingerprint);
  return crypto::sha256(w.take());
}

const char* upgrade_signal_reject_name(UpgradeSignalReject r) {
  switch (r) {
    case UpgradeSignalReject::None: return "none";
    case UpgradeSignalReject::Failed: return "upgrade-failed";
    case UpgradeSignalReject::BeforeWindow: return "before-signal-window";
    case UpgradeSignalReject::AfterTimeout: return "after-signal-timeout";
    case UpgradeSignalReject::NotActiveOperator: return "not-active-operator";
    case UpgradeSignalReject::Duplicate: return "duplicate-signal";
  }
  return "unknown";
}

namespace {
bool locked_or_active(UpgradeState s) { return s == UpgradeState::LockedIn || s == UpgradeState::Active; }
}  // namespace

UpgradeSignalReject check_upgrade_signal(const UpgradeDef& def, const UpgradeRecord& rec, const PubKey32& operator_id,
                                         bool is_active_operator, std::uint64_t height) {
  if (rec.state == UpgradeState::Failed) return UpgradeSignalReject::Failed;
  if (height < def.signal_start) return UpgradeSignalReject::BeforeWindow;
  if (!locked_or_active(rec.state) && height >= def.signal_timeout) return UpgradeSignalReject::AfterTimeout;
  if (!is_active_operator) return UpgradeSignalReject::NotActiveOperator;
  if (rec.signalers.count(operator_id) != 0) return UpgradeSignalReject::Duplicate;
  return UpgradeSignalReject::None;
}

std::size_t upgrade_operator_threshold(std::size_t active_operators) { return (2 * active_operators + 2) / 3; }

bool upgrade_lock_in_reached(const UpgradeRecord& rec, const UpgradeLockInInputs& in) {
  if (in.active_operators.empty() || in.next_committee_operators.empty()) return false;
  std::size_t active_signalers = 0;
  for (const auto& op : in.active_operators) active_signalers += rec.signalers.count(op);
  if (active_signalers < upgrade_operator_threshold(in.active_operators.size())) return false;
  if (active_signalers < in.min_eligible_operators) return false;
  std::size_t ready_seats = 0;
  for (const auto& op : in.next_committee_operators) ready_seats += rec.signalers.count(op);
  return ready_seats >= quorum_threshold(in.next_committee_operators.size());
}

void advance_upgrade_at_epoch_end(const UpgradeDef& def, UpgradeRecord* rec, std::uint64_t epoch_end_height,
                                  std::uint64_t epoch_blocks, const UpgradeLockInInputs& in) {
  if (rec == nullptr || epoch_blocks == 0) return;
  const std::uint64_t next_height = epoch_end_height + 1;
  switch (rec->state) {
    case UpgradeState::Defined:
      if (next_height < def.signal_start) return;
      rec->state = UpgradeState::Signaling;
      [[fallthrough]];
    case UpgradeState::Signaling:
      if (upgrade_lock_in_reached(*rec, in)) {
        rec->state = UpgradeState::LockedIn;
        rec->lock_in_height = epoch_end_height;
        rec->activation_height = next_height + (kUpgradeActivationDelayEpochs - 1) * epoch_blocks;
      } else if (next_height >= def.signal_timeout) {
        rec->state = UpgradeState::Failed;
      }
      return;
    case UpgradeState::LockedIn:
      if (next_height >= rec->activation_height) rec->state = UpgradeState::Active;
      return;
    case UpgradeState::Active:
    case UpgradeState::Failed:
      return;
  }
}

bool upgrade_active(const UpgradeRecord& rec, std::uint64_t height) {
  return locked_or_active(rec.state) && height >= rec.activation_height;
}

bool operator_eligible_under_upgrades(const std::vector<UpgradeRecord>& records, const PubKey32& operator_id,
                                      std::uint64_t epoch_start_height) {
  for (const auto& rec : records) {
    if (upgrade_active(rec, epoch_start_height) && rec.signalers.count(operator_id) == 0) return false;
  }
  return true;
}

}  // namespace finalis::consensus
