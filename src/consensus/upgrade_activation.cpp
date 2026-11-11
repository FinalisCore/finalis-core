// SPDX-License-Identifier: MIT

#include "consensus/upgrade_activation.hpp"

#include <algorithm>

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

std::vector<UpgradeDef> known_upgrades(const NetworkConfig& network) {
  (void)network;
  return {};
}

namespace {
std::optional<PubKey32> active_operator_of(const ValidatorRegistry& validators, std::uint64_t height,
                                           const PubKey32& validator_pubkey) {
  if (!validators.is_active_for_height(validator_pubkey, height)) return std::nullopt;
  const auto it = validators.all().find(validator_pubkey);
  if (it == validators.all().end()) return std::nullopt;
  return canonical_operator_id(validator_pubkey, it->second);
}
}  // namespace

std::string upgrade_signal_admission_error(const std::vector<UpgradeDef>& defs, const UpgradeRecords& records,
                                           const ValidatorRegistry& validators, std::uint64_t height,
                                           const PubKey32& validator_pubkey, const Hash32& upgrade_id) {
  const auto def = std::find_if(defs.begin(), defs.end(), [&](const UpgradeDef& d) { return d.id == upgrade_id; });
  if (def == defs.end()) return "unknown-upgrade";
  const auto op = active_operator_of(validators, height, validator_pubkey);
  const auto rec_it = records.find(upgrade_id);
  const UpgradeRecord empty;
  const auto& rec = rec_it == records.end() ? empty : rec_it->second;
  const auto reject = check_upgrade_signal(*def, rec, op.value_or(validator_pubkey), op.has_value(), height);
  return reject == UpgradeSignalReject::None ? std::string{} : std::string(upgrade_signal_reject_name(reject));
}

bool apply_upgrade_signal(const std::vector<UpgradeDef>& defs, const ValidatorRegistry& validators, std::uint64_t height,
                          const PubKey32& validator_pubkey, const Hash32& upgrade_id, UpgradeRecords* records) {
  if (records == nullptr) return false;
  if (!upgrade_signal_admission_error(defs, *records, validators, height, validator_pubkey, upgrade_id).empty()) {
    return false;
  }
  const auto op = active_operator_of(validators, height, validator_pubkey);
  return op.has_value() && (*records)[upgrade_id].signalers.insert(*op).second;
}

Bytes serialize_upgrade_record(const UpgradeRecord& record) {
  codec::ByteWriter w;
  w.u8(static_cast<std::uint8_t>(record.state));
  w.u64le(record.lock_in_height);
  w.u64le(record.activation_height);
  w.varint(record.signalers.size());
  for (const auto& op : record.signalers) w.bytes_fixed(op);
  return w.take();
}

std::optional<UpgradeRecord> parse_upgrade_record(const Bytes& bytes) {
  UpgradeRecord rec;
  if (!codec::parse_exact(bytes, [&](codec::ByteReader& r) {
        auto state = r.u8();
        auto lock_in = r.u64le();
        auto activation = r.u64le();
        auto count = r.varint();
        if (!state || !lock_in || !activation || !count) return false;
        if (*state > static_cast<std::uint8_t>(UpgradeState::Failed) || *count > 1'000'000) return false;
        rec.state = static_cast<UpgradeState>(*state);
        rec.lock_in_height = *lock_in;
        rec.activation_height = *activation;
        std::optional<PubKey32> last;
        for (std::uint64_t i = 0; i < *count; ++i) {
          auto op = r.bytes_fixed<32>();
          if (!op) return false;
          if (last.has_value() && !(*last < *op)) return false;  // canonical: strictly sorted
          last = *op;
          rec.signalers.insert(*op);
        }
        return true;
      })) {
    return std::nullopt;
  }
  return rec;
}

Hash32 upgrade_records_commitment_root(const UpgradeRecords& records) {
  codec::ByteWriter w;
  const std::string tag = "FINALIS-UPGRADE-RECORDS-V1";
  w.varbytes(Bytes(tag.begin(), tag.end()));
  w.varint(records.size());
  for (const auto& [id, rec] : records) {
    w.bytes_fixed(id);
    w.varbytes(serialize_upgrade_record(rec));
  }
  return crypto::sha256d(w.take());
}

}  // namespace finalis::consensus
