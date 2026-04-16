#include "consensus/validator_registry.hpp"

#include <algorithm>
#include <limits>
namespace finalis::consensus {

PubKey32 canonical_operator_id(const PubKey32& validator_pubkey, const ValidatorInfo& info) {
  return info.operator_id == PubKey32{} ? validator_pubkey : info.operator_id;
}

PubKey32 canonical_operator_id_from_join_request(const PubKey32& payout_pubkey) { return payout_pubkey; }

void ValidatorRegistry::upsert(PubKey32 pub, ValidatorInfo info) { validators_[pub] = info; }

bool ValidatorRegistry::register_onboarding(const PubKey32& pub, std::uint64_t joined_height, std::string* err,
                                            const std::optional<PubKey32>& operator_id) {
  const auto it = validators_.find(pub);
  if (it != validators_.end()) {
    const auto& v = it->second;
    if (v.status == ValidatorStatus::BANNED) {
      if (err) *err = "validator banned";
      return false;
    }
    if (err) *err = "validator already registered";
    return false;
  }

  auto& v = validators_[pub];
  v.status = ValidatorStatus::ONBOARDING;
  v.joined_height = joined_height;
  v.operator_id = operator_id.value_or(pub);
  v.has_bond = false;
  v.bond_outpoint = OutPoint{};
  v.bonded_amount = 0;
  v.unbond_height = 0;
  v.suspended_until_height = 0;
  v.last_join_height = joined_height;
  return true;
}

bool ValidatorRegistry::can_register_bond(const PubKey32& pub, std::uint64_t height, std::uint64_t bond_amount,
                                          std::string* err) const {
  if (bond_amount < rules_.min_bond) {
    if (err) *err = "bond below min";
    return false;
  }
  const auto it = validators_.find(pub);
  if (it == validators_.end()) return true;
  const auto& v = it->second;
  if (v.status == ValidatorStatus::BANNED) {
    if (err) *err = "validator banned";
    return false;
  }
  if (v.status == ValidatorStatus::ACTIVE || v.status == ValidatorStatus::PENDING || v.status == ValidatorStatus::SUSPENDED) {
    if (err) *err = "validator already registered";
    return false;
  }
  if (v.has_bond) {
    if (err) *err = "validator bond already active";
    return false;
  }
  if (rules_.cooldown_blocks > 0 && v.last_exit_height > 0) {
    if (v.last_exit_height > std::numeric_limits<std::uint64_t>::max() - rules_.cooldown_blocks) {
      if (err) *err = "validator cooldown overflow";
      return false;
    }
    if (height < v.last_exit_height + rules_.cooldown_blocks) {
      if (err) *err = "validator cooldown";
      return false;
    }
  }
  return true;
}

bool ValidatorRegistry::register_bond(const PubKey32& pub, const OutPoint& bond_outpoint, std::uint64_t joined_height) {
  auto& v = validators_[pub];
  v.status = ValidatorStatus::PENDING;
  v.joined_height = joined_height;
  v.bonded_amount = BOND_AMOUNT;
  v.operator_id = pub;
  v.has_bond = true;
  v.bond_outpoint = bond_outpoint;
  v.unbond_height = 0;
  v.last_join_height = joined_height;
  return true;
}

bool ValidatorRegistry::register_bond(const PubKey32& pub, const OutPoint& bond_outpoint, std::uint64_t joined_height,
                                      std::uint64_t bond_amount, std::string* err, const std::optional<PubKey32>& operator_id) {
  if (!can_register_bond(pub, joined_height, bond_amount, err)) return false;
  auto& v = validators_[pub];
  v.status = ValidatorStatus::PENDING;
  v.joined_height = joined_height;
  v.bonded_amount = bond_amount;
  v.operator_id = operator_id.value_or(pub);
  v.has_bond = true;
  v.bond_outpoint = bond_outpoint;
  v.unbond_height = 0;
  v.last_join_height = joined_height;
  if (v.liveness_window_start == 0) v.liveness_window_start = joined_height;
  return true;
}

bool ValidatorRegistry::request_unbond(const PubKey32& pub, std::uint64_t height) {
  auto it = validators_.find(pub);
  if (it == validators_.end()) return false;
  if (it->second.status == ValidatorStatus::BANNED) return false;
  if (!it->second.has_bond) return false;
  it->second.status = ValidatorStatus::EXITING;
  it->second.unbond_height = height;
  it->second.last_exit_height = height;
  return true;
}

void ValidatorRegistry::ban(const PubKey32& pub, std::uint64_t height) {
  auto it = validators_.find(pub);
  if (it != validators_.end()) {
    it->second.status = ValidatorStatus::BANNED;
    if (height != 0) it->second.unbond_height = std::max(it->second.unbond_height, height);
    it->second.last_exit_height = std::max(it->second.last_exit_height, std::max(height, it->second.unbond_height));
  }
}

bool ValidatorRegistry::finalize_withdrawal(const PubKey32& pub) {
  auto it = validators_.find(pub);
  if (it == validators_.end()) return false;
  it->second.has_bond = false;
  it->second.bond_outpoint = OutPoint{};
  return true;
}

bool ValidatorRegistry::can_withdraw_bond(const PubKey32& pub, std::uint64_t height, std::uint64_t delay_blocks) const {
  auto it = validators_.find(pub);
  if (it == validators_.end()) return false;
  const auto& info = it->second;
  if (!info.has_bond) return false;
  if (info.status == ValidatorStatus::BANNED) return false;
  if (info.status != ValidatorStatus::EXITING) return false;
  if (info.unbond_height == 0) return false;
  if (info.unbond_height > std::numeric_limits<std::uint64_t>::max() - delay_blocks) return false;
  return height >= info.unbond_height + delay_blocks;
}

void ValidatorRegistry::advance_height(std::uint64_t height) {
  for (auto& [_, info] : validators_) {
    if (info.status == ValidatorStatus::SUSPENDED && info.suspended_until_height > 0 && height >= info.suspended_until_height) {
      info.status = ValidatorStatus::ACTIVE;
      info.suspended_until_height = 0;
    }
    if (info.status == ValidatorStatus::PENDING && height >= info.joined_height + rules_.warmup_blocks) {
      info.status = ValidatorStatus::ACTIVE;
    }
  }
}

bool ValidatorRegistry::is_effectively_active(const ValidatorInfo& info, std::uint64_t height) const {
  if (!info.has_bond) return false;
  if (info.status == ValidatorStatus::BANNED || info.status == ValidatorStatus::EXITING ||
      info.status == ValidatorStatus::ONBOARDING) {
    return false;
  }
  if (info.status == ValidatorStatus::SUSPENDED) return false;
  if (info.suspended_until_height > height) return false;
  if (info.status == ValidatorStatus::ACTIVE) return true;
  return (info.status == ValidatorStatus::PENDING && height >= info.joined_height + rules_.warmup_blocks);
}

std::vector<PubKey32> ValidatorRegistry::active_sorted(std::uint64_t height) const {
  std::vector<PubKey32> out;
  for (const auto& [pub, info] : validators_) {
    if (is_effectively_active(info, height)) {
      out.push_back(pub);
    }
  }
  std::sort(out.begin(), out.end());
  return out;
}

bool ValidatorRegistry::is_active_for_height(const PubKey32& pub, std::uint64_t height) const {
  auto it = validators_.find(pub);
  if (it == validators_.end()) return false;
  return is_effectively_active(it->second, height);
}

std::optional<ValidatorInfo> ValidatorRegistry::get(const PubKey32& pub) const {
  auto it = validators_.find(pub);
  if (it == validators_.end()) return std::nullopt;
  return it->second;
}

std::optional<PubKey32> ValidatorRegistry::pubkey_by_bond_outpoint(const OutPoint& op) const {
  for (const auto& [pub, info] : validators_) {
    if (!info.has_bond) continue;
    if (info.bond_outpoint.txid == op.txid && info.bond_outpoint.index == op.index) return pub;
  }
  return std::nullopt;
}

std::size_t quorum_threshold(std::size_t n_active) { return (2 * n_active) / 3 + 1; }

bool validator_liveness_window_should_rollover(std::uint64_t height, std::uint64_t window_start_height,
                                               std::uint64_t window_blocks) {
  if (window_blocks == 0) return false;
  if (height + 1 < window_start_height + window_blocks) return false;
  return ((height + 1 - window_start_height) % window_blocks) == 0;
}

std::uint64_t validator_liveness_next_window_start(std::uint64_t height, std::uint64_t window_start_height,
                                                   std::uint64_t window_blocks) {
  if (window_blocks == 0) return window_start_height;
  if (height + 1 < window_start_height + window_blocks) return window_start_height;
  const std::uint64_t completed = (height + 1 - window_start_height) / window_blocks;
  return window_start_height + completed * window_blocks;
}

void advance_validator_join_window(std::uint64_t height, std::uint64_t window_blocks, std::uint64_t* window_start_height,
                                   std::uint32_t* window_count) {
  if (!window_start_height || !window_count) return;
  if (window_blocks == 0) return;
  if (height < *window_start_height + window_blocks) return;
  const std::uint64_t delta = height - *window_start_height;
  const std::uint64_t steps = delta / window_blocks;
  *window_start_height += steps * window_blocks;
  *window_count = 0;
}

}  // namespace finalis::consensus
