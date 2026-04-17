#pragma once

#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "common/types.hpp"
#include "utxo/tx.hpp"

namespace finalis::consensus {

enum class ValidatorStatus : std::uint8_t {
  PENDING = 0,
  ACTIVE = 1,
  EXITING = 2,
  BANNED = 3,
  SUSPENDED = 4,
  ONBOARDING = 5,
};

struct ValidatorInfo {
  ValidatorStatus status{ValidatorStatus::PENDING};
  std::uint64_t joined_height{0};
  std::uint64_t bonded_amount{BOND_AMOUNT};
  PubKey32 operator_id{};
  bool has_bond{false};
  OutPoint bond_outpoint{};
  std::uint64_t unbond_height{0};
  std::uint64_t eligible_count_window{0};
  std::uint64_t participated_count_window{0};
  std::uint64_t liveness_window_start{0};
  std::uint64_t suspended_until_height{0};
  std::uint64_t last_join_height{0};
  std::uint64_t last_exit_height{0};
  std::uint32_t penalty_strikes{0};
};

struct ValidatorRules {
  std::uint64_t min_bond{BOND_AMOUNT};
  std::uint64_t warmup_blocks{WARMUP_BLOCKS};
  std::uint64_t cooldown_blocks{0};
};

class ValidatorRegistry {
 public:
  void set_rules(ValidatorRules rules) { rules_ = rules; }
  const ValidatorRules& rules() const { return rules_; }
  void upsert(PubKey32 pub, ValidatorInfo info);
  bool register_onboarding(const PubKey32& pub, std::uint64_t joined_height, std::string* err = nullptr,
                           const std::optional<PubKey32>& operator_id = std::nullopt);
  bool can_register_bond(const PubKey32& pub, std::uint64_t height, std::uint64_t bond_amount, std::string* err = nullptr) const;
  bool register_bond(const PubKey32& pub, const OutPoint& bond_outpoint, std::uint64_t joined_height);
  bool register_bond(const PubKey32& pub, const OutPoint& bond_outpoint, std::uint64_t joined_height, std::uint64_t bond_amount,
                     std::string* err = nullptr, const std::optional<PubKey32>& operator_id = std::nullopt);
  bool request_unbond(const PubKey32& pub, std::uint64_t height);
  void ban(const PubKey32& pub, std::uint64_t height = 0);
  bool finalize_withdrawal(const PubKey32& pub);
  bool can_withdraw_bond(const PubKey32& pub, std::uint64_t height, std::uint64_t delay_blocks) const;
  void advance_height(std::uint64_t height);

  std::vector<PubKey32> active_sorted(std::uint64_t height) const;
  bool is_active_for_height(const PubKey32& pub, std::uint64_t height) const;
  std::optional<ValidatorInfo> get(const PubKey32& pub) const;
  std::optional<PubKey32> pubkey_by_bond_outpoint(const OutPoint& op) const;
  std::map<PubKey32, ValidatorInfo>& mutable_all() { return validators_; }
  const std::map<PubKey32, ValidatorInfo>& all() const { return validators_; }

 private:
  bool is_effectively_active(const ValidatorInfo& info, std::uint64_t height) const;

  std::map<PubKey32, ValidatorInfo> validators_;
  ValidatorRules rules_{};
};

PubKey32 canonical_operator_id(const PubKey32& validator_pubkey, const ValidatorInfo& info);
PubKey32 canonical_operator_id_from_join_request(const PubKey32& payout_pubkey);

std::size_t quorum_threshold(std::size_t n_active);
bool validator_liveness_window_should_rollover(std::uint64_t height, std::uint64_t window_start_height,
                                               std::uint64_t window_blocks);
std::uint64_t validator_liveness_next_window_start(std::uint64_t height, std::uint64_t window_start_height,
                                                   std::uint64_t window_blocks);
void advance_validator_join_window(std::uint64_t height, std::uint64_t window_blocks, std::uint64_t* window_start_height,
                                   std::uint32_t* window_count);

}  // namespace finalis::consensus
