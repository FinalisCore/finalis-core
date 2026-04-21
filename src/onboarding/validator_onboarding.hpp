// SPDX-License-Identifier: MIT

#pragma once

#include <optional>
#include <set>
#include <string>
#include <vector>

#include "common/network.hpp"
#include "common/types.hpp"
#include "consensus/validator_registry.hpp"
#include "storage/db.hpp"
#include "wallet/utxo_selection.hpp"

namespace finalis::onboarding {

enum class ValidatorOnboardingBroadcastOutcome : std::uint8_t {
  NONE = 0,
  SENT = 1,
  REJECTED = 2,
  AMBIGUOUS = 3,
};

enum class ValidatorOnboardingState : std::uint8_t {
  IDLE = 0,
  CHECKING_PREREQS = 1,
  WAITING_FOR_SYNC = 2,
  WAITING_FOR_FUNDS = 3,
  SELECTING_UTXOS = 4,
  BUILDING_JOIN_TX = 5,
  BROADCASTING_JOIN_TX = 6,
  WAITING_FOR_FINALIZATION = 7,
  PENDING_ACTIVATION = 8,
  ACTIVE = 9,
  FAILED = 10,
  CANCELLED = 11,
};

struct ReservedInput {
  OutPoint outpoint;
  std::uint64_t amount{0};
};

struct ValidatorOnboardingRecord {
  std::string onboarding_id;
  PubKey32 validator_pubkey{};
  std::string wallet_address;
  std::string wallet_pubkey_hex;
  ValidatorOnboardingState state{ValidatorOnboardingState::IDLE};
  std::uint64_t requested_at_unix_ms{0};
  std::uint64_t updated_at_unix_ms{0};
  bool wait_for_sync{false};
  bool tracking_detached{false};
  std::uint64_t fee{0};
  std::uint64_t bond_amount{0};
  std::uint64_t eligibility_bond_amount{0};
  std::uint64_t required_amount{0};
  std::uint64_t last_spendable_balance{0};
  std::uint64_t last_deficit{0};
  storage::NodeRuntimeStatusSnapshot readiness{};
  std::vector<ReservedInput> selected_inputs;
  bool selected_inputs_reserved{false};
  std::string txid_hex;
  Bytes tx_bytes;
  std::uint64_t broadcast_attempted_at_unix_ms{0};
  ValidatorOnboardingBroadcastOutcome broadcast_outcome{ValidatorOnboardingBroadcastOutcome::NONE};
  std::string broadcast_result;
  std::string rpc_endpoint;
  std::uint64_t finalized_height{0};
  std::string validator_status;
  std::uint64_t activation_height{0};
  std::string last_error_code;
  std::string last_error_message;
};

struct ValidatorOnboardingOptions {
  std::string db_path;
  std::string key_file;
  std::string passphrase;
  std::string rpc_url;
  std::uint64_t fee{10'000};
  bool wait_for_sync{false};
};

std::string validator_onboarding_state_name(ValidatorOnboardingState state);
bool validator_onboarding_state_terminal(ValidatorOnboardingState state);
bool validator_onboarding_state_pre_broadcast(ValidatorOnboardingState state);
std::optional<std::string> infer_node_db_path_from_wallet_file(const std::string& wallet_file);

class ValidatorOnboardingService {
 public:
  std::optional<ValidatorOnboardingRecord> start_or_resume(const ValidatorOnboardingOptions& options,
                                                           std::string* err = nullptr) const;
  std::optional<ValidatorOnboardingRecord> poll(const ValidatorOnboardingOptions& options, std::string* err = nullptr) const;
  std::optional<ValidatorOnboardingRecord> status(const ValidatorOnboardingOptions& options, std::string* err = nullptr) const;
  bool cancel(const ValidatorOnboardingOptions& options, std::string* err = nullptr) const;

  static std::optional<ValidatorOnboardingRecord> parse_record(const Bytes& bytes);
  static Bytes serialize_record(const ValidatorOnboardingRecord& record);
  static std::set<OutPoint> reserved_outpoints(const storage::DB& db, const PubKey32& owner_pubkey);

 private:
  std::optional<ValidatorOnboardingRecord> advance(const ValidatorOnboardingOptions& options, storage::DB& db,
                                                   ValidatorOnboardingRecord record, std::string* err) const;
};

}  // namespace finalis::onboarding
