// SPDX-License-Identifier: MIT

#pragma once

#include <optional>
#include <string>
#include <vector>

#include "common/types.hpp"

namespace finalis::privacy {

struct MintDepositRegistrationRequest {
  std::string chain{"mainnet"};
  Hash32 deposit_txid{};
  std::uint32_t deposit_vout{0};
  Hash32 mint_id{};
  std::array<std::uint8_t, 20> recipient_pubkey_hash{};
  std::uint64_t amount{0};
};

struct MintDepositRegistrationResponse {
  bool accepted{false};
  std::uint64_t finalization_depth_required{0};
  // Legacy compatibility mirror for older mint responses.
  std::uint64_t confirmations_required{0};
  std::string mint_deposit_ref;
};

struct MintBlindIssueRequest {
  std::string mint_deposit_ref;
  std::vector<std::string> blinded_messages;
  std::vector<std::uint64_t> note_amounts;
};

struct MintBlindIssueResponse {
  std::string issuance_id;
  std::vector<std::string> signed_blinds;
  std::vector<std::string> note_refs;
  std::vector<std::uint64_t> note_amounts;
  std::uint64_t mint_epoch{0};
};

struct MintRedemptionRequest {
  std::vector<std::string> notes;
  std::string redeem_address;
  std::uint64_t amount{0};
};

struct MintRedemptionResponse {
  bool accepted{false};
  std::string redemption_batch_id;
};

struct MintRedemptionStatusResponse {
  std::string state;
  std::string l1_txid;
  std::uint64_t amount{0};
};

std::string to_json(const MintDepositRegistrationRequest& req);
std::string to_json(const MintBlindIssueRequest& req);
std::string to_json(const MintRedemptionRequest& req);

std::optional<MintDepositRegistrationResponse> parse_mint_deposit_registration_response(const std::string& json);
std::optional<MintBlindIssueResponse> parse_mint_blind_issue_response(const std::string& json);
std::optional<MintRedemptionResponse> parse_mint_redemption_response(const std::string& json);
std::optional<MintRedemptionStatusResponse> parse_mint_redemption_status_response(const std::string& json);

}  // namespace finalis::privacy
