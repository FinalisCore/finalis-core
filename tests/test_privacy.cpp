// SPDX-License-Identifier: MIT

#include "test_framework.hpp"

#include "privacy/mint_client.hpp"

using namespace finalis;

TEST(test_mint_client_json_roundtrips) {
  privacy::MintDepositRegistrationRequest req;
  req.chain = "mainnet";
  req.deposit_txid.fill(0x11);
  req.deposit_vout = 3;
  req.mint_id.fill(0x22);
  req.recipient_pubkey_hash.fill(0x33);
  req.amount = 42'000;

  const auto json = privacy::to_json(req);
  ASSERT_TRUE(json.find("\"deposit_vout\":3") != std::string::npos);
  ASSERT_TRUE(json.find("\"amount\":42000") != std::string::npos);

  privacy::MintRedemptionRequest redeem_req;
  redeem_req.notes = {"note-1", "note-2"};
  redeem_req.redeem_address = "sc1example";
  redeem_req.amount = 1234;
  const auto redeem_json = privacy::to_json(redeem_req);
  ASSERT_TRUE(redeem_json.find("\"amount\":1234") != std::string::npos);

  const auto dep_resp = privacy::parse_mint_deposit_registration_response(
      "{\"accepted\":true,\"finalization_depth_required\":2,\"confirmations_required\":2,\"mint_deposit_ref\":\"ref-1\"}");
  ASSERT_TRUE(dep_resp.has_value());
  ASSERT_TRUE(dep_resp->accepted);
  ASSERT_EQ(dep_resp->finalization_depth_required, 2u);
  ASSERT_EQ(dep_resp->confirmations_required, 2u);
  ASSERT_EQ(dep_resp->mint_deposit_ref, "ref-1");

  const auto dep_resp_legacy = privacy::parse_mint_deposit_registration_response(
      "{\"accepted\":true,\"confirmations_required\":3,\"mint_deposit_ref\":\"ref-legacy\"}");
  ASSERT_TRUE(dep_resp_legacy.has_value());
  ASSERT_EQ(dep_resp_legacy->finalization_depth_required, 3u);
  ASSERT_EQ(dep_resp_legacy->confirmations_required, 3u);
  ASSERT_EQ(dep_resp_legacy->mint_deposit_ref, "ref-legacy");

  const auto issue_resp =
      privacy::parse_mint_blind_issue_response(
          "{\"issuance_id\":\"iss-1\",\"signed_blinds\":[\"aa\",\"bb\"],\"note_refs\":[\"n1\",\"n2\"],"
          "\"note_amounts\":[20000,22000],\"mint_epoch\":7}");
  ASSERT_TRUE(issue_resp.has_value());
  ASSERT_EQ(issue_resp->issuance_id, "iss-1");
  ASSERT_EQ(issue_resp->signed_blinds.size(), 2u);
  ASSERT_EQ(issue_resp->note_refs.size(), 2u);
  ASSERT_EQ(issue_resp->note_amounts.size(), 2u);
  ASSERT_EQ(issue_resp->note_amounts[0], 20'000u);
  ASSERT_EQ(issue_resp->mint_epoch, 7u);

  const auto redeem_resp =
      privacy::parse_mint_redemption_response("{\"accepted\":false,\"redemption_batch_id\":\"batch-9\"}");
  ASSERT_TRUE(redeem_resp.has_value());
  ASSERT_TRUE(!redeem_resp->accepted);
  ASSERT_EQ(redeem_resp->redemption_batch_id, "batch-9");

  const auto status_resp =
      privacy::parse_mint_redemption_status_response(
          "{\"state\":\"finalized\",\"l1_txid\":\"deadbeef\",\"amount\":1234}");
  ASSERT_TRUE(status_resp.has_value());
  ASSERT_EQ(status_resp->state, "finalized");
  ASSERT_EQ(status_resp->l1_txid, "deadbeef");
  ASSERT_EQ(status_resp->amount, 1234u);
}

void register_privacy_tests() {}
