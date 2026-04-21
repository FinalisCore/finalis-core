// SPDX-License-Identifier: MIT

#include "test_framework.hpp"

#include <algorithm>
#include <set>

#include "common/address.hpp"
#include "apps/finalis-wallet/history_merge.hpp"
#include "apps/finalis-wallet/refresh_gate.hpp"
#include "consensus/monetary.hpp"
#include "crypto/confidential.hpp"
#include "crypto/ed25519.hpp"
#include "crypto/hash.hpp"
#include "wallet/confidential_builder.hpp"
#include "utxo/signing.hpp"
#include "utxo/validate.hpp"

using namespace finalis;

namespace {

crypto::KeyPair key_from_byte(std::uint8_t b) {
  std::array<std::uint8_t, 32> seed{};
  seed.fill(b);
  auto kp = crypto::keypair_from_seed32(seed);
  if (!kp.has_value()) throw std::runtime_error("key generation failed");
  return *kp;
}

std::pair<OutPoint, TxOut> make_prev(std::uint8_t tag, std::uint32_t index, std::uint64_t value, const PubKey32& pubkey) {
  Hash32 txid{};
  txid.fill(tag);
  const auto pkh = crypto::h160(Bytes(pubkey.begin(), pubkey.end()));
  return {OutPoint{txid, index}, TxOut{value, address::p2pkh_script_pubkey(pkh)}};
}

PubKey33 compressed_key(std::uint8_t seed) {
  Hash32 scalar{};
  scalar.fill(seed);
  auto pub = crypto::secp256k1_pubkey_from_scalar(scalar);
  if (!pub.has_value()) throw std::runtime_error("compressed key derivation failed");
  return *pub;
}

crypto::Blind32 blind_from_byte(std::uint8_t seed) {
  crypto::Blind32 out;
  out.bytes.fill(seed);
  return out;
}

Hash32 nonce_from_byte(std::uint8_t seed) {
  Hash32 out{};
  out.fill(seed);
  return out;
}

}  // namespace

TEST(test_wallet_send_policy_uses_deterministic_largest_first_selection) {
  const auto kp = key_from_byte(0x11);
  std::vector<std::pair<OutPoint, TxOut>> available{
      make_prev(0x03, 0, 400, kp.public_key),
      make_prev(0x01, 2, 900, kp.public_key),
      make_prev(0x01, 1, 900, kp.public_key),
      make_prev(0x02, 0, 700, kp.public_key),
  };

  const auto sorted = deterministic_largest_first_prevs(available);
  ASSERT_EQ(sorted.size(), 4u);
  ASSERT_EQ(sorted[0].second.value, 900u);
  ASSERT_EQ(sorted[0].first.index, 1u);
  ASSERT_EQ(sorted[1].second.value, 900u);
  ASSERT_EQ(sorted[1].first.index, 2u);
  ASSERT_EQ(sorted[2].second.value, 700u);
  ASSERT_EQ(sorted[3].second.value, 400u);
}

TEST(test_wallet_send_policy_folds_dust_change_into_fee) {
  const auto sender = key_from_byte(0x12);
  const auto recipient = key_from_byte(0x22);
  std::vector<std::pair<OutPoint, TxOut>> available{
      make_prev(0x0A, 0, 1'001'500, sender.public_key),
  };

  std::string err;
  auto plan = plan_wallet_p2pkh_send(
      available, address::p2pkh_script_pubkey(crypto::h160(Bytes(recipient.public_key.begin(), recipient.public_key.end()))),
      address::p2pkh_script_pubkey(crypto::h160(Bytes(sender.public_key.begin(), sender.public_key.end()))), 1'000'000,
      DEFAULT_WALLET_SEND_FEE_UNITS, DEFAULT_WALLET_DUST_THRESHOLD_UNITS, &err);
  ASSERT_TRUE(plan.has_value());
  ASSERT_EQ(plan->selected_prevs.size(), 1u);
  ASSERT_EQ(plan->change_units, 0u);
  ASSERT_EQ(plan->applied_fee_units, 1'500u);
  ASSERT_EQ(plan->outputs.size(), 1u);
}

TEST(test_wallet_send_policy_creates_change_above_dust_threshold) {
  const auto sender = key_from_byte(0x13);
  const auto recipient = key_from_byte(0x23);
  std::vector<std::pair<OutPoint, TxOut>> available{
      make_prev(0x0B, 0, 1'001'547, sender.public_key),
  };

  std::string err;
  auto plan = plan_wallet_p2pkh_send(
      available, address::p2pkh_script_pubkey(crypto::h160(Bytes(recipient.public_key.begin(), recipient.public_key.end()))),
      address::p2pkh_script_pubkey(crypto::h160(Bytes(sender.public_key.begin(), sender.public_key.end()))), 1'000'000,
      DEFAULT_WALLET_SEND_FEE_UNITS, DEFAULT_WALLET_DUST_THRESHOLD_UNITS, &err);
  ASSERT_TRUE(plan.has_value());
  ASSERT_EQ(plan->change_units, 547u);
  ASSERT_EQ(plan->applied_fee_units, DEFAULT_WALLET_SEND_FEE_UNITS);
  ASSERT_EQ(plan->outputs.size(), 2u);
  ASSERT_EQ(plan->outputs[1].value, 547u);
}

TEST(test_wallet_send_policy_handles_under_exact_and_over_one_coin_without_boundary_bug) {
  const auto sender = key_from_byte(0x14);
  const auto recipient = key_from_byte(0x24);
  std::vector<std::pair<OutPoint, TxOut>> available{
      make_prev(0x10, 0, 2 * consensus::BASE_UNITS_PER_COIN, sender.public_key),
  };
  const Bytes recipient_spk =
      address::p2pkh_script_pubkey(crypto::h160(Bytes(recipient.public_key.begin(), recipient.public_key.end())));
  const Bytes change_spk =
      address::p2pkh_script_pubkey(crypto::h160(Bytes(sender.public_key.begin(), sender.public_key.end())));

  for (std::uint64_t amount : {consensus::BASE_UNITS_PER_COIN - 1, consensus::BASE_UNITS_PER_COIN,
                               consensus::BASE_UNITS_PER_COIN + 1}) {
    std::string err;
    auto plan = plan_wallet_p2pkh_send(available, recipient_spk, change_spk, amount, DEFAULT_WALLET_SEND_FEE_UNITS,
                                       DEFAULT_WALLET_DUST_THRESHOLD_UNITS, &err);
    ASSERT_TRUE(plan.has_value());
    ASSERT_EQ(plan->amount_units, amount);
    ASSERT_EQ(plan->outputs.front().value, amount);
  }
}

TEST(test_wallet_send_policy_rejects_reuse_of_reserved_confirmed_inputs) {
  const auto sender = key_from_byte(0x31);
  const auto recipient = key_from_byte(0x41);
  const auto prev = make_prev(0x55, 0, 2 * consensus::BASE_UNITS_PER_COIN, sender.public_key);
  std::vector<std::pair<OutPoint, TxOut>> available{prev};
  std::set<OutPoint> reserved{prev.first};
  std::vector<std::pair<OutPoint, TxOut>> filtered;
  for (const auto& candidate : available) {
    if (reserved.find(candidate.first) == reserved.end()) filtered.push_back(candidate);
  }

  std::string err;
  auto plan = plan_wallet_p2pkh_send(
      filtered, address::p2pkh_script_pubkey(crypto::h160(Bytes(recipient.public_key.begin(), recipient.public_key.end()))),
      address::p2pkh_script_pubkey(crypto::h160(Bytes(sender.public_key.begin(), sender.public_key.end()))),
      consensus::BASE_UNITS_PER_COIN, DEFAULT_WALLET_SEND_FEE_UNITS, DEFAULT_WALLET_DUST_THRESHOLD_UNITS, &err);
  ASSERT_TRUE(!plan.has_value());
  ASSERT_EQ(err, "insufficient finalized funds");
}

TEST(test_wallet_history_merge_finalized_wins_over_pending_for_same_txid) {
  using ChainRecord = finalis::wallet::ChainRecordView;
  const std::string txid = "tx-1";
  const auto merged = finalis::wallet::merge_chain_records_for_display({
      ChainRecord{"PENDING", "SENT", "awaiting finalization", txid, "pending", txid, "pending details"},
      ChainRecord{"FINALIZED", "SENT", "1.00000000 FLS", txid, "42", txid, "finalized details"},
  });

  ASSERT_EQ(merged.size(), 1u);
  ASSERT_EQ(merged[0].txid, txid);
  ASSERT_EQ(merged[0].status, "FINALIZED");
  ASSERT_EQ(merged[0].height, "42");
}

TEST(test_wallet_history_merge_keeps_stable_order_and_deduplicates_by_txid) {
  using ChainRecord = finalis::wallet::ChainRecordView;
  const auto merged = finalis::wallet::merge_chain_records_for_display({
      ChainRecord{"FINALIZED", "RECEIVED", "2.00000000 FLS", "tx-a", "10", "tx-a", "a"},
      ChainRecord{"PENDING", "SENT", "awaiting finalization", "tx-b", "pending", "tx-b", "b-pending"},
      ChainRecord{"FINALIZED", "SENT", "1.00000000 FLS", "tx-b", "11", "tx-b", "b-final"},
      ChainRecord{"PENDING", "SENT", "awaiting finalization", "tx-c", "pending", "tx-c", "c-pending"},
  });

  ASSERT_EQ(merged.size(), 3u);
  ASSERT_EQ(merged[0].txid, "tx-a");
  ASSERT_EQ(merged[1].txid, "tx-b");
  ASSERT_EQ(merged[1].status, "FINALIZED");
  ASSERT_EQ(merged[2].txid, "tx-c");

  const auto merged_again = finalis::wallet::merge_chain_records_for_display(merged);
  ASSERT_EQ(merged_again.size(), 3u);
  ASSERT_EQ(merged_again[0].txid, "tx-a");
  ASSERT_EQ(merged_again[1].txid, "tx-b");
  ASSERT_EQ(merged_again[2].txid, "tx-c");
}

TEST(test_wallet_refresh_gate_rejects_stale_generation_or_state_version) {
  ASSERT_TRUE(finalis::wallet::should_apply_refresh_result(7, 7, 3, 3));
  ASSERT_TRUE(!finalis::wallet::should_apply_refresh_result(6, 7, 3, 3));
  ASSERT_TRUE(!finalis::wallet::should_apply_refresh_result(7, 7, 2, 3));
  ASSERT_TRUE(!finalis::wallet::should_keep_refresh_indicator(7, 7));
  ASSERT_TRUE(finalis::wallet::should_keep_refresh_indicator(6, 7));
}

TEST(test_wallet_confidential_builder_creates_valid_transparent_to_confidential_txv2) {
  const auto sender = key_from_byte(0x51);
  const auto prev = make_prev(0x70, 0, 10'000, sender.public_key);
  const auto recipient = finalis::wallet::ConfidentialRecipient{
      .one_time_pubkey = compressed_key(0x61),
      .ephemeral_pubkey = compressed_key(0x62),
      .scan_tag = crypto::ScanTag{0x63},
      .memo = Bytes{0xAA, 0xBB},
  };
  const auto secrets = crypto::ConfidentialOutputSecrets{
      .amount = 9'000,
      .value_blind = blind_from_byte(0x64),
  };
  std::string err;
  auto confidential_out = finalis::wallet::build_confidential_output(recipient, secrets, nonce_from_byte(0x65), &err);
  ASSERT_TRUE(confidential_out.has_value());

  auto tx = finalis::wallet::build_txv2_transparent_to_confidential(
      prev.first, prev.second, Bytes(sender.private_key.begin(), sender.private_key.end()), prev.second.value, std::nullopt,
      *confidential_out, secrets.value_blind, secrets.amount, 1'000, &err);
  ASSERT_TRUE(tx.has_value());

  UtxoSetV2 view;
  view[prev.first] = UtxoEntryV2{prev.second};
  ConfidentialPolicy policy;
  policy.activation_height = 0;
  SpecialValidationContext ctx;
  ctx.current_height = 1;
  ctx.confidential_policy = &policy;

  const auto result = validate_tx_v2(*tx, 1, view, &ctx);
  if (!result.ok) throw std::runtime_error("wallet transparent->confidential builder error: " + result.error);
  ASSERT_TRUE(result.ok);
}

TEST(test_wallet_confidential_builder_creates_valid_confidential_to_transparent_txv2) {
  const auto recipient = key_from_byte(0x71);
  const auto spend_secret = blind_from_byte(0x72);
  const auto value_blind = blind_from_byte(0x73);
  const auto one_time_pubkey = crypto::secp256k1_pubkey_from_scalar(spend_secret.bytes);
  ASSERT_TRUE(one_time_pubkey.has_value());
  const auto commitment = crypto::confidential_amount_commitment(10'000, value_blind);
  ASSERT_TRUE(commitment.has_value());

  OutPoint op{};
  op.txid.fill(0x74);
  op.index = 0;
  finalis::wallet::ConfidentialOwnedCoin coin{
      .outpoint = op,
      .amount = 10'000,
      .spend_secret = spend_secret,
      .value_blind = value_blind,
      .value_commitment = *commitment,
      .one_time_pubkey = *one_time_pubkey,
  };
  const auto recipient_spk =
      address::p2pkh_script_pubkey(crypto::h160(Bytes(recipient.public_key.begin(), recipient.public_key.end())));

  std::string err;
  auto tx = finalis::wallet::build_txv2_confidential_to_transparent(
      coin, TransparentTxOutV2{9'000, recipient_spk}, 1'000, nonce_from_byte(0x75), nonce_from_byte(0x76), &err);
  ASSERT_TRUE(tx.has_value());

  UtxoSetV2 view;
  UtxoEntryV2 confidential_entry;
  confidential_entry.kind = UtxoOutputKind::Confidential;
  confidential_entry.body = UtxoConfidentialData{
      .value_commitment = *commitment,
      .one_time_pubkey = *one_time_pubkey,
      .ephemeral_pubkey = compressed_key(0x77),
      .scan_tag = crypto::ScanTag{0x78},
      .memo = {},
  };
  view[op] = confidential_entry;
  ConfidentialPolicy policy;
  policy.activation_height = 0;
  SpecialValidationContext ctx;
  ctx.current_height = 1;
  ctx.confidential_policy = &policy;

  const auto result = validate_tx_v2(*tx, 1, view, &ctx);
  if (!result.ok) throw std::runtime_error("wallet confidential->transparent builder error: " + result.error);
  ASSERT_TRUE(result.ok);
}

void register_wallet_send_policy_tests() {}
