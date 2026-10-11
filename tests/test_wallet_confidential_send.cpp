// SPDX-License-Identifier: MIT

#include "test_framework.hpp"

#include <memory>

#include "apps/finalis-wallet/confidential_receive.hpp"
#include "apps/finalis-wallet/confidential_send.hpp"
#include "crypto/hash.hpp"
#include "utxo/validate.hpp"
#include "wallet/confidential_keys.hpp"

using namespace finalis;
using finalis::wallet::WalletStore;

namespace {

Hash32 filled(std::uint8_t b) {
  Hash32 h{};
  h.fill(b);
  return h;
}

// Deterministic randomness for the planner.
std::function<Hash32()> counter_random(std::uint8_t seed) {
  auto counter = std::make_shared<std::uint64_t>(0);
  return [seed, counter]() {
    Bytes preimage{seed};
    for (int shift = 0; shift < 64; shift += 8) preimage.push_back(static_cast<std::uint8_t>(*counter >> shift));
    ++*counter;
    return crypto::sha256(preimage);
  };
}

WalletStore::ConfidentialAccountRecord account(const std::string& id, std::uint8_t view, std::uint8_t spend) {
  WalletStore::ConfidentialAccountRecord a;
  a.account_id = id;
  a.view_key_material_hex = hex_encode32(filled(view));
  a.spend_key_material_hex = hex_encode32(filled(spend));
  return a;
}

// A finalized confidential coin of `amount`: its wallet record and its UTXO entry for validation.
std::pair<WalletStore::ConfidentialCoinRecord, UtxoEntryV2> coin(std::uint8_t seed, std::uint64_t amount) {
  const Hash32 spend = filled(seed);
  const crypto::Blind32 blind{filled(static_cast<std::uint8_t>(seed + 1))};
  const auto one_time = crypto::secp256k1_pubkey_from_scalar(spend);
  const auto ephemeral = crypto::secp256k1_pubkey_from_scalar(filled(static_cast<std::uint8_t>(seed + 2)));
  const auto commitment = crypto::confidential_amount_commitment(amount, blind);
  ASSERT_TRUE(one_time.has_value() && ephemeral.has_value() && commitment.has_value());
  WalletStore::ConfidentialCoinRecord record{
      .txid_hex = hex_encode32(filled(static_cast<std::uint8_t>(seed + 3))),
      .vout = 0,
      .account_id = "sender",
      .amount = amount,
      .value_commitment_hex = hex_encode(Bytes(commitment->bytes.begin(), commitment->bytes.end())),
      .one_time_pubkey_hex = hex_encode(Bytes(one_time->begin(), one_time->end())),
      .ephemeral_pubkey_hex = hex_encode(Bytes(ephemeral->begin(), ephemeral->end())),
      .spend_secret_hex = hex_encode32(spend),
      .blinding_factor_hex = hex_encode32(blind.bytes),
      .spent = false,
  };
  UtxoEntryV2 entry;
  entry.kind = UtxoOutputKind::Confidential;
  entry.body = UtxoConfidentialData{.value_commitment = *commitment,
                                    .one_time_pubkey = *one_time,
                                    .ephemeral_pubkey = *ephemeral,
                                    .scan_tag = crypto::ScanTag{seed},
                                    .memo = {}};
  return {record, entry};
}

OutPoint outpoint_of(const WalletStore::ConfidentialCoinRecord& record) {
  OutPoint op{};
  const auto txid = hex_decode(record.txid_hex);
  std::copy(txid->begin(), txid->end(), op.txid.begin());
  op.index = record.vout;
  return op;
}

struct Fixture {
  WalletStore::State sender;
  WalletStore::State recipient;
  UtxoSetV2 view;
  wallet::ConfidentialRecipient to;
  Hash32 to_memo_key{};

  Fixture() {
    sender.confidential_accounts.push_back(account("sender", 0x21, 0x22));
    recipient.confidential_accounts.push_back(account("recipient", 0x31, 0x32));
    for (const auto& [seed, amount] : {std::pair<std::uint8_t, std::uint64_t>{0x41, 6'000}, {0x51, 4'000}}) {
      auto [record, entry] = coin(seed, amount);
      view[outpoint_of(record)] = entry;
      sender.confidential_coins.push_back(record);
    }
    // The recipient's request 0, as its scconfreq1 URI hands it to the sender.
    const auto keys = wallet::derive_confidential_request_keys(filled(0x31), filled(0x32), 0);
    ASSERT_TRUE(keys.has_value());
    to = wallet::ConfidentialRecipient{.one_time_pubkey = keys->pub.one_time_pubkey,
                                       .ephemeral_pubkey = keys->pub.ephemeral_pubkey,
                                       .scan_tag = keys->pub.scan_tag,
                                       .memo = {}};
    to_memo_key = keys->pub.memo_key;
  }
};

bool validates(const TxV2& tx, const UtxoSetV2& view) {
  ConfidentialPolicy policy;
  SpecialValidationContext ctx;
  ctx.current_height = 1;
  ctx.confidential_policy = &policy;
  const auto r = validate_tx_v2(tx, 1, view, &ctx);
  if (!r.ok) throw std::runtime_error("validate: " + r.error);
  return true;
}

}  // namespace

// 6000 + 4000 -> 7000 to the recipient, 2000 change, fee 1000. The recipient's wallet finds its 7000,
// the sender's wallet finds its change through its own derived request keys.
TEST(test_confidential_transfer_plan_pays_recipient_and_recovers_change) {
  ASSERT_TRUE(crypto::confidential_crypto_init());
  Fixture f;
  std::string err;
  const auto plan = wallet::plan_confidential_transfer(f.sender, {}, "sender", f.to, f.to_memo_key, 7'000, 1'000,
                                                       counter_random(0x01), &err);
  if (!plan) throw std::runtime_error("plan: " + err);
  ASSERT_EQ(plan->input_total, 10'000ULL);
  ASSERT_EQ(plan->change, 2'000ULL);
  ASSERT_EQ(plan->spent.size(), 2u);
  ASSERT_TRUE(plan->change_request_index.has_value() && *plan->change_request_index == 0u);
  ASSERT_EQ(plan->tx.outputs.size(), 2u);
  for (const auto& o : plan->tx.outputs) ASSERT_TRUE(o.kind == TxOutputKind::Confidential);
  ASSERT_TRUE(validates(plan->tx, f.view));

  const auto txid = plan->tx.txid();
  const auto received = wallet::match_received_confidential_outputs(plan->tx, txid, f.recipient);
  ASSERT_EQ(received.size(), 1u);
  ASSERT_EQ(received[0].coin.amount, 7'000ULL);
  ASSERT_EQ(received[0].coin.account_id, std::string("recipient"));

  const auto change = wallet::match_received_confidential_outputs(plan->tx, txid, f.sender);
  ASSERT_EQ(change.size(), 1u);
  ASSERT_EQ(change[0].coin.amount, 2'000ULL);
  ASSERT_TRUE(change[0].derived_index.has_value() && *change[0].derived_index == 0u);
}

// The change position follows the randomness, not a fixed slot.
TEST(test_confidential_transfer_plan_randomises_change_position) {
  ASSERT_TRUE(crypto::confidential_crypto_init());
  Fixture f;
  std::set<std::size_t> change_positions;
  for (std::uint8_t seed = 1; seed <= 16 && change_positions.size() < 2; ++seed) {
    std::string err;
    const auto plan = wallet::plan_confidential_transfer(f.sender, {}, "sender", f.to, f.to_memo_key, 7'000, 1'000,
                                                         counter_random(seed), &err);
    ASSERT_TRUE(plan.has_value());
    for (std::size_t i = 0; i < plan->tx.outputs.size(); ++i) {
      const auto& out = std::get<ConfidentialTxOutV2>(plan->tx.outputs[i].body);
      if (out.one_time_pubkey != f.to.one_time_pubkey) change_positions.insert(i);
    }
  }
  ASSERT_EQ(change_positions.size(), 2u);
}

TEST(test_confidential_transfer_plan_exact_amount_has_no_change_and_skips_reserved) {
  ASSERT_TRUE(crypto::confidential_crypto_init());
  Fixture f;
  std::string err;
  // 6000 coin exactly covers 5000 + 1000: one output, no change.
  const auto exact = wallet::plan_confidential_transfer(f.sender, {}, "sender", f.to, f.to_memo_key, 5'000, 1'000,
                                                        counter_random(0x02), &err);
  ASSERT_TRUE(exact.has_value());
  ASSERT_EQ(exact->change, 0ULL);
  ASSERT_TRUE(!exact->change_request_index.has_value());
  ASSERT_EQ(exact->tx.outputs.size(), 1u);
  ASSERT_TRUE(validates(exact->tx, f.view));

  // With the 6000 coin reserved by a pending send, 4000 alone cannot cover 7000 + 1000.
  const std::set<OutPoint> reserved{outpoint_of(f.sender.confidential_coins[0])};
  ASSERT_TRUE(!wallet::plan_confidential_transfer(f.sender, reserved, "sender", f.to, f.to_memo_key, 7'000, 1'000,
                                                  counter_random(0x03), &err)
                   .has_value());
}
