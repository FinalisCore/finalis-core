// SPDX-License-Identifier: MIT

#include "test_framework.hpp"

#include "apps/finalis-wallet/confidential_memo.hpp"
#include "apps/finalis-wallet/confidential_receive.hpp"
#include "wallet/confidential_keys.hpp"

using namespace finalis;
using finalis::wallet::WalletStore;

namespace {

PubKey33 pubkey(std::uint8_t seed) {
  Hash32 scalar{};
  scalar.fill(seed);
  auto pk = crypto::secp256k1_pubkey_from_scalar(scalar);
  ASSERT_TRUE(pk.has_value());
  return *pk;
}

Hash32 filled(std::uint8_t b) {
  Hash32 h{};
  h.fill(b);
  return h;
}

struct Request {
  PubKey33 one_time = pubkey(0x11);
  PubKey33 ephemeral = pubkey(0x12);
  std::uint8_t scan_tag = 0x7A;
  Hash32 memo_key = filled(0x13);

  WalletStore::ConfidentialRequestRecord record(bool consumed) const {
    return WalletStore::ConfidentialRequestRecord{
        .request_id = "req-1",
        .account_id = "acct-1",
        .one_time_pubkey_hex = hex_encode(Bytes(one_time.begin(), one_time.end())),
        .ephemeral_pubkey_hex = hex_encode(Bytes(ephemeral.begin(), ephemeral.end())),
        .scan_tag = scan_tag,
        .spend_secret_hex = hex_encode32(filled(0x14)),
        .memo_key_hex = hex_encode32(memo_key),
        .consumed = consumed,
    };
  }

  // A payment to this request: what a sender's wallet builds from the request URI.
  TxOutV2 payment(std::uint64_t amount, std::uint8_t blind_seed) const {
    crypto::Blind32 blind{};
    blind.bytes.fill(blind_seed);
    auto memo = wallet::encrypt_confidential_recovery_memo(amount, blind, memo_key, one_time, ephemeral);
    ASSERT_TRUE(memo.has_value());
    ConfidentialTxOutV2 out;
    out.one_time_pubkey = one_time;
    out.ephemeral_pubkey = ephemeral;
    out.scan_tag = crypto::ScanTag{scan_tag};
    out.memo = *memo;
    return TxOutV2{.kind = TxOutputKind::Confidential, .body = out};
  }
};

TxV2 tx_with(std::vector<TxOutV2> outputs) {
  TxV2 tx;
  tx.outputs = std::move(outputs);
  return tx;
}

}  // namespace

// Paying the same request URI twice must not strand the second payment.
TEST(test_confidential_receive_imports_repeat_payments_to_consumed_request) {
  ASSERT_TRUE(crypto::confidential_crypto_init());
  const Request req;
  WalletStore::State state;
  state.confidential_requests.push_back(req.record(/*consumed=*/false));

  const auto first = tx_with({req.payment(500, 0x21)});
  auto matches = wallet::match_received_confidential_outputs(first, filled(0xA1), state);
  ASSERT_EQ(matches.size(), 1u);
  ASSERT_EQ(matches[0].coin.amount, 500u);
  ASSERT_EQ(matches[0].request_id, std::string("req-1"));

  // After the first import the request is consumed and the coin stored.
  state.confidential_requests[0].consumed = true;
  state.confidential_coins.push_back(matches[0].coin);

  const auto second = tx_with({req.payment(700, 0x22)});
  std::size_t already = 99;
  matches = wallet::match_received_confidential_outputs(second, filled(0xA2), state, &already);
  ASSERT_EQ(already, 0u);
  ASSERT_EQ(matches.size(), 1u);
  ASSERT_EQ(matches[0].coin.amount, 700u);
  ASSERT_EQ(matches[0].coin.txid_hex, hex_encode32(filled(0xA2)));
  ASSERT_EQ(matches[0].coin.vout, 0u);
  ASSERT_EQ(matches[0].coin.spend_secret_hex, state.confidential_requests[0].spend_secret_hex);
}

// Two payments to the same request inside one tx are two coins.
TEST(test_confidential_receive_matches_every_output_paying_request) {
  ASSERT_TRUE(crypto::confidential_crypto_init());
  const Request req;
  WalletStore::State state;
  state.confidential_requests.push_back(req.record(true));
  TxOutV2 transparent{.kind = TxOutputKind::Transparent, .body = TransparentTxOutV2{1, Bytes{0x51}}};
  const auto tx = tx_with({req.payment(100, 0x31), transparent, req.payment(200, 0x32)});
  const auto matches = wallet::match_received_confidential_outputs(tx, filled(0xB1), state);
  ASSERT_EQ(matches.size(), 2u);
  ASSERT_EQ(matches[0].coin.vout, 0u);
  ASSERT_EQ(matches[0].coin.amount, 100u);
  ASSERT_EQ(matches[1].coin.vout, 2u);
  ASSERT_EQ(matches[1].coin.amount, 200u);
}

// Re-importing must never overwrite a stored coin (that would reset `spent` and resurrect it).
TEST(test_confidential_receive_skips_already_imported_outputs) {
  ASSERT_TRUE(crypto::confidential_crypto_init());
  const Request req;
  WalletStore::State state;
  state.confidential_requests.push_back(req.record(true));
  const auto tx = tx_with({req.payment(500, 0x41)});
  auto first = wallet::match_received_confidential_outputs(tx, filled(0xC1), state);
  ASSERT_EQ(first.size(), 1u);
  first[0].coin.spent = true;
  state.confidential_coins.push_back(first[0].coin);

  std::size_t already = 0;
  const auto again = wallet::match_received_confidential_outputs(tx, filled(0xC1), state, &already);
  ASSERT_TRUE(again.empty());
  ASSERT_EQ(already, 1u);
}

TEST(test_confidential_receive_ignores_foreign_outputs_and_bad_memos) {
  ASSERT_TRUE(crypto::confidential_crypto_init());
  const Request req;
  Request other;
  other.one_time = pubkey(0x51);
  WalletStore::State state;
  state.confidential_requests.push_back(req.record(false));

  Request wrong_key = req;
  wrong_key.memo_key = filled(0x52);  // sender used a different memo key
  const auto tx = tx_with({other.payment(100, 0x53), wrong_key.payment(100, 0x54)});
  std::size_t already = 0;
  ASSERT_TRUE(wallet::match_received_confidential_outputs(tx, filled(0xD1), state, &already).empty());
  ASSERT_EQ(already, 0u);
}

namespace {

WalletStore::ConfidentialAccountRecord derived_account(std::uint32_t next_request_index) {
  WalletStore::ConfidentialAccountRecord account;
  account.account_id = "acct-derived";
  account.view_key_material_hex = hex_encode32(filled(0x21));
  account.spend_key_material_hex = hex_encode32(filled(0x22));
  account.next_request_index = next_request_index;
  return account;
}

// A payment to request `index` of derived_account(), as a sender builds it from the request URI.
TxOutV2 derived_payment(std::uint32_t index, std::uint64_t amount) {
  const auto keys = wallet::derive_confidential_request_keys(filled(0x21), filled(0x22), index);
  ASSERT_TRUE(keys.has_value());
  crypto::Blind32 blind{};
  blind.bytes.fill(0x33);
  auto memo = wallet::encrypt_confidential_recovery_memo(amount, blind, keys->pub.memo_key, keys->pub.one_time_pubkey,
                                                         keys->pub.ephemeral_pubkey);
  ASSERT_TRUE(memo.has_value());
  ConfidentialTxOutV2 out;
  out.one_time_pubkey = keys->pub.one_time_pubkey;
  out.ephemeral_pubkey = keys->pub.ephemeral_pubkey;
  out.scan_tag = keys->pub.scan_tag;
  out.memo = *memo;
  return TxOutV2{.kind = TxOutputKind::Confidential, .body = out};
}

}  // namespace

// Restore from backup: the wallet holds only the account secrets, no request records, and must still
// find a payment to one of its earlier requests, with the spend secret that spends it.
TEST(test_confidential_receive_recovers_payment_from_account_secrets_alone) {
  ASSERT_TRUE(crypto::confidential_crypto_init());
  WalletStore::State state;
  state.confidential_accounts.push_back(derived_account(/*next_request_index=*/0));
  const auto tx = tx_with({derived_payment(37, 125'000)});

  const auto matches = wallet::match_received_confidential_outputs(tx, filled(0xE1), state);
  ASSERT_EQ(matches.size(), 1u);
  ASSERT_TRUE(matches[0].derived_index.has_value() && *matches[0].derived_index == 37u);
  ASSERT_TRUE(matches[0].request_id.empty());
  ASSERT_EQ(matches[0].coin.account_id, std::string("acct-derived"));
  ASSERT_EQ(matches[0].coin.amount, 125'000ULL);
  const auto keys = wallet::derive_confidential_request_keys(filled(0x21), filled(0x22), 37);
  ASSERT_TRUE(keys.has_value());
  ASSERT_EQ(matches[0].coin.spend_secret_hex, hex_encode32(keys->one_time_secret));

  // Re-import after storing the coin: recognised, not duplicated.
  state.confidential_coins.push_back(matches[0].coin);
  std::size_t already = 0;
  ASSERT_TRUE(wallet::match_received_confidential_outputs(tx, filled(0xE1), state, &already).empty());
  ASSERT_EQ(already, 1u);
}

TEST(test_confidential_receive_derived_matching_stops_at_gap_window) {
  ASSERT_TRUE(crypto::confidential_crypto_init());
  WalletStore::State state;
  state.confidential_accounts.push_back(derived_account(/*next_request_index=*/0));
  const std::uint32_t beyond = wallet::kConfidentialRequestGap;
  ASSERT_TRUE(wallet::match_received_confidential_outputs(tx_with({derived_payment(beyond, 1)}), filled(0xE2), state).empty());
  // Advancing next_request_index widens the window.
  state.confidential_accounts.front().next_request_index = 1;
  const auto matches = wallet::match_received_confidential_outputs(tx_with({derived_payment(beyond, 1)}), filled(0xE2), state);
  ASSERT_EQ(matches.size(), 1u);
  ASSERT_TRUE(matches[0].derived_index.has_value() && *matches[0].derived_index == beyond);
}
