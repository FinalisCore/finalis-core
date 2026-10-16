// SPDX-License-Identifier: MIT

#include <algorithm>

#include "test_framework.hpp"

#include "apps/finalis-wallet/confidential_memo.hpp"
#include "apps/finalis-wallet/confidential_receive.hpp"
#include "crypto/confidential.hpp"
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
  TxOutV2 payment(std::uint64_t amount, std::uint8_t blind_seed) const { return payment(amount, amount, blind_seed); }

  // `memo_amount` is what the memo claims; `committed_amount` is what the output commits to.
  TxOutV2 payment(std::uint64_t committed_amount, std::uint64_t memo_amount, std::uint8_t seed_byte) const {
    const Hash32 seed = filled(seed_byte);
    const auto blind = wallet::derive_output_value_blind(seed, one_time);
    ASSERT_TRUE(blind.has_value());
    auto memo = wallet::encrypt_confidential_recovery_memo(memo_amount, seed, memo_key, one_time, ephemeral);
    ASSERT_TRUE(memo.has_value());
    const auto commitment = crypto::confidential_amount_commitment(committed_amount, *blind);
    ASSERT_TRUE(commitment.has_value());
    ConfidentialTxOutV2 out;
    out.value_commitment = *commitment;
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

// The memo is sender-written. A memo claiming more than the output commits to must not be
// imported: the wallet would show coins that can never be spent.
TEST(test_confidential_receive_rejects_memo_that_does_not_open_commitment) {
  ASSERT_TRUE(crypto::confidential_crypto_init());
  const Request req;
  WalletStore::State state;
  state.confidential_requests.push_back(req.record(false));

  const auto tx = tx_with({req.payment(/*committed_amount=*/1, /*memo_amount=*/1000, 0x61), req.payment(250, 0x62)});
  const auto matches = wallet::match_received_confidential_outputs(tx, filled(0xE1), state);
  ASSERT_EQ(matches.size(), 1u);
  ASSERT_EQ(matches[0].coin.vout, 1u);
  ASSERT_EQ(matches[0].coin.amount, 250u);
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
  const Hash32 seed = filled(0x33);
  const auto blind = wallet::derive_output_value_blind(seed, keys->pub.one_time_pubkey);
  ASSERT_TRUE(blind.has_value());
  auto memo = wallet::encrypt_confidential_recovery_memo(amount, seed, keys->pub.memo_key, keys->pub.one_time_pubkey,
                                                         keys->pub.ephemeral_pubkey);
  ASSERT_TRUE(memo.has_value());
  const auto commitment = crypto::confidential_amount_commitment(amount, *blind);
  ASSERT_TRUE(commitment.has_value());
  ConfidentialTxOutV2 out;
  out.value_commitment = *commitment;
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

// Account secrets come from the wallet key seed alone: deterministic, distinct per account and per
// role, never the seed itself. The vector pins the derivation, since restore depends on it.
TEST(test_confidential_account_secrets_derive_from_wallet_seed) {
  ASSERT_TRUE(crypto::confidential_crypto_init());
  const Hash32 seed = filled(0x5A);
  const auto a0 = wallet::derive_confidential_account_secrets(seed, 0);
  const auto a0_again = wallet::derive_confidential_account_secrets(seed, 0);
  const auto a1 = wallet::derive_confidential_account_secrets(seed, 1);
  const auto other = wallet::derive_confidential_account_secrets(filled(0x5B), 0);
  ASSERT_TRUE(a0 && a0_again && a1 && other);
  ASSERT_EQ(hex_encode32(a0->view_secret), hex_encode32(a0_again->view_secret));
  ASSERT_EQ(hex_encode32(a0->spend_secret), hex_encode32(a0_again->spend_secret));
  ASSERT_TRUE(a0->view_secret != a0->spend_secret);
  ASSERT_TRUE(a0->view_secret != seed && a0->spend_secret != seed);
  ASSERT_TRUE(a0->view_secret != a1->view_secret && a0->spend_secret != a1->spend_secret);
  ASSERT_TRUE(a0->view_secret != other->view_secret && a0->spend_secret != other->spend_secret);
  ASSERT_EQ(hex_encode32(a0->view_secret), std::string("d4b5e2d46de085653736634d6d6a4c1eec31f8b211422b436b20dca9a2937f5e"));
  ASSERT_EQ(hex_encode32(a0->spend_secret), std::string("0f766bb78aee0add8fe3f218d7075d45bb275d63e43a484598500af28f43b0d9"));

  // A payment to a request of the derived account is found by an account rebuilt from the seed.
  const auto keys = wallet::derive_confidential_request_keys(a0->view_secret, a0->spend_secret, 5);
  ASSERT_TRUE(keys.has_value());
  WalletStore::State state;
  WalletStore::ConfidentialAccountRecord account;
  account.account_id = "acct-seed";
  account.view_key_material_hex = hex_encode32(a0_again->view_secret);
  account.spend_key_material_hex = hex_encode32(a0_again->spend_secret);
  state.confidential_accounts.push_back(account);
  const auto scan_keys = wallet::confidential_scan_history_keys(state);
  ASSERT_TRUE(std::binary_search(scan_keys.begin(), scan_keys.end(), confidential_history_key(keys->pub.one_time_pubkey)));
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

// Chain scan keys cover every derived request in the gap window, stored requests and coins, and
// change when the window moves, so a stale scan cursor is not reused.
TEST(test_confidential_scan_history_keys_cover_derived_window) {
  ASSERT_TRUE(crypto::confidential_crypto_init());
  WalletStore::State state;
  state.confidential_accounts.push_back(derived_account(/*next_request_index=*/0));
  const auto keys = wallet::confidential_scan_history_keys(state);
  ASSERT_EQ(keys.size(), static_cast<std::size_t>(wallet::kConfidentialRequestGap));
  ASSERT_TRUE(std::is_sorted(keys.begin(), keys.end()));
  const auto has = [&](const std::vector<Hash32>& set, const PubKey33& pk) {
    return std::binary_search(set.begin(), set.end(), confidential_history_key(pk));
  };
  const auto last = wallet::derive_confidential_request_keys(filled(0x21), filled(0x22), wallet::kConfidentialRequestGap - 1);
  const auto beyond = wallet::derive_confidential_request_keys(filled(0x21), filled(0x22), wallet::kConfidentialRequestGap);
  ASSERT_TRUE(last.has_value() && beyond.has_value());
  ASSERT_TRUE(has(keys, last->pub.one_time_pubkey));
  ASSERT_TRUE(!has(keys, beyond->pub.one_time_pubkey));

  Request request;
  state.confidential_requests.push_back(request.record(false));
  const auto with_request = wallet::confidential_scan_history_keys(state);
  ASSERT_TRUE(has(with_request, request.one_time));
  ASSERT_TRUE(wallet::confidential_scan_key_set_fingerprint(with_request) != wallet::confidential_scan_key_set_fingerprint(keys));

  state.confidential_accounts.front().next_request_index = 1;
  const auto widened = wallet::confidential_scan_history_keys(state);
  ASSERT_TRUE(has(widened, beyond->pub.one_time_pubkey));
  ASSERT_TRUE(wallet::confidential_scan_key_set_fingerprint(widened) != wallet::confidential_scan_key_set_fingerprint(with_request));
}

TEST(test_confidential_coins_spent_by_reports_owned_unspent_inputs) {
  WalletStore::State state;
  const Hash32 funding = filled(0xF1);
  state.confidential_coins.push_back(WalletStore::ConfidentialCoinRecord{.txid_hex = hex_encode32(funding), .vout = 0});
  state.confidential_coins.push_back(
      WalletStore::ConfidentialCoinRecord{.txid_hex = hex_encode32(funding), .vout = 1, .spent = true});
  TxV2 tx;
  const auto confidential_input = [&](std::uint32_t vout) {
    return TxInV2{.prev_txid = funding,
                  .prev_index = vout,
                  .kind = TxInputKind::Confidential,
                  .witness = ConfidentialInputWitnessV2{}};
  };
  tx.inputs.push_back(confidential_input(0));
  tx.inputs.push_back(confidential_input(1));  // already spent
  tx.inputs.push_back(confidential_input(2));  // not ours
  tx.inputs.push_back(TxInV2{.prev_txid = funding, .prev_index = 0});  // transparent
  const auto spent = wallet::confidential_coins_spent_by(tx, state);
  ASSERT_EQ(spent.size(), 1u);
  ASSERT_TRUE(spent[0].txid == funding && spent[0].index == 0u);
}
