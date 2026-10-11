// SPDX-License-Identifier: MIT

#include "test_framework.hpp"

#include "utxo/validate.hpp"
#include "wallet/confidential_builder.hpp"

using namespace finalis;

namespace {

crypto::Blind32 blind_of(std::uint8_t b) {
  crypto::Blind32 out{};
  out.bytes.fill(b);
  return out;
}

PubKey33 point_of(std::uint8_t b) {
  const auto pk = crypto::secp256k1_pubkey_from_scalar(blind_of(b).bytes);
  ASSERT_TRUE(pk.has_value());
  return *pk;
}

struct Coin {
  wallet::ConfidentialOwnedCoin owned;
  UtxoEntryV2 entry;
};

// A confidential coin worth `amount`, owned through spend secret `seed`, at outpoint (seed, 0).
Coin make_coin(std::uint8_t seed, std::uint64_t amount) {
  const auto spend = blind_of(seed);
  const auto vblind = blind_of(static_cast<std::uint8_t>(seed + 1));
  const auto commitment = crypto::confidential_amount_commitment(amount, vblind);
  ASSERT_TRUE(commitment.has_value());
  OutPoint op{};
  op.txid.fill(seed);
  op.index = 0;
  Coin c{.owned = {.outpoint = op,
                   .amount = amount,
                   .spend_secret = spend,
                   .value_blind = vblind,
                   .value_commitment = *commitment,
                   .one_time_pubkey = point_of(seed)},
         .entry = {}};
  c.entry.kind = UtxoOutputKind::Confidential;
  c.entry.body = UtxoConfidentialData{.value_commitment = *commitment,
                                      .one_time_pubkey = point_of(seed),
                                      .ephemeral_pubkey = point_of(static_cast<std::uint8_t>(seed + 2)),
                                      .scan_tag = crypto::ScanTag{seed},
                                      .memo = {}};
  return c;
}

// A confidential output that commits to `committed` but is declared to the builder as `declared`.
wallet::ConfidentialPayment make_payment(std::uint8_t seed, std::uint64_t declared, std::uint64_t committed) {
  std::string err;
  const auto out = wallet::build_confidential_output(
      wallet::ConfidentialRecipient{.one_time_pubkey = point_of(seed), .ephemeral_pubkey = point_of(seed + 1), .scan_tag = {},
                                    .memo = {}},
      crypto::ConfidentialOutputSecrets{.amount = committed, .value_blind = blind_of(static_cast<std::uint8_t>(seed + 2))},
      blind_of(static_cast<std::uint8_t>(seed + 3)).bytes, &err);
  ASSERT_TRUE(out.has_value());
  return wallet::ConfidentialPayment{.output = *out, .value = declared, .value_blind = blind_of(static_cast<std::uint8_t>(seed + 2))};
}

AnyTxValidationResult validate(const TxV2& tx, const std::vector<Coin>& coins) {
  UtxoSetV2 view;
  for (const auto& c : coins) view[c.owned.outpoint] = c.entry;
  ConfidentialPolicy policy;
  SpecialValidationContext ctx;
  ctx.current_height = 1;
  ctx.confidential_policy = &policy;
  return validate_tx_v2(tx, 1, view, &ctx);
}

}  // namespace

// Two coins (6000 + 4000) pay 7000 to a recipient and 2000 change, fee 1000: every amount is hidden.
TEST(test_confidential_to_confidential_transfer_validates) {
  ASSERT_TRUE(crypto::confidential_crypto_init());
  const std::vector<Coin> coins{make_coin(0x11, 6'000), make_coin(0x21, 4'000)};
  std::vector<wallet::ConfidentialOwnedCoin> owned{coins[0].owned, coins[1].owned};
  const std::vector<wallet::ConfidentialPayment> outputs{make_payment(0x31, 7'000, 7'000), make_payment(0x41, 2'000, 2'000)};
  std::string err;
  const auto tx = wallet::build_txv2_confidential_to_confidential(owned, outputs, 1'000, blind_of(0x51).bytes, &err);
  if (!tx.has_value()) throw std::runtime_error("build: " + err);
  ASSERT_EQ(tx->inputs.size(), 2u);
  ASSERT_EQ(tx->outputs.size(), 2u);
  for (const auto& o : tx->outputs) ASSERT_TRUE(o.kind == TxOutputKind::Confidential);
  const auto result = validate(*tx, coins);
  if (!result.ok) throw std::runtime_error("validate: " + result.error);
}

TEST(test_confidential_to_confidential_builder_requires_exact_balance) {
  ASSERT_TRUE(crypto::confidential_crypto_init());
  const auto coin = make_coin(0x12, 5'000);
  std::string err;
  const auto tx = wallet::build_txv2_confidential_to_confidential({coin.owned}, {make_payment(0x32, 3'000, 3'000)}, 1'000,
                                                                  blind_of(0x52).bytes, &err);
  ASSERT_TRUE(!tx.has_value());
  ASSERT_EQ(err, std::string("confidential inputs must equal outputs plus fee"));
}

// The builder trusts declared values, consensus does not: an output committing to more than declared
// (value from nothing) fails the commitment tally.
TEST(test_confidential_to_confidential_inflation_is_rejected_by_consensus) {
  ASSERT_TRUE(crypto::confidential_crypto_init());
  const std::vector<Coin> coins{make_coin(0x13, 5'000)};
  std::string err;
  const auto tx = wallet::build_txv2_confidential_to_confidential(
      {coins[0].owned}, {make_payment(0x33, 4'000, 900'000)}, 1'000, blind_of(0x53).bytes, &err);
  ASSERT_TRUE(tx.has_value());
  const auto result = validate(*tx, coins);
  ASSERT_TRUE(!result.ok);
}

// Every input must be authorised by its own one-time key.
TEST(test_confidential_to_confidential_input_signatures_are_checked) {
  ASSERT_TRUE(crypto::confidential_crypto_init());
  const std::vector<Coin> coins{make_coin(0x14, 3'000), make_coin(0x24, 3'000)};
  std::string err;
  auto tx = wallet::build_txv2_confidential_to_confidential({coins[0].owned, coins[1].owned},
                                                            {make_payment(0x34, 5'000, 5'000)}, 1'000,
                                                            blind_of(0x54).bytes, &err);
  ASSERT_TRUE(tx.has_value());
  std::get<ConfidentialInputWitnessV2>(tx->inputs[1].witness).spend_sig.fill(0);
  ASSERT_TRUE(!validate(*tx, coins).ok);
}
