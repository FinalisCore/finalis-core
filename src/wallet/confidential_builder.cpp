#include "wallet/confidential_builder.hpp"

#include <variant>

#include "crypto/ed25519.hpp"
#include "crypto/hash.hpp"

namespace finalis::wallet {
namespace {

Bytes make_p2pkh_script_sig(const Sig64& sig, const PubKey32& pub) {
  Bytes ss;
  ss.push_back(0x40);
  ss.insert(ss.end(), sig.begin(), sig.end());
  ss.push_back(0x20);
  ss.insert(ss.end(), pub.begin(), pub.end());
  return ss;
}

bool resign_transparent_input(TxV2& tx, const Bytes& private_key_32, std::size_t input_index, std::string* err) {
  if (private_key_32.size() != 32) {
    if (err) *err = "transparent private key must be 32 bytes";
    return false;
  }
  std::array<std::uint8_t, 32> seed{};
  std::copy(private_key_32.begin(), private_key_32.end(), seed.begin());
  auto kp = crypto::keypair_from_seed32(seed);
  if (!kp.has_value()) {
    if (err) *err = "failed to derive transparent input keypair";
    return false;
  }
  auto msg = signing_message_for_input_v2(tx, static_cast<std::uint32_t>(input_index));
  if (!msg.has_value()) {
    if (err) *err = "failed to derive transparent input sighash";
    return false;
  }
  auto sig = crypto::ed25519_sign(*msg, kp->private_key);
  if (!sig.has_value()) {
    if (err) *err = "failed to sign transparent input";
    return false;
  }
  std::get<TransparentInputWitnessV2>(tx.inputs.at(input_index).witness).script_sig =
      make_p2pkh_script_sig(*sig, kp->public_key);
  return true;
}

bool sign_balance_proof(TxV2& tx, const crypto::Blind32& excess_blind, const Hash32& aux_nonce, std::string* err) {
  const auto pubkey = crypto::excess_xonly_pubkey_from_scalar(excess_blind);
  if (!pubkey.has_value()) {
    if (err) *err = "failed to derive excess pubkey";
    return false;
  }
  tx.balance_proof.excess_pubkey = *pubkey;
  tx.balance_proof.excess_sig.fill(0);
  const auto msg = balance_proof_message_v2(tx);
  if (!msg.has_value()) {
    if (err) *err = "failed to derive balance proof message";
    return false;
  }
  const auto sig = crypto::sign_excess_authorization(*msg, excess_blind, aux_nonce);
  if (!sig.has_value()) {
    if (err) *err = "failed to sign balance proof";
    return false;
  }
  tx.balance_proof.excess_sig = *sig;
  return true;
}

bool sign_confidential_input(TxV2& tx, std::size_t input_index, const crypto::Blind32& spend_secret, const Hash32& aux_nonce,
                             std::string* err) {
  const auto pubkey = crypto::secp256k1_pubkey_from_scalar(spend_secret.bytes);
  if (!pubkey.has_value()) {
    if (err) *err = "failed to derive confidential input pubkey";
    return false;
  }
  auto& witness = std::get<ConfidentialInputWitnessV2>(tx.inputs.at(input_index).witness);
  witness.one_time_pubkey = *pubkey;
  witness.spend_sig.fill(0);
  const auto msg = signing_message_for_input_v2(tx, static_cast<std::uint32_t>(input_index));
  if (!msg.has_value()) {
    if (err) *err = "failed to derive confidential input sighash";
    return false;
  }
  Hash32 msg32{};
  std::copy(msg->begin(), msg->end(), msg32.begin());
  const auto sig = crypto::sign_schnorr_authorization(msg32, spend_secret, aux_nonce);
  if (!sig.has_value()) {
    if (err) *err = "failed to sign confidential input";
    return false;
  }
  witness.spend_sig = *sig;
  return true;
}

}  // namespace

std::optional<ConfidentialTxOutV2> build_confidential_output(
    const ConfidentialRecipient& recipient, const crypto::ConfidentialOutputSecrets& secrets,
    const Hash32& rangeproof_nonce, std::string* err) {
  const auto commitment = crypto::confidential_amount_commitment(secrets.amount, secrets.value_blind);
  if (!commitment.has_value()) {
    if (err) *err = "failed to build confidential value commitment";
    return std::nullopt;
  }
  const auto proof =
      crypto::sign_output_range_proof(*commitment, secrets.amount, secrets.value_blind, rangeproof_nonce);
  if (!proof.has_value()) {
    if (err) *err = "failed to build confidential range proof";
    return std::nullopt;
  }
  return ConfidentialTxOutV2{
      .value_commitment = *commitment,
      .one_time_pubkey = recipient.one_time_pubkey,
      .ephemeral_pubkey = recipient.ephemeral_pubkey,
      .scan_tag = recipient.scan_tag,
      .range_proof = *proof,
      .memo = recipient.memo,
  };
}

std::optional<TxV2> build_txv2_transparent_to_confidential(
    const OutPoint& prev_outpoint, const TxOut& prev_out, const Bytes& transparent_owner_private_key_32,
    std::uint64_t transparent_input_value, std::optional<TransparentTxOutV2> transparent_output,
    const ConfidentialTxOutV2& confidential_output, const crypto::Blind32& confidential_output_blind,
    std::uint64_t confidential_output_value, std::uint64_t fee, std::string* err) {
  if (transparent_input_value < fee + confidential_output_value) {
    if (err) *err = "transparent input value too small";
    return std::nullopt;
  }
  if (transparent_output.has_value() &&
      transparent_input_value < fee + confidential_output_value + transparent_output->value) {
    if (err) *err = "transparent input value does not cover outputs";
    return std::nullopt;
  }

  TxV2 tx;
  tx.inputs.push_back(TxInV2{
      .prev_txid = prev_outpoint.txid,
      .prev_index = prev_outpoint.index,
      .sequence = 0xFFFFFFFF,
      .kind = TxInputKind::TRANSPARENT,
      .witness = TransparentInputWitnessV2{},
  });
  if (transparent_output.has_value()) {
    tx.outputs.push_back(TxOutV2{.kind = TxOutputKind::TRANSPARENT, .body = *transparent_output});
  }
  tx.outputs.push_back(TxOutV2{.kind = TxOutputKind::CONFIDENTIAL, .body = confidential_output});
  tx.fee = fee;

  const auto transparent_output_value = transparent_output.has_value() ? transparent_output->value : 0;
  const auto excess_blind = crypto::combine_blinds(std::span<const crypto::Blind32>(&confidential_output_blind, 1), 0);
  if (!excess_blind.has_value()) {
    if (err) *err = "failed to compute confidential output excess blind";
    return std::nullopt;
  }
  const auto excess_commitment = crypto::confidential_amount_commitment(
      transparent_input_value - transparent_output_value - confidential_output_value - fee, *excess_blind);
  if (!excess_commitment.has_value()) {
    if (err) *err = "failed to compute confidential output excess commitment";
    return std::nullopt;
  }
  tx.balance_proof.excess_commitment = *excess_commitment;
  if (!sign_balance_proof(tx, *excess_blind, crypto::sha256d(Bytes{'b', 'a', 'l', 'o'}), err)) return std::nullopt;
  if (!resign_transparent_input(tx, transparent_owner_private_key_32, 0, err)) return std::nullopt;
  (void)prev_out;
  return tx;
}

std::optional<TxV2> build_txv2_confidential_to_transparent(
    const ConfidentialOwnedCoin& coin, const TransparentTxOutV2& transparent_output, std::uint64_t fee,
    const Hash32& spend_authorization_nonce, const Hash32& excess_authorization_nonce, std::string* err) {
  if (coin.amount < transparent_output.value + fee) {
    if (err) *err = "confidential input value too small";
    return std::nullopt;
  }

  TxV2 tx;
  tx.inputs.push_back(TxInV2{
      .prev_txid = coin.outpoint.txid,
      .prev_index = coin.outpoint.index,
      .sequence = 0xFFFFFFFF,
      .kind = TxInputKind::CONFIDENTIAL,
      .witness = ConfidentialInputWitnessV2{coin.one_time_pubkey, Sig64{}},
  });
  tx.outputs.push_back(TxOutV2{.kind = TxOutputKind::TRANSPARENT, .body = transparent_output});
  tx.fee = fee;

  const auto excess_commitment = crypto::confidential_amount_commitment(
      coin.amount - transparent_output.value - fee, coin.value_blind);
  if (!excess_commitment.has_value()) {
    if (err) *err = "failed to compute confidential input excess commitment";
    return std::nullopt;
  }
  tx.balance_proof.excess_commitment = *excess_commitment;
  if (!sign_balance_proof(tx, coin.value_blind, excess_authorization_nonce, err)) return std::nullopt;
  if (!sign_confidential_input(tx, 0, coin.spend_secret, spend_authorization_nonce, err)) return std::nullopt;
  return tx;
}

}  // namespace finalis::wallet
