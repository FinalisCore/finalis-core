// SPDX-License-Identifier: MIT

#include "test_framework.hpp"

#include <stdexcept>
#include <variant>

#include "common/address.hpp"
#include "codec/bytes.hpp"
#include "crypto/ed25519.hpp"
#include "crypto/hash.hpp"
#include "consensus/confidential_supply.hpp"
#include "utxo/confidential_tx.hpp"
#include "utxo/validate.hpp"

using namespace finalis;

namespace {

PubKey33 compressed_key(std::uint8_t seed) {
  Hash32 scalar{};
  scalar.fill(seed);
  const auto pubkey = crypto::secp256k1_pubkey_from_scalar(scalar);
  if (!pubkey.has_value()) throw std::runtime_error("secp pubkey derivation failed");
  return *pubkey;
}

crypto::Commitment33 commitment(std::uint8_t seed) {
  return crypto::transparent_amount_commitment(static_cast<std::uint64_t>(seed) + 1);
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

crypto::KeyPair key_from_byte(std::uint8_t seed) {
  std::array<std::uint8_t, 32> secret{};
  secret.fill(seed);
  auto kp = crypto::keypair_from_seed32(secret);
  if (!kp.has_value()) throw std::runtime_error("key derivation failed");
  return *kp;
}

Bytes make_p2pkh_script_sig(const Sig64& sig, const PubKey32& pub) {
  Bytes ss;
  ss.push_back(0x40);
  ss.insert(ss.end(), sig.begin(), sig.end());
  ss.push_back(0x20);
  ss.insert(ss.end(), pub.begin(), pub.end());
  return ss;
}

Bytes validator_register_script(const PubKey32& validator_pub) {
  Bytes s{'S', 'C', 'V', 'A', 'L', 'R', 'E', 'G'};
  s.insert(s.end(), validator_pub.begin(), validator_pub.end());
  return s;
}

Bytes validator_join_request_script(const PubKey32& validator_pub, const PubKey32& payout_pub, const Sig64& pop) {
  Bytes s{'S', 'C', 'V', 'A', 'L', 'J', 'R', 'Q'};
  s.insert(s.end(), validator_pub.begin(), validator_pub.end());
  s.insert(s.end(), payout_pub.begin(), payout_pub.end());
  s.insert(s.end(), pop.begin(), pop.end());
  return s;
}

void resign_input0(TxV2& tx, const crypto::KeyPair& from) {
  auto msg = finalis::signing_message_for_input_v2(tx, 0);
  if (!msg.has_value()) throw std::runtime_error("sighash failed");
  auto sig = crypto::ed25519_sign(*msg, from.private_key);
  if (!sig.has_value()) throw std::runtime_error("sign failed");
  std::get<TransparentInputWitnessV2>(tx.inputs[0].witness).script_sig = make_p2pkh_script_sig(*sig, from.public_key);
}

void sign_balance_proof(TxV2& tx, const crypto::Blind32& excess_blind, std::uint8_t aux_seed) {
  const auto pubkey = crypto::excess_xonly_pubkey_from_scalar(excess_blind);
  if (!pubkey.has_value()) throw std::runtime_error("excess pubkey derivation failed");
  tx.balance_proof.excess_pubkey = *pubkey;
  tx.balance_proof.excess_sig.fill(0);
  const auto msg = finalis::balance_proof_message_v2(tx);
  if (!msg.has_value()) throw std::runtime_error("balance proof sighash failed");
  const auto sig = crypto::sign_excess_authorization(*msg, excess_blind, nonce_from_byte(aux_seed));
  if (!sig.has_value()) throw std::runtime_error("excess signature failed");
  tx.balance_proof.excess_sig = *sig;
}

void sign_confidential_input(TxV2& tx, std::size_t input_index, const crypto::Blind32& spend_secret, std::uint8_t aux_seed) {
  const auto pubkey = crypto::secp256k1_pubkey_from_scalar(spend_secret.bytes);
  if (!pubkey.has_value()) throw std::runtime_error("confidential input pubkey derivation failed");
  auto& witness = std::get<ConfidentialInputWitnessV2>(tx.inputs.at(input_index).witness);
  witness.one_time_pubkey = *pubkey;
  witness.spend_sig.fill(0);
  const auto msg = finalis::signing_message_for_input_v2(tx, static_cast<std::uint32_t>(input_index));
  if (!msg.has_value()) throw std::runtime_error("confidential input sighash failed");
  Hash32 msg32{};
  std::copy(msg->begin(), msg->end(), msg32.begin());
  const auto sig = crypto::sign_schnorr_authorization(msg32, spend_secret, nonce_from_byte(aux_seed));
  if (!sig.has_value()) throw std::runtime_error("confidential input signature failed");
  witness.spend_sig = *sig;
}

TxV2 make_transparent_only_v2_tx(const OutPoint& op, const crypto::KeyPair& from, const PubKey32& to_pub,
                                 std::uint64_t value_in, std::uint64_t value_out) {
  const auto to_pkh = crypto::h160(Bytes(to_pub.begin(), to_pub.end()));
  TxV2 tx;
  tx.inputs.push_back(TxInV2{
      .prev_txid = op.txid,
      .prev_index = op.index,
      .sequence = 0xFFFFFFFF,
      .kind = TxInputKind::Transparent,
      .witness = TransparentInputWitnessV2{},
  });
  tx.outputs.push_back(TxOutV2{
      .kind = TxOutputKind::Transparent,
      .body = TransparentTxOutV2{value_out, address::p2pkh_script_pubkey(to_pkh)},
  });
  tx.fee = value_in - value_out;
  tx.balance_proof.excess_commitment = crypto::Commitment33{};
  tx.balance_proof.excess_pubkey.fill(0);
  tx.balance_proof.excess_sig.fill(0);
  resign_input0(tx, from);
  return tx;
}

TxV2 make_confidential_input_v2_tx(const OutPoint& op, const crypto::Blind32& one_time_secret,
                                   const crypto::Blind32& input_value_blind, const PubKey32& to_pub,
                                   std::uint64_t value_in, std::uint64_t value_out) {
  const auto one_time_pubkey = crypto::secp256k1_pubkey_from_scalar(one_time_secret.bytes);
  if (!one_time_pubkey.has_value()) throw std::runtime_error("one_time pubkey derivation failed");
  const auto to_pkh = crypto::h160(Bytes(to_pub.begin(), to_pub.end()));

  TxV2 tx;
  tx.inputs.push_back(TxInV2{
      .prev_txid = op.txid,
      .prev_index = op.index,
      .sequence = 0xFFFFFFFF,
      .kind = TxInputKind::Confidential,
      .witness = ConfidentialInputWitnessV2{*one_time_pubkey, Sig64{}},
  });
  tx.outputs.push_back(TxOutV2{
      .kind = TxOutputKind::Transparent,
      .body = TransparentTxOutV2{value_out, address::p2pkh_script_pubkey(to_pkh)},
  });
  tx.fee = value_in - value_out;
  const auto excess = crypto::confidential_amount_commitment(0, input_value_blind);
  if (!excess.has_value()) throw std::runtime_error("confidential input excess commitment failed");
  tx.balance_proof.excess_commitment = *excess;
  sign_balance_proof(tx, input_value_blind, 0x83);
  sign_confidential_input(tx, 0, one_time_secret, 0x84);
  return tx;
}

TxV2 make_confidential_output_v2_tx(const OutPoint& op, const crypto::KeyPair& from, std::uint64_t value_in,
                                    std::uint64_t transparent_value_out, std::uint64_t confidential_value,
                                    const crypto::Blind32& confidential_blind, const ConfidentialTxOutV2& confidential_out,
                                    std::uint64_t fee) {
  TxV2 tx;
  tx.inputs.push_back(TxInV2{
      .prev_txid = op.txid,
      .prev_index = op.index,
      .sequence = 0xFFFFFFFF,
      .kind = TxInputKind::Transparent,
      .witness = TransparentInputWitnessV2{},
  });
  if (transparent_value_out > 0) {
    const auto to = key_from_byte(0x66);
    tx.outputs.push_back(TxOutV2{
        .kind = TxOutputKind::Transparent,
        .body = TransparentTxOutV2{transparent_value_out,
                                   address::p2pkh_script_pubkey(crypto::h160(Bytes(to.public_key.begin(), to.public_key.end())))},
    });
  }
  tx.outputs.push_back(TxOutV2{.kind = TxOutputKind::Confidential, .body = confidential_out});
  tx.fee = fee;

  const auto blind_excess = crypto::combine_blinds(std::span<const crypto::Blind32>(&confidential_blind, 1), 0);
  if (!blind_excess.has_value()) throw std::runtime_error("blind sum failed");
  const auto excess = crypto::confidential_amount_commitment(value_in - transparent_value_out - confidential_value - fee,
                                                             *blind_excess);
  if (!excess.has_value()) throw std::runtime_error("excess commitment failed");
  tx.balance_proof.excess_commitment = *excess;
  sign_balance_proof(tx, *blind_excess, 0x5A);

  resign_input0(tx, from);
  return tx;
}

ConfidentialTxOutV2 make_valid_confidential_output(std::uint8_t seed, std::uint64_t value) {
  const auto blind = blind_from_byte(static_cast<std::uint8_t>(seed + 1));
  const auto commitment = crypto::confidential_amount_commitment(value, blind);
  if (!commitment.has_value()) throw std::runtime_error("confidential commitment failed");
  const auto proof = crypto::sign_output_range_proof(*commitment, value, blind, nonce_from_byte(static_cast<std::uint8_t>(seed + 2)));
  if (!proof.has_value()) throw std::runtime_error("rangeproof sign failed");
  return ConfidentialTxOutV2{
      .value_commitment = *commitment,
      .one_time_pubkey = compressed_key(static_cast<std::uint8_t>(seed + 3)),
      .ephemeral_pubkey = compressed_key(static_cast<std::uint8_t>(seed + 4)),
      .scan_tag = crypto::ScanTag{static_cast<std::uint8_t>(seed + 5)},
      .range_proof = *proof,
      .memo = Bytes{0x01, 0x02},
  };
}

}  // namespace

TEST(test_confidential_backend_status_reports_backend_capabilities_consistently) {
  const auto& status = crypto::confidential_backend_status();
  ASSERT_TRUE(status.secp256k1_available);
  ASSERT_TRUE(status.zkp_backend_available == status.rangeproof_backend_available);
  ASSERT_TRUE(status.confidential_outputs_supported == status.rangeproof_backend_available);
  ASSERT_TRUE(status.excess_authorization_available == status.zkp_backend_available);
}

TEST(test_tx_v1_parser_rejects_v2_bytes) {
  TxV2 tx;
  tx.inputs.push_back(TxInV2{
      .prev_txid = zero_hash(),
      .prev_index = 7,
      .sequence = 0xFFFFFFFF,
      .kind = TxInputKind::Transparent,
      .witness = TransparentInputWitnessV2{Bytes{0x51}},
  });
  tx.outputs.push_back(TxOutV2{
      .kind = TxOutputKind::Transparent,
      .body = TransparentTxOutV2{123, Bytes{0x51}},
  });
  tx.fee = 5;
  tx.balance_proof.excess_commitment = commitment(0x31);
  tx.balance_proof.excess_pubkey.fill(0x21);
  tx.balance_proof.excess_sig.fill(0x22);

  const auto ser = tx.serialize();
  ASSERT_TRUE(!Tx::parse(ser).has_value());
}

TEST(test_confidential_tx_v2_roundtrip_and_anytx_dispatch) {
  TxV2 tx;
  Hash32 prev{};
  prev.fill(0x11);
  tx.inputs.push_back(TxInV2{
      .prev_txid = prev,
      .prev_index = 3,
      .sequence = 9,
      .kind = TxInputKind::Confidential,
      .witness = ConfidentialInputWitnessV2{compressed_key(0x41), Sig64{}},
  });
  std::get<ConfidentialInputWitnessV2>(tx.inputs.back().witness).spend_sig.fill(0x33);

  tx.outputs.push_back(TxOutV2{
      .kind = TxOutputKind::Transparent,
      .body = TransparentTxOutV2{50, Bytes{0x51}},
  });
  tx.outputs.push_back(TxOutV2{
      .kind = TxOutputKind::Confidential,
      .body = ConfidentialTxOutV2{
          .value_commitment = commitment(0x51),
          .one_time_pubkey = compressed_key(0x61),
          .ephemeral_pubkey = compressed_key(0x71),
          .scan_tag = crypto::ScanTag{0x44},
          .range_proof = crypto::ProofBytes{Bytes{0xAA, 0xBB, 0xCC}},
          .memo = Bytes{0x01, 0x02, 0x03},
      },
  });
  tx.lock_time = 17;
  tx.fee = 9;
  tx.balance_proof.excess_commitment = commitment(0x81);
  tx.balance_proof.excess_pubkey.fill(0x54);
  tx.balance_proof.excess_sig.fill(0x55);

  const auto ser = tx.serialize();
  auto parsed = TxV2::parse(ser);
  ASSERT_TRUE(parsed.has_value());
  ASSERT_EQ(*parsed, tx);
  ASSERT_EQ(parsed->serialize(), ser);

  auto any = parse_any_tx(ser);
  ASSERT_TRUE(any.has_value());
  ASSERT_TRUE(std::holds_alternative<TxV2>(*any));
  ASSERT_EQ(std::get<TxV2>(*any), tx);
  ASSERT_EQ(serialize_any_tx(*any), ser);
  ASSERT_EQ(txid_any(*any), tx.txid());
}

TEST(test_parse_any_tx_dispatches_v1_and_rejects_unknown_version) {
  Tx tx;
  tx.version = 1;
  tx.inputs.push_back(TxIn{zero_hash(), 0, Bytes{0x51}, 0xFFFFFFFF});
  tx.outputs.push_back(TxOut{7, Bytes{0x51}});

  const auto v1_ser = tx.serialize();
  auto parsed_v1 = parse_any_tx(v1_ser);
  ASSERT_TRUE(parsed_v1.has_value());
  ASSERT_TRUE(std::holds_alternative<Tx>(*parsed_v1));
  ASSERT_EQ(std::get<Tx>(*parsed_v1).serialize(), v1_ser);

  Bytes bad = v1_ser;
  bad[0] = 0x03;
  bad[1] = 0x00;
  bad[2] = 0x00;
  bad[3] = 0x00;
  ASSERT_TRUE(!parse_any_tx(bad).has_value());
}

TEST(test_tx_v2_rejects_unknown_input_or_output_kinds) {
  codec::ByteWriter w;
  w.u32le(2);
  w.varint(1);
  w.bytes_fixed(zero_hash());
  w.u32le(0);
  w.u32le(0xFFFFFFFF);
  w.u8(9);
  w.varint(0);
  w.varint(0);
  w.u32le(0);
  w.u64le(0);
  w.bytes_fixed(commitment(0x91).bytes);
  Sig64 sig{};
  w.bytes_fixed(sig);
  ASSERT_TRUE(!TxV2::parse(w.take()).has_value());

  codec::ByteWriter w2;
  w2.u32le(2);
  w2.varint(0);
  w2.varint(1);
  w2.u8(9);
  w2.u32le(0);
  w2.u64le(0);
  w2.bytes_fixed(commitment(0x92).bytes);
  w2.bytes_fixed(sig);
  ASSERT_TRUE(!TxV2::parse(w2.take()).has_value());
}

TEST(test_validate_any_tx_dispatches_v1_against_utxoset_v2) {
  const auto from = key_from_byte(0x21);
  const auto to = key_from_byte(0x22);
  const auto from_pkh = crypto::h160(Bytes(from.public_key.begin(), from.public_key.end()));

  OutPoint op{};
  op.txid.fill(0x44);
  op.index = 0;
  TxOut prev{10'000, address::p2pkh_script_pubkey(from_pkh)};
  UtxoSetV2 view;
  view[op] = UtxoEntryV2(prev);

  Tx tx;
  tx.version = 1;
  tx.inputs.push_back(TxIn{op.txid, op.index, Bytes{}, 0xFFFFFFFF});
  tx.outputs.push_back(TxOut{9'000, address::p2pkh_script_pubkey(crypto::h160(Bytes(to.public_key.begin(), to.public_key.end())))});
  auto msg = signing_message_for_input(tx, 0);
  ASSERT_TRUE(msg.has_value());
  auto sig = crypto::ed25519_sign(*msg, from.private_key);
  ASSERT_TRUE(sig.has_value());
  tx.inputs[0].script_sig = make_p2pkh_script_sig(*sig, from.public_key);

  const auto result = validate_any_tx(AnyTx{tx}, 1, view, nullptr);
  ASSERT_TRUE(result.ok);
  ASSERT_EQ(result.cost.fee, 1'000u);
  ASSERT_EQ(result.cost.confidential_verify_weight, 0u);
}

TEST(test_validate_tx_v2_accepts_transparent_only) {
  const auto from = key_from_byte(0x25);
  const auto to = key_from_byte(0x26);
  const auto from_pkh = crypto::h160(Bytes(from.public_key.begin(), from.public_key.end()));

  OutPoint op{};
  op.txid.fill(0x46);
  op.index = 0;
  UtxoSetV2 view;
  view[op] = UtxoEntryV2(TxOut{10'000, address::p2pkh_script_pubkey(from_pkh)});

  auto tx = make_transparent_only_v2_tx(op, from, to.public_key, 10'000, 9'250);
  ConfidentialPolicy policy;
  SpecialValidationContext ctx;
  ctx.current_height = 100;
  ctx.confidential_policy = &policy;

  const auto result = validate_tx_v2(tx, 1, view, &ctx);
  ASSERT_TRUE(result.ok);
  ASSERT_EQ(result.cost.fee, 750u);
  ASSERT_EQ(result.cost.confidential_verify_weight, 0u);
}

TEST(test_validate_tx_v2_accepts_transparent_input_with_confidential_output) {
  const auto from = key_from_byte(0x27);
  const auto from_pkh = crypto::h160(Bytes(from.public_key.begin(), from.public_key.end()));

  OutPoint op{};
  op.txid.fill(0x47);
  op.index = 0;
  UtxoSetV2 view;
  view[op] = UtxoEntryV2(TxOut{10'000, address::p2pkh_script_pubkey(from_pkh)});

  const auto valid_blind = blind_from_byte(0x71);
  ConfidentialTxOutV2 confidential_out = crypto::confidential_backend_status().confidential_outputs_supported
                                             ? make_valid_confidential_output(0x70, 9'000)
                                             : ConfidentialTxOutV2{
                                                   .value_commitment = commitment(0x70),
                                                   .one_time_pubkey = compressed_key(0x71),
                                                   .ephemeral_pubkey = compressed_key(0x72),
                                                   .scan_tag = crypto::ScanTag{0x73},
                                                   .range_proof = crypto::ProofBytes{Bytes{0xA1, 0xB2, 0xC3, 0xD4}},
                                                   .memo = Bytes{0x01, 0x02},
                                               };
  auto tx = make_confidential_output_v2_tx(op, from, 10'000, 500, 9'000, valid_blind, confidential_out, 500);

  ConfidentialPolicy policy;
  SpecialValidationContext ctx;
  ctx.current_height = 100;
  ctx.confidential_policy = &policy;

  const auto result = validate_tx_v2(tx, 1, view, &ctx);
  if (!crypto::confidential_backend_status().confidential_outputs_supported) {
    ASSERT_TRUE(!result.ok);
    ASSERT_TRUE(result.error.find("unsupported by zkp backend") != std::string::npos);
  } else {
    if (!result.ok) throw std::runtime_error("accept confidential error: " + result.error);
    ASSERT_TRUE(result.ok);
    ASSERT_EQ(result.cost.fee, 500u);
    // range proof bytes + output charge + balance-proof excess signature + tx base.
    ASSERT_TRUE(!crypto::commitment_is_identity(tx.balance_proof.excess_commitment));
    ASSERT_EQ(result.cost.confidential_verify_weight,
              confidential_out.range_proof.bytes.size() + kConfidentialOutputVerifyWeight +
                  kConfidentialSignatureVerifyWeight + kConfidentialTxBaseVerifyWeight);

    UtxoSetV2 applied = view;
    apply_any_tx_to_utxo(AnyTx{tx}, applied);
    const auto txid = tx.txid();
    const auto it = applied.find(OutPoint{txid, 1});
    ASSERT_TRUE(it != applied.end());
    ASSERT_EQ(it->second.kind, UtxoOutputKind::Confidential);
  }
}

TEST(test_validate_tx_v2_accepts_confidential_input_with_transparent_output) {
  if (!crypto::confidential_backend_status().confidential_outputs_supported) {
    return;
  }

  const auto recipient = key_from_byte(0x34);
  const auto spend_secret = blind_from_byte(0x35);
  const auto input_blind = blind_from_byte(0x36);
  const auto input_pubkey = crypto::secp256k1_pubkey_from_scalar(spend_secret.bytes);
  ASSERT_TRUE(input_pubkey.has_value());
  const auto input_commitment = crypto::confidential_amount_commitment(10'000, input_blind);
  ASSERT_TRUE(input_commitment.has_value());

  OutPoint op{};
  op.txid.fill(0x5B);
  op.index = 0;
  UtxoSetV2 view;
  UtxoEntryV2 entry;
  entry.kind = UtxoOutputKind::Confidential;
  entry.body = UtxoConfidentialData{
      .value_commitment = *input_commitment,
      .one_time_pubkey = *input_pubkey,
      .ephemeral_pubkey = compressed_key(0x37),
      .scan_tag = crypto::ScanTag{0x38},
      .memo = Bytes{0x01},
  };
  view[op] = entry;

  auto tx = make_confidential_input_v2_tx(op, spend_secret, input_blind, recipient.public_key, 10'000, 9'500);

  ConfidentialPolicy policy;
  SpecialValidationContext ctx;
  ctx.current_height = 300;
  ctx.confidential_policy = &policy;

  const auto result = validate_tx_v2(tx, 1, view, &ctx);
  if (!result.ok) throw std::runtime_error("accept confidential-input error: " + result.error);
  ASSERT_TRUE(result.ok);
  ASSERT_EQ(result.cost.fee, 500u);
  // One confidential input signature + balance-proof excess signature + tx base; no range proofs.
  ASSERT_TRUE(!crypto::commitment_is_identity(tx.balance_proof.excess_commitment));
  ASSERT_EQ(result.cost.confidential_verify_weight, 2 * kConfidentialSignatureVerifyWeight + kConfidentialTxBaseVerifyWeight);
}

TEST(test_validate_tx_v2_rejects_duplicate_nullifier_like_confidential_spend_id) {
  if (!crypto::confidential_backend_status().confidential_outputs_supported) {
    return;
  }

  const auto to = key_from_byte(0x34);
  const auto shared_one_time_secret = blind_from_byte(0x35);
  const auto shared_one_time_pubkey = crypto::secp256k1_pubkey_from_scalar(shared_one_time_secret.bytes);
  ASSERT_TRUE(shared_one_time_pubkey.has_value());

  OutPoint op0{};
  op0.txid.fill(0x7A);
  op0.index = 0;
  OutPoint op1{};
  op1.txid.fill(0x7B);
  op1.index = 0;

  UtxoSetV2 view;
  UtxoConfidentialData prev0{};
  prev0.value_commitment = *crypto::confidential_amount_commitment(6'000, blind_from_byte(0x36));
  prev0.one_time_pubkey = *shared_one_time_pubkey;
  prev0.ephemeral_pubkey = compressed_key(0x37);
  prev0.scan_tag.value = 0x11;
  prev0.memo = Bytes{};
  UtxoConfidentialData prev1{};
  prev1.value_commitment = *crypto::confidential_amount_commitment(5'000, blind_from_byte(0x38));
  prev1.one_time_pubkey = *shared_one_time_pubkey;
  prev1.ephemeral_pubkey = compressed_key(0x39);
  prev1.scan_tag.value = 0x12;
  prev1.memo = Bytes{};
  UtxoEntryV2 entry0;
  entry0.kind = UtxoOutputKind::Confidential;
  entry0.body = std::move(prev0);
  UtxoEntryV2 entry1;
  entry1.kind = UtxoOutputKind::Confidential;
  entry1.body = std::move(prev1);
  view[op0] = std::move(entry0);
  view[op1] = std::move(entry1);

  TxV2 tx;
  tx.inputs.push_back(TxInV2{
      .prev_txid = op0.txid,
      .prev_index = op0.index,
      .sequence = 0xFFFFFFFF,
      .kind = TxInputKind::Confidential,
      .witness = ConfidentialInputWitnessV2{*shared_one_time_pubkey, Sig64{}},
  });
  tx.inputs.push_back(TxInV2{
      .prev_txid = op1.txid,
      .prev_index = op1.index,
      .sequence = 0xFFFFFFFF,
      .kind = TxInputKind::Confidential,
      .witness = ConfidentialInputWitnessV2{*shared_one_time_pubkey, Sig64{}},
  });
  tx.outputs.push_back(TxOutV2{
      .kind = TxOutputKind::Transparent,
      .body = TransparentTxOutV2{10'500, address::p2pkh_script_pubkey(crypto::h160(Bytes(to.public_key.begin(), to.public_key.end())))},
  });
  tx.fee = 500;

  const auto total_input_blind =
      crypto::combine_blinds(std::array<crypto::Blind32, 2>{blind_from_byte(0x36), blind_from_byte(0x38)}, 0);
  ASSERT_TRUE(total_input_blind.has_value());
  const auto excess = crypto::confidential_amount_commitment(0, *total_input_blind);
  ASSERT_TRUE(excess.has_value());
  tx.balance_proof.excess_commitment = *excess;
  sign_balance_proof(tx, *total_input_blind, 0x3A);
  sign_confidential_input(tx, 0, shared_one_time_secret, 0x3B);
  sign_confidential_input(tx, 1, shared_one_time_secret, 0x3C);

  ConfidentialPolicy policy;
  SpecialValidationContext ctx;
  ctx.current_height = 1;
  ctx.confidential_policy = &policy;

  const auto result = validate_tx_v2(tx, 1, view, &ctx);
  ASSERT_TRUE(!result.ok);
  ASSERT_TRUE(result.error.find("duplicate confidential spend id") != std::string::npos);
}

TEST(test_validate_tx_v2_rejects_invalid_confidential_input_authorization) {
  if (!crypto::confidential_backend_status().confidential_outputs_supported) {
    return;
  }

  const auto recipient = key_from_byte(0x39);
  const auto spend_secret = blind_from_byte(0x3A);
  const auto input_blind = blind_from_byte(0x3B);
  const auto input_pubkey = crypto::secp256k1_pubkey_from_scalar(spend_secret.bytes);
  ASSERT_TRUE(input_pubkey.has_value());
  const auto input_commitment = crypto::confidential_amount_commitment(10'000, input_blind);
  ASSERT_TRUE(input_commitment.has_value());

  OutPoint op{};
  op.txid.fill(0x5C);
  op.index = 0;
  UtxoSetV2 view;
  UtxoEntryV2 entry;
  entry.kind = UtxoOutputKind::Confidential;
  entry.body = UtxoConfidentialData{
      .value_commitment = *input_commitment,
      .one_time_pubkey = *input_pubkey,
      .ephemeral_pubkey = compressed_key(0x3C),
      .scan_tag = crypto::ScanTag{0x3D},
      .memo = Bytes{},
  };
  view[op] = entry;

  auto tx = make_confidential_input_v2_tx(op, spend_secret, input_blind, recipient.public_key, 10'000, 9'500);
  std::get<ConfidentialInputWitnessV2>(tx.inputs[0].witness).spend_sig[0] ^= 0x01;

  ConfidentialPolicy policy;
  SpecialValidationContext ctx;
  ctx.current_height = 300;
  ctx.confidential_policy = &policy;

  const auto result = validate_tx_v2(tx, 1, view, &ctx);
  ASSERT_TRUE(!result.ok);
  ASSERT_TRUE(result.error.find("confidential input authorization invalid") != std::string::npos);
}

TEST(test_validate_tx_v2_rejects_bad_confidential_commitment_or_keys) {
  const auto from = key_from_byte(0x28);
  const auto from_pkh = crypto::h160(Bytes(from.public_key.begin(), from.public_key.end()));

  OutPoint op{};
  op.txid.fill(0x48);
  op.index = 0;
  UtxoSetV2 view;
  view[op] = UtxoEntryV2(TxOut{10'000, address::p2pkh_script_pubkey(from_pkh)});

  const auto bad_blind = blind_from_byte(0x75);
  ConfidentialTxOutV2 confidential_out = crypto::confidential_backend_status().confidential_outputs_supported
                                             ? make_valid_confidential_output(0x74, 9'500)
                                             : ConfidentialTxOutV2{
                                                   .value_commitment = commitment(0x74),
                                                   .one_time_pubkey = compressed_key(0x75),
                                                   .ephemeral_pubkey = compressed_key(0x76),
                                                   .scan_tag = crypto::ScanTag{0x77},
                                                   .range_proof = crypto::ProofBytes{Bytes{0x01}},
                                                   .memo = Bytes{},
                                               };
  auto tx = make_confidential_output_v2_tx(op, from, 10'000, 0, 9'500, bad_blind, confidential_out, 500);
  std::get<ConfidentialTxOutV2>(tx.outputs[0].body).value_commitment.bytes[0] = 0x04;
  resign_input0(tx, from);

  ConfidentialPolicy policy;
  SpecialValidationContext ctx;
  ctx.current_height = 100;
  ctx.confidential_policy = &policy;

  const auto result = validate_tx_v2(tx, 1, view, &ctx);
  ASSERT_TRUE(!result.ok);
  if (!crypto::confidential_backend_status().confidential_outputs_supported) {
    ASSERT_TRUE(result.error.find("unsupported by zkp backend") != std::string::npos);
  } else {
    if (result.error.find("commitment") == std::string::npos) {
      throw std::runtime_error("bad commitment error: " + result.error);
    }
    ASSERT_TRUE(result.error.find("commitment") != std::string::npos);
  }
}

TEST(test_validate_tx_v2_rejects_confidential_range_proof_or_memo_bounds) {
  const auto from = key_from_byte(0x29);
  const auto from_pkh = crypto::h160(Bytes(from.public_key.begin(), from.public_key.end()));

  OutPoint op{};
  op.txid.fill(0x49);
  op.index = 0;
  UtxoSetV2 view;
  view[op] = UtxoEntryV2(TxOut{10'000, address::p2pkh_script_pubkey(from_pkh)});

  const auto bounds_blind = blind_from_byte(0x79);
  ConfidentialTxOutV2 confidential_out = crypto::confidential_backend_status().confidential_outputs_supported
                                             ? make_valid_confidential_output(0x78, 9'500)
                                             : ConfidentialTxOutV2{
                                                   .value_commitment = commitment(0x78),
                                                   .one_time_pubkey = compressed_key(0x79),
                                                   .ephemeral_pubkey = compressed_key(0x7A),
                                                   .scan_tag = crypto::ScanTag{0x7B},
                                                   .range_proof = crypto::ProofBytes{Bytes{0x10, 0x11, 0x12}},
                                                   .memo = Bytes{0x01, 0x02, 0x03},
                                               };
  auto tx = make_confidential_output_v2_tx(op, from, 10'000, 0, 9'500, bounds_blind, confidential_out, 500);

  ConfidentialPolicy policy;
  policy.max_range_proof_bytes = 2;
  policy.max_memo_bytes = 2;
  SpecialValidationContext ctx;
  ctx.current_height = 100;
  ctx.confidential_policy = &policy;

  const auto result = validate_tx_v2(tx, 1, view, &ctx);
  ASSERT_TRUE(!result.ok);
  if (!crypto::confidential_backend_status().confidential_outputs_supported) {
    ASSERT_TRUE(result.error.find("unsupported by zkp backend") != std::string::npos);
  } else {
    if (!(result.error.find("range proof too large") != std::string::npos ||
          result.error.find("memo too large") != std::string::npos)) {
      throw std::runtime_error("bounds error: " + result.error);
    }
    ASSERT_TRUE(result.error.find("range proof too large") != std::string::npos ||
                result.error.find("memo too large") != std::string::npos);
  }
}

TEST(test_validate_tx_v2_rejects_commitment_balance_mismatch) {
  const auto from = key_from_byte(0x2A);
  const auto from_pkh = crypto::h160(Bytes(from.public_key.begin(), from.public_key.end()));

  OutPoint op{};
  op.txid.fill(0x4A);
  op.index = 0;
  UtxoSetV2 view;
  view[op] = UtxoEntryV2(TxOut{10'000, address::p2pkh_script_pubkey(from_pkh)});

  const auto mismatch_blind = blind_from_byte(0x7D);
  ConfidentialTxOutV2 confidential_out = crypto::confidential_backend_status().confidential_outputs_supported
                                             ? make_valid_confidential_output(0x7C, 9'500)
                                             : ConfidentialTxOutV2{
                                                   .value_commitment = commitment(0x7C),
                                                   .one_time_pubkey = compressed_key(0x7D),
                                                   .ephemeral_pubkey = compressed_key(0x7E),
                                                   .scan_tag = crypto::ScanTag{0x7F},
                                                   .range_proof = crypto::ProofBytes{Bytes{0x20, 0x21}},
                                                   .memo = Bytes{},
                                               };
  auto tx = make_confidential_output_v2_tx(op, from, 10'000, 0, 9'500, mismatch_blind, confidential_out, 500);
  tx.balance_proof.excess_commitment = commitment(0x55);
  tx.balance_proof.excess_pubkey.fill(0);
  tx.balance_proof.excess_sig.fill(0);
  resign_input0(tx, from);

  ConfidentialPolicy policy;
  SpecialValidationContext ctx;
  ctx.current_height = 100;
  ctx.confidential_policy = &policy;

  const auto result = validate_tx_v2(tx, 1, view, &ctx);
  ASSERT_TRUE(!result.ok);
  if (!crypto::confidential_backend_status().confidential_outputs_supported) {
    ASSERT_TRUE(result.error.find("unsupported by zkp backend") != std::string::npos);
  } else {
    if (result.error.find("balance mismatch") == std::string::npos) {
      throw std::runtime_error("mismatch error: " + result.error);
    }
    ASSERT_TRUE(result.error.find("balance mismatch") != std::string::npos);
  }
}

TEST(test_validate_tx_v2_rejects_invalid_excess_authorization) {
  if (!crypto::confidential_backend_status().confidential_outputs_supported) {
    return;
  }

  const auto from = key_from_byte(0x33);
  const auto from_pkh = crypto::h160(Bytes(from.public_key.begin(), from.public_key.end()));

  OutPoint op{};
  op.txid.fill(0x5A);
  op.index = 0;
  UtxoSetV2 view;
  view[op] = UtxoEntryV2(TxOut{10'000, address::p2pkh_script_pubkey(from_pkh)});

  const auto blind = blind_from_byte(0x6A);
  const auto confidential_out = make_valid_confidential_output(0x69, 9'000);
  auto tx = make_confidential_output_v2_tx(op, from, 10'000, 500, 9'000, blind, confidential_out, 500);
  tx.balance_proof.excess_sig[0] ^= 0x01;
  resign_input0(tx, from);

  ConfidentialPolicy policy;
  SpecialValidationContext ctx;
  ctx.current_height = 200;
  ctx.confidential_policy = &policy;

  const auto result = validate_tx_v2(tx, 1, view, &ctx);
  ASSERT_TRUE(!result.ok);
  ASSERT_TRUE(result.error.find("excess authorization invalid") != std::string::npos);
}

TEST(test_validate_tx_v2_rejects_validator_join_request_without_matching_register_output) {
  const auto from = key_from_byte(0x40);
  const auto validator = key_from_byte(0x41);
  const auto payout = key_from_byte(0x42);
  const auto from_pkh = crypto::h160(Bytes(from.public_key.begin(), from.public_key.end()));

  OutPoint op{};
  op.txid.fill(0x6A);
  op.index = 0;
  UtxoSetV2 view;
  view[op] = UtxoEntryV2(TxOut{10'000, address::p2pkh_script_pubkey(from_pkh)});

  TxV2 tx;
  tx.inputs.push_back(TxInV2{
      .prev_txid = op.txid,
      .prev_index = op.index,
      .sequence = 0xFFFFFFFF,
      .kind = TxInputKind::Transparent,
      .witness = TransparentInputWitnessV2{},
  });
  const auto pop = crypto::ed25519_sign(validator_join_request_pop_message(validator.public_key, payout.public_key),
                                        validator.private_key);
  ASSERT_TRUE(pop.has_value());
  tx.outputs.push_back(TxOutV2{.kind = TxOutputKind::Transparent,
                               .body = TransparentTxOutV2{0, validator_join_request_script(validator.public_key,
                                                                                           payout.public_key, *pop)}});
  tx.outputs.push_back(TxOutV2{
      .kind = TxOutputKind::Transparent,
      .body = TransparentTxOutV2{9'500,
                                 address::p2pkh_script_pubkey(crypto::h160(Bytes(payout.public_key.begin(),
                                                                                payout.public_key.end())))}
  });
  tx.fee = 500;
  tx.balance_proof.excess_commitment = crypto::Commitment33{};
  tx.balance_proof.excess_pubkey.fill(0);
  tx.balance_proof.excess_sig.fill(0);
  resign_input0(tx, from);

  ConfidentialPolicy policy;
  SpecialValidationContext ctx;
  ctx.current_height = 1;
  ctx.confidential_policy = &policy;

  const auto result = validate_tx_v2(tx, 1, view, &ctx);
  ASSERT_TRUE(!result.ok);
  ASSERT_TRUE(result.error.find("join request missing matching SCVALREG output") != std::string::npos);
}

TEST(test_validate_tx_v2_accepts_matching_validator_register_and_join_request_outputs) {
  const auto from = key_from_byte(0x43);
  const auto validator = key_from_byte(0x44);
  const auto payout = key_from_byte(0x45);
  const auto from_pkh = crypto::h160(Bytes(from.public_key.begin(), from.public_key.end()));

  OutPoint op{};
  op.txid.fill(0x6B);
  op.index = 0;
  UtxoSetV2 view;
  view[op] = UtxoEntryV2(TxOut{BOND_AMOUNT + 2'000, address::p2pkh_script_pubkey(from_pkh)});

  TxV2 tx;
  tx.inputs.push_back(TxInV2{
      .prev_txid = op.txid,
      .prev_index = op.index,
      .sequence = 0xFFFFFFFF,
      .kind = TxInputKind::Transparent,
      .witness = TransparentInputWitnessV2{},
  });
  const auto pop = crypto::ed25519_sign(validator_join_request_pop_message(validator.public_key, payout.public_key),
                                        validator.private_key);
  ASSERT_TRUE(pop.has_value());
  tx.outputs.push_back(TxOutV2{.kind = TxOutputKind::Transparent,
                               .body = TransparentTxOutV2{BOND_AMOUNT, validator_register_script(validator.public_key)}});
  tx.outputs.push_back(TxOutV2{.kind = TxOutputKind::Transparent,
                               .body = TransparentTxOutV2{0, validator_join_request_script(validator.public_key,
                                                                                           payout.public_key, *pop)}});
  tx.outputs.push_back(TxOutV2{
      .kind = TxOutputKind::Transparent,
      .body = TransparentTxOutV2{1'000,
                                 address::p2pkh_script_pubkey(crypto::h160(Bytes(payout.public_key.begin(),
                                                                                payout.public_key.end())))}
  });
  tx.fee = 1'000;
  tx.balance_proof.excess_commitment = crypto::Commitment33{};
  tx.balance_proof.excess_pubkey.fill(0);
  tx.balance_proof.excess_sig.fill(0);
  resign_input0(tx, from);

  ConfidentialPolicy policy;
  SpecialValidationContext ctx;
  ctx.current_height = 1;
  ctx.confidential_policy = &policy;

  const auto result = validate_tx_v2(tx, 1, view, &ctx);
  ASSERT_TRUE(result.ok);
  ASSERT_EQ(result.cost.fee, 1'000u);
}

TEST(test_commitment_sum_is_homomorphic) {
  if (!crypto::confidential_backend_status().confidential_outputs_supported) return;
  const auto r1 = blind_from_byte(0x11);
  const auto r2 = blind_from_byte(0x12);
  const std::array<crypto::Blind32, 2> blinds{r1, r2};
  const auto r12 = crypto::combine_blinds(blinds, 2);
  ASSERT_TRUE(r12.has_value());
  const auto c1 = crypto::confidential_amount_commitment(3, r1);
  const auto c2 = crypto::confidential_amount_commitment(5, r2);
  const auto c12 = crypto::confidential_amount_commitment(8, *r12);
  ASSERT_TRUE(c1.has_value() && c2.has_value() && c12.has_value());
  crypto::CommitmentSum sum;
  ASSERT_TRUE(crypto::commitment_sum_add(&sum, *c1));
  ASSERT_TRUE(crypto::commitment_sum_add(&sum, *c2));
  crypto::CommitmentSum expected;
  ASSERT_TRUE(crypto::commitment_sum_add(&expected, *c12));
  ASSERT_TRUE(sum == expected);

  // C(0, r) + C(0, -r) is the point at infinity.
  const std::array<crypto::Blind32, 1> one{r1};
  const auto neg_r1 = crypto::combine_blinds(one, 0);
  ASSERT_TRUE(neg_r1.has_value());
  crypto::CommitmentSum zero;
  ASSERT_TRUE(crypto::commitment_sum_add(&zero, *crypto::confidential_amount_commitment(0, r1)));
  ASSERT_TRUE(crypto::commitment_sum_add(&zero, *crypto::confidential_amount_commitment(0, *neg_r1)));
  ASSERT_TRUE(zero.infinity);

  const auto v8 = crypto::commitment_sum_of_value(8);
  crypto::CommitmentSum c8;
  ASSERT_TRUE(crypto::commitment_sum_add(&c8, crypto::transparent_amount_commitment(8)));
  ASSERT_TRUE(v8.has_value() && *v8 == c8);
}

namespace {

struct ShieldFixture {
  UtxoSetV2 utxos;
  consensus::ConfidentialSupplyLedger ledger;
  OutPoint confidential_op;
  crypto::Blind32 spend_secret;
  crypto::Blind32 value_blind;
};

// Applies a validated tx at `height` the way apply_frontier_record does: account, then apply.
void apply_validated(ShieldFixture* f, const TxV2& tx, std::uint64_t height) {
  ConfidentialPolicy policy;
  SpecialValidationContext ctx;
  ctx.current_height = height;
  ctx.confidential_policy = &policy;
  const auto result = validate_tx_v2(tx, 1, f->utxos, &ctx);
  if (!result.ok) throw std::runtime_error("fixture tx invalid: " + result.error);
  consensus::account_confidential_supply(f->utxos, {AnyTx{tx}}, height, &f->ledger);
  apply_any_tx_to_utxo(AnyTx{tx}, f->utxos);
}

// Shields 9,000 of a 10,000 transparent UTXO (fee 1,000) into one spendable confidential output.
ShieldFixture shield_9000() {
  ShieldFixture f;
  const auto from = key_from_byte(0x61);
  const auto from_pkh = crypto::h160(Bytes(from.public_key.begin(), from.public_key.end()));
  OutPoint op{};
  op.txid.fill(0x62);
  f.utxos[op] = UtxoEntryV2(TxOut{10'000, address::p2pkh_script_pubkey(from_pkh)});

  f.spend_secret = blind_from_byte(0x63);
  f.value_blind = blind_from_byte(0x64);
  const auto commitment = crypto::confidential_amount_commitment(9'000, f.value_blind);
  const auto proof = crypto::sign_output_range_proof(*commitment, 9'000, f.value_blind, nonce_from_byte(0x65));
  const auto one_time = crypto::secp256k1_pubkey_from_scalar(f.spend_secret.bytes);
  if (!commitment || !proof || !one_time) throw std::runtime_error("fixture output build failed");
  const ConfidentialTxOutV2 out{
      .value_commitment = *commitment,
      .one_time_pubkey = *one_time,
      .ephemeral_pubkey = compressed_key(0x66),
      .scan_tag = crypto::ScanTag{0x67},
      .range_proof = *proof,
      .memo = Bytes{},
  };
  const auto tx = make_confidential_output_v2_tx(op, from, 10'000, 0, 9'000, f.value_blind, out, 1'000);
  apply_validated(&f, tx, 1);
  f.confidential_op = OutPoint{tx.txid(), 0};
  return f;
}

}  // namespace

TEST(test_confidential_supply_audit_invariant_holds) {
  if (!crypto::confidential_backend_status().confidential_outputs_supported) return;
  consensus::ConfidentialSupplyLedger empty;
  ASSERT_TRUE(consensus::audit_confidential_supply(UtxoSetV2{}, empty, 0).status ==
              consensus::ConfidentialSupplyAuditStatus::Ok);

  auto f = shield_9000();
  auto audit = consensus::audit_confidential_supply(f.utxos, f.ledger, static_cast<std::uint64_t>(std::max<std::int64_t>(0, f.ledger.pool_value)));
  if (audit.status != consensus::ConfidentialSupplyAuditStatus::Ok) throw std::runtime_error(audit.detail);
  ASSERT_EQ(f.ledger.pool_value, 9'000);
  ASSERT_EQ(audit.confidential_utxo_count, 1u);

  // Unshield all of it: 8,500 transparent + 500 fee. The pool returns to 0.
  const auto recipient = key_from_byte(0x68);
  const auto unshield =
      make_confidential_input_v2_tx(f.confidential_op, f.spend_secret, f.value_blind, recipient.public_key, 9'000, 8'500);
  apply_validated(&f, unshield, 2);
  audit = consensus::audit_confidential_supply(f.utxos, f.ledger, static_cast<std::uint64_t>(std::max<std::int64_t>(0, f.ledger.pool_value)));
  if (audit.status != consensus::ConfidentialSupplyAuditStatus::Ok) throw std::runtime_error(audit.detail);
  ASSERT_EQ(f.ledger.pool_value, 0);
  ASSERT_EQ(f.ledger.txv2_count, 2u);
  ASSERT_EQ(audit.confidential_utxo_count, 0u);

  std::uint64_t height = 0;
  const auto roundtrip =
      consensus::parse_confidential_supply_ledger(consensus::serialize_confidential_supply_ledger(f.ledger, 2), &height);
  ASSERT_TRUE(roundtrip.has_value() && *roundtrip == f.ledger);
  ASSERT_EQ(height, 2u);
}

TEST(test_confidential_supply_audit_detects_inflation) {
  if (!crypto::confidential_backend_status().confidential_outputs_supported) return;
  // (a) A stored confidential commitment worth more than was shielded breaks the commitment identity.
  {
    auto f = shield_9000();
    auto& entry = std::get<UtxoConfidentialData>(f.utxos.at(f.confidential_op).body);
    entry.value_commitment = *crypto::confidential_amount_commitment(9'001, f.value_blind);
    const auto audit = consensus::audit_confidential_supply(f.utxos, f.ledger, static_cast<std::uint64_t>(std::max<std::int64_t>(0, f.ledger.pool_value)));
    ASSERT_TRUE(audit.status == consensus::ConfidentialSupplyAuditStatus::Failed);
    ASSERT_TRUE(audit.detail.find("commitment-identity-mismatch") != std::string::npos);
  }
  // (b) Value created inside the pool (as a broken range proof would allow) shows up when it is
  // unshielded: more leaves the pool than ever entered it. Accounted directly, bypassing validation.
  {
    auto f = shield_9000();
    const auto recipient = key_from_byte(0x69);
    const auto inflated = make_confidential_input_v2_tx(f.confidential_op, f.spend_secret, f.value_blind,
                                                        recipient.public_key, 20'000, 19'500);
    consensus::account_confidential_supply(f.utxos, {AnyTx{inflated}}, 7, &f.ledger);
    ASSERT_TRUE(f.ledger.pool_value < 0);
    ASSERT_EQ(f.ledger.first_negative_height, 7u);
    const auto audit = consensus::audit_confidential_supply(f.utxos, f.ledger, static_cast<std::uint64_t>(std::max<std::int64_t>(0, f.ledger.pool_value)));
    ASSERT_TRUE(audit.status == consensus::ConfidentialSupplyAuditStatus::Failed);
    ASSERT_TRUE(audit.detail.find("turnstile-negative") != std::string::npos);
  }
  // (c) A ledger that was never derived from history yields no verdict rather than a false pass.
  {
    consensus::ConfidentialSupplyLedger unknown;
    unknown.known = false;
    ASSERT_TRUE(consensus::audit_confidential_supply(UtxoSetV2{}, unknown, 0).status ==
                consensus::ConfidentialSupplyAuditStatus::Unavailable);
  }
}

namespace {

// A shield tx whose single confidential output carries a proof of the given shape.
std::pair<TxV2, UtxoSetV2> shield_with_proof_shape(const crypto::RangeProofShape& shape) {
  const auto from = key_from_byte(0x71);
  const auto from_pkh = crypto::h160(Bytes(from.public_key.begin(), from.public_key.end()));
  OutPoint op{};
  op.txid.fill(0x72);
  UtxoSetV2 view;
  view[op] = UtxoEntryV2(TxOut{10'000, address::p2pkh_script_pubkey(from_pkh)});
  const auto blind = blind_from_byte(0x73);
  const auto commitment = crypto::confidential_amount_commitment(9'000, blind);
  const auto proof = crypto::sign_output_range_proof(*commitment, 9'000, blind, nonce_from_byte(0x74), shape);
  if (!commitment || !proof) throw std::runtime_error("proof build failed");
  const ConfidentialTxOutV2 out{
      .value_commitment = *commitment,
      .one_time_pubkey = compressed_key(0x75),
      .ephemeral_pubkey = compressed_key(0x76),
      .scan_tag = crypto::ScanTag{0x77},
      .range_proof = *proof,
      .memo = Bytes{},
  };
  return {make_confidential_output_v2_tx(op, from, 10'000, 0, 9'000, blind, out, 1'000), view};
}

ConfidentialTxOutV2 only_confidential_output(const TxV2& tx) {
  for (const auto& out : tx.outputs) {
    if (out.kind == TxOutputKind::Confidential) return std::get<ConfidentialTxOutV2>(out.body);
  }
  throw std::runtime_error("no confidential output");
}

}  // namespace

TEST(test_range_proof_correct_shape_accepted) {
  if (!crypto::confidential_backend_status().confidential_outputs_supported) return;
  const auto [tx, view] = shield_with_proof_shape(crypto::kCanonicalRangeProofShape);
  const auto out = only_confidential_output(tx);
  ASSERT_TRUE(crypto::range_proof_has_canonical_shape(out.range_proof));
  ConfidentialPolicy policy;
  SpecialValidationContext ctx;
  ctx.current_height = 1;
  ctx.confidential_policy = &policy;
  const auto result = validate_tx_v2(tx, 1, view, &ctx);
  if (!result.ok) throw std::runtime_error(result.error);
}

TEST(test_range_proof_wrong_shape_rejected) {
  if (!crypto::confidential_backend_status().confidential_outputs_supported) return;
  const std::vector<crypto::RangeProofShape> leaky{
      // exponent (with 64 bits the library normalizes exp back to 0, so use fewer bits to keep it)
      {.min_value = 0, .exp = 1, .min_bits = 40},
      {.min_value = 1'000, .exp = 0, .min_bits = 64}, // public minimum
      {.min_value = 0, .exp = 0, .min_bits = 32},     // fewer bits
  };
  for (const auto& shape : leaky) {
    const auto [tx, view] = shield_with_proof_shape(shape);
    const auto out = only_confidential_output(tx);
    // The proof itself is cryptographically valid; only its shape is non-canonical.
    ASSERT_TRUE(crypto::verify_output_range_proof(out.value_commitment, out.range_proof));
    ASSERT_TRUE(!crypto::range_proof_has_canonical_shape(out.range_proof));
    ConfidentialPolicy policy;
    SpecialValidationContext ctx;
    ctx.current_height = 1;
    ctx.confidential_policy = &policy;
    const auto result = validate_tx_v2(tx, 1, view, &ctx);
    ASSERT_TRUE(!result.ok);
    ASSERT_EQ(result.error, std::string("range-proof-shape-invalid"));
  }
}

TEST(test_validate_tx_v2_checks_tally_before_range_proofs) {
  if (!crypto::confidential_backend_status().confidential_outputs_supported) return;
  auto [tx, view] = shield_with_proof_shape(crypto::kCanonicalRangeProofShape);
  // Break both the balance (fee no longer matches the excess) and the proof body (header intact).
  tx.fee = 900;
  for (auto& out : tx.outputs) {
    if (out.kind != TxOutputKind::Confidential) continue;
    auto& proof = std::get<ConfidentialTxOutV2>(out.body).range_proof.bytes;
    proof.back() ^= 0x01;
    ASSERT_TRUE(crypto::range_proof_has_canonical_shape(crypto::ProofBytes{proof}));
  }
  resign_input0(tx, key_from_byte(0x71));
  ConfidentialPolicy policy;
  SpecialValidationContext ctx;
  ctx.current_height = 1;
  ctx.confidential_policy = &policy;
  const auto result = validate_tx_v2(tx, 1, view, &ctx);
  ASSERT_TRUE(!result.ok);
  ASSERT_EQ(result.error, std::string("commitment balance mismatch"));
}

namespace {

TxV2 txv2_with_counts(std::size_t inputs, std::size_t outputs) {
  TxV2 tx;
  for (std::size_t i = 0; i < inputs; ++i) {
    TxInV2 in;
    in.prev_txid.fill(static_cast<std::uint8_t>(i));
    in.prev_index = static_cast<std::uint32_t>(i);
    tx.inputs.push_back(in);
  }
  for (std::size_t i = 0; i < outputs; ++i) {
    tx.outputs.push_back(TxOutV2{.kind = TxOutputKind::Transparent, .body = TransparentTxOutV2{1, Bytes{0x51}}});
  }
  return tx;
}

}  // namespace

TEST(test_txv2_too_many_inputs_rejected) {
  ASSERT_TRUE(TxV2::parse(txv2_with_counts(kTxV2MaxInputs, 1).serialize()).has_value());
  ASSERT_TRUE(!TxV2::parse(txv2_with_counts(kTxV2MaxInputs + 1, 1).serialize()).has_value());
  ASSERT_TRUE(!parse_any_tx(txv2_with_counts(kTxV2MaxInputs + 1, 1).serialize()).has_value());
}

TEST(test_txv2_too_many_outputs_rejected) {
  ASSERT_TRUE(TxV2::parse(txv2_with_counts(1, kTxV2MaxOutputs).serialize()).has_value());
  ASSERT_TRUE(!TxV2::parse(txv2_with_counts(1, kTxV2MaxOutputs + 1).serialize()).has_value());
  ASSERT_TRUE(!parse_any_tx(txv2_with_counts(1, kTxV2MaxOutputs + 1).serialize()).has_value());
}

TEST(test_txv2_confidential_verify_weight_formula) {
  TxV2 tx;
  for (std::uint8_t i = 0; i < 2; ++i) {
    TxInV2 in;
    in.prev_txid.fill(i);
    in.kind = TxInputKind::Confidential;
    in.witness = ConfidentialInputWitnessV2{};
    tx.inputs.push_back(in);
  }
  for (std::size_t bytes : {std::size_t{5126}, std::size_t{5134}, std::size_t{100}}) {
    ConfidentialTxOutV2 conf;
    conf.range_proof = crypto::ProofBytes{Bytes(bytes, 0x01)};
    tx.outputs.push_back(TxOutV2{.kind = TxOutputKind::Confidential, .body = conf});
  }
  tx.outputs.push_back(TxOutV2{.kind = TxOutputKind::Transparent, .body = TransparentTxOutV2{1, Bytes{0x51}}});
  ASSERT_TRUE(crypto::commitment_is_identity(tx.balance_proof.excess_commitment));
  const std::uint64_t outputs = 5126 + 5134 + 100 + 3 * kConfidentialOutputVerifyWeight;
  ASSERT_EQ(txv2_confidential_verify_weight(tx),
            2 * kConfidentialSignatureVerifyWeight + outputs + kConfidentialTxBaseVerifyWeight);

  tx.balance_proof.excess_commitment.bytes[0] = 0x02;  // non-identity excess adds its signature
  ASSERT_EQ(txv2_confidential_verify_weight(tx),
            3 * kConfidentialSignatureVerifyWeight + outputs + kConfidentialTxBaseVerifyWeight);

  // Transparent-only TxV2: no confidential verification work, no base charge.
  TxV2 transparent;
  transparent.inputs.push_back(TxInV2{.kind = TxInputKind::Transparent, .witness = TransparentInputWitnessV2{}});
  transparent.outputs.push_back(TxOutV2{.kind = TxOutputKind::Transparent, .body = TransparentTxOutV2{1, Bytes{0x51}}});
  ASSERT_EQ(txv2_confidential_verify_weight(transparent), 0u);
}

// The output limit matches the proof-byte cap: 12 canonical proofs fit, 13 never could.
TEST(test_validate_tx_v2_confidential_output_limit_is_12) {
  if (!crypto::confidential_backend_status().confidential_outputs_supported) return;
  ConfidentialPolicy policy;
  ASSERT_EQ(policy.max_confidential_outputs_per_tx, 12u);
  ASSERT_TRUE(12ull * kTxV2MaxRangeProofBytes <= policy.max_total_proof_bytes_per_tx);
  ASSERT_TRUE(13ull * kTxV2MaxRangeProofBytes > policy.max_total_proof_bytes_per_tx);

  const auto from = key_from_byte(0x29);
  const auto from_pkh = crypto::h160(Bytes(from.public_key.begin(), from.public_key.end()));
  OutPoint op{};
  op.txid.fill(0x49);
  UtxoSetV2 view;
  view[op] = UtxoEntryV2(TxOut{100'000, address::p2pkh_script_pubkey(from_pkh)});
  SpecialValidationContext ctx;
  ctx.current_height = 100;
  ctx.confidential_policy = &policy;

  auto make = [&](std::size_t n_outputs) {
    TxV2 tx;
    tx.inputs.push_back(TxInV2{.prev_txid = op.txid, .prev_index = op.index, .sequence = 0xFFFFFFFF,
                               .kind = TxInputKind::Transparent, .witness = TransparentInputWitnessV2{}});
    for (std::size_t i = 0; i < n_outputs; ++i) {
      tx.outputs.push_back(TxOutV2{.kind = TxOutputKind::Confidential,
                                   .body = make_valid_confidential_output(static_cast<std::uint8_t>(0x10 + 8 * i), 1'000)});
    }
    tx.fee = 500;
    resign_input0(tx, from);
    return tx;
  };
  const auto at_limit = validate_tx_v2(make(12), 1, view, &ctx);
  ASSERT_TRUE(at_limit.error != "too many confidential outputs");
  const auto over = validate_tx_v2(make(13), 1, view, &ctx);
  ASSERT_TRUE(!over.ok);
  ASSERT_EQ(over.error, std::string("too many confidential outputs"));
}
