#include "test_framework.hpp"

#include <variant>

#include "address/address.hpp"
#include "codec/bytes.hpp"
#include "crypto/ed25519.hpp"
#include "crypto/hash.hpp"
#include "utxo/confidential_tx.hpp"
#include "utxo/validate.hpp"

using namespace finalis;

namespace {

PubKey33 compressed_key(std::uint8_t seed) {
  return crypto::transparent_amount_commitment(static_cast<std::uint64_t>(seed) + 1).bytes;
}

crypto::Commitment33 commitment(std::uint8_t seed) {
  return crypto::transparent_amount_commitment(static_cast<std::uint64_t>(seed) + 1);
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

void resign_input0(TxV2& tx, const crypto::KeyPair& from) {
  auto msg = finalis::signing_message_for_input_v2(tx, 0);
  if (!msg.has_value()) throw std::runtime_error("sighash failed");
  auto sig = crypto::ed25519_sign(*msg, from.private_key);
  if (!sig.has_value()) throw std::runtime_error("sign failed");
  std::get<TransparentInputWitnessV2>(tx.inputs[0].witness).script_sig = make_p2pkh_script_sig(*sig, from.public_key);
}

TxV2 make_transparent_only_v2_tx(const OutPoint& op, const crypto::KeyPair& from, const PubKey32& to_pub,
                                 std::uint64_t value_in, std::uint64_t value_out) {
  const auto to_pkh = crypto::h160(Bytes(to_pub.begin(), to_pub.end()));
  TxV2 tx;
  tx.inputs.push_back(TxInV2{
      .prev_txid = op.txid,
      .prev_index = op.index,
      .sequence = 0xFFFFFFFF,
      .kind = TxInputKind::TRANSPARENT,
      .witness = TransparentInputWitnessV2{},
  });
  tx.outputs.push_back(TxOutV2{
      .kind = TxOutputKind::TRANSPARENT,
      .body = TransparentTxOutV2{value_out, address::p2pkh_script_pubkey(to_pkh)},
  });
  tx.fee = value_in - value_out;
  const std::vector<crypto::Commitment33> inputs{crypto::transparent_amount_commitment(value_in)};
  const std::vector<crypto::Commitment33> outputs{crypto::transparent_amount_commitment(value_out),
                                                  crypto::transparent_amount_commitment(tx.fee)};
  const auto input_sum = crypto::add_commitments(inputs);
  const auto output_sum = crypto::add_commitments(outputs);
  if (!input_sum.has_value() || !output_sum.has_value()) throw std::runtime_error("commitment sum failed");
  const auto excess = crypto::subtract_commitments(*input_sum, *output_sum);
  if (!excess.has_value()) throw std::runtime_error("commitment subtract failed");
  tx.balance_proof.excess_commitment = *excess;
  tx.balance_proof.excess_sig.fill(0x42);
  resign_input0(tx, from);
  return tx;
}

TxV2 make_confidential_output_v2_tx(const OutPoint& op, const crypto::KeyPair& from, std::uint64_t value_in,
                                    std::uint64_t transparent_value_out, const ConfidentialTxOutV2& confidential_out,
                                    std::uint64_t fee) {
  TxV2 tx;
  tx.inputs.push_back(TxInV2{
      .prev_txid = op.txid,
      .prev_index = op.index,
      .sequence = 0xFFFFFFFF,
      .kind = TxInputKind::TRANSPARENT,
      .witness = TransparentInputWitnessV2{},
  });
  if (transparent_value_out > 0) {
    const auto to = key_from_byte(0x66);
    tx.outputs.push_back(TxOutV2{
        .kind = TxOutputKind::TRANSPARENT,
        .body = TransparentTxOutV2{transparent_value_out,
                                   address::p2pkh_script_pubkey(crypto::h160(Bytes(to.public_key.begin(), to.public_key.end())))},
    });
  }
  tx.outputs.push_back(TxOutV2{.kind = TxOutputKind::CONFIDENTIAL, .body = confidential_out});
  tx.fee = fee;

  std::vector<crypto::Commitment33> inputs{crypto::transparent_amount_commitment(value_in)};
  std::vector<crypto::Commitment33> outputs;
  if (transparent_value_out > 0) outputs.push_back(crypto::transparent_amount_commitment(transparent_value_out));
  outputs.push_back(confidential_out.value_commitment);
  outputs.push_back(crypto::transparent_amount_commitment(fee));
  const auto input_sum = crypto::add_commitments(inputs);
  const auto output_sum = crypto::add_commitments(outputs);
  if (!input_sum.has_value() || !output_sum.has_value()) throw std::runtime_error("commitment sum failed");
  const auto excess = crypto::subtract_commitments(*input_sum, *output_sum);
  if (!excess.has_value()) throw std::runtime_error("commitment subtract failed");
  tx.balance_proof.excess_commitment = *excess;
  tx.balance_proof.excess_sig.fill(0x52);

  resign_input0(tx, from);
  return tx;
}

}  // namespace

TEST(test_tx_v1_parser_rejects_v2_bytes) {
  TxV2 tx;
  tx.inputs.push_back(TxInV2{
      .prev_txid = zero_hash(),
      .prev_index = 7,
      .sequence = 0xFFFFFFFF,
      .kind = TxInputKind::TRANSPARENT,
      .witness = TransparentInputWitnessV2{Bytes{0x51}},
  });
  tx.outputs.push_back(TxOutV2{
      .kind = TxOutputKind::TRANSPARENT,
      .body = TransparentTxOutV2{123, Bytes{0x51}},
  });
  tx.fee = 5;
  tx.balance_proof.excess_commitment = commitment(0x31);
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
      .kind = TxInputKind::CONFIDENTIAL,
      .witness = ConfidentialInputWitnessV2{compressed_key(0x41), Sig64{}},
  });
  std::get<ConfidentialInputWitnessV2>(tx.inputs.back().witness).spend_sig.fill(0x33);

  tx.outputs.push_back(TxOutV2{
      .kind = TxOutputKind::TRANSPARENT,
      .body = TransparentTxOutV2{50, Bytes{0x51}},
  });
  tx.outputs.push_back(TxOutV2{
      .kind = TxOutputKind::CONFIDENTIAL,
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

TEST(test_validate_tx_v2_rejects_pre_activation) {
  const auto from = key_from_byte(0x23);
  const auto to = key_from_byte(0x24);
  const auto from_pkh = crypto::h160(Bytes(from.public_key.begin(), from.public_key.end()));

  OutPoint op{};
  op.txid.fill(0x45);
  op.index = 0;
  UtxoSetV2 view;
  view[op] = UtxoEntryV2(TxOut{10'000, address::p2pkh_script_pubkey(from_pkh)});

  auto tx = make_transparent_only_v2_tx(op, from, to.public_key, 10'000, 9'500);
  ConfidentialPolicy policy;
  policy.activation_height = 100;
  SpecialValidationContext ctx;
  ctx.current_height = 99;
  ctx.confidential_policy = &policy;

  const auto result = validate_tx_v2(tx, 1, view, &ctx);
  ASSERT_TRUE(!result.ok);
  ASSERT_TRUE(result.error.find("not active") != std::string::npos);
}

TEST(test_validate_tx_v2_accepts_transparent_only_post_activation) {
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
  policy.activation_height = 100;
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

  ConfidentialTxOutV2 confidential_out{
      .value_commitment = commitment(0x70),
      .one_time_pubkey = compressed_key(0x71),
      .ephemeral_pubkey = compressed_key(0x72),
      .scan_tag = crypto::ScanTag{0x73},
      .range_proof = crypto::ProofBytes{Bytes{0xA1, 0xB2, 0xC3, 0xD4}},
      .memo = Bytes{0x01, 0x02},
  };
  auto tx = make_confidential_output_v2_tx(op, from, 10'000, 500, confidential_out, 9'500);

  ConfidentialPolicy policy;
  policy.activation_height = 100;
  SpecialValidationContext ctx;
  ctx.current_height = 100;
  ctx.confidential_policy = &policy;

  const auto result = validate_tx_v2(tx, 1, view, &ctx);
  if (!crypto::confidential_backend_status().confidential_outputs_supported) {
    ASSERT_TRUE(!result.ok);
    ASSERT_TRUE(result.error.find("unsupported by crypto backend") != std::string::npos);
  } else {
    ASSERT_TRUE(result.ok);
    ASSERT_EQ(result.cost.fee, 9'500u);
    ASSERT_EQ(result.cost.confidential_verify_weight, confidential_out.range_proof.bytes.size());

    UtxoSetV2 applied = view;
    apply_any_tx_to_utxo(AnyTx{tx}, applied);
    const auto txid = tx.txid();
    const auto it = applied.find(OutPoint{txid, 1});
    ASSERT_TRUE(it != applied.end());
    ASSERT_EQ(it->second.kind, UtxoOutputKind::CONFIDENTIAL);
  }
}

TEST(test_validate_tx_v2_rejects_bad_confidential_commitment_or_keys) {
  const auto from = key_from_byte(0x28);
  const auto from_pkh = crypto::h160(Bytes(from.public_key.begin(), from.public_key.end()));

  OutPoint op{};
  op.txid.fill(0x48);
  op.index = 0;
  UtxoSetV2 view;
  view[op] = UtxoEntryV2(TxOut{10'000, address::p2pkh_script_pubkey(from_pkh)});

  ConfidentialTxOutV2 confidential_out{
      .value_commitment = commitment(0x74),
      .one_time_pubkey = compressed_key(0x75),
      .ephemeral_pubkey = compressed_key(0x76),
      .scan_tag = crypto::ScanTag{0x77},
      .range_proof = crypto::ProofBytes{Bytes{0x01}},
      .memo = Bytes{},
  };
  auto tx = make_confidential_output_v2_tx(op, from, 10'000, 0, confidential_out, 10'000);
  std::get<ConfidentialTxOutV2>(tx.outputs[0].body).value_commitment.bytes[0] = 0x04;
  resign_input0(tx, from);

  ConfidentialPolicy policy;
  policy.activation_height = 100;
  SpecialValidationContext ctx;
  ctx.current_height = 100;
  ctx.confidential_policy = &policy;

  const auto result = validate_tx_v2(tx, 1, view, &ctx);
  ASSERT_TRUE(!result.ok);
  if (!crypto::confidential_backend_status().confidential_outputs_supported) {
    ASSERT_TRUE(result.error.find("unsupported by crypto backend") != std::string::npos);
  } else {
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

  ConfidentialTxOutV2 confidential_out{
      .value_commitment = commitment(0x78),
      .one_time_pubkey = compressed_key(0x79),
      .ephemeral_pubkey = compressed_key(0x7A),
      .scan_tag = crypto::ScanTag{0x7B},
      .range_proof = crypto::ProofBytes{Bytes{0x10, 0x11, 0x12}},
      .memo = Bytes{0x01, 0x02, 0x03},
  };
  auto tx = make_confidential_output_v2_tx(op, from, 10'000, 0, confidential_out, 10'000);

  ConfidentialPolicy policy;
  policy.activation_height = 100;
  policy.max_range_proof_bytes = 2;
  policy.max_memo_bytes = 2;
  SpecialValidationContext ctx;
  ctx.current_height = 100;
  ctx.confidential_policy = &policy;

  const auto result = validate_tx_v2(tx, 1, view, &ctx);
  ASSERT_TRUE(!result.ok);
  if (!crypto::confidential_backend_status().confidential_outputs_supported) {
    ASSERT_TRUE(result.error.find("unsupported by crypto backend") != std::string::npos);
  } else {
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

  ConfidentialTxOutV2 confidential_out{
      .value_commitment = commitment(0x7C),
      .one_time_pubkey = compressed_key(0x7D),
      .ephemeral_pubkey = compressed_key(0x7E),
      .scan_tag = crypto::ScanTag{0x7F},
      .range_proof = crypto::ProofBytes{Bytes{0x20, 0x21}},
      .memo = Bytes{},
  };
  auto tx = make_confidential_output_v2_tx(op, from, 10'000, 0, confidential_out, 10'000);
  tx.balance_proof.excess_commitment = commitment(0x55);
  resign_input0(tx, from);

  ConfidentialPolicy policy;
  policy.activation_height = 100;
  SpecialValidationContext ctx;
  ctx.current_height = 100;
  ctx.confidential_policy = &policy;

  const auto result = validate_tx_v2(tx, 1, view, &ctx);
  ASSERT_TRUE(!result.ok);
  if (!crypto::confidential_backend_status().confidential_outputs_supported) {
    ASSERT_TRUE(result.error.find("unsupported by crypto backend") != std::string::npos);
  } else {
    ASSERT_TRUE(result.error.find("balance mismatch") != std::string::npos);
  }
}
