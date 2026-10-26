// SPDX-License-Identifier: MIT

#include "utxo/confidential_tx.hpp"

#include <sodium.h>

#include <string_view>

#include "codec/bytes.hpp"
#include "crypto/hash.hpp"

namespace finalis {
namespace {

constexpr std::size_t kMaxWitnessBytes = 256 * 1024;
constexpr std::size_t kMaxScriptBytes = 256 * 1024;

void serialize_txin_v2(codec::ByteWriter& w, const TxInV2& in) {
  w.bytes_fixed(in.prev_txid);
  w.u32le(in.prev_index);
  w.u32le(in.sequence);
  w.u8(static_cast<std::uint8_t>(in.kind));
  if (in.kind == TxInputKind::Transparent) {
    w.varbytes(std::get<TransparentInputWitnessV2>(in.witness).script_sig);
    return;
  }
  const auto& witness = std::get<ConfidentialInputWitnessV2>(in.witness);
  w.bytes_fixed(witness.one_time_pubkey);
  w.bytes_fixed(witness.spend_sig);
}

bool parse_txin_v2(codec::ByteReader& r, TxInV2* out) {
  if (!out) return false;
  TxInV2 in;
  auto prev_txid = r.bytes_fixed<32>();
  auto prev_index = r.u32le();
  auto sequence = r.u32le();
  auto kind = r.u8();
  if (!prev_txid || !prev_index || !sequence || !kind) return false;
  if (*kind > static_cast<std::uint8_t>(TxInputKind::Confidential)) return false;
  in.prev_txid = *prev_txid;
  in.prev_index = *prev_index;
  in.sequence = *sequence;
  in.kind = static_cast<TxInputKind>(*kind);
  if (in.kind == TxInputKind::Transparent) {
    auto script_sig = r.varbytes();
    if (!script_sig || script_sig->size() > kMaxWitnessBytes) return false;
    in.witness = TransparentInputWitnessV2{*script_sig};
  } else {
    auto one_time_pubkey = r.bytes_fixed<33>();
    auto spend_sig = r.bytes_fixed<64>();
    if (!one_time_pubkey || !spend_sig) return false;
    in.witness = ConfidentialInputWitnessV2{*one_time_pubkey, *spend_sig};
  }
  *out = std::move(in);
  return true;
}

void serialize_txout_v2(codec::ByteWriter& w, const TxOutV2& out) {
  w.u8(static_cast<std::uint8_t>(out.kind));
  if (out.kind == TxOutputKind::Transparent) {
    const auto& transparent = std::get<TransparentTxOutV2>(out.body);
    w.u64le(transparent.value);
    w.varbytes(transparent.script_pubkey);
    return;
  }
  const auto& confidential = std::get<ConfidentialTxOutV2>(out.body);
  w.bytes_fixed(confidential.value_commitment.bytes);
  w.bytes_fixed(confidential.one_time_pubkey);
  w.bytes_fixed(confidential.ephemeral_pubkey);
  w.u8(confidential.scan_tag.value);
  w.varbytes(confidential.range_proof.bytes);
  w.varbytes(confidential.memo);
}

bool parse_txout_v2(codec::ByteReader& r, TxOutV2* out) {
  if (!out) return false;
  TxOutV2 result;
  auto kind = r.u8();
  if (!kind) return false;
  if (*kind > static_cast<std::uint8_t>(TxOutputKind::Confidential)) return false;
  result.kind = static_cast<TxOutputKind>(*kind);
  if (result.kind == TxOutputKind::Transparent) {
    auto value = r.u64le();
    auto script_pubkey = r.varbytes();
    if (!value || !script_pubkey || script_pubkey->size() > kMaxScriptBytes) return false;
    result.body = TransparentTxOutV2{*value, *script_pubkey};
  } else {
    auto value_commitment = r.bytes_fixed<33>();
    auto one_time_pubkey = r.bytes_fixed<33>();
    auto ephemeral_pubkey = r.bytes_fixed<33>();
    auto scan_tag = r.u8();
    auto range_proof = r.varbytes();
    auto memo = r.varbytes();
    if (!value_commitment || !one_time_pubkey || !ephemeral_pubkey || !scan_tag || !range_proof || !memo) return false;
    if (range_proof->size() > kTxV2MaxRangeProofBytes || memo->size() > kTxV2MaxMemoBytes) return false;
    result.body = ConfidentialTxOutV2{
        .value_commitment = crypto::Commitment33{*value_commitment},
        .one_time_pubkey = *one_time_pubkey,
        .ephemeral_pubkey = *ephemeral_pubkey,
        .scan_tag = crypto::ScanTag{*scan_tag},
        .range_proof = crypto::ProofBytes{*range_proof},
        .memo = *memo,
    };
  }
  *out = std::move(result);
  return true;
}

}  // namespace

Bytes TxV2::serialize() const {
  codec::ByteWriter w;
  w.u32le(version);
  w.varint(inputs.size());
  for (const auto& in : inputs) serialize_txin_v2(w, in);
  w.varint(outputs.size());
  for (const auto& out : outputs) serialize_txout_v2(w, out);
  w.u32le(lock_time);
  w.u64le(fee);
  w.bytes_fixed(balance_proof.excess_commitment.bytes);
  w.bytes_fixed(balance_proof.excess_pubkey);
  w.bytes_fixed(balance_proof.excess_sig);
  return w.take();
}

std::optional<TxV2> TxV2::parse(const Bytes& b) {
  TxV2 tx;
  try {
    if (!codec::parse_exact(b, [&](codec::ByteReader& r) {
          auto version = r.u32le();
          auto input_count = r.varint();
          if (!version || !input_count) return false;
          if (*version != static_cast<std::uint32_t>(TxVersionKind::CONFIDENTIAL_V2)) return false;
          if (*input_count > kTxV2MaxInputs) return false;
          tx.version = *version;
          tx.inputs.clear();
          tx.inputs.reserve(*input_count);
          for (std::uint64_t i = 0; i < *input_count; ++i) {
            TxInV2 in;
            if (!parse_txin_v2(r, &in)) return false;
            tx.inputs.push_back(std::move(in));
          }

          auto output_count = r.varint();
          if (!output_count || *output_count > kTxV2MaxOutputs) return false;
          tx.outputs.clear();
          tx.outputs.reserve(*output_count);
          for (std::uint64_t i = 0; i < *output_count; ++i) {
            TxOutV2 out;
            if (!parse_txout_v2(r, &out)) return false;
            tx.outputs.push_back(std::move(out));
          }

          auto lock_time = r.u32le();
          auto fee = r.u64le();
          auto excess_commitment = r.bytes_fixed<33>();
          auto excess_pubkey = r.bytes_fixed<32>();
          auto excess_sig = r.bytes_fixed<64>();
          if (!lock_time || !fee || !excess_commitment || !excess_pubkey || !excess_sig) return false;
          tx.lock_time = *lock_time;
          tx.fee = *fee;
          tx.balance_proof.excess_commitment = crypto::Commitment33{*excess_commitment};
          tx.balance_proof.excess_pubkey = *excess_pubkey;
          tx.balance_proof.excess_sig = *excess_sig;
          return true;
        })) {
      return std::nullopt;
    }
    return tx;
  } catch (...) {
    return std::nullopt;
  }
}

Hash32 TxV2::txid() const { return crypto::sha256d(serialize()); }

std::optional<AnyTx> parse_any_tx(const Bytes& b) {
  if (b.size() < sizeof(std::uint32_t)) return std::nullopt;
  codec::ByteReader r(b);
  auto version = r.u32le();
  if (!version) return std::nullopt;
  if (*version == static_cast<std::uint32_t>(TxVersionKind::TRANSPARENT_V1)) {
    auto tx = Tx::parse(b);
    if (!tx.has_value()) return std::nullopt;
    return AnyTx{*tx};
  }
  if (*version == static_cast<std::uint32_t>(TxVersionKind::CONFIDENTIAL_V2)) {
    auto tx = TxV2::parse(b);
    if (!tx.has_value()) return std::nullopt;
    return AnyTx{*tx};
  }
  return std::nullopt;
}

Bytes serialize_any_tx(const AnyTx& tx) {
  return std::visit([](const auto& value) { return value.serialize(); }, tx);
}

Hash32 txid_any(const AnyTx& tx) {
  return std::visit([](const auto& value) { return value.txid(); }, tx);
}

namespace {

void write_timed(codec::ByteWriter& w, const TxTimed& tx, bool with_script_sig, bool with_body) {
  w.u32le(tx.version);
  w.bytes_fixed(tx.fee_input.prev_txid);
  w.u32le(tx.fee_input.prev_index);
  w.varbytes(with_script_sig ? tx.fee_input.script_sig : Bytes{});
  w.u32le(tx.fee_input.sequence);
  w.u64le(tx.prepaid_fee);
  w.u64le(tx.forfeit_bond);
  w.varbytes(tx.bond_refund_script);
  w.u8(tx.fee_change.has_value() ? 1 : 0);
  if (tx.fee_change) {
    w.u64le(tx.fee_change->value);
    w.varbytes(tx.fee_change->script_pubkey);
  }
  w.u64le(tx.unlock_height);
  w.u64le(tx.committee_epoch);
  w.bytes_fixed(tx.committee_root);
  w.varbytes(tx.swe_ciphertext);
  w.varbytes(tx.swe_proof);
  w.bytes_fixed(tx.body_nonce);
  w.varbytes(with_body ? tx.body_ciphertext : Bytes{});
}

std::optional<Bytes> read_capped(codec::ByteReader& r, std::size_t cap) {
  auto len = r.varint();
  if (!len || *len > cap || *len > r.remaining()) return std::nullopt;
  return r.bytes(static_cast<std::size_t>(*len));
}

}  // namespace

Bytes TxTimed::serialize() const {
  codec::ByteWriter w;
  write_timed(w, *this, true, true);
  return w.take();
}

std::optional<TxTimed> TxTimed::parse(const Bytes& b) {
  TxTimed tx;
  try {
    if (!codec::parse_exact(b, [&](codec::ByteReader& r) {
          const auto version = r.u32le();
          if (!version || *version != static_cast<std::uint32_t>(TxTimedVersionKind::TIMED_V3)) return false;
          tx.version = *version;
          const auto prev = r.bytes_fixed<32>();
          const auto idx = r.u32le();
          const auto script = read_capped(r, kTxTimedMaxScriptBytes);
          const auto seq = r.u32le();
          const auto fee = r.u64le();
          const auto bond = r.u64le();
          const auto refund = read_capped(r, kTxTimedMaxScriptBytes);
          const auto has_change = r.u8();
          if (!prev || !idx || !script || !seq || !fee || !bond || !refund || !has_change || *has_change > 1) {
            return false;
          }
          tx.fee_input = TxIn{*prev, *idx, *script, *seq};
          tx.prepaid_fee = *fee;
          tx.forfeit_bond = *bond;
          tx.bond_refund_script = *refund;
          if (*has_change == 1) {
            const auto value = r.u64le();
            const auto spk = read_capped(r, kTxTimedMaxScriptBytes);
            if (!value || !spk) return false;
            tx.fee_change = TxOut{*value, *spk};
          }
          const auto unlock = r.u64le();
          const auto epoch = r.u64le();
          const auto root = r.bytes_fixed<32>();
          const auto ct = read_capped(r, kTxTimedMaxSweCiphertextBytes);
          const auto proof = read_capped(r, kTxTimedSweProofBytes);
          const auto nonce = r.bytes_fixed<12>();
          const auto body = read_capped(r, kTxTimedMaxBodyCiphertextBytes);
          if (!unlock || !epoch || !root || !ct || !proof || !nonce || !body) return false;
          if (proof->size() != kTxTimedSweProofBytes || body->size() < kTxTimedBodyTagBytes) return false;
          tx.unlock_height = *unlock;
          tx.committee_epoch = *epoch;
          tx.committee_root = *root;
          tx.swe_ciphertext = std::move(*ct);
          tx.swe_proof = std::move(*proof);
          tx.body_nonce = *nonce;
          tx.body_ciphertext = std::move(*body);
          return true;
        })) {
      return std::nullopt;
    }
  } catch (...) {
    return std::nullopt;
  }
  return tx;
}

Hash32 TxTimed::txid() const { return crypto::sha256d(serialize()); }

Hash32 TxTimed::body_aad() const {
  codec::ByteWriter w;
  w.bytes(Bytes{'S', 'C', '-', 'T', 'I', 'M', 'E', 'D', '-', 'A', 'A', 'D', '-', 'V', '1'});
  write_timed(w, *this, false, false);
  return crypto::sha256d(w.data());
}

bool seal_timed_body(TxTimed& tx, const Hash32& key, const AnyTx& body) {
  if (sodium_init() < 0) return false;
  const Bytes plain = serialize_any_tx(body);
  if (plain.size() + kTxTimedBodyTagBytes > kTxTimedMaxBodyCiphertextBytes) return false;
  const Hash32 aad = tx.body_aad();
  Bytes out(plain.size() + crypto_aead_chacha20poly1305_ietf_ABYTES);
  unsigned long long out_len = 0;
  if (crypto_aead_chacha20poly1305_ietf_encrypt(out.data(), &out_len, plain.data(), plain.size(), aad.data(), aad.size(),
                                                nullptr, tx.body_nonce.data(), key.data()) != 0) {
    return false;
  }
  out.resize(static_cast<std::size_t>(out_len));
  tx.body_ciphertext = std::move(out);
  return true;
}

std::optional<AnyTx> open_timed_body(const TxTimed& tx, const Hash32& key) {
  if (sodium_init() < 0) return std::nullopt;
  if (tx.body_ciphertext.size() < crypto_aead_chacha20poly1305_ietf_ABYTES) return std::nullopt;
  const Hash32 aad = tx.body_aad();
  Bytes plain(tx.body_ciphertext.size() - crypto_aead_chacha20poly1305_ietf_ABYTES);
  unsigned long long plain_len = 0;
  if (crypto_aead_chacha20poly1305_ietf_decrypt(plain.data(), &plain_len, nullptr, tx.body_ciphertext.data(),
                                                tx.body_ciphertext.size(), aad.data(), aad.size(), tx.body_nonce.data(),
                                                key.data()) != 0) {
    return std::nullopt;
  }
  plain.resize(static_cast<std::size_t>(plain_len));
  return parse_any_tx(plain);  // exact Tx / TxV2 encoding only (parse_exact)
}

Hash32 confidential_history_key(const PubKey33& one_time_pubkey) {
  static constexpr std::string_view kDomain = "FINALIS/conf-history/v1";
  Bytes data(kDomain.begin(), kDomain.end());
  data.insert(data.end(), one_time_pubkey.begin(), one_time_pubkey.end());
  return crypto::sha256(data);
}

}  // namespace finalis
