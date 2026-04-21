// SPDX-License-Identifier: MIT

#include "utxo/confidential_tx.hpp"

#include "codec/bytes.hpp"
#include "crypto/hash.hpp"

namespace finalis {
namespace {

constexpr std::uint64_t kMaxTxV2Inputs = 10'000;
constexpr std::uint64_t kMaxTxV2Outputs = 10'000;
constexpr std::size_t kMaxWitnessBytes = 256 * 1024;
constexpr std::size_t kMaxScriptBytes = 256 * 1024;
constexpr std::size_t kMaxProofBytes = 256 * 1024;
constexpr std::size_t kMaxMemoBytes = 64 * 1024;

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
    if (range_proof->size() > kMaxProofBytes || memo->size() > kMaxMemoBytes) return false;
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
          if (*input_count > kMaxTxV2Inputs) return false;
          tx.version = *version;
          tx.inputs.clear();
          tx.inputs.reserve(*input_count);
          for (std::uint64_t i = 0; i < *input_count; ++i) {
            TxInV2 in;
            if (!parse_txin_v2(r, &in)) return false;
            tx.inputs.push_back(std::move(in));
          }

          auto output_count = r.varint();
          if (!output_count || *output_count > kMaxTxV2Outputs) return false;
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

}  // namespace finalis
