#include "consensus/state_commitment.hpp"

#include <algorithm>

#include "codec/bytes.hpp"
#include "crypto/hash.hpp"

namespace finalis::consensus {

Hash32 utxo_commitment_key(const OutPoint& op) {
  codec::ByteWriter w;
  w.bytes(Bytes{'S', 'C', '-', 'U', 'T', 'X', 'O', '-', 'K', 'E', 'Y', '-', 'V', '0'});
  w.bytes_fixed(op.txid);
  w.u32le(op.index);
  return crypto::sha256(w.data());
}

Bytes utxo_commitment_value(const TxOut& out) {
  codec::ByteWriter w;
  w.u64le(out.value);
  w.varbytes(out.script_pubkey);
  return w.take();
}

Bytes utxo_commitment_value(const UtxoEntryV2& entry) {
  codec::ByteWriter w;
  w.u8(static_cast<std::uint8_t>(entry.kind));
  if (entry.kind == UtxoOutputKind::Transparent) {
    const auto& transparent = std::get<UtxoTransparentData>(entry.body);
    w.varbytes(utxo_commitment_value(transparent.out));
    return w.take();
  }

  const auto& confidential = std::get<UtxoConfidentialData>(entry.body);
  w.bytes_fixed(confidential.value_commitment.bytes);
  w.bytes_fixed(confidential.one_time_pubkey);
  w.bytes_fixed(confidential.ephemeral_pubkey);
  w.u8(confidential.scan_tag.value);
  w.varbytes(confidential.memo);
  return w.take();
}

Hash32 validator_commitment_key(const PubKey32& pub) {
  codec::ByteWriter w;
  w.bytes(Bytes{'S', 'C', '-', 'V', 'A', 'L', '-', 'K', 'E', 'Y', '-', 'V', '0'});
  w.bytes_fixed(pub);
  return crypto::sha256(w.data());
}

Bytes validator_commitment_value_v3(const ValidatorInfo& info) {
  codec::ByteWriter w;
  w.u8(static_cast<std::uint8_t>(info.status));
  w.u64le(info.joined_height);
  w.u8(info.has_bond ? 1 : 0);
  w.bytes_fixed(info.bond_outpoint.txid);
  w.u32le(info.bond_outpoint.index);
  w.u64le(info.unbond_height);
  return w.take();
}

Bytes validator_commitment_value_v4(const ValidatorInfo& info) {
  codec::ByteWriter w;
  w.u8(static_cast<std::uint8_t>(info.status));
  w.u64le(info.joined_height);
  w.u8(info.has_bond ? 1 : 0);
  w.bytes_fixed(info.bond_outpoint.txid);
  w.u32le(info.bond_outpoint.index);
  w.u64le(info.unbond_height);
  w.u64le(info.eligible_count_window);
  w.u64le(info.participated_count_window);
  w.u64le(info.liveness_window_start);
  w.u64le(info.suspended_until_height);
  w.u64le(info.last_join_height);
  w.u64le(info.last_exit_height);
  w.u32le(info.penalty_strikes);
  return w.take();
}

Bytes validator_commitment_value_v6(const ValidatorInfo& info) {
  codec::ByteWriter w;
  w.u8(static_cast<std::uint8_t>(info.status));
  w.u64le(info.joined_height);
  w.u64le(info.bonded_amount);
  w.bytes_fixed(info.operator_id);
  w.u8(info.has_bond ? 1 : 0);
  w.bytes_fixed(info.bond_outpoint.txid);
  w.u32le(info.bond_outpoint.index);
  w.u64le(info.unbond_height);
  w.u64le(info.eligible_count_window);
  w.u64le(info.participated_count_window);
  w.u64le(info.liveness_window_start);
  w.u64le(info.suspended_until_height);
  w.u64le(info.last_join_height);
  w.u64le(info.last_exit_height);
  w.u32le(info.penalty_strikes);
  return w.take();
}

Bytes validator_commitment_value(const ValidatorInfo& info, std::uint32_t consensus_version) {
  if (consensus_version >= 6) return validator_commitment_value_v6(info);
  if (consensus_version >= 4) return validator_commitment_value_v4(info);
  return validator_commitment_value_v3(info);
}

Bytes append_v3_roots_to_coinbase_script(const Bytes& base_script, const Hash32& utxo_root, const Hash32& validators_root) {
  Bytes out = base_script;
  out.insert(out.end(), kSCR3Prefix.begin(), kSCR3Prefix.end());
  out.insert(out.end(), utxo_root.begin(), utxo_root.end());
  out.insert(out.end(), validators_root.begin(), validators_root.end());
  return out;
}

std::optional<V3Roots> find_scr3_roots_marker(const Bytes& script_sig, MarkerError* err) {
  if (err) *err = MarkerError::kNone;
  std::vector<std::size_t> positions;
  if (script_sig.size() >= kSCR3Prefix.size()) {
    for (std::size_t i = 0; i + kSCR3Prefix.size() <= script_sig.size(); ++i) {
      if (std::equal(kSCR3Prefix.begin(), kSCR3Prefix.end(), script_sig.begin() + static_cast<std::ptrdiff_t>(i))) {
        positions.push_back(i);
      }
    }
  }
  if (positions.empty()) {
    if (err) *err = MarkerError::kMissing;
    return std::nullopt;
  }
  if (positions.size() > 1) {
    if (err) *err = MarkerError::kMultipleMarkers;
    return std::nullopt;
  }

  constexpr std::size_t kMarkerLen = 4 + 32 + 32;
  const std::size_t pos = positions.front();
  if (pos + kMarkerLen != script_sig.size()) {
    if (err) *err = MarkerError::kWrongLength;
    return std::nullopt;
  }

  V3Roots roots{};
  const auto* p = script_sig.data() + pos + 4;
  std::copy(p, p + 32, roots.utxo_root.begin());
  std::copy(p + 32, p + 64, roots.validators_root.begin());
  return roots;
}

}  // namespace finalis::consensus
