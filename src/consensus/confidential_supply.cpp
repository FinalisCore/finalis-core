// SPDX-License-Identifier: MIT

#include "consensus/confidential_supply.hpp"

#include <limits>
#include <map>

#include "codec/bytes.hpp"

namespace finalis::consensus {
namespace {

constexpr std::uint8_t kLedgerVersion = 1;

void mark_unknown(ConfidentialSupplyLedger* ledger) { ledger->known = false; }

}  // namespace

void account_confidential_supply(const UtxoSetV2& pre_slice_utxos, const std::vector<AnyTx>& accepted_txs,
                                 std::uint64_t height, ConfidentialSupplyLedger* ledger) {
  if (!ledger || !ledger->known) return;
  // Transparent outputs created earlier in this slice, so later txs in the slice can spend them.
  std::map<OutPoint, std::uint64_t> slice_transparent_values;
  for (const auto& any : accepted_txs) {
    const Hash32 txid = txid_any(any);
    if (const auto* v1 = std::get_if<Tx>(&any)) {
      for (std::uint32_t i = 0; i < v1->outputs.size(); ++i) slice_transparent_values[OutPoint{txid, i}] = v1->outputs[i].value;
      continue;
    }
    const auto& tx = std::get<TxV2>(any);
    __int128 delta = 0;
    for (const auto& in : tx.inputs) {
      if (in.kind != TxInputKind::Transparent) continue;
      const OutPoint op{in.prev_txid, in.prev_index};
      if (auto it = slice_transparent_values.find(op); it != slice_transparent_values.end()) {
        delta += it->second;
        continue;
      }
      const auto it = pre_slice_utxos.find(op);
      if (it == pre_slice_utxos.end() || it->second.kind != UtxoOutputKind::Transparent) {
        mark_unknown(ledger);
        return;
      }
      delta += std::get<UtxoTransparentData>(it->second.body).out.value;
    }
    for (std::uint32_t i = 0; i < tx.outputs.size(); ++i) {
      if (tx.outputs[i].kind != TxOutputKind::Transparent) continue;
      const auto value = std::get<TransparentTxOutV2>(tx.outputs[i].body).value;
      delta -= value;
      slice_transparent_values[OutPoint{txid, i}] = value;
    }
    delta -= tx.fee;

    const __int128 next = static_cast<__int128>(ledger->pool_value) + delta;
    if (next > std::numeric_limits<std::int64_t>::max() || next < std::numeric_limits<std::int64_t>::min() ||
        !crypto::commitment_sum_add(&ledger->excess_sum, tx.balance_proof.excess_commitment)) {
      mark_unknown(ledger);
      return;
    }
    ledger->pool_value = static_cast<std::int64_t>(next);
    if (ledger->pool_value < 0 && ledger->first_negative_height == 0) ledger->first_negative_height = height;
    ++ledger->txv2_count;
  }
}

ConfidentialSupplyAuditResult audit_confidential_supply(const UtxoSetV2& utxos, const ConfidentialSupplyLedger& ledger) {
  ConfidentialSupplyAuditResult out;
  out.pool_value = ledger.pool_value;
  if (!ledger.known) {
    out.status = ConfidentialSupplyAuditStatus::Unavailable;
    out.detail = "ledger-unavailable (history not replayed)";
    return out;
  }
  if (ledger.pool_value < 0 || ledger.first_negative_height != 0) {
    out.status = ConfidentialSupplyAuditStatus::Failed;
    out.detail = "turnstile-negative pool_value=" + std::to_string(ledger.pool_value) +
                 " first_negative_height=" + std::to_string(ledger.first_negative_height);
    return out;
  }
  crypto::CommitmentSum lhs = ledger.excess_sum;
  for (const auto& [op, entry] : utxos) {
    if (entry.kind != UtxoOutputKind::Confidential) continue;
    ++out.confidential_utxo_count;
    if (!crypto::commitment_sum_add(&lhs, std::get<UtxoConfidentialData>(entry.body).value_commitment)) {
      out.status = ConfidentialSupplyAuditStatus::Failed;
      out.detail = "malformed-utxo-commitment txid=" + hex_encode32(op.txid) + " vout=" + std::to_string(op.index);
      return out;
    }
  }
  const auto expected = crypto::commitment_sum_of_value(static_cast<std::uint64_t>(ledger.pool_value));
  if (!expected.has_value()) {
    out.status = ConfidentialSupplyAuditStatus::Unavailable;
    out.detail = "commitment-backend-unavailable";
    return out;
  }
  if (!(lhs == *expected)) {
    out.status = ConfidentialSupplyAuditStatus::Failed;
    out.detail = "commitment-identity-mismatch pool_value=" + std::to_string(ledger.pool_value) +
                 " confidential_utxos=" + std::to_string(out.confidential_utxo_count);
    return out;
  }
  out.status = ConfidentialSupplyAuditStatus::Ok;
  return out;
}

const char* confidential_supply_audit_status_name(ConfidentialSupplyAuditStatus status) {
  switch (status) {
    case ConfidentialSupplyAuditStatus::Ok:
      return "ok";
    case ConfidentialSupplyAuditStatus::Unavailable:
      return "unavailable";
    case ConfidentialSupplyAuditStatus::Failed:
      return "failed";
  }
  return "unknown";
}

Bytes serialize_confidential_supply_ledger(const ConfidentialSupplyLedger& ledger, std::uint64_t height) {
  codec::ByteWriter w;
  w.u8(kLedgerVersion);
  w.u64le(height);
  w.u8(ledger.known ? 1 : 0);
  w.u64le(static_cast<std::uint64_t>(ledger.pool_value));
  w.u64le(ledger.first_negative_height);
  w.u8(ledger.excess_sum.infinity ? 1 : 0);
  w.bytes_fixed(ledger.excess_sum.point);
  w.u64le(ledger.txv2_count);
  return w.take();
}

std::optional<ConfidentialSupplyLedger> parse_confidential_supply_ledger(const Bytes& bytes, std::uint64_t* height) {
  ConfidentialSupplyLedger out;
  std::uint64_t parsed_height = 0;
  if (!codec::parse_exact(bytes, [&](codec::ByteReader& r) {
        auto version = r.u8();
        auto h = r.u64le();
        auto known = r.u8();
        auto pool = r.u64le();
        auto first_negative = r.u64le();
        auto infinity = r.u8();
        auto point = r.bytes_fixed<33>();
        auto count = r.u64le();
        if (!version || *version != kLedgerVersion || !h || !known || !pool || !first_negative || !infinity || !point ||
            !count) {
          return false;
        }
        parsed_height = *h;
        out.known = *known != 0;
        out.pool_value = static_cast<std::int64_t>(*pool);
        out.first_negative_height = *first_negative;
        out.excess_sum.infinity = *infinity != 0;
        out.excess_sum.point = *point;
        out.txv2_count = *count;
        return true;
      })) {
    return std::nullopt;
  }
  if (height) *height = parsed_height;
  return out;
}

}  // namespace finalis::consensus
