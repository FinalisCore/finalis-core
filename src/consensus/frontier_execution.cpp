#include "consensus/frontier_execution.hpp"

#include <set>
#include <type_traits>

#include "consensus/ingress.hpp"
#include "consensus/randomness.hpp"
#include "codec/bytes.hpp"
#include "consensus/state_commitment.hpp"
#include "crypto/hash.hpp"
#include "crypto/smt.hpp"
#include "utxo/confidential_tx.hpp"

namespace finalis::consensus {

namespace {

Hash32 record_id_for_raw_ingress_record(const Bytes& raw_record) { return crypto::sha256d(raw_record); }

void apply_accepted_tx_to_utxos(const AnyTx& tx, UtxoSetV2* utxos) {
  if (!utxos) return;
  apply_any_tx_to_utxo(tx, *utxos);
}

bool validate_certified_lane_records(const FrontierVector& prev_vector, const FrontierVector& next_vector,
                                     const CertifiedIngressLaneRecords& lane_records,
                                     const FrontierLaneRoots& prev_lane_roots,
                                     FrontierLaneRoots* next_lane_roots, std::vector<Bytes>* ordered_records,
                                     const SpecialValidationContext* ctx, std::string* error) {
  if (!next_lane_roots || !ordered_records) {
    if (error) *error = "missing-certified-ingress-output";
    return false;
  }

  FrontierLaneRoots lane_roots{};
  std::uint64_t max_delta = 0;
  const auto expected_ingress_epoch =
      (ctx && ctx->network && ctx->current_height != 0)
          ? committee_epoch_start(ctx->current_height, ctx->network->committee_epoch_blocks)
          : 0;
  for (std::size_t lane = 0; lane < finalis::INGRESS_LANE_COUNT; ++lane) {
    if (next_vector.lane_max_seq[lane] < prev_vector.lane_max_seq[lane]) {
      if (error) *error = "frontier-vector-rewind lane=" + std::to_string(lane);
      return false;
    }
    const auto delta = next_vector.lane_max_seq[lane] - prev_vector.lane_max_seq[lane];
    if (lane_records[lane].size() != delta) {
      if (error) *error = "frontier-lane-range-size-mismatch lane=" + std::to_string(lane) +
                          " expected=" + std::to_string(delta) +
                          " actual=" + std::to_string(lane_records[lane].size());
      return false;
    }
    max_delta = std::max(max_delta, delta);

    Hash32 lane_root = prev_lane_roots[lane];
    if (delta == 0) {
      lane_roots[lane] = lane_root;
      continue;
    }
    for (std::size_t offset = 0; offset < lane_records[lane].size(); ++offset) {
      const auto expected_seq = prev_vector.lane_max_seq[lane] + static_cast<std::uint64_t>(offset) + 1;
      const auto& record = lane_records[lane][offset];
      if (record.certificate.lane != lane) {
        if (error) *error = "frontier-lane-mismatch lane=" + std::to_string(lane);
        return false;
      }
      if (record.certificate.seq != expected_seq) {
        if (error) *error = "frontier-lane-seq-mismatch lane=" + std::to_string(lane) +
                            " expected=" + std::to_string(expected_seq) +
                            " actual=" + std::to_string(record.certificate.seq);
        return false;
      }
      const auto tx = parse_any_tx(record.tx_bytes);
      if (!tx.has_value()) {
        if (error) *error = "frontier-certified-ingress-parse-failed lane=" + std::to_string(lane) +
                            " seq=" + std::to_string(expected_seq);
        return false;
      }
      if (txid_any(*tx) != record.certificate.txid) {
        if (error) *error = "frontier-certified-ingress-txid-mismatch lane=" + std::to_string(lane) +
                            " seq=" + std::to_string(expected_seq);
        return false;
      }
      const auto tx_hash = crypto::sha256d(record.tx_bytes);
      if (tx_hash != record.certificate.tx_hash) {
        if (error) *error = "frontier-certified-ingress-hash-mismatch lane=" + std::to_string(lane) +
                            " seq=" + std::to_string(expected_seq);
        return false;
      }
      std::string cert_error;
      if (!validate_ingress_certificate_epoch(record.certificate, expected_ingress_epoch, &cert_error)) {
        // Legacy compatibility: older databases may store epoch=0 for the first
        // lane record. Keep strict checks for all other records.
        const bool legacy_first_record_epoch =
            expected_seq == 1 && record.certificate.epoch == 0 && record.certificate.prev_lane_root == zero_hash();
        if (legacy_first_record_epoch) {
          cert_error.clear();
        } else {
          if (error) {
            *error = "frontier-certified-ingress-epoch-mismatch lane=" + std::to_string(lane) +
                     " seq=" + std::to_string(expected_seq) + " reason=" + cert_error;
          }
          return false;
        }
      }
      if (!verify_ingress_certificate(record.certificate, {}, &cert_error)) {
        if (error) {
          *error = "frontier-certified-ingress-cert-invalid lane=" + std::to_string(lane) +
                   " seq=" + std::to_string(expected_seq) + " reason=" + cert_error;
        }
        return false;
      }
      if (ctx && ctx->is_committee_member) {
        const auto committee_epoch = expected_ingress_epoch != 0 ? expected_ingress_epoch : record.certificate.epoch;
        for (const auto& sig : record.certificate.sigs) {
          if (!ctx->is_committee_member(sig.validator_pubkey, committee_epoch, 0)) {
            if (error) {
              *error = "frontier-certified-ingress-signer-not-in-committee lane=" + std::to_string(lane) +
                       " seq=" + std::to_string(expected_seq);
            }
            return false;
          }
        }
      }
      if (assign_ingress_lane(*tx) != lane) {
        if (error) *error = "frontier-certified-ingress-lane-assignment-mismatch lane=" + std::to_string(lane) +
                            " seq=" + std::to_string(expected_seq);
        return false;
      }
      if (record.certificate.prev_lane_root != lane_root) {
        if (error) *error = "frontier-certified-ingress-prev-root-mismatch lane=" + std::to_string(lane) +
                            " seq=" + std::to_string(expected_seq);
        return false;
      }
      lane_root = compute_lane_root_append(lane_root, record.certificate.tx_hash);
    }
    lane_roots[lane] = lane_root;
  }

  ordered_records->clear();
  for (std::uint64_t round = 1; round <= max_delta; ++round) {
    for (std::size_t lane = 0; lane < finalis::INGRESS_LANE_COUNT; ++lane) {
      const auto candidate_seq = prev_vector.lane_max_seq[lane] + round;
      if (candidate_seq <= next_vector.lane_max_seq[lane]) {
        const auto index = static_cast<std::size_t>(round - 1);
        ordered_records->push_back(lane_records[lane][index].tx_bytes);
      }
    }
  }

  *next_lane_roots = lane_roots;
  return true;
}

}  // namespace

Hash32 FrontierExecutionResult::result_id() const {
  Bytes pre{'S', 'C', '-', 'F', 'R', '-', 'R', 'E', 'S', 'U', 'L', 'T', '-', 'V', '1'};
  const Bytes transition_bytes = transition.serialize();
  pre.insert(pre.end(), transition_bytes.begin(), transition_bytes.end());
  for (const auto& decision : decisions) {
    const Bytes decision_bytes = decision.serialize();
    pre.insert(pre.end(), decision_bytes.begin(), decision_bytes.end());
  }
  return crypto::sha256d(pre);
}

std::vector<OutPoint> frontier_conflict_domains_for_tx(const AnyTx& tx) {
  return std::visit(
      [](const auto& value) {
        std::vector<OutPoint> out;
        out.reserve(value.inputs.size());
        for (const auto& in : value.inputs) out.push_back(OutPoint{in.prev_txid, in.prev_index});
        return out;
      },
      tx);
}

Hash32 frontier_ordered_slice_commitment(const std::vector<Bytes>& ordered_records) {
  codec::ByteWriter w;
  w.bytes(Bytes{'F', 'I', 'N', 'A', 'L', 'I', 'S', '_', 'F', 'R', 'O', 'N', 'T', 'I', 'E', 'R',
                '_', 'S', 'L', 'I', 'C', 'E', '_', 'V', '1'});
  w.varint(ordered_records.size());
  for (const auto& record : ordered_records) w.varbytes(record);
  return crypto::sha256d(w.data());
}

Hash32 frontier_decisions_commitment(const std::vector<FrontierDecision>& decisions) {
  codec::ByteWriter w;
  w.bytes(Bytes{'F', 'I', 'N', 'A', 'L', 'I', 'S', '_', 'F', 'R', 'O', 'N', 'T', 'I', 'E', 'R',
                '_', 'D', 'E', 'C', 'I', 'S', 'I', 'O', 'N', 'S', '_', 'V', '1'});
  w.varint(decisions.size());
  for (const auto& decision : decisions) w.bytes(decision.serialize());
  return crypto::sha256d(w.data());
}

Hash32 frontier_utxo_state_root(const UtxoSet& utxos) {
  std::vector<std::pair<Hash32, Bytes>> leaves;
  leaves.reserve(utxos.size());
  for (const auto& [op, entry] : utxos) {
    leaves.push_back({utxo_commitment_key(op), utxo_commitment_value(entry.out)});
  }
  return crypto::SparseMerkleTree::compute_root_from_leaves(leaves);
}

Hash32 frontier_utxo_state_root(const UtxoSetV2& utxos) {
  std::vector<std::pair<Hash32, Bytes>> leaves;
  leaves.reserve(utxos.size());
  for (const auto& [op, entry] : utxos) {
    leaves.push_back({utxo_commitment_key(op), utxo_commitment_value(entry)});
  }
  return crypto::SparseMerkleTree::compute_root_from_leaves(leaves);
}

Hash32 frontier_ingress_commitment(const FrontierVector& prev_vector, const FrontierVector& next_vector,
                                   const FrontierLaneRoots& lane_roots) {
  codec::ByteWriter w;
  w.bytes(Bytes{'F', 'I', 'N', 'A', 'L', 'I', 'S', '_', 'F', 'R', 'O', 'N', 'T', 'I', 'E', 'R',
                '_', 'I', 'N', 'G', 'R', 'E', 'S', 'S', '_', 'V', '1'});
  w.varbytes(prev_vector.serialize());
  w.varbytes(next_vector.serialize());
  for (const auto& root : lane_roots) w.bytes_fixed(root);
  return crypto::sha256d(w.data());
}

bool frontier_merge_certified_ingress(const FrontierVector& prev_vector, const FrontierVector& next_vector,
                                      const CertifiedIngressLaneRecords& lane_records,
                                      const FrontierLaneRoots& prev_lane_roots, FrontierLaneRoots* next_lane_roots,
                                      std::vector<Bytes>* ordered_records, const SpecialValidationContext* ctx,
                                      std::string* error) {
  return validate_certified_lane_records(prev_vector, next_vector, lane_records, prev_lane_roots, next_lane_roots,
                                         ordered_records, ctx, error);
}

bool frontier_merge_certified_ingress(const FrontierVector& prev_vector, const FrontierVector& next_vector,
                                      const CertifiedIngressLaneRecords& lane_records,
                                      const FrontierLaneRoots& prev_lane_roots, FrontierLaneRoots* next_lane_roots,
                                      std::vector<Bytes>* ordered_records, std::string* error) {
  return frontier_merge_certified_ingress(prev_vector, next_vector, lane_records, prev_lane_roots, next_lane_roots,
                                          ordered_records, nullptr, error);
}

bool tx_uses_special_scripts(const AnyTx& tx) {
  return std::visit(
      [](const auto& value) {
        for (const auto& out : value.outputs) {
          if constexpr (std::is_same_v<std::decay_t<decltype(value)>, Tx>) {
            if (!is_p2pkh_script_pubkey(out.script_pubkey, nullptr)) return true;
          } else {
            if (out.kind != TxOutputKind::Transparent) continue;
            const auto& transparent = std::get<TransparentTxOutV2>(out.body);
            if (!is_p2pkh_script_pubkey(transparent.script_pubkey, nullptr)) return true;
          }
        }
        return false;
      },
      tx);
}

bool execute_frontier_slice(const UtxoSetV2& parent_utxos, std::uint64_t prev_frontier,
                            const std::vector<Bytes>& ordered_records, const SpecialValidationContext* ctx,
                            FrontierExecutionResult* out, std::string* error) {
  if (!out) {
    if (error) *error = "missing-output";
    return false;
  }

  UtxoSetV2 work = parent_utxos;
  std::set<OutPoint> consumed_domains;
  std::vector<FrontierDecision> decisions;
  decisions.reserve(ordered_records.size());
  std::vector<AnyTx> accepted_txs;
  std::uint64_t accepted_fee_units = 0;

  for (const auto& raw_record : ordered_records) {
    FrontierDecision decision;
    decision.record_id = record_id_for_raw_ingress_record(raw_record);

    auto tx = parse_any_tx(raw_record);
    if (!tx.has_value()) {
      decision.accepted = false;
      decision.reject_reason = FrontierRejectReason::TX_PARSE_FAILED;
      decisions.push_back(decision);
      continue;
    }
    const auto domains = frontier_conflict_domains_for_tx(*tx);
    bool conflict = false;
    for (const auto& domain : domains) {
      if (consumed_domains.find(domain) != consumed_domains.end()) {
        conflict = true;
        break;
      }
    }
    if (conflict) {
      decision.record_id = txid_any(*tx);
      decision.accepted = false;
      decision.reject_reason = FrontierRejectReason::CONFLICT_DOMAIN_USED;
      decisions.push_back(decision);
      continue;
    }

    decision.record_id = txid_any(*tx);
    if (!ctx && tx_uses_special_scripts(*tx)) {
      decision.accepted = false;
      decision.reject_reason = FrontierRejectReason::TX_INVALID;
      decisions.push_back(decision);
      continue;
    }
    const auto validation = validate_any_tx(*tx, 1, work, ctx);
    if (!validation.ok) {
      decision.accepted = false;
      decision.reject_reason = FrontierRejectReason::TX_INVALID;
      decisions.push_back(decision);
      continue;
    }

    for (const auto& domain : domains) consumed_domains.insert(domain);
    apply_accepted_tx_to_utxos(*tx, &work);
    accepted_txs.push_back(*tx);
    accepted_fee_units += validation.cost.fee;
    decision.accepted = true;
    decision.reject_reason = FrontierRejectReason::NONE;
    decisions.push_back(decision);
  }

  FrontierExecutionResult result;
  result.transition.prev_frontier = prev_frontier;
  result.transition.next_frontier = prev_frontier + ordered_records.size();
  result.transition.prev_state_root = frontier_utxo_state_root(parent_utxos);
  result.transition.next_state_root = frontier_utxo_state_root(work);
  result.transition.ordered_slice_commitment = frontier_ordered_slice_commitment(ordered_records);
  result.transition.decisions_commitment = frontier_decisions_commitment(decisions);
  result.decisions = std::move(decisions);
  result.accepted_txs = std::move(accepted_txs);
  result.next_utxos = std::move(work);
  result.accepted_fee_units = accepted_fee_units;
  *out = std::move(result);
  return true;
}

bool execute_frontier_slice(const UtxoSet& parent_utxos, std::uint64_t prev_frontier,
                            const std::vector<Bytes>& ordered_records, const SpecialValidationContext* ctx,
                            FrontierExecutionResult* out, std::string* error) {
  return execute_frontier_slice(upgrade_utxo_set_v2(parent_utxos), prev_frontier, ordered_records, ctx, out, error);
}

bool execute_frontier_lane_prefix(const UtxoSetV2& parent_utxos, const FrontierVector& prev_vector,
                                  const FrontierVector& next_vector, const CertifiedIngressLaneRecords& lane_records,
                                  const FrontierLaneRoots& prev_lane_roots, const SpecialValidationContext* ctx,
                                  FrontierExecutionResult* out, std::string* error) {
  FrontierLaneRoots recomputed_lane_roots{};
  std::vector<Bytes> ordered_records;
  if (!frontier_merge_certified_ingress(prev_vector, next_vector, lane_records, prev_lane_roots, &recomputed_lane_roots,
                                        &ordered_records, ctx, error)) {
    return false;
  }

  for (std::size_t lane = 0; lane < finalis::INGRESS_LANE_COUNT; ++lane) {
    Hash32 expected_root = prev_lane_roots[lane];
    const auto delta = next_vector.lane_max_seq[lane] - prev_vector.lane_max_seq[lane];
    for (std::size_t offset = 0; offset < delta; ++offset) {
      const auto& record = lane_records[lane][offset];
      if (record.certificate.prev_lane_root != expected_root) {
        if (error) *error = "frontier-certified-ingress-prev-root-state-mismatch lane=" + std::to_string(lane) +
                            " seq=" + std::to_string(record.certificate.seq);
        return false;
      }
      expected_root = compute_lane_root_append(expected_root, record.certificate.tx_hash);
    }
    if (expected_root != recomputed_lane_roots[lane]) {
      if (error) *error = "frontier-certified-ingress-root-recompute-mismatch lane=" + std::to_string(lane);
      return false;
    }
  }

  FrontierExecutionResult result;
  if (!execute_frontier_slice(parent_utxos, prev_vector.total_count(), ordered_records, ctx, &result, error)) return false;
  result.transition.prev_vector = prev_vector;
  result.transition.next_vector = next_vector;
  result.transition.ingress_commitment = frontier_ingress_commitment(prev_vector, next_vector, recomputed_lane_roots);
  result.transition.prev_frontier = prev_vector.total_count();
  result.transition.next_frontier = next_vector.total_count();
  result.next_lane_roots = recomputed_lane_roots;
  if (out) *out = std::move(result);
  return true;
}

bool execute_frontier_lane_prefix(const UtxoSet& parent_utxos, const FrontierVector& prev_vector,
                                  const FrontierVector& next_vector, const CertifiedIngressLaneRecords& lane_records,
                                  const FrontierLaneRoots& prev_lane_roots, const SpecialValidationContext* ctx,
                                  FrontierExecutionResult* out, std::string* error) {
  return execute_frontier_lane_prefix(upgrade_utxo_set_v2(parent_utxos), prev_vector, next_vector, lane_records,
                                      prev_lane_roots, ctx, out, error);
}

}  // namespace finalis::consensus
