// SPDX-License-Identifier: MIT

#include <atomic>
#include <cstdio>
#include "consensus/frontier_execution.hpp"

#include <limits>
#include <set>
#include <type_traits>

#include "consensus/confidential_supply.hpp"
#include "consensus/ingress.hpp"
#include "consensus/randomness.hpp"
#include "codec/bytes.hpp"
#include "consensus/state_commitment.hpp"
#include "consensus/validator_registry.hpp"
#include "crypto/ed25519.hpp"
#include "crypto/hash.hpp"
#include "crypto/smt.hpp"
#include "crypto/swe.hpp"
#include "crypto/swe_proofs.hpp"
#include "utxo/confidential_tx.hpp"

namespace finalis::consensus {

namespace {

Hash32 record_id_for_raw_ingress_record(const Bytes& raw_record) { return crypto::sha256d(raw_record); }

void apply_accepted_tx_to_utxos(const AnyTx& tx, UtxoSetV2* utxos) {
  if (!utxos) return;
  apply_any_tx_to_utxo(tx, *utxos);
}

bool is_p2pkh_entry(const UtxoEntryV2& entry) {
  const auto out = transparent_txout_from_utxo_entry(entry);
  return out.has_value() && is_p2pkh_script_pubkey(out->script_pubkey, nullptr);
}

// A time-locked body moves value only: P2PKH or confidential inputs and outputs, no validator or
// burn scripts (validator lifecycle changes are never deferred into a sealed envelope).
bool timed_body_is_plain(const AnyTx& body, const UtxoSetV2& utxos) {
  return std::visit(
      [&](const auto& tx) {
        for (const auto& in : tx.inputs) {
          const auto it = utxos.find(OutPoint{in.prev_txid, in.prev_index});
          if (it == utxos.end()) continue;  // missing: validation rejects it
          if (it->second.kind == UtxoOutputKind::Transparent && !is_p2pkh_entry(it->second)) return false;
        }
        for (const auto& out : tx.outputs) {
          if constexpr (std::is_same_v<std::decay_t<decltype(tx)>, Tx>) {
            if (!is_p2pkh_script_pubkey(out.script_pubkey, nullptr)) return false;
          } else {
            if (out.kind != TxOutputKind::Transparent) continue;
            if (!is_p2pkh_script_pubkey(std::get<TransparentTxOutV2>(out.body).script_pubkey, nullptr)) return false;
          }
        }
        return true;
      },
      body);
}

// The body of a due escrow, opened with the parent's time signature: SWE-decrypt the body key with
// the signers the block names, then open the AEAD. Nullopt on any failure (the bond is forfeited).
std::optional<AnyTx> open_due_timed_body(const TxTimed& tx, const TimedExecutionContext& timed) {
  if (!timed.parent_time_signature || timed.parent_committee_keys.empty()) return std::nullopt;
  const auto& keys = timed.parent_committee_keys;
  const auto ct = crypto::SweCiphertext::parse(tx.swe_ciphertext, keys.size(), crypto::kSweKeyChunks);
  if (!ct.has_value()) return std::nullopt;
  std::vector<crypto::BlsPublicKey> signers;
  for (const auto index : timed.parent_time_signature->signer_indices) {
    if (index >= keys.size()) return std::nullopt;
    signers.push_back(keys[index]);
  }
  const auto chunks = crypto::swe_decrypt(*ct, keys, signers, timed.parent_time_signature->aggregate,
                                          time_signature_message(timed.chain_domain, tx.unlock_height),
                                          crypto::kBlsTimeSignatureDst);
  if (!chunks.has_value()) return std::nullopt;
  const auto key = crypto::swe_key_from_chunks(*chunks);
  if (!key.has_value()) return std::nullopt;
  return open_timed_body(tx, *key);
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
      const auto identity = ingress_record_identity(record.tx_bytes);
      if (!identity.has_value()) {
        if (error) *error = "frontier-certified-ingress-parse-failed lane=" + std::to_string(lane) +
                            " seq=" + std::to_string(expected_seq);
        return false;
      }
      if (identity->txid != record.certificate.txid) {
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
        if (error) {
          *error = "frontier-certified-ingress-epoch-mismatch lane=" + std::to_string(lane) +
                   " seq=" + std::to_string(expected_seq) + " reason=" + cert_error;
        }
        return false;
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
      if (identity->lane != lane) {
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

std::uint64_t ordered_record_confidential_verify_weight(const Bytes& raw_record) {
  const auto tx = parse_any_tx(raw_record);
  return tx.has_value() ? any_tx_confidential_verify_weight(*tx) : 0;
}

namespace {
std::atomic<bool> g_utxo_tree_crosscheck{false};
}  // namespace

void set_utxo_tree_crosscheck(bool enabled) { g_utxo_tree_crosscheck = enabled; }
bool utxo_tree_crosscheck() { return g_utxo_tree_crosscheck; }

void check_utxo_tree_against(const crypto::PersistentSmt& tree, const UtxoSetV2& utxos, const char* where) {
  if (!utxo_tree_crosscheck()) return;
  if (tree.size() != utxos.size() || tree.root() != frontier_utxo_state_root(utxos)) {
    std::fprintf(stderr, "utxo-tree-crosscheck-failed where=%s tree_size=%zu utxos=%zu\n", where, tree.size(),
                 utxos.size());
    std::abort();
  }
}

std::pair<Hash32, Hash32> utxo_tree_leaf(const OutPoint& op, const UtxoEntryV2& entry) {
  const auto key = utxo_commitment_key(op);
  return {key, crypto::SparseMerkleTree::leaf_hash(key, utxo_commitment_value(entry))};
}

crypto::PersistentSmt utxo_tree_from(const UtxoSetV2& utxos) {
  std::vector<std::pair<Hash32, Hash32>> leaves;
  leaves.reserve(utxos.size());
  for (const auto& [op, entry] : utxos) leaves.push_back(utxo_tree_leaf(op, entry));
  return crypto::PersistentSmt::from_leaf_hashes(std::move(leaves));
}

crypto::PersistentSmt utxo_tree_with(const crypto::PersistentSmt& base, const UtxoSetV2& utxos,
                                     const std::vector<OutPoint>& touched) {
  std::vector<std::pair<Hash32, std::optional<Hash32>>> changes;
  changes.reserve(touched.size());
  for (const auto& op : touched) {
    if (const auto it = utxos.find(op); it != utxos.end()) {
      const auto [key, leaf] = utxo_tree_leaf(op, it->second);
      changes.push_back({key, leaf});
    } else {
      changes.push_back({utxo_commitment_key(op), std::nullopt});
    }
  }
  return base.updated(changes);
}

bool execute_frontier_slice(const UtxoSetV2& parent_utxos, std::uint64_t parent_confidential_pool_value,
                            std::uint64_t prev_frontier, const std::vector<Bytes>& ordered_records,
                            const SpecialValidationContext* ctx, FrontierExecutionResult* out, std::string* error,
                            bool compute_next_state_root, const crypto::PersistentSmt* parent_utxo_tree,
                            const TimedExecutionContext* timed) {
  if (!out) {
    if (error) *error = "missing-output";
    return false;
  }

  // Consensus: bound the slice's record count and raw bytes before parsing anything.
  if (ordered_records.size() > kMaxFrontierSliceRecords) {
    if (error) *error = "frontier-slice-record-count-exceeded";
    return false;
  }
  std::size_t total_bytes = 0;
  for (const auto& raw_record : ordered_records) {
    total_bytes += raw_record.size();
    if (total_bytes > kMaxFrontierSliceBytes) {
      if (error) *error = "frontier-slice-bytes-exceeded";
      return false;
    }
  }

  // Consensus: bound the transition's confidential verification work before any state
  // transition. Every parseable TxV2 is charged, including ones later rejected, because their
  // signatures and proofs are verified either way.
  const std::uint64_t max_verify_weight = (ctx && ctx->confidential_policy)
                                              ? ctx->confidential_policy->max_block_confidential_verify_weight
                                              : ConfidentialPolicy{}.max_block_confidential_verify_weight;
  std::uint64_t total_verify_weight = 0;
  for (const auto& raw_record : ordered_records) {
    total_verify_weight += ordered_record_confidential_verify_weight(raw_record);
    if (total_verify_weight > max_verify_weight) {
      if (error) *error = "frontier-confidential-verify-weight-exceeded";
      return false;
    }
  }

  UtxoSetV2 work = parent_utxos;
  std::set<OutPoint> consumed_domains;
  std::vector<FrontierDecision> decisions;
  decisions.reserve(ordered_records.size());
  std::vector<AnyTx> accepted_txs;
  std::vector<OutPoint> touched;  // outpoints accepted transactions spent or created
  std::uint64_t accepted_fee_units = 0;
  std::uint64_t confidential_pool_value = parent_confidential_pool_value;
  TimedEscrowState opened_escrows;
  std::vector<TimedSettlementRecord> settlements;

  // Applies one Tx / TxV2 as an accepted record; on rejection nothing changes and `reason` says why.
  const auto try_apply = [&](const AnyTx& tx, FrontierRejectReason* reason) -> bool {
    const auto domains = frontier_conflict_domains_for_tx(tx);
    for (const auto& domain : domains) {
      if (consumed_domains.find(domain) != consumed_domains.end()) {
        *reason = FrontierRejectReason::CONFLICT_DOMAIN_USED;
        return false;
      }
    }
    if (!ctx && tx_uses_special_scripts(tx)) {
      *reason = FrontierRejectReason::TX_INVALID;
      return false;
    }
    const auto validation = validate_any_tx(tx, 1, work, ctx);
    if (!validation.ok) {
      *reason = FrontierRejectReason::TX_INVALID;
      return false;
    }
    // Consensus turnstile: value can only leave the confidential pool if it entered it. Rejecting the
    // tx (not the slice) keeps a certified record from wedging its ingress lane; a transition that
    // accepts such a tx still fails recomputation of its decisions and state root.
    std::uint64_t next_pool_value = confidential_pool_value;
    if (const auto* v2 = std::get_if<TxV2>(&tx)) {
      wide::I128 delta;
      const bool resolved = txv2_confidential_pool_delta(*v2, work, &delta);
      const wide::I128 next = wide::add(wide::i128_from_u64(confidential_pool_value), delta);
      if (!resolved || !wide::fits_u64(next)) {
        *reason = FrontierRejectReason::CONFIDENTIAL_TURNSTILE_NEGATIVE;
        return false;
      }
      next_pool_value = wide::to_u64(next);
    }
    confidential_pool_value = next_pool_value;

    for (const auto& domain : domains) consumed_domains.insert(domain);
    apply_accepted_tx_to_utxos(tx, &work);
    std::visit(
        [&](const auto& value) {
          for (const auto& in : value.inputs) touched.push_back(OutPoint{in.prev_txid, in.prev_index});
          const Hash32 txid = value.txid();
          for (std::uint32_t i = 0; i < value.outputs.size(); ++i) touched.push_back(OutPoint{txid, i});
        },
        tx);
    accepted_txs.push_back(tx);
    accepted_fee_units += validation.cost.fee;
    return true;
  };

  // Settlement first: every escrow locked to the parent height, in inclusion order, before any record
  // of this block (so no record can front-run a revealed body to make it a double spend).
  if (timed != nullptr && timed->escrows != nullptr && timed->height >= 2) {
    const auto unlock = timed->height - 1;
    for (auto it = timed->escrows->lower_bound(TimedEscrowKey{unlock, 0, 0});
         it != timed->escrows->end() && it->first.unlock_height == unlock; ++it) {
      const auto& envelope = it->second;
      TimedSettlementRecord record{it->first, envelope.txid(), false, std::nullopt, std::nullopt,
                                   envelope.bond_refund_script};
      if (const auto body = open_due_timed_body(envelope, *timed); body.has_value()) {
        record.body_txid = txid_any(*body);
        FrontierRejectReason reason = FrontierRejectReason::NONE;
        record.body_applied = timed_body_is_plain(*body, work) && try_apply(*body, &reason);
        if (record.body_applied) record.applied_body = *body;
      }
      const auto settled = settle_timed_escrow(
          TimedEscrow{OutPoint{envelope.fee_input.prev_txid, envelope.fee_input.prev_index}, envelope.forfeit_bond,
                      envelope.bond_refund_script},
          record.body_applied);
      if (settled.refund.has_value()) {
        work[timed_refund_outpoint(record.timed_txid)] = UtxoEntryV2{*settled.refund};
        touched.push_back(timed_refund_outpoint(record.timed_txid));
      }
      accepted_fee_units += settled.forfeited_fee;
      settlements.push_back(record);
    }
  }

  // Inclusion of one TxTimed: the envelope rules (check_timed_inclusion), then the block's caps and conflicts.
  const auto try_include_timed = [&](const TxTimed& tx) -> bool {
    if (timed == nullptr || timed->escrows == nullptr || !timed->committee_keys) return false;
    if (opened_escrows.size() >= kMaxTimedTxPerBlock) return false;
    std::size_t waiting = 0;
    for (auto it = timed->escrows->lower_bound(TimedEscrowKey{tx.unlock_height, 0, 0});
         it != timed->escrows->end() && it->first.unlock_height == tx.unlock_height; ++it) {
      ++waiting;
    }
    for (const auto& [key, _] : opened_escrows) waiting += key.unlock_height == tx.unlock_height ? 1 : 0;
    if (waiting >= kMaxTimedEscrowsPerUnlockHeight) return false;
    const OutPoint fee_outpoint{tx.fee_input.prev_txid, tx.fee_input.prev_index};
    if (consumed_domains.count(fee_outpoint) != 0) return false;
    TimedInclusion inclusion_value;
    if (!check_timed_inclusion(tx, *timed, work, &inclusion_value)) return false;
    const auto inclusion = std::optional<TimedInclusion>(inclusion_value);
    const auto height = timed->height;

    const auto txid = tx.txid();
    consumed_domains.insert(fee_outpoint);
    work.erase(fee_outpoint);
    touched.push_back(fee_outpoint);
    if (inclusion->change.has_value()) {
      work[timed_change_outpoint(txid)] = UtxoEntryV2{*inclusion->change};
      touched.push_back(timed_change_outpoint(txid));
    }
    accepted_fee_units += inclusion->fee;
    opened_escrows[TimedEscrowKey{tx.unlock_height, height, static_cast<std::uint32_t>(opened_escrows.size())}] = tx;
    return true;
  };

  for (const auto& raw_record : ordered_records) {
    FrontierDecision decision;
    decision.record_id = record_id_for_raw_ingress_record(raw_record);

    auto tx = parse_any_tx(raw_record);
    if (!tx.has_value()) {
      if (const auto timed_tx = TxTimed::parse(raw_record); timed_tx.has_value()) {
        decision.record_id = timed_tx->txid();
        decision.accepted = try_include_timed(*timed_tx);
        decision.reject_reason = decision.accepted ? FrontierRejectReason::NONE : FrontierRejectReason::TX_INVALID;
        decisions.push_back(decision);
        continue;
      }
      decision.accepted = false;
      decision.reject_reason = FrontierRejectReason::TX_PARSE_FAILED;
      decisions.push_back(decision);
      continue;
    }
    decision.record_id = txid_any(*tx);
    FrontierRejectReason reason = FrontierRejectReason::NONE;
    decision.accepted = try_apply(*tx, &reason);
    decision.reject_reason = decision.accepted ? FrontierRejectReason::NONE : reason;
    decisions.push_back(decision);
  }

  FrontierExecutionResult result;
  result.transition.prev_frontier = prev_frontier;
  result.transition.next_frontier = prev_frontier + ordered_records.size();
  if (parent_utxo_tree != nullptr) {
    check_utxo_tree_against(*parent_utxo_tree, parent_utxos, "execution-parent");
    result.transition.prev_state_root = parent_utxo_tree->root();
    result.next_utxo_tree = utxo_tree_with(*parent_utxo_tree, work, touched);
    result.has_next_utxo_tree = true;
    check_utxo_tree_against(result.next_utxo_tree, work, "execution-next");
    if (compute_next_state_root) result.transition.next_state_root = result.next_utxo_tree.root();
  } else {
    result.transition.prev_state_root = frontier_utxo_state_root(parent_utxos);
    if (compute_next_state_root) result.transition.next_state_root = frontier_utxo_state_root(work);
  }
  result.transition.ordered_slice_commitment = frontier_ordered_slice_commitment(ordered_records);
  result.transition.decisions_commitment = frontier_decisions_commitment(decisions);
  result.decisions = std::move(decisions);
  result.accepted_txs = std::move(accepted_txs);
  result.next_utxos = std::move(work);
  result.accepted_fee_units = accepted_fee_units;
  result.next_confidential_pool_value = confidential_pool_value;
  result.opened_escrows = std::move(opened_escrows);
  result.settlements = std::move(settlements);
  *out = std::move(result);
  return true;
}

bool execute_frontier_slice(const UtxoSet& parent_utxos, std::uint64_t prev_frontier,
                            const std::vector<Bytes>& ordered_records, const SpecialValidationContext* ctx,
                            FrontierExecutionResult* out, std::string* error) {
  // A v1 UtxoSet holds no confidential outputs, so its turnstile value is 0.
  return execute_frontier_slice(upgrade_utxo_set_v2(parent_utxos), 0, prev_frontier, ordered_records, ctx, out, error);
}

bool execute_frontier_lane_prefix(const UtxoSetV2& parent_utxos, std::uint64_t parent_confidential_pool_value,
                                  const FrontierVector& prev_vector, const FrontierVector& next_vector,
                                  const CertifiedIngressLaneRecords& lane_records,
                                  const FrontierLaneRoots& prev_lane_roots, const SpecialValidationContext* ctx,
                                  FrontierExecutionResult* out, std::string* error, bool compute_next_state_root,
                                  const crypto::PersistentSmt* parent_utxo_tree, const TimedExecutionContext* timed) {
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
  if (!execute_frontier_slice(parent_utxos, parent_confidential_pool_value, prev_vector.total_count(), ordered_records, ctx,
                              &result, error, compute_next_state_root, parent_utxo_tree, timed)) {
    return false;
  }
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
  return execute_frontier_lane_prefix(upgrade_utxo_set_v2(parent_utxos), 0, prev_vector, next_vector, lane_records,
                                      prev_lane_roots, ctx, out, error);
}

bool check_timed_inclusion(const TxTimed& tx, const TimedExecutionContext& timed, const UtxoSetV2& utxos,
                           TimedInclusion* inclusion_out, std::string* reason) {
  const auto fail = [&](const char* why) {
    if (reason) *reason = why;
    return false;
  };
  if (!timed.committee_keys) return fail("no-committee-context");
  const auto height = timed.height;
  const auto epoch_blocks = std::max<std::uint64_t>(1, timed.committee_epoch_blocks);
  const auto horizon = committee_epoch_start(height, epoch_blocks) + epoch_blocks - 1;
  if (tx.unlock_height < height) return fail("unlock-height-passed");
  if (tx.unlock_height > horizon) return fail("unlock-height-beyond-known-committee");
  const auto epoch = committee_epoch_start(tx.unlock_height, epoch_blocks);
  if (tx.committee_epoch != epoch) return fail("committee-epoch-mismatch");

  const OutPoint fee_outpoint{tx.fee_input.prev_txid, tx.fee_input.prev_index};
  const auto fee_it = utxos.find(fee_outpoint);
  if (fee_it == utxos.end()) return fail("fee-input-missing");
  const auto fee_out = transparent_txout_from_utxo_entry(fee_it->second);
  std::array<std::uint8_t, 20> pkh{};
  if (!fee_out.has_value() || !is_p2pkh_script_pubkey(fee_out->script_pubkey, &pkh)) return fail("fee-input-not-p2pkh");
  Sig64 sig{};
  PubKey32 pub{};
  if (!is_p2pkh_script_sig(tx.fee_input.script_sig, &sig, &pub)) return fail("fee-script-sig-malformed");
  const auto derived = crypto::h160(Bytes(pub.begin(), pub.end()));
  if (!std::equal(derived.begin(), derived.end(), pkh.begin())) return fail("fee-pubkey-hash-mismatch");
  if (!crypto::ed25519_verify(signing_message_for_timed_fee_input(timed.chain_domain, tx), sig, pub)) {
    return fail("fee-signature-invalid");
  }
  if (!is_p2pkh_script_pubkey(tx.bond_refund_script, nullptr)) return fail("refund-script-not-p2pkh");
  if (tx.fee_change.has_value() && !is_p2pkh_script_pubkey(tx.fee_change->script_pubkey, nullptr)) {
    return fail("change-script-not-p2pkh");
  }
  const auto inclusion = open_timed_escrow(fee_outpoint, fee_out->value, tx.prepaid_fee, tx.forfeit_bond,
                                           tx.bond_refund_script, tx.fee_change, timed.min_bond);
  if (!inclusion.has_value()) return fail("value-accounting-or-bond-below-minimum");

  const auto keys = timed.committee_keys(epoch);
  if (!keys.has_value()) return fail("committee-keys-unknown");
  if (tx.committee_root != committee_bls_key_root(*keys)) return fail("committee-root-mismatch");
  const auto ct = crypto::SweCiphertext::parse(tx.swe_ciphertext, keys->size(), crypto::kSweKeyChunks);
  if (!ct.has_value() || ct->key_shares.size() != keys->size()) return fail("swe-ciphertext-invalid");
  if (ct->threshold != quorum_threshold(keys->size())) return fail("swe-threshold-mismatch");
  const auto proof = crypto::SweWellFormednessProof::parse(tx.swe_proof);
  if (!proof.has_value() ||
      !crypto::swe_verify_well_formed(*ct, *keys, time_signature_message(timed.chain_domain, tx.unlock_height),
                                      crypto::kBlsTimeSignatureDst, *proof)) {
    return fail("swe-proof-invalid");
  }
  if (inclusion_out) *inclusion_out = *inclusion;
  return true;
}

Hash32 committee_bls_key_root(const std::vector<crypto::BlsPublicKey>& ordered_bls_keys) {
  codec::ByteWriter w;
  w.bytes(Bytes{'F', 'I', 'N', 'A', 'L', 'I', 'S', '-', 'C', 'O', 'M', 'M', 'I', 'T', 'T', 'E', 'E', '-', 'B', 'L', 'S',
                '-', 'V', '1'});
  w.varint(ordered_bls_keys.size());
  for (const auto& key : ordered_bls_keys) w.bytes_fixed(key);
  return crypto::sha256d(w.data());
}

std::optional<TimedInclusion> open_timed_escrow(const OutPoint& fee_outpoint, std::uint64_t fee_input_value,
                                                std::uint64_t prepaid_fee, std::uint64_t forfeit_bond,
                                                const Bytes& bond_refund_script,
                                                const std::optional<TxOut>& fee_change, std::uint64_t min_bond) {
  if (forfeit_bond < min_bond) return std::nullopt;
  const std::uint64_t change = fee_change ? fee_change->value : 0;
  // value == prepaid + bond + change, each subtraction checked so nothing wraps.
  if (prepaid_fee > fee_input_value) return std::nullopt;
  const std::uint64_t after_fee = fee_input_value - prepaid_fee;
  if (forfeit_bond > after_fee || after_fee - forfeit_bond != change) return std::nullopt;
  TimedInclusion out;
  out.fee = prepaid_fee;
  if (fee_change && fee_change->value > 0) out.change = fee_change;
  out.escrow = TimedEscrow{fee_outpoint, forfeit_bond, bond_refund_script};
  return out;
}

TimedSettlement settle_timed_escrow(const TimedEscrow& escrow, bool body_applied) {
  TimedSettlement out;
  if (body_applied) {
    if (escrow.forfeit_bond > 0) out.refund = TxOut{escrow.forfeit_bond, escrow.bond_refund_script};
  } else {
    out.forfeited_fee = escrow.forfeit_bond;
  }
  return out;
}

}  // namespace finalis::consensus
