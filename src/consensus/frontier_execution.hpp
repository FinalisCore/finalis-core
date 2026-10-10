// SPDX-License-Identifier: MIT

#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <vector>

#include "utxo/tx.hpp"
#include "utxo/validate.hpp"

namespace finalis::consensus {

// Consensus bounds on one frontier slice (ordered records of a transition). Proposers stop before
// either is exceeded; execute_frontier_slice rejects a slice that exceeds them.
inline constexpr std::size_t kMaxFrontierSliceRecords = 1000;
inline constexpr std::size_t kMaxFrontierSliceBytes = 1 * 1024 * 1024;

struct CertifiedIngressRecord {
  IngressCertificate certificate;
  Bytes tx_bytes;

  bool operator==(const CertifiedIngressRecord&) const = default;
};

using CertifiedIngressLaneRecords = std::array<std::vector<CertifiedIngressRecord>, finalis::INGRESS_LANE_COUNT>;
using FrontierLaneRoots = std::array<Hash32, finalis::INGRESS_LANE_COUNT>;

struct FrontierExecutionResult {
  FrontierTransition transition;
  std::vector<FrontierDecision> decisions;
  std::vector<AnyTx> accepted_txs;
  UtxoSetV2 next_utxos;
  FrontierLaneRoots next_lane_roots{};
  std::uint64_t accepted_fee_units{0};
  // Confidential turnstile value after this slice (see CanonicalDerivedState::confidential_pool_value).
  std::uint64_t next_confidential_pool_value{0};
  std::vector<PubKey32> effective_committee;

  Hash32 result_id() const;
};

std::vector<OutPoint> frontier_conflict_domains_for_tx(const AnyTx& tx);
Hash32 frontier_ordered_slice_commitment(const std::vector<Bytes>& ordered_records);
Hash32 frontier_decisions_commitment(const std::vector<FrontierDecision>& decisions);
Hash32 frontier_utxo_state_root(const UtxoSet& utxos);
Hash32 frontier_utxo_state_root(const UtxoSetV2& utxos);
Hash32 frontier_ingress_commitment(const FrontierVector& prev_vector, const FrontierVector& next_vector,
                                   const FrontierLaneRoots& lane_roots);
bool frontier_merge_certified_ingress(const FrontierVector& prev_vector, const FrontierVector& next_vector,
                                      const CertifiedIngressLaneRecords& lane_records,
                                      const FrontierLaneRoots& prev_lane_roots, FrontierLaneRoots* next_lane_roots,
                                      std::vector<Bytes>* ordered_records,
                                      const SpecialValidationContext* ctx = nullptr,
                                      std::string* error = nullptr);
bool frontier_merge_certified_ingress(const FrontierVector& prev_vector, const FrontierVector& next_vector,
                                      const CertifiedIngressLaneRecords& lane_records,
                                      const FrontierLaneRoots& prev_lane_roots, FrontierLaneRoots* next_lane_roots,
                                      std::vector<Bytes>* ordered_records, std::string* error);

// Pre-execution confidential verify weight of one ordered record (0 for non-TxV2/unparseable).
// A transition whose records sum above ConfidentialPolicy::max_block_confidential_verify_weight
// is invalid ("frontier-confidential-verify-weight-exceeded").
std::uint64_t ordered_record_confidential_verify_weight(const Bytes& raw_record);
// `parent_confidential_pool_value` is the committed turnstile P of the parent state. Every consensus
// caller must pass the parent's value; a TxV2 that would make P negative is rejected
// (FrontierRejectReason::CONFIDENTIAL_TURNSTILE_NEGATIVE).
bool execute_frontier_slice(const UtxoSetV2& parent_utxos, std::uint64_t parent_confidential_pool_value,
                            std::uint64_t prev_frontier, const std::vector<Bytes>& ordered_records,
                            const SpecialValidationContext* ctx, FrontierExecutionResult* out,
                            std::string* error = nullptr);
bool execute_frontier_slice(const UtxoSet& parent_utxos, std::uint64_t prev_frontier,
                            const std::vector<Bytes>& ordered_records, const SpecialValidationContext* ctx,
                            FrontierExecutionResult* out, std::string* error = nullptr);
bool execute_frontier_lane_prefix(const UtxoSetV2& parent_utxos, std::uint64_t parent_confidential_pool_value,
                                  const FrontierVector& prev_vector, const FrontierVector& next_vector,
                                  const CertifiedIngressLaneRecords& lane_records,
                                  const FrontierLaneRoots& prev_lane_roots, const SpecialValidationContext* ctx,
                                  FrontierExecutionResult* out, std::string* error = nullptr);
bool execute_frontier_lane_prefix(const UtxoSet& parent_utxos, const FrontierVector& prev_vector,
                                  const FrontierVector& next_vector, const CertifiedIngressLaneRecords& lane_records,
                                  const FrontierLaneRoots& prev_lane_roots, const SpecialValidationContext* ctx,
                                  FrontierExecutionResult* out, std::string* error = nullptr);

}  // namespace finalis::consensus
