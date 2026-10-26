// SPDX-License-Identifier: MIT

#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <vector>

#include "crypto/smt.hpp"
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
  // The UTXO commitment tree of next_utxos, maintained incrementally when execution was given the
  // parent's tree (after populate_frontier_transition_metadata: including settlement outputs).
  crypto::PersistentSmt next_utxo_tree;
  bool has_next_utxo_tree{false};

  Hash32 result_id() const;
};

// The UTXO commitment tree: the sparse Merkle tree whose root is frontier_utxo_state_root, held as a
// crypto::PersistentSmt so a block updates only the leaves it touched.
std::pair<Hash32, Hash32> utxo_tree_leaf(const OutPoint& op, const UtxoEntryV2& entry);
crypto::PersistentSmt utxo_tree_from(const UtxoSetV2& utxos);
// `base` with each outpoint in `touched` set to its entry in `utxos`, or removed if absent there.
crypto::PersistentSmt utxo_tree_with(const crypto::PersistentSmt& base, const UtxoSetV2& utxos,
                                     const std::vector<OutPoint>& touched);
// When enabled (tests), every incrementally maintained root is checked against a full recomputation
// and a mismatch aborts.
void set_utxo_tree_crosscheck(bool enabled);
bool utxo_tree_crosscheck();
void check_utxo_tree_against(const crypto::PersistentSmt& tree, const UtxoSetV2& utxos, const char* where);

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
// compute_next_state_root = false leaves result.transition.next_state_root zero: callers that go on to
// populate_frontier_transition_metadata (which sets the post-settlement root) skip hashing the UTXO set.
bool execute_frontier_slice(const UtxoSetV2& parent_utxos, std::uint64_t parent_confidential_pool_value,
                            std::uint64_t prev_frontier, const std::vector<Bytes>& ordered_records,
                            const SpecialValidationContext* ctx, FrontierExecutionResult* out,
                            std::string* error = nullptr, bool compute_next_state_root = true,
                            const crypto::PersistentSmt* parent_utxo_tree = nullptr);
bool execute_frontier_slice(const UtxoSet& parent_utxos, std::uint64_t prev_frontier,
                            const std::vector<Bytes>& ordered_records, const SpecialValidationContext* ctx,
                            FrontierExecutionResult* out, std::string* error = nullptr);
bool execute_frontier_lane_prefix(const UtxoSetV2& parent_utxos, std::uint64_t parent_confidential_pool_value,
                                  const FrontierVector& prev_vector, const FrontierVector& next_vector,
                                  const CertifiedIngressLaneRecords& lane_records,
                                  const FrontierLaneRoots& prev_lane_roots, const SpecialValidationContext* ctx,
                                  FrontierExecutionResult* out, std::string* error = nullptr,
                                  bool compute_next_state_root = true,
                                  const crypto::PersistentSmt* parent_utxo_tree = nullptr);
bool execute_frontier_lane_prefix(const UtxoSet& parent_utxos, const FrontierVector& prev_vector,
                                  const FrontierVector& next_vector, const CertifiedIngressLaneRecords& lane_records,
                                  const FrontierLaneRoots& prev_lane_roots, const SpecialValidationContext* ctx,
                                  FrontierExecutionResult* out, std::string* error = nullptr);


// --- TxTimed value accounting (utxo/confidential_tx.hpp, "Value") ---
//
// The fee input is spent when the TxTimed is included: prepaid_fee is that block's validator fee and
// the rest (exactly fee_change.value) is escrowed. In the execution of unlock_height + 1 the escrow
// settles: released to fee_change if the body applied, otherwise forfeited to that block's
// validator reward. Invariant, checked by the tests: prepaid_fee + released + forfeited equals the
// fee input's value, and released and forfeited are never both non-zero.
struct TimedEscrow {
  OutPoint fee_outpoint{};
  std::uint64_t fee_input_value{0};
  std::uint64_t prepaid_fee{0};      // paid to the validators of the inclusion block
  std::optional<TxOut> fee_change;   // its value is the escrowed amount

  std::uint64_t escrowed() const { return fee_change ? fee_change->value : 0; }
};

// The escrow for an included TxTimed, or nullopt unless fee_input_value == prepaid_fee +
// fee_change.value exactly (no overflow): no implicit fee, nothing unaccounted for.
std::optional<TimedEscrow> open_timed_escrow(const OutPoint& fee_outpoint, std::uint64_t fee_input_value,
                                             std::uint64_t prepaid_fee, const std::optional<TxOut>& fee_change);

struct TimedSettlement {
  std::optional<TxOut> released_change;      // a new output owned by the sender, if the body applied
  std::uint64_t forfeited_to_validators{0};  // added to the settling block's validator reward
};

// body_applied: the body decrypted, opened (open_timed_body), parsed and applied as a whole in the
// settling block. Anything else (no key, a wrong tag, garbage, an invalid or double-spending body)
// forfeits the escrow; the body itself then changes nothing.
TimedSettlement settle_timed_escrow(const TimedEscrow& escrow, bool body_applied);

}  // namespace finalis::consensus
