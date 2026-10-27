// SPDX-License-Identifier: MIT

#pragma once

#include <compare>
#include <cstddef>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "crypto/bls12_381.hpp"
#include "crypto/smt.hpp"
#include "utxo/confidential_tx.hpp"
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

// --- TxTimed escrows (utxo/confidential_tx.hpp) ---
//
// An included TxTimed waits in the committed escrow state until the block that settles it before
// any of its own records: unlock_height + 1 for a short lock, see "Long locks" for a long one. Keyed so that map order is settlement order: unlock
// height, then inclusion height and position (index among the block's accepted timed records).
struct TimedEscrowKey {
  std::uint64_t unlock_height{0};
  std::uint64_t inclusion_height{0};
  std::uint32_t inclusion_index{0};

  auto operator<=>(const TimedEscrowKey&) const = default;
};
using TimedEscrowState = std::map<TimedEscrowKey, TxTimed>;

// The committee key root a TxTimed names (TxTimed::committee_root):
// sha256d("FINALIS-COMMITTEE-BLS-V1" || varint n || key_1 .. key_n), keys in checkpoint order.
Hash32 committee_bls_key_root(const std::vector<crypto::BlsPublicKey>& ordered_bls_keys);

// Consensus bounds. A block accepts at most kMaxTimedTxPerBlock TxTimed records (each costs an SWE
// well-formedness check, ~45 ms at 128 keys), and at most kMaxTimedEscrowsPerUnlockHeight escrows
// may wait for one unlock height (each costs a decryption, ~94 ms, in the settling block).
inline constexpr std::size_t kMaxTimedTxPerBlock = 8;
inline constexpr std::size_t kMaxTimedEscrowsPerUnlockHeight = 16;
// Provisional: the minimum forfeit_bond (0.01 FLS), a floor on the cost of an envelope that never opens.
inline constexpr std::uint64_t kTxTimedMinForfeitBond = 1'000'000;

// --- Long locks ---
//
// A TxTimed always names the committee of its inclusion epoch (committee_epoch, committee_root). If
// its unlock height lies in that epoch it is a short lock, settled by the next block's
// prev_time_signature. Otherwise it is a long lock: the same validators sign the unlock height once
// it is final, wherever they are then, and a block carries their aggregate as a LongTimeSignature
// (utxo/tx.hpp). The escrow settles in the first block from unlock + 1 to unlock + kTimedLongGraceBlocks
// that carries it; if none does, the bond is refunded at unlock + kTimedLongGraceBlocks + 1 (not the
// sender's failure). The named key set is kept in TimedKeySets while an escrow needs it (checkpoints
// are pruned). A validator whose BLS key a long escrow names cannot withdraw its bond until that
// escrow settles or kTimedLongLienBlocks after its inclusion, whichever is first.
inline constexpr std::uint64_t kTimedLongGraceBlocks = 480;     // one day at 180 s blocks
inline constexpr std::uint64_t kTimedLongLienBlocks = 175'200;  // one year at 180 s blocks
// Provisional: the minimum prepaid fee per epoch a long lock reaches beyond its inclusion epoch.
inline constexpr std::uint64_t kTxTimedLongFeePerEpoch = 100'000;  // 0.001 FLS
// A long lock's body ciphertext (plaintext + Poly1305 tag) is at most this.
inline constexpr std::size_t kTxTimedMaxLongBodyCiphertextBytes = 1024 + 16;
// Escrows a block may settle through its long_time_signatures (each is one SWE decryption).
inline constexpr std::size_t kMaxLongSettlementsPerBlock = 16;

// Key sets of long escrows, by committee_bls_key_root.
using TimedKeySets = std::map<Hash32, std::vector<crypto::BlsPublicKey>>;

// True if `tx` unlocks beyond the epoch it names (a long lock).
bool timed_is_long_lock(const TxTimed& tx, std::uint64_t committee_epoch_blocks);
// The minimum prepaid fee of a long lock included at `height`: kTxTimedLongFeePerEpoch for every
// epoch, started or whole, from the end of `height`'s epoch to unlock_height. 0 for a short lock;
// nullopt on overflow.
std::optional<std::uint64_t> timed_long_lock_min_fee(std::uint64_t height, std::uint64_t unlock_height,
                                                     std::uint64_t committee_epoch_blocks);

// What execution of block `height` needs for timed records. Consensus callers always pass it; without
// it a TxTimed record is rejected and nothing settles.
struct TimedExecutionContext {
  std::uint64_t height{0};
  Hash32 chain_domain{};
  std::uint64_t committee_epoch_blocks{1};
  // Escrows of the parent state (all of them: settlement takes those due, inclusion counts per height).
  const TimedEscrowState* escrows{nullptr};
  // Settlement of unlock height `height - 1`: the parent's time signature (as the block carries it)
  // and the key set of epoch_of(height - 1).
  const TimeSignatureAggregate* parent_time_signature{nullptr};
  std::vector<crypto::BlsPublicKey> parent_committee_keys;
  // Inclusion: the ordered checkpoint keys of an epoch, nullopt if not yet known. A TxTimed may lock
  // to any height from `height` to the end of `height`'s epoch (the horizon of known committees).
  std::function<std::optional<std::vector<crypto::BlsPublicKey>>(std::uint64_t epoch_start)> committee_keys;
  std::uint64_t min_bond{kTxTimedMinForfeitBond};
  // Long locks: the block's long_time_signatures and the parent's key sets.
  const std::vector<LongTimeSignature>* long_time_signatures{nullptr};
  const TimedKeySets* key_sets{nullptr};
};

// Outcome of one settled escrow, in settlement order.
struct TimedSettlementRecord {
  TimedEscrowKey key;
  Hash32 timed_txid{};
  bool body_applied{false};
  std::optional<Hash32> body_txid;  // set when a transfer body opened and parsed
  std::optional<AnyTx> applied_body;
  Bytes bond_refund_script;
  // A long lock nobody opened within the grace period: the bond was refunded, the body never ran.
  bool expired{false};
  // A reveal body's data (body_applied is then true and the bond refunded).
  std::optional<Bytes> revealed_data;
};



// A TxTimed's outputs: the fee change (if any) at index 0 at inclusion, the bond refund at index 1 at
// settlement.
inline OutPoint timed_change_outpoint(const Hash32& timed_txid) { return OutPoint{timed_txid, 0}; }
inline OutPoint timed_refund_outpoint(const Hash32& timed_txid) { return OutPoint{timed_txid, 1}; }

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
  // Timed records: escrows opened by this block (keyed for settlement) and the escrows it settled.
  TimedEscrowState opened_escrows;
  std::vector<TimedSettlementRecord> settlements;
  // Key sets the opened long escrows name.
  TimedKeySets opened_key_sets;

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
                            const crypto::PersistentSmt* parent_utxo_tree = nullptr,
                            const TimedExecutionContext* timed = nullptr);
bool execute_frontier_slice(const UtxoSet& parent_utxos, std::uint64_t prev_frontier,
                            const std::vector<Bytes>& ordered_records, const SpecialValidationContext* ctx,
                            FrontierExecutionResult* out, std::string* error = nullptr);
bool execute_frontier_lane_prefix(const UtxoSetV2& parent_utxos, std::uint64_t parent_confidential_pool_value,
                                  const FrontierVector& prev_vector, const FrontierVector& next_vector,
                                  const CertifiedIngressLaneRecords& lane_records,
                                  const FrontierLaneRoots& prev_lane_roots, const SpecialValidationContext* ctx,
                                  FrontierExecutionResult* out, std::string* error = nullptr,
                                  bool compute_next_state_root = true,
                                  const crypto::PersistentSmt* parent_utxo_tree = nullptr,
                                  const TimedExecutionContext* timed = nullptr);
bool execute_frontier_lane_prefix(const UtxoSet& parent_utxos, const FrontierVector& prev_vector,
                                  const FrontierVector& next_vector, const CertifiedIngressLaneRecords& lane_records,
                                  const FrontierLaneRoots& prev_lane_roots, const SpecialValidationContext* ctx,
                                  FrontierExecutionResult* out, std::string* error = nullptr);


// --- TxTimed value accounting (utxo/confidential_tx.hpp, "Value") ---
//
// At inclusion the fee input is spent into: prepaid_fee (a fee of the inclusion block), fee_change
// (an output created there) and forfeit_bond (escrowed). At unlock_height + 1 the bond settles:
// refunded to bond_refund_script if the body applied, otherwise a fee of the settling block.
// Invariant, checked by the tests: prepaid_fee + change + refund + forfeit == fee input value, and
// refund and forfeit are never both non-zero.
struct TimedEscrow {
  OutPoint fee_outpoint{};
  std::uint64_t forfeit_bond{0};
  Bytes bond_refund_script;
};

struct TimedInclusion {
  std::uint64_t fee{0};               // prepaid_fee: a fee of the inclusion block
  std::optional<TxOut> change;        // created at inclusion
  TimedEscrow escrow;
};

// Nullopt unless fee_input_value == prepaid_fee + forfeit_bond + change exactly (no overflow) and the
// bond is at least min_bond: no implicit fee, nothing unaccounted for, a protocol-minimum penalty.
std::optional<TimedInclusion> open_timed_escrow(const OutPoint& fee_outpoint, std::uint64_t fee_input_value,
                                                std::uint64_t prepaid_fee, std::uint64_t forfeit_bond,
                                                const Bytes& bond_refund_script,
                                                const std::optional<TxOut>& fee_change, std::uint64_t min_bond);

struct TimedSettlement {
  std::optional<TxOut> refund;         // the bond back to the sender, if the body applied
  std::uint64_t forfeited_fee{0};      // otherwise: the bond, as a fee of the settling block
};

// body_applied: the body decrypted, opened (open_timed_body), parsed and applied as a whole in the
// settling block, before any non-settlement transaction of it. Anything else (no key, a wrong tag,
// garbage, an invalid or double-spending body) forfeits the bond; the body itself changes nothing.
// A reveal body (TimedReveal) settles as body_applied: its data is published, nothing else changes.
// An expired long lock settles as body_applied (refund) with no body.
TimedSettlement settle_timed_escrow(const TimedEscrow& escrow, bool body_applied);

// The per-envelope inclusion rules of a TxTimed at block timed.height against `utxos` (everything but
// the per-block caps and conflicts with other records of the block): unlock height not passed, the
// inclusion epoch's committee and root, threshold, well-formedness proof, a long lock's fee and body
// size, a P2PKH fee input in `utxos` signed over the envelope, exact value accounting and the
// minimum bond. Mempool admission uses it as is.
// On success `inclusion` (if given) holds the fee, change and escrow; `reason` says why not otherwise.
bool check_timed_inclusion(const TxTimed& tx, const TimedExecutionContext& timed, const UtxoSetV2& utxos,
                           TimedInclusion* inclusion = nullptr, std::string* reason = nullptr);

}  // namespace finalis::consensus
