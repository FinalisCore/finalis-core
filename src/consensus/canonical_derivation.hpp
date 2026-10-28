// SPDX-License-Identifier: MIT

#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "common/chain_id.hpp"
#include "common/network.hpp"
#include "consensus/availability_retention.hpp"
#include "consensus/confidential_supply.hpp"
#include "consensus/frontier_execution.hpp"
#include "consensus/validator_registry.hpp"
#include "genesis/genesis.hpp"
#include "storage/db.hpp"
#include "utxo/validate.hpp"
#include "utxo/tx.hpp"

namespace finalis::consensus {

// Transition timestamps are bounded below by the chain (strictly increasing) and above by honest
// validators, which refuse to prevote one stamped more than this far past their wall clock. A leader
// does not propose height 1 until genesis time is within this bound.
inline constexpr std::uint64_t kMaxTransitionTimestampDriftS = 60;

struct CanonicalDerivationConfig {
  NetworkConfig network{};
  ChainId chain_id{};
  std::size_t max_committee{MAX_COMMITTEE};
  std::uint64_t validator_min_bond_override{BOND_AMOUNT};
  std::uint64_t validator_bond_min_amount{BOND_AMOUNT};
  std::uint64_t validator_bond_max_amount{BOND_AMOUNT};
  std::uint64_t validator_warmup_blocks{WARMUP_BLOCKS};
  std::uint64_t validator_cooldown_blocks{0};
  std::uint64_t validator_join_limit_window_blocks{0};
  std::uint32_t validator_join_limit_max_new{0};
  std::uint64_t validator_liveness_window_blocks{10'000};
  std::uint32_t validator_miss_rate_suspend_threshold_percent{30};
  std::uint32_t validator_miss_rate_exit_threshold_percent{60};
  std::uint64_t validator_suspend_duration_blocks{1'000};
  availability::AvailabilityConfig availability{};
  std::uint64_t availability_min_eligible_operators{1};
  std::uint32_t validation_rules_version{6};
  ConfidentialPolicy confidential_policy{};
  std::function<std::optional<Hash32>(std::uint64_t)> finalized_hash_at_height;
};

struct CanonicalGenesisState {
  Hash32 genesis_artifact_id{};
  std::vector<PubKey32> initial_validators;
  // Time-signature keys, parallel to initial_validators (genesis::Document::initial_validator_bls,
  // proofs checked by genesis::validate_document); empty leaves the validators without one.
  std::vector<crypto::BlsPublicKey> initial_validator_bls_keys;
  // Parent timestamp of height 1 (unix seconds).
  std::uint64_t genesis_time_unix{0};
};

// The canonical genesis state of a genesis document: artifact id, validators with their BLS keys,
// genesis time. Every builder (node, light client, tools, tests) uses this one.
CanonicalGenesisState canonical_genesis_state_from_document(const genesis::Document& doc);

struct CanonicalFrontierRecord {
  FrontierTransition transition;
  std::vector<Bytes> ordered_records;
  CertifiedIngressLaneRecords lane_records;

  CanonicalFrontierRecord() = default;
  CanonicalFrontierRecord(const FrontierTransition& transition_in, const std::vector<Bytes>& ordered_records_in)
      : transition(transition_in), ordered_records(ordered_records_in) {}
  CanonicalFrontierRecord(const FrontierTransition& transition_in, const CertifiedIngressLaneRecords& lane_records_in)
      : transition(transition_in), lane_records(lane_records_in) {}
};

struct CanonicalFinalizedMetadata {
  std::uint32_t round{0};
  std::uint32_t quorum_threshold{0};
  std::uint32_t signature_count{0};
};

enum class FinalizedIdentityKind : std::uint8_t {
  Genesis = 0,
  Transition = 1,
};

struct FinalizedIdentity {
  FinalizedIdentityKind kind{FinalizedIdentityKind::Genesis};
  Hash32 id{};

  static FinalizedIdentity genesis(const Hash32& genesis_id) {
    return FinalizedIdentity{FinalizedIdentityKind::Genesis, genesis_id};
  }

  static FinalizedIdentity transition(const Hash32& transition_id) {
    return FinalizedIdentity{FinalizedIdentityKind::Transition, transition_id};
  }

  bool is_genesis() const { return kind == FinalizedIdentityKind::Genesis; }
  bool is_transition() const { return kind == FinalizedIdentityKind::Transition; }
  const Hash32& value() const { return id; }
  std::optional<Hash32> genesis_id() const { return is_genesis() ? std::optional<Hash32>(id) : std::nullopt; }
  std::optional<Hash32> transition_id() const { return is_transition() ? std::optional<Hash32>(id) : std::nullopt; }
};

struct CanonicalDerivedState {
  std::uint64_t finalized_height{0};
  std::uint64_t finalized_frontier{0};
  FrontierVector finalized_frontier_vector{};
  FrontierLaneRoots finalized_lane_roots{};
  FinalizedIdentity finalized_identity{};
  // Timestamp (unix seconds) of the finalized tip transition; genesis time at height 0. Each
  // transition's timestamp must exceed it (frontier-timestamp-not-increasing).
  std::uint64_t finalized_timestamp{0};
  Hash32 last_finality_certificate_hash{};
  UtxoSetV2 utxos;
  ValidatorRegistry validators;
  std::map<Hash32, ValidatorJoinRequest> validator_join_requests;
  Hash32 finalized_randomness{};
  std::map<std::uint64_t, Hash32> committee_epoch_randomness_cache;
  std::uint64_t protocol_reserve_balance_units{0};
  // Confidential turnstile P: value held in confidential (TxV2) outputs, accounted from public boundary
  // flows only. Committed; a TxV2 that would make it negative is invalid (confidential-turnstile-negative).
  std::uint64_t confidential_pool_value{0};
  // TxTimed escrows waiting for their unlock height (consensus/frontier_execution.hpp). Committed.
  TimedEscrowState timed_escrows;
  // Key sets the waiting escrows name (long locks), by committee_root. Not committed separately: each
  // is fixed by its root, which the committed escrows carry. Kept because checkpoints are pruned.
  TimedKeySets timed_key_sets;
  // Settlements of the last applied transition (derived, not committed): what the node indexes.
  std::vector<TimedSettlementRecord> last_timed_settlements;
  std::map<std::uint64_t, storage::EpochRewardSettlementState> epoch_reward_states;
  std::map<std::uint64_t, storage::FinalizedCommitteeCheckpoint> finalized_committee_checkpoints;
  std::map<std::uint64_t, CanonicalFinalizedMetadata> finalized_block_metadata;
  std::uint64_t validator_join_window_start_height{0};
  std::uint32_t validator_join_count_in_window{0};
  std::uint64_t validator_liveness_window_start_height{0};
  std::size_t last_participation_eligible_signers{0};
  availability::AvailabilityPersistentState availability_state;
  // Derived supply-audit accumulators; deliberately not part of state_commitment.
  ConfidentialSupplyLedger confidential_supply;
  Hash32 state_commitment{};
  // Commitment tree of `utxos` (root = frontier_utxo_state_root(utxos)), maintained by apply. Use
  // utxo_tree_for(): a state whose tree does not match its UTXO set (e.g. built by hand) gets a fresh one.
  crypto::PersistentSmt utxo_tree;
};

crypto::PersistentSmt utxo_tree_for(const CanonicalDerivedState& state);

struct AdaptiveCheckpointParameters {
  std::uint64_t qualified_depth{0};
  std::uint64_t target_committee_size{1};
  std::uint64_t min_eligible_operators{1};
  std::uint64_t min_bond{150ULL * BASE_UNITS_PER_COIN};
  std::uint32_t target_expand_streak{0};
  std::uint32_t target_contract_streak{0};
};

bool build_genesis_canonical_state(const CanonicalDerivationConfig& cfg, const CanonicalGenesisState& genesis,
                                   CanonicalDerivedState* out, std::string* error);
std::uint64_t genesis_validator_bond_amount();
Hash32 canonical_finality_certificate_hash(const FinalityCertificate& cert);
Hash32 frontier_finality_link_hash(const FrontierTransition& transition);
// Synthetic txid of the transition's settlement (reward payout) outputs: OutPoint{txid, i} pays
// transition.settlement.outputs[i]. No transaction with this id exists.
Hash32 frontier_settlement_txid(const FrontierTransition& transition);
// The finalized parent of the next frontier transition, as needed to verify and
// account its participation record (FrontierTransition::prev_finality_signers).
struct ParentFinalityContext {
  bool has_parent{false};  // false when the parent is genesis
  std::uint64_t height{0};
  std::uint32_t round{0};
  Hash32 transition_id{};
  std::vector<PubKey32> committee;
  std::size_t quorum{0};
};

// Resolves the parent (prev.finalized_height) context at the parent's commit round, which a child
// names in prev_finality_round and which is never earlier than the parent transition's own round.
// The committee is the canonical committee for (parent height, commit round). Signatures are not
// checked here.
bool resolve_parent_finality_context(const CanonicalDerivationConfig& cfg, const CanonicalDerivedState& prev,
                                     std::uint32_t parent_commit_round, ParentFinalityContext* out,
                                     std::string* error);
// Sorts and dedups `signers` by pubkey, then requires: empty and commit round 0 iff the parent is
// genesis; otherwise every signer is a parent committee member with a valid precommit signature
// over (parent height, parent_commit_round, parent transition id), and the count is at least the
// parent quorum.
bool canonicalize_and_verify_prev_finality_signers(const CanonicalDerivationConfig& cfg,
                                                   const CanonicalDerivedState& prev,
                                                   const std::vector<FinalitySig>& signers,
                                                   std::uint32_t parent_commit_round,
                                                   std::vector<FinalitySig>* canonical, std::string* error);
// Accrues one finalized frontier transition into its epoch's reward state:
// emission and fees for transition.height, the leader's score, and committee
// participation for the parent height (parent_committee vs the signer pubkeys
// in transition.prev_finality_signers). Shared by canonical derivation and the
// node's frozen-epoch rebuild so the two cannot drift.
// The timed context for executing block `height` on `prev`, settling with `parent_time_signature`
// (the block's own prev_time_signature). Holds pointers into `prev` and `parent_time_signature`.
// `long_time_signatures`: the block's openings of long locks (also held by pointer).
TimedExecutionContext timed_execution_context_for(const CanonicalDerivationConfig& cfg, const CanonicalDerivedState& prev,
                                                  std::uint64_t height,
                                                  const TimeSignatureAggregate& parent_time_signature,
                                                  const std::vector<LongTimeSignature>* long_time_signatures = nullptr);
// Escrows after a block: those it settled removed, the opened ones added; key sets added for the
// opened long escrows and dropped once no escrow names them.
void apply_timed_escrows(const FrontierExecutionResult& result, TimedEscrowState* escrows, TimedKeySets* key_sets);
// True if `validator`'s BLS key is named by a long escrow of `state` included less than
// kTimedLongLienBlocks before `height`: its bond cannot be withdrawn yet.
bool timed_bond_lien(const CanonicalDerivedState& state, const PubKey32& validator, std::uint64_t height,
                     std::uint64_t committee_epoch_blocks);
// Root of the escrow set as committed in the post-state (one leaf per escrow: key -> envelope txid).
Hash32 timed_escrow_commitment_root(const TimedEscrowState& escrows);
// Time signatures (TimeSignatureAggregate). The key set of a height is its epoch checkpoint's
// ordered_bls_keys; a valid aggregate needs time_signature_threshold(n) of them, the same quorum
// that finalizes the height, so the f validators an adversary may hold can never produce one (and
// never open a TxTimed early), while the honest quorum always can once the height is final.
std::size_t time_signature_threshold(std::size_t committee_size);
// The epoch checkpoint keys for `height`, nullopt if the checkpoint is missing or a key is unset.
std::optional<std::vector<crypto::BlsPublicKey>> time_signature_committee_keys(const CanonicalDerivationConfig& cfg,
                                                                               const CanonicalDerivedState& state,
                                                                               std::uint64_t height);
// Requires: no signers and a zero aggregate iff the parent (prev.finalized_height) is genesis;
// otherwise strictly ascending indices into the parent's committee keys, at least the threshold,
// and an aggregate that verifies for them on time_signature_message(chain domain, parent height).
bool verify_prev_time_signature(const CanonicalDerivationConfig& cfg, const CanonicalDerivedState& prev,
                                const TimeSignatureAggregate& time_signature, std::string* error);
// Aggregates the lowest-index `threshold` signatures of `sigs` (index -> signature, each already
// verified); nullopt if there are fewer.
std::optional<TimeSignatureAggregate> aggregate_time_signatures(const std::vector<crypto::BlsPublicKey>& committee_keys,
                                                                const std::map<std::uint32_t, crypto::BlsSignature>& sigs,
                                                                std::size_t threshold);
void accrue_frontier_epoch_reward(const CanonicalDerivationConfig& cfg, const ValidatorRegistry& validators,
                                  std::map<std::uint64_t, storage::EpochRewardSettlementState>* reward_states,
                                  const FrontierTransition& transition,
                                  const std::vector<PubKey32>& parent_committee);
bool populate_frontier_transition_metadata(const CanonicalDerivationConfig& cfg, const CanonicalDerivedState& prev,
                                           std::uint64_t height, std::uint32_t round, const PubKey32& leader_pubkey,
                                           std::uint32_t prev_finality_round,
                                           const std::vector<FinalitySig>& prev_finality_signers,
                                           const TimeSignatureAggregate& prev_time_signature,
                                           std::uint64_t accepted_fee_units, const UtxoSetV2& post_execution_utxos,
                                           FrontierTransition* transition,
                                           std::string* error,
                                           const crypto::PersistentSmt* post_execution_tree = nullptr,
                                           crypto::PersistentSmt* settled_tree_out = nullptr);
bool load_certified_frontier_record_from_storage(const storage::DB& db, const FrontierTransition& transition,
                                                 CanonicalFrontierRecord* out, std::string* error);
bool verify_frontier_record_against_state(const CanonicalDerivationConfig& cfg, const CanonicalDerivedState& prev,
                                          const CanonicalFrontierRecord& record, FrontierExecutionResult* recomputed,
                                          std::string* error,
                                          std::string* validation_diagnostics = nullptr);
// accepted_txids (optional): txids of the slice's transactions that execution accepted. A finalized
// slice may also carry rejected transactions, which moved no funds and must not be indexed as transfers.
bool apply_frontier_record(const CanonicalDerivationConfig& cfg, const CanonicalDerivedState& prev,
                           const CanonicalFrontierRecord& record, CanonicalDerivedState* out, std::string* error,
                           std::set<Hash32>* accepted_txids = nullptr);
// Votes of round `vote_round` can certify a transition of round `transition_round` only from its own
// round on (a re-proposed valid value is precommitted in later rounds, never earlier). The derivation
// rejects a certificate below it, so the live path must ignore polkas, locks and precommit quorums
// below it too: a node that finalized from one could not restart from its own database.
inline bool vote_round_covers_transition(std::uint32_t vote_round, std::uint32_t transition_round) {
  return vote_round >= transition_round;
}
// Checks `cert` finalizes `transition` with a quorum of valid precommits from the committee that
// `state`'s checkpoints give for (transition.height, cert.round).
bool verify_frontier_finality_certificate(const CanonicalDerivationConfig& cfg, const CanonicalDerivedState& state,
                                          const FrontierTransition& transition, const FinalityCertificate& cert,
                                          std::string* error);
// For a proposer: applies `record` without checking its next_state_commitment and returns the value
// that field must hold. Everything else is verified as in apply_frontier_record.
bool derive_frontier_next_state_commitment(const CanonicalDerivationConfig& cfg, const CanonicalDerivedState& prev,
                                           const CanonicalFrontierRecord& record, Hash32* out, std::string* error);
bool derive_canonical_state_from_frontier_chain(const CanonicalDerivationConfig& cfg,
                                                const CanonicalDerivedState& initial_state,
                                                const std::vector<CanonicalFrontierRecord>& chain,
                                                CanonicalDerivedState* out, std::string* error);
// on_applied, when set, sees each height's resulting state with its transition and certificate.
using FrontierReplayObserver =
    std::function<void(const CanonicalDerivedState&, const FrontierTransition&, const FinalityCertificate&)>;
bool derive_canonical_state_from_frontier_storage(const CanonicalDerivationConfig& cfg,
                                                  const CanonicalDerivedState& initial_state,
                                                  const storage::DB& db,
                                                  CanonicalDerivedState* out, std::string* error,
                                                  const FrontierReplayObserver& on_applied = {});
// History the consensus state keeps (and commits to), counted back from the epoch of the next height:
// - committee checkpoints: the unbond delay plus 2 epochs, so equivocation evidence can be checked
//   against its height's committee for as long as the bond can still be slashed; this also covers the
//   ticket difficulty / adaptive lookbacks (at most 6 epochs);
// - block metadata and per-epoch randomness: kRetainedMetadataEpochs (ticket difficulty reads 6);
// - reward states: unsettled ones, and settled ones for one more epoch.
// Older entries are dropped from the state by prune_consensus_history at every height, so the state
// and the work per block stay bounded. The database keeps its history rows for queries.
inline constexpr std::uint64_t kRetainedMetadataEpochs = 8;
std::uint64_t retained_checkpoint_floor(const CanonicalDerivationConfig& cfg, std::uint64_t finalized_height);
std::uint64_t retained_metadata_floor(const CanonicalDerivationConfig& cfg, std::uint64_t finalized_height);
void prune_consensus_history(const CanonicalDerivationConfig& cfg, CanonicalDerivedState* state);
// The ticket difficulty checkpoint derivation uses for `epoch_start_height`, from finalized state (the
// same rule and inputs the next checkpoint will be derived with).
std::uint8_t ticket_difficulty_bits_for_epoch_from_state(const CanonicalDerivationConfig& cfg,
                                                         const CanonicalDerivedState& state,
                                                         std::uint64_t epoch_start_height);

// Commitment to the post-state of a finalized transition: everything consensus_state_commitment covers
// except finalized_identity and last_finality_certificate_hash, which are derived from the transition
// itself. A FrontierTransition signs it as next_state_commitment. known_utxo_root, when given, must equal
// frontier_utxo_state_root(state.utxos).
Hash32 consensus_post_state_commitment(const CanonicalDerivationConfig& cfg, const CanonicalDerivedState& state,
                                       const Hash32* known_utxo_root = nullptr);
// The bytes consensus_post_state_commitment hashes (sha256d). Fixed layout up to the checkpoint root:
// tag(16) height(8) frontier(8) utxo_root(32) validator_root(32) randomness(32) reward_root(32)
// reserve(8) checkpoint_root(32); see kPostStatePreimage* offsets.
Bytes consensus_post_state_preimage(const CanonicalDerivationConfig& cfg, const CanonicalDerivedState& state,
                                    const Hash32* known_utxo_root = nullptr);
inline constexpr std::size_t kPostStatePreimageHeightOffset = 16;
inline constexpr std::size_t kPostStatePreimageUtxoRootOffset = 32;
inline constexpr std::size_t kPostStatePreimageCheckpointRootOffset = 168;
// A committee checkpoint as a leaf of the post-state commitment's checkpoint tree.
Hash32 checkpoint_commitment_key(std::uint64_t epoch_start_height);
Bytes checkpoint_commitment_value(const storage::FinalizedCommitteeCheckpoint& checkpoint);
std::optional<storage::FinalizedCommitteeCheckpoint> parse_checkpoint_commitment_value(const Bytes& bytes);
std::vector<std::pair<Hash32, Bytes>> checkpoint_commitment_leaves(
    const std::map<std::uint64_t, storage::FinalizedCommitteeCheckpoint>& checkpoints);
// sha256d("SC-CANON-STATE-V3" || finalized_identity.id || last_finality_certificate_hash || post-state commitment).
Hash32 consensus_state_commitment(const CanonicalDerivationConfig& cfg, const CanonicalDerivedState& state);
Hash32 consensus_state_commitment_from_post_state(const CanonicalDerivedState& state, const Hash32& post_state_commitment);
std::uint64_t qualified_depth_at_checkpoint(const ValidatorRegistry& validators, std::uint64_t height,
                                            std::uint64_t effective_min_bond,
                                            const availability::AvailabilityPersistentState& availability_state,
                                            const availability::AvailabilityConfig& availability_cfg);
std::uint64_t derive_adaptive_committee_target(const std::optional<storage::FinalizedCommitteeCheckpoint>& previous_checkpoint,
                                               std::uint64_t qualified_depth, std::uint32_t* expand_streak,
                                               std::uint32_t* contract_streak);
std::uint64_t derive_adaptive_min_eligible(std::uint64_t target_committee_size);
// FALLBACK -> NORMAL needs at least this many eligible operators (spec §8: min + 2).
std::uint64_t fallback_recovery_threshold(std::uint64_t min_eligible_operators);
std::uint64_t derive_adaptive_min_bond(std::uint64_t target_committee_size, std::uint64_t qualified_depth);
AdaptiveCheckpointParameters adaptive_checkpoint_parameters_from_metadata(
    const std::optional<storage::FinalizedCommitteeCheckpoint>& checkpoint);
AdaptiveCheckpointParameters derive_adaptive_checkpoint_parameters(
    const std::optional<storage::FinalizedCommitteeCheckpoint>& previous_checkpoint, std::uint64_t qualified_depth);
bool bootstrap_availability_grace_active(const ValidatorRegistry& validators, std::uint64_t height);

// Registration bond floor at `height` (PROTOCOL-SPEC min_bond(height)). Single source of truth for
// replay validation and the live node (proposer, mempool). Values equal to BOND_AMOUNT mean "no
// override"; anything else pins the floor to max(min_bond_override, bond_min_amount).
std::uint64_t effective_validator_min_bond_for_height(const NetworkConfig& network, std::uint64_t min_bond_override,
                                                      std::uint64_t bond_min_amount, const ValidatorRegistry& validators,
                                                      std::uint64_t height);

// Emergency committee recovery (consensus rule). When no candidate survives the checkpoint
// filters, the committee is the first kEmergencyFallbackMaxMembers distinct members of the
// kEmergencyFallbackLookbackEpochs most recent prior checkpoints (newest epoch first, checkpoint
// order within an epoch) that still hold a bond and are not BANNED/ONBOARDING/EXITING, sorted by pubkey.
inline constexpr std::size_t kEmergencyFallbackMaxMembers = 4;
inline constexpr std::uint64_t kEmergencyFallbackLookbackEpochs = 2;
std::vector<PubKey32> emergency_fallback_committee_members(
    const ValidatorRegistry& validators,
    const std::map<std::uint64_t, storage::FinalizedCommitteeCheckpoint>& checkpoints, std::uint64_t epoch_start_height,
    std::uint64_t committee_epoch_blocks);
// Sets checkpoint->ordered_bls_keys to each member's registered BLS key, in member order (a zero
// key for a member without one; every registration and genesis entry carries one).
void assign_checkpoint_bls_keys(const ValidatorRegistry& validators, storage::FinalizedCommitteeCheckpoint* checkpoint);
// Fills `checkpoint` (whose ordered_members is empty) with the emergency committee. Returns false
// when there is no prior committee member to recover from.
bool apply_emergency_fallback_committee(const ValidatorRegistry& validators,
                                        const std::map<std::uint64_t, storage::FinalizedCommitteeCheckpoint>& checkpoints,
                                        std::uint64_t committee_epoch_blocks,
                                        storage::FinalizedCommitteeCheckpoint* checkpoint);
bool bootstrap_operator_grandfathered_for_availability(const ValidatorRegistry& validators, const PubKey32& operator_id,
                                                       std::uint64_t height);
std::uint64_t count_eligible_operators_at_checkpoint(const ValidatorRegistry& validators, std::uint64_t height,
                                                     const availability::AvailabilityPersistentState& availability_state,
                                                     const availability::AvailabilityConfig& availability_cfg);
availability::AvailabilityConfig availability_config_with_min_bond(const availability::AvailabilityConfig& base,
                                                                   std::uint64_t min_bond);
bool canonical_checkpoints_equal(const storage::FinalizedCommitteeCheckpoint& a,
                                 const storage::FinalizedCommitteeCheckpoint& b);
bool derive_next_epoch_checkpoint_from_state(const CanonicalDerivationConfig& cfg, const CanonicalDerivedState& state,
                                             std::uint64_t epoch_start_height,
                                             storage::FinalizedCommitteeCheckpoint* out, std::string* error);
bool validate_next_epoch_checkpoint_from_state(const CanonicalDerivationConfig& cfg, const CanonicalDerivedState& state,
                                               std::uint64_t epoch_start_height,
                                               const storage::FinalizedCommitteeCheckpoint& checkpoint,
                                               std::string* error);
bool validate_checkpoint_schedule_for_height(const CanonicalDerivationConfig& cfg, const CanonicalDerivedState& state,
                                             const storage::FinalizedCommitteeCheckpoint& checkpoint,
                                             std::uint64_t height, std::string* error);
bool bootstrap_handoff_complete(const CanonicalDerivedState& state);
std::optional<PubKey32> checkpoint_ticket_pow_fallback_member(const storage::FinalizedCommitteeCheckpoint& checkpoint);
std::optional<PubKey32> checkpoint_ticket_pow_fallback_member_for_round(
    const storage::FinalizedCommitteeCheckpoint& checkpoint, std::uint32_t round);
std::vector<PubKey32> checkpoint_committee_for_round(const storage::FinalizedCommitteeCheckpoint& checkpoint,
                                                     std::uint32_t round);

std::vector<PubKey32> canonical_committee_for_height_round(const CanonicalDerivationConfig& cfg,
                                                           const CanonicalDerivedState& state, std::uint64_t height,
                                                           std::uint32_t round);
std::optional<PubKey32> canonical_leader_for_height_round(const CanonicalDerivationConfig& cfg,
                                                          const CanonicalDerivedState& state, std::uint64_t height,
                                                          std::uint32_t round);

}  // namespace finalis::consensus
