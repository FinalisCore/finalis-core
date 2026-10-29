// SPDX-License-Identifier: MIT

#pragma once

#include <array>
#include <map>
#include <optional>
#include <string>
#include <tuple>
#include <variant>
#include <vector>

#include "common/types.hpp"
#include "crypto/bls12_381.hpp"
#include "crypto/confidential.hpp"

namespace finalis {

inline constexpr std::size_t INGRESS_LANE_COUNT = 8;

struct TxIn {
  Hash32 prev_txid;
  std::uint32_t prev_index{0};
  Bytes script_sig;
  std::uint32_t sequence{0xFFFFFFFF};
};

struct TxOut {
  std::uint64_t value{0};
  Bytes script_pubkey;
};

struct TxHashcashStamp {
  std::uint32_t version{1};
  std::uint64_t epoch_bucket{0};
  std::uint32_t bits{0};
  std::uint64_t nonce{0};
};

struct Tx {
  std::uint32_t version{1};
  std::vector<TxIn> inputs;
  std::vector<TxOut> outputs;
  std::uint32_t lock_time{0};
  std::optional<TxHashcashStamp> hashcash;

  Bytes serialize() const;
  Bytes serialize_without_hashcash() const;
  static std::optional<Tx> parse(const Bytes& b);
  Hash32 txid() const;
};

struct BlockHeader {
  Hash32 prev_finalized_hash;
  Hash32 prev_finality_cert_hash{};
  std::uint64_t height{0};
  std::uint64_t timestamp{0};
  Hash32 merkle_root;
  PubKey32 leader_pubkey;
  Sig64 leader_signature{};
  std::uint32_t round{0};

  Bytes serialize() const;
  Bytes serialize_without_signature() const;
  static std::optional<BlockHeader> parse(const Bytes& b);
  Hash32 block_id() const;
};

struct FinalitySig {
  PubKey32 validator_pubkey;
  Sig64 signature;

  bool operator==(const FinalitySig&) const = default;
};

using SignatureSet = std::vector<FinalitySig>;

struct FinalityProof {
  std::vector<FinalitySig> sigs;

  Bytes serialize() const;
  static std::optional<FinalityProof> parse(const Bytes& b);
};

struct FinalityCertificate {
  std::uint64_t height{0};
  std::uint32_t round{0};
  union {
    Hash32 frontier_transition_id;
    Hash32 block_id;
  };
  std::uint32_t quorum_threshold{0};
  // The conservative certificate slice stores explicit committee members rather
  // than a separate committee commitment so readers can reconstruct the finalized
  // quorum context without introducing new protocol assumptions.
  std::vector<PubKey32> committee_members;
  // Raw signatures are preserved as-is. Aggregated signatures are intentionally
  // deferred and not implied by this object.
  std::vector<FinalitySig> signatures;

  FinalityCertificate() : frontier_transition_id{} {}
  Bytes serialize() const;
  static std::optional<FinalityCertificate> parse(const Bytes& b);
};

struct QuorumCertificate {
  std::uint64_t height{0};
  std::uint32_t round{0};
  union {
    Hash32 frontier_transition_id;
    Hash32 block_id;
  };
  std::vector<FinalitySig> signatures;

  QuorumCertificate() : frontier_transition_id{} {}
};

struct TimeoutVote {
  std::uint64_t height{0};
  std::uint32_t round{0};
  PubKey32 validator_pubkey{};
  Sig64 signature{};
};

struct TimeoutCertificate {
  std::uint64_t height{0};
  std::uint32_t round{0};
  std::vector<FinalitySig> signatures;
};

struct Block {
  BlockHeader header;
  std::vector<Tx> txs;
  FinalityProof finality_proof;

  Bytes serialize() const;
  static std::optional<Block> parse(const Bytes& b);
};

enum class FrontierRejectReason : std::uint8_t {
  NONE = 0,
  TX_PARSE_FAILED = 1,
  TX_INVALID = 2,
  CONFLICT_DOMAIN_USED = 3,
  // A TxV2 that would take more value out of the confidential pool than ever entered it.
  CONFIDENTIAL_TURNSTILE_NEGATIVE = 4,
};

struct FrontierDecision {
  Hash32 record_id{};
  bool accepted{false};
  FrontierRejectReason reject_reason{FrontierRejectReason::NONE};

  Bytes serialize() const;
  static std::optional<FrontierDecision> parse(const Bytes& b);
};

struct FrontierSettlement {
  std::uint64_t settlement_epoch_start{0};
  std::vector<std::pair<PubKey32, std::uint64_t>> outputs;
  std::uint64_t total{0};
  std::uint64_t current_fees{0};
  std::uint64_t settled_epoch_fees{0};
  std::uint64_t settled_epoch_rewards{0};
  std::uint64_t reserve_subsidy_units{0};

  Bytes serialize() const;
  static std::optional<FrontierSettlement> parse(const Bytes& b);
  Hash32 commitment() const;
};

struct FrontierVector {
  std::array<std::uint64_t, INGRESS_LANE_COUNT> lane_max_seq{};

  bool operator==(const FrontierVector&) const = default;
  Bytes serialize() const;
  static std::optional<FrontierVector> parse(const Bytes& b);
  std::uint64_t total_count() const;
};

// The parent height's time signature: the Lagrange-weighted aggregate (crypto::mcfly_aggregate) of
// the BLS signatures of `signer_indices` (into the parent epoch checkpoint's ordered_bls_keys,
// strictly ascending) on time_signature_message(chain domain, parent height). Validators sign only
// heights they hold a finality certificate for, so the aggregate exists only once the parent is
// final; it is the witness that opens a TxTimed locked to the parent height.
struct TimeSignatureAggregate {
  std::vector<std::uint32_t> signer_indices;
  crypto::BlsSignature aggregate{};

  bool operator==(const TimeSignatureAggregate&) const = default;
};

// A long time lock's opening (consensus/frontier_execution.hpp, "long locks"): the aggregate, by the
// key set `committee_root` names (the committee of the lock's inclusion epoch), on
// time_signature_message(chain domain, unlock_height), signer indices into that key set.
struct LongTimeSignature {
  std::uint64_t unlock_height{0};
  Hash32 committee_root{};
  TimeSignatureAggregate signature;

  bool operator==(const LongTimeSignature&) const = default;
};
inline constexpr std::size_t kMaxLongTimeSignaturesPerBlock = 16;

struct FrontierTransition {
  Hash32 prev_finalized_hash{};
  Hash32 prev_finality_link_hash{};
  std::uint64_t height{0};
  std::uint64_t timestamp{0};
  std::uint32_t round{0};
  PubKey32 leader_pubkey{};
  // Leader's VRF proof over consensus::leader_vrf_alpha(parent randomness, height). Its output is the
  // leader's only input to finalized randomness, so the leader cannot steer the seed by choosing
  // the transition's contents; it can only decline to propose.
  VrfProof80 leader_vrf_proof{};
  FrontierVector prev_vector{};
  FrontierVector next_vector{};
  Hash32 ingress_commitment{};
  // Compatibility totals retained temporarily while the live path is still
  // migrating off raw scalar frontier counters.
  std::uint64_t prev_frontier{0};
  std::uint64_t next_frontier{0};
  Hash32 prev_state_root{};
  Hash32 next_state_root{};
  // consensus::consensus_post_state_commitment of the state after applying this transition: the full
  // committed consensus state minus the identity fields derived from the transition itself. Signed with
  // the transition, so a node can check a stored state against the finalized tip without replay.
  Hash32 next_state_commitment{};
  // Compatibility field retained temporarily while the local/live proposal
  // path still carries ordered slices. Replay-side frontier authority should
  // use ingress_commitment instead.
  Hash32 ordered_slice_commitment{};
  Hash32 decisions_commitment{};
  std::uint32_t quorum_threshold{0};
  // Round of the parent's precommits recorded in prev_finality_signers. A transition can be
  // re-proposed in a later round and finalized there, so this can differ from the parent
  // transition's own round; it is the canonical commit round of the parent.
  std::uint32_t prev_finality_round{0};
  // Participation record for the parent height (height - 1): the precommits this
  // transition's proposer observed for the parent's finalized
  // (height - 1, prev_finality_round, parent transition id). Sorted by pubkey, unique,
  // each signature valid, at least the parent committee's quorum. Empty only
  // when the parent is genesis. Liveness and reward accounting for the parent
  // height are evaluated from this set, not from the quorum-truncated
  // finality certificate.
  std::vector<FinalitySig> prev_finality_signers;
  // Time signature of the parent height, at least the parent committee's quorum of signers. Empty
  // (no signers, zero aggregate) only when the parent is genesis.
  TimeSignatureAggregate prev_time_signature;
  // Openings of long time locks this block settles, strictly ascending by (unlock_height,
  // committee_root); at most kMaxLongTimeSignaturesPerBlock. Optional: a block never waits for them.
  std::vector<LongTimeSignature> long_time_signatures;
  FrontierSettlement settlement;
  Hash32 settlement_commitment{};

  Bytes serialize() const;
  static std::optional<FrontierTransition> parse(const Bytes& b);
  Hash32 transition_id() const;
};

struct FrontierProposal {
  FrontierTransition transition;
  std::vector<Bytes> ordered_records;

  Bytes serialize() const;
  static std::optional<FrontierProposal> parse(const Bytes& b);
};

struct IngressCertificate {
  std::uint64_t epoch{0};
  std::uint32_t lane{0};
  std::uint64_t seq{0};
  Hash32 txid{};
  Hash32 tx_hash{};
  Hash32 prev_lane_root{};
  SignatureSet sigs;

  bool operator==(const IngressCertificate&) const = default;
  Bytes serialize() const;
  static std::optional<IngressCertificate> parse(const Bytes& b);
  Hash32 signing_hash() const;
};

struct LaneState {
  std::uint64_t epoch{0};
  std::uint32_t lane{0};
  std::uint64_t max_seq{0};
  Hash32 lane_root{};

  bool operator==(const LaneState&) const = default;
  Bytes serialize() const;
  static std::optional<LaneState> parse(const Bytes& b);
};

struct Vote {
  std::uint64_t height{0};
  std::uint32_t round{0};
  union {
    Hash32 frontier_transition_id;
    Hash32 block_id;
  };
  PubKey32 validator_pubkey;
  Sig64 signature;

  Vote() : frontier_transition_id{}, validator_pubkey{}, signature{} {}
  Vote(std::uint64_t height_in, std::uint32_t round_in, const Hash32& transition_id_in, const PubKey32& pubkey_in,
       const Sig64& signature_in)
      : height(height_in),
        round(round_in),
        frontier_transition_id(transition_id_in),
        validator_pubkey(pubkey_in),
        signature(signature_in) {}
};

struct EquivocationEvidence {
  Vote a;
  Vote b;
};

// Signing domain of the two conflicting votes in slash evidence (first byte of the evidence blob).
enum class SlashVoteKind : std::uint8_t {
  Precommit = 0,
  Prevote = 1,
};

struct OutPoint {
  Hash32 txid;
  std::uint32_t index{0};

  bool operator<(const OutPoint& o) const {
    return std::tie(txid, index) < std::tie(o.txid, o.index);
  }
};

struct UtxoEntry {
  TxOut out;
};

using UtxoSet = std::map<OutPoint, UtxoEntry>;

enum class UtxoOutputKind : std::uint8_t {
  Transparent = 0,
  Confidential = 1,
};

struct UtxoTransparentData {
  TxOut out;
  bool operator==(const UtxoTransparentData& other) const {
    return out.value == other.out.value && out.script_pubkey == other.out.script_pubkey;
  }
};

struct UtxoConfidentialData {
  crypto::Commitment33 value_commitment{};
  PubKey33 one_time_pubkey{};
  PubKey33 ephemeral_pubkey{};
  crypto::ScanTag scan_tag{};
  Bytes memo;

  bool operator==(const UtxoConfidentialData&) const = default;
};

struct UtxoEntryV2 {
  UtxoOutputKind kind{UtxoOutputKind::Transparent};
  std::variant<UtxoTransparentData, UtxoConfidentialData> body{UtxoTransparentData{}};

  UtxoEntryV2() = default;
  UtxoEntryV2(const UtxoEntry& entry) : kind(UtxoOutputKind::Transparent), body(UtxoTransparentData{entry.out}) {}
  UtxoEntryV2(const TxOut& out_in) : kind(UtxoOutputKind::Transparent), body(UtxoTransparentData{out_in}) {}
  UtxoEntryV2& operator=(const UtxoEntry& entry) {
    kind = UtxoOutputKind::Transparent;
    body = UtxoTransparentData{entry.out};
    return *this;
  }

  bool operator==(const UtxoEntryV2& other) const { return kind == other.kind && body == other.body; }
};

using UtxoSetV2 = std::map<OutPoint, UtxoEntryV2>;

Bytes serialize_utxo_entry_v2(const UtxoEntryV2& entry);
std::optional<UtxoEntryV2> parse_utxo_entry_v2(const Bytes& b);
std::optional<TxOut> transparent_txout_from_utxo_entry(const UtxoEntryV2& entry);

// SCVALJRQ / SCONBREG scripts: prefix(8) | validator_pubkey(32) | payout_pubkey(32) | pop(64) |
// bls_pubkey(48) | bls_pop(96) [| admission_pow_epoch(u64le) | admission_pow_nonce(u64le)]:
// 280 bytes, or 296 with admission PoW. pop is the Ed25519 signature of the registration message,
// which covers bls_pubkey (the validator vouches for its BLS key); bls_pop is the BLS proof of
// possession of bls_pubkey (crypto::bls_pop_prove; rules out rogue-key aggregation).
inline constexpr std::size_t kValidatorRegistrationScriptBytes = 8 + 32 + 32 + 64 + crypto::kBlsPublicKeyBytes +
                                                                 crypto::kBlsSignatureBytes;
inline constexpr std::size_t kValidatorRegistrationScriptPowBytes = kValidatorRegistrationScriptBytes + 16;

struct ValidatorJoinRequestScriptData {
  PubKey32 validator_pubkey{};
  PubKey32 payout_pubkey{};
  Sig64 pop{};
  crypto::BlsPublicKey bls_pubkey{};
  crypto::BlsSignature bls_pop{};
  bool has_admission_pow{false};
  std::uint64_t admission_pow_epoch{0};
  std::uint64_t admission_pow_nonce{0};
};

struct OnboardingRegistrationScriptData {
  PubKey32 validator_pubkey{};
  PubKey32 payout_pubkey{};
  Sig64 pop{};
  crypto::BlsPublicKey bls_pubkey{};
  crypto::BlsSignature bls_pop{};
  bool has_admission_pow{false};
  std::uint64_t admission_pow_epoch{0};
  std::uint64_t admission_pow_nonce{0};
};

Bytes encode_validator_join_request_script(const ValidatorJoinRequestScriptData& data);
Bytes encode_onboarding_registration_script(const OnboardingRegistrationScriptData& data);

bool is_validator_register_script(const Bytes& script, PubKey32* out_pubkey = nullptr);
bool is_validator_unbond_script(const Bytes& script, PubKey32* out_pubkey = nullptr);
bool parse_onboarding_registration_script(const Bytes& script, OnboardingRegistrationScriptData* out = nullptr);
bool is_onboarding_registration_script(const Bytes& script, PubKey32* out_validator_pubkey = nullptr,
                                       PubKey32* out_payout_pubkey = nullptr, Sig64* out_pop = nullptr,
                                       std::uint64_t* out_admission_pow_epoch = nullptr,
                                       std::uint64_t* out_admission_pow_nonce = nullptr);
bool parse_validator_join_request_script(const Bytes& script, ValidatorJoinRequestScriptData* out = nullptr);
bool is_validator_join_request_script(const Bytes& script, PubKey32* out_validator_pubkey = nullptr,
                                      PubKey32* out_payout_pubkey = nullptr, Sig64* out_pop = nullptr,
                                      std::uint64_t* out_admission_pow_epoch = nullptr,
                                      std::uint64_t* out_admission_pow_nonce = nullptr);
bool is_burn_script(const Bytes& script, Hash32* out_evidence_hash = nullptr);

enum class ValidatorJoinRequestStatus : std::uint8_t {
  REQUESTED = 0,
  APPROVED = 1,
};

struct ValidatorJoinRequest {
  Hash32 request_txid{};
  PubKey32 validator_pubkey{};
  PubKey32 payout_pubkey{};
  OutPoint bond_outpoint{};
  std::uint64_t bond_amount{0};
  std::uint64_t requested_height{0};
  std::uint64_t approved_height{0};
  // REQUESTED: finalized while the join window was full; admitted in order once it has room.
  ValidatorJoinRequestStatus status{ValidatorJoinRequestStatus::REQUESTED};
  crypto::BlsPublicKey bls_pubkey{};  // from the join request script, registered on admission
};

}  // namespace finalis
