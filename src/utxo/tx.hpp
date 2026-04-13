#pragma once

#include <array>
#include <map>
#include <optional>
#include <string>
#include <tuple>
#include <variant>
#include <vector>

#include "common/types.hpp"
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

struct FrontierTransition {
  Hash32 prev_finalized_hash{};
  Hash32 prev_finality_link_hash{};
  std::uint64_t height{0};
  std::uint32_t round{0};
  PubKey32 leader_pubkey{};
  FrontierVector prev_vector{};
  FrontierVector next_vector{};
  Hash32 ingress_commitment{};
  // Compatibility totals retained temporarily while the live path is still
  // migrating off raw scalar frontier counters.
  std::uint64_t prev_frontier{0};
  std::uint64_t next_frontier{0};
  Hash32 prev_state_root{};
  Hash32 next_state_root{};
  // Compatibility field retained temporarily while the local/live proposal
  // path still carries ordered slices. Replay-side frontier authority should
  // use ingress_commitment instead.
  Hash32 ordered_slice_commitment{};
  Hash32 decisions_commitment{};
  std::uint32_t quorum_threshold{0};
  std::vector<PubKey32> observed_signers;
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
UtxoSet downgrade_utxo_set_v1(const UtxoSetV2& utxos);

struct ValidatorJoinRequestScriptData {
  PubKey32 validator_pubkey{};
  PubKey32 payout_pubkey{};
  Sig64 pop{};
  bool has_admission_pow{false};
  std::uint64_t admission_pow_epoch{0};
  std::uint64_t admission_pow_nonce{0};
};

bool is_validator_register_script(const Bytes& script, PubKey32* out_pubkey = nullptr);
bool is_validator_unbond_script(const Bytes& script, PubKey32* out_pubkey = nullptr);
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
  ValidatorJoinRequestStatus status{ValidatorJoinRequestStatus::REQUESTED};
};

}  // namespace finalis
