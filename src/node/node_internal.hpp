// SPDX-License-Identifier: MIT

// Helpers and constants shared by the src/node/ translation units. Internal to the node
// runtime: not part of the public node.hpp API. See docs/NODE_CPP_DECOMPOSITION.md.

#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "consensus/ingress.hpp"
#include "node.hpp"

namespace finalis::node::detail {

// --- Constants ---
inline constexpr std::uint32_t kFixedValidationRulesVersion = 7;
inline constexpr std::size_t kMaxIngressRangeRequestRecords = 1024;
inline constexpr std::size_t kMaxIngressRangeResponseRecords = 1024;
inline constexpr std::size_t kMaxIngressRangeResponseBytes = 512 * 1024;
inline constexpr std::uint64_t kFinalizedTipFreshnessFloorMs = 15'000;
inline constexpr const char* kSmtTreeUtxo = "utxo";
inline constexpr const char* kSmtTreeValidators = "validators";
inline constexpr const char* kValidatorJoinWindowStartKey = "PVAL:JOIN_WINDOW_START";
inline constexpr const char* kValidatorJoinWindowCountKey = "PVAL:JOIN_WINDOW_COUNT";
inline constexpr const char* kValidatorLivenessWindowStartKey = "PVAL:LIVENESS_WINDOW_START";
inline constexpr const char* kFinalizedRandomnessKey = "PRAND:FINALIZED";
inline constexpr const char* kConsensusSafetyStatePrefix = "CSAFE:";
// Full FrontierProposal behind the local vote lock at a height, written in the same durable batch
// as the lock so a restarted node can still re-propose / re-vote its locked payload.
inline constexpr const char* kConsensusLockedProposalPrefix = "CSLP:";

// --- In-process local bus (disable_p2p mode); defined in node_internal.cpp ---
extern std::mutex g_local_bus_mu;
extern std::vector<Node*> g_local_bus_nodes;

struct StateRoots {
  Hash32 utxo_root{};
  Hash32 validators_root{};
};

// --- Trivial inline helpers ---
inline bool deferred_exit_fork_active(const NetworkConfig& network, std::uint64_t height) {
  return height >= network.deferred_exit_activation_height;
}

inline bool zero_outpoint(const OutPoint& op) { return op.txid == zero_hash() && op.index == 0; }

// --- Helpers (defined in node_internal.cpp) ---
std::string short_pub_hex(const PubKey32& pub);
std::string short_hash_hex(const Hash32& h);
const char* msg_type_name(std::uint16_t msg_type);
const char* availability_status_name(availability::AvailabilityOperatorStatus status);
const char* checkpoint_derivation_mode_name(storage::FinalizedCommitteeDerivationMode mode);
const char* checkpoint_fallback_reason_name(storage::FinalizedCommitteeFallbackReason reason);
std::size_t ingress_record_wire_size(const p2p::IngressRecordMsg& record);
std::size_t ingress_range_wire_size(const p2p::IngressRangeMsg& msg);
bool load_certified_ingress_record_from_db(const storage::DB& db, std::uint32_t lane, std::uint64_t seq,
                                           consensus::CertifiedIngressRecord* out, std::string* error);
std::vector<std::string> parse_endpoint_list(const std::string& raw);
bool is_local_only_bind(const std::string& host);
bool is_unroutable_ip_literal(const std::string& ip);
bool endpoint_fingerprint_safe(const std::string& endpoint);
bool advertised_endpoint_likely_public(const p2p::NetAddress& addr);
std::optional<std::pair<std::uint32_t, std::uint64_t>> parse_lane_seq_from_error(const std::string& error);
bool same_epoch_committee_snapshot(const consensus::EpochCommitteeSnapshot& a,
                                   const consensus::EpochCommitteeSnapshot& b);
std::string endpoint_to_ip(std::string endpoint);
std::string token_value(const std::string& s, const std::string& key);
std::string ascii_lower(std::string s);
std::string network_id_hex(const NetworkConfig& cfg);
std::string consensus_rules_fingerprint(const NetworkConfig& cfg, const ChainId& chain_id, std::uint32_t cv);
bool debug_economics_logs_enabled();
bool debug_finality_logs_enabled();
bool debug_liveness_logs_enabled();
consensus::ValidatorBestTicket checkpoint_best_ticket_for_member(
    const NetworkConfig& network, const consensus::ValidatorRegistry& validators,
    const storage::FinalizedCommitteeCheckpoint& checkpoint, std::size_t index);
std::vector<consensus::ValidatorBestTicket> checkpoint_winners(
    const NetworkConfig& network, const consensus::ValidatorRegistry& validators,
    const storage::FinalizedCommitteeCheckpoint& checkpoint);
std::vector<PubKey32> proposer_schedule_from_checkpoint(const NetworkConfig& network,
                                                        const consensus::ValidatorRegistry& validators,
                                                        const storage::FinalizedCommitteeCheckpoint& checkpoint,
                                                        std::uint64_t height);
bool finalized_checkpoint_matches_epoch_snapshot(const storage::FinalizedCommitteeCheckpoint& checkpoint,
                                                 const consensus::EpochCommitteeSnapshot& snapshot);
consensus::EpochCommitteeSnapshot epoch_committee_snapshot_from_checkpoint(
    const storage::FinalizedCommitteeCheckpoint& checkpoint);
bool same_validator_info(const consensus::ValidatorInfo& a, const consensus::ValidatorInfo& b);
bool same_validator_maps(const std::map<PubKey32, consensus::ValidatorInfo>& a,
                         const std::map<PubKey32, consensus::ValidatorInfo>& b);
bool maybe_reactivate_single_exiting_validator_for_startup_migration(
    const NetworkConfig& network, consensus::CanonicalDerivedState* state, PubKey32* reactivated_pubkey);
bool is_non_genesis_zero_bond_outpoint(const consensus::ValidatorInfo& info);
std::size_t repair_invalid_exiting_zero_bond_outpoints(consensus::ValidatorRegistry* validators, std::uint64_t height,
                                                       std::uint64_t unbond_delay_blocks,
                                                       const std::function<void(const std::string&)>& log_fn);
std::size_t repair_matured_bootstrap_exiting_records(const NetworkConfig& network, consensus::ValidatorRegistry* validators,
                                                     std::uint64_t height, std::uint64_t unbond_delay_blocks,
                                                     const std::function<void(const std::string&)>& log_fn);
std::string validator_info_debug_string(const consensus::ValidatorInfo& info);
std::string validator_map_mismatch_reason(const std::map<PubKey32, consensus::ValidatorInfo>& a,
                                          const std::map<PubKey32, consensus::ValidatorInfo>& b);
bool same_join_request(const ValidatorJoinRequest& a, const ValidatorJoinRequest& b);
bool same_join_request_maps(const std::map<Hash32, ValidatorJoinRequest>& a,
                            const std::map<Hash32, ValidatorJoinRequest>& b);
bool same_epoch_reward_state(const storage::EpochRewardSettlementState& a, const storage::EpochRewardSettlementState& b);
bool same_epoch_reward_maps(const std::map<std::uint64_t, storage::EpochRewardSettlementState>& a,
                            const std::map<std::uint64_t, storage::EpochRewardSettlementState>& b);
bool same_finalized_checkpoint(const storage::FinalizedCommitteeCheckpoint& a,
                               const storage::FinalizedCommitteeCheckpoint& b);
bool same_finalized_checkpoint_maps(const std::map<std::uint64_t, storage::FinalizedCommitteeCheckpoint>& a,
                                    const std::map<std::uint64_t, storage::FinalizedCommitteeCheckpoint>& b);
consensus::FinalizedIdentity finalized_identity_for_runtime_tip(std::uint64_t height, const Hash32& id);
bool finalized_identity_valid_for_frontier_runtime(std::uint64_t finalized_height,
                                                   const consensus::FinalizedIdentity& identity);
FinalityCertificate make_finality_certificate(std::uint64_t height, std::uint32_t round, const Hash32& transition_id,
                                              std::size_t quorum_threshold, const std::vector<PubKey32>& committee,
                                              const std::vector<FinalitySig>& signatures);
bool persist_canonical_cache_rows(storage::DB& db, storage::DB::Batch& batch, const consensus::CanonicalDerivedState& state);
bool persist_canonical_cache_rows(storage::DB& db, const consensus::CanonicalDerivedState& state);
bool certificate_matches_checkpoint_committee(const FinalityCertificate& cert,
                                              const storage::FinalizedCommitteeCheckpoint& checkpoint);
Hash32 consensus_payload_id(const FrontierTransition& transition);
bool parse_consensus_safety_state(const Bytes& b, std::optional<std::pair<Hash32, std::uint32_t>>* lock_state,
                                  std::optional<QuorumCertificate>* qc_state, std::optional<Hash32>* qc_payload_id);
std::string key_consensus_locked_proposal(std::uint64_t height);
void sync_smt_tree(storage::DB& db, storage::DB::Batch& batch, const std::string& tree_id,
                   const std::vector<std::pair<Hash32, Bytes>>& leaves);
StateRoots persist_state_roots(storage::DB& db, storage::DB::Batch& batch, std::uint64_t height, const UtxoSetV2& utxos,
                               const consensus::ValidatorRegistry& validators, std::uint32_t validation_rules_version);
StateRoots persist_state_roots(storage::DB& db, std::uint64_t height, const UtxoSetV2& utxos,
                               const consensus::ValidatorRegistry& validators, std::uint32_t validation_rules_version);

}  // namespace finalis::node::detail
