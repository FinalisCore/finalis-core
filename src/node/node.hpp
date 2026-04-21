// SPDX-License-Identifier: MIT

#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include "consensus/availability_retention.hpp"
#include "consensus/finalized_committee.hpp"
#include "consensus/canonical_derivation.hpp"
#include "consensus/committee_schedule.hpp"
#include "consensus/epoch_committee.hpp"
#include "consensus/epoch_tickets.hpp"
#include "consensus/randomness.hpp"
#include "consensus/validator_registry.hpp"
#include "consensus/votes.hpp"
#include "crypto/ed25519.hpp"
#include "mempool/mempool.hpp"
#include "p2p/messages.hpp"
#include "p2p/addrman.hpp"
#include "p2p/peer_manager.hpp"
#include "common/chain_id.hpp"
#include "common/network.hpp"
#include "p2p/hardening.hpp"
#include "storage/db.hpp"
#include "utxo/validate.hpp"

namespace finalis::node {

enum class LightserverLaunchMode {
  Disabled,
  Explicit,
};

struct NodeConfig {
  NetworkConfig network{mainnet_network()};
  bool allow_unsafe_genesis_override{false};
  std::string validator_key_file;
  std::string validator_passphrase;
  int node_id{0};
  std::string bind_ip{"127.0.0.1"};
  bool listen{true};
  bool public_mode{false};
  LightserverLaunchMode lightserver_mode{LightserverLaunchMode::Disabled};
  bool dns_seeds{true};
  std::size_t outbound_target{8};
  std::size_t max_inbound{64};
  std::uint16_t p2p_port{19440};
  std::string lightserver_bind{"127.0.0.1"};
  std::uint16_t lightserver_port{19444};
  std::vector<std::string> peers;
  std::vector<std::string> seeds;
  std::string db_path{"~/.finalis/mainnet"};
  std::string genesis_path;
  bool disable_p2p{false};
  bool reindex_on_start{true};
  bool log_json{false};
  std::size_t max_committee{MAX_COMMITTEE};
  std::uint32_t handshake_timeout_ms{10'000};
  std::uint32_t frame_timeout_ms{3'000};
  std::uint32_t idle_timeout_ms{600'000};
  std::size_t peer_queue_max_bytes{2 * 1024 * 1024};
  std::size_t peer_queue_max_msgs{2'000};
  std::uint64_t ban_seconds{600};
  int invalid_frame_ban_threshold{3};
  std::uint64_t invalid_frame_window_seconds{60};
  std::uint64_t min_relay_fee{0};
  bool min_relay_fee_explicit{false};
  bool hashcash_enabled{false};
  std::uint32_t hashcash_base_bits{18};
  std::uint32_t hashcash_max_bits{30};
  std::uint64_t hashcash_epoch_seconds{60};
  std::uint64_t hashcash_fee_exempt_min{1'000};
  std::size_t hashcash_pressure_tx_threshold{1'000};
  std::size_t hashcash_pressure_step_txs{500};
  std::uint32_t hashcash_pressure_bits_per_step{1};
  std::size_t hashcash_large_tx_bytes{2'048};
  std::uint32_t hashcash_large_tx_extra_bits{1};
  std::optional<std::uint64_t> validator_min_bond_override;
  std::optional<std::uint64_t> validator_bond_min_amount_override;
  std::optional<std::uint64_t> validator_bond_max_amount_override;
  std::optional<std::uint64_t> validator_warmup_blocks_override;
  std::optional<std::uint64_t> validator_cooldown_blocks_override;
  std::optional<std::uint64_t> validator_join_limit_window_blocks_override;
  std::optional<std::uint32_t> validator_join_limit_max_new_override;
  std::optional<std::uint64_t> liveness_window_blocks_override;
  std::optional<std::uint32_t> miss_rate_suspend_threshold_percent_override;
  std::optional<std::uint32_t> miss_rate_exit_threshold_percent_override;
  std::optional<std::uint64_t> suspend_duration_blocks_override;
  double tx_rate_capacity{200.0};
  double tx_rate_refill{100.0};
  double propose_rate_capacity{20.0};
  double propose_rate_refill{10.0};
  double vote_rate_capacity{120.0};
  double vote_rate_refill{60.0};
  double block_rate_capacity{40.0};
  double block_rate_refill{20.0};
  double vote_verify_capacity{60.0};
  double vote_verify_refill{30.0};
  double tx_verify_capacity{200.0};
  double tx_verify_refill{100.0};
  availability::AvailabilityConfig availability{};
  std::uint64_t availability_min_eligible_operators{1};
};

struct NodeStatus {
  std::string network_name;
  std::uint32_t protocol_version{0};
  std::string network_id_short;
  std::uint32_t magic{0};
  std::string genesis_hash;
  std::string genesis_source;
  bool chain_id_ok{true};
  std::string db_dir;
  std::uint64_t height{0};
  std::uint32_t round{0};
  Hash32 transition_hash{};
  std::string transition_hash_short;
  PubKey32 leader{};
  std::size_t votes_for_current{0};
  std::size_t peers{0};
  std::size_t established_peers{0};
  std::size_t mempool_size{0};
  std::size_t committee_size{0};
  std::size_t quorum_threshold{0};
  std::size_t addrman_size{0};
  std::size_t inbound_connected{0};
  std::size_t outbound_connected{0};
  std::size_t observed_signers{0};
  std::string consensus_state;
  std::string last_bootstrap_source;
  std::uint64_t rejected_network_id{0};
  std::uint64_t rejected_protocol_version{0};
  std::uint64_t rejected_pre_handshake{0};
  std::uint32_t consensus_version{1};
  std::uint64_t participation_eligible_signers{0};
  bool bootstrap_template_mode{false};
  std::string bootstrap_validator_pubkey;
  std::size_t pending_bootstrap_joiners{0};
  std::string consensus_model;
  std::size_t current_round_slot{0};
  std::size_t active_epoch_committee_size{0};
  std::string active_epoch_committee_members_short;
  std::size_t healthy_peer_count{0};
  bool observed_network_height_known{false};
  std::uint64_t observed_network_finalized_height{0};
  std::uint64_t finalized_lag{0};
  bool peer_height_disagreement{false};
  bool next_height_committee_available{false};
  bool next_height_proposer_available{false};
  bool registration_ready{false};
  std::uint32_t registration_readiness_stable_samples{0};
  std::string registration_readiness_blockers;
  std::uint64_t availability_epoch{0};
  std::uint64_t availability_retained_prefix_count{0};
  std::uint64_t availability_tracked_operator_count{0};
  std::uint64_t availability_eligible_operator_count{0};
  bool availability_below_min_eligible{false};
  std::uint64_t adaptive_target_committee_size{0};
  std::uint64_t adaptive_min_eligible{0};
  std::uint64_t adaptive_min_bond{0};
  std::uint64_t qualified_depth{0};
  std::int64_t adaptive_slack{0};
  std::uint32_t target_expand_streak{0};
  std::uint32_t target_contract_streak{0};
  std::uint32_t adaptive_fallback_rate_bps{0};
  std::uint32_t adaptive_sticky_fallback_rate_bps{0};
  std::uint32_t adaptive_fallback_window_epochs{0};
  bool adaptive_near_threshold_operation{false};
  bool adaptive_prolonged_expand_buildup{false};
  bool adaptive_prolonged_contract_buildup{false};
  bool adaptive_repeated_sticky_fallback{false};
  bool adaptive_depth_collapse_after_bond_increase{false};
  std::string availability_checkpoint_derivation_mode;
  std::string availability_checkpoint_fallback_reason;
  bool availability_fallback_sticky{false};
  bool availability_state_rebuild_triggered{false};
  std::string availability_state_rebuild_reason;
  bool availability_local_operator_known{false};
  std::string availability_local_operator_pubkey;
  std::string availability_local_operator_status;
  std::int64_t availability_local_service_score{0};
  std::uint64_t availability_local_warmup_epochs{0};
  std::uint64_t availability_local_successful_audits{0};
  std::uint64_t availability_local_late_audits{0};
  std::uint64_t availability_local_missed_audits{0};
  std::uint64_t availability_local_invalid_audits{0};
  std::uint64_t availability_local_retained_prefix_count{0};
  std::int64_t availability_local_eligibility_score{0};
  std::uint32_t availability_local_seat_budget{0};
};

class Node {
 public:
  explicit Node(NodeConfig cfg);
  ~Node() noexcept;

  bool init();
  void start();
  void stop();

  NodeStatus status() const;

  // Test hooks.
  bool inject_vote_for_test(const Vote& vote);
  bool inject_timeout_vote_for_test(const TimeoutVote& vote);
  std::string inject_network_vote_result_for_test(const Vote& vote);
  std::string inject_network_vote_diagnostic_for_test(const Vote& vote);
  std::string inject_network_propose_result_for_test(const p2p::ProposeMsg& msg);
  std::string inject_network_propose_diagnostic_for_test(const p2p::ProposeMsg& msg);
  bool inject_frontier_transition_for_test(const FrontierProposal& proposal, const FinalityCertificate& certificate);
  bool inject_propose_msg_for_test(const p2p::ProposeMsg& msg);
  bool inject_ingress_tips_for_test(const p2p::IngressTipsMsg& msg, int peer_id = 1);
  bool inject_ingress_range_for_test(const p2p::IngressRangeMsg& msg, int peer_id = 1);
  std::string inject_ingress_range_result_for_test(const p2p::IngressRangeMsg& msg, int peer_id = 1);
  void set_requested_ingress_range_for_test(int peer_id, const p2p::GetIngressRangeMsg& msg);
  bool observe_frontier_proposal_for_test(const FrontierProposal& proposal);
  bool inject_frontier_block_for_test(const FrontierProposal& proposal, const std::vector<FinalitySig>& finality_signatures);
  bool inject_tx_for_test(const AnyTx& tx, bool relay);
  bool pause_proposals_for_test(bool pause);
  bool advance_round_for_test(std::uint64_t expected_height, std::uint32_t target_round);
  bool mempool_contains_for_test(const Hash32& txid) const;
  std::optional<TxOut> find_utxo_by_pubkey_hash_for_test(const std::array<std::uint8_t, 20>& pkh,
                                                         OutPoint* outpoint = nullptr) const;
  std::vector<std::pair<OutPoint, TxOut>> find_utxos_by_pubkey_hash_for_test(
      const std::array<std::uint8_t, 20>& pkh) const;
  bool has_utxo_for_test(const OutPoint& op, TxOut* out = nullptr) const;
  std::string proposer_path_for_next_height_for_test() const;
  std::string committee_path_for_next_height_for_test() const;
  std::string vote_path_for_next_height_for_test() const;
  std::size_t quorum_threshold_for_next_height_for_test() const;
  std::vector<PubKey32> active_validators_for_next_height_for_test() const;
  std::vector<PubKey32> committee_for_next_height_for_test() const;
  std::vector<PubKey32> committee_for_height_round_for_test(std::uint64_t height, std::uint32_t round) const;
  std::optional<PubKey32> proposer_for_height_round_for_test(std::uint64_t height, std::uint32_t round) const;
  std::optional<QuorumCertificate> highest_qc_for_height_for_test(std::uint64_t height) const;
  std::optional<TimeoutCertificate> highest_tc_for_height_for_test(std::uint64_t height) const;
  std::size_t timeout_vote_count_for_height_round_for_test(std::uint64_t height, std::uint32_t round) const;
  bool local_timeout_vote_reserved_for_test(std::uint64_t height, std::uint32_t round) const;
  bool local_is_committee_member_for_test(std::uint64_t height, std::uint32_t round) const;
  std::uint64_t round_age_ms_for_test() const;
  Hash32 epoch_ticket_challenge_anchor_for_test(std::uint64_t height) const;
  PubKey32 local_validator_pubkey_for_test() const;
  std::optional<consensus::ValidatorInfo> validator_info_for_test(const PubKey32& pub) const;
  bool seed_bonded_validator_for_test(const PubKey32& pub, const OutPoint& bond_outpoint, std::uint64_t bond_amount);
  Hash32 canonical_state_commitment_for_test() const;
  std::uint64_t canonical_state_height_for_test() const;
  std::uint16_t p2p_port_for_test() const;
  bool endpoint_is_obvious_self_for_test(const std::string& host, std::uint16_t port) const;
  bool self_endpoint_suppressed_for_test(const std::string& host, std::uint16_t port) const;
  std::optional<FrontierProposal> build_frontier_proposal_for_test(std::uint64_t height, std::uint32_t round);
  std::string last_test_hook_error_for_test() const;
  std::optional<p2p::GetIngressRangeMsg> requested_ingress_range_for_test(int peer_id, std::uint32_t lane) const;
  bool overwrite_runtime_next_height_checkpoint_for_test(const storage::FinalizedCommitteeCheckpoint& checkpoint);
  bool overwrite_runtime_frontier_cursor_for_test(std::uint64_t finalized_frontier);

  static std::vector<crypto::KeyPair> deterministic_test_keypairs();

 private:
  enum class ProposeHandlingResult { Accepted, SoftReject, HardReject };
  enum class VoteHandlingResult { Accepted, SoftReject, HardReject };
  enum class TimeoutVoteHandlingResult { Accepted, SoftReject, HardReject };

  void event_loop();
  void handle_message(int peer_id, std::uint16_t msg_type, const Bytes& payload);

  void send_version(int peer_id);
  void maybe_send_verack(int peer_id);
  void send_ping(int peer_id);
  Hash32 epoch_ticket_challenge_anchor_locked(std::uint64_t height) const;
  std::uint64_t current_epoch_ticket_epoch_locked() const;
  bool epoch_committee_closed_locked(std::uint64_t epoch) const;
  bool epoch_committee_frozen_locked(std::uint64_t epoch) const;
  std::optional<std::uint64_t> epoch_committee_snapshot_epoch_for_height_locked(std::uint64_t height) const;
  std::optional<consensus::EpochCommitteeSnapshot> frozen_epoch_committee_snapshot_for_height_locked(std::uint64_t height) const;
  std::vector<PubKey32> epoch_bootstrap_committee_for_height_locked(std::uint64_t height) const;
  std::vector<PubKey32> epoch_committee_for_next_height_locked(std::uint64_t height, std::uint32_t round) const;
  std::optional<PubKey32> epoch_leader_for_next_height_locked(std::uint64_t height, std::uint32_t round) const;
  bool bootstrap_handoff_complete_locked() const;
  bool single_node_bootstrap_active_locked(std::uint64_t height) const;
  bool recover_single_validator_epoch_committee_locked(std::uint64_t epoch, const char* reason);
  bool ensure_required_epoch_committee_state_locked();
  bool ensure_required_epoch_committee_state_startup();
  std::string required_epoch_committee_state_reason_locked(std::uint64_t epoch) const;
  storage::EpochCommitteeFreezeMarker make_epoch_committee_freeze_marker_locked(
      const consensus::EpochCommitteeSnapshot& snapshot) const;
  void rebuild_epoch_committee_state_locked(std::uint64_t epoch, const char* reason, bool log_summary);
  void maybe_finalize_epoch_committees_locked();
  void maybe_request_epoch_ticket_reconciliation_locked(std::uint64_t now_ms);
  void request_epoch_tickets(int peer_id, std::uint64_t epoch, std::uint32_t max_tickets);
  std::optional<consensus::EpochTicket> mine_local_epoch_ticket_locked(std::uint64_t height) const;
  bool handle_epoch_ticket_locked(const consensus::EpochTicket& ticket, bool from_network, int from_peer_id,
                                  std::string* reject_reason = nullptr,
                                  bool allow_closed_epoch_reconcile = false);
  bool handle_epoch_ticket(const consensus::EpochTicket& ticket, bool from_network, int from_peer_id = 0,
                           bool allow_closed_epoch_reconcile = false);

  ProposeHandlingResult handle_propose_result(const p2p::ProposeMsg& msg, bool from_network,
                                              std::string* reject_reason = nullptr);
  VoteHandlingResult handle_vote_result(const Vote& vote, bool from_network, int from_peer_id = 0,
                                        std::string* reject_reason = nullptr);
  TimeoutVoteHandlingResult handle_timeout_vote_result(const TimeoutVote& vote, bool from_network, int from_peer_id = 0);
  bool handle_propose(const p2p::ProposeMsg& msg, bool from_network);
  bool handle_vote(const Vote& vote, bool from_network, int from_peer_id = 0);
  bool handle_timeout_vote(const TimeoutVote& vote, bool from_network, int from_peer_id = 0);
  bool handle_frontier_block_locked(const FrontierProposal& proposal, const std::optional<FinalityCertificate>& certificate,
                                    int from_peer_id, bool from_network);
  bool maybe_buffer_sync_frontier_locked(const FrontierProposal& proposal,
                                         const std::optional<FinalityCertificate>& certificate, int from_peer_id);
  bool maybe_apply_buffered_sync_frontiers_locked(int preferred_peer_id);
  bool handle_tx(const AnyTx& tx, bool from_network, int from_peer_id = 0);
  bool maybe_certify_locally_accepted_tx_locked(const AnyTx& tx, std::string* error = nullptr);
  bool handle_ingress_record_locked(int peer_id, const p2p::IngressRecordMsg& msg, bool* appended = nullptr,
                                    std::string* error = nullptr);
  bool finalize_if_quorum(const Hash32& transition_id, std::uint64_t height, std::uint32_t round);
  bool verify_quorum_certificate_locked(const QuorumCertificate& qc, std::vector<FinalitySig>* filtered = nullptr,
                                        std::string* error = nullptr) const;
  bool verify_timeout_certificate_locked(const TimeoutCertificate& tc, std::vector<FinalitySig>* filtered = nullptr,
                                         std::string* error = nullptr) const;
  bool verify_finality_certificate_for_frontier_locked(const FinalityCertificate& cert, const FrontierTransition& transition,
                                                    std::vector<FinalitySig>* canonical_signatures = nullptr,
                                                    std::string* error = nullptr) const;
  std::optional<Hash32> quorum_certificate_payload_id_locked(const QuorumCertificate& qc) const;
  std::optional<QuorumCertificate> highest_qc_for_height_locked(std::uint64_t height) const;
  std::optional<TimeoutCertificate> highest_tc_for_height_locked(std::uint64_t height) const;
  void maybe_record_quorum_certificate_locked(const Hash32& transition_id, std::uint64_t height, std::uint32_t round);
  void maybe_record_timeout_certificate_locked(std::uint64_t height, std::uint32_t round);
  bool can_vote_for_frontier_locked(const FrontierTransition& transition,
                                 const std::optional<QuorumCertificate>& justify_qc,
                                 const std::optional<TimeoutCertificate>& justify_tc,
                                 std::string* reason = nullptr) const;
  bool can_accept_frontier_with_lock_locked(const FrontierTransition& transition, std::string* reason = nullptr) const;
  void update_local_vote_lock_locked(std::uint64_t height, std::uint32_t round, const Hash32& payload_id);
  void persist_consensus_safety_state_locked(std::uint64_t height);
  void clear_consensus_safety_state_locked(std::uint64_t height);
  std::vector<FinalitySig> canonicalize_finality_signatures_locked(const std::vector<FinalitySig>& signatures,
                                                                   std::size_t quorum) const;
  bool apply_finalized_frontier_effects_locked(const consensus::CanonicalFrontierRecord& record,
                                               std::vector<FinalitySig> finality_signatures,
                                               bool clear_requested_sync = false,
                                               const std::vector<PubKey32>* effective_committee = nullptr);

  std::optional<FrontierProposal> build_frontier_transition_locked(std::uint64_t height, std::uint32_t round);
  bool refresh_runtime_from_frontier_storage_locked(const char* reason, std::string* error = nullptr);
  void broadcast_epoch_ticket(const consensus::EpochTicket& ticket);
  void broadcast_propose(const FrontierProposal& proposal, const std::optional<QuorumCertificate>& justify_qc = std::nullopt,
                         const std::optional<TimeoutCertificate>& justify_tc = std::nullopt);
  void broadcast_vote(const Vote& vote);
  void broadcast_timeout_vote(const TimeoutVote& vote);
  void broadcast_finalized_frontier(const FrontierProposal& proposal, const FinalityCertificate& certificate);
  void broadcast_tx(const AnyTx& tx, int skip_peer_id = 0);
  void broadcast_ingress_record(const IngressCertificate& cert, const Bytes& tx_bytes, int skip_peer_id = 0);
  void maybe_forward_tx_to_designated_certifier_locked(const AnyTx& tx, int skip_peer_id = 0);

  bool persist_finalized_frontier_record(const consensus::CanonicalFrontierRecord& record, const UtxoSetV2& prev_utxos);
  bool begin_finalized_write(const Block& block);
  bool finish_finalized_write(const Block& block);
  bool check_no_incomplete_finalized_write() const;
  void hydrate_runtime_from_canonical_state_locked(const consensus::CanonicalDerivedState& state);
  consensus::CanonicalDerivationConfig canonical_derivation_config_locked() const;
  bool verify_and_persist_consensus_state_commitment_locked(const consensus::CanonicalDerivedState& state);
  bool init_local_validator_key();
  bool bootstrap_template_bind_validator(const PubKey32& pub, bool local_validator);
  bool maybe_adopt_bootstrap_validator_from_peer(int peer_id, const PubKey32& pub, std::uint64_t peer_height,
                                                 const char* source);
  void maybe_self_bootstrap_template(std::uint64_t now_ms);
  bool bootstrap_joiner_ready_locked(const PubKey32& pub) const;
  bool bootstrap_sync_incomplete_locked(int peer_id) const;
  bool verify_block_proposer_locked(const Block& block) const;
  bool check_and_record_proposer_equivocation_locked(const FrontierTransition& transition);
  bool validate_prev_finality_cert_hash_locked(const Block& block, std::string* error = nullptr) const;
  bool validate_frontier_proposal_locked(const FrontierProposal& proposal, std::string* error = nullptr) const;
  Hash32 committee_epoch_randomness_for_height_locked(std::uint64_t height) const;
  std::optional<storage::FinalizedCommitteeCheckpoint> finalized_committee_checkpoint_for_height_locked(
      std::uint64_t height) const;
  storage::FinalizedCommitteeCheckpoint build_finalized_committee_checkpoint_locked(
      std::uint64_t epoch_start_height, std::size_t active_validator_count,
      const std::vector<consensus::FinalizedCommitteeCandidate>& active,
      const Hash32& epoch_randomness) const;
  void persist_finalized_committee_checkpoint_locked(std::uint64_t epoch_start_height,
                                                     std::size_t active_validator_count,
                                                     const std::vector<consensus::FinalizedCommitteeCandidate>& active,
                                                     const Hash32& epoch_randomness);
  std::uint8_t ticket_difficulty_bits_for_epoch_locked(std::uint64_t epoch_start_height,
                                                       std::size_t active_validator_count) const;
  std::vector<consensus::FinalizedCommitteeCandidate> finalized_committee_candidates_for_height_locked(
      std::uint64_t height, std::uint8_t ticket_difficulty_bits) const;
  std::optional<std::uint64_t> settlement_epoch_for_block_height_locked(std::uint64_t height) const;
  storage::EpochRewardSettlementState epoch_reward_state_for_epoch_locked(std::uint64_t epoch_start_height) const;
  std::map<PubKey32, std::uint64_t> compute_onboarding_score_units_for_epoch_locked(std::uint64_t epoch_start_height) const;
  bool ensure_settlement_onboarding_scores_loaded_locked(std::uint64_t height);
  consensus::DeterministicCoinbasePayout coinbase_payout_for_height_locked(std::uint64_t height,
                                                                           const PubKey32& leader_pubkey,
                                                                           std::uint64_t fees_units) const;
  std::vector<TxOut> coinbase_outputs_for_height_locked(std::uint64_t height, const PubKey32& leader_pubkey,
                                                        std::uint64_t fees_units) const;
  void accrue_epoch_reward_for_finalized_block_locked(const Block& block, const std::vector<FinalitySig>& finality_sigs,
                                                      std::uint64_t finalized_fee_units);
  void mark_epoch_reward_settled_if_needed_locked(std::uint64_t height);
  std::optional<Hash32> pending_join_request_for_validator_locked(const PubKey32& pub) const;
  std::size_t pending_join_request_count_locked() const;
  bool init_mainnet_genesis();
  bool load_state();
  void apply_validator_state_changes(const Block& block, const UtxoSet& pre_utxos, std::uint64_t height);
  bool is_committee_member_for(const PubKey32& pub, std::uint64_t height, std::uint32_t round) const;
  std::vector<PubKey32> committee_for_height(std::uint64_t height) const;
  std::vector<PubKey32> committee_for_height_round(std::uint64_t height, std::uint32_t round) const;
  std::vector<consensus::WeightedParticipant> reward_participants_for_height_round(std::uint64_t height,
                                                                                   std::uint32_t round) const;
  std::optional<PubKey32> leader_for_height_round(std::uint64_t height, std::uint32_t round) const;
  void load_persisted_peers();
  void persist_peers() const;
  void persist_peers(const std::vector<p2p::PeerInfo>& peers) const;
  void load_addrman();
  void persist_addrman() const;
  bool load_availability_state_locked();
  bool persist_availability_state_locked();
  void rebuild_availability_retained_prefixes_from_finalized_frontier_locked();
  bool finalize_availability_restore_locked(const char* source);
  bool validate_availability_state_locked(const char* source) const;
  void update_availability_from_finalized_frontier_locked(const consensus::CanonicalFrontierRecord& record);
  void advance_availability_epoch_locked(std::uint64_t epoch);
  void refresh_availability_operator_state_locked(bool advance_epoch);
  std::optional<PubKey32> local_operator_pubkey_locked() const;
  bool seed_preflight_ok(const std::string& host, std::uint16_t port);
  bool endpoint_matches_local_listener(const std::string& host, std::uint16_t port,
                                       std::vector<std::string>* resolved_endpoints = nullptr) const;
  void try_connect_bootstrap_peers();
  std::vector<std::string> resolve_dns_seeds_once() const;
  void maybe_request_getaddr(int peer_id);
  void request_ingress_tips(int peer_id);
  void send_ingress_tips(int peer_id);
  void request_finalized_tip(int peer_id);
  void send_finalized_tip(int peer_id);
  void broadcast_finalized_tip();
  std::vector<PubKey32> ingress_committee_locked(std::uint64_t epoch) const;
  std::array<std::uint64_t, INGRESS_LANE_COUNT> local_ingress_lane_tips_locked() const;
  bool handle_ingress_tips_locked(int peer_id, const p2p::IngressTipsMsg& msg);
  bool handle_ingress_range_locked(int peer_id, const p2p::IngressRangeMsg& msg, std::string* error = nullptr);
  bool maybe_request_forward_sync_block_locked(int preferred_peer_id = 0);
  bool maybe_request_candidate_transition_locked(int peer_id, const Hash32& transition_id);
  bool next_height_requires_repair_locked(std::string* reason = nullptr) const;
  bool maybe_repair_next_height_locked(std::uint64_t now_ms, std::string* reason = nullptr);
  bool has_peer_endpoint(const std::string& host, std::uint16_t port) const;
  bool should_mute_peer_locked(int peer_id) const;
  std::size_t peer_count() const;
  std::size_t established_peer_count() const;
  std::size_t outbound_peer_count() const;
  std::string peer_ip_for_locked(int peer_id) const;
  std::string peer_ip_for(int peer_id) const;
  bool is_bootstrap_peer_ip(const std::string& ip) const;
  bool suppress_self_endpoint_locked(const std::string& endpoint);
  bool is_self_endpoint_suppressed_locked(const std::string& endpoint) const;
  std::optional<p2p::NetAddress> addrman_address_for_peer(const p2p::PeerInfo& info) const;
  storage::NodeRuntimeStatusSnapshot build_runtime_status_snapshot_locked(std::uint64_t now_ms);
  void score_peer_locked(int peer_id, p2p::MisbehaviorReason reason, const std::string& note);
  void score_peer(int peer_id, p2p::MisbehaviorReason reason, const std::string& note);
  bool should_mute_peer(int peer_id) const;
  void prune_caches_locked(std::uint64_t height, std::uint32_t round);
  bool check_rate_limit_locked(int peer_id, std::uint16_t msg_type);
  std::string consensus_state_locked(std::uint64_t now_ms, std::size_t* observed_signers = nullptr,
                                     std::size_t* quorum_threshold = nullptr) const;
  bool validate_validator_registration_rules(const Block& block, std::uint64_t height) const;
  void update_validator_liveness_from_finality(std::uint64_t height, std::uint32_t round,
                                               const std::vector<FinalitySig>& finality_sigs);
  std::size_t active_operator_count_for_height_locked(std::uint64_t height) const;
  std::uint64_t effective_validator_min_bond_for_height(std::uint64_t height) const;
  std::uint64_t effective_validator_bond_max_for_height(std::uint64_t height) const;
  std::uint64_t effective_min_relay_fee_for_height(std::uint64_t height) const;
  bool start_lightserver_child();
  void stop_lightserver_child();
  bool reap_lightserver_child(bool verbose);
  bool preflight_lightserver_bind(std::string* err) const;
  std::optional<std::string> detect_possible_public_ip() const;
  std::string lightserver_mode_name() const;
  std::string lightserver_binary_path(bool* sibling_found = nullptr) const;
  bool lightserver_is_public() const;

  std::uint64_t now_unix() const;
  std::uint64_t now_ms() const;
  void log_line(const std::string& s) const;
  void append_mining_log(const Block& block, std::uint32_t round, std::size_t votes, std::size_t quorum);
  void spawn_local_bus_task(std::function<void()> fn);
  void join_local_bus_tasks();

  NodeConfig cfg_;
  storage::DB db_;
  mutable std::mutex mu_;

  std::uint64_t finalized_height_{0};
  consensus::FinalizedIdentity finalized_identity_{};
  Hash32 finalized_randomness_{};
  std::map<std::uint64_t, Hash32> committee_epoch_randomness_cache_;
  std::uint64_t protocol_reserve_balance_units_{0};
  mutable std::map<std::uint64_t, storage::FinalizedCommitteeCheckpoint> finalized_committee_checkpoints_;
  mutable std::map<std::uint64_t, storage::EpochRewardSettlementState> epoch_reward_states_;
  std::string last_test_hook_error_;
  std::uint32_t current_round_{0};
  std::uint64_t round_started_ms_{0};
  bool reconnect_round_reset_pending_{false};
  bool repair_mode_{false};
  std::uint64_t repair_target_height_{0};
  std::string repair_reason_;
  std::uint64_t repair_started_ms_{0};
  std::uint64_t last_repair_log_ms_{0};

  consensus::ValidatorRegistry validators_;
  ConfidentialPolicy confidential_policy_{};
  UtxoSetV2 utxos_;
  mempool::Mempool mempool_;
  consensus::VoteTracker votes_;
  consensus::TimeoutVoteTracker timeout_votes_;
  p2p::PeerDiscipline discipline_{30, 100, 600};
  p2p::VoteVerifyCache vote_verify_cache_{20'000};
  p2p::VoteVerifyCache invalid_vote_verify_cache_{20'000};
  p2p::RecentHashCache invalid_message_payloads_{16'384};
  p2p::RecentHashCache accepted_propose_payloads_{4'096};
  p2p::RecentHashCache accepted_block_payloads_{4'096};
  p2p::RecentHashCache accepted_tx_payloads_{16'384};
  std::map<int, std::map<std::uint16_t, p2p::TokenBucket>> msg_rate_buckets_;
  std::map<int, p2p::TokenBucket> vote_verify_buckets_;
  std::map<int, p2p::TokenBucket> tx_verify_buckets_;
  std::map<Hash32, std::size_t> candidate_block_sizes_;
  std::map<Hash32, ValidatorJoinRequest> validator_join_requests_;
  std::map<Hash32, std::uint64_t> requested_sync_artifacts_;
  std::map<std::uint64_t, std::uint64_t> requested_sync_heights_;
  std::map<int, std::string> peer_ip_cache_;
  std::map<int, bool> peer_inbound_cache_;
  std::map<int, std::uint64_t> peer_keepalive_ms_;
  std::map<std::string, std::uint64_t> invalid_frame_log_ms_;
  std::map<std::string, std::uint64_t> addr_drop_log_ms_;
  std::uint64_t rejected_network_id_{0};
  std::uint64_t rejected_protocol_version_{0};
  std::uint64_t rejected_pre_handshake_{0};
  std::uint64_t validator_min_bond_{BOND_AMOUNT};
  std::uint64_t validator_bond_min_amount_{BOND_AMOUNT};
  std::uint64_t validator_bond_max_amount_{BOND_AMOUNT};
  std::uint64_t validator_warmup_blocks_{WARMUP_BLOCKS};
  std::uint64_t validator_cooldown_blocks_{0};
  std::uint64_t validator_join_limit_window_blocks_{0};
  std::uint32_t validator_join_limit_max_new_{0};
  std::uint64_t validator_join_window_start_height_{0};
  std::uint32_t validator_join_count_in_window_{0};
  std::uint64_t validator_liveness_window_blocks_{10'000};
  std::uint64_t validator_liveness_window_start_height_{0};
  std::uint32_t validator_miss_rate_suspend_threshold_percent_{30};
  std::uint32_t validator_miss_rate_exit_threshold_percent_{60};
  std::uint64_t validator_suspend_duration_blocks_{1'000};
  std::size_t last_participation_eligible_signers_{0};
  struct BufferedSyncFrontier {
    FrontierProposal proposal;
    std::optional<FinalityCertificate> certificate;
    int from_peer_id{0};
  };
  std::map<Hash32, FrontierProposal> candidate_frontier_proposals_;
  std::map<std::uint64_t, BufferedSyncFrontier> buffered_sync_frontiers_;
  std::map<std::uint64_t, QuorumCertificate> highest_qc_by_height_;
  std::map<std::uint64_t, Hash32> highest_qc_payload_by_height_;
  std::map<std::uint64_t, TimeoutCertificate> highest_tc_by_height_;
  std::map<std::uint64_t, std::pair<Hash32, std::uint32_t>> local_vote_locks_;
  std::set<PubKey32> locally_observed_equivocators_;
  std::map<std::tuple<std::uint64_t, std::uint32_t, PubKey32>, Hash32> observed_proposals_;
  std::map<std::pair<std::uint64_t, std::uint32_t>, bool> proposed_in_round_;
  std::set<std::pair<std::uint64_t, std::uint32_t>> local_vote_reservations_;
  std::set<std::pair<std::uint64_t, std::uint32_t>> local_timeout_vote_reservations_;
  std::set<std::pair<std::uint64_t, std::uint32_t>> logged_committee_rounds_;
  std::map<std::uint64_t, consensus::EpochBestTicket> local_epoch_tickets_;
  std::optional<consensus::CanonicalDerivedState> canonical_state_;
  std::uint64_t last_open_epoch_ticket_epoch_{0};
  std::map<std::pair<int, std::uint64_t>, std::uint64_t> epoch_ticket_request_ms_;
  availability::AvailabilityPersistentState availability_state_;
  bool availability_state_rebuild_triggered_{false};
  std::string availability_state_rebuild_reason_;

  crypto::KeyPair local_key_;
  bool is_validator_{false};

  std::atomic<bool> running_{false};
  std::thread loop_thread_;
  mutable std::mutex local_bus_tasks_mu_;
  std::vector<std::thread> local_bus_tasks_;
  p2p::PeerManager p2p_;

  std::atomic<bool> pause_proposals_{false};
  std::uint64_t last_seed_attempt_ms_{0};
  std::uint64_t last_addrman_save_ms_{0};
  std::uint64_t last_summary_log_ms_{0};
  std::uint64_t last_finalized_progress_ms_{0};
  std::uint64_t last_finalized_tip_poll_ms_{0};
  std::uint32_t registration_ready_streak_{0};
  std::uint64_t last_runtime_status_persist_ms_{0};
  std::vector<std::string> bootstrap_peers_;
  std::vector<std::string> dns_seed_peers_;
  std::set<std::string> preflight_checked_seeds_;
  std::set<std::string> self_peer_endpoints_;
  p2p::AddrMan addrman_{10'000};
  ChainId chain_id_{};
  std::optional<Hash32> expected_genesis_hash_;
  std::string genesis_source_hint_{"embedded"};
  std::set<int> getaddr_requested_peers_;
  std::string last_bootstrap_source_{"none"};
  std::string mining_log_path_;
  bool bootstrap_template_mode_{false};
  std::optional<PubKey32> bootstrap_validator_pubkey_;
  mutable std::uint64_t last_logged_bootstrap_committee_height_{0};
  mutable std::uint64_t last_logged_bootstrap_committee_epoch_{0};
  mutable std::uint64_t last_logged_missing_bootstrap_committee_height_{0};
  std::uint64_t startup_ms_{0};
  std::map<int, PubKey32> peer_validator_pubkeys_;
  std::map<int, p2p::FinalizedTipMsg> peer_finalized_tips_;
  std::map<int, p2p::IngressTipsMsg> peer_ingress_tips_;
  std::map<std::pair<int, std::uint32_t>, p2p::GetIngressRangeMsg> requested_ingress_ranges_;
  std::optional<FrontierProposal> last_broadcast_finalized_frontier_;
  std::optional<FinalityCertificate> last_broadcast_finality_certificate_;
  bool restart_debug_{false};
  mutable std::mutex lightserver_mu_;
  int lightserver_pid_{-1};
  std::string lightserver_exec_path_;
};

std::optional<NodeConfig> parse_args(int argc, char** argv);

}  // namespace finalis::node
