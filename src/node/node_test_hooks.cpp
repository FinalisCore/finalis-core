// SPDX-License-Identifier: MIT

// Node test hooks: the public *_for_test methods and deterministic_test_keypairs.

#include "node.hpp"
#include "node_internal.hpp"

namespace finalis::node {
using namespace detail;

std::vector<crypto::KeyPair> Node::deterministic_test_keypairs() {
  std::vector<crypto::KeyPair> out;
  for (int i = 1; i <= 16; ++i) {
    std::array<std::uint8_t, 32> seed{};
    for (size_t j = 0; j < seed.size(); ++j) seed[j] = static_cast<std::uint8_t>(i * 19 + j);
    auto kp = crypto::keypair_from_seed32(seed);
    if (kp.has_value()) out.push_back(*kp);
  }
  return out;
}

bool Node::inject_vote_for_test(const Vote& vote) { return handle_vote(vote, false, 0); }

bool Node::inject_timeout_vote_for_test(const TimeoutVote& vote) { return handle_timeout_vote(vote, false, 0); }

std::string Node::inject_network_vote_result_for_test(const Vote& vote) {
  switch (handle_vote_result(vote, true, 1)) {
    case VoteHandlingResult::Accepted:
      return "accepted";
    case VoteHandlingResult::SoftReject:
      return "soft-reject";
    case VoteHandlingResult::HardReject:
      return "hard-reject";
  }
  return "unknown";
}

std::string Node::inject_network_vote_diagnostic_for_test(const Vote& vote) {
  std::string reject_reason;
  switch (handle_vote_result(vote, true, 1, &reject_reason)) {
    case VoteHandlingResult::Accepted:
      return "accepted";
    case VoteHandlingResult::SoftReject:
      return "soft-reject" + (reject_reason.empty() ? std::string() : ":" + reject_reason);
    case VoteHandlingResult::HardReject:
      return "hard-reject" + (reject_reason.empty() ? std::string() : ":" + reject_reason);
  }
  return "unknown";
}

std::string Node::inject_network_propose_result_for_test(const p2p::ProposeMsg& msg) {
  switch (handle_propose_result(msg, true, 0, nullptr)) {
    case ProposeHandlingResult::Accepted:
      return "accepted";
    case ProposeHandlingResult::SoftReject:
      return "soft-reject";
    case ProposeHandlingResult::HardReject:
      return "hard-reject";
  }
  return "unknown";
}

std::string Node::inject_network_propose_diagnostic_for_test(const p2p::ProposeMsg& msg) {
  std::string reject_reason;
  switch (handle_propose_result(msg, true, 0, &reject_reason)) {
    case ProposeHandlingResult::Accepted:
      return "accepted";
    case ProposeHandlingResult::SoftReject:
      return "soft-reject" + (reject_reason.empty() ? std::string() : ":" + reject_reason);
    case ProposeHandlingResult::HardReject:
      return "hard-reject" + (reject_reason.empty() ? std::string() : ":" + reject_reason);
  }
  return "unknown";
}

bool Node::inject_frontier_transition_for_test(const FrontierProposal& proposal, const FinalityCertificate& certificate) {
  const auto cert_check = precheck_finality_certificate(certificate, proposal.transition);
  std::lock_guard<std::mutex> lk(mu_);
  return handle_frontier_block_locked(proposal, certificate, 0, false, cert_check);
}

bool Node::inject_propose_msg_for_test(const p2p::ProposeMsg& msg) { return handle_propose(msg, false); }

bool Node::observe_frontier_proposal_for_test(const FrontierProposal& proposal) {
  std::lock_guard<std::mutex> lk(mu_);
  return check_and_record_proposer_equivocation_locked(proposal.transition);
}

bool Node::inject_frontier_block_for_test(const FrontierProposal& proposal, const std::vector<FinalitySig>& finality_signatures) {
  std::lock_guard<std::mutex> lk(mu_);
  last_test_hook_error_.clear();
  if (!running_) {
    last_test_hook_error_ = "node-not-running";
    return false;
  }
  if (!finalized_identity_valid_for_frontier_runtime(finalized_height_, finalized_identity_)) {
    last_test_hook_error_ = "frontier-parent-identity-kind-mismatch";
    return false;
  }
  const auto committee = committee_for_height_round(proposal.transition.height, proposal.transition.round);
  if (committee.empty()) {
    last_test_hook_error_ = "empty-committee";
    return false;
  }
  const auto quorum = consensus::quorum_threshold(committee.size());
  const auto canonical_sigs = canonicalize_finality_signatures_locked(finality_signatures, quorum);
  if (canonical_sigs.size() < quorum) {
    last_test_hook_error_ = "insufficient-signatures";
    return false;
  }
  const auto cert = make_finality_certificate(proposal.transition.height, proposal.transition.round,
                                              proposal.transition.transition_id(), quorum, committee, canonical_sigs);
  std::string validation_error;
  if (!validate_frontier_proposal_locked(proposal, &validation_error)) {
    last_test_hook_error_ = "validate-frontier-proposal-failed:" + validation_error;
    return false;
  }
  std::string lock_error;
  if (!can_accept_frontier_with_lock_locked(proposal.transition, &lock_error)) {
    last_test_hook_error_ = "frontier-lock-reject:" + lock_error;
    return false;
  }
  std::vector<FinalitySig> verified_sigs;
  std::string cert_error;
  if (!verify_finality_certificate_for_frontier_locked(cert, proposal.transition, &verified_sigs, &cert_error)) {
    last_test_hook_error_ = "frontier-certificate-reject:" + cert_error;
    return false;
  }
  consensus::CanonicalFrontierRecord certified_record;
  std::string frontier_record_error;
  if (!consensus::load_certified_frontier_record_from_storage(db_, proposal.transition, &certified_record,
                                                              &frontier_record_error)) {
    last_test_hook_error_ = "load-certified-frontier-record-failed:" + frontier_record_error;
    return false;
  }
  certified_record.ordered_records = proposal.ordered_records;
  std::string apply_error;
  consensus::CanonicalDerivedState next_state;
  if (!canonical_state_.has_value()) {
    last_test_hook_error_ = "missing-canonical-state";
    return false;
  }
  if (!consensus::apply_frontier_record(canonical_derivation_config_locked(), *canonical_state_, certified_record,
                                        &next_state, &apply_error)) {
    last_test_hook_error_ = "apply-finalized-frontier-failed:" + apply_error;
    return false;
  }
  // Already verified via verify_finality_certificate_for_frontier_locked just above
  // (we'd have returned false otherwise) -- build the precheck result from that, rather
  // than calling precheck_finality_certificate again and re-running the crypto.
  CertificateCheck cert_check;
  cert_check.ok = true;
  cert_check.canonical_sigs = verified_sigs;
  if (handle_frontier_block_locked(proposal, cert, 0, false, cert_check)) return true;
  last_test_hook_error_ = "handle-frontier-block-rejected";
  return false;
}

bool Node::inject_tx_for_test(const AnyTx& tx, bool relay) {
  if (relay) return handle_tx(tx, false);
  std::lock_guard<std::mutex> lk(mu_);
  mempool_.set_validation_context(special_validation_context_locked(finalized_height_ + 1));
  (void)mempool_.set_confidential_pool_value(mempool_confidential_pool_value_locked());
  std::string err;
  return mempool_.accept_tx(tx, utxos_, &err);
}

bool Node::pause_proposals_for_test(bool pause) {
  pause_proposals_.store(pause);
  std::lock_guard<std::mutex> lk(mu_);
  const auto now = now_ms();
  round_started_ms_ = now;
  last_finalized_progress_ms_ = now;
  arm_round0_deadline_locked(now);
  return true;
}

bool Node::advance_round_for_test(std::uint64_t expected_height, std::uint32_t target_round) {
  std::lock_guard<std::mutex> lk(mu_);
  if (!running_) return false;
  if (expected_height != finalized_height_ + 1) return false;
  current_round_ = target_round;
  round_started_ms_ = now_ms();
  if (current_round_ == 0) arm_round0_deadline_locked(round_started_ms_);
  return true;
}

bool Node::mempool_contains_for_test(const Hash32& txid) const {
  std::lock_guard<std::mutex> lk(mu_);
  return mempool_.contains(txid);
}

std::optional<TxOut> Node::find_utxo_by_pubkey_hash_for_test(const std::array<std::uint8_t, 20>& pkh,
                                                              OutPoint* outpoint) const {
  std::lock_guard<std::mutex> lk(mu_);
  for (const auto& [op, e] : utxos_) {
    const auto txout = transparent_txout_from_utxo_entry(e);
    if (!txout.has_value()) continue;
    std::array<std::uint8_t, 20> got{};
    if (!is_p2pkh_script_pubkey(txout->script_pubkey, &got)) continue;
    if (got != pkh) continue;
    if (outpoint) *outpoint = op;
    return *txout;
  }
  return std::nullopt;
}

std::vector<std::pair<OutPoint, TxOut>> Node::find_utxos_by_pubkey_hash_for_test(
    const std::array<std::uint8_t, 20>& pkh) const {
  std::vector<std::pair<OutPoint, TxOut>> out;
  std::lock_guard<std::mutex> lk(mu_);
  for (const auto& [op, e] : utxos_) {
    const auto txout = transparent_txout_from_utxo_entry(e);
    if (!txout.has_value()) continue;
    std::array<std::uint8_t, 20> got{};
    if (!is_p2pkh_script_pubkey(txout->script_pubkey, &got)) continue;
    if (got != pkh) continue;
    out.push_back({op, *txout});
  }
  return out;
}

bool Node::has_utxo_for_test(const OutPoint& op, TxOut* out) const {
  std::lock_guard<std::mutex> lk(mu_);
  auto it = utxos_.find(op);
  if (it == utxos_.end()) return false;
  const auto txout = transparent_txout_from_utxo_entry(it->second);
  if (!txout.has_value()) return false;
  if (out) *out = *txout;
  return true;
}

std::string Node::proposer_path_for_next_height_for_test() const {
  return "finalized-checkpoint-proposer-schedule";
}

std::string Node::committee_path_for_next_height_for_test() const {
  return "finalized-committee-checkpoint";
}

std::string Node::vote_path_for_next_height_for_test() const {
  return "committee-membership";
}

std::size_t Node::quorum_threshold_for_next_height_for_test() const {
  std::lock_guard<std::mutex> lk(mu_);
  const auto committee = committee_for_height_round(finalized_height_ + 1, current_round_);
  return consensus::quorum_threshold(committee.size());
}

std::vector<PubKey32> Node::active_validators_for_next_height_for_test() const {
  std::lock_guard<std::mutex> lk(mu_);
  return validators_.active_sorted(finalized_height_ + 1);
}

std::vector<PubKey32> Node::committee_for_next_height_for_test() const {
  std::lock_guard<std::mutex> lk(mu_);
  return committee_for_height_round(finalized_height_ + 1, current_round_);
}

std::vector<PubKey32> Node::committee_for_height_round_for_test(std::uint64_t height, std::uint32_t round) const {
  std::lock_guard<std::mutex> lk(mu_);
  return committee_for_height_round(height, round);
}

std::optional<PubKey32> Node::proposer_for_height_round_for_test(std::uint64_t height, std::uint32_t round) const {
  std::lock_guard<std::mutex> lk(mu_);
  return leader_for_height_round(height, round);
}

std::optional<QuorumCertificate> Node::highest_qc_for_height_for_test(std::uint64_t height) const {
  std::lock_guard<std::mutex> lk(mu_);
  return highest_qc_for_height_locked(height);
}

std::optional<TimeoutCertificate> Node::highest_tc_for_height_for_test(std::uint64_t height) const {
  std::lock_guard<std::mutex> lk(mu_);
  return highest_tc_for_height_locked(height);
}

std::optional<std::pair<Hash32, std::uint32_t>> Node::local_vote_lock_for_test(std::uint64_t height) const {
  std::lock_guard<std::mutex> lk(mu_);
  auto it = local_vote_locks_.find(height);
  if (it == local_vote_locks_.end()) return std::nullopt;
  return it->second;
}

bool Node::local_vote_recorded_for_test(std::uint64_t height, std::uint32_t round, const Hash32& transition_id) const {
  std::lock_guard<std::mutex> lk(mu_);
  for (const auto& sig : votes_.signatures_for(height, round, transition_id)) {
    if (sig.validator_pubkey == local_key_.public_key) return true;
  }
  return false;
}

bool Node::has_candidate_frontier_proposal_for_test(const Hash32& transition_id) const {
  std::lock_guard<std::mutex> lk(mu_);
  return candidate_frontier_proposals_.find(transition_id) != candidate_frontier_proposals_.end();
}

consensus::ConfidentialSupplyAuditResult Node::confidential_supply_audit_for_test() {
  std::lock_guard<std::mutex> lk(mu_);
  run_confidential_supply_audit_locked("test");
  return last_confidential_supply_audit_;
}

std::set<std::uint64_t> Node::abstain_heights_for_test() const {
  std::lock_guard<std::mutex> lk(mu_);
  return abstain_heights_;
}

std::size_t Node::timeout_vote_count_for_height_round_for_test(std::uint64_t height, std::uint32_t round) const {
  std::lock_guard<std::mutex> lk(mu_);
  return timeout_votes_.signatures_for(height, round).size();
}

bool Node::local_timeout_vote_reserved_for_test(std::uint64_t height, std::uint32_t round) const {
  std::lock_guard<std::mutex> lk(mu_);
  return local_timeout_vote_reservations_.find({height, round}) != local_timeout_vote_reservations_.end();
}

bool Node::local_is_committee_member_for_test(std::uint64_t height, std::uint32_t round) const {
  std::lock_guard<std::mutex> lk(mu_);
  return is_committee_member_for(local_key_.public_key, height, round);
}

std::uint64_t Node::round_age_ms_for_test() const {
  std::lock_guard<std::mutex> lk(mu_);
  const auto now = now_ms();
  return now > round_started_ms_ ? (now - round_started_ms_) : 0;
}

Hash32 Node::epoch_ticket_challenge_anchor_for_test(std::uint64_t height) const {
  std::lock_guard<std::mutex> lk(mu_);
  return epoch_ticket_challenge_anchor_locked(height);
}

PubKey32 Node::local_validator_pubkey_for_test() const {
  std::lock_guard<std::mutex> lk(mu_);
  return local_key_.public_key;
}

std::string Node::consensus_rules_fingerprint_for_test() const {
  std::lock_guard<std::mutex> lk(mu_);
  return ascii_lower(consensus_rules_fingerprint(cfg_.network, chain_id_, kFixedValidationRulesVersion));
}

std::optional<consensus::ValidatorInfo> Node::validator_info_for_test(const PubKey32& pub) const {
  std::lock_guard<std::mutex> lk(mu_);
  return validators_.get(pub);
}

bool Node::seed_bonded_validator_for_test(const PubKey32& pub, const OutPoint& bond_outpoint, std::uint64_t bond_amount) {
  std::lock_guard<std::mutex> lk(mu_);
  auto info = validators_.get(pub);
  if (!info.has_value()) return false;

  Bytes reg_spk{'S', 'C', 'V', 'A', 'L', 'R', 'E', 'G'};
  reg_spk.insert(reg_spk.end(), pub.begin(), pub.end());
  TxOut bond_out{bond_amount, reg_spk};

  info->has_bond = true;
  info->bonded_amount = bond_amount;
  info->bond_outpoint = bond_outpoint;
  validators_.upsert(pub, *info);

  if (!canonical_state_.has_value()) return false;
  auto updated = *canonical_state_;
  updated.validators.upsert(pub, *info);
  updated.utxos[bond_outpoint] = UtxoEntryV2{bond_out};
  updated.state_commitment = consensus::consensus_state_commitment(canonical_derivation_config_locked(), updated);

  if (!db_.put_utxo_v2(bond_outpoint, UtxoEntryV2{bond_out})) return false;
  if (!db_.put_validator(pub, *info)) return false;
  if (!persist_canonical_cache_rows(db_, updated)) return false;
  (void)db_.erase(storage::key_consensus_state_commitment_cache());
  if (!verify_and_persist_consensus_state_commitment_locked(updated)) return false;
  canonical_state_ = updated;
  utxos_ = updated.utxos;
  return true;
}

Hash32 Node::canonical_state_commitment_for_test() const {
  std::lock_guard<std::mutex> lk(mu_);
  if (!canonical_state_.has_value()) return zero_hash();
  return canonical_state_->state_commitment;
}

std::uint64_t Node::canonical_state_height_for_test() const {
  std::lock_guard<std::mutex> lk(mu_);
  if (!canonical_state_.has_value()) return 0;
  return canonical_state_->finalized_height;
}

std::uint16_t Node::p2p_port_for_test() const { return cfg_.p2p_port; }

bool Node::endpoint_is_obvious_self_for_test(const std::string& host, std::uint16_t port) const {
  return endpoint_matches_local_listener(host, port, nullptr);
}

bool Node::self_endpoint_suppressed_for_test(const std::string& host, std::uint16_t port) const {
  std::lock_guard<std::mutex> lk(mu_);
  return is_self_endpoint_suppressed_locked(host + ":" + std::to_string(port));
}

std::optional<FrontierProposal> Node::build_frontier_proposal_for_test(std::uint64_t height, std::uint32_t round) {
  std::lock_guard<std::mutex> lk(mu_);
  last_test_hook_error_.clear();
  return build_frontier_transition_locked(height, round);
}

std::string Node::last_test_hook_error_for_test() const {
  std::lock_guard<std::mutex> lk(mu_);
  return last_test_hook_error_;
}

bool Node::inject_ingress_tips_for_test(const p2p::IngressTipsMsg& msg, int peer_id) {
  std::lock_guard<std::mutex> lk(mu_);
  return handle_ingress_tips_locked(peer_id, msg);
}

bool Node::inject_ingress_range_for_test(const p2p::IngressRangeMsg& msg, int peer_id) {
  std::lock_guard<std::mutex> lk(mu_);
  return handle_ingress_range_locked(peer_id, msg);
}

std::string Node::inject_ingress_range_result_for_test(const p2p::IngressRangeMsg& msg, int peer_id) {
  std::lock_guard<std::mutex> lk(mu_);
  std::string error;
  if (handle_ingress_range_locked(peer_id, msg, &error)) return {};
  return error.empty() ? "unknown" : error;
}

void Node::set_requested_ingress_range_for_test(int peer_id, const p2p::GetIngressRangeMsg& msg) {
  std::lock_guard<std::mutex> lk(mu_);
  requested_ingress_ranges_[{peer_id, msg.lane}] = msg;
}

std::optional<p2p::GetIngressRangeMsg> Node::requested_ingress_range_for_test(int peer_id, std::uint32_t lane) const {
  std::lock_guard<std::mutex> lk(mu_);
  auto it = requested_ingress_ranges_.find({peer_id, lane});
  if (it == requested_ingress_ranges_.end()) return std::nullopt;
  return it->second;
}

bool Node::overwrite_runtime_next_height_checkpoint_for_test(const storage::FinalizedCommitteeCheckpoint& checkpoint) {
  std::lock_guard<std::mutex> lk(mu_);
  const auto target_epoch = consensus::committee_epoch_start(finalized_height_ + 1, cfg_.network.committee_epoch_blocks);
  if (checkpoint.epoch_start_height != target_epoch) return false;
  finalized_committee_checkpoints_[target_epoch] = checkpoint;
  return true;
}

bool Node::overwrite_runtime_frontier_cursor_for_test(std::uint64_t finalized_frontier) {
  std::lock_guard<std::mutex> lk(mu_);
  if (!canonical_state_.has_value()) return false;
  canonical_state_->finalized_frontier = finalized_frontier;
  return true;
}

void Node::set_peer_ip_for_test(int peer_id, const std::string& ip) {
  std::lock_guard<std::mutex> lk(mu_);
  if (peer_id <= 0 || ip.empty()) return;
  peer_ip_cache_[peer_id] = ip;
}

void Node::score_peer_for_test(int peer_id, p2p::MisbehaviorReason reason, const std::string& note) {
  std::lock_guard<std::mutex> lk(mu_);
  score_peer_locked(peer_id, reason, note);
}

p2p::PeerScoreStatus Node::peer_score_status_for_test(const std::string& ip,
                                                      std::optional<std::uint64_t> now_unix_opt) const {
  std::lock_guard<std::mutex> lk(mu_);
  const auto now = now_unix_opt.value_or(now_unix());
  return discipline_.status(ip, now);
}

void Node::decay_peer_discipline_for_test(std::uint64_t now_unix_value) {
  std::lock_guard<std::mutex> lk(mu_);
  discipline_.decay(now_unix_value);
}

}  // namespace finalis::node
