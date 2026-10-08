// SPDX-License-Identifier: MIT

// BFT consensus: proposal/vote/timeout handling, QC/TC and finality certificates, vote locks and
// safety state, frontier acceptance and sync buffering, finalization and proposal building.

#include "node.hpp"
#include "node_internal.hpp"

#include <algorithm>
#include <iostream>
#include <array>
#include <set>
#include <sstream>

#include "codec/bytes.hpp"
#include "consensus/canonical_derivation.hpp"
#include "consensus/ingress.hpp"
#include "consensus/validator_registry.hpp"
#include "crypto/ed25519.hpp"
#include "crypto/hash.hpp"
#include "utxo/confidential_tx.hpp"

namespace finalis::node {
using namespace detail;

namespace {

constexpr std::size_t kMaxBlockTxs = 1000;
constexpr std::size_t kMaxBlockBytes = 1 * 1024 * 1024;

constexpr std::size_t kMaxCandidateBlocks = 512;
constexpr std::size_t kMaxCandidateBlockBytes = 32 * 1024 * 1024;
constexpr std::uint32_t kProposalRoundWindow = 32;

constexpr std::uint64_t kTimeoutVoteMessageDedupTtlMs = 120'000;
constexpr std::size_t kMaxSeenTimeoutVoteMessages = 65'536;
constexpr std::uint32_t kTimeoutVoteDuplicateLogEvery = 32;

struct FrontierBuildSelection {
  FrontierVector next_vector{};
  consensus::CertifiedIngressLaneRecords lane_records;
  std::vector<Bytes> ordered_records;
};

bool inspect_frontier_ordered_record_supported(const Bytes& raw_record, std::size_t index, Hash32* txid_out,
                                               std::string* error) {
  const auto tx = parse_any_tx(raw_record);
  if (!tx.has_value()) {
    if (error) *error = "frontier-ordered-record-parse-failed index=" + std::to_string(index);
    return false;
  }
  if (txid_out) *txid_out = txid_any(*tx);
  return true;
}

std::string justify_summary(const std::optional<QuorumCertificate>& qc, const std::optional<TimeoutCertificate>& tc) {
  if (qc.has_value()) {
    return "qc(height=" + std::to_string(qc->height) + ",round=" + std::to_string(qc->round) +
           ",transition=" + short_hash_hex(qc->frontier_transition_id) + ")";
  }
  if (tc.has_value()) {
    return "tc(height=" + std::to_string(tc->height) + ",round=" + std::to_string(tc->round) + ")";
  }
  return "none";
}

std::string signer_set_summary(const std::vector<FinalitySig>& sigs) {
  std::ostringstream oss;
  bool first = true;
  for (const auto& sig : sigs) {
    if (!first) oss << ",";
    first = false;
    oss << short_pub_hex(sig.validator_pubkey);
  }
  return oss.str();
}

Bytes serialize_consensus_safety_state(const std::optional<std::pair<Hash32, std::uint32_t>>& lock_state,
                                       const std::optional<QuorumCertificate>& qc_state,
                                       const std::optional<Hash32>& qc_payload_id) {
  codec::ByteWriter w;
  w.u8(lock_state.has_value() ? 1 : 0);
  if (lock_state.has_value()) {
    w.bytes_fixed(lock_state->first);
    w.u32le(lock_state->second);
  }
  w.u8(qc_state.has_value() ? 1 : 0);
  if (qc_state.has_value()) {
    w.u64le(qc_state->height);
    w.u32le(qc_state->round);
    w.bytes_fixed(qc_state->frontier_transition_id);
    w.u8(qc_payload_id.has_value() ? 1 : 0);
    if (qc_payload_id.has_value()) w.bytes_fixed(*qc_payload_id);
    w.varint(qc_state->signatures.size());
    for (const auto& sig : qc_state->signatures) {
      w.bytes_fixed(sig.validator_pubkey);
      w.bytes_fixed(sig.signature);
    }
  }
  return w.take();
}

QuorumCertificate make_quorum_certificate(std::uint64_t height, std::uint32_t round, const Hash32& transition_id,
                                          const std::vector<FinalitySig>& signatures) {
  QuorumCertificate qc;
  qc.height = height;
  qc.round = round;
  qc.frontier_transition_id = transition_id;
  qc.signatures = signatures;
  return qc;
}

Hash32 vote_equivocation_record_id(const EquivocationEvidence& ev) {
  codec::ByteWriter w;
  w.bytes(Bytes{'S', 'L', 'V', 'O', 'T', 'E'});
  w.u64le(ev.a.height);
  w.u32le(ev.a.round);
  w.bytes_fixed(ev.a.validator_pubkey);
  w.bytes_fixed(ev.a.frontier_transition_id);
  w.bytes_fixed(ev.a.signature);
  w.bytes_fixed(ev.b.frontier_transition_id);
  w.bytes_fixed(ev.b.signature);
  return crypto::sha256d(w.data());
}

storage::SlashingRecord make_vote_equivocation_record(const EquivocationEvidence& ev, std::uint64_t observed_height) {
  storage::SlashingRecord rec;
  rec.record_id = vote_equivocation_record_id(ev);
  rec.kind = storage::SlashingRecordKind::VOTE_EQUIVOCATION;
  rec.validator_pubkey = ev.a.validator_pubkey;
  rec.height = ev.a.height;
  rec.round = ev.a.round;
  rec.observed_height = observed_height;
  rec.object_a = ev.a.block_id;
  rec.object_b = ev.b.block_id;
  return rec;
}

storage::SlashingRecord make_proposer_equivocation_record(const PubKey32& leader_pubkey, std::uint64_t height,
                                                          std::uint32_t round, const Hash32& object_a,
                                                          const Hash32& object_b, std::uint64_t observed_height) {
  storage::SlashingRecord rec;
  codec::ByteWriter w;
  w.bytes_fixed(leader_pubkey);
  w.u64le(height);
  w.u32le(round);
  w.bytes_fixed(object_a);
  w.bytes_fixed(object_b);
  rec.record_id = crypto::sha256d(w.data());
  rec.kind = storage::SlashingRecordKind::PROPOSER_EQUIVOCATION;
  rec.validator_pubkey = leader_pubkey;
  rec.height = height;
  rec.round = round;
  rec.observed_height = observed_height;
  rec.object_a = object_a;
  rec.object_b = object_b;
  return rec;
}

}  // namespace

std::string Node::consensus_state_locked(std::uint64_t now_ms, std::size_t* observed_signers,
                                         std::size_t* quorum_threshold) const {
  if (repair_mode_) {
    if (observed_signers) *observed_signers = 0;
    if (quorum_threshold) *quorum_threshold = 0;
    return "REPAIRING";
  }
  const std::uint64_t h = finalized_height_ + 1;
  const auto committee = committee_for_height_round(h, current_round_);
  const std::size_t quorum = consensus::quorum_threshold(committee.size());
  if (quorum_threshold) *quorum_threshold = quorum;

  std::size_t observed = 0;
  if (!committee.empty()) {
    const auto participants = votes_.participants_for(h, current_round_);
    for (const auto& pub : committee) {
      if (participants.find(pub) != participants.end()) ++observed;
    }
    if (is_committee_member_for(local_key_.public_key, h, current_round_)) observed = std::max<std::size_t>(observed, 1);
  }
  if (observed_signers) *observed_signers = observed;

  const std::size_t peers = peer_count();
  const bool single_node_bootstrap = single_node_bootstrap_active_locked(h);
  if (!single_node_bootstrap && (peers == 0 || (finalized_height_ == 0 && observed == 0))) return "SYNCING";
  if (single_node_bootstrap && observed < quorum) return "WAITING_FOR_QUORUM";

  const std::uint64_t stale_ms = cfg_.network.round_timeout_ms * 2ULL;
  if (now_ms > last_finalized_progress_ms_ + stale_ms) {
    if (observed < quorum) return "WAITING_FOR_QUORUM";
    return single_node_bootstrap ? "FINALIZING" : "SYNCING";
  }
  return "FINALIZING";
}

bool Node::next_height_requires_repair_locked(std::string* reason) const {
  const std::uint64_t height = finalized_height_ + 1;
  if (bootstrap_template_mode_ && finalized_height_ == 0 && bootstrap_validator_pubkey_.has_value()) {
    const auto active = validators_.active_sorted(1);
    if (active.size() == 1 && active.front() == *bootstrap_validator_pubkey_) {
      if (reason) reason->clear();
      return false;
    }
  }
  if (bootstrap_template_mode_ && finalized_height_ == 0 && !bootstrap_validator_pubkey_.has_value() &&
      validators_.active_sorted(1).empty()) {
    const bool has_bootstrap_sources = !cfg_.disable_p2p && (!bootstrap_peers_.empty() || !dns_seed_peers_.empty());
    if (!has_bootstrap_sources) {
      if (reason) reason->clear();
      return false;
    }
  }
  const auto checkpoint = finalized_committee_checkpoint_for_height_locked(height);
  if (!checkpoint.has_value() || checkpoint->ordered_members.empty()) {
    if (reason) *reason = "missing-finalized-committee-checkpoint";
    return true;
  }

  const auto committee = epoch_committee_for_next_height_locked(height, 0);
  if (committee.empty()) {
    if (reason) *reason = "empty-committee";
    return true;
  }

  if (!cfg_.disable_p2p && established_peer_count() == 0 && current_round_ > 0 &&
      !single_node_bootstrap_active_locked(height)) {
    if (reason) *reason = "no-established-peers";
    return true;
  }

  const auto schedule = proposer_schedule_from_checkpoint(cfg_.network, validators_, *checkpoint, height);
  if (schedule.empty()) {
    if (reason) *reason = "empty-proposer-schedule";
    return true;
  }
  return false;
}

bool Node::maybe_repair_next_height_locked(std::uint64_t now_ms, std::string* reason) {
  std::string local_reason;
  if (!next_height_requires_repair_locked(&local_reason)) {
    if (repair_mode_) {
      log_line("consensus-repair-exit target_height=" + std::to_string(finalized_height_ + 1) + " status=ok");
    }
    repair_mode_ = false;
    repair_target_height_ = 0;
    repair_reason_.clear();
    repair_started_ms_ = 0;
    last_repair_log_ms_ = 0;
    if (reason) reason->clear();
    return true;
  }

  const std::uint64_t target_height = finalized_height_ + 1;
  const bool entering = !repair_mode_ || repair_target_height_ != target_height;
  repair_mode_ = true;
  repair_target_height_ = target_height;
  repair_reason_ = local_reason;
  if (entering) {
    repair_started_ms_ = now_ms;
    current_round_ = 0;
    round_started_ms_ = now_ms;
    arm_round0_deadline_locked(round_started_ms_);
    log_line("consensus-repair-enter target_height=" + std::to_string(target_height) +
             " parent_height=" + std::to_string(target_height - 1) + " reason=" + repair_reason_);
  }

  maybe_finalize_epoch_committees_locked();
  const auto required_epoch = epoch_committee_snapshot_epoch_for_height_locked(target_height);
  if (required_epoch.has_value() && !frozen_epoch_committee_snapshot_for_height_locked(target_height).has_value()) {
    rebuild_epoch_committee_state_locked(*required_epoch, "runtime-repair", true);
    if (!frozen_epoch_committee_snapshot_for_height_locked(target_height).has_value()) {
      const auto tickets = db_.load_epoch_tickets(*required_epoch);
      if (tickets.empty()) (void)recover_single_validator_epoch_committee_locked(*required_epoch, "runtime-repair");
    }
  }
  if (!cfg_.disable_p2p) {
    maybe_request_epoch_ticket_reconciliation_locked(now_ms);
    (void)maybe_request_forward_sync_block_locked();
  }

  if (!next_height_requires_repair_locked(&local_reason)) {
    repair_mode_ = false;
    repair_target_height_ = 0;
    repair_reason_.clear();
    repair_started_ms_ = 0;
    last_repair_log_ms_ = 0;
    current_round_ = 0;
    round_started_ms_ = now_ms;
    arm_round0_deadline_locked(round_started_ms_);
    log_line("consensus-repair-exit target_height=" + std::to_string(target_height) + " status=ok");
    if (reason) reason->clear();
    return true;
  }

  repair_reason_ = local_reason;
  if (reason) *reason = repair_reason_;
  if (now_ms >= last_repair_log_ms_ + 5000) {
    last_repair_log_ms_ = now_ms;
    log_line("consensus-repair-wait target_height=" + std::to_string(target_height) +
             " parent_height=" + std::to_string(target_height - 1) + " reason=" + repair_reason_);
  }
  return false;
}

std::vector<FinalitySig> Node::canonicalize_finality_signatures_locked(const std::vector<FinalitySig>& signatures,
                                                                       std::size_t quorum) const {
  std::vector<FinalitySig> out = signatures;
  std::sort(out.begin(), out.end(), [](const FinalitySig& a, const FinalitySig& b) {
    if (a.validator_pubkey != b.validator_pubkey) return a.validator_pubkey < b.validator_pubkey;
    return a.signature < b.signature;
  });
  out.erase(std::unique(out.begin(), out.end(), [](const FinalitySig& a, const FinalitySig& b) {
              return a.validator_pubkey == b.validator_pubkey;
            }),
            out.end());
  if (out.size() > quorum) out.resize(quorum);
  return out;
}

void Node::arm_round0_deadline_locked(std::uint64_t now_ms) {
  const std::uint64_t min_block_interval_ms = static_cast<std::uint64_t>(cfg_.network.min_block_interval_ms);
  const std::uint64_t half_round_timeout_ms =
      std::max<std::uint64_t>(1, static_cast<std::uint64_t>(cfg_.network.round_timeout_ms) / 2);
  const std::uint64_t grace_ms =
      std::min<std::uint64_t>(static_cast<std::uint64_t>(cfg_.network.round_timeout_ms),
                              std::max<std::uint64_t>(min_block_interval_ms, half_round_timeout_ms));
  round0_deadline_ms_ = now_ms + grace_ms;
}

bool Node::apply_finalized_frontier_effects_locked(const consensus::CanonicalFrontierRecord& record,
                                                   std::vector<FinalitySig> finality_signatures,
                                                   bool clear_requested_sync,
                                                   const std::vector<PubKey32>* effective_committee,
                                                   std::string* error) {
  const std::uint64_t previous_finalized_height = finalized_height_;
  const auto committee =
      effective_committee != nullptr ? *effective_committee : committee_for_height_round(record.transition.height, record.transition.round);
  if (committee.empty()) {
    if (error) *error = "empty-committee";
    return false;
  }
  const std::size_t quorum = consensus::quorum_threshold(committee.size());
  const auto canonical_sigs = canonicalize_finality_signatures_locked(finality_signatures, quorum);
  if (canonical_sigs.size() < quorum) {
    if (error) *error = "quorum-not-met";
    return false;
  }

  const auto transition_id = record.transition.transition_id();
  const FinalityCertificate certificate = make_finality_certificate(record.transition.height, record.transition.round,
                                                                    transition_id, quorum, committee, canonical_sigs);

  if (!canonical_state_.has_value()) {
    if (error) *error = "missing-canonical-state";
    return false;
  }
  consensus::CanonicalDerivedState next_state;
  std::string derivation_error;
  if (!consensus::apply_frontier_record(canonical_derivation_config_locked(), *canonical_state_, record, &next_state,
                                        &derivation_error)) {
    log_line("finalized-state-invariant-violation source=live-frontier-apply height=" +
             std::to_string(record.transition.height) + " detail=" + derivation_error);
    if (error) *error = "apply-frontier-record-failed:" + derivation_error;
    return false;
  }

  // Every write for this finalized block accumulates here and commits once,
  // atomically, at the very end of this function (db_.write_batch(batch))
  // instead of each db_.put_X/erase hitting the WAL as a separate synchronous
  // call while mu_ is held on the network reader thread.
  storage::DB::Batch batch(db_);

  std::string persist_error;
  if (!persist_finalized_frontier_record(record, utxos_, batch, &persist_error)) {
    if (error) *error = "persist-frontier-record-failed" +
                        (persist_error.empty() ? std::string() : ":" + persist_error);
    return false;
  }
  if (!batch.put_finality_certificate(certificate)) {
    if (error) *error = "put-finality-certificate-failed";
    return false;
  }
  batch.put(kConfidentialSupplyLedgerKey,
            consensus::serialize_confidential_supply_ledger(next_state.confidential_supply, record.transition.height));
  const bool block_had_txv2 =
      next_state.confidential_supply.txv2_count != canonical_state_->confidential_supply.txv2_count ||
      next_state.confidential_supply.known != canonical_state_->confidential_supply.known;

  highest_qc_by_height_[record.transition.height] =
      make_quorum_certificate(record.transition.height, record.transition.round, transition_id, canonical_sigs);
  highest_qc_payload_by_height_[record.transition.height] = consensus_payload_id(record.transition);
  persist_consensus_safety_state_locked(record.transition.height, batch);

  std::vector<Hash32> confirmed_txids;
  for (const auto& raw : record.ordered_records) {
    auto tx = parse_any_tx(raw);
    if (tx.has_value()) confirmed_txids.push_back(txid_any(*tx));
  }
  if (record.transition.timestamp != 0) {
    mempool_.on_finalized_block_timestamp(record.transition.timestamp);
  }
  mempool_.remove_confirmed(confirmed_txids);
  hydrate_runtime_from_canonical_state_locked(next_state);
  if (block_had_txv2) run_confidential_supply_audit_locked("finalized-block");
  mempool_.prune_against_utxo(utxos_);
  const auto now = now_ms();
  if (finalized_height_ > previous_finalized_height) {
    current_round_ = 0;
    round_started_ms_ = now;
    arm_round0_deadline_locked(now);
    last_finalized_progress_ms_ = now;
    proposed_in_round_.clear();

    // Drop stale vote reservations and per-height vote caches at/below the newly finalized tip.
    for (auto it = local_vote_reservations_.begin(); it != local_vote_reservations_.end();) {
      if (it->first <= finalized_height_) {
        it = local_vote_reservations_.erase(it);
      } else {
        ++it;
      }
    }
    for (auto it = local_timeout_vote_reservations_.begin(); it != local_timeout_vote_reservations_.end();) {
      if (it->first <= finalized_height_) {
        it = local_timeout_vote_reservations_.erase(it);
      } else {
        ++it;
      }
    }
    votes_.clear_height(finalized_height_ + 1);
    timeout_votes_.clear_height(finalized_height_ + 1);
    log_line("round-state-reset height=" + std::to_string(finalized_height_ + 1) +
             " round=0 reason=finalized-advance previous_height=" + std::to_string(previous_finalized_height) +
             " new_height=" + std::to_string(finalized_height_));
  } else {
    current_round_ = 0;
    round_started_ms_ = now;
    arm_round0_deadline_locked(now);
    last_finalized_progress_ms_ = now;
  }

  if (!persist_canonical_cache_rows(db_, batch, next_state)) {
    if (error) *error = "persist-canonical-cache-rows-failed";
    return false;
  }
  if (!verify_and_persist_consensus_state_commitment_locked(next_state, batch)) {
    if (error) *error = "persist-consensus-state-commitment-failed";
    return false;
  }
  (void)persist_state_roots(db_, batch, finalized_height_, utxos_, validators_, kFixedValidationRulesVersion);

  if (clear_requested_sync) {
    requested_sync_artifacts_.erase(transition_id);
    requested_sync_heights_.erase(record.transition.height);
    for (auto it = requested_sync_height_peers_.begin(); it != requested_sync_height_peers_.end();) {
      if (it->first.first == record.transition.height) {
        it = requested_sync_height_peers_.erase(it);
      } else {
        ++it;
      }
    }
  }
  candidate_frontier_proposals_.clear();
  candidate_block_sizes_.clear();
  // Keep every verified vote for the finalized transition (not just the
  // quorum-truncated certificate) so the next proposer can record the full
  // participation of this height.
  finalized_tip_votes_ = FinalizedTipVotes{};
  finalized_tip_votes_.height = record.transition.height;
  finalized_tip_votes_.round = record.transition.round;
  finalized_tip_votes_.transition_id = transition_id;
  finalized_tip_votes_.committee.insert(committee.begin(), committee.end());
  for (const auto& sig : votes_.signatures_for(record.transition.height, record.transition.round, transition_id)) {
    if (finalized_tip_votes_.committee.count(sig.validator_pubkey) != 0) {
      finalized_tip_votes_.sigs.emplace(sig.validator_pubkey, sig.signature);
    }
  }
  for (const auto& sig : canonical_sigs) finalized_tip_votes_.sigs.emplace(sig.validator_pubkey, sig.signature);
  votes_.clear_height(record.transition.height);
  timeout_votes_.clear_height(record.transition.height);
  if (finalized_height_ > 0) {
    clear_consensus_safety_state_locked(finalized_height_, batch);
    local_vote_locks_.erase(finalized_height_);
    highest_qc_by_height_.erase(finalized_height_);
    highest_qc_payload_by_height_.erase(finalized_height_);
    highest_tc_by_height_.erase(finalized_height_);
  }
  // Epoch-committee closeout only fires at epoch boundaries (not every
  // block) and owns its own checkpoint/telemetry persistence; left on its
  // existing immediate-write path rather than folded into this batch.
  maybe_finalize_epoch_committees_locked();
  persist_availability_state_locked(batch);
  batch.put_node_runtime_status_snapshot(build_runtime_status_snapshot_locked(now_unix() * 1000));

  if (!db_.write_batch(batch)) {
    if (error) *error = "write-batch-commit-failed";
    return false;
  }
  if (error) error->clear();
  return true;
}
bool Node::verify_quorum_certificate_locked(const QuorumCertificate& qc, std::vector<FinalitySig>* filtered,
                                            std::string* error, bool skip_signature_crypto) const {
  const auto committee = committee_for_height_round(qc.height, qc.round);
  if (committee.empty()) {
    if (error) *error = "empty-committee";
    return false;
  }
  const std::size_t quorum = consensus::quorum_threshold(committee.size());
  std::set<PubKey32> committee_set(committee.begin(), committee.end());
  std::set<PubKey32> seen;
  std::vector<FinalitySig> valid;
  valid.reserve(qc.signatures.size());
  const auto msg = vote_signing_message(qc.height, qc.round, qc.frontier_transition_id);
  for (const auto& sig : qc.signatures) {
    if (committee_set.find(sig.validator_pubkey) == committee_set.end()) continue;
    if (!seen.insert(sig.validator_pubkey).second) continue;
    // See the skip_signature_crypto comment on this method's declaration: only safe when
    // qc.signatures is already-verified votes_-sourced data, never for network-supplied QCs.
    if (!skip_signature_crypto && !crypto::ed25519_verify(msg, sig.signature, sig.validator_pubkey)) continue;
    valid.push_back(sig);
  }
  if (valid.size() < quorum) {
    if (error) *error = "insufficient-valid-signatures";
    return false;
  }
  if (filtered) *filtered = std::move(valid);
  return true;
}

bool Node::verify_timeout_certificate_locked(const TimeoutCertificate& tc, std::vector<FinalitySig>* filtered,
                                             std::string* error, bool skip_signature_crypto) const {
  const auto committee = committee_for_height_round(tc.height, tc.round);
  if (committee.empty()) {
    if (error) *error = "empty-committee";
    return false;
  }
  const std::size_t quorum = consensus::quorum_threshold(committee.size());
  std::set<PubKey32> committee_set(committee.begin(), committee.end());
  std::set<PubKey32> seen;
  std::vector<FinalitySig> valid;
  valid.reserve(tc.signatures.size());
  const auto msg = timeout_vote_signing_message(tc.height, tc.round);
  for (const auto& sig : tc.signatures) {
    if (committee_set.find(sig.validator_pubkey) == committee_set.end()) continue;
    if (!seen.insert(sig.validator_pubkey).second) continue;
    // See the skip_signature_crypto comment on this method's declaration: only safe when
    // tc.signatures is already-verified timeout_votes_-sourced data, never for a network-supplied TC.
    if (!skip_signature_crypto && !crypto::ed25519_verify(msg, sig.signature, sig.validator_pubkey)) continue;
    valid.push_back(sig);
  }
  if (valid.size() < quorum) {
    if (error) *error = "insufficient-valid-signatures";
    return false;
  }
  if (filtered) *filtered = std::move(valid);
  return true;
}

bool Node::verify_finality_certificate_for_frontier_locked(const FinalityCertificate& cert,
                                                           const FrontierTransition& transition,
                                                           std::vector<FinalitySig>* canonical_signatures,
                                                           std::string* error) const {
  if (cert.height != transition.height) {
    if (error) *error = "certificate-height-mismatch";
    return false;
  }
  if (cert.round != transition.round) {
    if (error) *error = "certificate-round-mismatch";
    return false;
  }
  const auto transition_id = transition.transition_id();
  if (cert.frontier_transition_id != transition_id) {
    if (error) *error = "certificate-transition-id-mismatch";
    return false;
  }
  if (cert.committee_members.empty()) {
    if (error) *error = "certificate-empty-committee";
    return false;
  }
  const std::size_t expected_quorum = consensus::quorum_threshold(cert.committee_members.size());
  if (cert.quorum_threshold != expected_quorum) {
    if (error) *error = "certificate-quorum-mismatch";
    return false;
  }

  std::set<PubKey32> committee_set(cert.committee_members.begin(), cert.committee_members.end());
  if (committee_set.size() != cert.committee_members.size()) {
    if (error) *error = "certificate-duplicate-committee-members";
    return false;
  }

  std::set<PubKey32> seen;
  std::vector<FinalitySig> valid;
  valid.reserve(cert.signatures.size());
  const auto msg = vote_signing_message(cert.height, cert.round, cert.frontier_transition_id);
  for (const auto& sig : cert.signatures) {
    if (committee_set.find(sig.validator_pubkey) == committee_set.end()) continue;
    if (!seen.insert(sig.validator_pubkey).second) continue;
    if (!crypto::ed25519_verify(msg, sig.signature, sig.validator_pubkey)) continue;
    valid.push_back(sig);
  }
  if (valid.size() < expected_quorum) {
    if (error) *error = "certificate-insufficient-valid-signatures";
    return false;
  }

  const auto canonical = canonicalize_finality_signatures_locked(valid, expected_quorum);
  if (canonical.size() != expected_quorum) {
    if (error) *error = "certificate-canonicalization-failed";
    return false;
  }
  if (canonical_signatures) *canonical_signatures = canonical;
  return true;
}

Node::CertificateCheck Node::precheck_finality_certificate(const FinalityCertificate& cert,
                                                            const FrontierTransition& transition) const {
  // verify_finality_certificate_for_frontier_locked touches only its two parameters --
  // no canonical_state_, no validators_, no committee_for_height_round -- it trusts
  // cert.committee_members (and checks cert.quorum_threshold against it), which is why it
  // is safe to run here, before mu_ is ever locked, despite the "_locked" name it kept for
  // historical reasons. Every handle_frontier_block_locked call site must call this first
  // and pass the result in; see that function's cert_check parameter comment.
  CertificateCheck r;
  r.ok = verify_finality_certificate_for_frontier_locked(cert, transition, &r.canonical_sigs, &r.error);
  return r;
}

std::optional<Hash32> Node::quorum_certificate_payload_id_locked(const QuorumCertificate& qc) const {
  auto it = highest_qc_by_height_.find(qc.height);
  if (it != highest_qc_by_height_.end() && it->second.round == qc.round &&
      it->second.frontier_transition_id == qc.frontier_transition_id) {
    auto pit = highest_qc_payload_by_height_.find(qc.height);
    if (pit != highest_qc_payload_by_height_.end()) return pit->second;
  }
  auto frontier_it = candidate_frontier_proposals_.find(qc.frontier_transition_id);
  if (frontier_it != candidate_frontier_proposals_.end()) return consensus_payload_id(frontier_it->second.transition);
  return std::nullopt;
}

std::optional<QuorumCertificate> Node::highest_qc_for_height_locked(std::uint64_t height) const {
  auto it = highest_qc_by_height_.find(height);
  if (it == highest_qc_by_height_.end()) return std::nullopt;
  return it->second;
}

std::optional<TimeoutCertificate> Node::highest_tc_for_height_locked(std::uint64_t height) const {
  auto it = highest_tc_by_height_.find(height);
  if (it == highest_tc_by_height_.end()) return std::nullopt;
  return it->second;
}

void Node::maybe_record_quorum_certificate_locked(const Hash32& transition_id, std::uint64_t height, std::uint32_t round) {
  QuorumCertificate qc =
      make_quorum_certificate(height, round, transition_id, votes_.signatures_for(height, round, transition_id));
  std::vector<FinalitySig> filtered;
  // qc.signatures == votes_.signatures_for(...) above: every signature already passed
  // crypto::ed25519_verify in handle_vote_result before being accepted into votes_ (see the
  // invariant comment at that call site). Safe to skip the redundant re-verify here --
  // O(k^2) -> O(k) crypto work across a quorum's accumulation. Do not copy this to a call
  // site whose qc came from the network (e.g. ProposeMsg::justify_qc); see
  // verify_quorum_certificate_locked's declaration comment.
  if (!verify_quorum_certificate_locked(qc, &filtered, nullptr, /*skip_signature_crypto=*/true)) return;
  qc.signatures = std::move(filtered);
  auto frontier_it = candidate_frontier_proposals_.find(transition_id);
  if (frontier_it == candidate_frontier_proposals_.end()) return;
  const auto payload_id = consensus_payload_id(frontier_it->second.transition);
  auto it = highest_qc_by_height_.find(height);
  if (it == highest_qc_by_height_.end() || qc.round > it->second.round ||
      (qc.round == it->second.round && qc.frontier_transition_id != it->second.frontier_transition_id)) {
    highest_qc_by_height_[height] = std::move(qc);
    highest_qc_payload_by_height_[height] = payload_id;
    persist_consensus_safety_state_locked(height);
  }
}

void Node::maybe_record_timeout_certificate_locked(std::uint64_t height, std::uint32_t round) {
  TimeoutCertificate tc;
  tc.height = height;
  tc.round = round;
  tc.signatures = timeout_votes_.signatures_for(height, round);
  std::vector<FinalitySig> filtered;
  // Same invariant as maybe_record_quorum_certificate_locked above: tc.signatures ==
  // timeout_votes_.signatures_for(...), already verified at insertion.
  if (!verify_timeout_certificate_locked(tc, &filtered, nullptr, /*skip_signature_crypto=*/true)) return;
  tc.signatures = std::move(filtered);
  auto it = highest_tc_by_height_.find(height);
  if (it == highest_tc_by_height_.end() || tc.round > it->second.round) {
    highest_tc_by_height_[height] = std::move(tc);
    if (height == finalized_height_ + 1 && current_round_ <= round) {
      current_round_ = round + 1;
      round_started_ms_ = now_ms();
      log_line("round-catchup height=" + std::to_string(height) + " old_round=" + std::to_string(round) +
               " new_round=" + std::to_string(current_round_) + " reason=timeout-certificate");
    }
  }
}

void Node::run_confidential_supply_audit_locked(const char* trigger) {
  if (!canonical_state_.has_value()) return;
  last_confidential_supply_audit_ =
      consensus::audit_confidential_supply(canonical_state_->utxos, canonical_state_->confidential_supply,
                                           canonical_state_->confidential_pool_value);
  const auto& r = last_confidential_supply_audit_;
  const std::string line = std::string("confidential-supply-audit status=") +
                           consensus::confidential_supply_audit_status_name(r.status) + " trigger=" + trigger +
                           " height=" + std::to_string(finalized_height_) + " pool_value=" + std::to_string(r.pool_value) +
                           " confidential_utxos=" + std::to_string(r.confidential_utxo_count) +
                           (r.detail.empty() ? std::string() : " detail=" + r.detail);
  if (r.status == consensus::ConfidentialSupplyAuditStatus::Failed) {
    // Possible hidden inflation or corrupted confidential state: operators must investigate.
    log_line("CRITICAL " + line);
    std::cerr << "CRITICAL " << line << "\n";
  } else {
    log_line(line);
  }
}

bool Node::abstaining_at_height_locked(std::uint64_t height) const {
  return abstain_heights_.find(height) != abstain_heights_.end();
}

bool Node::can_vote_for_frontier_locked(const FrontierTransition& transition,
                                        const std::optional<QuorumCertificate>& justify_qc,
                                        const std::optional<TimeoutCertificate>& justify_tc,
                                        std::string* reason) const {
  const auto payload_id = consensus_payload_id(transition);
  const auto height = transition.height;
  const auto round = transition.round;
  // SAFETY: this node's vote history at `height` was lost (unreadable safety state), so any
  // vote here could contradict one already broadcast. Checked before the normal lock rules.
  if (abstaining_at_height_locked(height)) {
    if (reason) *reason = "abstain-corrupt-safety-state";
    return false;
  }
  auto it = local_vote_locks_.find(height);
  if (it == local_vote_locks_.end()) return true;
  const auto& [locked_payload_id, locked_round] = it->second;
  if (payload_id == locked_payload_id) return true;
  if (justify_tc.has_value()) {
    if (reason) *reason = "tc-cannot-unlock";
    return false;
  }
  if (!justify_qc.has_value()) {
    if (reason) *reason = "missing-qc";
    return false;
  }
  std::vector<FinalitySig> filtered;
  std::string qc_error;
  if (!verify_quorum_certificate_locked(*justify_qc, &filtered, &qc_error)) {
    if (reason) *reason = "invalid-qc detail=" + qc_error;
    return false;
  }
  if (justify_qc->height != height) {
    if (reason) *reason = "wrong-qc-height";
    return false;
  }
  if (justify_qc->round >= round) {
    if (reason) *reason = "non-lower-qc-round";
    return false;
  }
  if (justify_qc->round < locked_round) {
    if (reason) *reason = "stale-qc";
    return false;
  }
  auto qc_payload_id = quorum_certificate_payload_id_locked(*justify_qc);
  if (!qc_payload_id.has_value()) {
    if (reason) *reason = "unknown-qc-transition";
    return false;
  }
  if (*qc_payload_id != payload_id) {
    if (reason) *reason = "qc-mismatch";
    return false;
  }
  return true;
}

bool Node::can_accept_frontier_with_lock_locked(const FrontierTransition& transition, std::string* reason) const {
  const auto payload_id = consensus_payload_id(transition);
  auto it = local_vote_locks_.find(transition.height);
  if (it == local_vote_locks_.end()) return true;
  const auto& [locked_payload_id, locked_round] = it->second;
  if (payload_id == locked_payload_id) return true;
  if (transition.round < locked_round) {
    if (reason) *reason = "lock-round-regression";
    return false;
  }
  return false;
}

// Returns false only if the lock changed and could not be made durable.
//
// SAFETY INVARIANT: once this node has signed a vote for payload P at height h, the lock (P, round)
// is durable and is released only when h finalizes (clear_consensus_safety_state_locked from the
// finalization batch). It may move to another payload only through can_vote_for_frontier_locked,
// i.e. a valid QC for that payload from a round in [locked_round, proposal_round). Neither a TC nor
// a restart releases it. The proposal body is persisted alongside so that, after a restart, this
// node can still re-propose P in a TC-driven round instead of deadlocking on a payload it cannot
// reconstruct.
bool Node::update_local_vote_lock_locked(std::uint64_t height, std::uint32_t round, const FrontierProposal& proposal) {
  const auto payload_id = consensus_payload_id(proposal.transition);
  auto it = local_vote_locks_.find(height);
  if (it != local_vote_locks_.end() && it->second.first == payload_id && it->second.second == round) return true;
  if (it == local_vote_locks_.end() || round >= it->second.second) {
    local_vote_locks_[height] = {payload_id, round};
    storage::DB::Batch batch(db_);
    persist_consensus_safety_state_locked(height, batch);
    batch.put(key_consensus_locked_proposal(height), proposal.serialize());
    return db_.write_batch_durable(batch);
  }
  return true;
}

std::vector<FinalitySig> Node::prev_finality_signers_for_next_height_locked() const {
  if (!canonical_state_.has_value()) return {};
  const auto derivation_cfg = canonical_derivation_config_locked();
  consensus::ParentFinalityContext parent;
  std::string err;
  if (!consensus::resolve_parent_finality_context(derivation_cfg, *canonical_state_, {}, &parent, &err) ||
      !parent.has_parent) {
    return {};
  }
  std::map<PubKey32, Sig64> candidates;
  if (finalized_tip_votes_.height == parent.height && finalized_tip_votes_.transition_id == parent.transition_id) {
    candidates = finalized_tip_votes_.sigs;
  }
  // The persisted certificate always holds at least a quorum, which covers a
  // restart or a tip finalized from a delivered certificate.
  if (auto cert = db_.get_finality_certificate_by_height(parent.height);
      cert.has_value() && cert->frontier_transition_id == parent.transition_id) {
    for (const auto& sig : cert->signatures) candidates.emplace(sig.validator_pubkey, sig.signature);
  }
  const std::set<PubKey32> committee(parent.committee.begin(), parent.committee.end());
  const auto msg = vote_signing_message(parent.height, parent.round, parent.transition_id);
  std::vector<FinalitySig> out;
  out.reserve(candidates.size());
  for (const auto& [pub, sig] : candidates) {  // std::map order == pubkey order
    if (committee.count(pub) == 0) continue;
    if (!crypto::ed25519_verify(msg, sig, pub)) continue;
    out.push_back(FinalitySig{pub, sig});
  }
  return out;
}

bool Node::record_late_finalized_vote_locked(const Vote& vote) {
  if (finalized_tip_votes_.height == 0 || vote.height != finalized_tip_votes_.height) return false;
  if (vote.round != finalized_tip_votes_.round || vote.frontier_transition_id != finalized_tip_votes_.transition_id) return false;
  if (finalized_tip_votes_.committee.count(vote.validator_pubkey) == 0) return false;
  if (finalized_tip_votes_.sigs.count(vote.validator_pubkey) != 0) return false;
  const auto msg = vote_signing_message(vote.height, vote.round, vote.frontier_transition_id);
  if (!crypto::ed25519_verify(msg, vote.signature, vote.validator_pubkey)) return false;
  finalized_tip_votes_.sigs.emplace(vote.validator_pubkey, vote.signature);
  return true;
}

void Node::persist_consensus_safety_state_locked(std::uint64_t height, storage::DB::Batch& batch) {
  std::optional<std::pair<Hash32, std::uint32_t>> lock_state;
  if (auto it = local_vote_locks_.find(height); it != local_vote_locks_.end()) lock_state = it->second;
  std::optional<QuorumCertificate> qc_state;
  if (auto it = highest_qc_by_height_.find(height); it != highest_qc_by_height_.end()) qc_state = it->second;
  std::optional<Hash32> qc_payload_id;
  if (auto it = highest_qc_payload_by_height_.find(height); it != highest_qc_payload_by_height_.end()) qc_payload_id = it->second;
  if (!lock_state.has_value() && !qc_state.has_value()) {
    batch.erase(key_consensus_safety_state(height));
    batch.erase(key_consensus_safety_mirror(height));
    return;
  }
  // Primary and mirror go in the same atomic batch; load_state falls back to the mirror when the
  // primary is unreadable and abstains only if both are.
  const Bytes inner = serialize_consensus_safety_state(lock_state, qc_state, qc_payload_id);
  batch.put(key_consensus_safety_state(height), seal_consensus_safety_row(inner, false));
  batch.put(key_consensus_safety_mirror(height), seal_consensus_safety_row(inner, true));
}

// Convenience wrapper for callers outside the batched finalization path
// (round-state cleanup on its own, not alongside a broader commit).
bool Node::persist_consensus_safety_state_locked(std::uint64_t height) {
  storage::DB::Batch batch(db_);
  persist_consensus_safety_state_locked(height, batch);
  return db_.write_batch_durable(batch);
}

// SAFETY: releases the local vote lock at `height`. Only call this for a height that has
// finalized; calling it for an open height lets this node sign a conflicting payload there.
void Node::clear_consensus_safety_state_locked(std::uint64_t height, storage::DB::Batch& batch) {
  local_vote_locks_.erase(height);
  highest_qc_by_height_.erase(height);
  highest_qc_payload_by_height_.erase(height);
  highest_tc_by_height_.erase(height);
  for (auto it = local_timeout_vote_reservations_.begin(); it != local_timeout_vote_reservations_.end();) {
    if (it->first == height) {
      it = local_timeout_vote_reservations_.erase(it);
    } else {
      ++it;
    }
  }
  batch.erase(key_consensus_safety_state(height));
  batch.erase(key_consensus_safety_mirror(height));
  batch.erase(key_consensus_locked_proposal(height));
  // The height is final, so an abstention there has done its job.
  if (abstain_heights_.erase(height) != 0) {
    log_line("consensus-abstain-end height=" + std::to_string(height) + " reason=height-finalized");
  }
  batch.erase(key_consensus_safety_quarantine(height));
}

void Node::clear_consensus_safety_state_locked(std::uint64_t height) {
  storage::DB::Batch batch(db_);
  clear_consensus_safety_state_locked(height, batch);
  (void)db_.write_batch(batch);
}

void Node::on_get_transition(int peer_id, const Bytes& payload) {
  constexpr std::uint16_t msg_type = p2p::MsgType::GET_TRANSITION;
  auto gb = p2p::de_get_transition(payload);
  if (!gb.has_value()) {
    score_peer(peer_id, p2p::MisbehaviorReason::INVALID_PAYLOAD, "bad-get-transition");
    return;
  }
  log_line("recv " + std::string(msg_type_name(msg_type)) + " peer_id=" + std::to_string(peer_id) +
           " hash=" + short_hash_hex(gb->hash));
  auto transition_bytes = db_.get_frontier_transition(gb->hash);
  if (!transition_bytes.has_value()) return;
  auto transition = FrontierTransition::parse(*transition_bytes);
  if (!transition.has_value()) return;
  auto ordered_records = db_.load_ingress_slice(transition->prev_frontier, transition->next_frontier);
  if (ordered_records.size() != transition->next_frontier - transition->prev_frontier) return;
  auto cert = db_.get_finality_certificate_by_height(transition->height);
  if (!cert.has_value()) {
    log_line("send-frontier peer_id=" + std::to_string(peer_id) + " height=" + std::to_string(transition->height) +
             " hash=" + short_hash_hex(gb->hash) + " status=missing-certificate");
    return;
  }
  if (cert->height != transition->height || cert->frontier_transition_id != gb->hash) {
    log_line("send-frontier peer_id=" + std::to_string(peer_id) + " height=" + std::to_string(transition->height) +
             " hash=" + short_hash_hex(gb->hash) + " status=certificate-mismatch");
    return;
  }
  p2p::TransitionMsg msg;
  msg.frontier_proposal_bytes = FrontierProposal{*transition, ordered_records}.serialize();
  msg.certificate = cert;
  const bool ok = p2p_.send_to(peer_id, p2p::MsgType::TRANSITION, p2p::ser_transition(msg), true);
  log_line("send-frontier peer_id=" + std::to_string(peer_id) + " height=" + std::to_string(transition->height) +
           " hash=" + short_hash_hex(gb->hash) + " status=" + (ok ? "ok" : "failed"));
  return;
}

void Node::on_get_transition_by_height(int peer_id, const Bytes& payload) {
  constexpr std::uint16_t msg_type = p2p::MsgType::GET_TRANSITION_BY_HEIGHT;
  constexpr std::uint64_t kGetTransitionByHeightPerPeerHeightMinIntervalMs = 1500;
  constexpr std::uint64_t kGetTransitionByHeightActiveSyncTargetTtlMs = 5 * 60 * 1000;
  constexpr std::uint64_t kGetTransitionByHeightLogCoalesceWindowMs = 30 * 1000;
  constexpr std::uint64_t kGetTransitionByHeightDefaultHistoryWindow = 512;
  auto gbh = p2p::de_get_transition_by_height(payload);
  if (!gbh.has_value()) {
    score_peer(peer_id, p2p::MisbehaviorReason::INVALID_PAYLOAD, "bad-get-transition-by-height");
    return;
  }
  const std::uint64_t tms = now_ms();
  auto log_frontier_by_height = [&](const std::string& status, const std::string& extra = std::string()) {
    std::string suffix;
    bool emit = true;
    {
      std::lock_guard<std::mutex> lk(mu_);
      auto& state = send_frontier_by_height_log_state_[status];
      if (state.first != 0 && tms < state.first + kGetTransitionByHeightLogCoalesceWindowMs) {
        ++state.second;
        emit = false;
      } else {
        if (state.second != 0) suffix = " suppressed=" + std::to_string(state.second);
        state.first = tms;
        state.second = 0;
      }
    }
    if (!emit) return;
    log_line("send-frontier-by-height peer_id=" + std::to_string(peer_id) +
             " requested_height=" + std::to_string(gbh->height) +
             " status=" + status + extra + suffix);
  };
  bool throttled_rate_limit = false;
  {
    std::lock_guard<std::mutex> lk(mu_);
    auto& last_req = get_transition_by_height_last_req_ms_[{peer_id, gbh->height}];
    if (last_req != 0 && tms < last_req + kGetTransitionByHeightPerPeerHeightMinIntervalMs) {
      throttled_rate_limit = true;
    } else {
      last_req = tms;
    }
  }
  if (throttled_rate_limit) {
    log_frontier_by_height("throttled-rate-limit",
                           " detail=per-peer-height-min-interval-ms=" +
                               std::to_string(kGetTransitionByHeightPerPeerHeightMinIntervalMs));
    return;
  }
  log_line("recv " + std::string(msg_type_name(msg_type)) + " peer_id=" + std::to_string(peer_id) +
           " height=" + std::to_string(gbh->height));
  {
    bool allow_historical_replay = false;
    bool active_sync_target = false;
    bool active_validator_peer = false;
    std::uint64_t peer_tip_height = 0;
    {
      std::lock_guard<std::mutex> lk(mu_);
      if (gbh->height + kGetTransitionByHeightDefaultHistoryWindow < finalized_height_) {
        for (const auto& [key, requested_ms] : requested_sync_height_peers_) {
          if (key.second != peer_id) continue;
          if (tms < requested_ms + kGetTransitionByHeightActiveSyncTargetTtlMs) {
            active_sync_target = true;
            break;
          }
        }
        if (auto pit = peer_validator_pubkeys_.find(peer_id); pit != peer_validator_pubkeys_.end()) {
          const auto info = p2p_.get_peer_info(peer_id);
          if (info.established() && validators_.is_active_for_height(pit->second, finalized_height_ + 1)) {
            active_validator_peer = true;
          }
        }
        if (auto tip_it = peer_finalized_tips_.find(peer_id); tip_it != peer_finalized_tips_.end()) {
          peer_tip_height = tip_it->second.height;
        }
        auto& last_h = get_transition_by_height_last_progress_height_[peer_id];
        auto& last_ms = get_transition_by_height_last_progress_ms_[peer_id];
        const bool progressing = gbh->height > last_h;
        if (progressing) {
          last_h = gbh->height;
          last_ms = tms;
        }
        const bool recent_progress = (last_ms != 0 && tms < last_ms + kGetTransitionByHeightActiveSyncTargetTtlMs);
        allow_historical_replay = active_sync_target || active_validator_peer || recent_progress;
      } else {
        allow_historical_replay = true;
        auto& last_h = get_transition_by_height_last_progress_height_[peer_id];
        auto& last_ms = get_transition_by_height_last_progress_ms_[peer_id];
        if (gbh->height > last_h) {
          last_h = gbh->height;
          last_ms = tms;
        }
      }
    }
    if (!allow_historical_replay) {
      log_frontier_by_height("throttled-history-window",
                             " local_height=" + std::to_string(finalized_height_) +
                                 " history_window=" + std::to_string(kGetTransitionByHeightDefaultHistoryWindow) +
                                 " peer_tip_height=" + std::to_string(peer_tip_height) +
                                 " active_sync_target=" + std::string(active_sync_target ? "yes" : "no") +
                                 " active_validator_peer=" + std::string(active_validator_peer ? "yes" : "no"));
      return;
    }
  }
  auto bh = db_.get_height_hash(gbh->height);
  if (!bh.has_value()) {
    log_frontier_by_height("not-found");
    return;
  }
  auto transition_bytes = db_.get_frontier_transition(*bh);
  if (!transition_bytes.has_value()) {
    log_frontier_by_height("missing-bytes", " hash=" + short_hash_hex(*bh));
    return;
  }
  auto transition = FrontierTransition::parse(*transition_bytes);
  if (!transition.has_value()) {
    log_frontier_by_height("parse-error", " hash=" + short_hash_hex(*bh));
    return;
  }
  auto ordered_records = db_.load_ingress_slice(transition->prev_frontier, transition->next_frontier);
  if (ordered_records.size() != transition->next_frontier - transition->prev_frontier) {
    log_frontier_by_height("ingress-slice-mismatch",
                           " hash=" + short_hash_hex(*bh) + " expected=" +
                               std::to_string(transition->next_frontier - transition->prev_frontier) +
                               " got=" + std::to_string(ordered_records.size()));
    return;
  }
  auto cert = db_.get_finality_certificate_by_height(transition->height);
  if (!cert.has_value()) {
    log_frontier_by_height("missing-certificate", " hash=" + short_hash_hex(*bh));
    return;
  }
  if (cert->height != transition->height || cert->frontier_transition_id != *bh) {
    log_frontier_by_height("certificate-mismatch", " hash=" + short_hash_hex(*bh));
    return;
  }
  p2p::TransitionMsg msg;
  msg.frontier_proposal_bytes = FrontierProposal{*transition, ordered_records}.serialize();
  msg.certificate = cert;
  const bool ok = p2p_.send_to(peer_id, p2p::MsgType::TRANSITION, p2p::ser_transition(msg), true);
  log_frontier_by_height(ok ? "ok" : "failed",
                         " hash=" + short_hash_hex(*bh) +
                             " cert_height=" + std::to_string(cert->height));
  return;
}

void Node::on_transition(int peer_id, const Bytes& payload, const Hash32& payload_id) {
  constexpr std::uint16_t msg_type = p2p::MsgType::TRANSITION;
  auto b = p2p::de_transition(payload);
  if (!b.has_value()) {
    log_line("sync-recv-drop peer_id=" + std::to_string(peer_id) +
             " type=TRANSITION reason=decode-failed payload_size=" + std::to_string(payload.size()));
    log_line("sync-recv-drop peer_id=" + std::to_string(peer_id) +
             " type=TRANSITION reason=decode-failed payload_id=" + short_hash_hex(payload_id));
    std::lock_guard<std::mutex> lk(mu_);
    invalid_message_payloads_.insert(payload_id);
    score_peer_locked(peer_id, p2p::MisbehaviorReason::INVALID_PAYLOAD, "bad-block-msg");
    return;
  }
  auto proposal = FrontierProposal::parse(b->frontier_proposal_bytes);
  if (!proposal.has_value()) {
    log_line("sync-recv-drop peer_id=" + std::to_string(peer_id) +
             " type=TRANSITION reason=frontier-parse-failed payload_size=" + std::to_string(payload.size()) +
             " proposal_size=" + std::to_string(b->frontier_proposal_bytes.size()));
    log_line("sync-recv-drop peer_id=" + std::to_string(peer_id) +
             " type=TRANSITION reason=frontier-parse-failed payload_id=" + short_hash_hex(payload_id));
    std::lock_guard<std::mutex> lk(mu_);
    invalid_message_payloads_.insert(payload_id);
    score_peer_locked(peer_id, p2p::MisbehaviorReason::INVALID_PAYLOAD, "bad-frontier-parse");
    return;
  }
  log_line("recv " + std::string(msg_type_name(msg_type)) + " peer_id=" + std::to_string(peer_id) +
           " height=" + std::to_string(proposal->transition.height) + " hash=" +
           short_hash_hex(proposal->transition.transition_id()) + " prev=" +
           short_hash_hex(proposal->transition.prev_finalized_hash));
  // Runs on this peer's own reader thread, before mu_ is ever locked -- the whole point
  // of precheck_finality_certificate is that the ed25519 loop over the committee's
  // signatures (16-24 verifies) happens here, in parallel with every other peer's reader
  // thread, instead of serializing them all behind mu_ inside handle_frontier_block_locked.
  std::optional<CertificateCheck> cert_check;
  if (b->certificate.has_value()) {
    cert_check = precheck_finality_certificate(*b->certificate, proposal->transition);
    if (!cert_check->ok) {
      // SECURITY: an internally inconsistent certificate is never produced by an honest
      // peer; cache and score it so resends cannot burn signature verification for free.
      log_line("sync-recv-drop peer_id=" + std::to_string(peer_id) +
               " type=TRANSITION reason=certificate-precheck-failed error=" + cert_check->error +
               " payload_id=" + short_hash_hex(payload_id));
      std::lock_guard<std::mutex> lk(mu_);
      invalid_message_payloads_.insert(payload_id);
      score_peer_locked(peer_id, p2p::MisbehaviorReason::INVALID_PAYLOAD, "bad-transition-certificate");
      return;
    }
  }
  {
    std::lock_guard<std::mutex> lk(mu_);
    if (proposal->transition.height == finalized_height_ + 1) {
      log_line("sync-recv-next-height peer_id=" + std::to_string(peer_id) +
               " height=" + std::to_string(proposal->transition.height) + " has_cert=" +
               (b->certificate.has_value() ? "yes" : "no"));
    }
  }
  {
    std::lock_guard<std::mutex> lk(mu_);
    const bool duplicate_accepted = accepted_block_payloads_.contains(payload_id);
    const std::uint64_t next_height = finalized_height_ + 1;
    if (duplicate_accepted && proposal->transition.height < next_height) {
      log_line("sync-recv-drop peer_id=" + std::to_string(peer_id) +
               " type=TRANSITION reason=duplicate-accepted payload_id=" + short_hash_hex(payload_id) +
               " height=" + std::to_string(proposal->transition.height) + " next_height=" +
               std::to_string(next_height));
      return;
    }
    if (duplicate_accepted) {
      log_line("sync-recv-duplicate-horizon-bypass peer_id=" + std::to_string(peer_id) +
               " type=TRANSITION payload_id=" + short_hash_hex(payload_id) + " height=" +
               std::to_string(proposal->transition.height) + " next_height=" + std::to_string(next_height));
    }
    bool accepted = false;
    std::string acceptance_path = "none";
    if (!running_) {
      if (b->certificate.has_value() && proposal->transition.height >= finalized_height_ + 1) {
        const auto transition_id = proposal->transition.transition_id();
        accepted = insert_buffered_sync_frontier_locked(*proposal, *b->certificate, peer_id, cert_check);
        if (accepted) {
          acceptance_path = "startup-buffered";
          log_line("startup-sync-defer-transition peer_id=" + std::to_string(peer_id) +
                   " height=" + std::to_string(proposal->transition.height) + " transition=" +
                   short_hash_hex(transition_id));
        }
      } else {
        log_line("startup-sync-drop-transition peer_id=" + std::to_string(peer_id) +
                 " height=" + std::to_string(proposal->transition.height) +
                 " reason=node-not-running");
      }
      if (accepted) accepted_block_payloads_.insert(payload_id);
      if (!accepted) {
        log_line("sync-recv-drop peer_id=" + std::to_string(peer_id) +
                 " type=TRANSITION reason=not-accepted path=startup payload_id=" +
                 short_hash_hex(payload_id) + " height=" + std::to_string(proposal->transition.height));
      }
      return;
    }
    if (proposal->transition.height >= finalized_height_ + 1 && !b->certificate.has_value()) {
      log_line("sync-stall reason=peer-served-uncertified-transition peer_id=" + std::to_string(peer_id) +
               " height=" + std::to_string(proposal->transition.height) + " next_needed=" +
               std::to_string(finalized_height_ + 1) + " transition=" +
               short_hash_hex(proposal->transition.transition_id()));
      acceptance_path = "reject-uncertified";
      score_peer_locked(peer_id, p2p::MisbehaviorReason::INVALID_PAYLOAD, "uncertified-sync-transition");
      requested_sync_height_peers_.erase({proposal->transition.height, peer_id});
      (void)maybe_request_forward_sync_block_locked();
    } else if (proposal->transition.height > finalized_height_ + 1 && b->certificate.has_value()) {
      acceptance_path = "buffer-forward";
      accepted = maybe_buffer_sync_frontier_locked(*proposal, b->certificate, peer_id, cert_check);
      if (accepted) (void)maybe_apply_buffered_sync_frontiers_locked(peer_id);
    } else {
      acceptance_path = "handle-next";
      accepted = handle_frontier_block_locked(*proposal, b->certificate, peer_id, true, cert_check);
      if (accepted) (void)maybe_apply_buffered_sync_frontiers_locked(peer_id);
    }
    if (accepted) accepted_block_payloads_.insert(payload_id);
    if (!accepted) {
      log_line("sync-recv-drop peer_id=" + std::to_string(peer_id) +
               " type=TRANSITION reason=not-accepted path=" + acceptance_path + " payload_id=" +
               short_hash_hex(payload_id) + " height=" + std::to_string(proposal->transition.height) +
               " has_cert=" + (b->certificate.has_value() ? "yes" : "no"));
    }
  }
  return;
}

void Node::on_propose(int peer_id, const Bytes& payload, const Hash32& payload_id) {
  constexpr std::uint16_t msg_type = p2p::MsgType::PROPOSE;
  auto p = p2p::de_propose(payload);
  if (!p.has_value()) {
    std::lock_guard<std::mutex> lk(mu_);
    invalid_message_payloads_.insert(payload_id);
    score_peer_locked(peer_id, p2p::MisbehaviorReason::INVALID_PAYLOAD, "bad-propose-msg");
    return;
  }
  log_line("recv " + std::string(msg_type_name(msg_type)) + " peer_id=" + std::to_string(peer_id) +
           " height=" + std::to_string(p->height) + " round=" + std::to_string(p->round));
  {
    std::lock_guard<std::mutex> lk(mu_);
    if (bootstrap_sync_incomplete_locked(peer_id)) {
      log_line("defer-consensus peer_id=" + std::to_string(peer_id) + " type=PROPOSE reason=bootstrap-sync-incomplete" +
               " local_height=" + std::to_string(finalized_height_));
      return;
    }
  }
  {
    std::lock_guard<std::mutex> lk(mu_);
    if (accepted_propose_payloads_.contains(payload_id)) {
      Hash32 block_id{};
      if (auto proposal = FrontierProposal::parse(p->frontier_proposal_bytes); proposal.has_value()) {
        block_id = proposal->transition.transition_id();
      }
      const std::string result_name = "duplicate";
      log_line("proposal-duplicate-skip peer_id=" + std::to_string(peer_id) +
               " height=" + std::to_string(p->height) + " round=" + std::to_string(p->round) +
               " transition=" + short_hash_hex(block_id) + " payload=" +
               hex_encode(Bytes(payload_id.begin(), payload_id.end())) + " result=" + result_name);
      return;
    }
  }
  const auto propose_result = handle_propose_result(*p, true, peer_id);
  Hash32 block_id{};
  if (auto proposal = FrontierProposal::parse(p->frontier_proposal_bytes); proposal.has_value()) {
    block_id = proposal->transition.transition_id();
  }
  const char* result_name = propose_result == ProposeHandlingResult::Accepted
                                ? "accepted"
                                : (propose_result == ProposeHandlingResult::SoftReject ? "soft-reject" : "hard-reject");
  log_line("proposal-dispatch-result peer_id=" + std::to_string(peer_id) +
           " height=" + std::to_string(p->height) + " round=" + std::to_string(p->round) +
           " transition=" + short_hash_hex(block_id) + " result=" + result_name);
  if (propose_result == ProposeHandlingResult::HardReject) {
    std::lock_guard<std::mutex> lk(mu_);
    invalid_message_payloads_.insert(payload_id);
    score_peer_locked(peer_id, p2p::MisbehaviorReason::INVALID_PROPOSE, "invalid-propose");
  } else if (propose_result == ProposeHandlingResult::Accepted) {
    std::lock_guard<std::mutex> lk(mu_);
    accepted_propose_payloads_.insert(payload_id);
  }
  return;
}

void Node::on_vote(int peer_id, const Bytes& payload, const Hash32& payload_id) {
  constexpr std::uint16_t msg_type = p2p::MsgType::VOTE;
  auto v = p2p::de_vote(payload);
  if (!v.has_value()) {
    std::lock_guard<std::mutex> lk(mu_);
    invalid_message_payloads_.insert(payload_id);
    score_peer_locked(peer_id, p2p::MisbehaviorReason::INVALID_PAYLOAD, "bad-vote-msg");
    return;
  }
  log_line("recv " + std::string(msg_type_name(msg_type)) + " peer_id=" + std::to_string(peer_id) +
           " height=" + std::to_string(v->vote.height) + " round=" + std::to_string(v->vote.round) +
           " transition=" + short_hash_hex(v->vote.frontier_transition_id));
  {
    std::lock_guard<std::mutex> lk(mu_);
    if (bootstrap_sync_incomplete_locked(peer_id)) {
      log_line("defer-consensus peer_id=" + std::to_string(peer_id) + " type=VOTE reason=bootstrap-sync-incomplete" +
               " local_height=" + std::to_string(finalized_height_));
      return;
    }
  }
  const auto vote_result = handle_vote_result(v->vote, true, peer_id);
  if (vote_result == VoteHandlingResult::HardReject) {
    std::lock_guard<std::mutex> lk(mu_);
    invalid_message_payloads_.insert(payload_id);
    score_peer_locked(peer_id, p2p::MisbehaviorReason::INVALID_VOTE_SIGNATURE, "invalid-vote");
  }
  return;
}

void Node::on_timeout_vote(int peer_id, const Bytes& payload, const Hash32& payload_id) {
  constexpr std::uint16_t msg_type = p2p::MsgType::TIMEOUT_VOTE;
  auto v = p2p::de_timeout_vote(payload);
  if (!v.has_value()) {
    std::lock_guard<std::mutex> lk(mu_);
    invalid_message_payloads_.insert(payload_id);
    score_peer_locked(peer_id, p2p::MisbehaviorReason::INVALID_PAYLOAD, "bad-timeout-vote-msg");
    return;
  }
  log_line("recv " + std::string(msg_type_name(msg_type)) + " peer_id=" + std::to_string(peer_id) +
           " height=" + std::to_string(v->vote.height) + " round=" + std::to_string(v->vote.round));
  {
    std::lock_guard<std::mutex> lk(mu_);
    if (bootstrap_sync_incomplete_locked(peer_id)) {
      log_line("defer-consensus peer_id=" + std::to_string(peer_id) +
               " type=TIMEOUT_VOTE reason=bootstrap-sync-incomplete" +
               " local_height=" + std::to_string(finalized_height_));
      return;
    }
  }
  const auto timeout_result = handle_timeout_vote_result(v->vote, true, peer_id);
  if (timeout_result == TimeoutVoteHandlingResult::HardReject) {
    std::lock_guard<std::mutex> lk(mu_);
    invalid_message_payloads_.insert(payload_id);
    score_peer_locked(peer_id, p2p::MisbehaviorReason::INVALID_VOTE_SIGNATURE, "invalid-timeout-vote");
  }
  return;
}

Node::ProposeHandlingResult Node::handle_propose_result(const p2p::ProposeMsg& msg, bool from_network, int from_peer_id,
                                                        std::string* reject_reason) {
  const FinalizedBroadcastFlushGuard flush_guard{this};  // destroyed last, after any mu_ scope
  if (from_network && !running_) return ProposeHandlingResult::SoftReject;
  std::optional<Vote> maybe_vote;
  {
    std::lock_guard<std::mutex> lk(mu_);
    auto set_reject_reason = [&](const std::string& reason) {
      if (reject_reason != nullptr) *reject_reason = reason;
    };
    auto log_propose_soft_reject = [&](const std::string& reason, const std::string& extra = std::string()) {
      set_reject_reason(reason);
      log_line("propose-soft-reject height=" + std::to_string(msg.height) + " round=" + std::to_string(msg.round) +
               " reason=" + reason + extra);
    };
    auto log_propose_hard_reject = [&](const std::string& reason, const std::string& extra = std::string()) {
      set_reject_reason(reason);
      log_line("propose-hard-reject height=" + std::to_string(msg.height) + " round=" + std::to_string(msg.round) +
               " reason=" + reason + extra);
    };
    if (from_network && !running_) return ProposeHandlingResult::SoftReject;
    if (msg.height != finalized_height_ + 1) {
      if (msg.height > finalized_height_ + 1) {
        log_propose_soft_reject("future-height", " local_next=" + std::to_string(finalized_height_ + 1));
        return ProposeHandlingResult::SoftReject;
      }
      log_propose_hard_reject("unexpected-height", " local_next=" + std::to_string(finalized_height_ + 1));
      return ProposeHandlingResult::HardReject;
    }
    const bool allow_late_round0_after_first_timeout =
        from_network && msg.round == 0 && current_round_ == 1 && msg.height == finalized_height_ + 1;
    if (msg.round < current_round_ && !allow_late_round0_after_first_timeout) {
      log_propose_soft_reject("stale-round", " local_round=" + std::to_string(current_round_) +
                                                 " justify=" + justify_summary(msg.justify_qc, msg.justify_tc));
      return ProposeHandlingResult::SoftReject;
    }
    if (msg.prev_finalized_hash != finalized_identity_.id) {
      log_propose_hard_reject("prev-hash-mismatch",
                              " local_transition=" + short_hash_hex(finalized_identity_.id) +
                                  " remote_prev=" + short_hash_hex(msg.prev_finalized_hash));
      return ProposeHandlingResult::HardReject;
    }
    auto proposal = FrontierProposal::parse(msg.frontier_proposal_bytes);
    if (!proposal.has_value()) {
      log_propose_hard_reject("frontier-proposal-parse-failed");
      return ProposeHandlingResult::HardReject;
    }
    const auto& transition = proposal->transition;
    if (transition.height != msg.height || transition.round != msg.round) {
      log_propose_hard_reject("header-mismatch", " transition_height=" + std::to_string(transition.height) +
                                                     " transition_round=" + std::to_string(transition.round));
      return ProposeHandlingResult::HardReject;
    }
    if (transition.prev_finalized_hash != msg.prev_finalized_hash) {
      log_propose_hard_reject("prev-hash-mismatch");
      return ProposeHandlingResult::HardReject;
    }
    if (from_network && from_peer_id > 0 && is_validator_) {
      auto peer_validator_it = peer_validator_pubkeys_.find(from_peer_id);
      if (peer_validator_it == peer_validator_pubkeys_.end()) {
        bool allow_fallback = false;
        std::string fallback_detail = " detail=missing-validator-pubkey";
        const auto info = p2p_.get_peer_info(from_peer_id);
        if (info.established()) {
          if (auto expected_leader = leader_for_height_round(msg.height, msg.round); expected_leader.has_value()) {
            if (transition.leader_pubkey == *expected_leader &&
                validators_.is_active_for_height(*expected_leader, msg.height)) {
              allow_fallback = true;
              fallback_detail = " detail=established-session-leader-fallback validator=" +
                                short_hash_hex(*expected_leader);
            }
          }
        }
        if (!allow_fallback) {
          log_propose_hard_reject("peer-not-active-validator",
                                  " peer_id=" + std::to_string(from_peer_id) + fallback_detail);
          return ProposeHandlingResult::HardReject;
        }
        log_line("propose-peer-validator-fallback peer_id=" + std::to_string(from_peer_id) +
                 " height=" + std::to_string(msg.height) + " round=" + std::to_string(msg.round) + fallback_detail);
      }
      if (peer_validator_it != peer_validator_pubkeys_.end() &&
          !validators_.is_active_for_height(peer_validator_it->second, msg.height)) {
        log_propose_hard_reject("peer-not-active-validator",
                                " peer_id=" + std::to_string(from_peer_id) + " validator=" +
                                    short_hash_hex(peer_validator_it->second) + " height=" + std::to_string(msg.height));
        return ProposeHandlingResult::HardReject;
      }
    }
    const auto transition_id = transition.transition_id();
    const bool local_cached_proposal =
        !from_network && transition.leader_pubkey == local_key_.public_key &&
        candidate_frontier_proposals_.find(transition_id) != candidate_frontier_proposals_.end();

    std::string validation_error;
    if (!local_cached_proposal && !validate_frontier_proposal_locked(*proposal, &validation_error)) {
      std::string extra;
      if (validation_error == "frontier-settlement-commitment-mismatch" && canonical_state_.has_value()) {
        consensus::CanonicalFrontierRecord diag_record{proposal->transition, proposal->ordered_records};
        consensus::FrontierExecutionResult diag_recomputed;
        std::string diag_error;
        std::string diag_details;
        (void)consensus::verify_frontier_record_against_state(canonical_derivation_config_locked(), *canonical_state_,
                                                              diag_record, &diag_recomputed, &diag_error, &diag_details);
        if (!diag_details.empty()) {
          extra = " details=" + diag_details;
        } else if (!diag_error.empty() && diag_error != validation_error) {
          extra = " detail=" + diag_error;
        }
      }
      log_propose_hard_reject(validation_error, extra);
      return ProposeHandlingResult::HardReject;
    }
    if (local_cached_proposal) {
      log_line("proposal-local-validation-skip height=" + std::to_string(msg.height) +
               " round=" + std::to_string(msg.round) + " transition=" + short_hash_hex(transition_id) +
               " reason=locally-built-cached-proposal");
    }
    const auto justify_committee = committee_for_height_round(msg.height, msg.round);
    const bool singleton_fallback_round = msg.round > 0 && justify_committee.size() == 1;
    if (msg.round > 0 && !singleton_fallback_round && !msg.justify_qc.has_value() && !msg.justify_tc.has_value()) {
      log_propose_hard_reject("missing-justify", " local_round=" + std::to_string(current_round_) +
                                                   " justify=" + justify_summary(msg.justify_qc, msg.justify_tc));
      return ProposeHandlingResult::HardReject;
    }
    if (msg.justify_qc.has_value()) {
      std::vector<FinalitySig> filtered_qc;
      std::string qc_error;
      if (!verify_quorum_certificate_locked(*msg.justify_qc, &filtered_qc, &qc_error)) {
        log_propose_hard_reject("invalid-qc", " detail=" + qc_error);
        return ProposeHandlingResult::HardReject;
      }
      if (msg.justify_qc->height != msg.height) {
        log_propose_hard_reject("wrong-qc-height");
        return ProposeHandlingResult::HardReject;
      }
      if (msg.justify_qc->round >= msg.round) {
        log_propose_hard_reject("non-lower-qc-round");
        return ProposeHandlingResult::HardReject;
      }
      auto qc_payload_id = quorum_certificate_payload_id_locked(*msg.justify_qc);
      if (!qc_payload_id.has_value()) {
        log_propose_hard_reject("unknown-qc-transition");
        return ProposeHandlingResult::HardReject;
      }
      if (*qc_payload_id != consensus_payload_id(transition)) {
        log_propose_hard_reject("qc-mismatch");
        return ProposeHandlingResult::HardReject;
      }
    }
    if (msg.justify_tc.has_value()) {
      std::vector<FinalitySig> filtered_tc;
      std::string tc_error;
      if (!verify_timeout_certificate_locked(*msg.justify_tc, &filtered_tc, &tc_error)) {
        log_propose_hard_reject("invalid-tc", " detail=" + tc_error);
        return ProposeHandlingResult::HardReject;
      }
      if (msg.justify_tc->height != msg.height) {
        log_propose_hard_reject("wrong-tc-height");
        return ProposeHandlingResult::HardReject;
      }
      if (msg.justify_tc->round >= msg.round) {
        log_propose_hard_reject("non-lower-tc-round");
        return ProposeHandlingResult::HardReject;
      }
    }
    if (msg.round > current_round_) {
      log_line("round-catchup height=" + std::to_string(msg.height) + " old_round=" + std::to_string(current_round_) +
               " new_round=" + std::to_string(msg.round) +
               " reason=justified-propose justify=" + justify_summary(msg.justify_qc, msg.justify_tc));
      current_round_ = msg.round;
    }

    if (candidate_frontier_proposals_.find(transition_id) == candidate_frontier_proposals_.end()) {
      const std::size_t sz = msg.frontier_proposal_bytes.size();
      std::size_t total = 0;
      for (const auto& [_, s] : candidate_block_sizes_) total += s;
      if (candidate_frontier_proposals_.size() >= kMaxCandidateBlocks || total + sz > kMaxCandidateBlockBytes) {
        log_propose_hard_reject("candidate-cache-full");
        return ProposeHandlingResult::HardReject;
      }
      candidate_block_sizes_[transition_id] = sz;
    }
    candidate_frontier_proposals_[transition_id] = *proposal;
    prune_caches_locked(msg.height, msg.round);
    (void)finalize_if_quorum(transition_id, msg.height, msg.round);
    if (finalized_height_ >= msg.height) {
      // Votes already present (or the quorum-1 self-vote) finalized this proposal; a local
      // vote now would be stale and must not turn a valid proposal into a peer penalty.
      log_line("proposal-local-vote-skip height=" + std::to_string(msg.height) + " round=" + std::to_string(msg.round) +
               " transition=" + short_hash_hex(transition_id) + " reason=already-finalized");
      return ProposeHandlingResult::Accepted;
    }

    std::string vote_reason;
    const auto local_vote_key = std::make_pair(msg.height, msg.round);
    const bool local_is_committee_member = is_committee_member_for(local_key_.public_key, msg.height, msg.round);
    const bool local_vote_reserved = local_vote_reservations_.find(local_vote_key) != local_vote_reservations_.end();
    const bool local_can_vote = local_is_committee_member && !local_vote_reserved &&
                                can_vote_for_frontier_locked(transition, msg.justify_qc, msg.justify_tc, &vote_reason);
    if (local_can_vote) {
      auto sig = crypto::ed25519_sign(vote_signing_message(msg.height, msg.round, transition_id), local_key_.private_key);
      if (!sig.has_value()) {
        log_propose_hard_reject("local-vote-sign-failed");
        return ProposeHandlingResult::HardReject;
      }
      // SAFETY: the lock must be durable before the vote can leave this process.
      // Otherwise a crash after broadcast loses it and, on restart, this node
      // could sign a conflicting payload at the same (height, round).
      if (!update_local_vote_lock_locked(msg.height, msg.round, *proposal)) {
        log_propose_hard_reject("local-vote-lock-persist-failed");
        return ProposeHandlingResult::HardReject;
      }
      local_vote_reservations_.insert(local_vote_key);
      log_line("local-vote-emit height=" + std::to_string(msg.height) + " round=" + std::to_string(msg.round) +
               " transition=" + short_hash_hex(transition_id) + " current_round=" + std::to_string(current_round_) +
               " committee_member=yes");
      maybe_vote = Vote{msg.height, msg.round, transition_id, local_key_.public_key, *sig};
    } else {
      if (!local_is_committee_member) vote_reason = "not-committee-member";
      else if (local_vote_reserved) vote_reason = "vote-already-reserved";
      else if (vote_reason.empty()) vote_reason = "not-votable";
      log_line("proposal-local-vote-skip height=" + std::to_string(msg.height) + " round=" + std::to_string(msg.round) +
               " transition=" + short_hash_hex(transition_id) + " current_round=" + std::to_string(current_round_) +
               " committee_member=" + std::string(local_is_committee_member ? "yes" : "no") +
               " reserved=" + std::string(local_vote_reserved ? "yes" : "no") + " reason=" + vote_reason);
    }
  }

propose_done:

  if (maybe_vote.has_value()) {
    broadcast_vote(*maybe_vote);
    const bool ok = handle_vote(*maybe_vote, false, 0);
    {
      std::lock_guard<std::mutex> lk(mu_);
      local_vote_reservations_.erase(std::make_pair(maybe_vote->height, maybe_vote->round));
    }
    return ok ? ProposeHandlingResult::Accepted : ProposeHandlingResult::HardReject;
  }
  return ProposeHandlingResult::Accepted;
}

bool Node::handle_propose(const p2p::ProposeMsg& msg, bool from_network) {
  return handle_propose_result(msg, from_network, 0, nullptr) == ProposeHandlingResult::Accepted;
}

Node::VoteHandlingResult Node::handle_vote_result(const Vote& vote, bool from_network, int from_peer_id,
                                                  std::string* reject_reason) {
  const FinalizedBroadcastFlushGuard flush_guard{this};  // destroyed last, after any mu_ scope
  if (from_network && !running_) {
    if (reject_reason) *reject_reason = "not-running";
    return VoteHandlingResult::SoftReject;
  }
  bool relay_vote = false;
  bool finalize_ok = false;
  bool accepted = false;
  {
    std::lock_guard<std::mutex> lk(mu_);
    auto log_vote_soft_reject = [&](const std::string& reason, const std::string& extra = std::string()) {
      log_line("vote-soft-reject height=" + std::to_string(vote.height) + " round=" + std::to_string(vote.round) +
               " reason=" + reason + extra);
    };
    auto log_vote_hard_reject = [&](const std::string& reason, const std::string& extra = std::string()) {
      log_line("vote-hard-reject height=" + std::to_string(vote.height) + " round=" + std::to_string(vote.round) +
               " reason=" + reason + extra);
    };
    if (from_network && !running_) {
      if (reject_reason) *reject_reason = "not-running";
      return VoteHandlingResult::SoftReject;
    }
    if (vote.height != finalized_height_ + 1) {
      if (vote.height == finalized_height_ && record_late_finalized_vote_locked(vote)) {
        // A vote for the finalized tip that arrived after quorum still counts as
        // participation; the next proposer records it in prev_finality_signers.
        if (reject_reason) *reject_reason = "late-finalized-vote-recorded";
        return VoteHandlingResult::SoftReject;
      }
      if (vote.height <= finalized_height_) {
        // Late duplicate votes are expected under broadcast races once a block is finalized.
        // Ignore them without peer penalty, but keep a precise operator-visible reason.
        log_vote_soft_reject("stale-finalized-height", " local_finalized=" + std::to_string(finalized_height_));
        if (reject_reason) *reject_reason = "stale-finalized-height";
        return VoteHandlingResult::SoftReject;
      } else {
        log_vote_soft_reject("future-height", " local_next=" + std::to_string(finalized_height_ + 1));
        if (reject_reason) *reject_reason = "future-height";
        return VoteHandlingResult::SoftReject;
      }
    }
    if (vote.round > current_round_) {
      log_vote_soft_reject("future-round", " local_round=" + std::to_string(current_round_));
      if (reject_reason) *reject_reason = "future-round";
      return VoteHandlingResult::SoftReject;
    }
    if (!is_committee_member_for(vote.validator_pubkey, vote.height, vote.round)) {
      log_vote_hard_reject("non-member", " validator=" + short_pub_hex(vote.validator_pubkey));
      if (reject_reason) *reject_reason = "non-member";
      return VoteHandlingResult::HardReject;
    }

    const auto nowm = now_ms();
    auto& verify_bucket = vote_verify_buckets_[from_peer_id];
    verify_bucket.configure(cfg_.vote_verify_capacity, cfg_.vote_verify_refill);
    if (from_network && !verify_bucket.consume(1.0, nowm)) {
      log_vote_soft_reject("rate-limited", " peer_id=" + std::to_string(from_peer_id));
      if (reject_reason) *reject_reason = "rate-limited";
      return VoteHandlingResult::SoftReject;
    }

    const p2p::VoteVerifyCache::Key vkey{vote.height, vote.round, vote.frontier_transition_id, vote.validator_pubkey};
    if (invalid_vote_verify_cache_.contains(vkey)) {
      log_vote_hard_reject("cached-invalid-signature", " validator=" + short_pub_hex(vote.validator_pubkey));
      if (reject_reason) *reject_reason = "cached-invalid-signature";
      return VoteHandlingResult::HardReject;
    }
    if (!vote_verify_cache_.contains(vkey)) {
      const auto msg = vote_signing_message(vote.height, vote.round, vote.frontier_transition_id);
      if (!crypto::ed25519_verify(msg, vote.signature, vote.validator_pubkey)) {
        log_vote_hard_reject("invalid-signature", " validator=" + short_pub_hex(vote.validator_pubkey));
        invalid_vote_verify_cache_.insert(vkey);
        if (reject_reason) *reject_reason = "invalid-signature";
        return VoteHandlingResult::HardReject;
      }
      vote_verify_cache_.insert(vkey);
    }

    if (locally_observed_equivocators_.find(vote.validator_pubkey) != locally_observed_equivocators_.end()) {
      log_vote_hard_reject("known-equivocator", " validator=" + short_pub_hex(vote.validator_pubkey));
      if (reject_reason) *reject_reason = "known-equivocator";
      return VoteHandlingResult::HardReject;
    }

    // INVARIANT: this is the only place (besides the local self-vote in finalize_if_quorum)
    // that inserts into votes_. Every signature reaching this point has just passed
    // crypto::ed25519_verify above (or was already cached as valid). Code elsewhere
    // (verify_quorum_certificate_locked's skip_signature_crypto path,
    // finalize_if_quorum's committee filter) relies on that being true for everything
    // votes_.signatures_for(...) returns. If you add another insertion path into votes_,
    // verify the signature first or that trust breaks silently.
    auto tr = votes_.add_vote(vote);
    if (tr.equivocation && tr.evidence.has_value()) {
      locally_observed_equivocators_.insert(vote.validator_pubkey);
      (void)db_.put_slashing_record(make_vote_equivocation_record(*tr.evidence, finalized_height_));
      log_line("equivocation-observed validator=" +
               hex_encode(Bytes(vote.validator_pubkey.begin(), vote.validator_pubkey.end())) +
               " height=" + std::to_string(vote.height) + " round=" + std::to_string(vote.round));
    }

    if (!tr.accepted) {
      if (!tr.duplicate) {
        log_vote_hard_reject("tracker-rejected", " transition=" + short_hash_hex(vote.frontier_transition_id) +
                                                    " validator=" + short_pub_hex(vote.validator_pubkey));
        if (reject_reason) *reject_reason = "tracker-rejected";
        return VoteHandlingResult::HardReject;
      }
      log_vote_soft_reject("duplicate", " transition=" + short_hash_hex(vote.frontier_transition_id) +
                                           " validator=" + short_pub_hex(vote.validator_pubkey) +
                                           " peer_id=" + std::to_string(from_peer_id));
      if (reject_reason) *reject_reason = "duplicate";
      return VoteHandlingResult::SoftReject;
    }
    accepted = true;

    if (vote.validator_pubkey == local_key_.public_key) {
      auto frontier_it = candidate_frontier_proposals_.find(vote.frontier_transition_id);
      if (frontier_it != candidate_frontier_proposals_.end()) {
        update_local_vote_lock_locked(vote.height, vote.round, frontier_it->second);
      }
    }
    relay_vote = from_network && !should_mute_peer_locked(from_peer_id);
    if (candidate_frontier_proposals_.find(vote.frontier_transition_id) == candidate_frontier_proposals_.end()) {
      (void)maybe_request_candidate_transition_locked(from_peer_id, vote.frontier_transition_id);
    }
    maybe_record_quorum_certificate_locked(vote.frontier_transition_id, vote.height, vote.round);
    finalize_ok = finalize_if_quorum(vote.frontier_transition_id, vote.height, vote.round);
    if (!finalize_ok) {
      log_line("vote-accepted-waiting height=" + std::to_string(vote.height) + " round=" + std::to_string(vote.round) +
               " transition=" + short_hash_hex(vote.frontier_transition_id) +
               " validator=" + short_pub_hex(vote.validator_pubkey));
    }
  }

  if (relay_vote) broadcast_vote(vote);
  // A valid vote may arrive before the candidate block body. That is an accepted
  // network message and should not be treated as peer misbehavior just because
  // finalization must wait for block fetch/reassembly.
  return accepted ? VoteHandlingResult::Accepted : VoteHandlingResult::SoftReject;
}

bool Node::handle_vote(const Vote& vote, bool from_network, int from_peer_id) {
  return handle_vote_result(vote, from_network, from_peer_id) == VoteHandlingResult::Accepted;
}

Node::TimeoutVoteHandlingResult Node::handle_timeout_vote_result(const TimeoutVote& vote, bool from_network, int from_peer_id) {
  if (from_network && !running_) return TimeoutVoteHandlingResult::SoftReject;
  bool relay_vote = false;
  bool accepted = false;
  {
    std::lock_guard<std::mutex> lk(mu_);
    const auto now_ms = this->now_ms();
    auto log_timeout_soft_reject = [&](const std::string& reason, const std::string& extra = std::string()) {
      if (reason == "duplicate") {
        const auto key = std::make_tuple(vote.height, vote.round, vote.validator_pubkey, reason);
        auto it = timeout_vote_soft_reject_log_counts_.find(key);
        if (it == timeout_vote_soft_reject_log_counts_.end()) {
          timeout_vote_soft_reject_log_counts_.emplace(key, 1);
        } else {
          ++it->second;
          if ((it->second % kTimeoutVoteDuplicateLogEvery) != 0) return;
        }
      }
      log_line("timeout-vote-soft-reject height=" + std::to_string(vote.height) + " round=" + std::to_string(vote.round) +
               " reason=" + reason + extra);
    };
    auto log_timeout_hard_reject = [&](const std::string& reason, const std::string& extra = std::string()) {
      log_line("timeout-vote-hard-reject height=" + std::to_string(vote.height) + " round=" + std::to_string(vote.round) +
               " reason=" + reason + extra);
    };
    if (vote.height != finalized_height_ + 1) {
      if (vote.height <= finalized_height_) {
        log_timeout_soft_reject("stale-finalized-height", " local_finalized=" + std::to_string(finalized_height_));
      } else {
        log_timeout_soft_reject("future-height", " local_next=" + std::to_string(finalized_height_ + 1));
      }
      return TimeoutVoteHandlingResult::SoftReject;
    }
    if (vote.round > current_round_ + kProposalRoundWindow) {
      log_timeout_soft_reject("future-round",
                              " local_round=" + std::to_string(current_round_) +
                                  " validator=" + short_pub_hex(vote.validator_pubkey));
      return TimeoutVoteHandlingResult::SoftReject;
    }
    if (!is_committee_member_for(vote.validator_pubkey, vote.height, vote.round)) {
      log_timeout_hard_reject("non-member", " validator=" + short_pub_hex(vote.validator_pubkey));
      return TimeoutVoteHandlingResult::HardReject;
    }
    const auto msg = timeout_vote_signing_message(vote.height, vote.round);
    if (!crypto::ed25519_verify(msg, vote.signature, vote.validator_pubkey)) {
      log_timeout_hard_reject("invalid-signature", " validator=" + short_pub_hex(vote.validator_pubkey));
      return TimeoutVoteHandlingResult::HardReject;
    }
    if (from_network) {
      const auto dedup_key = std::make_tuple(vote.height, vote.round, vote.validator_pubkey, vote.signature);
      auto dedup_it = seen_timeout_vote_messages_ms_.find(dedup_key);
      if (dedup_it != seen_timeout_vote_messages_ms_.end()) {
        const bool fresh = now_ms <= dedup_it->second + kTimeoutVoteMessageDedupTtlMs;
        dedup_it->second = now_ms;
        if (fresh) {
          log_timeout_soft_reject("duplicate", " validator=" + short_pub_hex(vote.validator_pubkey));
          return TimeoutVoteHandlingResult::SoftReject;
        }
      } else {
        seen_timeout_vote_messages_ms_.emplace(dedup_key, now_ms);
      }
    }
    // Conservative liveness catchup: allow a bounded round jump from a valid
    // higher-round timeout vote when this node is visibly stalled at the same height.
    const std::uint64_t stall_ms = cfg_.network.round_timeout_ms * 2ULL;
    const bool consensus_stalled = now_ms > last_finalized_progress_ms_ + stall_ms;
    if (from_network && !repair_mode_ && !pause_proposals_.load() && vote.height == finalized_height_ + 1 &&
        vote.round > current_round_ && vote.round <= current_round_ + kProposalRoundWindow &&
        consensus_stalled) {
      const auto old_round = current_round_;
      current_round_ = vote.round;
      round_started_ms_ = now_ms;
      const auto leader = leader_for_height_round(vote.height, current_round_);
      log_line("round-catchup height=" + std::to_string(vote.height) + " old_round=" + std::to_string(old_round) +
               " new_round=" + std::to_string(current_round_) +
               " reason=observed-timeout-vote leader=" +
               (leader.has_value() ? short_pub_hex(*leader) : std::string("none")) +
               " validator=" + short_pub_hex(vote.validator_pubkey));
    }
    // INVARIANT: see the matching comment at votes_.add_vote in handle_vote_result.
    // Everything reaching timeout_votes_.add_vote here has already passed
    // crypto::ed25519_verify above; verify_timeout_certificate_locked's
    // skip_signature_crypto path depends on that staying true.
    const auto tr = timeout_votes_.add_vote(vote);
    if (!tr.accepted) {
      if (tr.stale) {
        log_timeout_soft_reject("stale-round-outside-window", " validator=" + short_pub_hex(vote.validator_pubkey));
        return TimeoutVoteHandlingResult::SoftReject;
      }
      if (!tr.duplicate) {
        log_timeout_hard_reject("tracker-rejected");
        return TimeoutVoteHandlingResult::HardReject;
      }
      log_timeout_soft_reject("duplicate", " validator=" + short_pub_hex(vote.validator_pubkey));
      return TimeoutVoteHandlingResult::SoftReject;
    }
    if (tr.evicted_round.has_value()) {
      log_line("timeout-window-evict height=" + std::to_string(vote.height) +
               " evicted_round=" + std::to_string(*tr.evicted_round) + " new_round=" + std::to_string(vote.round));
    }
    accepted = true;
    relay_vote = from_network && !should_mute_peer_locked(from_peer_id);
    maybe_record_timeout_certificate_locked(vote.height, vote.round);
  }
  if (relay_vote) broadcast_timeout_vote(vote);
  return accepted ? TimeoutVoteHandlingResult::Accepted : TimeoutVoteHandlingResult::SoftReject;
}

bool Node::handle_timeout_vote(const TimeoutVote& vote, bool from_network, int from_peer_id) {
  return handle_timeout_vote_result(vote, from_network, from_peer_id) == TimeoutVoteHandlingResult::Accepted;
}

bool Node::handle_frontier_block_locked(const FrontierProposal& proposal,
                                        const std::optional<FinalityCertificate>& certificate, int from_peer_id,
                                        bool from_network, const std::optional<CertificateCheck>& cert_check) {
  auto log_reject = [&](const std::string& reason, const std::string& extra = std::string()) {
    log_line("frontier-block-reject height=" + std::to_string(proposal.transition.height) + " round=" +
             std::to_string(proposal.transition.round) + " transition=" +
             short_hash_hex(proposal.transition.transition_id()) + " reason=" + reason + extra);
  };
  auto clear_sync_request_for_height = [&](std::uint64_t height) {
    requested_sync_heights_.erase(height);
    for (auto it = requested_sync_height_peers_.begin(); it != requested_sync_height_peers_.end();) {
      if (it->first.first == height) {
        it = requested_sync_height_peers_.erase(it);
      } else {
        ++it;
      }
    }
  };
  const auto& transition = proposal.transition;
  const auto transition_id = transition.transition_id();
  if (!running_ && from_network) {
    if (certificate.has_value() && transition.height >= finalized_height_ + 1) {
      const bool buffered = maybe_buffer_sync_frontier_locked(proposal, certificate, from_peer_id, cert_check);
      if (buffered) {
        log_line("startup-sync-defer-transition path=handle_frontier_block_locked peer_id=" + std::to_string(from_peer_id) +
                 " height=" + std::to_string(transition.height) + " transition=" + short_hash_hex(transition_id));
      } else {
        log_reject("node-not-running-buffer-failed");
      }
      return buffered;
    }
    log_reject("node-not-running");
    return false;
  }
  if (!finalized_identity_valid_for_frontier_runtime(finalized_height_, finalized_identity_)) {
    log_reject("invalid-finalized-identity");
    return false;
  }
  requested_sync_artifacts_.erase(transition_id);
  // Frontier runtime accepts either a transition parent or the explicit
  // genesis block handoff at height 0, so the parent link intentionally uses
  // the raw finalized identity value here.
  if (transition.height <= finalized_height_) {
    const bool is_current_tip = transition.height == finalized_height_ && transition_id == finalized_identity_.id;
    if (is_current_tip) clear_sync_request_for_height(transition.height);
    if (!is_current_tip) {
      log_reject("stale-or-mismatch-height",
                 " local_height=" + std::to_string(finalized_height_) +
                     " local_transition=" + short_hash_hex(finalized_identity_.id));
    }
    return is_current_tip;
  }
  if (transition.height > finalized_height_ + 1 || transition.prev_finalized_hash != finalized_identity_.id) {
    log_reject("noncontiguous-or-prev-mismatch",
               " local_next=" + std::to_string(finalized_height_ + 1) +
                   " local_prev=" + short_hash_hex(finalized_identity_.id) +
                   " remote_prev=" + short_hash_hex(transition.prev_finalized_hash));
    return false;
  }
  if (canonical_state_.has_value()) (void)ensure_settlement_onboarding_scores_loaded_locked(transition.height);
  if (certificate.has_value()) {
    if (!canonical_state_.has_value()) {
      log_line("frontier-block-reject height=" + std::to_string(transition.height) + " round=" +
               std::to_string(transition.round) + " transition=" + short_hash_hex(transition_id) +
               " reason=missing-canonical-state");
      return false;
    }
    // Certificate signatures are verified by the caller via precheck_finality_certificate,
    // BEFORE mu_ was locked -- this function never runs the crypto itself anymore. A missing
    // cert_check here is a caller bug (every handle_frontier_block_locked call site must
    // precheck first), not a valid "retry under lock" state.
    if (!cert_check.has_value()) {
      log_line("frontier-block-reject height=" + std::to_string(transition.height) + " round=" +
               std::to_string(transition.round) + " transition=" + short_hash_hex(transition_id) +
               " reason=missing-certificate-precheck");
      return false;
    }
    if (!cert_check->ok) {
      log_line("frontier-block-reject height=" + std::to_string(transition.height) + " round=" +
               std::to_string(transition.round) + " transition=" + short_hash_hex(transition_id) +
               " reason=" + cert_check->error);
      if (from_network) {
        log_line("sync-stall reason=certificate-verification-failed peer_id=" + std::to_string(from_peer_id) +
                 " height=" + std::to_string(transition.height) + " transition=" + short_hash_hex(transition_id) +
                 " cert_reason=" + cert_check->error);
      }
      return false;
    }
    const auto& canonical_sigs = cert_check->canonical_sigs;
    consensus::CanonicalFrontierRecord certified_record{transition, proposal.ordered_records};
    consensus::FrontierExecutionResult recomputed;
    std::string validation_error;
    std::string validation_diagnostics;
    // Settlement is valid only if it matches canonical derivation from canonical
    // state. No node-local reward state may substitute for it.
    if (!consensus::verify_frontier_record_against_state(canonical_derivation_config_locked(), *canonical_state_,
                                                         certified_record, &recomputed, &validation_error,
                                                         &validation_diagnostics)) {
      last_test_hook_error_ = "frontier-verify-reject:" + validation_error;
      if (!validation_diagnostics.empty()) {
        last_test_hook_error_ += " details=" + validation_diagnostics;
      }
      log_line("frontier-block-reject height=" + std::to_string(transition.height) + " round=" +
               std::to_string(transition.round) + " transition=" + short_hash_hex(transition_id) +
               " reason=" + validation_error);
      if (!validation_diagnostics.empty()) {
        log_line("frontier-block-reject-diagnostics height=" + std::to_string(transition.height) +
                 " round=" + std::to_string(transition.round) + " transition=" + short_hash_hex(transition_id) +
                 " details=" + validation_diagnostics);
      }
      return false;
    }
    std::vector<PubKey32> expected_committee = recomputed.effective_committee;
    std::size_t expected_quorum = consensus::quorum_threshold(expected_committee.size());
    if (certificate->committee_members != expected_committee || certificate->quorum_threshold != expected_quorum) {
      log_line("frontier-block-reject height=" + std::to_string(transition.height) + " round=" +
               std::to_string(transition.round) + " transition=" + short_hash_hex(transition_id) +
               " reason=certificate-committee-mismatch");
      return false;
    }
    std::string apply_error;
    if (!apply_finalized_frontier_effects_locked(certified_record, canonical_sigs, true, &expected_committee,
                                                 &apply_error)) {
      log_reject("apply-finalized-frontier-effects-failed",
                 apply_error.empty() ? std::string() : " detail=" + apply_error);
      return false;
    }
    clear_sync_request_for_height(transition.height);
    pending_finalized_tip_broadcast_ = true;  // mu_ is held; sent by flush_pending_finalized_broadcasts()
    if (from_peer_id != 0) (void)maybe_request_forward_sync_block_locked(from_peer_id);
    return true;
  }
  if (from_network && transition.height == finalized_height_ + 1) {
    log_reject("missing-certificate-for-next-height");
    return false;
  }

  std::string validation_error;
  if (!validate_frontier_proposal_locked(proposal, &validation_error)) {
    log_line("frontier-block-reject height=" + std::to_string(transition.height) + " round=" +
             std::to_string(transition.round) + " transition=" + short_hash_hex(transition_id) +
             " reason=" + validation_error);
    if (from_network && !certificate.has_value()) {
      log_line("sync-stall reason=uncertified-transition-invalid peer_id=" + std::to_string(from_peer_id) +
               " height=" + std::to_string(transition.height) + " transition=" + short_hash_hex(transition_id) +
               " validation_reason=" + validation_error);
    }
    return false;
  }
  std::string lock_error;
  if (!can_accept_frontier_with_lock_locked(transition, &lock_error)) {
    log_line("frontier-block-reject height=" + std::to_string(transition.height) + " round=" +
             std::to_string(transition.round) + " transition=" + short_hash_hex(transition_id) +
             " reason=" + lock_error);
    return false;
  }
  candidate_frontier_proposals_[transition_id] = proposal;
  candidate_block_sizes_[transition_id] = proposal.serialize().size();
  clear_sync_request_for_height(transition.height);

  (void)finalize_if_quorum(transition_id, transition.height, transition.round);
  return true;
}

bool Node::maybe_buffer_sync_frontier_locked(const FrontierProposal& proposal,
                                             const std::optional<FinalityCertificate>& certificate, int from_peer_id,
                                             const std::optional<CertificateCheck>& cert_check) {
  if (!certificate.has_value()) {
    if (proposal.transition.height > finalized_height_ + 1) {
      log_line("sync-stall reason=missing-certificate-for-future-height peer_id=" + std::to_string(from_peer_id) +
               " height=" + std::to_string(proposal.transition.height) + " next_needed=" +
               std::to_string(finalized_height_ + 1) + " transition=" +
               short_hash_hex(proposal.transition.transition_id()));
    }
    return false;
  }
  const auto& transition = proposal.transition;
  const auto transition_id = transition.transition_id();
  if (transition.height <= finalized_height_) {
    return transition.height == finalized_height_ && transition_id == finalized_identity_.id;
  }
  if (transition.height == finalized_height_ + 1) return false;
  if (auto existing = db_.get_height_hash(transition.height); existing.has_value()) return *existing == transition_id;
  return insert_buffered_sync_frontier_locked(proposal, *certificate, from_peer_id, cert_check);
}

bool Node::insert_buffered_sync_frontier_locked(const FrontierProposal& proposal, const FinalityCertificate& certificate,
                                                int from_peer_id, const std::optional<CertificateCheck>& cert_check) {
  const auto& transition = proposal.transition;
  const auto transition_id = transition.transition_id();
  auto reject = [&](const std::string& reason) {
    log_line("buffer-sync-reject peer_id=" + std::to_string(from_peer_id) + " height=" +
             std::to_string(transition.height) + " hash=" + short_hash_hex(transition_id) + " reason=" + reason);
    return false;
  };
  if (!cert_check.has_value() || !cert_check->ok) return reject("certificate-precheck-failed");
  if (transition.height <= finalized_height_) return reject("stale-height");
  if (transition.height > finalized_height_ + kMaxBufferedSyncAhead) return reject("beyond-buffer-window");

  std::size_t bytes = sizeof(BufferedSyncFrontier);
  for (const auto& rec : proposal.ordered_records) bytes += rec.size();

  auto it = buffered_sync_frontiers_.find(transition.height);
  if (it != buffered_sync_frontiers_.end()) {
    for (auto& candidate : it->second) {
      if (candidate.proposal.transition.transition_id() == transition_id) {
        if (candidate.from_peer_id == 0) candidate.from_peer_id = from_peer_id;
        return true;
      }
    }
    for (const auto& candidate : it->second) {
      if (from_peer_id != 0 && candidate.from_peer_id == from_peer_id) return reject("peer-already-buffered-height");
    }
    if (it->second.size() >= kMaxBufferedSyncCandidatesPerHeight) return reject("height-candidates-full");
    log_line("buffer-sync-conflict height=" + std::to_string(transition.height) + " existing=" +
             short_hash_hex(it->second.front().proposal.transition.transition_id()) + " incoming=" +
             short_hash_hex(transition_id));
  }
  if (buffered_sync_bytes_ + bytes > kMaxBufferedSyncBytes) return reject("buffer-bytes-full");

  buffered_sync_frontiers_[transition.height].push_back(
      BufferedSyncFrontier{proposal, certificate, from_peer_id, bytes});
  buffered_sync_bytes_ += bytes;
  log_line("buffer-sync-transition peer_id=" + std::to_string(from_peer_id) + " height=" +
           std::to_string(transition.height) + " hash=" + short_hash_hex(transition_id) + " prev=" +
           short_hash_hex(transition.prev_finalized_hash));
  return true;
}

bool Node::maybe_apply_buffered_sync_frontiers_locked(int preferred_peer_id) {
  bool advanced = false;
  // Drop candidates that finalized through another path.
  while (!buffered_sync_frontiers_.empty() && buffered_sync_frontiers_.begin()->first <= finalized_height_) {
    for (const auto& c : buffered_sync_frontiers_.begin()->second) buffered_sync_bytes_ -= c.bytes;
    buffered_sync_frontiers_.erase(buffered_sync_frontiers_.begin());
  }
  while (true) {
    auto it = buffered_sync_frontiers_.find(finalized_height_ + 1);
    if (it == buffered_sync_frontiers_.end()) break;
    std::vector<BufferedSyncFrontier> candidates = std::move(it->second);
    buffered_sync_frontiers_.erase(it);
    for (const auto& c : candidates) buffered_sync_bytes_ -= c.bytes;
    const auto expected_height = finalized_height_ + 1;
    bool applied = false;
    for (const auto& buffered : candidates) {
      // Unlike the live TRANSITION path in handle_message, `buffered.certificate` only
      // becomes known after the locked buffered_sync_frontiers_ lookup above, so this precheck
      // can't be hoisted before mu_ here -- this is the startup/catch-up replay path, not the
      // steady-state hot path precheck_finality_certificate is optimizing for. Still correct
      // (same pure, stateless check), just not off the lock in this call path.
      std::optional<CertificateCheck> cert_check;
      if (buffered.certificate.has_value()) {
        cert_check = precheck_finality_certificate(*buffered.certificate, buffered.proposal.transition);
      }
      const int source_peer = buffered.from_peer_id != 0 ? buffered.from_peer_id : preferred_peer_id;
      if (handle_frontier_block_locked(buffered.proposal, buffered.certificate, source_peer, true, cert_check)) {
        applied = true;
        break;
      }
      log_line("buffer-sync-apply-failed height=" + std::to_string(expected_height) + " hash=" +
               short_hash_hex(buffered.proposal.transition.transition_id()));
      // A finalized transition that fails full validation at its own height was forged.
      if (buffered.from_peer_id != 0 && running_) {
        score_peer_locked(buffered.from_peer_id, p2p::MisbehaviorReason::INVALID_PAYLOAD, "buffered-transition-invalid");
      }
    }
    if (!applied) {
      log_line("sync-stall reason=buffered-transition-apply-failed peer_id=" + std::to_string(preferred_peer_id) +
               " height=" + std::to_string(expected_height) + " candidates=" + std::to_string(candidates.size()));
      break;
    }
    advanced = true;
  }
  return advanced;
}

bool Node::validate_frontier_proposal_locked(const FrontierProposal& proposal, std::string* error) const {
  if (!canonical_state_.has_value()) {
    if (error) *error = "missing-canonical-state";
    return false;
  }
  if (!finalized_identity_valid_for_frontier_runtime(finalized_height_, finalized_identity_)) {
    if (error) *error = "frontier-parent-identity-kind-mismatch";
    return false;
  }
  const auto& transition = proposal.transition;
  const auto finalized_transition_id = finalized_identity_.id;
  if (transition.height != finalized_height_ + 1) {
    if (error) *error = "frontier-height-mismatch";
    return false;
  }
  if (transition.prev_finalized_hash != finalized_transition_id) {
    if (error) *error = "frontier-prev-finalized-hash-mismatch";
    return false;
  }
  for (std::size_t i = 0; i < proposal.ordered_records.size(); ++i) {
    std::string ordered_record_error;
    if (!inspect_frontier_ordered_record_supported(proposal.ordered_records[i], i, nullptr, &ordered_record_error)) {
      if (error) *error = ordered_record_error;
      return false;
    }
  }
  if (auto expected = leader_for_height_round(transition.height, transition.round); !expected.has_value() ||
                                                                      *expected != transition.leader_pubkey) {
    if (error) *error = "invalid-proposer";
    return false;
  }
  for (std::size_t lane = 0; lane < finalis::INGRESS_LANE_COUNT; ++lane) {
    if (transition.next_vector.lane_max_seq[lane] < transition.prev_vector.lane_max_seq[lane]) {
      log_line("frontier-validation-vector-rewind transition=" + short_hash_hex(transition.transition_id()) +
               " lane=" + std::to_string(lane) + " prev=" +
               std::to_string(transition.prev_vector.lane_max_seq[lane]) + " next=" +
               std::to_string(transition.next_vector.lane_max_seq[lane]));
      if (error) *error = "frontier-vector-rewind";
      return false;
    }
  }
  consensus::CanonicalFrontierRecord certified_record{transition, proposal.ordered_records};
  consensus::FrontierExecutionResult recomputed;
  std::string validation_diagnostics;
  if (!consensus::verify_frontier_record_against_state(canonical_derivation_config_locked(), *canonical_state_,
                                                       certified_record, &recomputed, error,
                                                       &validation_diagnostics)) {
    if (error != nullptr && !validation_diagnostics.empty()) {
      if (!error->empty()) *error += " details=" + validation_diagnostics;
      else *error = "details=" + validation_diagnostics;
    }
    log_line("frontier-validation-failed transition=" + short_hash_hex(transition.transition_id()) + " range=(" +
             std::to_string(transition.prev_frontier + 1) + "," + std::to_string(transition.next_frontier) +
             "] detail=" + (error ? *error : std::string("unknown")));
    if (error && error->empty()) *error = "frontier-verification-failed";
    return false;
  }
  return true;
}

bool Node::check_and_record_proposer_equivocation_locked(const FrontierTransition& transition) {
  constexpr std::uint64_t kObservedProposalRetentionDepth = 512;
  const std::uint64_t min_height_to_keep =
      finalized_height_ > kObservedProposalRetentionDepth ? (finalized_height_ - kObservedProposalRetentionDepth) : 0;
  for (auto it = observed_proposals_.begin(); it != observed_proposals_.end();) {
    if (std::get<0>(it->first) < min_height_to_keep) {
      it = observed_proposals_.erase(it);
    } else {
      ++it;
    }
  }
  const auto key = std::make_tuple(transition.height, transition.round, transition.leader_pubkey);
  const auto new_transition_id = transition.transition_id();
  auto it = observed_proposals_.find(key);
  if (it == observed_proposals_.end()) {
    observed_proposals_[key] = new_transition_id;
    return false;
  }
  const auto old_transition_id = it->second;
  if (old_transition_id == new_transition_id) return false;

  locally_observed_equivocators_.insert(transition.leader_pubkey);
  (void)db_.put_slashing_record(make_proposer_equivocation_record(transition.leader_pubkey, transition.height,
                                                                  transition.round, old_transition_id,
                                                                  new_transition_id, finalized_height_));
  log_line("proposer-equivocation-observed validator=" +
           hex_encode(Bytes(transition.leader_pubkey.begin(), transition.leader_pubkey.end())) +
           " height=" + std::to_string(transition.height) + " round=" + std::to_string(transition.round) +
           " block_a=" + hex_encode32(old_transition_id) + " block_b=" + hex_encode32(new_transition_id));
  return true;
}

bool Node::finalize_if_quorum(const Hash32& block_id, std::uint64_t height, std::uint32_t round) {
  auto proposal_it = candidate_frontier_proposals_.find(block_id);
  if (proposal_it == candidate_frontier_proposals_.end()) {
    const bool in_flight = requested_sync_artifacts_.find(block_id) != requested_sync_artifacts_.end();
    log_line(std::string(in_flight ? "finalize-wait" : "finalize-skip") + " height=" + std::to_string(height) +
             " round=" + std::to_string(round) + " transition=" + short_hash_hex(block_id) + " reason=" +
             (in_flight ? "candidate-pending" : "missing-candidate"));
    return false;
  }
  FrontierProposal finalized_proposal = proposal_it->second;

  std::string lock_error;
  if (!can_accept_frontier_with_lock_locked(proposal_it->second.transition, &lock_error)) {
    log_line("finalize-skip height=" + std::to_string(height) + " round=" + std::to_string(round) +
             " transition=" + short_hash_hex(block_id) + " reason=" + lock_error);
    return false;
  }
  consensus::CanonicalFrontierRecord certified_record;
  std::string frontier_record_error;
  if (!consensus::load_certified_frontier_record_from_storage(db_, finalized_proposal.transition, &certified_record,
                                                              &frontier_record_error)) {
    log_line("finalize-skip height=" + std::to_string(height) + " round=" + std::to_string(round) +
             " transition=" + short_hash_hex(block_id) + " reason=" + frontier_record_error);
    return false;
  }
  certified_record.ordered_records = finalized_proposal.ordered_records;

  if (!canonical_state_.has_value()) {
    log_line("finalize-skip height=" + std::to_string(height) + " round=" + std::to_string(round) +
             " transition=" + short_hash_hex(block_id) + " reason=missing-canonical-state");
    return false;
  }
  consensus::FrontierExecutionResult recomputed;
  std::string validation_error;
  if (!consensus::verify_frontier_record_against_state(canonical_derivation_config_locked(), *canonical_state_,
                                                       certified_record, &recomputed, &validation_error)) {
    log_line("finalize-skip height=" + std::to_string(height) + " round=" + std::to_string(round) +
             " transition=" + short_hash_hex(block_id) + " reason=" + validation_error);
    return false;
  }
  const auto expected_committee = recomputed.effective_committee;
  if (expected_committee.empty()) {
    log_line("finalize-skip height=" + std::to_string(height) + " round=" + std::to_string(round) +
             " transition=" + short_hash_hex(block_id) + " reason=empty-effective-committee");
    return false;
  }
  const std::size_t expected_quorum = consensus::quorum_threshold(expected_committee.size());
  auto sigs = votes_.signatures_for(height, round, block_id);
  std::set<PubKey32> committee_set(expected_committee.begin(), expected_committee.end());
  // The quorum-1 self-vote below signs without going through can_vote_for_frontier_locked, so the
  // abstention must be enforced here as well.
  if (sigs.empty() && expected_quorum == 1 && expected_committee.size() == 1 &&
      expected_committee.front() == local_key_.public_key && !abstaining_at_height_locked(height)) {
    if (auto sig = crypto::ed25519_sign(vote_signing_message(height, round, block_id), local_key_.private_key);
        sig.has_value()) {
      const Vote local_vote{height, round, block_id, local_key_.public_key, *sig};
      // INVARIANT: this is the other insertion path into votes_ (see the matching comment
      // at votes_.add_vote in handle_vote_result). Trusted without a separate verify step
      // because it is signed with our own private key right above, not attacker-supplied.
      const auto tr = votes_.add_vote(local_vote);
      if (tr.accepted || tr.duplicate) {
        sigs = votes_.signatures_for(height, round, block_id);
        log_line("finalize-quorum1-local-self-vote height=" + std::to_string(height) +
                 " round=" + std::to_string(round) + " transition=" + short_hash_hex(block_id));
      }
    } else {
      log_line("finalize-skip height=" + std::to_string(height) + " round=" + std::to_string(round) +
               " transition=" + short_hash_hex(block_id) + " reason=local-vote-sign-failed");
    }
  }
  if (sigs.size() < expected_quorum) {
    std::ostringstream oss;
    oss << "finalize-skip height=" << height << " round=" << round << " transition=" << short_hash_hex(block_id)
        << " reason=insufficient-votes votes=" << sigs.size() << " quorum=" << expected_quorum
        << " signers=" << signer_set_summary(sigs);
    if (debug_finality_logs_enabled()) {
      oss << " committee_size=" << expected_committee.size();
      if (auto proposer = leader_for_height_round(height, round); proposer.has_value()) {
        oss << " proposer=" << short_pub_hex(*proposer);
      }
    }
    log_line(oss.str());
    return false;
  }

  // sigs (above) == votes_.signatures_for(height, round, block_id): every entry already
  // passed crypto::ed25519_verify in handle_vote_result (or is our own self-signed vote,
  // see the branch above) before it was accepted into votes_. No need to re-verify a third
  // time here -- just the committee-membership/dedup filter.
  std::set<PubKey32> seen;
  std::vector<FinalitySig> filtered;
  for (const auto& s : sigs) {
    if (committee_set.find(s.validator_pubkey) == committee_set.end()) continue;
    if (!seen.insert(s.validator_pubkey).second) continue;
    filtered.push_back(s);
  }
  if (filtered.size() < expected_quorum) {
    log_line("finalize-skip height=" + std::to_string(height) + " round=" + std::to_string(round) +
             " transition=" + short_hash_hex(block_id) + " reason=insufficient-valid-signatures valid=" +
             std::to_string(filtered.size()) + " quorum=" + std::to_string(expected_quorum));
    return false;
  }
  const auto canonical_sigs = canonicalize_finality_signatures_locked(filtered, expected_quorum);

  std::string apply_error;
  if (!apply_finalized_frontier_effects_locked(certified_record, canonical_sigs, false, &expected_committee,
                                               &apply_error)) {
    log_line("finalize-skip height=" + std::to_string(height) + " round=" + std::to_string(round) +
             " transition=" + short_hash_hex(block_id) + " reason=apply-failed" +
             (apply_error.empty() ? std::string() : " detail=" + apply_error));
    return false;
  }

  const FinalityCertificate cert =
      make_finality_certificate(height, round, block_id, expected_quorum, expected_committee, canonical_sigs);
  // mu_ is held here; the sends happen in flush_pending_finalized_broadcasts().
  last_broadcast_finalized_frontier_ = finalized_proposal;
  last_broadcast_finality_certificate_ = cert;
  pending_finalized_broadcasts_.emplace_back(std::move(finalized_proposal), cert);
  pending_finalized_tip_broadcast_ = true;
  return true;
}

std::optional<FrontierProposal> Node::build_frontier_transition_locked(std::uint64_t height, std::uint32_t round) {
  if (!canonical_state_.has_value()) {
    last_test_hook_error_ = "missing-canonical-state";
    return std::nullopt;
  }
  if (canonical_state_->finalized_frontier != canonical_state_->finalized_frontier_vector.total_count()) {
    std::string repair_error;
    log_line("finalized-state-invariant-violation source=frontier-build-runtime-cursor-mismatch height=" +
             std::to_string(height) + " finalized_frontier=" + std::to_string(canonical_state_->finalized_frontier) +
             " vector_total=" + std::to_string(canonical_state_->finalized_frontier_vector.total_count()));
    if (!refresh_runtime_from_frontier_storage_locked("frontier-build-runtime-cursor-mismatch", &repair_error)) {
      last_test_hook_error_ = "frontier-build-runtime-refresh-failed:" + repair_error;
      return std::nullopt;
    }
    if (!canonical_state_.has_value() ||
        canonical_state_->finalized_frontier != canonical_state_->finalized_frontier_vector.total_count()) {
      last_test_hook_error_ = "frontier-build-runtime-cursor-mismatch-persisted";
      return std::nullopt;
    }
  }
  if (!finalized_identity_valid_for_frontier_runtime(finalized_height_, finalized_identity_)) {
    last_test_hook_error_ = "frontier-parent-identity-kind-mismatch";
    return std::nullopt;
  }
  (void)ensure_settlement_onboarding_scores_loaded_locked(height);

  for (int attempt = 0; attempt < 2; ++attempt) {
    FrontierBuildSelection selection;
    selection.next_vector = canonical_state_->finalized_frontier_vector;
    std::array<std::uint64_t, finalis::INGRESS_LANE_COUNT> lane_tips{};
    std::uint64_t max_delta = 0;
    for (std::size_t lane = 0; lane < finalis::INGRESS_LANE_COUNT; ++lane) {
      if (auto state = db_.get_lane_state(static_cast<std::uint32_t>(lane)); state.has_value()) {
        lane_tips[lane] = state->max_seq;
      } else {
        lane_tips[lane] = 0;
      }
      if (lane_tips[lane] < canonical_state_->finalized_frontier_vector.lane_max_seq[lane]) {
        last_test_hook_error_ = "frontier-build-lane-tip-rewind lane=" + std::to_string(lane);
        return std::nullopt;
      }
      max_delta = std::max(max_delta, lane_tips[lane] - canonical_state_->finalized_frontier_vector.lane_max_seq[lane]);
    }

    std::array<Hash32, finalis::INGRESS_LANE_COUNT> expected_lane_roots = canonical_state_->finalized_lane_roots;
    std::array<bool, finalis::INGRESS_LANE_COUNT> lane_blocked{};
    std::size_t total_bytes = 0;
    std::uint64_t total_verify_weight = 0;
    bool capped = false;
    for (std::uint64_t r = 1; r <= max_delta && !capped; ++r) {
      for (std::size_t lane = 0; lane < finalis::INGRESS_LANE_COUNT; ++lane) {
        if (lane_blocked[lane]) continue;
        const auto seq = canonical_state_->finalized_frontier_vector.lane_max_seq[lane] + r;
        if (seq > lane_tips[lane]) continue;
        if (quarantined_ingress_records_.contains({static_cast<std::uint32_t>(lane), seq})) {
          lane_blocked[lane] = true;
          continue;
        }
        consensus::CertifiedIngressRecord ingress;
        std::string ingress_error;
        if (!load_certified_ingress_record_from_db(db_, static_cast<std::uint32_t>(lane), seq, &ingress, &ingress_error)) {
          last_test_hook_error_ = "frontier-build-ingress-load-failed:" + ingress_error;
          log_line("frontier-build-failed height=" + std::to_string(height) + " round=" + std::to_string(round) +
                   " lane=" + std::to_string(lane) + " seq=" + std::to_string(seq) +
                   " reason=" + ingress_error);
          return std::nullopt;
        }
        if (ingress.certificate.prev_lane_root != expected_lane_roots[lane]) {
          quarantined_ingress_records_.insert({static_cast<std::uint32_t>(lane), seq});
          log_line("frontier-ingress-quarantine lane=" + std::to_string(lane) + " seq=" + std::to_string(seq) +
                   " reason=prev-root-mismatch expected_prev_root=" + short_hash_hex(expected_lane_roots[lane]) +
                   " provided_prev_root=" + short_hash_hex(ingress.certificate.prev_lane_root));
          lane_blocked[lane] = true;
          continue;
        }
        std::string ordered_record_error;
        if (!inspect_frontier_ordered_record_supported(ingress.tx_bytes, selection.ordered_records.size(), nullptr,
                                                       &ordered_record_error)) {
          last_test_hook_error_ = "frontier-build-ordered-record-invalid:" + ordered_record_error;
          log_line("frontier-build-failed height=" + std::to_string(height) + " round=" + std::to_string(round) +
                   " lane=" + std::to_string(lane) + " seq=" + std::to_string(seq) +
                   " reason=" + ordered_record_error);
          return std::nullopt;
        }
        const auto record_verify_weight = consensus::ordered_record_confidential_verify_weight(ingress.tx_bytes);
        if (selection.ordered_records.size() >= kMaxBlockTxs ||
            total_bytes + ingress.tx_bytes.size() > kMaxBlockBytes ||
            total_verify_weight + record_verify_weight > confidential_policy_.max_block_confidential_verify_weight) {
          capped = true;
          break;
        }
        total_verify_weight += record_verify_weight;
        selection.next_vector.lane_max_seq[lane] = seq;
        selection.lane_records[lane].push_back(ingress);
        selection.ordered_records.push_back(ingress.tx_bytes);
        total_bytes += ingress.tx_bytes.size();
        expected_lane_roots[lane] = consensus::compute_lane_root_append(expected_lane_roots[lane], ingress.certificate.tx_hash);
      }
    }

  SpecialValidationContext vctx = special_validation_context_locked(height);

    consensus::FrontierExecutionResult result;
    std::string validation_error;
    if (!consensus::execute_frontier_lane_prefix(canonical_state_->utxos, canonical_state_->confidential_pool_value,
                                                 canonical_state_->finalized_frontier_vector,
                                                 selection.next_vector, selection.lane_records,
                                                 canonical_state_->finalized_lane_roots, &vctx, &result, &validation_error)) {
      if (attempt == 0 &&
          (validation_error.find("frontier-certified-ingress-prev-root-mismatch") != std::string::npos ||
           validation_error.find("frontier-certified-ingress-prev-root-state-mismatch") != std::string::npos)) {
        if (auto lane_seq = parse_lane_seq_from_error(validation_error); lane_seq.has_value()) {
          quarantined_ingress_records_.insert(*lane_seq);
          log_line("frontier-ingress-quarantine lane=" + std::to_string(lane_seq->first) +
                   " seq=" + std::to_string(lane_seq->second) +
                   " reason=execution-prev-root-mismatch retry=1 detail=" + validation_error);
          continue;
        }
      }
      last_test_hook_error_ = "frontier-build-execution-failed:" + validation_error;
      return std::nullopt;
    }
    if (!consensus::populate_frontier_transition_metadata(canonical_derivation_config_locked(), *canonical_state_, height, round,
                                                          local_key_.public_key,
                                                          prev_finality_signers_for_next_height_locked(),
                                                          result.accepted_fee_units,
                                                          result.next_utxos, &result.transition, &validation_error)) {
      last_test_hook_error_ = "frontier-build-metadata-failed:" + validation_error;
      return std::nullopt;
    }
    if (height == finalized_height_ + 1) {
      log_line("frontier-build-summary height=" + std::to_string(height) + " round=" + std::to_string(round) +
               " transition=" + short_hash_hex(result.transition.transition_id()) +
               " settlement_commitment=" + short_hash_hex(result.transition.settlement_commitment) +
               " settlement_payload_hash=" + short_hash_hex(crypto::sha256(result.transition.settlement.serialize())) +
               " tx_count=" + std::to_string(result.accepted_txs.size()));
    }
    last_test_hook_error_.clear();
    return FrontierProposal{result.transition, selection.ordered_records};
  }
  last_test_hook_error_ = "frontier-build-execution-failed:quarantine-retry-exhausted";
  return std::nullopt;
}

void Node::prune_caches_locked(std::uint64_t height, std::uint32_t round) {
  const auto now = now_ms();
  for (auto it = proposed_in_round_.begin(); it != proposed_in_round_.end();) {
    if (it->first.first < height || (it->first.first == height && it->first.second + kProposalRoundWindow < round)) {
      it = proposed_in_round_.erase(it);
    } else {
      ++it;
    }
  }
  for (auto it = logged_committee_rounds_.begin(); it != logged_committee_rounds_.end();) {
    if (it->first < height || (it->first == height && it->second + kProposalRoundWindow < round)) {
      it = logged_committee_rounds_.erase(it);
    } else {
      ++it;
    }
  }
  for (auto it = seen_timeout_vote_messages_ms_.begin(); it != seen_timeout_vote_messages_ms_.end();) {
    const bool stale = (it->second + kTimeoutVoteMessageDedupTtlMs) < now;
    const bool old_height = std::get<0>(it->first) + 2 < height;
    if (stale || old_height || seen_timeout_vote_messages_ms_.size() > kMaxSeenTimeoutVoteMessages) {
      it = seen_timeout_vote_messages_ms_.erase(it);
    } else {
      ++it;
    }
  }
  for (auto it = timeout_vote_soft_reject_log_counts_.begin(); it != timeout_vote_soft_reject_log_counts_.end();) {
    const bool old_height = std::get<0>(it->first) + 2 < height;
    const bool old_round = std::get<0>(it->first) == height && (std::get<1>(it->first) + kProposalRoundWindow) < round;
    if (old_height || old_round) {
      it = timeout_vote_soft_reject_log_counts_.erase(it);
    } else {
      ++it;
    }
  }
}

}  // namespace finalis::node
