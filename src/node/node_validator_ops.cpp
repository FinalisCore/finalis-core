// SPDX-License-Identifier: MIT

// Validators, committees and availability: local key and bootstrap, epoch tickets and committees,
// committee/leader selection, finalized committee checkpoints, settlement onboarding scores.

#include "node.hpp"
#include "node_internal.hpp"

#include <algorithm>
#include <iostream>
#include <set>
#include <sstream>

#include "consensus/canonical_derivation.hpp"
#include "consensus/randomness.hpp"
#include "consensus/validator_registry.hpp"
#include "common/paths.hpp"
#include "crypto/secure_memory.hpp"
#include "genesis/genesis.hpp"
#include "common/keystore.hpp"

namespace finalis::node {
using namespace detail;

namespace {

constexpr std::uint32_t kEpochReconcileRequestMaxTickets = 128;
constexpr std::size_t kEpochReconcileMinPeersPerTick = 3;
constexpr std::size_t kEpochReconcileMaxPeersPerTick = 8;
constexpr std::uint64_t kEpochTicketRejectLogIntervalMs = 10'000;
constexpr std::uint64_t kEpochReconcileRejectLogIntervalMs = 30'000;
constexpr std::uint64_t kEpochReconcileClosedRebuildLogIntervalMs = 60'000;

std::optional<PubKey32> leader_from_checkpoint(const NetworkConfig& network, const consensus::ValidatorRegistry& validators,
                                               const storage::FinalizedCommitteeCheckpoint& checkpoint,
                                               std::uint64_t height, std::uint32_t round) {
  if (auto fallback = consensus::checkpoint_ticket_pow_fallback_member_for_round(checkpoint, round); fallback.has_value()) {
    return fallback;
  }
  const auto schedule = proposer_schedule_from_checkpoint(network, validators, checkpoint, height);
  if (schedule.empty()) return std::nullopt;
  return schedule[static_cast<std::size_t>(round) % schedule.size()];
}

}  // namespace

bool Node::init_local_validator_key() {
  const std::string key_path = expand_user_home(cfg_.validator_key_file.empty()
                                                    ? keystore::default_validator_keystore_path(cfg_.db_path)
                                                    : cfg_.validator_key_file);
  keystore::ValidatorKey vk;
  std::string kerr;
  // The passphrase is only needed to open the keystore; do not keep it for the process lifetime.
  struct WipePassphrase {
    std::string& s;
    ~WipePassphrase() { crypto::secure_wipe(s); }
  } wipe_passphrase{cfg_.validator_passphrase};
  const bool is_mainnet = cfg_.network.name == "mainnet";
  if (keystore::keystore_exists(key_path)) {
    if (!keystore::load_validator_keystore(key_path, cfg_.validator_passphrase, &vk, &kerr)) {
      std::cerr << "failed to load validator keystore: " << kerr << "\n";
      return false;
    }
    if (is_mainnet && !keystore::keystore_is_encrypted(key_path)) {
      std::cerr << "warning: validator keystore " << key_path
                << " stores the private key UNENCRYPTED; re-create it with a passphrase\n";
    }
  } else {
    // SECURITY: never silently write a plaintext validator key on mainnet.
    if (is_mainnet && cfg_.validator_passphrase.empty() && !cfg_.allow_unencrypted_keystore) {
      std::cerr << "refusing to create an unencrypted mainnet validator keystore at " << key_path
                << "; set --validator-passphrase-env (or pass --allow-unencrypted-keystore)\n";
      return false;
    }
    if (!keystore::create_validator_keystore(key_path, cfg_.validator_passphrase, cfg_.network.name,
                                             keystore::hrp_for_network(cfg_.network.name), std::nullopt, &vk, &kerr)) {
      std::cerr << "failed to create validator keystore: " << kerr << "\n";
      return false;
    }
    log_line("created validator keystore path=" + key_path);
  }
  crypto::secure_wipe(local_key_.private_key);
  local_key_.private_key.reserve(32);
  local_key_.private_key.assign(vk.privkey.begin(), vk.privkey.end());
  local_key_.public_key = vk.pubkey;
  if (!crypto::lock_memory(local_key_.private_key.data(), local_key_.private_key.size())) {
    log_line("warning: mlock of validator key failed; key pages may be swapped to disk");
  }
  log_line("validator pubkey=" + hex_encode(Bytes(vk.pubkey.begin(), vk.pubkey.end())) + " address=" + vk.address);
  return true;
}

bool Node::bootstrap_template_bind_validator(const PubKey32& pub, bool local_validator) {
  if (bootstrap_handoff_complete_locked()) {
    log_line("bootstrap-bind-skip reason=handoff-complete height=" + std::to_string(finalized_height_));
    return false;
  }
  genesis::Document effective;
  effective.version = 1;
  effective.network_name = cfg_.network.name;
  effective.protocol_version = cfg_.network.protocol_version;
  effective.network_id = cfg_.network.network_id;
  effective.magic = cfg_.network.magic;
  effective.genesis_time_unix = 1735689600ULL;
  effective.initial_height = 0;
  effective.initial_validators = {pub};
  effective.initial_active_set_size = 1;
  effective.initial_committee_params.min_committee = 1;
  effective.initial_committee_params.max_committee = static_cast<std::uint32_t>(cfg_.network.max_committee);
  effective.initial_committee_params.sizing_rule = "min(MAX_COMMITTEE,ACTIVE_SIZE)";
  effective.initial_committee_params.c = 1;
  effective.monetary_params_ref = "README.md#monetary-policy-7m-hard-cap";
  effective.note = local_validator ? "single-node bootstrap bound to local validator"
                                   : "bootstrap validator adopted from network";
  const auto json = genesis::to_json(effective);
  if (!db_.put(storage::key_genesis_json(), Bytes(json.begin(), json.end()))) return false;

  consensus::CanonicalGenesisState rebound_genesis;
  rebound_genesis.genesis_artifact_id = genesis::block_id(effective);
  if (auto stored_genesis_artifact = db_.get(storage::key_genesis_artifact());
      stored_genesis_artifact.has_value() && stored_genesis_artifact->size() == 32) {
    std::copy(stored_genesis_artifact->begin(), stored_genesis_artifact->end(), rebound_genesis.genesis_artifact_id.begin());
  }
  rebound_genesis.initial_validators = {pub};

  consensus::CanonicalDerivedState rebound_state;
  std::string rebound_error;
  if (!consensus::build_genesis_canonical_state(canonical_derivation_config_locked(), rebound_genesis, &rebound_state,
                                                &rebound_error)) {
    log_line("bootstrap-bind-canonical-rebuild-failed detail=" + rebound_error);
    return false;
  }

  validators_ = rebound_state.validators;
  finalized_randomness_ = rebound_state.finalized_randomness;
  committee_epoch_randomness_cache_ = rebound_state.committee_epoch_randomness_cache;
  protocol_reserve_balance_units_ = rebound_state.protocol_reserve_balance_units;
  finalized_committee_checkpoints_ = rebound_state.finalized_committee_checkpoints;
  canonical_state_ = rebound_state;
  if (!persist_canonical_cache_rows(db_, rebound_state)) return false;
  (void)db_.erase(storage::key_consensus_state_commitment_cache());
  if (!verify_and_persist_consensus_state_commitment_locked(rebound_state)) return false;

  const UtxoSetV2 empty_utxos;
  (void)persist_state_roots(db_, 0, empty_utxos, validators_, kFixedValidationRulesVersion);
  (void)db_.put(kFinalizedRandomnessKey, Bytes(finalized_randomness_.begin(), finalized_randomness_.end()));
  if (!db_.flush()) return false;

  bootstrap_validator_pubkey_ = pub;
  is_validator_ = local_validator;
  return true;
}

bool Node::maybe_adopt_bootstrap_validator_from_peer(int peer_id, const PubKey32& pub, std::uint64_t peer_height,
                                                     const char* source) {
  const auto info = p2p_.get_peer_info(peer_id);
  const std::string ip = info.ip.empty() ? endpoint_to_ip(info.endpoint) : info.ip;
  // Trust boundary: height-0 bootstrap adoption is only allowed from an explicitly
  // configured bootstrap peer that advertises bootstrap_validator in VERSION.
  const bool explicit_bootstrap_advertisement = std::string(source) == "version-bootstrap";
  if (bootstrap_handoff_complete_locked()) {
    log_line("bootstrap-adopt-skip peer_id=" + std::to_string(peer_id) + " source=" + source +
             " reason=handoff-complete height=" + std::to_string(finalized_height_));
    return false;
  }
  if (bootstrap_validator_pubkey_.has_value()) {
    log_line("bootstrap-adopt-skip peer_id=" + std::to_string(peer_id) + " source=" + source +
             " reason=already-bound");
    return false;
  }
  if (finalized_height_ != 0) {
    log_line("bootstrap-adopt-skip peer_id=" + std::to_string(peer_id) + " source=" + source +
             " reason=already-synced height=" + std::to_string(finalized_height_));
    return false;
  }
  if (!validators_.active_sorted(1).empty()) {
    log_line("bootstrap-adopt-skip peer_id=" + std::to_string(peer_id) + " source=" + source +
             " reason=validators-present");
    return false;
  }
  if (!is_bootstrap_peer_ip(ip)) {
    log_line("bootstrap-adopt-skip peer_id=" + std::to_string(peer_id) + " source=" + source +
             " reason=peer-not-bootstrap ip=" + ip);
    return false;
  }
  if (peer_height == 0 && !explicit_bootstrap_advertisement) {
    log_line("bootstrap-adopt-skip peer_id=" + std::to_string(peer_id) + " source=" + source +
             " reason=peer-height-zero");
    return false;
  }
  if (!bootstrap_template_bind_validator(pub, pub == local_key_.public_key)) {
    log_line("bootstrap-adopt-skip peer_id=" + std::to_string(peer_id) + " source=" + source +
             " reason=bind-failed");
    return false;
  }
  log_line(std::string("adopted bootstrap validator from peer pubkey=") +
           hex_encode(Bytes(pub.begin(), pub.end())) + " source=" + source + " peer_id=" + std::to_string(peer_id) +
           " peer_height=" + std::to_string(peer_height));
  return true;
}

void Node::maybe_self_bootstrap_template(std::uint64_t now_ms) {
  if (!bootstrap_template_mode_ || bootstrap_validator_pubkey_.has_value()) return;
  if (bootstrap_handoff_complete_locked()) return;
  if (finalized_height_ != 0) return;
  if (!validators_.active_sorted(1).empty()) return;
  const bool has_bootstrap_sources = !cfg_.disable_p2p && (!bootstrap_peers_.empty() || !dns_seed_peers_.empty());
  if (has_bootstrap_sources) return;
  const std::uint64_t wait_ms = cfg_.disable_p2p ? 0ULL : 5000ULL;
  if (now_ms < startup_ms_ + wait_ms) return;
  if (bootstrap_template_bind_validator(local_key_.public_key, true)) {
    log_line("bootstrap single-node genesis from local validator pubkey=" +
             hex_encode(Bytes(local_key_.public_key.begin(), local_key_.public_key.end())));
    if (!cfg_.disable_p2p) {
      // Safe: duplicate VERSION handling is idempotent and is used here to refresh
      // already-connected peers with the newly-bound bootstrap validator identity.
      for (int peer_id : p2p_.peer_ids()) send_version(peer_id);
    }
  }
}

std::size_t Node::pending_join_request_count_locked() const {
  std::size_t count = 0;
  for (const auto& [_, req] : validator_join_requests_) {
    if (req.status == ValidatorJoinRequestStatus::REQUESTED) ++count;
  }
  return count;
}

bool Node::bootstrap_sync_incomplete_locked(int peer_id) const {
  if (is_validator_) return false;
  if (finalized_height_ == 0) return true;
  const auto it = peer_finalized_tips_.find(peer_id);
  if (it == peer_finalized_tips_.end()) return false;
  return it->second.height > finalized_height_ || it->second.hash != finalized_identity_.id;
}

Hash32 Node::committee_epoch_randomness_for_height_locked(std::uint64_t height) const {
  const auto epoch_start = consensus::committee_epoch_start(height, cfg_.network.committee_epoch_blocks);
  auto it = committee_epoch_randomness_cache_.find(epoch_start);
  if (it != committee_epoch_randomness_cache_.end()) return it->second;
  return consensus::initial_finalized_randomness(cfg_.network, chain_id_);
}

std::optional<storage::FinalizedCommitteeCheckpoint> Node::finalized_committee_checkpoint_for_height_locked(
    std::uint64_t height) const {
  if (height == 0) return std::nullopt;
  const auto epoch_start = consensus::committee_epoch_start(height, cfg_.network.committee_epoch_blocks);
  auto it = finalized_committee_checkpoints_.find(epoch_start);
  if (it != finalized_committee_checkpoints_.end()) {
    if (canonical_state_.has_value() && epoch_start == finalized_height_ + 1) {
      std::string error;
      auto& cached = next_epoch_checkpoint_validation_cache_;
      if (!cached.has_value() || cached->epoch_start != epoch_start || cached->finalized_height != finalized_height_ ||
          cached->state_commitment != canonical_state_->state_commitment ||
          !consensus::canonical_checkpoints_equal(cached->checkpoint, it->second)) {
        NextEpochCheckpointValidation fresh;
        fresh.epoch_start = epoch_start;
        fresh.finalized_height = finalized_height_;
        fresh.state_commitment = canonical_state_->state_commitment;
        fresh.checkpoint = it->second;
        fresh.valid = consensus::validate_next_epoch_checkpoint_from_state(
            canonical_derivation_config_locked(), *canonical_state_, epoch_start, it->second, &fresh.error);
        cached = std::move(fresh);
      }
      if (!cached->valid) {
        log_line("finalized-state-invariant-violation source=checkpoint-next-height-recompute-mismatch epoch=" +
                 std::to_string(epoch_start) + " detail=" + cached->error);
        return std::nullopt;
      }
      if (!consensus::validate_checkpoint_schedule_for_height(canonical_derivation_config_locked(), *canonical_state_,
                                                              it->second, height, &error)) {
        log_line("finalized-state-invariant-violation source=checkpoint-schedule-mismatch epoch=" +
                 std::to_string(epoch_start) + " detail=" + error);
        return std::nullopt;
      }
    }
    return it->second;
  }
  return std::nullopt;
}

std::uint8_t Node::ticket_difficulty_bits_for_epoch_locked(std::uint64_t epoch_start_height,
                                                           std::size_t active_validator_count) const {
  std::uint8_t previous_bits = consensus::DEFAULT_TICKET_DIFFICULTY_BITS;
  const auto epoch_blocks = std::max<std::uint64_t>(1, cfg_.network.committee_epoch_blocks);
  const auto& econ = active_economics_policy(cfg_.network, epoch_start_height);
  if (epoch_start_height > 1) {
    const auto previous_epoch_start = epoch_start_height > epoch_blocks ? (epoch_start_height - epoch_blocks) : 1;
    if (auto checkpoint = finalized_committee_checkpoint_for_height_locked(previous_epoch_start); checkpoint.has_value()) {
      previous_bits = checkpoint->ticket_difficulty_bits;
    }
  }

  constexpr std::size_t kWindowEpochs = 6;
  std::size_t consecutive_healthy_epochs = 0;
  std::size_t consecutive_unhealthy_epochs = 0;
  std::size_t inspected_epochs = 0;
  for (std::uint64_t epoch = epoch_start_height; epoch > 1 && inspected_epochs < kWindowEpochs;) {
    if (epoch <= epoch_blocks) break;
    epoch -= epoch_blocks;
    ++inspected_epochs;
    std::uint64_t blocks = 0;
    std::uint64_t total_round_x1000 = 0;
    std::uint64_t total_participation_bps = 0;
    for (std::uint64_t h = epoch; h < epoch + epoch_blocks && h <= finalized_height_; ++h) {
      auto cert = db_.get_finality_certificate_by_height(h);
      if (!cert.has_value()) continue;
      ++blocks;
      total_round_x1000 += static_cast<std::uint64_t>(cert->round) * 1000ULL;
      total_participation_bps +=
          consensus::quorum_relative_participation_bps(cert->signatures.size(), cert->quorum_threshold);
    }
    const std::uint32_t average_round_x1000 =
        blocks == 0 ? 0U : static_cast<std::uint32_t>(total_round_x1000 / blocks);
    const std::uint32_t average_participation_bps =
        blocks == 0 ? 10'000U : static_cast<std::uint32_t>(total_participation_bps / blocks);
    const bool healthy = consensus::ticket_difficulty_epoch_is_healthy(active_validator_count, cfg_.max_committee,
                                                                       average_round_x1000, average_participation_bps);
    const bool unhealthy =
        consensus::ticket_difficulty_epoch_is_unhealthy(average_round_x1000, average_participation_bps);
    if (healthy && consecutive_unhealthy_epochs == 0) {
      ++consecutive_healthy_epochs;
    } else if (unhealthy && consecutive_healthy_epochs == 0) {
      ++consecutive_unhealthy_epochs;
    } else {
      break;
    }
  }
  return consensus::adjust_bounded_ticket_difficulty_bits(previous_bits, active_validator_count, cfg_.max_committee,
                                                          consecutive_healthy_epochs, consecutive_unhealthy_epochs);
}

std::optional<std::uint64_t> Node::settlement_epoch_for_block_height_locked(std::uint64_t height) const {
  const auto epoch_blocks = std::max<std::uint64_t>(1, cfg_.network.committee_epoch_blocks);
  const auto epoch_start = consensus::committee_epoch_start(height, epoch_blocks);
  if (height != epoch_start || epoch_start <= 1 || epoch_start <= epoch_blocks) return std::nullopt;
  return epoch_start - epoch_blocks;
}

std::map<PubKey32, std::uint64_t> Node::compute_onboarding_score_units_for_epoch_locked(std::uint64_t epoch_start_height) const {
  std::map<PubKey32, std::uint64_t> out;
  if (epoch_committee_frozen_locked(epoch_start_height)) {
    if (auto checkpoint = finalized_committee_checkpoint_for_height_locked(epoch_start_height);
        checkpoint.has_value() && !checkpoint->ordered_members.empty()) {
      for (const auto& member : checkpoint->ordered_members) out[member] = 1;
      return out;
    }
    if (auto snapshot = db_.get_epoch_committee_snapshot(epoch_start_height);
        snapshot.has_value() && !snapshot->ordered_members.empty()) {
      for (const auto& member : snapshot->ordered_members) out[member] = 1;
      return out;
    }
  }
  const bool local_registered = validators_.get(local_key_.public_key).has_value();
  const auto should_ignore_local_unregistered_participant =
      [&](const PubKey32& participant, consensus::EpochTicketOrigin origin) {
    // Startup on a fresh node may generate a local keystore that is not in the
    // validator registry. Ignore historical local-only ticket residue so replay
    // remains aligned with network-produced settlement payloads, but keep
    // network-origin tickets (including for this pubkey) once reconciled.
    return !local_registered && participant == local_key_.public_key && origin == consensus::EpochTicketOrigin::LOCAL;
  };
  const auto tickets = db_.load_epoch_tickets(epoch_start_height);
  const auto best_tickets = consensus::best_epoch_tickets_by_pubkey(tickets);
  for (const auto& [pub, ticket] : best_tickets) {
    if (should_ignore_local_unregistered_participant(pub, ticket.origin)) continue;
    const auto score = static_cast<std::uint64_t>(
        std::max<std::uint8_t>(1, consensus::leading_zero_bits(ticket.work_hash)));
    out[pub] = score;
  }
  for (const auto& [pub, ticket] : db_.load_best_epoch_tickets(epoch_start_height)) {
    if (should_ignore_local_unregistered_participant(pub, ticket.origin)) continue;
    const auto score = static_cast<std::uint64_t>(
        std::max<std::uint8_t>(1, consensus::leading_zero_bits(ticket.work_hash)));
    auto it = out.find(pub);
    if (it == out.end() || score > it->second) out[pub] = score;
  }

  return out;
}

bool Node::ensure_settlement_onboarding_scores_loaded_locked(std::uint64_t height) {
  const auto settlement_epoch = settlement_epoch_for_block_height_locked(height);
  if (!settlement_epoch.has_value()) return true;

  std::size_t established_peers = 0;
  for (int peer_id : p2p_.peer_ids()) {
    const auto info = p2p_.get_peer_info(peer_id);
    if (!info.established()) continue;
    ++established_peers;
  }
  auto request_epoch_reconcile = [&]() {
    for (int peer_id : p2p_.peer_ids()) {
      const auto info = p2p_.get_peer_info(peer_id);
      if (!info.established()) continue;
      request_epoch_tickets(peer_id, *settlement_epoch, 512);
    }
  };

  const auto onboarding_scores = compute_onboarding_score_units_for_epoch_locked(*settlement_epoch);
  if (onboarding_scores.empty()) request_epoch_reconcile();
  if (epoch_committee_closed_locked(*settlement_epoch) && !epoch_committee_frozen_locked(*settlement_epoch) &&
      established_peers != 0) {
    request_epoch_reconcile();
  }

  auto& reward_state = epoch_reward_states_[*settlement_epoch];
  reward_state.epoch_start_height = *settlement_epoch;
  const bool runtime_updated = reward_state.onboarding_score_units != onboarding_scores;
  if (runtime_updated) reward_state.onboarding_score_units = onboarding_scores;
  if (runtime_updated) {
    (void)db_.put_epoch_reward_settlement(reward_state);
  }

  if (canonical_state_.has_value()) {
    auto& canonical_reward_state = canonical_state_->epoch_reward_states[*settlement_epoch];
    canonical_reward_state.epoch_start_height = *settlement_epoch;
    const bool canonical_updated = canonical_reward_state.onboarding_score_units != onboarding_scores;
    if (canonical_updated) canonical_reward_state.onboarding_score_units = onboarding_scores;
    if (canonical_updated) {
      canonical_state_->state_commitment =
          consensus::consensus_state_commitment(canonical_derivation_config_locked(), *canonical_state_);
    }
  }

  return true;
}

Hash32 Node::epoch_ticket_challenge_anchor_locked(std::uint64_t height) const {
  if (height == 0) return zero_hash();
  if (auto checkpoint = finalized_committee_checkpoint_for_height_locked(height); checkpoint.has_value()) {
    return checkpoint->epoch_seed;
  }
  const auto epoch_start = consensus::committee_epoch_start(height, cfg_.network.committee_epoch_blocks);
  return consensus::committee_epoch_seed(committee_epoch_randomness_for_height_locked(height), epoch_start);
}

std::uint64_t Node::current_epoch_ticket_epoch_locked() const {
  return consensus::committee_epoch_start(finalized_height_ + 1, cfg_.network.committee_epoch_blocks);
}

std::optional<PubKey32> Node::local_operator_pubkey_locked() const {
  auto info = validators_.get(local_key_.public_key);
  if (!info.has_value()) return std::nullopt;
  return consensus::canonical_operator_id(local_key_.public_key, *info);
}

void Node::persist_availability_state_locked(storage::DB::Batch& batch) {
  batch.put(storage::key_availability_persistent_state(), availability_state_.serialize());
}

bool Node::persist_availability_state_locked() {
  storage::DB::Batch batch(db_);
  persist_availability_state_locked(batch);
  return db_.write_batch(batch);
}

bool Node::validate_availability_state_locked(const char* source) const {
  std::string error;
  if (availability::validate_availability_persistent_state_for_live_derivation(availability_state_, cfg_.availability, &error)) {
    return true;
  }
  log_line(std::string("availability-state-invariant-violation source=") + (source ? source : "unknown") +
           " detail=" + error);
  return false;
}

bool Node::finalize_availability_restore_locked(const char* source) {
  availability::normalize_availability_persistent_state(&availability_state_);
  if (!validate_availability_state_locked(source)) return false;
  log_line(std::string("availability-state-ready source=") + (source ? source : "unknown") +
           " epoch=" + std::to_string(availability_state_.current_epoch) +
           " operators=" + std::to_string(availability_state_.operators.size()) +
           " retained_prefixes=" + std::to_string(availability_state_.retained_prefixes.size()));
  return persist_availability_state_locked();
}

void Node::rebuild_availability_retained_prefixes_from_finalized_frontier_locked() {
  std::map<Hash32, availability::RetainedPrefix> merged;
  for (std::uint64_t height = 1; height <= finalized_height_; ++height) {
    auto transition_id = db_.get_frontier_transition_by_height(height);
    if (!transition_id.has_value()) continue;
    auto transition_bytes = db_.get_frontier_transition(*transition_id);
    if (!transition_bytes.has_value()) continue;
    auto transition = FrontierTransition::parse(*transition_bytes);
    if (!transition.has_value()) continue;
    consensus::CanonicalFrontierRecord record;
    std::string error;
    if (!consensus::load_certified_frontier_record_from_storage(db_, *transition, &record, &error)) {
      log_line("availability-backfill-skip height=" + std::to_string(height) + " detail=" + error);
      continue;
    }
    for (const auto& payload : availability::build_retained_prefix_payloads_from_lane_records(
             record.lane_records, record.transition.height, cfg_.availability.audit_chunk_size)) {
      merged[payload.prefix.prefix_id] = payload.prefix;
    }
  }
  availability_state_.retained_prefixes.clear();
  availability_state_.retained_prefixes.reserve(merged.size());
  for (const auto& [_, prefix] : merged) availability_state_.retained_prefixes.push_back(prefix);
  availability::normalize_availability_persistent_state(&availability_state_);
}

void Node::refresh_availability_operator_state_locked(bool advance_epoch) {
  std::map<PubKey32, std::uint64_t> operator_bonds;
  for (const auto& [validator_pubkey, info] : validators_.all()) {
    operator_bonds[consensus::canonical_operator_id(validator_pubkey, info)] += info.bonded_amount;
  }
  availability::refresh_live_availability_state(finalized_identity_.id, operator_bonds, advance_epoch, &availability_state_,
                                                cfg_.availability, cfg_.network.availability_recovery_activation_height);
  (void)validate_availability_state_locked(advance_epoch ? "availability-advance-epoch" : "availability-refresh");
}

void Node::advance_availability_epoch_locked(std::uint64_t epoch) {
  std::map<PubKey32, std::uint64_t> operator_bonds;
  for (const auto& [validator_pubkey, info] : validators_.all()) {
    operator_bonds[consensus::canonical_operator_id(validator_pubkey, info)] += info.bonded_amount;
  }
  availability::advance_live_availability_epoch(finalized_identity_.id, operator_bonds, epoch, &availability_state_,
                                                cfg_.availability, cfg_.network.availability_recovery_activation_height);
  (void)validate_availability_state_locked("availability-advance-epoch");
}

bool Node::load_availability_state_locked() {
  availability_state_rebuild_triggered_ = false;
  availability_state_rebuild_reason_.clear();
  if (canonical_state_.has_value()) {
    availability_state_ = canonical_state_->availability_state;
    return finalize_availability_restore_locked("canonical-replay");
  }
  const auto current_epoch = current_epoch_ticket_epoch_locked();
  const auto persisted_raw = db_.get(storage::key_availability_persistent_state());
  auto persisted = db_.get_availability_persistent_state();
  if (!persisted.has_value()) {
    if (persisted_raw.has_value()) {
      log_line("availability-snapshot-invalid action=reset");
      availability_state_rebuild_triggered_ = true;
      availability_state_rebuild_reason_ = "invalid_persisted_state";
    } else {
      availability_state_rebuild_triggered_ = true;
      availability_state_rebuild_reason_ = "missing_persisted_state";
    }
    availability_state_ = {};
    availability_state_.current_epoch = current_epoch;
    if (finalized_height_ > 0) {
      rebuild_availability_retained_prefixes_from_finalized_frontier_locked();
    }
    refresh_availability_operator_state_locked(false);
    return finalize_availability_restore_locked("frontier-replay");
  }
  availability_state_ = *persisted;
  availability::normalize_availability_persistent_state(&availability_state_);
  if (finalized_height_ > 0 && availability_state_.retained_prefixes.empty()) {
    availability_state_rebuild_triggered_ = true;
    availability_state_rebuild_reason_ = "missing_retained_prefix_snapshot";
    rebuild_availability_retained_prefixes_from_finalized_frontier_locked();
  }
  availability_state_.retained_prefixes =
      availability::expire_retained_prefixes(availability_state_.retained_prefixes, current_epoch,
                                             cfg_.availability.retention_window_min_epochs);
  if (availability_state_.current_epoch < current_epoch) {
    advance_availability_epoch_locked(current_epoch);
  } else {
    availability_state_.current_epoch = current_epoch;
    refresh_availability_operator_state_locked(false);
  }
  return finalize_availability_restore_locked("persisted-restore");
}

bool Node::epoch_committee_closed_locked(std::uint64_t epoch) const {
  if (epoch == 0) return false;
  return epoch < current_epoch_ticket_epoch_locked();
}

bool Node::epoch_committee_frozen_locked(std::uint64_t epoch) const {
  if (!epoch_committee_closed_locked(epoch)) return false;
  auto marker = db_.get_epoch_committee_freeze_marker(epoch);
  if (!marker.has_value()) return false;
  auto snapshot = db_.get_epoch_committee_snapshot(epoch);
  if (!snapshot.has_value()) return false;
  if (snapshot->ordered_members.empty()) return false;
  return marker->challenge_anchor == snapshot->challenge_anchor &&
         marker->member_count == snapshot->ordered_members.size();
}

std::optional<std::uint64_t> Node::epoch_committee_snapshot_epoch_for_height_locked(std::uint64_t height) const {
  if (height == 0) return std::nullopt;
  const auto epoch = consensus::committee_epoch_start(height, cfg_.network.committee_epoch_blocks);
  const auto step = std::max<std::uint64_t>(1, cfg_.network.committee_epoch_blocks);
  if (epoch <= step) return std::nullopt;
  return epoch - step;
}

std::optional<consensus::EpochCommitteeSnapshot> Node::frozen_epoch_committee_snapshot_for_height_locked(
    std::uint64_t height) const {
  auto snapshot_epoch = epoch_committee_snapshot_epoch_for_height_locked(height);
  if (!snapshot_epoch.has_value()) return std::nullopt;
  if (!epoch_committee_frozen_locked(*snapshot_epoch)) return std::nullopt;
  auto snapshot = db_.get_epoch_committee_snapshot(*snapshot_epoch);
  if (!snapshot.has_value() || snapshot->ordered_members.empty()) return std::nullopt;
  return snapshot;
}

std::vector<PubKey32> Node::epoch_bootstrap_committee_for_height_locked(std::uint64_t height) const {
  if (height == 0) return {};
  std::vector<PubKey32> bootstrap_members;
  if (auto gj = db_.get(storage::key_genesis_json()); gj.has_value()) {
    const std::string js(gj->begin(), gj->end());
    if (auto gd = genesis::parse_json(js); gd.has_value()) {
      for (const auto& pub : gd->initial_validators) {
        auto it = validators_.all().find(pub);
        if (it == validators_.all().end()) continue;
        if (!it->second.has_bond) continue;
        if (it->second.status == consensus::ValidatorStatus::BANNED) continue;
        bootstrap_members.push_back(pub);
      }
    }
  }
  std::sort(bootstrap_members.begin(), bootstrap_members.end());
  bootstrap_members.erase(std::unique(bootstrap_members.begin(), bootstrap_members.end()), bootstrap_members.end());
  if (bootstrap_members.size() > cfg_.max_committee) bootstrap_members.resize(cfg_.max_committee);
  return bootstrap_members;
}

bool Node::bootstrap_handoff_complete_locked() const {
  if (finalized_height_ == 0) return false;
  return validators_.active_sorted(finalized_height_ + 1).size() >= 2;
}

bool Node::single_node_bootstrap_active_locked(std::uint64_t height) const {
  if (!bootstrap_template_mode_) return false;
  if (bootstrap_handoff_complete_locked()) return false;
  if (cfg_.disable_p2p) return false;
  if (cfg_.outbound_target != 0) return false;
  if (!bootstrap_validator_pubkey_.has_value()) return false;
  const auto bootstrap_committee = epoch_bootstrap_committee_for_height_locked(height);
  return bootstrap_committee.size() == 1 && bootstrap_committee.front() == *bootstrap_validator_pubkey_;
}

std::vector<PubKey32> Node::epoch_committee_for_next_height_locked(std::uint64_t height, std::uint32_t round) const {
  if (height == 0 || height != finalized_height_ + 1) return {};
  auto checkpoint = finalized_committee_checkpoint_for_height_locked(height);
  if (!checkpoint.has_value() || checkpoint->ordered_members.empty()) {
    log_line("epoch-committee-unavailable height=" + std::to_string(height) +
             " reason=missing-finalized-committee-checkpoint");
    return {};
  }
  return consensus::checkpoint_committee_for_round(*checkpoint, round);
}

std::optional<PubKey32> Node::epoch_leader_for_next_height_locked(std::uint64_t height, std::uint32_t round) const {
  if (height == 0 || height != finalized_height_ + 1) return std::nullopt;
  auto checkpoint = finalized_committee_checkpoint_for_height_locked(height);
  if (!checkpoint.has_value() || checkpoint->ordered_members.empty()) return std::nullopt;
  if (auto fallback = consensus::checkpoint_ticket_pow_fallback_member_for_round(*checkpoint, round); fallback.has_value()) {
    return fallback;
  }
  const auto schedule = proposer_schedule_from_checkpoint(cfg_.network, validators_, *checkpoint, height);
  if (schedule.empty()) {
    log_line("epoch-proposer-unavailable height=" + std::to_string(height) + " round=" + std::to_string(round) +
             " reason=empty-schedule");
    return std::nullopt;
  }
  return schedule[static_cast<std::size_t>(round) % schedule.size()];
}

bool Node::recover_single_validator_epoch_committee_locked(std::uint64_t epoch, const char* reason) {
  auto checkpoint = finalized_committee_checkpoint_for_height_locked(epoch);
  if (!checkpoint.has_value()) return false;
  if (checkpoint->ordered_members.size() != 1) return false;

  consensus::EpochCommitteeSnapshot snapshot;
  snapshot.epoch = epoch;
  snapshot.challenge_anchor = checkpoint->epoch_seed;

  const auto& pub = checkpoint->ordered_members.front();
  const auto best = checkpoint_best_ticket_for_member(cfg_.network, validators_, *checkpoint, 0);
  snapshot.selected_winners.push_back(consensus::EpochCommitteeMember{
      .participant_pubkey = pub,
      .work_hash = best.best_ticket_hash,
      .nonce = best.nonce,
      .source_height = epoch,
  });
  snapshot.ordered_members.push_back(pub);

  const auto marker = make_epoch_committee_freeze_marker_locked(snapshot);
  const bool ok = db_.put_epoch_committee_snapshot(snapshot) && db_.put_epoch_committee_freeze_marker(marker);
  if (ok) {
    log_line(std::string("epoch-committee-recovered reason=") + reason + " epoch=" + std::to_string(epoch) +
             " source=single-validator-finalized-checkpoint committee=1");
  }
  return ok;
}

storage::EpochCommitteeFreezeMarker Node::make_epoch_committee_freeze_marker_locked(
    const consensus::EpochCommitteeSnapshot& snapshot) const {
  return storage::EpochCommitteeFreezeMarker{
      .epoch = snapshot.epoch,
      .challenge_anchor = snapshot.challenge_anchor,
      .member_count = static_cast<std::uint64_t>(snapshot.ordered_members.size()),
  };
}

void Node::rebuild_epoch_committee_state_locked(std::uint64_t epoch, const char* reason, bool log_summary) {
  if (epoch == 0) return;
  auto checkpoint = finalized_committee_checkpoint_for_height_locked(epoch);
  if (!checkpoint.has_value() || checkpoint->ordered_members.empty()) {
    if (log_summary) {
      log_line(std::string("epoch-committee-rebuilt reason=") + reason + " epoch=" + std::to_string(epoch) +
               " status=skipped missing_finalized_checkpoint");
    }
    return;
  }

  auto effective_checkpoint = *checkpoint;

  auto snapshot = epoch_committee_snapshot_from_checkpoint(effective_checkpoint);
  auto existing = db_.get_epoch_committee_snapshot(epoch);
  const bool same_snapshot = existing.has_value() && same_epoch_committee_snapshot(*existing, snapshot);
  const bool should_be_frozen = epoch_committee_closed_locked(epoch);
  const auto expected_marker = make_epoch_committee_freeze_marker_locked(snapshot);
  auto existing_marker = db_.get_epoch_committee_freeze_marker(epoch);
  const bool same_marker = existing_marker.has_value() && existing_marker->epoch == expected_marker.epoch &&
                           existing_marker->challenge_anchor == expected_marker.challenge_anchor &&
                           existing_marker->member_count == expected_marker.member_count;

  (void)db_.put_epoch_committee_snapshot(snapshot);
  if (should_be_frozen) (void)db_.put_epoch_committee_freeze_marker(expected_marker);

  if (log_summary) {
    std::ostringstream winners;
    if (!effective_checkpoint.ordered_members.empty()) {
      const std::size_t take = std::min<std::size_t>(effective_checkpoint.ordered_members.size(), 4);
      for (std::size_t i = 0; i < take; ++i) {
        const auto best = checkpoint_best_ticket_for_member(cfg_.network, validators_, effective_checkpoint, i);
        if (i) winners << ",";
        winners << short_pub_hex(effective_checkpoint.ordered_members[i]) << ":" << short_hash_hex(best.best_ticket_hash)
                << ":" << best.nonce;
      }
    }
    log_line(std::string("epoch-committee-rebuilt reason=") + reason + " epoch=" + std::to_string(epoch) +
             " committee=" + std::to_string(snapshot.ordered_members.size()) +
             " closed=" + (should_be_frozen ? "yes" : "no") +
             " snapshot=" + (same_snapshot ? "verified" : "rewritten") +
             " best_index=ignored-for-finalized-checkpoint" +
             " freeze_marker=" + (should_be_frozen ? (same_marker ? "verified" : "rewritten") : "open") +
             " winners=" + winners.str());
  }
  local_epoch_tickets_.erase(epoch);
}

void Node::maybe_finalize_epoch_committees_locked() {
  const std::uint64_t current_epoch = current_epoch_ticket_epoch_locked();
  if (last_open_epoch_ticket_epoch_ == 0) {
    last_open_epoch_ticket_epoch_ = current_epoch;
    return;
  }
  if (current_epoch <= last_open_epoch_ticket_epoch_) return;
  const std::uint64_t step = std::max<std::uint64_t>(1, cfg_.network.committee_epoch_blocks);
  for (std::uint64_t epoch = last_open_epoch_ticket_epoch_; epoch < current_epoch; epoch += step) {
    rebuild_epoch_committee_state_locked(epoch, "epoch-closed", true);
    auto snapshot = db_.get_epoch_committee_snapshot(epoch);
    const std::size_t members = snapshot.has_value() ? snapshot->ordered_members.size() : 0;
    log_line("epoch-committee-closed epoch=" + std::to_string(epoch) + " frozen=" +
             (epoch_committee_frozen_locked(epoch) ? "yes" : "no") + " committee=" + std::to_string(members));
  }
  last_open_epoch_ticket_epoch_ = current_epoch;
}

bool Node::ensure_required_epoch_committee_state_locked() {
  const std::uint64_t height = finalized_height_ + 1;
  if (bootstrap_template_mode_ && finalized_height_ == 0 && bootstrap_validator_pubkey_.has_value()) {
    const auto active = validators_.active_sorted(1);
    if (active.size() == 1 && active.front() == *bootstrap_validator_pubkey_) return true;
  }
  if (bootstrap_template_mode_ && finalized_height_ == 0 && !bootstrap_validator_pubkey_.has_value()) return true;
  if (epoch_committee_for_next_height_locked(height, 0).empty()) {
    log_line("epoch-committee-startup next_height=" + std::to_string(height) +
             " reason=missing-finalized-committee-checkpoint");
    return false;
  }
  return true;
}

bool Node::ensure_required_epoch_committee_state_startup() {
  std::lock_guard<std::mutex> lk(mu_);
  return ensure_required_epoch_committee_state_locked();
}

void Node::maybe_request_epoch_ticket_reconciliation_locked(std::uint64_t now_ms) {
  const std::uint64_t open_epoch = current_epoch_ticket_epoch_locked();
  const std::uint64_t step = std::max<std::uint64_t>(1, cfg_.network.committee_epoch_blocks);
  std::vector<std::uint64_t> epochs;
  std::vector<std::uint64_t> settlement_epochs;
  if (auto required = epoch_committee_snapshot_epoch_for_height_locked(finalized_height_ + 1); required.has_value()) {
    for (std::uint64_t epoch = *required; epoch <= open_epoch; epoch += step) {
      epochs.push_back(epoch);
      if (epochs.size() >= 4) break;
    }
  }
  if (epochs.empty() || epochs.back() != open_epoch) epochs.push_back(open_epoch);
  
  // Add settlement epoch for current finalized height (settlement applies at next height)
  // and for next finalized height if either is a settlement boundary
  for (auto check_height : {finalized_height_, finalized_height_ + 1}) {
    if (auto settlement_epoch = settlement_epoch_for_block_height_locked(check_height); settlement_epoch.has_value()) {
      settlement_epochs.push_back(*settlement_epoch);
      if (std::find(epochs.begin(), epochs.end(), *settlement_epoch) == epochs.end()) {
        epochs.push_back(*settlement_epoch);
      }
    }
  }
  
  std::vector<int> eligible_peer_ids;
  eligible_peer_ids.reserve(p2p_.peer_ids().size());
  for (int peer_id : p2p_.peer_ids()) {
    const auto info = p2p_.get_peer_info(peer_id);
    if (!info.established()) continue;
    if (!peer_is_fresh_for_epoch_reconcile_locked(peer_id)) continue;
    eligible_peer_ids.push_back(peer_id);
  }
  if (eligible_peer_ids.empty()) return;
  const std::size_t fanout = std::min<std::size_t>(
      eligible_peer_ids.size(),
      std::max<std::size_t>(kEpochReconcileMinPeersPerTick,
                            std::min<std::size_t>(kEpochReconcileMaxPeersPerTick, cfg_.outbound_target)));
  const std::size_t start = epoch_reconcile_peer_cursor_ % eligible_peer_ids.size();
  epoch_reconcile_peer_cursor_ = (start + fanout) % eligible_peer_ids.size();
  const std::uint64_t interval = std::max<std::uint64_t>(3000, static_cast<std::uint64_t>(cfg_.network.round_timeout_ms));
  for (std::size_t index = 0; index < fanout; ++index) {
    const int peer_id = eligible_peer_ids[(start + index) % eligible_peer_ids.size()];
    for (const auto epoch : epochs) {
      // Skip closed/frozen epochs after local checkpoint snapshot is available.
      if (epoch != open_epoch && epoch_committee_frozen_locked(epoch) && db_.get_epoch_committee_snapshot(epoch).has_value()) {
        auto snapshot = db_.get_epoch_committee_snapshot(epoch);
        if (snapshot.has_value() && !snapshot->ordered_members.empty()) continue;
      }
      auto key = std::make_pair(peer_id, epoch);
      auto it = epoch_ticket_request_ms_.find(key);
      if (it != epoch_ticket_request_ms_.end() && now_ms < it->second + interval) continue;
      epoch_ticket_request_ms_[key] = now_ms;
      request_epoch_tickets(peer_id, epoch, kEpochReconcileRequestMaxTickets);
    }
  }
}

std::optional<consensus::EpochTicket> Node::mine_local_epoch_ticket_locked(std::uint64_t height) const {
  const auto epoch = consensus::committee_epoch_start(height, cfg_.network.committee_epoch_blocks);
  const auto anchor = epoch_ticket_challenge_anchor_locked(height);
  auto local_info = validators_.get(local_key_.public_key);
  PubKey32 participant = local_key_.public_key;
  if (local_info.has_value()) {
    if (!validators_.is_active_for_height(local_key_.public_key, height) &&
        local_info->status != consensus::ValidatorStatus::ONBOARDING) {
      return std::nullopt;
    }
    participant = consensus::canonical_operator_id(local_key_.public_key, *local_info);
  }
  auto ticket = consensus::best_epoch_ticket_for_operator_id(epoch, anchor, participant, height);
  if (!ticket.has_value()) return std::nullopt;
  const auto difficulty_bits = ticket_difficulty_bits_for_epoch_locked(epoch, validators_.active_sorted(height).size());
  if (!consensus::epoch_ticket_meets_difficulty(*ticket, difficulty_bits)) return std::nullopt;
  return ticket;
}

bool Node::handle_epoch_ticket_locked(const consensus::EpochTicket& ticket, bool from_network, int from_peer_id,
                                      std::string* reject_reason, bool allow_closed_epoch_reconcile) {
  consensus::EpochTicket stored = ticket;
  stored.origin = from_network ? consensus::EpochTicketOrigin::NETWORK : consensus::EpochTicketOrigin::LOCAL;
  const std::uint64_t current_epoch = current_epoch_ticket_epoch_locked();
  const bool closed_epoch_reconcile_read_only =
      allow_closed_epoch_reconcile && stored.epoch != current_epoch && epoch_committee_closed_locked(stored.epoch);
  if (!from_network) {
    auto local_info = validators_.get(local_key_.public_key);
    if (local_info.has_value()) {
      const auto expected_participant = consensus::canonical_operator_id(local_key_.public_key, *local_info);
      if (stored.participant_pubkey != expected_participant) {
        if (reject_reason) *reject_reason = "local-participant-mismatch";
        return false;
      }
      if (!validators_.is_active_for_height(local_key_.public_key, finalized_height_ + 1) &&
          local_info->status != consensus::ValidatorStatus::ONBOARDING) {
        if (reject_reason) *reject_reason = "local-non-active";
        return false;
      }
    } else if (stored.participant_pubkey != local_key_.public_key) {
      if (reject_reason) *reject_reason = "local-participant-mismatch";
      return false;
    }
  }
  if (stored.epoch == 0) {
    if (reject_reason) *reject_reason = "epoch-zero";
    return false;
  }
  if (from_network && stored.epoch == current_epoch) {
    // Open-epoch ticket flow is consensus-sensitive: accept only from peers that
    // have proven validator identity and are currently active in validator set.
    auto peer_it = peer_validator_pubkeys_.find(from_peer_id);
    if (peer_it == peer_validator_pubkeys_.end()) {
      if (reject_reason) *reject_reason = "untrusted-open-epoch-source";
      return false;
    }
    if (!validators_.is_active_for_height(peer_it->second, stored.epoch)) {
      if (reject_reason) *reject_reason = "non-validator-open-epoch-source";
      return false;
    }
  }
  if (epoch_committee_closed_locked(stored.epoch)) {
    if (allow_closed_epoch_reconcile) {
      // Explicit reconciliation may store tickets for a closed epoch, even a
      // frozen one.  Frozen epochs still need onboarding_score_units populated
      // so that settle-boundary blocks produced by older nodes can be replayed
      // with the correct settlement_commitment.  The committee snapshot update
      // below is harmless: for frozen epochs it is immediately overridden by
      // the finalized checkpoint.
    } else {
      if (reject_reason) *reject_reason = "epoch-closed";
      return false;
    }
  }
  if (stored.epoch > current_epoch) {
    if (reject_reason) *reject_reason = "future-epoch";
    return false;
  }
  if (stored.epoch != current_epoch && !allow_closed_epoch_reconcile) {
    if (reject_reason) *reject_reason = "wrong-open-epoch";
    return false;
  }
  if (allow_closed_epoch_reconcile && stored.epoch != current_epoch && !epoch_committee_closed_locked(stored.epoch)) {
    if (reject_reason) *reject_reason = "reconcile-nonclosed-epoch";
    return false;
  }
  if (allow_closed_epoch_reconcile && stored.epoch != current_epoch && epoch_committee_frozen_locked(stored.epoch)) {
    if (reject_reason) *reject_reason = "closed-frozen-readonly";
    return false;
  }
  if (stored.challenge_anchor != epoch_ticket_challenge_anchor_locked(stored.epoch)) {
    if (reject_reason) *reject_reason = "bad-anchor";
    return false;
  }
  if (!consensus::validate_epoch_ticket(stored)) {
    if (reject_reason) *reject_reason = "bad-work";
    return false;
  }
  const auto difficulty_bits =
      ticket_difficulty_bits_for_epoch_locked(stored.epoch, validators_.active_sorted(stored.epoch).size());
  if (!consensus::epoch_ticket_meets_difficulty(stored, difficulty_bits)) {
    if (reject_reason) *reject_reason = "below-difficulty";
    return false;
  }

  auto best = db_.load_best_epoch_tickets(stored.epoch);
  auto it = best.find(stored.participant_pubkey);
  const bool improved = it == best.end() || consensus::epoch_ticket_better(stored, it->second);
  if (!improved) {
    const bool allow_legacy_replay_override = allow_closed_epoch_reconcile;
    if (!allow_legacy_replay_override) {
      if (reject_reason) *reject_reason = "not-best";
      return false;
    }
  }

  (void)db_.put_epoch_ticket(stored);
  if (improved && !closed_epoch_reconcile_read_only) {
    // Consensus-critical: never let replay/reconcile of a worse ticket
    // overwrite best epoch ticket state, otherwise onboarding score units can
    // become message-order dependent and cause settlement commitment drift.
    best[stored.participant_pubkey] = stored;
    (void)db_.put_best_epoch_ticket(stored);
    const auto score_work_hash = stored.work_hash;
    const auto onboarding_score =
        static_cast<std::uint64_t>(std::max<std::uint8_t>(1, consensus::leading_zero_bits(score_work_hash)));
    auto& reward_state = epoch_reward_states_[stored.epoch];
    reward_state.epoch_start_height = stored.epoch;
    reward_state.onboarding_score_units[stored.participant_pubkey] = onboarding_score;
    if (canonical_state_.has_value()) {
      auto& canonical_reward_state = canonical_state_->epoch_reward_states[stored.epoch];
      canonical_reward_state.epoch_start_height = stored.epoch;
      canonical_reward_state.onboarding_score_units[stored.participant_pubkey] = onboarding_score;
      canonical_state_->state_commitment =
          consensus::consensus_state_commitment(canonical_derivation_config_locked(), *canonical_state_);
    }
  }
  if (!closed_epoch_reconcile_read_only) {
    auto snapshot = consensus::derive_epoch_committee_snapshot(stored.epoch, stored.challenge_anchor, best,
                                                               cfg_.max_committee, &validators_.all(), true);
    if (auto checkpoint = finalized_committee_checkpoint_for_height_locked(stored.epoch); checkpoint.has_value() &&
        !checkpoint->ordered_members.empty()) {
      snapshot = epoch_committee_snapshot_from_checkpoint(*checkpoint);
    }
    (void)db_.put_epoch_committee_snapshot(snapshot);
  }

  if (!from_network) {
    local_epoch_tickets_[stored.epoch] = stored;
  }
  (void)from_peer_id;
  return true;
}

bool Node::handle_epoch_ticket(const consensus::EpochTicket& ticket, bool from_network, int from_peer_id,
                               bool allow_closed_epoch_reconcile) {
  std::lock_guard<std::mutex> lk(mu_);
  std::string reject_reason;
  const bool accepted =
      handle_epoch_ticket_locked(ticket, from_network, from_peer_id, &reject_reason, allow_closed_epoch_reconcile);
  if (!accepted) {
    if (from_network && reject_reason == "bad-anchor") {
      const auto expected_anchor = epoch_ticket_challenge_anchor_locked(ticket.epoch);
      const auto checkpoint = finalized_committee_checkpoint_for_height_locked(ticket.epoch);
      const auto epoch_start = consensus::committee_epoch_start(ticket.epoch, cfg_.network.committee_epoch_blocks);
      const auto formula_anchor =
          consensus::committee_epoch_seed(committee_epoch_randomness_for_height_locked(ticket.epoch), epoch_start);
      log_line("epoch-ticket-anchor-mismatch peer_id=" + std::to_string(from_peer_id) +
               " epoch=" + std::to_string(ticket.epoch) + " participant=" + short_pub_hex(ticket.participant_pubkey) +
               " expected_anchor=" + short_hash_hex(expected_anchor) +
               " got_anchor=" + short_hash_hex(ticket.challenge_anchor) +
               " checkpoint_anchor=" +
               (checkpoint.has_value() ? short_hash_hex(checkpoint->epoch_seed) : std::string("none")) +
               " formula_anchor=" + short_hash_hex(formula_anchor) +
               " finalized_height=" + std::to_string(finalized_height_) +
               " current_epoch=" + std::to_string(current_epoch_ticket_epoch_locked()));
    }
    bool should_log = true;
    std::string suffix;
    if (from_network && reject_reason == "not-best") {
      const std::uint64_t tms = now_ms();
      auto& state = epoch_ticket_reject_log_state_[std::make_tuple(from_peer_id, ticket.epoch, reject_reason)];
      if (state.first != 0 && tms < state.first + kEpochTicketRejectLogIntervalMs) {
        ++state.second;
        should_log = false;
      } else {
        if (state.second != 0) suffix = " suppressed=" + std::to_string(state.second);
        state.first = tms;
        state.second = 0;
      }
    }
    if (should_log) {
      log_line("epoch-ticket-rejected peer_id=" + std::to_string(from_peer_id) + " epoch=" + std::to_string(ticket.epoch) +
               " participant=" + short_pub_hex(ticket.participant_pubkey) + " reason=" + reject_reason + suffix);
    }
  } else {
    log_line(std::string(from_network ? "epoch-ticket-recv-accepted" : "epoch-ticket-local-accepted") +
             " peer_id=" + std::to_string(from_peer_id) + " epoch=" + std::to_string(ticket.epoch) +
             " participant=" + short_pub_hex(ticket.participant_pubkey) + " work=" + short_hash_hex(ticket.work_hash));
  }
  return accepted;
}

void Node::on_epoch_ticket(int peer_id, const Bytes& payload) {
  constexpr std::uint16_t msg_type = p2p::MsgType::EPOCH_TICKET;
  auto t = p2p::de_epoch_ticket(payload);
  if (!t.has_value()) {
    score_peer(peer_id, p2p::MisbehaviorReason::INVALID_PAYLOAD, "bad-epoch-ticket");
    return;
  }
  {
    std::uint64_t peer_height = 0;
    std::uint64_t max_peer_height = 0;
    std::lock_guard<std::mutex> lk(mu_);
    if (!peer_is_fresh_for_epoch_reconcile_locked(peer_id, &peer_height, &max_peer_height)) {
      log_line("epoch-ticket-drop peer_id=" + std::to_string(peer_id) +
               " epoch=" + std::to_string(t->ticket.epoch) +
               " reason=peer-tip-stale-for-reconcile peer_height=" + std::to_string(peer_height) +
               " max_peer_height=" + std::to_string(max_peer_height));
      return;
    }
  }
  log_line("recv " + std::string(msg_type_name(msg_type)) + " peer_id=" + std::to_string(peer_id) +
           " epoch=" + std::to_string(t->ticket.epoch) + " participant=" + short_pub_hex(t->ticket.participant_pubkey));
  (void)handle_epoch_ticket(t->ticket, true, peer_id);
  return;
}

void Node::on_get_epoch_tickets(int peer_id, const Bytes& payload) {
  auto req = p2p::de_get_epoch_tickets(payload);
  if (!req.has_value()) {
    score_peer(peer_id, p2p::MisbehaviorReason::INVALID_PAYLOAD, "bad-get-epoch-tickets");
    return;
  }
  std::vector<consensus::EpochTicket> tickets;
  bool closed = false;
  {
    std::lock_guard<std::mutex> lk(mu_);
    const auto best_tickets = db_.load_best_epoch_tickets(req->epoch);
    if (!best_tickets.empty()) {
      tickets.reserve(best_tickets.size());
      for (const auto& [_, ticket] : best_tickets) tickets.push_back(ticket);
    } else {
      const auto all_tickets = db_.load_epoch_tickets(req->epoch);
      const auto best_by_pubkey = consensus::best_epoch_tickets_by_pubkey(all_tickets);
      tickets.reserve(best_by_pubkey.size());
      for (const auto& [_, ticket] : best_by_pubkey) tickets.push_back(ticket);
    }
    closed = epoch_committee_closed_locked(req->epoch);
  }
  const std::size_t limit = std::min<std::size_t>(tickets.size(), std::max<std::uint32_t>(1, req->max_tickets));
  tickets.resize(limit);
  const bool ok = p2p_.send_to(
      peer_id, p2p::MsgType::EPOCH_TICKETS, p2p::ser_epoch_tickets(p2p::EpochTicketsMsg{req->epoch, closed, tickets}));
  log_line("epoch-reconcile-response peer_id=" + std::to_string(peer_id) + " epoch=" + std::to_string(req->epoch) +
           " tickets=" + std::to_string(tickets.size()) + " closed=" + (closed ? "yes" : "no") +
           " status=" + (ok ? "ok" : "failed"));
  return;
}

void Node::on_epoch_tickets(int peer_id, const Bytes& payload) {
  auto resp = p2p::de_epoch_tickets(payload);
  if (!resp.has_value()) {
    score_peer(peer_id, p2p::MisbehaviorReason::INVALID_PAYLOAD, "bad-epoch-tickets");
    return;
  }
  {
    std::uint64_t peer_height = 0;
    std::uint64_t max_peer_height = 0;
    std::lock_guard<std::mutex> lk(mu_);
    if (!peer_is_fresh_for_epoch_reconcile_locked(peer_id, &peer_height, &max_peer_height)) {
      log_line("epoch-reconcile-drop peer_id=" + std::to_string(peer_id) +
               " epoch=" + std::to_string(resp->epoch) +
               " reason=peer-tip-stale-for-reconcile peer_height=" + std::to_string(peer_height) +
               " max_peer_height=" + std::to_string(max_peer_height));
      return;
    }
  }
  std::size_t accepted = 0;
  std::size_t rejected = 0;
  for (const auto& ticket : resp->tickets) {
    if (handle_epoch_ticket(ticket, true, peer_id, resp->epoch_closed)) {
      ++accepted;
    } else {
      ++rejected;
    }
  }
  if (resp->epoch_closed) {
    std::lock_guard<std::mutex> lk(mu_);
#ifdef _WIN32
    windows_settlement_epoch_reconcile_ms_[resp->epoch] = now_ms();
#endif
    const bool already_frozen = epoch_committee_frozen_locked(resp->epoch);
    const bool already_verified_snapshot = [&]() {
      auto checkpoint = finalized_committee_checkpoint_for_height_locked(resp->epoch);
      if (!checkpoint.has_value() || checkpoint->ordered_members.empty()) return false;
      auto existing = db_.get_epoch_committee_snapshot(resp->epoch);
      if (!existing.has_value()) return false;
      const auto expected = epoch_committee_snapshot_from_checkpoint(*checkpoint);
      return same_epoch_committee_snapshot(*existing, expected);
    }();
    if (already_frozen && already_verified_snapshot) {
      const std::uint64_t tms = now_ms();
      auto& state = epoch_reconcile_closed_rebuild_log_state_[resp->epoch];
      if (state.first != 0 && tms < state.first + kEpochReconcileClosedRebuildLogIntervalMs) {
        ++state.second;
      } else {
        std::string suffix;
        if (state.second != 0) suffix = " suppressed=" + std::to_string(state.second);
        state.first = tms;
        state.second = 0;
        log_line("epoch-reconcile-closed-skip epoch=" + std::to_string(resp->epoch) +
                 " reason=already-frozen-and-verified" + suffix);
      }
    } else {
      rebuild_epoch_committee_state_locked(resp->epoch, "reconcile-closed", true);
    }
  }
  bool should_log_reconcile = true;
  std::string reconcile_suffix;
  const bool repetitive_full_reject =
      !resp->epoch_closed && !resp->tickets.empty() && accepted == 0 && rejected == resp->tickets.size();
  if (repetitive_full_reject) {
    const std::uint64_t tms = now_ms();
    std::lock_guard<std::mutex> lk(mu_);
    auto& state = epoch_reconcile_reject_log_state_[std::make_pair(peer_id, resp->epoch)];
    if (state.first != 0 && tms < state.first + kEpochReconcileRejectLogIntervalMs) {
      ++state.second;
      should_log_reconcile = false;
    } else {
      if (state.second != 0) reconcile_suffix = " suppressed=" + std::to_string(state.second);
      state.first = tms;
      state.second = 0;
    }
  }
  if (should_log_reconcile) {
    log_line("epoch-reconcile-recv peer_id=" + std::to_string(peer_id) + " epoch=" + std::to_string(resp->epoch) +
             " tickets=" + std::to_string(resp->tickets.size()) + " accepted=" + std::to_string(accepted) +
             " rejected=" + std::to_string(rejected) + " closed=" + (resp->epoch_closed ? "yes" : "no") +
             reconcile_suffix);
  }
  return;
}

std::vector<PubKey32> Node::committee_for_height_round(std::uint64_t height, std::uint32_t round) const {
  if (height == finalized_height_ + 1) {
    if (canonical_state_.has_value()) {
      const auto canonical =
          consensus::canonical_committee_for_height_round(canonical_derivation_config_locked(), *canonical_state_, height, round);
      if (!canonical.empty()) return canonical;
    }
    return epoch_committee_for_next_height_locked(height, round);
  }

  if (height == 0 || height > finalized_height_ + 1) return {};
  if (auto cert = db_.get_finality_certificate_by_height(height); cert.has_value()) {
    if (auto checkpoint = finalized_committee_checkpoint_for_height_locked(height); checkpoint.has_value()) {
      if (!certificate_matches_checkpoint_committee(*cert, *checkpoint)) {
        log_line("finalized-state-invariant-violation source=persisted-committee-checkpoint-mismatch height=" +
                 std::to_string(height));
        return {};
      }
    }
    return cert->committee_members;
  }
  return {};
}

std::optional<PubKey32> Node::leader_for_height_round(std::uint64_t height, std::uint32_t round) const {
  if (height == finalized_height_ + 1) {
    if (canonical_state_.has_value()) {
      if (auto canonical =
              consensus::canonical_leader_for_height_round(canonical_derivation_config_locked(), *canonical_state_, height, round);
          canonical.has_value()) {
        return canonical;
      }
    }
    return epoch_leader_for_next_height_locked(height, round);
  }

  if (height == 0 || height > finalized_height_ + 1) return std::nullopt;
  if (auto checkpoint = finalized_committee_checkpoint_for_height_locked(height); checkpoint.has_value()) {
    if (auto cert = db_.get_finality_certificate_by_height(height); cert.has_value()) {
      if (!certificate_matches_checkpoint_committee(*cert, *checkpoint)) {
        log_line("finalized-state-invariant-violation source=persisted-proposer-checkpoint-mismatch height=" +
                 std::to_string(height));
        return std::nullopt;
      }
    }
    if (canonical_state_.has_value()) {
      std::string error;
      if (!consensus::validate_checkpoint_schedule_for_height(canonical_derivation_config_locked(), *canonical_state_,
                                                              *checkpoint, height, &error)) {
        log_line("finalized-state-invariant-violation source=persisted-proposer-schedule-invalid height=" +
                 std::to_string(height) + " detail=" + error);
        return std::nullopt;
      }
    }
    if (auto leader = leader_from_checkpoint(cfg_.network, validators_, *checkpoint, height, round); leader.has_value()) {
      return leader;
    }
  }
  return std::nullopt;
}

bool Node::is_committee_member_for(const PubKey32& pub, std::uint64_t height, std::uint32_t round) const {
  const auto committee = committee_for_height_round(height, round);
  return std::find(committee.begin(), committee.end(), pub) != committee.end();
}

std::size_t Node::active_operator_count_for_height_locked(std::uint64_t height) const {
  std::set<PubKey32> operators;
  for (const auto& [pub, info] : validators_.all()) {
    if (!validators_.is_active_for_height(pub, height)) continue;
    operators.insert(info.operator_id == PubKey32{} ? pub : info.operator_id);
  }
  return operators.size();
}

}  // namespace finalis::node
