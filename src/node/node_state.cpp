// SPDX-License-Identifier: MIT

// Finalized-state persistence and startup: genesis loading, load_state() (fast-start cache, frontier
// replay and tail repair, cache verification), frontier record persistence and runtime hydration.

#include <iostream>

#include "codec/bytes.hpp"
#include "common/wide_arith.hpp"
#include "crypto/hash.hpp"
#include "genesis/embedded_mainnet.hpp"
#include "node.hpp"
#include "node_internal.hpp"

namespace finalis::node {
using namespace detail;

namespace {

constexpr const char* kStartupReplayModeKey = "REPLAY:MODE";

std::optional<Hash32> parse_transition_hash_from_error(const std::string& error) {
  const std::string marker = "transition=";
  const auto pos = error.find(marker);
  if (pos == std::string::npos) return std::nullopt;
  const std::size_t start = pos + marker.size();
  if (start + 64 > error.size()) return std::nullopt;
  const auto hex = error.substr(start, 64);
  auto bytes = hex_decode(hex);
  if (!bytes.has_value() || bytes->size() != 32) return std::nullopt;
  Hash32 out{};
  std::copy(bytes->begin(), bytes->end(), out.begin());
  return out;
}

std::optional<std::uint64_t> parse_height_from_error(const std::string& error) {
  const std::string marker = "height=";
  const auto pos = error.find(marker);
  if (pos == std::string::npos) return std::nullopt;
  const std::size_t start = pos + marker.size();
  std::size_t end = start;
  while (end < error.size() && error[end] >= '0' && error[end] <= '9') ++end;
  if (end == start) return std::nullopt;
  try {
    return static_cast<std::uint64_t>(std::stoull(error.substr(start, end - start)));
  } catch (...) {
    return std::nullopt;
  }
}

std::uint64_t compute_startup_frontier_repair_cap(const NodeConfig& cfg, std::uint64_t frontier_tip_height) {
  const std::uint64_t base_cap = std::max<std::uint64_t>(1, cfg.startup_frontier_repair_max_rollback);
  const std::uint64_t abs_cap =
      std::max<std::uint64_t>(base_cap, cfg.startup_frontier_repair_absolute_max_rollback);
  std::uint64_t adaptive_cap = base_cap;
  if (cfg.startup_frontier_repair_adaptive_percent > 0 && frontier_tip_height > 0) {
    const auto pct_wide = wide::mul_u64(frontier_tip_height, cfg.startup_frontier_repair_adaptive_percent);
    std::uint64_t pct_cap = wide::div_u64(pct_wide, 100);  // floor(tip * percent / 100)
    // ceil(tip * percent / 100) without compiler-specific 128-bit arithmetic.
    if (wide::compare_mul_u64(pct_cap, 100, frontier_tip_height, cfg.startup_frontier_repair_adaptive_percent) < 0 &&
        pct_cap < std::numeric_limits<std::uint64_t>::max()) {
      ++pct_cap;
    }
    adaptive_cap = std::max<std::uint64_t>(adaptive_cap, pct_cap);
  }
  return std::min<std::uint64_t>(adaptive_cap, abs_cap);
}

std::uint64_t compute_startup_frontier_repair_floor(storage::DB& db, std::uint64_t frontier_tip_height) {
  std::uint64_t floor_height = 0;

  auto bounded_floor_candidate = [&](std::uint64_t epoch_start_height) {
    if (epoch_start_height == 0) return;
    const std::uint64_t candidate = epoch_start_height - 1;
    // Never let future/non-finalized epoch cache rows force rollback floor above
    // the locally finalized frontier tip.
    if (candidate > frontier_tip_height) return;
    floor_height = std::max<std::uint64_t>(floor_height, candidate);
  };

  const auto checkpoints = db.load_finalized_committee_checkpoints();
  if (!checkpoints.empty()) {
    const auto max_epoch_start = checkpoints.rbegin()->first;
    bounded_floor_candidate(max_epoch_start);
  }

  const auto snapshots = db.load_epoch_committee_snapshots();
  if (!snapshots.empty()) {
    const auto max_epoch_start = snapshots.rbegin()->first;
    bounded_floor_candidate(max_epoch_start);
  }

  const auto freeze_markers = db.load_epoch_committee_freeze_markers();
  if (!freeze_markers.empty()) {
    const auto max_epoch_start = freeze_markers.rbegin()->first;
    bounded_floor_candidate(max_epoch_start);
  }

  return floor_height;
}

bool rollback_frontier_tail_from_transition(storage::DB& db, const Hash32& bad_transition_id,
                                            std::uint64_t max_rollback_blocks, std::uint64_t rollback_floor_height,
                                            std::uint64_t* bad_height,
                                            std::uint64_t* new_tip_height, std::string* error) {
  const auto maybe_max_frontier = db.get_finalized_frontier_height();
  if (!maybe_max_frontier.has_value()) {
    if (error) *error = "missing-finalized-frontier-height";
    return false;
  }
  const std::uint64_t max_frontier = *maybe_max_frontier;
  std::optional<std::uint64_t> matched_height;
  for (std::uint64_t h = max_frontier; h >= 1; --h) {
    auto id = db.get_frontier_transition_by_height(h);
    if (id.has_value() && *id == bad_transition_id) {
      matched_height = h;
      break;
    }
    if (h == 1) break;
  }
  if (!matched_height.has_value()) {
    if (error) *error = "bad-transition-height-not-found";
    return false;
  }
  const std::uint64_t bad_h = *matched_height;
  if (max_frontier < bad_h) {
    if (error) *error = "invalid-frontier-range";
    return false;
  }
  const std::uint64_t rollback_count = max_frontier - bad_h + 1;
  if (rollback_count > std::max<std::uint64_t>(1, max_rollback_blocks)) {
    if (error) {
      *error = "rollback-cap-exceeded need=" + std::to_string(rollback_count) +
               " cap=" + std::to_string(max_rollback_blocks);
    }
    return false;
  }
  const std::uint64_t repaired_tip = bad_h - 1;
  if (repaired_tip < rollback_floor_height) {
    if (error) {
      *error = "rollback-floor-breached requested_new_tip=" + std::to_string(repaired_tip) +
               " floor=" + std::to_string(rollback_floor_height) +
               " bad_height=" + std::to_string(bad_h) +
               " current_tip=" + std::to_string(max_frontier);
    }
    return false;
  }

  for (std::uint64_t h = max_frontier; h >= bad_h; --h) {
    const auto transition_id = db.get_frontier_transition_by_height(h);
    if (transition_id.has_value()) {
      (void)db.erase(storage::key_frontier_transition(*transition_id));
    }
    (void)db.erase(storage::key_frontier_height(h));
    (void)db.erase(storage::key_finality_certificate_height(h));
    (void)db.erase(storage::key_height(h));
    if (h == bad_h) break;
  }

  (void)db.erase(storage::key_finalized_frontier_height());
  if (!db.set_finalized_frontier_height(repaired_tip)) {
    if (error) *error = "set-finalized-frontier-height-failed";
    return false;
  }

  Hash32 tip_hash = zero_hash();
  std::uint64_t repaired_ingress_tip = 0;
  if (repaired_tip > 0) {
    auto id = db.get_frontier_transition_by_height(repaired_tip);
    if (!id.has_value()) {
      if (error) *error = "repaired-tip-transition-missing";
      return false;
    }
    tip_hash = *id;
    if (!db.set_height_hash(repaired_tip, tip_hash)) {
      if (error) *error = "set-height-hash-failed";
      return false;
    }
    auto transition_bytes = db.get_frontier_transition(*id);
    if (!transition_bytes.has_value()) {
      if (error) *error = "repaired-tip-transition-bytes-missing";
      return false;
    }
    auto transition = FrontierTransition::parse(*transition_bytes);
    if (!transition.has_value()) {
      if (error) *error = "repaired-tip-transition-parse-failed";
      return false;
    }
    repaired_ingress_tip = transition->next_frontier;
  }
  if (!db.force_set_finalized_ingress_tip(repaired_ingress_tip)) {
    if (error) *error = "force-set-finalized-ingress-tip-failed";
    return false;
  }
  if (!db.set_tip(storage::TipState{repaired_tip, tip_hash})) {
    if (error) *error = "set-tip-failed";
    return false;
  }
  if (!db.flush()) {
    if (error) *error = "flush-failed";
    return false;
  }
  if (bad_height) *bad_height = bad_h;
  if (new_tip_height) *new_tip_height = repaired_tip;
  return true;
}

bool same_utxos(const UtxoSetV2& a, const UtxoSetV2& b) {
  if (a.size() != b.size()) return false;
  auto ita = a.begin();
  auto itb = b.begin();
  for (; ita != a.end(); ++ita, ++itb) {
    if (ita->first.txid != itb->first.txid || ita->first.index != itb->first.index || ita->second != itb->second) {
      return false;
    }
  }
  return true;
}

bool same_consensus_state_commitment_cache(const storage::ConsensusStateCommitmentCache& a,
                                           const storage::ConsensusStateCommitmentCache& b) {
  return a.height == b.height && a.hash == b.hash && a.commitment == b.commitment;
}

bool replay_mode_is_frontier(const Bytes& bytes) { return std::string(bytes.begin(), bytes.end()) == "frontier"; }

bool load_trusted_runtime_checkpoint_from_cache(const consensus::CanonicalDerivationConfig& cfg, storage::DB& db,
                                                std::uint64_t finalized_height, const Hash32& finalized_hash,
                                                consensus::CanonicalDerivedState* out, std::string* error,
                                                bool trust_lane_state_roots = false,
                                                bool allow_commitment_cache_mismatch = false) {
  if (!out) {
    if (error) *error = "null-output";
    return false;
  }
  if (finalized_height == 0) {
    if (error) *error = "no-finalized-height";
    return false;
  }

  auto transition_bytes = db.get_frontier_transition(finalized_hash);
  if (!transition_bytes.has_value()) {
    if (error) *error = "checkpoint-tip-transition-missing";
    return false;
  }
  auto transition = FrontierTransition::parse(*transition_bytes);
  if (!transition.has_value()) {
    if (error) *error = "checkpoint-tip-transition-parse-failed";
    return false;
  }
  if (transition->height != finalized_height) {
    if (error) *error = "checkpoint-tip-height-mismatch";
    return false;
  }

  consensus::CanonicalDerivedState state;
  state.finalized_height = finalized_height;
  state.finalized_identity = consensus::FinalizedIdentity::transition(finalized_hash);
  state.finalized_frontier = transition->next_frontier;
  state.finalized_frontier_vector = transition->next_vector;
  state.finalized_lane_roots = consensus::FrontierLaneRoots{};
  for (std::uint32_t lane = 0; lane < INGRESS_LANE_COUNT; ++lane) {
    const std::uint64_t max_seq = state.finalized_frontier_vector.lane_max_seq[lane];
    if (trust_lane_state_roots) {
      auto lane_state = db.get_lane_state(lane);
      const std::uint64_t lane_tip = lane_state.has_value() ? lane_state->max_seq : 0;
      if (lane_tip < max_seq) {
        if (error) {
          *error = "checkpoint-lane-state-tip-too-low lane=" + std::to_string(lane) +
                   " lane_tip=" + std::to_string(lane_tip) + " expected=" + std::to_string(max_seq);
        }
        return false;
      }
      state.finalized_lane_roots[lane] = lane_state.has_value() ? lane_state->lane_root : zero_hash();
      continue;
    }
    Hash32 lane_root = zero_hash();
    for (std::uint64_t seq = 1; seq <= max_seq; ++seq) {
      auto cert_bytes = db.get_ingress_certificate(lane, seq);
      if (!cert_bytes.has_value()) {
        if (error) {
          *error = "checkpoint-lane-root-rebuild-missing-certificate lane=" + std::to_string(lane) +
                   " seq=" + std::to_string(seq);
        }
        return false;
      }
      auto cert = IngressCertificate::parse(*cert_bytes);
      if (!cert.has_value()) {
        if (error) {
          *error = "checkpoint-lane-root-rebuild-invalid-certificate lane=" + std::to_string(lane) +
                   " seq=" + std::to_string(seq);
        }
        return false;
      }
      if (cert->lane != lane || cert->seq != seq) {
        if (error) {
          *error = "checkpoint-lane-root-rebuild-certificate-index-mismatch lane=" + std::to_string(lane) +
                   " seq=" + std::to_string(seq);
        }
        return false;
      }
      if (cert->prev_lane_root != lane_root) {
        if (error) {
          *error = "checkpoint-lane-root-rebuild-prev-root-mismatch lane=" + std::to_string(lane) +
                   " seq=" + std::to_string(seq);
        }
        return false;
      }
      lane_root = consensus::compute_lane_root_append(lane_root, cert->tx_hash);
    }
    state.finalized_lane_roots[lane] = lane_root;
  }

  state.utxos = db.load_utxos_v2();
  state.validators.mutable_all() = db.load_validators();
  state.validator_join_requests = db.load_validator_join_requests();
  state.epoch_reward_states = db.load_epoch_reward_settlements();
  state.finalized_committee_checkpoints = db.load_finalized_committee_checkpoints();

  if (auto reserve = db.get_protocol_reserve_balance(); reserve.has_value()) {
    state.protocol_reserve_balance_units = *reserve;
  }
  if (auto persisted_randomness = db.get(kFinalizedRandomnessKey);
      persisted_randomness.has_value() && persisted_randomness->size() == 32) {
    std::copy(persisted_randomness->begin(), persisted_randomness->end(), state.finalized_randomness.begin());
  } else {
    state.finalized_randomness = consensus::initial_finalized_randomness(cfg.network, cfg.chain_id);
  }
  if (auto availability = db.get_availability_persistent_state(); availability.has_value()) {
    state.availability_state = *availability;
  }

  // Frontier replay chains prev_finality_link_hash against the finalized
  // transition-derived link hash, not the serialized finality certificate hash.
  state.last_finality_certificate_hash = consensus::frontier_finality_link_hash(*transition);
  if (auto cert = db.get_finality_certificate_by_height(finalized_height); cert.has_value()) {
    state.finalized_block_metadata[finalized_height] =
        consensus::CanonicalFinalizedMetadata{cert->round, cert->quorum_threshold,
                                              static_cast<std::uint32_t>(cert->signatures.size())};
  }

  if (auto b = db.get(kValidatorJoinWindowStartKey); b.has_value()) {
    codec::parse_exact(*b, [&](codec::ByteReader& r) {
      auto v = r.u64le();
      if (!v.has_value()) return false;
      state.validator_join_window_start_height = *v;
      return true;
    });
  }
  if (auto b = db.get(kValidatorJoinWindowCountKey); b.has_value()) {
    codec::parse_exact(*b, [&](codec::ByteReader& r) {
      auto v = r.u32le();
      if (!v.has_value()) return false;
      state.validator_join_count_in_window = *v;
      return true;
    });
  }
  if (auto b = db.get(kValidatorLivenessWindowStartKey); b.has_value()) {
    codec::parse_exact(*b, [&](codec::ByteReader& r) {
      auto v = r.u64le();
      if (!v.has_value()) return false;
      state.validator_liveness_window_start_height = *v;
      return true;
    });
  }

  state.state_commitment = consensus::consensus_state_commitment(cfg, state);
  if (auto persisted = db.get_consensus_state_commitment_cache(); persisted.has_value()) {
    if (persisted->height != state.finalized_height || persisted->hash != state.finalized_identity.id ||
        persisted->commitment != state.state_commitment) {
      if (!allow_commitment_cache_mismatch) {
        if (error) *error = "checkpoint-commitment-cache-mismatch";
        return false;
      }
    }
  }

  *out = std::move(state);
  return true;
}

}  // namespace

bool Node::refresh_runtime_from_frontier_storage_locked(const char* reason, std::string* error) {
  auto genesis_json = db_.get(storage::key_genesis_json());
  if (!genesis_json.has_value()) {
    if (error) *error = "missing-genesis-json";
    return false;
  }
  const std::string js(genesis_json->begin(), genesis_json->end());
  auto genesis_doc = genesis::parse_json(js);
  if (!genesis_doc.has_value()) {
    if (error) *error = "invalid-genesis-json";
    return false;
  }

  consensus::CanonicalGenesisState genesis_state;
  genesis_state.genesis_artifact_id = genesis::block_id(*genesis_doc);
  if (auto stored_genesis_artifact = db_.get(storage::key_genesis_artifact());
      stored_genesis_artifact.has_value() && stored_genesis_artifact->size() == 32) {
    std::copy(stored_genesis_artifact->begin(), stored_genesis_artifact->end(), genesis_state.genesis_artifact_id.begin());
  }
  genesis_state.initial_validators = genesis_doc->initial_validators;
  if (bootstrap_template_mode_ && finalized_height_ == 0 && bootstrap_validator_pubkey_.has_value()) {
    genesis_state.initial_validators = {*bootstrap_validator_pubkey_};
  }

  const auto derivation_cfg = canonical_derivation_config_locked();
  consensus::CanonicalDerivedState canonical_genesis_state;
  std::string canonical_error;
  if (!consensus::build_genesis_canonical_state(derivation_cfg, genesis_state, &canonical_genesis_state, &canonical_error)) {
    if (error) *error = "canonical-genesis-failed:" + canonical_error;
    return false;
  }

  consensus::CanonicalDerivedState derived_state;
  std::string derivation_error;
  if (!consensus::derive_canonical_state_from_frontier_storage(derivation_cfg, canonical_genesis_state, db_, &derived_state,
                                                               &derivation_error)) {
    if (error) *error = "frontier-derive-failed:" + derivation_error;
    return false;
  }
  if (derived_state.finalized_height != finalized_height_ || derived_state.finalized_identity.id != finalized_identity_.id) {
    if (error) {
      *error = "frontier-derive-tip-mismatch local_height=" + std::to_string(finalized_height_) +
               " derived_height=" + std::to_string(derived_state.finalized_height);
    }
    return false;
  }

  hydrate_runtime_from_canonical_state_locked(derived_state);
  log_line(std::string("canonical-runtime-refresh source=") + reason + " height=" + std::to_string(finalized_height_) +
           " finalized_frontier=" + std::to_string(canonical_state_->finalized_frontier) + " vector_total=" +
           std::to_string(canonical_state_->finalized_frontier_vector.total_count()));
  return true;
}

bool Node::persist_finalized_frontier_record(const consensus::CanonicalFrontierRecord& record, const UtxoSetV2& prev_utxos,
                                             storage::DB::Batch& batch, std::string* error) {
  auto fail = [&](const std::string& reason) {
    if (error) *error = reason;
    return false;
  };
  if (record.transition.next_frontier !=
      record.transition.prev_frontier + static_cast<std::uint64_t>(record.ordered_records.size())) {
    log_line("finalized-state-invariant-violation source=runtime-write-frontier-continuity height=" +
             std::to_string(record.transition.height));
    return fail("frontier-continuity-mismatch");
  }

  std::uint64_t seq = record.transition.prev_frontier;
  std::uint32_t tx_index = 0;
  for (const auto& ordered_record : record.ordered_records) {
    ++seq;
    if (!batch.put_ingress_record(seq, ordered_record)) return fail("put-ingress-record-failed seq=" + std::to_string(seq));
    auto tx = parse_any_tx(ordered_record);
    if (!tx.has_value()) {
      log_line("finalized-state-invariant-violation source=runtime-write-frontier-tx-parse height=" +
               std::to_string(record.transition.height));
      return fail("ordered-record-tx-parse-failed seq=" + std::to_string(seq));
    }
    const Hash32 txid = txid_any(*tx);
    batch.put_tx_index(txid, record.transition.height, tx_index++, ordered_record);
    if (std::holds_alternative<Tx>(*tx)) {
      const auto& legacy = std::get<Tx>(*tx);
      for (const auto& input : legacy.inputs) {
        const auto prev_it = prev_utxos.find(OutPoint{input.prev_txid, input.prev_index});
        if (prev_it == prev_utxos.end()) continue;
        const auto spent_out = transparent_txout_from_utxo_entry(prev_it->second);
        if (!spent_out.has_value()) continue;
        const auto spent_scripthash = crypto::sha256(spent_out->script_pubkey);
        batch.add_script_history(spent_scripthash, record.transition.height, txid);
      }
      for (const auto& output : legacy.outputs) {
        const auto received_scripthash = crypto::sha256(output.script_pubkey);
        batch.add_script_history(received_scripthash, record.transition.height, txid);
      }
    }
  }
  // DB::set_finalized_ingress_tip's monotonicity check, replicated here: a
  // staged write can't read-then-conditionally-write against uncommitted
  // batch state, so the decision (force-rewind vs. fail) has to happen before
  // staging, against committed db_ state, exactly as it did before batching.
  if (auto existing_ingress_tip = db_.get_finalized_ingress_tip();
      existing_ingress_tip.has_value() && *existing_ingress_tip > record.transition.next_frontier) {
    const bool can_force_rewind = record.transition.height == finalized_height_ + 1;
    if (!can_force_rewind) return fail("set-finalized-ingress-tip-failed");
    log_line("finalized-ingress-tip-rewind-forced height=" + std::to_string(record.transition.height) +
             " existing=" + std::to_string(*existing_ingress_tip) +
             " target=" + std::to_string(record.transition.next_frontier));
  }
  batch.stage_finalized_ingress_tip(record.transition.next_frontier);
  if (!batch.put_frontier_transition(record.transition.transition_id(), record.transition.serialize())) {
    return fail("put-frontier-transition-failed transition=" + short_hash_hex(record.transition.transition_id()));
  }
  if (!batch.map_height_to_frontier_transition(record.transition.height, record.transition.transition_id())) {
    return fail("map-height-to-frontier-transition-failed height=" + std::to_string(record.transition.height));
  }
  if (!batch.set_finalized_frontier_height(record.transition.height)) return fail("set-finalized-frontier-height-failed");
  if (!batch.set_height_hash(record.transition.height, record.transition.transition_id())) {
    return fail("set-height-hash-failed height=" + std::to_string(record.transition.height));
  }
  batch.set_tip(storage::TipState{record.transition.height, record.transition.transition_id()});
  batch.put(kStartupReplayModeKey, Bytes{'f', 'r', 'o', 'n', 't', 'i', 'e', 'r'});
  if (error) error->clear();
  return true;
}

void Node::hydrate_runtime_from_canonical_state_locked(const consensus::CanonicalDerivedState& state) {
  canonical_state_ = state;
  finalized_height_ = state.finalized_height;
  finalized_identity_ = state.finalized_identity;
  utxos_ = state.utxos;
  validators_ = state.validators;
  std::size_t repaired_count = 0;
  repaired_count +=
      repair_invalid_exiting_zero_bond_outpoints(&validators_, state.finalized_height, cfg_.network.unbond_delay_blocks,
                                                 [this](const std::string& s) { log_line(s); });
  repaired_count +=
      repair_matured_bootstrap_exiting_records(cfg_.network, &validators_, state.finalized_height,
                                               cfg_.network.unbond_delay_blocks,
                                               [this](const std::string& s) { log_line(s); });
  if (repaired_count > 0) {
    for (const auto& [pub, info] : validators_.all()) (void)db_.put_validator(pub, info);
    if (canonical_state_.has_value()) canonical_state_->validators = validators_;
    log_line("validator-repair-persisted source=hydrate repaired=" + std::to_string(repaired_count) +
             " finalized_height=" + std::to_string(state.finalized_height));
  }
  validator_join_requests_ = state.validator_join_requests;
  finalized_randomness_ = state.finalized_randomness;
  committee_epoch_randomness_cache_ = state.committee_epoch_randomness_cache;
  protocol_reserve_balance_units_ = state.protocol_reserve_balance_units;
  epoch_reward_states_ = state.epoch_reward_states;
  finalized_committee_checkpoints_ = state.finalized_committee_checkpoints;
  validator_join_window_start_height_ = state.validator_join_window_start_height;
  validator_join_count_in_window_ = state.validator_join_count_in_window;
  validator_liveness_window_start_height_ = state.validator_liveness_window_start_height;
  last_participation_eligible_signers_ = state.last_participation_eligible_signers;
  availability_state_ = state.availability_state;
}

bool Node::init_mainnet_genesis() {
  const bool use_embedded = cfg_.genesis_path.empty();
  std::string err;
  std::optional<genesis::Document> doc;
  Hash32 ghash{};
  if (use_embedded) {
    const Bytes bin(genesis::MAINNET_GENESIS_BIN, genesis::MAINNET_GENESIS_BIN + genesis::MAINNET_GENESIS_BIN_LEN);
    doc = genesis::decode_bin(bin, &err);
    if (doc.has_value()) ghash = genesis::hash_bin(bin);
  } else {
    doc = genesis::load_from_path(cfg_.genesis_path, &err);
    if (doc.has_value()) ghash = genesis::hash_doc(*doc);
  }
  if (!doc.has_value()) {
    std::cerr << "genesis load failed: " << err << "\n";
    return false;
  }
  bootstrap_template_mode_ = (!use_embedded && doc->initial_validators.empty());
  if (!genesis::validate_document(*doc, cfg_.network, &err, bootstrap_template_mode_ ? 0 : 1)) {
    std::cerr << "genesis validation failed: " << err << "\n";
    return false;
  }
  if (use_embedded && ghash != genesis::MAINNET_GENESIS_HASH) {
    std::cerr << "embedded genesis hash mismatch; binary may be corrupted\n";
    return false;
  }
  expected_genesis_hash_ = ghash;

  const Bytes ghash_b(ghash.begin(), ghash.end());
  const Hash32 gblock = genesis::block_id(*doc);
  const Bytes gblock_b(gblock.begin(), gblock.end());
  const auto stored = db_.get(storage::key_genesis_hash());
  if (stored.has_value()) {
    if (stored->size() != 32 || !std::equal(stored->begin(), stored->end(), ghash_b.begin())) {
      std::cerr << "genesis mismatch against existing database\n";
      return false;
    }
    if (!db_.get(storage::key_genesis_json()).has_value()) {
      const auto json = genesis::to_json(*doc);
      (void)db_.put(storage::key_genesis_json(), Bytes(json.begin(), json.end()));
    }
    if (bootstrap_template_mode_) {
      const auto all = db_.scan_prefix(storage::key_validator_prefix());
      if (all.size() == 1) {
        const auto& key = all.begin()->first;
        if (key.size() > 2) {
          auto b = hex_decode(key.substr(2));
          if (b && b->size() == 32) {
            PubKey32 pub{};
            std::copy(b->begin(), b->end(), pub.begin());
            bootstrap_validator_pubkey_ = pub;
          }
        }
      }
    }
    const auto tip = db_.get_tip();
  if (tip.has_value() && tip->height == 0 && tip->hash != gblock) {
    std::cerr << "genesis block id mismatch against existing database tip\n";
    return false;
  }
  availability_state_ = {};
  availability_state_.current_epoch = current_epoch_ticket_epoch_locked();
  return true;
}

  if (!db_.put(storage::key_genesis_hash(), ghash_b)) return false;
  if (!db_.put(storage::key_genesis_artifact(), gblock_b)) return false;
  {
    const auto json = genesis::to_json(*doc);
    if (!db_.put(storage::key_genesis_json(), Bytes(json.begin(), json.end()))) return false;
  }
  auto tip = db_.get_tip();
  if (!tip.has_value()) {
    if (!db_.set_tip(storage::TipState{0, gblock})) return false;
  } else if (!(tip->height == 0 && tip->hash == zero_hash()) && tip->height != 0) {
    std::cerr << "existing non-empty database is missing genesis marker\n";
    return false;
  } else if (tip->height == 0 && tip->hash == zero_hash()) {
    if (!db_.set_tip(storage::TipState{0, gblock})) return false;
  } else if (tip->height == 0 && tip->hash != gblock) {
    std::cerr << "height-0 tip does not match provided genesis\n";
    return false;
  }

  for (const auto& pub : doc->initial_validators) {
    consensus::ValidatorInfo vi;
    vi.status = consensus::ValidatorStatus::ACTIVE;
    vi.joined_height = 0;
    vi.bonded_amount = consensus::genesis_validator_bond_amount();
    vi.operator_id = pub;
    vi.has_bond = true;
    vi.bond_outpoint = OutPoint{zero_hash(), 0};
    vi.unbond_height = 0;
    if (!db_.put_validator(pub, vi)) return false;
  }
  {
    consensus::ValidatorRegistry vr;
    for (const auto& pub : doc->initial_validators) {
      consensus::ValidatorInfo vi;
      vi.status = consensus::ValidatorStatus::ACTIVE;
      vi.joined_height = 0;
      vi.bonded_amount = consensus::genesis_validator_bond_amount();
      vi.operator_id = pub;
      vi.has_bond = true;
      vi.bond_outpoint = OutPoint{zero_hash(), 0};
      vi.unbond_height = 0;
      vr.upsert(pub, vi);
    }
    const UtxoSetV2 empty_utxos;
    (void)persist_state_roots(db_, 0, empty_utxos, vr, kFixedValidationRulesVersion);
  }
  {
    codec::ByteWriter w0;
    w0.u64le(0);
    (void)db_.put(kValidatorJoinWindowStartKey, w0.take());
    codec::ByteWriter w1;
    w1.u32le(0);
    (void)db_.put(kValidatorJoinWindowCountKey, w1.take());
    codec::ByteWriter w2;
    w2.u64le(0);
    (void)db_.put(kValidatorLivenessWindowStartKey, w2.take());
  }
  chain_id_ =
      ChainId::from_config_and_db(cfg_.network, db_, std::nullopt, genesis_source_hint_, expected_genesis_hash_);
  consensus::CanonicalGenesisState genesis_state;
  genesis_state.genesis_artifact_id = gblock;
  genesis_state.initial_validators = doc->initial_validators;
  consensus::CanonicalDerivedState canonical_genesis_state;
  std::string canonical_error;
  if (!consensus::build_genesis_canonical_state(canonical_derivation_config_locked(), genesis_state,
                                                &canonical_genesis_state, &canonical_error)) {
    std::cerr << "canonical genesis derivation failed: " << canonical_error << "\n";
    return false;
  }
  finalized_randomness_ = canonical_genesis_state.finalized_randomness;
  committee_epoch_randomness_cache_ = canonical_genesis_state.committee_epoch_randomness_cache;
  protocol_reserve_balance_units_ = canonical_genesis_state.protocol_reserve_balance_units;
  finalized_committee_checkpoints_ = canonical_genesis_state.finalized_committee_checkpoints;
  epoch_reward_states_ = canonical_genesis_state.epoch_reward_states;
  canonical_state_ = canonical_genesis_state;
  if (!persist_canonical_cache_rows(db_, canonical_genesis_state)) return false;
  if (!verify_and_persist_consensus_state_commitment_locked(canonical_genesis_state)) return false;
  return db_.flush();
}

bool Node::load_state() {
  log_line("startup-progress phase=load-state-start");
  auto tip = db_.get_tip();
  if (!tip.has_value()) {
    finalized_height_ = 0;
    finalized_identity_ = finalized_identity_for_runtime_tip(0, zero_hash());
    db_.set_tip(storage::TipState{0, finalized_identity_.id});
  } else {
    finalized_height_ = tip->height;
    finalized_identity_ = finalized_identity_for_runtime_tip(tip->height, tip->hash);
    if (finalized_height_ > 0) {
      auto indexed = db_.get_height_hash(finalized_height_);
      if (!indexed.has_value() || *indexed != finalized_identity_.id) {
        log_line("finalized-state-invariant-violation source=load-state-tip height=" +
                 std::to_string(finalized_height_) + " existing_transition=" +
                 (indexed.has_value() ? hex_encode(Bytes(indexed->begin(), indexed->end())) : std::string("missing")) +
                 " conflicting_transition=" + hex_encode(Bytes(finalized_identity_.id.begin(), finalized_identity_.id.end())));
        return false;
      }
    }
  }

  auto genesis_json = db_.get(storage::key_genesis_json());
  if (!genesis_json.has_value()) {
    log_line("finalized-state-invariant-violation source=load-state-missing-genesis-json");
    std::cerr << "load_state: missing genesis json\n";
    return false;
  }
  const std::string js(genesis_json->begin(), genesis_json->end());
  auto genesis_doc = genesis::parse_json(js);
  if (!genesis_doc.has_value()) {
    log_line("finalized-state-invariant-violation source=load-state-invalid-genesis-json");
    std::cerr << "load_state: invalid genesis json\n";
    return false;
  }
  consensus::CanonicalGenesisState genesis_state;
  genesis_state.genesis_artifact_id = genesis::block_id(*genesis_doc);
  if (auto stored_genesis_artifact = db_.get(storage::key_genesis_artifact());
      stored_genesis_artifact.has_value() && stored_genesis_artifact->size() == 32) {
    std::copy(stored_genesis_artifact->begin(), stored_genesis_artifact->end(), genesis_state.genesis_artifact_id.begin());
  }
  genesis_state.initial_validators = genesis_doc->initial_validators;
  if (bootstrap_template_mode_ && finalized_height_ == 0 && bootstrap_validator_pubkey_.has_value()) {
    genesis_state.initial_validators = {*bootstrap_validator_pubkey_};
  }

  const auto stored_replay_mode_bytes = db_.get(kStartupReplayModeKey);
  if (stored_replay_mode_bytes.has_value() && !replay_mode_is_frontier(*stored_replay_mode_bytes)) {
    log_line("finalized-state-invariant-violation source=load-state-invalid-replay-mode");
    std::cerr << "load_state: invalid replay mode\n";
    return false;
  }
  const bool frontier_storage_present =
      db_.get_finalized_frontier_height().has_value() || !db_.scan_prefix(storage::key_frontier_transition_prefix()).empty() ||
      !db_.scan_prefix(storage::key_frontier_height_prefix()).empty();
  const bool obsolete_block_storage_present = !db_.scan_prefix("B:").empty();
  if (!frontier_storage_present && obsolete_block_storage_present) {
    log_line("finalized-state-invariant-violation source=load-state-missing-frontier-storage");
    std::cerr << "load_state: missing frontier storage in frontier-only runtime\n";
    return false;
  }
  const bool using_frontier_replay = true;
  consensus::CanonicalDerivedState derived_state;
  bool have_derived_state = false;

  const auto derivation_cfg = canonical_derivation_config_locked();
  if (cfg_.fast_start) {
    log_line("startup-progress phase=fast-start-attempt");
    consensus::CanonicalDerivedState fast_state;
    std::string fast_error;
    if (load_trusted_runtime_checkpoint_from_cache(derivation_cfg, db_, finalized_height_, finalized_identity_.id,
                                                   &fast_state, &fast_error, true, true)) {
      {
        PubKey32 reactivated{};
        if (maybe_reactivate_single_exiting_validator_for_startup_migration(cfg_.network, &fast_state, &reactivated)) {
          log_line("startup-fast-start-active-set-migration-reactivation height=" +
                   std::to_string(fast_state.finalized_height) +
                   " next_height=" + std::to_string(fast_state.finalized_height + 1) +
                   " pub=" + short_pub_hex(reactivated));
        }
      }
      const std::uint64_t next_height = finalized_height_ + 1;
      const auto next_epoch_start = consensus::committee_epoch_start(next_height, cfg_.network.committee_epoch_blocks);
      const auto next_checkpoint_it = fast_state.finalized_committee_checkpoints.find(next_epoch_start);
      if (next_checkpoint_it == fast_state.finalized_committee_checkpoints.end() ||
          next_checkpoint_it->second.ordered_members.empty()) {
        storage::FinalizedCommitteeCheckpoint repaired_checkpoint;
        std::string checkpoint_error;
        if (consensus::derive_next_epoch_checkpoint_from_state(derivation_cfg, fast_state, next_epoch_start,
                                                               &repaired_checkpoint, &checkpoint_error) &&
            !repaired_checkpoint.ordered_members.empty() &&
            consensus::validate_next_epoch_checkpoint_from_state(derivation_cfg, fast_state, next_epoch_start,
                                                                 repaired_checkpoint, &checkpoint_error) &&
            consensus::validate_checkpoint_schedule_for_height(derivation_cfg, fast_state, repaired_checkpoint,
                                                               next_height, &checkpoint_error)) {
          fast_state.finalized_committee_checkpoints[next_epoch_start] = std::move(repaired_checkpoint);
          log_line("startup-fast-start checkpoint-repair status=ok epoch=" + std::to_string(next_epoch_start) +
                   " reason=missing-finalized-committee-checkpoint");
        } else {
          fast_error = checkpoint_error.empty() ? "missing-finalized-committee-checkpoint" : checkpoint_error;
        }
      } else {
        std::string checkpoint_error;
        if (!consensus::validate_next_epoch_checkpoint_from_state(derivation_cfg, fast_state, next_epoch_start,
                                                                  next_checkpoint_it->second, &checkpoint_error) ||
            !consensus::validate_checkpoint_schedule_for_height(derivation_cfg, fast_state,
                                                                next_checkpoint_it->second, next_height,
                                                                &checkpoint_error)) {
          storage::FinalizedCommitteeCheckpoint repaired_checkpoint;
          if (consensus::derive_next_epoch_checkpoint_from_state(derivation_cfg, fast_state, next_epoch_start,
                                                                 &repaired_checkpoint, &checkpoint_error) &&
              !repaired_checkpoint.ordered_members.empty() &&
              consensus::validate_next_epoch_checkpoint_from_state(derivation_cfg, fast_state, next_epoch_start,
                                                                   repaired_checkpoint, &checkpoint_error) &&
              consensus::validate_checkpoint_schedule_for_height(derivation_cfg, fast_state, repaired_checkpoint,
                                                                 next_height, &checkpoint_error)) {
            fast_state.finalized_committee_checkpoints[next_epoch_start] = std::move(repaired_checkpoint);
            log_line("startup-fast-start checkpoint-repair status=ok epoch=" + std::to_string(next_epoch_start) +
                     " reason=checkpoint-recomputation-mismatch");
          } else {
            fast_error = checkpoint_error.empty() ? "checkpoint-recomputation-mismatch" : checkpoint_error;
          }
        }
      }
    }
    if (fast_error.empty()) {
      // Fast-start checkpoint self-repair can mutate canonical state fields that
      // are committed; refresh commitment before verification/persist.
      fast_state.state_commitment = consensus::consensus_state_commitment(derivation_cfg, fast_state);
      // The supply ledger is history-derived: restore it only if it was persisted for this exact tip.
      fast_state.confidential_supply.known = false;
      if (const auto raw = db_.get(kConfidentialSupplyLedgerKey); raw.has_value()) {
        std::uint64_t ledger_height = 0;
        if (auto ledger = consensus::parse_confidential_supply_ledger(*raw, &ledger_height);
            ledger.has_value() && ledger_height == finalized_height_) {
          fast_state.confidential_supply = *ledger;
        }
      }
      hydrate_runtime_from_canonical_state_locked(fast_state);
      if (using_frontier_replay) (void)db_.erase(storage::key_consensus_state_commitment_cache());
      if (!verify_and_persist_consensus_state_commitment_locked(fast_state)) return false;
      if (!persist_canonical_cache_rows(db_, fast_state)) return false;
      if (auto existing = db_.get(storage::key_root_index("UTXO", finalized_height_));
          !existing.has_value() || existing->size() != 32) {
        (void)persist_state_roots(db_, finalized_height_, utxos_, validators_, kFixedValidationRulesVersion);
      }
      log_line("startup-fast-start status=ok finalized_height=" + std::to_string(finalized_height_) +
               " transition=" + short_hash_hex(finalized_identity_.id));
      log_line("startup-progress phase=fast-start-done");
      derived_state = std::move(fast_state);
      have_derived_state = true;
    }
    if (!have_derived_state) {
      log_line("startup-fast-start status=fallback reason=" + fast_error);
      log_line("startup-progress phase=fast-start-fallback");
    }
  }

  if (!have_derived_state) {
    log_line("startup-progress phase=frontier-derive-begin");
    consensus::CanonicalDerivedState canonical_genesis_state;
    std::string canonical_error;
    if (!consensus::build_genesis_canonical_state(derivation_cfg, genesis_state, &canonical_genesis_state,
                                                  &canonical_error)) {
      log_line("finalized-state-invariant-violation source=load-state-canonical-genesis detail=" + canonical_error);
      std::cerr << "load_state: canonical genesis failed: " << canonical_error << "\n";
      return false;
    }

    std::string derivation_error;
    consensus::CanonicalDerivedState frontier_state;
    bool derived_ok =
        consensus::derive_canonical_state_from_frontier_storage(derivation_cfg, canonical_genesis_state, db_, &frontier_state,
                                                                 &derivation_error);
    if (!derived_ok) {
      const bool lane_tip_low = derivation_error.find("frontier-storage-lane-tip-too-low") != std::string::npos;
      const bool missing_lane_record =
          derivation_error.find("frontier-storage-missing-lane-record") != std::string::npos;
      const bool settlement_commitment_mismatch =
          derivation_error.find("frontier-settlement-commitment-mismatch") != std::string::npos;
      bool repaired = false;
      if (lane_tip_low || missing_lane_record || settlement_commitment_mismatch) {
        std::optional<Hash32> bad_transition = parse_transition_hash_from_error(derivation_error);
        if (!bad_transition.has_value()) {
          if (auto bad_height = parse_height_from_error(derivation_error); bad_height.has_value()) {
            bad_transition = db_.get_frontier_transition_by_height(*bad_height);
          }
        }
        if (bad_transition.has_value()) {
          std::string repair_error;
          std::uint64_t bad_height = 0;
          std::uint64_t new_tip_height = 0;
          const std::uint64_t frontier_tip_height = db_.get_finalized_frontier_height().value_or(finalized_height_);
          const std::uint64_t repair_cap = compute_startup_frontier_repair_cap(cfg_, frontier_tip_height);
          const std::uint64_t repair_floor = compute_startup_frontier_repair_floor(db_, frontier_tip_height);
          repaired =
              rollback_frontier_tail_from_transition(db_, *bad_transition, repair_cap, repair_floor, &bad_height,
                                                     &new_tip_height, &repair_error);
          if (repaired) {
            std::string reason = "repair-trigger";
            if (lane_tip_low) reason = "lane-tip-too-low";
            else if (missing_lane_record) reason = "missing-lane-record";
            else if (settlement_commitment_mismatch) reason = "settlement-commitment-mismatch";
            log_line("startup-frontier-tail-repair status=ok reason=" + reason + " bad_height=" +
                     std::to_string(bad_height) + " new_tip_height=" + std::to_string(new_tip_height) +
                     " effective_cap=" + std::to_string(repair_cap) +
                     " rollback-floor_height=" + std::to_string(repair_floor));
            auto repaired_tip = db_.get_tip();
            finalized_height_ = repaired_tip.has_value() ? repaired_tip->height : 0;
            finalized_identity_ =
                finalized_identity_for_runtime_tip(finalized_height_, repaired_tip.has_value() ? repaired_tip->hash : zero_hash());
            derivation_error.clear();
            derived_ok = consensus::derive_canonical_state_from_frontier_storage(derivation_cfg, canonical_genesis_state, db_,
                                                                                 &frontier_state, &derivation_error);
          } else {
            log_line("startup-frontier-tail-repair status=failed reason=" + repair_error +
                     " effective_cap=" + std::to_string(repair_cap) +
                     " rollback-floor_height=" + std::to_string(repair_floor));
          }
        }
      }
      if (!derived_ok) {
        log_line("finalized-state-invariant-violation source=load-state-frontier-derive detail=" + derivation_error);
        std::cerr << "load_state: frontier derive failed: " << derivation_error << "\n";
        return false;
      }
    }
    log_line("startup-progress phase=frontier-derive-done");
    derived_state = std::move(frontier_state);
    have_derived_state = true;
  }

  if (!have_derived_state) return false;
  {
    PubKey32 reactivated{};
    if (maybe_reactivate_single_exiting_validator_for_startup_migration(cfg_.network, &derived_state, &reactivated)) {
      log_line("startup-active-set-migration-reactivation height=" + std::to_string(derived_state.finalized_height) +
               " next_height=" + std::to_string(derived_state.finalized_height + 1) +
               " pub=" + short_pub_hex(reactivated));
    }
  }
  if (derived_state.finalized_height > 0 && !derived_state.finalized_identity.is_transition()) {
    log_line("finalized-state-invariant-violation source=load-state-frontier-kind-mismatch");
    std::cerr << "load_state: frontier replay produced non-transition finalized identity\n";
    return false;
  }
  if (derived_state.finalized_height != finalized_height_ || derived_state.finalized_identity.id != finalized_identity_.id) {
    log_line("finalized-state-invariant-violation source=load-state-frontier-tip-mismatch");
    std::cerr << "load_state: frontier replay tip mismatch\n";
    return false;
  }
  if (!db_.put(kStartupReplayModeKey, Bytes{'f', 'r', 'o', 'n', 't', 'i', 'e', 'r'})) return false;

  const auto persisted_commitment = db_.get_consensus_state_commitment_cache();
  const auto derived_commitment = consensus::consensus_state_commitment(derivation_cfg, derived_state);
  const storage::ConsensusStateCommitmentCache expected_commitment{derived_state.finalized_height,
                                                                   derived_state.finalized_identity.id,
                                                                   derived_commitment};
  const bool stale_canonical_cache_tip =
      !persisted_commitment.has_value() || persisted_commitment->height != expected_commitment.height ||
      persisted_commitment->hash != expected_commitment.hash;
  bool canonical_cache_rewrite_needed = stale_canonical_cache_tip;

  const auto persisted_utxos = db_.load_utxos_v2();
  if (!persisted_utxos.empty() && !same_utxos(persisted_utxos, derived_state.utxos)) {
    if (using_frontier_replay) {
      log_line("canonical-cache-rewrite source=load-state-utxo-cache-mismatch");
      canonical_cache_rewrite_needed = true;
    } else {
      log_line("finalized-state-invariant-violation source=load-state-utxo-cache-mismatch");
      std::cerr << "load_state: utxo cache mismatch\n";
      return false;
    }
  }
  const auto persisted_validators = db_.load_validators();
  if (!persisted_validators.empty() && !same_validator_maps(persisted_validators, derived_state.validators.all())) {
    if (stale_canonical_cache_tip) {
      log_line("canonical-cache-rewrite source=load-state-validator-cache-mismatch");
      canonical_cache_rewrite_needed = true;
    } else {
      log_line("finalized-state-invariant-violation source=load-state-validator-cache-mismatch");
      std::cerr << "load_state: validator cache mismatch "
                << validator_map_mismatch_reason(persisted_validators, derived_state.validators.all()) << "\n";
      return false;
    }
  }
  const auto persisted_join_requests = db_.load_validator_join_requests();
  if (!persisted_join_requests.empty() &&
      !same_join_request_maps(persisted_join_requests, derived_state.validator_join_requests)) {
    log_line("canonical-cache-rewrite source=load-state-join-request-cache-mismatch");
    canonical_cache_rewrite_needed = true;
  }
  const auto persisted_checkpoints = db_.load_finalized_committee_checkpoints();
  if (!persisted_checkpoints.empty() &&
      !same_finalized_checkpoint_maps(persisted_checkpoints, derived_state.finalized_committee_checkpoints)) {
    log_line("canonical-cache-rewrite source=load-state-checkpoint-cache-mismatch");
    canonical_cache_rewrite_needed = true;
  }
  const auto persisted_rewards = db_.load_epoch_reward_settlements();
  if (!persisted_rewards.empty() && !same_epoch_reward_maps(persisted_rewards, derived_state.epoch_reward_states)) {
    log_line("canonical-cache-rewrite source=load-state-reward-cache-mismatch");
    canonical_cache_rewrite_needed = true;
  }
  if (auto persisted_reserve = db_.get_protocol_reserve_balance(); persisted_reserve.has_value()) {
    if (*persisted_reserve != derived_state.protocol_reserve_balance_units) {
      if (stale_canonical_cache_tip) {
        log_line("canonical-cache-rewrite source=load-state-protocol-reserve-balance-mismatch");
        canonical_cache_rewrite_needed = true;
      } else {
        log_line("finalized-state-invariant-violation source=load-state-protocol-reserve-balance-mismatch");
        std::cerr << "load_state: protocol reserve balance mismatch\n";
        return false;
      }
    }
  }
  if (auto persisted_randomness = db_.get(kFinalizedRandomnessKey); persisted_randomness.has_value()) {
    if (persisted_randomness->size() != 32 ||
        !std::equal(persisted_randomness->begin(), persisted_randomness->end(), derived_state.finalized_randomness.begin())) {
      log_line("canonical-cache-rewrite source=load-state-randomness-cache-mismatch");
      canonical_cache_rewrite_needed = true;
    }
  }

  if (persisted_commitment.has_value()) {
    if (!same_consensus_state_commitment_cache(*persisted_commitment, expected_commitment)) {
      if (canonical_cache_rewrite_needed) {
        log_line("canonical-cache-rewrite source=load-state-consensus-state-commitment-cache-mismatch");
      } else {
        log_line("finalized-state-invariant-violation source=load-state-consensus-state-commitment-cache-mismatch");
        std::cerr << "load_state: consensus state commitment cache mismatch\n";
        return false;
      }
    }
  }
  log_line("startup-progress phase=cache-verify-begin");
  if (using_frontier_replay) (void)db_.erase(storage::key_consensus_state_commitment_cache());
  if (!verify_and_persist_consensus_state_commitment_locked(derived_state)) return false;
  hydrate_runtime_from_canonical_state_locked(derived_state);
  if (!persist_canonical_cache_rows(db_, derived_state)) return false;
  (void)db_.put(kConfidentialSupplyLedgerKey,
                consensus::serialize_confidential_supply_ledger(derived_state.confidential_supply, finalized_height_));
  run_confidential_supply_audit_locked("startup");
  log_line("startup-progress phase=cache-verify-done");

  const auto existing = db_.get(storage::key_root_index("UTXO", finalized_height_));
  if (!existing.has_value() || existing->size() != 32) {
    (void)persist_state_roots(db_, finalized_height_, utxos_, validators_, kFixedValidationRulesVersion);
  }

  local_epoch_tickets_.clear();
  local_vote_locks_.clear();
  highest_qc_by_height_.clear();
  highest_qc_payload_by_height_.clear();
  highest_tc_by_height_.clear();
  std::set<std::uint64_t> rebuild_epochs;
  for (const auto epoch : db_.load_epoch_ticket_epochs()) rebuild_epochs.insert(epoch);
  for (const auto& [epoch, _] : db_.load_epoch_committee_snapshots()) rebuild_epochs.insert(epoch);
  for (const auto& [epoch, _] : db_.load_epoch_committee_freeze_markers()) rebuild_epochs.insert(epoch);
  for (const auto epoch : rebuild_epochs) {
    rebuild_epoch_committee_state_locked(epoch, "startup", true);
  }
  for (auto& [epoch_start, checkpoint] : finalized_committee_checkpoints_) {
    auto snapshot = db_.get_epoch_committee_snapshot(epoch_start);
    if (!snapshot.has_value() || snapshot->ordered_members.empty()) continue;
    if (!finalized_checkpoint_matches_epoch_snapshot(checkpoint, *snapshot)) {
      log_line("canonical-cache-rewrite source=load-state-checkpoint-snapshot-mismatch epoch=" +
               std::to_string(epoch_start));
      checkpoint.ordered_members = snapshot->ordered_members;
      checkpoint.ordered_ticket_hashes.clear();
      checkpoint.ordered_ticket_nonces.clear();
      checkpoint.ordered_ticket_hashes.reserve(snapshot->selected_winners.size());
      checkpoint.ordered_ticket_nonces.reserve(snapshot->selected_winners.size());
      for (const auto& winner : snapshot->selected_winners) {
        checkpoint.ordered_ticket_hashes.push_back(winner.work_hash);
        checkpoint.ordered_ticket_nonces.push_back(winner.nonce);
      }
      if (!db_.put_finalized_committee_checkpoint(checkpoint)) {
        log_line("finalized-state-invariant-violation source=load-state-checkpoint-repair-failed epoch=" +
                 std::to_string(epoch_start));
        std::cerr << "load_state: checkpoint repair failed epoch=" << epoch_start << "\n";
        return false;
      }
      if (epoch_committee_closed_locked(epoch_start)) {
        const auto marker = make_epoch_committee_freeze_marker_locked(*snapshot);
        if (!db_.put_epoch_committee_freeze_marker(marker)) {
          log_line("finalized-state-invariant-violation source=load-state-checkpoint-freeze-marker-rewrite-failed epoch=" +
                   std::to_string(epoch_start));
          std::cerr << "load_state: checkpoint freeze marker rewrite failed epoch=" << epoch_start << "\n";
          return false;
        }
      }
    }
  }
  // SAFETY: a persisted local vote lock for a height that has not finalized is restored as-is and
  // is never dropped at startup, whether or not a QC exists for it. Dropping it would let this node
  // sign a payload conflicting with a vote it already broadcast (see update_local_vote_lock_locked).
  // Rows at or below the finalized height are released, as the finalization batch would have done.
  auto parse_height_key = [](const std::string& key, const char* prefix) -> std::optional<std::uint64_t> {
    if (key.size() <= std::strlen(prefix)) return std::nullopt;
    auto height_bytes = hex_decode(key.substr(std::strlen(prefix)));
    if (!height_bytes.has_value() || height_bytes->size() != 8) return std::nullopt;
    std::uint64_t height = 0;
    for (std::size_t i = 0; i < 8; ++i) height |= static_cast<std::uint64_t>((*height_bytes)[i]) << (8 * i);
    return height;
  };
  abstain_heights_.clear();
  std::set<std::uint64_t> safety_heights;
  for (const char* prefix : {kConsensusSafetyStatePrefix, kConsensusSafetyMirrorPrefix}) {
    for (const auto& [key, value] : db_.scan_prefix(prefix)) {
      const auto height = parse_height_key(key, prefix);
      if (!height.has_value()) continue;
      if (*height <= finalized_height_) {
        (void)db_.erase(key);
        continue;
      }
      safety_heights.insert(*height);
    }
  }
  for (const auto height : safety_heights) {
    const auto primary_row = db_.get(key_consensus_safety_state(height));
    const auto mirror_row = db_.get(key_consensus_safety_mirror(height));
    std::optional<std::pair<Hash32, std::uint32_t>> lock_state;
    std::optional<QuorumCertificate> qc_state;
    std::optional<Hash32> qc_payload_id;
    auto decode = [&](const std::optional<Bytes>& row, bool mirror) {
      if (!row.has_value()) return false;
      const auto inner = unseal_consensus_safety_row(*row, mirror);
      if (!inner.has_value()) return false;
      lock_state.reset();
      qc_state.reset();
      qc_payload_id.reset();
      return parse_consensus_safety_state(*inner, &lock_state, &qc_state, &qc_payload_id);
    };
    const bool primary_ok = decode(primary_row, false);
    const bool mirror_ok = !primary_ok && decode(mirror_row, true);
    if (!primary_ok && !mirror_ok) {
      // Both copies unreadable: the lock (if any) is lost.
      // A node outside a multi-member committee for this height cannot have voted here, so the
      // row could only have held an observed QC and is safe to drop. Committees of size < 2 use
      // per-round fallback members, so membership is not knowable for every round: quarantine.
      if (height == finalized_height_ + 1) {
        const auto committee = committee_for_height_round(height, 0);
        if (committee.size() >= 2 &&
            std::find(committee.begin(), committee.end(), local_key_.public_key) == committee.end()) {
          log_line("consensus-safety-row-dropped height=" + std::to_string(height) +
                   " reason=unreadable-not-committee-member");
          storage::DB::Batch drop(db_);
          drop.erase(key_consensus_safety_state(height));
          drop.erase(key_consensus_safety_mirror(height));
          if (!db_.write_batch_durable(drop)) return false;
          continue;
        }
      }
      // SAFETY: never erase what may be this node's only record of a broadcast vote. Keep the
      // raw bytes (a fixed binary may be able to read them) and abstain at this height.
      log_line("Consensus safety state for height " + std::to_string(height) +
               " unreadable, quarantining and abstaining from voting");
      storage::DB::Batch quarantine(db_);
      if (!db_.get(key_consensus_safety_quarantine(height)).has_value()) {
        quarantine.put(key_consensus_safety_quarantine(height), primary_row.has_value() ? *primary_row : *mirror_row);
      }
      quarantine.erase(key_consensus_safety_state(height));
      quarantine.erase(key_consensus_safety_mirror(height));
      if (!db_.write_batch_durable(quarantine)) return false;
      continue;
    }
    if (mirror_ok) {
      log_line("consensus-safety-primary-repaired height=" + std::to_string(height) + " source=mirror");
    }
    bool qc_valid = true;
    if (qc_state.has_value()) {
      if (qc_state->height != height || !qc_payload_id.has_value()) {
        qc_valid = false;
      } else {
        std::vector<FinalitySig> filtered;
        qc_valid = verify_quorum_certificate_locked(*qc_state, &filtered, nullptr);
      }
    } else if (qc_payload_id.has_value()) {
      qc_valid = false;
    }
    if (lock_state.has_value()) local_vote_locks_[height] = *lock_state;
    if (qc_valid) {
      if (qc_state.has_value()) highest_qc_by_height_[height] = *qc_state;
      if (qc_payload_id.has_value()) highest_qc_payload_by_height_[height] = *qc_payload_id;
    } else {
      // Drop only the unverifiable QC; the lock is kept.
      log_line("consensus-safety-qc-dropped height=" + std::to_string(height) + " reason=invalid-persisted-qc" +
               " lock=" + std::string(lock_state.has_value() ? "kept" : "none"));
    }
    // Rewrite both sealed copies when the primary was bad, legacy-format, or the mirror is missing.
    const bool needs_rewrite = !qc_valid || mirror_ok || !mirror_row.has_value() ||
                               !unseal_consensus_safety_row(*mirror_row, true).has_value();
    if (needs_rewrite && !persist_consensus_safety_state_locked(height)) return false;
  }
  for (const auto& [key, value] : db_.scan_prefix(kConsensusSafetyQuarantinePrefix)) {
    const auto height = parse_height_key(key, kConsensusSafetyQuarantinePrefix);
    if (!height.has_value()) continue;
    if (*height <= finalized_height_) {
      (void)db_.erase(key);
      continue;
    }
    abstain_heights_.insert(*height);
  }
  if (cfg_.unsafe_discard_vote_lock_height.has_value()) {
    const auto h = *cfg_.unsafe_discard_vote_lock_height;
    if (abstain_heights_.count(h) != 0) {
      log_line("OPERATOR OVERRIDE: discarding corrupted vote lock at height " + std::to_string(h));
      std::cerr << "OPERATOR OVERRIDE: discarding corrupted vote lock at height " << h << "\n";
      storage::DB::Batch discard(db_);
      discard.erase(key_consensus_safety_quarantine(h));
      discard.erase(key_consensus_locked_proposal(h));
      if (!db_.write_batch_durable(discard)) return false;
      abstain_heights_.erase(h);
    } else {
      log_line("operator-override-ignored flag=unsafe-discard-vote-lock-at-height height=" + std::to_string(h) +
               " reason=no-quarantined-safety-state-at-height");
    }
  }
  for (const auto h : abstain_heights_) {
    log_line("consensus-abstain height=" + std::to_string(h) + " reason=unreadable-safety-state");
  }
  for (const auto& [key, value] : db_.scan_prefix(kConsensusLockedProposalPrefix)) {
    const auto height = parse_height_key(key, kConsensusLockedProposalPrefix);
    if (!height.has_value()) continue;
    if (*height <= finalized_height_) {
      (void)db_.erase(key);
      continue;
    }
    // Restore the locked proposal as a candidate so the TC-round re-proposal path in the
    // proposer loop can rebuild it; without it a lock held across a network-wide restart can
    // never be satisfied (the deadlock that previously motivated dropping the lock here).
    const auto lock_it = local_vote_locks_.find(*height);
    auto proposal = FrontierProposal::parse(value);
    if (lock_it == local_vote_locks_.end() || !proposal.has_value() || proposal->transition.height != *height ||
        consensus_payload_id(proposal->transition) != lock_it->second.first) {
      log_line("consensus-locked-proposal-ignored height=" + std::to_string(*height) +
               " reason=" + std::string(lock_it == local_vote_locks_.end() ? "no-lock"
                                        : !proposal.has_value()             ? "parse-failed"
                                                                            : "payload-mismatch"));
      continue;
    }
    const auto transition_id = proposal->transition.transition_id();
    candidate_block_sizes_[transition_id] = value.size();
    candidate_frontier_proposals_[transition_id] = std::move(*proposal);
    log_line("consensus-locked-proposal-restored height=" + std::to_string(*height) +
             " round=" + std::to_string(lock_it->second.second) + " payload=" + short_hash_hex(lock_it->second.first));
  }
  for (const auto& [height, lock] : local_vote_locks_) {
    const bool has_body = std::any_of(candidate_frontier_proposals_.begin(), candidate_frontier_proposals_.end(),
                                      [&](const auto& kv) {
                                        return kv.second.transition.height == height &&
                                               consensus_payload_id(kv.second.transition) == lock.first;
                                      });
    log_line("consensus-safety-lock-restored height=" + std::to_string(height) + " round=" +
             std::to_string(lock.second) + " payload=" + short_hash_hex(lock.first) +
             " proposal=" + std::string(has_body ? "restored" : "missing"));
  }
  log_line("startup-progress phase=load-state-done");
  last_open_epoch_ticket_epoch_ = current_epoch_ticket_epoch_locked();
  if (!load_availability_state_locked()) {
    log_line("availability-init-reset reason=load-or-parse-failed");
    availability_state_rebuild_triggered_ = true;
    availability_state_rebuild_reason_ = "load_or_parse_failed";
    availability_state_ = {};
    availability_state_.current_epoch = current_epoch_ticket_epoch_locked();
    if (finalized_height_ > 0) {
      rebuild_availability_retained_prefixes_from_finalized_frontier_locked();
    }
    refresh_availability_operator_state_locked(false);
    (void)finalize_availability_restore_locked("load-failure-rebuild");
  }

  return true;
}

}  // namespace finalis::node
