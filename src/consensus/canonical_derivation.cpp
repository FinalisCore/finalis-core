#include "consensus/canonical_derivation.hpp"

#include <algorithm>
#include <limits>
#include <map>
#include <set>
#include <sstream>

#include "address/address.hpp"
#include "codec/bytes.hpp"
#include "common/wide_arith.hpp"
#include "consensus/committee_schedule.hpp"
#include "consensus/finalized_committee.hpp"
#include "consensus/ingress.hpp"
#include "consensus/monetary.hpp"
#include "consensus/randomness.hpp"
#include "consensus/state_commitment.hpp"
#include "consensus/votes.hpp"
#include "crypto/ed25519.hpp"
#include "crypto/hash.hpp"
#include "crypto/smt.hpp"
#include "merkle/merkle.hpp"
#include "utxo/validate.hpp"

namespace finalis::consensus {
namespace {

constexpr std::uint64_t kAdaptiveMinBondFloor = 150ULL * BASE_UNITS_PER_COIN;
constexpr std::uint64_t kAdaptiveMinBondCeiling = 500ULL * BASE_UNITS_PER_COIN;
constexpr std::uint64_t kAdaptiveMinBondBase = 150ULL * BASE_UNITS_PER_COIN;

bool finalized_identity_valid_for_frontier_parent(const CanonicalDerivedState& prev) {
  if (prev.finalized_identity.is_transition()) return true;
  return prev.finalized_height == 0 && prev.finalized_identity.is_genesis();
}

struct DeterministicEpochRewardInputs {
  std::map<PubKey32, std::uint64_t> reward_score_units;
  std::map<PubKey32, std::uint64_t> expected_participation_units;
  std::map<PubKey32, std::uint64_t> observed_participation_units;
};

std::map<PubKey32, std::uint64_t> availability_operator_bonds(const ValidatorRegistry& validators) {
  std::map<PubKey32, std::uint64_t> operator_bonds;
  for (const auto& [validator_pubkey, info] : validators.all()) {
    operator_bonds[canonical_operator_id(validator_pubkey, info)] += info.bonded_amount;
  }
  return operator_bonds;
}

void refresh_availability_operator_state(const CanonicalDerivationConfig& cfg, const FinalizedIdentity& finalized_identity,
                                         const ValidatorRegistry& validators, bool advance_epoch,
                                         availability::AvailabilityPersistentState* state) {
  if (!state) return;
  const auto operator_bonds = availability_operator_bonds(validators);
  availability::refresh_live_availability_state(finalized_identity.id, operator_bonds, advance_epoch, state, cfg.availability,
                                                cfg.network.availability_recovery_activation_height);
}

void advance_availability_epoch(const CanonicalDerivationConfig& cfg, const FinalizedIdentity& finalized_identity,
                                const ValidatorRegistry& validators, std::uint64_t epoch,
                                availability::AvailabilityPersistentState* state) {
  if (!state) return;
  const auto operator_bonds = availability_operator_bonds(validators);
  availability::advance_live_availability_epoch(finalized_identity.id, operator_bonds, epoch, state, cfg.availability,
                                                cfg.network.availability_recovery_activation_height);
}

void update_availability_from_frontier(const CanonicalDerivationConfig& cfg, const CanonicalFrontierRecord& record,
                                       availability::AvailabilityPersistentState* state) {
  if (!state) return;
  const auto retained = availability::build_retained_prefix_payloads_from_lane_records(
      record.lane_records, record.transition.height, cfg.availability.audit_chunk_size);
  if (retained.empty()) return;
  std::map<Hash32, availability::RetainedPrefix> merged;
  for (const auto& prefix : state->retained_prefixes) merged[prefix.prefix_id] = prefix;
  for (const auto& payload : retained) merged[payload.prefix.prefix_id] = payload.prefix;
  state->retained_prefixes.clear();
  state->retained_prefixes.reserve(merged.size());
  for (const auto& [_, prefix] : merged) state->retained_prefixes.push_back(prefix);
  availability::normalize_availability_persistent_state(state);
}

struct AvailabilityCommitteeDecision {
  storage::FinalizedCommitteeDerivationMode mode{storage::FinalizedCommitteeDerivationMode::NORMAL};
  storage::FinalizedCommitteeFallbackReason fallback_reason{storage::FinalizedCommitteeFallbackReason::NONE};
  std::uint64_t eligible_operator_count{0};
  std::uint64_t min_eligible_operators{0};
  std::uint64_t effective_committee_size{0};
  AdaptiveCheckpointParameters adaptive{};
};

std::uint64_t target_committee_size_for_qualified_depth(std::uint64_t qualified_depth) {
  if (qualified_depth <= 1) return 1;
  if (qualified_depth == 2) return 2;
  if (qualified_depth == 3) return 3;
  if (qualified_depth <= 6) return 4;
  if (qualified_depth <= 10) return 7;
  if (qualified_depth <= 16) return 10;
  if (qualified_depth <= 24) return 16;
  return 24 + ((qualified_depth - 24) / 2);
}

std::uint64_t fallback_recovery_threshold(std::uint64_t target_committee_size) {
  if (target_committee_size <= 3) return target_committee_size;
  if (target_committee_size <= 7) return target_committee_size + 1;
  return target_committee_size + 2;
}

std::optional<storage::FinalizedCommitteeCheckpoint> previous_checkpoint_for_epoch(
    const CanonicalDerivationConfig& cfg, const CanonicalDerivedState& state, std::uint64_t epoch_start_height) {
  const auto epoch_blocks = std::max<std::uint64_t>(1, cfg.network.committee_epoch_blocks);
  if (epoch_start_height <= epoch_blocks) return std::nullopt;
  const auto previous_epoch_start = epoch_start_height - epoch_blocks;
  auto it = state.finalized_committee_checkpoints.find(previous_epoch_start);
  if (it == state.finalized_committee_checkpoints.end()) return std::nullopt;
  return it->second;
}

AvailabilityCommitteeDecision decide_availability_committee_mode(
    const CanonicalDerivationConfig& cfg, const CanonicalDerivedState& state, std::uint64_t epoch_start_height,
    const availability::AvailabilityPersistentState& availability_state) {
  AvailabilityCommitteeDecision decision;
  const auto previous_checkpoint = previous_checkpoint_for_epoch(cfg, state, epoch_start_height);
  const auto prior_adaptive = adaptive_checkpoint_parameters_from_metadata(previous_checkpoint);
  const auto qualified_cfg = availability_config_with_min_bond(cfg.availability, prior_adaptive.min_bond);
  decision.adaptive.qualified_depth = qualified_depth_at_checkpoint(state.validators, epoch_start_height, prior_adaptive.min_bond,
                                                                    availability_state, qualified_cfg);
  decision.adaptive = derive_adaptive_checkpoint_parameters(previous_checkpoint, decision.adaptive.qualified_depth);
  if (bootstrap_availability_grace_active(state.validators, epoch_start_height)) {
    decision.adaptive.target_committee_size = 1;
    decision.adaptive.min_eligible_operators = 1;
    decision.adaptive.min_bond = genesis_validator_bond_amount();
    decision.adaptive.qualified_depth = std::max<std::uint64_t>(1, decision.adaptive.qualified_depth);
    decision.adaptive.target_expand_streak = 0;
    decision.adaptive.target_contract_streak = 0;
  }
  decision.eligible_operator_count =
      count_eligible_operators_at_checkpoint(state.validators, epoch_start_height, availability_state,
                                             availability_config_with_min_bond(cfg.availability, decision.adaptive.min_bond));
  decision.min_eligible_operators = decision.adaptive.min_eligible_operators;
  decision.effective_committee_size =
      std::max<std::uint64_t>(1, std::min(decision.eligible_operator_count, decision.adaptive.target_committee_size));
  if (decision.min_eligible_operators == 0) return decision;

  if (decision.eligible_operator_count < decision.min_eligible_operators) {
    decision.mode = storage::FinalizedCommitteeDerivationMode::FALLBACK;
    decision.fallback_reason = storage::FinalizedCommitteeFallbackReason::INSUFFICIENT_ELIGIBLE_OPERATORS;
    return decision;
  }

  const auto previous_mode =
      previous_checkpoint.has_value() ? std::optional<storage::FinalizedCommitteeDerivationMode>(previous_checkpoint->derivation_mode)
                                      : std::nullopt;
  const std::uint64_t recovery_threshold = fallback_recovery_threshold(decision.adaptive.target_committee_size);
  if (previous_mode == storage::FinalizedCommitteeDerivationMode::FALLBACK &&
      decision.eligible_operator_count < recovery_threshold) {
    decision.mode = storage::FinalizedCommitteeDerivationMode::FALLBACK;
    decision.fallback_reason = storage::FinalizedCommitteeFallbackReason::HYSTERESIS_RECOVERY_PENDING;
  }
  return decision;
}

std::vector<FinalitySig> canonicalize_finality_signatures(const std::vector<FinalitySig>& signatures, std::size_t quorum) {
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

std::vector<PubKey32> canonicalize_signer_pubkeys(std::vector<PubKey32> signers, std::size_t quorum) {
  std::sort(signers.begin(), signers.end());
  signers.erase(std::unique(signers.begin(), signers.end()), signers.end());
  if (signers.size() > quorum) signers.resize(quorum);
  return signers;
}

bool verify_frontier_finality_certificate_against_state(const CanonicalDerivationConfig& cfg,
                                                        const CanonicalDerivedState& prev,
                                                        const FrontierTransition& transition,
                                                        const FinalityCertificate& cert,
                                                        std::string* error) {
  if (cert.height != transition.height) {
    if (error) *error = "certificate-height-mismatch";
    return false;
  }
  if (cert.round != transition.round) {
    if (error) *error = "certificate-round-mismatch";
    return false;
  }
  if (cert.frontier_transition_id != transition.transition_id()) {
    if (error) *error = "certificate-transition-id-mismatch";
    return false;
  }
  const auto committee = canonical_committee_for_height_round(cfg, prev, transition.height, transition.round);
  if (committee.empty()) {
    if (error) *error = "missing-canonical-committee";
    return false;
  }
  const auto legacy_committee = legacy_canonical_committee_for_height_round(cfg, prev, transition.height, transition.round);
  const bool committee_matches =
      cert.committee_members == committee || (!legacy_committee.empty() && cert.committee_members == legacy_committee);
  if (!committee_matches) {
    if (error) *error = "certificate-committee-mismatch";
    return false;
  }
  const auto& effective_committee = (cert.committee_members == committee) ? committee : legacy_committee;
  std::set<PubKey32> committee_set(effective_committee.begin(), effective_committee.end());
  if (committee_set.size() != effective_committee.size()) {
    if (error) *error = "certificate-committee-duplicates";
    return false;
  }
  const std::size_t quorum = quorum_threshold(effective_committee.size());
  const auto msg = vote_signing_message(cert.height, cert.round, cert.frontier_transition_id);
  std::set<PubKey32> seen;
  std::vector<FinalitySig> valid;
  for (const auto& sig : cert.signatures) {
    if (committee_set.find(sig.validator_pubkey) == committee_set.end()) continue;
    if (!seen.insert(sig.validator_pubkey).second) continue;
    if (!crypto::ed25519_verify(msg, sig.signature, sig.validator_pubkey)) continue;
    valid.push_back(sig);
  }
  const auto canonical = canonicalize_finality_signatures(valid, quorum);
  if (canonical.size() < quorum) {
    if (error) *error = "certificate-insufficient-valid-signatures";
    return false;
  }
  return true;
}

Hash32 canonical_finality_certificate_hash_impl(const FinalityCertificate& cert) {
  const auto canonical_signatures =
      canonicalize_finality_signatures(cert.signatures, std::numeric_limits<std::size_t>::max());
  codec::ByteWriter w;
  w.bytes(Bytes{'F', 'I', 'N', 'A', 'L', 'I', 'S', '_', 'F', 'I', 'N', 'A', 'L', 'I', 'T', 'Y',
                '_', 'C', 'E', 'R', 'T', '_', 'V', '1'});
  w.u64le(cert.height);
  w.u32le(cert.round);
  w.bytes_fixed(cert.frontier_transition_id);
  w.varint(cert.committee_members.size());
  for (const auto& member : cert.committee_members) w.bytes_fixed(member);
  w.varint(canonical_signatures.size());
  for (const auto& sig : canonical_signatures) {
    w.bytes_fixed(sig.validator_pubkey);
    w.bytes_fixed(sig.signature);
  }
  return crypto::sha256d(w.data());
}

std::optional<std::uint64_t> settlement_epoch_for_height(const CanonicalDerivationConfig& cfg, std::uint64_t height) {
  const auto epoch_blocks = std::max<std::uint64_t>(1, cfg.network.committee_epoch_blocks);
  const auto epoch_start = committee_epoch_start(height, epoch_blocks);
  if (height != epoch_start || epoch_start <= 1 || epoch_start <= epoch_blocks) return std::nullopt;
  return epoch_start - epoch_blocks;
}

FrontierSettlement derive_frontier_settlement_from_state(const CanonicalDerivationConfig& cfg,
                                                         const CanonicalDerivedState& prev, std::uint64_t height,
                                                         const PubKey32& leader_pubkey,
                                                         std::uint64_t accepted_fee_units) {
  FrontierSettlement settlement;
  settlement.current_fees = accepted_fee_units;

  std::map<PubKey32, std::uint64_t> settlement_scores;
  std::uint64_t settlement_rewards = 0;
  std::uint64_t settled_epoch_fees = 0;
  std::uint64_t reserve_subsidy = 0;
  if (auto settlement_epoch = settlement_epoch_for_height(cfg, height); settlement_epoch.has_value()) {
    settlement.settlement_epoch_start = *settlement_epoch;
    auto it = prev.epoch_reward_states.find(*settlement_epoch);
    if (it != prev.epoch_reward_states.end() && !it->second.settled) {
      settlement_rewards = it->second.total_reward_units;
      settled_epoch_fees = height >= EMISSION_BLOCKS ? it->second.fee_pool_units : 0;
      reserve_subsidy = height >= EMISSION_BLOCKS ? it->second.reserve_subsidy_units : 0;
      settlement_scores = it->second.reward_score_units;
      const auto& econ = active_economics_policy(cfg.network, height);
      const auto threshold_bps = econ.participation_threshold_bps;
      for (auto& [pub, score] : settlement_scores) {
        const auto expected_it = it->second.expected_participation_units.find(pub);
        const auto observed_it = it->second.observed_participation_units.find(pub);
        const std::uint64_t expected =
            expected_it == it->second.expected_participation_units.end() ? 0 : expected_it->second;
        const std::uint64_t observed =
            observed_it == it->second.observed_participation_units.end() ? 0 : observed_it->second;
        const std::uint32_t participation_bps =
            expected == 0
                ? 10'000U
                : static_cast<std::uint32_t>(wide::mul_div_u64(std::min(observed, expected), 10'000ULL, expected));
        score = apply_participation_penalty_bps(score, participation_bps, threshold_bps);
      }
    }
  }

  // Frontier transition identity must remain stable across justified round
  // re-proposals of the same ordered ingress slice. Current-block fees are
  // therefore accounted but not paid into the transition settlement outputs.
  // This keeps the live payload independent of the round leader.
  const auto payout =
      compute_epoch_settlement_payout(settlement_rewards, settled_epoch_fees, reserve_subsidy, leader_pubkey,
                                      settlement_scores, {});
  settlement.settled_epoch_fees = payout.settled_epoch_fees;
  settlement.settled_epoch_rewards = payout.settled_epoch_rewards;
  settlement.reserve_subsidy_units = payout.reserve_subsidy_units;
  settlement.total = payout.total;
  settlement.outputs = payout.outputs;
  return settlement;
}

Hash32 frontier_settlement_txid(const FrontierTransition& transition) {
  codec::ByteWriter w;
  w.bytes(Bytes{'F', 'I', 'N', 'A', 'L', 'I', 'S', '_', 'F', 'R', 'O', 'N', 'T', 'I', 'E', 'R',
                '_', 'S', 'E', 'T', 'T', 'L', 'E', 'M', 'E', 'N', 'T', '_', 'V', '1'});
  w.bytes_fixed(transition.prev_finalized_hash);
  w.u64le(transition.height);
  w.varbytes(transition.prev_vector.serialize());
  w.varbytes(transition.next_vector.serialize());
  w.bytes_fixed(transition.settlement_commitment);
  return crypto::sha256d(w.data());
}

void apply_frontier_settlement_to_utxos(const FrontierTransition& transition, UtxoSetV2* utxos) {
  if (!utxos) return;
  const auto settlement_txid = frontier_settlement_txid(transition);
  for (std::uint32_t out_index = 0; out_index < transition.settlement.outputs.size(); ++out_index) {
    const auto& [pub, units] = transition.settlement.outputs[out_index];
    const auto pkh = crypto::h160(Bytes(pub.begin(), pub.end()));
    (*utxos)[OutPoint{settlement_txid, out_index}] =
        UtxoEntryV2{TxOut{units, address::p2pkh_script_pubkey(pkh)}};
  }
}

std::size_t active_operator_count_for_height(const ValidatorRegistry& validators, std::uint64_t height) {
  std::set<PubKey32> operators;
  for (const auto& [pub, info] : validators.all()) {
    if (!validators.is_active_for_height(pub, height)) continue;
    operators.insert(canonical_operator_id(pub, info));
  }
  return operators.size();
}

std::uint64_t effective_validator_min_bond_for_height(const CanonicalDerivationConfig& cfg,
                                                      const CanonicalDerivedState& state, std::uint64_t height) {
  if (cfg.validator_min_bond_override != BOND_AMOUNT || cfg.validator_bond_min_amount != BOND_AMOUNT) {
    return std::max<std::uint64_t>(cfg.validator_min_bond_override, cfg.validator_bond_min_amount);
  }
  const auto active_operator_count = active_operator_count_for_height(state.validators, height);
  return std::max<std::uint64_t>(cfg.validator_bond_min_amount,
                                 validator_min_bond_units(cfg.network, height, active_operator_count));
}

std::uint8_t ticket_difficulty_bits_for_epoch(const CanonicalDerivationConfig& cfg, const CanonicalDerivedState& state,
                                              std::uint64_t epoch_start_height, std::size_t active_validator_count) {
  std::uint8_t previous_bits = DEFAULT_TICKET_DIFFICULTY_BITS;
  const auto epoch_blocks = std::max<std::uint64_t>(1, cfg.network.committee_epoch_blocks);
  const auto& econ = active_economics_policy(cfg.network, epoch_start_height);
  if (epoch_start_height > 1) {
    const auto previous_epoch_start = epoch_start_height > epoch_blocks ? (epoch_start_height - epoch_blocks) : 1;
    if (auto checkpoint_it = state.finalized_committee_checkpoints.find(previous_epoch_start);
        checkpoint_it != state.finalized_committee_checkpoints.end()) {
      previous_bits = checkpoint_it->second.ticket_difficulty_bits;
    }
  }

  auto accumulate_epoch = [&](std::uint64_t epoch, std::uint64_t* blocks, std::uint64_t* total_round_x1000,
                              std::uint64_t* total_participation_bps) {
    for (std::uint64_t h = epoch; h < epoch + epoch_blocks && h <= state.finalized_height; ++h) {
      auto it = state.finalized_block_metadata.find(h);
      if (it == state.finalized_block_metadata.end()) continue;
      ++(*blocks);
      *total_round_x1000 += static_cast<std::uint64_t>(it->second.round) * 1000ULL;
      *total_participation_bps +=
          quorum_relative_participation_bps(it->second.signature_count, it->second.quorum_threshold);
    }
  };

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
    accumulate_epoch(epoch, &blocks, &total_round_x1000, &total_participation_bps);
    const std::uint32_t average_round_x1000 =
        blocks == 0 ? 0U : static_cast<std::uint32_t>(total_round_x1000 / blocks);
    const std::uint32_t average_participation_bps =
        blocks == 0 ? 10'000U : static_cast<std::uint32_t>(total_participation_bps / blocks);
    const bool healthy = ticket_difficulty_epoch_is_healthy(active_validator_count, cfg.max_committee,
                                                            average_round_x1000, average_participation_bps);
    const bool unhealthy = ticket_difficulty_epoch_is_unhealthy(average_round_x1000, average_participation_bps);
    if (healthy && consecutive_unhealthy_epochs == 0) {
      ++consecutive_healthy_epochs;
    } else if (unhealthy && consecutive_healthy_epochs == 0) {
      ++consecutive_unhealthy_epochs;
    } else {
      break;
    }
  }
  return adjust_bounded_ticket_difficulty_bits(previous_bits, active_validator_count, cfg.max_committee,
                                               consecutive_healthy_epochs, consecutive_unhealthy_epochs);
}

Hash32 committee_epoch_randomness_for_height(const CanonicalDerivationConfig& cfg, const CanonicalDerivedState& state,
                                             std::uint64_t height) {
  const auto epoch_start = committee_epoch_start(height, cfg.network.committee_epoch_blocks);
  auto it = state.committee_epoch_randomness_cache.find(epoch_start);
  if (it != state.committee_epoch_randomness_cache.end()) return it->second;
  return initial_finalized_randomness(cfg.network, cfg.chain_id);
}

ValidatorBestTicket checkpoint_best_ticket_for_member(const CanonicalDerivationConfig& cfg,
                                                      const CanonicalDerivedState& state,
                                                      const storage::FinalizedCommitteeCheckpoint& checkpoint,
                                                      std::size_t index) {
  const auto& pub = checkpoint.ordered_members[index];
  if (index < checkpoint.ordered_ticket_hashes.size() && index < checkpoint.ordered_ticket_nonces.size()) {
    return ValidatorBestTicket{pub, checkpoint.ordered_ticket_hashes[index], checkpoint.ordered_ticket_nonces[index]};
  }

  PubKey32 operator_id = pub;
  if (index < checkpoint.ordered_operator_ids.size() && checkpoint.ordered_operator_ids[index] != PubKey32{}) {
    operator_id = checkpoint.ordered_operator_ids[index];
  } else if (auto it = state.validators.all().find(pub); it != state.validators.all().end()) {
    operator_id = canonical_operator_id(pub, it->second);
  }
  auto ticket = best_epoch_ticket_for_operator_id(checkpoint.epoch_start_height, checkpoint.epoch_seed, operator_id,
                                                  checkpoint.epoch_start_height, EPOCH_TICKET_MAX_NONCE);
  if (ticket.has_value()) return ValidatorBestTicket{pub, ticket->work_hash, ticket->nonce};
  return ValidatorBestTicket{
      pub,
      make_epoch_ticket_work_hash(checkpoint.epoch_start_height, checkpoint.epoch_seed, operator_id, 0),
      0,
  };
}

std::vector<ValidatorBestTicket> checkpoint_winners(const CanonicalDerivationConfig& cfg, const CanonicalDerivedState& state,
                                                    const storage::FinalizedCommitteeCheckpoint& checkpoint) {
  std::vector<ValidatorBestTicket> winners;
  winners.reserve(checkpoint.ordered_members.size());
  for (std::size_t i = 0; i < checkpoint.ordered_members.size(); ++i) {
    winners.push_back(checkpoint_best_ticket_for_member(cfg, state, checkpoint, i));
  }
  return winners;
}

std::vector<PubKey32> proposer_schedule_from_checkpoint(const CanonicalDerivationConfig& cfg, const CanonicalDerivedState& state,
                                                        const storage::FinalizedCommitteeCheckpoint& checkpoint,
                                                        std::uint64_t height) {
  const auto winners = checkpoint_winners(cfg, state, checkpoint);
  return proposer_schedule_from_committee(
      winners, compute_proposer_seed(checkpoint.epoch_seed, height, compute_committee_root(winners)));
}

std::vector<FinalizedCommitteeCandidate> finalized_committee_candidates_for_height(
    const CanonicalDerivationConfig& cfg, const CanonicalDerivedState& state, std::uint64_t height,
    std::uint8_t ticket_difficulty_bits, AvailabilityCommitteeDecision* decision_out = nullptr) {
  std::vector<OperatorCommitteeInput> operator_inputs;
  const auto epoch_start = committee_epoch_start(height, cfg.network.committee_epoch_blocks);
  const auto epoch_seed = committee_epoch_seed(committee_epoch_randomness_for_height(cfg, state, height), epoch_start);
  const auto& econ = active_economics_policy(cfg.network, height);
  std::map<PubKey32, const availability::AvailabilityOperatorState*> availability_by_operator;
  for (const auto& operator_state : state.availability_state.operators) {
    availability_by_operator[operator_state.operator_pubkey] = &operator_state;
  }
  auto decision = decide_availability_committee_mode(cfg, state, epoch_start, state.availability_state);
  const bool enforce_availability = decision.mode == storage::FinalizedCommitteeDerivationMode::NORMAL;
  if (decision_out) *decision_out = decision;
  auto adaptive_availability_cfg = availability_config_with_min_bond(cfg.availability, decision.adaptive.min_bond);
  auto adaptive_econ = econ;
  adaptive_econ.target_validators = decision.adaptive.target_committee_size;

  struct OperatorSeed {
    PubKey32 representative_pub{};
    std::uint64_t bonded_amount{0};
    bool has_representative{false};
  };
  std::map<PubKey32, OperatorSeed> by_operator;
  for (const auto& [pub, info] : state.validators.all()) {
    const auto operator_id = canonical_operator_id(pub, info);
    const auto availability_it = availability_by_operator.find(operator_id);
    const auto eligibility = committee_eligibility_at_checkpoint(
        state.validators, pub, info, height, decision.adaptive.min_bond,
        availability_it == availability_by_operator.end() ? nullptr : availability_it->second, adaptive_availability_cfg,
        enforce_availability);
    if (!eligibility.eligible) continue;
    auto& seed = by_operator[operator_id];
    seed.bonded_amount += info.bonded_amount;
    if (!seed.has_representative || pub < seed.representative_pub) {
      seed.representative_pub = pub;
      seed.has_representative = true;
    }
  }
  operator_inputs.reserve(by_operator.size());
  for (const auto& [operator_id, seed] : by_operator) {
    if (!seed.has_representative) continue;
    OperatorCommitteeInput input;
    input.pubkey = seed.representative_pub;
    input.operator_id = operator_id;
    input.bonded_amount = seed.bonded_amount;
    auto ticket = best_epoch_ticket_for_operator_id(epoch_start, epoch_seed, operator_id, epoch_start, EPOCH_TICKET_MAX_NONCE);
    if (ticket.has_value()) {
      input.ticket_work_hash = ticket->work_hash;
      input.ticket_nonce = ticket->nonce;
      input.ticket_bonus_bps = ticket_pow_bonus_bps(*ticket, ticket_difficulty_bits, econ.ticket_bonus_cap_bps);
    }
    operator_inputs.push_back(input);
  }
  std::sort(operator_inputs.begin(), operator_inputs.end(), [](const OperatorCommitteeInput& a, const OperatorCommitteeInput& b) {
    const auto a_id = a.operator_id == PubKey32{} ? a.pubkey : a.operator_id;
    const auto b_id = b.operator_id == PubKey32{} ? b.pubkey : b.operator_id;
    if (a_id != b_id) return a_id < b_id;
    if (a.pubkey != b.pubkey) return a.pubkey < b.pubkey;
    if (a.bonded_amount != b.bonded_amount) return a.bonded_amount < b.bonded_amount;
    if (a.ticket_work_hash != b.ticket_work_hash) return a.ticket_work_hash < b.ticket_work_hash;
              if (a.ticket_nonce != b.ticket_nonce) return a.ticket_nonce < b.ticket_nonce;
              return a.ticket_bonus_bps < b.ticket_bonus_bps;
            });
  return aggregate_operator_committee_candidates(operator_inputs, adaptive_econ, height,
                                                 std::max<std::size_t>(1, decision.adaptive.qualified_depth));
}

DeterministicEpochRewardInputs compute_deterministic_epoch_reward_inputs(
    const CanonicalDerivationConfig& cfg, const CanonicalDerivedState& state, std::uint64_t height,
    const PubKey32& leader_pubkey, const std::vector<PubKey32>& committee, const std::vector<FinalitySig>& finality_sigs) {
  DeterministicEpochRewardInputs out;
  std::set<PubKey32> canonical_members(committee.begin(), committee.end());
  const auto observed_members = committee_participants_from_finality(committee, finality_sigs);
  std::set<PubKey32> observed_set(observed_members.begin(), observed_members.end());
  const auto active_operator_count = active_operator_count_for_height(state.validators, height);

  for (const auto& pub : canonical_members) {
    out.expected_participation_units[pub] += 1;
    if (observed_set.find(pub) != observed_set.end()) out.observed_participation_units[pub] += 1;
    auto it = state.validators.all().find(pub);
    if (it == state.validators.all().end()) continue;
    out.reward_score_units[pub] += reward_weight(cfg.network, height, active_operator_count, it->second.bonded_amount);
  }
  if (auto it = state.validators.all().find(leader_pubkey); it != state.validators.all().end()) {
    out.reward_score_units[leader_pubkey] += reward_weight(cfg.network, height, active_operator_count, it->second.bonded_amount);
  }
  return out;
}

DeterministicEpochRewardInputs compute_deterministic_epoch_reward_inputs(
    const CanonicalDerivationConfig& cfg, const CanonicalDerivedState& state, std::uint64_t height,
    const PubKey32& leader_pubkey, const std::vector<PubKey32>& committee, const std::vector<PubKey32>& observed_members) {
  DeterministicEpochRewardInputs out;
  std::set<PubKey32> canonical_members(committee.begin(), committee.end());
  std::set<PubKey32> observed_set(observed_members.begin(), observed_members.end());
  const auto active_operator_count = active_operator_count_for_height(state.validators, height);

  for (const auto& pub : canonical_members) {
    out.expected_participation_units[pub] += 1;
    if (observed_set.find(pub) != observed_set.end()) out.observed_participation_units[pub] += 1;
    auto it = state.validators.all().find(pub);
    if (it == state.validators.all().end()) continue;
    out.reward_score_units[pub] += reward_weight(cfg.network, height, active_operator_count, it->second.bonded_amount);
  }
  if (auto it = state.validators.all().find(leader_pubkey); it != state.validators.all().end()) {
    out.reward_score_units[leader_pubkey] += reward_weight(cfg.network, height, active_operator_count, it->second.bonded_amount);
  }
  return out;
}

void mark_epoch_reward_settled_for_height(const CanonicalDerivationConfig& cfg, std::uint64_t height,
                                          CanonicalDerivedState* state) {
  const auto epoch_start = committee_epoch_start(height, cfg.network.committee_epoch_blocks);
  if (height != epoch_start || epoch_start <= 1 || epoch_start <= cfg.network.committee_epoch_blocks) return;
  const auto settlement_epoch = epoch_start - cfg.network.committee_epoch_blocks;
  auto& reward_state = state->epoch_reward_states[settlement_epoch];
  reward_state.epoch_start_height = settlement_epoch;
  if (reward_state.settled) return;
  reward_state.reserve_subsidy_units = 0;
  if (height >= EMISSION_BLOCKS) {
    const auto& econ = active_economics_policy(cfg.network, height);
    std::size_t eligible_validator_count = 0;
    for (const auto& [pub, raw_score] : reward_state.reward_score_units) {
      const auto expected_it = reward_state.expected_participation_units.find(pub);
      const auto observed_it = reward_state.observed_participation_units.find(pub);
      const std::uint64_t expected = expected_it == reward_state.expected_participation_units.end() ? 0 : expected_it->second;
      const std::uint64_t observed = observed_it == reward_state.observed_participation_units.end() ? 0 : observed_it->second;
      const std::uint32_t participation_bps =
          expected == 0 ? 10'000U
                        : static_cast<std::uint32_t>(wide::mul_div_u64(std::min(observed, expected), 10'000ULL, expected));
      const auto adjusted_score = apply_participation_penalty_bps(raw_score, participation_bps, econ.participation_threshold_bps);
      if (adjusted_score > 0) ++eligible_validator_count;
    }
    const auto reserve_after_accrual = state->protocol_reserve_balance_units + reward_state.reserve_accrual_units;
    reward_state.reserve_subsidy_units = post_cap_reserve_subsidy_units(eligible_validator_count, reward_state.fee_pool_units,
                                                                        reserve_after_accrual);
  }
  reward_state.settled = true;
  state->protocol_reserve_balance_units += reward_state.reserve_accrual_units;
  if (state->protocol_reserve_balance_units >= reward_state.reserve_subsidy_units) {
    state->protocol_reserve_balance_units -= reward_state.reserve_subsidy_units;
  } else {
    state->protocol_reserve_balance_units = 0;
  }
}

void accrue_epoch_reward_state_for_block(const CanonicalDerivationConfig& cfg, CanonicalDerivedState* state, const Block& block,
                                         const std::vector<PubKey32>& committee,
                                         const std::vector<FinalitySig>& finality_sigs) {
  const auto epoch_start = committee_epoch_start(block.header.height, cfg.network.committee_epoch_blocks);
  auto& reward_state = state->epoch_reward_states[epoch_start];
  reward_state.epoch_start_height = epoch_start;
  const auto gross_reward = reward_units(block.header.height);
  const auto prior_gross_reward = reward_state.total_reward_units + reward_state.reserve_accrual_units;
  const auto next_gross_reward = prior_gross_reward + gross_reward;
  const auto next_reserve =
      wide::mul_div_u64(next_gross_reward, static_cast<std::uint64_t>(RESERVE_ACCRUAL_BPS), 10'000ULL);
  const auto reserve_delta = next_reserve - reward_state.reserve_accrual_units;
  reward_state.reserve_accrual_units = next_reserve;
  reward_state.total_reward_units += gross_reward - reserve_delta;
  if (block.header.height >= EMISSION_BLOCKS) reward_state.fee_pool_units += 0;
  const auto inputs = compute_deterministic_epoch_reward_inputs(cfg, *state, block.header.height, block.header.leader_pubkey,
                                                                committee, finality_sigs);
  for (const auto& [pub, units] : inputs.expected_participation_units) reward_state.expected_participation_units[pub] += units;
  for (const auto& [pub, units] : inputs.observed_participation_units) reward_state.observed_participation_units[pub] += units;
  for (const auto& [pub, units] : inputs.reward_score_units) reward_state.reward_score_units[pub] += units;
}

void accrue_epoch_reward_state_for_frontier(const CanonicalDerivationConfig& cfg, CanonicalDerivedState* state,
                                            const FrontierTransition& transition, const std::vector<PubKey32>& committee) {
  const auto epoch_start = committee_epoch_start(transition.height, cfg.network.committee_epoch_blocks);
  auto& reward_state = state->epoch_reward_states[epoch_start];
  reward_state.epoch_start_height = epoch_start;
  const auto gross_reward = reward_units(transition.height);
  const auto prior_gross_reward = reward_state.total_reward_units + reward_state.reserve_accrual_units;
  const auto next_gross_reward = prior_gross_reward + gross_reward;
  const auto next_reserve =
      wide::mul_div_u64(next_gross_reward, static_cast<std::uint64_t>(RESERVE_ACCRUAL_BPS), 10'000ULL);
  const auto reserve_delta = next_reserve - reward_state.reserve_accrual_units;
  reward_state.reserve_accrual_units = next_reserve;
  reward_state.total_reward_units += gross_reward - reserve_delta;
  if (transition.height >= EMISSION_BLOCKS) reward_state.fee_pool_units += transition.settlement.current_fees;
  const auto inputs = compute_deterministic_epoch_reward_inputs(cfg, *state, transition.height, transition.leader_pubkey,
                                                                committee, transition.observed_signers);
  for (const auto& [pub, units] : inputs.expected_participation_units) reward_state.expected_participation_units[pub] += units;
  for (const auto& [pub, units] : inputs.observed_participation_units) reward_state.observed_participation_units[pub] += units;
  for (const auto& [pub, units] : inputs.reward_score_units) reward_state.reward_score_units[pub] += units;
}

void update_validator_liveness_from_finality(const CanonicalDerivationConfig& cfg, CanonicalDerivedState* state,
                                             std::uint64_t height, const std::vector<PubKey32>& committee,
                                             const std::vector<FinalitySig>& finality_sigs) {
  if (committee.empty()) return;
  const auto participants = committee_participants_from_finality(committee, finality_sigs);
  std::set<PubKey32> participant_set(participants.begin(), participants.end());
  state->last_participation_eligible_signers = participant_set.size();

  auto& all = state->validators.mutable_all();
  for (const auto& pub : committee) {
    auto it = all.find(pub);
    if (it == all.end()) continue;
    auto& info = it->second;
    if (info.status != ValidatorStatus::ACTIVE && info.status != ValidatorStatus::SUSPENDED) continue;
    info.liveness_window_start = state->validator_liveness_window_start_height;
    ++info.eligible_count_window;
    if (participant_set.find(pub) != participant_set.end()) ++info.participated_count_window;
  }

  if (!validator_liveness_window_should_rollover(height, state->validator_liveness_window_start_height,
                                                 cfg.validator_liveness_window_blocks)) {
    return;
  }

  for (auto& [_, info] : all) {
    const std::uint64_t eligible = info.eligible_count_window;
    const std::uint64_t participated = info.participated_count_window;
    if (eligible >= 10) {
      const std::uint64_t miss = eligible >= participated ? (eligible - participated) : 0;
      const std::uint32_t miss_rate = static_cast<std::uint32_t>((miss * 100) / eligible);
      if (miss_rate >= cfg.validator_miss_rate_exit_threshold_percent) {
        info.status = ValidatorStatus::EXITING;
        info.last_exit_height = height;
        info.unbond_height = height;
        info.penalty_strikes += 1;
      } else if (miss_rate >= cfg.validator_miss_rate_suspend_threshold_percent) {
        info.status = ValidatorStatus::SUSPENDED;
        info.suspended_until_height = height + cfg.validator_suspend_duration_blocks;
        info.penalty_strikes += 1;
      }
    }
    info.eligible_count_window = 0;
    info.participated_count_window = 0;
    info.liveness_window_start = height + 1;
  }
  state->validator_liveness_window_start_height =
      validator_liveness_next_window_start(height, state->validator_liveness_window_start_height,
                                           cfg.validator_liveness_window_blocks);
}

void update_validator_liveness_from_observed_participants(const CanonicalDerivationConfig& cfg, CanonicalDerivedState* state,
                                                          std::uint64_t height, const std::vector<PubKey32>& committee,
                                                          const std::vector<PubKey32>& participants) {
  if (committee.empty()) return;
  std::set<PubKey32> participant_set(participants.begin(), participants.end());
  state->last_participation_eligible_signers = participant_set.size();

  auto& all = state->validators.mutable_all();
  for (const auto& pub : committee) {
    auto it = all.find(pub);
    if (it == all.end()) continue;
    auto& info = it->second;
    if (info.status != ValidatorStatus::ACTIVE && info.status != ValidatorStatus::SUSPENDED) continue;
    info.liveness_window_start = state->validator_liveness_window_start_height;
    ++info.eligible_count_window;
    if (participant_set.find(pub) != participant_set.end()) ++info.participated_count_window;
  }

  if (!validator_liveness_window_should_rollover(height, state->validator_liveness_window_start_height,
                                                 cfg.validator_liveness_window_blocks)) {
    return;
  }

  for (auto& [_, info] : all) {
    const std::uint64_t eligible = info.eligible_count_window;
    const std::uint64_t participated = info.participated_count_window;
    if (eligible >= 10) {
      const std::uint64_t miss = eligible >= participated ? (eligible - participated) : 0;
      const std::uint32_t miss_rate = static_cast<std::uint32_t>((miss * 100) / eligible);
      if (miss_rate >= cfg.validator_miss_rate_exit_threshold_percent) {
        info.status = ValidatorStatus::EXITING;
        info.last_exit_height = height;
        info.unbond_height = height;
        info.penalty_strikes += 1;
      } else if (miss_rate >= cfg.validator_miss_rate_suspend_threshold_percent) {
        info.status = ValidatorStatus::SUSPENDED;
        info.suspended_until_height = height + cfg.validator_suspend_duration_blocks;
        info.penalty_strikes += 1;
      }
    }
    info.eligible_count_window = 0;
    info.participated_count_window = 0;
    info.liveness_window_start = height + 1;
  }
  state->validator_liveness_window_start_height =
      validator_liveness_next_window_start(height, state->validator_liveness_window_start_height,
                                           cfg.validator_liveness_window_blocks);
}

void apply_validator_state_changes_from_txs(const CanonicalDerivationConfig& cfg, CanonicalDerivedState* state,
                                            const std::vector<Tx>& txs, std::size_t input_start_index,
                                            const UtxoSetV2& pre_utxos, std::uint64_t height) {
  state->validators.set_rules(ValidatorRules{
      .min_bond = effective_validator_min_bond_for_height(cfg, *state, height),
      .warmup_blocks = cfg.validator_warmup_blocks,
      .cooldown_blocks = cfg.validator_cooldown_blocks,
  });
  if (cfg.validator_join_limit_window_blocks > 0) {
    advance_validator_join_window(height, cfg.validator_join_limit_window_blocks, &state->validator_join_window_start_height,
                                  &state->validator_join_count_in_window);
  }

  for (size_t txi = input_start_index; txi < txs.size(); ++txi) {
    const auto& tx = txs[txi];
    for (const auto& in : tx.inputs) {
      OutPoint op{in.prev_txid, in.prev_index};
      auto it = pre_utxos.find(op);
      if (it == pre_utxos.end()) continue;
      const auto prev_out = transparent_txout_from_utxo_entry(it->second);
      if (!prev_out.has_value()) continue;
      PubKey32 pub{};
      SlashEvidence evidence;
      if (is_validator_register_script(prev_out->script_pubkey, &pub)) {
        if (parse_slash_script_sig(in.script_sig, &evidence)) {
          state->validators.ban(pub, height);
          (void)state->validators.finalize_withdrawal(pub);
        } else {
          state->validators.request_unbond(pub, height);
        }
        continue;
      }
      if (is_validator_unbond_script(prev_out->script_pubkey, &pub)) {
        if (parse_slash_script_sig(in.script_sig, &evidence)) state->validators.ban(pub, height);
        (void)state->validators.finalize_withdrawal(pub);
      }
    }
  }

  for (const auto& tx : txs) {
    const Hash32 txid = tx.txid();
    for (std::uint32_t out_i = 0; out_i < tx.outputs.size(); ++out_i) {
      const auto& out = tx.outputs[out_i];
      PubKey32 onboarding_validator_pub{};
      PubKey32 onboarding_payout_pub{};
      Sig64 onboarding_pop{};
      if (is_onboarding_registration_script(out.script_pubkey, &onboarding_validator_pub, &onboarding_payout_pub,
                                            &onboarding_pop)) {
        std::string err;
        (void)state->validators.register_onboarding(
            onboarding_validator_pub, height, &err,
            canonical_operator_id_from_join_request(onboarding_payout_pub));
        continue;
      }
      PubKey32 validator_pub{};
      PubKey32 payout_pub{};
      Sig64 pop{};
      if (!is_validator_join_request_script(out.script_pubkey, &validator_pub, &payout_pub, &pop)) continue;

      for (std::uint32_t bond_i = 0; bond_i < tx.outputs.size(); ++bond_i) {
        PubKey32 bond_pub{};
        if (!is_validator_register_script(tx.outputs[bond_i].script_pubkey, &bond_pub) || bond_pub != validator_pub) continue;
        ValidatorJoinRequest req;
        req.request_txid = txid;
        req.validator_pubkey = validator_pub;
        req.payout_pubkey = payout_pub;
        req.bond_outpoint = OutPoint{txid, bond_i};
        req.bond_amount = tx.outputs[bond_i].value;
        req.requested_height = height;
        if (cfg.validator_join_limit_window_blocks > 0 && cfg.validator_join_limit_max_new > 0 &&
            state->validator_join_count_in_window >= cfg.validator_join_limit_max_new) {
          break;
        }
        std::string err;
        if (state->validators.register_bond(req.validator_pubkey, req.bond_outpoint, height, req.bond_amount, &err,
                                            canonical_operator_id_from_join_request(req.payout_pubkey))) {
          req.status = ValidatorJoinRequestStatus::APPROVED;
          req.approved_height = height;
          state->validator_join_requests[txid] = req;
          if (cfg.validator_join_limit_window_blocks > 0) ++state->validator_join_count_in_window;
        }
        break;
      }
    }
  }
  state->validators.advance_height(height + 1);
}

void apply_validator_state_changes(const CanonicalDerivationConfig& cfg, CanonicalDerivedState* state, const Block& block,
                                   const UtxoSetV2& pre_utxos, std::uint64_t height) {
  apply_validator_state_changes_from_txs(cfg, state, block.txs, 1, pre_utxos, height);
}

}  // namespace

Hash32 canonical_finality_certificate_hash(const FinalityCertificate& cert) {
  return canonical_finality_certificate_hash_impl(cert);
}

Hash32 frontier_finality_link_hash(const FrontierTransition& transition) {
  codec::ByteWriter w;
  w.bytes(Bytes{'F', 'I', 'N', 'A', 'L', 'I', 'S', '_', 'F', 'R', 'O', 'N', 'T', 'I', 'E', 'R',
                '_', 'F', 'I', 'N', 'A', 'L', 'I', 'T', 'Y', '_', 'V', '1'});
  w.u64le(transition.height);
  w.u32le(transition.round);
  w.bytes_fixed(transition.transition_id());
  w.u32le(transition.quorum_threshold);
  w.varint(transition.observed_signers.size());
  for (const auto& pub : transition.observed_signers) w.bytes_fixed(pub);
  return crypto::sha256d(w.data());
}

bool populate_frontier_transition_metadata(const CanonicalDerivationConfig& cfg, const CanonicalDerivedState& prev,
                                           std::uint64_t height, std::uint32_t round, const PubKey32& leader_pubkey,
                                           const std::vector<PubKey32>& observed_signers,
                                           std::uint64_t accepted_fee_units, const UtxoSetV2& post_execution_utxos,
                                           FrontierTransition* transition,
                                           std::string* error) {
  if (!transition) {
    if (error) *error = "missing-transition-output";
    return false;
  }
  if (height != prev.finalized_height + 1) {
    if (error) *error = "frontier-height-not-sequential";
    return false;
  }
  const auto committee = canonical_committee_for_height_round(cfg, prev, height, round);
  if (committee.empty()) {
    if (error) *error = "missing-canonical-committee";
    return false;
  }
  const auto leader = canonical_leader_for_height_round(cfg, prev, height, round);
  if (!leader.has_value()) {
    if (error) *error = "missing-canonical-leader";
    return false;
  }
  if (*leader != leader_pubkey) {
    if (error) *error = "frontier-leader-mismatch";
    return false;
  }
  const auto quorum = static_cast<std::uint32_t>(quorum_threshold(committee.size()));
  const auto canonical_signers = canonicalize_signer_pubkeys(observed_signers, quorum);
  std::set<PubKey32> committee_set(committee.begin(), committee.end());
  for (const auto& pub : canonical_signers) {
    if (committee_set.find(pub) == committee_set.end()) {
      if (error) *error = "frontier-non-committee-signer";
      return false;
    }
  }

  // Frontier transitions normally chain to a finalized transition identity, but
  // the genesis handoff intentionally uses the raw finalized identity value so
  // height-0 block-artifact genesis can seed the first frontier transition.
  transition->prev_finalized_hash = prev.finalized_identity.id;
  transition->prev_finality_link_hash = prev.last_finality_certificate_hash;
  transition->height = height;
  transition->round = round;
  transition->leader_pubkey = leader_pubkey;
  transition->quorum_threshold = quorum;
  transition->observed_signers = canonical_signers;
  transition->settlement = derive_frontier_settlement_from_state(cfg, prev, height, leader_pubkey, accepted_fee_units);
  transition->settlement_commitment = transition->settlement.commitment();
  UtxoSetV2 settled_utxos = post_execution_utxos;
  apply_frontier_settlement_to_utxos(*transition, &settled_utxos);
  transition->next_state_root = frontier_utxo_state_root(settled_utxos);
  return true;
}

bool populate_frontier_transition_metadata_legacy_for_replay(const CanonicalDerivationConfig& cfg,
                                                             const CanonicalDerivedState& prev, std::uint64_t height,
                                                             std::uint32_t round, const PubKey32& leader_pubkey,
                                                             const std::vector<PubKey32>& observed_signers,
                                                             std::uint64_t accepted_fee_units,
                                                             const UtxoSetV2& post_execution_utxos,
                                                             FrontierTransition* transition,
                                                             std::string* error) {
  if (!transition) {
    if (error) *error = "missing-transition-output";
    return false;
  }
  if (height != prev.finalized_height + 1) {
    if (error) *error = "frontier-height-not-sequential";
    return false;
  }
  const auto committee = legacy_canonical_committee_for_height_round(cfg, prev, height, round);
  if (committee.empty()) {
    if (error) *error = "missing-canonical-committee";
    return false;
  }
  const auto leader = legacy_canonical_leader_for_height_round(cfg, prev, height, round);
  if (!leader.has_value()) {
    if (error) *error = "missing-canonical-leader";
    return false;
  }
  if (*leader != leader_pubkey) {
    if (error) *error = "frontier-leader-mismatch";
    return false;
  }
  const auto quorum = static_cast<std::uint32_t>(quorum_threshold(committee.size()));
  const auto canonical_signers = canonicalize_signer_pubkeys(observed_signers, quorum);
  std::set<PubKey32> committee_set(committee.begin(), committee.end());
  for (const auto& pub : canonical_signers) {
    if (committee_set.find(pub) == committee_set.end()) {
      if (error) *error = "frontier-non-committee-signer";
      return false;
    }
  }

  transition->prev_finalized_hash = prev.finalized_identity.id;
  transition->prev_finality_link_hash = prev.last_finality_certificate_hash;
  transition->height = height;
  transition->round = round;
  transition->leader_pubkey = leader_pubkey;
  transition->quorum_threshold = quorum;
  transition->observed_signers = canonical_signers;
  transition->settlement = derive_frontier_settlement_from_state(cfg, prev, height, leader_pubkey, accepted_fee_units);
  transition->settlement_commitment = transition->settlement.commitment();
  UtxoSetV2 settled_utxos = post_execution_utxos;
  apply_frontier_settlement_to_utxos(*transition, &settled_utxos);
  transition->next_state_root = frontier_utxo_state_root(settled_utxos);
  return true;
}

bool load_certified_frontier_record_from_storage(const storage::DB& db, const FrontierTransition& transition,
                                                 CanonicalFrontierRecord* out, std::string* error) {
  if (!out) {
    if (error) *error = "missing-frontier-record-output";
    return false;
  }

  CertifiedIngressLaneRecords lane_records;
  for (std::size_t lane = 0; lane < finalis::INGRESS_LANE_COUNT; ++lane) {
    const auto required_seq = transition.next_vector.lane_max_seq[lane];
    auto lane_state = db.get_lane_state(static_cast<std::uint32_t>(lane));
    if (required_seq == 0 && !lane_state.has_value()) continue;
    if (!lane_state.has_value() || lane_state->max_seq < required_seq) {
      if (error) *error = "frontier-storage-lane-tip-too-low transition=" + hex_encode32(transition.transition_id()) +
                          " lane=" + std::to_string(lane) + " required=" + std::to_string(required_seq);
      return false;
    }
    const auto from_seq = transition.prev_vector.lane_max_seq[lane] + 1;
    const auto to_seq = transition.next_vector.lane_max_seq[lane];
    if (to_seq < from_seq) continue;
    const auto cert_bytes = db.load_ingress_lane_range(static_cast<std::uint32_t>(lane), from_seq, to_seq);
    const auto expected = to_seq - from_seq + 1;
    if (cert_bytes.size() != expected) {
      if (error) *error = "frontier-storage-missing-lane-record transition=" + hex_encode32(transition.transition_id()) +
                          " lane=" + std::to_string(lane) + " range=(" + std::to_string(from_seq) + "," +
                          std::to_string(to_seq) + "]";
      return false;
    }
    for (const auto& raw_cert : cert_bytes) {
      const auto cert = IngressCertificate::parse(raw_cert);
      if (!cert.has_value()) {
        if (error) *error = "frontier-storage-invalid-lane-record transition=" + hex_encode32(transition.transition_id()) +
                            " lane=" + std::to_string(lane);
        return false;
      }
      const auto tx_bytes = db.get_ingress_bytes(cert->txid);
      if (!tx_bytes.has_value()) {
        if (error) *error = "frontier-storage-missing-ingress-bytes transition=" +
                            hex_encode32(transition.transition_id()) + " lane=" + std::to_string(lane) +
                            " seq=" + std::to_string(cert->seq);
        return false;
      }
      lane_records[lane].push_back(CertifiedIngressRecord{*cert, *tx_bytes});
    }
  }

  *out = CanonicalFrontierRecord{transition, lane_records};
  return true;
}

std::vector<PubKey32> canonical_committee_for_height_round(const CanonicalDerivationConfig& cfg,
                                                           const CanonicalDerivedState& state, std::uint64_t height,
                                                           std::uint32_t round) {
  if (height == 0) return {};
  const auto epoch_start = committee_epoch_start(height, cfg.network.committee_epoch_blocks);
  auto it = state.finalized_committee_checkpoints.find(epoch_start);
  if (it == state.finalized_committee_checkpoints.end()) return {};
  return checkpoint_committee_for_round(it->second, round);
}

std::vector<PubKey32> legacy_canonical_committee_for_height_round(const CanonicalDerivationConfig& cfg,
                                                                  const CanonicalDerivedState& state,
                                                                  std::uint64_t height, std::uint32_t round) {
  if (height == 0) return {};
  const auto epoch_start = committee_epoch_start(height, cfg.network.committee_epoch_blocks);
  auto it = state.finalized_committee_checkpoints.find(epoch_start);
  if (it == state.finalized_committee_checkpoints.end()) return {};
  return legacy_checkpoint_committee_for_round(it->second, round);
}

std::optional<PubKey32> canonical_leader_for_height_round(const CanonicalDerivationConfig& cfg,
                                                          const CanonicalDerivedState& state, std::uint64_t height,
                                                          std::uint32_t round) {
  if (height == 0) return std::nullopt;
  const auto epoch_start = committee_epoch_start(height, cfg.network.committee_epoch_blocks);
  auto it = state.finalized_committee_checkpoints.find(epoch_start);
  if (it == state.finalized_committee_checkpoints.end()) return std::nullopt;
  if (auto fallback = checkpoint_ticket_pow_fallback_member_for_round(it->second, round); fallback.has_value()) {
    return fallback;
  }
  const auto schedule = proposer_schedule_from_checkpoint(cfg, state, it->second, height);
  if (schedule.empty()) return std::nullopt;
  return schedule[static_cast<std::size_t>(round) % schedule.size()];
}

std::optional<PubKey32> legacy_canonical_leader_for_height_round(const CanonicalDerivationConfig& cfg,
                                                                 const CanonicalDerivedState& state,
                                                                 std::uint64_t height, std::uint32_t round) {
  if (height == 0) return std::nullopt;
  const auto epoch_start = committee_epoch_start(height, cfg.network.committee_epoch_blocks);
  auto it = state.finalized_committee_checkpoints.find(epoch_start);
  if (it == state.finalized_committee_checkpoints.end()) return std::nullopt;
  if (auto fallback = legacy_checkpoint_ticket_pow_fallback_member_for_round(it->second, round); fallback.has_value()) {
    return fallback;
  }
  const auto schedule = proposer_schedule_from_checkpoint(cfg, state, it->second, height);
  if (schedule.empty()) return std::nullopt;
  return schedule[static_cast<std::size_t>(round) % schedule.size()];
}

bool build_genesis_canonical_state(const CanonicalDerivationConfig& cfg, const CanonicalGenesisState& genesis,
                                   CanonicalDerivedState* out, std::string* error) {
  if (!out) {
    if (error) *error = "missing-output";
    return false;
  }
  CanonicalDerivedState state;
  state.finalized_height = 0;
  state.finalized_frontier = 0;
  state.finalized_frontier_vector = FrontierVector{};
  state.finalized_lane_roots = FrontierLaneRoots{};
  state.finalized_identity = FinalizedIdentity::genesis(genesis.genesis_artifact_id);
  state.last_finality_certificate_hash = zero_hash();
  state.finalized_randomness = initial_finalized_randomness(cfg.network, cfg.chain_id);
  state.committee_epoch_randomness_cache[1] = state.finalized_randomness;
  state.validators.set_rules(ValidatorRules{
      .min_bond = std::max<std::uint64_t>(cfg.validator_bond_min_amount, cfg.validator_min_bond_override),
      .warmup_blocks = cfg.validator_warmup_blocks,
      .cooldown_blocks = cfg.validator_cooldown_blocks,
  });
  for (const auto& pub : genesis.initial_validators) {
    ValidatorInfo vi;
    vi.status = ValidatorStatus::ACTIVE;
    vi.joined_height = 0;
    vi.bonded_amount = genesis_validator_bond_amount();
    vi.operator_id = pub;
    vi.has_bond = true;
    vi.bond_outpoint = OutPoint{zero_hash(), 0};
    state.validators.upsert(pub, vi);
  }
  state.availability_state.current_epoch = committee_epoch_start(1, cfg.network.committee_epoch_blocks);
  refresh_availability_operator_state(cfg, state.finalized_identity, state.validators, false, &state.availability_state);
  const auto difficulty_bits = ticket_difficulty_bits_for_epoch(cfg, state, 1, state.validators.active_sorted(1).size());
  AvailabilityCommitteeDecision genesis_decision;
  const auto genesis_active = finalized_committee_candidates_for_height(cfg, state, 1, difficulty_bits, &genesis_decision);
  storage::FinalizedCommitteeCheckpoint checkpoint;
  checkpoint.epoch_start_height = 1;
  checkpoint.epoch_seed = committee_epoch_seed(state.finalized_randomness, 1);
  checkpoint.ticket_difficulty_bits = difficulty_bits;
  checkpoint.derivation_mode = genesis_decision.mode;
  checkpoint.fallback_reason = genesis_decision.fallback_reason;
  checkpoint.availability_eligible_operator_count = genesis_decision.eligible_operator_count;
  checkpoint.availability_min_eligible_operators = genesis_decision.min_eligible_operators;
  checkpoint.adaptive_target_committee_size = genesis_decision.adaptive.target_committee_size;
  checkpoint.adaptive_min_eligible = genesis_decision.adaptive.min_eligible_operators;
  checkpoint.adaptive_min_bond = genesis_decision.adaptive.min_bond;
  checkpoint.qualified_depth = genesis_decision.adaptive.qualified_depth;
  checkpoint.target_expand_streak = genesis_decision.adaptive.target_expand_streak;
  checkpoint.target_contract_streak = genesis_decision.adaptive.target_contract_streak;
  checkpoint.ordered_members = select_finalized_committee(genesis_active, checkpoint.epoch_seed,
                                                          std::min<std::size_t>(
                                                              {cfg.max_committee,
                                                               static_cast<std::size_t>(genesis_decision.effective_committee_size),
                                                               genesis_active.size()}));
  checkpoint.ordered_operator_ids.reserve(checkpoint.ordered_members.size());
  checkpoint.ordered_base_weights.reserve(checkpoint.ordered_members.size());
  checkpoint.ordered_ticket_bonus_bps.reserve(checkpoint.ordered_members.size());
  checkpoint.ordered_final_weights.reserve(checkpoint.ordered_members.size());
  checkpoint.ordered_ticket_hashes.reserve(checkpoint.ordered_members.size());
  checkpoint.ordered_ticket_nonces.reserve(checkpoint.ordered_members.size());
  for (const auto& pub : checkpoint.ordered_members) {
    auto it = std::find_if(genesis_active.begin(), genesis_active.end(), [&](const auto& candidate) {
      return candidate.pubkey == pub;
    });
    if (it == genesis_active.end()) {
      if (error) *error = "genesis-checkpoint-member-missing-from-candidates";
      return false;
    }
    checkpoint.ordered_operator_ids.push_back(it->selection_id == PubKey32{} ? it->pubkey : it->selection_id);
    checkpoint.ordered_base_weights.push_back(it->effective_weight);
    checkpoint.ordered_ticket_bonus_bps.push_back(it->ticket_bonus_bps);
    checkpoint.ordered_final_weights.push_back(finalized_committee_candidate_strength(*it));
    checkpoint.ordered_ticket_hashes.push_back(it->ticket_work_hash);
    checkpoint.ordered_ticket_nonces.push_back(it->ticket_nonce);
  }
  state.finalized_committee_checkpoints[1] = checkpoint;
  state.state_commitment = consensus_state_commitment(cfg, state);
  *out = std::move(state);
  return true;
}

std::uint64_t genesis_validator_bond_amount() { return kAdaptiveMinBondFloor; }

bool verify_frontier_record_against_state(const CanonicalDerivationConfig& cfg, const CanonicalDerivedState& prev,
                                          const CanonicalFrontierRecord& record, FrontierExecutionResult* recomputed,
                                          std::string* error) {
  const auto reconstruct_legacy_frontier_cursor =
      [&](const std::vector<Bytes>& ordered_records, FrontierVector* next_vector, FrontierLaneRoots* next_lane_roots,
          std::string* cursor_error) -> bool {
    if (!next_vector || !next_lane_roots) {
      if (cursor_error) *cursor_error = "missing-legacy-frontier-cursor-output";
      return false;
    }
    *next_vector = prev.finalized_frontier_vector;
    *next_lane_roots = prev.finalized_lane_roots;
    for (const auto& raw : ordered_records) {
      const auto tx = parse_any_tx(raw);
      if (!tx.has_value()) {
        if (cursor_error) *cursor_error = "frontier-certified-ingress-parse-failed";
        return false;
      }
      const auto lane = assign_ingress_lane(*tx);
      if (lane >= finalis::INGRESS_LANE_COUNT) {
        if (cursor_error) *cursor_error = "frontier-certified-ingress-lane-out-of-range";
        return false;
      }
      ++next_vector->lane_max_seq[lane];
      (*next_lane_roots)[lane] = compute_lane_root_append((*next_lane_roots)[lane], crypto::sha256d(raw));
    }
    return true;
  };

  const auto build_validation_context = [&](std::uint64_t height) {
    const auto min_bond_amount = effective_validator_min_bond_for_height(cfg, prev, height);
    return SpecialValidationContext{
        .network = &cfg.network,
        .chain_id = &cfg.chain_id,
        .validators = &prev.validators,
        .current_height = height,
        .enforce_variable_bond_range = true,
        .min_bond_amount = min_bond_amount,
        .max_bond_amount = std::max<std::uint64_t>(cfg.validator_bond_max_amount, min_bond_amount),
        .unbond_delay_blocks = cfg.network.unbond_delay_blocks,
        .is_committee_member =
            [&](const PubKey32& pub, std::uint64_t h, std::uint32_t r) {
              const auto committee = canonical_committee_for_height_round(cfg, prev, h, r);
              return std::find(committee.begin(), committee.end(), pub) != committee.end();
            },
        .finalized_hash_at_height =
            [&](std::uint64_t h) -> std::optional<Hash32> {
              if (h == 0) return zero_hash();
              if (cfg.finalized_hash_at_height) return cfg.finalized_hash_at_height(h);
              if (h == prev.finalized_height) return prev.finalized_identity.id;
              return std::nullopt;
            },
        .confidential_policy = &cfg.confidential_policy,
    };
  };

  bool has_lane_records = false;
  for (const auto& lane : record.lane_records) {
    if (!lane.empty()) {
      has_lane_records = true;
      break;
    }
  }
  if (!has_lane_records) {
    if (record.ordered_records.size() !=
        (record.transition.next_frontier >= record.transition.prev_frontier
             ? static_cast<std::size_t>(record.transition.next_frontier - record.transition.prev_frontier)
             : std::numeric_limits<std::size_t>::max())) {
      if (error) *error = "frontier-ingress-slice-size-mismatch";
      return false;
    }
    const auto expected_height = prev.finalized_height + 1;
    if (record.transition.height != expected_height) {
      if (error) *error = "frontier-height-not-sequential";
      return false;
    }
    if (!finalized_identity_valid_for_frontier_parent(prev)) {
      if (error) *error = "frontier-parent-identity-kind-mismatch";
      return false;
    }
    if (record.transition.prev_finalized_hash != prev.finalized_identity.id) {
      if (error) *error = "frontier-prev-finalized-hash-mismatch";
      return false;
    }
    if (record.transition.prev_finality_link_hash != prev.last_finality_certificate_hash) {
      if (error) *error = "frontier-prev-finality-link-mismatch";
      return false;
    }
    if (record.transition.prev_frontier != prev.finalized_frontier) {
      if (error) *error = "frontier-prev-frontier-mismatch";
      return false;
    }
    if (record.transition.next_frontier < record.transition.prev_frontier) {
      if (error) *error = "frontier-non-monotone";
      return false;
    }
    const auto expected_next_frontier =
        record.transition.prev_frontier + static_cast<std::uint64_t>(record.ordered_records.size());
    if (record.transition.next_frontier != expected_next_frontier) {
      if (error) *error = "frontier-continuity-mismatch";
      return false;
    }
    const auto expected_prev_state_root = frontier_utxo_state_root(prev.utxos);
    if (record.transition.prev_state_root != expected_prev_state_root) {
      if (error) *error = "frontier-prev-state-root-mismatch";
      return false;
    }
    const auto expected_slice_commitment = frontier_ordered_slice_commitment(record.ordered_records);
    if (record.transition.ordered_slice_commitment != expected_slice_commitment) {
      if (error) *error = "frontier-ordered-slice-commitment-mismatch";
      return false;
    }
    auto vctx = build_validation_context(record.transition.height);
    FrontierExecutionResult result;
    if (!execute_frontier_slice(prev.utxos, prev.finalized_frontier, record.ordered_records, &vctx, &result, error)) {
      if (error && error->empty()) *error = "frontier-execution-failed";
      return false;
    }
    FrontierVector reconstructed_next_vector{};
    FrontierLaneRoots reconstructed_next_lane_roots{};
    if (!reconstruct_legacy_frontier_cursor(record.ordered_records, &reconstructed_next_vector, &reconstructed_next_lane_roots,
                                            error)) {
      return false;
    }
    result.transition.prev_vector = prev.finalized_frontier_vector;
    result.transition.next_vector = reconstructed_next_vector;
    result.transition.ingress_commitment =
        frontier_ingress_commitment(result.transition.prev_vector, result.transition.next_vector, reconstructed_next_lane_roots);
    result.next_lane_roots = reconstructed_next_lane_roots;
    if (record.transition.prev_vector != result.transition.prev_vector) {
      if (error) *error = "frontier-prev-vector-mismatch";
      return false;
    }
    if (record.transition.next_vector != result.transition.next_vector) {
      if (error) *error = "frontier-next-vector-mismatch";
      return false;
    }
    if (record.transition.ingress_commitment != result.transition.ingress_commitment) {
      if (error) *error = "frontier-ingress-commitment-mismatch";
      return false;
    }
    if (result.transition.prev_frontier != record.transition.prev_frontier) {
      if (error) *error = "frontier-prev-frontier-recompute-mismatch";
      return false;
    }
    if (result.transition.next_frontier != record.transition.next_frontier) {
      if (error) *error = "frontier-next-frontier-mismatch";
      return false;
    }
    if (result.transition.prev_state_root != record.transition.prev_state_root) {
      if (error) *error = "frontier-prev-state-root-recompute-mismatch";
      return false;
    }
    if (result.transition.ordered_slice_commitment != record.transition.ordered_slice_commitment) {
      if (error) *error = "frontier-ordered-slice-recompute-mismatch";
      return false;
    }
    if (result.transition.decisions_commitment != record.transition.decisions_commitment) {
      if (error) *error = "frontier-decisions-commitment-mismatch";
      return false;
    }
    FrontierTransition expected_transition = result.transition;
    const bool have_current_expected = populate_frontier_transition_metadata(
        cfg, prev, record.transition.height, record.transition.round, record.transition.leader_pubkey,
        record.transition.observed_signers, result.accepted_fee_units, result.next_utxos, &expected_transition, error);
    FrontierTransition legacy_expected_transition = result.transition;
    std::string legacy_error;
    const bool have_legacy_expected = populate_frontier_transition_metadata_legacy_for_replay(
        cfg, prev, record.transition.height, record.transition.round, record.transition.leader_pubkey,
        record.transition.observed_signers, result.accepted_fee_units, result.next_utxos, &legacy_expected_transition,
        &legacy_error);
    const auto transition_metadata_matches = [&](const FrontierTransition& expected) {
      return record.transition.quorum_threshold == expected.quorum_threshold &&
             record.transition.observed_signers == expected.observed_signers &&
             record.transition.settlement_commitment == record.transition.settlement.commitment() &&
             record.transition.settlement_commitment == expected.settlement_commitment &&
             record.transition.settlement.serialize() == expected.settlement.serialize() &&
             record.transition.next_state_root == expected.next_state_root;
    };
    std::vector<PubKey32> effective_committee = canonical_committee_for_height_round(cfg, prev, record.transition.height,
                                                                                     record.transition.round);
    if (!have_current_expected || !transition_metadata_matches(expected_transition)) {
      if (!have_legacy_expected || !transition_metadata_matches(legacy_expected_transition)) {
        if (record.transition.quorum_threshold != expected_transition.quorum_threshold) {
          if (error) *error = "frontier-quorum-threshold-mismatch";
        } else if (!have_current_expected && !legacy_error.empty()) {
          if (error) *error = legacy_error;
        } else if (record.transition.observed_signers != expected_transition.observed_signers) {
          if (error) *error = "frontier-observed-signers-mismatch";
        } else if (record.transition.settlement_commitment != record.transition.settlement.commitment()) {
          if (error) *error = "frontier-settlement-self-commitment-mismatch";
        } else if (record.transition.settlement_commitment != expected_transition.settlement_commitment) {
          if (error) *error = "frontier-settlement-commitment-mismatch";
        } else if (record.transition.settlement.serialize() != expected_transition.settlement.serialize()) {
          if (error) *error = "frontier-settlement-mismatch";
        } else if (record.transition.next_state_root != expected_transition.next_state_root) {
          if (error) *error = "frontier-next-state-root-mismatch";
        }
        return false;
      }
      expected_transition = std::move(legacy_expected_transition);
      effective_committee = legacy_canonical_committee_for_height_round(cfg, prev, record.transition.height,
                                                                        record.transition.round);
    }
    result.transition = expected_transition;
    result.effective_committee = std::move(effective_committee);
    apply_frontier_settlement_to_utxos(result.transition, &result.next_utxos);
    if (recomputed) *recomputed = std::move(result);
    return true;
  }

  const auto expected_height = prev.finalized_height + 1;
  if (record.transition.height != expected_height) {
    if (error) *error = "frontier-height-not-sequential";
    return false;
  }
  if (!finalized_identity_valid_for_frontier_parent(prev)) {
    if (error) *error = "frontier-parent-identity-kind-mismatch";
    return false;
  }
  if (record.transition.prev_finalized_hash != prev.finalized_identity.id) {
    if (error) *error = "frontier-prev-finalized-hash-mismatch";
    return false;
  }
  if (record.transition.prev_finality_link_hash != prev.last_finality_certificate_hash) {
    if (error) *error = "frontier-prev-finality-link-mismatch";
    return false;
  }
  if (record.transition.prev_vector != prev.finalized_frontier_vector) {
    if (error) *error = "frontier-prev-vector-mismatch";
    return false;
  }
  for (std::size_t lane = 0; lane < finalis::INGRESS_LANE_COUNT; ++lane) {
    if (record.transition.next_vector.lane_max_seq[lane] < record.transition.prev_vector.lane_max_seq[lane]) {
      if (error) *error = "frontier-vector-rewind lane=" + std::to_string(lane);
      return false;
    }
  }
  if (record.transition.prev_frontier != record.transition.prev_vector.total_count()) {
    if (error) *error = "frontier-prev-frontier-total-mismatch";
    return false;
  }
  if (record.transition.next_frontier != record.transition.next_vector.total_count()) {
    if (error) *error = "frontier-next-frontier-total-mismatch";
    return false;
  }
  if (record.transition.prev_frontier != prev.finalized_frontier) {
    if (error) *error = "frontier-prev-frontier-mismatch";
    return false;
  }
  const auto expected_prev_state_root = frontier_utxo_state_root(prev.utxos);
  if (record.transition.prev_state_root != expected_prev_state_root) {
    if (error) *error = "frontier-prev-state-root-mismatch";
    return false;
  }
  auto vctx = build_validation_context(record.transition.height);
  FrontierExecutionResult result;
  if (!execute_frontier_lane_prefix(prev.utxos, prev.finalized_frontier_vector, record.transition.next_vector,
                                    record.lane_records, prev.finalized_lane_roots, &vctx, &result, error)) {
    if (error && error->empty()) *error = "frontier-execution-failed";
    return false;
  }
  if (result.transition.prev_vector != record.transition.prev_vector) {
    if (error) *error = "frontier-prev-vector-recompute-mismatch";
    return false;
  }
  if (result.transition.next_vector != record.transition.next_vector) {
    if (error) *error = "frontier-next-vector-mismatch";
    return false;
  }
  if (result.transition.prev_state_root != record.transition.prev_state_root) {
    if (error) *error = "frontier-prev-state-root-recompute-mismatch";
    return false;
  }
  if (result.transition.ingress_commitment != record.transition.ingress_commitment) {
    if (error) *error = "frontier-ingress-commitment-mismatch";
    return false;
  }
  if (result.transition.ordered_slice_commitment != record.transition.ordered_slice_commitment) {
    if (error) *error = "frontier-ordered-slice-recompute-mismatch";
    return false;
  }
  if (result.transition.decisions_commitment != record.transition.decisions_commitment) {
    if (error) *error = "frontier-decisions-commitment-mismatch";
    return false;
  }
  FrontierTransition expected_transition = result.transition;
  const bool have_current_expected = populate_frontier_transition_metadata(
      cfg, prev, record.transition.height, record.transition.round, record.transition.leader_pubkey,
      record.transition.observed_signers, result.accepted_fee_units, result.next_utxos, &expected_transition, error);
  FrontierTransition legacy_expected_transition = result.transition;
  std::string legacy_error;
  const bool have_legacy_expected = populate_frontier_transition_metadata_legacy_for_replay(
      cfg, prev, record.transition.height, record.transition.round, record.transition.leader_pubkey,
      record.transition.observed_signers, result.accepted_fee_units, result.next_utxos, &legacy_expected_transition,
      &legacy_error);
  if (!have_current_expected && !have_legacy_expected) {
    return false;
  }
  const auto transition_metadata_matches = [&](const FrontierTransition& expected) {
    return record.transition.quorum_threshold == expected.quorum_threshold &&
           record.transition.observed_signers == expected.observed_signers &&
           record.transition.settlement_commitment == record.transition.settlement.commitment() &&
           record.transition.settlement_commitment == expected.settlement_commitment &&
           record.transition.settlement.serialize() == expected.settlement.serialize() &&
           record.transition.next_state_root == expected.next_state_root;
  };
  std::vector<PubKey32> effective_committee = canonical_committee_for_height_round(cfg, prev, record.transition.height,
                                                                                   record.transition.round);
  if (!have_current_expected || !transition_metadata_matches(expected_transition)) {
    if (!have_legacy_expected || !transition_metadata_matches(legacy_expected_transition)) {
      if (record.transition.quorum_threshold != expected_transition.quorum_threshold) {
        if (error) *error = "frontier-quorum-threshold-mismatch";
      } else if (record.transition.observed_signers != expected_transition.observed_signers) {
        if (error) *error = "frontier-observed-signers-mismatch";
      } else if (record.transition.settlement_commitment != record.transition.settlement.commitment()) {
        if (error) *error = "frontier-settlement-self-commitment-mismatch";
      } else if (record.transition.settlement_commitment != expected_transition.settlement_commitment) {
        if (error) *error = "frontier-settlement-commitment-mismatch";
      } else if (record.transition.settlement.serialize() != expected_transition.settlement.serialize()) {
        if (error) *error = "frontier-settlement-mismatch";
      } else if (record.transition.next_state_root != expected_transition.next_state_root) {
        if (error) *error = "frontier-next-state-root-mismatch";
      }
      return false;
    }
    expected_transition = std::move(legacy_expected_transition);
    effective_committee = legacy_canonical_committee_for_height_round(cfg, prev, record.transition.height,
                                                                      record.transition.round);
  }
  result.transition = expected_transition;
  result.effective_committee = std::move(effective_committee);
  apply_frontier_settlement_to_utxos(result.transition, &result.next_utxos);
  if (recomputed) *recomputed = std::move(result);
  return true;
}

bool apply_frontier_record_impl(const CanonicalDerivationConfig& cfg, const CanonicalDerivedState& prev,
                                const CanonicalFrontierRecord& record, bool recompute_state_commitment,
                                CanonicalDerivedState* out, std::string* error) {
  if (!out) {
    if (error) *error = "missing-output";
    return false;
  }
  FrontierExecutionResult recomputed;
  if (!verify_frontier_record_against_state(cfg, prev, record, &recomputed, error)) return false;

  CanonicalDerivedState next = prev;
  mark_epoch_reward_settled_for_height(cfg, record.transition.height, &next);
  const auto committee = !recomputed.effective_committee.empty()
                             ? recomputed.effective_committee
                             : canonical_committee_for_height_round(cfg, prev, record.transition.height,
                                                                    record.transition.round);
  accrue_epoch_reward_state_for_frontier(cfg, &next, record.transition, committee);
  update_validator_liveness_from_observed_participants(cfg, &next, record.transition.height, committee,
                                                       record.transition.observed_signers);
  const UtxoSetV2 pre_utxos = next.utxos;
  std::vector<Tx> accepted_legacy_txs;
  accepted_legacy_txs.reserve(recomputed.accepted_txs.size());
  for (const auto& tx : recomputed.accepted_txs) {
    if (std::holds_alternative<Tx>(tx)) accepted_legacy_txs.push_back(std::get<Tx>(tx));
  }
  apply_validator_state_changes_from_txs(cfg, &next, accepted_legacy_txs, 0, pre_utxos, record.transition.height);
  next.finalized_height = record.transition.height;
  next.finalized_frontier = recomputed.transition.next_frontier;
  next.finalized_frontier_vector = recomputed.transition.next_vector;
  next.finalized_lane_roots = recomputed.next_lane_roots;
  next.utxos = std::move(recomputed.next_utxos);
  next.finalized_identity = FinalizedIdentity::transition(record.transition.transition_id());
  next.last_finality_certificate_hash = frontier_finality_link_hash(record.transition);
  next.finalized_randomness = advance_finalized_randomness(prev.finalized_randomness, record.transition);
  next.finalized_block_metadata[next.finalized_height] = CanonicalFinalizedMetadata{
      .round = record.transition.round,
      .quorum_threshold = record.transition.quorum_threshold,
      .signature_count = static_cast<std::uint32_t>(record.transition.observed_signers.size()),
  };
  update_availability_from_frontier(cfg, record, &next.availability_state);
  const auto next_epoch = committee_epoch_start(next.finalized_height + 1, cfg.network.committee_epoch_blocks);
  if (next.availability_state.current_epoch == 0) next.availability_state.current_epoch = next_epoch;
  advance_availability_epoch(cfg, next.finalized_identity, next.validators, next_epoch, &next.availability_state);
  availability::normalize_availability_persistent_state(&next.availability_state);
  if (!availability::validate_availability_persistent_state_for_live_derivation(next.availability_state, cfg.availability,
                                                                                error)) {
    if (error && error->empty()) *error = "availability-state-invalid-after-frontier-apply";
    return false;
  }
  if (committee_epoch_start(next.finalized_height + 1, cfg.network.committee_epoch_blocks) == next.finalized_height + 1) {
    const auto next_epoch_start = next.finalized_height + 1;
    next.committee_epoch_randomness_cache[next_epoch_start] = next.finalized_randomness;
    storage::FinalizedCommitteeCheckpoint checkpoint;
    if (!derive_next_epoch_checkpoint_from_state(cfg, next, next_epoch_start, &checkpoint, error)) return false;
    if (!validate_next_epoch_checkpoint_from_state(cfg, next, next_epoch_start, checkpoint, error)) return false;
    if (!validate_checkpoint_schedule_for_height(cfg, next, checkpoint, next_epoch_start, error)) {
      if (error && error->empty()) *error = "checkpoint-schedule-validation-failed";
      return false;
    }
    next.finalized_committee_checkpoints[next_epoch_start] = checkpoint;
  }
  if (recompute_state_commitment) next.state_commitment = consensus_state_commitment(cfg, next);
  *out = std::move(next);
  return true;
}

bool apply_frontier_record(const CanonicalDerivationConfig& cfg, const CanonicalDerivedState& prev,
                           const CanonicalFrontierRecord& record, CanonicalDerivedState* out, std::string* error) {
  return apply_frontier_record_impl(cfg, prev, record, true, out, error);
}

bool derive_canonical_state_from_frontier_chain(const CanonicalDerivationConfig& cfg,
                                                const CanonicalDerivedState& initial_state,
                                                const std::vector<CanonicalFrontierRecord>& chain,
                                                CanonicalDerivedState* out, std::string* error) {
  CanonicalDerivedState state = initial_state;
  for (const auto& record : chain) {
    CanonicalDerivedState next;
    if (!apply_frontier_record_impl(cfg, state, record, false, &next, error)) return false;
    state = std::move(next);
  }
  state.state_commitment = consensus_state_commitment(cfg, state);
  if (out) *out = std::move(state);
  return true;
}

bool derive_canonical_state_from_frontier_storage(const CanonicalDerivationConfig& cfg,
                                                  const CanonicalDerivedState& initial_state,
                                                  const storage::DB& db,
                                                  CanonicalDerivedState* out, std::string* error) {
  CanonicalDerivedState state = initial_state;
  const auto finalized_frontier_height = db.get_finalized_frontier_height();
  if (!finalized_frontier_height.has_value()) {
    if (out) *out = std::move(state);
    return true;
  }

  for (std::uint64_t height = 1; height <= *finalized_frontier_height; ++height) {
    const auto transition_id = db.get_frontier_transition_by_height(height);
    if (!transition_id.has_value()) {
      if (error) *error = "frontier-storage-missing-height-mapping height=" + std::to_string(height);
      return false;
    }
    const auto transition_bytes = db.get_frontier_transition(*transition_id);
    if (!transition_bytes.has_value()) {
      if (error) *error = "frontier-storage-missing-transition height=" + std::to_string(height) +
                          " transition=" + hex_encode32(*transition_id);
      return false;
    }
    const auto transition = FrontierTransition::parse(*transition_bytes);
    if (!transition.has_value()) {
      if (error) *error = "frontier-storage-invalid-transition height=" + std::to_string(height) +
                          " transition=" + hex_encode32(*transition_id);
      return false;
    }
    if (transition->transition_id() != *transition_id) {
      if (error) *error = "frontier-storage-transition-id-mismatch height=" + std::to_string(height) +
                          " expected=" + hex_encode32(*transition_id) +
                          " actual=" + hex_encode32(transition->transition_id());
      return false;
    }
    const auto cert = db.get_finality_certificate_by_height(height);
    if (!cert.has_value()) {
      if (error) *error = "frontier-storage-missing-finality-certificate height=" + std::to_string(height);
      return false;
    }
    if (!verify_frontier_finality_certificate_against_state(cfg, state, *transition, *cert, error)) return false;

    CanonicalFrontierRecord record;
    if (!load_certified_frontier_record_from_storage(db, *transition, &record, error)) return false;
    CanonicalDerivedState next;
    if (!apply_frontier_record_impl(cfg, state, record, false, &next, error)) return false;
    state = std::move(next);
  }

  state.state_commitment = consensus_state_commitment(cfg, state);
  if (out) *out = std::move(state);
  return true;
}

Hash32 consensus_state_commitment(const CanonicalDerivationConfig& cfg, const CanonicalDerivedState& state) {
  std::vector<std::pair<Hash32, Bytes>> utxo_leaves;
  utxo_leaves.reserve(state.utxos.size());
  for (const auto& [op, ue] : state.utxos) {
    utxo_leaves.push_back({utxo_commitment_key(op), utxo_commitment_value(ue)});
  }
  std::vector<std::pair<Hash32, Bytes>> validator_leaves;
  validator_leaves.reserve(state.validators.all().size());
  for (const auto& [pub, info] : state.validators.all()) {
    validator_leaves.push_back({validator_commitment_key(pub), validator_commitment_value(info, cfg.validation_rules_version)});
  }
  const auto utxo_root = crypto::SparseMerkleTree::compute_root_from_leaves(utxo_leaves);
  const auto validator_root = crypto::SparseMerkleTree::compute_root_from_leaves(validator_leaves);

  std::vector<std::pair<Hash32, Bytes>> reward_leaves;
  reward_leaves.reserve(state.epoch_reward_states.size());
  for (const auto& [epoch, reward_state] : state.epoch_reward_states) {
    codec::ByteWriter w;
    w.u64le(epoch);
    w.u64le(reward_state.total_reward_units);
    w.u64le(reward_state.fee_pool_units);
    w.u64le(reward_state.reserve_accrual_units);
    w.u64le(reward_state.reserve_subsidy_units);
    w.u8(reward_state.settled ? 1 : 0);
    auto append_map = [&](const std::map<PubKey32, std::uint64_t>& m) {
      w.varint(m.size());
      for (const auto& [pub, value] : m) {
        w.bytes_fixed(pub);
        w.u64le(value);
      }
    };
    append_map(reward_state.reward_score_units);
    append_map(reward_state.expected_participation_units);
    append_map(reward_state.observed_participation_units);
    codec::ByteWriter key;
    key.bytes(Bytes{'S', 'C', '-', 'R', 'E', 'W'});
    key.u64le(epoch);
    reward_leaves.push_back({crypto::sha256(key.data()), w.take()});
  }
  const auto reward_root = crypto::SparseMerkleTree::compute_root_from_leaves(reward_leaves);

  std::vector<std::pair<Hash32, Bytes>> checkpoint_leaves;
  checkpoint_leaves.reserve(state.finalized_committee_checkpoints.size());
  for (const auto& [epoch, checkpoint] : state.finalized_committee_checkpoints) {
    codec::ByteWriter w;
    w.u64le(checkpoint.epoch_start_height);
    w.bytes_fixed(checkpoint.epoch_seed);
    w.u8(checkpoint.ticket_difficulty_bits);
    w.u8(static_cast<std::uint8_t>(checkpoint.derivation_mode));
    w.u8(static_cast<std::uint8_t>(checkpoint.fallback_reason));
    w.u64le(checkpoint.availability_eligible_operator_count);
    w.u64le(checkpoint.availability_min_eligible_operators);
    w.u64le(checkpoint.adaptive_target_committee_size);
    w.u64le(checkpoint.adaptive_min_eligible);
    w.u64le(checkpoint.adaptive_min_bond);
    w.u64le(checkpoint.qualified_depth);
    w.u32le(checkpoint.target_expand_streak);
    w.u32le(checkpoint.target_contract_streak);
    auto append_pubkeys = [&](const std::vector<PubKey32>& pubs) {
      w.varint(pubs.size());
      for (const auto& pub : pubs) w.bytes_fixed(pub);
    };
    auto append_u64s = [&](const std::vector<std::uint64_t>& nums) {
      w.varint(nums.size());
      for (const auto num : nums) w.u64le(num);
    };
    auto append_u32s = [&](const std::vector<std::uint32_t>& nums) {
      w.varint(nums.size());
      for (const auto num : nums) w.u32le(num);
    };
    auto append_hashes = [&](const std::vector<Hash32>& hashes) {
      w.varint(hashes.size());
      for (const auto& hash : hashes) w.bytes_fixed(hash);
    };
    append_pubkeys(checkpoint.ordered_members);
    append_pubkeys(checkpoint.ordered_operator_ids);
    append_u64s(checkpoint.ordered_base_weights);
    append_u32s(checkpoint.ordered_ticket_bonus_bps);
    append_u64s(checkpoint.ordered_final_weights);
    append_hashes(checkpoint.ordered_ticket_hashes);
    append_u64s(checkpoint.ordered_ticket_nonces);
    codec::ByteWriter key;
    key.bytes(Bytes{'S', 'C', '-', 'C', 'H', 'K'});
    key.u64le(epoch);
    checkpoint_leaves.push_back({crypto::sha256(key.data()), w.take()});
  }
  const auto checkpoint_root = crypto::SparseMerkleTree::compute_root_from_leaves(checkpoint_leaves);

  std::vector<std::pair<Hash32, Bytes>> availability_operator_leaves;
  availability_operator_leaves.reserve(state.availability_state.operators.size());
  for (const auto& operator_state : state.availability_state.operators) {
    codec::ByteWriter key;
    key.bytes(Bytes{'S', 'C', '-', 'A', 'V', 'O'});
    key.bytes_fixed(operator_state.operator_pubkey);
    codec::ByteWriter value;
    value.bytes_fixed(operator_state.operator_pubkey);
    value.u64le(operator_state.bond);
    value.u8(static_cast<std::uint8_t>(operator_state.status));
    value.u64le(static_cast<std::uint64_t>(operator_state.service_score) ^ 0x8000000000000000ULL);
    value.u64le(operator_state.successful_audits);
    value.u64le(operator_state.late_audits);
    value.u64le(operator_state.missed_audits);
    value.u64le(operator_state.invalid_audits);
    value.u64le(operator_state.warmup_epochs);
    value.u64le(operator_state.retained_prefix_count);
    availability_operator_leaves.push_back({crypto::sha256(key.data()), value.take()});
  }
  const auto availability_operator_root = crypto::SparseMerkleTree::compute_root_from_leaves(availability_operator_leaves);

  std::vector<std::pair<Hash32, Bytes>> availability_prefix_leaves;
  availability_prefix_leaves.reserve(state.availability_state.retained_prefixes.size());
  for (const auto& prefix : state.availability_state.retained_prefixes) {
    codec::ByteWriter key;
    key.bytes(Bytes{'S', 'C', '-', 'A', 'V', 'P'});
    key.bytes_fixed(prefix.prefix_id);
    codec::ByteWriter value;
    value.u32le(prefix.lane_id);
    value.u64le(prefix.start_seq);
    value.u64le(prefix.end_seq);
    value.bytes_fixed(prefix.prefix_id);
    value.bytes_fixed(prefix.payload_commitment);
    value.bytes_fixed(prefix.chunk_root);
    value.u64le(prefix.byte_length);
    value.u32le(prefix.chunk_count);
    value.u64le(prefix.certified_height);
    availability_prefix_leaves.push_back({crypto::sha256(key.data()), value.take()});
  }
  const auto availability_prefix_root = crypto::SparseMerkleTree::compute_root_from_leaves(availability_prefix_leaves);

  codec::ByteWriter w;
  w.bytes(Bytes{'S', 'C', '-', 'C', 'A', 'N', 'O', 'N', '-', 'S', 'T', 'A', 'T', 'E', '-', 'V', '1'});
  w.u64le(state.finalized_height);
  w.u64le(state.finalized_frontier);
  // The canonical state commitment intentionally binds only the finalized
  // identity value. Artifact kind remains a compatibility-sensitive concern at
  // storage/runtime boundaries, not part of this commitment format.
  w.bytes_fixed(state.finalized_identity.id);
  w.bytes_fixed(state.last_finality_certificate_hash);
  w.bytes_fixed(utxo_root);
  w.bytes_fixed(validator_root);
  w.bytes_fixed(state.finalized_randomness);
  w.bytes_fixed(reward_root);
  w.u64le(state.protocol_reserve_balance_units);
  w.bytes_fixed(checkpoint_root);
  w.u64le(state.availability_state.current_epoch);
  // Availability evidence is intentionally excluded here. The consensus
  // commitment binds only the consensus-relevant availability epoch, operator
  // state, and retained-prefix set used by live eligibility and checkpoint
  // derivation.
  w.bytes_fixed(availability_operator_root);
  w.bytes_fixed(availability_prefix_root);
  w.u64le(state.validator_join_window_start_height);
  w.u32le(state.validator_join_count_in_window);
  w.u64le(state.validator_liveness_window_start_height);
  return crypto::sha256d(w.data());
}

std::uint64_t qualified_depth_at_checkpoint(const ValidatorRegistry& validators, std::uint64_t height,
                                            std::uint64_t effective_min_bond,
                                            const availability::AvailabilityPersistentState& availability_state,
                                            const availability::AvailabilityConfig& availability_cfg) {
  std::set<PubKey32> qualified_operators;
  std::map<PubKey32, const availability::AvailabilityOperatorState*> availability_by_operator;
  for (const auto& operator_state : availability_state.operators) {
    availability_by_operator[operator_state.operator_pubkey] = &operator_state;
  }
  for (const auto& [pub, info] : validators.all()) {
    const auto operator_id = canonical_operator_id(pub, info);
    const auto availability_it = availability_by_operator.find(operator_id);
    const auto eligibility = committee_eligibility_at_checkpoint(
        validators, pub, info, height, effective_min_bond,
        availability_it == availability_by_operator.end() ? nullptr : availability_it->second, availability_cfg, true);
    if (eligibility.eligible) qualified_operators.insert(operator_id);
  }
  return static_cast<std::uint64_t>(qualified_operators.size());
}

std::uint64_t derive_adaptive_min_eligible(std::uint64_t target_committee_size) {
  return std::max<std::uint64_t>(1, target_committee_size);
}

std::uint64_t derive_adaptive_min_bond(std::uint64_t target_committee_size, std::uint64_t qualified_depth) {
  if (qualified_depth <= 3) return kAdaptiveMinBondFloor;
  const std::uint64_t depth = std::max<std::uint64_t>(1, qualified_depth);
  constexpr std::uint64_t kScale = 100'000'000ULL;
  constexpr std::uint64_t kScaleSqrt = 10'000ULL;
  const std::uint64_t scaled_ratio = wide::mul_div_u64(target_committee_size, kScale, depth);
  const std::uint64_t multiplier = integer_sqrt(scaled_ratio);
  const std::uint64_t scaled = wide::mul_div_u64(kAdaptiveMinBondBase, multiplier, kScaleSqrt);
  return std::min<std::uint64_t>(kAdaptiveMinBondCeiling, std::max<std::uint64_t>(kAdaptiveMinBondFloor, scaled));
}

AdaptiveCheckpointParameters adaptive_checkpoint_parameters_from_metadata(
    const std::optional<storage::FinalizedCommitteeCheckpoint>& checkpoint) {
  AdaptiveCheckpointParameters adaptive;
  if (!checkpoint.has_value()) return adaptive;
  if (checkpoint->adaptive_target_committee_size != 0) {
    adaptive.target_committee_size = checkpoint->adaptive_target_committee_size;
  }
  if (checkpoint->adaptive_min_eligible != 0) adaptive.min_eligible_operators = checkpoint->adaptive_min_eligible;
  if (checkpoint->adaptive_min_bond != 0) adaptive.min_bond = checkpoint->adaptive_min_bond;
  adaptive.qualified_depth = checkpoint->qualified_depth;
  adaptive.target_expand_streak = checkpoint->target_expand_streak;
  adaptive.target_contract_streak = checkpoint->target_contract_streak;
  return adaptive;
}

std::uint64_t derive_adaptive_committee_target(const std::optional<storage::FinalizedCommitteeCheckpoint>& previous_checkpoint,
                                               std::uint64_t qualified_depth, std::uint32_t* expand_streak,
                                               std::uint32_t* contract_streak) {
  (void)previous_checkpoint;
  if (expand_streak) *expand_streak = 0;
  if (contract_streak) *contract_streak = 0;
  return target_committee_size_for_qualified_depth(qualified_depth);
}

AdaptiveCheckpointParameters derive_adaptive_checkpoint_parameters(
    const std::optional<storage::FinalizedCommitteeCheckpoint>& previous_checkpoint, std::uint64_t qualified_depth) {
  AdaptiveCheckpointParameters adaptive = adaptive_checkpoint_parameters_from_metadata(previous_checkpoint);
  adaptive.qualified_depth = qualified_depth;
  adaptive.target_committee_size = derive_adaptive_committee_target(previous_checkpoint, qualified_depth,
                                                                    &adaptive.target_expand_streak,
                                                                    &adaptive.target_contract_streak);
  adaptive.min_eligible_operators = derive_adaptive_min_eligible(adaptive.target_committee_size);
  adaptive.min_bond = derive_adaptive_min_bond(adaptive.target_committee_size, qualified_depth);
  return adaptive;
}

bool bootstrap_availability_grace_active(const ValidatorRegistry& validators, std::uint64_t height) {
  const auto active = validators.active_sorted(height);
  if (active.size() != 1) return false;
  const auto info = validators.get(active.front());
  if (!info.has_value()) return false;
  const bool genesis_bond = info->bond_outpoint.txid == zero_hash() && info->bond_outpoint.index == 0;
  return info->joined_height == 0 && genesis_bond &&
         canonical_operator_id(active.front(), *info) == active.front();
}

bool bootstrap_operator_grandfathered_for_availability(const ValidatorRegistry& validators, const PubKey32& operator_id,
                                                       std::uint64_t height) {
  for (const auto& [validator_pubkey, info] : validators.all()) {
    if (!validators.is_active_for_height(validator_pubkey, height)) continue;
    if (canonical_operator_id(validator_pubkey, info) != operator_id) continue;
    const bool genesis_bond = info.bond_outpoint.txid == zero_hash() && info.bond_outpoint.index == 0;
    if (info.joined_height == 0 && genesis_bond) return true;
  }
  return false;
}

std::uint64_t count_eligible_operators_at_checkpoint(const ValidatorRegistry& validators, std::uint64_t height,
                                                     const availability::AvailabilityPersistentState& availability_state,
                                                     const availability::AvailabilityConfig& availability_cfg) {
  std::map<PubKey32, const availability::AvailabilityOperatorState*> availability_by_operator;
  for (const auto& operator_state : availability_state.operators) {
    availability_by_operator[operator_state.operator_pubkey] = &operator_state;
  }

  std::set<PubKey32> counted;
  std::uint64_t out = 0;
  for (const auto& validator_pubkey : validators.active_sorted(height)) {
    const auto info = validators.get(validator_pubkey);
    if (!info.has_value()) continue;
    const auto operator_id = canonical_operator_id(validator_pubkey, *info);
    if (!counted.insert(operator_id).second) continue;

    if (bootstrap_operator_grandfathered_for_availability(validators, operator_id, height)) {
      ++out;
      continue;
    }

    const auto availability_it = availability_by_operator.find(operator_id);
    if (availability_it == availability_by_operator.end()) continue;
    if (availability::operator_is_eligible(*availability_it->second, availability_cfg)) ++out;
  }
  return out;
}

availability::AvailabilityConfig availability_config_with_min_bond(const availability::AvailabilityConfig& base,
                                                                   std::uint64_t min_bond) {
  auto cfg = base;
  cfg.min_bond = min_bond;
  return cfg;
}

bool canonical_checkpoints_equal(const storage::FinalizedCommitteeCheckpoint& a,
                                 const storage::FinalizedCommitteeCheckpoint& b) {
  return a.epoch_start_height == b.epoch_start_height && a.epoch_seed == b.epoch_seed &&
         a.ticket_difficulty_bits == b.ticket_difficulty_bits && a.derivation_mode == b.derivation_mode &&
         a.fallback_reason == b.fallback_reason &&
         a.availability_eligible_operator_count == b.availability_eligible_operator_count &&
         a.availability_min_eligible_operators == b.availability_min_eligible_operators &&
         a.adaptive_target_committee_size == b.adaptive_target_committee_size &&
         a.adaptive_min_eligible == b.adaptive_min_eligible && a.adaptive_min_bond == b.adaptive_min_bond &&
         a.qualified_depth == b.qualified_depth && a.target_expand_streak == b.target_expand_streak &&
         a.target_contract_streak == b.target_contract_streak &&
         a.ordered_members == b.ordered_members &&
         a.ordered_operator_ids == b.ordered_operator_ids && a.ordered_base_weights == b.ordered_base_weights &&
         a.ordered_ticket_bonus_bps == b.ordered_ticket_bonus_bps && a.ordered_final_weights == b.ordered_final_weights &&
         a.ordered_ticket_hashes == b.ordered_ticket_hashes && a.ordered_ticket_nonces == b.ordered_ticket_nonces;
}

bool derive_next_epoch_checkpoint_from_state(const CanonicalDerivationConfig& cfg, const CanonicalDerivedState& state,
                                             std::uint64_t epoch_start_height,
                                             storage::FinalizedCommitteeCheckpoint* out, std::string* error) {
  // Normative implementation anchor:
  // docs/spec/CHECKPOINT_DERIVATION_SPEC.md §16 "DeriveCheckpointForEpoch"
  if (!out) {
    if (error) *error = "missing-checkpoint-output";
    return false;
  }
  if (epoch_start_height == 0) {
    if (error) *error = "invalid-epoch-start";
    return false;
  }
  const auto epoch_randomness = committee_epoch_randomness_for_height(cfg, state, epoch_start_height);
  const auto active_validator_count = state.validators.active_sorted(epoch_start_height).size();
  const auto difficulty_bits = ticket_difficulty_bits_for_epoch(cfg, state, epoch_start_height, active_validator_count);
  AvailabilityCommitteeDecision decision;
  const auto active = finalized_committee_candidates_for_height(cfg, state, epoch_start_height, difficulty_bits, &decision);
  storage::FinalizedCommitteeCheckpoint checkpoint;
  checkpoint.epoch_start_height = epoch_start_height;
  checkpoint.epoch_seed = committee_epoch_seed(epoch_randomness, epoch_start_height);
  checkpoint.ticket_difficulty_bits = difficulty_bits;
  checkpoint.derivation_mode = decision.mode;
  checkpoint.fallback_reason = decision.fallback_reason;
  checkpoint.availability_eligible_operator_count = decision.eligible_operator_count;
  checkpoint.availability_min_eligible_operators = decision.min_eligible_operators;
  checkpoint.adaptive_target_committee_size = decision.adaptive.target_committee_size;
  checkpoint.adaptive_min_eligible = decision.adaptive.min_eligible_operators;
  checkpoint.adaptive_min_bond = decision.adaptive.min_bond;
  checkpoint.qualified_depth = decision.adaptive.qualified_depth;
  checkpoint.target_expand_streak = decision.adaptive.target_expand_streak;
  checkpoint.target_contract_streak = decision.adaptive.target_contract_streak;
  checkpoint.ordered_members =
      select_finalized_committee(active, checkpoint.epoch_seed,
                                 std::min<std::size_t>({cfg.max_committee,
                                                        static_cast<std::size_t>(decision.effective_committee_size),
                                                        active.size()}));
  checkpoint.ordered_operator_ids.reserve(checkpoint.ordered_members.size());
  checkpoint.ordered_base_weights.reserve(checkpoint.ordered_members.size());
  checkpoint.ordered_ticket_bonus_bps.reserve(checkpoint.ordered_members.size());
  checkpoint.ordered_final_weights.reserve(checkpoint.ordered_members.size());
  checkpoint.ordered_ticket_hashes.reserve(checkpoint.ordered_members.size());
  checkpoint.ordered_ticket_nonces.reserve(checkpoint.ordered_members.size());
  for (const auto& pub : checkpoint.ordered_members) {
    auto it = std::find_if(active.begin(), active.end(), [&](const auto& candidate) { return candidate.pubkey == pub; });
    if (it == active.end()) {
      if (error) *error = "checkpoint-member-missing-from-candidates";
      return false;
    }
    checkpoint.ordered_operator_ids.push_back(it->selection_id == PubKey32{} ? it->pubkey : it->selection_id);
    checkpoint.ordered_base_weights.push_back(it->effective_weight);
    checkpoint.ordered_ticket_bonus_bps.push_back(it->ticket_bonus_bps);
    checkpoint.ordered_final_weights.push_back(finalized_committee_candidate_strength(*it));
    checkpoint.ordered_ticket_hashes.push_back(it->ticket_work_hash);
    checkpoint.ordered_ticket_nonces.push_back(it->ticket_nonce);
  }
  *out = std::move(checkpoint);
  return true;
}

bool validate_next_epoch_checkpoint_from_state(const CanonicalDerivationConfig& cfg, const CanonicalDerivedState& state,
                                               std::uint64_t epoch_start_height,
                                               const storage::FinalizedCommitteeCheckpoint& checkpoint,
                                               std::string* error) {
  storage::FinalizedCommitteeCheckpoint recomputed;
  if (!derive_next_epoch_checkpoint_from_state(cfg, state, epoch_start_height, &recomputed, error)) return false;
  if (!canonical_checkpoints_equal(recomputed, checkpoint)) {
    if (error) *error = "checkpoint-recomputation-mismatch";
    return false;
  }
  return true;
}

bool validate_checkpoint_schedule_for_height(const CanonicalDerivationConfig& cfg, const CanonicalDerivedState& state,
                                             const storage::FinalizedCommitteeCheckpoint& checkpoint,
                                             std::uint64_t height, std::string* error) {
  if (checkpoint.ordered_members.empty()) {
    if (error) *error = "empty-checkpoint-committee";
    return false;
  }
  const auto schedule = proposer_schedule_from_checkpoint(cfg, state, checkpoint, height);
  if (schedule.empty()) {
    if (error) *error = "empty-proposer-schedule";
    return false;
  }
  std::set<PubKey32> committee(checkpoint.ordered_members.begin(), checkpoint.ordered_members.end());
  if (committee.size() != checkpoint.ordered_members.size()) {
    if (error) *error = "duplicate-checkpoint-members";
    return false;
  }
  for (const auto& proposer : schedule) {
    if (committee.find(proposer) == committee.end()) {
      if (error) *error = "schedule-proposer-outside-committee";
      return false;
    }
  }
  return true;
}

bool bootstrap_handoff_complete(const CanonicalDerivedState& state) {
  if (state.finalized_height == 0) return false;
  return state.validators.active_sorted(state.finalized_height + 1).size() >= 2;
}

std::optional<PubKey32> checkpoint_ticket_pow_fallback_member(const storage::FinalizedCommitteeCheckpoint& checkpoint) {
  if (checkpoint.ordered_members.empty()) return std::nullopt;
  const auto ticket_hash_at = [&](std::size_t index) -> Hash32 {
    if (index < checkpoint.ordered_ticket_hashes.size()) return checkpoint.ordered_ticket_hashes[index];
    Hash32 worst{};
    worst.fill(0xff);
    return worst;
  };
  const auto ticket_nonce_at = [&](std::size_t index) -> std::uint64_t {
    if (index < checkpoint.ordered_ticket_nonces.size()) return checkpoint.ordered_ticket_nonces[index];
    return std::numeric_limits<std::uint64_t>::max();
  };

  std::size_t best_index = 0;
  for (std::size_t i = 1; i < checkpoint.ordered_members.size(); ++i) {
    const auto best_hash = ticket_hash_at(best_index);
    const auto cand_hash = ticket_hash_at(i);
    if (cand_hash != best_hash) {
      if (cand_hash < best_hash) best_index = i;
      continue;
    }
    const auto best_nonce = ticket_nonce_at(best_index);
    const auto cand_nonce = ticket_nonce_at(i);
    if (cand_nonce != best_nonce) {
      if (cand_nonce < best_nonce) best_index = i;
      continue;
    }
    if (checkpoint.ordered_members[i] < checkpoint.ordered_members[best_index]) best_index = i;
  }
  return checkpoint.ordered_members[best_index];
}

std::optional<PubKey32> checkpoint_ticket_pow_fallback_member_for_round(const storage::FinalizedCommitteeCheckpoint& checkpoint,
                                                                        std::uint32_t round) {
  if (checkpoint.ordered_members.empty()) return std::nullopt;
  const auto committee_size = static_cast<std::uint32_t>(checkpoint.ordered_members.size());
  if (round < committee_size) return std::nullopt;

  std::vector<std::size_t> ranked(checkpoint.ordered_members.size());
  for (std::size_t i = 0; i < ranked.size(); ++i) ranked[i] = i;

  const auto ticket_hash_at = [&](std::size_t index) -> Hash32 {
    if (index < checkpoint.ordered_ticket_hashes.size()) return checkpoint.ordered_ticket_hashes[index];
    Hash32 worst{};
    worst.fill(0xff);
    return worst;
  };
  const auto ticket_nonce_at = [&](std::size_t index) -> std::uint64_t {
    if (index < checkpoint.ordered_ticket_nonces.size()) return checkpoint.ordered_ticket_nonces[index];
    return std::numeric_limits<std::uint64_t>::max();
  };

  std::sort(ranked.begin(), ranked.end(), [&](std::size_t a, std::size_t b) {
    const auto ah = ticket_hash_at(a);
    const auto bh = ticket_hash_at(b);
    if (ah != bh) return ah < bh;
    const auto an = ticket_nonce_at(a);
    const auto bn = ticket_nonce_at(b);
    if (an != bn) return an < bn;
    return checkpoint.ordered_members[a] < checkpoint.ordered_members[b];
  });

  const std::size_t selected =
      std::min<std::size_t>(static_cast<std::size_t>(round - committee_size), ranked.size() - 1);
  return checkpoint.ordered_members[ranked[selected]];
}

std::optional<PubKey32> legacy_checkpoint_ticket_pow_fallback_member_for_round(
    const storage::FinalizedCommitteeCheckpoint& checkpoint, std::uint32_t round) {
  if (checkpoint.ordered_members.empty() || round == 0) return std::nullopt;

  std::vector<std::size_t> ranked(checkpoint.ordered_members.size());
  for (std::size_t i = 0; i < ranked.size(); ++i) ranked[i] = i;

  const auto ticket_hash_at = [&](std::size_t index) -> Hash32 {
    if (index < checkpoint.ordered_ticket_hashes.size()) return checkpoint.ordered_ticket_hashes[index];
    Hash32 worst{};
    worst.fill(0xff);
    return worst;
  };
  const auto ticket_nonce_at = [&](std::size_t index) -> std::uint64_t {
    if (index < checkpoint.ordered_ticket_nonces.size()) return checkpoint.ordered_ticket_nonces[index];
    return std::numeric_limits<std::uint64_t>::max();
  };

  std::sort(ranked.begin(), ranked.end(), [&](std::size_t a, std::size_t b) {
    const auto ah = ticket_hash_at(a);
    const auto bh = ticket_hash_at(b);
    if (ah != bh) return ah < bh;
    const auto an = ticket_nonce_at(a);
    const auto bn = ticket_nonce_at(b);
    if (an != bn) return an < bn;
    return checkpoint.ordered_members[a] < checkpoint.ordered_members[b];
  });

  const std::size_t selected = std::min<std::size_t>(static_cast<std::size_t>(round - 1), ranked.size() - 1);
  return checkpoint.ordered_members[ranked[selected]];
}

std::vector<PubKey32> legacy_checkpoint_committee_for_round(const storage::FinalizedCommitteeCheckpoint& checkpoint,
                                                            std::uint32_t round) {
  if (round == 0) return checkpoint.ordered_members;
  if (auto fallback = legacy_checkpoint_ticket_pow_fallback_member_for_round(checkpoint, round); fallback.has_value()) {
    return {*fallback};
  }
  return {};
}

std::vector<PubKey32> checkpoint_committee_for_round(const storage::FinalizedCommitteeCheckpoint& checkpoint,
                                                     std::uint32_t round) {
  if (round < checkpoint.ordered_members.size()) return checkpoint.ordered_members;
  if (auto fallback = checkpoint_ticket_pow_fallback_member_for_round(checkpoint, round); fallback.has_value()) {
    return {*fallback};
  }
  return {};
}

}  // namespace finalis::consensus
