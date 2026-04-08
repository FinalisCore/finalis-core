#include "consensus/finalized_committee.hpp"

#include <algorithm>
#include <map>
#include <set>

#include "codec/bytes.hpp"
#include "common/wide_arith.hpp"
#include "crypto/hash.hpp"

namespace finalis::consensus {

namespace {

static_assert(sizeof(std::uint64_t) == 8);

std::uint64_t hash64_prefix(const Hash32& hash) {
  std::uint64_t out = 0;
  for (std::size_t i = 0; i < 8; ++i) out = (out << 8) | static_cast<std::uint64_t>(hash[i]);
  return out;
}

Hash32 finalized_committee_candidate_hash(const Hash32& seed, const PubKey32& pub) {
  codec::ByteWriter sw;
  sw.bytes(Bytes{'S', 'C', '-', 'C', 'O', 'M', 'M', 'I', 'T', 'T', 'E', 'E', '-', 'V', '3'});
  sw.bytes_fixed(seed);
  sw.bytes_fixed(pub);
  return crypto::sha256d(sw.data());
}

Hash32 operator_representative_hash(const PubKey32& operator_id, std::uint64_t height, const PubKey32& pubkey) {
  codec::ByteWriter w;
  w.bytes(Bytes{'S', 'C', '-', 'R', 'E', 'P', '-', 'V', '1'});
  w.bytes_fixed(operator_id);
  w.u64le(height);
  w.bytes_fixed(pubkey);
  return crypto::sha256d(w.data());
}

std::uint64_t candidate_strength(const FinalizedCommitteeCandidate& candidate) {
  const auto base_weight =
      candidate.effective_weight != 0 ? candidate.effective_weight : effective_weight(candidate.bonded_amount);
  const auto bounded_bonus = std::min<std::uint32_t>(candidate.ticket_bonus_bps, candidate.ticket_bonus_cap_bps);
  const auto bonded_coins = std::max<std::uint64_t>(1, candidate.bonded_amount / BASE_UNITS_PER_COIN);
  const auto bonus_scale = 1ULL + integer_sqrt(bonded_coins);
  const auto adjusted_bonus = static_cast<std::uint64_t>(bounded_bonus) / bonus_scale;
  return std::max<std::uint64_t>(1, base_weight * static_cast<std::uint64_t>(10'000U + adjusted_bonus));
}

// Canonical committee selection must use a total order so that identical
// finalized history yields identical top-K output even under exact tie
// conditions or adversarial input ordering.
bool compare_ranked_candidates(const FinalizedCommitteeCandidate& a, const FinalizedCommitteeCandidate& b,
                               const Hash32& seed) {
  const auto a_selection_id = a.selection_id == PubKey32{} ? a.pubkey : a.selection_id;
  const auto b_selection_id = b.selection_id == PubKey32{} ? b.pubkey : b.selection_id;
  const auto a_hash = finalized_committee_candidate_hash(seed, a_selection_id);
  const auto b_hash = finalized_committee_candidate_hash(seed, b_selection_id);
  const auto a_hash64 = hash64_prefix(a_hash);
  const auto b_hash64 = hash64_prefix(b_hash);
  const auto a_strength = candidate_strength(a);
  const auto b_strength = candidate_strength(b);
  // Spec §9.4 clause 1: compare selection_hash64 / strength with widened
  // cross-multiplication so ranking is architecture-stable and overflow-safe.
  if (const int rank_cmp = wide::compare_mul_u64(a_hash64, b_strength, b_hash64, a_strength); rank_cmp != 0) {
    return rank_cmp < 0;
  }
  // Spec §9.4 clauses 2..11: exhaustive total-order tie-break chain.
  if (a_hash != b_hash) return a_hash < b_hash;
  if (a_selection_id != b_selection_id) return a_selection_id < b_selection_id;
  if (a.pubkey != b.pubkey) return a.pubkey < b.pubkey;
  if (a.effective_weight != b.effective_weight) return a.effective_weight > b.effective_weight;
  if (a.capped_bonded_amount != b.capped_bonded_amount) return a.capped_bonded_amount > b.capped_bonded_amount;
  if (a.bonded_amount != b.bonded_amount) return a.bonded_amount > b.bonded_amount;
  if (a.ticket_bonus_bps != b.ticket_bonus_bps) return a.ticket_bonus_bps > b.ticket_bonus_bps;
  if (a.ticket_work_hash != b.ticket_work_hash) return a.ticket_work_hash < b.ticket_work_hash;
  if (a.ticket_nonce != b.ticket_nonce) return a.ticket_nonce < b.ticket_nonce;
  return a.ticket_bonus_cap_bps < b.ticket_bonus_cap_bps;
}

}  // namespace

std::uint64_t finalized_committee_candidate_strength(const FinalizedCommitteeCandidate& candidate) {
  return candidate_strength(candidate);
}

CommitteeEligibilityDecision committee_eligibility_at_checkpoint(
    const ValidatorRegistry& validators, const PubKey32& validator_pubkey, const ValidatorInfo& info, std::uint64_t height,
    std::uint64_t effective_min_bond, const availability::AvailabilityOperatorState* availability_state,
    const availability::AvailabilityConfig& availability_cfg, bool enforce_availability_gate) {
  // Normative mapping:
  // docs/spec/CHECKPOINT_DERIVATION_SPEC.md §6
  // The caller supplies derivation mode as enforce_availability_gate. This
  // helper must not recompute fallback mode internally.
  CommitteeEligibilityDecision decision;
  decision.validator_lifecycle_eligible =
      info.has_bond && validators.is_active_for_height(validator_pubkey, height);
  if (!decision.validator_lifecycle_eligible) return decision;
  // Genesis/bootstrap validators can be grandfathered below later dynamic bond
  // floors; post-genesis joins must satisfy the live checkpoint bond floor.
  decision.min_bond_eligible = info.joined_height == 0 || info.bonded_amount >= effective_min_bond;
  if (!decision.min_bond_eligible) return decision;
  decision.availability_tracked = availability_state != nullptr;
  const bool bootstrap_genesis_operator =
      info.joined_height == 0 && info.bond_outpoint.txid == zero_hash() && info.bond_outpoint.index == 0 &&
      canonical_operator_id(validator_pubkey, info) == validator_pubkey;
  decision.availability_eligible = bootstrap_genesis_operator ||
                                   (availability_state != nullptr &&
                                    availability::operator_is_eligible(*availability_state, availability_cfg));
  decision.eligible = decision.validator_lifecycle_eligible && decision.min_bond_eligible &&
                      (!enforce_availability_gate || decision.availability_eligible);
  return decision;
}

std::vector<FinalizedCommitteeCandidate> aggregate_operator_committee_candidates(
    const std::vector<OperatorCommitteeInput>& validators, const NetworkConfig& network, std::uint64_t height) {
  return aggregate_operator_committee_candidates(validators, active_economics_policy(network, height), height, 0);
}

std::vector<FinalizedCommitteeCandidate> aggregate_operator_committee_candidates(
    const std::vector<OperatorCommitteeInput>& validators, const EconomicsConfig& economics, std::uint64_t height,
    std::size_t finalized_active_operators) {
  struct Aggregate {
    PubKey32 representative_pub{};
    std::uint64_t total_bonded_amount{0};
    Hash32 best_ticket_work_hash{};
    std::uint64_t best_ticket_nonce{0};
    std::uint32_t best_ticket_bonus_bps{0};
    bool has_representative{false};
  };

  std::map<PubKey32, Aggregate> by_operator;
  for (const auto& validator : validators) {
    const auto operator_id = (validator.operator_id == PubKey32{}) ? validator.pubkey : validator.operator_id;
    auto& agg = by_operator[operator_id];
    agg.total_bonded_amount += validator.bonded_amount;
    const bool prefer_canonical_representative =
        !agg.has_representative ||
        operator_representative_hash(operator_id, height, validator.pubkey) <
            operator_representative_hash(operator_id, height, agg.representative_pub) ||
        (operator_representative_hash(operator_id, height, validator.pubkey) ==
             operator_representative_hash(operator_id, height, agg.representative_pub) &&
         validator.pubkey < agg.representative_pub);
    if (prefer_canonical_representative) {
      agg.representative_pub = validator.pubkey;
      agg.has_representative = true;
    }
    if (!agg.has_representative || agg.best_ticket_work_hash == Hash32{} || validator.pubkey == agg.representative_pub) {
      if (validator.pubkey == agg.representative_pub) {
        agg.best_ticket_work_hash = validator.ticket_work_hash;
        agg.best_ticket_nonce = validator.ticket_nonce;
        agg.best_ticket_bonus_bps = validator.ticket_bonus_bps;
      }
    }
  }

  std::vector<FinalizedCommitteeCandidate> out;
  out.reserve(by_operator.size());
  const auto active_operator_count =
      finalized_active_operators == 0 ? by_operator.size() : finalized_active_operators;
  const auto ticket_bonus_cap_bps = economics.ticket_bonus_cap_bps;
  for (const auto& [_, agg] : by_operator) {
    if (!agg.has_representative) continue;
    const auto capped_bond = capped_effective_bond_units(economics, active_operator_count, agg.total_bonded_amount);
    out.push_back(FinalizedCommitteeCandidate{
        .pubkey = agg.representative_pub,
        .selection_id = _,
        .bonded_amount = agg.total_bonded_amount,
        .capped_bonded_amount = capped_bond,
        .effective_weight = effective_weight(economics, active_operator_count, agg.total_bonded_amount),
        .ticket_work_hash = agg.best_ticket_work_hash,
        .ticket_nonce = agg.best_ticket_nonce,
        .ticket_bonus_bps = std::min<std::uint32_t>(agg.best_ticket_bonus_bps, ticket_bonus_cap_bps),
        .ticket_bonus_cap_bps = ticket_bonus_cap_bps,
    });
  }
  std::sort(out.begin(), out.end(), [](const auto& a, const auto& b) {
    const auto a_id = a.selection_id == PubKey32{} ? a.pubkey : a.selection_id;
    const auto b_id = b.selection_id == PubKey32{} ? b.pubkey : b.selection_id;
    if (a_id != b_id) return a_id < b_id;
    return a.pubkey < b.pubkey;
  });
  return out;
}

Hash32 compute_finality_entropy(const Hash32& prev_block_id, const FinalityProof& prev_finality_proof) {
  std::vector<FinalitySig> canon = prev_finality_proof.sigs;
  std::sort(canon.begin(), canon.end(), [](const FinalitySig& a, const FinalitySig& b) {
    if (a.validator_pubkey != b.validator_pubkey) return a.validator_pubkey < b.validator_pubkey;
    return a.signature < b.signature;
  });

  std::vector<FinalitySig> deduped;
  deduped.reserve(canon.size());
  for (const auto& fs : canon) {
    if (!deduped.empty() && deduped.back().validator_pubkey == fs.validator_pubkey) continue;
    deduped.push_back(fs);
  }

  codec::ByteWriter w;
  w.bytes(Bytes{'S', 'C', '-', 'E', 'N', 'T', 'R', 'O', 'P', 'Y', '-', 'V', '2'});
  w.bytes_fixed(prev_block_id);
  for (const auto& fs : deduped) {
    w.bytes_fixed(fs.validator_pubkey);
    w.bytes_fixed(fs.signature);
  }
  return crypto::sha256d(w.data());
}

Hash32 make_finalized_committee_seed(const Hash32& prev_entropy, std::uint64_t height, std::uint32_t round) {
  codec::ByteWriter w;
  w.bytes(Bytes{'S', 'C', '-', 'S', 'E', 'E', 'D', '-', 'V', '2'});
  w.bytes_fixed(prev_entropy);
  w.u64le(height);
  w.u32le(round);
  return crypto::sha256d(w.data());
}

std::size_t finalized_committee_size(std::size_t active_count, std::size_t configured_max_committee) {
  if (active_count <= 2) return active_count;
  const std::size_t k = std::min(active_count, configured_max_committee);
  return std::max<std::size_t>(2, k);
}

std::vector<PubKey32> select_finalized_committee(const std::vector<FinalizedCommitteeCandidate>& candidates,
                                                 const Hash32& seed, std::size_t committee_size) {
  if (candidates.empty() || committee_size == 0) return {};
  const auto ranked = rank_finalized_committee_candidates(candidates, seed);
  const std::size_t take = std::min(committee_size, ranked.size());

  std::vector<PubKey32> out;
  out.reserve(take);
  for (std::size_t i = 0; i < take; ++i) out.push_back(ranked[i].pubkey);
  return out;
}

std::vector<FinalizedCommitteeCandidate> rank_finalized_committee_candidates(
    const std::vector<FinalizedCommitteeCandidate>& candidates, const Hash32& seed) {
  std::vector<FinalizedCommitteeCandidate> ranked = candidates;
  std::sort(ranked.begin(), ranked.end(),
            [&](const FinalizedCommitteeCandidate& a, const FinalizedCommitteeCandidate& b) {
              return compare_ranked_candidates(a, b, seed);
            });
  return ranked;
}

std::optional<PubKey32> select_finalized_committee_leader(const std::vector<PubKey32>& committee) {
  if (committee.empty()) return std::nullopt;
  return committee.front();
}

std::vector<PubKey32> committee_participants_from_finality(const std::vector<PubKey32>& committee,
                                                           const std::vector<FinalitySig>& sigs) {
  std::set<PubKey32> committee_set(committee.begin(), committee.end());
  std::set<PubKey32> out_set;
  for (const auto& s : sigs) {
    if (committee_set.find(s.validator_pubkey) == committee_set.end()) continue;
    out_set.insert(s.validator_pubkey);
  }
  return std::vector<PubKey32>(out_set.begin(), out_set.end());
}

}  // namespace finalis::consensus
