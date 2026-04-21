#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

#include "consensus/availability_retention.hpp"
#include "common/network.hpp"
#include "consensus/monetary.hpp"
#include "consensus/validator_registry.hpp"
#include "common/types.hpp"
#include "utxo/tx.hpp"

namespace finalis::consensus {

struct FinalizedCommitteeCandidate {
  PubKey32 pubkey{};
  PubKey32 selection_id{};
  std::uint64_t bonded_amount{0};
  std::uint64_t capped_bonded_amount{0};
  std::uint64_t effective_weight{0};
  Hash32 ticket_work_hash{};
  std::uint64_t ticket_nonce{0};
  std::uint32_t ticket_bonus_bps{0};
  std::uint32_t ticket_bonus_cap_bps{2'500};
};

struct OperatorCommitteeInput {
  PubKey32 pubkey{};
  PubKey32 operator_id{};
  std::uint64_t bonded_amount{0};
  Hash32 ticket_work_hash{};
  std::uint64_t ticket_nonce{0};
  std::uint32_t ticket_bonus_bps{0};
};

struct CommitteeEligibilityDecision {
  bool validator_lifecycle_eligible{false};
  bool min_bond_eligible{false};
  bool availability_tracked{false};
  bool availability_eligible{false};
  bool eligible{false};
};

Hash32 compute_finality_entropy(const Hash32& prev_block_id, const FinalityProof& prev_finality_proof);
Hash32 make_finalized_committee_seed(const Hash32& prev_entropy, std::uint64_t height, std::uint32_t round);
std::size_t finalized_committee_size(std::size_t active_count, std::size_t configured_max_committee = 128);
std::vector<FinalizedCommitteeCandidate> aggregate_operator_committee_candidates(
    const std::vector<OperatorCommitteeInput>& validators, const NetworkConfig& network, std::uint64_t height);
std::vector<FinalizedCommitteeCandidate> aggregate_operator_committee_candidates(
    const std::vector<OperatorCommitteeInput>& validators, const EconomicsConfig& economics, std::uint64_t height,
    std::size_t finalized_active_operators);
std::uint64_t finalized_committee_candidate_strength(const FinalizedCommitteeCandidate& candidate);
CommitteeEligibilityDecision committee_eligibility_at_checkpoint(
    const ValidatorRegistry& validators, const PubKey32& validator_pubkey, const ValidatorInfo& info, std::uint64_t height,
    std::uint64_t effective_min_bond, const availability::AvailabilityOperatorState* availability_state,
    const availability::AvailabilityConfig& availability_cfg, bool enforce_availability_gate);
std::vector<FinalizedCommitteeCandidate> rank_finalized_committee_candidates(
    const std::vector<FinalizedCommitteeCandidate>& candidates, const Hash32& seed);
std::vector<PubKey32> select_finalized_committee(const std::vector<FinalizedCommitteeCandidate>& candidates,
                                                 const Hash32& seed, std::size_t committee_size);
std::optional<PubKey32> select_finalized_committee_leader(const std::vector<PubKey32>& committee);
std::vector<PubKey32> committee_participants_from_finality(const std::vector<PubKey32>& committee,
                                                           const std::vector<FinalitySig>& sigs);

}  // namespace finalis::consensus
