// SPDX-License-Identifier: MIT

#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <vector>

#include "common/types.hpp"
#include "consensus/epoch_tickets.hpp"
#include "consensus/validator_registry.hpp"

namespace finalis::consensus {

struct EpochCommitteeMember {
  PubKey32 participant_pubkey{};
  Hash32 work_hash{};
  std::uint64_t nonce{0};
  std::uint64_t source_height{0};
};

struct EpochCommitteeSnapshot {
  std::uint64_t epoch{0};
  Hash32 challenge_anchor{};
  std::vector<EpochCommitteeMember> selected_winners;
  std::vector<PubKey32> ordered_members;
};

EpochCommitteeSnapshot derive_epoch_committee_snapshot(
    std::uint64_t epoch, const Hash32& challenge_anchor, const std::map<PubKey32, EpochBestTicket>& best_tickets,
    std::size_t committee_size_limit, const std::map<PubKey32, ValidatorInfo>* validators = nullptr,
    bool require_bonded_validator = false);

}  // namespace finalis::consensus
