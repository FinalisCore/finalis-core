// SPDX-License-Identifier: MIT

#pragma once

#include <cstdint>
#include <vector>

#include "common/types.hpp"

namespace finalis::consensus {

struct ValidatorBestTicket {
  PubKey32 validator_pubkey{};
  Hash32 best_ticket_hash{};
  std::uint64_t nonce{0};
};

Hash32 compute_committee_root(const std::vector<ValidatorBestTicket>& committee);

Hash32 compute_proposer_seed(const Hash32& epoch_anchor, std::uint64_t height, const Hash32& committee_root);

std::vector<PubKey32> proposer_schedule_from_committee(const std::vector<ValidatorBestTicket>& committee,
                                                       const Hash32& proposer_seed);

}  // namespace finalis::consensus
