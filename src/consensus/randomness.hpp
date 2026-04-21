// SPDX-License-Identifier: MIT

#pragma once

#include "common/chain_id.hpp"
#include "common/network.hpp"
#include "utxo/tx.hpp"

namespace finalis::consensus {

Hash32 initial_finalized_randomness(const NetworkConfig& network, const ChainId& chain_id);
Hash32 advance_finalized_randomness(const Hash32& prev_randomness, const BlockHeader& header);
Hash32 advance_finalized_randomness(const Hash32& prev_randomness, const FrontierTransition& transition);
std::uint64_t committee_epoch_start(std::uint64_t height, std::uint64_t epoch_blocks);
Hash32 committee_epoch_seed(const Hash32& epoch_randomness, std::uint64_t epoch_start_height);

}  // namespace finalis::consensus
