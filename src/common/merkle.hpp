// SPDX-License-Identifier: MIT

#pragma once

#include <optional>

#include "common/types.hpp"

namespace finalis::merkle {

std::optional<Hash32> compute_merkle_root_from_leaves(const std::vector<Hash32>& leaf_hashes);
std::optional<Hash32> compute_merkle_root_from_txs(const std::vector<Bytes>& tx_bytes);

}  // namespace finalis::merkle
