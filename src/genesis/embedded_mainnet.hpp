// SPDX-License-Identifier: MIT

#pragma once

#include <cstddef>
#include <cstdint>

#include "common/types.hpp"

namespace finalis::genesis {

// MAINNET_GENESIS_BIN_LEN is 0 until mainnet launches and its genesis is embedded.
extern const std::uint8_t MAINNET_GENESIS_BIN[];
extern const std::size_t MAINNET_GENESIS_BIN_LEN;
extern const Hash32 MAINNET_GENESIS_HASH;

}  // namespace finalis::genesis
