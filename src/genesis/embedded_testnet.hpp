// SPDX-License-Identifier: MIT

#pragma once

#include <cstddef>
#include <cstdint>

#include "common/types.hpp"

namespace finalis::genesis {

// TESTNET_GENESIS_BIN_LEN is 0 until testnet/genesis.bin is frozen and embedded.
extern const std::uint8_t TESTNET_GENESIS_BIN[];
extern const std::size_t TESTNET_GENESIS_BIN_LEN;
extern const Hash32 TESTNET_GENESIS_HASH;

}  // namespace finalis::genesis
