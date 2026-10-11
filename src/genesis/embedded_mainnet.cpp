// SPDX-License-Identifier: MIT

#include "genesis/embedded_mainnet.hpp"

namespace finalis::genesis {

// Mainnet has not launched: nothing is embedded. At launch this file is regenerated from
// mainnet/genesis.bin with scripts/genesis_to_cpp.py --network mainnet. Until then a mainnet node
// needs --genesis.
const std::uint8_t MAINNET_GENESIS_BIN[] = {0x00};

const std::size_t MAINNET_GENESIS_BIN_LEN = 0;

const Hash32 MAINNET_GENESIS_HASH{};

}  // namespace finalis::genesis
