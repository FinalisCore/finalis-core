// SPDX-License-Identifier: MIT

#include "genesis/embedded.hpp"

#include "common/network.hpp"
#include "genesis/embedded_mainnet.hpp"
#include "genesis/embedded_testnet.hpp"

namespace finalis::genesis {

std::optional<EmbeddedGenesis> embedded_genesis_for(const std::string& network_name) {
  if (is_testnet_name(network_name)) {
    if (TESTNET_GENESIS_BIN_LEN == 0) return std::nullopt;
    return EmbeddedGenesis{TESTNET_GENESIS_BIN, TESTNET_GENESIS_BIN_LEN, TESTNET_GENESIS_HASH};
  }
  if (network_name == "mainnet") {
    if (MAINNET_GENESIS_BIN_LEN == 0) return std::nullopt;
    return EmbeddedGenesis{MAINNET_GENESIS_BIN, MAINNET_GENESIS_BIN_LEN, MAINNET_GENESIS_HASH};
  }
  return std::nullopt;
}

}  // namespace finalis::genesis
