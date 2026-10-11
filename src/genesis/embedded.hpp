// SPDX-License-Identifier: MIT

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

#include "common/types.hpp"

namespace finalis::genesis {

struct EmbeddedGenesis {
  const std::uint8_t* data;
  std::size_t len;
  Hash32 hash;  // sha256d of the bytes
};

// The genesis compiled into this binary for `network_name`; nullopt when it embeds none (testnet
// before its genesis is frozen).
std::optional<EmbeddedGenesis> embedded_genesis_for(const std::string& network_name);

}  // namespace finalis::genesis
