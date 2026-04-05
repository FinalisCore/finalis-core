#pragma once

#include <array>

#include "common/types.hpp"

namespace finalis::crypto {

Hash32 sha256(const Bytes& data);
Hash32 sha256d(const Bytes& data);
std::array<std::uint8_t, 20> h160(const Bytes& data);

}  // namespace finalis::crypto
