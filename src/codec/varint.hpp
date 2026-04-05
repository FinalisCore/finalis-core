#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

#include "common/types.hpp"

namespace finalis::codec {

Bytes encode_uleb128(std::uint64_t v);
std::optional<std::uint64_t> decode_uleb128(const Bytes& in, size_t& off, bool minimal = true);
bool is_minimal_uleb128_encoding(const Bytes& enc);

}  // namespace finalis::codec
