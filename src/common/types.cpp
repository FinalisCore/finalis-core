#include "common/types.hpp"

#include <algorithm>
#include <sstream>

namespace finalis {

std::string hex_encode(const Bytes& data) {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string out;
  out.resize(data.size() * 2);
  for (size_t i = 0; i < data.size(); ++i) {
    out[2 * i] = kHex[(data[i] >> 4) & 0xF];
    out[2 * i + 1] = kHex[data[i] & 0xF];
  }
  return out;
}

std::string hex_encode32(const Hash32& h) {
  return hex_encode(Bytes(h.begin(), h.end()));
}

std::optional<Bytes> hex_decode(const std::string& s) {
  if (s.size() % 2 != 0) {
    return std::nullopt;
  }
  auto nibble = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
  };

  Bytes out;
  out.reserve(s.size() / 2);
  for (size_t i = 0; i < s.size(); i += 2) {
    const int hi = nibble(s[i]);
    const int lo = nibble(s[i + 1]);
    if (hi < 0 || lo < 0) {
      return std::nullopt;
    }
    out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
  }
  return out;
}

Hash32 zero_hash() {
  Hash32 h{};
  h.fill(0);
  return h;
}

}  // namespace finalis
