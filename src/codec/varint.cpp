#include "codec/varint.hpp"

namespace finalis::codec {

Bytes encode_uleb128(std::uint64_t v) {
  Bytes out;
  do {
    std::uint8_t byte = static_cast<std::uint8_t>(v & 0x7F);
    v >>= 7;
    if (v != 0) byte |= 0x80;
    out.push_back(byte);
  } while (v != 0);
  return out;
}

bool is_minimal_uleb128_encoding(const Bytes& enc) {
  if (enc.empty()) return false;
  size_t off = 0;
  const auto v = decode_uleb128(enc, off, false);
  if (!v.has_value() || off != enc.size()) return false;
  return encode_uleb128(v.value()) == enc;
}

std::optional<std::uint64_t> decode_uleb128(const Bytes& in, size_t& off, bool minimal) {
  std::uint64_t result = 0;
  int shift = 0;
  const size_t start = off;

  while (off < in.size() && shift <= 63) {
    const std::uint8_t byte = in[off++];
    const std::uint64_t chunk = static_cast<std::uint64_t>(byte & 0x7F);
    if (shift == 63 && chunk > 1) return std::nullopt;
    result |= (chunk << shift);
    if ((byte & 0x80) == 0) {
      if (minimal) {
        Bytes enc(in.begin() + static_cast<long>(start), in.begin() + static_cast<long>(off));
        if (encode_uleb128(result) != enc) return std::nullopt;
      }
      return result;
    }
    shift += 7;
  }
  return std::nullopt;
}

}  // namespace finalis::codec
