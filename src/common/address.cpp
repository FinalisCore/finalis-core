#include "common/address.hpp"

#include <algorithm>

#include "crypto/hash.hpp"

namespace finalis::address {
namespace {

constexpr char kAlphabet[] = "abcdefghijklmnopqrstuvwxyz234567";

std::optional<int> base32_rev(char c) {
  if (c >= 'a' && c <= 'z') return c - 'a';
  if (c >= '2' && c <= '7') return c - '2' + 26;
  return std::nullopt;
}

std::string base32_encode(const Bytes& data) {
  std::string out;
  std::uint32_t buffer = 0;
  int bits = 0;
  for (std::uint8_t b : data) {
    buffer = (buffer << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out.push_back(kAlphabet[(buffer >> (bits - 5)) & 0x1F]);
      bits -= 5;
    }
  }
  if (bits > 0) {
    out.push_back(kAlphabet[(buffer << (5 - bits)) & 0x1F]);
  }
  return out;
}

std::optional<Bytes> base32_decode(const std::string& s) {
  Bytes out;
  std::uint32_t buffer = 0;
  int bits = 0;
  for (char c : s) {
    if (c < 'a' || c > 'z') {
      if (!(c >= '2' && c <= '7')) return std::nullopt;
    }
    auto v = base32_rev(c);
    if (!v.has_value()) return std::nullopt;
    buffer = (buffer << 5) | static_cast<std::uint32_t>(v.value());
    bits += 5;
    if (bits >= 8) {
      out.push_back(static_cast<std::uint8_t>((buffer >> (bits - 8)) & 0xFF));
      bits -= 8;
    }
  }
  if (bits > 0) {
    const auto remainder = static_cast<std::uint8_t>(buffer & ((1u << bits) - 1));
    if (remainder != 0) return std::nullopt;
  }
  return out;
}

Hash32 checksum_hash(const std::string& hrp, const Bytes& payload) {
  Bytes pre;
  pre.insert(pre.end(), hrp.begin(), hrp.end());
  pre.push_back(0x00);
  pre.insert(pre.end(), payload.begin(), payload.end());
  return crypto::sha256d(pre);
}

}  // namespace

std::optional<std::string> encode_p2pkh(const std::string& hrp, const std::array<std::uint8_t, 20>& pubkey_hash) {
  if (hrp != "sc" && hrp != "tsc") return std::nullopt;
  Bytes payload;
  payload.push_back(0x00);
  payload.insert(payload.end(), pubkey_hash.begin(), pubkey_hash.end());

  const auto chk = checksum_hash(hrp, payload);
  Bytes data = payload;
  data.insert(data.end(), chk.begin(), chk.begin() + 4);
  return hrp + "1" + base32_encode(data);
}

ValidationResult validate(const std::string& addr) {
  ValidationResult out;
  const auto sep = addr.find('1');
  if (sep == std::string::npos) {
    out.error = "missing separator";
    return out;
  }
  const std::string hrp = addr.substr(0, sep);
  const std::string b32 = addr.substr(sep + 1);
  if (hrp != "sc" && hrp != "tsc") {
    out.error = "unsupported hrp";
    return out;
  }
  if (b32.empty()) {
    out.error = "missing payload";
    return out;
  }

  auto data_opt = base32_decode(b32);
  if (!data_opt.has_value()) {
    out.error = "invalid base32";
    return out;
  }
  const auto& data = data_opt.value();
  if (data.size() != 25) {
    out.error = "invalid payload length";
    return out;
  }

  Bytes payload(data.begin(), data.begin() + 21);
  const auto chk = checksum_hash(hrp, payload);
  if (!std::equal(data.begin() + 21, data.end(), chk.begin())) {
    out.error = "checksum mismatch";
    return out;
  }
  if (payload[0] != 0x00) {
    out.error = "unsupported address type";
    return out;
  }

  DecodedAddress decoded;
  decoded.hrp = hrp;
  decoded.addr_type = payload[0];
  std::copy(payload.begin() + 1, payload.end(), decoded.pubkey_hash.begin());
  out.valid = true;
  out.decoded = decoded;
  out.normalized_address = encode_p2pkh(hrp, decoded.pubkey_hash);
  return out;
}

std::optional<DecodedAddress> decode(const std::string& addr) {
  auto validated = validate(addr);
  return validated.decoded;
}

Bytes p2pkh_script_pubkey(const std::array<std::uint8_t, 20>& pubkey_hash) {
  Bytes s;
  s.push_back(0x76);
  s.push_back(0xA9);
  s.push_back(0x14);
  s.insert(s.end(), pubkey_hash.begin(), pubkey_hash.end());
  s.push_back(0x88);
  s.push_back(0xAC);
  return s;
}

}  // namespace finalis::address
