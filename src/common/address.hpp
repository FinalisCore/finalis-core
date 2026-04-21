#pragma once

#include <array>
#include <optional>
#include <string>

#include "common/types.hpp"

namespace finalis::address {

struct DecodedAddress {
  std::string hrp;
  std::uint8_t addr_type;
  std::array<std::uint8_t, 20> pubkey_hash;
};

struct ValidationResult {
  bool valid{false};
  std::string error;
  std::optional<DecodedAddress> decoded;
  std::optional<std::string> normalized_address;
};

std::optional<std::string> encode_p2pkh(const std::string& hrp, const std::array<std::uint8_t, 20>& pubkey_hash);
std::optional<DecodedAddress> decode(const std::string& addr);
ValidationResult validate(const std::string& addr);
Bytes p2pkh_script_pubkey(const std::array<std::uint8_t, 20>& pubkey_hash);

}  // namespace finalis::address
