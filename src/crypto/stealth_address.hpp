#pragma once

#include <optional>

#include "common/types.hpp"

namespace finalis::crypto {

struct StealthAddress {
  PubKey33 view_pubkey{};
  PubKey33 spend_pubkey{};
  bool operator==(const StealthAddress&) const = default;
};

struct StealthScanResult {
  PubKey33 one_time_pubkey{};
  bool mine{false};
  bool operator==(const StealthScanResult&) const = default;
};

bool stealth_address_is_canonical(const StealthAddress& addr);
std::optional<StealthScanResult> scan_stealth_output(const PubKey33& ephemeral_pubkey, std::uint8_t scan_tag,
                                                     const Bytes& wallet_view_key_material);

}  // namespace finalis::crypto
