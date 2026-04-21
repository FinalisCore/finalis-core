// SPDX-License-Identifier: MIT

#include "crypto/stealth_address.hpp"

#include <algorithm>

#include "crypto/confidential.hpp"
#include "crypto/hash.hpp"

namespace finalis::crypto {

bool stealth_address_is_canonical(const StealthAddress& addr) {
  return compressed_pubkey33_is_canonical(addr.view_pubkey) && compressed_pubkey33_is_canonical(addr.spend_pubkey);
}

std::optional<StealthScanResult> scan_stealth_output(const PubKey33& ephemeral_pubkey, std::uint8_t scan_tag,
                                                     const Bytes& wallet_view_key_material) {
  if (!compressed_pubkey33_is_canonical(ephemeral_pubkey) || wallet_view_key_material.empty()) return std::nullopt;
  Bytes preimage(wallet_view_key_material.begin(), wallet_view_key_material.end());
  preimage.insert(preimage.end(), ephemeral_pubkey.begin(), ephemeral_pubkey.end());
  preimage.push_back(scan_tag);
  const auto digest = sha256d(preimage);
  StealthScanResult out;
  out.one_time_pubkey[0] = 0x02 | (digest[0] & 0x01);
  std::copy(digest.begin(), digest.end(), out.one_time_pubkey.begin() + 1);
  out.mine = true;
  return out;
}

}  // namespace finalis::crypto
