// SPDX-License-Identifier: MIT

#include "privacy/mint_scripts.hpp"

#include <algorithm>

namespace finalis::privacy {
namespace {

constexpr std::array<std::uint8_t, 9> kMintDepositTag = {
    'S', 'C', 'M', 'I', 'N', 'T', 'D', 'E', 'P',
};
constexpr std::size_t kMintDepositTagSize = kMintDepositTag.size();

}  // namespace

Bytes mint_deposit_script_pubkey(const Hash32& mint_id, const std::array<std::uint8_t, 20>& recipient_pubkey_hash) {
  Bytes out;
  out.reserve(kMintDepositTagSize + mint_id.size() + recipient_pubkey_hash.size());
  out.insert(out.end(), kMintDepositTag.begin(), kMintDepositTag.end());
  out.insert(out.end(), mint_id.begin(), mint_id.end());
  out.insert(out.end(), recipient_pubkey_hash.begin(), recipient_pubkey_hash.end());
  return out;
}

bool is_mint_deposit_script(const Bytes& script_pubkey, Hash32* out_mint_id,
                            std::array<std::uint8_t, 20>* out_recipient_pubkey_hash) {
  if (script_pubkey.size() != kMintDepositTagSize + 32 + 20) return false;
  if (!std::equal(kMintDepositTag.begin(), kMintDepositTag.end(), script_pubkey.begin())) return false;
  if (out_mint_id) {
    std::copy(script_pubkey.begin() + static_cast<long>(kMintDepositTagSize),
              script_pubkey.begin() + static_cast<long>(kMintDepositTagSize + 32), out_mint_id->begin());
  }
  if (out_recipient_pubkey_hash) {
    std::copy(script_pubkey.begin() + static_cast<long>(kMintDepositTagSize + 32), script_pubkey.end(),
              out_recipient_pubkey_hash->begin());
  }
  return true;
}

}  // namespace finalis::privacy
