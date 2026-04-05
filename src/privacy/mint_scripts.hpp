#pragma once

#include <array>

#include "common/types.hpp"

namespace finalis::privacy {

Bytes mint_deposit_script_pubkey(const Hash32& mint_id, const std::array<std::uint8_t, 20>& recipient_pubkey_hash);
bool is_mint_deposit_script(const Bytes& script_pubkey, Hash32* out_mint_id = nullptr,
                            std::array<std::uint8_t, 20>* out_recipient_pubkey_hash = nullptr);

}  // namespace finalis::privacy
