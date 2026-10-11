// SPDX-License-Identifier: MIT

#pragma once

#include <cstdint>
#include <optional>

#include "crypto/confidential.hpp"
#include "crypto/secure_memory.hpp"

namespace finalis::wallet {

// Deterministic per-request receive keys for a confidential account (view secret v, spend secret s,
// spend pubkey S = s*G). Request i:
//
//   t_i              = hash_to_scalar("FINALIS/conf-request/tweak/v1",     v, i)
//   one_time_pubkey  = S + t_i*G          (watch-only: needs v and S)
//   one_time_secret  = s + t_i mod n      (spending: needs s)
//   ephemeral_pubkey = hash_to_scalar("FINALIS/conf-request/ephemeral/v1", v, i) * G
//   scan_tag         = first byte of tagged_hash("FINALIS/conf-request/scan-tag/v1", v, i)
//   memo_key         = tagged_hash("FINALIS/conf-request/memo/v1", v, i)
//
// Backing up (v, s) therefore recovers every request, so every received coin; (v, S) alone is a
// watch-only key that recognises incoming coins and decrypts their amounts but cannot spend.
// Caveat of this (BIP32-style non-hardened) construction: one leaked one_time_secret together with
// v reveals s. One-time secrets must be protected exactly like s.

struct ConfidentialRequestPublicKeys {
  PubKey33 one_time_pubkey{};
  PubKey33 ephemeral_pubkey{};
  crypto::ScanTag scan_tag{};
  Hash32 memo_key{};

  ~ConfidentialRequestPublicKeys() { crypto::secure_wipe(memo_key); }
};

struct ConfidentialRequestKeys {
  ConfidentialRequestPublicKeys pub;
  Hash32 one_time_secret{};

  ~ConfidentialRequestKeys() { crypto::secure_wipe(one_time_secret); }
};

// Watch-only derivation. Nullopt if v or S is invalid.
std::optional<ConfidentialRequestPublicKeys> derive_confidential_request_public_keys(const Hash32& view_secret,
                                                                                    const PubKey33& spend_pubkey,
                                                                                    std::uint32_t index);

// Full derivation; pub matches derive_confidential_request_public_keys(v, s*G, i). Nullopt if v or s is
// invalid.
std::optional<ConfidentialRequestKeys> derive_confidential_request_keys(const Hash32& view_secret,
                                                                        const Hash32& spend_secret,
                                                                        std::uint32_t index);

}  // namespace finalis::wallet
