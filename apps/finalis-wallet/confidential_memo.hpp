// SPDX-License-Identifier: MIT

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>

#include "common/types.hpp"
#include "crypto/confidential.hpp"

namespace finalis::wallet {

// Recovery memo carried in a confidential output so the receiver can learn amount + blind.
// Wire layout (opaque to consensus): nonce[12] || AES-256-GCM(ciphertext) || tag[16].
// The nonce is fresh CSPRNG output per encryption; memo_key is reused across payments to
// the same request URI, so a derived nonce would repeat. AAD binds the memo to its output.
inline constexpr std::uint32_t kConfidentialRecoveryMemoVersion = 1;
inline constexpr std::size_t kConfidentialMemoNonceLen = 12;
inline constexpr std::size_t kConfidentialMemoTagLen = 16;

struct ConfidentialRecoveryPayload {
  std::uint64_t amount{0};
  crypto::Blind32 blind{};
};

std::optional<Bytes> encrypt_confidential_recovery_memo(std::uint64_t amount, const crypto::Blind32& blind,
                                                        const Hash32& memo_key, const PubKey33& one_time_pubkey,
                                                        const PubKey33& ephemeral_pubkey);

std::optional<ConfidentialRecoveryPayload> decrypt_confidential_recovery_memo(const Bytes& memo, const Hash32& memo_key,
                                                                              const PubKey33& one_time_pubkey,
                                                                              const PubKey33& ephemeral_pubkey);

}  // namespace finalis::wallet
