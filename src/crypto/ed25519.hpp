// SPDX-License-Identifier: MIT

#pragma once

#include <optional>

#include "common/types.hpp"

namespace finalis::crypto {

struct KeyPair {
  Bytes private_key;  // 32 bytes seed/private scalar (OpenSSL raw private)
  PubKey32 public_key;
};

std::optional<KeyPair> keypair_from_seed32(const std::array<std::uint8_t, 32>& seed);
std::optional<Sig64> ed25519_sign(const Bytes& msg, const Bytes& private_key_32);
bool ed25519_verify(const Bytes& msg, const Sig64& sig, const PubKey32& pubkey);

}  // namespace finalis::crypto
