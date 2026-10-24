// SPDX-License-Identifier: MIT

#pragma once

#include <array>
#include <optional>

#include "common/types.hpp"

namespace finalis::crypto {

// Verifiable random function on a validator's Ed25519 key (same seed, same public key).
//
// RFC 9381 ECVRF-EDWARDS25519-SHA512-TAI (suite_string 0x03), byte for byte:
//   x, prefix  = clamp(SHA512(seed)[0..32]) mod L, SHA512(seed)[32..64]   (RFC 8032 key expansion)
//   Y          = x*B, the Ed25519 public key
//   H          = 8 * string_to_point(SHA512(0x03 || 0x01 || Y || alpha || ctr || 0x00)[0..32]) for
//                the first one-byte ctr that decodes to a point whose multiple is not the identity
//   Gamma      = x*H
//   k          = SHA512(prefix || H) mod L
//   c          = SHA512(0x03 || 0x02 || Y || H || Gamma || k*B || k*H || 0x00)[0..16]
//   s          = k + c*x mod L
//   proof      = Gamma || c || s                                  (80 bytes)
//   output     = SHA512(0x03 || 0x03 || 8*Gamma || 0x00)          (64 bytes)
// Verification uses validate_key = TRUE (small-order keys are rejected) and RFC 8032 decoding
// (non-canonical encodings are rejected).
//
// Points are decoded, cofactor-cleared and verified with plain big-integer arithmetic, never with
// libsodium's point validation: that validation changed in a libsodium security fix shipped under
// an unchanged version number, and builds disagreed on proofs. Proving keeps libsodium's
// constant-time code for the secret scalars, applied only to prime-order points. vrf_init() checks
// the RFC test vectors once and fails if this build does not reproduce them.
//
// Uniqueness: for a valid key, each alpha has exactly one output; the prover can choose only
// whether to publish it.

inline constexpr std::size_t kVrfProofBytes = 80;
inline constexpr std::size_t kVrfOutputBytes = 64;
using VrfOutput = std::array<std::uint8_t, kVrfOutputBytes>;

// False if libsodium could not be initialized or this build does not reproduce the RFC 9381 test
// vectors. A node must not take part in consensus then.
bool vrf_init();

// Nullopt if the key is not a 32-byte seed or libsodium is unavailable.
std::optional<VrfProof80> vrf_prove(const Bytes& private_key_32, const Bytes& alpha);

// The output if `proof` is the proof for (pubkey, alpha), else nullopt. Rejects public keys
// outside the prime-order subgroup, non-canonical encodings and s >= L.
std::optional<VrfOutput> vrf_verify(const PubKey32& pubkey, const VrfProof80& proof, const Bytes& alpha);

// Output of a proof, without checking it. Only for proofs already verified (all zero if Gamma does
// not decode).
VrfOutput vrf_proof_to_output(const VrfProof80& proof);

}  // namespace finalis::crypto
