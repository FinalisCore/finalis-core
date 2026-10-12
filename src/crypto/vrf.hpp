// SPDX-License-Identifier: MIT

#pragma once

#include <array>
#include <optional>

#include "common/types.hpp"

namespace finalis::crypto {

// Verifiable random function on a validator's Ed25519 key (same seed, same public key).
//
// ECVRF in the structure of RFC 9381 over edwards25519, with SHA-512:
//   x, prefix  = clamp(SHA512(seed)[0..32]) mod L, SHA512(seed)[32..64]   (RFC 8032 key expansion)
//   Y          = x*B, the Ed25519 public key
//   H          = encode_to_curve(Y, alpha): first ctr in 0..1023 with
//                SHA512(SUITE || 0x01 || Y || alpha || le32(ctr))[0..32] a canonical point of the
//                prime-order subgroup (try-and-increment, rejecting instead of clearing the cofactor)
//   Gamma      = x*H
//   k          = SHA512(prefix || H) mod L
//   c          = SHA512(SUITE || 0x02 || Y || H || Gamma || k*B || k*H)[0..16]
//   s          = k + c*x mod L
//   proof      = Gamma || c || s                                  (80 bytes)
//   output     = SHA512(SUITE || 0x03 || Gamma)                   (64 bytes)
// SUITE = "FINALIS-ECVRF-EDWARDS25519-SHA512-TAI-V1". Not byte-compatible with RFC 9381's suites
// (its TAI suite multiplies by the cofactor), but uniqueness and pseudorandomness rest on the same
// argument. Every check is a mathematical predicate, so outputs agree across libsodium versions.
//
// Uniqueness: for a valid key, each alpha has exactly one output; the prover can choose only
// whether to publish it.

inline constexpr std::size_t kVrfProofBytes = 80;
inline constexpr std::size_t kVrfOutputBytes = 64;
using VrfOutput = std::array<std::uint8_t, kVrfOutputBytes>;

// False if libsodium could not be initialized.
bool vrf_init();

// Nullopt if the key is not a 32-byte seed or libsodium is unavailable.
std::optional<VrfProof80> vrf_prove(const Bytes& private_key_32, const Bytes& alpha);

// The output if `proof` is the proof for (pubkey, alpha), else nullopt. Rejects public keys
// outside the prime-order subgroup, non-canonical encodings and s >= L.
std::optional<VrfOutput> vrf_verify(const PubKey32& pubkey, const VrfProof80& proof, const Bytes& alpha);

// Output of a proof, without checking it. Only for proofs already verified.
VrfOutput vrf_proof_to_output(const VrfProof80& proof);

}  // namespace finalis::crypto
