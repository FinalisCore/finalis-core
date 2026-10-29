// SPDX-License-Identifier: MIT

#pragma once

// Internal to src/crypto (swe.cpp, swe_proofs.cpp): blst helpers shared by the SWE scheme and its
// proofs. Not part of the crypto API; includes blst.h.

#include <optional>
#include <string_view>
#include <vector>

#include <blst.h>

#include "crypto/bls12_381.hpp"
#include "crypto/swe.hpp"

namespace finalis::crypto::swe_internal {

const byte* bytes_of(std::string_view s);

// Uniform non-zero scalar from a 32-byte seed, a label and an index (SHA-256 expanded to 64 bytes,
// reduced mod r). Encryption randomness, proof nonces and Fiat-Shamir challenges all use it.
blst_scalar derive_scalar(const Hash32& seed, std::string_view label, std::uint32_t index);

blst_fr to_fr(const blst_scalar& s);
blst_scalar to_scalar(const blst_fr& f);
blst_fr fr_from_be(const BlsScalar& b);

blst_p1 g1_mul(const blst_p1& p, const blst_scalar& s);
blst_p1 g1_add(const blst_p1& a, const blst_p1& b);
BlsPublicKey g1_bytes(const blst_p1& p);
BlsSignature g2_bytes(const blst_p2& p);
// In the subgroup and not the identity.
std::optional<blst_p1_affine> g1_decode(const BlsPublicKey& b);
std::optional<blst_p2_affine> g2_decode(const BlsSignature& b);
blst_p1 g1_point(const blst_p1_affine& a);
blst_p1_affine g1_affine(const blst_p1& p);
blst_p2_affine g2_affine(const blst_p2& p);
// h = HashToG1(c) under kSweHDst.
blst_p1 h_point(const BlsPublicKey& c);
// e(P1, Q1) * e(P2, Q2), one final exponentiation.
blst_fp12 pairing2(const blst_p1_affine& p1, const blst_p2_affine& q1, const blst_p1_affine& p2,
                   const blst_p2_affine& q2);
// xi_j = H2(vk_j) for every key; nullopt on an undecodable key or a repeated point.
std::optional<std::vector<blst_fr>> evaluation_points(const std::vector<BlsPublicKey>& keys);

}  // namespace finalis::crypto::swe_internal
