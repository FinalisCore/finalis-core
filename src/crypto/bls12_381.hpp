// SPDX-License-Identifier: MIT

#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

#include "common/types.hpp"
#include "crypto/secure_memory.hpp"

namespace finalis::crypto {

// BLS12-381 signatures over blst, for validator time signatures and McFly signature-based witness
// encryption (Döttling, Hanzlik, Magri, Wohnig, "McFly: Verifiable Encryption to the Future Made
// Practical", ePrint 2022/433, sections 5-6).
//
// Variant: public keys in G1 (48-byte compressed), signatures in G2 (96 bytes), messages hashed to
// G2 (RFC 9380 hash_to_curve, SSWU, random oracle). A McFly ciphertext carries one element per
// committee key in the key group, so keys in G1 halve its size and keep the per-key work in the
// faster group. Every decoded point is checked to be on the curve and in the prime-order subgroup;
// the identity is rejected as a key or signature.
//
// Keys must come with a proof of possession (bls_pop_*), checked once when the key is registered:
// aggregation below trusts that no key was chosen as a function of the others (rogue-key attack).

inline constexpr std::size_t kBlsSecretKeyBytes = 32;
inline constexpr std::size_t kBlsPublicKeyBytes = 48;
inline constexpr std::size_t kBlsSignatureBytes = 96;
inline constexpr std::size_t kBlsScalarBytes = 32;

using BlsPublicKey = std::array<std::uint8_t, kBlsPublicKeyBytes>;
using BlsSignature = std::array<std::uint8_t, kBlsSignatureBytes>;
// An element of Z_r (r = the group order), 32 bytes big-endian, reduced.
using BlsScalar = std::array<std::uint8_t, kBlsScalarBytes>;

// Domain separation tags. The time-signature message itself (chain domain, height) is built by the
// consensus layer; these only separate the hash-to-curve uses.
inline constexpr std::string_view kBlsTimeSignatureDst = "FINALIS-TIME-V1_BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
inline constexpr std::string_view kBlsPopDst = "FINALIS-TIME-V1_BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

struct BlsSecretKey {
  std::array<std::uint8_t, kBlsSecretKeyBytes> bytes{};  // big-endian scalar, 0 < sk < r
  ~BlsSecretKey() { secure_wipe(bytes); }
};

// IETF BLS KeyGen (HKDF-SHA256) from at least 32 bytes of key material.
std::optional<BlsSecretKey> bls_keygen(const Bytes& ikm);
std::optional<BlsPublicKey> bls_public_key(const BlsSecretKey& sk);
std::optional<BlsSignature> bls_sign(const BlsSecretKey& sk, const Bytes& msg, std::string_view dst);
bool bls_verify(const BlsPublicKey& pk, const Bytes& msg, std::string_view dst, const BlsSignature& sig);

// Proof of possession: a signature on the compressed public key under kBlsPopDst.
std::optional<BlsSignature> bls_pop_prove(const BlsSecretKey& sk);
bool bls_pop_verify(const BlsPublicKey& pk, const BlsSignature& pop);

// --- McFly aggregation (paper section 5): Lagrange-weighted, for t-out-of-n decryption ---
//
// Each committee key vk_j gets an evaluation point xi_j = H2(vk_j) in Z_r. For a signer set I the
// aggregate is sigma = prod_{j in I} sigma_j^{L_j} with L_j = prod_{i in I, i != j} xi_i / (xi_i - xi_j),
// the Lagrange coefficient of j at 0. It verifies against prod_{j in I} vk_j^{L_j}, and it is the
// witness an SWE ciphertext (encrypted to Shamir shares evaluated at the same xi_j) needs.
// All signers must sign the same message. Whether |I| reaches the threshold is the caller's rule.

// xi = H2(vk): SHA-256 expanded to 64 bytes and reduced mod r, never 0 (nullopt if it were, or if
// the key does not decode to a valid G1 point).
std::optional<BlsScalar> mcfly_evaluation_point(const BlsPublicKey& pk);
// Lagrange coefficients at 0 for the given points, in order. Nullopt if a point is 0 or repeated.
std::optional<std::vector<BlsScalar>> lagrange_coefficients_at_zero(const std::vector<BlsScalar>& points);
// Nullopt on mismatched sizes, an empty or duplicate signer set, or an undecodable key/signature.
// The signatures are not verified here.
std::optional<BlsSignature> mcfly_aggregate(const std::vector<BlsPublicKey>& signers,
                                            const std::vector<BlsSignature>& sigs);
std::optional<BlsPublicKey> mcfly_aggregate_public_key(const std::vector<BlsPublicKey>& signers);
bool mcfly_aggregate_verify(const std::vector<BlsPublicKey>& signers, const Bytes& msg, std::string_view dst,
                            const BlsSignature& aggregate);

}  // namespace finalis::crypto
