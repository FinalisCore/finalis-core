// SPDX-License-Identifier: MIT

#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

#include "common/types.hpp"
#include "crypto/bls12_381.hpp"

namespace finalis::crypto {

// McFly signature-based witness encryption (ePrint 2022/433, section 6.1, enhanced construction
// SWE'), t-out-of-n over the committee's BLS keys and one reference message T (the time-signature
// message of the unlock height). Decryption needs the Lagrange-weighted aggregate
// (mcfly_aggregate) of at least t committee signatures on T.
//
// Our group orientation (bls12_381.hpp) swaps the paper's G1/G2: keys and the per-key components
// live in G1, signatures and H(T) in G2, e : G1 x G2 -> GT, g_T = e(g1, g2).
//
//   r, f(x) = r0 + r1 x + ... + r_{t-1} x^{t-1} random;  xi_j = H2(vk_j);  s_j = f(xi_j)
//   c   = g1^r
//   h   = HashToG1(c)                      (paper: "h random"; derived, so nobody knows log h)
//   c0  = h^r * g1^r0
//   c_j = vk_j^r * g1^{s_j}                for every committee key j, in committee order
//   per chunk i (all T_i = T; the enhanced construction re-randomizes each with alpha_i):
//   a_i = c^{alpha_i},  t_i = H(T)^{alpha_i},  c'_i = e(g1^r0, t_i) * g_T^{m_i}
//
// Decryption with signer set I, |I| >= t, sigma = prod_{j in I} sigma_j^{L_j}:
//   c* = prod_{j in I} c_j^{L_j} = (prod vk_j^{L_j})^r * g1^r0
//   z_i = c'_i * e(a_i, sigma) / e(c*, t_i) = g_T^{m_i},   m_i = dlog by baby-step giant-step.
//
// Chunks are kSweChunkBits wide; a 256-bit key is kSweKeyChunks chunks. A malformed ciphertext can
// decrypt differently for different signer sets or to an out-of-range chunk: the verifiability
// proofs (section 7, not in this module) exclude that; until then decryption reports a chunk it
// cannot find as nullopt.
//
// All randomness comes from the caller's 32-byte seed (expanded with SHA-256, reduced mod r). The
// seed must be fresh and secret per ciphertext: whoever knows it can decrypt.

inline constexpr unsigned kSweChunkBits = 24;
inline constexpr std::uint32_t kSweChunkLimit = 1u << kSweChunkBits;  // chunks are in [0, 2^24)
inline constexpr std::size_t kSweKeyChunks = 11;                       // 10 x 24 + 16 bits
inline constexpr std::size_t kGtBytes = 576;                           // 12 x 48-byte Fp coefficients
inline constexpr std::size_t kSweMaxKeys = 1024;
inline constexpr std::size_t kSweMaxChunks = 64;
inline constexpr std::string_view kSweHDst = "FINALIS-SWE-V1_H_BLS12381G1_XMD:SHA-256_SSWU_RO_";

using GtBytes = std::array<std::uint8_t, kGtBytes>;

struct SweChunk {
  BlsPublicKey a{};     // G1: c^alpha
  BlsSignature t{};     // G2: H(T)^alpha
  GtBytes c_prime{};    // GT: e(g1^r0, t) * g_T^m

  bool operator==(const SweChunk&) const = default;
};

struct SweCiphertext {
  std::uint32_t threshold{0};
  BlsPublicKey c{};                       // G1: g1^r
  BlsPublicKey c0{};                      // G1: h^r g1^r0
  std::vector<BlsPublicKey> key_shares;   // G1: c_j, one per committee key, committee order
  std::vector<SweChunk> chunks;

  // version(1) | threshold(u16) | n(u16) | l(u16) | c | c0 | c_j... | (a | t | c')...   (big-endian)
  Bytes serialize() const;
  // Checks sizes against the limits, every point on its curve and in its subgroup (and not the
  // identity), every GT element canonical and in the order-r subgroup.
  static std::optional<SweCiphertext> parse(const Bytes& b, std::size_t max_keys = kSweMaxKeys,
                                            std::size_t max_chunks = kSweMaxChunks);

  bool operator==(const SweCiphertext&) const = default;
};

// Nullopt if the committee is empty or larger than kSweMaxKeys, has an undecodable or repeated key
// (or a repeated evaluation point), threshold is 0 or > n, a chunk is >= kSweChunkLimit, or there
// are no or too many chunks.
std::optional<SweCiphertext> swe_encrypt(const std::vector<BlsPublicKey>& committee, std::uint32_t threshold,
                                         const Bytes& msg, std::string_view dst,
                                         const std::vector<std::uint32_t>& chunks, const Hash32& seed);

// Chunks, or nullopt if: the ciphertext does not match the committee (count), a signer is not a
// committee member or repeated, |signers| < threshold, the aggregate does not verify for
// (signers, msg), or a chunk is not in [0, kSweChunkLimit) after decryption (malformed ciphertext).
std::optional<std::vector<std::uint32_t>> swe_decrypt(const SweCiphertext& ct, const std::vector<BlsPublicKey>& committee,
                                                      const std::vector<BlsPublicKey>& signers,
                                                      const BlsSignature& aggregate, const Bytes& msg,
                                                      std::string_view dst);

// A 256-bit key as kSweKeyChunks chunks (big-endian bit order) and back. key_from_chunks: nullopt
// if the count is wrong or a chunk exceeds its width (the last one is 16 bits).
std::vector<std::uint32_t> swe_key_to_chunks(const Hash32& key);
std::optional<Hash32> swe_key_from_chunks(const std::vector<std::uint32_t>& chunks);

// m with g_T^m == z for m in [0, kSweChunkLimit), else nullopt (baby-step giant-step, 2^12 x 2^12;
// the baby-step table is built once per process).
std::optional<std::uint32_t> swe_gt_dlog(const GtBytes& z);
// g_T^m, for tests and table checks.
GtBytes swe_gt_pow(std::uint32_t m);

}  // namespace finalis::crypto
