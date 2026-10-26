// SPDX-License-Identifier: MIT

#pragma once

#include <optional>
#include <string_view>
#include <vector>

#include "common/types.hpp"
#include "crypto/bls12_381.hpp"
#include "crypto/swe.hpp"

namespace finalis::crypto {

// Well-formedness proof for an SWE' ciphertext (ePrint 2022/433, section 7.1), non-interactive in
// the random-oracle model (Fiat-Shamir over SHA-256). It shows, for the given committee, threshold
// and reference message:
//   (1) (r0, s_1, ..., s_n) behind c0 and the key shares c_j is a Reed-Solomon codeword of
//       dimension t over the points (0, xi_1, ..., xi_n): every signer set of size >= t recovers the
//       same g1^r0, so the ciphertext decrypts to the same chunks whoever signs;
//   (2) every chunk has (c, a_i) and (H(T), t_i) with the same discrete-log ratio (batched into one
//       pairing check with Fiat-Shamir weights).
// For a random challenge v the verifier forms w = v^T H (H the code's parity-check matrix), then
// c* = c0^{w0} prod c_j^{wj} and g* = h^{w0} prod vk_j^{wj}; for a well-formed ciphertext
// c* = (g*)^r, and the proof is a Chaum-Pedersen equality of log_g1(c) and log_{g*}(c*).
//
// It does not show that a chunk is in [0, 2^24) or what the chunks are (the paper's section 7.2-7.3
// range and plaintext-equality proofs); a chunk out of range makes decryption fail, which the
// chain treats as an invalid body.
//
// Wire: version(1) | f (G1, 48) | f* (G1, 48) | z (32, big-endian, < r) = 129 bytes.

inline constexpr std::size_t kSweWellFormednessProofBytes = 1 + 2 * kBlsPublicKeyBytes + kBlsScalarBytes;

struct SweWellFormednessProof {
  BlsPublicKey f{};
  BlsPublicKey f_star{};
  BlsScalar z{};

  Bytes serialize() const;
  static std::optional<SweWellFormednessProof> parse(const Bytes& b);

  bool operator==(const SweWellFormednessProof&) const = default;
};

// `seed` is the one swe_encrypt used (the witness r is derived from it). Nullopt if the ciphertext
// was not produced from this seed for this committee, or the statement is malformed.
std::optional<SweWellFormednessProof> swe_prove_well_formed(const SweCiphertext& ct,
                                                            const std::vector<BlsPublicKey>& committee,
                                                            const Bytes& msg, std::string_view dst,
                                                            const Hash32& seed);

bool swe_verify_well_formed(const SweCiphertext& ct, const std::vector<BlsPublicKey>& committee, const Bytes& msg,
                            std::string_view dst, const SweWellFormednessProof& proof);

}  // namespace finalis::crypto
