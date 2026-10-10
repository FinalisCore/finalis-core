// SPDX-License-Identifier: MIT

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

#include "common/types.hpp"

namespace finalis::crypto {

struct Commitment33 {
  PubKey33 bytes{};
  bool operator==(const Commitment33&) const = default;
};

struct ProofBytes {
  Bytes bytes;
  bool operator==(const ProofBytes&) const = default;
};

struct ScanTag {
  std::uint8_t value{0};
  bool operator==(const ScanTag&) const = default;
};

struct Blind32 {
  Hash32 bytes{};
  bool operator==(const Blind32&) const = default;
};

struct ConfidentialOutputSecrets {
  std::uint64_t amount{0};
  Blind32 value_blind{};
  bool operator==(const ConfidentialOutputSecrets&) const = default;
};

struct ConfidentialBackendStatus {
  bool secp256k1_available{false};
  bool zkp_backend_available{false};
  bool rangeproof_backend_available{false};
  bool excess_authorization_available{false};
  bool confidential_outputs_supported{false};
};

bool confidential_crypto_init();
const ConfidentialBackendStatus& confidential_backend_status();
bool commitment_is_identity(const Commitment33& commitment);
std::optional<PubKey33> secp256k1_pubkey_from_scalar(const Hash32& scalar32);
// pubkey + tweak*G, and scalar + tweak mod n. Nullopt for an invalid key or tweak (>= n) or a zero result.
std::optional<PubKey33> secp256k1_pubkey_tweak_add(const PubKey33& pubkey, const Hash32& tweak32);
std::optional<Hash32> secp256k1_scalar_tweak_add(const Hash32& scalar32, const Hash32& tweak32);
bool xonly_pubkey32_is_canonical(const PubKey32& pubkey);
bool compressed_pubkey33_is_canonical(const PubKey33& pubkey);
bool commitment_is_canonical(const Commitment33& commitment);
Commitment33 transparent_amount_commitment(std::uint64_t amount);
std::optional<Commitment33> confidential_amount_commitment(std::uint64_t amount, const Blind32& blind);
std::optional<PubKey32> excess_xonly_pubkey_from_scalar(const Blind32& blind);
bool excess_pubkey_matches_commitment(const Commitment33& commitment, const PubKey32& excess_pubkey);
std::optional<Sig64> sign_schnorr_authorization(const Hash32& msg32, const Blind32& secret_scalar, const Hash32& aux32);
bool verify_schnorr_authorization(const Hash32& msg32, const PubKey33& pubkey, const Sig64& sig);
std::optional<Sig64> sign_excess_authorization(const Hash32& msg32, const Blind32& excess_blind, const Hash32& aux32);
bool verify_excess_authorization(const Hash32& msg32, const Commitment33& commitment, const PubKey32& excess_pubkey,
                                 const Sig64& sig);
std::optional<Blind32> combine_blinds(std::span<const Blind32> blinds, std::size_t npositive);
// Borromean range-proof parameters. Consensus accepts only kCanonicalRangeProofShape: a full 64-bit
// proof reveals nothing about the amount, whereas a non-zero minimum, an exponent or fewer bits each
// publish amount information and split users into distinguishable sets.
struct RangeProofShape {
  std::uint64_t min_value{0};
  int exp{0};
  int min_bits{64};
  bool operator==(const RangeProofShape&) const = default;
};
inline constexpr RangeProofShape kCanonicalRangeProofShape{};

std::optional<ProofBytes> sign_output_range_proof(const Commitment33& commitment, std::uint64_t amount,
                                                  const Blind32& blind, const Hash32& nonce32,
                                                  const RangeProofShape& shape = kCanonicalRangeProofShape);
// Cheap header-only check (no verification): exponent 0, minimum value 0, 64-bit mantissa.
bool range_proof_has_canonical_shape(const ProofBytes& proof);
bool verify_commitment_tally(std::span<const Commitment33> positives, std::span<const Commitment33> negatives);

// Running sum of Pedersen commitments as a curve point (secp256k1-zkp has no public commitment
// addition). `infinity` is the identity; otherwise `point` is the compressed sum.
struct CommitmentSum {
  bool infinity{true};
  PubKey33 point{};
  bool operator==(const CommitmentSum&) const = default;
};
// Adds a commitment to the sum. The all-zero identity sentinel is a no-op. False on a malformed commitment.
bool commitment_sum_add(CommitmentSum* sum, const Commitment33& commitment);
bool commitment_sum_add(CommitmentSum* sum, const CommitmentSum& other);
// value * H as a CommitmentSum (identity for 0).
std::optional<CommitmentSum> commitment_sum_of_value(std::uint64_t value);

bool verify_output_range_proof(const Commitment33& commitment, const ProofBytes& proof);
bool verify_output_range_proofs_batch(std::span<const Commitment33> commitments, std::span<const ProofBytes> proofs);


}  // namespace finalis::crypto
