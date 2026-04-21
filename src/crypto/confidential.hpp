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
std::optional<ProofBytes> sign_output_range_proof(const Commitment33& commitment, std::uint64_t amount,
                                                  const Blind32& blind, const Hash32& nonce32);
std::optional<Commitment33> add_commitments(std::span<const Commitment33> commitments);
std::optional<Commitment33> subtract_commitments(const Commitment33& lhs, const Commitment33& rhs);
bool verify_commitment_tally(std::span<const Commitment33> positives, std::span<const Commitment33> negatives);

bool verify_output_range_proof(const Commitment33& commitment, const ProofBytes& proof);
bool verify_output_range_proofs_batch(std::span<const Commitment33> commitments, std::span<const ProofBytes> proofs);

std::size_t range_proof_verify_weight(const ProofBytes& proof);

}  // namespace finalis::crypto
