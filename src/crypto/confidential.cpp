#include "crypto/confidential.hpp"

#include <algorithm>
#include <array>
#include <mutex>
#include <vector>

#if defined(SC_HAS_SECP256K1)
#include <secp256k1.h>
#endif
#if defined(SC_HAS_SECP256K1_ZKP)
#include <secp256k1_commitment.h>
#include <secp256k1_generator.h>
#include <secp256k1_rangeproof.h>
#endif

namespace finalis::crypto {
namespace {

#if defined(SC_HAS_SECP256K1_ZKP)
inline constexpr bool kRangeproofVerificationImplemented = false;
#else
inline constexpr bool kRangeproofVerificationImplemented = false;
#endif

Commitment33 zero_commitment() {
  Commitment33 out;
  out.bytes.fill(0);
  return out;
}

bool is_zero_commitment(const Commitment33& commitment) {
  return std::all_of(commitment.bytes.begin(), commitment.bytes.end(), [](std::uint8_t b) { return b == 0; });
}

std::array<std::uint8_t, 32> scalar_from_u64(std::uint64_t value) {
  std::array<std::uint8_t, 32> scalar{};
  for (int i = 0; i < 8; ++i) {
    scalar[31 - i] = static_cast<std::uint8_t>((value >> (8 * i)) & 0xFF);
  }
  return scalar;
}

#if defined(SC_HAS_SECP256K1)
struct SecpBackend {
  secp256k1_context* ctx{nullptr};
  ConfidentialBackendStatus status{};
  bool initialized{false};
};

SecpBackend& backend() {
  static SecpBackend state;
  return state;
}

bool parse_pubkey(const PubKey33& bytes, secp256k1_pubkey* pubkey_out) {
  if (!backend().ctx) return false;
  return secp256k1_ec_pubkey_parse(backend().ctx, pubkey_out, bytes.data(), bytes.size()) == 1;
}

std::optional<PubKey33> serialize_pubkey(const secp256k1_pubkey& pubkey) {
  if (!backend().ctx) return std::nullopt;
  PubKey33 out{};
  size_t out_len = out.size();
  if (secp256k1_ec_pubkey_serialize(backend().ctx, out.data(), &out_len, &pubkey, SECP256K1_EC_COMPRESSED) != 1) {
    return std::nullopt;
  }
  if (out_len != out.size()) return std::nullopt;
  return out;
}
#endif

}  // namespace

bool confidential_crypto_init() {
#if defined(SC_HAS_SECP256K1)
  static std::once_flag once;
  std::call_once(once, []() {
    auto& state = backend();
    state.ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);
    state.status.secp256k1_available = state.ctx != nullptr;
#if defined(SC_HAS_SECP256K1_ZKP)
    state.status.zkp_backend_available = state.ctx != nullptr;
    state.status.rangeproof_backend_available = state.ctx != nullptr && kRangeproofVerificationImplemented;
#else
    state.status.zkp_backend_available = false;
    state.status.rangeproof_backend_available = false;
#endif
    state.status.excess_authorization_available = false;
    state.status.confidential_outputs_supported =
        state.status.secp256k1_available && state.status.rangeproof_backend_available;
    state.initialized = true;
  });
  return backend().status.secp256k1_available;
#else
  return false;
#endif
}

const ConfidentialBackendStatus& confidential_backend_status() {
#if defined(SC_HAS_SECP256K1)
  (void)confidential_crypto_init();
  return backend().status;
#else
  static const ConfidentialBackendStatus unavailable{};
  return unavailable;
#endif
}

bool commitment_is_identity(const Commitment33& commitment) { return is_zero_commitment(commitment); }

bool compressed_pubkey33_is_canonical(const PubKey33& pubkey) {
#if defined(SC_HAS_SECP256K1)
  if (!confidential_crypto_init()) return false;
  secp256k1_pubkey parsed{};
  return parse_pubkey(pubkey, &parsed);
#else
  (void)pubkey;
  return false;
#endif
}

bool commitment_is_canonical(const Commitment33& commitment) {
  if (is_zero_commitment(commitment)) return false;
  return compressed_pubkey33_is_canonical(commitment.bytes);
}

Commitment33 transparent_amount_commitment(std::uint64_t amount) {
#if defined(SC_HAS_SECP256K1)
  if (!confidential_crypto_init()) return zero_commitment();
  if (amount == 0) return zero_commitment();

  const auto scalar = scalar_from_u64(amount);
  secp256k1_pubkey pubkey{};
  if (secp256k1_ec_pubkey_create(backend().ctx, &pubkey, scalar.data()) != 1) return zero_commitment();
  const auto serialized = serialize_pubkey(pubkey);
  if (!serialized.has_value()) return zero_commitment();

  Commitment33 out;
  out.bytes = *serialized;
  return out;
#else
  (void)amount;
  return zero_commitment();
#endif
}

std::optional<Commitment33> add_commitments(std::span<const Commitment33> commitments) {
#if defined(SC_HAS_SECP256K1)
  if (!confidential_crypto_init()) return std::nullopt;

  std::vector<secp256k1_pubkey> parsed;
  std::vector<const secp256k1_pubkey*> ptrs;
  parsed.reserve(commitments.size());
  ptrs.reserve(commitments.size());

  for (const auto& commitment : commitments) {
    if (is_zero_commitment(commitment)) continue;
    secp256k1_pubkey parsed_commitment{};
    if (!parse_pubkey(commitment.bytes, &parsed_commitment)) return std::nullopt;
    parsed.push_back(parsed_commitment);
  }
  if (parsed.empty()) return zero_commitment();
  for (const auto& item : parsed) ptrs.push_back(&item);

  secp256k1_pubkey combined{};
  if (secp256k1_ec_pubkey_combine(backend().ctx, &combined, ptrs.data(), ptrs.size()) != 1) return std::nullopt;
  const auto serialized = serialize_pubkey(combined);
  if (!serialized.has_value()) return std::nullopt;

  Commitment33 out;
  out.bytes = *serialized;
  return out;
#else
  (void)commitments;
  return std::nullopt;
#endif
}

std::optional<Commitment33> subtract_commitments(const Commitment33& lhs, const Commitment33& rhs) {
#if defined(SC_HAS_SECP256K1)
  if (!confidential_crypto_init()) return std::nullopt;
  if (is_zero_commitment(rhs)) return lhs;

  secp256k1_pubkey neg_rhs{};
  if (!parse_pubkey(rhs.bytes, &neg_rhs)) return std::nullopt;
  if (secp256k1_ec_pubkey_negate(backend().ctx, &neg_rhs) != 1) return std::nullopt;

  std::vector<secp256k1_pubkey> parsed;
  std::vector<const secp256k1_pubkey*> ptrs;
  if (!is_zero_commitment(lhs)) {
    secp256k1_pubkey parsed_lhs{};
    if (!parse_pubkey(lhs.bytes, &parsed_lhs)) return std::nullopt;
    parsed.push_back(parsed_lhs);
  }
  parsed.push_back(neg_rhs);
  for (const auto& item : parsed) ptrs.push_back(&item);

  secp256k1_pubkey combined{};
  if (secp256k1_ec_pubkey_combine(backend().ctx, &combined, ptrs.data(), ptrs.size()) != 1) return zero_commitment();
  const auto serialized = serialize_pubkey(combined);
  if (!serialized.has_value()) return std::nullopt;

  Commitment33 out;
  out.bytes = *serialized;
  return out;
#else
  (void)lhs;
  (void)rhs;
  return std::nullopt;
#endif
}

bool verify_output_range_proof(const Commitment33& commitment, const ProofBytes& proof) {
  (void)proof;
  return confidential_backend_status().confidential_outputs_supported && commitment_is_canonical(commitment);
}

bool verify_output_range_proofs_batch(std::span<const Commitment33> commitments, std::span<const ProofBytes> proofs) {
  if (!confidential_backend_status().confidential_outputs_supported) return false;
  if (commitments.size() != proofs.size()) return false;
  for (std::size_t i = 0; i < commitments.size(); ++i) {
    if (!verify_output_range_proof(commitments[i], proofs[i])) return false;
  }
  return true;
}

std::size_t range_proof_verify_weight(const ProofBytes& proof) {
  if (!confidential_backend_status().confidential_outputs_supported) return 0;
  return proof.bytes.size();
}

}  // namespace finalis::crypto
