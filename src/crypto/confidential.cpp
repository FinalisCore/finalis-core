#include "crypto/confidential.hpp"

#include <algorithm>
#include <array>
#include <mutex>
#include <cstring>
#include <vector>

#if defined(SC_HAS_SECP256K1)
#include <secp256k1.h>
#endif
#if defined(SC_HAS_SECP256K1_ZKP)
#include <secp256k1_generator.h>
#include <secp256k1_rangeproof.h>
#endif

namespace finalis::crypto {
namespace {

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
#if defined(SC_HAS_SECP256K1_ZKP)
  const secp256k1_generator* value_generator{nullptr};
#endif
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

#if defined(SC_HAS_SECP256K1_ZKP)
bool parse_pedersen_commitment(const Commitment33& bytes, secp256k1_pedersen_commitment* out) {
  if (!backend().ctx) return false;
  return secp256k1_pedersen_commitment_parse(backend().ctx, out, bytes.bytes.data()) == 1;
}

std::optional<Commitment33> serialize_pedersen_commitment(const secp256k1_pedersen_commitment& commitment) {
  if (!backend().ctx) return std::nullopt;
  Commitment33 out;
  if (secp256k1_pedersen_commitment_serialize(backend().ctx, out.bytes.data(), &commitment) != 1) return std::nullopt;
  return out;
}

std::array<unsigned char, 32> zero_blind() {
  std::array<unsigned char, 32> blind{};
  blind.fill(0);
  return blind;
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
    state.value_generator = secp256k1_generator_h;
    state.status.rangeproof_backend_available = state.ctx != nullptr && state.value_generator != nullptr;
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

std::optional<PubKey33> secp256k1_pubkey_from_scalar(const Hash32& scalar32) {
#if defined(SC_HAS_SECP256K1)
  if (!confidential_crypto_init()) return std::nullopt;
  secp256k1_pubkey pubkey{};
  if (secp256k1_ec_pubkey_create(backend().ctx, &pubkey, scalar32.data()) != 1) return std::nullopt;
  return serialize_pubkey(pubkey);
#else
  (void)scalar32;
  return std::nullopt;
#endif
}

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
#if defined(SC_HAS_SECP256K1_ZKP)
  if (!confidential_crypto_init()) return false;
  secp256k1_pedersen_commitment parsed{};
  return parse_pedersen_commitment(commitment, &parsed);
#else
  return compressed_pubkey33_is_canonical(commitment.bytes);
#endif
}

Commitment33 transparent_amount_commitment(std::uint64_t amount) {
#if defined(SC_HAS_SECP256K1)
  if (!confidential_crypto_init()) return zero_commitment();
  if (amount == 0) return zero_commitment();
#if defined(SC_HAS_SECP256K1_ZKP)
  if (backend().status.rangeproof_backend_available && backend().value_generator != nullptr) {
    secp256k1_pedersen_commitment commitment{};
    const auto blind = zero_blind();
    if (secp256k1_pedersen_commit(backend().ctx, &commitment, blind.data(), amount, backend().value_generator) != 1) {
      return zero_commitment();
    }
    const auto serialized = serialize_pedersen_commitment(commitment);
    if (!serialized.has_value()) return zero_commitment();
    return *serialized;
  }
#endif
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

std::optional<Commitment33> confidential_amount_commitment(std::uint64_t amount, const Blind32& blind) {
#if defined(SC_HAS_SECP256K1_ZKP)
  if (!confidential_crypto_init()) return std::nullopt;
  if (!backend().status.rangeproof_backend_available || backend().value_generator == nullptr) return std::nullopt;
  secp256k1_pedersen_commitment commitment{};
  if (secp256k1_pedersen_commit(backend().ctx, &commitment, blind.bytes.data(), amount, backend().value_generator) != 1) {
    return std::nullopt;
  }
  return serialize_pedersen_commitment(commitment);
#else
  (void)amount;
  (void)blind;
  return std::nullopt;
#endif
}

std::optional<Blind32> combine_blinds(std::span<const Blind32> blinds, std::size_t npositive) {
#if defined(SC_HAS_SECP256K1_ZKP)
  if (!confidential_crypto_init()) return std::nullopt;
  if (!backend().status.rangeproof_backend_available) return std::nullopt;
  std::vector<const unsigned char*> ptrs;
  ptrs.reserve(blinds.size());
  for (const auto& blind : blinds) ptrs.push_back(blind.bytes.data());
  Blind32 out{};
  if (secp256k1_pedersen_blind_sum(backend().ctx, out.bytes.data(), ptrs.data(), ptrs.size(), npositive) != 1) {
    return std::nullopt;
  }
  return out;
#else
  (void)blinds;
  (void)npositive;
  return std::nullopt;
#endif
}

std::optional<ProofBytes> sign_output_range_proof(const Commitment33& commitment, std::uint64_t amount,
                                                  const Blind32& blind, const Hash32& nonce32) {
#if defined(SC_HAS_SECP256K1_ZKP)
  if (!confidential_crypto_init()) return std::nullopt;
  if (!backend().status.rangeproof_backend_available || backend().value_generator == nullptr) return std::nullopt;

  secp256k1_pedersen_commitment parsed{};
  if (!parse_pedersen_commitment(commitment, &parsed)) return std::nullopt;

  ProofBytes out;
  out.bytes.resize(secp256k1_rangeproof_max_size(backend().ctx, UINT64_MAX, 64));
  size_t proof_len = out.bytes.size();
  if (secp256k1_rangeproof_sign(backend().ctx, out.bytes.data(), &proof_len, 0, &parsed, blind.bytes.data(),
                                nonce32.data(), 0, 64, amount, nullptr, 0, nullptr, 0, backend().value_generator) != 1) {
    return std::nullopt;
  }
  out.bytes.resize(proof_len);
  return out;
#else
  (void)commitment;
  (void)amount;
  (void)blind;
  (void)nonce32;
  return std::nullopt;
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

bool verify_commitment_tally(std::span<const Commitment33> positives, std::span<const Commitment33> negatives) {
#if defined(SC_HAS_SECP256K1_ZKP)
  if (!confidential_crypto_init()) return false;
  if (!backend().status.rangeproof_backend_available) return false;

  std::vector<secp256k1_pedersen_commitment> pos_storage;
  std::vector<const secp256k1_pedersen_commitment*> pos_ptrs;
  std::vector<secp256k1_pedersen_commitment> neg_storage;
  std::vector<const secp256k1_pedersen_commitment*> neg_ptrs;

  for (const auto& commitment : positives) {
    if (is_zero_commitment(commitment)) continue;
    secp256k1_pedersen_commitment parsed{};
    if (!parse_pedersen_commitment(commitment, &parsed)) return false;
    pos_storage.push_back(parsed);
  }
  for (const auto& parsed : pos_storage) pos_ptrs.push_back(&parsed);

  for (const auto& commitment : negatives) {
    if (is_zero_commitment(commitment)) continue;
    secp256k1_pedersen_commitment parsed{};
    if (!parse_pedersen_commitment(commitment, &parsed)) return false;
    neg_storage.push_back(parsed);
  }
  for (const auto& parsed : neg_storage) neg_ptrs.push_back(&parsed);

  return secp256k1_pedersen_verify_tally(backend().ctx, pos_ptrs.data(), pos_ptrs.size(), neg_ptrs.data(),
                                         neg_ptrs.size()) == 1;
#else
  (void)positives;
  (void)negatives;
  return false;
#endif
}

bool verify_output_range_proof(const Commitment33& commitment, const ProofBytes& proof) {
#if defined(SC_HAS_SECP256K1_ZKP)
  if (!confidential_backend_status().confidential_outputs_supported) return false;
  secp256k1_pedersen_commitment parsed{};
  if (!parse_pedersen_commitment(commitment, &parsed)) return false;
  std::uint64_t min_value = 0;
  std::uint64_t max_value = 0;
  return secp256k1_rangeproof_verify(backend().ctx, &min_value, &max_value, &parsed, proof.bytes.data(),
                                     proof.bytes.size(), nullptr, 0, backend().value_generator) == 1;
#else
  (void)commitment;
  (void)proof;
  return false;
#endif
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
