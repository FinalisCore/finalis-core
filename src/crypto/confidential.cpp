// SPDX-License-Identifier: MIT

#include "crypto/confidential.hpp"

#include <algorithm>
#include <array>
#include <mutex>
#include <cstring>
#include <vector>

#if defined(SC_HAS_SECP256K1)
#include <secp256k1.h>
#endif
#include <openssl/bn.h>

#if defined(SC_HAS_SECP256K1_ZKP)
#include <secp256k1_extrakeys.h>
#include <secp256k1_generator.h>
#include <secp256k1_rangeproof.h>
#include <secp256k1_schnorrsig.h>
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

bool parse_xonly_pubkey(const PubKey32& bytes, secp256k1_xonly_pubkey* pubkey_out) {
#if defined(SC_HAS_SECP256K1_ZKP)
  if (!backend().ctx) return false;
  return secp256k1_xonly_pubkey_parse(backend().ctx, pubkey_out, bytes.data()) == 1;
#else
  (void)bytes;
  (void)pubkey_out;
  return false;
#endif
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

std::optional<PubKey32> serialize_xonly_pubkey(const secp256k1_xonly_pubkey& pubkey) {
#if defined(SC_HAS_SECP256K1_ZKP)
  if (!backend().ctx) return std::nullopt;
  PubKey32 out{};
  if (secp256k1_xonly_pubkey_serialize(backend().ctx, out.data(), &pubkey) != 1) return std::nullopt;
  return out;
#else
  (void)pubkey;
  return std::nullopt;
#endif
}

bool xonly_pubkey_from_pubkey(const PubKey33& pubkey_bytes, secp256k1_xonly_pubkey* xonly_out) {
#if defined(SC_HAS_SECP256K1_ZKP)
  if (!backend().ctx || !xonly_out) return false;
  secp256k1_pubkey pubkey{};
  if (!parse_pubkey(pubkey_bytes, &pubkey)) return false;
  return secp256k1_xonly_pubkey_from_pubkey(backend().ctx, xonly_out, nullptr, &pubkey) == 1;
#else
  (void)pubkey_bytes;
  (void)xonly_out;
  return false;
#endif
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

// True iff the 32-byte big-endian field element y is a quadratic residue mod p (Euler's criterion).
bool field_element_is_square(const unsigned char* y32) {
  static const char* kFieldPHex = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F";
  BN_CTX* bn_ctx = BN_CTX_new();
  BIGNUM* p = nullptr;
  BIGNUM* y = BN_bin2bn(y32, 32, nullptr);
  BIGNUM* e = BN_new();
  BIGNUM* r = BN_new();
  bool square = false;
  if (bn_ctx && y && e && r && BN_hex2bn(&p, kFieldPHex) != 0 && BN_copy(e, p) && BN_sub_word(e, 1) &&
      BN_rshift1(e, e) && BN_mod_exp(r, y, e, p, bn_ctx) == 1) {
    square = BN_is_zero(y) || BN_is_one(r);
  }
  BN_free(r);
  BN_free(e);
  BN_free(y);
  BN_free(p);
  BN_CTX_free(bn_ctx);
  return square;
}

// secp256k1-zkp serializes a commitment as (9 ^ is_square(y)) || x, whereas a compressed pubkey encodes
// the parity of y. Recover the point with either y, then negate if its square-ness does not match.
bool commitment_to_pubkey(const Commitment33& commitment, secp256k1_pubkey* out) {
  if (!backend().ctx || !out) return false;
  if (commitment.bytes[0] != 0x08 && commitment.bytes[0] != 0x09) return false;
  PubKey33 candidate = commitment.bytes;
  candidate[0] = 0x02;
  if (!parse_pubkey(candidate, out)) return false;
  std::array<unsigned char, 65> uncompressed{};
  size_t len = uncompressed.size();
  if (secp256k1_ec_pubkey_serialize(backend().ctx, uncompressed.data(), &len, out, SECP256K1_EC_UNCOMPRESSED) != 1 ||
      len != uncompressed.size()) {
    return false;
  }
  const bool want_square = commitment.bytes[0] == 0x08;
  if (field_element_is_square(uncompressed.data() + 33) != want_square) {
    if (secp256k1_ec_pubkey_negate(backend().ctx, out) != 1) return false;
  }
  return true;
}

bool commitment_sum_add_point(CommitmentSum* sum, const secp256k1_pubkey& point) {
  if (sum->infinity) {
    const auto serialized = serialize_pubkey(point);
    if (!serialized.has_value()) return false;
    sum->infinity = false;
    sum->point = *serialized;
    return true;
  }
  secp256k1_pubkey current{};
  if (!parse_pubkey(sum->point, &current)) return false;
  const secp256k1_pubkey* ptrs[2] = {&current, &point};
  secp256k1_pubkey combined{};
  if (secp256k1_ec_pubkey_combine(backend().ctx, &combined, ptrs, 2) != 1) {
    // Both inputs are valid points, so the only failure is a sum at infinity.
    *sum = CommitmentSum{};
    return true;
  }
  const auto serialized = serialize_pubkey(combined);
  if (!serialized.has_value()) return false;
  sum->point = *serialized;
  return true;
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
    state.status.excess_authorization_available = state.ctx != nullptr;
#else
    state.status.zkp_backend_available = false;
    state.status.rangeproof_backend_available = false;
    state.status.excess_authorization_available = false;
#endif
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

bool xonly_pubkey32_is_canonical(const PubKey32& pubkey) {
#if defined(SC_HAS_SECP256K1_ZKP)
  if (!confidential_crypto_init()) return false;
  secp256k1_xonly_pubkey parsed{};
  return parse_xonly_pubkey(pubkey, &parsed);
#else
  (void)pubkey;
  return false;
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

std::optional<PubKey32> excess_xonly_pubkey_from_scalar(const Blind32& blind) {
#if defined(SC_HAS_SECP256K1_ZKP)
  if (!confidential_crypto_init()) return std::nullopt;
  if (!backend().status.excess_authorization_available) return std::nullopt;
  secp256k1_keypair keypair{};
  if (secp256k1_keypair_create(backend().ctx, &keypair, blind.bytes.data()) != 1) return std::nullopt;
  secp256k1_xonly_pubkey xonly{};
  if (secp256k1_keypair_xonly_pub(backend().ctx, &xonly, nullptr, &keypair) != 1) return std::nullopt;
  return serialize_xonly_pubkey(xonly);
#else
  (void)blind;
  return std::nullopt;
#endif
}

bool excess_pubkey_matches_commitment(const Commitment33& commitment, const PubKey32& excess_pubkey) {
  if (is_zero_commitment(commitment)) return false;
  if (!commitment_is_canonical(commitment)) return false;
  if (!xonly_pubkey32_is_canonical(excess_pubkey)) return false;
  return std::equal(commitment.bytes.begin() + 1, commitment.bytes.end(), excess_pubkey.begin());
}

std::optional<Sig64> sign_schnorr_authorization(const Hash32& msg32, const Blind32& secret_scalar,
                                                const Hash32& aux32) {
#if defined(SC_HAS_SECP256K1_ZKP)
  if (!confidential_crypto_init()) return std::nullopt;
  if (!backend().status.excess_authorization_available) return std::nullopt;
  secp256k1_keypair keypair{};
  if (secp256k1_keypair_create(backend().ctx, &keypair, secret_scalar.bytes.data()) != 1) return std::nullopt;
  Sig64 sig{};
  if (secp256k1_schnorrsig_sign32(backend().ctx, sig.data(), msg32.data(), &keypair, aux32.data()) != 1) {
    return std::nullopt;
  }
  return sig;
#else
  (void)msg32;
  (void)secret_scalar;
  (void)aux32;
  return std::nullopt;
#endif
}

bool verify_schnorr_authorization(const Hash32& msg32, const PubKey33& pubkey, const Sig64& sig) {
#if defined(SC_HAS_SECP256K1_ZKP)
  if (!confidential_crypto_init()) return false;
  if (!backend().status.excess_authorization_available) return false;
  secp256k1_xonly_pubkey xonly{};
  if (!xonly_pubkey_from_pubkey(pubkey, &xonly)) return false;
  return secp256k1_schnorrsig_verify(backend().ctx, sig.data(), msg32.data(), msg32.size(), &xonly) == 1;
#else
  (void)msg32;
  (void)pubkey;
  (void)sig;
  return false;
#endif
}

std::optional<Sig64> sign_excess_authorization(const Hash32& msg32, const Blind32& excess_blind, const Hash32& aux32) {
  return sign_schnorr_authorization(msg32, excess_blind, aux32);
}

bool verify_excess_authorization(const Hash32& msg32, const Commitment33& commitment, const PubKey32& excess_pubkey,
                                 const Sig64& sig) {
#if defined(SC_HAS_SECP256K1_ZKP)
  if (!confidential_crypto_init()) return false;
  if (!backend().status.excess_authorization_available) return false;
  if (!excess_pubkey_matches_commitment(commitment, excess_pubkey)) return false;
  secp256k1_xonly_pubkey parsed{};
  if (!parse_xonly_pubkey(excess_pubkey, &parsed)) return false;
  return secp256k1_schnorrsig_verify(backend().ctx, sig.data(), msg32.data(), msg32.size(), &parsed) == 1;
#else
  (void)msg32;
  (void)commitment;
  (void)excess_pubkey;
  (void)sig;
  return false;
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
                                                  const Blind32& blind, const Hash32& nonce32,
                                                  const RangeProofShape& shape) {
#if defined(SC_HAS_SECP256K1_ZKP)
  if (!confidential_crypto_init()) return std::nullopt;
  if (!backend().status.rangeproof_backend_available || backend().value_generator == nullptr) return std::nullopt;

  secp256k1_pedersen_commitment parsed{};
  if (!parse_pedersen_commitment(commitment, &parsed)) return std::nullopt;

  ProofBytes out;
  out.bytes.resize(secp256k1_rangeproof_max_size(backend().ctx, UINT64_MAX, 64));
  size_t proof_len = out.bytes.size();
  if (secp256k1_rangeproof_sign(backend().ctx, out.bytes.data(), &proof_len, shape.min_value, &parsed, blind.bytes.data(),
                                nonce32.data(), shape.exp, shape.min_bits, amount, nullptr, 0, nullptr, 0,
                                backend().value_generator) != 1) {
    return std::nullopt;
  }
  out.bytes.resize(proof_len);
  return out;
#else
  (void)commitment;
  (void)amount;
  (void)blind;
  (void)nonce32;
  (void)shape;
  return std::nullopt;
#endif
}

bool range_proof_has_canonical_shape(const ProofBytes& proof) {
#if defined(SC_HAS_SECP256K1_ZKP)
  if (!confidential_crypto_init() || proof.bytes.empty()) return false;
  int exp = 0;
  int mantissa = 0;
  std::uint64_t min_value = 0;
  std::uint64_t max_value = 0;
  if (secp256k1_rangeproof_info(backend().ctx, &exp, &mantissa, &min_value, &max_value, proof.bytes.data(),
                                proof.bytes.size()) != 1) {
    return false;
  }
  return exp == kCanonicalRangeProofShape.exp && mantissa == kCanonicalRangeProofShape.min_bits &&
         min_value == kCanonicalRangeProofShape.min_value;
#else
  (void)proof;
  return false;
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

bool commitment_sum_add(CommitmentSum* sum, const Commitment33& commitment) {
#if defined(SC_HAS_SECP256K1_ZKP)
  if (!sum || !confidential_crypto_init()) return false;
  if (is_zero_commitment(commitment)) return true;
  secp256k1_pubkey point{};
  if (!commitment_to_pubkey(commitment, &point)) return false;
  return commitment_sum_add_point(sum, point);
#else
  (void)sum;
  (void)commitment;
  return false;
#endif
}

bool commitment_sum_add(CommitmentSum* sum, const CommitmentSum& other) {
#if defined(SC_HAS_SECP256K1_ZKP)
  if (!sum || !confidential_crypto_init()) return false;
  if (other.infinity) return true;
  secp256k1_pubkey point{};
  if (!parse_pubkey(other.point, &point)) return false;
  return commitment_sum_add_point(sum, point);
#else
  (void)sum;
  (void)other;
  return false;
#endif
}

std::optional<CommitmentSum> commitment_sum_of_value(std::uint64_t value) {
  CommitmentSum out;
  if (value == 0) return out;
  const auto commitment = confidential_amount_commitment(value, Blind32{});
  if (!commitment.has_value() || !commitment_sum_add(&out, *commitment)) return std::nullopt;
  return out;
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

}  // namespace finalis::crypto
