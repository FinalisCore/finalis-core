// SPDX-License-Identifier: MIT

#include "crypto/bls12_381.hpp"

#include <algorithm>
#include <set>

#include <blst.h>

#include "crypto/hash.hpp"

namespace finalis::crypto {
namespace {

const byte* dst_ptr(std::string_view dst) { return reinterpret_cast<const byte*>(dst.data()); }

std::optional<blst_scalar> secret_scalar(const BlsSecretKey& sk) {
  blst_scalar s;
  blst_scalar_from_bendian(&s, sk.bytes.data());
  if (!blst_sk_check(&s)) return std::nullopt;  // 0 < s < r
  return s;
}

// Decodes a key: on the curve, in G1, not the identity.
std::optional<blst_p1_affine> decode_public_key(const BlsPublicKey& pk) {
  blst_p1_affine p;
  if (blst_p1_uncompress(&p, pk.data()) != BLST_SUCCESS) return std::nullopt;
  if (blst_p1_affine_is_inf(&p) || !blst_p1_affine_in_g1(&p)) return std::nullopt;
  return p;
}

std::optional<blst_p2_affine> decode_signature(const BlsSignature& sig) {
  blst_p2_affine p;
  if (blst_p2_uncompress(&p, sig.data()) != BLST_SUCCESS) return std::nullopt;
  if (blst_p2_affine_is_inf(&p) || !blst_p2_affine_in_g2(&p)) return std::nullopt;
  return p;
}

blst_fr fr_from_bytes(const BlsScalar& b) {
  blst_scalar s;
  blst_scalar_from_bendian(&s, b.data());
  blst_fr f;
  blst_fr_from_scalar(&f, &s);
  return f;
}

BlsScalar bytes_from_fr(const blst_fr& f) {
  blst_scalar s;
  blst_scalar_from_fr(&s, &f);
  BlsScalar out;
  blst_bendian_from_scalar(out.data(), &s);
  return out;
}

// Little-endian scalar bytes, as blst_p*_mult takes them.
blst_scalar scalar_from_fr(const blst_fr& f) {
  blst_scalar s;
  blst_scalar_from_fr(&s, &f);
  return s;
}

// Lagrange coefficients of the signers' evaluation points (nullopt on a bad key or a repeat).
std::optional<std::vector<blst_scalar>> signer_coefficients(const std::vector<BlsPublicKey>& signers) {
  std::vector<BlsScalar> points;
  points.reserve(signers.size());
  for (const auto& pk : signers) {
    auto xi = mcfly_evaluation_point(pk);
    if (!xi) return std::nullopt;
    points.push_back(*xi);
  }
  auto coeffs = lagrange_coefficients_at_zero(points);
  if (!coeffs) return std::nullopt;
  std::vector<blst_scalar> out;
  out.reserve(coeffs->size());
  for (const auto& c : *coeffs) out.push_back(scalar_from_fr(fr_from_bytes(c)));
  return out;
}

}  // namespace

std::optional<BlsSecretKey> bls_keygen(const Bytes& ikm) {
  if (ikm.size() < 32) return std::nullopt;
  blst_scalar s;
  blst_keygen(&s, ikm.data(), ikm.size(), nullptr, 0);
  BlsSecretKey sk;
  blst_bendian_from_scalar(sk.bytes.data(), &s);
  secure_wipe(&s, sizeof s);
  if (!secret_scalar(sk)) return std::nullopt;
  return sk;
}

std::optional<BlsSecretKey> bls_key_from_validator_seed(const Bytes& ed25519_seed_32) {
  if (ed25519_seed_32.size() != 32) return std::nullopt;
  static constexpr std::string_view kTag = "FINALIS-VALIDATOR-BLS-V1";
  Bytes ikm;
  ScopedWipe wipe(ikm);
  for (std::uint8_t ctr = 0; ctr < 2; ++ctr) {
    Bytes in(kTag.begin(), kTag.end());
    in.push_back(ctr);
    in.insert(in.end(), ed25519_seed_32.begin(), ed25519_seed_32.end());
    auto h = sha256(in);
    secure_wipe(in);
    ikm.insert(ikm.end(), h.begin(), h.end());
    secure_wipe(h);
  }
  return bls_keygen(ikm);
}

std::optional<BlsPublicKey> bls_public_key(const BlsSecretKey& sk) {
  auto s = secret_scalar(sk);
  if (!s) return std::nullopt;
  blst_p1 p;
  blst_sk_to_pk_in_g1(&p, &*s);
  secure_wipe(&*s, sizeof *s);
  BlsPublicKey out;
  blst_p1_compress(out.data(), &p);
  return out;
}

std::optional<BlsSignature> bls_sign(const BlsSecretKey& sk, const Bytes& msg, std::string_view dst) {
  auto s = secret_scalar(sk);
  if (!s) return std::nullopt;
  blst_p2 h;
  blst_hash_to_g2(&h, msg.data(), msg.size(), dst_ptr(dst), dst.size(), nullptr, 0);
  blst_p2 sig;
  blst_sign_pk_in_g1(&sig, &h, &*s);
  secure_wipe(&*s, sizeof *s);
  BlsSignature out;
  blst_p2_compress(out.data(), &sig);
  return out;
}

bool bls_verify(const BlsPublicKey& pk, const Bytes& msg, std::string_view dst, const BlsSignature& sig) {
  const auto p = decode_public_key(pk);
  const auto s = decode_signature(sig);
  if (!p || !s) return false;
  return blst_core_verify_pk_in_g1(&*p, &*s, true, msg.data(), msg.size(), dst_ptr(dst), dst.size(), nullptr, 0) ==
         BLST_SUCCESS;
}

std::optional<BlsSignature> bls_pop_prove(const BlsSecretKey& sk) {
  const auto pk = bls_public_key(sk);
  if (!pk) return std::nullopt;
  return bls_sign(sk, Bytes(pk->begin(), pk->end()), kBlsPopDst);
}

bool bls_pop_verify(const BlsPublicKey& pk, const BlsSignature& pop) {
  return bls_verify(pk, Bytes(pk.begin(), pk.end()), kBlsPopDst, pop);
}

std::optional<BlsScalar> mcfly_evaluation_point(const BlsPublicKey& pk) {
  if (!decode_public_key(pk)) return std::nullopt;
  // 64 bytes reduced mod r (bias ~2^-256), as hash_to_field does.
  static constexpr std::string_view kTag = "FINALIS-TIME-V1-MCFLY-XI";
  Bytes wide;
  for (std::uint8_t ctr = 0; ctr < 2; ++ctr) {
    Bytes in(kTag.begin(), kTag.end());
    in.push_back(ctr);
    in.insert(in.end(), pk.begin(), pk.end());
    const auto h = sha256(in);
    wide.insert(wide.end(), h.begin(), h.end());
  }
  blst_scalar s;
  if (!blst_scalar_from_be_bytes(&s, wide.data(), wide.size())) return std::nullopt;  // false: s == 0
  BlsScalar out;
  blst_bendian_from_scalar(out.data(), &s);
  return out;
}

std::optional<std::vector<BlsScalar>> lagrange_coefficients_at_zero(const std::vector<BlsScalar>& points) {
  if (points.empty()) return std::nullopt;
  const BlsScalar zero{};
  std::set<BlsScalar> seen;
  for (const auto& p : points) {
    if (p == zero || !seen.insert(p).second) return std::nullopt;
  }
  std::vector<blst_fr> xs;
  xs.reserve(points.size());
  for (const auto& p : points) xs.push_back(fr_from_bytes(p));
  std::vector<BlsScalar> out;
  out.reserve(xs.size());
  for (std::size_t j = 0; j < xs.size(); ++j) {
    // L_j = prod_{i != j} x_i / (x_i - x_j)
    blst_fr num{};
    blst_fr den{};
    bool first = true;
    for (std::size_t i = 0; i < xs.size(); ++i) {
      if (i == j) continue;
      blst_fr diff;
      blst_fr_sub(&diff, &xs[i], &xs[j]);
      if (first) {
        num = xs[i];
        den = diff;
        first = false;
      } else {
        blst_fr_mul(&num, &num, &xs[i]);
        blst_fr_mul(&den, &den, &diff);
      }
    }
    if (first) {  // a single point: L = 1
      BlsScalar one{};
      one.back() = 1;
      out.push_back(one);
      continue;
    }
    blst_fr inv;
    blst_fr_inverse(&inv, &den);  // den != 0: points are distinct
    blst_fr l;
    blst_fr_mul(&l, &num, &inv);
    out.push_back(bytes_from_fr(l));
  }
  return out;
}

std::optional<BlsSignature> mcfly_aggregate(const std::vector<BlsPublicKey>& signers,
                                            const std::vector<BlsSignature>& sigs) {
  if (signers.empty() || signers.size() != sigs.size()) return std::nullopt;
  const auto coeffs = signer_coefficients(signers);
  if (!coeffs) return std::nullopt;
  blst_p2 acc{};
  for (std::size_t j = 0; j < sigs.size(); ++j) {
    const auto s = decode_signature(sigs[j]);
    if (!s) return std::nullopt;
    blst_p2 pt;
    blst_p2_from_affine(&pt, &*s);
    blst_p2 term;
    blst_p2_mult(&term, &pt, (*coeffs)[j].b, 255);
    if (j == 0) {
      acc = term;
    } else {
      blst_p2_add_or_double(&acc, &acc, &term);
    }
  }
  BlsSignature out;
  blst_p2_compress(out.data(), &acc);
  return out;
}

std::optional<BlsPublicKey> mcfly_aggregate_public_key(const std::vector<BlsPublicKey>& signers) {
  if (signers.empty()) return std::nullopt;
  const auto coeffs = signer_coefficients(signers);
  if (!coeffs) return std::nullopt;
  blst_p1 acc{};
  for (std::size_t j = 0; j < signers.size(); ++j) {
    const auto p = decode_public_key(signers[j]);
    if (!p) return std::nullopt;
    blst_p1 pt;
    blst_p1_from_affine(&pt, &*p);
    blst_p1 term;
    blst_p1_mult(&term, &pt, (*coeffs)[j].b, 255);
    if (j == 0) {
      acc = term;
    } else {
      blst_p1_add_or_double(&acc, &acc, &term);
    }
  }
  BlsPublicKey out;
  blst_p1_compress(out.data(), &acc);
  return out;
}

bool mcfly_aggregate_verify(const std::vector<BlsPublicKey>& signers, const Bytes& msg, std::string_view dst,
                            const BlsSignature& aggregate) {
  // e(sigma, g1) = prod_j e(H(T), vk_j)^{L_j} = e(H(T), prod_j vk_j^{L_j}): one pairing check.
  const auto apk = mcfly_aggregate_public_key(signers);
  if (!apk) return false;
  const auto p = decode_public_key(*apk);  // the identity here (a cancelling set) is rejected too
  const auto s = decode_signature(aggregate);
  if (!p || !s) return false;
  return blst_core_verify_pk_in_g1(&*p, &*s, true, msg.data(), msg.size(), dst_ptr(dst), dst.size(), nullptr, 0) ==
         BLST_SUCCESS;
}

}  // namespace finalis::crypto
