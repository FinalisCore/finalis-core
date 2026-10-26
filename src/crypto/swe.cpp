// SPDX-License-Identifier: MIT

#include "crypto/swe.hpp"

#include <algorithm>
#include <map>
#include <set>
#include <string>
#include <unordered_map>

#include <blst.h>

#include "crypto/hash.hpp"

namespace finalis::crypto {
namespace {

constexpr std::uint8_t kSweVersion = 1;
constexpr std::uint32_t kBabySteps = 1u << (kSweChunkBits / 2);  // 4096
constexpr std::size_t kChunkWireBytes = kBlsPublicKeyBytes + kBlsSignatureBytes + kGtBytes;

const byte* bytes_of(std::string_view s) { return reinterpret_cast<const byte*>(s.data()); }

// --- scalars ---

// Uniform non-zero scalar from the seed: SHA-256 expanded to 64 bytes, reduced mod r.
blst_scalar derive_scalar(const Hash32& seed, std::string_view label, std::uint32_t index) {
  static constexpr std::string_view kTag = "FINALIS-SWE-V1-RNG";
  for (std::uint32_t attempt = 0;; ++attempt) {
    Bytes in(kTag.begin(), kTag.end());
    in.insert(in.end(), seed.begin(), seed.end());
    in.insert(in.end(), label.begin(), label.end());
    for (const std::uint32_t v : {index, attempt}) {
      for (int s = 24; s >= 0; s -= 8) in.push_back(static_cast<std::uint8_t>(v >> s));
    }
    Bytes wide;
    for (std::uint8_t ctr = 0; ctr < 2; ++ctr) {
      Bytes block = in;
      block.push_back(ctr);
      const auto h = sha256(block);
      wide.insert(wide.end(), h.begin(), h.end());
    }
    blst_scalar s;
    if (blst_scalar_from_be_bytes(&s, wide.data(), wide.size())) return s;  // false only for 0
  }
}

blst_fr to_fr(const blst_scalar& s) {
  blst_fr f;
  blst_fr_from_scalar(&f, &s);
  return f;
}

blst_scalar to_scalar(const blst_fr& f) {
  blst_scalar s;
  blst_scalar_from_fr(&s, &f);
  return s;
}

blst_fr fr_from_be(const BlsScalar& b) {
  blst_scalar s;
  blst_scalar_from_bendian(&s, b.data());
  return to_fr(s);
}

// --- points ---

blst_p1 g1_mul(const blst_p1& p, const blst_scalar& s) {
  blst_p1 out;
  blst_p1_mult(&out, &p, s.b, 255);
  return out;
}

blst_p1 g1_add(const blst_p1& a, const blst_p1& b) {
  blst_p1 out;
  blst_p1_add_or_double(&out, &a, &b);
  return out;
}

BlsPublicKey g1_bytes(const blst_p1& p) {
  BlsPublicKey out;
  blst_p1_compress(out.data(), &p);
  return out;
}

BlsSignature g2_bytes(const blst_p2& p) {
  BlsSignature out;
  blst_p2_compress(out.data(), &p);
  return out;
}

// In the subgroup and not the identity.
std::optional<blst_p1_affine> g1_decode(const BlsPublicKey& b) {
  blst_p1_affine p;
  if (blst_p1_uncompress(&p, b.data()) != BLST_SUCCESS) return std::nullopt;
  if (blst_p1_affine_is_inf(&p) || !blst_p1_affine_in_g1(&p)) return std::nullopt;
  return p;
}

std::optional<blst_p2_affine> g2_decode(const BlsSignature& b) {
  blst_p2_affine p;
  if (blst_p2_uncompress(&p, b.data()) != BLST_SUCCESS) return std::nullopt;
  if (blst_p2_affine_is_inf(&p) || !blst_p2_affine_in_g2(&p)) return std::nullopt;
  return p;
}

blst_p1 g1_point(const blst_p1_affine& a) {
  blst_p1 p;
  blst_p1_from_affine(&p, &a);
  return p;
}

blst_p1_affine g1_affine(const blst_p1& p) {
  blst_p1_affine a;
  blst_p1_to_affine(&a, &p);
  return a;
}

blst_p2_affine g2_affine(const blst_p2& p) {
  blst_p2_affine a;
  blst_p2_to_affine(&a, &p);
  return a;
}

blst_p1 h_point(const BlsPublicKey& c) {
  blst_p1 h;
  blst_hash_to_g1(&h, c.data(), c.size(), bytes_of(kSweHDst), kSweHDst.size(), nullptr, 0);
  return h;
}

// --- GT ---

GtBytes gt_bytes(const blst_fp12& f) {
  GtBytes out;
  std::size_t o = 0;
  for (const auto& f6 : f.fp6) {
    for (const auto& f2 : f6.fp2) {
      for (const auto& fp : f2.fp) {
        blst_bendian_from_fp(out.data() + o, &fp);
        o += 48;
      }
    }
  }
  return out;
}

// Canonical (every coefficient < p) and in the order-r subgroup.
std::optional<blst_fp12> gt_decode(const GtBytes& b) {
  blst_fp12 f;
  std::size_t o = 0;
  for (auto& f6 : f.fp6) {
    for (auto& f2 : f6.fp2) {
      for (auto& fp : f2.fp) {
        blst_fp_from_bendian(&fp, b.data() + o);
        o += 48;
      }
    }
  }
  if (gt_bytes(f) != b || !blst_fp12_in_group(&f)) return std::nullopt;
  return f;
}

blst_fp12 gt_mul(const blst_fp12& a, const blst_fp12& b) {
  blst_fp12 out;
  blst_fp12_mul(&out, &a, &b);
  return out;
}

const blst_fp12& gt_generator() {
  static const blst_fp12 g = [] {
    blst_fp12 ml;
    blst_miller_loop(&ml, blst_p2_affine_generator(), blst_p1_affine_generator());
    blst_fp12 out;
    blst_final_exp(&out, &ml);
    return out;
  }();
  return g;
}

blst_fp12 gt_pow(const blst_fp12& base, std::uint32_t m) {
  blst_fp12 acc = *blst_fp12_one();
  for (int bit = 31; bit >= 0; --bit) {
    blst_fp12_sqr(&acc, &acc);
    if ((m >> bit) & 1u) acc = gt_mul(acc, base);
  }
  return acc;
}

// e(P1, Q1) * e(P2, Q2), one final exponentiation.
blst_fp12 pairing2(const blst_p1_affine& p1, const blst_p2_affine& q1, const blst_p1_affine& p2,
                   const blst_p2_affine& q2) {
  const blst_p2_affine* qs[2] = {&q1, &q2};
  const blst_p1_affine* ps[2] = {&p1, &p2};
  blst_fp12 ml;
  blst_miller_loop_n(&ml, qs, ps, 2);
  blst_fp12 out;
  blst_final_exp(&out, &ml);
  return out;
}

struct BabySteps {
  std::unordered_map<std::string, std::uint32_t> index;  // canonical bytes of g_T^j -> j
  blst_fp12 giant;                                       // g_T^{-kBabySteps}
};

const BabySteps& baby_steps() {
  static const BabySteps table = [] {
    BabySteps t;
    t.index.reserve(kBabySteps);
    blst_fp12 cur = *blst_fp12_one();
    for (std::uint32_t j = 0; j < kBabySteps; ++j) {
      const auto b = gt_bytes(cur);
      t.index.emplace(std::string(b.begin(), b.end()), j);
      cur = gt_mul(cur, gt_generator());
    }
    blst_fp12_inverse(&t.giant, &cur);  // cur = g_T^kBabySteps
    return t;
  }();
  return table;
}

std::optional<std::vector<blst_fr>> evaluation_points(const std::vector<BlsPublicKey>& keys) {
  std::vector<blst_fr> out;
  std::set<BlsScalar> seen;
  for (const auto& k : keys) {
    const auto xi = mcfly_evaluation_point(k);
    if (!xi || !seen.insert(*xi).second) return std::nullopt;
    out.push_back(fr_from_be(*xi));
  }
  return out;
}

void put_u16(Bytes& out, std::size_t v) {
  out.push_back(static_cast<std::uint8_t>(v >> 8));
  out.push_back(static_cast<std::uint8_t>(v));
}

}  // namespace

// --- ciphertext encoding ---

Bytes SweCiphertext::serialize() const {
  Bytes out;
  out.reserve(7 + 2 * kBlsPublicKeyBytes + key_shares.size() * kBlsPublicKeyBytes + chunks.size() * kChunkWireBytes);
  out.push_back(kSweVersion);
  put_u16(out, threshold);
  put_u16(out, key_shares.size());
  put_u16(out, chunks.size());
  out.insert(out.end(), c.begin(), c.end());
  out.insert(out.end(), c0.begin(), c0.end());
  for (const auto& k : key_shares) out.insert(out.end(), k.begin(), k.end());
  for (const auto& ch : chunks) {
    out.insert(out.end(), ch.a.begin(), ch.a.end());
    out.insert(out.end(), ch.t.begin(), ch.t.end());
    out.insert(out.end(), ch.c_prime.begin(), ch.c_prime.end());
  }
  return out;
}

std::optional<SweCiphertext> SweCiphertext::parse(const Bytes& b, std::size_t max_keys, std::size_t max_chunks) {
  if (b.size() < 7 || b[0] != kSweVersion) return std::nullopt;
  const std::size_t threshold = (std::size_t{b[1]} << 8) | b[2];
  const std::size_t n = (std::size_t{b[3]} << 8) | b[4];
  const std::size_t l = (std::size_t{b[5]} << 8) | b[6];
  if (n == 0 || n > max_keys || l == 0 || l > max_chunks || threshold == 0 || threshold > n) return std::nullopt;
  if (b.size() != 7 + (2 + n) * kBlsPublicKeyBytes + l * kChunkWireBytes) return std::nullopt;
  SweCiphertext ct;
  ct.threshold = static_cast<std::uint32_t>(threshold);
  std::size_t o = 7;
  auto take_g1 = [&](BlsPublicKey* out) {
    std::copy_n(b.begin() + static_cast<std::ptrdiff_t>(o), kBlsPublicKeyBytes, out->begin());
    o += kBlsPublicKeyBytes;
    return g1_decode(*out).has_value();
  };
  if (!take_g1(&ct.c) || !take_g1(&ct.c0)) return std::nullopt;
  ct.key_shares.resize(n);
  for (auto& k : ct.key_shares) {
    if (!take_g1(&k)) return std::nullopt;
  }
  ct.chunks.resize(l);
  for (auto& ch : ct.chunks) {
    if (!take_g1(&ch.a)) return std::nullopt;
    std::copy_n(b.begin() + static_cast<std::ptrdiff_t>(o), kBlsSignatureBytes, ch.t.begin());
    o += kBlsSignatureBytes;
    if (!g2_decode(ch.t)) return std::nullopt;
    std::copy_n(b.begin() + static_cast<std::ptrdiff_t>(o), kGtBytes, ch.c_prime.begin());
    o += kGtBytes;
    if (!gt_decode(ch.c_prime)) return std::nullopt;
  }
  return ct;
}

// --- encryption / decryption ---

std::optional<SweCiphertext> swe_encrypt(const std::vector<BlsPublicKey>& committee, std::uint32_t threshold,
                                         const Bytes& msg, std::string_view dst,
                                         const std::vector<std::uint32_t>& chunks, const Hash32& seed) {
  if (committee.empty() || committee.size() > kSweMaxKeys) return std::nullopt;
  if (threshold == 0 || threshold > committee.size()) return std::nullopt;
  if (chunks.empty() || chunks.size() > kSweMaxChunks) return std::nullopt;
  for (const auto m : chunks) {
    if (m >= kSweChunkLimit) return std::nullopt;
  }
  std::vector<blst_p1> keys;
  for (const auto& k : committee) {
    const auto p = g1_decode(k);
    if (!p) return std::nullopt;
    keys.push_back(g1_point(*p));
  }
  const auto xs = evaluation_points(committee);
  if (!xs) return std::nullopt;

  const blst_scalar r = derive_scalar(seed, "r", 0);
  std::vector<blst_fr> poly;  // f(x) = poly[0] + poly[1] x + ...; poly[0] = r0
  for (std::uint32_t k = 0; k < threshold; ++k) poly.push_back(to_fr(derive_scalar(seed, "poly", k)));
  const blst_scalar r0 = to_scalar(poly[0]);

  SweCiphertext ct;
  ct.threshold = threshold;
  const blst_p1& g1 = *blst_p1_generator();
  const blst_p1 c = g1_mul(g1, r);
  ct.c = g1_bytes(c);
  const blst_p1 g1_r0 = g1_mul(g1, r0);
  ct.c0 = g1_bytes(g1_add(g1_mul(h_point(ct.c), r), g1_r0));
  ct.key_shares.reserve(keys.size());
  for (std::size_t j = 0; j < keys.size(); ++j) {
    blst_fr s = poly.back();  // Horner: s_j = f(xi_j)
    for (std::size_t k = poly.size() - 1; k-- > 0;) {
      blst_fr_mul(&s, &s, &(*xs)[j]);
      blst_fr_add(&s, &s, &poly[k]);
    }
    ct.key_shares.push_back(g1_bytes(g1_add(g1_mul(keys[j], r), g1_mul(g1, to_scalar(s)))));
  }

  blst_p2 ht;
  blst_hash_to_g2(&ht, msg.data(), msg.size(), bytes_of(dst), dst.size(), nullptr, 0);
  const blst_p1_affine g1_r0_aff = g1_affine(g1_r0);
  ct.chunks.reserve(chunks.size());
  for (std::size_t i = 0; i < chunks.size(); ++i) {
    const blst_scalar alpha = derive_scalar(seed, "alpha", static_cast<std::uint32_t>(i));
    SweChunk ch;
    ch.a = g1_bytes(g1_mul(c, alpha));
    blst_p2 t;
    blst_p2_mult(&t, &ht, alpha.b, 255);
    ch.t = g2_bytes(t);
    blst_fp12 ml;
    const blst_p2_affine t_aff = g2_affine(t);
    blst_miller_loop(&ml, &t_aff, &g1_r0_aff);
    blst_fp12 e;
    blst_final_exp(&e, &ml);
    ch.c_prime = gt_bytes(gt_mul(e, gt_pow(gt_generator(), chunks[i])));
    ct.chunks.push_back(ch);
  }
  return ct;
}

std::optional<std::vector<std::uint32_t>> swe_decrypt(const SweCiphertext& ct, const std::vector<BlsPublicKey>& committee,
                                                      const std::vector<BlsPublicKey>& signers,
                                                      const BlsSignature& aggregate, const Bytes& msg,
                                                      std::string_view dst) {
  if (ct.key_shares.size() != committee.size() || ct.threshold == 0 || ct.threshold > committee.size()) {
    return std::nullopt;
  }
  if (signers.size() < ct.threshold) return std::nullopt;
  std::map<BlsPublicKey, std::size_t> position;
  for (std::size_t j = 0; j < committee.size(); ++j) {
    if (!position.emplace(committee[j], j).second) return std::nullopt;
  }
  std::vector<std::size_t> idx;
  std::set<std::size_t> used;
  for (const auto& s : signers) {
    const auto it = position.find(s);
    if (it == position.end() || !used.insert(it->second).second) return std::nullopt;
    idx.push_back(it->second);
  }
  if (!mcfly_aggregate_verify(signers, msg, dst, aggregate)) return std::nullopt;

  std::vector<BlsScalar> points;
  for (const auto& s : signers) points.push_back(*mcfly_evaluation_point(s));  // verified above
  const auto coeffs = lagrange_coefficients_at_zero(points);
  if (!coeffs) return std::nullopt;
  blst_p1 cstar{};
  for (std::size_t k = 0; k < idx.size(); ++k) {
    const auto cj = g1_decode(ct.key_shares[idx[k]]);
    if (!cj) return std::nullopt;
    blst_scalar l;
    blst_scalar_from_bendian(&l, (*coeffs)[k].data());
    const blst_p1 term = g1_mul(g1_point(*cj), l);
    cstar = k == 0 ? term : g1_add(cstar, term);
  }
  if (blst_p1_is_inf(&cstar)) return std::nullopt;
  blst_p1_cneg(&cstar, true);
  const blst_p1_affine neg_cstar = g1_affine(cstar);
  const auto sigma = g2_decode(aggregate);
  if (!sigma) return std::nullopt;

  std::vector<std::uint32_t> out;
  out.reserve(ct.chunks.size());
  for (const auto& ch : ct.chunks) {
    const auto a = g1_decode(ch.a);
    const auto t = g2_decode(ch.t);
    const auto cp = gt_decode(ch.c_prime);
    if (!a || !t || !cp) return std::nullopt;
    // z = c' * e(a, sigma) * e(-c*, t)
    const blst_fp12 z = gt_mul(*cp, pairing2(*a, *sigma, neg_cstar, *t));
    const auto m = swe_gt_dlog(gt_bytes(z));
    if (!m) return std::nullopt;
    out.push_back(*m);
  }
  return out;
}

// --- chunks and discrete logarithms ---

std::vector<std::uint32_t> swe_key_to_chunks(const Hash32& key) {
  std::vector<std::uint32_t> out(kSweKeyChunks, 0);
  for (std::size_t bit = 0; bit < 256; ++bit) {
    const std::uint32_t v = (key[bit / 8] >> (7 - bit % 8)) & 1u;
    const std::size_t chunk = bit / kSweChunkBits;
    out[chunk] = (out[chunk] << 1) | v;
  }
  return out;
}

std::optional<Hash32> swe_key_from_chunks(const std::vector<std::uint32_t>& chunks) {
  if (chunks.size() != kSweKeyChunks) return std::nullopt;
  const unsigned last_bits = 256 - kSweChunkBits * (kSweKeyChunks - 1);
  for (std::size_t i = 0; i < chunks.size(); ++i) {
    const unsigned width = i + 1 == chunks.size() ? last_bits : kSweChunkBits;
    if (chunks[i] >> width) return std::nullopt;
  }
  Hash32 key{};
  for (std::size_t bit = 0; bit < 256; ++bit) {
    const std::size_t chunk = bit / kSweChunkBits;
    const unsigned width = chunk + 1 == chunks.size() ? last_bits : kSweChunkBits;
    const unsigned pos = static_cast<unsigned>(bit % kSweChunkBits);
    const std::uint32_t v = (chunks[chunk] >> (width - 1 - pos)) & 1u;
    key[bit / 8] = static_cast<std::uint8_t>(key[bit / 8] | (v << (7 - bit % 8)));
  }
  return key;
}

std::optional<std::uint32_t> swe_gt_dlog(const GtBytes& z) {
  const auto start = gt_decode(z);
  if (!start) return std::nullopt;
  const auto& table = baby_steps();
  blst_fp12 cur = *start;
  for (std::uint32_t i = 0; i < kSweChunkLimit / kBabySteps; ++i) {
    const auto b = gt_bytes(cur);
    if (const auto it = table.index.find(std::string(b.begin(), b.end())); it != table.index.end()) {
      return i * kBabySteps + it->second;
    }
    cur = gt_mul(cur, table.giant);
  }
  return std::nullopt;
}

GtBytes swe_gt_pow(std::uint32_t m) { return gt_bytes(gt_pow(gt_generator(), m)); }

}  // namespace finalis::crypto
