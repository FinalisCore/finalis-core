// SPDX-License-Identifier: MIT

#include "crypto/swe_proofs.hpp"

#include <algorithm>

#include "crypto/hash.hpp"
#include "crypto/swe_internal.hpp"

namespace finalis::crypto {
namespace {

using namespace swe_internal;

constexpr std::uint8_t kProofVersion = 1;

void append(Bytes& out, const std::uint8_t* p, std::size_t n) { out.insert(out.end(), p, p + n); }

Hash32 hash_with(const Hash32& base, std::initializer_list<const BlsPublicKey*> points) {
  Bytes in(base.begin(), base.end());
  for (const auto* p : points) append(in, p->data(), p->size());
  return sha256(in);
}

// Everything both sides derive from the public statement.
struct Statement {
  Hash32 transcript{};  // binds committee, message, DST and the whole ciphertext
  blst_p1 c{};
  blst_p1 c_star{};
  blst_p1 g_star{};
  BlsPublicKey c_bytes{};
  BlsPublicKey c_star_bytes{};
  BlsPublicKey g_star_bytes{};
};

std::optional<Statement> derive_statement(const SweCiphertext& ct, const std::vector<BlsPublicKey>& committee,
                                          const Bytes& msg, std::string_view dst) {
  const std::size_t n = committee.size();
  if (n == 0 || n > kSweMaxKeys || ct.key_shares.size() != n) return std::nullopt;
  if (ct.threshold == 0 || ct.threshold > n || ct.chunks.empty()) return std::nullopt;

  Statement st;
  {
    static constexpr std::string_view kTag = "FINALIS-SWE-V1-WELLFORMED";
    Bytes in(kTag.begin(), kTag.end());
    for (const auto& k : committee) append(in, k.data(), k.size());
    const std::uint64_t mlen = msg.size();
    for (int s = 56; s >= 0; s -= 8) in.push_back(static_cast<std::uint8_t>(mlen >> s));
    in.insert(in.end(), msg.begin(), msg.end());
    in.insert(in.end(), dst.begin(), dst.end());
    const Bytes wire = ct.serialize();
    in.insert(in.end(), wire.begin(), wire.end());
    st.transcript = sha256(in);
  }

  // Points of the code: X_0 = 0 (the secret r0), X_j = xi_j.
  const auto xs = evaluation_points(committee);
  if (!xs) return std::nullopt;
  std::vector<blst_fr> X(n + 1);
  X[0] = blst_fr{};
  std::copy(xs->begin(), xs->end(), X.begin() + 1);

  // Generator columns: C_0 = c0, C_j = c_j;  G_0 = h, G_j = vk_j.
  const auto c = g1_decode(ct.c);
  const auto c0 = g1_decode(ct.c0);
  if (!c || !c0) return std::nullopt;
  std::vector<blst_p1> C(n + 1), G(n + 1);
  C[0] = g1_point(*c0);
  G[0] = h_point(ct.c);
  for (std::size_t j = 0; j < n; ++j) {
    const auto cj = g1_decode(ct.key_shares[j]);
    const auto vk = g1_decode(committee[j]);
    if (!cj || !vk) return std::nullopt;
    C[j + 1] = g1_point(*cj);
    G[j + 1] = g1_point(*vk);
  }

  // w = v^T H for the parity-check matrix H_{i,j} = u_j X_j^i (rows i < n + 1 - t) of RS[n+1, t]:
  // w_j = u_j * P_v(X_j), P_v(x) = sum_i v_i x^i, u_j = 1 / prod_{l != j} (X_j - X_l).
  const std::size_t rows = n + 1 - ct.threshold;
  std::vector<blst_fr> v(rows);
  for (std::size_t i = 0; i < rows; ++i) v[i] = to_fr(derive_scalar(st.transcript, "v", static_cast<std::uint32_t>(i)));
  blst_p1 c_star{}, g_star{};
  bool first = true;
  for (std::size_t j = 0; j <= n; ++j) {
    blst_fr denom{};
    bool have = false;
    for (std::size_t l = 0; l <= n; ++l) {
      if (l == j) continue;
      blst_fr d;
      blst_fr_sub(&d, &X[j], &X[l]);
      if (!have) {
        denom = d;
        have = true;
      } else {
        blst_fr_mul(&denom, &denom, &d);
      }
    }
    blst_fr u;
    blst_fr_inverse(&u, &denom);  // points are distinct, so denom != 0
    blst_fr p = v[rows - 1];
    for (std::size_t i = rows - 1; i-- > 0;) {
      blst_fr_mul(&p, &p, &X[j]);
      blst_fr_add(&p, &p, &v[i]);
    }
    blst_fr wj;
    blst_fr_mul(&wj, &u, &p);
    const blst_scalar ws = to_scalar(wj);
    const blst_p1 ct_term = g1_mul(C[j], ws);
    const blst_p1 g_term = g1_mul(G[j], ws);
    if (first) {
      c_star = ct_term;
      g_star = g_term;
      first = false;
    } else {
      c_star = g1_add(c_star, ct_term);
      g_star = g1_add(g_star, g_term);
    }
  }
  if (blst_p1_is_inf(&g_star)) return std::nullopt;
  st.c = g1_point(*c);
  st.c_star = c_star;
  st.g_star = g_star;
  st.c_bytes = ct.c;
  st.c_star_bytes = g1_bytes(c_star);
  st.g_star_bytes = g1_bytes(g_star);
  return st;
}

// Batched e(a_i, H(T)) == e(c, t_i): with Fiat-Shamir weights rho_i,
// e(sum rho_i a_i, H(T)) * e(-c, sum rho_i t_i) == 1.
bool chunk_bases_consistent(const SweCiphertext& ct, const Statement& st, const Bytes& msg, std::string_view dst) {
  blst_p1 a_sum{};
  blst_p2 t_sum{};
  for (std::size_t i = 0; i < ct.chunks.size(); ++i) {
    const auto a = g1_decode(ct.chunks[i].a);
    const auto t = g2_decode(ct.chunks[i].t);
    if (!a || !t) return false;
    const blst_scalar rho = derive_scalar(st.transcript, "rho", static_cast<std::uint32_t>(i));
    const blst_p1 a_term = g1_mul(g1_point(*a), rho);
    blst_p2 t_pt, t_term;
    blst_p2_from_affine(&t_pt, &*t);
    blst_p2_mult(&t_term, &t_pt, rho.b, 255);
    if (i == 0) {
      a_sum = a_term;
      t_sum = t_term;
    } else {
      a_sum = g1_add(a_sum, a_term);
      blst_p2_add_or_double(&t_sum, &t_sum, &t_term);
    }
  }
  if (blst_p1_is_inf(&a_sum) || blst_p2_is_inf(&t_sum)) return false;
  blst_p2 ht;
  blst_hash_to_g2(&ht, msg.data(), msg.size(), bytes_of(dst), dst.size(), nullptr, 0);
  blst_p1 neg_c = st.c;
  blst_p1_cneg(&neg_c, true);
  const blst_fp12 prod = pairing2(g1_affine(a_sum), g2_affine(ht), g1_affine(neg_c), g2_affine(t_sum));
  return blst_fp12_is_one(&prod);
}

blst_scalar challenge(const Statement& st, const BlsPublicKey& f, const BlsPublicKey& f_star) {
  const Hash32 h = hash_with(st.transcript, {&st.c_bytes, &st.g_star_bytes, &st.c_star_bytes, &f, &f_star});
  return derive_scalar(h, "alpha", 0);
}

}  // namespace

Bytes SweWellFormednessProof::serialize() const {
  Bytes out;
  out.reserve(kSweWellFormednessProofBytes);
  out.push_back(kProofVersion);
  out.insert(out.end(), f.begin(), f.end());
  out.insert(out.end(), f_star.begin(), f_star.end());
  out.insert(out.end(), z.begin(), z.end());
  return out;
}

std::optional<SweWellFormednessProof> SweWellFormednessProof::parse(const Bytes& b) {
  if (b.size() != kSweWellFormednessProofBytes || b[0] != kProofVersion) return std::nullopt;
  SweWellFormednessProof p;
  auto it = b.begin() + 1;
  std::copy_n(it, kBlsPublicKeyBytes, p.f.begin());
  it += kBlsPublicKeyBytes;
  std::copy_n(it, kBlsPublicKeyBytes, p.f_star.begin());
  it += kBlsPublicKeyBytes;
  std::copy_n(it, kBlsScalarBytes, p.z.begin());
  if (!g1_decode(p.f) || !g1_decode(p.f_star)) return std::nullopt;
  blst_scalar z;
  blst_scalar_from_bendian(&z, p.z.data());
  if (!blst_scalar_fr_check(&z)) return std::nullopt;  // z < r
  return p;
}

std::optional<SweWellFormednessProof> swe_prove_well_formed(const SweCiphertext& ct,
                                                            const std::vector<BlsPublicKey>& committee,
                                                            const Bytes& msg, std::string_view dst,
                                                            const Hash32& seed) {
  const auto st = derive_statement(ct, committee, msg, dst);
  if (!st) return std::nullopt;
  const blst_scalar r = derive_scalar(seed, "r", 0);  // the witness, as swe_encrypt derived it
  if (g1_bytes(g1_mul(*blst_p1_generator(), r)) != ct.c) return std::nullopt;
  // Nonce bound to seed and statement: one seed proving two statements never reuses y.
  Bytes nonce_in;
  static constexpr std::string_view kTag = "FINALIS-SWE-V1-WELLFORMED-NONCE";
  nonce_in.insert(nonce_in.end(), kTag.begin(), kTag.end());
  nonce_in.insert(nonce_in.end(), seed.begin(), seed.end());
  nonce_in.insert(nonce_in.end(), st->transcript.begin(), st->transcript.end());
  const blst_scalar y = derive_scalar(sha256(nonce_in), "y", 0);

  SweWellFormednessProof proof;
  proof.f = g1_bytes(g1_mul(*blst_p1_generator(), y));
  proof.f_star = g1_bytes(g1_mul(st->g_star, y));
  const blst_fr alpha = to_fr(challenge(*st, proof.f, proof.f_star));
  const blst_fr rf = to_fr(r);
  blst_fr z;
  blst_fr_mul(&z, &alpha, &rf);
  const blst_fr yf = to_fr(y);
  blst_fr_add(&z, &z, &yf);
  const blst_scalar zs = to_scalar(z);
  blst_bendian_from_scalar(proof.z.data(), &zs);
  return proof;
}

bool swe_verify_well_formed(const SweCiphertext& ct, const std::vector<BlsPublicKey>& committee, const Bytes& msg,
                            std::string_view dst, const SweWellFormednessProof& proof) {
  const auto st = derive_statement(ct, committee, msg, dst);
  if (!st || !chunk_bases_consistent(ct, *st, msg, dst)) return false;
  const auto f = g1_decode(proof.f);
  const auto f_star = g1_decode(proof.f_star);
  blst_scalar z;
  blst_scalar_from_bendian(&z, proof.z.data());
  if (!f || !f_star || !blst_scalar_fr_check(&z)) return false;
  const blst_scalar alpha = challenge(*st, proof.f, proof.f_star);
  // c^alpha * f == g1^z  and  (c*)^alpha * f* == (g*)^z
  const auto lhs1 = g1_bytes(g1_add(g1_mul(st->c, alpha), g1_point(*f)));
  const auto rhs1 = g1_bytes(g1_mul(*blst_p1_generator(), z));
  const auto lhs2 = g1_bytes(g1_add(g1_mul(st->c_star, alpha), g1_point(*f_star)));
  const auto rhs2 = g1_bytes(g1_mul(st->g_star, z));
  return lhs1 == rhs1 && lhs2 == rhs2;
}

}  // namespace finalis::crypto
