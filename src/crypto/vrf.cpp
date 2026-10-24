// SPDX-License-Identifier: MIT

#include "crypto/vrf.hpp"

#include <openssl/bn.h>
#include <sodium.h>

#include <algorithm>
#include <memory>
#include <new>
#include <string>

#include "crypto/secure_memory.hpp"

namespace finalis::crypto {
namespace {

// RFC 9381 suite_string of ECVRF-EDWARDS25519-SHA512-TAI.
constexpr std::uint8_t kSuite = 0x03;
using Point = std::array<std::uint8_t, crypto_core_ed25519_BYTES>;
using Scalar = std::array<std::uint8_t, crypto_core_ed25519_SCALARBYTES>;
using Digest = std::array<std::uint8_t, crypto_hash_sha512_BYTES>;

Scalar reduce64(const Digest& wide) {
  Scalar out{};
  crypto_core_ed25519_scalar_reduce(out.data(), wide.data());
  return out;
}

struct Sha512 {
  crypto_hash_sha512_state st{};
  Sha512() { crypto_hash_sha512_init(&st); }
  Sha512& add(const std::uint8_t* p, std::size_t n) {
    crypto_hash_sha512_update(&st, p, n);
    return *this;
  }
  template <typename C>
  Sha512& add(const C& c) {
    return add(reinterpret_cast<const std::uint8_t*>(c.data()), c.size());
  }
  Sha512& add_byte(std::uint8_t b) { return add(&b, 1); }
  Digest finish() {
    Digest d{};
    crypto_hash_sha512_final(&st, d.data());
    return d;
  }
};

// ---------------------------------------------------------------------------------------------
// edwards25519 on public data: RFC 8032 decoding and encoding, and the twisted Edwards formulas in
// extended coordinates, over OpenSSL big integers. Variable time, so only for public values (keys,
// proofs, hash outputs). Every result is fixed by the curve alone. libsodium's point validation is
// not used here: its answer for points outside the prime-order subgroup changed in a security fix,
// and Ubuntu shipped the fix under the same 1.0.18 version, so builds disagreed on VRF proofs.
//
// Point coordinates are kept in Montgomery form (x*R mod p) for OpenSSL's fast modular
// multiplication; decode() and encode() convert at the boundary. Points are updated in place with
// per-thread scratch values, so the scalar-multiplication loops do not allocate.

struct BnDeleter {
  void operator()(BIGNUM* b) const { BN_free(b); }
};
using Bn = std::unique_ptr<BIGNUM, BnDeleter>;

Bn bn_new() {
  Bn b(BN_new());
  if (!b) throw std::bad_alloc();
  return b;
}

Bn bn_le(const std::uint8_t* p, std::size_t n) {
  Bn b(BN_lebin2bn(p, static_cast<int>(n), nullptr));
  if (!b) throw std::bad_alloc();
  return b;
}

BN_CTX* bn_ctx() {
  struct CtxDeleter {
    void operator()(BN_CTX* c) const { BN_CTX_free(c); }
  };
  thread_local std::unique_ptr<BN_CTX, CtxDeleter> ctx(BN_CTX_new());
  if (!ctx) throw std::bad_alloc();
  return ctx.get();
}

struct Curve {
  Bn p, d, sqrt_m1, sqrt_exp, l;  // ordinary form
  Bn d2_m, one_m;                 // Montgomery form
  std::unique_ptr<BN_MONT_CTX, void (*)(BN_MONT_CTX*)> mont{nullptr, BN_MONT_CTX_free};
};

const Curve& curve();

// Montgomery-form field operations; inputs are reduced, so the quick add/sub variants apply.
void fmul(BIGNUM* r, const BIGNUM* a, const BIGNUM* b) {
  BN_mod_mul_montgomery(r, a, b, curve().mont.get(), bn_ctx());
}
void fadd(BIGNUM* r, const BIGNUM* a, const BIGNUM* b) { BN_mod_add_quick(r, a, b, curve().p.get()); }
void fsub(BIGNUM* r, const BIGNUM* a, const BIGNUM* b) { BN_mod_sub_quick(r, a, b, curve().p.get()); }
// Ordinary-form multiplication, for decoding and encoding.
void nmul(BIGNUM* r, const BIGNUM* a, const BIGNUM* b) { BN_mod_mul(r, a, b, curve().p.get(), bn_ctx()); }

struct Ext {
  Bn x, y, z, t;  // x/z, y/z, xy = t/z, all in Montgomery form
};

Ext ext_new() { return Ext{bn_new(), bn_new(), bn_new(), bn_new()}; }

Ext ext_copy(const Ext& p) {
  Ext r = ext_new();
  BN_copy(r.x.get(), p.x.get());
  BN_copy(r.y.get(), p.y.get());
  BN_copy(r.z.get(), p.z.get());
  BN_copy(r.t.get(), p.t.get());
  return r;
}

void set_identity(Ext& r) {
  BN_zero(r.x.get());
  BN_copy(r.y.get(), curve().one_m.get());
  BN_copy(r.z.get(), curve().one_m.get());
  BN_zero(r.t.get());
}

struct Scratch {
  Bn a = bn_new(), b = bn_new(), c = bn_new(), d = bn_new(), e = bn_new(), f = bn_new(), g = bn_new(),
     h = bn_new();
};

Scratch& scratch() {
  thread_local Scratch s;
  return s;
}

// r = p + q, add-2008-hwcd-3 (a = -1, complete on edwards25519). r may alias p or q: every input
// is read before r is written.
void add_to(Ext& r, const Ext& p, const Ext& q) {
  Scratch& s = scratch();
  fsub(s.e.get(), p.y.get(), p.x.get());
  fsub(s.f.get(), q.y.get(), q.x.get());
  fmul(s.a.get(), s.e.get(), s.f.get());  // A = (Y1-X1)(Y2-X2)
  fadd(s.e.get(), p.y.get(), p.x.get());
  fadd(s.f.get(), q.y.get(), q.x.get());
  fmul(s.b.get(), s.e.get(), s.f.get());  // B = (Y1+X1)(Y2+X2)
  fmul(s.e.get(), p.t.get(), q.t.get());
  fmul(s.c.get(), s.e.get(), curve().d2_m.get());  // C = 2d T1 T2
  fmul(s.e.get(), p.z.get(), q.z.get());
  fadd(s.d.get(), s.e.get(), s.e.get());  // D = 2 Z1 Z2
  fsub(s.e.get(), s.b.get(), s.a.get());  // E = B - A
  fsub(s.f.get(), s.d.get(), s.c.get());  // F = D - C
  fadd(s.g.get(), s.d.get(), s.c.get());  // G = D + C
  fadd(s.h.get(), s.b.get(), s.a.get());  // H = B + A
  fmul(r.x.get(), s.e.get(), s.f.get());
  fmul(r.y.get(), s.g.get(), s.h.get());
  fmul(r.t.get(), s.e.get(), s.h.get());
  fmul(r.z.get(), s.f.get(), s.g.get());
}

// r = 2p, dbl-2008-hwcd (a = -1). r may alias p.
void double_to(Ext& r, const Ext& p) {
  Scratch& s = scratch();
  fmul(s.a.get(), p.x.get(), p.x.get());  // A = X1^2
  fmul(s.b.get(), p.y.get(), p.y.get());  // B = Y1^2
  fmul(s.e.get(), p.z.get(), p.z.get());
  fadd(s.c.get(), s.e.get(), s.e.get());  // C = 2 Z1^2
  fadd(s.e.get(), p.x.get(), p.y.get());
  fmul(s.h.get(), s.e.get(), s.e.get());
  fsub(s.h.get(), s.h.get(), s.a.get());
  fsub(s.e.get(), s.h.get(), s.b.get());  // E = (X1+Y1)^2 - A - B
  fsub(s.g.get(), s.b.get(), s.a.get());  // G = D + B with D = -A
  fsub(s.f.get(), s.g.get(), s.c.get());  // F = G - C
  BN_zero(s.d.get());
  fsub(s.d.get(), s.d.get(), s.a.get());
  fsub(s.h.get(), s.d.get(), s.b.get());  // H = D - B
  fmul(r.x.get(), s.e.get(), s.f.get());
  fmul(r.y.get(), s.g.get(), s.h.get());
  fmul(r.t.get(), s.e.get(), s.h.get());
  fmul(r.z.get(), s.f.get(), s.g.get());
}

Ext negate(const Ext& p) {
  Ext r = ext_copy(p);
  BN_zero(r.x.get());
  fsub(r.x.get(), r.x.get(), p.x.get());
  BN_zero(r.t.get());
  fsub(r.t.get(), r.t.get(), p.t.get());
  return r;
}

// a*P + b*Q in one double-and-add pass over the bits of both scalars (Straus/Shamir).
Ext joint_mul(const BIGNUM* a, const Ext& p, const BIGNUM* b, const Ext& q) {
  Ext pq = ext_new();
  add_to(pq, p, q);
  Ext r = ext_new();
  set_identity(r);
  for (int i = std::max(BN_num_bits(a), BN_num_bits(b)) - 1; i >= 0; --i) {
    double_to(r, r);
    const bool ba = BN_is_bit_set(a, i) != 0;
    const bool bb = BN_is_bit_set(b, i) != 0;
    if (ba && bb) {
      add_to(r, r, pq);
    } else if (ba) {
      add_to(r, r, p);
    } else if (bb) {
      add_to(r, r, q);
    }
  }
  return r;
}

Ext mul_cofactor(const Ext& p) {
  Ext r = ext_copy(p);
  double_to(r, r);
  double_to(r, r);
  double_to(r, r);
  return r;
}

bool is_identity(const Ext& p) { return BN_is_zero(p.x.get()) && BN_cmp(p.y.get(), p.z.get()) == 0; }

Point encode(const Ext& p) {
  const Curve& c = curve();
  Bn x = bn_new(), y = bn_new(), z = bn_new();
  BN_from_montgomery(x.get(), p.x.get(), c.mont.get(), bn_ctx());
  BN_from_montgomery(y.get(), p.y.get(), c.mont.get(), bn_ctx());
  BN_from_montgomery(z.get(), p.z.get(), c.mont.get(), bn_ctx());
  Bn zi(BN_mod_inverse(nullptr, z.get(), c.p.get(), bn_ctx()));
  if (!zi) throw std::bad_alloc();
  nmul(x.get(), x.get(), zi.get());
  nmul(y.get(), y.get(), zi.get());
  Point out{};
  BN_bn2lebinpad(y.get(), out.data(), static_cast<int>(out.size()));
  if (BN_is_odd(x.get())) out[31] |= 0x80;
  return out;
}

// RFC 8032 section 5.1.3: rejects y >= p, x = 0 with the sign bit set, and points off the curve.
std::optional<Ext> decode(const std::uint8_t* s) {
  const Curve& c = curve();
  Point b{};
  std::copy_n(s, b.size(), b.begin());
  const bool x0 = (b[31] & 0x80) != 0;
  b[31] &= 0x7f;
  Bn y = bn_le(b.data(), b.size());
  if (BN_cmp(y.get(), c.p.get()) >= 0) return std::nullopt;
  Bn one = bn_new(), y2 = bn_new(), u = bn_new(), v = bn_new(), t = bn_new(), zero = bn_new();
  BN_one(one.get());
  BN_zero(zero.get());
  nmul(y2.get(), y.get(), y.get());
  BN_mod_sub_quick(u.get(), y2.get(), one.get(), c.p.get());
  nmul(t.get(), c.d.get(), y2.get());
  BN_mod_add_quick(v.get(), t.get(), one.get(), c.p.get());
  // x = u v^3 (u v^7)^((p-5)/8)
  Bn v3 = bn_new(), v7 = bn_new(), x = bn_new();
  nmul(t.get(), v.get(), v.get());
  nmul(v3.get(), t.get(), v.get());
  nmul(t.get(), v3.get(), v3.get());
  nmul(v7.get(), t.get(), v.get());
  nmul(t.get(), u.get(), v7.get());
  BN_mod_exp(t.get(), t.get(), c.sqrt_exp.get(), c.p.get(), bn_ctx());
  nmul(x.get(), u.get(), v3.get());
  nmul(x.get(), x.get(), t.get());
  Bn vx2 = bn_new(), neg_u = bn_new();
  nmul(t.get(), x.get(), x.get());
  nmul(vx2.get(), v.get(), t.get());
  BN_mod_sub_quick(neg_u.get(), zero.get(), u.get(), c.p.get());
  if (BN_cmp(vx2.get(), u.get()) != 0) {
    if (BN_cmp(vx2.get(), neg_u.get()) != 0) return std::nullopt;
    nmul(x.get(), x.get(), c.sqrt_m1.get());
  }
  if (BN_is_zero(x.get()) && x0) return std::nullopt;
  if ((BN_is_odd(x.get()) != 0) != x0) BN_mod_sub_quick(x.get(), zero.get(), x.get(), c.p.get());
  Ext pt = ext_new();
  BN_to_montgomery(pt.x.get(), x.get(), c.mont.get(), bn_ctx());
  BN_to_montgomery(pt.y.get(), y.get(), c.mont.get(), bn_ctx());
  BN_copy(pt.z.get(), c.one_m.get());
  fmul(pt.t.get(), pt.x.get(), pt.y.get());
  return pt;
}

const Curve& curve() {
  static const Curve c = [] {
    Curve k;
    BN_CTX* ctx = bn_ctx();
    k.p = bn_new();
    BN_set_bit(k.p.get(), 255);
    BN_sub_word(k.p.get(), 19);
    k.mont.reset(BN_MONT_CTX_new());
    if (!k.mont || BN_MONT_CTX_set(k.mont.get(), k.p.get(), ctx) != 1) throw std::bad_alloc();
    // d = -121665 / 121666
    Bn num = bn_new(), den = bn_new();
    BN_set_word(num.get(), 121665);
    BN_sub(num.get(), k.p.get(), num.get());
    BN_set_word(den.get(), 121666);
    Bn inv(BN_mod_inverse(nullptr, den.get(), k.p.get(), ctx));
    if (!inv) throw std::bad_alloc();
    k.d = bn_new();
    BN_mod_mul(k.d.get(), num.get(), inv.get(), k.p.get(), ctx);
    Bn d2 = bn_new();
    BN_mod_add(d2.get(), k.d.get(), k.d.get(), k.p.get(), ctx);
    k.d2_m = bn_new();
    BN_to_montgomery(k.d2_m.get(), d2.get(), k.mont.get(), ctx);
    Bn one = bn_new();
    BN_one(one.get());
    k.one_m = bn_new();
    BN_to_montgomery(k.one_m.get(), one.get(), k.mont.get(), ctx);
    // sqrt(-1) = 2^((p-1)/4); exponent (p-5)/8 for the square root in decoding
    Bn two = bn_new(), e = bn_new();
    BN_set_word(two.get(), 2);
    BN_copy(e.get(), k.p.get());
    BN_sub_word(e.get(), 1);
    BN_rshift(e.get(), e.get(), 2);
    k.sqrt_m1 = bn_new();
    BN_mod_exp(k.sqrt_m1.get(), two.get(), e.get(), k.p.get(), ctx);
    k.sqrt_exp = bn_new();
    BN_copy(k.sqrt_exp.get(), k.p.get());
    BN_sub_word(k.sqrt_exp.get(), 5);
    BN_rshift(k.sqrt_exp.get(), k.sqrt_exp.get(), 3);
    // L = 2^252 + 27742317777372353535851937790883648493
    BIGNUM* l = nullptr;
    BN_dec2bn(&l, "7237005577332262213973186563042994240857116359379907606001950938285454250989");
    k.l = Bn(l);
    return k;
  }();
  return c;
}

const Ext& base_point() {
  static const Ext b = [] {
    Point s{};
    s.fill(0x66);
    s[0] = 0x58;
    return *decode(s.data());
  }();
  return b;
}

// RFC 9381 section 5.4.1.1 (try-and-increment) with the cofactor cleared: H = 8 * string_to_point(
// SHA512(suite || 0x01 || PK || alpha || ctr || 0x00)[0..32]) for the first ctr giving a point
// that is not the identity. About half of the candidates decode.
std::optional<Ext> encode_to_curve(const PubKey32& pk, const Bytes& alpha) {
  for (unsigned ctr = 0; ctr < 256; ++ctr) {
    const Digest d = Sha512()
                         .add_byte(kSuite)
                         .add_byte(0x01)
                         .add(pk)
                         .add(alpha)
                         .add_byte(static_cast<std::uint8_t>(ctr))
                         .add_byte(0x00)
                         .finish();
    auto p = decode(d.data());
    if (!p) continue;
    Ext h = mul_cofactor(*p);
    if (!is_identity(h)) return h;
  }
  return std::nullopt;
}

// RFC 9381 section 5.4.3.
std::array<std::uint8_t, 16> challenge(const PubKey32& y, const Point& h, const Point& gamma, const Point& u,
                                       const Point& v) {
  const Digest d =
      Sha512().add_byte(kSuite).add_byte(0x02).add(y).add(h).add(gamma).add(u).add(v).add_byte(0x00).finish();
  std::array<std::uint8_t, 16> c{};
  std::copy_n(d.begin(), c.size(), c.begin());
  return c;
}

// RFC 9381 section 5.2: SHA512(suite || 0x03 || point_to_string(8 * Gamma) || 0x00).
VrfOutput proof_to_hash(const Ext& gamma) {
  const Digest d = Sha512().add_byte(kSuite).add_byte(0x03).add(encode(mul_cofactor(gamma))).add_byte(0x00).finish();
  VrfOutput out{};
  std::copy(d.begin(), d.end(), out.begin());
  return out;
}

// RFC 9381 section 5.1 with RFC 8032 key expansion and nonce generation (section 5.4.2.2). The
// secret scalars only meet the base point and H through libsodium's constant-time code; H is
// cofactor-cleared, so it is in the prime-order subgroup that every libsodium build accepts.
std::optional<VrfProof80> prove_impl(const Bytes& sk, const Bytes& alpha) {
  if (sk.size() != 32) return std::nullopt;
  Digest az{};
  crypto_hash_sha512(az.data(), sk.data(), sk.size());
  az[0] &= 248;
  az[31] &= 127;
  az[31] |= 64;
  Digest x_wide{};
  std::copy_n(az.begin(), 32, x_wide.begin());
  Scalar x = reduce64(x_wide);
  secure_wipe(x_wide.data(), x_wide.size());

  std::optional<VrfProof80> out;
  PubKey32 y{};
  Point gamma{}, u{}, v{};
  Scalar k{}, c32{}, cx{}, s{};
  Digest k_wide{};
  if (crypto_scalarmult_ed25519_base_noclamp(y.data(), x.data()) == 0) {
    if (const auto h = encode_to_curve(y, alpha)) {
      const Point h_str = encode(*h);
      k_wide = Sha512().add(az.data() + 32, 32).add(h_str).finish();
      k = reduce64(k_wide);
      if (crypto_scalarmult_ed25519_noclamp(gamma.data(), x.data(), h_str.data()) == 0 &&
          crypto_scalarmult_ed25519_base_noclamp(u.data(), k.data()) == 0 &&
          crypto_scalarmult_ed25519_noclamp(v.data(), k.data(), h_str.data()) == 0) {
        const auto c = challenge(y, h_str, gamma, u, v);
        std::copy(c.begin(), c.end(), c32.begin());
        crypto_core_ed25519_scalar_mul(cx.data(), c32.data(), x.data());
        crypto_core_ed25519_scalar_add(s.data(), k.data(), cx.data());
        VrfProof80 proof{};
        std::copy(gamma.begin(), gamma.end(), proof.begin());
        std::copy(c.begin(), c.end(), proof.begin() + 32);
        std::copy(s.begin(), s.end(), proof.begin() + 48);
        out = proof;
      }
    }
  }
  secure_wipe(az.data(), az.size());
  secure_wipe(x.data(), x.size());
  secure_wipe(k.data(), k.size());
  secure_wipe(k_wide.data(), k_wide.size());
  secure_wipe(cx.data(), cx.size());
  return out;
}

// RFC 9381 section 5.3 with validate_key = TRUE, computed entirely in the public-data arithmetic.
std::optional<VrfOutput> verify_impl(const PubKey32& pk, const VrfProof80& proof, const Bytes& alpha) {
  const auto y = decode(pk.data());
  if (!y || is_identity(mul_cofactor(*y))) return std::nullopt;  // ECVRF_validate_key
  const auto gamma = decode(proof.data());
  if (!gamma) return std::nullopt;
  const Bn c = bn_le(proof.data() + 32, 16);
  const Bn s = bn_le(proof.data() + 48, 32);
  if (BN_cmp(s.get(), curve().l.get()) >= 0) return std::nullopt;
  const auto h = encode_to_curve(pk, alpha);
  if (!h) return std::nullopt;
  const Ext u = joint_mul(s.get(), base_point(), c.get(), negate(*y));  // s*B - c*Y
  const Ext v = joint_mul(s.get(), *h, c.get(), negate(*gamma));        // s*H - c*Gamma
  Point gamma_str{};
  std::copy_n(proof.begin(), gamma_str.size(), gamma_str.begin());
  const auto expected = challenge(pk, encode(*h), gamma_str, encode(u), encode(v));
  if (!std::equal(expected.begin(), expected.end(), proof.begin() + 32)) return std::nullopt;
  return proof_to_hash(*gamma);
}

// RFC 9381 appendix B.3, examples 16-18. Run once before any proof is made or checked, so a build
// whose libsodium or OpenSSL behaves differently refuses to take part in consensus.
bool self_test() {
  struct Vector {
    const char* sk;
    const char* pk;
    const char* alpha;
    const char* pi;
    const char* beta;
  };
  static constexpr Vector kVectors[] = {
      {"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
       "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
       "8657106690b5526245a92b003bb079ccd1a92130477671f6fc01ad16f26f723f26f8a57ccaed74ee1b190bed1f479d9727d2d0f9b0"
       "05a6e456a35d4fb0daab1268a1b0db10836d9826a528ca76567805",
       "90cf1df3b703cce59e2a35b925d411164068269d7b2d29f3301c03dd757876ff66b71dda49d2de59d03450451af026798e8f81cd2e33"
       "3de5cdf4f3e140fdd8ae"},
      {"4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
       "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
       "f3141cd382dc42909d19ec5110469e4feae18300e94f304590abdced48aed5933bf0864a62558b3ed7f2fea45c92a465301b3bbf5e"
       "3e54ddf2d935be3b67926da3ef39226bbc355bdc9850112c8f4b02",
       "eb4440665d3891d668e7e0fcaf587f1b4bd7fbfe99d0eb2211ccec90496310eb5e33821bc613efb94db5e5b54c70a848a0bef4553a41"
       "befc57663b56373a5031"},
      {"c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
       "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "af82",
       "9bc0f79119cc5604bf02d23b4caede71393cedfbb191434dd016d30177ccbf8096bb474e53895c362d8628ee9f9ea3c0e52c7a5c69"
       "1b6c18c9979866568add7a2d41b00b05081ed0f58ee5e31b3a970e",
       "645427e5d00c62a23fb703732fa5d892940935942101e456ecca7bb217c61c452118fec1219202a0edcf038bb6373241578be7217b"
       "a85a2687f7a0310b2df19f"},
  };
  for (const auto& vec : kVectors) {
    const auto sk = hex_decode(vec.sk);
    const auto pk_bytes = hex_decode(vec.pk);
    const auto alpha = hex_decode(vec.alpha);
    const auto pi = hex_decode(vec.pi);
    const auto beta = hex_decode(vec.beta);
    if (!sk || !pk_bytes || !alpha || !pi || !beta || pk_bytes->size() != 32 || pi->size() != kVrfProofBytes)
      return false;
    PubKey32 pk{};
    std::copy(pk_bytes->begin(), pk_bytes->end(), pk.begin());
    VrfProof80 expected_pi{};
    std::copy(pi->begin(), pi->end(), expected_pi.begin());
    const auto proved = prove_impl(*sk, *alpha);
    if (!proved || *proved != expected_pi) return false;
    const auto out = verify_impl(pk, expected_pi, *alpha);
    if (!out || !std::equal(out->begin(), out->end(), beta->begin(), beta->end())) return false;
    Bytes other = *alpha;
    other.push_back(0x00);
    if (verify_impl(pk, expected_pi, other).has_value()) return false;
  }
  // The decoder is part of the consensus rule: y >= p, x = 0 with the sign bit set, a point off the
  // curve and a small-order key must all be rejected (tests/test_vrf.cpp has the full set).
  static constexpr const char* kRejectedKeys[] = {
      "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
      "0100000000000000000000000000000000000000000000000000000000000080",
      "0200000000000000000000000000000000000000000000000000000000000000",
      "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
  };
  const auto pi = hex_decode(kVectors[0].pi);
  if (!pi || pi->size() != kVrfProofBytes) return false;
  VrfProof80 proof{};
  std::copy(pi->begin(), pi->end(), proof.begin());
  for (const char* key : kRejectedKeys) {
    const auto enc = hex_decode(key);
    if (!enc || enc->size() != 32) return false;
    PubKey32 pk{};
    std::copy(enc->begin(), enc->end(), pk.begin());
    if (verify_impl(pk, proof, Bytes{}).has_value()) return false;
  }
  return true;
}

}  // namespace

bool vrf_init() {
  static const bool ok = sodium_init() >= 0 && self_test();
  return ok;
}

std::optional<VrfProof80> vrf_prove(const Bytes& private_key_32, const Bytes& alpha) {
  if (private_key_32.size() != 32 || !vrf_init()) return std::nullopt;
  return prove_impl(private_key_32, alpha);
}

std::optional<VrfOutput> vrf_verify(const PubKey32& pubkey, const VrfProof80& proof, const Bytes& alpha) {
  if (!vrf_init()) return std::nullopt;
  return verify_impl(pubkey, proof, alpha);
}

VrfOutput vrf_proof_to_output(const VrfProof80& proof) {
  const auto gamma = decode(proof.data());
  if (!gamma) return VrfOutput{};
  return proof_to_hash(*gamma);
}

}  // namespace finalis::crypto
