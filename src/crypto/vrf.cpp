// SPDX-License-Identifier: MIT

#include "crypto/vrf.hpp"

#include <sodium.h>

#include <algorithm>
#include <cstring>
#include <string_view>

#include "crypto/secure_memory.hpp"

namespace finalis::crypto {
namespace {

constexpr std::string_view kSuite = "FINALIS-ECVRF-EDWARDS25519-SHA512-TAI-V1";
using Point = std::array<std::uint8_t, crypto_core_ed25519_BYTES>;
using Scalar = std::array<std::uint8_t, crypto_core_ed25519_SCALARBYTES>;
using Digest = std::array<std::uint8_t, crypto_hash_sha512_BYTES>;

// L = 2^252 + 27742317777372353535851937790883648493, little endian.
constexpr Scalar kGroupOrder = {0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7,
                                0xa2, 0xde, 0xf9, 0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10};

bool scalar_is_canonical(const Scalar& s) {
  for (std::size_t i = s.size(); i-- > 0;) {
    if (s[i] < kGroupOrder[i]) return true;
    if (s[i] > kGroupOrder[i]) return false;
  }
  return false;  // s == L
}

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

// About 1 in 16 candidates is a canonical prime-order point; 1024 tries all fail with probability
// (15/16)^1024 < 2^-95.
std::optional<Point> encode_to_curve(const PubKey32& y, const Bytes& alpha) {
  for (std::uint32_t ctr = 0; ctr < 1024; ++ctr) {
    const std::array<std::uint8_t, 4> ctr_le{static_cast<std::uint8_t>(ctr), static_cast<std::uint8_t>(ctr >> 8),
                                             static_cast<std::uint8_t>(ctr >> 16), static_cast<std::uint8_t>(ctr >> 24)};
    const Digest d = Sha512().add(kSuite).add_byte(0x01).add(y).add(alpha).add(ctr_le).finish();
    Point h{};
    std::copy_n(d.begin(), h.size(), h.begin());
    if (crypto_core_ed25519_is_valid_point(h.data()) == 1) return h;
  }
  return std::nullopt;
}

Scalar challenge(const PubKey32& y, const Point& h, const Point& gamma, const Point& u, const Point& v) {
  const Digest d = Sha512().add(kSuite).add_byte(0x02).add(y).add(h).add(gamma).add(u).add(v).finish();
  Scalar c{};
  std::copy_n(d.begin(), 16, c.begin());
  return c;
}

}  // namespace

bool vrf_init() {
  static const bool ok = sodium_init() >= 0;
  return ok;
}

std::optional<VrfProof80> vrf_prove(const Bytes& private_key_32, const Bytes& alpha) {
  if (private_key_32.size() != 32 || !vrf_init()) return std::nullopt;
  Digest az{};
  crypto_hash_sha512(az.data(), private_key_32.data(), private_key_32.size());
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
  Scalar k{}, cx{}, s{};
  Digest k_wide{};
  if (crypto_scalarmult_ed25519_base_noclamp(y.data(), x.data()) == 0) {
    if (const auto h = encode_to_curve(y, alpha)) {
      k_wide = Sha512().add(az.data() + 32, 32).add(*h).finish();
      k = reduce64(k_wide);
      if (crypto_scalarmult_ed25519_noclamp(gamma.data(), x.data(), h->data()) == 0 &&
          crypto_scalarmult_ed25519_base_noclamp(u.data(), k.data()) == 0 &&
          crypto_scalarmult_ed25519_noclamp(v.data(), k.data(), h->data()) == 0) {
        const Scalar c = challenge(y, *h, gamma, u, v);
        crypto_core_ed25519_scalar_mul(cx.data(), c.data(), x.data());
        crypto_core_ed25519_scalar_add(s.data(), k.data(), cx.data());
        VrfProof80 proof{};
        std::copy(gamma.begin(), gamma.end(), proof.begin());
        std::copy_n(c.begin(), 16, proof.begin() + 32);
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

std::optional<VrfOutput> vrf_verify(const PubKey32& pubkey, const VrfProof80& proof, const Bytes& alpha) {
  if (!vrf_init()) return std::nullopt;
  Point gamma{};
  Scalar c{}, s{};
  std::copy_n(proof.begin(), 32, gamma.begin());
  std::copy_n(proof.begin() + 32, 16, c.begin());
  std::copy_n(proof.begin() + 48, 32, s.begin());
  if (!scalar_is_canonical(s)) return std::nullopt;
  if (crypto_core_ed25519_is_valid_point(pubkey.data()) != 1) return std::nullopt;
  if (crypto_core_ed25519_is_valid_point(gamma.data()) != 1) return std::nullopt;
  const auto h = encode_to_curve(pubkey, alpha);
  if (!h) return std::nullopt;

  // U = s*B - c*Y, V = s*H - c*Gamma
  Point sb{}, cy{}, sh{}, cg{}, u{}, v{};
  if (crypto_scalarmult_ed25519_base_noclamp(sb.data(), s.data()) != 0 ||
      crypto_scalarmult_ed25519_noclamp(cy.data(), c.data(), pubkey.data()) != 0 ||
      crypto_scalarmult_ed25519_noclamp(sh.data(), s.data(), h->data()) != 0 ||
      crypto_scalarmult_ed25519_noclamp(cg.data(), c.data(), gamma.data()) != 0 ||
      crypto_core_ed25519_sub(u.data(), sb.data(), cy.data()) != 0 ||
      crypto_core_ed25519_sub(v.data(), sh.data(), cg.data()) != 0) {
    return std::nullopt;
  }
  const Scalar expected = challenge(pubkey, *h, gamma, u, v);
  if (sodium_memcmp(expected.data(), c.data(), 16) != 0) return std::nullopt;
  return vrf_proof_to_output(proof);
}

VrfOutput vrf_proof_to_output(const VrfProof80& proof) {
  const Digest d = Sha512().add(kSuite).add_byte(0x03).add(proof.data(), 32).finish();
  VrfOutput out{};
  std::copy(d.begin(), d.end(), out.begin());
  return out;
}

}  // namespace finalis::crypto
