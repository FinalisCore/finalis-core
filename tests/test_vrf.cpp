// SPDX-License-Identifier: MIT

#include "test_framework.hpp"

#include "crypto/ed25519.hpp"
#include "crypto/vrf.hpp"

using namespace finalis;

namespace {

crypto::KeyPair key_from_byte(std::uint8_t b) {
  std::array<std::uint8_t, 32> seed{};
  seed.fill(b);
  auto kp = crypto::keypair_from_seed32(seed);
  ASSERT_TRUE(kp.has_value());
  return *kp;
}

Bytes text(const char* s) { return Bytes(s, s + std::char_traits<char>::length(s)); }

}  // namespace

TEST(test_vrf_proves_and_verifies_under_the_ed25519_key) {
  ASSERT_TRUE(crypto::vrf_init());
  const auto kp = key_from_byte(0x31);
  const auto proof = crypto::vrf_prove(kp.private_key, text("alpha"));
  ASSERT_TRUE(proof.has_value());
  const auto out = crypto::vrf_verify(kp.public_key, *proof, text("alpha"));
  ASSERT_TRUE(out.has_value());
  ASSERT_TRUE(*out == crypto::vrf_proof_to_output(*proof));
  // Deterministic: proving again gives the same proof.
  ASSERT_TRUE(*crypto::vrf_prove(kp.private_key, text("alpha")) == *proof);
}

TEST(test_vrf_rejects_wrong_alpha_key_and_tampered_proofs) {
  ASSERT_TRUE(crypto::vrf_init());
  const auto kp = key_from_byte(0x32);
  const auto other = key_from_byte(0x33);
  const auto proof = *crypto::vrf_prove(kp.private_key, text("alpha"));
  ASSERT_TRUE(!crypto::vrf_verify(kp.public_key, proof, text("alphb")).has_value());
  ASSERT_TRUE(!crypto::vrf_verify(other.public_key, proof, text("alpha")).has_value());
  for (std::size_t i : {std::size_t{0}, std::size_t{31}, std::size_t{32}, std::size_t{47}, std::size_t{48}, std::size_t{79}}) {
    auto bad = proof;
    bad[i] ^= 0x01;
    ASSERT_TRUE(!crypto::vrf_verify(kp.public_key, bad, text("alpha")).has_value());
  }
  // s + L encodes the same scalar; only the canonical encoding is accepted.
  auto s_plus_l = proof;
  const std::array<std::uint8_t, 32> l = {0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7,
                                          0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10};
  unsigned carry = 0;
  for (std::size_t i = 0; i < 32; ++i) {
    const unsigned sum = s_plus_l[48 + i] + l[i] + carry;
    s_plus_l[48 + i] = static_cast<std::uint8_t>(sum);
    carry = sum >> 8;
  }
  ASSERT_EQ(carry, 0u);
  ASSERT_TRUE(!crypto::vrf_verify(kp.public_key, s_plus_l, text("alpha")).has_value());
}

// Small-order public keys would let a prover pass the proof check for many outputs.
TEST(test_vrf_rejects_small_order_and_non_canonical_public_keys) {
  ASSERT_TRUE(crypto::vrf_init());
  const auto kp = key_from_byte(0x34);
  const auto proof = *crypto::vrf_prove(kp.private_key, text("alpha"));
  PubKey32 identity{};
  identity[0] = 0x01;  // the neutral element (0, 1)
  ASSERT_TRUE(!crypto::vrf_verify(identity, proof, text("alpha")).has_value());
  PubKey32 zero{};
  ASSERT_TRUE(!crypto::vrf_verify(zero, proof, text("alpha")).has_value());
}

TEST(test_vrf_outputs_differ_per_key_and_alpha) {
  ASSERT_TRUE(crypto::vrf_init());
  const auto a = key_from_byte(0x35);
  const auto b = key_from_byte(0x36);
  const auto out_a1 = crypto::vrf_proof_to_output(*crypto::vrf_prove(a.private_key, text("h1")));
  const auto out_a2 = crypto::vrf_proof_to_output(*crypto::vrf_prove(a.private_key, text("h2")));
  const auto out_b1 = crypto::vrf_proof_to_output(*crypto::vrf_prove(b.private_key, text("h1")));
  ASSERT_TRUE(out_a1 != out_a2);
  ASSERT_TRUE(out_a1 != out_b1);
}

// Pins the construction: any change to the suite, hashing or encoding moves these bytes and is a
// consensus change. The values come from an independent pure-integer edwards25519 implementation
// of the construction in crypto/vrf.hpp (no libsodium), so they also check this one.
TEST(test_vrf_known_answer) {
  ASSERT_TRUE(crypto::vrf_init());
  const auto kp = key_from_byte(0x42);
  ASSERT_EQ(hex_encode(Bytes(kp.public_key.begin(), kp.public_key.end())),
            std::string("2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12"));
  const auto proof = *crypto::vrf_prove(kp.private_key, text("finalis-vrf-kat"));
  ASSERT_EQ(hex_encode(Bytes(proof.begin(), proof.end())),
            std::string("adbb2d042f536ad188a994dae02ffba740ba7f52d8f2ce1b00a25302434e2120b3ba359c03cc6fe57e3708d67a7759b7"
                        "e445426ae80ce4d09828e9ef0bc82bd1988e24497795ea4fa75ac9e2c035160c"));
  const auto out = crypto::vrf_proof_to_output(proof);
  ASSERT_EQ(hex_encode(Bytes(out.begin(), out.end())),
            std::string("2f1aee387e47aa864d2b793b56960a02fefe1114be0fe7d3eb916f35494bc7527bc919bf8e9e5cbf75de6700fc2eaa76"
                        "879050c2fc0eb481500dbc37fa60d532"));
  ASSERT_TRUE(crypto::vrf_verify(kp.public_key, proof, text("finalis-vrf-kat")).has_value());

  const auto kp2 = key_from_byte(0x31);
  const auto proof2 = *crypto::vrf_prove(kp2.private_key, text("alpha"));
  ASSERT_EQ(hex_encode(Bytes(proof2.begin(), proof2.end())),
            std::string("8cbd7933ba6f470fc43e6184ee6299c826dc2f00fbb57cb814cd669666fa438448c33bbba88627398932298d0239bf"
                        "70d21d529e67f78ba9473ab399833b5813689c82cb6c82401cd509b1f2a7023b01"));
}
