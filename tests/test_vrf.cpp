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

// The decoder is part of the consensus rule, and the RFC vectors only cover valid proofs. These
// are the encodings Ed25519 implementations are known to disagree on ("Taming the many EdDSAs",
// Chalkias et al. 2020), each classified with an independent RFC 8032 implementation: a public key
// or Gamma with any of them must be rejected.
TEST(test_vrf_rejects_non_canonical_off_curve_and_small_order_encodings) {
  ASSERT_TRUE(crypto::vrf_init());
  const auto kp = key_from_byte(0x37);
  const auto proof = *crypto::vrf_prove(kp.private_key, text("alpha"));
  ASSERT_TRUE(crypto::vrf_verify(kp.public_key, proof, text("alpha")).has_value());
  struct Case {
    const char* what;
    const char* hex;
    bool decodes;
  };
  const Case cases[] = {
      {"y = p", "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", false},
      {"y = p + 1 (alias of the identity)", "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", false},
      {"y = 2^255 - 1", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", false},
      {"identity with the sign bit set", "0100000000000000000000000000000000000000000000000000000000000080", false},
      {"(0, -1) with the sign bit set", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", false},
      {"y = 2, not on the curve", "0200000000000000000000000000000000000000000000000000000000000000", false},
      {"identity (order 1)", "0100000000000000000000000000000000000000000000000000000000000000", true},
      {"(0, -1) (order 2)", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", true},
      {"y = 0 (order 4)", "0000000000000000000000000000000000000000000000000000000000000000", true},
      {"y = 0, negative x (order 4)", "0000000000000000000000000000000000000000000000000000000000000080", true},
      {"order 8", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a", true},
      {"order 8", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa", true},
      {"order 8", "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", true},
      {"order 8", "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85", true},
  };
  for (const auto& c : cases) {
    const Bytes enc = *hex_decode(c.hex);
    PubKey32 pk{};
    std::copy(enc.begin(), enc.end(), pk.begin());
    if (crypto::vrf_verify(pk, proof, text("alpha")).has_value()) throw std::runtime_error(std::string("accepted key: ") + c.what);
    auto bad = proof;
    std::copy(enc.begin(), enc.end(), bad.begin());
    if (crypto::vrf_verify(kp.public_key, bad, text("alpha")).has_value())
      throw std::runtime_error(std::string("accepted Gamma: ") + c.what);
    // Only a Gamma that does not decode has no output (all zero); a small-order one still decodes.
    const bool zero_output = crypto::vrf_proof_to_output(bad) == crypto::VrfOutput{};
    if (zero_output == c.decodes) throw std::runtime_error(std::string("decode mismatch: ") + c.what);
  }
}

// RFC 9381 appendix B.3 (ECVRF-EDWARDS25519-SHA512-TAI), examples 16-18: the published proofs and
// outputs, so the construction is the standard one and any change to it is caught here.
TEST(test_vrf_matches_rfc9381_edwards25519_tai_vectors) {
  ASSERT_TRUE(crypto::vrf_init());
  struct Vector {
    const char* sk;
    const char* pk;
    const char* alpha;
    const char* pi;
    const char* beta;
  };
  const Vector vectors[] = {
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
  for (const auto& v : vectors) {
    const Bytes sk = *hex_decode(v.sk);
    const Bytes alpha = *hex_decode(v.alpha);
    std::array<std::uint8_t, 32> seed{};
    std::copy(sk.begin(), sk.end(), seed.begin());
    const auto kp = *crypto::keypair_from_seed32(seed);
    ASSERT_EQ(hex_encode(Bytes(kp.public_key.begin(), kp.public_key.end())), std::string(v.pk));
    const auto proof = *crypto::vrf_prove(kp.private_key, alpha);
    ASSERT_EQ(hex_encode(Bytes(proof.begin(), proof.end())), std::string(v.pi));
    const auto out = crypto::vrf_verify(kp.public_key, proof, alpha);
    ASSERT_TRUE(out.has_value());
    ASSERT_EQ(hex_encode(Bytes(out->begin(), out->end())), std::string(v.beta));
    ASSERT_TRUE(*out == crypto::vrf_proof_to_output(proof));
  }
}

// The input on which an Ubuntu 20.04 build (libsodium 1.0.18-1) and an Ubuntu 24.04 build
// (1.0.18-1ubuntu0.24.04.1) produced different proofs and rejected each other's with the earlier
// construction, which hashed to the curve through crypto_core_ed25519_is_valid_point. The proof is
// now fixed by the curve alone; CI runs these tests on both kinds of build.
TEST(test_vrf_proof_does_not_depend_on_libsodium_point_validation) {
  ASSERT_TRUE(crypto::vrf_init());
  const auto kp = key_from_byte(90);
  const Bytes alpha = *hex_decode(
      "53432d52414e442d5652462d56313f47e57357e6be94871d5cfdf73149b65c8fc40217390586e683872043cc3be00300000000000000");
  const auto proof = *crypto::vrf_prove(kp.private_key, alpha);
  ASSERT_TRUE(crypto::vrf_verify(kp.public_key, proof, alpha).has_value());
  ASSERT_EQ(hex_encode(Bytes(proof.begin(), proof.end())),
            std::string("9ceb68c1d38d7c1429c75b59a260612fd0a203ca04334a494d7bd56589fb88df8797dc57dbe504fc110c790db23b30f5"
                        "72fddadf77045d7c562c8366998148525b81eb10dd9be5d7eb9b53662dc20f0a"));
}
