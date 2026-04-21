#include "test_framework.hpp"

#include "crypto/ed25519.hpp"
#include "crypto/hash.hpp"
#include "common/merkle.hpp"

using namespace finalis;

TEST(test_sha256d_vectors) {
  const auto v0 = crypto::sha256d(Bytes{});
  ASSERT_EQ(hex_encode32(v0), "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456");

  Bytes abc{'a', 'b', 'c'};
  const auto v1 = crypto::sha256d(abc);
  ASSERT_EQ(hex_encode32(v1), "4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358");
}

TEST(test_h160_vector) {
  Bytes abc{'a', 'b', 'c'};
  const auto h = crypto::h160(abc);
  ASSERT_EQ(hex_encode(Bytes(h.begin(), h.end())), "bb1be98c142444d7a56aa3981c3942a978e4dc33");
}

TEST(test_merkle_root_and_odd_duplication) {
  Bytes a{'a'}, b{'b'}, c{'c'};
  std::vector<Bytes> txs = {a, b, c};
  auto root = merkle::compute_merkle_root_from_txs(txs);
  ASSERT_TRUE(root.has_value());

  Hash32 ha = crypto::sha256d(a);
  Hash32 hb = crypto::sha256d(b);
  Hash32 hc = crypto::sha256d(c);
  Bytes ab;
  ab.insert(ab.end(), ha.begin(), ha.end());
  ab.insert(ab.end(), hb.begin(), hb.end());
  Hash32 hab = crypto::sha256d(ab);

  Bytes cc;
  cc.insert(cc.end(), hc.begin(), hc.end());
  cc.insert(cc.end(), hc.begin(), hc.end());
  Hash32 hcc = crypto::sha256d(cc);

  Bytes top;
  top.insert(top.end(), hab.begin(), hab.end());
  top.insert(top.end(), hcc.begin(), hcc.end());
  Hash32 expected = crypto::sha256d(top);
  ASSERT_EQ(*root, expected);
}

TEST(test_ed25519_roundtrip) {
  std::array<std::uint8_t, 32> seed{};
  for (size_t i = 0; i < 32; ++i) seed[i] = static_cast<std::uint8_t>(i + 1);
  auto kp = crypto::keypair_from_seed32(seed);
  ASSERT_TRUE(kp.has_value());

  Bytes msg{'t', 'e', 's', 't'};
  auto sig = crypto::ed25519_sign(msg, kp->private_key);
  ASSERT_TRUE(sig.has_value());
  ASSERT_TRUE(crypto::ed25519_verify(msg, *sig, kp->public_key));

  msg[0] ^= 0x01;
  ASSERT_TRUE(!crypto::ed25519_verify(msg, *sig, kp->public_key));
}

void register_crypto_tests() {}
