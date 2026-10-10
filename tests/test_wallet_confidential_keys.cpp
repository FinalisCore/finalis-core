// SPDX-License-Identifier: MIT

#include "test_framework.hpp"

#include <set>

#include "common/types.hpp"
#include "wallet/confidential_keys.hpp"

using namespace finalis;

namespace {

Hash32 filled(std::uint8_t b) {
  Hash32 h{};
  h.fill(b);
  return h;
}

std::string hex33(const PubKey33& p) { return hex_encode(Bytes(p.begin(), p.end())); }
std::string hex32(const Hash32& h) { return hex_encode(Bytes(h.begin(), h.end())); }

}  // namespace

// Pinned vector, cross-checked against an independent pure-Python secp256k1/SHA-256 implementation of
// the formulas in wallet/confidential_keys.hpp. Changing any value invalidates every wallet backup.
TEST(test_confidential_request_keys_known_answer) {
  const auto k = wallet::derive_confidential_request_keys(filled(0x11), filled(0x22), 7);
  ASSERT_TRUE(k.has_value());
  ASSERT_EQ(hex33(k->pub.one_time_pubkey), std::string("02792b2be80b0cff5b5ec5fc30347f9acce80cc3353da933de5ab3fa8decbe712d"));
  ASSERT_EQ(hex33(k->pub.ephemeral_pubkey), std::string("03e3b95068962195688f7282a226cb6bf66c6cb874da2da030a1394e243a96d7de"));
  ASSERT_EQ(k->pub.scan_tag.value, 245);
  ASSERT_EQ(hex32(k->pub.memo_key), std::string("6e75b3dc94986908cec59c4975024933e04f4cdb013ada19ce261d95616078bf"));
  ASSERT_EQ(hex32(k->one_time_secret), std::string("70b0a2e644b0e6c1776a4825e3a331f5ad5cf2b0104a2204ec8a261e2a45b8af"));
}

TEST(test_confidential_request_keys_watch_only_matches_full_and_secret_matches_pubkey) {
  const Hash32 view = filled(0x31);
  const Hash32 spend = filled(0x42);
  const auto spend_pubkey = crypto::secp256k1_pubkey_from_scalar(spend);
  ASSERT_TRUE(spend_pubkey.has_value());
  for (std::uint32_t i : {0u, 1u, 2u, 1000u, 0xFFFF'FFFFu}) {
    const auto full = wallet::derive_confidential_request_keys(view, spend, i);
    const auto watch = wallet::derive_confidential_request_public_keys(view, *spend_pubkey, i);
    ASSERT_TRUE(full.has_value() && watch.has_value());
    ASSERT_TRUE(full->pub.one_time_pubkey == watch->one_time_pubkey);
    ASSERT_TRUE(full->pub.ephemeral_pubkey == watch->ephemeral_pubkey);
    ASSERT_TRUE(full->pub.scan_tag == watch->scan_tag);
    ASSERT_TRUE(full->pub.memo_key == watch->memo_key);
    ASSERT_TRUE(crypto::secp256k1_pubkey_from_scalar(full->one_time_secret) == full->pub.one_time_pubkey);
    ASSERT_TRUE(crypto::compressed_pubkey33_is_canonical(full->pub.one_time_pubkey));
    ASSERT_TRUE(crypto::compressed_pubkey33_is_canonical(full->pub.ephemeral_pubkey));
    // Same inputs, same keys: a restored wallet re-derives exactly these.
    const auto again = wallet::derive_confidential_request_keys(view, spend, i);
    ASSERT_TRUE(again.has_value() && again->one_time_secret == full->one_time_secret);
  }
}

// The derived secret is what spends the coin: it must produce a spend authorization that verifies
// against the one-time pubkey, exactly as validate.cpp checks confidential inputs.
TEST(test_confidential_request_one_time_secret_authorizes_spend) {
  const auto k = wallet::derive_confidential_request_keys(filled(0x51), filled(0x62), 3);
  ASSERT_TRUE(k.has_value());
  const Hash32 msg = filled(0xA5);
  const auto sig = crypto::sign_schnorr_authorization(msg, crypto::Blind32{k->one_time_secret}, filled(0x01));
  ASSERT_TRUE(sig.has_value());
  ASSERT_TRUE(crypto::verify_schnorr_authorization(msg, k->pub.one_time_pubkey, *sig));
  // Another request's key must not verify it.
  const auto other = wallet::derive_confidential_request_keys(filled(0x51), filled(0x62), 4);
  ASSERT_TRUE(other.has_value());
  ASSERT_TRUE(!crypto::verify_schnorr_authorization(msg, other->pub.one_time_pubkey, *sig));
}

// Unlinkability needs fresh keys per request: no two requests of an account, or of two accounts,
// may share a one-time pubkey, ephemeral pubkey or memo key.
TEST(test_confidential_request_keys_are_distinct_per_request_and_account) {
  std::set<PubKey33> one_time;
  std::set<PubKey33> ephemeral;
  std::set<Hash32> memo;
  for (std::uint8_t account = 1; account <= 2; ++account) {
    for (std::uint32_t i = 0; i < 64; ++i) {
      const auto k = wallet::derive_confidential_request_keys(filled(account), filled(0x70 + account), i);
      ASSERT_TRUE(k.has_value());
      ASSERT_TRUE(one_time.insert(k->pub.one_time_pubkey).second);
      ASSERT_TRUE(ephemeral.insert(k->pub.ephemeral_pubkey).second);
      ASSERT_TRUE(memo.insert(k->pub.memo_key).second);
    }
  }
  // The spend secret only moves the one-time key: the view-derived parts are shared by design.
  const auto a = wallet::derive_confidential_request_keys(filled(0x01), filled(0x02), 0);
  const auto b = wallet::derive_confidential_request_keys(filled(0x01), filled(0x03), 0);
  ASSERT_TRUE(a.has_value() && b.has_value());
  ASSERT_TRUE(a->pub.one_time_pubkey != b->pub.one_time_pubkey);
  ASSERT_TRUE(a->pub.memo_key == b->pub.memo_key);
}

TEST(test_confidential_request_keys_reject_invalid_secrets) {
  Hash32 over_order{};
  over_order.fill(0xFF);  // >= group order n
  const Hash32 zero{};
  ASSERT_TRUE(!wallet::derive_confidential_request_keys(zero, filled(0x22), 0).has_value());
  ASSERT_TRUE(!wallet::derive_confidential_request_keys(filled(0x11), zero, 0).has_value());
  ASSERT_TRUE(!wallet::derive_confidential_request_keys(over_order, filled(0x22), 0).has_value());
  ASSERT_TRUE(!wallet::derive_confidential_request_keys(filled(0x11), over_order, 0).has_value());
  PubKey33 bad_point{};
  bad_point[0] = 0x02;  // x = 0 is not on the curve
  ASSERT_TRUE(!wallet::derive_confidential_request_public_keys(filled(0x11), bad_point, 0).has_value());
}
