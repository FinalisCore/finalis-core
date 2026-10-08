// SPDX-License-Identifier: MIT

#include "test_framework.hpp"

#include <algorithm>

#include "apps/finalis-wallet/confidential_memo.hpp"
#include "utxo/confidential_tx.hpp"

using namespace finalis;

namespace {

struct MemoFixture {
  Hash32 memo_key{};
  crypto::Blind32 blind{};
  PubKey33 one_time{};
  PubKey33 ephemeral{};

  MemoFixture() {
    ASSERT_TRUE(crypto::confidential_crypto_init());
    memo_key.fill(0x11);
    blind.bytes.fill(0x22);
    Hash32 s1{};
    s1.fill(0x33);
    Hash32 s2{};
    s2.fill(0x44);
    auto a = crypto::secp256k1_pubkey_from_scalar(s1);
    auto b = crypto::secp256k1_pubkey_from_scalar(s2);
    ASSERT_TRUE(a.has_value() && b.has_value());
    one_time = *a;
    ephemeral = *b;
  }
};

}  // namespace

// Paying the same request URI twice reuses memo_key; each memo must carry its own nonce.
TEST(test_confidential_memo_fresh_nonce_per_encryption) {
  MemoFixture f;
  auto m1 = wallet::encrypt_confidential_recovery_memo(500, f.blind, f.memo_key, f.one_time, f.ephemeral);
  auto m2 = wallet::encrypt_confidential_recovery_memo(500, f.blind, f.memo_key, f.one_time, f.ephemeral);
  ASSERT_TRUE(m1.has_value() && m2.has_value());
  ASSERT_TRUE(m1->size() <= kTxV2MaxMemoBytes);
  ASSERT_TRUE(!std::equal(m1->begin(), m1->begin() + wallet::kConfidentialMemoNonceLen, m2->begin()));
  ASSERT_NE(*m1, *m2);

  auto r1 = wallet::decrypt_confidential_recovery_memo(*m1, f.memo_key, f.one_time, f.ephemeral);
  auto r2 = wallet::decrypt_confidential_recovery_memo(*m2, f.memo_key, f.one_time, f.ephemeral);
  ASSERT_TRUE(r1.has_value() && r2.has_value());
  ASSERT_EQ(r1->amount, 500u);
  ASSERT_TRUE(r1->blind == f.blind);
  ASSERT_EQ(r2->amount, 500u);
  ASSERT_TRUE(r2->blind == f.blind);
}

TEST(test_confidential_memo_rejects_tamper_wrong_key_and_foreign_output) {
  MemoFixture f;
  auto m = wallet::encrypt_confidential_recovery_memo(7, f.blind, f.memo_key, f.one_time, f.ephemeral);
  ASSERT_TRUE(m.has_value());

  for (std::size_t i : {std::size_t{0}, wallet::kConfidentialMemoNonceLen, m->size() - 1}) {
    auto tampered = *m;
    tampered[i] ^= 0x01;
    ASSERT_TRUE(!wallet::decrypt_confidential_recovery_memo(tampered, f.memo_key, f.one_time, f.ephemeral));
  }
  Hash32 wrong_key = f.memo_key;
  wrong_key[0] ^= 0x01;
  ASSERT_TRUE(!wallet::decrypt_confidential_recovery_memo(*m, wrong_key, f.one_time, f.ephemeral));
  // AAD binds the memo to (one_time_pubkey, ephemeral_pubkey); it cannot be replayed onto another output.
  ASSERT_TRUE(!wallet::decrypt_confidential_recovery_memo(*m, f.memo_key, f.ephemeral, f.one_time));
  ASSERT_TRUE(!wallet::decrypt_confidential_recovery_memo(
      Bytes(wallet::kConfidentialMemoNonceLen + wallet::kConfidentialMemoTagLen - 1, 0), f.memo_key, f.one_time,
      f.ephemeral));
}
