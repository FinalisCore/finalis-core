// SPDX-License-Identifier: MIT

#include "confidential_memo.hpp"

#include <openssl/evp.h>

#include "codec/bytes.hpp"
#include "crypto/secure_memory.hpp"
#include "wallet/confidential_keys.hpp"

namespace finalis::wallet {
namespace {

Bytes memo_aad(const PubKey33& one_time_pubkey, const PubKey33& ephemeral_pubkey) {
  Bytes aad(one_time_pubkey.begin(), one_time_pubkey.end());
  aad.insert(aad.end(), ephemeral_pubkey.begin(), ephemeral_pubkey.end());
  return aad;
}

struct CipherCtx {
  EVP_CIPHER_CTX* ctx{EVP_CIPHER_CTX_new()};
  ~CipherCtx() { EVP_CIPHER_CTX_free(ctx); }  // _free cleanses the expanded key schedule
};

bool aes_gcm_encrypt(const Hash32& key, const std::uint8_t* nonce, const Bytes& aad, const Bytes& plaintext,
                     std::uint8_t* out_cipher, std::uint8_t* out_tag) {
  CipherCtx c;
  if (!c.ctx) return false;
  int len = 0;
  if (EVP_EncryptInit_ex(c.ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
      EVP_CIPHER_CTX_ctrl(c.ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(kConfidentialMemoNonceLen), nullptr) != 1 ||
      EVP_EncryptInit_ex(c.ctx, nullptr, nullptr, key.data(), nonce) != 1 ||
      EVP_EncryptUpdate(c.ctx, nullptr, &len, aad.data(), static_cast<int>(aad.size())) != 1 ||
      EVP_EncryptUpdate(c.ctx, out_cipher, &len, plaintext.data(), static_cast<int>(plaintext.size())) != 1 ||
      EVP_EncryptFinal_ex(c.ctx, out_cipher + len, &len) != 1 ||
      EVP_CIPHER_CTX_ctrl(c.ctx, EVP_CTRL_GCM_GET_TAG, static_cast<int>(kConfidentialMemoTagLen), out_tag) != 1) {
    return false;
  }
  return true;
}

bool aes_gcm_decrypt(const Hash32& key, const std::uint8_t* nonce, const Bytes& aad, const std::uint8_t* cipher,
                     std::size_t cipher_len, const std::uint8_t* tag, Bytes* out_plaintext) {
  CipherCtx c;
  if (!c.ctx) return false;
  out_plaintext->assign(cipher_len, 0);
  int len = 0;
  if (EVP_DecryptInit_ex(c.ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
      EVP_CIPHER_CTX_ctrl(c.ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(kConfidentialMemoNonceLen), nullptr) != 1 ||
      EVP_DecryptInit_ex(c.ctx, nullptr, nullptr, key.data(), nonce) != 1 ||
      EVP_DecryptUpdate(c.ctx, nullptr, &len, aad.data(), static_cast<int>(aad.size())) != 1 ||
      EVP_DecryptUpdate(c.ctx, out_plaintext->data(), &len, cipher, static_cast<int>(cipher_len)) != 1 ||
      EVP_CIPHER_CTX_ctrl(c.ctx, EVP_CTRL_GCM_SET_TAG, static_cast<int>(kConfidentialMemoTagLen),
                          const_cast<std::uint8_t*>(tag)) != 1 ||
      EVP_DecryptFinal_ex(c.ctx, out_plaintext->data() + len, &len) != 1) {
    crypto::secure_wipe(*out_plaintext);
    return false;
  }
  return true;
}

}  // namespace

std::optional<Bytes> encrypt_confidential_recovery_memo(std::uint64_t amount, const Hash32& blind_seed,
                                                        const Hash32& memo_key, const PubKey33& one_time_pubkey,
                                                        const PubKey33& ephemeral_pubkey) {
  codec::ByteWriter w;
  w.u32le(kConfidentialRecoveryMemoVersion);
  w.u64le(amount);
  w.bytes_fixed(blind_seed);
  Bytes plain = w.take();
  crypto::ScopedWipe<Bytes> wipe_plain(plain);

  Bytes out(kConfidentialMemoNonceLen + plain.size() + kConfidentialMemoTagLen, 0);
  std::uint8_t* nonce = out.data();
  std::uint8_t* cipher = nonce + kConfidentialMemoNonceLen;
  std::uint8_t* tag = cipher + plain.size();
  if (!crypto::secure_random_bytes(nonce, kConfidentialMemoNonceLen)) return std::nullopt;
  if (!aes_gcm_encrypt(memo_key, nonce, memo_aad(one_time_pubkey, ephemeral_pubkey), plain, cipher, tag)) {
    return std::nullopt;
  }
  return out;
}

std::optional<ConfidentialRecoveryPayload> decrypt_confidential_recovery_memo(const Bytes& memo, const Hash32& memo_key,
                                                                              const PubKey33& one_time_pubkey,
                                                                              const PubKey33& ephemeral_pubkey) {
  if (memo.size() < kConfidentialMemoNonceLen + kConfidentialMemoTagLen) return std::nullopt;
  const std::uint8_t* nonce = memo.data();
  const std::uint8_t* cipher = nonce + kConfidentialMemoNonceLen;
  const std::size_t cipher_len = memo.size() - kConfidentialMemoNonceLen - kConfidentialMemoTagLen;
  const std::uint8_t* tag = cipher + cipher_len;
  Bytes plain;
  crypto::ScopedWipe<Bytes> wipe_plain(plain);
  if (!aes_gcm_decrypt(memo_key, nonce, memo_aad(one_time_pubkey, ephemeral_pubkey), cipher, cipher_len, tag, &plain)) {
    return std::nullopt;
  }
  ConfidentialRecoveryPayload out;
  if (!codec::parse_exact(plain, [&](codec::ByteReader& r) {
        auto version = r.u32le();
        auto amount = r.u64le();
        auto seed = r.bytes_fixed<32>();
        if (!version || !amount || !seed) return false;
        if (*version != kConfidentialRecoveryMemoVersion) return false;
        out.amount = *amount;
        std::copy(seed->begin(), seed->end(), out.blind_seed.begin());
        crypto::secure_wipe(*seed);
        return true;
      })) {
    crypto::secure_wipe(out.blind_seed);
    return std::nullopt;
  }
  auto blind = derive_output_value_blind(out.blind_seed, one_time_pubkey);
  if (!blind) {
    crypto::secure_wipe(out.blind_seed);
    return std::nullopt;
  }
  out.blind = *blind;
  crypto::secure_wipe(blind->bytes);
  return out;
}

}  // namespace finalis::wallet
