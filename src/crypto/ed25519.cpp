// SPDX-License-Identifier: MIT

#include "crypto/ed25519.hpp"

#include <openssl/evp.h>

namespace finalis::crypto {

std::optional<KeyPair> keypair_from_seed32(const std::array<std::uint8_t, 32>& seed) {
  EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, seed.data(), seed.size());
  if (!pkey) return std::nullopt;

  KeyPair out;
  out.private_key.assign(seed.begin(), seed.end());
  size_t pub_len = out.public_key.size();
  if (EVP_PKEY_get_raw_public_key(pkey, out.public_key.data(), &pub_len) != 1 || pub_len != out.public_key.size()) {
    EVP_PKEY_free(pkey);
    return std::nullopt;
  }
  EVP_PKEY_free(pkey);
  return out;
}

std::optional<Sig64> ed25519_sign(const Bytes& msg, const Bytes& private_key_32) {
  if (private_key_32.size() != 32) return std::nullopt;

  EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, private_key_32.data(), private_key_32.size());
  if (!pkey) return std::nullopt;

  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if (!ctx) {
    EVP_PKEY_free(pkey);
    return std::nullopt;
  }

  size_t siglen = 64;
  Sig64 sig{};
  bool ok = EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, pkey) == 1 &&
            EVP_DigestSign(ctx, sig.data(), &siglen, msg.data(), msg.size()) == 1 &&
            siglen == sig.size();

  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(pkey);
  if (!ok) return std::nullopt;
  return sig;
}

bool ed25519_verify(const Bytes& msg, const Sig64& sig, const PubKey32& pubkey) {
  EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, pubkey.data(), pubkey.size());
  if (!pkey) return false;

  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if (!ctx) {
    EVP_PKEY_free(pkey);
    return false;
  }

  bool ok = EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pkey) == 1 &&
            EVP_DigestVerify(ctx, sig.data(), sig.size(), msg.data(), msg.size()) == 1;

  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(pkey);
  return ok;
}

}  // namespace finalis::crypto
