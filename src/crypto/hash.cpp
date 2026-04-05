#include "crypto/hash.hpp"

#include <openssl/evp.h>
#include <openssl/sha.h>

namespace finalis::crypto {

Hash32 sha256(const Bytes& data) {
  Hash32 out{};
  SHA256(data.data(), data.size(), out.data());
  return out;
}

Hash32 sha256d(const Bytes& data) {
  unsigned char first[SHA256_DIGEST_LENGTH];
  SHA256(data.data(), data.size(), first);
  Hash32 out{};
  SHA256(first, SHA256_DIGEST_LENGTH, out.data());
  return out;
}

std::array<std::uint8_t, 20> h160(const Bytes& data) {
  unsigned char sha[SHA256_DIGEST_LENGTH];
  SHA256(data.data(), data.size(), sha);
  std::array<std::uint8_t, 20> out{};
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if (!ctx) return out;

  const EVP_MD* ripemd = EVP_MD_fetch(nullptr, "RIPEMD160", nullptr);
  if (!ripemd) ripemd = EVP_MD_fetch(nullptr, "RIPEMD-160", nullptr);
  const bool fetched = (ripemd != nullptr);
  if (!ripemd) ripemd = EVP_ripemd160();

  unsigned int out_len = 0;
  const bool ok = ripemd && EVP_DigestInit_ex(ctx, ripemd, nullptr) == 1 &&
                  EVP_DigestUpdate(ctx, sha, SHA256_DIGEST_LENGTH) == 1 &&
                  EVP_DigestFinal_ex(ctx, out.data(), &out_len) == 1 && out_len == out.size();

  if (fetched) EVP_MD_free(const_cast<EVP_MD*>(ripemd));
  EVP_MD_CTX_free(ctx);
  if (!ok) out.fill(0);
  return out;
}

}  // namespace finalis::crypto
