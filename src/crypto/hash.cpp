// SPDX-License-Identifier: MIT

#include "crypto/hash.hpp"

#include <openssl/evp.h>
#include <openssl/ripemd.h>
#include <openssl/sha.h>

#include <stdexcept>

namespace finalis::crypto {

namespace {

// OpenSSL 3's one-shot SHA256() looks the digest up in the provider store (a locked fetch) on every
// call. Fetch it once and reuse a per-thread context instead.
const EVP_MD* sha256_md() {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
  static EVP_MD* const md = EVP_MD_fetch(nullptr, "SHA256", nullptr);  // process lifetime, never freed
  return md;
#else
  return EVP_sha256();
#endif
}

struct DigestCtx {
  EVP_MD_CTX* ctx{EVP_MD_CTX_new()};
  ~DigestCtx() { EVP_MD_CTX_free(ctx); }
};

void sha256_raw(const unsigned char* data, std::size_t len, unsigned char* out) {
  thread_local DigestCtx c;
  const EVP_MD* md = sha256_md();
  if (md == nullptr || c.ctx == nullptr || EVP_DigestInit_ex(c.ctx, md, nullptr) != 1 ||
      EVP_DigestUpdate(c.ctx, data, len) != 1 || EVP_DigestFinal_ex(c.ctx, out, nullptr) != 1) {
    throw std::runtime_error("SHA256 unavailable");
  }
}

}  // namespace

Hash32 sha256(const Bytes& data) {
  Hash32 out{};
  sha256_raw(data.data(), data.size(), out.data());
  return out;
}

Hash32 sha256d(const Bytes& data) {
  unsigned char first[SHA256_DIGEST_LENGTH];
  sha256_raw(data.data(), data.size(), first);
  Hash32 out{};
  sha256_raw(first, SHA256_DIGEST_LENGTH, out.data());
  return out;
}

std::array<std::uint8_t, 20> h160(const Bytes& data) {
  unsigned char sha[SHA256_DIGEST_LENGTH];
  sha256_raw(data.data(), data.size(), sha);
  std::array<std::uint8_t, 20> out{};

  // Address derivation must not depend on OpenSSL provider configuration.
  // On some OpenSSL 3 installs, RIPEMD-160 is unavailable through EVP fetch and
  // the old code silently returned all-zero hashes, collapsing every pubkey to
  // the same address. Use the direct RIPEMD160 primitive instead.
  // FIX: A zero hash makes unrelated public keys map to one address. Fail
  // closed if the required digest primitive is unavailable.
  if (!RIPEMD160(sha, SHA256_DIGEST_LENGTH, out.data())) throw std::runtime_error("RIPEMD160 unavailable");
  return out;
}

}  // namespace finalis::crypto
