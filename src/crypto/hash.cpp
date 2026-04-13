#include "crypto/hash.hpp"

#include <openssl/ripemd.h>
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

  // Address derivation must not depend on OpenSSL provider configuration.
  // On some OpenSSL 3 installs, RIPEMD-160 is unavailable through EVP fetch and
  // the old code silently returned all-zero hashes, collapsing every pubkey to
  // the same address. Use the direct RIPEMD160 primitive instead.
  if (!RIPEMD160(sha, SHA256_DIGEST_LENGTH, out.data())) out.fill(0);
  return out;
}

}  // namespace finalis::crypto
