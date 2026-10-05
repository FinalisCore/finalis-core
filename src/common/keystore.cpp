// SPDX-License-Identifier: MIT

#include "common/keystore.hpp"

#include <cerrno>
#include <filesystem>
#include <fstream>
#include <limits>
#include <nlohmann/json.hpp>

#include <openssl/evp.h>
#include <openssl/rand.h>

#ifndef _WIN32
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#include "common/address.hpp"
#include "common/paths.hpp"
#include "crypto/ed25519.hpp"
#include "crypto/hash.hpp"
#include "crypto/secure_memory.hpp"

namespace finalis::keystore {
namespace {

constexpr std::uint32_t kKeystoreVersion = 1;
constexpr std::uint32_t kPbkdf2Iterations = 600'000;
// Files written by earlier releases used 200k; anything below 100k is treated as tampering.
constexpr std::uint32_t kPbkdf2MinIterations = 100'000;
constexpr std::uint32_t kPbkdf2MaxIterations = 10'000'000;
constexpr std::size_t kSaltLen = 16;
constexpr std::size_t kNonceLen = 12;
constexpr std::size_t kTagLen = 16;

std::optional<std::string> json_string(const nlohmann::json& parsed, const std::string& key) {
  if (!parsed.is_object() || !parsed.contains(key) || !parsed.at(key).is_string()) return std::nullopt;
  return parsed.at(key).get<std::string>();
}

std::optional<std::uint32_t> json_u32(const nlohmann::json& parsed, const std::string& key) {
  if (!parsed.is_object() || !parsed.contains(key) || !parsed.at(key).is_number_unsigned()) return std::nullopt;
  const auto v = parsed.at(key).get<std::uint64_t>();
  if (v > std::numeric_limits<std::uint32_t>::max()) return std::nullopt;
  return static_cast<std::uint32_t>(v);
}

// Creates the file 0600 from the first byte (no umask window), fsyncs, then renames into place.
bool write_private_file_atomic(const std::string& path, const std::string& body, std::string* err) {
  const std::string tmp = path + ".tmp";
#ifdef _WIN32
  std::error_code rm_ec;
  std::filesystem::remove(tmp, rm_ec);
  {
    std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
    if (!f.good()) {
      if (err) *err = "failed to open keystore file for write";
      return false;
    }
    f << body;
    f.flush();
    if (!f.good()) {
      if (err) *err = "failed to write keystore";
      return false;
    }
  }
  std::error_code ec;
  std::filesystem::permissions(tmp, std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
                               std::filesystem::perm_options::replace, ec);
#else
  (void)::unlink(tmp.c_str());
  const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, S_IRUSR | S_IWUSR);
  if (fd < 0) {
    if (err) *err = "failed to open keystore file for write";
    return false;
  }
  std::size_t off = 0;
  while (off < body.size()) {
    const ssize_t k = ::write(fd, body.data() + off, body.size() - off);
    if (k < 0 && errno == EINTR) continue;
    if (k <= 0) break;
    off += static_cast<std::size_t>(k);
  }
  const bool ok = off == body.size() && ::fsync(fd) == 0;
  ::close(fd);
  if (!ok) {
    (void)::unlink(tmp.c_str());
    if (err) *err = "failed to write keystore";
    return false;
  }
#endif
  std::error_code ec;
  std::filesystem::rename(tmp, path, ec);
  if (ec) {
    std::filesystem::remove(tmp, ec);
    if (err) *err = "failed to move keystore into place";
    return false;
  }
  return true;
}

bool derive_key_pbkdf2(const std::string& passphrase, const Bytes& salt, std::uint32_t iterations, Bytes* out32) {
  out32->assign(32, 0);
  return PKCS5_PBKDF2_HMAC(passphrase.c_str(), static_cast<int>(passphrase.size()), salt.data(),
                           static_cast<int>(salt.size()), static_cast<int>(iterations), EVP_sha256(),
                           static_cast<int>(out32->size()), out32->data()) == 1;
}

bool aes_gcm_encrypt(const Bytes& key32, const Bytes& nonce12, const Bytes& plaintext, Bytes* out_cipher_and_tag) {
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) return false;
  int ok = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
  ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce12.size()), nullptr);
  ok = ok && EVP_EncryptInit_ex(ctx, nullptr, nullptr, key32.data(), nonce12.data());
  if (!ok) {
    EVP_CIPHER_CTX_free(ctx);
    return false;
  }
  Bytes cipher(plaintext.size() + kTagLen, 0);
  int out_len = 0;
  int total = 0;
  if (EVP_EncryptUpdate(ctx, cipher.data(), &out_len, plaintext.data(), static_cast<int>(plaintext.size())) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return false;
  }
  total += out_len;
  if (EVP_EncryptFinal_ex(ctx, cipher.data() + total, &out_len) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return false;
  }
  total += out_len;
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, static_cast<int>(kTagLen), cipher.data() + total) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return false;
  }
  total += static_cast<int>(kTagLen);
  cipher.resize(static_cast<std::size_t>(total));
  EVP_CIPHER_CTX_free(ctx);
  *out_cipher_and_tag = std::move(cipher);
  return true;
}

bool aes_gcm_decrypt(const Bytes& key32, const Bytes& nonce12, const Bytes& cipher_and_tag, Bytes* out_plaintext) {
  if (cipher_and_tag.size() < kTagLen) return false;
  const std::size_t clen = cipher_and_tag.size() - kTagLen;
  const std::uint8_t* tag = cipher_and_tag.data() + clen;

  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) return false;
  int ok = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
  ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce12.size()), nullptr);
  ok = ok && EVP_DecryptInit_ex(ctx, nullptr, nullptr, key32.data(), nonce12.data());
  if (!ok) {
    EVP_CIPHER_CTX_free(ctx);
    return false;
  }
  Bytes plain(clen, 0);
  const crypto::ScopedWipe wipe_plain(plain);  // moved out on success; wiped on every failure path
  int out_len = 0;
  int total = 0;
  if (EVP_DecryptUpdate(ctx, plain.data(), &out_len, cipher_and_tag.data(), static_cast<int>(clen)) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return false;
  }
  total += out_len;
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, static_cast<int>(kTagLen), const_cast<std::uint8_t*>(tag)) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return false;
  }
  if (EVP_DecryptFinal_ex(ctx, plain.data() + total, &out_len) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return false;
  }
  total += out_len;
  plain.resize(static_cast<std::size_t>(total));
  EVP_CIPHER_CTX_free(ctx);
  *out_plaintext = std::move(plain);
  return true;
}

bool random_bytes(Bytes* out) {
  if (out->empty()) return true;
  return RAND_bytes(out->data(), static_cast<int>(out->size())) == 1;
}

}  // namespace

bool keystore_exists(const std::string& path) {
  std::error_code ec;
  return std::filesystem::exists(path, ec);
}

std::string default_validator_keystore_path(const std::string& db_dir) {
  return db_dir + "/keystore/validator.json";
}

std::string hrp_for_network(const std::string& network_name) {
  // FIX: Testnet addresses require a distinct HRP to prevent cross-network use.
  if (network_name == "testnet" || network_name == "tsc") return "tsc";
  return "sc";
}

bool create_validator_keystore(const std::string& path, const std::string& passphrase, const std::string& network_name,
                               const std::string& hrp, const std::optional<std::array<std::uint8_t, 32>>& seed_override,
                               ValidatorKey* out, std::string* err) {
  std::array<std::uint8_t, 32> seed{};
  Bytes rand;
  Bytes key32;
  Bytes plain;
  Bytes cipher_and_tag;
  const crypto::ScopedWipe wipe(seed, rand, key32, plain, cipher_and_tag);
  if (seed_override.has_value()) {
    seed = *seed_override;
  } else {
    rand.assign(32, 0);
    if (!random_bytes(&rand)) {
      if (err) *err = "secure random generation failed";
      return false;
    }
    std::copy(rand.begin(), rand.end(), seed.begin());
  }

  auto kp = crypto::keypair_from_seed32(seed);
  if (!kp.has_value()) {
    if (err) *err = "failed to derive ed25519 keypair";
    return false;
  }
  const auto pkh = crypto::h160(Bytes(kp->public_key.begin(), kp->public_key.end()));
  auto addr = address::encode_p2pkh(hrp, pkh);
  if (!addr.has_value()) {
    if (err) *err = "failed to derive address";
    return false;
  }

  const bool encrypted = !passphrase.empty();
  Bytes salt;
  Bytes nonce;
  std::string kdf = "none";
  std::uint32_t iters = 0;
  std::string cipher_name = "none";
  if (encrypted) {
    kdf = "pbkdf2-sha256";
    iters = kPbkdf2Iterations;
    cipher_name = "aes-256-gcm";
    salt.assign(kSaltLen, 0);
    nonce.assign(kNonceLen, 0);
    if (!random_bytes(&salt) || !random_bytes(&nonce)) {
      if (err) *err = "secure random generation failed";
      return false;
    }
    if (!derive_key_pbkdf2(passphrase, salt, iters, &key32)) {
      if (err) *err = "pbkdf2 failed";
      return false;
    }
    plain.assign(seed.begin(), seed.end());
    if (!aes_gcm_encrypt(key32, nonce, plain, &cipher_and_tag)) {
      if (err) *err = "aes-gcm encrypt failed";
      return false;
    }
  } else {
    cipher_and_tag.assign(seed.begin(), seed.end());
  }

  const std::filesystem::path p = std::filesystem::path(path);
  const auto parent = p.parent_path();
  if (!parent.empty()) {
    if (!ensure_private_dir(parent.string())) {
      if (err) *err = "failed to create keystore directory";
      return false;
    }
  }

  nlohmann::ordered_json doc;
  doc["version"] = kKeystoreVersion;
  doc["network_name"] = network_name;
  doc["kdf"] = kdf;
  doc["kdf_iterations"] = iters;
  doc["salt_hex"] = hex_encode(salt);
  doc["cipher"] = cipher_name;
  doc["nonce_hex"] = hex_encode(nonce);
  doc["ciphertext_hex"] = hex_encode(cipher_and_tag);
  doc["pubkey_hex"] = hex_encode(Bytes(kp->public_key.begin(), kp->public_key.end()));
  doc["address"] = *addr;
  std::string body = doc.dump(2) + "\n";
  const crypto::ScopedWipe wipe_body(body);  // holds the plaintext seed for unencrypted keystores
  doc = nlohmann::ordered_json();

  if (!write_private_file_atomic(path, body, err)) return false;

  if (out) {
    out->privkey = seed;
    out->pubkey = kp->public_key;
    out->address = *addr;
    out->network_name = network_name;
  }
  return true;
}

bool load_validator_keystore(const std::string& path, const std::string& passphrase, ValidatorKey* out, std::string* err) {
  std::ifstream f(path, std::ios::binary);
  if (!f.good()) {
    if (err) *err = "failed to open keystore";
    return false;
  }
  std::string json((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
  f.close();
  std::optional<std::string> cipher_hex;
  Bytes cipher;
  Bytes key32;
  Bytes plain;
  std::array<std::uint8_t, 32> seed{};
  const crypto::ScopedWipe wipe(json, cipher, key32, plain, seed);
  struct WipeOptional {
    std::optional<std::string>& s;
    ~WipeOptional() {
      if (s) crypto::secure_wipe(*s);
    }
  } wipe_cipher_hex{cipher_hex};

  nlohmann::json parsed;
  try {
    parsed = nlohmann::json::parse(json);
  } catch (const nlohmann::json::exception&) {
    if (err) *err = "invalid keystore json";
    return false;
  }
  struct WipeJson {
    nlohmann::json& j;
    ~WipeJson() {
      if (j.is_object() && j.contains("ciphertext_hex") && j["ciphertext_hex"].is_string()) {
        crypto::secure_wipe(j["ciphertext_hex"].get_ref<std::string&>());
      }
    }
  } wipe_parsed{parsed};

  const auto version = json_u32(parsed, "version");
  const auto network_name = json_string(parsed, "network_name");
  const auto kdf = json_string(parsed, "kdf");
  const auto cipher_name = json_string(parsed, "cipher");
  const auto iter = json_u32(parsed, "kdf_iterations");
  const auto salt_hex = json_string(parsed, "salt_hex");
  const auto nonce_hex = json_string(parsed, "nonce_hex");
  cipher_hex = json_string(parsed, "ciphertext_hex");
  const auto pub_hex = json_string(parsed, "pubkey_hex");
  const auto address = json_string(parsed, "address");
  if (!version || !network_name || !kdf || !cipher_name || !iter || !salt_hex || !nonce_hex || !cipher_hex || !pub_hex ||
      !address) {
    if (err) *err = "invalid keystore json";
    return false;
  }
  if (*version != kKeystoreVersion) {
    if (err) *err = "unsupported keystore version";
    return false;
  }

  auto salt = hex_decode(*salt_hex);
  auto nonce = hex_decode(*nonce_hex);
  auto cipher_opt = hex_decode(*cipher_hex);
  auto pub = hex_decode(*pub_hex);
  if (cipher_opt) {
    cipher = std::move(*cipher_opt);
    crypto::secure_wipe(*cipher_opt);
  }
  if (!salt || !nonce || !cipher_opt || !pub || pub->size() != 32) {
    if (err) *err = "invalid keystore fields";
    return false;
  }

  if (*kdf == "none" && *cipher_name == "none") {
    if (cipher.size() != 32) {
      if (err) *err = "invalid unencrypted keystore payload";
      return false;
    }
    plain = cipher;
  } else if (*kdf == "pbkdf2-sha256" && *cipher_name == "aes-256-gcm") {
    if (passphrase.empty()) {
      if (err) *err = "passphrase required for encrypted keystore";
      return false;
    }
    if (salt->size() != kSaltLen || nonce->size() != kNonceLen) {
      if (err) *err = "invalid encrypted keystore fields";
      return false;
    }
    // SECURITY: the iteration count is read from the file; refuse downgraded or absurd values.
    if (*iter < kPbkdf2MinIterations || *iter > kPbkdf2MaxIterations) {
      if (err) *err = "keystore kdf_iterations out of range";
      return false;
    }
    if (!derive_key_pbkdf2(passphrase, *salt, *iter, &key32)) {
      if (err) *err = "pbkdf2 failed";
      return false;
    }

    if (!aes_gcm_decrypt(key32, *nonce, cipher, &plain) || plain.size() != 32) {
      if (err) *err = "invalid passphrase or corrupted keystore";
      return false;
    }
  } else {
    if (err) *err = "unsupported keystore kdf/cipher";
    return false;
  }

  std::copy(plain.begin(), plain.end(), seed.begin());
  auto kp = crypto::keypair_from_seed32(seed);
  if (!kp) {
    if (err) *err = "failed to derive key from decrypted seed";
    return false;
  }
  PubKey32 stored{};
  std::copy(pub->begin(), pub->end(), stored.begin());
  if (kp->public_key != stored) {
    if (err) *err = "pubkey mismatch: wrong passphrase or corrupted keystore";
    return false;
  }

  if (out) {
    out->privkey = seed;
    out->pubkey = kp->public_key;
    out->address = *address;
    out->network_name = *network_name;
  }
  return true;
}

bool keystore_is_encrypted(const std::string& path) {
  std::ifstream f(path, std::ios::binary);
  if (!f.good()) return false;
  std::string json((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
  const crypto::ScopedWipe wipe(json);
  try {
    auto parsed = nlohmann::json::parse(json);
    const auto kdf = json_string(parsed, "kdf");
    if (parsed.is_object() && parsed.contains("ciphertext_hex") && parsed["ciphertext_hex"].is_string()) {
      crypto::secure_wipe(parsed["ciphertext_hex"].get_ref<std::string&>());
    }
    return kdf.has_value() && *kdf != "none";
  } catch (const nlohmann::json::exception&) {
    return false;
  }
}

}  // namespace finalis::keystore
