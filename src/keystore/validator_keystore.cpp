#include "keystore/validator_keystore.hpp"

#include <filesystem>
#include <fstream>
#include <regex>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include "address/address.hpp"
#include "common/paths.hpp"
#include "crypto/ed25519.hpp"
#include "crypto/hash.hpp"

namespace finalis::keystore {
namespace {

constexpr std::uint32_t kKeystoreVersion = 1;
constexpr std::uint32_t kPbkdf2Iterations = 200'000;
constexpr std::size_t kSaltLen = 16;
constexpr std::size_t kNonceLen = 12;
constexpr std::size_t kTagLen = 16;

std::optional<std::string> find_json_string(const std::string& json, const std::string& key) {
  std::regex re("\"" + key + "\"\\s*:\\s*\"([^\"]*)\"");
  std::smatch m;
  if (!std::regex_search(json, m, re)) return std::nullopt;
  return m[1].str();
}

std::optional<std::uint32_t> find_json_u32(const std::string& json, const std::string& key) {
  std::regex re("\"" + key + "\"\\s*:\\s*([0-9]+)");
  std::smatch m;
  if (!std::regex_search(json, m, re)) return std::nullopt;
  return static_cast<std::uint32_t>(std::stoul(m[1].str()));
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
  (void)network_name;
  return "sc";
}

bool create_validator_keystore(const std::string& path, const std::string& passphrase, const std::string& network_name,
                               const std::string& hrp, const std::optional<std::array<std::uint8_t, 32>>& seed_override,
                               ValidatorKey* out, std::string* err) {
  std::array<std::uint8_t, 32> seed{};
  if (seed_override.has_value()) {
    seed = *seed_override;
  } else {
    Bytes rand(32, 0);
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
  Bytes cipher_and_tag;
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
    Bytes key32;
    if (!derive_key_pbkdf2(passphrase, salt, iters, &key32)) {
      if (err) *err = "pbkdf2 failed";
      return false;
    }
    Bytes plain(seed.begin(), seed.end());
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

  std::ofstream f(path, std::ios::binary | std::ios::trunc);
  if (!f.good()) {
    if (err) *err = "failed to open keystore file for write";
    return false;
  }
  f << "{\n";
  f << "  \"version\": " << kKeystoreVersion << ",\n";
  f << "  \"network_name\": \"" << network_name << "\",\n";
  f << "  \"kdf\": \"" << kdf << "\",\n";
  f << "  \"kdf_iterations\": " << iters << ",\n";
  f << "  \"salt_hex\": \"" << hex_encode(salt) << "\",\n";
  f << "  \"cipher\": \"" << cipher_name << "\",\n";
  f << "  \"nonce_hex\": \"" << hex_encode(nonce) << "\",\n";
  f << "  \"ciphertext_hex\": \"" << hex_encode(cipher_and_tag) << "\",\n";
  f << "  \"pubkey_hex\": \"" << hex_encode(Bytes(kp->public_key.begin(), kp->public_key.end())) << "\",\n";
  f << "  \"address\": \"" << *addr << "\"\n";
  f << "}\n";
  if (!f.good()) {
    if (err) *err = "failed to write keystore";
    return false;
  }

  std::error_code ec;
  std::filesystem::permissions(path, std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
                               std::filesystem::perm_options::replace, ec);

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
  const std::string json((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());

  const auto version = find_json_u32(json, "version");
  const auto network_name = find_json_string(json, "network_name");
  const auto kdf = find_json_string(json, "kdf");
  const auto cipher_name = find_json_string(json, "cipher");
  const auto iter = find_json_u32(json, "kdf_iterations");
  const auto salt_hex = find_json_string(json, "salt_hex");
  const auto nonce_hex = find_json_string(json, "nonce_hex");
  const auto cipher_hex = find_json_string(json, "ciphertext_hex");
  const auto pub_hex = find_json_string(json, "pubkey_hex");
  const auto address = find_json_string(json, "address");
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
  auto cipher = hex_decode(*cipher_hex);
  auto pub = hex_decode(*pub_hex);
  if (!salt || !nonce || !cipher || !pub || pub->size() != 32) {
    if (err) *err = "invalid keystore fields";
    return false;
  }

  Bytes plain;
  if (*kdf == "none" && *cipher_name == "none") {
    if (cipher->size() != 32) {
      if (err) *err = "invalid unencrypted keystore payload";
      return false;
    }
    plain = *cipher;
  } else {
    if (passphrase.empty()) {
      if (err) *err = "passphrase required for encrypted keystore";
      return false;
    }
    if (salt->size() != kSaltLen || nonce->size() != kNonceLen) {
      if (err) *err = "invalid encrypted keystore fields";
      return false;
    }
    Bytes key32;
    if (!derive_key_pbkdf2(passphrase, *salt, *iter, &key32)) {
      if (err) *err = "pbkdf2 failed";
      return false;
    }

    if (!aes_gcm_decrypt(key32, *nonce, *cipher, &plain) || plain.size() != 32) {
      if (err) *err = "invalid passphrase or corrupted keystore";
      return false;
    }
  }

  std::array<std::uint8_t, 32> seed{};
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

}  // namespace finalis::keystore
