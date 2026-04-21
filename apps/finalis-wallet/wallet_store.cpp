// SPDX-License-Identifier: MIT

#include "wallet_store.hpp"

#include <cstdio>
#include <algorithm>
#include <filesystem>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include "codec/bytes.hpp"

namespace finalis::wallet {
namespace {

constexpr std::uint32_t kConfidentialWalletRecordVersion = 1;
constexpr std::uint32_t kConfidentialWalletPbkdf2Iterations = 200'000;
constexpr std::size_t kWalletSaltLen = 16;
constexpr std::size_t kWalletNonceLen = 12;
constexpr std::size_t kWalletTagLen = 16;
constexpr std::size_t kMaxPendingTxStatusRecords = 64;
constexpr std::uint64_t kPendingTxStatusRetentionMs = 7ull * 24ull * 60ull * 60ull * 1000ull;

Bytes to_bytes(const std::string& value) { return Bytes(value.begin(), value.end()); }

std::string from_bytes(const Bytes& value) { return std::string(value.begin(), value.end()); }

std::string key_sent(const std::string& txid) { return "SENT:" + txid; }
std::string key_pending(const std::string& txid) { return "PEND:" + txid; }
std::string key_event_seq() { return "EVT:SEQ"; }
std::string key_history_seq() { return "HIST:SEQ"; }
std::string key_event(std::uint64_t seq) {
  char buf[32];
  std::snprintf(buf, sizeof(buf), "EVT:%020llu", static_cast<unsigned long long>(seq));
  return std::string(buf);
}
std::string key_history(std::uint64_t seq) {
  char buf[32];
  std::snprintf(buf, sizeof(buf), "HIST:%020llu", static_cast<unsigned long long>(seq));
  return std::string(buf);
}
std::string key_note(const std::string& note_ref) { return "NOTE:" + note_ref; }
std::string key_meta(const std::string& name) { return "META:" + name; }
std::string key_snapshot() { return "SNAPSHOT:wallet"; }
std::string key_view_snapshot() { return "SNAPSHOT:view"; }
std::string key_pending_tx_status(const std::string& txid_hex) { return "PENDINGTX:" + txid_hex; }
std::string key_confidential_account(const std::string& account_id) { return "CACCT:" + account_id; }
std::string key_confidential_coin(const std::string& txid_hex, std::uint32_t vout) {
  char buf[32];
  std::snprintf(buf, sizeof(buf), "%08x", vout);
  return "CCOIN:" + txid_hex + ":" + buf;
}
std::string key_confidential_request(const std::string& request_id) { return "CREQ:" + request_id; }

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
  Bytes cipher(plaintext.size() + kWalletTagLen, 0);
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
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, static_cast<int>(kWalletTagLen), cipher.data() + total) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return false;
  }
  total += static_cast<int>(kWalletTagLen);
  cipher.resize(static_cast<std::size_t>(total));
  EVP_CIPHER_CTX_free(ctx);
  *out_cipher_and_tag = std::move(cipher);
  return true;
}

bool aes_gcm_decrypt(const Bytes& key32, const Bytes& nonce12, const Bytes& cipher_and_tag, Bytes* out_plaintext) {
  if (cipher_and_tag.size() < kWalletTagLen) return false;
  const std::size_t clen = cipher_and_tag.size() - kWalletTagLen;
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
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, static_cast<int>(kWalletTagLen), const_cast<std::uint8_t*>(tag)) != 1) {
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

Bytes serialize_pending_spend(const WalletStore::PendingSpend& pending) {
  codec::ByteWriter w;
  w.u32le(static_cast<std::uint32_t>(pending.inputs.size()));
  for (const auto& input : pending.inputs) {
    w.bytes_fixed(input.txid);
    w.u32le(input.index);
  }
  w.u64le(pending.created_tip_height);
  w.u64le(pending.created_unix_ms);
  return w.take();
}

std::optional<WalletStore::PendingSpend> parse_pending_spend(const std::string& txid_hex, const Bytes& value) {
  WalletStore::PendingSpend out;
  out.txid_hex = txid_hex;
  codec::ByteReader r(value);
  auto count = r.u32le();
  if (!count) return std::nullopt;
  out.inputs.reserve(*count);
  for (std::uint32_t i = 0; i < *count; ++i) {
    auto txid = r.bytes_fixed<32>();
    auto index = r.u32le();
    if (!txid || !index) return std::nullopt;
    out.inputs.push_back(OutPoint{*txid, *index});
  }
  if (r.remaining() == 16) {
    auto created_tip_height = r.u64le();
    auto created_unix_ms = r.u64le();
    if (!created_tip_height || !created_unix_ms) return std::nullopt;
    out.created_tip_height = *created_tip_height;
    out.created_unix_ms = *created_unix_ms;
  } else if (!r.eof()) {
    return std::nullopt;
  }
  return out;
}

Bytes serialize_finalized_history_record(const WalletStore::FinalizedHistoryRecord& record) {
  codec::ByteWriter w;
  w.u64le(record.height);
  w.varbytes(to_bytes(record.txid_hex));
  w.varbytes(to_bytes(record.kind));
  w.varbytes(to_bytes(record.detail));
  return w.take();
}

std::optional<WalletStore::FinalizedHistoryRecord> parse_finalized_history_record(const Bytes& value) {
  WalletStore::FinalizedHistoryRecord out;
  if (!codec::parse_exact(value, [&](codec::ByteReader& r) {
        auto height = r.u64le();
        auto txid = r.varbytes();
        auto kind = r.varbytes();
        auto detail = r.varbytes();
        if (!height || !txid || !kind || !detail) return false;
        out.height = *height;
        out.txid_hex = from_bytes(*txid);
        out.kind = from_bytes(*kind);
        out.detail = from_bytes(*detail);
        return true;
      })) {
    return std::nullopt;
  }
  return out;
}

Bytes serialize_wallet_snapshot(const WalletStore::WalletSnapshot& snapshot) {
  codec::ByteWriter w;
  w.u32le(kConfidentialWalletRecordVersion);
  w.varbytes(to_bytes(snapshot.chain_network_name));
  w.varbytes(to_bytes(snapshot.transition_hash));
  w.varbytes(to_bytes(snapshot.network_id_hex));
  w.varbytes(to_bytes(snapshot.genesis_hash_hex));
  w.varbytes(to_bytes(snapshot.binary_version));
  w.varbytes(to_bytes(snapshot.wallet_api_version));
  w.varbytes(to_bytes(snapshot.last_refresh_text));
  w.varbytes(to_bytes(snapshot.last_successful_endpoint));
  w.u64le(snapshot.tip_height);
  w.u8(snapshot.finalized_lag.has_value() ? 1 : 0);
  if (snapshot.finalized_lag.has_value()) w.u64le(*snapshot.finalized_lag);
  w.u8(snapshot.peer_height_disagreement ? 1 : 0);
  w.u8(snapshot.bootstrap_sync_incomplete ? 1 : 0);
  w.u32le(static_cast<std::uint32_t>(snapshot.utxos.size()));
  for (const auto& utxo : snapshot.utxos) {
    w.varbytes(to_bytes(utxo.txid_hex));
    w.u32le(utxo.vout);
    w.u64le(utxo.value);
    w.u64le(utxo.height);
    w.varbytes(utxo.script_pubkey);
  }
  return w.take();
}

std::optional<WalletStore::WalletSnapshot> parse_wallet_snapshot(const Bytes& value) {
  WalletStore::WalletSnapshot out;
  if (!codec::parse_exact(value, [&](codec::ByteReader& r) {
        auto version = r.u32le();
        auto chain_network_name = r.varbytes();
        auto transition_hash = r.varbytes();
        auto network_id_hex = r.varbytes();
        auto genesis_hash_hex = r.varbytes();
        auto binary_version = r.varbytes();
        auto wallet_api_version = r.varbytes();
        auto last_refresh_text = r.varbytes();
        auto last_successful_endpoint = r.varbytes();
        auto tip_height = r.u64le();
        auto has_finalized_lag = r.u8();
        if (!version || !chain_network_name || !transition_hash || !network_id_hex || !genesis_hash_hex ||
            !binary_version || !wallet_api_version || !last_refresh_text || !last_successful_endpoint ||
            !tip_height || !has_finalized_lag) {
          return false;
        }
        if (*version != kConfidentialWalletRecordVersion) return false;
        out.chain_network_name = from_bytes(*chain_network_name);
        out.transition_hash = from_bytes(*transition_hash);
        out.network_id_hex = from_bytes(*network_id_hex);
        out.genesis_hash_hex = from_bytes(*genesis_hash_hex);
        out.binary_version = from_bytes(*binary_version);
        out.wallet_api_version = from_bytes(*wallet_api_version);
        out.last_refresh_text = from_bytes(*last_refresh_text);
        out.last_successful_endpoint = from_bytes(*last_successful_endpoint);
        out.tip_height = *tip_height;
        if (*has_finalized_lag != 0) {
          auto finalized_lag = r.u64le();
          if (!finalized_lag) return false;
          out.finalized_lag = *finalized_lag;
        }
        auto peer_height_disagreement = r.u8();
        auto bootstrap_sync_incomplete = r.u8();
        auto utxo_count = r.u32le();
        if (!peer_height_disagreement || !bootstrap_sync_incomplete || !utxo_count) return false;
        out.peer_height_disagreement = (*peer_height_disagreement != 0);
        out.bootstrap_sync_incomplete = (*bootstrap_sync_incomplete != 0);
        out.utxos.reserve(*utxo_count);
        for (std::uint32_t i = 0; i < *utxo_count; ++i) {
          auto txid_hex = r.varbytes();
          auto vout = r.u32le();
          auto amount = r.u64le();
          auto height = r.u64le();
          auto script_pubkey = r.varbytes();
          if (!txid_hex || !vout || !amount || !height || !script_pubkey) return false;
          out.utxos.push_back(WalletStore::SnapshotUtxoRecord{
              .txid_hex = from_bytes(*txid_hex),
              .vout = *vout,
              .value = *amount,
              .height = *height,
              .script_pubkey = *script_pubkey,
          });
        }
        return true;
      })) {
    return std::nullopt;
  }
  return out;
}

Bytes serialize_wallet_view_snapshot(const WalletStore::WalletViewSnapshot& snapshot) {
  codec::ByteWriter w;
  w.u32le(kConfidentialWalletRecordVersion);
  w.varbytes(to_bytes(snapshot.balance_text));
  w.varbytes(to_bytes(snapshot.pending_balance_text));
  w.varbytes(to_bytes(snapshot.confidential_balance_text));
  w.varbytes(to_bytes(snapshot.confidential_request_summary_text));
  w.varbytes(to_bytes(snapshot.confidential_coin_summary_text));
  w.varbytes(to_bytes(snapshot.activity_finalized_count_text));
  w.varbytes(to_bytes(snapshot.activity_pending_count_text));
  w.varbytes(to_bytes(snapshot.activity_local_count_text));
  w.varbytes(to_bytes(snapshot.activity_mint_count_text));
  w.varbytes(to_bytes(snapshot.activity_confidential_count_text));
  auto write_rows = [&](const std::vector<WalletStore::ViewSnapshotRow>& rows) {
    w.u32le(static_cast<std::uint32_t>(rows.size()));
    for (const auto& row : rows) {
      w.varbytes(to_bytes(row.col0));
      w.varbytes(to_bytes(row.col1));
      w.varbytes(to_bytes(row.col2));
      w.varbytes(to_bytes(row.col3));
      w.varbytes(to_bytes(row.col4));
    }
  };
  write_rows(snapshot.overview_activity_rows);
  write_rows(snapshot.history_rows);
  return w.take();
}

std::optional<WalletStore::WalletViewSnapshot> parse_wallet_view_snapshot(const Bytes& value) {
  WalletStore::WalletViewSnapshot out;
  if (!codec::parse_exact(value, [&](codec::ByteReader& r) {
        auto version = r.u32le();
        auto balance_text = r.varbytes();
        auto pending_balance_text = r.varbytes();
        auto confidential_balance_text = r.varbytes();
        auto confidential_request_summary_text = r.varbytes();
        auto confidential_coin_summary_text = r.varbytes();
        auto activity_finalized_count_text = r.varbytes();
        auto activity_pending_count_text = r.varbytes();
        auto activity_local_count_text = r.varbytes();
        auto activity_mint_count_text = r.varbytes();
        auto activity_confidential_count_text = r.varbytes();
        if (!version || !balance_text || !pending_balance_text || !confidential_balance_text ||
            !confidential_request_summary_text || !confidential_coin_summary_text || !activity_finalized_count_text ||
            !activity_pending_count_text || !activity_local_count_text || !activity_mint_count_text ||
            !activity_confidential_count_text) {
          return false;
        }
        if (*version != kConfidentialWalletRecordVersion) return false;
        out.balance_text = from_bytes(*balance_text);
        out.pending_balance_text = from_bytes(*pending_balance_text);
        out.confidential_balance_text = from_bytes(*confidential_balance_text);
        out.confidential_request_summary_text = from_bytes(*confidential_request_summary_text);
        out.confidential_coin_summary_text = from_bytes(*confidential_coin_summary_text);
        out.activity_finalized_count_text = from_bytes(*activity_finalized_count_text);
        out.activity_pending_count_text = from_bytes(*activity_pending_count_text);
        out.activity_local_count_text = from_bytes(*activity_local_count_text);
        out.activity_mint_count_text = from_bytes(*activity_mint_count_text);
        out.activity_confidential_count_text = from_bytes(*activity_confidential_count_text);
        auto read_rows = [&](std::vector<WalletStore::ViewSnapshotRow>* rows) -> bool {
          auto count = r.u32le();
          if (!count) return false;
          rows->reserve(*count);
          for (std::uint32_t i = 0; i < *count; ++i) {
            auto col0 = r.varbytes();
            auto col1 = r.varbytes();
            auto col2 = r.varbytes();
            auto col3 = r.varbytes();
            auto col4 = r.varbytes();
            if (!col0 || !col1 || !col2 || !col3 || !col4) return false;
            rows->push_back(WalletStore::ViewSnapshotRow{
                .col0 = from_bytes(*col0),
                .col1 = from_bytes(*col1),
                .col2 = from_bytes(*col2),
                .col3 = from_bytes(*col3),
                .col4 = from_bytes(*col4),
            });
          }
          return true;
        };
        return read_rows(&out.overview_activity_rows) && read_rows(&out.history_rows);
      })) {
    return std::nullopt;
  }
  return out;
}

Bytes serialize_pending_tx_status_record(const WalletStore::PendingTxStatusRecord& record) {
  codec::ByteWriter w;
  w.u32le(kConfidentialWalletRecordVersion);
  w.varbytes(to_bytes(record.txid_hex));
  w.varbytes(to_bytes(record.endpoint));
  w.varbytes(to_bytes(record.cached_at));
  w.u64le(record.cached_at_ms);
  w.varbytes(to_bytes(record.status));
  w.u8(record.finalized ? 1 : 0);
  w.u64le(record.height);
  w.u64le(record.finalized_depth);
  w.u8(record.credit_safe ? 1 : 0);
  w.varbytes(to_bytes(record.transition_hash));
  return w.take();
}

std::optional<WalletStore::PendingTxStatusRecord> parse_pending_tx_status_record(const Bytes& value) {
  WalletStore::PendingTxStatusRecord out;
  if (!codec::parse_exact(value, [&](codec::ByteReader& r) {
        auto version = r.u32le();
        auto txid_hex = r.varbytes();
        auto endpoint = r.varbytes();
        auto cached_at = r.varbytes();
        auto cached_at_ms = r.u64le();
        auto status = r.varbytes();
        auto finalized = r.u8();
        auto height = r.u64le();
        auto finalized_depth = r.u64le();
        auto credit_safe = r.u8();
        auto transition_hash = r.varbytes();
        if (!version || !txid_hex || !endpoint || !cached_at || !cached_at_ms || !status || !finalized || !height ||
            !finalized_depth || !credit_safe || !transition_hash) {
          return false;
        }
        if (*version != kConfidentialWalletRecordVersion) return false;
        out.txid_hex = from_bytes(*txid_hex);
        out.endpoint = from_bytes(*endpoint);
        out.cached_at = from_bytes(*cached_at);
        out.cached_at_ms = *cached_at_ms;
        out.status = from_bytes(*status);
        out.finalized = (*finalized != 0);
        out.height = *height;
        out.finalized_depth = *finalized_depth;
        out.credit_safe = (*credit_safe != 0);
        out.transition_hash = from_bytes(*transition_hash);
        return true;
      })) {
    return std::nullopt;
  }
  return out;
}

Bytes serialize_note(std::uint64_t amount, bool active) {
  codec::ByteWriter w;
  w.u64le(amount);
  w.u8(active ? 1 : 0);
  return w.take();
}

std::optional<std::pair<std::uint64_t, bool>> parse_note(const Bytes& value) {
  std::pair<std::uint64_t, bool> out{};
  if (!codec::parse_exact(value, [&](codec::ByteReader& r) {
        auto amount = r.u64le();
        auto active = r.u8();
        if (!amount || !active) return false;
        out.first = *amount;
        out.second = (*active != 0);
        return true;
      })) {
    return std::nullopt;
  }
  return out;
}

Bytes serialize_confidential_account_plain(const WalletStore::ConfidentialAccountRecord& record) {
  codec::ByteWriter w;
  w.u32le(kConfidentialWalletRecordVersion);
  w.varbytes(to_bytes(record.account_id));
  w.varbytes(to_bytes(record.label));
  w.varbytes(to_bytes(record.stealth_address));
  w.varbytes(to_bytes(record.view_key_material_hex));
  w.varbytes(to_bytes(record.spend_key_material_hex));
  w.u8(record.active ? 1 : 0);
  return w.take();
}

std::optional<WalletStore::ConfidentialAccountRecord> parse_confidential_account_plain(const Bytes& value) {
  WalletStore::ConfidentialAccountRecord out;
  if (!codec::parse_exact(value, [&](codec::ByteReader& r) {
        auto version = r.u32le();
        auto account_id = r.varbytes();
        auto label = r.varbytes();
        auto stealth_address = r.varbytes();
        auto view_key_material = r.varbytes();
        auto spend_key_material = r.varbytes();
        auto active = r.u8();
        if (!version || !account_id || !label || !stealth_address || !view_key_material || !spend_key_material || !active) {
          return false;
        }
        if (*version != kConfidentialWalletRecordVersion) return false;
        out.account_id = from_bytes(*account_id);
        out.label = from_bytes(*label);
        out.stealth_address = from_bytes(*stealth_address);
        out.view_key_material_hex = from_bytes(*view_key_material);
        out.spend_key_material_hex = from_bytes(*spend_key_material);
        out.active = (*active != 0);
        return true;
      })) {
    return std::nullopt;
  }
  return out;
}

Bytes serialize_confidential_coin_plain(const WalletStore::ConfidentialCoinRecord& record) {
  codec::ByteWriter w;
  w.u32le(kConfidentialWalletRecordVersion);
  w.varbytes(to_bytes(record.txid_hex));
  w.u32le(record.vout);
  w.varbytes(to_bytes(record.account_id));
  w.u64le(record.amount);
  w.varbytes(to_bytes(record.value_commitment_hex));
  w.varbytes(to_bytes(record.one_time_pubkey_hex));
  w.varbytes(to_bytes(record.ephemeral_pubkey_hex));
  w.varbytes(to_bytes(record.spend_secret_hex));
  w.varbytes(to_bytes(record.blinding_factor_hex));
  w.u8(record.spent ? 1 : 0);
  return w.take();
}

std::optional<WalletStore::ConfidentialCoinRecord> parse_confidential_coin_plain(const Bytes& value) {
  WalletStore::ConfidentialCoinRecord out;
  if (!codec::parse_exact(value, [&](codec::ByteReader& r) {
        auto version = r.u32le();
        auto txid_hex = r.varbytes();
        auto vout = r.u32le();
        auto account_id = r.varbytes();
        auto amount = r.u64le();
        auto commitment = r.varbytes();
        auto one_time = r.varbytes();
        auto ephemeral = r.varbytes();
        auto spend_secret = r.varbytes();
        auto blinding = r.varbytes();
        auto spent = r.u8();
        if (!version || !txid_hex || !vout || !account_id || !amount || !commitment || !one_time || !ephemeral ||
            !spend_secret || !blinding || !spent) {
          return false;
        }
        if (*version != kConfidentialWalletRecordVersion) return false;
        out.txid_hex = from_bytes(*txid_hex);
        out.vout = *vout;
        out.account_id = from_bytes(*account_id);
        out.amount = *amount;
        out.value_commitment_hex = from_bytes(*commitment);
        out.one_time_pubkey_hex = from_bytes(*one_time);
        out.ephemeral_pubkey_hex = from_bytes(*ephemeral);
        out.spend_secret_hex = from_bytes(*spend_secret);
        out.blinding_factor_hex = from_bytes(*blinding);
        out.spent = (*spent != 0);
        return true;
      })) {
    return std::nullopt;
  }
  return out;
}

Bytes serialize_confidential_request_plain(const WalletStore::ConfidentialRequestRecord& record) {
  codec::ByteWriter w;
  w.u32le(kConfidentialWalletRecordVersion);
  w.varbytes(to_bytes(record.request_id));
  w.varbytes(to_bytes(record.account_id));
  w.varbytes(to_bytes(record.one_time_pubkey_hex));
  w.varbytes(to_bytes(record.ephemeral_pubkey_hex));
  w.u8(record.scan_tag);
  w.varbytes(to_bytes(record.spend_secret_hex));
  w.varbytes(to_bytes(record.memo_key_hex));
  w.u8(record.consumed ? 1 : 0);
  return w.take();
}

std::optional<WalletStore::ConfidentialRequestRecord> parse_confidential_request_plain(const Bytes& value) {
  WalletStore::ConfidentialRequestRecord out;
  if (!codec::parse_exact(value, [&](codec::ByteReader& r) {
        auto version = r.u32le();
        auto request_id = r.varbytes();
        auto account_id = r.varbytes();
        auto one_time_pubkey_hex = r.varbytes();
        auto ephemeral_pubkey_hex = r.varbytes();
        auto scan_tag = r.u8();
        auto spend_secret_hex = r.varbytes();
        auto memo_key_hex = r.varbytes();
        auto consumed = r.u8();
        if (!version || !request_id || !account_id || !one_time_pubkey_hex || !ephemeral_pubkey_hex || !scan_tag ||
            !spend_secret_hex || !memo_key_hex || !consumed) {
          return false;
        }
        if (*version != kConfidentialWalletRecordVersion) return false;
        out.request_id = from_bytes(*request_id);
        out.account_id = from_bytes(*account_id);
        out.one_time_pubkey_hex = from_bytes(*one_time_pubkey_hex);
        out.ephemeral_pubkey_hex = from_bytes(*ephemeral_pubkey_hex);
        out.scan_tag = *scan_tag;
        out.spend_secret_hex = from_bytes(*spend_secret_hex);
        out.memo_key_hex = from_bytes(*memo_key_hex);
        out.consumed = (*consumed != 0);
        return true;
      })) {
    return std::nullopt;
  }
  return out;
}

Bytes encrypt_secret_payload(const std::string& passphrase, const Bytes& plain) {
  if (passphrase.empty()) return {};
  Bytes salt(kWalletSaltLen, 0);
  Bytes nonce(kWalletNonceLen, 0);
  if (!random_bytes(&salt) || !random_bytes(&nonce)) return {};
  Bytes key32;
  if (!derive_key_pbkdf2(passphrase, salt, kConfidentialWalletPbkdf2Iterations, &key32)) return {};
  Bytes cipher_and_tag;
  if (!aes_gcm_encrypt(key32, nonce, plain, &cipher_and_tag)) return {};
  codec::ByteWriter w;
  w.u32le(kConfidentialWalletRecordVersion);
  w.u32le(kConfidentialWalletPbkdf2Iterations);
  w.varbytes(salt);
  w.varbytes(nonce);
  w.varbytes(cipher_and_tag);
  return w.take();
}

std::optional<Bytes> decrypt_secret_payload(const std::string& passphrase, const Bytes& value) {
  if (passphrase.empty()) return std::nullopt;
  Bytes plain;
  if (!codec::parse_exact(value, [&](codec::ByteReader& r) {
        auto version = r.u32le();
        auto iterations = r.u32le();
        auto salt = r.varbytes();
        auto nonce = r.varbytes();
        auto cipher_and_tag = r.varbytes();
        if (!version || !iterations || !salt || !nonce || !cipher_and_tag) return false;
        if (*version != kConfidentialWalletRecordVersion) return false;
        Bytes key32;
        if (!derive_key_pbkdf2(passphrase, *salt, *iterations, &key32)) return false;
        return aes_gcm_decrypt(key32, *nonce, *cipher_and_tag, &plain);
      })) {
    return std::nullopt;
  }
  return plain;
}

}  // namespace

bool WalletStore::open(const std::string& wallet_file_path, const std::string& passphrase) {
  path_ = wallet_file_path + ".walletdb";
  passphrase_ = passphrase;
  std::filesystem::create_directories(path_);
  return db_.open(path_);
}

bool WalletStore::load(State* out) const {
  if (!out) return false;
  out->sent_txids.clear();
  out->local_events.clear();
  out->mint_notes.clear();
  out->pending_spends.clear();
  out->finalized_history.clear();
  out->history_cursor_height.reset();
  out->history_cursor_txid.reset();
  out->confidential_accounts.clear();
  out->confidential_coins.clear();
  out->confidential_requests.clear();
  out->confidential_primary_account_id.reset();
  out->wallet_snapshot.reset();
  out->wallet_view_snapshot.reset();
  out->pending_tx_statuses.clear();

  for (const auto& [key, _] : db_.scan_prefix("SENT:")) out->sent_txids.push_back(key.substr(5));
  std::sort(out->sent_txids.begin(), out->sent_txids.end());

  for (const auto& [key, value] : db_.scan_prefix("PEND:")) {
    auto parsed = parse_pending_spend(key.substr(5), value);
    if (!parsed) continue;
    out->pending_spends.push_back(*parsed);
  }
  std::sort(out->pending_spends.begin(), out->pending_spends.end(),
            [](const auto& a, const auto& b) { return a.txid_hex < b.txid_hex; });

  for (const auto& [key, value] : db_.scan_prefix("HIST:")) {
    if (key == key_history_seq()) continue;
    auto parsed = parse_finalized_history_record(value);
    if (!parsed) continue;
    out->finalized_history.push_back(*parsed);
  }

  for (const auto& [key, value] : db_.scan_prefix("EVT:")) {
    if (key == key_event_seq()) continue;
    out->local_events.push_back(from_bytes(value));
  }

  for (const auto& [key, value] : db_.scan_prefix("NOTE:")) {
    auto parsed = parse_note(value);
    if (!parsed) continue;
    out->mint_notes.push_back(MintNoteRecord{key.substr(5), parsed->first, parsed->second});
  }
  std::sort(out->mint_notes.begin(), out->mint_notes.end(),
            [](const auto& a, const auto& b) { return a.note_ref < b.note_ref; });

  out->mint_deposit_ref = get_string(key_meta("mint_deposit_ref")).value_or("");
  out->mint_last_deposit_txid = get_string(key_meta("mint_last_deposit_txid")).value_or("");
  out->mint_last_deposit_vout = get_u32(key_meta("mint_last_deposit_vout")).value_or(0);
  out->mint_last_redemption_batch_id = get_string(key_meta("mint_last_redemption_batch_id")).value_or("");
  out->history_cursor_height = get_u64(key_meta("history_cursor_height"));
  out->history_cursor_txid = get_string(key_meta("history_cursor_txid"));
  out->confidential_primary_account_id = get_string(key_meta("confidential_primary_account_id"));
  if (const auto snapshot = db_.get(key_snapshot()); snapshot.has_value()) {
    out->wallet_snapshot = parse_wallet_snapshot(*snapshot);
  }
  if (const auto snapshot = db_.get(key_view_snapshot()); snapshot.has_value()) {
    out->wallet_view_snapshot = parse_wallet_view_snapshot(*snapshot);
  }
  for (const auto& [key, value] : db_.scan_prefix("PENDINGTX:")) {
    auto parsed = parse_pending_tx_status_record(value);
    if (!parsed) continue;
    if (parsed->txid_hex.empty()) parsed->txid_hex = key.substr(10);
    out->pending_tx_statuses.push_back(*parsed);
  }
  std::sort(out->pending_tx_statuses.begin(), out->pending_tx_statuses.end(),
            [](const auto& a, const auto& b) { return a.txid_hex < b.txid_hex; });

  for (const auto& [key, value] : db_.scan_prefix("CACCT:")) {
    auto plain = decrypt_secret_payload(passphrase_, value);
    if (!plain) continue;
    auto parsed = parse_confidential_account_plain(*plain);
    if (!parsed) continue;
    out->confidential_accounts.push_back(*parsed);
  }
  std::sort(out->confidential_accounts.begin(), out->confidential_accounts.end(),
            [](const auto& a, const auto& b) { return a.account_id < b.account_id; });

  for (const auto& [key, value] : db_.scan_prefix("CCOIN:")) {
    auto plain = decrypt_secret_payload(passphrase_, value);
    if (!plain) continue;
    auto parsed = parse_confidential_coin_plain(*plain);
    if (!parsed) continue;
    out->confidential_coins.push_back(*parsed);
  }
  std::sort(out->confidential_coins.begin(), out->confidential_coins.end(), [](const auto& a, const auto& b) {
    if (a.txid_hex != b.txid_hex) return a.txid_hex < b.txid_hex;
    return a.vout < b.vout;
  });

  for (const auto& [key, value] : db_.scan_prefix("CREQ:")) {
    auto plain = decrypt_secret_payload(passphrase_, value);
    if (!plain) continue;
    auto parsed = parse_confidential_request_plain(*plain);
    if (!parsed) continue;
    out->confidential_requests.push_back(*parsed);
  }
  std::sort(out->confidential_requests.begin(), out->confidential_requests.end(),
            [](const auto& a, const auto& b) { return a.request_id < b.request_id; });
  return true;
}

bool WalletStore::add_sent_txid(const std::string& txid) { return db_.put(key_sent(txid), Bytes{}); }

bool WalletStore::remove_sent_txid(const std::string& txid) { return db_.erase(key_sent(txid)); }

bool WalletStore::upsert_pending_spend(const std::string& txid, const std::vector<OutPoint>& inputs,
                                       std::uint64_t created_tip_height, std::uint64_t created_unix_ms) {
  return db_.put(key_pending(txid), serialize_pending_spend(PendingSpend{
                                   .txid_hex = txid,
                                   .inputs = inputs,
                                   .created_tip_height = created_tip_height,
                                   .created_unix_ms = created_unix_ms,
                               }));
}

bool WalletStore::remove_pending_spend(const std::string& txid) { return db_.erase(key_pending(txid)); }

bool WalletStore::replace_finalized_history(const std::vector<FinalizedHistoryRecord>& records) {
  for (const auto& [key, _] : db_.scan_prefix("HIST:")) {
    if (key == key_history_seq()) continue;
    if (!db_.erase(key)) return false;
  }
  if (!db_.erase(key_history_seq())) return false;
  return append_finalized_history(records);
}

bool WalletStore::append_finalized_history(const std::vector<FinalizedHistoryRecord>& records) {
  std::uint64_t seq = next_history_seq();
  for (const auto& record : records) {
    ++seq;
    if (!db_.put(key_history(seq), serialize_finalized_history_record(record))) return false;
  }
  codec::ByteWriter w;
  w.u64le(seq);
  return db_.put(key_history_seq(), w.take());
}

bool WalletStore::set_history_cursor(const std::optional<std::uint64_t>& height, const std::optional<std::string>& txid) {
  if (height.has_value() != txid.has_value()) return false;
  if (!height.has_value()) {
    return db_.erase(key_meta("history_cursor_height")) && db_.erase(key_meta("history_cursor_txid"));
  }
  return set_u64(key_meta("history_cursor_height"), *height) && set_string(key_meta("history_cursor_txid"), *txid);
}

bool WalletStore::set_wallet_snapshot(const WalletSnapshot& snapshot) {
  return db_.put(key_snapshot(), serialize_wallet_snapshot(snapshot));
}

bool WalletStore::clear_wallet_snapshot() { return db_.erase(key_snapshot()); }

bool WalletStore::set_wallet_view_snapshot(const WalletViewSnapshot& snapshot) {
  return db_.put(key_view_snapshot(), serialize_wallet_view_snapshot(snapshot));
}

bool WalletStore::clear_wallet_view_snapshot() { return db_.erase(key_view_snapshot()); }

bool WalletStore::upsert_pending_tx_status(const PendingTxStatusRecord& record) {
  if (!db_.put(key_pending_tx_status(record.txid_hex), serialize_pending_tx_status_record(record))) return false;
  return prune_pending_tx_status_cache();
}

bool WalletStore::remove_pending_tx_status(const std::string& txid_hex) {
  return db_.erase(key_pending_tx_status(txid_hex));
}

bool WalletStore::prune_pending_tx_status_cache() {
  struct Entry {
    std::string key;
    PendingTxStatusRecord record;
  };
  std::vector<Entry> entries;
  entries.reserve(kMaxPendingTxStatusRecords + 8);
  std::uint64_t newest_cached_at_ms = 0;
  for (const auto& [key, value] : db_.scan_prefix("PENDINGTX:")) {
    auto parsed = parse_pending_tx_status_record(value);
    if (!parsed) {
      (void)db_.erase(key);
      continue;
    }
    newest_cached_at_ms = std::max(newest_cached_at_ms, parsed->cached_at_ms);
    entries.push_back(Entry{key, *parsed});
  }
  if (entries.empty()) return true;

  const std::uint64_t min_cached_at_ms =
      newest_cached_at_ms > kPendingTxStatusRetentionMs ? (newest_cached_at_ms - kPendingTxStatusRetentionMs) : 0;
  for (const auto& entry : entries) {
    if (entry.record.cached_at_ms < min_cached_at_ms) {
      if (!db_.erase(entry.key)) return false;
    }
  }

  entries.clear();
  for (const auto& [key, value] : db_.scan_prefix("PENDINGTX:")) {
    auto parsed = parse_pending_tx_status_record(value);
    if (!parsed) {
      (void)db_.erase(key);
      continue;
    }
    entries.push_back(Entry{key, *parsed});
  }
  if (entries.size() <= kMaxPendingTxStatusRecords) return true;

  std::sort(entries.begin(), entries.end(), [](const Entry& a, const Entry& b) {
    if (a.record.cached_at_ms != b.record.cached_at_ms) return a.record.cached_at_ms > b.record.cached_at_ms;
    return a.record.txid_hex < b.record.txid_hex;
  });
  for (std::size_t i = kMaxPendingTxStatusRecords; i < entries.size(); ++i) {
    if (!db_.erase(entries[i].key)) return false;
  }
  return true;
}

bool WalletStore::append_local_event(const std::string& line) {
  const std::uint64_t seq = next_event_seq() + 1;
  if (!db_.put(key_event(seq), to_bytes(line))) return false;
  codec::ByteWriter w;
  w.u64le(seq);
  return db_.put(key_event_seq(), w.take());
}

bool WalletStore::upsert_mint_note(const std::string& note_ref, std::uint64_t amount, bool active) {
  return db_.put(key_note(note_ref), serialize_note(amount, active));
}

bool WalletStore::set_mint_deposit_ref(const std::string& value) { return set_string(key_meta("mint_deposit_ref"), value); }

bool WalletStore::set_mint_last_deposit_txid(const std::string& value) {
  return set_string(key_meta("mint_last_deposit_txid"), value);
}

bool WalletStore::set_mint_last_deposit_vout(std::uint32_t value) { return set_u32(key_meta("mint_last_deposit_vout"), value); }

bool WalletStore::set_mint_last_redemption_batch_id(const std::string& value) {
  return set_string(key_meta("mint_last_redemption_batch_id"), value);
}

bool WalletStore::upsert_confidential_account(const ConfidentialAccountRecord& record) {
  if (!can_persist_confidential_secrets()) return false;
  const auto encrypted = encrypt_secret_payload(passphrase_, serialize_confidential_account_plain(record));
  if (encrypted.empty()) return false;
  return db_.put(key_confidential_account(record.account_id), encrypted);
}

bool WalletStore::set_confidential_primary_account_id(const std::optional<std::string>& account_id) {
  if (!account_id.has_value()) return db_.erase(key_meta("confidential_primary_account_id"));
  return set_string(key_meta("confidential_primary_account_id"), *account_id);
}

bool WalletStore::upsert_confidential_coin(const ConfidentialCoinRecord& record) {
  if (!can_persist_confidential_secrets()) return false;
  const auto encrypted = encrypt_secret_payload(passphrase_, serialize_confidential_coin_plain(record));
  if (encrypted.empty()) return false;
  return db_.put(key_confidential_coin(record.txid_hex, record.vout), encrypted);
}

bool WalletStore::set_confidential_coin_spent(const std::string& txid_hex, std::uint32_t vout, bool spent) {
  if (!can_persist_confidential_secrets()) return false;
  const auto current = db_.get(key_confidential_coin(txid_hex, vout));
  if (!current) return false;
  const auto plain = decrypt_secret_payload(passphrase_, *current);
  if (!plain) return false;
  auto parsed = parse_confidential_coin_plain(*plain);
  if (!parsed) return false;
  parsed->spent = spent;
  return upsert_confidential_coin(*parsed);
}

bool WalletStore::remove_confidential_coin(const std::string& txid_hex, std::uint32_t vout) {
  return db_.erase(key_confidential_coin(txid_hex, vout));
}

bool WalletStore::upsert_confidential_request(const ConfidentialRequestRecord& record) {
  if (!can_persist_confidential_secrets()) return false;
  const auto encrypted = encrypt_secret_payload(passphrase_, serialize_confidential_request_plain(record));
  if (encrypted.empty()) return false;
  return db_.put(key_confidential_request(record.request_id), encrypted);
}

bool WalletStore::set_confidential_request_consumed(const std::string& request_id, bool consumed) {
  if (!can_persist_confidential_secrets()) return false;
  const auto current = db_.get(key_confidential_request(request_id));
  if (!current) return false;
  const auto plain = decrypt_secret_payload(passphrase_, *current);
  if (!plain) return false;
  auto parsed = parse_confidential_request_plain(*plain);
  if (!parsed) return false;
  parsed->consumed = consumed;
  return upsert_confidential_request(*parsed);
}

bool WalletStore::remove_confidential_request(const std::string& request_id) {
  return db_.erase(key_confidential_request(request_id));
}

bool WalletStore::can_persist_confidential_secrets() const { return !passphrase_.empty(); }

bool WalletStore::set_string(const std::string& key, const std::string& value) { return db_.put(key, to_bytes(value)); }

bool WalletStore::set_u32(const std::string& key, std::uint32_t value) {
  codec::ByteWriter w;
  w.u32le(value);
  return db_.put(key, w.take());
}

bool WalletStore::set_u64(const std::string& key, std::uint64_t value) {
  codec::ByteWriter w;
  w.u64le(value);
  return db_.put(key, w.take());
}

std::optional<std::string> WalletStore::get_string(const std::string& key) const {
  auto value = db_.get(key);
  if (!value) return std::nullopt;
  return from_bytes(*value);
}

std::optional<std::uint32_t> WalletStore::get_u32(const std::string& key) const {
  auto value = db_.get(key);
  if (!value) return std::nullopt;
  std::uint32_t out = 0;
  if (!codec::parse_exact(*value, [&](codec::ByteReader& r) {
        auto parsed = r.u32le();
        if (!parsed) return false;
        out = *parsed;
        return true;
      })) {
    return std::nullopt;
  }
  return out;
}

std::optional<std::uint64_t> WalletStore::get_u64(const std::string& key) const {
  auto value = db_.get(key);
  if (!value) return std::nullopt;
  std::uint64_t out = 0;
  if (!codec::parse_exact(*value, [&](codec::ByteReader& r) {
        auto parsed = r.u64le();
        if (!parsed) return false;
        out = *parsed;
        return true;
      })) {
    return std::nullopt;
  }
  return out;
}

std::uint64_t WalletStore::next_event_seq() const {
  auto value = db_.get(key_event_seq());
  if (!value) return 0;
  std::uint64_t out = 0;
  if (!codec::parse_exact(*value, [&](codec::ByteReader& r) {
        auto parsed = r.u64le();
        if (!parsed) return false;
        out = *parsed;
        return true;
      })) {
    return 0;
  }
  return out;
}

std::uint64_t WalletStore::next_history_seq() const {
  auto value = db_.get(key_history_seq());
  if (!value) return 0;
  std::uint64_t out = 0;
  if (!codec::parse_exact(*value, [&](codec::ByteReader& r) {
        auto parsed = r.u64le();
        if (!parsed) return false;
        out = *parsed;
        return true;
      })) {
    return 0;
  }
  return out;
}

std::set<OutPoint> WalletStore::reserved_pending_outpoints(const State& state) {
  std::set<OutPoint> out;
  for (const auto& pending : state.pending_spends) {
    for (const auto& input : pending.inputs) out.insert(input);
  }
  return out;
}

}  // namespace finalis::wallet
