#include "wallet_window.hpp"

#include "widgets/activity_page.hpp"
#include "widgets/advanced_page.hpp"
#include "widgets/overview_page.hpp"
#include "widgets/receive_page.hpp"
#include "widgets/send_page.hpp"
#include "widgets/settings_page.hpp"

#include <array>
#include <algorithm>
#include <map>
#include <random>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <thread>

#include <QApplication>
#include <QAbstractItemView>
#include <QClipboard>
#include <QCheckBox>
#include <QComboBox>
#include <QDateTime>
#include <QDesktopServices>
#include <QDir>
#include <QFileDialog>
#include <QFileInfo>
#include <QFormLayout>
#include <QFrame>
#include <QHBoxLayout>
#include <QInputDialog>
#include <QIcon>
#include <QLabel>
#include <QLineEdit>
#include <QAction>
#include <QKeySequence>
#include <QMessageBox>
#include <QMenuBar>
#include <QPushButton>
#include <QSettings>
#include <QStatusBar>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTextEdit>
#include <QTimer>
#include <QHeaderView>
#include <QMenu>
#include <QPointer>
#include <QTabWidget>
#include <QFontDatabase>
#include <QUrl>
#include <QVBoxLayout>
#include <QWidget>

#include <openssl/evp.h>

#include "address/address.hpp"
#include "codec/bytes.hpp"
#include "history_merge.hpp"
#include "refresh_gate.hpp"
#include "common/network.hpp"
#include "common/types.hpp"
#include "consensus/monetary.hpp"
#include "crypto/hash.hpp"
#include "crypto/stealth_address.hpp"
#include "genesis/embedded_mainnet.hpp"
#include "keystore/validator_keystore.hpp"
#include "lightserver/client.hpp"
#include "onboarding/validator_onboarding.hpp"
#include "privacy/mint_client.hpp"
#include "privacy/mint_scripts.hpp"
#include "wallet/confidential_builder.hpp"
#include "utxo/confidential_tx.hpp"
#include "utxo/signing.hpp"
#include "utxo/tx.hpp"

namespace finalis::wallet {
namespace {

constexpr const char* kSettingsOrg = "finalis";
constexpr const char* kSettingsApp = "finalis-wallet";
constexpr const char* kLegacySettingsApp = "reference-wallet";
constexpr std::uint64_t kPendingSendReleaseMinTipDelta = 2;
constexpr std::uint64_t kPendingSendReleaseMinAgeMs = 120000;
constexpr const char* kDisplayTicker = "FLS";

enum class ThemeMode { Light, Dark };

ThemeMode theme_mode_from_string(const QString& value) {
  return value.trimmed().compare("dark", Qt::CaseInsensitive) == 0 ? ThemeMode::Dark : ThemeMode::Light;
}

QString theme_mode_to_string(ThemeMode mode) {
  return mode == ThemeMode::Dark ? "dark" : "light";
}

QPalette make_wallet_palette(ThemeMode mode) {
  QPalette palette;
  if (mode == ThemeMode::Dark) {
    palette.setColor(QPalette::Window, QColor(18, 18, 18));
    palette.setColor(QPalette::WindowText, QColor(237, 237, 237));
    palette.setColor(QPalette::Base, QColor(12, 12, 12));
    palette.setColor(QPalette::AlternateBase, QColor(26, 26, 26));
    palette.setColor(QPalette::ToolTipBase, QColor(24, 24, 24));
    palette.setColor(QPalette::ToolTipText, QColor(237, 237, 237));
    palette.setColor(QPalette::Text, QColor(237, 237, 237));
    palette.setColor(QPalette::Button, QColor(28, 28, 28));
    palette.setColor(QPalette::ButtonText, QColor(237, 237, 237));
    palette.setColor(QPalette::PlaceholderText, QColor(142, 142, 142));
    palette.setColor(QPalette::Highlight, QColor(220, 220, 220));
    palette.setColor(QPalette::HighlightedText, QColor(12, 12, 12));
    palette.setColor(QPalette::Light, QColor(42, 42, 42));
    palette.setColor(QPalette::Mid, QColor(72, 72, 72));
    palette.setColor(QPalette::Dark, QColor(10, 10, 10));
    return palette;
  }

  palette.setColor(QPalette::Window, QColor(244, 244, 244));
  palette.setColor(QPalette::WindowText, QColor(20, 20, 20));
  palette.setColor(QPalette::Base, QColor(255, 255, 255));
  palette.setColor(QPalette::AlternateBase, QColor(248, 248, 248));
  palette.setColor(QPalette::ToolTipBase, QColor(255, 255, 255));
  palette.setColor(QPalette::ToolTipText, QColor(20, 20, 20));
  palette.setColor(QPalette::Text, QColor(20, 20, 20));
  palette.setColor(QPalette::Button, QColor(236, 236, 236));
  palette.setColor(QPalette::ButtonText, QColor(20, 20, 20));
  palette.setColor(QPalette::PlaceholderText, QColor(128, 128, 128));
  palette.setColor(QPalette::Highlight, QColor(32, 32, 32));
  palette.setColor(QPalette::HighlightedText, QColor(255, 255, 255));
  return palette;
}

QString wallet_stylesheet(ThemeMode mode) {
  if (mode == ThemeMode::Dark) {
    return QString(
        "QMainWindow, QWidget { background: #121212; color: #ededed; }"
        "QMenuBar { background: #121212; color: #ededed; }"
        "QMenuBar::item:selected, QMenu::item:selected { background: #2a2a2a; }"
        "QMenu { background: #181818; color: #ededed; border: 1px solid #3a3a3a; }"
        "QGroupBox { border: 1px solid #353535; border-radius: 8px; margin-top: 14px; padding: 12px; background: #1a1a1a; }"
        "QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 6px; color: #f2f2f2; }"
        "QPushButton { background: #242424; border: 1px solid #4b4b4b; border-radius: 6px; padding: 8px 12px; }"
        "QPushButton:hover { background: #303030; }"
        "QPushButton:pressed { background: #3a3a3a; }"
        "QPushButton:disabled { color: #8a8a8a; border-color: #303030; background: #1c1c1c; }"
        "QLineEdit, QComboBox, QTableWidget, QTextEdit { background: #0f0f0f; border: 1px solid #3d3d3d; border-radius: 6px; padding: 6px; }"
        "QTabWidget::pane { border: 1px solid #353535; top: -1px; }"
        "QTabBar::tab { background: #1f1f1f; border: 1px solid #353535; padding: 8px 12px; margin-right: 4px; }"
        "QTabBar::tab:selected { background: #2a2a2a; }"
        "QHeaderView::section { background: #202020; color: #ededed; padding: 6px; border: 0; border-right: 1px solid #353535; border-bottom: 1px solid #353535; }"
        "QStatusBar { background: #151515; border-top: 1px solid #2b2b2b; }"
        "QFrame[role='headerCard'] { background: #161616; border: 0; border-bottom: 1px solid #2f2f2f; border-radius: 0; }"
        "QLabel[role='muted'] { color: #c2c2c2; }"
        "QLabel[role='metric'] { font-size: 16px; font-weight: 600; }"
        "QLabel[role='chip'] { background: #262626; border: 1px solid #4b4b4b; border-radius: 9px; padding: 3px 8px; }");
  }

  return QString(
      "QMainWindow, QWidget { background: #f4f4f4; color: #141414; }"
      "QMenuBar { background: #f4f4f4; color: #141414; }"
      "QMenuBar::item:selected, QMenu::item:selected { background: #e8e8e8; }"
      "QMenu { background: #ffffff; color: #141414; border: 1px solid #cbcbcb; }"
      "QGroupBox { border: 1px solid #d6d6d6; border-radius: 8px; margin-top: 14px; padding: 12px; background: #ffffff; }"
      "QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 6px; color: #202020; }"
      "QPushButton { background: #f0f0f0; border: 1px solid #c4c4c4; border-radius: 6px; padding: 8px 12px; }"
      "QPushButton:hover { background: #e8e8e8; }"
      "QPushButton:pressed { background: #dddddd; }"
      "QPushButton:disabled { color: #909090; border-color: #d5d5d5; background: #f6f6f6; }"
      "QLineEdit, QComboBox, QTableWidget, QTextEdit { background: #ffffff; border: 1px solid #d0d0d0; border-radius: 6px; padding: 6px; }"
      "QTabWidget::pane { border: 1px solid #d6d6d6; top: -1px; background: #ffffff; }"
      "QTabBar::tab { background: #ededed; border: 1px solid #d6d6d6; padding: 8px 12px; margin-right: 4px; }"
      "QTabBar::tab:selected { background: #ffffff; }"
      "QHeaderView::section { background: #f0f0f0; color: #141414; padding: 6px; border: 0; border-right: 1px solid #d6d6d6; border-bottom: 1px solid #d6d6d6; }"
      "QStatusBar { background: #f7f7f7; border-top: 1px solid #dadada; }"
      "QFrame[role='headerCard'] { background: transparent; border: 0; border-bottom: 1px solid #dadada; border-radius: 0; }"
      "QLabel[role='muted'] { color: #4f4f4f; }"
      "QLabel[role='metric'] { font-size: 16px; font-weight: 600; }"
      "QLabel[role='chip'] { background: #f3f3f3; border: 1px solid #d2d2d2; border-radius: 9px; padding: 3px 8px; }");
}

QLabel* make_brand_image(const QString& resource_path, const QSize& size, QWidget* parent, const QString& fallback = {}) {
  auto* label = new QLabel(parent);
  label->setAlignment(Qt::AlignCenter);
  QIcon icon(resource_path);
  const QPixmap pixmap = icon.pixmap(size);
  if (!pixmap.isNull()) {
    label->setPixmap(pixmap);
  } else {
    label->setText(fallback);
  }
  return label;
}

QString inferred_validator_key_path_from_db(const QString& db_path) {
  const QString trimmed = db_path.trimmed();
  if (trimmed.isEmpty()) return {};
  const QString candidate = QDir(trimmed).filePath("keystore/validator.json");
  return QFileInfo::exists(candidate) && QFileInfo(candidate).isFile() ? candidate : QString{};
}

bool looks_like_node_validator_key(const QString& path) {
  const QFileInfo info(path);
  if (!info.exists() || !info.isFile()) return false;
  return info.fileName() == "validator.json" && info.dir().dirName() == "keystore";
}

QString default_finalis_root_path() {
#ifdef Q_OS_WIN
  const QString appdata = qEnvironmentVariable("APPDATA").trimmed();
  if (!appdata.isEmpty()) return QDir(appdata).filePath(".finalis");
#endif
  return QDir::home().filePath(".finalis");
}

QString default_mainnet_db_path() { return QDir(default_finalis_root_path()).filePath("mainnet"); }

QString default_mainnet_validator_key_path() {
  return QDir(default_finalis_root_path()).filePath("mainnet/keystore/validator.json");
}

QString preferred_startup_wallet_path() {
  QSettings settings(kSettingsOrg, kSettingsApp);
  QSettings legacy(kSettingsOrg, kLegacySettingsApp);
  QString path = settings.value("wallet/last_opened_file").toString().trimmed();
  if (path.isEmpty()) path = legacy.value("wallet/last_opened_file").toString().trimmed();
  if (!path.isEmpty() && QFileInfo::exists(path) && QFileInfo(path).isFile()) return path;
  const QString fallback = default_mainnet_validator_key_path();
  return QFileInfo::exists(fallback) && QFileInfo(fallback).isFile() ? fallback : QString{};
}

std::optional<std::array<std::uint8_t, 32>> decode_hex32_string(const std::string& hex) {
  auto bytes = finalis::hex_decode(hex);
  if (!bytes || bytes->size() != 32) return std::nullopt;
  std::array<std::uint8_t, 32> out{};
  std::copy(bytes->begin(), bytes->end(), out.begin());
  return out;
}

std::optional<PubKey33> decode_hex33_string(const std::string& hex) {
  auto bytes = finalis::hex_decode(hex);
  if (!bytes || bytes->size() != 33) return std::nullopt;
  PubKey33 out{};
  std::copy(bytes->begin(), bytes->end(), out.begin());
  return out;
}

std::optional<crypto::Blind32> decode_blind32_string(const std::string& hex) {
  auto bytes = finalis::hex_decode(hex);
  if (!bytes || bytes->size() != 32) return std::nullopt;
  crypto::Blind32 out;
  std::copy(bytes->begin(), bytes->end(), out.bytes.begin());
  return out;
}

std::optional<Bytes> decode_hex_bytes_string(const std::string& hex) {
  return finalis::hex_decode(hex);
}

Hash32 random_hash32() {
  std::random_device rd;
  Hash32 out{};
  for (auto& b : out) b = static_cast<std::uint8_t>(rd());
  return out;
}

enum class WalletSendMode : std::uint8_t {
  TransparentToTransparent = 0,
  TransparentToConfidential = 1,
  ConfidentialToTransparent = 2,
};

WalletSendMode wallet_send_mode_from_combo(const QComboBox* combo) {
  if (!combo) return WalletSendMode::TransparentToTransparent;
  switch (combo->currentIndex()) {
    case 1:
      return WalletSendMode::TransparentToConfidential;
    case 2:
      return WalletSendMode::ConfidentialToTransparent;
    default:
      return WalletSendMode::TransparentToTransparent;
  }
}

QString wallet_send_mode_default_placeholder(WalletSendMode mode) {
  switch (mode) {
    case WalletSendMode::TransparentToTransparent:
      return "sc...";
    case WalletSendMode::TransparentToConfidential:
      return "ctxv2:<one_time_pubkey_hex>:<ephemeral_pubkey_hex>:<scan_tag_hex>[:memo_hex]";
    case WalletSendMode::ConfidentialToTransparent:
      return "sc...";
  }
  return "sc...";
}

QString wallet_send_mode_recipient_label(WalletSendMode mode) {
  switch (mode) {
    case WalletSendMode::TransparentToTransparent:
      return "Recipient address";
    case WalletSendMode::TransparentToConfidential:
      return "Recipient descriptor";
    case WalletSendMode::ConfidentialToTransparent:
      return "Recipient address";
  }
  return "Recipient";
}

constexpr std::uint32_t kConfidentialRecoveryMemoVersion = 1;
constexpr std::size_t kWalletMemoTagLen = 16;

struct ParsedConfidentialRecipient {
  wallet::ConfidentialRecipient recipient;
  std::optional<Hash32> memo_key;
};

std::string encode_confidential_request_uri(const wallet::ConfidentialRecipient& recipient,
                                            const std::optional<Hash32>& memo_key = std::nullopt) {
  Bytes payload;
  payload.insert(payload.end(), recipient.one_time_pubkey.begin(), recipient.one_time_pubkey.end());
  payload.insert(payload.end(), recipient.ephemeral_pubkey.begin(), recipient.ephemeral_pubkey.end());
  payload.push_back(recipient.scan_tag.value);
  if (memo_key.has_value()) payload.insert(payload.end(), memo_key->begin(), memo_key->end());
  return "scconfreq1:" + finalis::hex_encode(payload);
}

std::string encode_local_stealth_address(const PubKey33& view_pubkey, const PubKey33& spend_pubkey) {
  Bytes payload;
  payload.insert(payload.end(), view_pubkey.begin(), view_pubkey.end());
  payload.insert(payload.end(), spend_pubkey.begin(), spend_pubkey.end());
  return "scstealth1:" + finalis::hex_encode(payload);
}

Bytes confidential_memo_nonce(const PubKey33& ephemeral_pubkey) {
  Bytes preimage(ephemeral_pubkey.begin(), ephemeral_pubkey.end());
  preimage.push_back(0x6d);
  preimage.push_back(0x65);
  preimage.push_back(0x6d);
  preimage.push_back(0x6f);
  const auto digest = crypto::sha256d(preimage);
  return Bytes(digest.begin(), digest.begin() + 12);
}

bool aes_gcm_encrypt_wallet_memo(const Bytes& key32, const Bytes& nonce12, const Bytes& plaintext, Bytes* out_cipher_and_tag) {
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) return false;
  int ok = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
  ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce12.size()), nullptr);
  ok = ok && EVP_EncryptInit_ex(ctx, nullptr, nullptr, key32.data(), nonce12.data());
  if (!ok) {
    EVP_CIPHER_CTX_free(ctx);
    return false;
  }
  Bytes cipher(plaintext.size() + kWalletMemoTagLen, 0);
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
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, static_cast<int>(kWalletMemoTagLen), cipher.data() + total) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return false;
  }
  total += static_cast<int>(kWalletMemoTagLen);
  cipher.resize(static_cast<std::size_t>(total));
  EVP_CIPHER_CTX_free(ctx);
  *out_cipher_and_tag = std::move(cipher);
  return true;
}

bool aes_gcm_decrypt_wallet_memo(const Bytes& key32, const Bytes& nonce12, const Bytes& cipher_and_tag, Bytes* out_plaintext) {
  if (cipher_and_tag.size() < kWalletMemoTagLen) return false;
  const std::size_t clen = cipher_and_tag.size() - kWalletMemoTagLen;
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
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, static_cast<int>(kWalletMemoTagLen), const_cast<std::uint8_t*>(tag)) != 1) {
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

std::optional<Bytes> encrypt_confidential_recovery_memo(std::uint64_t amount, const crypto::Blind32& blind,
                                                        const Hash32& memo_key, const PubKey33& ephemeral_pubkey) {
  codec::ByteWriter w;
  w.u32le(kConfidentialRecoveryMemoVersion);
  w.u64le(amount);
  w.bytes_fixed(blind.bytes);
  const Bytes plain = w.take();
  Bytes cipher;
  const Bytes key(memo_key.begin(), memo_key.end());
  if (!aes_gcm_encrypt_wallet_memo(key, confidential_memo_nonce(ephemeral_pubkey), plain, &cipher)) return std::nullopt;
  return cipher;
}

struct ConfidentialRecoveryPayload {
  std::uint64_t amount{0};
  crypto::Blind32 blind{};
};

std::optional<ConfidentialRecoveryPayload> decrypt_confidential_recovery_memo(const Bytes& cipher_and_tag, const Hash32& memo_key,
                                                                              const PubKey33& ephemeral_pubkey) {
  Bytes plain;
  const Bytes key(memo_key.begin(), memo_key.end());
  if (!aes_gcm_decrypt_wallet_memo(key, confidential_memo_nonce(ephemeral_pubkey), cipher_and_tag, &plain)) {
    return std::nullopt;
  }
  ConfidentialRecoveryPayload out;
  if (!codec::parse_exact(plain, [&](codec::ByteReader& r) {
        auto version = r.u32le();
        auto amount = r.u64le();
        auto blind = r.bytes_fixed<32>();
        if (!version || !amount || !blind) return false;
        if (*version != kConfidentialRecoveryMemoVersion) return false;
        out.amount = *amount;
        std::copy(blind->begin(), blind->end(), out.blind.bytes.begin());
        return true;
      })) {
    return std::nullopt;
  }
  return out;
}

std::optional<ParsedConfidentialRecipient> parse_confidential_request_uri(const QString& text, QString* err) {
  const QString trimmed = text.trimmed();
  const QString prefix = "scconfreq1:";
  if (!trimmed.startsWith(prefix, Qt::CaseInsensitive)) return std::nullopt;
  auto payload = decode_hex_bytes_string(trimmed.mid(prefix.size()).trimmed().toStdString());
  if (!payload || (payload->size() != 67 && payload->size() != 99)) {
    if (err) *err = "Confidential request URI payload is malformed.";
    return std::nullopt;
  }
  ParsedConfidentialRecipient out;
  std::copy(payload->begin(), payload->begin() + 33, out.recipient.one_time_pubkey.begin());
  std::copy(payload->begin() + 33, payload->begin() + 66, out.recipient.ephemeral_pubkey.begin());
  out.recipient.scan_tag = crypto::ScanTag{(*payload)[66]};
  if (!crypto::compressed_pubkey33_is_canonical(out.recipient.one_time_pubkey) ||
      !crypto::compressed_pubkey33_is_canonical(out.recipient.ephemeral_pubkey)) {
    if (err) *err = "Confidential request URI contains non-canonical pubkeys.";
    return std::nullopt;
  }
  if (payload->size() == 99) {
    Hash32 memo_key{};
    std::copy(payload->begin() + 67, payload->begin() + 99, memo_key.begin());
    out.memo_key = memo_key;
  }
  return out;
}

std::optional<ParsedConfidentialRecipient> parse_confidential_recipient_descriptor(const QString& text, QString* err) {
  if (auto uri = parse_confidential_request_uri(text, err); uri.has_value()) return uri;
  const QString trimmed = text.trimmed();
  const QString prefix = "ctxv2:";
  if (!trimmed.startsWith(prefix, Qt::CaseInsensitive)) {
    if (err) *err = "Confidential recipient must use the ctxv2 descriptor format.";
    return std::nullopt;
  }
  const QStringList parts = trimmed.mid(prefix.size()).split(':');
  if (parts.size() < 3 || parts.size() > 4) {
    if (err) *err = "Confidential recipient format is ctxv2:<one_time_pubkey_hex>:<ephemeral_pubkey_hex>:<scan_tag_hex>[:memo_hex].";
    return std::nullopt;
  }
  const auto one_time_pubkey = decode_hex33_string(parts[0].trimmed().toStdString());
  if (!one_time_pubkey || !crypto::compressed_pubkey33_is_canonical(*one_time_pubkey)) {
    if (err) *err = "Confidential recipient one-time pubkey must be a canonical 33-byte compressed secp256k1 key.";
    return std::nullopt;
  }
  const auto ephemeral_pubkey = decode_hex33_string(parts[1].trimmed().toStdString());
  if (!ephemeral_pubkey || !crypto::compressed_pubkey33_is_canonical(*ephemeral_pubkey)) {
    if (err) *err = "Confidential recipient ephemeral pubkey must be a canonical 33-byte compressed secp256k1 key.";
    return std::nullopt;
  }
  const auto scan_tag_bytes = decode_hex_bytes_string(parts[2].trimmed().toStdString());
  if (!scan_tag_bytes || scan_tag_bytes->size() != 1) {
    if (err) *err = "Confidential recipient scan tag must be a 1-byte hex value.";
    return std::nullopt;
  }
  Bytes memo;
  if (parts.size() == 4) {
    auto memo_bytes = decode_hex_bytes_string(parts[3].trimmed().toStdString());
    if (!memo_bytes) {
      if (err) *err = "Confidential recipient memo must be valid hex.";
      return std::nullopt;
    }
    memo = std::move(*memo_bytes);
  }
  return ParsedConfidentialRecipient{
      .recipient =
          wallet::ConfidentialRecipient{
              .one_time_pubkey = *one_time_pubkey,
              .ephemeral_pubkey = *ephemeral_pubkey,
              .scan_tag = crypto::ScanTag{(*scan_tag_bytes)[0]},
              .memo = std::move(memo),
          },
      .memo_key = std::nullopt,
  };
}

std::optional<std::pair<OutPoint, TxOut>> select_single_covering_prev(
    const std::vector<std::pair<OutPoint, TxOut>>& available_prevs, std::uint64_t target_units) {
  std::optional<std::pair<OutPoint, TxOut>> best;
  for (const auto& prev : available_prevs) {
    if (prev.second.value < target_units) continue;
    if (!best || prev.second.value < best->second.value) best = prev;
  }
  return best;
}

std::optional<wallet::ConfidentialOwnedCoin> select_exact_confidential_coin(
    const wallet::WalletStore::State& state, const std::set<OutPoint>& reserved, std::uint64_t total_units, QString* err) {
  for (const auto& coin : state.confidential_coins) {
    if (coin.spent || coin.amount != total_units) continue;
    auto txid = decode_hex32_string(coin.txid_hex);
    auto value_commitment = decode_hex33_string(coin.value_commitment_hex);
    auto one_time_pubkey = decode_hex33_string(coin.one_time_pubkey_hex);
    auto spend_secret = decode_blind32_string(coin.spend_secret_hex);
    auto value_blind = decode_blind32_string(coin.blinding_factor_hex);
    if (!txid || !value_commitment || !one_time_pubkey || !spend_secret || !value_blind) continue;
    wallet::ConfidentialOwnedCoin out;
    out.outpoint = OutPoint{*txid, coin.vout};
    if (reserved.find(out.outpoint) != reserved.end()) continue;
    out.amount = coin.amount;
    out.spend_secret = *spend_secret;
    out.value_blind = *value_blind;
    out.value_commitment = crypto::Commitment33{*value_commitment};
    out.one_time_pubkey = *one_time_pubkey;
    return out;
  }
  if (err) {
    *err =
        QString("No unlocked confidential coin exactly matching %1 base units is available. Confidential sends currently support exact single-coin spends only.")
            .arg(QString::number(total_units));
  }
  return std::nullopt;
}

QString elide_middle(const QString& value, int keep = 14) {
  if (value.size() <= keep * 2) return value;
  return value.left(keep) + "..." + value.right(keep);
}

std::optional<std::uint64_t> parse_coin_amount(const QString& value) {
  const QString trimmed = value.trimmed();
  if (trimmed.isEmpty()) return std::nullopt;
  const QStringList parts = trimmed.split('.');
  if (parts.size() > 2) return std::nullopt;
  bool whole_ok = false;
  const std::uint64_t whole = parts[0].isEmpty() ? 0 : parts[0].toULongLong(&whole_ok);
  if (!whole_ok && !parts[0].isEmpty()) return std::nullopt;
  std::uint64_t units = whole * consensus::BASE_UNITS_PER_COIN;
  if (parts.size() == 2) {
    QString frac = parts[1];
    if (frac.size() > 8) return std::nullopt;
    while (frac.size() < 8) frac.append('0');
    bool frac_ok = false;
    const std::uint64_t frac_units = frac.isEmpty() ? 0 : frac.toULongLong(&frac_ok);
    if (!frac_ok) return std::nullopt;
    units += frac_units;
  }
  return units;
}

QString format_coin_amount(std::uint64_t units) {
  const std::uint64_t whole = units / consensus::BASE_UNITS_PER_COIN;
  const std::uint64_t frac = units % consensus::BASE_UNITS_PER_COIN;
  if (frac == 0) return QString("%1 %2").arg(whole).arg(kDisplayTicker);
  QString frac_str = QString("%1").arg(frac, 8, 10, QChar('0'));
  while (frac_str.endsWith('0')) frac_str.chop(1);
  return QString("%1.%2 %3").arg(whole).arg(frac_str).arg(kDisplayTicker);
}

QString format_coin_input_amount(std::uint64_t units) {
  const std::uint64_t whole = units / consensus::BASE_UNITS_PER_COIN;
  const std::uint64_t frac = units % consensus::BASE_UNITS_PER_COIN;
  if (frac == 0) return QString::number(whole);
  QString frac_str = QString("%1").arg(frac, 8, 10, QChar('0'));
  while (frac_str.endsWith('0')) frac_str.chop(1);
  return QString("%1.%2").arg(whole).arg(frac_str);
}

HistoryFlowClassification classify_wallet_history_flow_impl(std::uint64_t credited, std::uint64_t debited) {
  if (credited > 0 && debited == 0) return {"received", format_coin_amount(credited)};
  if (debited > 0 && credited == 0) return {"sent", format_coin_amount(debited)};
  if (credited > debited) return {"received", QString("%1 net").arg(format_coin_amount(credited - debited))};
  if (debited > credited) return {"sent", QString("%1 net").arg(format_coin_amount(debited - credited))};
  if (credited > 0 || debited > 0) return {"activity", "self-transfer"};
  return {"activity", {}};
}

QString format_bps_percentage(std::uint64_t bps) {
  return QString("%1%").arg(QString::number(static_cast<double>(bps) / 100.0, 'f', 2));
}

QString yes_no_text(bool value) { return value ? "yes" : "no"; }

QString mint_endpoint(const QString& base_url, const QString& path) {
  QString out = base_url.trimmed();
  while (out.endsWith('/')) out.chop(1);
  return out + path;
}

QString random_hex_string(std::size_t bytes_len) {
  std::random_device rd;
  Bytes b(bytes_len, 0);
  for (auto& v : b) v = static_cast<std::uint8_t>(rd());
  return QString::fromStdString(hex_encode(b));
}

std::string network_id_hex_for_wallet_network(const std::string& network_name) {
  const auto& net = finalis::network_by_name(network_name);
  return finalis::hex_encode(finalis::Bytes(net.network_id.begin(), net.network_id.end()));
}

std::optional<std::string> expected_genesis_hash_hex_for_wallet_network(const std::string& network_name) {
  if (network_name == "mainnet") {
    return finalis::hex_encode32(finalis::genesis::MAINNET_GENESIS_HASH);
  }
  return std::nullopt;
}

std::optional<QString> endpoint_chain_mismatch_reason(const finalis::lightserver::RpcStatusView& status,
                                                      const QString& expected_network_name) {
  const QString observed_network_name = QString::fromStdString(status.chain.network_name);
  if (observed_network_name != expected_network_name) {
    return QString("network mismatch: expected %1 got %2").arg(expected_network_name, observed_network_name);
  }
  if (!status.chain_id_ok) {
    return QString("endpoint reported chain_id_ok=false for %1").arg(observed_network_name);
  }
  const QString expected_network_id = QString::fromStdString(network_id_hex_for_wallet_network(status.chain.network_name));
  const QString observed_network_id = QString::fromStdString(status.chain.network_id_hex);
  if (!expected_network_id.isEmpty() && observed_network_id != expected_network_id) {
    return QString("network_id mismatch: expected %1 got %2")
        .arg(elide_middle(expected_network_id, 8), elide_middle(observed_network_id, 8));
  }
  const auto expected_genesis_hash = expected_genesis_hash_hex_for_wallet_network(status.chain.network_name);
  const QString observed_genesis_hash = QString::fromStdString(status.chain.genesis_hash_hex);
  if (expected_genesis_hash.has_value()) {
    const QString expected_genesis = QString::fromStdString(*expected_genesis_hash);
    if (observed_genesis_hash != expected_genesis) {
      return QString("genesis mismatch: expected %1 got %2")
          .arg(elide_middle(expected_genesis, 10), elide_middle(observed_genesis_hash, 10));
    }
  }
  return std::nullopt;
}

QString onboarding_state_display_text(finalis::onboarding::ValidatorOnboardingState state) {
  using finalis::onboarding::ValidatorOnboardingState;
  switch (state) {
    case ValidatorOnboardingState::IDLE:
      return "Not started";
    case ValidatorOnboardingState::CHECKING_PREREQS:
      return "Checking readiness";
    case ValidatorOnboardingState::WAITING_FOR_SYNC:
      return "Waiting for node sync";
    case ValidatorOnboardingState::WAITING_FOR_FUNDS:
      return "Waiting for bond funding";
    case ValidatorOnboardingState::SELECTING_UTXOS:
      return "Selecting finalized inputs";
    case ValidatorOnboardingState::BUILDING_JOIN_TX:
      return "Building join transaction";
    case ValidatorOnboardingState::BROADCASTING_JOIN_TX:
      return "Broadcasting join transaction";
    case ValidatorOnboardingState::WAITING_FOR_FINALIZATION:
      return "Waiting for finalized inclusion";
    case ValidatorOnboardingState::PENDING_ACTIVATION:
      return "Join finalized, waiting for activation";
    case ValidatorOnboardingState::ACTIVE:
      return "Validator active";
    case ValidatorOnboardingState::FAILED:
      return "Failed";
    case ValidatorOnboardingState::CANCELLED:
      return "Cancelled";
  }
  return "Unknown";
}

QString send_reservation_note(std::size_t pending_reserved, std::size_t onboarding_reserved) {
  QStringList lines;
  if (pending_reserved > 0) {
    lines << QString("Reserved by pending local sends: %1.").arg(static_cast<qulonglong>(pending_reserved));
  }
  if (onboarding_reserved > 0) {
    lines << QString("Reserved by validator onboarding: %1.").arg(static_cast<qulonglong>(onboarding_reserved));
  }
  return lines.join("\n");
}

}  // namespace

QString onboarding_error_display_text(const QString& error_code, const QString& fallback_message) {
  const QString code = error_code.trimmed().toLower();
  if (code == "node_not_ready") {
    return "Node is not ready for validator registration yet. Wait for sync/readiness blockers to clear.";
  }
  if (code == "selection_failed") {
    return "Unable to reserve finalized inputs for the validator bond. Check finalized balance and any pending local sends.";
  }
  if (code == "build_failed") {
    return "Unable to build the validator join transaction from the current wallet and key data.";
  }
  if (code == "tx_rejected") {
    return "The validator join transaction was built but rejected by the relay/runtime checks.";
  }
  if (code == "relay_unavailable") {
    return "The relay service could not be reached while trying to submit the validator join transaction.";
  }
  if (code == "tx_missing_or_unconfirmed_input" || code == "missing_utxo") {
    return "The selected finalized inputs changed before broadcast. Refresh finalized state and try again.";
  }
  return fallback_message.trimmed().isEmpty() ? "Validator onboarding failed." : fallback_message;
}

QString onboarding_badge_html(const QString& badge) {
  const QString upper = badge.trimmed().toUpper();
  QString background = "#3a3a3a";
  QString foreground = "#f3f3f3";
  if (upper == "TRACKED") {
    background = "#1f4b99";
  } else if (upper == "DETACHED") {
    background = "#66511f";
  } else if (upper == "FAILED") {
    background = "#7a2f2f";
  } else if (upper == "IDLE") {
    background = "#4a4a4a";
  }
  return QString("<span style=\"display:inline-block;padding:2px 8px;border-radius:10px;background:%1;color:%2;font-weight:600;\">%3</span>")
      .arg(background, foreground, upper.toHtmlEscaped());
}

namespace {

std::vector<std::uint64_t> split_into_denominations(std::uint64_t amount) {
  std::vector<std::uint64_t> out;
  if (amount == 0) return out;
  std::vector<std::uint64_t> denoms;
  for (std::uint64_t scale = 1; scale <= amount; ) {
    denoms.push_back(scale);
    if (scale <= amount / 2) denoms.push_back(scale * 2);
    if (scale <= amount / 5) denoms.push_back(scale * 5);
    if (scale > amount / 10) break;
    scale *= 10;
  }
  std::sort(denoms.begin(), denoms.end());
  denoms.erase(std::unique(denoms.begin(), denoms.end()), denoms.end());
  std::sort(denoms.rbegin(), denoms.rend());
  std::uint64_t remaining = amount;
  for (const auto denom : denoms) {
    while (denom <= remaining) {
      out.push_back(denom);
      remaining -= denom;
    }
  }
  if (remaining > 0) out.push_back(remaining);
  return out;
}

QString mono_font_family() {
  QFont f = QFontDatabase::systemFont(QFontDatabase::FixedFont);
  return f.family();
}

QString trim_after_token(const QString& line, const QString& token) {
  const int pos = line.indexOf(token);
  if (pos < 0) return {};
  return line.mid(pos + token.size()).trimmed();
}

QString normalize_lightserver_endpoint(QString endpoint) {
  endpoint = endpoint.trimmed();
  while (endpoint.endsWith('/')) endpoint.chop(1);
  if (!endpoint.isEmpty() && !endpoint.endsWith("/rpc")) endpoint += "/rpc";
  return endpoint;
}

QStringList parse_lightserver_endpoint_lines(const QString& text) {
  QStringList endpoints;
  const QStringList lines = text.split('\n');
  for (QString endpoint : lines) {
    endpoint = normalize_lightserver_endpoint(endpoint);
    if (endpoint.isEmpty()) continue;
    if (!endpoints.contains(endpoint)) endpoints.push_back(endpoint);
  }
  return endpoints;
}

QString display_lightserver_endpoint(QString endpoint) {
  endpoint = endpoint.trimmed();
  endpoint.remove("http://");
  endpoint.remove("/rpc");
  return endpoint;
}

QString extract_field_value(const QString& line, const QString& field) {
  const QString needle = field + "=";
  const int pos = line.indexOf(needle);
  if (pos < 0) return {};
  int end = line.indexOf(' ', pos + needle.size());
  if (end < 0) end = line.size();
  return line.mid(pos + needle.size(), end - (pos + needle.size())).trimmed();
}

QString extract_amount_prefix(const QString& text) {
  const QString ticker_suffix = QString(" ") + kDisplayTicker;
  const int pos = text.indexOf(ticker_suffix);
  if (pos < 0) return {};
  return text.left(pos + ticker_suffix.size()).trimmed();
}

QString local_history_status(const QString& line) {
  if (line.startsWith("[pending]")) return "PENDING";
  if (line.startsWith("[finalized]")) return "FINALIZED";
  if (line.startsWith("[onboarding]")) return "INFO";
  return "INFO";
}

QString local_history_kind(const QString& line) {
  if (line.startsWith("[pending]") || line.startsWith("[finalized]")) return "Local Send";
  if (line.startsWith("[onboarding]")) return "Onboarding";
  return "Local Event";
}

QString local_history_reference(const QString& line) {
  if (line.startsWith("[pending]")) {
    const int open = line.lastIndexOf('(');
    const int close = line.lastIndexOf(')');
    if (open >= 0 && close > open) return line.mid(open + 1, close - open - 1).trimmed();
  }
  if (line.startsWith("[finalized]")) return trim_after_token(line, "[finalized]");
  return {};
}

QString local_history_state(const QString& line) {
  if (line.startsWith("[pending]")) return "local relay accepted";
  if (line.startsWith("[finalized]")) return "local note";
  if (line.startsWith("[onboarding]")) return "local tracking";
  return "local event";
}

QString format_relative_duration_ms(std::uint64_t ms) {
  const std::uint64_t seconds = ms / 1000;
  if (seconds < 60) return QString("%1s").arg(seconds);
  const std::uint64_t minutes = seconds / 60;
  const std::uint64_t rem_seconds = seconds % 60;
  if (minutes < 60) return rem_seconds == 0 ? QString("%1m").arg(minutes)
                                             : QString("%1m %2s").arg(minutes).arg(rem_seconds);
  const std::uint64_t hours = minutes / 60;
  const std::uint64_t rem_minutes = minutes % 60;
  return rem_minutes == 0 ? QString("%1h").arg(hours)
                          : QString("%1h %2m").arg(hours).arg(rem_minutes);
}

QString pending_release_state_text(const WalletStore::PendingSpend& pending, std::uint64_t current_tip_height,
                                   std::uint64_t now_ms) {
  const QString txid_text = pending.txid_hex.empty() ? "-" : elide_middle(QString::fromStdString(pending.txid_hex), 10);
  const std::uint64_t tip_delta =
      current_tip_height >= pending.created_tip_height ? (current_tip_height - pending.created_tip_height) : 0;
  const std::uint64_t age_ms = now_ms >= pending.created_unix_ms ? (now_ms - pending.created_unix_ms) : 0;
  const std::uint64_t tip_remaining =
      tip_delta >= kPendingSendReleaseMinTipDelta ? 0 : (kPendingSendReleaseMinTipDelta - tip_delta);
  const std::uint64_t age_remaining =
      age_ms >= kPendingSendReleaseMinAgeMs ? 0 : (kPendingSendReleaseMinAgeMs - age_ms);
  if (tip_remaining == 0 && age_remaining == 0) {
    return QString("Pending tx %1. Release-eligible after explicit not_found. Tip +%2/%3, age %4/%5")
        .arg(txid_text)
        .arg(tip_delta)
        .arg(kPendingSendReleaseMinTipDelta)
        .arg(format_relative_duration_ms(age_ms))
        .arg(format_relative_duration_ms(kPendingSendReleaseMinAgeMs));
  }
  return QString("Pending tx %1. Reserved. Release gate: tip +%2/%3, age %4/%5")
      .arg(txid_text)
      .arg(tip_delta)
      .arg(kPendingSendReleaseMinTipDelta)
      .arg(format_relative_duration_ms(age_ms))
      .arg(format_relative_duration_ms(kPendingSendReleaseMinAgeMs));
}

QString badge_text(const QString& status) {
  const QString upper = status.trimmed().toUpper();
  return upper.isEmpty() ? "[INFO]" : "[" + upper + "]";
}

QString title_case_status(const QString& status) {
  const QString upper = status.trimmed().toUpper();
  if (upper == "FINALIZED") return "Finalized";
  if (upper == "PENDING") return "Pending";
  if (upper == "FAILED") return "Failed";
  if (upper == "REJECTED") return "Rejected";
  if (upper == "INFO") return "Info";
  return status.trimmed().isEmpty() ? "Info" : status.trimmed();
}

QString display_chain_kind(const QString& kind) {
  const QString upper = kind.trimmed().toUpper();
  if (upper == "SENT") return "Sent";
  if (upper == "RECEIVED") return "Received";
  if (upper == "ACTIVITY") return "On-chain";
  return kind.trimmed().isEmpty() ? "Activity" : kind.trimmed();
}

QString display_mint_kind(const QString& kind) {
  const QString lower = kind.trimmed().toLower();
  if (lower == "deposit") return "Mint Deposit";
  if (lower == "redemption") return "Mint Redemption";
  if (lower == "note") return "Mint Note";
  if (lower == "issue") return "Mint Issue";
  if (lower == "status") return "Mint Status";
  return kind.trimmed().isEmpty() ? "Mint" : kind.trimmed();
}

QString mint_state_badge(const QString& state) {
  const QString lower = state.trimmed().toLower();
  if (lower == "finalized" || lower == "issued") return "FINALIZED";
  if (lower == "broadcast" || lower == "pending" || lower == "registered") return "PENDING";
  if (lower == "rejected" || lower == "failed") return "FAILED";
  return state.trimmed().isEmpty() ? "INFO" : state.trimmed().toUpper();
}

void configure_table(QTableWidget* table, const QStringList& headers) {
  table->setColumnCount(headers.size());
  table->setHorizontalHeaderLabels(headers);
  table->setSelectionBehavior(QAbstractItemView::SelectRows);
  table->setSelectionMode(QAbstractItemView::SingleSelection);
  table->setEditTriggers(QAbstractItemView::NoEditTriggers);
  table->setAlternatingRowColors(true);
  table->setSortingEnabled(true);
  table->verticalHeader()->setVisible(false);
  table->horizontalHeader()->setStretchLastSection(true);
  table->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
}

void configure_page_layout(QVBoxLayout* layout, int spacing = 12) {
  if (!layout) return;
  layout->setContentsMargins(14, 14, 14, 14);
  layout->setSpacing(spacing);
}

void configure_form_layout(QFormLayout* layout) {
  if (!layout) return;
  layout->setContentsMargins(0, 0, 0, 0);
  layout->setHorizontalSpacing(14);
  layout->setVerticalSpacing(10);
  layout->setFieldGrowthPolicy(QFormLayout::ExpandingFieldsGrow);
  layout->setFormAlignment(Qt::AlignTop | Qt::AlignLeft);
  layout->setLabelAlignment(Qt::AlignLeft | Qt::AlignVCenter);
}

void restore_table_sort(QTableWidget* table, QSettings& settings, const QString& prefix, int default_col = 0) {
  const int column = settings.value(prefix + "_sort_column", default_col).toInt();
  const auto order = static_cast<Qt::SortOrder>(settings.value(prefix + "_sort_order", static_cast<int>(Qt::AscendingOrder)).toInt());
  table->sortByColumn(column, order);
}

QColor status_background(const QString& status) {
  const QString upper = status.trimmed().toUpper();
  const bool dark = qApp && qApp->palette().color(QPalette::Window).lightness() < 128;
  if (dark) {
    if (upper == "FINALIZED") return QColor(46, 46, 46);
    if (upper == "PENDING") return QColor(58, 58, 58);
    if (upper == "FAILED") return QColor(72, 52, 52);
    return QColor(34, 34, 34);
  }
  if (upper == "FINALIZED") return QColor(232, 232, 232);
  if (upper == "PENDING") return QColor(240, 240, 240);
  if (upper == "FAILED") return QColor(236, 224, 224);
  return QColor(243, 243, 243);
}

QColor amount_foreground(bool positive) {
  const bool dark = qApp && qApp->palette().color(QPalette::Window).lightness() < 128;
  if (positive) return dark ? QColor(122, 214, 143) : QColor(19, 124, 52);
  return dark ? QColor(255, 150, 150) : QColor(176, 43, 43);
}

void apply_amount_item_style(QTableWidgetItem* item, const QString& kind, const QString& status) {
  if (!item) return;
  const QString upper_kind = kind.trimmed().toUpper();
  const QString upper_status = status.trimmed().toUpper();
  if (upper_kind == "RECEIVED") {
    item->setForeground(QBrush(amount_foreground(true)));
    return;
  }
  if (upper_kind == "SENT" || (upper_kind == "PENDING (LOCAL)" && upper_status == "PENDING")) {
    item->setForeground(QBrush(amount_foreground(false)));
  }
}

void apply_status_item_style(QTableWidgetItem* item) {
  if (!item) return;
  item->setBackground(QBrush(status_background(item->text())));
}

void install_copy_menu(QLabel* label, QWidget* owner) {
  label->setContextMenuPolicy(Qt::CustomContextMenu);
  QObject::connect(label, &QLabel::customContextMenuRequested, owner, [label, owner](const QPoint& pos) {
    if (label->text().trimmed().isEmpty() || label->text() == "-") return;
    QMenu menu(owner);
    auto* copy = menu.addAction("Copy");
    if (menu.exec(label->mapToGlobal(pos)) == copy) QApplication::clipboard()->setText(label->text().trimmed());
  });
}

void install_table_copy_menu(QTableWidget* table, QWidget* owner) {
  table->setContextMenuPolicy(Qt::CustomContextMenu);
  QObject::connect(table, &QTableWidget::customContextMenuRequested, owner, [table, owner](const QPoint& pos) {
    auto* item = table->itemAt(pos);
    if (!item || item->text().trimmed().isEmpty()) return;
    QMenu menu(owner);
    auto* copy_cell = menu.addAction("Copy Cell");
    auto* copy_row = menu.addAction("Copy Row");
    auto* chosen = menu.exec(table->viewport()->mapToGlobal(pos));
    if (chosen == copy_cell) {
      QApplication::clipboard()->setText(item->text().trimmed());
      return;
    }
    if (chosen == copy_row) {
      QStringList values;
      for (int c = 0; c < table->columnCount(); ++c) {
        auto* cell = table->item(item->row(), c);
        if (cell && !cell->text().trimmed().isEmpty()) values.push_back(cell->text().trimmed());
      }
      QApplication::clipboard()->setText(values.join(" | "));
    }
  });
}

std::optional<std::vector<std::size_t>> choose_note_subset_exact(const std::vector<finalis::wallet::WalletWindow::MintNote>& notes,
                                                                 std::uint64_t target) {
  std::map<std::uint64_t, std::vector<std::size_t>> reachable;
  reachable[0] = {};
  for (std::size_t i = 0; i < notes.size(); ++i) {
    std::vector<std::pair<std::uint64_t, std::vector<std::size_t>>> additions;
    for (const auto& [sum, indexes] : reachable) {
      if (sum + notes[i].amount > target) continue;
      if (reachable.find(sum + notes[i].amount) != reachable.end()) continue;
      auto next = indexes;
      next.push_back(i);
      additions.push_back({sum + notes[i].amount, std::move(next)});
    }
    for (auto& [sum, indexes] : additions) reachable.emplace(sum, std::move(indexes));
    auto it = reachable.find(target);
    if (it != reachable.end()) return it->second;
  }
  return std::nullopt;
}

std::vector<WalletWindow::ChainRecord> normalize_chain_records_for_display(const std::vector<WalletWindow::ChainRecord>& records) {
  std::vector<ChainRecordView> raw;
  raw.reserve(records.size());
  for (const auto& rec : records) {
    raw.push_back(ChainRecordView{
        .status = rec.status.toStdString(),
        .kind = rec.kind.toStdString(),
        .amount = rec.amount.toStdString(),
        .reference = rec.reference.toStdString(),
        .height = rec.height.toStdString(),
        .txid = rec.txid.toStdString(),
        .details = rec.details.toStdString(),
    });
  }
  auto merged = merge_chain_records_for_display(raw);
  struct OrderedChainRecord {
    ChainRecordView rec;
    std::size_t original_index;
  };
  std::vector<OrderedChainRecord> ordered;
  ordered.reserve(merged.size());
  for (std::size_t i = 0; i < merged.size(); ++i) ordered.push_back(OrderedChainRecord{std::move(merged[i]), i});
  std::stable_sort(ordered.begin(), ordered.end(), [](const OrderedChainRecord& a, const OrderedChainRecord& b) {
    const QString a_status = QString::fromStdString(a.rec.status).trimmed().toUpper();
    const QString b_status = QString::fromStdString(b.rec.status).trimmed().toUpper();
    const bool a_finalized = a_status == "FINALIZED";
    const bool b_finalized = b_status == "FINALIZED";
    if (a_finalized != b_finalized) return a_finalized;

    bool a_height_ok = false;
    bool b_height_ok = false;
    const qulonglong a_height = QString::fromStdString(a.rec.height).toULongLong(&a_height_ok);
    const qulonglong b_height = QString::fromStdString(b.rec.height).toULongLong(&b_height_ok);
    if (a_height_ok != b_height_ok) return a_height_ok;
    if (a_height_ok && b_height_ok && a_height != b_height) return a_height > b_height;

    const bool a_pending = a_status == "PENDING";
    const bool b_pending = b_status == "PENDING";
    if (a_pending != b_pending) return a_pending;

    return a.original_index > b.original_index;
  });
  std::vector<WalletWindow::ChainRecord> out;
  out.reserve(ordered.size());
  for (const auto& ordered_rec : ordered) {
    const auto& rec = ordered_rec.rec;
    out.push_back(WalletWindow::ChainRecord{
        QString::fromStdString(rec.status),
        QString::fromStdString(rec.kind),
        QString::fromStdString(rec.amount),
        QString::fromStdString(rec.reference),
        QString::fromStdString(rec.height),
        QString::fromStdString(rec.txid),
        QString::fromStdString(rec.details),
    });
  }
  return out;
}

}  // namespace

HistoryFlowClassification classify_wallet_history_flow(std::uint64_t credited, std::uint64_t debited) {
  return classify_wallet_history_flow_impl(credited, debited);
}

WalletWindow::WalletWindow() {
  build_ui();
  load_settings();
  const QString startup_wallet_path = preferred_startup_wallet_path();
  if (!wallet_ && !startup_wallet_path.isEmpty()) {
    const auto passphrase = prompt_passphrase("Open Default Wallet", false);
    if (passphrase.has_value()) {
      if (auto loaded = load_wallet_file(startup_wallet_path, *passphrase)) {
        wallet_ = *loaded;
        (void)open_wallet_store();
        load_wallet_local_state();
        (void)refresh_finalized_send_state();
        QSettings settings(kSettingsOrg, kSettingsApp);
        settings.setValue("wallet/last_opened_file", startup_wallet_path);
        append_local_event("Opened default wallet " + startup_wallet_path);
      }
    }
  }
  update_wallet_views();
  update_connection_views();
  if (wallet_) refresh_chain_state(false);
}

void WalletWindow::build_ui() {
  setWindowTitle("Finalis Wallet");
  setWindowIcon(QIcon(":/branding/finalis-app-icon.svg"));
  resize(1024, 760);
  setMinimumSize(760, 560);

  auto* central = new QWidget(this);
  auto* root = new QVBoxLayout(central);
  root->setContentsMargins(12, 8, 12, 10);
  root->setSpacing(10);

  auto* file_menu = menuBar()->addMenu("&File");
  auto* wallet_menu = menuBar()->addMenu("&Wallet");
  auto* view_menu = menuBar()->addMenu("&View");
  auto* help_menu = menuBar()->addMenu("&Help");

  auto* create_action = file_menu->addAction("Create Wallet");
  create_action->setShortcut(QKeySequence("Ctrl+N"));
  auto* open_action = file_menu->addAction("Open Wallet");
  open_action->setShortcut(QKeySequence::Open);
  auto* import_action = file_menu->addAction("Import Wallet");
  import_action->setShortcut(QKeySequence("Ctrl+I"));
  auto* export_action = file_menu->addAction("Export Backup");
  export_action->setShortcut(QKeySequence("Ctrl+E"));
  file_menu->addSeparator();
  auto* quit_action = file_menu->addAction("Quit");
  quit_action->setShortcut(QKeySequence::Quit);

  auto* refresh_action = view_menu->addAction("Refresh");
  refresh_action->setShortcut(QKeySequence::Refresh);
  auto* unlock_confidential_action = wallet_menu->addAction("Unlock Confidential State");
  auto* history_detail_action = view_menu->addAction("Selected Record Details");
  history_detail_action->setShortcut(QKeySequence("Ctrl+D"));
  auto* mint_detail_action = wallet_menu->addAction("Selected Mint Details");
  mint_detail_action->setShortcut(QKeySequence("Ctrl+M"));
  auto* about_action = help_menu->addAction("About");

  auto* header_card = new QFrame(this);
  header_card->setProperty("role", "headerCard");
  auto* header_layout = new QHBoxLayout(header_card);
  header_layout->setContentsMargins(6, 4, 6, 8);
  header_layout->setSpacing(12);

  header_logo_label_ = make_brand_image(":/branding/finalis-symbol.svg", QSize(42, 42), header_card, "FLS");
  header_logo_label_->setMinimumSize(42, 42);
  header_logo_label_->setMaximumSize(42, 42);
  header_layout->addWidget(header_logo_label_, 0, Qt::AlignVCenter);

  auto* header_text = new QVBoxLayout();
  header_text->setSpacing(1);
  header_title_label_ = new QLabel("Wallet overview", header_card);
  header_title_label_->setProperty("role", "metric");
  auto* header_note = new QLabel(
      "Desktop wallet for finalized state. Private keys stay local.",
      header_card);
  header_note->setWordWrap(true);
  header_note->setProperty("role", "muted");
  header_text->addWidget(header_title_label_);
  header_text->addWidget(header_note);
  header_layout->addLayout(header_text, 1);

  auto* header_status = new QGridLayout();
  header_status->setHorizontalSpacing(6);
  header_status->setVerticalSpacing(4);
  header_network_label_ = new QLabel("Network: mainnet", header_card);
  header_network_label_->setProperty("role", "chip");
  header_network_label_->setWordWrap(true);
  header_network_label_->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Preferred);
  header_tip_label_ = new QLabel("Finalized tip: unavailable", header_card);
  header_tip_label_->setProperty("role", "chip");
  header_tip_label_->setWordWrap(true);
  header_tip_label_->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Preferred);
  header_connection_label_ = new QLabel("Lightserver: unavailable", header_card);
  header_connection_label_->setProperty("role", "chip");
  header_connection_label_->setWordWrap(true);
  header_connection_label_->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Preferred);
  header_crosscheck_label_ = new QLabel("Cross-check: unavailable", header_card);
  header_crosscheck_label_->setProperty("role", "chip");
  header_crosscheck_label_->setWordWrap(true);
  header_crosscheck_label_->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Preferred);
  header_status->addWidget(header_network_label_, 0, 0, Qt::AlignRight);
  header_status->addWidget(header_tip_label_, 0, 1, Qt::AlignRight);
  header_status->addWidget(header_connection_label_, 1, 0, Qt::AlignRight);
  header_status->addWidget(header_crosscheck_label_, 1, 1, Qt::AlignRight);
  header_layout->addLayout(header_status, 0);
  root->addWidget(header_card);

  auto* top_actions = new QHBoxLayout();
  top_actions->setContentsMargins(0, 2, 0, 2);
  top_actions->setSpacing(8);
  auto* create_button = new QPushButton("New Wallet", this);
  auto* open_button = new QPushButton("Open Wallet", this);
  auto* import_button = new QPushButton("Import Wallet", this);
  auto* export_button = new QPushButton("Export Backup", this);
  auto* refresh_button = new QPushButton("Refresh State", this);
  create_button->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Preferred);
  open_button->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Preferred);
  import_button->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Preferred);
  export_button->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Preferred);
  refresh_button->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Preferred);
  auto* primary_actions = new QHBoxLayout();
  primary_actions->setSpacing(8);
  primary_actions->addWidget(create_button);
  primary_actions->addWidget(open_button);
  auto* secondary_actions = new QHBoxLayout();
  secondary_actions->setSpacing(8);
  secondary_actions->addWidget(import_button);
  secondary_actions->addWidget(export_button);
  auto* utility_separator = new QFrame(this);
  utility_separator->setFrameShape(QFrame::VLine);
  utility_separator->setFrameShadow(QFrame::Plain);
  top_actions->addLayout(primary_actions);
  top_actions->addSpacing(6);
  top_actions->addLayout(secondary_actions);
  top_actions->addSpacing(10);
  top_actions->addWidget(utility_separator);
  top_actions->addSpacing(10);
  top_actions->addWidget(refresh_button);
  top_actions->addStretch(1);
  root->addLayout(top_actions);

  tabs_ = new QTabWidget(this);
  tabs_->setDocumentMode(true);
  root->addWidget(tabs_);

  overview_page_ = new OverviewPage(this);
  send_page_ = new SendPage(this);
  receive_page_ = new ReceivePage(this);
  activity_page_ = new ActivityPage(this);
  advanced_page_ = new AdvancedPage(this);
  settings_page_ = new SettingsPage(this);

  wallet_status_label_ = overview_page_->wallet_status_label();
  wallet_file_label_ = overview_page_->wallet_file_label();
  network_label_ = overview_page_->network_label();
  balance_label_ = overview_page_->balance_label();
  pending_balance_label_ = overview_page_->pending_balance_label();
  confidential_balance_label_ = overview_page_->confidential_balance_label();
  receive_address_home_label_ = overview_page_->receive_address_label();
  overview_confidential_receive_label_ = overview_page_->confidential_receive_label();
  tip_status_label_ = overview_page_->tip_status_label();
  overview_connection_status_label_ = overview_page_->connection_status_label();
  overview_send_button_ = overview_page_->send_button();
  overview_receive_button_ = overview_page_->receive_button();
  overview_activity_button_ = overview_page_->view_activity_button();
  overview_open_explorer_button_ = overview_page_->open_explorer_button();

  send_address_edit_ = send_page_->address_edit();
  send_mode_combo_ = send_page_->mode_combo();
  send_amount_edit_ = send_page_->amount_edit();
  send_fee_edit_ = send_page_->fee_edit();
  send_max_button_ = send_page_->max_button();
  send_import_confidential_request_button_ = send_page_->import_confidential_request_button();
  send_review_button_ = send_page_->review_button();
  send_button_ = send_page_->send_button();
  send_review_status_label_ = send_page_->review_status_label();
  send_review_warning_label_ = send_page_->review_warning_label();
  send_review_recipient_label_ = send_page_->review_recipient_label();
  send_review_amount_label_ = send_page_->review_amount_label();
  send_review_fee_label_ = send_page_->review_fee_label();
  send_review_total_label_ = send_page_->review_total_label();
  send_review_change_label_ = send_page_->review_change_label();
  send_review_inputs_label_ = send_page_->review_inputs_label();
  send_review_note_label_ = send_page_->review_note_label();

  receive_address_label_ = receive_page_->address_label();
  receive_confidential_address_label_ = receive_page_->confidential_address_label();
  receive_confidential_request_label_ = receive_page_->confidential_request_label();
  receive_confidential_request_summary_label_ = receive_page_->confidential_request_summary_label();
  receive_confidential_requests_table_ = receive_page_->confidential_requests_table();
  receive_confidential_coin_summary_label_ = receive_page_->confidential_coin_summary_label();
  receive_confidential_coins_table_ = receive_page_->confidential_coins_table();
  receive_confidential_pending_status_view_ = receive_page_->confidential_pending_status_view();
  receive_copy_confidential_pending_txid_button_ = receive_page_->copy_confidential_pending_txid_button();
  receive_inspect_confidential_pending_tx_button_ = receive_page_->inspect_confidential_pending_tx_button();
  receive_copy_status_label_ = receive_page_->copy_status_label();
  receive_finalized_note_label_ = receive_page_->finalized_note_label();
  receive_confidential_note_label_ = receive_page_->confidential_note_label();
  auto* copy_address_button = receive_page_->copy_button();
  auto* create_confidential_account_button = receive_page_->create_confidential_account_button();
  auto* import_confidential_account_button = receive_page_->import_confidential_account_button();
  auto* generate_confidential_request_button = receive_page_->generate_confidential_request_button();
  auto* copy_confidential_request_button = receive_page_->copy_confidential_request_button();
  auto* import_confidential_tx_button = receive_page_->import_confidential_tx_button();
  auto* copy_confidential_pending_txid_button = receive_page_->copy_confidential_pending_txid_button();
  auto* inspect_confidential_pending_tx_button = receive_page_->inspect_confidential_pending_tx_button();

  history_filter_combo_ = activity_page_->filter_combo();
  history_detail_button_ = activity_page_->detail_button();
  history_view_ = activity_page_->table();
  activity_finalized_count_label_ = activity_page_->finalized_count_label();
  activity_pending_count_label_ = activity_page_->pending_count_label();
  activity_local_count_label_ = activity_page_->local_count_label();
  activity_mint_count_label_ = activity_page_->mint_count_label();
  activity_confidential_count_label_ = activity_page_->confidential_count_label();
  activity_detail_title_label_ = activity_page_->detail_title_label();
  activity_detail_view_ = activity_page_->detail_view();

  validator_readiness_label_ = advanced_page_->validator_readiness_label();
  validator_funding_label_ = advanced_page_->validator_funding_label();
  validator_state_label_ = advanced_page_->validator_state_label();
  validator_required_bond_label_ = advanced_page_->validator_required_bond_label();
  validator_available_balance_label_ = advanced_page_->validator_available_balance_label();
  validator_blockers_label_ = advanced_page_->validator_blockers_label();
  validator_live_status_label_ = advanced_page_->validator_live_status_label();
  validator_summary_label_ = advanced_page_->validator_summary_label();
  validator_action_button_ = advanced_page_->validator_action_button();
  validator_refresh_button_ = advanced_page_->validator_refresh_button();
  validator_cancel_button_ = advanced_page_->validator_cancel_button();
  validator_toggle_details_button_ = advanced_page_->validator_toggle_details_button();
  validator_db_path_edit_ = advanced_page_->validator_db_path_edit();
  validator_key_path_edit_ = advanced_page_->validator_key_path_edit();
  validator_rpc_url_edit_ = advanced_page_->validator_rpc_url_edit();
  validator_details_view_ = advanced_page_->validator_details_view();

  mint_deposit_amount_edit_ = advanced_page_->mint_deposit_amount_edit();
  mint_redeem_amount_edit_ = advanced_page_->mint_redeem_amount_edit();
  mint_redeem_address_edit_ = advanced_page_->mint_redeem_address_edit();
  mint_issue_amount_edit_ = advanced_page_->mint_issue_amount_edit();
  mint_deposit_ref_label_ = advanced_page_->mint_deposit_ref_label();
  mint_notes_label_ = advanced_page_->mint_notes_label();
  mint_redemption_label_ = advanced_page_->mint_redemption_label();
  mint_status_label_ = advanced_page_->mint_status_label();
  mint_private_balance_label_ = advanced_page_->mint_private_balance_label();
  mint_note_count_label_ = advanced_page_->mint_note_count_label();
  mint_deposits_view_ = advanced_page_->mint_deposits_view();
  mint_notes_view_ = advanced_page_->mint_notes_view();
  mint_redemptions_view_ = advanced_page_->mint_redemptions_view();
  mint_detail_button_ = advanced_page_->mint_detail_button();
  mint_deposit_button_ = advanced_page_->mint_deposit_button();
  mint_issue_button_ = advanced_page_->mint_issue_button();
  mint_redeem_button_ = advanced_page_->mint_redeem_button();
  mint_redeem_status_button_ = advanced_page_->mint_redeem_status_button();

  lightserver_urls_edit_ = advanced_page_->lightserver_urls_edit();
  pin_lightserver_endpoint_checkbox_ = advanced_page_->pin_lightserver_endpoint_checkbox();
  mint_url_edit_ = advanced_page_->mint_url_edit();
  mint_id_edit_ = advanced_page_->mint_id_edit();
  connection_summary_label_ = advanced_page_->connection_summary_label();
  save_settings_button_ = advanced_page_->save_settings_button();
  crosscheck_detail_view_ = advanced_page_->crosscheck_detail_view();
  adaptive_regime_view_ = advanced_page_->adaptive_regime_view();

  theme_combo_ = settings_page_->theme_combo();
  branding_symbol_label_ = settings_page_->branding_symbol_label();
  about_button_ = settings_page_->about_button();

  const QString default_fee_text = format_coin_amount(finalis::DEFAULT_WALLET_SEND_FEE_UNITS).replace(
      QString(" ") + kDisplayTicker, "");
  send_fee_edit_->setText(default_fee_text);
  send_fee_edit_->setPlaceholderText(default_fee_text);

  tabs_->addTab(overview_page_, "Overview");
  tabs_->addTab(send_page_, "Send");
  tabs_->addTab(receive_page_, "Receive");
  tabs_->addTab(activity_page_, "Activity");
  tabs_->addTab(advanced_page_, "Advanced");
  tabs_->addTab(settings_page_, "Settings");

  setCentralWidget(central);

  connect(create_button, &QPushButton::clicked, this, [this]() { create_wallet(); });
  connect(create_action, &QAction::triggered, this, [this]() { create_wallet(); });
  connect(open_button, &QPushButton::clicked, this, [this]() { open_wallet(); });
  connect(open_action, &QAction::triggered, this, [this]() { open_wallet(); });
  connect(import_button, &QPushButton::clicked, this, [this]() { import_wallet(); });
  connect(import_action, &QAction::triggered, this, [this]() { import_wallet(); });
  connect(unlock_confidential_action, &QAction::triggered, this, [this]() { unlock_confidential_state(); });
  connect(export_button, &QPushButton::clicked, this, [this]() { export_wallet_secret(); });
  connect(export_action, &QAction::triggered, this, [this]() { export_wallet_secret(); });
  connect(refresh_button, &QPushButton::clicked, this, [this]() { refresh_chain_state(true); });
  connect(refresh_action, &QAction::triggered, this, [this]() { refresh_chain_state(true); });
  connect(copy_address_button, &QPushButton::clicked, this, [this]() {
    if (!wallet_) return;
    QApplication::clipboard()->setText(QString::fromStdString(wallet_->address));
    if (receive_copy_status_label_) receive_copy_status_label_->setText("Address copied to clipboard.");
    statusBar()->showMessage("Receive address copied to clipboard.", 3000);
  });
  connect(create_confidential_account_button, &QPushButton::clicked, this,
          [this]() { create_confidential_account(); });
  connect(import_confidential_account_button, &QPushButton::clicked, this,
          [this]() { import_confidential_account(); });
  connect(generate_confidential_request_button, &QPushButton::clicked, this,
          [this]() { generate_confidential_request(); });
  connect(copy_confidential_request_button, &QPushButton::clicked, this, [this]() {
    const QString value =
        receive_confidential_request_label_ ? receive_confidential_request_label_->text().trimmed() : QString{};
    if (value.isEmpty() || value == "not generated") return;
    QApplication::clipboard()->setText(value);
    statusBar()->showMessage("Confidential request copied to clipboard.", 3000);
  });
  connect(import_confidential_tx_button, &QPushButton::clicked, this, [this]() { import_received_confidential_tx(); });
  connect(copy_confidential_pending_txid_button, &QPushButton::clicked, this, [this]() {
    if (!receive_confidential_coins_table_) return;
    const int row = receive_confidential_coins_table_->currentRow();
    if (row < 0) return;
    auto* item = receive_confidential_coins_table_->item(row, 0);
    if (!item) return;
    const QString txid = item->data(Qt::UserRole).toString().trimmed();
    if (txid.isEmpty()) return;
    QApplication::clipboard()->setText(txid);
    statusBar()->showMessage("Pending confidential send txid copied to clipboard.", 3000);
  });
  connect(inspect_confidential_pending_tx_button, &QPushButton::clicked, this, [this]() {
    if (!receive_confidential_coins_table_) return;
    const int row = receive_confidential_coins_table_->currentRow();
    if (row < 0) return;
    auto* item = receive_confidential_coins_table_->item(row, 0);
    const QString txid = item ? item->data(Qt::UserRole).toString().trimmed() : QString{};
    if (txid.isEmpty()) return;

    QUrl explorer = explorer_home_url();
    bool opened = false;
    if (explorer.isValid() && !explorer.scheme().isEmpty()) {
      explorer.setPath("/tx/" + txid);
      opened = QDesktopServices::openUrl(explorer);
    }
    if (opened) {
      statusBar()->showMessage("Opened pending transaction in explorer.", 3000);
      return;
    }

    update_selected_confidential_pending_tx_status_panel();

    auto parsed_txid = decode_hex32_string(txid.toStdString());
    if (!parsed_txid) {
      QMessageBox::warning(this, "Inspect Pending Tx", "Pending txid is malformed.");
      return;
    }
    QString used_endpoint;
    std::string rpc_err;
    std::optional<lightserver::TxStatusView> tx_status;
    for (const QString& endpoint : ordered_lightserver_endpoints()) {
      tx_status = lightserver::rpc_get_tx_status(endpoint.toStdString(), *parsed_txid, &rpc_err);
      if (tx_status) {
        used_endpoint = endpoint;
        break;
      }
    }
    if (!tx_status) {
      QMessageBox::warning(this, "Inspect Pending Tx",
                           rpc_err.empty() ? "Unable to query pending transaction status from configured lightservers."
                                           : QString::fromStdString(rpc_err));
      return;
    }
    QMessageBox::information(
        this, "Inspect Pending Tx",
        QString("Txid: %1\nEndpoint: %2\nStatus: %3\nFinalized: %4\nHeight: %5\nFinalized depth: %6\nCredit safe: %7\nTransition: %8")
            .arg(txid,
                 used_endpoint.isEmpty() ? "-" : display_lightserver_endpoint(used_endpoint),
                 QString::fromStdString(tx_status->status),
                 tx_status->finalized ? "yes" : "no",
                 QString::number(tx_status->height),
                 QString::number(tx_status->finalized_depth),
                 tx_status->credit_safe ? "yes" : "no",
                 tx_status->transition_hash.empty() ? "-" : elide_middle(QString::fromStdString(tx_status->transition_hash), 10)));
  });
  connect(receive_confidential_coins_table_, &QTableWidget::itemSelectionChanged, this, [this]() {
    if (!receive_copy_confidential_pending_txid_button_ || !receive_inspect_confidential_pending_tx_button_ ||
        !receive_confidential_coins_table_) {
      return;
    }
    const int row = receive_confidential_coins_table_->currentRow();
    bool enabled = false;
    if (row >= 0) {
      auto* item = receive_confidential_coins_table_->item(row, 0);
      enabled = item && !item->data(Qt::UserRole).toString().trimmed().isEmpty();
    }
    receive_copy_confidential_pending_txid_button_->setEnabled(enabled);
    receive_inspect_confidential_pending_tx_button_->setEnabled(enabled);
    update_selected_confidential_pending_tx_status_panel();
  });
  connect(overview_send_button_, &QPushButton::clicked, this, [this]() { tabs_->setCurrentWidget(send_page_); });
  connect(overview_receive_button_, &QPushButton::clicked, this, [this]() { tabs_->setCurrentWidget(receive_page_); });
  connect(overview_activity_button_, &QPushButton::clicked, this, [this]() { tabs_->setCurrentWidget(activity_page_); });
  connect(overview_open_explorer_button_, &QPushButton::clicked, this, [this]() { open_explorer_home(); });
  connect(send_max_button_, &QPushButton::clicked, this, [this]() { populate_send_max_amount(); });
  connect(send_import_confidential_request_button_, &QPushButton::clicked, this,
          [this]() { import_confidential_request(); });
  connect(send_review_button_, &QPushButton::clicked, this, [this]() { validate_send_form(); });
  connect(send_button_, &QPushButton::clicked, this, [this]() { submit_send(); });
  connect(validator_action_button_, &QPushButton::clicked, this, [this]() { start_validator_onboarding_clicked(); });
  connect(validator_refresh_button_, &QPushButton::clicked, this, [this]() { refresh_validator_readiness_panel(true); });
  connect(validator_cancel_button_, &QPushButton::clicked, this, [this]() { cancel_validator_onboarding_clicked(); });
  connect(validator_toggle_details_button_, &QPushButton::clicked, this, [this]() { toggle_validator_details(); });
  connect(advanced_page_->validator_db_browse_button(), &QPushButton::clicked, this, [this]() { browse_validator_db_path(); });
  connect(advanced_page_->validator_key_browse_button(), &QPushButton::clicked, this, [this]() { browse_validator_key_path(); });
  connect(validator_db_path_edit_, &QLineEdit::editingFinished, this, [this]() { save_settings(); refresh_validator_readiness_panel(false); });
  connect(validator_key_path_edit_, &QLineEdit::editingFinished, this, [this]() { save_settings(); refresh_validator_readiness_panel(false); });
  connect(validator_rpc_url_edit_, &QLineEdit::editingFinished, this, [this]() { save_settings(); refresh_validator_readiness_panel(false); });
  connect(history_detail_button_, &QPushButton::clicked, this, [this]() { show_selected_history_detail(); });
  connect(history_detail_action, &QAction::triggered, this, [this]() { show_selected_history_detail(); });
  connect(mint_deposit_button_, &QPushButton::clicked, this, [this]() { submit_mint_deposit(); });
  connect(mint_issue_button_, &QPushButton::clicked, this, [this]() { issue_mint_note(); });
  connect(mint_redeem_button_, &QPushButton::clicked, this, [this]() { submit_mint_redemption(); });
  connect(mint_redeem_status_button_, &QPushButton::clicked, this, [this]() { refresh_mint_redemption_status(); });
  connect(mint_detail_button_, &QPushButton::clicked, this, [this]() { show_selected_mint_detail(); });
  connect(mint_detail_action, &QAction::triggered, this, [this]() { show_selected_mint_detail(); });
  connect(about_action, &QAction::triggered, this, [this]() { show_about(); });
  connect(about_button_, &QPushButton::clicked, this, [this]() { show_about(); });
  connect(save_settings_button_, &QPushButton::clicked, this, [this]() { save_connection_settings(); });
  connect(theme_combo_, &QComboBox::currentTextChanged, this, [this](const QString&) { apply_selected_theme(); });
  connect(history_filter_combo_, &QComboBox::currentTextChanged, this, [this](const QString&) { refresh_history_table(); });
  connect(history_view_, &QTableWidget::cellDoubleClicked, this, [this](int, int) { show_selected_history_detail(); });
  connect(history_view_, &QTableWidget::itemSelectionChanged, this, [this]() { update_selected_history_detail(); });
  connect(mint_deposits_view_, &QTableWidget::cellDoubleClicked, this, [this](int, int) { show_selected_mint_detail(); });
  connect(mint_notes_view_, &QTableWidget::cellDoubleClicked, this, [this](int, int) { show_selected_mint_detail(); });
  connect(mint_redemptions_view_, &QTableWidget::cellDoubleClicked, this, [this](int, int) { show_selected_mint_detail(); });
  connect(tabs_, &QTabWidget::currentChanged, this, [this](int index) {
    if (!header_title_label_) return;
    switch (index) {
      case 0: header_title_label_->setText("Wallet overview"); break;
      case 1: header_title_label_->setText("Send"); break;
      case 2: header_title_label_->setText("Receive"); break;
      case 3: header_title_label_->setText("Activity"); break;
      case 4: header_title_label_->setText("Advanced"); break;
      case 5: header_title_label_->setText("Settings"); break;
      default: header_title_label_->setText("Finalis Wallet"); break;
    }
  });

  const QString mono = mono_font_family();
  history_view_->setFont(QFont(mono));
  mint_deposits_view_->setFont(QFont(mono));
  mint_notes_view_->setFont(QFont(mono));
  mint_redemptions_view_->setFont(QFont(mono));
  wallet_file_label_->setFont(QFont(mono));
  receive_address_home_label_->setFont(QFont(mono));
  receive_address_label_->setFont(QFont(mono));
  send_address_edit_->setFont(QFont(mono));
  mint_redeem_address_edit_->setFont(QFont(mono));
  lightserver_urls_edit_->setFont(QFont(mono));
  mint_id_edit_->setFont(QFont(mono));
  connection_summary_label_->setFont(QFont(mono));
  crosscheck_detail_view_->setFont(QFont(mono));
  adaptive_regime_view_->setFont(QFont(mono));
  mint_notes_label_->setFont(QFont(mono));
  activity_detail_view_->setFont(QFont(mono));
  overview_page_->activity_preview_table()->setFont(QFont(mono));
  install_copy_menu(receive_address_home_label_, this);
  install_copy_menu(receive_address_label_, this);
  install_copy_menu(mint_deposit_ref_label_, this);
  install_copy_menu(mint_redemption_label_, this);
  install_table_copy_menu(history_view_, this);
  install_table_copy_menu(receive_confidential_requests_table_, this);
  install_table_copy_menu(receive_confidential_coins_table_, this);
  install_table_copy_menu(mint_deposits_view_, this);
  install_table_copy_menu(mint_notes_view_, this);
  install_table_copy_menu(mint_redemptions_view_, this);
  connect(quit_action, &QAction::triggered, this, [this]() { close(); });

  send_max_button_->setEnabled(false);
  send_review_button_->setEnabled(false);
  send_button_->setEnabled(false);
  const auto update_send_mode_ui = [this]() {
    const auto mode = wallet_send_mode_from_combo(send_mode_combo_);
    if (send_address_edit_) send_address_edit_->setPlaceholderText(wallet_send_mode_default_placeholder(mode));
  };
  const auto update_send_state = [this]() {
    const bool wallet_ready = wallet_.has_value();
    const bool ready =
        wallet_ready && !send_address_edit_->text().trimmed().isEmpty() && !send_amount_edit_->text().trimmed().isEmpty();
    send_max_button_->setEnabled(wallet_ready);
    send_review_button_->setEnabled(ready);
    send_button_->setEnabled(ready);
  };
  connect(send_address_edit_, &QLineEdit::textChanged, this, [update_send_state](const QString&) { update_send_state(); });
  connect(send_amount_edit_, &QLineEdit::textChanged, this, [update_send_state](const QString&) { update_send_state(); });
  connect(send_address_edit_, &QLineEdit::textChanged, this, [this](const QString&) { reset_send_review_panel(); });
  connect(send_amount_edit_, &QLineEdit::textChanged, this, [this](const QString&) { reset_send_review_panel(); });
  connect(send_mode_combo_, qOverload<int>(&QComboBox::currentIndexChanged), this, [this, update_send_mode_ui](int) {
    update_send_mode_ui();
    reset_send_review_panel();
  });
  update_send_mode_ui();
  reset_send_review_panel();

  finalized_tip_poll_timer_ = new QTimer(this);
  finalized_tip_poll_timer_->setInterval(10'000);
  connect(finalized_tip_poll_timer_, &QTimer::timeout, this, [this]() { poll_finalized_tip_status(); });
  finalized_tip_poll_timer_->start();
}

void WalletWindow::load_settings() {
  QSettings settings(kSettingsOrg, kSettingsApp);
  QSettings legacy(kSettingsOrg, kLegacySettingsApp);
  auto load_value = [&](const QString& key, const QVariant& fallback) {
    if (settings.contains(key)) return settings.value(key, fallback);
    return legacy.value(key, fallback);
  };

  QStringList endpoints;
  const QVariant endpoints_value = load_value("lightserver_endpoints", QVariant{});
  if (endpoints_value.isValid()) {
    endpoints = endpoints_value.toStringList();
  }
  if (endpoints.isEmpty()) {
    const QString single =
        normalize_lightserver_endpoint(load_value("lightserver_url", "http://127.0.0.1:19444/rpc").toString());
    if (!single.isEmpty()) endpoints.push_back(single);
  }
  set_lightserver_endpoints(endpoints);
  pin_lightserver_endpoint_checkbox_->setChecked(load_value("lightserver_pin_first", false).toBool());
  last_successful_lightserver_endpoint_ =
      normalize_lightserver_endpoint(load_value("lightserver_last_good", QString{}).toString());
  mint_url_edit_->setText(load_value("mint_url", "http://127.0.0.1:8090").toString());
  mint_id_edit_->setText(load_value("mint_id", "").toString());
  validator_db_path_edit_->setText(load_value("validator/db_path", default_mainnet_db_path()).toString());
  validator_key_path_edit_->setText(load_value("validator/key_path", default_mainnet_validator_key_path()).toString());
  validator_rpc_url_edit_->setText(load_value("validator/rpc_url", "http://127.0.0.1:19444/rpc").toString());
  const QString theme_name = load_value("theme", "Light").toString();
  const int theme_idx = theme_combo_->findText(theme_name, Qt::MatchFixedString);
  if (theme_idx >= 0) theme_combo_->setCurrentIndex(theme_idx);
  apply_selected_theme();

  const QString history_filter = load_value("history_filter", "All").toString();
  const int history_idx = history_filter_combo_->findText(history_filter);
  if (history_idx >= 0) history_filter_combo_->setCurrentIndex(history_idx);
  restore_table_sort(history_view_, settings.contains("history_table_sort_column") ? settings : legacy, "history_table", 4);
  restore_table_sort(mint_deposits_view_,
                     settings.contains("mint_deposits_table_sort_column") ? settings : legacy, "mint_deposits_table", 0);
  restore_table_sort(mint_notes_view_,
                     settings.contains("mint_notes_table_sort_column") ? settings : legacy, "mint_notes_table", 1);
  restore_table_sort(mint_redemptions_view_,
                     settings.contains("mint_redemptions_table_sort_column") ? settings : legacy, "mint_redemptions_table", 0);
}

void WalletWindow::save_settings() const {
  QSettings settings(kSettingsOrg, kSettingsApp);
  const QStringList endpoints = configured_lightserver_endpoints();
  settings.setValue("lightserver_endpoints", endpoints);
  settings.setValue("lightserver_url", endpoints.isEmpty() ? QString{} : endpoints.front());
  settings.setValue("lightserver_pin_first", pin_lightserver_endpoint_checkbox_ &&
                                                 pin_lightserver_endpoint_checkbox_->isChecked());
  settings.setValue("lightserver_last_good", last_successful_lightserver_endpoint_);
  settings.setValue("mint_url", mint_url_edit_->text().trimmed());
  settings.setValue("mint_id", mint_id_edit_->text().trimmed());
  settings.setValue("validator/db_path", validator_db_path_edit_ ? validator_db_path_edit_->text().trimmed() : QString{});
  settings.setValue("validator/key_path", validator_key_path_edit_ ? validator_key_path_edit_->text().trimmed() : QString{});
  settings.setValue("validator/rpc_url", validator_rpc_url_edit_ ? validator_rpc_url_edit_->text().trimmed() : QString{});
  settings.setValue("theme", theme_combo_->currentText());
  settings.setValue("history_filter", history_filter_combo_->currentText());
  settings.setValue("history_table_sort_column", history_view_->horizontalHeader()->sortIndicatorSection());
  settings.setValue("history_table_sort_order", static_cast<int>(history_view_->horizontalHeader()->sortIndicatorOrder()));
  settings.setValue("mint_deposits_table_sort_column", mint_deposits_view_->horizontalHeader()->sortIndicatorSection());
  settings.setValue("mint_deposits_table_sort_order", static_cast<int>(mint_deposits_view_->horizontalHeader()->sortIndicatorOrder()));
  settings.setValue("mint_notes_table_sort_column", mint_notes_view_->horizontalHeader()->sortIndicatorSection());
  settings.setValue("mint_notes_table_sort_order", static_cast<int>(mint_notes_view_->horizontalHeader()->sortIndicatorOrder()));
  settings.setValue("mint_redemptions_table_sort_column", mint_redemptions_view_->horizontalHeader()->sortIndicatorSection());
  settings.setValue("mint_redemptions_table_sort_order", static_cast<int>(mint_redemptions_view_->horizontalHeader()->sortIndicatorOrder()));
}

QUrl WalletWindow::explorer_home_url() const {
  QSettings settings(kSettingsOrg, kSettingsApp);
  QSettings legacy(kSettingsOrg, kLegacySettingsApp);
  QString explorer = settings.value("explorer_url").toString().trimmed();
  if (explorer.isEmpty()) explorer = legacy.value("explorer_url").toString().trimmed();
  if (explorer.isEmpty()) explorer = "http://127.0.0.1:18080";
  QUrl url = QUrl::fromUserInput(explorer);
  if (url.isValid() && url.path().isEmpty()) url.setPath("/");
  return url;
}

void WalletWindow::open_explorer_home() {
  const QUrl url = explorer_home_url();
  if (!url.isValid() || url.scheme().isEmpty()) {
    QMessageBox::warning(this, "Open Explorer", "Explorer URL is invalid.");
    return;
  }
  if (!QDesktopServices::openUrl(url)) {
    QMessageBox::warning(this, "Open Explorer",
                         QString("Could not open explorer URL in the default browser.\n\n%1").arg(url.toString()));
    return;
  }
  statusBar()->showMessage(QString("Opened explorer: %1").arg(url.toString()), 3000);
}

void WalletWindow::poll_finalized_tip_status() {
  const QStringList endpoints = ordered_lightserver_endpoints();
  if (endpoints.isEmpty()) return;

  for (int i = 0; i < endpoints.size(); ++i) {
    const QString endpoint = endpoints[i];
    std::string err;
    auto status = lightserver::rpc_get_status(endpoint.toStdString(), &err);
    if (!status) {
      record_lightserver_failure(endpoint, QString::fromStdString(err));
      continue;
    }
    if (wallet_) {
      if (auto mismatch = endpoint_chain_mismatch_reason(*status, QString::fromStdString(wallet_->network_name))) {
        record_lightserver_failure(endpoint, *mismatch);
        continue;
      }
    }
    record_lightserver_success(endpoint, i > 0);

    const QString network_name = QString::fromStdString(status->chain.network_name);
    const QString transition_hash = QString::fromStdString(status->transition_hash);
    const std::uint64_t tip_height = status->tip_height;
    const bool tip_changed =
        tip_height != last_polled_tip_height_ || transition_hash != last_polled_transition_hash_;

    current_chain_name_ = network_name;
    current_transition_hash_ = transition_hash;
    current_network_id_ = QString::fromStdString(status->chain.network_id_hex);
    current_genesis_hash_ = QString::fromStdString(status->chain.genesis_hash_hex);
    current_binary_version_ = QString::fromStdString(status->binary_version);
    current_wallet_api_version_ = QString::fromStdString(status->wallet_api_version);
    current_lightserver_status_ = *status;
    current_peer_height_disagreement_ = status->peer_height_disagreement;
    current_bootstrap_sync_incomplete_ = status->bootstrap_sync_incomplete;
    current_finalized_lag_ = status->finalized_lag ? std::optional<qulonglong>(*status->finalized_lag) : std::nullopt;
    tip_height_ = tip_height;
    last_refresh_text_ = QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss");
    last_polled_tip_height_ = tip_height;
    last_polled_transition_hash_ = transition_hash;
    if (wallet_ && wallet_->network_name == status->chain.network_name && tip_changed) {
      refresh_chain_state(false);
    } else {
      update_wallet_views();
      update_connection_views();
    }
    return;
  }

  update_connection_views();
}

void WalletWindow::apply_selected_theme() {
  const ThemeMode mode = theme_mode_from_string(theme_combo_ ? theme_combo_->currentText() : "Light");
  if (qApp) {
    qApp->setPalette(make_wallet_palette(mode));
    qApp->setStyleSheet(wallet_stylesheet(mode));
  }
  const QString symbol_path =
      mode == ThemeMode::Dark ? ":/branding/finalis-symbol-dark.svg" : ":/branding/finalis-symbol.svg";
  if (header_logo_label_) {
    const QPixmap pixmap = QIcon(symbol_path).pixmap(QSize(42, 42));
    if (!pixmap.isNull()) header_logo_label_->setPixmap(pixmap);
  }
  if (branding_symbol_label_) {
    const QPixmap pixmap = QIcon(symbol_path).pixmap(QSize(52, 52));
    if (!pixmap.isNull()) branding_symbol_label_->setPixmap(pixmap);
  }
  render_history_view();
  render_mint_state();
}

QStringList WalletWindow::configured_lightserver_endpoints() const {
  if (!lightserver_urls_edit_) return {};
  return parse_lightserver_endpoint_lines(lightserver_urls_edit_->toPlainText());
}

QStringList WalletWindow::ordered_lightserver_endpoints() const {
  QStringList endpoints = configured_lightserver_endpoints();
  if (endpoints.isEmpty()) return endpoints;
  const bool pin_first = pin_lightserver_endpoint_checkbox_ && pin_lightserver_endpoint_checkbox_->isChecked();
  if (pin_first || last_successful_lightserver_endpoint_.isEmpty()) return endpoints;
  const int idx = endpoints.indexOf(last_successful_lightserver_endpoint_);
  if (idx <= 0) return endpoints;
  endpoints.move(idx, 0);
  return endpoints;
}

void WalletWindow::set_lightserver_endpoints(const QStringList& endpoints) {
  if (!lightserver_urls_edit_) return;
  lightserver_urls_edit_->setPlainText(endpoints.join("\n"));
}

void WalletWindow::record_lightserver_success(const QString& endpoint, bool fallback_used) {
  const QString normalized = normalize_lightserver_endpoint(endpoint);
  if (normalized.isEmpty()) return;
  last_successful_lightserver_endpoint_ = normalized;
  last_refresh_used_fallback_ = fallback_used;
  last_failed_lightserver_endpoint_.clear();
  last_lightserver_error_.clear();
  auto& runtime = endpoint_runtime_state_[normalized];
  runtime.last_success = QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss");
  runtime.last_error.clear();
}

void WalletWindow::record_lightserver_failure(const QString& endpoint, const QString& error) {
  const QString normalized = normalize_lightserver_endpoint(endpoint);
  if (normalized.isEmpty()) return;
  last_failed_lightserver_endpoint_ = normalized;
  last_lightserver_error_ = error.trimmed();
  auto& runtime = endpoint_runtime_state_[normalized];
  runtime.last_failure = QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss");
  runtime.last_error = last_lightserver_error_;
}

void WalletWindow::clear_lightserver_runtime_status() {
  last_refresh_used_fallback_ = false;
  last_failed_lightserver_endpoint_.clear();
  last_lightserver_error_.clear();
}

void WalletWindow::update_crosscheck_summary(const std::vector<EndpointObservation>& observations) {
  if (observations.empty()) {
    crosscheck_summary_ = "Cross-check: unavailable";
    crosscheck_detail_text_ = "No endpoint cross-check yet.";
  } else {
    std::map<QString, int> counts;
    bool chain_mismatch = false;
    int successes = 0;
    for (const auto& obs : observations) {
      if (!obs.error.isEmpty()) continue;
      ++successes;
      if (!obs.chain_id_ok) chain_mismatch = true;
      const QString key = QString("%1|%2|%3|%4|%5")
                              .arg(obs.network_name, obs.network_id, obs.genesis_hash,
                                   QString::number(obs.tip_height), obs.transition_hash);
      counts[key] += 1;
    }

    if (successes <= 1) {
      crosscheck_summary_ = "Cross-check: unavailable";
    } else if (chain_mismatch) {
      crosscheck_summary_ = "Cross-check: chain mismatch";
    } else if (counts.size() == 1) {
      crosscheck_summary_ = "Cross-check: consistent";
    } else {
      int max_count = 0;
      for (const auto& [_, count] : counts) max_count = std::max(max_count, count);
      if (counts.size() == 2 && max_count == successes - 1) {
        crosscheck_summary_ = "Cross-check: one endpoint differs";
      } else {
        crosscheck_summary_ = "Cross-check: endpoint disagreement";
      }
    }

    QStringList lines;
    for (const auto& obs : observations) {
      if (!obs.error.isEmpty()) {
        lines.push_back(QString("%1\n  error: %2")
                            .arg(display_lightserver_endpoint(obs.endpoint), obs.error));
        continue;
      }
      QString suffix;
      if (!obs.chain_id_ok) suffix += "\n  chain_id_ok: no";
      if (obs.bootstrap_sync_incomplete) suffix += "\n  bootstrap_sync_incomplete: yes";
      if (obs.peer_height_disagreement) suffix += "\n  peer_height_disagreement: yes";
      if (!obs.binary_version.isEmpty()) suffix += QString("\n  binary: %1").arg(obs.binary_version);
      if (!obs.wallet_api_version.isEmpty()) suffix += QString("\n  wallet_api: %1").arg(obs.wallet_api_version);
      lines.push_back(QString("%1\n  network: %2\n  network_id: %3\n  genesis: %4\n  height: %5\n  transition: %6%7")
                          .arg(display_lightserver_endpoint(obs.endpoint),
                               obs.network_name,
                               elide_middle(obs.network_id, 8),
                               elide_middle(obs.genesis_hash, 10),
                               QString::number(obs.tip_height),
                               elide_middle(obs.transition_hash, 12),
                               suffix));
    }
    crosscheck_detail_text_ = lines.join("\n\n");
  }

  if (header_crosscheck_label_) header_crosscheck_label_->setText(crosscheck_summary_);
  if (crosscheck_detail_view_) crosscheck_detail_view_->setPlainText(crosscheck_detail_text_);
}

std::optional<lightserver::BroadcastResult> WalletWindow::broadcast_tx_with_failover(const Bytes& tx_bytes, std::string* err,
                                                                                      QString* used_endpoint) {
  QStringList endpoints = ordered_lightserver_endpoints();
  if (endpoints.isEmpty()) {
    if (err) *err = "configure at least one lightserver endpoint first";
    return std::nullopt;
  }
  if (!last_refresh_endpoint_.isEmpty()) {
    const int idx = endpoints.indexOf(last_refresh_endpoint_);
    if (idx > 0) endpoints.move(idx, 0);
  }
  clear_lightserver_runtime_status();
  for (int i = 0; i < endpoints.size(); ++i) {
    const QString endpoint = endpoints[i];
    std::string call_err;
    auto result = lightserver::rpc_broadcast_tx(endpoint.toStdString(), tx_bytes, &call_err);
    if (result.outcome == lightserver::BroadcastOutcome::Ambiguous) {
      record_lightserver_failure(endpoint, QString::fromStdString(call_err));
      continue;
    }
    if (used_endpoint) *used_endpoint = endpoint;
    record_lightserver_success(endpoint, i > 0);
    if (err) err->clear();
    return result;
  }
  if (err) *err = last_lightserver_error_.toStdString();
  return std::nullopt;
}

void WalletWindow::update_wallet_views() {
  if (!wallet_) {
    wallet_status_label_->setText("No wallet open");
    wallet_file_label_->setText("-");
    wallet_file_label_->setToolTip({});
    network_label_->setText("mainnet");
    receive_address_home_label_->setText("-");
    receive_address_home_label_->setToolTip({});
    receive_address_label_->setText("-");
    receive_address_label_->setToolTip({});
    if (overview_confidential_receive_label_) overview_confidential_receive_label_->setText("not configured");
    if (receive_confidential_address_label_) receive_confidential_address_label_->setText("not configured");
    if (receive_confidential_request_label_) receive_confidential_request_label_->setText("not generated");
    if (receive_copy_status_label_) receive_copy_status_label_->setText("Open or create a wallet to get a receive address.");
    balance_label_->setText(QString("0 %1").arg(kDisplayTicker));
    pending_balance_label_->setText(QString("Pending outgoing: 0 %1").arg(kDisplayTicker));
    if (confidential_balance_label_) confidential_balance_label_->setText("Confidential balance: unavailable");
    if (receive_confidential_note_label_) {
      receive_confidential_note_label_->setText(
          "Confidential receive requires a configured stealth account and encrypted local recovery material.");
    }
    current_chain_name_.clear();
    current_transition_hash_.clear();
    current_network_id_.clear();
    current_genesis_hash_.clear();
    current_binary_version_.clear();
    current_wallet_api_version_.clear();
    current_lightserver_status_.reset();
    current_finalized_lag_.reset();
    current_peer_height_disagreement_ = false;
    current_bootstrap_sync_incomplete_ = false;
    tip_status_label_->setText("not refreshed");
    if (overview_connection_status_label_) overview_connection_status_label_->setText("No healthy endpoint");
    if (header_network_label_) header_network_label_->setText("Network: mainnet");
    if (header_tip_label_) header_tip_label_->setText("Finalized tip: unavailable");
    if (header_connection_label_) header_connection_label_->setText("Lightserver: unavailable");
    update_crosscheck_summary({});
    render_confidential_receive_views();
    refresh_overview_activity_preview();
    update_validator_onboarding_view();
    return;
  }
  const QString refresh_suffix = refresh_in_flight_ ? " · Refreshing..." : QString{};
  wallet_status_label_->setText("Wallet open" + refresh_suffix);
  wallet_file_label_->setText(QString::fromStdString(wallet_->file_path));
  wallet_file_label_->setToolTip(QString::fromStdString(wallet_->file_path));
  network_label_->setText(QString::fromStdString(wallet_->network_name));
  receive_address_home_label_->setText(QString::fromStdString(wallet_->address));
  receive_address_home_label_->setToolTip(QString::fromStdString(wallet_->address));
  receive_address_label_->setText(QString::fromStdString(wallet_->address));
  receive_address_label_->setToolTip(QString::fromStdString(wallet_->address));
  if (overview_confidential_receive_label_) overview_confidential_receive_label_->setText(confidential_receive_address_);
  if (receive_confidential_address_label_) receive_confidential_address_label_->setText(confidential_receive_address_);
  if (receive_confidential_request_label_ && receive_confidential_request_label_->text().trimmed().isEmpty()) {
    receive_confidential_request_label_->setText("not generated");
  }
  if (receive_copy_status_label_) receive_copy_status_label_->setText("Address ready to share.");
  std::uint64_t total = 0;
  std::uint64_t pending_outgoing = 0;
  const auto reserved = pending_wallet_reserved_outpoints();
  for (const auto& utxo : utxos_) total += utxo.value;
  for (const auto& utxo : utxos_) {
    auto txid = decode_hex32_string(utxo.txid_hex);
    if (!txid) continue;
    if (reserved.find(OutPoint{*txid, utxo.vout}) != reserved.end()) pending_outgoing += utxo.value;
  }
  balance_label_->setText(format_coin_amount(total));
  pending_balance_label_->setText(QString("Pending outgoing: %1").arg(format_coin_amount(pending_outgoing)));
  if (confidential_balance_label_) {
    if (confidential_storage_locked_) {
      confidential_balance_label_->setText("Confidential balance: locked (wallet passphrase required)");
    } else {
      confidential_balance_label_->setText(
          QString("Confidential balance: %1 across %2 coin(s)")
              .arg(format_coin_amount(confidential_balance_units_))
              .arg(static_cast<qulonglong>(confidential_coin_count_)));
    }
  }
  if (receive_confidential_note_label_) {
    if (confidential_storage_locked_) {
      receive_confidential_note_label_->setText(
          "Confidential recovery material is encrypted. Reopen the wallet with its passphrase to unlock confidential receive state.");
    } else if (confidential_receive_address_ == "not configured") {
      receive_confidential_note_label_->setText(
          "No stealth account is configured locally yet. This wallet will not advertise a confidential address until encrypted recovery state exists.");
    } else {
      receive_confidential_note_label_->setText(
          "Confidential receive is configured locally. The displayed stealth address depends on encrypted wallet recovery material.");
    }
  }
  tip_status_label_->setText(tip_height_ == 0 ? (refresh_in_flight_ ? "not refreshed · refreshing..." : "not refreshed")
                                              : QString("height %1%2").arg(tip_height_).arg(refresh_in_flight_ ? " · refreshing..." : ""));
  if (header_network_label_) {
    header_network_label_->setText(QString("Network: %1").arg(QString::fromStdString(wallet_->network_name)));
  }
  if (header_tip_label_) {
    header_tip_label_->setText(tip_height_ == 0 ? "Finalized tip: unavailable"
                                                 : QString("Finalized tip: %1").arg(tip_height_));
  }
  if (send_review_button_ && send_button_ && send_max_button_) {
    const bool ready = !send_address_edit_->text().trimmed().isEmpty() && !send_amount_edit_->text().trimmed().isEmpty();
    send_max_button_->setEnabled(true);
    send_review_button_->setEnabled(ready);
    send_button_->setEnabled(ready);
  }
  render_confidential_receive_views();
  refresh_overview_activity_preview();
  update_validator_onboarding_view();
}

void WalletWindow::update_connection_views() {
  const QStringList configured = configured_lightserver_endpoints();
  const QString mint = mint_url_edit_->text().trimmed();
  const QString chain = current_chain_name_.isEmpty() ? "not refreshed" : current_chain_name_;
  const QString transition_hash =
      current_transition_hash_.isEmpty() ? "-" : elide_middle(current_transition_hash_, 10);
  const QString refreshed = last_refresh_text_.isEmpty() ? "never" : last_refresh_text_;
  QString lightserver_summary = "No healthy endpoint";
  if (!last_successful_lightserver_endpoint_.isEmpty()) {
    lightserver_summary = QString("%1: %2")
                              .arg(last_refresh_used_fallback_ ? "Fallback" : "Connected")
                              .arg(display_lightserver_endpoint(last_successful_lightserver_endpoint_));
  } else if (!configured.isEmpty()) {
    lightserver_summary = QString("Configured endpoints: %1").arg(configured.size());
  }
  QString failure_summary;
  if (!last_failed_lightserver_endpoint_.isEmpty()) {
    failure_summary = QString("\nLast endpoint failure: %1\nLast error: %2")
                          .arg(display_lightserver_endpoint(last_failed_lightserver_endpoint_))
                          .arg(last_lightserver_error_.isEmpty() ? "unavailable" : last_lightserver_error_);
  }
  QString summary =
      QString("RPC endpoints: %1\nMint service: %2\nChain: %3\nTransition hash: %4\nLast refresh: %5")
          .arg(lightserver_summary)
          .arg(mint.isEmpty() ? "not configured" : mint)
          .arg(chain)
          .arg(transition_hash)
          .arg(refreshed);
  if (!current_network_id_.isEmpty()) summary += QString("\nNetwork ID: %1").arg(elide_middle(current_network_id_, 8));
  if (!current_genesis_hash_.isEmpty()) summary += QString("\nGenesis: %1").arg(elide_middle(current_genesis_hash_, 10));
  if (!current_binary_version_.isEmpty()) summary += QString("\nLightserver build: %1").arg(current_binary_version_);
  if (!current_wallet_api_version_.isEmpty()) summary += QString("\nWallet API: %1").arg(current_wallet_api_version_);
  if (current_bootstrap_sync_incomplete_) summary += "\nSync: bootstrap catch-up incomplete";
  else if (current_peer_height_disagreement_) summary += "\nSync: peer disagreement detected";
  else if (current_finalized_lag_.has_value()) summary += QString("\nFinalized lag: %1").arg(*current_finalized_lag_);
  if (refresh_in_flight_) summary += "\nRefresh: in progress";
  if (!failure_summary.isEmpty()) summary += failure_summary;
  connection_summary_label_->setText(summary);
  if (overview_connection_status_label_) {
    overview_connection_status_label_->setText(refresh_in_flight_ ? lightserver_summary + " · Refreshing..." : lightserver_summary);
  }
  if (header_connection_label_) {
    if (!last_successful_lightserver_endpoint_.isEmpty()) {
      header_connection_label_->setText(
          QString("%1: %2")
              .arg(last_refresh_used_fallback_ ? "Fallback" : "Connected")
              .arg(display_lightserver_endpoint(last_successful_lightserver_endpoint_)) +
          (refresh_in_flight_ ? " · Refreshing..." : ""));
    } else {
      header_connection_label_->setText(refresh_in_flight_ ? "No healthy endpoint · Refreshing..." : "No healthy endpoint");
    }
  }
  mint_status_label_->setText(mint.isEmpty() ? "Mint service is not configured yet." : "Mint service configured: " + mint);
  update_adaptive_regime_view();
  render_mint_state();
}

void WalletWindow::update_adaptive_regime_view() {
  if (!adaptive_regime_view_) return;
  if (!current_lightserver_status_.has_value()) {
    adaptive_regime_view_->setPlainText("Adaptive checkpoint diagnostics unavailable.");
    return;
  }

  const auto& status = *current_lightserver_status_;
  QStringList lines;
  lines << "Adaptive regime diagnostics";
  lines << QString("Checkpoint mode: %1").arg(QString::fromStdString(status.checkpoint_derivation_mode.value_or("unknown")));
  lines << QString("Checkpoint fallback reason: %1").arg(QString::fromStdString(status.checkpoint_fallback_reason.value_or("unknown")));
  lines << QString("Sticky fallback: %1").arg(yes_no_text(status.fallback_sticky.value_or(false)));
  lines << "";
  lines << QString("Qualified operator depth: %1")
               .arg(status.qualified_depth ? QString::number(*status.qualified_depth) : QString("unknown"));
  lines << QString("Adaptive committee target: %1")
               .arg(status.adaptive_target_committee_size ? QString::number(*status.adaptive_target_committee_size)
                                                          : QString("unknown"));
  lines << QString("Adaptive eligible threshold: %1")
               .arg(status.adaptive_min_eligible ? QString::number(*status.adaptive_min_eligible) : QString("unknown"));
  lines << QString("Adaptive bond floor: %1")
               .arg(status.adaptive_min_bond ? format_coin_amount(*status.adaptive_min_bond) : QString("unknown"));
  lines << QString("Eligibility slack: %1").arg(status.adaptive_slack ? QString::number(*status.adaptive_slack) : QString("unknown"));
  lines << QString("Target expand streak: %1")
               .arg(status.target_expand_streak ? QString::number(*status.target_expand_streak) : QString("unknown"));
  lines << QString("Target contract streak: %1")
               .arg(status.target_contract_streak ? QString::number(*status.target_contract_streak) : QString("unknown"));
  lines << "";

  const QString window =
      status.fallback_rate_window_epochs ? QString::number(*status.fallback_rate_window_epochs) : QString("unknown");
  lines << QString("Fallback rate: %1 over %2 epochs")
               .arg(status.fallback_rate_bps ? format_bps_percentage(*status.fallback_rate_bps) : QString("unknown"))
               .arg(window);
  lines << QString("Sticky fallback rate: %1")
               .arg(status.sticky_fallback_rate_bps ? format_bps_percentage(*status.sticky_fallback_rate_bps)
                                                    : QString("unknown"));

  QStringList flags;
  if (status.near_threshold_operation.value_or(false)) flags << "near-threshold-operation";
  if (status.prolonged_expand_buildup.value_or(false)) flags << "prolonged-expand-buildup";
  if (status.prolonged_contract_buildup.value_or(false)) flags << "prolonged-contract-buildup";
  if (status.repeated_sticky_fallback.value_or(false)) flags << "repeated-sticky-fallback";
  if (status.depth_collapse_after_bond_increase.value_or(false)) flags << "depth-collapse-after-bond-increase";
  lines << "";
  lines << "Adaptive alert flags:";
  if (flags.isEmpty()) {
    lines << "- none";
  } else {
    for (const auto& flag : flags) lines << QString("- %1").arg(flag);
  }

  adaptive_regime_view_->setPlainText(lines.join('\n'));
}

void WalletWindow::update_validator_onboarding_view() {
  refresh_validator_readiness_panel(false);
}

void WalletWindow::persist_validator_onboarding_ui_state(
    const std::optional<finalis::onboarding::ValidatorOnboardingRecord>& record, const QString& last_error) const {
  QSettings settings(kSettingsOrg, kSettingsApp);
  settings.setValue("validator/db_path", validator_db_path_edit_ ? validator_db_path_edit_->text().trimmed() : QString{});
  settings.setValue("validator/key_path", validator_key_path_edit_ ? validator_key_path_edit_->text().trimmed() : QString{});
  settings.setValue("validator/rpc_url", validator_rpc_url_edit_ ? validator_rpc_url_edit_->text().trimmed() : QString{});
  settings.setValue("validator/last_error", last_error);
  settings.setValue("validator/detached_local", false);
  if (!record.has_value()) return;
  settings.setValue("validator/last_txid", QString::fromStdString(record->txid_hex));
  settings.setValue("validator/status",
                    QString::fromStdString(finalis::onboarding::validator_onboarding_state_name(record->state)));
  settings.setValue("validator/last_checked_height", static_cast<qulonglong>(record->finalized_height));
}

void WalletWindow::refresh_validator_readiness_panel(bool interactive) {
  if (!validator_readiness_label_ || !validator_funding_label_ || !validator_state_label_ || !validator_action_button_) return;

  if (wallet_ && validator_db_path_edit_ && validator_db_path_edit_->text().trimmed().isEmpty()) {
    if (auto inferred = inferred_local_db_path(); inferred.has_value()) {
      validator_db_path_edit_->setText(QString::fromStdString(*inferred));
    }
  }
  if (validator_key_path_edit_) {
    const QString current_key = validator_key_path_edit_->text().trimmed();
    const QString inferred_key = inferred_validator_key_path_from_db(
        validator_db_path_edit_ ? validator_db_path_edit_->text().trimmed() : QString{});
    const bool should_replace_with_inferred =
        !inferred_key.isEmpty() &&
        (current_key.isEmpty() ||
         (wallet_ && current_key == QString::fromStdString(wallet_->file_path) && !looks_like_node_validator_key(current_key)));
    if (should_replace_with_inferred) {
      validator_key_path_edit_->setText(inferred_key);
    } else if (current_key.isEmpty() && wallet_ &&
               looks_like_node_validator_key(QString::fromStdString(wallet_->file_path))) {
      validator_key_path_edit_->setText(QString::fromStdString(wallet_->file_path));
    }
  }
  if (validator_rpc_url_edit_ && validator_rpc_url_edit_->text().trimmed().isEmpty()) {
    const auto endpoints = ordered_lightserver_endpoints();
    if (!endpoints.isEmpty()) validator_rpc_url_edit_->setText(endpoints.front());
  }

  const QString db_path = validator_db_path_edit_ ? validator_db_path_edit_->text().trimmed() : QString{};
  const QString key_path = validator_key_path_edit_ ? validator_key_path_edit_->text().trimmed() : QString{};
  const QString rpc_url = validator_rpc_url_edit_ ? validator_rpc_url_edit_->text().trimmed() : QString{};

  const bool wallet_loaded = wallet_.has_value();
  const bool db_path_valid = !db_path.isEmpty() && QDir(db_path).exists();
  const bool key_exists = !key_path.isEmpty() && QFileInfo::exists(key_path) && QFileInfo(key_path).isFile();
  bool key_loadable = false;
  QString selected_validator_pubkey = "-";
  QString selected_validator_address = "-";
  QString selected_validator_network = "-";
  QString key_error = key_exists ? "Key file is not readable with the current wallet passphrase" : "Select validator key file";
  if (wallet_loaded && key_exists) {
    finalis::keystore::ValidatorKey validator_key;
    std::string load_err;
    if (finalis::keystore::load_validator_keystore(key_path.toStdString(), wallet_->passphrase, &validator_key, &load_err)) {
      selected_validator_pubkey =
          elide_middle(QString::fromStdString(finalis::hex_encode(finalis::Bytes(validator_key.pubkey.begin(), validator_key.pubkey.end()))), 16);
      selected_validator_address = QString::fromStdString(validator_key.address);
      selected_validator_network = QString::fromStdString(validator_key.network_name);
      if (validator_key.network_name != wallet_->network_name) {
        key_error = QString("Validator key targets %1, wallet expects %2")
                        .arg(QString::fromStdString(validator_key.network_name),
                             QString::fromStdString(wallet_->network_name));
      } else {
        key_loadable = true;
        key_error.clear();
      }
    } else if (!load_err.empty()) {
      key_error = QString::fromStdString(load_err);
    }
  }

  bool rpc_reachable = false;
  QString rpc_error = "Set local RPC endpoint";
  if (!rpc_url.isEmpty()) {
    std::string rpc_err;
    auto status = lightserver::rpc_get_status(rpc_url.toStdString(), &rpc_err);
    if (status && wallet_) {
      if (auto mismatch = endpoint_chain_mismatch_reason(*status, QString::fromStdString(wallet_->network_name))) {
        rpc_error = *mismatch;
      } else {
        rpc_reachable = true;
        rpc_error.clear();
      }
    } else if (status) {
      rpc_reachable = true;
      rpc_error.clear();
    } else if (!rpc_err.empty()) {
      rpc_error = QString::fromStdString(rpc_err);
    }
  }

  std::optional<finalis::onboarding::ValidatorOnboardingRecord> record;
  QString onboarding_error;
  QSettings settings(kSettingsOrg, kSettingsApp);
  const QString tracked_txid = settings.value("validator/last_txid").toString().trimmed();
  const bool detached_local = settings.value("validator/detached_local", false).toBool();
  if (wallet_loaded && key_loadable && !rpc_url.isEmpty()) {
    finalis::onboarding::ValidatorOnboardingOptions options;
    options.key_file = key_path.toStdString();
    options.passphrase = wallet_->passphrase;
    options.rpc_url = rpc_url.toStdString();
    options.fee = 10'000;
    options.wait_for_sync = true;
    std::string err;
    record = finalis::lightserver::rpc_validator_onboarding_status(rpc_url.toStdString(), options, tracked_txid.toStdString(), &err);
    if (!record.has_value() && !err.empty()) onboarding_error = QString::fromStdString(err);
  }

  storage::NodeRuntimeStatusSnapshot runtime_snapshot{};
  bool runtime_snapshot_valid = false;
  if (db_path_valid) {
    storage::DB db;
    if (db.open_readonly(db_path.toStdString())) {
      auto snapshot = db.get_node_runtime_status_snapshot();
      if (snapshot.has_value()) {
        runtime_snapshot = *snapshot;
        runtime_snapshot_valid = true;
      }
      db.close();
    }
  }

  bool node_synced = false;
  QString node_status = "Select your node data folder";
  if (record.has_value() && record->readiness.captured_at_unix_ms != 0) {
    node_synced = record->readiness.registration_ready;
    node_status = node_synced ? QString("Ready (%1 healthy peers, lag %2)")
                                      .arg(static_cast<qulonglong>(record->readiness.healthy_peer_count))
                                      .arg(static_cast<qulonglong>(record->readiness.finalized_lag))
                              : QString("Waiting: %1")
                                      .arg(record->readiness.readiness_blockers_csv.empty()
                                               ? "runtime status not ready"
                                               : QString::fromStdString(record->readiness.readiness_blockers_csv));
  } else if (runtime_snapshot_valid) {
    node_synced = runtime_snapshot.registration_ready;
    node_status = node_synced ? QString("Ready (%1 healthy peers, lag %2)")
                                      .arg(static_cast<qulonglong>(runtime_snapshot.healthy_peer_count))
                                      .arg(static_cast<qulonglong>(runtime_snapshot.finalized_lag))
                              : QString("Waiting: %1")
                                      .arg(runtime_snapshot.readiness_blockers_csv.empty()
                                               ? "runtime status not ready"
                                               : QString::fromStdString(runtime_snapshot.readiness_blockers_csv));
  } else if (db_path_valid) {
    node_status = "Node runtime status not available yet";
  }

  const std::uint64_t required_bond_units =
      record.has_value() ? record->bond_amount : consensus::validator_min_bond_units(tip_height_ + 1);
  const std::uint64_t eligibility_bond_units =
      record.has_value() && record->eligibility_bond_amount != 0 ? record->eligibility_bond_amount : required_bond_units;
  const std::uint64_t required_fee_units = record.has_value() ? record->fee : 10'000;
  const std::uint64_t required_total_units = required_bond_units + required_fee_units;
  std::uint64_t wallet_finalized_spendable_units = 0;
  for (const auto& utxo : utxos_) wallet_finalized_spendable_units += utxo.value;
  const std::uint64_t available_finalized_units =
      record.has_value() ? record->last_spendable_balance : wallet_finalized_spendable_units;

  bool enough_balance = false;
  QString funding_text = "Balance not checked yet";
  QString registration_status = detached_local ? "Detached locally" : "Not started";
  qulonglong tracked_checked_height = 0;
  bool tracked_checked_height_ok = false;
  const qulonglong persisted_checked_height = settings.value("validator/last_checked_height").toULongLong(&tracked_checked_height_ok);
  if (record.has_value()) {
    enough_balance = record->last_spendable_balance >= record->required_amount;
    if (enough_balance) {
      funding_text = QString("%1 available, %2 required to register (bond %3 + fee %4)")
                         .arg(format_coin_amount(record->last_spendable_balance))
                         .arg(format_coin_amount(record->required_amount))
                         .arg(format_coin_amount(record->bond_amount))
                         .arg(format_coin_amount(record->fee));
    } else {
      funding_text = QString("Need %1 more. Minimum required to register: %2 (bond %3 + fee %4)")
                         .arg(format_coin_amount(record->last_deficit == 0
                                                     ? (record->required_amount - record->last_spendable_balance)
                                                     : record->last_deficit))
                         .arg(format_coin_amount(record->required_amount))
                         .arg(format_coin_amount(record->bond_amount))
                         .arg(format_coin_amount(record->fee));
    }
    if (record->eligibility_bond_amount > record->bond_amount) {
      funding_text += QString("\nCurrent eligibility floor: %1 bond").arg(format_coin_amount(record->eligibility_bond_amount));
    }
    registration_status = onboarding_state_display_text(record->state);
    if (!record->validator_status.empty() && record->validator_status != "NOT_REGISTERED") {
      registration_status += QString(" (%1)").arg(QString::fromStdString(record->validator_status));
    }
    if (!tracked_txid.isEmpty()) {
      registration_status += QString(" · tx %1").arg(elide_middle(tracked_txid, 12));
    }
    tracked_checked_height = static_cast<qulonglong>(record->finalized_height);
    tracked_checked_height_ok = record->finalized_height != 0;
    if (record->state == finalis::onboarding::ValidatorOnboardingState::FAILED) {
      funding_text = onboarding_error_display_text(QString::fromStdString(record->last_error_code),
                                                   QString::fromStdString(record->last_error_message));
    }
  } else if (!onboarding_error.isEmpty()) {
    funding_text = "Unable to refresh onboarding status";
    registration_status = "Status unavailable";
  } else {
    funding_text = QString("Minimum required to register: %1 (bond %2 + fee %3)")
                       .arg(format_coin_amount(required_total_units))
                       .arg(format_coin_amount(required_bond_units))
                       .arg(format_coin_amount(required_fee_units));
    if (eligibility_bond_units > required_bond_units) {
      funding_text += QString("\nCurrent eligibility floor: %1 bond").arg(format_coin_amount(eligibility_bond_units));
    }
  }
  const QString onboarding_badge =
      detached_local ? "DETACHED" :
      (record.has_value() && record->state == finalis::onboarding::ValidatorOnboardingState::FAILED ? "FAILED" :
       (!tracked_txid.isEmpty() ? "TRACKED" : "IDLE"));

  QStringList blockers;
  if (!wallet_loaded) blockers << "Open the operator wallet";
  if (!db_path_valid) blockers << "Select the local node data folder";
  if (!key_loadable) blockers << QString("Fix validator key: %1").arg(key_error);
  if (!rpc_reachable) blockers << QString("Fix RPC endpoint: %1").arg(rpc_error);
  if (wallet_loaded && key_loadable && rpc_reachable && !node_synced) {
    if (record.has_value() && record->readiness.captured_at_unix_ms != 0 &&
        !record->readiness.readiness_blockers_csv.empty()) {
      blockers << QString::fromStdString(record->readiness.readiness_blockers_csv);
    } else if (runtime_snapshot_valid && !runtime_snapshot.readiness_blockers_csv.empty()) {
      blockers << QString::fromStdString(runtime_snapshot.readiness_blockers_csv);
    } else {
      blockers << "Node is not registration-ready yet";
    }
  }
  if ((record.has_value() || wallet_loaded) && !enough_balance) {
    blockers << QString("Need %1 more finalized balance")
                    .arg(format_coin_amount((record.has_value() && record->last_deficit != 0)
                                                ? record->last_deficit
                                                : (available_finalized_units >= required_total_units
                                                       ? 0
                                                       : (required_total_units - available_finalized_units))));
  }
  if (detached_local) blockers << "Local tracking is detached; refresh or retry to resume tracking";
  if (record.has_value() && record->state == finalis::onboarding::ValidatorOnboardingState::FAILED && !onboarding_error.isEmpty()) {
    blockers << onboarding_error;
  }
  blockers.removeDuplicates();

  QStringList checklist;
  checklist << QString("%1 Wallet loaded").arg(wallet_loaded ? "OK" : "Missing")
            << QString("%1 RPC reachable").arg(rpc_reachable ? "OK" : "Missing")
            << QString("%1 Node synced").arg(node_synced ? "OK" : "Waiting")
            << QString("%1 DB path valid").arg(db_path_valid ? "OK" : "Missing")
            << QString("%1 Validator key ready").arg(key_loadable ? "OK" : "Missing")
            << QString("%1 Balance >= %2").arg(enough_balance ? "OK" : "Waiting", format_coin_amount(record.has_value() ? record->required_amount : required_total_units));
  if (eligibility_bond_units > required_bond_units) {
    checklist << QString("Info Eligibility floor = %1 bond").arg(format_coin_amount(eligibility_bond_units));
  }
  if (validator_summary_label_) validator_summary_label_->setText(checklist.join("\n"));

  if (validator_required_bond_label_) {
    QString bond_text = QString("%1 required now (%2 bond + %3 fee)")
                            .arg(format_coin_amount(record.has_value() ? record->required_amount : required_total_units))
                            .arg(format_coin_amount(required_bond_units))
                            .arg(format_coin_amount(required_fee_units));
    if (eligibility_bond_units > required_bond_units) {
      bond_text += QString("\nEligibility floor currently %1 bond").arg(format_coin_amount(eligibility_bond_units));
    }
    validator_required_bond_label_->setText(bond_text);
  }
  if (validator_available_balance_label_) {
    QString balance_text = QString("%1 finalized and spendable").arg(format_coin_amount(available_finalized_units));
    if (available_finalized_units >= required_total_units) {
      balance_text += QString("\nSufficient for registration with %1 headroom")
                          .arg(format_coin_amount(available_finalized_units - required_total_units));
    } else {
      balance_text += QString("\nShort by %1").arg(format_coin_amount(required_total_units - available_finalized_units));
    }
    validator_available_balance_label_->setText(balance_text);
  }
  if (validator_blockers_label_) {
    validator_blockers_label_->setText(blockers.isEmpty() ? "No blockers. You can start registration now."
                                                          : blockers.join("\n"));
  }
  if (validator_live_status_label_) {
    QString live_text = registration_status;
    if (!tracked_txid.isEmpty()) {
      live_text += QString("\nTracked txid: %1").arg(elide_middle(tracked_txid, 12));
    }
    if (record.has_value()) {
      live_text += QString("\nOnboarding state: %1")
                       .arg(QString::fromStdString(finalis::onboarding::validator_onboarding_state_name(record->state)));
      if (record->finalized_height != 0) {
        live_text += QString("\nLast checked finalized height: %1")
                         .arg(static_cast<qulonglong>(record->finalized_height));
      }
      if (!record->validator_status.empty() && record->validator_status != "NOT_REGISTERED") {
        live_text += QString("\nValidator status: %1").arg(QString::fromStdString(record->validator_status));
      }
    } else if (tracked_checked_height_ok) {
      live_text += QString("\nLast checked finalized height: %1").arg(tracked_checked_height);
    } else {
      live_text += "\nNo live registration transaction tracked yet";
    }
    validator_live_status_label_->setText(live_text);
  }

  QString readiness_text = wallet_loaded ? QString("%1\nRPC: %2")
                                               .arg(node_status,
                                                    key_loadable ? (rpc_reachable ? "reachable" : rpc_error)
                                                                 : QString("validator key: %1").arg(key_error))
                                         : "Open your operator wallet first";
  if (wallet_loaded) {
    readiness_text += "\nRegistration action is one-step: the wallet will wait for sync if needed, reserve finalized inputs, build the join transaction, broadcast it, and then track finalization/activation.";
    readiness_text += QString("\nMinimum required to register: %1 (bond %2 + fee %3)")
                          .arg(format_coin_amount(record.has_value() ? record->required_amount : required_total_units))
                          .arg(format_coin_amount(required_bond_units))
                          .arg(format_coin_amount(required_fee_units));
    if (eligibility_bond_units > required_bond_units) {
      readiness_text += QString("\nCurrent eligibility floor: %1 bond").arg(format_coin_amount(eligibility_bond_units));
    }
    readiness_text += QString("\nTracked txid: %1").arg(tracked_txid.isEmpty() ? "none" : elide_middle(tracked_txid, 12));
    if (tracked_checked_height_ok) {
      readiness_text += QString("\nLast checked finalized height: %1").arg(tracked_checked_height);
    }
  }
  validator_readiness_label_->setText(readiness_text);
  validator_funding_label_->setText(funding_text);
  validator_state_label_->setText(QString("%1 <span style=\"margin-left:8px;\">%2</span>")
                                      .arg(onboarding_badge_html(onboarding_badge), registration_status.toHtmlEscaped()));

  QString details =
      QString("Bond amount: %1\nFee: %2\nValidator pubkey: %3\nValidator address: %4\nValidator network: %5\nFunding wallet pubkey: %6\nDB path: %7\nValidator key path: %8\nRPC endpoint: %9\nRefresh cadence: manual refresh and wallet refresh cycle")
          .arg(format_coin_amount(required_bond_units))
          .arg(format_coin_amount(required_fee_units))
          .arg(record.has_value()
                   ? elide_middle(QString::fromStdString(finalis::hex_encode(finalis::Bytes(record->validator_pubkey.begin(),
                                                                                             record->validator_pubkey.end()))),
                                  16)
                   : selected_validator_pubkey)
          .arg(selected_validator_address)
          .arg(selected_validator_network)
          .arg(wallet_ ? elide_middle(QString::fromStdString(wallet_->pubkey_hex), 16) : "-")
          .arg(db_path.isEmpty() ? "-" : db_path)
          .arg(key_path.isEmpty() ? "-" : key_path)
          .arg(rpc_url.isEmpty() ? "-" : rpc_url);
  details += QString("\nMinimum required to register: %1").arg(format_coin_amount(record.has_value() ? record->required_amount : required_total_units));
  details += QString("\nCurrent eligibility floor: %1 bond").arg(format_coin_amount(eligibility_bond_units));
  if (record.has_value()) {
    details += QString("\nRaw status: %1\nLast txid: %2\nLast checked height: %3")
                   .arg(QString::fromStdString(finalis::onboarding::validator_onboarding_state_name(record->state)))
                   .arg(record->txid_hex.empty() ? "-" : QString::fromStdString(record->txid_hex))
                   .arg(static_cast<qulonglong>(record->finalized_height));
    if (!record->last_error_message.empty() || !record->last_error_code.empty()) {
      details += "\nLast error code: " + QString::fromStdString(record->last_error_code);
      details += "\nLast error: " + onboarding_error_display_text(QString::fromStdString(record->last_error_code),
                                                                  QString::fromStdString(record->last_error_message));
    }
  } else if (!onboarding_error.isEmpty()) {
    details += "\nLast error: " + onboarding_error;
  }
  if (validator_details_view_) validator_details_view_->setPlainText(details);

  const bool in_progress_or_done =
      record.has_value() &&
      (record->state == finalis::onboarding::ValidatorOnboardingState::ACTIVE ||
       record->state == finalis::onboarding::ValidatorOnboardingState::PENDING_ACTIVATION ||
       record->state == finalis::onboarding::ValidatorOnboardingState::WAITING_FOR_FINALIZATION ||
       record->state == finalis::onboarding::ValidatorOnboardingState::BROADCASTING_JOIN_TX);
  const bool can_start = wallet_loaded && key_loadable && rpc_reachable && !in_progress_or_done;
  QString action_text = "Register Validator";
  if (!wallet_loaded) action_text = "Open Wallet First";
  else if (!key_loadable) action_text = "Fix Validator Key";
  else if (!rpc_reachable) action_text = "Fix RPC Endpoint";
  else if (record.has_value()) {
    switch (record->state) {
      case finalis::onboarding::ValidatorOnboardingState::WAITING_FOR_SYNC:
        action_text = "Waiting For Sync";
        break;
      case finalis::onboarding::ValidatorOnboardingState::WAITING_FOR_FUNDS:
        action_text = "Waiting For Funds";
        break;
      case finalis::onboarding::ValidatorOnboardingState::SELECTING_UTXOS:
      case finalis::onboarding::ValidatorOnboardingState::BUILDING_JOIN_TX:
      case finalis::onboarding::ValidatorOnboardingState::BROADCASTING_JOIN_TX:
      case finalis::onboarding::ValidatorOnboardingState::WAITING_FOR_FINALIZATION:
      case finalis::onboarding::ValidatorOnboardingState::PENDING_ACTIVATION:
        action_text = "Registration In Progress";
        break;
      case finalis::onboarding::ValidatorOnboardingState::ACTIVE:
        action_text = "Validator Active";
        break;
      case finalis::onboarding::ValidatorOnboardingState::FAILED:
        action_text = "Retry Validator Registration";
        break;
      case finalis::onboarding::ValidatorOnboardingState::CANCELLED:
      case finalis::onboarding::ValidatorOnboardingState::IDLE:
      case finalis::onboarding::ValidatorOnboardingState::CHECKING_PREREQS:
        action_text = "Register Validator";
        break;
    }
  }
  validator_action_button_->setText(action_text);
  validator_action_button_->setEnabled(can_start);
  if (validator_refresh_button_) validator_refresh_button_->setEnabled(wallet_loaded || db_path_valid || key_exists);
  if (validator_cancel_button_) {
    const bool can_cancel = record.has_value() &&
                            record->state != finalis::onboarding::ValidatorOnboardingState::ACTIVE &&
                            record->state != finalis::onboarding::ValidatorOnboardingState::CANCELLED;
    validator_cancel_button_->setEnabled(can_cancel);
  }

  persist_validator_onboarding_ui_state(record, onboarding_error);
  if (interactive && !onboarding_error.isEmpty()) {
    statusBar()->showMessage("Validator status refreshed with warnings.", 3000);
  }
}

void WalletWindow::browse_validator_db_path() {
  const QString start = validator_db_path_edit_ && !validator_db_path_edit_->text().trimmed().isEmpty()
                            ? validator_db_path_edit_->text().trimmed()
                            : QDir::homePath();
  const QString path = QFileDialog::getExistingDirectory(this, "Select Node Data Folder", start);
  if (path.isEmpty()) return;
  validator_db_path_edit_->setText(path);
  save_settings();
  refresh_validator_readiness_panel(false);
}

void WalletWindow::browse_validator_key_path() {
  const QString start = validator_key_path_edit_ && !validator_key_path_edit_->text().trimmed().isEmpty()
                            ? validator_key_path_edit_->text().trimmed()
                            : QDir::homePath();
  const QString path = QFileDialog::getOpenFileName(this, "Select Validator Key File", start, "Key files (*.json);;All files (*)");
  if (path.isEmpty()) return;
  validator_key_path_edit_->setText(path);
  save_settings();
  refresh_validator_readiness_panel(false);
}

void WalletWindow::toggle_validator_details() {
  if (!advanced_page_) return;
  auto* details = advanced_page_->validator_details_container();
  if (!details || !validator_toggle_details_button_) return;
  const bool show = !details->isVisible();
  details->setVisible(show);
  validator_toggle_details_button_->setText(show ? "Hide Details" : "Show Details");
}

void WalletWindow::start_validator_onboarding_clicked() {
  if (!ensure_wallet_loaded("Start Validator Onboarding")) return;
  refresh_validator_readiness_panel(false);

  const QString db_path = validator_db_path_edit_ ? validator_db_path_edit_->text().trimmed() : QString{};
  const QString key_path = validator_key_path_edit_ ? validator_key_path_edit_->text().trimmed() : QString{};
  const QString rpc_url = validator_rpc_url_edit_ ? validator_rpc_url_edit_->text().trimmed() : QString{};
  if (db_path.isEmpty() || !QDir(db_path).exists()) {
    QMessageBox::warning(this, "Start Validator Onboarding", "Select your node data folder.");
    return;
  }
  if (key_path.isEmpty() || !QFileInfo::exists(key_path)) {
    QMessageBox::warning(this, "Start Validator Onboarding", "Select your validator key file.");
    return;
  }
  finalis::keystore::ValidatorKey validator_key;
  std::string key_err;
  if (!finalis::keystore::load_validator_keystore(key_path.toStdString(), wallet_->passphrase, &validator_key, &key_err)) {
    QMessageBox::warning(
        this, "Start Validator Onboarding",
        QString("The selected validator key cannot be opened with the current wallet passphrase.\n\n%1")
            .arg(key_err.empty() ? "Load failed." : QString::fromStdString(key_err)));
    return;
  }
  if (validator_key.network_name != wallet_->network_name) {
    QMessageBox::warning(this, "Start Validator Onboarding",
                         QString("The selected validator key targets %1, but the wallet is on %2.")
                             .arg(QString::fromStdString(validator_key.network_name),
                                  QString::fromStdString(wallet_->network_name)));
    return;
  }
  if (rpc_url.isEmpty()) {
    QMessageBox::warning(this, "Start Validator Onboarding", "Set local RPC endpoint.");
    return;
  }

  finalis::onboarding::ValidatorOnboardingOptions options;
  options.key_file = key_path.toStdString();
  options.passphrase = wallet_->passphrase;
  options.rpc_url = rpc_url.toStdString();
  options.fee = 10'000;
  options.wait_for_sync = true;

  std::string err;
  auto preview = finalis::lightserver::rpc_validator_onboarding_status(rpc_url.toStdString(), options, "", &err);
  if (!preview && !err.empty()) {
    QMessageBox::warning(this, "Start Validator Onboarding", QString::fromStdString(err));
    persist_validator_onboarding_ui_state(std::nullopt, QString::fromStdString(err));
    return;
  }

  const QString bond_amount =
      format_coin_amount(preview.has_value() ? preview->bond_amount : consensus::validator_min_bond_units(tip_height_ + 1));
  const QString fee_amount = format_coin_amount(preview.has_value() ? preview->fee : 10'000);
  const QString validator_identity =
      QString::fromStdString(finalis::hex_encode(finalis::Bytes(validator_key.pubkey.begin(), validator_key.pubkey.end())));
  const QString confirm_text =
      QString("Confirm validator onboarding.\n\nBond amount: %1\nFee: %2\nValidator pubkey: %3\nValidator address: %4\nRPC endpoint: %5")
          .arg(bond_amount)
          .arg(fee_amount)
          .arg(validator_identity.isEmpty() ? "-" : elide_middle(validator_identity, 16))
          .arg(QString::fromStdString(validator_key.address))
          .arg(rpc_url);
  if (QMessageBox::question(this, "Confirm Validator Onboarding", confirm_text,
                            QMessageBox::Ok | QMessageBox::Cancel, QMessageBox::Cancel) != QMessageBox::Ok) {
    return;
  }

  save_settings();
  auto record = finalis::lightserver::rpc_validator_onboarding_start(rpc_url.toStdString(), options, &err);
  if (!record) {
    QMessageBox::warning(this, "Start Validator Onboarding", QString::fromStdString(err));
    persist_validator_onboarding_ui_state(std::nullopt, QString::fromStdString(err));
    return;
  }

  persist_validator_onboarding_ui_state(record, {});
  refresh_validator_readiness_panel(false);
  if (record->state == finalis::onboarding::ValidatorOnboardingState::FAILED) {
    QMessageBox::warning(this, "Start Validator Onboarding",
                         onboarding_error_display_text(QString::fromStdString(record->last_error_code),
                                                       QString::fromStdString(record->last_error_message)));
    return;
  }
  statusBar()->showMessage(QString("Validator onboarding: %1").arg(onboarding_state_display_text(record->state)),
                           4000);
}

void WalletWindow::cancel_validator_onboarding_clicked() {
  if (!ensure_wallet_loaded("Cancel Validator Registration")) return;
  if (QMessageBox::question(this, "Detach Validator Onboarding",
                            "Detach local tracking for the current validator onboarding flow?\n\nThis does not cancel any join transaction that may already have been built or broadcast.",
                            QMessageBox::Ok | QMessageBox::Cancel, QMessageBox::Cancel) != QMessageBox::Ok) {
    return;
  }
  QSettings settings(kSettingsOrg, kSettingsApp);
  settings.remove("validator/last_txid");
  settings.remove("validator/status");
  settings.remove("validator/last_checked_height");
  settings.remove("validator/last_error");
  settings.setValue("validator/detached_local", true);
  refresh_validator_readiness_panel(false);
  append_local_event("[onboarding] detached local validator onboarding tracking");
  statusBar()->showMessage("Validator onboarding tracking detached locally.", 3000);
}

void WalletWindow::render_history_view() {
  refresh_history_table();
  refresh_overview_activity_preview();
  persist_wallet_view_snapshot();
}

void WalletWindow::render_confidential_receive_views() {
  if (!receive_confidential_requests_table_ || !receive_confidential_coins_table_) return;

  std::optional<OutPoint> selected_outpoint;
  if (const int current_row = receive_confidential_coins_table_->currentRow(); current_row >= 0) {
    if (auto* current_item = receive_confidential_coins_table_->item(current_row, 0)) {
      const QString selected_txid = current_item->data(Qt::UserRole + 1).toString().trimmed();
      bool vout_ok = false;
      const auto selected_vout = current_item->data(Qt::UserRole + 2).toUInt(&vout_ok);
      auto parsed_txid = decode_hex32_string(selected_txid.toStdString());
      if (parsed_txid && vout_ok) {
        selected_outpoint = OutPoint{*parsed_txid, selected_vout};
      }
    }
  }

  receive_confidential_requests_table_->setSortingEnabled(false);
  receive_confidential_requests_table_->setRowCount(0);
  int outstanding_requests = 0;
  int consumed_requests = 0;
  for (const auto& request : confidential_request_views_) {
    if (request.consumed) {
      ++consumed_requests;
    } else {
      ++outstanding_requests;
    }
    const int row = receive_confidential_requests_table_->rowCount();
    receive_confidential_requests_table_->insertRow(row);
    receive_confidential_requests_table_->setItem(row, 0, new QTableWidgetItem(request.consumed ? "Consumed" : "Outstanding"));
    receive_confidential_requests_table_->setItem(row, 1, new QTableWidgetItem(request.account_id));
    receive_confidential_requests_table_->setItem(row, 2, new QTableWidgetItem(elide_middle(request.request_id, 10)));
    receive_confidential_requests_table_->setItem(
        row, 3, new QTableWidgetItem(QString("0x%1").arg(static_cast<unsigned int>(request.scan_tag), 2, 16, QChar('0'))));
    receive_confidential_requests_table_->setItem(row, 4, new QTableWidgetItem(elide_middle(request.one_time_pubkey_hex, 10)));
  }
  if (receive_confidential_requests_table_->rowCount() == 0) {
    receive_confidential_requests_table_->insertRow(0);
    receive_confidential_requests_table_->setItem(0, 0, new QTableWidgetItem("No confidential requests"));
  }
  if (receive_confidential_request_summary_label_) {
    receive_confidential_request_summary_label_->setText(
        QString("Outstanding requests: %1 · Consumed: %2").arg(outstanding_requests).arg(consumed_requests));
  }

  receive_confidential_coins_table_->setSortingEnabled(false);
  receive_confidential_coins_table_->setRowCount(0);
  if (receive_copy_confidential_pending_txid_button_) receive_copy_confidential_pending_txid_button_->setEnabled(false);
  if (receive_inspect_confidential_pending_tx_button_) receive_inspect_confidential_pending_tx_button_->setEnabled(false);
  int active_coins = 0;
  const std::uint64_t now_ms = static_cast<std::uint64_t>(QDateTime::currentMSecsSinceEpoch());
  int restore_row = -1;
  for (const auto& coin : confidential_coin_views_) {
    if (!coin.spent) ++active_coins;
    const auto reservation_it = pending_confidential_reservations_.find(coin.outpoint);
    const bool reserved = reservation_it != pending_confidential_reservations_.end();
    const QString reservation_text =
        reserved ? pending_release_state_text(reservation_it->second, tip_height_, now_ms) : "Not reserved";
    const int row = receive_confidential_coins_table_->rowCount();
    receive_confidential_coins_table_->insertRow(row);
    auto* status_item = new QTableWidgetItem(coin.spent ? "Spent" : (reserved ? "Reserved" : "Unspent"));
    if (reserved) status_item->setData(Qt::UserRole, QString::fromStdString(reservation_it->second.txid_hex));
    status_item->setData(Qt::UserRole + 1, coin.txid_hex);
    status_item->setData(Qt::UserRole + 2, QVariant::fromValue(static_cast<qulonglong>(coin.vout)));
    receive_confidential_coins_table_->setItem(row, 0, status_item);
    receive_confidential_coins_table_->setItem(row, 1, new QTableWidgetItem(format_coin_amount(coin.amount)));
    receive_confidential_coins_table_->setItem(
        row, 2, new QTableWidgetItem(QString("%1:%2").arg(elide_middle(coin.txid_hex, 10)).arg(coin.vout)));
    receive_confidential_coins_table_->setItem(row, 3, new QTableWidgetItem(coin.account_id));
    receive_confidential_coins_table_->setItem(row, 4, new QTableWidgetItem(elide_middle(coin.one_time_pubkey_hex, 10)));
    receive_confidential_coins_table_->setItem(row, 5, new QTableWidgetItem(reservation_text));
    if (selected_outpoint.has_value() && coin.outpoint.index == selected_outpoint->index &&
        coin.outpoint.txid == selected_outpoint->txid) {
      restore_row = row;
    }
  }
  if (receive_confidential_coins_table_->rowCount() == 0) {
    receive_confidential_coins_table_->insertRow(0);
    receive_confidential_coins_table_->setItem(0, 0, new QTableWidgetItem("No imported confidential coins"));
  }
  if (receive_confidential_coin_summary_label_) {
    receive_confidential_coin_summary_label_->setText(
        QString("Imported confidential coins: %1 · Unspent: %2")
            .arg(static_cast<qulonglong>(confidential_coin_views_.size()))
            .arg(active_coins));
  }
  if (restore_row >= 0) {
    receive_confidential_coins_table_->setCurrentCell(restore_row, 0);
    receive_confidential_coins_table_->selectRow(restore_row);
  }
  update_selected_confidential_pending_tx_status_panel();
}

void WalletWindow::update_selected_confidential_pending_tx_status_panel() {
  if (!receive_confidential_pending_status_view_ || !receive_confidential_coins_table_) return;

  const int row = receive_confidential_coins_table_->currentRow();
  if (row < 0) {
    receive_confidential_pending_status_view_->setPlainText(
        "Select a reserved confidential coin to inspect the current pending transaction status.");
    return;
  }

  auto* status_item = receive_confidential_coins_table_->item(row, 0);
  const QString txid = status_item ? status_item->data(Qt::UserRole).toString().trimmed() : QString{};
  if (txid.isEmpty()) {
    receive_confidential_pending_status_view_->setPlainText(
        "The selected confidential coin does not have an active pending transaction reservation.");
    return;
  }

  auto parsed_txid = decode_hex32_string(txid.toStdString());
  if (!parsed_txid) {
    receive_confidential_pending_status_view_->setPlainText(
        QString("Pending txid is malformed.\n\nTxid: %1").arg(txid));
    return;
  }

  const auto now_ms = static_cast<std::uint64_t>(QDateTime::currentMSecsSinceEpoch());
  if (const auto cache_it = pending_tx_status_cache_.find(txid); cache_it != pending_tx_status_cache_.end()) {
    const auto& cached = cache_it->second;
    receive_confidential_pending_status_view_->setPlainText(
        QString("Txid: %1\nEndpoint: %2\nStatus: %3\nFinalized: %4\nHeight: %5\nFinalized depth: %6\nCredit safe: %7\nTransition: %8\nCached at: %9")
            .arg(txid,
                 cached.endpoint.isEmpty() ? "-" : display_lightserver_endpoint(cached.endpoint),
                 QString::fromStdString(cached.status.status),
                 cached.status.finalized ? "yes" : "no",
                 QString::number(cached.status.height),
                 QString::number(cached.status.finalized_depth),
                 cached.status.credit_safe ? "yes" : "no",
                 cached.status.transition_hash.empty() ? "-" : elide_middle(QString::fromStdString(cached.status.transition_hash), 10),
                 cached.cached_at.isEmpty() ? "unknown" : cached.cached_at));
    if (now_ms - cached.cached_at_ms <= 30000) return;
  } else {
    receive_confidential_pending_status_view_->setPlainText(
        QString("Txid: %1\nStatus lookup: refreshing in background...").arg(txid));
  }
  request_pending_tx_status_refresh(txid);
}

void WalletWindow::request_pending_tx_status_refresh(const QString& txid) {
  if (txid.trimmed().isEmpty() || !receive_confidential_pending_status_view_) return;
  const QStringList endpoints = ordered_lightserver_endpoints();
  if (endpoints.isEmpty()) {
    const bool no_healthy_endpoint = last_successful_lightserver_endpoint_.trimmed().isEmpty();
    const QString stale_note =
        no_healthy_endpoint
            ? "Status is stale: no healthy lightserver endpoint is currently available. This is not a chain-level "
              "not_found result."
            : "Status lookup failed against configured lightservers. This is not a confirmed chain-level not_found result.";
    QString last_known_text = "Last known status: unavailable";
    if (const auto cache_it = pending_tx_status_cache_.find(txid); cache_it != pending_tx_status_cache_.end()) {
      const auto& cached = cache_it->second;
      last_known_text =
          QString("Last known status (%1)\nEndpoint: %2\nStatus: %3\nFinalized: %4\nHeight: %5\nFinalized depth: %6\n"
                  "Credit safe: %7\nTransition: %8")
              .arg(cached.cached_at.isEmpty() ? "unknown time" : cached.cached_at,
                   cached.endpoint.isEmpty() ? "-" : display_lightserver_endpoint(cached.endpoint),
                   QString::fromStdString(cached.status.status),
                   cached.status.finalized ? "yes" : "no",
                   QString::number(cached.status.height),
                   QString::number(cached.status.finalized_depth),
                   cached.status.credit_safe ? "yes" : "no",
                   cached.status.transition_hash.empty() ? "-" : elide_middle(QString::fromStdString(cached.status.transition_hash), 10));
    }
    receive_confidential_pending_status_view_->setPlainText(
        QString("Txid: %1\nEndpoint: -\nStatus lookup: failed\nStale: %2\n\n%3\n\n%4\n\n%5")
            .arg(txid,
                 no_healthy_endpoint ? "yes" : "possible",
                 stale_note,
                 "Unable to query pending transaction status from configured lightservers.",
                 last_known_text));
    return;
  }
  auto parsed_txid = decode_hex32_string(txid.toStdString());
  if (!parsed_txid) return;
  pending_tx_status_panel_txid_ = txid;
  const std::uint64_t generation = ++pending_tx_status_generation_;
  QPointer<WalletWindow> self(this);
  std::thread([self, generation, txid, txid32 = *parsed_txid, endpoints]() mutable {
    QString used_endpoint;
    std::string rpc_err;
    std::optional<lightserver::TxStatusView> tx_status;
    for (const QString& endpoint : endpoints) {
      tx_status = lightserver::rpc_get_tx_status(endpoint.toStdString(), txid32, &rpc_err);
      if (tx_status) {
        used_endpoint = endpoint;
        break;
      }
    }
    QMetaObject::invokeMethod(
        self,
        [self, generation, txid, used_endpoint, rpc_err = std::move(rpc_err), tx_status = std::move(tx_status)]() mutable {
          if (!self || generation != self->pending_tx_status_generation_ || txid != self->pending_tx_status_panel_txid_) return;
          if (tx_status) {
            self->pending_tx_status_cache_[txid] = CachedPendingTxStatus{
                .status = *tx_status,
                .endpoint = used_endpoint,
                .cached_at = QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),
                .cached_at_ms = static_cast<std::uint64_t>(QDateTime::currentMSecsSinceEpoch()),
            };
            (void)self->store_.upsert_pending_tx_status(WalletStore::PendingTxStatusRecord{
                .txid_hex = txid.toStdString(),
                .endpoint = used_endpoint.toStdString(),
                .cached_at = self->pending_tx_status_cache_[txid].cached_at.toStdString(),
                .cached_at_ms = self->pending_tx_status_cache_[txid].cached_at_ms,
                .status = tx_status->status,
                .finalized = tx_status->finalized,
                .height = tx_status->height,
                .finalized_depth = tx_status->finalized_depth,
                .credit_safe = tx_status->credit_safe,
                .transition_hash = tx_status->transition_hash,
            });
            self->update_selected_confidential_pending_tx_status_panel();
            return;
          }
          const bool no_healthy_endpoint = self->last_successful_lightserver_endpoint_.trimmed().isEmpty();
          const QString stale_note =
              no_healthy_endpoint
                  ? "Status is stale: no healthy lightserver endpoint is currently available. This is not a chain-level not_found result."
                  : "Status lookup failed against configured lightservers. This is not a confirmed chain-level not_found result.";
          QString last_known_text = "Last known status: unavailable";
          if (const auto cache_it = self->pending_tx_status_cache_.find(txid); cache_it != self->pending_tx_status_cache_.end()) {
            const auto& cached = cache_it->second;
            last_known_text =
                QString("Last known status (%1)\nEndpoint: %2\nStatus: %3\nFinalized: %4\nHeight: %5\nFinalized depth: %6\nCredit safe: %7\nTransition: %8")
                    .arg(cached.cached_at.isEmpty() ? "unknown time" : cached.cached_at,
                         cached.endpoint.isEmpty() ? "-" : display_lightserver_endpoint(cached.endpoint),
                         QString::fromStdString(cached.status.status),
                         cached.status.finalized ? "yes" : "no",
                         QString::number(cached.status.height),
                         QString::number(cached.status.finalized_depth),
                         cached.status.credit_safe ? "yes" : "no",
                         cached.status.transition_hash.empty() ? "-" : elide_middle(QString::fromStdString(cached.status.transition_hash), 10));
          }
          if (self->receive_confidential_pending_status_view_) {
            self->receive_confidential_pending_status_view_->setPlainText(
                QString("Txid: %1\nEndpoint: -\nStatus lookup: failed\nStale: %2\n\n%3\n\n%4\n\n%5")
                    .arg(txid,
                         no_healthy_endpoint ? "yes" : "possible",
                         stale_note,
                         rpc_err.empty() ? "Unable to query pending transaction status from configured lightservers."
                                         : QString::fromStdString(rpc_err),
                         last_known_text));
          }
        },
        Qt::QueuedConnection);
  }).detach();
}

void WalletWindow::refresh_overview_activity_preview() {
  auto* table = overview_page_ ? overview_page_->activity_preview_table() : nullptr;
  if (!table) return;
  table->setRowCount(0);
  if (chain_records_.empty() && mint_records_.empty() && wallet_view_snapshot_.has_value() &&
      !wallet_view_snapshot_->overview_activity_rows.empty()) {
    for (const auto& row : wallet_view_snapshot_->overview_activity_rows) {
      const int r = table->rowCount();
      table->insertRow(r);
      auto* status_item = new QTableWidgetItem(QString::fromStdString(row.col0));
      apply_status_item_style(status_item);
      table->setItem(r, 0, status_item);
      table->setItem(r, 1, new QTableWidgetItem(QString::fromStdString(row.col1)));
      table->setItem(r, 2, new QTableWidgetItem(QString::fromStdString(row.col2)));
    }
    return;
  }
  int added = 0;
  const auto add_row = [&](const QString& status, const QString& activity, const QString& state) {
    const int row = table->rowCount();
    table->insertRow(row);
    auto* status_item = new QTableWidgetItem(status);
    apply_status_item_style(status_item);
    table->setItem(row, 0, status_item);
    table->setItem(row, 1, new QTableWidgetItem(activity));
    table->setItem(row, 2, new QTableWidgetItem(state));
  };
  for (const auto& rec : chain_records_) {
    if (added >= 4) break;
    add_row(title_case_status(rec.status), display_chain_kind(rec.kind),
            rec.status.trimmed().toUpper() == "PENDING" ? rec.height : QString("Height %1").arg(rec.height));
    ++added;
  }
  for (const auto& rec : mint_records_) {
    if (added >= 4) break;
    add_row(title_case_status(rec.status), display_mint_kind(rec.kind), rec.height_or_state.isEmpty() ? "-" : rec.height_or_state);
    ++added;
  }
  if (added == 0) {
    add_row("Info", "No recent activity yet", "waiting for finalized activity");
  }
}

void WalletWindow::render_mint_state() {
  mint_deposit_ref_label_->setText(mint_deposit_ref_.isEmpty() ? "No active deposit reference yet." : mint_deposit_ref_);
  mint_redemption_label_->setText(mint_last_redemption_batch_id_.isEmpty() ? "No redemption batch yet." : mint_last_redemption_batch_id_);
  std::uint64_t private_total = 0;
  std::map<std::uint64_t, std::size_t, std::greater<std::uint64_t>> by_amount;
  for (const auto& note : mint_notes_) {
    private_total += note.amount;
    by_amount[note.amount] += 1;
  }
  mint_records_.clear();
  mint_deposits_view_->setSortingEnabled(false);
  mint_notes_view_->setSortingEnabled(false);
  mint_redemptions_view_->setSortingEnabled(false);
  mint_deposits_view_->setRowCount(0);
  mint_notes_view_->setRowCount(0);
  mint_redemptions_view_->setRowCount(0);
  mint_private_balance_label_->setText(format_coin_amount(private_total));
  mint_note_count_label_->setText(QString::number(mint_notes_.size()));
  if (mint_notes_.empty()) {
    mint_notes_label_->setText("No active private notes yet.");
  } else {
    QStringList summary_lines;
    for (const auto& [amount, count] : by_amount) {
      summary_lines.push_back(QString("%1 x %2").arg(QString::number(count), format_coin_amount(amount)));
    }
    for (const auto& note : mint_notes_) {
      const QString amount = format_coin_amount(note.amount);
      const QString details = QString("Active note\nReference: %1\nAmount: %2").arg(note.note_ref, amount);
      mint_records_.push_back(MintRecord{"FINALIZED", "note", note.note_ref, amount, "active", details});
      const int row = mint_notes_view_->rowCount();
      mint_notes_view_->insertRow(row);
      auto* status_item = new QTableWidgetItem("FINALIZED");
      status_item->setData(Qt::UserRole, static_cast<int>(mint_records_.size() - 1));
      apply_status_item_style(status_item);
      mint_notes_view_->setItem(row, 0, status_item);
      mint_notes_view_->setItem(row, 1, new QTableWidgetItem(amount));
      mint_notes_view_->setItem(row, 2, new QTableWidgetItem(elide_middle(note.note_ref, 10)));
      mint_notes_view_->setItem(row, 3, new QTableWidgetItem("active"));
    }
    mint_notes_label_->setText(summary_lines.join("\n"));
  }
  if (mint_notes_view_->rowCount() == 0) {
    mint_notes_view_->insertRow(0);
    auto* item = new QTableWidgetItem("No private notes available yet");
    item->setData(Qt::UserRole, -1);
    mint_notes_view_->setItem(0, 0, item);
  }

  for (int i = local_history_lines_.size() - 1; i >= 0; --i) {
    const QString line = local_history_lines_[i];
    if (line.startsWith("[mint-deposit]")) {
      const QString details = trim_after_token(line, "[mint-deposit]");
      const QString amount = extract_amount_prefix(details);
      mint_records_.push_back(MintRecord{"PENDING", "deposit", mint_deposit_ref_, amount, "registered", details});
      const int row = mint_deposits_view_->rowCount();
      mint_deposits_view_->insertRow(row);
      auto* status_item = new QTableWidgetItem("PENDING");
      status_item->setData(Qt::UserRole, static_cast<int>(mint_records_.size() - 1));
      apply_status_item_style(status_item);
      mint_deposits_view_->setItem(row, 0, status_item);
      mint_deposits_view_->setItem(row, 1, new QTableWidgetItem(amount.isEmpty() ? "-" : amount));
      mint_deposits_view_->setItem(row, 2, new QTableWidgetItem(elide_middle(mint_deposit_ref_, 10)));
      mint_deposits_view_->setItem(row, 3, new QTableWidgetItem(elide_middle(mint_last_deposit_txid_, 10)));
    } else if (line.startsWith("[mint-redeem]")) {
      const QString batch = extract_field_value(line, "batch");
      const QString amount = extract_field_value(line, "amount");
      const QString notes = extract_field_value(line, "notes");
      const QString details = QString("batch=%1  amount=%2  notes=%3").arg(batch, amount, notes);
      mint_records_.push_back(MintRecord{"PENDING", "redemption", batch, amount, "pending", details});
      const int row = mint_redemptions_view_->rowCount();
      mint_redemptions_view_->insertRow(row);
      auto* status_item = new QTableWidgetItem("PENDING");
      status_item->setData(Qt::UserRole, static_cast<int>(mint_records_.size() - 1));
      apply_status_item_style(status_item);
      mint_redemptions_view_->setItem(row, 0, status_item);
      mint_redemptions_view_->setItem(row, 1, new QTableWidgetItem(amount.isEmpty() ? "-" : amount));
      mint_redemptions_view_->setItem(row, 2, new QTableWidgetItem(elide_middle(batch, 10)));
      mint_redemptions_view_->setItem(row, 3, new QTableWidgetItem("pending"));
    } else if (line.startsWith("[mint-status]")) {
      const QString batch = extract_field_value(line, "batch");
      const QString state = extract_field_value(line, "state");
      const QString txid = extract_field_value(line, "l1_txid");
      const QString details = QString("batch=%1  state=%2  tx=%3")
                                  .arg(batch, state, txid.isEmpty() ? "-" : elide_middle(txid, 8));
      mint_records_.push_back(MintRecord{mint_state_badge(state), "status", batch, {}, state, details});
      const int row = mint_redemptions_view_->rowCount();
      mint_redemptions_view_->insertRow(row);
      auto* status_item = new QTableWidgetItem(mint_state_badge(state));
      status_item->setData(Qt::UserRole, static_cast<int>(mint_records_.size() - 1));
      apply_status_item_style(status_item);
      mint_redemptions_view_->setItem(row, 0, status_item);
      mint_redemptions_view_->setItem(row, 1, new QTableWidgetItem("-"));
      mint_redemptions_view_->setItem(row, 2, new QTableWidgetItem(elide_middle(batch, 10)));
      mint_redemptions_view_->setItem(row, 3, new QTableWidgetItem(state.isEmpty() ? "-" : state));
    } else if (line.startsWith("[mint-issue]")) {
      const QString issuance = extract_field_value(line, "issuance");
      const QString amount = extract_field_value(line, "amount");
      const QString notes = extract_field_value(line, "notes");
      const QString details = QString("issuance=%1  amount=%2  notes=%3").arg(issuance, amount, notes);
      mint_records_.push_back(MintRecord{"FINALIZED", "issue", issuance, amount, "issued", details});
      const int row = mint_redemptions_view_->rowCount();
      mint_redemptions_view_->insertRow(row);
      auto* status_item = new QTableWidgetItem("FINALIZED");
      status_item->setData(Qt::UserRole, static_cast<int>(mint_records_.size() - 1));
      apply_status_item_style(status_item);
      mint_redemptions_view_->setItem(row, 0, status_item);
      mint_redemptions_view_->setItem(row, 1, new QTableWidgetItem(amount.isEmpty() ? "-" : amount));
      mint_redemptions_view_->setItem(row, 2, new QTableWidgetItem(elide_middle(issuance, 10)));
      mint_redemptions_view_->setItem(row, 3, new QTableWidgetItem("issued"));
    }
    if (mint_deposits_view_->rowCount() >= 10 && mint_redemptions_view_->rowCount() >= 12) break;
  }
  if (mint_deposits_view_->rowCount() == 0) {
    mint_deposits_view_->insertRow(0);
    auto* item = new QTableWidgetItem("No mint deposits recorded yet");
    item->setData(Qt::UserRole, -1);
    mint_deposits_view_->setItem(0, 0, item);
  }
  if (mint_redemptions_view_->rowCount() == 0) {
    mint_redemptions_view_->insertRow(0);
    auto* item = new QTableWidgetItem("No mint redemptions recorded yet");
    item->setData(Qt::UserRole, -1);
    mint_redemptions_view_->setItem(0, 0, item);
  }
  mint_deposits_view_->setSortingEnabled(true);
  mint_notes_view_->setSortingEnabled(true);
  mint_redemptions_view_->setSortingEnabled(true);
  mint_detail_button_->setEnabled(!mint_records_.empty());
}

void WalletWindow::save_wallet_local_state() {
  if (!wallet_) return;
  QSettings settings(kSettingsOrg, kSettingsApp);
  settings.setValue("wallet/last_opened_file", QString::fromStdString(wallet_->file_path));
  (void)store_.set_mint_deposit_ref(mint_deposit_ref_.toStdString());
  (void)store_.set_mint_last_deposit_txid(mint_last_deposit_txid_.toStdString());
  (void)store_.set_mint_last_deposit_vout(mint_last_deposit_vout_);
  (void)store_.set_mint_last_redemption_batch_id(mint_last_redemption_batch_id_.toStdString());
  for (const auto& note : mint_notes_) {
    (void)store_.upsert_mint_note(note.note_ref.toStdString(), note.amount, true);
  }
}

void WalletWindow::load_wallet_local_state() {
  utxos_.clear();
  local_sent_txids_.clear();
  local_history_lines_.clear();
  mint_notes_.clear();
  confidential_request_views_.clear();
  confidential_coin_views_.clear();
  confidential_receive_address_ = "not configured";
  if (receive_confidential_request_label_) receive_confidential_request_label_->setText("not generated");
  confidential_balance_units_ = 0;
  confidential_coin_count_ = 0;
  confidential_storage_locked_ = false;
  pending_wallet_spends_.clear();
  pending_confidential_reservations_.clear();
  pending_tx_status_cache_.clear();
  finalized_tx_summary_cache_.clear();
  chain_records_.clear();
  finalized_history_cursor_height_.reset();
  finalized_history_cursor_txid_.reset();
  wallet_view_snapshot_.reset();
  current_chain_name_.clear();
  current_transition_hash_.clear();
  current_network_id_.clear();
  current_genesis_hash_.clear();
  current_binary_version_.clear();
  current_wallet_api_version_.clear();
  current_lightserver_status_.reset();
  current_finalized_lag_.reset();
  current_peer_height_disagreement_ = false;
  current_bootstrap_sync_incomplete_ = false;
  last_refresh_text_.clear();
  last_successful_lightserver_endpoint_.clear();
  if (!wallet_ || !open_wallet_store()) return;
  WalletStore::State state;
  if (!store_.load(&state)) return;
  if (state.wallet_snapshot.has_value()) {
    const auto& snapshot = *state.wallet_snapshot;
    current_chain_name_ = QString::fromStdString(snapshot.chain_network_name);
    current_transition_hash_ = QString::fromStdString(snapshot.transition_hash);
    current_network_id_ = QString::fromStdString(snapshot.network_id_hex);
    current_genesis_hash_ = QString::fromStdString(snapshot.genesis_hash_hex);
    current_binary_version_ = QString::fromStdString(snapshot.binary_version);
    current_wallet_api_version_ = QString::fromStdString(snapshot.wallet_api_version);
    last_refresh_text_ = QString::fromStdString(snapshot.last_refresh_text);
    last_successful_lightserver_endpoint_ = QString::fromStdString(snapshot.last_successful_endpoint);
    tip_height_ = snapshot.tip_height;
    current_finalized_lag_ =
        snapshot.finalized_lag.has_value() ? std::optional<qulonglong>(*snapshot.finalized_lag) : std::nullopt;
    current_peer_height_disagreement_ = snapshot.peer_height_disagreement;
    current_bootstrap_sync_incomplete_ = snapshot.bootstrap_sync_incomplete;
    current_lightserver_status_ = lightserver::RpcStatusView{};
    current_lightserver_status_->chain.network_name = snapshot.chain_network_name;
    current_lightserver_status_->chain.network_id_hex = snapshot.network_id_hex;
    current_lightserver_status_->chain.genesis_hash_hex = snapshot.genesis_hash_hex;
    current_lightserver_status_->tip_height = snapshot.tip_height;
    current_lightserver_status_->transition_hash = snapshot.transition_hash;
    current_lightserver_status_->binary_version = snapshot.binary_version;
    current_lightserver_status_->wallet_api_version = snapshot.wallet_api_version;
    current_lightserver_status_->finalized_lag = snapshot.finalized_lag;
    current_lightserver_status_->peer_height_disagreement = snapshot.peer_height_disagreement;
    current_lightserver_status_->bootstrap_sync_incomplete = snapshot.bootstrap_sync_incomplete;
    for (const auto& utxo : snapshot.utxos) {
      utxos_.push_back(WalletUtxo{
          .txid_hex = utxo.txid_hex,
          .vout = utxo.vout,
          .value = utxo.value,
          .height = utxo.height,
          .script_pubkey = utxo.script_pubkey,
      });
    }
  }
  wallet_view_snapshot_ = state.wallet_view_snapshot;
  for (const auto& record : state.pending_tx_statuses) {
    pending_tx_status_cache_[QString::fromStdString(record.txid_hex)] = CachedPendingTxStatus{
        .status = lightserver::TxStatusView{
            .txid_hex = record.txid_hex,
            .status = record.status,
            .finalized = record.finalized,
            .height = record.height,
            .finalized_depth = record.finalized_depth,
            .credit_safe = record.credit_safe,
            .transition_hash = record.transition_hash,
        },
        .endpoint = QString::fromStdString(record.endpoint),
        .cached_at = QString::fromStdString(record.cached_at),
        .cached_at_ms = record.cached_at_ms,
    };
  }
  local_sent_txids_ = state.sent_txids;
  for (const auto& pending : state.pending_spends) {
    pending_wallet_spends_[pending.txid_hex] = pending.inputs;
    for (const auto& input : pending.inputs) pending_confidential_reservations_[input] = pending;
  }
  finalized_history_cursor_height_ = state.history_cursor_height;
  finalized_history_cursor_txid_ = state.history_cursor_txid;
  for (const auto& record : state.finalized_history) {
    const QString txid_q = QString::fromStdString(record.txid_hex);
    const QString detail_q = QString::fromStdString(record.detail);
    const QString kind_q = QString::fromStdString(record.kind);
    chain_records_.push_back(ChainRecord{"FINALIZED", kind_q.toUpper(), detail_q, txid_q, QString::number(record.height), txid_q,
                                         QString("Height: %1\nTransaction: %2\nAmount/Detail: %3")
                                             .arg(record.height)
                                             .arg(txid_q)
                                             .arg(detail_q)});
    finalized_tx_summary_cache_[record.txid_hex] = {kind_q.toLower(), detail_q};
  }
  chain_records_ = normalize_chain_records_for_display(chain_records_);
  for (const auto& line : state.local_events) local_history_lines_.push_back(QString::fromStdString(line));
  mint_deposit_ref_ = QString::fromStdString(state.mint_deposit_ref);
  mint_last_deposit_txid_ = QString::fromStdString(state.mint_last_deposit_txid);
  mint_last_deposit_vout_ = state.mint_last_deposit_vout;
  mint_last_redemption_batch_id_ = QString::fromStdString(state.mint_last_redemption_batch_id);
  if (store_.can_persist_confidential_secrets()) {
    const auto primary_account_id = state.confidential_primary_account_id.value_or("");
    const auto account_it = std::find_if(state.confidential_accounts.begin(), state.confidential_accounts.end(),
                                         [&](const auto& account) { return account.account_id == primary_account_id; });
    if (account_it != state.confidential_accounts.end()) {
      confidential_receive_address_ = QString::fromStdString(account_it->stealth_address);
    } else if (!state.confidential_accounts.empty()) {
      confidential_receive_address_ = QString::fromStdString(state.confidential_accounts.front().stealth_address);
    }
    for (const auto& request : state.confidential_requests) {
      confidential_request_views_.push_back(ConfidentialRequestView{
          .request_id = QString::fromStdString(request.request_id),
          .account_id = QString::fromStdString(request.account_id),
          .one_time_pubkey_hex = QString::fromStdString(request.one_time_pubkey_hex),
          .ephemeral_pubkey_hex = QString::fromStdString(request.ephemeral_pubkey_hex),
          .scan_tag = request.scan_tag,
          .consumed = request.consumed,
      });
    }
    for (const auto& coin : state.confidential_coins) {
      auto txid = decode_hex32_string(coin.txid_hex);
      if (!txid) continue;
      confidential_coin_views_.push_back(ConfidentialCoinView{
          .outpoint = OutPoint{*txid, coin.vout},
          .txid_hex = QString::fromStdString(coin.txid_hex),
          .vout = coin.vout,
          .account_id = QString::fromStdString(coin.account_id),
          .amount = coin.amount,
          .one_time_pubkey_hex = QString::fromStdString(coin.one_time_pubkey_hex),
          .spent = coin.spent,
      });
      if (coin.spent) continue;
      confidential_balance_units_ += coin.amount;
      ++confidential_coin_count_;
    }
    const auto request_it = std::find_if(state.confidential_requests.rbegin(), state.confidential_requests.rend(),
                                         [](const auto& request) { return !request.consumed; });
    if (request_it != state.confidential_requests.rend() && receive_confidential_request_label_) {
      auto one_time_pubkey = decode_hex33_string(request_it->one_time_pubkey_hex);
      auto ephemeral_pubkey = decode_hex33_string(request_it->ephemeral_pubkey_hex);
      auto memo_key = decode_hex32_string(request_it->memo_key_hex);
      if (one_time_pubkey && ephemeral_pubkey && memo_key) {
        ConfidentialRecipient recipient{
            .one_time_pubkey = *one_time_pubkey,
            .ephemeral_pubkey = *ephemeral_pubkey,
            .scan_tag = crypto::ScanTag{request_it->scan_tag},
            .memo = {},
        };
        receive_confidential_request_label_->setText(
            QString::fromStdString(encode_confidential_request_uri(recipient, *memo_key)));
      }
    }
  } else if (wallet_ && wallet_->passphrase.empty()) {
    confidential_storage_locked_ = true;
  }
  for (const auto& note : state.mint_notes) {
    if (note.active) mint_notes_.push_back(MintNote{QString::fromStdString(note.note_ref), note.amount});
  }
  mark_refresh_state_changed();
  render_confidential_receive_views();
  render_mint_state();
}

bool WalletWindow::open_wallet_store() {
  if (!wallet_) return false;
  return store_.open(wallet_->file_path, wallet_->passphrase);
}

void WalletWindow::append_local_event(const QString& line) {
  local_history_lines_.push_back(line);
  if (wallet_) (void)store_.append_local_event(line.toStdString());
  render_history_view();
}

void WalletWindow::reset_send_review_panel() {
  if (!send_review_status_label_) return;
  send_review_status_label_->setText("Enter a recipient and amount to prepare a send review.");
  if (send_review_warning_label_) {
    send_review_warning_label_->clear();
    send_review_warning_label_->hide();
  }
  if (send_review_recipient_label_) send_review_recipient_label_->setText("-");
  if (send_review_amount_label_) send_review_amount_label_->setText("-");
  if (send_review_fee_label_) send_review_fee_label_->setText("-");
  if (send_review_total_label_) send_review_total_label_->setText("-");
  if (send_review_change_label_) send_review_change_label_->setText("-");
  if (send_review_inputs_label_) send_review_inputs_label_->setText("-");
  if (send_review_note_label_) {
    send_review_note_label_->setText(
        "Use Review Send to compute the current plan. A final confirmation still appears before broadcast.");
  }
}

void WalletWindow::show_send_inline_warning(const QString& text) {
  if (!send_review_warning_label_) return;
  send_review_warning_label_->setText(text);
  send_review_warning_label_->setStyleSheet("color: #a33d3d;");
  send_review_warning_label_->show();
}

void WalletWindow::show_send_inline_status(const QString& text) {
  if (!send_review_status_label_) return;
  send_review_status_label_->setText(text);
}

std::optional<std::vector<std::pair<OutPoint, TxOut>>> WalletWindow::send_available_prevs(std::size_t* reserved_excluded,
                                                                                           std::size_t* pending_reserved_excluded,
                                                                                           std::size_t* onboarding_reserved_excluded,
                                                                                           QString* err) {
  if (reserved_excluded) *reserved_excluded = 0;
  if (pending_reserved_excluded) *pending_reserved_excluded = 0;
  if (onboarding_reserved_excluded) *onboarding_reserved_excluded = 0;
  QString refresh_err;
  if (!refresh_finalized_send_state(&refresh_err)) {
    if (err) *err = refresh_err;
    return std::nullopt;
  }
  std::vector<std::pair<OutPoint, TxOut>> available_prevs;
  available_prevs.reserve(utxos_.size());
  std::set<OutPoint> reserved_for_onboarding;
  if (auto db_path = inferred_local_db_path(); db_path.has_value()) {
    finalis::storage::DB db;
    if (db.open(*db_path)) {
      std::string err_status;
      auto key = load_wallet_key(&err_status);
      if (key) {
        auto blob = db.get_validator_onboarding_record(key->pubkey);
        if (blob.has_value()) {
          auto record = finalis::onboarding::ValidatorOnboardingService::parse_record(*blob);
          if (record.has_value() && record->selected_inputs_reserved &&
              !finalis::onboarding::validator_onboarding_state_terminal(record->state)) {
            for (const auto& input : record->selected_inputs) reserved_for_onboarding.insert(input.outpoint);
          }
        }
      }
    }
  }
  const auto wallet_reserved = pending_wallet_reserved_outpoints();
  for (const auto& utxo : utxos_) {
    auto txid = decode_hex32_string(utxo.txid_hex);
    if (!txid) continue;
    const OutPoint op{*txid, utxo.vout};
    if (reserved_for_onboarding.find(op) != reserved_for_onboarding.end()) {
      if (reserved_excluded) *reserved_excluded += 1;
      if (onboarding_reserved_excluded) *onboarding_reserved_excluded += 1;
      continue;
    }
    if (wallet_reserved.find(op) != wallet_reserved.end()) {
      if (reserved_excluded) *reserved_excluded += 1;
      if (pending_reserved_excluded) *pending_reserved_excluded += 1;
      continue;
    }
    available_prevs.push_back({op, TxOut{utxo.value, utxo.script_pubkey}});
  }
  if (available_prevs.empty() && err) {
    const std::size_t pending_reserved = pending_reserved_excluded ? *pending_reserved_excluded : 0;
    const std::size_t onboarding_reserved = onboarding_reserved_excluded ? *onboarding_reserved_excluded : 0;
    if (pending_reserved > 0 || onboarding_reserved > 0) {
      QString detail = "No spendable finalized inputs are currently free.";
      const QString note = send_reservation_note(pending_reserved, onboarding_reserved);
      if (!note.isEmpty()) detail += "\n" + note;
      detail += "\nWait for finalization or cancel the in-progress flow before sending again.";
      *err = detail;
    } else {
      *err = "No spendable finalized inputs are currently available.";
    }
  }
  return available_prevs;
}

std::set<OutPoint> WalletWindow::pending_wallet_reserved_outpoints() const {
  std::set<OutPoint> out;
  for (const auto& [_, inputs] : pending_wallet_spends_) {
    out.insert(inputs.begin(), inputs.end());
  }
  return out;
}

bool WalletWindow::refresh_finalized_send_state(QString* err) {
  if (!wallet_) {
    if (err) *err = "Wallet is not loaded.";
    return false;
  }
  const QStringList endpoints = ordered_lightserver_endpoints();
  if (endpoints.isEmpty()) {
    clear_lightserver_runtime_status();
    update_connection_views();
    if (err) *err = "Configure at least one lightserver endpoint first.";
    return false;
  }
  clear_lightserver_runtime_status();
  last_refresh_endpoint_.clear();
  std::optional<lightserver::RpcStatusView> status;
  std::optional<lightserver::AddressValidationView> validated_address;
  std::optional<std::vector<lightserver::UtxoView>> utxos;
  std::vector<EndpointObservation> observations;
  for (int i = 0; i < endpoints.size(); ++i) {
    const QString endpoint = endpoints[i];
    std::string rpc_err;
    auto endpoint_status = lightserver::rpc_get_status(endpoint.toStdString(), &rpc_err);
    if (!endpoint_status) {
      record_lightserver_failure(endpoint, QString::fromStdString(rpc_err));
      if (observations.size() < 3) {
        observations.push_back(EndpointObservation{endpoint, {}, {}, {}, 0, {}, {}, {}, true, false, false,
                                                   QString::fromStdString(rpc_err)});
      }
      continue;
    }
    if (observations.size() < 3) {
      observations.push_back(EndpointObservation{endpoint,
                                                 QString::fromStdString(endpoint_status->chain.network_name),
                                                 QString::fromStdString(endpoint_status->chain.network_id_hex),
                                                 QString::fromStdString(endpoint_status->chain.genesis_hash_hex),
                                                 endpoint_status->tip_height,
                                                 QString::fromStdString(endpoint_status->transition_hash),
                                                 QString::fromStdString(endpoint_status->binary_version),
                                                 QString::fromStdString(endpoint_status->wallet_api_version),
                                                 endpoint_status->chain_id_ok,
                                                 endpoint_status->bootstrap_sync_incomplete,
                                                 endpoint_status->peer_height_disagreement,
                                                 {}});
    }
    if (auto mismatch = endpoint_chain_mismatch_reason(*endpoint_status, QString::fromStdString(wallet_->network_name))) {
      record_lightserver_failure(endpoint, *mismatch);
      continue;
    }
    auto endpoint_address = lightserver::rpc_validate_address(endpoint.toStdString(), wallet_->address, &rpc_err);
    if (!endpoint_address) {
      record_lightserver_failure(endpoint, QString::fromStdString(rpc_err));
      continue;
    }
    if (!endpoint_address->valid) {
      record_lightserver_failure(endpoint, QString("wallet address invalid: %1").arg(QString::fromStdString(endpoint_address->error)));
      continue;
    }
    if (!endpoint_address->server_network_match || !endpoint_address->has_scripthash) {
      record_lightserver_failure(endpoint, "wallet address does not match backend network");
      continue;
    }
    auto endpoint_utxos = lightserver::rpc_get_utxos(endpoint.toStdString(), endpoint_address->scripthash, &rpc_err);
    if (!endpoint_utxos) {
      record_lightserver_failure(endpoint, QString::fromStdString(rpc_err));
      continue;
    }
    status = endpoint_status;
    validated_address = endpoint_address;
    utxos = endpoint_utxos;
    last_refresh_endpoint_ = endpoint;
    record_lightserver_success(endpoint, i > 0);
    break;
  }
  const QStringList crosscheck_endpoints = endpoints.mid(0, std::min(3, endpoints.size()));
  for (const QString& endpoint : crosscheck_endpoints) {
    const auto already = std::find_if(observations.begin(), observations.end(),
                                      [&](const EndpointObservation& obs) { return obs.endpoint == endpoint; });
    if (already != observations.end()) continue;
    std::string rpc_err;
    auto endpoint_status = lightserver::rpc_get_status(endpoint.toStdString(), &rpc_err);
    if (!endpoint_status) {
      observations.push_back(EndpointObservation{endpoint, {}, {}, {}, 0, {}, {}, {}, true, false, false,
                                                 QString::fromStdString(rpc_err)});
      continue;
    }
    observations.push_back(EndpointObservation{endpoint,
                                               QString::fromStdString(endpoint_status->chain.network_name),
                                               QString::fromStdString(endpoint_status->chain.network_id_hex),
                                               QString::fromStdString(endpoint_status->chain.genesis_hash_hex),
                                               endpoint_status->tip_height,
                                               QString::fromStdString(endpoint_status->transition_hash),
                                               QString::fromStdString(endpoint_status->binary_version),
                                               QString::fromStdString(endpoint_status->wallet_api_version),
                                               endpoint_status->chain_id_ok,
                                               endpoint_status->bootstrap_sync_incomplete,
                                               endpoint_status->peer_height_disagreement,
                                               {}});
  }
  update_crosscheck_summary(observations);
  if (!status || !validated_address || !utxos) {
    update_connection_views();
    if (err) {
      *err = last_lightserver_error_.isEmpty() ? "No healthy lightserver endpoint was available." : last_lightserver_error_;
    }
    return false;
  }

  current_chain_name_ = QString::fromStdString(status->chain.network_name);
  current_transition_hash_ = QString::fromStdString(status->transition_hash);
  current_network_id_ = QString::fromStdString(status->chain.network_id_hex);
  current_genesis_hash_ = QString::fromStdString(status->chain.genesis_hash_hex);
  current_binary_version_ = QString::fromStdString(status->binary_version);
  current_wallet_api_version_ = QString::fromStdString(status->wallet_api_version);
  current_peer_height_disagreement_ = status->peer_height_disagreement;
  current_bootstrap_sync_incomplete_ = status->bootstrap_sync_incomplete;
  current_finalized_lag_ = status->finalized_lag ? std::optional<qulonglong>(*status->finalized_lag) : std::nullopt;
  last_refresh_text_ = QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss");
  tip_height_ = status->tip_height;
  utxos_.clear();
  for (const auto& utxo : *utxos) {
    utxos_.push_back(WalletUtxo{
        .txid_hex = hex_encode32(utxo.txid),
        .vout = utxo.vout,
        .value = utxo.value,
        .height = utxo.height,
        .script_pubkey = utxo.script_pubkey,
    });
  }
  update_wallet_views();
  update_connection_views();
  return true;
}

void WalletWindow::mark_refresh_state_changed() { ++refresh_state_version_; }

WalletWindow::RefreshResult WalletWindow::build_refresh_result(const RefreshRequest& request) {
  RefreshResult result;
  std::optional<lightserver::RpcStatusView> status;
  std::optional<lightserver::AddressValidationView> validated_address;
  std::optional<std::vector<lightserver::UtxoView>> utxos;
  QString active_endpoint;
  QString last_error;
  for (int i = 0; i < request.endpoints.size(); ++i) {
    const QString endpoint = request.endpoints[i];
    std::string err;
    auto endpoint_status = lightserver::rpc_get_status(endpoint.toStdString(), &err);
    if (!endpoint_status) {
      const QString qerr = QString::fromStdString(err);
      result.endpoint_failures.push_back({endpoint, qerr});
      if (result.observations.size() < 3) {
        result.observations.push_back(EndpointObservation{endpoint, {}, {}, {}, 0, {}, {}, {}, true, false, false, qerr});
      }
      last_error = qerr;
      continue;
    }
    if (result.observations.size() < 3) {
      result.observations.push_back(EndpointObservation{
          endpoint,
          QString::fromStdString(endpoint_status->chain.network_name),
          QString::fromStdString(endpoint_status->chain.network_id_hex),
          QString::fromStdString(endpoint_status->chain.genesis_hash_hex),
          endpoint_status->tip_height,
          QString::fromStdString(endpoint_status->transition_hash),
          QString::fromStdString(endpoint_status->binary_version),
          QString::fromStdString(endpoint_status->wallet_api_version),
          endpoint_status->chain_id_ok,
          endpoint_status->bootstrap_sync_incomplete,
          endpoint_status->peer_height_disagreement,
          {}});
    }
    if (auto mismatch = endpoint_chain_mismatch_reason(*endpoint_status, request.wallet_network_name)) {
      const QString qerr = *mismatch;
      result.endpoint_failures.push_back({endpoint, qerr});
      last_error = qerr;
      continue;
    }
    auto endpoint_address = lightserver::rpc_validate_address(endpoint.toStdString(), request.wallet_address.toStdString(), &err);
    if (!endpoint_address) {
      const QString qerr = QString::fromStdString(err);
      result.endpoint_failures.push_back({endpoint, qerr});
      last_error = qerr;
      continue;
    }
    if (!endpoint_address->valid) {
      const QString qerr = QString("wallet address invalid: %1").arg(QString::fromStdString(endpoint_address->error));
      result.endpoint_failures.push_back({endpoint, qerr});
      last_error = qerr;
      continue;
    }
    if (!endpoint_address->server_network_match || !endpoint_address->has_scripthash) {
      const QString qerr = "wallet address does not match backend network";
      result.endpoint_failures.push_back({endpoint, qerr});
      last_error = qerr;
      continue;
    }
    auto endpoint_utxos = lightserver::rpc_get_utxos(endpoint.toStdString(), endpoint_address->scripthash, &err);
    if (!endpoint_utxos) {
      const QString qerr = QString::fromStdString(err);
      result.endpoint_failures.push_back({endpoint, qerr});
      last_error = qerr;
      continue;
    }
    status = endpoint_status;
    validated_address = endpoint_address;
    utxos = endpoint_utxos;
    active_endpoint = endpoint;
    result.endpoint_success = std::make_pair(endpoint, i > 0);
    break;
  }
  const QStringList crosscheck_endpoints = request.endpoints.mid(0, std::min(3, request.endpoints.size()));
  for (const QString& endpoint : crosscheck_endpoints) {
    const auto already = std::find_if(result.observations.begin(), result.observations.end(),
                                      [&](const EndpointObservation& obs) { return obs.endpoint == endpoint; });
    if (already != result.observations.end()) continue;
    std::string err;
    auto endpoint_status = lightserver::rpc_get_status(endpoint.toStdString(), &err);
    if (!endpoint_status) {
      result.observations.push_back(EndpointObservation{endpoint, {}, {}, {}, 0, {}, {}, {}, true, false, false,
                                                        QString::fromStdString(err)});
      continue;
    }
    result.observations.push_back(EndpointObservation{
        endpoint,
        QString::fromStdString(endpoint_status->chain.network_name),
        QString::fromStdString(endpoint_status->chain.network_id_hex),
        QString::fromStdString(endpoint_status->chain.genesis_hash_hex),
        endpoint_status->tip_height,
        QString::fromStdString(endpoint_status->transition_hash),
        QString::fromStdString(endpoint_status->binary_version),
        QString::fromStdString(endpoint_status->wallet_api_version),
        endpoint_status->chain_id_ok,
        endpoint_status->bootstrap_sync_incomplete,
        endpoint_status->peer_height_disagreement,
        {}});
  }
  if (!status || !validated_address || !utxos) {
    result.error = last_error.isEmpty() ? "No healthy lightserver endpoint was available." : last_error;
    return result;
  }

  result.success = true;
  result.status = status;
  result.active_endpoint = active_endpoint;
  for (const auto& utxo : *utxos) {
    result.utxos.push_back(WalletUtxo{
        .txid_hex = hex_encode32(utxo.txid),
        .vout = utxo.vout,
        .value = utxo.value,
        .height = utxo.height,
        .script_pubkey = utxo.script_pubkey,
    });
  }

  const bool tip_changed =
      status->tip_height != request.previous_tip_height ||
      QString::fromStdString(status->transition_hash) != request.previous_transition_hash;
  std::set<std::string> sent_index(request.local_sent_txids.begin(), request.local_sent_txids.end());
  std::vector<ChainRecord> finalized_records;
  std::set<std::string> finalized_seen;
  auto next_summary_cache = request.finalized_tx_summary_cache;
  for (const auto& rec : request.current_chain_records) {
    if (rec.status.trimmed().toUpper() != "FINALIZED") continue;
    finalized_records.push_back(rec);
    finalized_seen.insert(rec.txid.toStdString());
  }

  std::optional<lightserver::HistoryCursor> history_cursor;
  if (request.finalized_history_cursor_height.has_value() && request.finalized_history_cursor_txid.has_value()) {
    auto cursor_txid = decode_hex32_string(*request.finalized_history_cursor_txid);
    if (cursor_txid) history_cursor = lightserver::HistoryCursor{*request.finalized_history_cursor_height, *cursor_txid};
  }

  const auto append_history_record =
      [&](const lightserver::DetailedHistoryEntry& entry, std::vector<WalletStore::FinalizedHistoryRecord>* persisted_out) {
        const std::string txid_hex = hex_encode32(entry.txid);
        QString kind;
        QString detail;
        if (auto cached = next_summary_cache.find(txid_hex); cached != next_summary_cache.end()) {
          kind = cached->second.first;
          detail = cached->second.second;
        } else {
          kind = QString::fromStdString(entry.direction);
          detail = QString::fromStdString(entry.detail);
          if (sent_index.count(txid_hex) != 0) {
            kind = "sent";
            if (entry.net_amount < 0) detail = QString("%1 net").arg(format_coin_amount(static_cast<std::uint64_t>(-entry.net_amount)));
          }
          if (kind.isEmpty()) kind = sent_index.count(txid_hex) ? "sent" : "activity";
          if (detail.isEmpty()) detail = QString("tx %1").arg(elide_middle(QString::fromStdString(txid_hex), 10));
          if (sent_index.count(txid_hex) != 0) {
            detail += " · replaces earlier local pending send";
          }
          next_summary_cache[txid_hex] = {kind, detail};
        }
        const QString txid_q = QString::fromStdString(txid_hex);
        finalized_records.push_back(ChainRecord{"FINALIZED", kind.toUpper(), detail, txid_q, QString::number(entry.height), txid_q,
                                                QString("Height: %1\nTransaction: %2\nAmount/Detail: %3")
                                                    .arg(entry.height)
                                                    .arg(txid_q)
                                                    .arg(detail)});
        finalized_seen.insert(txid_hex);
        if (persisted_out) {
          persisted_out->push_back(WalletStore::FinalizedHistoryRecord{
              .txid_hex = txid_hex,
              .height = entry.height,
              .kind = kind.toLower().toStdString(),
              .detail = detail.toStdString(),
          });
        }
      };

  const auto run_full_rebuild = [&]() -> bool {
    finalized_records.clear();
    finalized_seen.clear();
    std::vector<WalletStore::FinalizedHistoryRecord> persisted_records;
    next_summary_cache.clear();
    std::optional<lightserver::HistoryCursor> page_cursor;
    std::optional<lightserver::HistoryCursor> last_processed;
    while (true) {
      std::string rpc_err;
      auto page = lightserver::rpc_get_history_page_detailed(active_endpoint.toStdString(), validated_address->scripthash, 200,
                                                             page_cursor, &rpc_err);
      if (!page) {
        result.error = QString("Wallet history refresh failed.\n\nLast error: %1").arg(QString::fromStdString(rpc_err));
        result.success = false;
        return false;
      }
      for (const auto& entry : page->items) {
        append_history_record(entry, &persisted_records);
        last_processed = lightserver::HistoryCursor{entry.height, entry.txid};
      }
      if (!page->has_more) {
        result.history_persist_mode = HistoryPersistMode::Replace;
        result.history_records = persisted_records;
        result.update_history_cursor = true;
        result.finalized_history_cursor_height =
            last_processed ? std::optional<std::uint64_t>(last_processed->height) : std::nullopt;
        result.finalized_history_cursor_txid =
            last_processed ? std::optional<std::string>(hex_encode32(last_processed->txid)) : std::nullopt;
        break;
      }
      if (!page->next_start_after.has_value()) {
        result.error = "Wallet history pagination cursor was missing.";
        result.success = false;
        return false;
      }
      page_cursor = page->next_start_after;
    }
    return true;
  };

  bool full_rebuild = finalized_records.empty() || !history_cursor.has_value();
  if (!tip_changed && !finalized_records.empty()) full_rebuild = false;
  if (full_rebuild) {
    if (!run_full_rebuild()) return result;
  } else if (tip_changed) {
    std::vector<WalletStore::FinalizedHistoryRecord> appended_records;
    auto page_cursor = history_cursor;
    std::optional<lightserver::HistoryCursor> last_processed = history_cursor;
    bool incremental_rebuilt = false;
    while (true) {
      std::string rpc_err;
      auto page = lightserver::rpc_get_history_page_detailed(active_endpoint.toStdString(), validated_address->scripthash, 200,
                                                             page_cursor, &rpc_err);
      if (!page) {
        result.finalized_history_cursor_height.reset();
        result.finalized_history_cursor_txid.reset();
        result.update_history_cursor = true;
        if (!run_full_rebuild()) return result;
        incremental_rebuilt = true;
        break;
      }
      for (const auto& entry : page->items) {
        const std::string txid_hex = hex_encode32(entry.txid);
        if (finalized_seen.find(txid_hex) != finalized_seen.end()) {
          result.finalized_history_cursor_height.reset();
          result.finalized_history_cursor_txid.reset();
          result.update_history_cursor = true;
          if (!run_full_rebuild()) return result;
          incremental_rebuilt = true;
          break;
        }
        append_history_record(entry, &appended_records);
        last_processed = lightserver::HistoryCursor{entry.height, entry.txid};
      }
      if (incremental_rebuilt) break;
      if (!page->has_more) {
        if (!appended_records.empty()) {
          result.history_persist_mode = HistoryPersistMode::Append;
          result.history_records = appended_records;
        }
        result.update_history_cursor = true;
        if (last_processed.has_value()) {
          result.finalized_history_cursor_height = last_processed->height;
          result.finalized_history_cursor_txid = hex_encode32(last_processed->txid);
        } else {
          result.finalized_history_cursor_height = request.finalized_history_cursor_height;
          result.finalized_history_cursor_txid = request.finalized_history_cursor_txid;
        }
        break;
      }
      if (!page->next_start_after.has_value()) {
        result.finalized_history_cursor_height.reset();
        result.finalized_history_cursor_txid.reset();
        result.update_history_cursor = true;
        if (!run_full_rebuild()) return result;
        break;
      }
      page_cursor = page->next_start_after;
    }
  } else {
    result.finalized_history_cursor_height = request.finalized_history_cursor_height;
    result.finalized_history_cursor_txid = request.finalized_history_cursor_txid;
  }

  std::map<std::string, std::vector<OutPoint>> pending_spends = request.pending_wallet_spends;
  std::map<std::string, WalletStore::PendingSpend> pending_spend_meta;
  for (const auto& pending : request.pending_spend_records) {
    pending_spend_meta.emplace(pending.txid_hex, pending);
  }
  std::vector<std::string> remaining_sent_txids;
  std::set<std::string> remove_pending;
  std::set<std::string> remove_sent;
  std::vector<OutPoint> spent_confidential_outpoints;
  std::vector<std::string> released_pending_txids;
  remaining_sent_txids.reserve(request.local_sent_txids.size());
  const std::uint64_t now_ms = static_cast<std::uint64_t>(QDateTime::currentMSecsSinceEpoch());
  for (const auto& txid_hex : request.local_sent_txids) {
    bool finalized_direct = finalized_seen.count(txid_hex) != 0;
    bool dropped_from_runtime = false;
    if (!finalized_direct) {
      auto txid = decode_hex32_string(txid_hex);
      if (txid) {
        std::string rpc_err;
        auto tx_status = lightserver::rpc_get_tx_status(active_endpoint.toStdString(), *txid, &rpc_err);
        if (tx_status.has_value()) {
          finalized_direct = tx_status->finalized;
          const auto meta_it = pending_spend_meta.find(txid_hex);
          const std::uint64_t created_tip_height =
              meta_it == pending_spend_meta.end() ? 0 : meta_it->second.created_tip_height;
          const std::uint64_t created_unix_ms =
              meta_it == pending_spend_meta.end() ? 0 : meta_it->second.created_unix_ms;
          const bool release_height_ok =
              status->tip_height >= created_tip_height + kPendingSendReleaseMinTipDelta;
          const bool release_age_ok =
              created_unix_ms == 0 || now_ms >= created_unix_ms + kPendingSendReleaseMinAgeMs;
          dropped_from_runtime = tip_changed && !tx_status->finalized &&
                                 QString::fromStdString(tx_status->status).trimmed().compare("not_found", Qt::CaseInsensitive) == 0 &&
                                 release_height_ok && release_age_ok;
        }
      }
    }
    if (finalized_direct) {
      const auto pending_it = pending_spends.find(txid_hex);
      if (pending_it != pending_spends.end()) {
        spent_confidential_outpoints.insert(spent_confidential_outpoints.end(), pending_it->second.begin(), pending_it->second.end());
      }
      pending_spends.erase(txid_hex);
      remove_pending.insert(txid_hex);
      remove_sent.insert(txid_hex);
      finalized_seen.insert(txid_hex);
      continue;
    }
    if (dropped_from_runtime) {
      pending_spends.erase(txid_hex);
      remove_pending.insert(txid_hex);
      remove_sent.insert(txid_hex);
      released_pending_txids.push_back(txid_hex);
      continue;
    }
    remaining_sent_txids.push_back(txid_hex);
  }
  for (auto it = pending_spends.begin(); it != pending_spends.end();) {
    if (finalized_seen.count(it->first) == 0) {
      ++it;
      continue;
    }
    remove_pending.insert(it->first);
    it = pending_spends.erase(it);
  }

  std::vector<ChainRecord> chain_records = finalized_records;
  for (const auto& txid_hex : remaining_sent_txids) {
    if (finalized_seen.count(txid_hex)) continue;
    const QString txid_q = QString::fromStdString(txid_hex);
    chain_records.push_back(ChainRecord{
        "PENDING",
        "SENT",
        "accepted for relay",
        txid_q,
        "awaiting finalized inclusion",
        txid_q,
        QString("Transaction: %1\nState: accepted for relay, awaiting finalized inclusion\nLocal reservation: selected finalized inputs remain reserved until this transaction finalizes or is superseded.")
            .arg(txid_q),
    });
  }

  result.chain_records = normalize_chain_records_for_display(chain_records);
  result.finalized_tx_summary_cache = std::move(next_summary_cache);
  result.pending_wallet_spends = std::move(pending_spends);
  result.local_sent_txids = std::move(remaining_sent_txids);
  result.remove_pending_txids.assign(remove_pending.begin(), remove_pending.end());
  result.remove_sent_txids.assign(remove_sent.begin(), remove_sent.end());
  result.mark_spent_confidential_outpoints = std::move(spent_confidential_outpoints);
  result.released_pending_txids = std::move(released_pending_txids);
  return result;
}

void WalletWindow::apply_refresh_result(std::uint64_t generation, std::uint64_t base_state_version, bool interactive,
                                        RefreshResult result) {
  if (!should_apply_refresh_result(generation, refresh_generation_, base_state_version, refresh_state_version_)) return;

  clear_lightserver_runtime_status();
  for (const auto& [endpoint, error] : result.endpoint_failures) record_lightserver_failure(endpoint, error);
  if (result.endpoint_success.has_value()) record_lightserver_success(result.endpoint_success->first, result.endpoint_success->second);
  update_crosscheck_summary(result.observations);

  if (!result.success || !result.status.has_value()) {
    refresh_in_flight_ = should_keep_refresh_indicator(generation, refresh_generation_);
    update_connection_views();
    if (interactive) {
      QMessageBox::warning(this, "Refresh",
                           result.error.isEmpty() ? "No healthy lightserver endpoint was available."
                                                  : result.error);
    }
    return;
  }

  current_chain_name_ = QString::fromStdString(result.status->chain.network_name);
  current_transition_hash_ = QString::fromStdString(result.status->transition_hash);
  current_network_id_ = QString::fromStdString(result.status->chain.network_id_hex);
  current_genesis_hash_ = QString::fromStdString(result.status->chain.genesis_hash_hex);
  current_binary_version_ = QString::fromStdString(result.status->binary_version);
  current_wallet_api_version_ = QString::fromStdString(result.status->wallet_api_version);
  current_lightserver_status_ = *result.status;
  current_peer_height_disagreement_ = result.status->peer_height_disagreement;
  current_bootstrap_sync_incomplete_ = result.status->bootstrap_sync_incomplete;
  current_finalized_lag_ =
      result.status->finalized_lag ? std::optional<qulonglong>(*result.status->finalized_lag) : std::nullopt;
  last_refresh_text_ = QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss");
  tip_height_ = result.status->tip_height;
  utxos_ = std::move(result.utxos);
  chain_records_ = std::move(result.chain_records);
  local_sent_txids_ = std::move(result.local_sent_txids);
  pending_wallet_spends_ = std::move(result.pending_wallet_spends);
  finalized_history_cursor_height_ = result.finalized_history_cursor_height;
  finalized_history_cursor_txid_ = result.finalized_history_cursor_txid;
  finalized_tx_summary_cache_ = std::move(result.finalized_tx_summary_cache);
  WalletStore::WalletSnapshot snapshot;
  snapshot.chain_network_name = result.status->chain.network_name;
  snapshot.transition_hash = result.status->transition_hash;
  snapshot.network_id_hex = result.status->chain.network_id_hex;
  snapshot.genesis_hash_hex = result.status->chain.genesis_hash_hex;
  snapshot.binary_version = result.status->binary_version;
  snapshot.wallet_api_version = result.status->wallet_api_version;
  snapshot.last_refresh_text = last_refresh_text_.toStdString();
  snapshot.last_successful_endpoint = last_successful_lightserver_endpoint_.toStdString();
  snapshot.tip_height = result.status->tip_height;
  if (result.status->finalized_lag.has_value()) snapshot.finalized_lag = *result.status->finalized_lag;
  snapshot.peer_height_disagreement = result.status->peer_height_disagreement;
  snapshot.bootstrap_sync_incomplete = result.status->bootstrap_sync_incomplete;
  snapshot.utxos.reserve(utxos_.size());
  for (const auto& utxo : utxos_) {
    snapshot.utxos.push_back(WalletStore::SnapshotUtxoRecord{
        .txid_hex = utxo.txid_hex,
        .vout = utxo.vout,
        .value = utxo.value,
        .height = utxo.height,
        .script_pubkey = utxo.script_pubkey,
    });
  }
  (void)store_.set_wallet_snapshot(snapshot);

  if (result.history_persist_mode == HistoryPersistMode::Replace) {
    (void)store_.replace_finalized_history(result.history_records);
  } else if (result.history_persist_mode == HistoryPersistMode::Append && !result.history_records.empty()) {
    (void)store_.append_finalized_history(result.history_records);
  }
  if (result.update_history_cursor) {
    (void)store_.set_history_cursor(finalized_history_cursor_height_, finalized_history_cursor_txid_);
  }
  for (const auto& txid : result.remove_sent_txids) {
    const QString line = QString("[finalized] pending send finalized %1")
                             .arg(elide_middle(QString::fromStdString(txid), 12));
    local_history_lines_.push_back(line);
    (void)store_.append_local_event(line.toStdString());
  }
  for (const auto& txid : result.released_pending_txids) {
    const QString line = QString("[info] pending send released %1")
                             .arg(elide_middle(QString::fromStdString(txid), 12));
    local_history_lines_.push_back(line);
    (void)store_.append_local_event(line.toStdString());
  }
  for (const auto& outpoint : result.mark_spent_confidential_outpoints) {
    (void)store_.set_confidential_coin_spent(hex_encode32(outpoint.txid), outpoint.index, true);
  }
  for (const auto& txid : result.remove_pending_txids) {
    (void)store_.remove_pending_spend(txid);
    (void)store_.remove_pending_tx_status(txid);
    pending_tx_status_cache_.erase(QString::fromStdString(txid));
  }
  for (const auto& txid : result.remove_sent_txids) {
    (void)store_.remove_sent_txid(txid);
    (void)store_.remove_pending_tx_status(txid);
    pending_tx_status_cache_.erase(QString::fromStdString(txid));
  }
  refresh_in_flight_ = should_keep_refresh_indicator(generation, refresh_generation_);
  mark_refresh_state_changed();

  load_wallet_local_state();
  update_wallet_views();
  render_history_view();
  update_connection_views();
  if (interactive) {
    const QString message =
        last_refresh_used_fallback_
            ? QString("Wallet state refreshed using fallback lightserver %1.")
                  .arg(display_lightserver_endpoint(last_successful_lightserver_endpoint_))
            : QString("Wallet state refreshed from %1.")
                  .arg(display_lightserver_endpoint(last_successful_lightserver_endpoint_));
    statusBar()->showMessage(message, 3000);
  }
}

void WalletWindow::refresh_chain_state(bool interactive) {
  if (!wallet_) return;
  const QStringList endpoints = ordered_lightserver_endpoints();
  if (endpoints.isEmpty()) {
    clear_lightserver_runtime_status();
    update_connection_views();
    if (interactive) QMessageBox::warning(this, "Refresh", "Configure at least one lightserver endpoint first.");
    return;
  }
  clear_lightserver_runtime_status();
  refresh_in_flight_ = true;
  update_connection_views();
  update_wallet_views();
  statusBar()->showMessage("Refreshing finalized state...", 1500);

  const std::uint64_t generation = ++refresh_generation_;
  const std::uint64_t base_state_version = refresh_state_version_;
  RefreshRequest request;
  request.wallet_address = QString::fromStdString(wallet_->address);
  request.wallet_network_name = QString::fromStdString(wallet_->network_name);
  request.endpoints = endpoints;
  request.previous_tip_height = tip_height_;
  request.previous_transition_hash = current_transition_hash_;
  request.current_chain_records = chain_records_;
  request.local_sent_txids = local_sent_txids_;
  request.pending_wallet_spends = pending_wallet_spends_;
  if (wallet_) {
    WalletStore::State local_state;
    if (store_.load(&local_state)) request.pending_spend_records = std::move(local_state.pending_spends);
  }
  request.finalized_history_cursor_height = finalized_history_cursor_height_;
  request.finalized_history_cursor_txid = finalized_history_cursor_txid_;
  request.finalized_tx_summary_cache = finalized_tx_summary_cache_;

  QPointer<WalletWindow> self(this);
  std::thread([self, generation, base_state_version, interactive, request = std::move(request)]() mutable {
    auto result = WalletWindow::build_refresh_result(request);
    QMetaObject::invokeMethod(
        self,
        [self, generation, base_state_version, interactive, result = std::move(result)]() mutable {
          if (!self) return;
          self->apply_refresh_result(generation, base_state_version, interactive, std::move(result));
        },
        Qt::QueuedConnection);
  }).detach();
}

std::optional<WalletWindow::LoadedWallet> WalletWindow::load_wallet_file(const QString& path, const QString& passphrase) {
  finalis::keystore::ValidatorKey key;
  std::string err;
  if (!finalis::keystore::load_validator_keystore(path.toStdString(), passphrase.toStdString(), &key, &err)) {
    QMessageBox::warning(this, "Open Wallet", QString::fromStdString(err));
    return std::nullopt;
  }

  LoadedWallet loaded;
  loaded.file_path = path.toStdString();
  loaded.passphrase = passphrase.toStdString();
  loaded.network_name = key.network_name;
  loaded.address = key.address;
  loaded.pubkey_hex = finalis::hex_encode(finalis::Bytes(key.pubkey.begin(), key.pubkey.end()));
  return loaded;
}

std::optional<QString> WalletWindow::prompt_passphrase(const QString& title, bool confirm) const {
  bool ok = false;
  const QString pass = QInputDialog::getText(const_cast<WalletWindow*>(this), title, "Passphrase",
                                             QLineEdit::Password, "", &ok);
  if (!ok) return std::nullopt;
  if (!confirm) return pass;
  const QString confirm_pass = QInputDialog::getText(const_cast<WalletWindow*>(this), title, "Confirm passphrase",
                                                     QLineEdit::Password, "", &ok);
  if (!ok) return std::nullopt;
  if (pass != confirm_pass) {
    QMessageBox::warning(const_cast<WalletWindow*>(this), title, "Passphrases do not match.");
    return std::nullopt;
  }
  return pass;
}

bool WalletWindow::ensure_wallet_loaded(const QString& action_name) {
  if (wallet_) return true;
  QMessageBox::information(this, action_name, "Open, create, or import a wallet first.");
  return false;
}

std::optional<finalis::keystore::ValidatorKey> WalletWindow::load_wallet_key(std::string* err) const {
  if (!wallet_) {
    if (err) *err = "wallet not loaded";
    return std::nullopt;
  }
  finalis::keystore::ValidatorKey key;
  if (!finalis::keystore::load_validator_keystore(wallet_->file_path, wallet_->passphrase, &key, err)) return std::nullopt;
  return key;
}

std::optional<std::string> WalletWindow::inferred_local_db_path() const {
  if (!wallet_) return std::nullopt;
  return finalis::onboarding::infer_node_db_path_from_wallet_file(wallet_->file_path);
}

void WalletWindow::create_wallet() {
  const QString path = QFileDialog::getSaveFileName(this, "Create Wallet", QDir::homePath() + "/finalis-wallet.json",
                                                    "Wallet files (*.json)");
  if (path.isEmpty()) return;
  const auto passphrase = prompt_passphrase("Create Wallet", true);
  if (!passphrase.has_value()) return;

  finalis::keystore::ValidatorKey key;
  std::string err;
  if (!finalis::keystore::create_validator_keystore(path.toStdString(), passphrase->toStdString(), "mainnet",
                                                      finalis::keystore::hrp_for_network("mainnet"), std::nullopt, &key,
                                                      &err)) {
    QMessageBox::warning(this, "Create Wallet", QString::fromStdString(err));
    return;
  }

  LoadedWallet loaded;
  loaded.file_path = path.toStdString();
  loaded.passphrase = passphrase->toStdString();
  loaded.network_name = key.network_name;
  loaded.address = key.address;
  loaded.pubkey_hex = finalis::hex_encode(finalis::Bytes(key.pubkey.begin(), key.pubkey.end()));
  wallet_ = loaded;
  (void)open_wallet_store();
  load_wallet_local_state();
  update_wallet_views();
  render_history_view();
  append_local_event("Created wallet at " + path);
  refresh_chain_state(false);
  statusBar()->showMessage("Wallet created.", 3000);
}

void WalletWindow::open_wallet() {
  const QString path = QFileDialog::getOpenFileName(this, "Open Wallet", QDir::homePath(), "Wallet files (*.json)");
  if (path.isEmpty()) return;
  const auto passphrase = prompt_passphrase("Open Wallet", false);
  if (!passphrase.has_value()) return;
  auto loaded = load_wallet_file(path, *passphrase);
  if (!loaded) return;
  wallet_ = *loaded;
  (void)open_wallet_store();
  load_wallet_local_state();
  update_wallet_views();
  render_history_view();
  append_local_event("Opened wallet " + path);
  refresh_chain_state(false);
  statusBar()->showMessage("Wallet opened.", 3000);
}

void WalletWindow::import_wallet() {
  const QString path = QFileDialog::getSaveFileName(this, "Import Wallet", QDir::homePath() + "/finalis-wallet.json",
                                                    "Wallet files (*.json)");
  if (path.isEmpty()) return;
  bool ok = false;
  const QString privkey_hex = QInputDialog::getText(this, "Import Wallet", "Private key (32-byte hex)",
                                                    QLineEdit::Normal, "", &ok);
  if (!ok || privkey_hex.trimmed().isEmpty()) return;
  auto seed = decode_hex32_string(privkey_hex.trimmed().toStdString());
  if (!seed) {
    QMessageBox::warning(this, "Import Wallet", "Private key must be exactly 32 bytes in hex.");
    return;
  }
  const auto passphrase = prompt_passphrase("Import Wallet", true);
  if (!passphrase.has_value()) return;

  finalis::keystore::ValidatorKey key;
  std::string err;
  if (!finalis::keystore::create_validator_keystore(path.toStdString(), passphrase->toStdString(), "mainnet",
                                                      finalis::keystore::hrp_for_network("mainnet"), *seed, &key, &err)) {
    QMessageBox::warning(this, "Import Wallet", QString::fromStdString(err));
    return;
  }

  LoadedWallet loaded;
  loaded.file_path = path.toStdString();
  loaded.passphrase = passphrase->toStdString();
  loaded.network_name = key.network_name;
  loaded.address = key.address;
  loaded.pubkey_hex = finalis::hex_encode(finalis::Bytes(key.pubkey.begin(), key.pubkey.end()));
  wallet_ = loaded;
  (void)open_wallet_store();
  load_wallet_local_state();
  update_wallet_views();
  render_history_view();
  append_local_event("Imported wallet into " + path);
  refresh_chain_state(false);
  statusBar()->showMessage("Wallet imported.", 3000);
}

void WalletWindow::unlock_confidential_state() {
  if (!ensure_wallet_loaded("Unlock Confidential State")) return;

  const auto passphrase = prompt_passphrase("Unlock Confidential State", false);
  if (!passphrase.has_value()) return;

  auto loaded = load_wallet_file(QString::fromStdString(wallet_->file_path), *passphrase);
  if (!loaded) return;

  wallet_->passphrase = loaded->passphrase;
  if (!open_wallet_store()) {
    QMessageBox::warning(this, "Unlock Confidential State", "Failed to reopen wallet local state.");
    return;
  }
  load_wallet_local_state();
  update_wallet_views();
  render_history_view();
  append_local_event("Unlocked confidential local state for " + QString::fromStdString(wallet_->file_path));
  statusBar()->showMessage("Confidential local state unlocked.", 3000);
}

void WalletWindow::create_confidential_account() {
  if (!ensure_wallet_loaded("Create Confidential Account")) return;
  if (!store_.can_persist_confidential_secrets()) {
    QMessageBox::warning(this, "Create Confidential Account",
                         "Confidential accounts require an opened wallet with a non-empty passphrase.");
    return;
  }
  bool ok = false;
  const QString label = QInputDialog::getText(
      this, "New Confidential Account", "Account label", QLineEdit::Normal, "Primary confidential account", &ok);
  if (!ok) return;

  const Hash32 view_secret = random_hash32();
  const Hash32 spend_secret = random_hash32();
  auto view_pubkey = crypto::secp256k1_pubkey_from_scalar(view_secret);
  auto spend_pubkey = crypto::secp256k1_pubkey_from_scalar(spend_secret);
  if (!view_pubkey || !spend_pubkey) {
    QMessageBox::warning(this, "Create Confidential Account", "Failed to derive confidential account pubkeys.");
    return;
  }

  const Hash32 account_seed = random_hash32();
  WalletStore::ConfidentialAccountRecord record{
      .account_id = finalis::hex_encode32(account_seed),
      .label = label.trimmed().isEmpty() ? "Confidential account" : label.trimmed().toStdString(),
      .stealth_address = encode_local_stealth_address(*view_pubkey, *spend_pubkey),
      .view_key_material_hex = finalis::hex_encode(Bytes(view_secret.begin(), view_secret.end())),
      .spend_key_material_hex = finalis::hex_encode(Bytes(spend_secret.begin(), spend_secret.end())),
      .active = true,
  };
  if (!store_.upsert_confidential_account(record) || !store_.set_confidential_primary_account_id(record.account_id)) {
    QMessageBox::warning(this, "Create Confidential Account", "Failed to persist confidential account state.");
    return;
  }
  load_wallet_local_state();
  update_wallet_views();
  append_local_event(QString("[confidential] created account %1")
                         .arg(QString::fromStdString(record.label)));
  statusBar()->showMessage("Confidential account created.", 3000);
}

void WalletWindow::import_confidential_account() {
  if (!ensure_wallet_loaded("Import Confidential Account")) return;
  if (!store_.can_persist_confidential_secrets()) {
    QMessageBox::warning(this, "Import Confidential Account",
                         "Confidential accounts require an opened wallet with a non-empty passphrase.");
    return;
  }
  bool ok = false;
  const QString label = QInputDialog::getText(
      this, "Import Confidential Account", "Account label", QLineEdit::Normal, "Imported confidential account", &ok);
  if (!ok) return;
  const QString view_hex = QInputDialog::getText(
      this, "Import Confidential Account", "View secret hex (32 bytes)", QLineEdit::Normal, {}, &ok);
  if (!ok) return;
  const QString spend_hex = QInputDialog::getText(
      this, "Import Confidential Account", "Spend secret hex (32 bytes)", QLineEdit::Normal, {}, &ok);
  if (!ok) return;

  auto view_secret = decode_hex32_string(view_hex.trimmed().toStdString());
  auto spend_secret = decode_hex32_string(spend_hex.trimmed().toStdString());
  if (!view_secret || !spend_secret) {
    QMessageBox::warning(this, "Import Confidential Account", "View and spend secrets must both be 32-byte hex values.");
    return;
  }
  auto view_pubkey = crypto::secp256k1_pubkey_from_scalar(*view_secret);
  auto spend_pubkey = crypto::secp256k1_pubkey_from_scalar(*spend_secret);
  if (!view_pubkey || !spend_pubkey) {
    QMessageBox::warning(this, "Import Confidential Account", "Failed to derive confidential account pubkeys.");
    return;
  }

  Hash32 account_seed = random_hash32();
  WalletStore::ConfidentialAccountRecord record{
      .account_id = finalis::hex_encode32(account_seed),
      .label = label.trimmed().isEmpty() ? "Imported confidential account" : label.trimmed().toStdString(),
      .stealth_address = encode_local_stealth_address(*view_pubkey, *spend_pubkey),
      .view_key_material_hex = view_hex.trimmed().toStdString(),
      .spend_key_material_hex = spend_hex.trimmed().toStdString(),
      .active = true,
  };
  if (!store_.upsert_confidential_account(record) || !store_.set_confidential_primary_account_id(record.account_id)) {
    QMessageBox::warning(this, "Import Confidential Account", "Failed to persist confidential account state.");
    return;
  }
  load_wallet_local_state();
  update_wallet_views();
  append_local_event(QString("[confidential] imported account %1")
                         .arg(QString::fromStdString(record.label)));
  statusBar()->showMessage("Confidential account imported.", 3000);
}

void WalletWindow::generate_confidential_request() {
  if (!ensure_wallet_loaded("Generate Confidential Request")) return;
  if (confidential_storage_locked_) {
    QMessageBox::warning(this, "Generate Confidential Request",
                         "Unlock confidential state first. Request generation needs local confidential recovery material.");
    return;
  }
  WalletStore::State state;
  if (!store_.load(&state)) {
    QMessageBox::warning(this, "Generate Confidential Request", "Unable to load local confidential wallet state.");
    return;
  }
  const std::string primary_account_id = state.confidential_primary_account_id.value_or("");
  auto account_it = std::find_if(
      state.confidential_accounts.begin(), state.confidential_accounts.end(),
      [&](const WalletStore::ConfidentialAccountRecord& account) { return account.account_id == primary_account_id; });
  if (account_it == state.confidential_accounts.end() && !state.confidential_accounts.empty()) {
    account_it = state.confidential_accounts.begin();
  }
  if (account_it == state.confidential_accounts.end()) {
    QMessageBox::warning(this, "Generate Confidential Request",
                         "No confidential account is configured locally yet.");
    return;
  }
  const Hash32 spend_secret = random_hash32();
  auto one_time_pubkey = crypto::secp256k1_pubkey_from_scalar(spend_secret);
  if (!one_time_pubkey) {
    QMessageBox::warning(this, "Generate Confidential Request", "Failed to derive a one-time confidential receive key.");
    return;
  }
  const Hash32 memo_key = random_hash32();
  const Hash32 ephemeral_secret = random_hash32();
  auto ephemeral_pubkey = crypto::secp256k1_pubkey_from_scalar(ephemeral_secret);
  if (!ephemeral_pubkey) {
    QMessageBox::warning(this, "Generate Confidential Request", "Failed to derive an ephemeral request key.");
    return;
  }
  const std::uint8_t scan_tag = random_hash32()[0];
  const ConfidentialRecipient recipient{
      .one_time_pubkey = *one_time_pubkey,
      .ephemeral_pubkey = *ephemeral_pubkey,
      .scan_tag = crypto::ScanTag{scan_tag},
      .memo = {},
  };
  const QString uri = QString::fromStdString(encode_confidential_request_uri(recipient, memo_key));
  const QByteArray uri_utf8 = uri.toUtf8();
  const Bytes uri_bytes(uri_utf8.begin(), uri_utf8.end());
  WalletStore::ConfidentialRequestRecord request_record{
      .request_id = finalis::hex_encode32(crypto::sha256d(uri_bytes)),
      .account_id = account_it->account_id,
      .one_time_pubkey_hex = finalis::hex_encode(Bytes(recipient.one_time_pubkey.begin(), recipient.one_time_pubkey.end())),
      .ephemeral_pubkey_hex = finalis::hex_encode(Bytes(recipient.ephemeral_pubkey.begin(), recipient.ephemeral_pubkey.end())),
      .scan_tag = recipient.scan_tag.value,
      .spend_secret_hex = finalis::hex_encode(Bytes(spend_secret.begin(), spend_secret.end())),
      .memo_key_hex = finalis::hex_encode(Bytes(memo_key.begin(), memo_key.end())),
      .consumed = false,
  };
  if (!store_.upsert_confidential_request(request_record)) {
    QMessageBox::warning(this, "Generate Confidential Request", "Failed to persist local confidential request state.");
    return;
  }
  if (receive_confidential_request_label_) receive_confidential_request_label_->setText(uri);
  QApplication::clipboard()->setText(uri);
  append_local_event(QString("[confidential] generated receive request for %1")
                         .arg(QString::fromStdString(account_it->label.empty() ? account_it->account_id : account_it->label)));
  statusBar()->showMessage("Confidential request generated and copied to clipboard.", 3000);
}

void WalletWindow::import_received_confidential_tx() {
  if (!ensure_wallet_loaded("Import Received Confidential Tx")) return;
  if (confidential_storage_locked_) {
    QMessageBox::warning(this, "Import Received Confidential Tx", "Unlock confidential state first.");
    return;
  }
  if (configured_lightserver_endpoints().isEmpty()) {
    QMessageBox::warning(this, "Import Received Confidential Tx", "Configure at least one lightserver endpoint first.");
    return;
  }
  WalletStore::State state;
  if (!store_.load(&state)) {
    QMessageBox::warning(this, "Import Received Confidential Tx", "Unable to load local confidential wallet state.");
    return;
  }
  if (state.confidential_requests.empty()) {
    QMessageBox::warning(this, "Import Received Confidential Tx",
                         "No local confidential receive requests are available to match against.");
    return;
  }
  bool ok = false;
  const QString txid_text = QInputDialog::getText(this, "Import Received Confidential Tx", "Finalized txid hex",
                                                  QLineEdit::Normal, {}, &ok);
  if (!ok || txid_text.trimmed().isEmpty()) return;
  auto txid = decode_hex32_string(txid_text.trimmed().toStdString());
  if (!txid) {
    QMessageBox::warning(this, "Import Received Confidential Tx", "Txid must be exactly 32 bytes in hex.");
    return;
  }

  QString used_endpoint;
  std::string rpc_err;
  std::optional<lightserver::TxStatusView> tx_status;
  std::optional<lightserver::TxView> tx_view;
  for (const QString& endpoint : ordered_lightserver_endpoints()) {
    tx_status = lightserver::rpc_get_tx_status(endpoint.toStdString(), *txid, &rpc_err);
    if (!tx_status || !tx_status->finalized) continue;
    tx_view = lightserver::rpc_get_tx(endpoint.toStdString(), *txid, &rpc_err);
    if (!tx_view) continue;
    used_endpoint = endpoint;
    break;
  }
  if (!tx_status || !tx_status->finalized || !tx_view) {
    QMessageBox::warning(this, "Import Received Confidential Tx",
                         rpc_err.empty() ? "Unable to fetch a finalized transaction from the configured lightservers."
                                         : QString::fromStdString(rpc_err));
    return;
  }
  auto any_tx = parse_any_tx(tx_view->tx_bytes);
  if (!any_tx || !std::holds_alternative<TxV2>(*any_tx)) {
    QMessageBox::warning(this, "Import Received Confidential Tx", "Transaction is not a supported TxV2 record.");
    return;
  }
  const auto& tx = std::get<TxV2>(*any_tx);
  bool imported_any = false;
  for (std::size_t i = 0; i < tx.outputs.size(); ++i) {
    const auto& output = tx.outputs[i];
    if (output.kind != TxOutputKind::Confidential) continue;
    const auto& confidential = std::get<ConfidentialTxOutV2>(output.body);
    const std::string one_time_hex = finalis::hex_encode(Bytes(confidential.one_time_pubkey.begin(), confidential.one_time_pubkey.end()));
    const std::string ephemeral_hex = finalis::hex_encode(Bytes(confidential.ephemeral_pubkey.begin(), confidential.ephemeral_pubkey.end()));
    const auto request_it = std::find_if(
        state.confidential_requests.begin(), state.confidential_requests.end(),
        [&](const WalletStore::ConfidentialRequestRecord& req) {
          return !req.consumed && req.one_time_pubkey_hex == one_time_hex &&
                 req.ephemeral_pubkey_hex == ephemeral_hex && req.scan_tag == confidential.scan_tag.value;
        });
    if (request_it == state.confidential_requests.end()) continue;
    auto memo_key = decode_hex32_string(request_it->memo_key_hex);
    auto spend_secret = decode_hex32_string(request_it->spend_secret_hex);
    if (!memo_key || !spend_secret) continue;
    auto recovery = decrypt_confidential_recovery_memo(confidential.memo, *memo_key, confidential.ephemeral_pubkey);
    if (!recovery) continue;
    WalletStore::ConfidentialCoinRecord coin{
        .txid_hex = hex_encode32(*txid),
        .vout = static_cast<std::uint32_t>(i),
        .account_id = request_it->account_id,
        .amount = recovery->amount,
        .value_commitment_hex = finalis::hex_encode(Bytes(confidential.value_commitment.bytes.begin(), confidential.value_commitment.bytes.end())),
        .one_time_pubkey_hex = one_time_hex,
        .ephemeral_pubkey_hex = ephemeral_hex,
        .spend_secret_hex = request_it->spend_secret_hex,
        .blinding_factor_hex = finalis::hex_encode(Bytes(recovery->blind.bytes.begin(), recovery->blind.bytes.end())),
        .spent = false,
    };
    if (!store_.upsert_confidential_coin(coin)) continue;
    (void)store_.set_confidential_request_consumed(request_it->request_id, true);
    imported_any = true;
  }
  if (!imported_any) {
    QMessageBox::warning(this, "Import Received Confidential Tx",
                         "No matching confidential output for any local receive request was found in that finalized TxV2.");
    return;
  }
  load_wallet_local_state();
  update_wallet_views();
  append_local_event(QString("[confidential] imported received output from %1 via %2")
                         .arg(elide_middle(txid_text.trimmed(), 12))
                         .arg(used_endpoint.isEmpty() ? "lightserver" : display_lightserver_endpoint(used_endpoint)));
  statusBar()->showMessage("Confidential output imported.", 3000);
}

void WalletWindow::import_confidential_request() {
  const auto mode = wallet_send_mode_from_combo(send_mode_combo_);
  if (mode != WalletSendMode::TransparentToConfidential) {
    if (send_mode_combo_) send_mode_combo_->setCurrentIndex(static_cast<int>(WalletSendMode::TransparentToConfidential));
  }
  bool ok = false;
  const QString current = QApplication::clipboard()->text().trimmed();
  const QString input = QInputDialog::getMultiLineText(
      this, "Import Confidential Request",
      "Paste a confidential request URI or legacy ctxv2 descriptor.\n\nPreferred format: scconfreq1:...", current, &ok);
  if (!ok) return;
  QString parse_err;
  auto recipient = parse_confidential_recipient_descriptor(input, &parse_err);
  if (!recipient) {
    QMessageBox::warning(this, "Import Confidential Request", parse_err.isEmpty() ? "Request is invalid." : parse_err);
    return;
  }
  const QString normalized = input.trimmed().startsWith("scconfreq1:", Qt::CaseInsensitive)
                                 ? input.trimmed()
                                 : QString::fromStdString(encode_confidential_request_uri(recipient->recipient, recipient->memo_key));
  send_address_edit_->setText(normalized);
  tabs_->setCurrentWidget(send_page_);
  show_send_inline_status("Confidential request imported. Review before sending.");
}

void WalletWindow::export_wallet_secret() {
  if (!ensure_wallet_loaded("Export Backup")) return;

  finalis::keystore::ValidatorKey key;
  std::string err;
  if (!finalis::keystore::load_validator_keystore(wallet_->file_path, wallet_->passphrase, &key, &err)) {
    QMessageBox::warning(this, "Export Backup", QString::fromStdString(err));
    return;
  }

  const QString privkey_hex = QString::fromStdString(finalis::hex_encode(finalis::Bytes(key.privkey.begin(), key.privkey.end())));
  QMessageBox::information(
      this, "Export Backup",
      "Store this private key offline.\n\nPrivate key:\n" + privkey_hex +
          "\n\nThe wallet does not show it during normal use unless you explicitly export it.");
  append_local_event("Exported backup material for " + QString::fromStdString(wallet_->file_path));
}

void WalletWindow::save_connection_settings() {
  save_settings();
  clear_lightserver_runtime_status();
  utxos_.clear();
  update_connection_views();
  append_local_event("Saved local connection settings.");
  refresh_chain_state(false);
  statusBar()->showMessage("Settings saved.", 3000);
}

void WalletWindow::show_about() {
  QMessageBox box(this);
  box.setWindowTitle("About");
  const ThemeMode mode = theme_mode_from_string(theme_combo_ ? theme_combo_->currentText() : "Light");
  const QString symbol_path =
      mode == ThemeMode::Dark ? ":/branding/finalis-symbol-dark.svg" : ":/branding/finalis-symbol.svg";
  box.setIconPixmap(QIcon(symbol_path).pixmap(QSize(56, 56)));
  box.setText("Finalis Wallet");
  box.setInformativeText(
      "Qt desktop wallet for finalized-state operations.\n"
      "It connects to configured lightserver and mint services and does not embed a node.");
  box.setStandardButtons(QMessageBox::Ok);
  box.exec();
}

void WalletWindow::validate_send_form() {
  if (!ensure_wallet_loaded("Review Send")) return;
  reset_send_review_panel();
  const auto mode = wallet_send_mode_from_combo(send_mode_combo_);
  const QString recipient_text = send_address_edit_->text().trimmed();
  const QString amount_text = send_amount_edit_->text().trimmed();
  if (recipient_text.isEmpty() || amount_text.isEmpty()) {
    show_send_inline_warning("Recipient address and amount are required.");
    show_send_inline_status("Review unavailable");
    return;
  }
  bool amount_ok = false;
  const double amount_value = amount_text.toDouble(&amount_ok);
  if (!amount_ok || amount_value <= 0.0) {
    show_send_inline_warning("Amount must be positive.");
    show_send_inline_status("Review unavailable");
    return;
  }

  auto amount_units = parse_coin_amount(amount_text);
  if (!amount_units) {
    show_send_inline_warning("Amount must be a valid coin value with up to 8 decimals.");
    show_send_inline_status("Review unavailable");
    return;
  }
  if (mode == WalletSendMode::TransparentToTransparent) {
    if (!finalis::address::decode(recipient_text.toStdString()).has_value()) {
      show_send_inline_warning("Recipient address is invalid.");
      show_send_inline_status("Review unavailable");
      return;
    }
    std::size_t reserved_excluded = 0;
    std::size_t pending_reserved_excluded = 0;
    std::size_t onboarding_reserved_excluded = 0;
    QString prev_err;
    auto available_prevs =
        send_available_prevs(&reserved_excluded, &pending_reserved_excluded, &onboarding_reserved_excluded, &prev_err);
    if (!available_prevs) {
      show_send_inline_warning(prev_err.isEmpty() ? "No spendable finalized inputs are currently available." : prev_err);
      show_send_inline_status("Review unavailable");
      return;
    }
    auto decoded_to = finalis::address::decode(recipient_text.toStdString());
    auto own_decoded = finalis::address::decode(wallet_->address);
    if (!decoded_to || !own_decoded) {
      show_send_inline_warning("Address data is invalid.");
      show_send_inline_status("Review unavailable");
      return;
    }
    std::string err;
    auto plan = finalis::plan_wallet_p2pkh_send(
        *available_prevs, finalis::address::p2pkh_script_pubkey(decoded_to->pubkey_hash),
        finalis::address::p2pkh_script_pubkey(own_decoded->pubkey_hash), *amount_units,
        finalis::DEFAULT_WALLET_SEND_FEE_UNITS, finalis::DEFAULT_WALLET_DUST_THRESHOLD_UNITS, &err);
    if (!plan) {
      show_send_inline_warning(QString::fromStdString(err));
      show_send_inline_status("Review unavailable");
      return;
    }

    const QString change_text =
        plan->change_units > 0
            ? QString("%1 back to %2")
                  .arg(format_coin_amount(plan->change_units))
                  .arg(elide_middle(QString::fromStdString(wallet_->address)))
            : QString("Folded into fee (dust <= %1 units)").arg(finalis::DEFAULT_WALLET_DUST_THRESHOLD_UNITS);
    send_review_recipient_label_->setText(recipient_text);
    send_review_amount_label_->setText(format_coin_amount(*amount_units));
    send_review_fee_label_->setText(format_coin_amount(plan->applied_fee_units));
    send_review_total_label_->setText(format_coin_amount(*amount_units + plan->applied_fee_units));
    send_review_change_label_->setText(change_text);
    send_review_inputs_label_->setText(QString::number(plan->selected_prevs.size()));
    QString note =
        "The review is based on finalized wallet state only. Pending local sends keep their inputs reserved until finalization.";
    if (reserved_excluded > 0) {
      note += QString("\nReserved finalized inputs excluded from this review: %1.").arg(reserved_excluded);
      const QString reservation_breakdown = send_reservation_note(pending_reserved_excluded, onboarding_reserved_excluded);
      if (!reservation_breakdown.isEmpty()) note += "\n" + reservation_breakdown;
    }
    send_review_note_label_->setText(note);
    show_send_inline_status("Review ready");
    if (send_review_warning_label_) send_review_warning_label_->hide();
    return;
  }

  if (mode == WalletSendMode::TransparentToConfidential) {
    QString recipient_err;
    auto recipient = parse_confidential_recipient_descriptor(recipient_text, &recipient_err);
    if (!recipient) {
      show_send_inline_warning(recipient_err);
      show_send_inline_status("Review unavailable");
      return;
    }
    std::size_t reserved_excluded = 0;
    std::size_t pending_reserved_excluded = 0;
    std::size_t onboarding_reserved_excluded = 0;
    QString prev_err;
    auto available_prevs =
        send_available_prevs(&reserved_excluded, &pending_reserved_excluded, &onboarding_reserved_excluded, &prev_err);
    if (!available_prevs) {
      show_send_inline_warning(prev_err.isEmpty() ? "No spendable finalized inputs are currently available." : prev_err);
      show_send_inline_status("Review unavailable");
      return;
    }
    const std::uint64_t min_required = *amount_units + finalis::DEFAULT_WALLET_SEND_FEE_UNITS;
    auto selected_prev = select_single_covering_prev(*available_prevs, min_required);
    if (!selected_prev) {
      show_send_inline_warning(
          QString("Transparent -> confidential currently requires one finalized UTXO covering at least %1.")
              .arg(format_coin_amount(min_required)));
      show_send_inline_status("Review unavailable");
      return;
    }
    std::uint64_t applied_fee_units = finalis::DEFAULT_WALLET_SEND_FEE_UNITS;
    const std::uint64_t leftover = selected_prev->second.value - min_required;
    std::optional<TransparentTxOutV2> change_output;
    QString change_text;
    if (leftover == 0) {
      change_text = "No transparent change output.";
    } else if (leftover <= finalis::DEFAULT_WALLET_DUST_THRESHOLD_UNITS) {
      applied_fee_units += leftover;
      change_text = QString("No change output. Dust %1 folded into fee.").arg(format_coin_amount(leftover));
    } else {
      auto own_decoded = finalis::address::decode(wallet_->address);
      if (!own_decoded) {
        show_send_inline_warning("Wallet change address is invalid.");
        show_send_inline_status("Review unavailable");
        return;
      }
      change_output = TransparentTxOutV2{
          leftover,
          finalis::address::p2pkh_script_pubkey(own_decoded->pubkey_hash),
      };
      change_text = QString("%1 transparent change back to %2")
                        .arg(format_coin_amount(leftover))
                        .arg(elide_middle(QString::fromStdString(wallet_->address)));
    }
    send_review_recipient_label_->setText(elide_middle(recipient_text, 18));
    send_review_amount_label_->setText(format_coin_amount(*amount_units));
    send_review_fee_label_->setText(format_coin_amount(applied_fee_units));
    send_review_total_label_->setText(format_coin_amount(selected_prev->second.value));
    send_review_change_label_->setText(change_text);
    send_review_inputs_label_->setText("1");
    QString note =
        "This builds a TxV2 transparent -> confidential transfer. Current wallet support requires a single transparent finalized UTXO.";
    if (reserved_excluded > 0) {
      note += QString("\nReserved finalized inputs excluded from this review: %1.").arg(reserved_excluded);
      const QString reservation_breakdown = send_reservation_note(pending_reserved_excluded, onboarding_reserved_excluded);
      if (!reservation_breakdown.isEmpty()) note += "\n" + reservation_breakdown;
    }
    send_review_note_label_->setText(note);
    show_send_inline_status("Review ready");
    if (send_review_warning_label_) send_review_warning_label_->hide();
    return;
  }

  if (!finalis::address::decode(recipient_text.toStdString()).has_value()) {
    show_send_inline_warning("Recipient address is invalid.");
    show_send_inline_status("Review unavailable");
    return;
  }
  if (confidential_storage_locked_) {
    show_send_inline_warning("Unlock confidential state first. This flow needs locally stored confidential spend secrets.");
    show_send_inline_status("Review unavailable");
    return;
  }
  WalletStore::State state;
  if (!store_.load(&state)) {
    show_send_inline_warning("Unable to load local confidential wallet state.");
    show_send_inline_status("Review unavailable");
    return;
  }
  const auto reserved = pending_wallet_reserved_outpoints();
  const std::uint64_t total_units = *amount_units + finalis::DEFAULT_WALLET_SEND_FEE_UNITS;
  QString selection_err;
  auto coin = select_exact_confidential_coin(state, reserved, total_units, &selection_err);
  if (!coin) {
    show_send_inline_warning(selection_err);
    show_send_inline_status("Review unavailable");
    return;
  }
  send_review_recipient_label_->setText(recipient_text);
  send_review_amount_label_->setText(format_coin_amount(*amount_units));
  send_review_fee_label_->setText(format_coin_amount(finalis::DEFAULT_WALLET_SEND_FEE_UNITS));
  send_review_total_label_->setText(format_coin_amount(total_units));
  send_review_change_label_->setText("No change. Exact confidential coin spend only.");
  send_review_inputs_label_->setText("1");
  send_review_note_label_->setText(
      "This builds a TxV2 confidential -> transparent transfer. Current wallet support only allows exact single-coin full spends.");
  show_send_inline_status("Review ready");
  if (send_review_warning_label_) send_review_warning_label_->hide();
}

void WalletWindow::populate_send_max_amount() {
  if (!ensure_wallet_loaded("Send Max")) return;
  reset_send_review_panel();
  const auto mode = wallet_send_mode_from_combo(send_mode_combo_);
  if (mode == WalletSendMode::ConfidentialToTransparent) {
    if (confidential_storage_locked_) {
      show_send_inline_warning("Unlock confidential state first.");
      show_send_inline_status("Send max unavailable");
      return;
    }
    WalletStore::State state;
    if (!store_.load(&state)) {
      show_send_inline_warning("Unable to load local confidential wallet state.");
      show_send_inline_status("Send max unavailable");
      return;
    }
    const auto reserved = pending_wallet_reserved_outpoints();
    std::uint64_t best_units = 0;
    for (const auto& coin : state.confidential_coins) {
      if (coin.spent || coin.amount <= finalis::DEFAULT_WALLET_SEND_FEE_UNITS) continue;
      auto txid = decode_hex32_string(coin.txid_hex);
      if (!txid) continue;
      const OutPoint op{*txid, coin.vout};
      if (reserved.find(op) != reserved.end()) continue;
      best_units = std::max(best_units, coin.amount - finalis::DEFAULT_WALLET_SEND_FEE_UNITS);
    }
    if (best_units == 0) {
      show_send_inline_warning("No unlocked confidential coin is available for an exact full-spend send.");
      show_send_inline_status("Send max unavailable");
      return;
    }
    send_amount_edit_->setText(format_coin_input_amount(best_units));
    show_send_inline_status(QString("Max confidential spend loaded: %1 after fixed fee %2.")
                                .arg(format_coin_amount(best_units))
                                .arg(format_coin_amount(finalis::DEFAULT_WALLET_SEND_FEE_UNITS)));
    if (!send_address_edit_->text().trimmed().isEmpty()) validate_send_form();
    return;
  }

  std::size_t reserved_excluded = 0;
  std::size_t pending_reserved_excluded = 0;
  std::size_t onboarding_reserved_excluded = 0;
  QString prev_err;
  auto available_prevs =
      send_available_prevs(&reserved_excluded, &pending_reserved_excluded, &onboarding_reserved_excluded, &prev_err);
  if (!available_prevs) {
    show_send_inline_warning(prev_err.isEmpty() ? "No spendable finalized inputs are currently available." : prev_err);
    show_send_inline_status("Send max unavailable");
    return;
  }

  if (mode == WalletSendMode::TransparentToConfidential) {
    std::uint64_t best_units = 0;
    for (const auto& [_, prevout] : *available_prevs) {
      if (prevout.value <= finalis::DEFAULT_WALLET_SEND_FEE_UNITS) continue;
      best_units = std::max(best_units, prevout.value - finalis::DEFAULT_WALLET_SEND_FEE_UNITS);
    }
    if (best_units == 0) {
      show_send_inline_warning("No single finalized transparent UTXO can cover the fixed fee.");
      show_send_inline_status("Send max unavailable");
      return;
    }
    send_amount_edit_->setText(format_coin_input_amount(best_units));
    QString note = QString("Max confidential-send amount loaded from the largest single finalized UTXO: %1 after fixed fee %2.")
                       .arg(format_coin_amount(best_units))
                       .arg(format_coin_amount(finalis::DEFAULT_WALLET_SEND_FEE_UNITS));
    if (reserved_excluded > 0) {
      note += QString("\nReserved finalized inputs excluded: %1.").arg(reserved_excluded);
      const QString reservation_breakdown = send_reservation_note(pending_reserved_excluded, onboarding_reserved_excluded);
      if (!reservation_breakdown.isEmpty()) note += "\n" + reservation_breakdown;
    }
    show_send_inline_status(note);
    if (!send_address_edit_->text().trimmed().isEmpty()) validate_send_form();
    return;
  }

  std::uint64_t total_units = 0;
  for (const auto& [_, prevout] : *available_prevs) total_units += prevout.value;
  if (total_units <= finalis::DEFAULT_WALLET_SEND_FEE_UNITS) {
    show_send_inline_warning("Available finalized balance is too small to cover the fixed fee.");
    show_send_inline_status("Send max unavailable");
    return;
  }

  const std::uint64_t max_send_units = total_units - finalis::DEFAULT_WALLET_SEND_FEE_UNITS;
  send_amount_edit_->setText(format_coin_input_amount(max_send_units));
  QString note = QString("Max spendable amount loaded: %1 after fixed fee %2.")
                     .arg(format_coin_amount(max_send_units))
                     .arg(format_coin_amount(finalis::DEFAULT_WALLET_SEND_FEE_UNITS));
  if (reserved_excluded > 0) {
    note += QString("\nReserved finalized inputs excluded: %1.").arg(reserved_excluded);
    const QString reservation_breakdown = send_reservation_note(pending_reserved_excluded, onboarding_reserved_excluded);
    if (!reservation_breakdown.isEmpty()) note += "\n" + reservation_breakdown;
  }
  show_send_inline_status(note);
  if (!send_address_edit_->text().trimmed().isEmpty()) validate_send_form();
}

void WalletWindow::submit_send() {
  if (!ensure_wallet_loaded("Send")) return;
  reset_send_review_panel();
  if (configured_lightserver_endpoints().isEmpty()) {
    QMessageBox::warning(this, "Send", "Configure at least one lightserver endpoint first.");
    return;
  }

  const auto mode = wallet_send_mode_from_combo(send_mode_combo_);
  const QString destination = send_address_edit_->text().trimmed();
  auto amount_units = parse_coin_amount(send_amount_edit_->text());
  if (!amount_units || *amount_units == 0) {
    show_send_inline_warning("Amount must be positive.");
    show_send_inline_status("Send blocked");
    return;
  }
  std::string err;
  QString used_endpoint;
  std::vector<OutPoint> reserved_inputs;
  QString confirm;
  Bytes tx_bytes;

  if (mode == WalletSendMode::TransparentToTransparent) {
    auto decoded_to = finalis::address::decode(destination.toStdString());
    if (!decoded_to) {
      QMessageBox::warning(this, "Send", "Destination address is invalid.");
      return;
    }
    std::size_t reserved_excluded = 0;
    std::size_t pending_reserved_excluded = 0;
    std::size_t onboarding_reserved_excluded = 0;
    QString prev_err;
    auto available_prevs =
        send_available_prevs(&reserved_excluded, &pending_reserved_excluded, &onboarding_reserved_excluded, &prev_err);
    if (!available_prevs) {
      show_send_inline_warning(prev_err.isEmpty() ? "No spendable finalized inputs are currently available." : prev_err);
      show_send_inline_status("Send blocked");
      return;
    }
    auto key = load_wallet_key(&err);
    if (!key) {
      QMessageBox::warning(this, "Send", QString::fromStdString(err));
      return;
    }
    auto own_decoded = finalis::address::decode(wallet_->address);
    if (!own_decoded) {
      QMessageBox::warning(this, "Send", "Wallet address is invalid.");
      return;
    }
    auto plan = finalis::plan_wallet_p2pkh_send(
        *available_prevs, finalis::address::p2pkh_script_pubkey(decoded_to->pubkey_hash),
        finalis::address::p2pkh_script_pubkey(own_decoded->pubkey_hash), *amount_units,
        finalis::DEFAULT_WALLET_SEND_FEE_UNITS, finalis::DEFAULT_WALLET_DUST_THRESHOLD_UNITS, &err);
    if (!plan) {
      QMessageBox::warning(this, "Send", QString::fromStdString(err));
      return;
    }

    const QString change_text =
        plan->change_units > 0
            ? QString("%1 back to %2")
                  .arg(format_coin_amount(plan->change_units))
                  .arg(elide_middle(QString::fromStdString(wallet_->address)))
            : QString("Folded into fee (dust <= %1 units)").arg(finalis::DEFAULT_WALLET_DUST_THRESHOLD_UNITS);
    send_review_recipient_label_->setText(destination);
    send_review_amount_label_->setText(format_coin_amount(*amount_units));
    send_review_fee_label_->setText(format_coin_amount(plan->applied_fee_units));
    send_review_total_label_->setText(format_coin_amount(*amount_units + plan->applied_fee_units));
    send_review_change_label_->setText(change_text);
    send_review_inputs_label_->setText(QString::number(plan->selected_prevs.size()));
    QString note =
        "The wallet will broadcast through the configured lightserver list. Final settlement is finalized inclusion.";
    if (reserved_excluded > 0) {
      note += QString("\nReserved finalized inputs excluded: %1.").arg(reserved_excluded);
      const QString reservation_breakdown = send_reservation_note(pending_reserved_excluded, onboarding_reserved_excluded);
      if (!reservation_breakdown.isEmpty()) note += "\n" + reservation_breakdown;
    }
    send_review_note_label_->setText(note);
    show_send_inline_status("Ready to confirm");
    if (send_review_warning_label_) send_review_warning_label_->hide();

    confirm = QString("Send to %1\n\nAmount: %2\nFee: %3\nTotal spend: %4\nChange: %5\nInputs selected: %6")
                  .arg(elide_middle(destination))
                  .arg(format_coin_amount(*amount_units))
                  .arg(format_coin_amount(plan->applied_fee_units))
                  .arg(format_coin_amount(*amount_units + plan->applied_fee_units))
                  .arg(change_text)
                  .arg(plan->selected_prevs.size());
    if (reserved_excluded > 0) {
      confirm += QString("\nReserved finalized inputs excluded: %1").arg(reserved_excluded);
      const QString reservation_breakdown = send_reservation_note(pending_reserved_excluded, onboarding_reserved_excluded);
      if (!reservation_breakdown.isEmpty()) confirm += "\n" + reservation_breakdown;
    }
    confirm += "\n\nAccepted for relay by lightserver is not finality.";
    if (QMessageBox::question(this, "Confirm Send", confirm, QMessageBox::Yes | QMessageBox::No, QMessageBox::No) !=
        QMessageBox::Yes) {
      show_send_inline_status("Send cancelled");
      return;
    }

    auto tx = finalis::build_signed_p2pkh_tx_multi_input(
        plan->selected_prevs, finalis::Bytes(key->privkey.begin(), key->privkey.end()), plan->outputs, &err);
    if (!tx) {
      QMessageBox::warning(this, "Send", QString::fromStdString(err));
      return;
    }
    tx_bytes = tx->serialize();
    reserved_inputs.reserve(plan->selected_prevs.size());
    for (const auto& [op, _] : plan->selected_prevs) reserved_inputs.push_back(op);
  } else if (mode == WalletSendMode::TransparentToConfidential) {
    QString recipient_err;
    auto parsed_recipient = parse_confidential_recipient_descriptor(destination, &recipient_err);
    if (!parsed_recipient) {
      QMessageBox::warning(this, "Send", recipient_err);
      return;
    }
    std::size_t reserved_excluded = 0;
    std::size_t pending_reserved_excluded = 0;
    std::size_t onboarding_reserved_excluded = 0;
    QString prev_err;
    auto available_prevs =
        send_available_prevs(&reserved_excluded, &pending_reserved_excluded, &onboarding_reserved_excluded, &prev_err);
    if (!available_prevs) {
      show_send_inline_warning(prev_err.isEmpty() ? "No spendable finalized inputs are currently available." : prev_err);
      show_send_inline_status("Send blocked");
      return;
    }
    auto key = load_wallet_key(&err);
    if (!key) {
      QMessageBox::warning(this, "Send", QString::fromStdString(err));
      return;
    }
    const std::uint64_t base_required = *amount_units + finalis::DEFAULT_WALLET_SEND_FEE_UNITS;
    auto selected_prev = select_single_covering_prev(*available_prevs, base_required);
    if (!selected_prev) {
      QMessageBox::warning(
          this, "Send",
          QString("Transparent -> confidential currently requires one finalized UTXO covering at least %1.")
              .arg(format_coin_amount(base_required)));
      return;
    }
    std::uint64_t applied_fee_units = finalis::DEFAULT_WALLET_SEND_FEE_UNITS;
    std::optional<TransparentTxOutV2> change_output;
    QString change_text = "No transparent change output.";
    const std::uint64_t leftover = selected_prev->second.value - base_required;
    if (leftover > 0) {
      if (leftover <= finalis::DEFAULT_WALLET_DUST_THRESHOLD_UNITS) {
        applied_fee_units += leftover;
        change_text = QString("No change output. Dust %1 folded into fee.").arg(format_coin_amount(leftover));
      } else {
        auto own_decoded = finalis::address::decode(wallet_->address);
        if (!own_decoded) {
          QMessageBox::warning(this, "Send", "Wallet change address is invalid.");
          return;
        }
        change_output = TransparentTxOutV2{
            leftover,
            finalis::address::p2pkh_script_pubkey(own_decoded->pubkey_hash),
        };
        change_text = QString("%1 transparent change back to %2")
                          .arg(format_coin_amount(leftover))
                          .arg(elide_middle(QString::fromStdString(wallet_->address)));
      }
    }
    crypto::ConfidentialOutputSecrets secrets{
        .amount = *amount_units,
        .value_blind = crypto::Blind32{random_hash32()},
    };
    auto recipient = parsed_recipient->recipient;
    if (parsed_recipient->memo_key.has_value()) {
      auto recovery_memo =
          encrypt_confidential_recovery_memo(*amount_units, secrets.value_blind, *parsed_recipient->memo_key,
                                             recipient.ephemeral_pubkey);
      if (!recovery_memo) {
        QMessageBox::warning(this, "Send", "Failed to encrypt confidential recovery memo.");
        return;
      }
      recipient.memo = *recovery_memo;
    }
    auto confidential_out = build_confidential_output(recipient, secrets, random_hash32(), &err);
    if (!confidential_out) {
      QMessageBox::warning(this, "Send", QString::fromStdString(err));
      return;
    }
    auto tx = build_txv2_transparent_to_confidential(
        selected_prev->first, selected_prev->second, Bytes(key->privkey.begin(), key->privkey.end()),
        selected_prev->second.value, change_output, *confidential_out, secrets.value_blind, *amount_units,
        applied_fee_units, &err);
    if (!tx) {
      QMessageBox::warning(this, "Send", QString::fromStdString(err));
      return;
    }
    send_review_recipient_label_->setText(elide_middle(destination, 18));
    send_review_amount_label_->setText(format_coin_amount(*amount_units));
    send_review_fee_label_->setText(format_coin_amount(applied_fee_units));
    send_review_total_label_->setText(format_coin_amount(selected_prev->second.value));
    send_review_change_label_->setText(change_text);
    send_review_inputs_label_->setText("1");
    send_review_note_label_->setText(
        "The wallet will broadcast a TxV2 transparent -> confidential transfer through the configured lightserver list.");
    show_send_inline_status("Ready to confirm");
    if (send_review_warning_label_) send_review_warning_label_->hide();
    confirm = QString("Send confidential TxV2\n\nDescriptor: %1\nAmount: %2\nFee: %3\nTotal spend: %4\nChange: %5\nInputs selected: 1")
                  .arg(elide_middle(destination, 18))
                  .arg(format_coin_amount(*amount_units))
                  .arg(format_coin_amount(applied_fee_units))
                  .arg(format_coin_amount(selected_prev->second.value))
                  .arg(change_text);
    if (QMessageBox::question(this, "Confirm Send", confirm, QMessageBox::Yes | QMessageBox::No, QMessageBox::No) !=
        QMessageBox::Yes) {
      show_send_inline_status("Send cancelled");
      return;
    }
    tx_bytes = tx->serialize();
    reserved_inputs.push_back(selected_prev->first);
  } else {
    auto decoded_to = finalis::address::decode(destination.toStdString());
    if (!decoded_to) {
      QMessageBox::warning(this, "Send", "Destination address is invalid.");
      return;
    }
    if (confidential_storage_locked_) {
      QMessageBox::warning(this, "Send", "Unlock confidential state first.");
      return;
    }
    WalletStore::State state;
    if (!store_.load(&state)) {
      QMessageBox::warning(this, "Send", "Unable to load local confidential wallet state.");
      return;
    }
    const auto reserved = pending_wallet_reserved_outpoints();
    const std::uint64_t total_units = *amount_units + finalis::DEFAULT_WALLET_SEND_FEE_UNITS;
    QString selection_err;
    auto coin = select_exact_confidential_coin(state, reserved, total_units, &selection_err);
    if (!coin) {
      QMessageBox::warning(this, "Send", selection_err);
      return;
    }
    auto tx = build_txv2_confidential_to_transparent(
        *coin,
        TransparentTxOutV2{
            *amount_units,
            finalis::address::p2pkh_script_pubkey(decoded_to->pubkey_hash),
        },
        finalis::DEFAULT_WALLET_SEND_FEE_UNITS, random_hash32(), random_hash32(), &err);
    if (!tx) {
      QMessageBox::warning(this, "Send", QString::fromStdString(err));
      return;
    }
    send_review_recipient_label_->setText(destination);
    send_review_amount_label_->setText(format_coin_amount(*amount_units));
    send_review_fee_label_->setText(format_coin_amount(finalis::DEFAULT_WALLET_SEND_FEE_UNITS));
    send_review_total_label_->setText(format_coin_amount(total_units));
    send_review_change_label_->setText("No change. Exact confidential coin spend only.");
    send_review_inputs_label_->setText("1");
    send_review_note_label_->setText(
        "The wallet will broadcast a TxV2 confidential -> transparent transfer. Current support is exact single-coin full-spend only.");
    show_send_inline_status("Ready to confirm");
    if (send_review_warning_label_) send_review_warning_label_->hide();
    confirm = QString("Send confidential spend TxV2\n\nTo: %1\nAmount: %2\nFee: %3\nTotal spend: %4\nChange: none\nInputs selected: 1")
                  .arg(elide_middle(destination))
                  .arg(format_coin_amount(*amount_units))
                  .arg(format_coin_amount(finalis::DEFAULT_WALLET_SEND_FEE_UNITS))
                  .arg(format_coin_amount(total_units));
    if (QMessageBox::question(this, "Confirm Send", confirm, QMessageBox::Yes | QMessageBox::No, QMessageBox::No) !=
        QMessageBox::Yes) {
      show_send_inline_status("Send cancelled");
      return;
    }
    tx_bytes = tx->serialize();
    reserved_inputs.push_back(coin->outpoint);
  }

  auto result = broadcast_tx_with_failover(tx_bytes, &err, &used_endpoint);
  if (!result) {
    QMessageBox::warning(this, "Send", QString::fromStdString(err));
    return;
  }
  if (result->outcome != lightserver::BroadcastOutcome::Sent) {
    if (result->error_code == "mempool_full_not_good_enough") {
      QString detail = "Network is busy. Your transaction was not accepted because its fee rate is too low for current mempool pressure. Try again later.";
      if (result->min_fee_rate_to_enter_when_full.has_value()) {
        detail += QString("\n\nCurrent minimum fee rate to enter: %1 milliunits/byte.")
                      .arg(QString::number(*result->min_fee_rate_to_enter_when_full));
      }
      QMessageBox::warning(this, "Send", detail);
    } else if (result->error_code == "relay_unavailable") {
      QMessageBox::warning(this, "Send", "Unable to reach the relay service. Try again shortly.");
    } else if (result->error == "missing utxo" || result->error_code == "tx_missing_or_unconfirmed_input") {
      QString refresh_err;
      (void)refresh_finalized_send_state(&refresh_err);
      QMessageBox::warning(
          this, "Send",
          "Broadcast rejected: missing utxo.\n\nThe finalized spendable set changed before broadcast. The wallet refreshed its finalized state. Review and send again.");
    } else if (result->error_code == "tx_duplicate" || result->error_code == "tx_conflict_in_mempool") {
      QMessageBox::warning(
          this, "Send",
          "This transaction was already submitted or conflicts with another pending spend.");
    } else {
      const std::string reason = !result->error_message.empty() ? result->error_message : result->error;
      QMessageBox::warning(this, "Send", QString("Broadcast rejected: %1").arg(QString::fromStdString(reason)));
    }
    return;
  }

  local_sent_txids_.push_back(result->txid_hex);
  pending_wallet_spends_[result->txid_hex] = reserved_inputs;
  mark_refresh_state_changed();
  (void)store_.add_sent_txid(result->txid_hex);
  (void)store_.upsert_pending_spend(result->txid_hex, reserved_inputs, tip_height_,
                                    static_cast<std::uint64_t>(QDateTime::currentMSecsSinceEpoch()));
  save_wallet_local_state();
  append_local_event(QString("[pending] sent %1 -> %2 (%3)")
                         .arg(format_coin_amount(*amount_units))
                         .arg(elide_middle(destination))
                         .arg(elide_middle(QString::fromStdString(result->txid_hex), 12)));
  refresh_chain_state(false);
  const QString endpoint_note = used_endpoint.isEmpty() ? QString{} : QString(" via %1").arg(display_lightserver_endpoint(used_endpoint));
  show_send_inline_status(QString("Accepted for relay%1. Inputs stay reserved locally until finalized inclusion.")
                              .arg(endpoint_note));
  statusBar()->showMessage(QString("Transaction accepted for relay%1.").arg(endpoint_note), 3000);
}

void WalletWindow::show_selected_history_detail() {
  update_selected_history_detail();
  if (activity_detail_view_) activity_detail_view_->setFocus();
}

void WalletWindow::show_selected_mint_detail() {
  QTableWidget* table = nullptr;
  if (mint_deposits_view_->hasFocus()) table = mint_deposits_view_;
  if (!table && mint_notes_view_->hasFocus()) table = mint_notes_view_;
  if (!table && mint_redemptions_view_->hasFocus()) table = mint_redemptions_view_;
  if (!table && mint_redemptions_view_->currentRow() >= 0) table = mint_redemptions_view_;
  if (!table && mint_deposits_view_->currentRow() >= 0) table = mint_deposits_view_;
  if (!table && mint_notes_view_->currentRow() >= 0) table = mint_notes_view_;
  if (!table) {
    QMessageBox::information(this, "Mint Details", "Select a mint row first.");
    return;
  }
  const int row = table->currentRow();
  auto* item = row >= 0 ? table->item(row, 0) : nullptr;
  if (!item) {
    QMessageBox::information(this, "Mint Details", "Select a mint row first.");
    return;
  }
  const int index = item->data(Qt::UserRole).toInt();
  if (index < 0 || static_cast<std::size_t>(index) >= mint_records_.size()) {
    QMessageBox::information(this, "Mint Details", "The selected row does not have mint details.");
    return;
  }
  const auto& rec = mint_records_[static_cast<std::size_t>(index)];
  QMessageBox::information(
      this, "Mint Details",
      QString("Status: %1\nKind: %2\nReference: %3\nAmount: %4\n\n%5")
          .arg(rec.status,
               rec.kind,
               rec.reference.isEmpty() ? "-" : elide_middle(rec.reference, 12),
               rec.amount.isEmpty() ? "-" : rec.amount,
               rec.details));
}

void WalletWindow::update_selected_history_detail() {
  if (!activity_detail_title_label_ || !activity_detail_view_) return;
  const int row = history_view_ ? history_view_->currentRow() : -1;
  if (row < 0 || row >= static_cast<int>(history_row_refs_.size())) {
    activity_detail_title_label_->setText("No record selected");
    activity_detail_view_->setPlainText("Choose an activity row to inspect the current details.");
    return;
  }
  const auto ref = history_row_refs_[static_cast<std::size_t>(row)];
  if (ref.index < 0) {
    QString detail = "The selected row is only a cached summary and does not contain full wallet activity details yet.";
    if (wallet_view_snapshot_.has_value() && row < static_cast<int>(wallet_view_snapshot_->history_rows.size())) {
      const auto& cached = wallet_view_snapshot_->history_rows[static_cast<std::size_t>(row)];
      activity_detail_title_label_->setText(QString("%1 · Cached Summary")
                                                .arg(QString::fromStdString(cached.col1).isEmpty()
                                                         ? "Cached"
                                                         : QString::fromStdString(cached.col1)));
      activity_detail_view_->setPlainText(
          QString("Category: %1\nStatus: %2\nAmount: %3\nReference: %4\nState: %5\n\nCached view summary loaded from local wallet state. Full row detail will refresh after background sync.")
              .arg(QString::fromStdString(cached.col0),
                   QString::fromStdString(cached.col1),
                   QString::fromStdString(cached.col2),
                   QString::fromStdString(cached.col3),
                   QString::fromStdString(cached.col4)));
      return;
    }
    activity_detail_title_label_->setText("No inspectable details");
    activity_detail_view_->setPlainText(detail);
    return;
  }
  if (ref.source == HistoryRowRef::Source::Chain) {
    if (static_cast<std::size_t>(ref.index) >= chain_records_.size()) return;
    const auto& rec = chain_records_[static_cast<std::size_t>(ref.index)];
    activity_detail_title_label_->setText(QString("%1 · %2").arg(title_case_status(rec.status), display_chain_kind(rec.kind)));
    activity_detail_view_->setPlainText(
        QString("Status: %1\nCategory: %2\nAmount/Detail: %3\nReference: %4\nState/Height: %5\nTransaction: %6\n\n%7")
            .arg(title_case_status(rec.status),
                 display_chain_kind(rec.kind),
                 rec.amount.isEmpty() ? "-" : rec.amount,
                 rec.reference.isEmpty() ? "-" : rec.reference,
                 rec.height.isEmpty() ? "-" : rec.height,
                 rec.txid,
                 rec.details));
    return;
  }
  if (ref.source == HistoryRowRef::Source::Local) {
    if (static_cast<std::size_t>(ref.index) >= local_history_lines_.size()) return;
    const auto& line = local_history_lines_[static_cast<std::size_t>(ref.index)];
    activity_detail_title_label_->setText(QString("%1 · %2")
                                              .arg(title_case_status(local_history_status(line)),
                                                   local_history_kind(line)));
    activity_detail_view_->setPlainText(
        QString("Status: %1\nCategory: %2\nReference: %3\nState: %4\n\n%5")
            .arg(title_case_status(local_history_status(line)),
                 local_history_kind(line),
                 local_history_reference(line).isEmpty() ? "-" : local_history_reference(line),
                 local_history_state(line),
                 line));
    return;
  }
  if (ref.source == HistoryRowRef::Source::Confidential) {
    if (static_cast<std::size_t>(ref.index) >= confidential_coin_views_.size()) return;
    const auto& coin = confidential_coin_views_[static_cast<std::size_t>(ref.index)];
    const auto reservation_it = pending_confidential_reservations_.find(coin.outpoint);
    const bool reserved = reservation_it != pending_confidential_reservations_.end();
    const std::uint64_t now_ms = static_cast<std::uint64_t>(QDateTime::currentMSecsSinceEpoch());
    const QString reservation_text =
        reserved ? pending_release_state_text(reservation_it->second, tip_height_, now_ms) : "No active reservation";
    activity_detail_title_label_->setText(
        QString("%1 · Confidential Coin").arg(coin.spent ? "Spent" : (reserved ? "Reserved" : "Finalized")));
    activity_detail_view_->setPlainText(
        QString("Status: %1\nCategory: Confidential Coin\nAmount: %2\nOutpoint: %3:%4\nAccount: %5\nOne-time key: %6\nReservation: %7")
            .arg(coin.spent ? "Spent" : (reserved ? "Reserved" : "Unspent"),
                 format_coin_amount(coin.amount),
                 coin.txid_hex,
                 QString::number(coin.vout),
                 coin.account_id.isEmpty() ? "-" : coin.account_id,
                 coin.one_time_pubkey_hex,
                 reservation_text));
    return;
  }
  if (static_cast<std::size_t>(ref.index) >= mint_records_.size()) return;
  const auto& rec = mint_records_[static_cast<std::size_t>(ref.index)];
  activity_detail_title_label_->setText(QString("%1 · %2").arg(title_case_status(rec.status), display_mint_kind(rec.kind)));
  activity_detail_view_->setPlainText(
      QString("Status: %1\nCategory: %2\nReference: %3\nAmount: %4\n\n%5")
          .arg(title_case_status(rec.status),
               display_mint_kind(rec.kind),
               rec.reference.isEmpty() ? "-" : rec.reference,
               rec.amount.isEmpty() ? "-" : rec.amount,
               rec.details));
}

void WalletWindow::refresh_history_table() {
  history_view_->setRowCount(0);
  history_row_refs_.clear();
  const QString filter = history_filter_combo_ ? history_filter_combo_->currentText() : "All";
  history_view_->setSortingEnabled(false);
  if (chain_records_.empty() && local_history_lines_.empty() && mint_records_.empty() && confidential_coin_views_.empty() &&
      wallet_view_snapshot_.has_value()) {
    const auto& snapshot = *wallet_view_snapshot_;
    if (activity_finalized_count_label_) activity_finalized_count_label_->setText(QString::fromStdString(snapshot.activity_finalized_count_text));
    if (activity_pending_count_label_) activity_pending_count_label_->setText(QString::fromStdString(snapshot.activity_pending_count_text));
    if (activity_local_count_label_) activity_local_count_label_->setText(QString::fromStdString(snapshot.activity_local_count_text));
    if (activity_mint_count_label_) activity_mint_count_label_->setText(QString::fromStdString(snapshot.activity_mint_count_text));
    if (activity_confidential_count_label_) activity_confidential_count_label_->setText(QString::fromStdString(snapshot.activity_confidential_count_text));
    for (const auto& row : snapshot.history_rows) {
      if (filter == "Pending" && QString::fromStdString(row.col1).trimmed().toUpper() != "PENDING") continue;
      const int r = history_view_->rowCount();
      history_view_->insertRow(r);
      auto* status_item = new QTableWidgetItem(QString::fromStdString(row.col1));
      apply_status_item_style(status_item);
      history_view_->setItem(r, 0, new QTableWidgetItem(QString::fromStdString(row.col0)));
      history_view_->setItem(r, 1, status_item);
      history_view_->setItem(r, 2, new QTableWidgetItem(QString::fromStdString(row.col2)));
      history_view_->setItem(r, 3, new QTableWidgetItem(QString::fromStdString(row.col3)));
      history_view_->setItem(r, 4, new QTableWidgetItem(QString::fromStdString(row.col4)));
      history_row_refs_.push_back(HistoryRowRef{HistoryRowRef::Source::Local, -1});
    }
    if (history_row_refs_.empty()) {
      history_view_->insertRow(0);
      history_view_->setItem(0, 0, new QTableWidgetItem("No history cached"));
      history_row_refs_.push_back(HistoryRowRef{HistoryRowRef::Source::Local, -1});
    }
    history_view_->setSortingEnabled(true);
    update_selected_history_detail();
    return;
  }
  int finalized_count = 0;
  int pending_count = 0;
  int local_count = 0;
  int mint_count = 0;
  int confidential_count = 0;
  struct HistoryDisplayRow {
    QString type;
    QString status;
    QString amount;
    QString reference;
    QString height_or_state;
    HistoryRowRef::Source source{HistoryRowRef::Source::Chain};
    int index{-1};
    int bucket{0};
    qulonglong numeric_height{0};
    bool numeric_height_ok{false};
    int insertion_order{0};
  };
  std::vector<HistoryDisplayRow> rows;
  auto push_row = [&](const QString& type, const QString& status, const QString& amount,
                      const QString& reference, const QString& height_or_state,
                      HistoryRowRef::Source source, int index, int bucket) {
    if (filter == "On-Chain" && source != HistoryRowRef::Source::Chain) return;
    if (filter == "Local" && source != HistoryRowRef::Source::Local) return;
    if (filter == "Mint" && source != HistoryRowRef::Source::Mint) return;
    if (filter == "Confidential" && source != HistoryRowRef::Source::Confidential) return;
    if (filter == "Pending" && status.trimmed().toUpper() != "PENDING") return;
    if (status.trimmed().toUpper() == "FINALIZED") ++finalized_count;
    if (status.trimmed().toUpper() == "PENDING") ++pending_count;
    if (source == HistoryRowRef::Source::Local) ++local_count;
    if (source == HistoryRowRef::Source::Mint) ++mint_count;
    if (source == HistoryRowRef::Source::Confidential) ++confidential_count;
    bool height_ok = false;
    const qulonglong numeric_height = height_or_state.toULongLong(&height_ok);
    rows.push_back(HistoryDisplayRow{
        type,
        status,
        amount,
        reference,
        height_or_state,
        source,
        index,
        bucket,
        numeric_height,
        height_ok,
        static_cast<int>(rows.size()),
    });
  };
  for (std::size_t i = 0; i < chain_records_.size(); ++i) {
    const auto& rec = chain_records_[i];
    const QString upper = rec.status.trimmed().toUpper();
    const int bucket = upper == "PENDING" ? 1 : (upper == "FINALIZED" ? 3 : 4);
    push_row(display_chain_kind(rec.kind), rec.status, rec.amount, elide_middle(rec.reference, 10), rec.height,
             HistoryRowRef::Source::Chain, static_cast<int>(i), bucket);
  }
  for (std::size_t i = 0; i < local_history_lines_.size(); ++i) {
    const auto& line = local_history_lines_[i];
    const QString status = local_history_status(line);
    const QString upper = status.trimmed().toUpper();
    const int bucket = upper == "PENDING" ? 0 : (upper == "FINALIZED" ? 2 : 4);
    push_row(local_history_kind(line), status, "-",
             elide_middle(local_history_reference(line), 10),
             local_history_state(line),
             HistoryRowRef::Source::Local, static_cast<int>(i), bucket);
  }
  for (std::size_t i = 0; i < mint_records_.size(); ++i) {
    const auto& rec = mint_records_[i];
    const QString upper = rec.status.trimmed().toUpper();
    const int bucket = upper == "PENDING" ? 5 : 6;
    push_row(display_mint_kind(rec.kind), rec.status, rec.amount.isEmpty() ? "-" : rec.amount,
             elide_middle(rec.reference, 10), rec.height_or_state.isEmpty() ? "-" : rec.height_or_state,
             HistoryRowRef::Source::Mint, static_cast<int>(i), bucket);
  }
  for (std::size_t i = 0; i < confidential_coin_views_.size(); ++i) {
    const auto& rec = confidential_coin_views_[i];
    const bool reserved = pending_confidential_reservations_.find(rec.outpoint) != pending_confidential_reservations_.end();
    push_row("Confidential Coin", rec.spent ? "FINALIZED" : (reserved ? "PENDING" : "FINALIZED"), format_coin_amount(rec.amount),
             QString("%1:%2").arg(elide_middle(rec.txid_hex, 10)).arg(rec.vout),
             rec.spent ? "spent" : (reserved ? "reserved" : "unspent"),
             HistoryRowRef::Source::Confidential, static_cast<int>(i), rec.spent ? 4 : (reserved ? 1 : 3));
  }
  std::stable_sort(rows.begin(), rows.end(), [](const HistoryDisplayRow& a, const HistoryDisplayRow& b) {
    if (a.bucket != b.bucket) return a.bucket < b.bucket;
    if (a.numeric_height_ok != b.numeric_height_ok) return a.numeric_height_ok > b.numeric_height_ok;
    if (a.numeric_height_ok && b.numeric_height_ok && a.numeric_height != b.numeric_height) return a.numeric_height > b.numeric_height;
    if (a.source == HistoryRowRef::Source::Local && b.source == HistoryRowRef::Source::Local) return a.index > b.index;
    return a.insertion_order < b.insertion_order;
  });
  for (const auto& row_data : rows) {
    const int row = history_view_->rowCount();
    history_view_->insertRow(row);
    const QString source_suffix =
        row_data.source == HistoryRowRef::Source::Local ? " (local)"
        : (row_data.source == HistoryRowRef::Source::Mint ? " (mint)" : QString{});
    history_view_->setItem(row, 0, new QTableWidgetItem(row_data.type + source_suffix));
    const bool local_pending = row_data.status.trimmed().toUpper() == "PENDING" &&
                               (row_data.source == HistoryRowRef::Source::Chain || row_data.source == HistoryRowRef::Source::Local);
    auto* status_item = new QTableWidgetItem(local_pending ? "Pending (local)" : title_case_status(row_data.status));
    apply_status_item_style(status_item);
    history_view_->setItem(row, 1, status_item);
    auto* amount_item = new QTableWidgetItem(row_data.amount);
    if (row_data.source == HistoryRowRef::Source::Chain) {
      apply_amount_item_style(amount_item, row_data.type, status_item->text());
    }
    history_view_->setItem(row, 2, amount_item);
    history_view_->setItem(row, 3, new QTableWidgetItem(row_data.reference));
    history_view_->setItem(row, 4, new QTableWidgetItem(row_data.height_or_state));
    history_row_refs_.push_back(HistoryRowRef{row_data.source, row_data.index});
  }
  if (history_view_->rowCount() == 0) {
    history_view_->insertRow(0);
    QString message = "No history recorded yet";
    if (filter == "On-Chain") message = "No on-chain records yet";
    else if (filter == "Local") message = "No local activity records yet";
    else if (filter == "Mint") message = "No mint records yet";
    else if (filter == "Confidential") message = "No confidential coin records yet";
    else if (filter == "Pending") message = "No pending records";
    auto* item = new QTableWidgetItem(message);
    item->setData(Qt::UserRole, -1);
    history_view_->setItem(0, 0, item);
    history_row_refs_.push_back(HistoryRowRef{HistoryRowRef::Source::Chain, -1});
  }
  history_detail_button_->setEnabled(!history_row_refs_.empty() &&
                                     !(history_row_refs_.size() == 1 && history_row_refs_[0].index < 0));
  if (activity_finalized_count_label_) activity_finalized_count_label_->setText(QString("Finalized: %1").arg(finalized_count));
  if (activity_pending_count_label_) activity_pending_count_label_->setText(QString("Pending: %1").arg(pending_count));
  if (activity_local_count_label_) activity_local_count_label_->setText(QString("Local: %1").arg(local_count));
  if (activity_mint_count_label_) activity_mint_count_label_->setText(QString("Mint: %1").arg(mint_count));
  if (activity_confidential_count_label_) {
    activity_confidential_count_label_->setText(QString("Confidential: %1").arg(confidential_count));
  }
  update_selected_history_detail();
}

void WalletWindow::persist_wallet_view_snapshot() {
  if (!wallet_ || !history_view_ || !overview_page_) return;
  WalletStore::WalletViewSnapshot snapshot;
  snapshot.balance_text = balance_label_ ? balance_label_->text().toStdString() : "";
  snapshot.pending_balance_text = pending_balance_label_ ? pending_balance_label_->text().toStdString() : "";
  snapshot.confidential_balance_text = confidential_balance_label_ ? confidential_balance_label_->text().toStdString() : "";
  snapshot.confidential_request_summary_text =
      receive_confidential_request_summary_label_ ? receive_confidential_request_summary_label_->text().toStdString() : "";
  snapshot.confidential_coin_summary_text =
      receive_confidential_coin_summary_label_ ? receive_confidential_coin_summary_label_->text().toStdString() : "";
  snapshot.activity_finalized_count_text =
      activity_finalized_count_label_ ? activity_finalized_count_label_->text().toStdString() : "";
  snapshot.activity_pending_count_text =
      activity_pending_count_label_ ? activity_pending_count_label_->text().toStdString() : "";
  snapshot.activity_local_count_text =
      activity_local_count_label_ ? activity_local_count_label_->text().toStdString() : "";
  snapshot.activity_mint_count_text =
      activity_mint_count_label_ ? activity_mint_count_label_->text().toStdString() : "";
  snapshot.activity_confidential_count_text =
      activity_confidential_count_label_ ? activity_confidential_count_label_->text().toStdString() : "";
  if (auto* preview = overview_page_->activity_preview_table()) {
    for (int row = 0; row < preview->rowCount(); ++row) {
      snapshot.overview_activity_rows.push_back(WalletStore::ViewSnapshotRow{
          .col0 = preview->item(row, 0) ? preview->item(row, 0)->text().toStdString() : "",
          .col1 = preview->item(row, 1) ? preview->item(row, 1)->text().toStdString() : "",
          .col2 = preview->item(row, 2) ? preview->item(row, 2)->text().toStdString() : "",
      });
    }
  }
  for (int row = 0; row < history_view_->rowCount(); ++row) {
    snapshot.history_rows.push_back(WalletStore::ViewSnapshotRow{
        .col0 = history_view_->item(row, 0) ? history_view_->item(row, 0)->text().toStdString() : "",
        .col1 = history_view_->item(row, 1) ? history_view_->item(row, 1)->text().toStdString() : "",
        .col2 = history_view_->item(row, 2) ? history_view_->item(row, 2)->text().toStdString() : "",
        .col3 = history_view_->item(row, 3) ? history_view_->item(row, 3)->text().toStdString() : "",
        .col4 = history_view_->item(row, 4) ? history_view_->item(row, 4)->text().toStdString() : "",
    });
  }
  wallet_view_snapshot_ = snapshot;
  (void)store_.set_wallet_view_snapshot(snapshot);
}

void WalletWindow::submit_mint_deposit() {
  if (!ensure_wallet_loaded("Mint Deposit")) return;
  const QString mint_url = mint_url_edit_->text().trimmed();
  const QString mint_id_hex = mint_id_edit_->text().trimmed();
  if (configured_lightserver_endpoints().isEmpty() || mint_url.isEmpty() || mint_id_hex.isEmpty()) {
    QMessageBox::warning(this, "Mint Deposit", "Configure lightserver endpoints, mint URL, and mint ID first.");
    return;
  }
  auto mint_id = decode_hex32_string(mint_id_hex.toStdString());
  if (!mint_id) {
    QMessageBox::warning(this, "Mint Deposit", "Mint ID must be 32-byte hex.");
    return;
  }
  auto amount_units = parse_coin_amount(mint_deposit_amount_edit_->text());
  if (!amount_units || *amount_units == 0) {
    QMessageBox::warning(this, "Mint Deposit", "Enter a valid deposit amount.");
    return;
  }

  if (utxos_.empty()) refresh_chain_state(false);
  std::vector<std::pair<OutPoint, TxOut>> prevs;
  std::uint64_t selected = 0;
  for (const auto& utxo : utxos_) {
    auto txid = decode_hex32_string(utxo.txid_hex);
    if (!txid) continue;
    prevs.push_back({OutPoint{*txid, utxo.vout}, TxOut{utxo.value, utxo.script_pubkey}});
    selected += utxo.value;
    if (selected >= *amount_units) break;
  }
  if (selected < *amount_units) {
    QMessageBox::warning(this, "Mint Deposit", "Insufficient finalized UTXOs.");
    return;
  }

  std::string err;
  auto key = load_wallet_key(&err);
  if (!key) {
    QMessageBox::warning(this, "Mint Deposit", QString::fromStdString(err));
    return;
  }
  auto own_decoded = finalis::address::decode(wallet_->address);
  if (!own_decoded) {
    QMessageBox::warning(this, "Mint Deposit", "Wallet address is invalid.");
    return;
  }
  std::vector<TxOut> outputs;
  outputs.push_back(TxOut{
      *amount_units, finalis::privacy::mint_deposit_script_pubkey(*mint_id, own_decoded->pubkey_hash)});
  const std::uint64_t change = selected - *amount_units;
  if (change > 0) outputs.push_back(TxOut{change, finalis::address::p2pkh_script_pubkey(own_decoded->pubkey_hash)});

  auto tx = finalis::build_signed_p2pkh_tx_multi_input(
      prevs, finalis::Bytes(key->privkey.begin(), key->privkey.end()), outputs, &err);
  if (!tx) {
    QMessageBox::warning(this, "Mint Deposit", QString::fromStdString(err));
    return;
  }
  QString used_endpoint;
  auto broadcast = broadcast_tx_with_failover(tx->serialize(), &err, &used_endpoint);
  if (!broadcast || broadcast->outcome != lightserver::BroadcastOutcome::Sent) {
    const QString reason = broadcast ? QString::fromStdString(broadcast->error) : QString::fromStdString(err);
    QMessageBox::warning(this, "Mint Deposit", "Broadcast failed: " + reason);
    return;
  }

  finalis::privacy::MintDepositRegistrationRequest req;
  req.chain = "mainnet";
  req.deposit_txid = tx->txid();
  req.deposit_vout = 0;
  req.mint_id = *mint_id;
  req.recipient_pubkey_hash = own_decoded->pubkey_hash;
  req.amount = *amount_units;
  auto reg_body = lightserver::http_post_json_raw(mint_endpoint(mint_url, "/deposits/register").toStdString(),
                                                  finalis::privacy::to_json(req), &err);
  if (!reg_body) {
    QMessageBox::warning(this, "Mint Deposit", "Mint registration failed: " + QString::fromStdString(err));
    return;
  }
  auto reg = finalis::privacy::parse_mint_deposit_registration_response(*reg_body);
  if (!reg || !reg->accepted) {
    QMessageBox::warning(this, "Mint Deposit", "Mint registration was rejected.");
    return;
  }

  mint_deposit_ref_ = QString::fromStdString(reg->mint_deposit_ref);
  mint_last_deposit_txid_ = QString::fromStdString(hex_encode32(tx->txid()));
  mint_last_deposit_vout_ = 0;
  save_wallet_local_state();
  render_mint_state();
  append_local_event(QString("[mint-deposit] %1 %2 ref=%3")
                         .arg(format_coin_amount(*amount_units))
                         .arg(elide_middle(mint_last_deposit_txid_, 12))
                         .arg(mint_deposit_ref_));
  refresh_chain_state(false);
  const QString endpoint_note = used_endpoint.isEmpty() ? QString{} : QString(" via %1").arg(display_lightserver_endpoint(used_endpoint));
  statusBar()->showMessage(QString("Mint deposit accepted for relay and registered%1.").arg(endpoint_note), 3000);
}

void WalletWindow::issue_mint_note() {
  if (!ensure_wallet_loaded("Issue Note")) return;
  const QString mint_url = mint_url_edit_->text().trimmed();
  if (mint_url.isEmpty() || mint_deposit_ref_.isEmpty()) {
    QMessageBox::warning(this, "Issue Note", "Create and register a mint deposit first.");
    return;
  }
  auto amount_units = parse_coin_amount(mint_issue_amount_edit_->text());
  if (!amount_units || *amount_units == 0) {
    QMessageBox::warning(this, "Issue Note", "Enter a valid issue amount.");
    return;
  }
  const auto denominations = split_into_denominations(*amount_units);
  if (denominations.empty()) {
    QMessageBox::warning(this, "Issue Note", "Failed to derive note denominations.");
    return;
  }

  finalis::privacy::MintBlindIssueRequest req;
  req.mint_deposit_ref = mint_deposit_ref_.toStdString();
  for (const auto denom : denominations) {
    req.blinded_messages.push_back(random_hex_string(64).toStdString());
    req.note_amounts.push_back(denom);
  }

  std::string err;
  auto body = lightserver::http_post_json_raw(mint_endpoint(mint_url, "/issuance/blind").toStdString(),
                                              finalis::privacy::to_json(req), &err);
  if (!body) {
    QMessageBox::warning(this, "Issue Note", "Mint issuance failed: " + QString::fromStdString(err));
    return;
  }
  auto resp = finalis::privacy::parse_mint_blind_issue_response(*body);
  if (!resp || resp->note_refs.empty()) {
    QMessageBox::warning(this, "Issue Note", "Mint issuance response was invalid.");
    return;
  }

  for (std::size_t i = 0; i < resp->note_refs.size(); ++i) {
    const std::uint64_t amount = i < resp->note_amounts.size() ? resp->note_amounts[i] : *amount_units;
    mint_notes_.push_back(MintNote{QString::fromStdString(resp->note_refs[i]), amount});
    (void)store_.upsert_mint_note(resp->note_refs[i], amount, true);
  }
  save_wallet_local_state();
  render_mint_state();
  append_local_event(QString("[mint-issue] issuance=%1 amount=%2 notes=%3")
                         .arg(QString::fromStdString(resp->issuance_id))
                         .arg(format_coin_amount(*amount_units))
                         .arg(resp->note_refs.size()));
  statusBar()->showMessage("Mint note issued.", 3000);
}

void WalletWindow::submit_mint_redemption() {
  if (!ensure_wallet_loaded("Redeem")) return;
  const QString mint_url = mint_url_edit_->text().trimmed();
  if (mint_url.isEmpty()) {
    QMessageBox::warning(this, "Redeem", "Configure a mint URL first.");
    return;
  }
  const QString redeem_address = mint_redeem_address_edit_->text().trimmed();
  if (!finalis::address::decode(redeem_address.toStdString()).has_value()) {
    QMessageBox::warning(this, "Redeem", "Destination address is invalid.");
    return;
  }
  auto amount_units = parse_coin_amount(mint_redeem_amount_edit_->text());
  if (!amount_units || *amount_units == 0) {
    QMessageBox::warning(this, "Redeem", "Enter a valid redemption amount.");
    return;
  }

  auto selected_indexes = choose_note_subset_exact(mint_notes_, *amount_units);
  if (!selected_indexes) {
    QMessageBox::warning(this, "Redeem", "No exact note combination matches that redemption amount.");
    return;
  }
  std::vector<std::string> selected_notes;
  for (auto idx : *selected_indexes) selected_notes.push_back(mint_notes_[idx].note_ref.toStdString());

  finalis::privacy::MintRedemptionRequest req;
  req.notes = selected_notes;
  req.redeem_address = redeem_address.toStdString();
  req.amount = *amount_units;
  std::string err;
  auto body = lightserver::http_post_json_raw(mint_endpoint(mint_url, "/redemptions/create").toStdString(),
                                              finalis::privacy::to_json(req), &err);
  if (!body) {
    QMessageBox::warning(this, "Redeem", "Mint redemption failed: " + QString::fromStdString(err));
    return;
  }
  auto resp = finalis::privacy::parse_mint_redemption_response(*body);
  if (!resp || !resp->accepted) {
    QMessageBox::warning(this, "Redeem", "Mint redemption was rejected.");
    return;
  }

  mint_last_redemption_batch_id_ = QString::fromStdString(resp->redemption_batch_id);
  for (const auto& note_ref : selected_notes) {
    auto it = std::find_if(mint_notes_.begin(), mint_notes_.end(),
                           [&](const MintNote& note) { return note.note_ref.toStdString() == note_ref; });
    if (it != mint_notes_.end()) (void)store_.upsert_mint_note(note_ref, it->amount, false);
    mint_notes_.erase(std::remove_if(mint_notes_.begin(), mint_notes_.end(),
                                     [&](const MintNote& note) { return note.note_ref.toStdString() == note_ref; }),
                      mint_notes_.end());
  }
  save_wallet_local_state();
  render_mint_state();
  append_local_event(QString("[mint-redeem] batch=%1 amount=%2 notes=%3")
                         .arg(mint_last_redemption_batch_id_)
                         .arg(format_coin_amount(*amount_units))
                         .arg(selected_notes.size()));
  statusBar()->showMessage("Mint redemption created.", 3000);
}

void WalletWindow::refresh_mint_redemption_status() {
  if (mint_last_redemption_batch_id_.isEmpty()) {
    QMessageBox::information(this, "Redemption Status", "No redemption batch has been created yet.");
    return;
  }
  const QString mint_url = mint_url_edit_->text().trimmed();
  if (mint_url.isEmpty()) {
    QMessageBox::warning(this, "Redemption Status", "Configure a mint URL first.");
    return;
  }
  std::ostringstream body_json;
  body_json << "{\"redemption_batch_id\":\"" << mint_last_redemption_batch_id_.toStdString() << "\"}";
  std::string err;
  auto body = lightserver::http_post_json_raw(mint_endpoint(mint_url, "/redemptions/status").toStdString(),
                                              body_json.str(), &err);
  if (!body) {
    QMessageBox::warning(this, "Redemption Status", "Status query failed: " + QString::fromStdString(err));
    return;
  }
  auto resp = finalis::privacy::parse_mint_redemption_status_response(*body);
  if (!resp) {
    QMessageBox::warning(this, "Redemption Status", "Status response was invalid.");
    return;
  }
  mint_status_label_->setText(QString("Redemption %1: state=%2 l1_txid=%3 amount=%4")
                                  .arg(mint_last_redemption_batch_id_)
                                  .arg(QString::fromStdString(resp->state))
                                  .arg(QString::fromStdString(resp->l1_txid))
                                  .arg(format_coin_amount(resp->amount)));
  append_local_event(QString("[mint-status] batch=%1 state=%2 l1_txid=%3")
                         .arg(mint_last_redemption_batch_id_)
                         .arg(QString::fromStdString(resp->state))
                         .arg(elide_middle(QString::fromStdString(resp->l1_txid), 12)));
}

}  // namespace finalis::wallet
