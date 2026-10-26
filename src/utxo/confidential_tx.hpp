// SPDX-License-Identifier: MIT

#pragma once

#include <optional>
#include <variant>

#include "crypto/confidential.hpp"
#include "utxo/tx.hpp"

namespace finalis {

// Hard TxV2 limits, enforced while parsing so a hostile encoding cannot force large allocations.
// ConfidentialPolicy's defaults are these same values.
inline constexpr std::uint32_t kTxV2MaxInputs = 64;
inline constexpr std::uint32_t kTxV2MaxOutputs = 32;
inline constexpr std::uint32_t kTxV2MaxRangeProofBytes = 5134;
inline constexpr std::uint32_t kTxV2MaxMemoBytes = 128;

enum class TxVersionKind : std::uint32_t {
  TRANSPARENT_V1 = 1,
  CONFIDENTIAL_V2 = 2,
};

enum class TxInputKind : std::uint8_t {
  Transparent = 0,
  Confidential = 1,
};

enum class TxOutputKind : std::uint8_t {
  Transparent = 0,
  Confidential = 1,
};

struct TransparentInputWitnessV2 {
  Bytes script_sig;
  bool operator==(const TransparentInputWitnessV2&) const = default;
};

struct ConfidentialInputWitnessV2 {
  PubKey33 one_time_pubkey{};
  Sig64 spend_sig{};
  bool operator==(const ConfidentialInputWitnessV2&) const = default;
};

struct TxInV2 {
  Hash32 prev_txid{};
  std::uint32_t prev_index{0};
  std::uint32_t sequence{0xFFFFFFFF};
  TxInputKind kind{TxInputKind::Transparent};
  std::variant<TransparentInputWitnessV2, ConfidentialInputWitnessV2> witness{TransparentInputWitnessV2{}};

  bool operator==(const TxInV2&) const = default;
};

struct TransparentTxOutV2 {
  std::uint64_t value{0};
  Bytes script_pubkey;
  bool operator==(const TransparentTxOutV2&) const = default;
};

struct ConfidentialTxOutV2 {
  crypto::Commitment33 value_commitment{};
  PubKey33 one_time_pubkey{};
  PubKey33 ephemeral_pubkey{};
  crypto::ScanTag scan_tag{};
  crypto::ProofBytes range_proof;
  Bytes memo;

  bool operator==(const ConfidentialTxOutV2&) const = default;
};

struct TxOutV2 {
  TxOutputKind kind{TxOutputKind::Transparent};
  std::variant<TransparentTxOutV2, ConfidentialTxOutV2> body{TransparentTxOutV2{}};

  bool operator==(const TxOutV2&) const = default;
};

struct TxBalanceProofV2 {
  crypto::Commitment33 excess_commitment{};
  PubKey32 excess_pubkey{};
  Sig64 excess_sig{};
  bool operator==(const TxBalanceProofV2&) const = default;
};

struct TxV2 {
  std::uint32_t version{static_cast<std::uint32_t>(TxVersionKind::CONFIDENTIAL_V2)};
  std::vector<TxInV2> inputs;
  std::vector<TxOutV2> outputs;
  std::uint32_t lock_time{0};
  std::uint64_t fee{0};
  TxBalanceProofV2 balance_proof;

  Bytes serialize() const;
  static std::optional<TxV2> parse(const Bytes& b);
  Hash32 txid() const;

  bool operator==(const TxV2&) const = default;
};

// --- Timed transactions (McFly time layer; design sketch, not yet part of AnyTx) ---
//
// A TxTimed is included at height h and ordered blindly; its body is decrypted and applied in the
// execution of block unlock_height + 1, once the aggregate time signature for unlock_height exists
// (every block carries the one for its parent). Hybrid encryption: a 256-bit AEAD key is encrypted
// with McFly SWE to the committee of epoch_of(unlock_height) and the time-signature message for
// unlock_height; the body (a serialized Tx or TxV2) is AEAD-encrypted under that key.
//
// Validity at inclusion (block h), all public:
//   h <= unlock_height <= the last height whose committee is already finalized (the horizon), and
//   committee_root is that committee's key root (a ciphertext to any other key set never opens);
//   the SWE proof verifies (decrypts to the same key for every signer subset, every chunk in range);
//   the fee input is a standard transparent UTXO, its script_sig signs the whole envelope, and it
//   covers prepaid_fee (+ the change output). The fee is charged at h whatever the body turns out to
//   be: an undecryptable-looking but proven ciphertext, garbage, or a double spend at execution.
// A TxTimed included after unlock_height is invalid: its key is already public, so it would be
// ordered with its contents known. Delay ("time-locked outputs") is unlock_height > h: the body's
// outputs appear only at unlock_height + 1.
inline constexpr std::uint32_t kTxTimedMaxSweCiphertextBytes = 32 * 1024;  // n <= MAX_COMMITTEE key-group elements + 11 chunks
inline constexpr std::uint32_t kTxTimedMaxSweProofBytes = 16 * 1024;
inline constexpr std::uint32_t kTxTimedMaxBodyCiphertextBytes = 64 * 1024;

enum class TxTimedVersionKind : std::uint32_t {
  TIMED_V3 = 3,
};

struct TxTimed {
  std::uint32_t version{static_cast<std::uint32_t>(TxTimedVersionKind::TIMED_V3)};
  // Cleartext fee part, applied at inclusion.
  TxIn fee_input;                     // transparent, P2PKH; script_sig signs the envelope
  std::uint64_t prepaid_fee{0};
  std::optional<TxOut> fee_change;    // transparent P2PKH change from fee_input
  // Time lock.
  std::uint64_t unlock_height{0};     // decrypted with the time signature of this height
  std::uint64_t committee_epoch{0};   // epoch_of(unlock_height); checked, not trusted
  Hash32 committee_root{};            // root of that epoch's ordered BLS keys (the SWE key set V)
  // McFly SWE' (paper section 6.1, enhanced) of the 256-bit AEAD key, and its verifiability proof
  // (well-formedness + plaintext equality + range, section 7). Opaque here; crypto/swe.* owns the
  // encodings and their size checks.
  Bytes swe_ciphertext;
  Bytes swe_proof;
  // AEAD (ChaCha20-Poly1305, 12-byte nonce) of serialize_any_tx(body); the associated data commits
  // to every field above, so no part of the envelope can be swapped under a valid body.
  std::array<std::uint8_t, 12> body_nonce{};
  Bytes body_ciphertext;

  bool operator==(const TxTimed&) const = default;
};

using AnyTx = std::variant<Tx, TxV2>;

std::optional<AnyTx> parse_any_tx(const Bytes& b);
Bytes serialize_any_tx(const AnyTx& tx);
Hash32 txid_any(const AnyTx& tx);

// Address-history key of a confidential one-time key: SHA256("FINALIS/conf-history/v1" || one_time_pubkey).
// Finalized outputs paying the key and confidential inputs spending it are indexed under it, so a
// wallet that derives its request keys from its account secrets finds its coins without stored records.
// The domain prefix keeps it apart from transparent scripthashes (SHA256(script_pubkey)).
Hash32 confidential_history_key(const PubKey33& one_time_pubkey);

}  // namespace finalis
