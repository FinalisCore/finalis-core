// SPDX-License-Identifier: MIT

#pragma once

#include <optional>
#include <variant>

#include "crypto/confidential.hpp"
#include "crypto/swe.hpp"
#include "crypto/swe_proofs.hpp"
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

// --- Timed transactions (McFly time layer; not yet part of AnyTx) ---
//
// A TxTimed is included at height h and ordered blindly; its body is decrypted and applied in the
// execution of block unlock_height + 1, once the aggregate time signature for unlock_height exists
// (every block carries the one for its parent). Hybrid encryption: a 256-bit AEAD key is encrypted
// with McFly SWE (crypto/swe.hpp) to the committee of epoch_of(unlock_height) and the time-signature
// message of unlock_height (time_signature_message); the body, a serialized Tx or TxV2, is
// ChaCha20-Poly1305-encrypted under that key.
//
// Validity at inclusion (block h), all public:
//   h <= unlock_height <= the last height whose committee is already finalized (the horizon), and
//   committee_root is that committee's key root (a ciphertext to any other key set never opens);
//   swe_ciphertext parses for that committee and swe_proof (crypto/swe_proofs.hpp) verifies;
//   the fee input is a standard transparent P2PKH UTXO whose script_sig signs the envelope
//   (signing_message_for_timed_fee_input), and its value is exactly prepaid_fee + fee_change.value.
// A TxTimed included after unlock_height is invalid: its key is already public.
// Delay ("time-locked outputs") is unlock_height > h: the body's outputs appear at unlock_height + 1.
//
// Value (consensus::settle_timed_escrow): the fee input is spent at h; prepaid_fee goes to the
// validators of h, the rest is held in escrow. At unlock_height + 1 a body that decrypts, parses and
// applies releases fee_change to its owner; any other body (undecryptable, unparsable, invalid, a
// double spend) applies nothing and the escrow goes to the validators of that block. Either way the
// whole fee-input value is accounted for; nothing is burned or created.
inline constexpr std::uint32_t kTxTimedMaxScriptBytes = 1024;
// Exact SWE footprint at MAX_COMMITTEE keys and a 256-bit key (crypto::SweCiphertext::serialize).
inline constexpr std::uint32_t kTxTimedMaxSweCiphertextBytes =
    7 + (2 + MAX_COMMITTEE) * crypto::kBlsPublicKeyBytes +
    crypto::kSweKeyChunks * (crypto::kBlsPublicKeyBytes + crypto::kBlsSignatureBytes + crypto::kGtBytes);
inline constexpr std::uint32_t kTxTimedSweProofBytes = crypto::kSweWellFormednessProofBytes;
inline constexpr std::uint32_t kTxTimedBodyTagBytes = 16;  // Poly1305
inline constexpr std::uint32_t kTxTimedMaxBodyCiphertextBytes = 64 * 1024;

enum class TxTimedVersionKind : std::uint32_t {
  TIMED_V3 = 3,
};

struct TxTimed {
  std::uint32_t version{static_cast<std::uint32_t>(TxTimedVersionKind::TIMED_V3)};
  // Cleartext fee part: spent at inclusion (see "Value" above).
  TxIn fee_input;                     // transparent, P2PKH; script_sig signs the envelope
  std::uint64_t prepaid_fee{0};
  std::optional<TxOut> fee_change;    // transparent P2PKH, released only if the body applies
  // Time lock.
  std::uint64_t unlock_height{0};     // decrypted with the time signature of this height
  std::uint64_t committee_epoch{0};   // epoch_of(unlock_height); checked, not trusted
  Hash32 committee_root{};            // root of that epoch's ordered BLS keys (the SWE key set V)
  Bytes swe_ciphertext;               // crypto::SweCiphertext of the 256-bit body key
  Bytes swe_proof;                    // crypto::SweWellFormednessProof
  std::array<std::uint8_t, 12> body_nonce{};
  Bytes body_ciphertext;              // ciphertext || 16-byte tag

  // u32 version | fee_input (prev_txid, prev_index, varbytes script_sig, sequence) | u64 prepaid_fee
  // | u8 has_change [u64 value, varbytes script_pubkey] | u64 unlock_height | u64 committee_epoch
  // | committee_root | varbytes swe_ciphertext | varbytes swe_proof | body_nonce
  // | varbytes body_ciphertext   (little-endian integers, as Tx / TxV2)
  Bytes serialize() const;
  // Enforces the size limits above; does not parse the SWE ciphertext or proof (that needs the
  // committee).
  static std::optional<TxTimed> parse(const Bytes& b);
  Hash32 txid() const;
  // Associated data of the body AEAD: SHA256d("SC-TIMED-AAD-V1" || serialize() without the fee
  // script_sig and the body ciphertext), so the body key opens the body only inside this envelope.
  Hash32 body_aad() const;
};
using AnyTx = std::variant<Tx, TxV2>;

std::optional<AnyTx> parse_any_tx(const Bytes& b);
Bytes serialize_any_tx(const AnyTx& tx);
Hash32 txid_any(const AnyTx& tx);

// Encrypts serialize_any_tx(body) into tx.body_ciphertext under `key`, with tx.body_nonce and
// tx.body_aad(); every other field must already be final. False if the body is too large.
bool seal_timed_body(TxTimed& tx, const Hash32& key, const AnyTx& body);
// The body, or nullopt if the tag does not verify under `key` and tx.body_aad() or the plaintext is
// not exactly one Tx / TxV2 encoding. Either way the chain treats nullopt as an invalid body.
std::optional<AnyTx> open_timed_body(const TxTimed& tx, const Hash32& key);

// Address-history key of a confidential one-time key: SHA256("FINALIS/conf-history/v1" || one_time_pubkey).
// Finalized outputs paying the key and confidential inputs spending it are indexed under it, so a
// wallet that derives its request keys from its account secrets finds its coins without stored records.
// The domain prefix keeps it apart from transparent scripthashes (SHA256(script_pubkey)).
Hash32 confidential_history_key(const PubKey33& one_time_pubkey);

}  // namespace finalis
