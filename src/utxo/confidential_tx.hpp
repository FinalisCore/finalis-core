#pragma once

#include <optional>
#include <variant>

#include "crypto/confidential.hpp"
#include "utxo/tx.hpp"

namespace finalis {

enum class TxVersionKind : std::uint32_t {
  TRANSPARENT_V1 = 1,
  CONFIDENTIAL_V2 = 2,
};

enum class TxInputKind : std::uint8_t {
  TRANSPARENT = 0,
  CONFIDENTIAL = 1,
};

enum class TxOutputKind : std::uint8_t {
  TRANSPARENT = 0,
  CONFIDENTIAL = 1,
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
  TxInputKind kind{TxInputKind::TRANSPARENT};
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
  TxOutputKind kind{TxOutputKind::TRANSPARENT};
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

using AnyTx = std::variant<Tx, TxV2>;

std::optional<AnyTx> parse_any_tx(const Bytes& b);
Bytes serialize_any_tx(const AnyTx& tx);
Hash32 txid_any(const AnyTx& tx);

}  // namespace finalis
