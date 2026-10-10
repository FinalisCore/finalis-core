// SPDX-License-Identifier: MIT

#pragma once

#include <optional>
#include <string>

#include "crypto/confidential.hpp"
#include "crypto/secure_memory.hpp"
#include "utxo/confidential_tx.hpp"
#include "utxo/signing.hpp"
#include "utxo/validate.hpp"

namespace finalis::wallet {

struct ConfidentialRecipient {
  PubKey33 one_time_pubkey{};
  PubKey33 ephemeral_pubkey{};
  crypto::ScanTag scan_tag{};
  Bytes memo;
};

struct ConfidentialOwnedCoin {
  OutPoint outpoint;
  std::uint64_t amount{0};
  crypto::Blind32 spend_secret{};
  crypto::Blind32 value_blind{};
  crypto::Commitment33 value_commitment{};
  PubKey33 one_time_pubkey{};

  // Destructor only (no constructors) so the struct stays an aggregate.
  ~ConfidentialOwnedCoin() {
    crypto::secure_wipe(spend_secret.bytes);
    crypto::secure_wipe(value_blind.bytes);
  }
};

std::optional<ConfidentialTxOutV2> build_confidential_output(
    const ConfidentialRecipient& recipient, const crypto::ConfidentialOutputSecrets& secrets,
    const Hash32& rangeproof_nonce, std::string* err = nullptr);

std::optional<TxV2> build_txv2_transparent_to_confidential(
    const OutPoint& prev_outpoint, const TxOut& prev_out, const Bytes& transparent_owner_private_key_32,
    std::uint64_t transparent_input_value, std::optional<TransparentTxOutV2> transparent_output,
    const ConfidentialTxOutV2& confidential_output, const crypto::Blind32& confidential_output_blind,
    std::uint64_t confidential_output_value, std::uint64_t fee, std::string* err = nullptr);

// One confidential output of a transaction under construction: the built output (see
// build_confidential_output) with the value and blind it commits to.
struct ConfidentialPayment {
  ConfidentialTxOutV2 output;
  std::uint64_t value{0};
  crypto::Blind32 value_blind{};

  ~ConfidentialPayment() { crypto::secure_wipe(value_blind.bytes); }
};

// Confidential -> confidential: spends every coin in full into the given confidential outputs, in the
// given order (callers randomise it so change is not recognisable by position). Requires
// sum(coin amounts) == sum(output values) + fee exactly. Only the fee is public. Authorization nonces
// derive from `nonce_seed` (fresh randomness from callers; fixed in tests).
std::optional<TxV2> build_txv2_confidential_to_confidential(const std::vector<ConfidentialOwnedCoin>& coins,
                                                            const std::vector<ConfidentialPayment>& outputs,
                                                            std::uint64_t fee, const Hash32& nonce_seed,
                                                            std::string* err = nullptr);

std::optional<TxV2> build_txv2_confidential_to_transparent(
    const ConfidentialOwnedCoin& coin, const TransparentTxOutV2& transparent_output, std::uint64_t fee,
    const Hash32& spend_authorization_nonce, const Hash32& excess_authorization_nonce, std::string* err = nullptr);

}  // namespace finalis::wallet
