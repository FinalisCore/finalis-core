// SPDX-License-Identifier: MIT

#pragma once

#include <optional>
#include <string>

#include "crypto/confidential.hpp"
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
};

std::optional<ConfidentialTxOutV2> build_confidential_output(
    const ConfidentialRecipient& recipient, const crypto::ConfidentialOutputSecrets& secrets,
    const Hash32& rangeproof_nonce, std::string* err = nullptr);

std::optional<TxV2> build_txv2_transparent_to_confidential(
    const OutPoint& prev_outpoint, const TxOut& prev_out, const Bytes& transparent_owner_private_key_32,
    std::uint64_t transparent_input_value, std::optional<TransparentTxOutV2> transparent_output,
    const ConfidentialTxOutV2& confidential_output, const crypto::Blind32& confidential_output_blind,
    std::uint64_t confidential_output_value, std::uint64_t fee, std::string* err = nullptr);

std::optional<TxV2> build_txv2_confidential_to_transparent(
    const ConfidentialOwnedCoin& coin, const TransparentTxOutV2& transparent_output, std::uint64_t fee,
    const Hash32& spend_authorization_nonce, const Hash32& excess_authorization_nonce, std::string* err = nullptr);

}  // namespace finalis::wallet
