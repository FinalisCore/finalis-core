// SPDX-License-Identifier: MIT

#pragma once

#include <array>
#include <optional>
#include <string>

#include "common/types.hpp"
#include "consensus/validator_registry.hpp"
#include "utxo/tx.hpp"

namespace finalis::consensus {

Hash32 utxo_commitment_key(const OutPoint& op);
Bytes utxo_commitment_value(const TxOut& out);
Bytes utxo_commitment_value(const UtxoEntryV2& entry);

Hash32 validator_commitment_key(const PubKey32& pub);
Bytes validator_commitment_value_v3(const ValidatorInfo& info);
Bytes validator_commitment_value_v4(const ValidatorInfo& info);
Bytes validator_commitment_value_v6(const ValidatorInfo& info);
Bytes validator_commitment_value(const ValidatorInfo& info, std::uint32_t consensus_version);

inline constexpr std::array<std::uint8_t, 4> kSCR3Prefix{{'S', 'C', 'R', '3'}};

struct V3Roots {
  Hash32 utxo_root{};
  Hash32 validators_root{};
};

enum class MarkerError {
  kNone = 0,
  kMissing,
  kMultipleMarkers,
  kWrongLength,
};

Bytes append_v3_roots_to_coinbase_script(const Bytes& base_script, const Hash32& utxo_root, const Hash32& validators_root);
std::optional<V3Roots> find_scr3_roots_marker(const Bytes& script_sig, MarkerError* err = nullptr);

}  // namespace finalis::consensus
