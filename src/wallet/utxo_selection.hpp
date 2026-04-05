#pragma once

#include <optional>
#include <set>
#include <string>
#include <vector>

#include "storage/db.hpp"

namespace finalis::wallet {

struct SpendableUtxo {
  OutPoint outpoint;
  TxOut prevout;
};

struct UtxoSelection {
  std::vector<SpendableUtxo> selected;
  std::uint64_t selected_total{0};
  std::uint64_t required_total{0};
};

std::vector<SpendableUtxo> spendable_p2pkh_utxos_for_pubkey_hash(
    const storage::DB& db, const std::array<std::uint8_t, 20>& pubkey_hash,
    const std::set<OutPoint>* excluded = nullptr);

std::optional<UtxoSelection> select_deterministic_utxos(
    const std::vector<SpendableUtxo>& spendable, std::uint64_t required_total, std::string* err = nullptr);

}  // namespace finalis::wallet
