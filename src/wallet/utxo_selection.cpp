#include "wallet/utxo_selection.hpp"

#include <algorithm>

#include "address/address.hpp"
#include "crypto/hash.hpp"

namespace finalis::wallet {
namespace {

bool outpoint_less(const OutPoint& a, const OutPoint& b) {
  if (a.txid != b.txid) return a.txid < b.txid;
  return a.index < b.index;
}

}  // namespace

std::vector<SpendableUtxo> spendable_p2pkh_utxos_for_pubkey_hash(
    const storage::DB& db, const std::array<std::uint8_t, 20>& pubkey_hash, const std::set<OutPoint>* excluded) {
  const Hash32 scripthash = crypto::sha256(address::p2pkh_script_pubkey(pubkey_hash));
  auto entries = db.get_script_utxos(scripthash);
  std::vector<SpendableUtxo> out;
  out.reserve(entries.size());
  for (const auto& entry : entries) {
    if (excluded && excluded->find(entry.outpoint) != excluded->end()) continue;
    out.push_back(SpendableUtxo{entry.outpoint, TxOut{entry.value, entry.script_pubkey}});
  }
  std::sort(out.begin(), out.end(), [](const SpendableUtxo& a, const SpendableUtxo& b) {
    if (a.prevout.value != b.prevout.value) return a.prevout.value > b.prevout.value;
    return outpoint_less(a.outpoint, b.outpoint);
  });
  return out;
}

std::optional<UtxoSelection> select_deterministic_utxos(
    const std::vector<SpendableUtxo>& spendable, std::uint64_t required_total, std::string* err) {
  if (required_total == 0) {
    if (err) *err = "required total must be positive";
    return std::nullopt;
  }

  UtxoSelection selection;
  selection.required_total = required_total;
  for (const auto& utxo : spendable) {
    selection.selected.push_back(utxo);
    selection.selected_total += utxo.prevout.value;
    if (selection.selected_total >= required_total) return selection;
  }
  if (err) *err = "insufficient selectable funds";
  return std::nullopt;
}

}  // namespace finalis::wallet
