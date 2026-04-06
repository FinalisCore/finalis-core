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
  const auto entries = db.get_script_utxos(scripthash);
  const auto canonical_utxos = db.load_utxos();
  std::map<OutPoint, TxOut> canonical_matches;
  for (const auto& [op, entry] : canonical_utxos) {
    if (crypto::sha256(entry.out.script_pubkey) != scripthash) continue;
    canonical_matches.emplace(op, entry.out);
  }

  std::vector<SpendableUtxo> out;
  out.reserve(std::max(entries.size(), canonical_matches.size()));
  std::set<OutPoint> seen;
  for (const auto& entry : entries) {
    if (excluded && excluded->find(entry.outpoint) != excluded->end()) continue;
    const auto canonical_it = canonical_matches.find(entry.outpoint);
    if (canonical_it == canonical_matches.end()) continue;
    if (canonical_it->second.value != entry.value || canonical_it->second.script_pubkey != entry.script_pubkey) continue;
    out.push_back(SpendableUtxo{entry.outpoint, canonical_it->second});
    seen.insert(entry.outpoint);
  }
  for (const auto& [op, prevout] : canonical_matches) {
    if (excluded && excluded->find(op) != excluded->end()) continue;
    if (seen.find(op) != seen.end()) continue;
    out.push_back(SpendableUtxo{op, prevout});
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
