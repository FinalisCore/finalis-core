#include "mempool/mempool.hpp"

#include <algorithm>
#include <ctime>

#include "codec/bytes.hpp"
#include "utxo/validate.hpp"

namespace finalis::mempool {

namespace {

bool outpoint_exists(const UtxoView& view, const OutPoint& op) {
  return view.find(op) != view.end();
}

int compare_fee_rate(std::uint64_t fee_a, std::size_t size_a, std::uint64_t fee_b, std::size_t size_b) {
  const auto lhs = static_cast<unsigned __int128>(fee_a) * static_cast<unsigned __int128>(size_b);
  const auto rhs = static_cast<unsigned __int128>(fee_b) * static_cast<unsigned __int128>(size_a);
  if (lhs > rhs) return 1;
  if (lhs < rhs) return -1;
  return 0;
}

int compare_entry_score(const MempoolEntry& a, const MempoolEntry& b) {
  if (const int fee_rate_cmp = compare_fee_rate(a.fee, a.size_bytes, b.fee, b.size_bytes); fee_rate_cmp != 0) {
    return fee_rate_cmp;
  }
  if (a.fee != b.fee) return a.fee > b.fee ? 1 : -1;
  if (a.txid < b.txid) return 1;
  if (a.txid > b.txid) return -1;
  return 0;
}

bool meets_full_replacement_margin(const MempoolEntry& incoming, const MempoolEntry& worst, std::uint32_t margin_bps) {
  const auto lhs = static_cast<unsigned __int128>(incoming.fee) * static_cast<unsigned __int128>(10'000) *
                   static_cast<unsigned __int128>(worst.size_bytes);
  const auto rhs = static_cast<unsigned __int128>(worst.fee) * static_cast<unsigned __int128>(10'000 + margin_bps) *
                   static_cast<unsigned __int128>(incoming.size_bytes);
  return lhs >= rhs;
}

}  // namespace

bool Mempool::EvictionKeyLess::operator()(const EvictionKey& a, const EvictionKey& b) const {
  if (const int fee_rate_cmp = compare_fee_rate(a.fee, a.size_bytes, b.fee, b.size_bytes); fee_rate_cmp != 0) {
    return fee_rate_cmp < 0;
  }
  if (a.fee != b.fee) return a.fee < b.fee;
  return a.txid > b.txid;
}

void Mempool::erase_entry(std::map<Hash32, TxMeta>::iterator it) {
  for (const auto& op : it->second.spent) {
    auto sit = spent_outpoints_.find(op);
    if (sit != spent_outpoints_.end() && sit->second == it->first) {
      spent_outpoints_.erase(sit);
    }
  }
  eviction_index_.erase(it->second.eviction_key);
  total_bytes_ -= it->second.entry.size_bytes;
  by_txid_.erase(it);
}

std::optional<Mempool::EvictionKey> Mempool::worst_entry_key() const {
  if (eviction_index_.empty()) return std::nullopt;
  return eviction_index_.begin()->first;
}

bool Mempool::accept_tx(const Tx& tx, const UtxoView& view, std::string* err, std::uint64_t min_fee,
                        std::uint64_t* accepted_fee) {
  const Bytes raw = tx.serialize();
  if (raw.size() > kMaxTxBytes) {
    if (err) *err = "tx too large";
    return false;
  }

  const Hash32 txid = tx.txid();
  if (by_txid_.find(txid) != by_txid_.end()) {
    if (err) *err = "tx already exists";
    return false;
  }

  // v0: no unconfirmed parents. Every input must reference confirmed UTXO view.
  for (const auto& in : tx.inputs) {
    OutPoint op{in.prev_txid, in.prev_index};
    if (!outpoint_exists(view, op)) {
      if (err) *err = "input depends on unconfirmed or missing utxo";
      return false;
    }
    if (spent_outpoints_.find(op) != spent_outpoints_.end()) {
      if (err) *err = "double spend in mempool";
      return false;
    }
  }

  const auto vr = validate_tx(tx, 1, view, ctx_ ? &*ctx_ : nullptr);
  if (!vr.ok) {
    if (err) *err = "tx invalid: " + vr.error;
    return false;
  }
  if (vr.fee < min_fee) {
    if (err) *err = "fee below min relay fee";
    return false;
  }

  const auto required_bits = policy::required_hashcash_bits(hashcash_cfg_, tx, vr.fee, by_txid_.size());
  if (required_bits != 0) {
    if (!tx.hashcash.has_value()) {
      if (err) *err = "hashcash stamp required";
      return false;
    }
    if (!policy::verify_hashcash_stamp(tx, network_, *tx.hashcash, hashcash_cfg_, required_bits,
                                       static_cast<std::uint64_t>(std::time(nullptr)), err)) {
      return false;
    }
  } else if (tx.hashcash.has_value()) {
    if (!policy::verify_hashcash_stamp(tx, network_, *tx.hashcash, hashcash_cfg_, 0,
                                       static_cast<std::uint64_t>(std::time(nullptr)), err)) {
      return false;
    }
  }

  TxMeta meta;
  meta.entry = MempoolEntry{tx, txid, vr.fee, raw.size()};
  meta.eviction_key = EvictionKey{meta.entry.fee, meta.entry.size_bytes, meta.entry.txid};
  meta.spent.reserve(tx.inputs.size());
  for (const auto& in : tx.inputs) {
    OutPoint op{in.prev_txid, in.prev_index};
    meta.spent.push_back(op);
    spent_outpoints_[op] = txid;
  }

  const bool full_by_count = by_txid_.size() >= kMaxTxCount;
  const bool full_by_bytes = total_bytes_ + raw.size() > kMaxPoolBytes;
  if (full_by_count || full_by_bytes) {
    const auto worst_key = worst_entry_key();
    if (!worst_key.has_value()) {
      if (err) *err = full_by_count ? "mempool count limit reached" : "mempool bytes limit reached";
      for (const auto& op : meta.spent) spent_outpoints_.erase(op);
      return false;
    }
    auto worst_index_it = eviction_index_.find(*worst_key);
    if (worst_index_it == eviction_index_.end()) {
      if (err) *err = "mempool eviction index corrupted";
      for (const auto& op : meta.spent) spent_outpoints_.erase(op);
      return false;
    }
    auto worst_it = by_txid_.find(worst_index_it->second);
    if (worst_it == by_txid_.end()) {
      if (err) *err = "mempool entry missing for eviction key";
      for (const auto& op : meta.spent) spent_outpoints_.erase(op);
      return false;
    }
    if (!meets_full_replacement_margin(meta.entry, worst_it->second.entry, full_replacement_margin_bps_)) {
      ++rejected_full_not_good_enough_;
      if (err) *err = "mempool full: not good enough";
      for (const auto& op : meta.spent) spent_outpoints_.erase(op);
      return false;
    }
    if (compare_entry_score(meta.entry, worst_it->second.entry) <= 0) {
      ++rejected_full_not_good_enough_;
      if (err) *err = "mempool full: not good enough";
      for (const auto& op : meta.spent) spent_outpoints_.erase(op);
      return false;
    }
    if (total_bytes_ - worst_it->second.entry.size_bytes + raw.size() > kMaxPoolBytes) {
      if (err) *err = "mempool bytes limit reached";
      for (const auto& op : meta.spent) spent_outpoints_.erase(op);
      return false;
    }
    erase_entry(worst_it);
    ++evicted_for_better_incoming_;
  }

  total_bytes_ += raw.size();
  by_txid_[txid] = std::move(meta);
  eviction_index_[by_txid_[txid].eviction_key] = txid;
  if (accepted_fee) *accepted_fee = vr.fee;
  return true;
}

std::vector<Tx> Mempool::select_for_block(std::size_t max_txs, std::size_t max_bytes, const UtxoView& view,
                                          std::vector<std::string>* diagnostics) const {
  std::vector<const TxMeta*> candidates;
  candidates.reserve(by_txid_.size());
  for (const auto& [_, meta] : by_txid_) {
    candidates.push_back(&meta);
  }

  std::sort(candidates.begin(), candidates.end(), [](const TxMeta* a, const TxMeta* b) {
    return compare_entry_score(a->entry, b->entry) > 0;
  });

  std::vector<Tx> out;
  out.reserve(std::min(max_txs, candidates.size()));
  std::size_t used_bytes = 0;
  UtxoView work = view;

  for (const TxMeta* m : candidates) {
    if (out.size() >= max_txs) break;
    if (used_bytes + m->entry.size_bytes > max_bytes) {
      if (diagnostics) {
        diagnostics->push_back("skip txid=" + hex_encode32(m->entry.txid) + " reason=max-bytes");
      }
      continue;
    }

    const auto vr = validate_tx(m->entry.tx, 1, work, ctx_ ? &*ctx_ : nullptr);
    if (!vr.ok) {
      if (diagnostics) {
        diagnostics->push_back("skip txid=" + hex_encode32(m->entry.txid) + " reason=" + vr.error);
      }
      continue;
    }

    for (const auto& in : m->entry.tx.inputs) {
      work.erase(OutPoint{in.prev_txid, in.prev_index});
    }
    const Hash32 txid = m->entry.txid;
    for (std::uint32_t i = 0; i < m->entry.tx.outputs.size(); ++i) {
      work[OutPoint{txid, i}] = UtxoEntry{m->entry.tx.outputs[i]};
    }

    out.push_back(m->entry.tx);
    used_bytes += m->entry.size_bytes;
  }
  return out;
}

void Mempool::remove_confirmed(const std::vector<Hash32>& txids) {
  std::set<Hash32> to_remove(txids.begin(), txids.end());

  for (auto it = by_txid_.begin(); it != by_txid_.end();) {
    bool remove = to_remove.find(it->first) != to_remove.end();
    if (!remove) {
      ++it;
      continue;
    }
    auto erase_it = it++;
    erase_entry(erase_it);
  }
}

void Mempool::prune_against_utxo(const UtxoView& view) {
  for (auto it = by_txid_.begin(); it != by_txid_.end();) {
    bool ok = true;
    for (const auto& in : it->second.entry.tx.inputs) {
      if (!outpoint_exists(view, OutPoint{in.prev_txid, in.prev_index})) {
        ok = false;
        break;
      }
    }
    if (ok) {
      ++it;
      continue;
    }
    auto erase_it = it++;
    erase_entry(erase_it);
  }
}

std::size_t Mempool::size() const { return by_txid_.size(); }

std::size_t Mempool::total_bytes() const { return total_bytes_; }

bool Mempool::contains(const Hash32& txid) const { return by_txid_.find(txid) != by_txid_.end(); }

MempoolPolicyStats Mempool::policy_stats() const {
  MempoolPolicyStats out;
  out.rejected_full_not_good_enough = rejected_full_not_good_enough_;
  out.evicted_for_better_incoming = evicted_for_better_incoming_;
  const bool full = by_txid_.size() >= kMaxTxCount || total_bytes_ >= kMaxPoolBytes;
  if (!full || by_txid_.empty()) return out;
  const auto worst_key = worst_entry_key();
  if (!worst_key.has_value() || worst_key->size_bytes == 0) return out;
  out.min_fee_rate_to_enter_when_full =
      (static_cast<double>(worst_key->fee) * static_cast<double>(10'000 + full_replacement_margin_bps_)) /
      (static_cast<double>(10'000) * static_cast<double>(worst_key->size_bytes));
  return out;
}

}  // namespace finalis::mempool
