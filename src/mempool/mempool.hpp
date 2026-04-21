#pragma once

#include <map>
#include <tuple>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "common/network.hpp"
#include "consensus/policy_hashcash.hpp"
#include "utxo/confidential_tx.hpp"
#include "utxo/validate.hpp"
#include "utxo/tx.hpp"

namespace finalis::mempool {

using UtxoView = UtxoSetV2;

struct MempoolEntry {
  AnyTx tx;
  Hash32 txid;
  std::uint64_t fee{0};
  std::size_t size_bytes{0};
  std::uint64_t score_weight{0};
  std::uint64_t confidential_verify_weight{0};
};

struct MempoolPolicyStats {
  std::size_t rejected_full_not_good_enough{0};
  std::size_t evicted_for_better_incoming{0};
  std::optional<double> min_fee_rate_to_enter_when_full;
};

class Mempool {
 public:
  static constexpr std::size_t kMaxTxBytes = 100 * 1024;
  static constexpr std::size_t kMaxTxCount = 10'000;
  static constexpr std::size_t kMaxPoolBytes = 10 * 1024 * 1024;
  static constexpr std::uint32_t kDefaultFullReplacementMarginBps = 1'000;

  bool accept_tx(const AnyTx& tx, const UtxoView& view, std::string* err, std::uint64_t min_fee = 0,
                 std::uint64_t* accepted_fee = nullptr);
  bool accept_tx(const Tx& tx, const UtxoView& view, std::string* err, std::uint64_t min_fee = 0,
                 std::uint64_t* accepted_fee = nullptr) {
    return accept_tx(AnyTx{tx}, view, err, min_fee, accepted_fee);
  }
  std::vector<AnyTx> select_for_block(std::size_t max_txs, std::size_t max_bytes, const UtxoView& view,
                                      std::vector<std::string>* diagnostics = nullptr) const;
  void remove_confirmed(const std::vector<Hash32>& txids);
  void prune_against_utxo(const UtxoView& view);
  std::size_t size() const;
  std::size_t total_bytes() const;
  bool contains(const Hash32& txid) const;
  MempoolPolicyStats policy_stats() const;
  void set_validation_context(SpecialValidationContext ctx) { ctx_ = ctx; }
  void set_hashcash_config(policy::HashcashConfig cfg) { hashcash_cfg_ = std::move(cfg); }
  void set_network(NetworkConfig cfg) { network_ = std::move(cfg); }
  void set_full_replacement_margin_bps(std::uint32_t margin_bps) { full_replacement_margin_bps_ = margin_bps; }

 private:
  struct EvictionKey {
    std::uint64_t fee{0};
    std::uint64_t score_weight{0};
    Hash32 txid{};
  };

  struct EvictionKeyLess {
    bool operator()(const EvictionKey& a, const EvictionKey& b) const;
  };

  struct TxMeta {
    MempoolEntry entry;
    std::vector<OutPoint> spent;
    EvictionKey eviction_key;
  };

  void erase_entry(std::map<Hash32, TxMeta>::iterator it);
  std::optional<EvictionKey> worst_entry_key() const;

  std::map<Hash32, TxMeta> by_txid_;
  std::map<EvictionKey, Hash32, EvictionKeyLess> eviction_index_;
  std::map<OutPoint, Hash32> spent_outpoints_;
  std::size_t total_bytes_{0};
  std::optional<SpecialValidationContext> ctx_;
  policy::HashcashConfig hashcash_cfg_{};
  NetworkConfig network_{mainnet_network()};
  std::uint32_t full_replacement_margin_bps_{kDefaultFullReplacementMarginBps};
  std::size_t rejected_full_not_good_enough_{0};
  std::size_t evicted_for_better_incoming_{0};
};

}  // namespace finalis::mempool
