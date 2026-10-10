// SPDX-License-Identifier: MIT

#pragma once

#include <cstdint>
#include <set>
#include <optional>
#include <string>
#include <vector>

#include "common/types.hpp"
#include "crypto/secure_memory.hpp"
#include "storage/db.hpp"
#include "utxo/tx.hpp"

namespace finalis::wallet {

class WalletStore {
 public:
  WalletStore() = default;
  WalletStore(const WalletStore&) = delete;
  WalletStore& operator=(const WalletStore&) = delete;
  ~WalletStore() { crypto::secure_wipe(passphrase_); }

  struct PendingSpend {
    std::string txid_hex;
    std::vector<OutPoint> inputs;
    std::uint64_t created_tip_height{0};
    std::uint64_t created_unix_ms{0};
  };

  struct FinalizedHistoryRecord {
    std::string txid_hex;
    std::uint64_t height{0};
    std::string kind;
    std::string detail;
  };

  struct SnapshotUtxoRecord {
    std::string txid_hex;
    std::uint32_t vout{0};
    std::uint64_t value{0};
    std::uint64_t height{0};
    Bytes script_pubkey;
  };

  struct WalletSnapshot {
    std::string chain_network_name;
    std::string transition_hash;
    std::string network_id_hex;
    std::string genesis_hash_hex;
    std::string binary_version;
    std::string wallet_api_version;
    std::string last_refresh_text;
    std::string last_successful_endpoint;
    std::uint64_t tip_height{0};
    std::optional<std::uint64_t> finalized_lag;
    bool peer_height_disagreement{false};
    bool bootstrap_sync_incomplete{false};
    std::vector<SnapshotUtxoRecord> utxos;
  };

  struct ViewSnapshotRow {
    std::string col0;
    std::string col1;
    std::string col2;
    std::string col3;
    std::string col4;
  };

  struct WalletViewSnapshot {
    std::string balance_text;
    std::string pending_balance_text;
    std::string confidential_balance_text;
    std::string confidential_request_summary_text;
    std::string confidential_coin_summary_text;
    std::string activity_finalized_count_text;
    std::string activity_pending_count_text;
    std::string activity_local_count_text;
    std::string activity_confidential_count_text;
    std::vector<ViewSnapshotRow> overview_activity_rows;
    std::vector<ViewSnapshotRow> history_rows;
  };

  struct PendingTxStatusRecord {
    std::string txid_hex;
    std::string endpoint;
    std::string cached_at;
    std::uint64_t cached_at_ms{0};
    std::string status;
    bool finalized{false};
    std::uint64_t height{0};
    std::uint64_t finalized_depth{0};
    bool credit_safe{false};
    std::string transition_hash;
  };

  struct ConfidentialAccountRecord {
    std::string account_id;
    std::string label;
    std::string stealth_address;
    std::string view_key_material_hex;
    std::string spend_key_material_hex;
    bool active{true};
    // Next receive-request index; request keys derive from the account secrets and this index
    // (wallet/confidential_keys.hpp), so the account secrets alone recover every request.
    std::uint32_t next_request_index{0};

    ~ConfidentialAccountRecord() { crypto::secure_wipe(view_key_material_hex); crypto::secure_wipe(spend_key_material_hex); }
  };

  struct ConfidentialCoinRecord {
    std::string txid_hex;
    std::uint32_t vout{0};
    std::string account_id;
    std::uint64_t amount{0};
    std::string value_commitment_hex;
    std::string one_time_pubkey_hex;
    std::string ephemeral_pubkey_hex;
    std::string spend_secret_hex;
    std::string blinding_factor_hex;
    bool spent{false};

    ~ConfidentialCoinRecord() { crypto::secure_wipe(spend_secret_hex); crypto::secure_wipe(blinding_factor_hex); }
  };

  struct ConfidentialRequestRecord {
    std::string request_id;
    std::string account_id;
    std::string one_time_pubkey_hex;
    std::string ephemeral_pubkey_hex;
    std::uint8_t scan_tag{0};
    std::string spend_secret_hex;
    std::string memo_key_hex;
    bool consumed{false};

    ~ConfidentialRequestRecord() { crypto::secure_wipe(spend_secret_hex); crypto::secure_wipe(memo_key_hex); }
  };

  struct State {
    std::vector<std::string> sent_txids;
    std::vector<std::string> local_events;
    std::vector<PendingSpend> pending_spends;
    std::vector<FinalizedHistoryRecord> finalized_history;
    std::optional<std::uint64_t> history_cursor_height;
    std::optional<std::string> history_cursor_txid;
    std::vector<ConfidentialAccountRecord> confidential_accounts;
    std::vector<ConfidentialCoinRecord> confidential_coins;
    std::vector<ConfidentialRequestRecord> confidential_requests;
    std::optional<std::string> confidential_primary_account_id;
    std::optional<WalletSnapshot> wallet_snapshot;
    std::optional<WalletViewSnapshot> wallet_view_snapshot;
    std::vector<PendingTxStatusRecord> pending_tx_statuses;
  };

  bool open(const std::string& wallet_file_path, const std::string& passphrase = {});
  bool load(State* out) const;

  bool add_sent_txid(const std::string& txid);
  bool remove_sent_txid(const std::string& txid);
  bool upsert_pending_spend(const std::string& txid, const std::vector<OutPoint>& inputs,
                            std::uint64_t created_tip_height = 0, std::uint64_t created_unix_ms = 0);
  bool remove_pending_spend(const std::string& txid);
  bool replace_finalized_history(const std::vector<FinalizedHistoryRecord>& records);
  bool append_finalized_history(const std::vector<FinalizedHistoryRecord>& records);
  bool set_history_cursor(const std::optional<std::uint64_t>& height, const std::optional<std::string>& txid);
  bool set_wallet_snapshot(const WalletSnapshot& snapshot);
  bool clear_wallet_snapshot();
  bool set_wallet_view_snapshot(const WalletViewSnapshot& snapshot);
  bool clear_wallet_view_snapshot();
  bool upsert_pending_tx_status(const PendingTxStatusRecord& record);
  bool remove_pending_tx_status(const std::string& txid_hex);
  bool append_local_event(const std::string& line);
  bool upsert_confidential_account(const ConfidentialAccountRecord& record);
  bool set_confidential_primary_account_id(const std::optional<std::string>& account_id);
  bool upsert_confidential_coin(const ConfidentialCoinRecord& record);
  bool set_confidential_coin_spent(const std::string& txid_hex, std::uint32_t vout, bool spent);
  bool remove_confidential_coin(const std::string& txid_hex, std::uint32_t vout);
  bool upsert_confidential_request(const ConfidentialRequestRecord& record);
  bool set_confidential_request_consumed(const std::string& request_id, bool consumed);
  bool remove_confidential_request(const std::string& request_id);
  bool can_persist_confidential_secrets() const;

  static std::set<OutPoint> reserved_pending_outpoints(const State& state);

 private:
  bool prune_pending_tx_status_cache();
  bool set_string(const std::string& key, const std::string& value);
  bool set_u64(const std::string& key, std::uint64_t value);
  std::optional<std::string> get_string(const std::string& key) const;
  std::optional<std::uint64_t> get_u64(const std::string& key) const;
  std::uint64_t next_event_seq() const;
  std::uint64_t next_history_seq() const;

  storage::DB db_;
  std::string path_;
  std::string passphrase_;
};

}  // namespace finalis::wallet
