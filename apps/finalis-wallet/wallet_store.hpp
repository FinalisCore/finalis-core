#pragma once

#include <cstdint>
#include <set>
#include <optional>
#include <string>
#include <vector>

#include "common/types.hpp"
#include "storage/db.hpp"
#include "utxo/tx.hpp"

namespace finalis::wallet {

class WalletStore {
 public:
  struct MintNoteRecord {
    std::string note_ref;
    std::uint64_t amount{0};
    bool active{true};
  };

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

  struct ConfidentialAccountRecord {
    std::string account_id;
    std::string label;
    std::string stealth_address;
    std::string view_key_material_hex;
    std::string spend_key_material_hex;
    bool active{true};
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
  };

  struct State {
    std::vector<std::string> sent_txids;
    std::vector<std::string> local_events;
    std::vector<MintNoteRecord> mint_notes;
    std::vector<PendingSpend> pending_spends;
    std::vector<FinalizedHistoryRecord> finalized_history;
    std::optional<std::uint64_t> history_cursor_height;
    std::optional<std::string> history_cursor_txid;
    std::string mint_deposit_ref;
    std::string mint_last_deposit_txid;
    std::uint32_t mint_last_deposit_vout{0};
    std::string mint_last_redemption_batch_id;
    std::vector<ConfidentialAccountRecord> confidential_accounts;
    std::vector<ConfidentialCoinRecord> confidential_coins;
    std::vector<ConfidentialRequestRecord> confidential_requests;
    std::optional<std::string> confidential_primary_account_id;
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
  bool append_local_event(const std::string& line);
  bool upsert_mint_note(const std::string& note_ref, std::uint64_t amount, bool active);
  bool set_mint_deposit_ref(const std::string& value);
  bool set_mint_last_deposit_txid(const std::string& value);
  bool set_mint_last_deposit_vout(std::uint32_t value);
  bool set_mint_last_redemption_batch_id(const std::string& value);
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
  bool set_string(const std::string& key, const std::string& value);
  bool set_u32(const std::string& key, std::uint32_t value);
  bool set_u64(const std::string& key, std::uint64_t value);
  std::optional<std::string> get_string(const std::string& key) const;
  std::optional<std::uint32_t> get_u32(const std::string& key) const;
  std::optional<std::uint64_t> get_u64(const std::string& key) const;
  std::uint64_t next_event_seq() const;
  std::uint64_t next_history_seq() const;

  storage::DB db_;
  std::string path_;
  std::string passphrase_;
};

}  // namespace finalis::wallet
