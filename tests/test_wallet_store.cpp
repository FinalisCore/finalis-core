#include "test_framework.hpp"

#include <filesystem>

#include "apps/finalis-wallet/wallet_store.hpp"

using namespace finalis::wallet;
using finalis::Hash32;
using finalis::OutPoint;

TEST(test_wallet_store_persists_sent_events_and_notes) {
  const std::string wallet_file = "/tmp/finalis_wallet_store_test/wallet.json";
  std::filesystem::remove_all("/tmp/finalis_wallet_store_test");
  std::filesystem::create_directories("/tmp/finalis_wallet_store_test");

  {
    WalletStore store;
    ASSERT_TRUE(store.open(wallet_file));
  ASSERT_TRUE(store.add_sent_txid("abc123"));
  Hash32 spend_txid{};
  spend_txid.fill(0x42);
  std::vector<OutPoint> pending_inputs{OutPoint{spend_txid, 7}};
  ASSERT_TRUE(store.upsert_pending_spend("abc123", pending_inputs, 44, 123456789));
  ASSERT_TRUE(store.replace_finalized_history({WalletStore::FinalizedHistoryRecord{
      .txid_hex = "tx-final-1",
      .height = 9,
      .kind = "received",
      .detail = "1.00000000 FLS",
  }}));
  ASSERT_TRUE(store.append_finalized_history({WalletStore::FinalizedHistoryRecord{
      .txid_hex = "tx-final-2",
      .height = 10,
      .kind = "sent",
      .detail = "0.50000000 FLS",
  }}));
  ASSERT_TRUE(store.set_history_cursor(10, std::string("tx-final-2")));
    ASSERT_TRUE(store.append_local_event("event-one"));
    ASSERT_TRUE(store.append_local_event("event-two"));
    ASSERT_TRUE(store.upsert_mint_note("note-a", 250000000, true));
    ASSERT_TRUE(store.upsert_mint_note("note-b", 50000000, false));
    ASSERT_TRUE(store.set_mint_deposit_ref("dep-ref"));
    ASSERT_TRUE(store.set_mint_last_deposit_txid("txid1"));
    ASSERT_TRUE(store.set_mint_last_deposit_vout(3));
    ASSERT_TRUE(store.set_mint_last_redemption_batch_id("batch-9"));
  }

  WalletStore reload;
  ASSERT_TRUE(reload.open(wallet_file));
  WalletStore::State state;
  ASSERT_TRUE(reload.load(&state));

  ASSERT_EQ(state.sent_txids.size(), 1u);
  ASSERT_EQ(state.sent_txids[0], "abc123");
  ASSERT_EQ(state.pending_spends.size(), 1u);
  ASSERT_EQ(state.pending_spends[0].txid_hex, "abc123");
  ASSERT_EQ(state.pending_spends[0].inputs.size(), 1u);
  ASSERT_EQ(state.pending_spends[0].inputs[0].index, 7u);
  ASSERT_EQ(state.pending_spends[0].created_tip_height, 44u);
  ASSERT_EQ(state.pending_spends[0].created_unix_ms, 123456789u);
  ASSERT_EQ(state.finalized_history.size(), 2u);
  ASSERT_EQ(state.finalized_history[0].txid_hex, "tx-final-1");
  ASSERT_EQ(state.finalized_history[1].txid_hex, "tx-final-2");
  ASSERT_TRUE(state.history_cursor_height.has_value());
  ASSERT_EQ(*state.history_cursor_height, 10u);
  ASSERT_TRUE(state.history_cursor_txid.has_value());
  ASSERT_EQ(*state.history_cursor_txid, "tx-final-2");
  ASSERT_EQ(state.local_events.size(), 2u);
  ASSERT_EQ(state.local_events[0], "event-one");
  ASSERT_EQ(state.local_events[1], "event-two");
  ASSERT_EQ(state.mint_notes.size(), 2u);
  ASSERT_EQ(state.mint_deposit_ref, "dep-ref");
  ASSERT_EQ(state.mint_last_deposit_txid, "txid1");
  ASSERT_EQ(state.mint_last_deposit_vout, 3u);
  ASSERT_EQ(state.mint_last_redemption_batch_id, "batch-9");
  const auto reserved = WalletStore::reserved_pending_outpoints(state);
  ASSERT_EQ(reserved.size(), 1u);
  ASSERT_TRUE(reserved.find(state.pending_spends[0].inputs[0]) != reserved.end());
}

TEST(test_wallet_store_removes_sent_txid_without_touching_other_local_state) {
  const std::string wallet_file = "/tmp/finalis_wallet_store_remove_sent/wallet.json";
  std::filesystem::remove_all("/tmp/finalis_wallet_store_remove_sent");
  std::filesystem::create_directories("/tmp/finalis_wallet_store_remove_sent");

  {
    WalletStore store;
    ASSERT_TRUE(store.open(wallet_file));
    ASSERT_TRUE(store.add_sent_txid("sent-a"));
    ASSERT_TRUE(store.add_sent_txid("sent-b"));
    Hash32 spend_txid{};
    spend_txid.fill(0x21);
    ASSERT_TRUE(store.upsert_pending_spend("sent-a", {OutPoint{spend_txid, 1}}, 10, 1000));
    ASSERT_TRUE(store.upsert_pending_spend("sent-b", {OutPoint{spend_txid, 2}}, 11, 2000));
    ASSERT_TRUE(store.remove_sent_txid("sent-a"));
  }

  WalletStore reload;
  ASSERT_TRUE(reload.open(wallet_file));
  WalletStore::State state;
  ASSERT_TRUE(reload.load(&state));

  ASSERT_EQ(state.sent_txids.size(), 1u);
  ASSERT_EQ(state.sent_txids[0], "sent-b");
  ASSERT_EQ(state.pending_spends.size(), 2u);
  ASSERT_EQ(state.pending_spends[0].created_tip_height, 10u);
  ASSERT_EQ(state.pending_spends[1].created_tip_height, 11u);
}

TEST(test_wallet_store_persists_encrypted_confidential_accounts_and_coins) {
  const std::string wallet_file = "/tmp/finalis_wallet_store_confidential/wallet.json";
  std::filesystem::remove_all("/tmp/finalis_wallet_store_confidential");
  std::filesystem::create_directories("/tmp/finalis_wallet_store_confidential");

  {
    WalletStore store;
    ASSERT_TRUE(store.open(wallet_file, "secret-pass"));
    ASSERT_TRUE(store.can_persist_confidential_secrets());
    ASSERT_TRUE(store.upsert_confidential_account(WalletStore::ConfidentialAccountRecord{
        .account_id = "acct-main",
        .label = "Primary stealth",
        .stealth_address = "sc_stealth1example",
        .view_key_material_hex = "aa11",
        .spend_key_material_hex = "bb22",
        .active = true,
    }));
    ASSERT_TRUE(store.set_confidential_primary_account_id(std::string("acct-main")));
    ASSERT_TRUE(store.upsert_confidential_coin(WalletStore::ConfidentialCoinRecord{
        .txid_hex = "cc33",
        .vout = 1,
        .account_id = "acct-main",
        .amount = 123456789ull,
        .value_commitment_hex = "02cafe",
        .one_time_pubkey_hex = "02beef",
        .ephemeral_pubkey_hex = "03f00d",
        .spend_secret_hex = "deadc0de",
        .blinding_factor_hex = "b10b",
        .spent = false,
    }));
  }

  WalletStore reload;
  ASSERT_TRUE(reload.open(wallet_file, "secret-pass"));
  WalletStore::State state;
  ASSERT_TRUE(reload.load(&state));

  ASSERT_TRUE(state.confidential_primary_account_id.has_value());
  ASSERT_EQ(*state.confidential_primary_account_id, "acct-main");
  ASSERT_EQ(state.confidential_accounts.size(), 1u);
  ASSERT_EQ(state.confidential_accounts[0].stealth_address, "sc_stealth1example");
  ASSERT_EQ(state.confidential_accounts[0].view_key_material_hex, "aa11");
  ASSERT_EQ(state.confidential_coins.size(), 1u);
  ASSERT_EQ(state.confidential_coins[0].account_id, "acct-main");
  ASSERT_EQ(state.confidential_coins[0].amount, 123456789ull);
  ASSERT_EQ(state.confidential_coins[0].spend_secret_hex, "deadc0de");
  ASSERT_EQ(state.confidential_coins[0].blinding_factor_hex, "b10b");
}

TEST(test_wallet_store_marks_confidential_requests_consumed_without_deleting_them) {
  const std::string wallet_file = "/tmp/finalis_wallet_store_confidential_requests/wallet.json";
  std::filesystem::remove_all("/tmp/finalis_wallet_store_confidential_requests");
  std::filesystem::create_directories("/tmp/finalis_wallet_store_confidential_requests");

  {
    WalletStore store;
    ASSERT_TRUE(store.open(wallet_file, "secret-pass"));
    ASSERT_TRUE(store.upsert_confidential_request(WalletStore::ConfidentialRequestRecord{
        .request_id = "req-1",
        .account_id = "acct-main",
        .one_time_pubkey_hex = "02aa",
        .ephemeral_pubkey_hex = "03bb",
        .scan_tag = 0x19,
        .spend_secret_hex = "dead",
        .memo_key_hex = "beef",
        .consumed = false,
    }));
    ASSERT_TRUE(store.set_confidential_request_consumed("req-1", true));
  }

  WalletStore reload;
  ASSERT_TRUE(reload.open(wallet_file, "secret-pass"));
  WalletStore::State state;
  ASSERT_TRUE(reload.load(&state));

  ASSERT_EQ(state.confidential_requests.size(), 1u);
  ASSERT_EQ(state.confidential_requests[0].request_id, "req-1");
  ASSERT_TRUE(state.confidential_requests[0].consumed);
}

TEST(test_wallet_store_marks_confidential_coin_spent_without_deleting_it) {
  const std::string wallet_file = "/tmp/finalis_wallet_store_confidential_coin_spent/wallet.json";
  std::filesystem::remove_all("/tmp/finalis_wallet_store_confidential_coin_spent");
  std::filesystem::create_directories("/tmp/finalis_wallet_store_confidential_coin_spent");

  {
    WalletStore store;
    ASSERT_TRUE(store.open(wallet_file, "secret-pass"));
    ASSERT_TRUE(store.upsert_confidential_coin(WalletStore::ConfidentialCoinRecord{
        .txid_hex = "cc33",
        .vout = 1,
        .account_id = "acct-main",
        .amount = 123456789ull,
        .value_commitment_hex = "02cafe",
        .one_time_pubkey_hex = "02beef",
        .ephemeral_pubkey_hex = "03f00d",
        .spend_secret_hex = "deadc0de",
        .blinding_factor_hex = "b10b",
        .spent = false,
    }));
    ASSERT_TRUE(store.set_confidential_coin_spent("cc33", 1, true));
  }

  WalletStore reload;
  ASSERT_TRUE(reload.open(wallet_file, "secret-pass"));
  WalletStore::State state;
  ASSERT_TRUE(reload.load(&state));

  ASSERT_EQ(state.confidential_coins.size(), 1u);
  ASSERT_EQ(state.confidential_coins[0].txid_hex, "cc33");
  ASSERT_EQ(state.confidential_coins[0].vout, 1u);
  ASSERT_TRUE(state.confidential_coins[0].spent);
}

TEST(test_wallet_store_refuses_confidential_secret_persistence_without_passphrase) {
  const std::string wallet_file = "/tmp/finalis_wallet_store_confidential_nopass/wallet.json";
  std::filesystem::remove_all("/tmp/finalis_wallet_store_confidential_nopass");
  std::filesystem::create_directories("/tmp/finalis_wallet_store_confidential_nopass");

  WalletStore store;
  ASSERT_TRUE(store.open(wallet_file));
  ASSERT_TRUE(!store.can_persist_confidential_secrets());
  ASSERT_TRUE(!store.upsert_confidential_account(WalletStore::ConfidentialAccountRecord{
      .account_id = "acct-main",
      .label = "Primary stealth",
      .stealth_address = "sc_stealth1example",
      .view_key_material_hex = "aa11",
      .spend_key_material_hex = "bb22",
      .active = true,
  }));
  ASSERT_TRUE(!store.upsert_confidential_coin(WalletStore::ConfidentialCoinRecord{
      .txid_hex = "cc33",
      .vout = 1,
      .account_id = "acct-main",
      .amount = 123456789ull,
      .value_commitment_hex = "02cafe",
      .one_time_pubkey_hex = "02beef",
      .ephemeral_pubkey_hex = "03f00d",
      .spend_secret_hex = "deadc0de",
      .blinding_factor_hex = "b10b",
      .spent = false,
  }));
}
