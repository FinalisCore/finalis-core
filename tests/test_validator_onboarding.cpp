#include "test_framework.hpp"

#include <ctime>
#include <filesystem>

#include "address/address.hpp"
#include "common/network.hpp"
#include "crypto/ed25519.hpp"
#include "crypto/hash.hpp"
#include "keystore/validator_keystore.hpp"
#include "onboarding/validator_onboarding.hpp"
#include "storage/db.hpp"
#include "wallet/utxo_selection.hpp"

using namespace finalis;

namespace {

std::uint64_t now_unix_ms() {
  return static_cast<std::uint64_t>(std::time(nullptr)) * 1000ULL;
}

std::filesystem::path make_temp_dir(const char* name) {
  const auto base = std::filesystem::temp_directory_path() / "finalis-tests";
  std::filesystem::create_directories(base);
  const auto path = base / name;
  std::filesystem::remove_all(path);
  std::filesystem::create_directories(path);
  return path;
}

keystore::ValidatorKey create_test_wallet(const std::filesystem::path& db_dir, std::string* passphrase_out) {
  std::filesystem::create_directories(db_dir / "keystore");
  const std::string passphrase = "test-pass";
  keystore::ValidatorKey key;
  std::string err;
  const auto seed = std::array<std::uint8_t, 32>{0x41};
  ASSERT_TRUE(keystore::create_validator_keystore((db_dir / "keystore" / "validator.json").string(), passphrase, "mainnet",
                                                  keystore::hrp_for_network("mainnet"), seed, &key, &err));
  if (passphrase_out) *passphrase_out = passphrase;
  return key;
}

void put_spendable_p2pkh(storage::DB& db, const keystore::ValidatorKey& key, std::uint8_t tag, std::uint64_t value) {
  Hash32 txid{};
  txid.fill(tag);
  const OutPoint op{txid, 0};
  const auto pkh = crypto::h160(Bytes(key.pubkey.begin(), key.pubkey.end()));
  const TxOut out{value, address::p2pkh_script_pubkey(pkh)};
  ASSERT_TRUE(db.put_utxo(op, out));
  const auto scripthash = crypto::sha256(out.script_pubkey);
  ASSERT_TRUE(db.put_script_utxo(scripthash, op, out, 1));
}

storage::NodeRuntimeStatusSnapshot ready_snapshot(std::uint64_t local_height) {
  storage::NodeRuntimeStatusSnapshot snapshot;
  snapshot.chain_id_ok = true;
  snapshot.db_open = true;
  snapshot.local_finalized_height = local_height;
  snapshot.observed_network_height_known = true;
  snapshot.observed_network_finalized_height = local_height;
  snapshot.healthy_peer_count = 1;
  snapshot.established_peer_count = 1;
  snapshot.finalized_lag = 0;
  snapshot.next_height_committee_available = true;
  snapshot.next_height_proposer_available = true;
  snapshot.registration_ready_preflight = true;
  snapshot.registration_ready = true;
  snapshot.readiness_stable_samples = 2;
  snapshot.captured_at_unix_ms = now_unix_ms();
  return snapshot;
}

onboarding::ValidatorOnboardingOptions make_options(const std::filesystem::path& db_dir, const std::string& passphrase) {
  onboarding::ValidatorOnboardingOptions options;
  options.db_path = db_dir.string();
  options.key_file = (db_dir / "keystore" / "validator.json").string();
  options.passphrase = passphrase;
  options.rpc_url = "http://127.0.0.1:19444/rpc";
  options.fee = 10'000;
  options.wait_for_sync = true;
  return options;
}

}  // namespace

TEST(test_validator_onboarding_selection_is_deterministic) {
  const auto dir = make_temp_dir("validator-onboarding-selection");
  std::string passphrase;
  const auto key = create_test_wallet(dir, &passphrase);
  storage::DB db;
  ASSERT_TRUE(db.open(dir.string()));
  put_spendable_p2pkh(db, key, 0x01, 3'000'000'000);
  put_spendable_p2pkh(db, key, 0x02, 2'000'000'000);
  put_spendable_p2pkh(db, key, 0x03, 1'500'000'000);
  const auto pkh = crypto::h160(Bytes(key.pubkey.begin(), key.pubkey.end()));
  const auto spendable = wallet::spendable_p2pkh_utxos_for_pubkey_hash(db, pkh);
  std::string err;
  const auto selection_a = wallet::select_deterministic_utxos(spendable, 5'000'010'000, &err);
  const auto selection_b = wallet::select_deterministic_utxos(spendable, 5'000'010'000, &err);
  ASSERT_TRUE(selection_a.has_value());
  ASSERT_TRUE(selection_b.has_value());
  ASSERT_EQ(selection_a->selected.size(), selection_b->selected.size());
  ASSERT_EQ(selection_a->selected[0].outpoint.txid, selection_b->selected[0].outpoint.txid);
  ASSERT_EQ(selection_a->selected[1].outpoint.txid, selection_b->selected[1].outpoint.txid);
}

TEST(test_validator_onboarding_waits_for_funds_and_reports_deficit) {
  const auto dir = make_temp_dir("validator-onboarding-funds");
  std::string passphrase;
  const auto key = create_test_wallet(dir, &passphrase);
  storage::DB db;
  ASSERT_TRUE(db.open(dir.string()));
  ASSERT_TRUE(db.set_tip(storage::TipState{100, Hash32{}}));
  ASSERT_TRUE(db.put_node_runtime_status_snapshot(ready_snapshot(100)));
  put_spendable_p2pkh(db, key, 0x11, 500'000'000);
  db.close();
  onboarding::ValidatorOnboardingService service;
  std::string err;
  const auto record = service.start_or_resume(make_options(dir, passphrase), &err);
  ASSERT_TRUE(record.has_value());
  ASSERT_EQ(record->state, onboarding::ValidatorOnboardingState::WAITING_FOR_FUNDS);
  ASSERT_EQ(record->last_deficit, record->required_amount - record->last_spendable_balance);
}

TEST(test_validator_onboarding_returns_active_immediately_when_validator_is_active) {
  const auto dir = make_temp_dir("validator-onboarding-active");
  std::string passphrase;
  const auto key = create_test_wallet(dir, &passphrase);
  storage::DB db;
  ASSERT_TRUE(db.open(dir.string()));
  ASSERT_TRUE(db.set_tip(storage::TipState{250, Hash32{}}));
  ASSERT_TRUE(db.put_node_runtime_status_snapshot(ready_snapshot(250)));
  consensus::ValidatorInfo info;
  info.status = consensus::ValidatorStatus::ACTIVE;
  info.joined_height = 100;
  info.has_bond = true;
  ASSERT_TRUE(db.put_validator(key.pubkey, info));
  db.close();
  onboarding::ValidatorOnboardingService service;
  std::string err;
  const auto record = service.start_or_resume(make_options(dir, passphrase), &err);
  ASSERT_TRUE(record.has_value());
  ASSERT_EQ(record->state, onboarding::ValidatorOnboardingState::ACTIVE);
}

TEST(test_validator_onboarding_resume_is_idempotent_for_same_validator) {
  const auto dir = make_temp_dir("validator-onboarding-resume");
  std::string passphrase;
  const auto key = create_test_wallet(dir, &passphrase);
  storage::DB db;
  ASSERT_TRUE(db.open(dir.string()));
  ASSERT_TRUE(db.set_tip(storage::TipState{300, Hash32{}}));
  ASSERT_TRUE(db.put_node_runtime_status_snapshot(ready_snapshot(300)));
  put_spendable_p2pkh(db, key, 0x21, 5'100'000'000);

  onboarding::ValidatorOnboardingRecord stored;
  stored.onboarding_id = "resume-test";
  stored.validator_pubkey = key.pubkey;
  stored.wallet_address = key.address;
  stored.wallet_pubkey_hex = hex_encode(Bytes(key.pubkey.begin(), key.pubkey.end()));
  stored.state = onboarding::ValidatorOnboardingState::WAITING_FOR_FINALIZATION;
  stored.requested_at_unix_ms = 1;
  stored.updated_at_unix_ms = 2;
  stored.wait_for_sync = true;
  stored.fee = 10'000;
  stored.bond_amount = BOND_AMOUNT;
  stored.required_amount = BOND_AMOUNT + 10'000;
  stored.readiness = ready_snapshot(300);
  Hash32 selected_txid{};
  selected_txid.fill(0x21);
  stored.selected_inputs.push_back(onboarding::ReservedInput{OutPoint{selected_txid, 0}, 5'100'000'000});
  stored.selected_inputs_reserved = true;
  stored.txid_hex = std::string(64, 'a');
  stored.broadcast_attempted_at_unix_ms = 10;
  stored.broadcast_outcome = onboarding::ValidatorOnboardingBroadcastOutcome::SENT;
  ASSERT_TRUE(db.put_validator_onboarding_record(key.pubkey, onboarding::ValidatorOnboardingService::serialize_record(stored)));
  db.close();

  onboarding::ValidatorOnboardingService service;
  std::string err;
  const auto record = service.start_or_resume(make_options(dir, passphrase), &err);
  ASSERT_TRUE(record.has_value());
  ASSERT_EQ(record->state, onboarding::ValidatorOnboardingState::WAITING_FOR_FINALIZATION);
  ASSERT_EQ(record->onboarding_id, "resume-test");
  ASSERT_EQ(record->txid_hex, std::string(64, 'a'));
}

TEST(test_validator_onboarding_broadcast_failure_transitions_to_failed) {
  const auto dir = make_temp_dir("validator-onboarding-broadcast-fail");
  std::string passphrase;
  const auto key = create_test_wallet(dir, &passphrase);
  storage::DB db;
  ASSERT_TRUE(db.open(dir.string()));
  ASSERT_TRUE(db.set_tip(storage::TipState{400, Hash32{}}));
  ASSERT_TRUE(db.put_node_runtime_status_snapshot(ready_snapshot(400)));
  put_spendable_p2pkh(db, key, 0x31, 60'000'000'000);
  db.close();

  auto options = make_options(dir, passphrase);
  options.rpc_url = "http://127.0.0.1:1/rpc";
  onboarding::ValidatorOnboardingService service;
  std::string err;
  const auto record = service.start_or_resume(options, &err);
  ASSERT_TRUE(record.has_value());
  ASSERT_EQ(record->state, onboarding::ValidatorOnboardingState::WAITING_FOR_FINALIZATION);
  ASSERT_EQ(record->broadcast_outcome, onboarding::ValidatorOnboardingBroadcastOutcome::AMBIGUOUS);
  ASSERT_TRUE(record->selected_inputs_reserved);
  ASSERT_TRUE(!record->tx_bytes.empty());
}

TEST(test_validator_onboarding_cancel_pre_broadcast_marks_cancelled) {
  const auto dir = make_temp_dir("validator-onboarding-cancel");
  std::string passphrase;
  const auto key = create_test_wallet(dir, &passphrase);
  storage::DB db;
  ASSERT_TRUE(db.open(dir.string()));
  onboarding::ValidatorOnboardingRecord stored;
  stored.onboarding_id = "cancel-test";
  stored.validator_pubkey = key.pubkey;
  stored.wallet_address = key.address;
  stored.wallet_pubkey_hex = hex_encode(Bytes(key.pubkey.begin(), key.pubkey.end()));
  stored.state = onboarding::ValidatorOnboardingState::BUILDING_JOIN_TX;
  stored.requested_at_unix_ms = 1;
  stored.updated_at_unix_ms = 2;
  stored.wait_for_sync = true;
  stored.fee = 10'000;
  stored.bond_amount = BOND_AMOUNT;
  stored.required_amount = BOND_AMOUNT + 10'000;
  stored.readiness = ready_snapshot(500);
  ASSERT_TRUE(db.put_validator_onboarding_record(key.pubkey, onboarding::ValidatorOnboardingService::serialize_record(stored)));
  db.close();

  onboarding::ValidatorOnboardingService service;
  std::string err;
  ASSERT_TRUE(service.cancel(make_options(dir, passphrase), &err));
  auto db_check = storage::DB{};
  ASSERT_TRUE(db_check.open(dir.string()));
  auto blob = db_check.get_validator_onboarding_record(key.pubkey);
  ASSERT_TRUE(blob.has_value());
  auto record = onboarding::ValidatorOnboardingService::parse_record(*blob);
  ASSERT_TRUE(record.has_value());
  ASSERT_EQ(record->state, onboarding::ValidatorOnboardingState::CANCELLED);
}

TEST(test_validator_onboarding_stale_readiness_fails_closed) {
  const auto dir = make_temp_dir("validator-onboarding-stale-readiness");
  std::string passphrase;
  const auto key = create_test_wallet(dir, &passphrase);
  storage::DB db;
  ASSERT_TRUE(db.open(dir.string()));
  ASSERT_TRUE(db.set_tip(storage::TipState{600, Hash32{}}));
  auto snapshot = ready_snapshot(600);
  snapshot.captured_at_unix_ms = 1;
  ASSERT_TRUE(db.put_node_runtime_status_snapshot(snapshot));
  put_spendable_p2pkh(db, key, 0x41, 5'100'000'000);
  db.close();

  onboarding::ValidatorOnboardingService service;
  std::string err;
  const auto record = service.start_or_resume(make_options(dir, passphrase), &err);
  ASSERT_TRUE(record.has_value());
  ASSERT_EQ(record->state, onboarding::ValidatorOnboardingState::WAITING_FOR_SYNC);
  ASSERT_EQ(record->last_error_code, "");
}

TEST(test_validator_onboarding_ambiguous_broadcast_resumes_same_attempt_without_rebuild) {
  const auto dir = make_temp_dir("validator-onboarding-ambiguous-resume");
  std::string passphrase;
  const auto key = create_test_wallet(dir, &passphrase);
  storage::DB db;
  ASSERT_TRUE(db.open(dir.string()));
  ASSERT_TRUE(db.set_tip(storage::TipState{700, Hash32{}}));
  ASSERT_TRUE(db.put_node_runtime_status_snapshot(ready_snapshot(700)));
  put_spendable_p2pkh(db, key, 0x51, 60'000'000'000);
  db.close();

  auto options = make_options(dir, passphrase);
  options.rpc_url = "http://127.0.0.1:1/rpc";
  onboarding::ValidatorOnboardingService service;
  std::string err;
  const auto first = service.start_or_resume(options, &err);
  ASSERT_TRUE(first.has_value());
  ASSERT_EQ(first->state, onboarding::ValidatorOnboardingState::WAITING_FOR_FINALIZATION);
  ASSERT_EQ(first->broadcast_outcome, onboarding::ValidatorOnboardingBroadcastOutcome::AMBIGUOUS);
  ASSERT_TRUE(first->selected_inputs_reserved);
  ASSERT_TRUE(!first->txid_hex.empty());
  ASSERT_TRUE(!first->tx_bytes.empty());
  const auto txid = first->txid_hex;
  const auto tx_bytes = first->tx_bytes;

  const auto second = service.start_or_resume(options, &err);
  ASSERT_TRUE(second.has_value());
  ASSERT_EQ(second->state, onboarding::ValidatorOnboardingState::WAITING_FOR_FINALIZATION);
  ASSERT_EQ(second->broadcast_outcome, onboarding::ValidatorOnboardingBroadcastOutcome::AMBIGUOUS);
  ASSERT_EQ(second->txid_hex, txid);
  ASSERT_EQ(second->tx_bytes, tx_bytes);
  ASSERT_TRUE(second->selected_inputs_reserved);
}

TEST(test_validator_onboarding_second_invocation_reuses_existing_record) {
  const auto dir = make_temp_dir("validator-onboarding-second-invocation");
  std::string passphrase;
  const auto key = create_test_wallet(dir, &passphrase);
  storage::DB db;
  ASSERT_TRUE(db.open(dir.string()));
  ASSERT_TRUE(db.set_tip(storage::TipState{800, Hash32{}}));
  ASSERT_TRUE(db.put_node_runtime_status_snapshot(ready_snapshot(800)));
  put_spendable_p2pkh(db, key, 0x61, 5'100'000'000);
  db.close();

  auto options = make_options(dir, passphrase);
  options.rpc_url = "http://127.0.0.1:1/rpc";
  onboarding::ValidatorOnboardingService service;
  std::string err;
  const auto first = service.start_or_resume(options, &err);
  ASSERT_TRUE(first.has_value());
  const auto second = service.start_or_resume(options, &err);
  ASSERT_TRUE(second.has_value());
  ASSERT_EQ(first->onboarding_id, second->onboarding_id);
  ASSERT_EQ(first->txid_hex, second->txid_hex);

  storage::DB db_check;
  ASSERT_TRUE(db_check.open(dir.string()));
  const auto records = db_check.load_validator_onboarding_records();
  ASSERT_EQ(records.size(), static_cast<std::size_t>(1));
}

void register_validator_onboarding_tests() {}
