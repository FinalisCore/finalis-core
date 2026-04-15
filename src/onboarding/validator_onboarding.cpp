#include "onboarding/validator_onboarding.hpp"

#include <ctime>
#include <filesystem>
#include <map>
#include <memory>
#include <mutex>

#include "address/address.hpp"
#include "codec/bytes.hpp"
#include "consensus/monetary.hpp"
#include "consensus/randomness.hpp"
#include "crypto/hash.hpp"
#include "keystore/validator_keystore.hpp"
#include "lightserver/client.hpp"
#include "utxo/signing.hpp"

namespace finalis::onboarding {
namespace {

using consensus::ValidatorStatus;

constexpr std::uint64_t kReadinessSnapshotFreshnessMs = 3'000;

std::mutex g_onboarding_lock_index_mu;
std::map<std::string, std::shared_ptr<std::mutex>> g_onboarding_locks;

std::uint64_t now_unix_ms() {
  return static_cast<std::uint64_t>(std::time(nullptr)) * 1000ULL;
}

std::string hex_pubkey(const PubKey32& pub) {
  return hex_encode(Bytes(pub.begin(), pub.end()));
}

std::shared_ptr<std::mutex> onboarding_lock_for_pubkey(const PubKey32& pub) {
  const auto key = hex_pubkey(pub);
  std::lock_guard<std::mutex> guard(g_onboarding_lock_index_mu);
  auto& slot = g_onboarding_locks[key];
  if (!slot) slot = std::make_shared<std::mutex>();
  return slot;
}

std::string make_onboarding_id(const PubKey32& pub) {
  const auto hash = crypto::sha256(Bytes(pub.begin(), pub.end()));
  return hex_encode(Bytes(hash.begin(), hash.begin() + 12));
}

bool readiness_snapshot_is_fresh(const storage::NodeRuntimeStatusSnapshot& snapshot, std::uint64_t now_ms) {
  if (snapshot.captured_at_unix_ms == 0 || snapshot.captured_at_unix_ms > now_ms) return false;
  return (now_ms - snapshot.captured_at_unix_ms) <= kReadinessSnapshotFreshnessMs;
}

bool readiness_snapshot_allows_registration(const storage::NodeRuntimeStatusSnapshot& snapshot, std::uint64_t now_ms,
                                            std::string* reason) {
  if (!readiness_snapshot_is_fresh(snapshot, now_ms)) {
    if (reason) *reason = "stale_runtime_snapshot";
    return false;
  }
  if (!snapshot.registration_ready) {
    if (reason) {
      *reason = snapshot.readiness_blockers_csv.empty() ? "registration readiness false" : snapshot.readiness_blockers_csv;
    }
    return false;
  }
  return true;
}

ValidatorOnboardingBroadcastOutcome onboarding_broadcast_outcome_from_lightserver(lightserver::BroadcastOutcome outcome) {
  switch (outcome) {
    case lightserver::BroadcastOutcome::Sent:
      return ValidatorOnboardingBroadcastOutcome::SENT;
    case lightserver::BroadcastOutcome::Rejected:
      return ValidatorOnboardingBroadcastOutcome::REJECTED;
    case lightserver::BroadcastOutcome::Ambiguous:
      return ValidatorOnboardingBroadcastOutcome::AMBIGUOUS;
  }
  return ValidatorOnboardingBroadcastOutcome::NONE;
}

bool broadcast_outcome_is_post_broadcast(ValidatorOnboardingBroadcastOutcome outcome) {
  return outcome == ValidatorOnboardingBroadcastOutcome::SENT ||
         outcome == ValidatorOnboardingBroadcastOutcome::REJECTED ||
         outcome == ValidatorOnboardingBroadcastOutcome::AMBIGUOUS;
}

Bytes serialize_runtime_snapshot(const storage::NodeRuntimeStatusSnapshot& snapshot) {
  codec::ByteWriter w;
  w.u8(snapshot.chain_id_ok ? 1 : 0);
  w.u8(snapshot.db_open ? 1 : 0);
  w.u64le(snapshot.local_finalized_height);
  w.u8(snapshot.observed_network_height_known ? 1 : 0);
  w.u64le(snapshot.observed_network_finalized_height);
  w.u64le(static_cast<std::uint64_t>(snapshot.healthy_peer_count));
  w.u64le(static_cast<std::uint64_t>(snapshot.established_peer_count));
  w.u64le(snapshot.finalized_lag);
  w.u8(snapshot.peer_height_disagreement ? 1 : 0);
  w.u8(snapshot.next_height_committee_available ? 1 : 0);
  w.u8(snapshot.next_height_proposer_available ? 1 : 0);
  w.u8(snapshot.bootstrap_sync_incomplete ? 1 : 0);
  w.u8(snapshot.registration_ready_preflight ? 1 : 0);
  w.u8(snapshot.registration_ready ? 1 : 0);
  w.u32le(snapshot.readiness_stable_samples);
  w.varbytes(Bytes(snapshot.readiness_blockers_csv.begin(), snapshot.readiness_blockers_csv.end()));
  w.u64le(snapshot.captured_at_unix_ms);
  return w.take();
}

std::optional<storage::NodeRuntimeStatusSnapshot> parse_runtime_snapshot(const Bytes& bytes) {
  storage::NodeRuntimeStatusSnapshot snapshot;
  if (!codec::parse_exact(bytes, [&](codec::ByteReader& r) {
        auto chain_ok = r.u8();
        auto db_open = r.u8();
        auto local_height = r.u64le();
        auto observed_known = r.u8();
        auto observed_height = r.u64le();
        auto healthy_peers = r.u64le();
        auto established_peers = r.u64le();
        auto lag = r.u64le();
        auto disagreement = r.u8();
        auto committee_available = r.u8();
        auto proposer_available = r.u8();
        auto bootstrap_incomplete = r.u8();
        auto ready_preflight = r.u8();
        auto ready = r.u8();
        auto stable_samples = r.u32le();
        auto blockers = r.varbytes();
        auto captured_at = r.u64le();
        if (!chain_ok || !db_open || !local_height || !observed_known || !observed_height || !healthy_peers ||
            !established_peers || !lag || !disagreement || !committee_available || !proposer_available ||
            !bootstrap_incomplete || !ready_preflight || !ready || !stable_samples || !blockers || !captured_at) {
          return false;
        }
        snapshot.chain_id_ok = (*chain_ok != 0);
        snapshot.db_open = (*db_open != 0);
        snapshot.local_finalized_height = *local_height;
        snapshot.observed_network_height_known = (*observed_known != 0);
        snapshot.observed_network_finalized_height = *observed_height;
        snapshot.healthy_peer_count = static_cast<std::size_t>(*healthy_peers);
        snapshot.established_peer_count = static_cast<std::size_t>(*established_peers);
        snapshot.finalized_lag = *lag;
        snapshot.peer_height_disagreement = (*disagreement != 0);
        snapshot.next_height_committee_available = (*committee_available != 0);
        snapshot.next_height_proposer_available = (*proposer_available != 0);
        snapshot.bootstrap_sync_incomplete = (*bootstrap_incomplete != 0);
        snapshot.registration_ready_preflight = (*ready_preflight != 0);
        snapshot.registration_ready = (*ready != 0);
        snapshot.readiness_stable_samples = *stable_samples;
        snapshot.readiness_blockers_csv = std::string(blockers->begin(), blockers->end());
        snapshot.captured_at_unix_ms = *captured_at;
        return true;
      })) {
    return std::nullopt;
  }
  return snapshot;
}

std::optional<keystore::ValidatorKey> load_key(const ValidatorOnboardingOptions& options, std::string* err) {
  keystore::ValidatorKey key;
  if (!keystore::load_validator_keystore(options.key_file, options.passphrase, &key, err)) return std::nullopt;
  return key;
}

bool open_db(const std::string& path, storage::DB* db, std::string* err) {
  if (!db->open(path)) {
    storage::DB readonly_probe;
    if (readonly_probe.open_readonly(path)) {
      readonly_probe.close();
      if (err) *err = "node database is locked by the running finalis-node process";
    } else {
      if (err) *err = "failed to open db";
    }
    return false;
  }
  return true;
}

bool open_db_readonly(const std::string& path, storage::DB* db, std::string* err) {
  if (!db->open_readonly(path)) {
    if (err) *err = "failed to open db";
    return false;
  }
  return true;
}

std::optional<ValidatorStatus> validator_status_from_string(const std::string& status) {
  if (status == "ONBOARDING") return ValidatorStatus::ONBOARDING;
  if (status == "PENDING") return ValidatorStatus::PENDING;
  if (status == "ACTIVE") return ValidatorStatus::ACTIVE;
  if (status == "EXITING") return ValidatorStatus::EXITING;
  if (status == "BANNED") return ValidatorStatus::BANNED;
  if (status == "SUSPENDED") return ValidatorStatus::SUSPENDED;
  return std::nullopt;
}

std::string validator_status_name(const std::optional<consensus::ValidatorInfo>& info) {
  if (!info.has_value()) return "NOT_REGISTERED";
  switch (info->status) {
    case ValidatorStatus::ONBOARDING:
      return "ONBOARDING";
    case ValidatorStatus::PENDING:
      return "PENDING";
    case ValidatorStatus::ACTIVE:
      return "ACTIVE";
    case ValidatorStatus::EXITING:
      return "EXITING";
    case ValidatorStatus::BANNED:
      return "BANNED";
    case ValidatorStatus::SUSPENDED:
      return "SUSPENDED";
  }
  return "UNKNOWN";
}

std::optional<ValidatorJoinRequest> find_join_request_for_pubkey(const std::map<Hash32, ValidatorJoinRequest>& requests,
                                                                 const PubKey32& pub) {
  for (const auto& [_, req] : requests) {
    if (req.validator_pubkey == pub) return req;
  }
  return std::nullopt;
}

bool state_holds_reservation(ValidatorOnboardingState state) {
  return state == ValidatorOnboardingState::SELECTING_UTXOS || state == ValidatorOnboardingState::BUILDING_JOIN_TX ||
         state == ValidatorOnboardingState::BROADCASTING_JOIN_TX ||
         state == ValidatorOnboardingState::WAITING_FOR_FINALIZATION ||
         state == ValidatorOnboardingState::PENDING_ACTIVATION;
}

bool state_is_live_attempt(ValidatorOnboardingState state) {
  return !validator_onboarding_state_terminal(state);
}

void set_error(ValidatorOnboardingRecord* record, const std::string& code, const std::string& message) {
  record->last_error_code = code;
  record->last_error_message = message;
  record->updated_at_unix_ms = now_unix_ms();
}

bool persist_record(storage::DB& db, const ValidatorOnboardingRecord& record, std::string* err) {
  if (!db.put_validator_onboarding_record(record.validator_pubkey, ValidatorOnboardingService::serialize_record(record))) {
    if (err) *err = "failed to persist onboarding record";
    return false;
  }
  return true;
}

std::size_t active_operator_count_for_onboarding(const NetworkConfig& network,
                                                 const std::map<PubKey32, consensus::ValidatorInfo>& validators,
                                                 std::uint64_t height) {
  consensus::ValidatorRegistry registry;
  registry.set_rules(consensus::ValidatorRules{
      .min_bond = consensus::validator_min_bond_units(network, height, validators.size()),
      .warmup_blocks = network.validator_warmup_blocks,
      .cooldown_blocks = network.validator_cooldown_blocks,
  });
  for (const auto& [pub, info] : validators) registry.upsert(pub, info);
  std::set<PubKey32> operators;
  for (const auto& pub : registry.active_sorted(height)) {
    auto it = validators.find(pub);
    if (it == validators.end()) continue;
    operators.insert(consensus::canonical_operator_id(pub, it->second));
  }
  return operators.size();
}

std::uint64_t registration_bond_amount_for_onboarding(const NetworkConfig& network, storage::DB& db,
                                                      std::uint64_t planning_height) {
  const auto validators = db.load_validators();
  const auto active_operator_count = active_operator_count_for_onboarding(network, validators, planning_height);
  return std::max<std::uint64_t>(network.validator_bond_min_amount,
                                 consensus::validator_min_bond_units(network, planning_height, active_operator_count));
}

std::uint64_t eligibility_bond_amount_for_onboarding(const NetworkConfig& network, storage::DB& db,
                                                     std::uint64_t planning_height, std::uint64_t registration_bond_amount) {
  const auto epoch_start = consensus::committee_epoch_start(std::max<std::uint64_t>(1, planning_height), network.committee_epoch_blocks);
  if (auto checkpoint = db.get_finalized_committee_checkpoint(epoch_start); checkpoint.has_value() &&
      checkpoint->adaptive_min_bond != 0) {
    return std::max<std::uint64_t>(registration_bond_amount, checkpoint->adaptive_min_bond);
  }
  return registration_bond_amount;
}

std::set<OutPoint> reserved_outpoints_except(const storage::DB& db, const PubKey32& owner_pubkey) {
  return ValidatorOnboardingService::reserved_outpoints(db, owner_pubkey);
}

}  // namespace

std::string validator_onboarding_state_name(ValidatorOnboardingState state) {
  switch (state) {
    case ValidatorOnboardingState::IDLE:
      return "idle";
    case ValidatorOnboardingState::CHECKING_PREREQS:
      return "checking_prereqs";
    case ValidatorOnboardingState::WAITING_FOR_SYNC:
      return "waiting_for_sync";
    case ValidatorOnboardingState::WAITING_FOR_FUNDS:
      return "waiting_for_funds";
    case ValidatorOnboardingState::SELECTING_UTXOS:
      return "selecting_utxos";
    case ValidatorOnboardingState::BUILDING_JOIN_TX:
      return "building_join_tx";
    case ValidatorOnboardingState::BROADCASTING_JOIN_TX:
      return "broadcasting_join_tx";
    case ValidatorOnboardingState::WAITING_FOR_FINALIZATION:
      return "waiting_for_finalization";
    case ValidatorOnboardingState::PENDING_ACTIVATION:
      return "pending_activation";
    case ValidatorOnboardingState::ACTIVE:
      return "active";
    case ValidatorOnboardingState::FAILED:
      return "failed";
    case ValidatorOnboardingState::CANCELLED:
      return "cancelled";
  }
  return "unknown";
}

bool validator_onboarding_state_terminal(ValidatorOnboardingState state) {
  return state == ValidatorOnboardingState::ACTIVE || state == ValidatorOnboardingState::FAILED ||
         state == ValidatorOnboardingState::CANCELLED;
}

bool validator_onboarding_state_pre_broadcast(ValidatorOnboardingState state) {
  return state == ValidatorOnboardingState::IDLE || state == ValidatorOnboardingState::CHECKING_PREREQS ||
         state == ValidatorOnboardingState::WAITING_FOR_SYNC || state == ValidatorOnboardingState::WAITING_FOR_FUNDS ||
         state == ValidatorOnboardingState::SELECTING_UTXOS || state == ValidatorOnboardingState::BUILDING_JOIN_TX;
}

std::optional<std::string> infer_node_db_path_from_wallet_file(const std::string& wallet_file) {
  std::filesystem::path p(wallet_file);
  if (p.parent_path().filename() != "keystore") return std::nullopt;
  auto db_path = p.parent_path().parent_path();
  if (db_path.empty()) return std::nullopt;
  return db_path.string();
}

Bytes ValidatorOnboardingService::serialize_record(const ValidatorOnboardingRecord& record) {
  codec::ByteWriter w;
  w.varbytes(Bytes(record.onboarding_id.begin(), record.onboarding_id.end()));
  w.bytes_fixed(record.validator_pubkey);
  w.varbytes(Bytes(record.wallet_address.begin(), record.wallet_address.end()));
  w.varbytes(Bytes(record.wallet_pubkey_hex.begin(), record.wallet_pubkey_hex.end()));
  w.u8(static_cast<std::uint8_t>(record.state));
  w.u64le(record.requested_at_unix_ms);
  w.u64le(record.updated_at_unix_ms);
  w.u8(record.wait_for_sync ? 1 : 0);
  w.u8(record.tracking_detached ? 1 : 0);
  w.u64le(record.fee);
  w.u64le(record.bond_amount);
  w.u64le(record.required_amount);
  w.u64le(record.last_spendable_balance);
  w.u64le(record.last_deficit);
  w.varbytes(serialize_runtime_snapshot(record.readiness));
  w.varint(record.selected_inputs.size());
  for (const auto& input : record.selected_inputs) {
    w.bytes_fixed(input.outpoint.txid);
    w.u32le(input.outpoint.index);
    w.u64le(input.amount);
  }
  w.u8(record.selected_inputs_reserved ? 1 : 0);
  w.varbytes(Bytes(record.txid_hex.begin(), record.txid_hex.end()));
  w.varbytes(record.tx_bytes);
  w.u64le(record.broadcast_attempted_at_unix_ms);
  w.u8(static_cast<std::uint8_t>(record.broadcast_outcome));
  w.varbytes(Bytes(record.broadcast_result.begin(), record.broadcast_result.end()));
  w.varbytes(Bytes(record.rpc_endpoint.begin(), record.rpc_endpoint.end()));
  w.u64le(record.finalized_height);
  w.varbytes(Bytes(record.validator_status.begin(), record.validator_status.end()));
  w.u64le(record.activation_height);
  w.varbytes(Bytes(record.last_error_code.begin(), record.last_error_code.end()));
  w.varbytes(Bytes(record.last_error_message.begin(), record.last_error_message.end()));
  return w.take();
}

std::optional<ValidatorOnboardingRecord> ValidatorOnboardingService::parse_record(const Bytes& bytes) {
  ValidatorOnboardingRecord record;
  if (!codec::parse_exact(bytes, [&](codec::ByteReader& r) {
        auto onboarding_id = r.varbytes();
        auto validator_pubkey = r.bytes_fixed<32>();
        auto wallet_address = r.varbytes();
        auto wallet_pubkey_hex = r.varbytes();
        auto state = r.u8();
        auto requested_at = r.u64le();
        auto updated_at = r.u64le();
        auto wait_for_sync = r.u8();
        auto tracking_detached = r.u8();
        auto fee = r.u64le();
        auto bond_amount = r.u64le();
        auto required_amount = r.u64le();
        auto last_spendable_balance = r.u64le();
        auto last_deficit = r.u64le();
        auto readiness_bytes = r.varbytes();
        auto selected_count = r.varint();
        if (!onboarding_id || !validator_pubkey || !wallet_address || !wallet_pubkey_hex || !state || !requested_at ||
            !updated_at || !wait_for_sync || !tracking_detached || !fee || !bond_amount || !required_amount ||
            !last_spendable_balance || !last_deficit || !readiness_bytes || !selected_count) {
          return false;
        }
        auto readiness = parse_runtime_snapshot(*readiness_bytes);
        if (!readiness.has_value()) return false;
        record.onboarding_id = std::string(onboarding_id->begin(), onboarding_id->end());
        record.validator_pubkey = *validator_pubkey;
        record.wallet_address = std::string(wallet_address->begin(), wallet_address->end());
        record.wallet_pubkey_hex = std::string(wallet_pubkey_hex->begin(), wallet_pubkey_hex->end());
        record.state = static_cast<ValidatorOnboardingState>(*state);
        record.requested_at_unix_ms = *requested_at;
        record.updated_at_unix_ms = *updated_at;
        record.wait_for_sync = (*wait_for_sync != 0);
        record.tracking_detached = (*tracking_detached != 0);
        record.fee = *fee;
        record.bond_amount = *bond_amount;
        record.required_amount = *required_amount;
        record.last_spendable_balance = *last_spendable_balance;
        record.last_deficit = *last_deficit;
        record.readiness = *readiness;
        record.selected_inputs.clear();
        for (std::uint64_t i = 0; i < *selected_count; ++i) {
          auto txid = r.bytes_fixed<32>();
          auto index = r.u32le();
          auto amount = r.u64le();
          if (!txid || !index || !amount) return false;
          record.selected_inputs.push_back(ReservedInput{OutPoint{*txid, *index}, *amount});
        }
        auto selected_reserved = r.u8();
        auto txid_hex = r.varbytes();
        auto tx_bytes = r.varbytes();
        auto broadcast_attempted = r.u64le();
        auto broadcast_outcome = r.u8();
        auto broadcast_result = r.varbytes();
        auto rpc_endpoint = r.varbytes();
        auto finalized_height = r.u64le();
        auto validator_status = r.varbytes();
        auto activation_height = r.u64le();
        auto last_error_code = r.varbytes();
        auto last_error_message = r.varbytes();
        if (!selected_reserved || !txid_hex || !tx_bytes || !broadcast_attempted || !broadcast_outcome ||
            !broadcast_result || !rpc_endpoint || !finalized_height || !validator_status || !activation_height ||
            !last_error_code || !last_error_message) {
          return false;
        }
        record.selected_inputs_reserved = (*selected_reserved != 0);
        record.txid_hex = std::string(txid_hex->begin(), txid_hex->end());
        record.tx_bytes = *tx_bytes;
        record.broadcast_attempted_at_unix_ms = *broadcast_attempted;
        switch (*broadcast_outcome) {
          case 0:
            record.broadcast_outcome = ValidatorOnboardingBroadcastOutcome::NONE;
            break;
          case 1:
            record.broadcast_outcome = ValidatorOnboardingBroadcastOutcome::SENT;
            break;
          case 2:
            record.broadcast_outcome = ValidatorOnboardingBroadcastOutcome::REJECTED;
            break;
          case 3:
            record.broadcast_outcome = ValidatorOnboardingBroadcastOutcome::AMBIGUOUS;
            break;
          default:
            return false;
        }
        record.broadcast_result = std::string(broadcast_result->begin(), broadcast_result->end());
        record.rpc_endpoint = std::string(rpc_endpoint->begin(), rpc_endpoint->end());
        record.finalized_height = *finalized_height;
        record.validator_status = std::string(validator_status->begin(), validator_status->end());
        record.activation_height = *activation_height;
        record.last_error_code = std::string(last_error_code->begin(), last_error_code->end());
        record.last_error_message = std::string(last_error_message->begin(), last_error_message->end());
        return true;
      })) {
    return std::nullopt;
  }
  return record;
}

std::set<OutPoint> ValidatorOnboardingService::reserved_outpoints(const storage::DB& db, const PubKey32& owner_pubkey) {
  std::set<OutPoint> out;
  for (const auto& [pub, blob] : db.load_validator_onboarding_records()) {
    if (pub == owner_pubkey) continue;
    auto parsed = parse_record(blob);
    if (!parsed.has_value()) continue;
    if (!state_is_live_attempt(parsed->state)) continue;
    if (!parsed->selected_inputs_reserved || !state_holds_reservation(parsed->state)) continue;
    for (const auto& input : parsed->selected_inputs) out.insert(input.outpoint);
  }
  return out;
}

std::optional<ValidatorOnboardingRecord> ValidatorOnboardingService::status(const ValidatorOnboardingOptions& options,
                                                                            std::string* err) const {
  auto key = load_key(options, err);
  if (!key) return std::nullopt;
  auto onboarding_mu = onboarding_lock_for_pubkey(key->pubkey);
  std::lock_guard<std::mutex> guard(*onboarding_mu);
  storage::DB db;
  if (!open_db_readonly(options.db_path, &db, err)) return std::nullopt;
  auto existing = db.get_validator_onboarding_record(key->pubkey);
  const auto tip = db.get_tip();
  const std::uint64_t planning_height = tip ? (tip->height + 1) : 0;
  const std::uint64_t bond_amount = registration_bond_amount_for_onboarding(mainnet_network(), db, planning_height);
  const std::uint64_t eligibility_bond_amount =
      eligibility_bond_amount_for_onboarding(mainnet_network(), db, planning_height, bond_amount);
  if (!existing.has_value()) {
    ValidatorOnboardingRecord record;
    record.onboarding_id = make_onboarding_id(key->pubkey);
    record.validator_pubkey = key->pubkey;
    record.wallet_address = key->address;
    record.wallet_pubkey_hex = hex_pubkey(key->pubkey);
    record.state = ValidatorOnboardingState::IDLE;
    record.fee = options.fee;
    record.bond_amount = bond_amount;
    record.eligibility_bond_amount = eligibility_bond_amount;
    record.required_amount = bond_amount + options.fee;
    record.wait_for_sync = options.wait_for_sync;
    return record;
  }
  return parse_record(*existing);
}

std::optional<ValidatorOnboardingRecord> ValidatorOnboardingService::start_or_resume(
    const ValidatorOnboardingOptions& options, std::string* err) const {
  auto key = load_key(options, err);
  if (!key) return std::nullopt;
  auto onboarding_mu = onboarding_lock_for_pubkey(key->pubkey);
  std::lock_guard<std::mutex> guard(*onboarding_mu);
  storage::DB db;
  if (!open_db(options.db_path, &db, err)) return std::nullopt;
  ValidatorOnboardingRecord record;
  const auto tip = db.get_tip();
  const std::uint64_t planning_height = tip ? (tip->height + 1) : 0;
  const std::uint64_t bond_amount = registration_bond_amount_for_onboarding(mainnet_network(), db, planning_height);
  const std::uint64_t eligibility_bond_amount =
      eligibility_bond_amount_for_onboarding(mainnet_network(), db, planning_height, bond_amount);
  if (auto existing = db.get_validator_onboarding_record(key->pubkey); existing.has_value()) {
    auto parsed = parse_record(*existing);
    if (!parsed.has_value()) {
      if (err) *err = "failed to parse stored onboarding record";
      return std::nullopt;
    }
    record = *parsed;
  } else {
    record.onboarding_id = make_onboarding_id(key->pubkey);
    record.validator_pubkey = key->pubkey;
    record.wallet_address = key->address;
    record.wallet_pubkey_hex = hex_pubkey(key->pubkey);
    record.state = ValidatorOnboardingState::CHECKING_PREREQS;
    record.requested_at_unix_ms = now_unix_ms();
    record.updated_at_unix_ms = record.requested_at_unix_ms;
    record.fee = options.fee;
    record.bond_amount = bond_amount;
    record.eligibility_bond_amount = eligibility_bond_amount;
    record.required_amount = bond_amount + options.fee;
    record.wait_for_sync = options.wait_for_sync;
  }
  return advance(options, db, record, err);
}

std::optional<ValidatorOnboardingRecord> ValidatorOnboardingService::poll(const ValidatorOnboardingOptions& options,
                                                                          std::string* err) const {
  auto key = load_key(options, err);
  if (!key) return std::nullopt;
  storage::DB db;
  if (!open_db(options.db_path, &db, err)) return std::nullopt;
  auto existing = db.get_validator_onboarding_record(key->pubkey);
  if (!existing.has_value()) return status(options, err);
  auto parsed = parse_record(*existing);
  if (!parsed.has_value()) {
    if (err) *err = "failed to parse stored onboarding record";
    return std::nullopt;
  }
  return advance(options, db, *parsed, err);
}

bool ValidatorOnboardingService::cancel(const ValidatorOnboardingOptions& options, std::string* err) const {
  auto key = load_key(options, err);
  if (!key) return false;
  auto onboarding_mu = onboarding_lock_for_pubkey(key->pubkey);
  std::lock_guard<std::mutex> guard(*onboarding_mu);
  storage::DB db;
  if (!open_db(options.db_path, &db, err)) return false;
  auto existing = db.get_validator_onboarding_record(key->pubkey);
  if (!existing.has_value()) {
    if (err) *err = "no onboarding record";
    return false;
  }
  auto parsed = parse_record(*existing);
  if (!parsed.has_value()) {
    if (err) *err = "failed to parse stored onboarding record";
    return false;
  }
  auto record = *parsed;
  const bool pre_broadcast_cancel =
      validator_onboarding_state_pre_broadcast(record.state) ||
      (record.state == ValidatorOnboardingState::BROADCASTING_JOIN_TX && record.broadcast_attempted_at_unix_ms == 0);
  if (pre_broadcast_cancel) {
    record.state = ValidatorOnboardingState::CANCELLED;
    record.selected_inputs.clear();
    record.selected_inputs_reserved = false;
    record.tx_bytes.clear();
    record.txid_hex.clear();
    record.updated_at_unix_ms = now_unix_ms();
    return persist_record(db, record, err);
  }
  record.tracking_detached = true;
  record.updated_at_unix_ms = now_unix_ms();
  return persist_record(db, record, err);
}

std::optional<ValidatorOnboardingRecord> ValidatorOnboardingService::advance(const ValidatorOnboardingOptions& options,
                                                                             storage::DB& db,
                                                                             ValidatorOnboardingRecord record,
                                                                             std::string* err) const {
  auto key = load_key(options, err);
  if (!key) return std::nullopt;

  const auto own_pkh = crypto::h160(Bytes(key->pubkey.begin(), key->pubkey.end()));
  std::string build_err;
  for (int step = 0; step < 16; ++step) {
    record.updated_at_unix_ms = now_unix_ms();
    record.fee = options.fee;
    const auto tip = db.get_tip();
    const std::uint64_t planning_height = tip ? (tip->height + 1) : 0;
    const std::uint64_t bond_amount = registration_bond_amount_for_onboarding(mainnet_network(), db, planning_height);
    record.bond_amount = bond_amount;
    record.eligibility_bond_amount =
        eligibility_bond_amount_for_onboarding(mainnet_network(), db, planning_height, bond_amount);
    record.required_amount = bond_amount + options.fee;
    record.wait_for_sync = options.wait_for_sync;

    const auto validators = db.load_validators();
    const auto join_requests = db.load_validator_join_requests();
    const auto info_it = validators.find(key->pubkey);
    const std::optional<consensus::ValidatorInfo> validator_info =
        (info_it == validators.end()) ? std::nullopt : std::optional<consensus::ValidatorInfo>(info_it->second);
    record.validator_status = validator_status_name(validator_info);
    if (validator_info.has_value() && validator_info->status == ValidatorStatus::ACTIVE) {
      record.state = ValidatorOnboardingState::ACTIVE;
      record.activation_height = validator_info->joined_height;
      record.finalized_height = db.get_tip().has_value() ? db.get_tip()->height : 0;
      record.selected_inputs_reserved = false;
      record.last_error_code.clear();
      record.last_error_message.clear();
      (void)persist_record(db, record, err);
      return record;
    }
    if (validator_info.has_value() && validator_info->status == ValidatorStatus::PENDING) {
      record.state = ValidatorOnboardingState::PENDING_ACTIVATION;
      record.activation_height = validator_info->joined_height + mainnet_network().validator_warmup_blocks;
      record.finalized_height = db.get_tip().has_value() ? db.get_tip()->height : 0;
      record.selected_inputs_reserved = false;
      (void)persist_record(db, record, err);
      return record;
    }

    switch (record.state) {
      case ValidatorOnboardingState::IDLE:
        record.state = ValidatorOnboardingState::CHECKING_PREREQS;
        continue;

      case ValidatorOnboardingState::CHECKING_PREREQS: {
        std::string readiness_err;
        auto readiness = db.get_node_runtime_status_snapshot();
        if (!readiness.has_value()) {
          record.readiness = {};
          record.state = options.wait_for_sync ? ValidatorOnboardingState::WAITING_FOR_SYNC
                                               : ValidatorOnboardingState::FAILED;
          set_error(&record, "node_not_ready", "runtime readiness snapshot unavailable");
          if (record.state == ValidatorOnboardingState::WAITING_FOR_SYNC) {
            record.last_error_code.clear();
            record.last_error_message.clear();
          }
          (void)persist_record(db, record, err);
          return record;
        }
        record.readiness = *readiness;
        if (!readiness_snapshot_allows_registration(*readiness, record.updated_at_unix_ms, &readiness_err)) {
          if (options.wait_for_sync) {
            record.state = ValidatorOnboardingState::WAITING_FOR_SYNC;
            record.last_error_code.clear();
            record.last_error_message.clear();
            record.broadcast_result.clear();
            (void)persist_record(db, record, err);
            return record;
          }
          record.state = ValidatorOnboardingState::FAILED;
          set_error(&record, "node_not_ready", readiness_err);
          (void)persist_record(db, record, err);
          return record;
        }
        const auto reserved = reserved_outpoints_except(db, key->pubkey);
        const auto spendable = wallet::spendable_p2pkh_utxos_for_pubkey_hash(db, own_pkh, &reserved);
        record.last_spendable_balance = 0;
        for (const auto& utxo : spendable) record.last_spendable_balance += utxo.prevout.value;
        record.last_deficit =
            record.last_spendable_balance >= record.required_amount ? 0 : record.required_amount - record.last_spendable_balance;
        if (record.last_spendable_balance < record.required_amount) {
          record.state = ValidatorOnboardingState::WAITING_FOR_FUNDS;
          record.last_error_code.clear();
          record.last_error_message.clear();
          (void)persist_record(db, record, err);
          return record;
        }
        record.state = ValidatorOnboardingState::SELECTING_UTXOS;
        continue;
      }

      case ValidatorOnboardingState::WAITING_FOR_SYNC: {
        std::string readiness_err;
        auto readiness = db.get_node_runtime_status_snapshot();
        if (!readiness.has_value()) {
          record.readiness = {};
          (void)persist_record(db, record, err);
          return record;
        }
        record.readiness = *readiness;
        if (readiness_snapshot_allows_registration(*readiness, record.updated_at_unix_ms, &readiness_err)) {
          record.state = ValidatorOnboardingState::CHECKING_PREREQS;
          continue;
        }
        (void)persist_record(db, record, err);
        return record;
      }

      case ValidatorOnboardingState::WAITING_FOR_FUNDS:
        record.state = ValidatorOnboardingState::CHECKING_PREREQS;
        continue;

      case ValidatorOnboardingState::SELECTING_UTXOS: {
        const auto reserved = reserved_outpoints_except(db, key->pubkey);
        const auto spendable = wallet::spendable_p2pkh_utxos_for_pubkey_hash(db, own_pkh, &reserved);
        auto selection = wallet::select_deterministic_utxos(spendable, record.required_amount, &build_err);
        if (!selection.has_value()) {
          record.state = ValidatorOnboardingState::FAILED;
          set_error(&record, "selection_failed", build_err);
          (void)persist_record(db, record, err);
          return record;
        }
        record.selected_inputs.clear();
        for (const auto& utxo : selection->selected) {
          record.selected_inputs.push_back(ReservedInput{utxo.outpoint, utxo.prevout.value});
        }
        record.selected_inputs_reserved = true;
        record.state = ValidatorOnboardingState::BUILDING_JOIN_TX;
        continue;
      }

      case ValidatorOnboardingState::BUILDING_JOIN_TX: {
        if (record.selected_inputs.empty()) {
          record.state = ValidatorOnboardingState::FAILED;
          set_error(&record, "selection_failed", "no reserved inputs available");
          (void)persist_record(db, record, err);
          return record;
        }
        std::vector<std::pair<OutPoint, TxOut>> prevs;
        prevs.reserve(record.selected_inputs.size());
        for (const auto& input : record.selected_inputs) {
          if (!db.get(storage::key_utxo(input.outpoint)).has_value()) {
            record.state = ValidatorOnboardingState::FAILED;
            set_error(&record, "reserved_input_unavailable", "reserved input spent before build");
            record.selected_inputs_reserved = false;
            (void)persist_record(db, record, err);
            return record;
          }
          prevs.push_back({input.outpoint, TxOut{input.amount, address::p2pkh_script_pubkey(own_pkh)}});
        }
        auto own_address = address::decode(key->address);
        if (!own_address.has_value()) {
          record.state = ValidatorOnboardingState::FAILED;
          set_error(&record, "build_failed", "invalid wallet address");
          record.selected_inputs_reserved = false;
          (void)persist_record(db, record, err);
          return record;
        }
        auto tx = build_validator_join_request_tx(prevs, Bytes(key->privkey.begin(), key->privkey.end()), key->pubkey,
                                                  Bytes(key->privkey.begin(), key->privkey.end()), key->pubkey,
                                                  record.bond_amount, record.fee,
                                                  address::p2pkh_script_pubkey(own_address->pubkey_hash), &build_err);
        if (!tx.has_value()) {
          record.state = ValidatorOnboardingState::FAILED;
          set_error(&record, "build_failed", build_err);
          record.selected_inputs_reserved = false;
          (void)persist_record(db, record, err);
          return record;
        }
        record.tx_bytes = tx->serialize();
        record.txid_hex = hex_encode32(tx->txid());
        record.broadcast_outcome = ValidatorOnboardingBroadcastOutcome::NONE;
        record.broadcast_result.clear();
        record.state = ValidatorOnboardingState::BROADCASTING_JOIN_TX;
        continue;
      }

      case ValidatorOnboardingState::BROADCASTING_JOIN_TX: {
        if (record.broadcast_attempted_at_unix_ms == 0) {
          if (record.tx_bytes.empty()) {
            record.state = ValidatorOnboardingState::FAILED;
            set_error(&record, "broadcast_failed", "missing built transaction bytes");
            record.selected_inputs_reserved = false;
            (void)persist_record(db, record, err);
            return record;
          }
          std::string rpc_err;
          auto result = lightserver::rpc_broadcast_tx(options.rpc_url, record.tx_bytes, &rpc_err);
          record.broadcast_attempted_at_unix_ms = now_unix_ms();
          record.broadcast_outcome = onboarding_broadcast_outcome_from_lightserver(result.outcome);
          record.broadcast_result = !result.error.empty() ? result.error : rpc_err;
          record.rpc_endpoint = options.rpc_url;
          if (!result.txid_hex.empty()) record.txid_hex = result.txid_hex;
          if (result.outcome == lightserver::BroadcastOutcome::Rejected) {
            record.state = ValidatorOnboardingState::FAILED;
            set_error(&record, "tx_rejected", result.error.empty() ? "broadcast rejected" : result.error);
            (void)persist_record(db, record, err);
            return record;
          }
        }
        if (!broadcast_outcome_is_post_broadcast(record.broadcast_outcome)) {
          record.state = ValidatorOnboardingState::FAILED;
          set_error(&record, "broadcast_failed", "missing post-broadcast outcome");
          (void)persist_record(db, record, err);
          return record;
        }
        record.state = ValidatorOnboardingState::WAITING_FOR_FINALIZATION;
        (void)persist_record(db, record, err);
        return record;
      }

      case ValidatorOnboardingState::WAITING_FOR_FINALIZATION: {
        if (!record.txid_hex.empty()) {
          auto txid = hex_decode(record.txid_hex);
          if (txid.has_value() && txid->size() == 32) {
            Hash32 tx_hash{};
            std::copy(txid->begin(), txid->end(), tx_hash.begin());
            if (auto loc = db.get_tx_index(tx_hash); loc.has_value()) record.finalized_height = loc->height;
          }
        }
        if (find_join_request_for_pubkey(join_requests, key->pubkey).has_value()) {
          record.state = ValidatorOnboardingState::PENDING_ACTIVATION;
          (void)persist_record(db, record, err);
          return record;
        }
        (void)persist_record(db, record, err);
        return record;
      }

      case ValidatorOnboardingState::PENDING_ACTIVATION:
        (void)persist_record(db, record, err);
        return record;

      case ValidatorOnboardingState::ACTIVE:
      case ValidatorOnboardingState::FAILED:
      case ValidatorOnboardingState::CANCELLED:
        (void)persist_record(db, record, err);
        return record;
    }
  }

  record.state = ValidatorOnboardingState::FAILED;
  set_error(&record, "internal_error", "state machine iteration limit reached");
  (void)persist_record(db, record, err);
  return record;
}

}  // namespace finalis::onboarding
