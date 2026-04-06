#include "lightserver/server.hpp"

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <ctime>
#include <cstring>
#include <iostream>
#include <map>
#include <regex>
#include <set>
#include <sstream>

#include "address/address.hpp"
#include "consensus/ingress.hpp"
#include "codec/bytes.hpp"
#include "common/minijson.hpp"
#include "common/paths.hpp"
#include "common/version.hpp"
#include "consensus/epoch_tickets.hpp"
#include "consensus/finalized_committee.hpp"
#include "consensus/frontier_execution.hpp"
#include "consensus/randomness.hpp"
#include "consensus/state_commitment.hpp"
#include "consensus/validator_registry.hpp"
#include "crypto/hash.hpp"
#include "crypto/smt.hpp"
#include "genesis/genesis.hpp"
#include "keystore/validator_keystore.hpp"
#include "onboarding/validator_onboarding.hpp"
#include "p2p/framing.hpp"
#include "p2p/messages.hpp"
#include "utxo/validate.hpp"
#include "utxo/signing.hpp"
#include "wallet/utxo_selection.hpp"

namespace finalis::lightserver {
namespace {

constexpr std::size_t kMaxHttpHeaderBytes = 16 * 1024;
constexpr std::size_t kMaxRpcBodyBytes = 256 * 1024;

std::vector<storage::DB::ScriptUtxoEntry> reconciled_script_utxos(const storage::DB& db, const Hash32& scripthash) {
  const auto indexed_entries = db.get_script_utxos(scripthash);
  const auto canonical_utxos = db.load_utxos();
  std::map<OutPoint, TxOut> canonical_matches;
  for (const auto& [op, entry] : canonical_utxos) {
    if (crypto::sha256(entry.out.script_pubkey) != scripthash) continue;
    canonical_matches.emplace(op, entry.out);
  }

  std::vector<storage::DB::ScriptUtxoEntry> out;
  out.reserve(std::max(indexed_entries.size(), canonical_matches.size()));
  std::set<OutPoint> seen;
  for (const auto& entry : indexed_entries) {
    const auto canonical_it = canonical_matches.find(entry.outpoint);
    if (canonical_it == canonical_matches.end()) continue;
    if (canonical_it->second.value != entry.value || canonical_it->second.script_pubkey != entry.script_pubkey) continue;
    storage::DB::ScriptUtxoEntry merged = entry;
    if (auto loc = db.get_tx_index(entry.outpoint.txid); loc.has_value()) merged.height = loc->height;
    out.push_back(std::move(merged));
    seen.insert(entry.outpoint);
  }
  for (const auto& [op, prevout] : canonical_matches) {
    if (seen.find(op) != seen.end()) continue;
    storage::DB::ScriptUtxoEntry merged;
    merged.outpoint = op;
    merged.value = prevout.value;
    merged.script_pubkey = prevout.script_pubkey;
    if (auto loc = db.get_tx_index(op.txid); loc.has_value()) merged.height = loc->height;
    out.push_back(std::move(merged));
  }
  std::sort(out.begin(), out.end(), [](const auto& a, const auto& b) {
    if (a.height != b.height) return a.height < b.height;
    return std::tie(a.outpoint.txid, a.outpoint.index) < std::tie(b.outpoint.txid, b.outpoint.index);
  });
  return out;
}

std::string json_escape(const std::string& in) {
  std::string out;
  out.reserve(in.size() + 8);
  for (char c : in) {
    if (c == '"' || c == '\\') {
      out.push_back('\\');
      out.push_back(c);
    } else if (c == '\n') {
      out += "\\n";
    } else {
      out.push_back(c);
    }
  }
  return out;
}

std::optional<Hash32> parse_hex32(const std::string& s) {
  auto b = hex_decode(s);
  if (!b.has_value() || b->size() != 32) return std::nullopt;
  Hash32 out{};
  std::copy(b->begin(), b->end(), out.begin());
  return out;
}

std::optional<PubKey32> parse_pubkey32(const std::string& s) {
  auto b = hex_decode(s);
  if (!b.has_value() || b->size() != 32) return std::nullopt;
  PubKey32 out{};
  std::copy(b->begin(), b->end(), out.begin());
  return out;
}

enum class TicketPowEpochHealth : std::uint8_t {
  Healthy = 1,
  Unhealthy = 2,
  Mixed = 3,
};

struct TicketPowStatusView {
  std::uint8_t difficulty{consensus::DEFAULT_TICKET_DIFFICULTY_BITS};
  std::uint8_t difficulty_min{consensus::MIN_BOUNDED_TICKET_DIFFICULTY_BITS};
  std::uint8_t difficulty_max{consensus::MAX_BOUNDED_TICKET_DIFFICULTY_BITS};
  TicketPowEpochHealth epoch_health{TicketPowEpochHealth::Mixed};
  std::size_t streak_up{0};
  std::size_t streak_down{0};
  std::uint64_t nonce_search_limit{consensus::EPOCH_TICKET_MAX_NONCE + 1};
  std::uint32_t bonus_cap_bps{2500};
};

struct CommitteeOperatorStatusView {
  PubKey32 operator_id{};
  PubKey32 representative_pubkey{};
  std::optional<std::uint64_t> base_weight;
  std::optional<std::uint32_t> ticket_bonus_bps;
  std::optional<std::uint64_t> final_weight;
  std::optional<Hash32> ticket_hash;
  std::optional<std::uint64_t> ticket_nonce;
};

std::string ticket_pow_epoch_health_name(TicketPowEpochHealth health) {
  switch (health) {
    case TicketPowEpochHealth::Healthy:
      return "healthy";
    case TicketPowEpochHealth::Unhealthy:
      return "unhealthy";
    case TicketPowEpochHealth::Mixed:
      return "mixed";
  }
  return "mixed";
}

std::optional<consensus::ValidatorRegistry> validator_registry_from_db(const storage::DB& db) {
  consensus::ValidatorRegistry vr;
  bool any = false;
  for (const auto& [pub, info] : db.load_validators()) {
    vr.upsert(pub, info);
    any = true;
  }
  if (!any) return std::nullopt;
  return vr;
}

struct EpochSignalSnapshot {
  std::uint32_t average_round_x1000{0};
  std::uint32_t average_participation_bps{10'000};
  TicketPowEpochHealth health{TicketPowEpochHealth::Mixed};
};

EpochSignalSnapshot compute_epoch_signal_snapshot(const storage::DB& db, std::uint64_t epoch_start, std::uint64_t epoch_end_inclusive) {
  EpochSignalSnapshot out;
  if (epoch_end_inclusive < epoch_start) return out;
  std::uint64_t blocks = 0;
  std::uint64_t total_round_x1000 = 0;
  std::uint64_t total_participation_bps = 0;
  for (std::uint64_t h = epoch_start; h <= epoch_end_inclusive; ++h) {
    auto cert = db.get_finality_certificate_by_height(h);
    if (!cert.has_value()) continue;
    ++blocks;
    total_round_x1000 += static_cast<std::uint64_t>(cert->round) * 1000ULL;
    total_participation_bps +=
        consensus::quorum_relative_participation_bps(cert->signatures.size(), cert->quorum_threshold);
  }
  if (blocks == 0) return out;
  out.average_round_x1000 = static_cast<std::uint32_t>(total_round_x1000 / blocks);
  out.average_participation_bps = static_cast<std::uint32_t>(total_participation_bps / blocks);
  if (out.average_round_x1000 <= 1'250 && out.average_participation_bps >= 9'500) {
    out.health = TicketPowEpochHealth::Healthy;
  } else if (out.average_round_x1000 >= 2'500 && out.average_participation_bps < 8'500) {
    out.health = TicketPowEpochHealth::Unhealthy;
  } else {
    out.health = TicketPowEpochHealth::Mixed;
  }
  return out;
}

TicketPowStatusView compute_ticket_pow_status_view(const storage::DB& db, const NetworkConfig& network,
                                                   std::uint64_t finalized_height) {
  TicketPowStatusView out;
  const auto epoch_start = consensus::committee_epoch_start(finalized_height, network.committee_epoch_blocks);
  const auto& econ = active_economics_policy(network, epoch_start);
  out.bonus_cap_bps = econ.ticket_bonus_cap_bps;
  out.difficulty_min = consensus::MIN_BOUNDED_TICKET_DIFFICULTY_BITS;
  out.difficulty_max = consensus::MAX_BOUNDED_TICKET_DIFFICULTY_BITS;
  if (auto checkpoint = db.get_finalized_committee_checkpoint(epoch_start); checkpoint.has_value()) {
    out.difficulty = checkpoint->ticket_difficulty_bits;
  }

  auto signal = compute_epoch_signal_snapshot(db, epoch_start, finalized_height);
  out.epoch_health = signal.health;
  const auto vr = validator_registry_from_db(db);
  const std::size_t active_validator_count = vr.has_value() ? vr->active_sorted(epoch_start).size() : 0;
  if (active_validator_count <= network.max_committee) return out;

  std::size_t streak_up = 0;
  std::size_t streak_down = 0;
  constexpr std::size_t kWindowEpochs = 6;
  std::size_t inspected_epochs = 0;
  std::uint64_t cursor = epoch_start + network.committee_epoch_blocks;
  while (cursor > 1 && inspected_epochs < kWindowEpochs) {
    const auto this_epoch_start = cursor - network.committee_epoch_blocks;
    const auto this_epoch_end = std::min<std::uint64_t>(finalized_height, cursor - 1);
    if (this_epoch_end < this_epoch_start) break;
    const auto epoch_signal = compute_epoch_signal_snapshot(db, this_epoch_start, this_epoch_end);
    if (epoch_signal.health == TicketPowEpochHealth::Healthy && streak_down == 0) {
      ++streak_up;
    } else if (epoch_signal.health == TicketPowEpochHealth::Unhealthy && streak_up == 0) {
      ++streak_down;
    } else {
      break;
    }
    ++inspected_epochs;
    if (this_epoch_start <= 1 || this_epoch_start <= network.committee_epoch_blocks) break;
    cursor = this_epoch_start;
  }
  out.streak_up = streak_up;
  out.streak_down = streak_down;
  return out;
}

std::string ticket_pow_status_json(const TicketPowStatusView& status) {
  std::ostringstream oss;
  oss << "{\"difficulty\":" << static_cast<std::uint32_t>(status.difficulty)
      << ",\"difficulty_min\":" << static_cast<std::uint32_t>(status.difficulty_min)
      << ",\"difficulty_max\":" << static_cast<std::uint32_t>(status.difficulty_max)
      << ",\"epoch_health\":\"" << ticket_pow_epoch_health_name(status.epoch_health) << "\""
      << ",\"streak_up\":" << status.streak_up
      << ",\"streak_down\":" << status.streak_down
      << ",\"nonce_search_limit\":" << status.nonce_search_limit
      << ",\"bonus_cap_bps\":" << status.bonus_cap_bps
      << "}";
  return oss.str();
}

std::string finality_certificate_json(const FinalityCertificate& cert) {
  std::ostringstream oss;
  oss << "{\"height\":" << cert.height << ",\"round\":" << cert.round << ",\"transition_hash\":\""
      << hex_encode32(cert.frontier_transition_id) << "\",\"quorum_threshold\":" << cert.quorum_threshold << ",\"committee\":[";
  for (size_t i = 0; i < cert.committee_members.size(); ++i) {
    if (i) oss << ",";
    oss << "\"" << hex_encode(Bytes(cert.committee_members[i].begin(), cert.committee_members[i].end())) << "\"";
  }
  oss << "],\"signatures\":[";
  for (size_t i = 0; i < cert.signatures.size(); ++i) {
    if (i) oss << ",";
    const auto& s = cert.signatures[i];
    oss << "{\"pubkey_hex\":\"" << hex_encode(Bytes(s.validator_pubkey.begin(), s.validator_pubkey.end()))
        << "\",\"sig_hex\":\"" << hex_encode(Bytes(s.signature.begin(), s.signature.end())) << "\"}";
  }
  oss << "]}";
  return oss.str();
}

std::optional<Bytes> canonical_transition_bytes_by_hash(const storage::DB& db, const Hash32& hash) {
  return db.get_frontier_transition(hash);
}

std::optional<Bytes> canonical_transition_bytes_by_height(const storage::DB& db, std::uint64_t height,
                                                          Hash32* transition_hash_out = nullptr) {
  auto transition_hash = db.get_height_hash(height);
  if (!transition_hash.has_value()) return std::nullopt;
  if (transition_hash_out) *transition_hash_out = *transition_hash;
  return canonical_transition_bytes_by_hash(db, *transition_hash);
}

std::string ingress_record_json(std::uint64_t seq, const std::optional<Bytes>& record) {
  std::ostringstream oss;
  oss << "{\"seq\":" << seq << ",\"present\":" << (record.has_value() ? "true" : "false");
  if (!record.has_value()) {
    oss << "}";
    return oss.str();
  }
  const auto record_hash = crypto::sha256d(*record);
  oss << ",\"hash\":\"" << hex_encode32(record_hash) << "\"";
  if (auto tx = Tx::parse(*record); tx.has_value()) {
    oss << ",\"txid\":\"" << hex_encode32(tx->txid()) << "\"";
  }
  oss << "}";
  return oss.str();
}

std::string ingress_lane_tip_json(const storage::DB& db, std::uint32_t lane) {
  std::ostringstream oss;
  oss << "{\"lane\":" << lane;
  auto state = db.get_lane_state(lane);
  if (!state.has_value()) {
    oss << ",\"present\":false,\"tip_seq\":0}";
    return oss.str();
  }
  oss << ",\"present\":true,\"tip_seq\":" << state->max_seq << ",\"epoch\":" << state->epoch
      << ",\"lane_root\":\"" << hex_encode32(state->lane_root) << "\"}";
  return oss.str();
}

std::string ingress_lane_record_json(const storage::DB& db, std::uint32_t lane, std::uint64_t seq) {
  std::ostringstream oss;
  oss << "{\"lane\":" << lane << ",\"seq\":" << seq;
  auto cert_bytes = db.get_ingress_certificate(lane, seq);
  if (!cert_bytes.has_value()) {
    oss << ",\"present\":false}";
    return oss.str();
  }
  auto cert = IngressCertificate::parse(*cert_bytes);
  if (!cert.has_value()) {
    oss << ",\"present\":false,\"failure\":\"invalid-certificate\"}";
    return oss.str();
  }
  auto tx_bytes = db.get_ingress_bytes(cert->txid);
  oss << ",\"present\":true,\"txid\":\"" << hex_encode32(cert->txid) << "\",\"tx_hash\":\"" << hex_encode32(cert->tx_hash)
      << "\",\"cert_hash\":\"" << hex_encode32(cert->signing_hash()) << "\",\"signer_count\":" << cert->sigs.size()
      << ",\"bytes_present\":" << (tx_bytes.has_value() ? "true" : "false");
  if (tx_bytes.has_value()) {
    oss << ",\"bytes_hash\":\"" << hex_encode32(crypto::sha256d(*tx_bytes)) << "\"";
  }
  oss << "}";
  return oss.str();
}

bool verify_exact_ingress_slice(const storage::DB& db, std::uint64_t start_seq, std::uint64_t end_seq,
                                std::vector<Bytes>* ordered_records, std::string* mismatch_detail) {
  if (ordered_records) ordered_records->clear();
  if (start_seq == 0 || end_seq < start_seq) {
    if (mismatch_detail) *mismatch_detail = "invalid-range";
    return false;
  }
  std::vector<Bytes> collected;
  if (end_seq >= start_seq) collected.reserve(static_cast<std::size_t>((end_seq - start_seq) + 1));
  for (std::uint64_t seq = start_seq; seq <= end_seq; ++seq) {
    auto record = db.get_ingress_record(seq);
    if (!record.has_value()) {
      if (mismatch_detail) *mismatch_detail = "missing-seq-" + std::to_string(seq);
      return false;
    }
    collected.push_back(*record);
  }
  if (!db.ingress_slice_matches(start_seq - 1, collected)) {
    if (mismatch_detail) *mismatch_detail = "persisted-slice-mismatch";
    return false;
  }
  if (ordered_records) *ordered_records = std::move(collected);
  return true;
}

const minijson::Value* params_object(const minijson::Value& root) {
  const auto* params = root.get("params");
  if (!params || !params->is_object()) return nullptr;
  return params;
}

std::optional<std::uint64_t> field_u64(const minijson::Value* obj, const char* key) {
  if (!obj) return std::nullopt;
  const auto* value = obj->get(key);
  if (!value) return std::nullopt;
  return value->as_u64();
}

std::optional<std::string> field_string(const minijson::Value* obj, const char* key) {
  if (!obj) return std::nullopt;
  const auto* value = obj->get(key);
  if (!value) return std::nullopt;
  return value->as_string();
}

std::optional<bool> field_bool(const minijson::Value* obj, const char* key) {
  if (!obj) return std::nullopt;
  const auto* value = obj->get(key);
  if (!value) return std::nullopt;
  return value->as_bool();
}

const minijson::Value* field_object(const minijson::Value* obj, const char* key) {
  if (!obj) return nullptr;
  const auto* value = obj->get(key);
  if (!value || !value->is_object()) return nullptr;
  return value;
}

std::string tx_status_json(const Hash32& txid, const std::optional<storage::DB::TxLocation>& loc,
                           const std::optional<storage::TipState>& tip, const storage::DB& db) {
  std::ostringstream oss;
  oss << "{\"txid\":\"" << hex_encode32(txid) << "\"";
  if (!loc.has_value()) {
    if (db.get_ingress_bytes(txid).has_value()) {
      oss << ",\"status\":\"certified_ingress\",\"finalized\":false,\"finalized_depth\":0,\"credit_safe\":false}";
    } else {
      oss << ",\"status\":\"not_found\",\"finalized\":false,\"finalized_depth\":0,\"credit_safe\":false}";
    }
    return oss.str();
  }

  auto transition_hash = db.get_height_hash(loc->height);
  const std::uint64_t finalized_depth =
      (tip.has_value() && tip->height >= loc->height) ? (tip->height - loc->height + 1) : 0;
  oss << ",\"status\":\"finalized\",\"finalized\":true,\"height\":" << loc->height << ",\"finalized_depth\":"
      << finalized_depth << ",\"credit_safe\":true";
  if (transition_hash.has_value()) {
    oss << ",\"transition_hash\":\"" << hex_encode32(*transition_hash) << "\"";
  }
  oss << "}";
  return oss.str();
}

std::string readiness_json(const storage::NodeRuntimeStatusSnapshot& snapshot) {
  std::ostringstream oss;
  oss << "{\"chain_id_ok\":" << (snapshot.chain_id_ok ? "true" : "false")
      << ",\"db_open\":" << (snapshot.db_open ? "true" : "false")
      << ",\"local_finalized_height\":" << snapshot.local_finalized_height
      << ",\"observed_network_height_known\":" << (snapshot.observed_network_height_known ? "true" : "false")
      << ",\"observed_network_finalized_height\":" << snapshot.observed_network_finalized_height
      << ",\"healthy_peer_count\":" << snapshot.healthy_peer_count
      << ",\"established_peer_count\":" << snapshot.established_peer_count
      << ",\"finalized_lag\":" << snapshot.finalized_lag
      << ",\"peer_height_disagreement\":" << (snapshot.peer_height_disagreement ? "true" : "false")
      << ",\"next_height_committee_available\":" << (snapshot.next_height_committee_available ? "true" : "false")
      << ",\"next_height_proposer_available\":" << (snapshot.next_height_proposer_available ? "true" : "false")
      << ",\"bootstrap_sync_incomplete\":" << (snapshot.bootstrap_sync_incomplete ? "true" : "false")
      << ",\"registration_ready_preflight\":" << (snapshot.registration_ready_preflight ? "true" : "false")
      << ",\"registration_ready\":" << (snapshot.registration_ready ? "true" : "false")
      << ",\"readiness_stable_samples\":" << snapshot.readiness_stable_samples
      << ",\"readiness_blockers_csv\":\"" << json_escape(snapshot.readiness_blockers_csv) << "\""
      << ",\"captured_at_unix_ms\":" << snapshot.captured_at_unix_ms << "}";
  return oss.str();
}

std::string broadcast_result_json(bool accepted, const std::string& txid_hex, const std::string& status,
                                  const std::string& message, const std::optional<std::string>& error_code,
                                  const std::optional<std::string>& error_message, bool retryable,
                                  const std::string& retry_class, bool mempool_full,
                                  const std::optional<std::uint64_t>& min_fee_rate_to_enter_when_full_milliunits_per_byte) {
  std::ostringstream oss;
  oss << "{\"ok\":true,\"accepted\":" << (accepted ? "true" : "false") << ",\"status\":\"" << json_escape(status)
      << "\",\"finalized\":false";
  if (!txid_hex.empty()) oss << ",\"txid\":\"" << json_escape(txid_hex) << "\"";
  if (!message.empty()) oss << ",\"message\":\"" << json_escape(message) << "\"";
  if (error_code.has_value()) oss << ",\"error_code\":\"" << json_escape(*error_code) << "\"";
  if (error_message.has_value()) {
    oss << ",\"error_message\":\"" << json_escape(*error_message) << "\"";
    oss << ",\"error\":\"" << json_escape(*error_message) << "\"";
  }
  oss << ",\"retryable\":" << (retryable ? "true" : "false");
  oss << ",\"retry_class\":\"" << json_escape(retry_class) << "\"";
  oss << ",\"mempool_full\":" << (mempool_full ? "true" : "false");
  if (min_fee_rate_to_enter_when_full_milliunits_per_byte.has_value()) {
    oss << ",\"min_fee_rate_to_enter_when_full\":" << *min_fee_rate_to_enter_when_full_milliunits_per_byte;
    oss << ",\"min_fee_rate_to_enter_when_full_milliunits_per_byte\":"
        << *min_fee_rate_to_enter_when_full_milliunits_per_byte;
  } else {
    oss << ",\"min_fee_rate_to_enter_when_full\":null";
    oss << ",\"min_fee_rate_to_enter_when_full_milliunits_per_byte\":null";
  }
  oss << "}";
  return oss.str();
}

std::string validation_error_code(const std::string& err) {
  if (err == "missing utxo" || err == "input depends on unconfirmed or missing utxo") {
    return "tx_missing_or_unconfirmed_input";
  }
  return "tx_invalid";
}

std::string validation_error_message(const std::string& err) {
  if (err == "missing utxo" || err == "input depends on unconfirmed or missing utxo") {
    return "Transaction input is missing from finalized state or depends on an unconfirmed input.";
  }
  return "Transaction rejected.";
}

std::string retry_class_for_error_code(const std::string& error_code) {
  if (error_code == "tx_invalid" || error_code == "tx_duplicate" || error_code == "tx_conflict_in_mempool") return "none";
  if (error_code == "tx_missing_or_unconfirmed_input") return "after_state_change";
  if (error_code == "tx_fee_below_min_relay" || error_code == "mempool_full_not_good_enough") return "after_fee_bump";
  if (error_code == "relay_unavailable") return "transport";
  if (error_code == "internal_error") return "later";
  return "none";
}

bool fee_rate_below_threshold(std::uint64_t fee, std::size_t size_bytes, std::uint64_t threshold_milliunits_per_byte) {
  return static_cast<unsigned __int128>(fee) * static_cast<unsigned __int128>(1000) <
         static_cast<unsigned __int128>(threshold_milliunits_per_byte) * static_cast<unsigned __int128>(size_bytes);
}

std::string onboarding_record_json(const onboarding::ValidatorOnboardingRecord& record) {
  std::ostringstream oss;
  oss << "{\"validator_pubkey_hex\":\""
      << hex_encode(Bytes(record.validator_pubkey.begin(), record.validator_pubkey.end()))
      << "\",\"wallet_address\":\"" << json_escape(record.wallet_address)
      << "\",\"wallet_pubkey_hex\":\"" << json_escape(record.wallet_pubkey_hex)
      << "\",\"state\":\"" << onboarding::validator_onboarding_state_name(record.state)
      << "\",\"fee\":" << record.fee
      << ",\"bond_amount\":" << record.bond_amount
      << ",\"eligibility_bond_amount\":" << record.eligibility_bond_amount
      << ",\"required_amount\":" << record.required_amount
      << ",\"last_spendable_balance\":" << record.last_spendable_balance
      << ",\"last_deficit\":" << record.last_deficit
      << ",\"txid_hex\":\"" << json_escape(record.txid_hex)
      << "\",\"finalized_height\":" << record.finalized_height
      << ",\"validator_status\":\"" << json_escape(record.validator_status)
      << "\",\"activation_height\":" << record.activation_height
      << ",\"last_error_code\":\"" << json_escape(record.last_error_code)
      << "\",\"last_error_message\":\"" << json_escape(record.last_error_message)
      << "\",\"readiness\":" << readiness_json(record.readiness) << "}";
  return oss.str();
}

std::optional<keystore::ValidatorKey> load_validator_key_for_rpc(const std::string& key_file, const std::string& passphrase,
                                                                 std::string* err) {
  keystore::ValidatorKey key;
  if (!keystore::load_validator_keystore(key_file, passphrase, &key, err)) return std::nullopt;
  return key;
}

std::string validator_status_name_for_rpc(const std::optional<consensus::ValidatorInfo>& info) {
  if (!info.has_value()) return "NOT_REGISTERED";
  switch (info->status) {
    case consensus::ValidatorStatus::PENDING:
      return "PENDING";
    case consensus::ValidatorStatus::ACTIVE:
      return "ACTIVE";
    case consensus::ValidatorStatus::EXITING:
      return "EXITING";
    case consensus::ValidatorStatus::BANNED:
      return "BANNED";
    case consensus::ValidatorStatus::SUSPENDED:
      return "SUSPENDED";
  }
  return "UNKNOWN";
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

bool readiness_snapshot_is_fresh_for_rpc(const storage::NodeRuntimeStatusSnapshot& snapshot, std::uint64_t now_ms) {
  if (snapshot.captured_at_unix_ms == 0 || snapshot.captured_at_unix_ms > now_ms) return false;
  return (now_ms - snapshot.captured_at_unix_ms) <= 3'000;
}

bool readiness_snapshot_allows_registration_for_rpc(const storage::NodeRuntimeStatusSnapshot& snapshot, std::uint64_t now_ms,
                                                    std::string* reason) {
  if (!readiness_snapshot_is_fresh_for_rpc(snapshot, now_ms)) {
    if (reason) *reason = "stale_runtime_snapshot";
    return false;
  }
  if (!snapshot.registration_ready) {
    if (reason) *reason = snapshot.readiness_blockers_csv.empty() ? "registration readiness false"
                                                                  : snapshot.readiness_blockers_csv;
    return false;
  }
  return true;
}

std::optional<onboarding::ValidatorOnboardingRecord> onboarding_status_from_readonly_db(
    const NetworkConfig& network, storage::DB& db, const keystore::ValidatorKey& key, std::uint64_t fee, bool wait_for_sync,
    const std::string& tracked_txid_hex, std::string* err) {
  onboarding::ValidatorOnboardingRecord record;
  record.onboarding_id = "rpc";
  record.validator_pubkey = key.pubkey;
  record.wallet_address = key.address;
  record.wallet_pubkey_hex = hex_encode(Bytes(key.pubkey.begin(), key.pubkey.end()));
  record.state = onboarding::ValidatorOnboardingState::IDLE;
  record.fee = fee;
  const auto tip = db.get_tip();
  const std::uint64_t planning_height = tip ? (tip->height + 1) : 0;
  record.bond_amount = registration_bond_amount_for_onboarding(network, db, planning_height);
  record.eligibility_bond_amount = eligibility_bond_amount_for_onboarding(network, db, planning_height, record.bond_amount);
  record.required_amount = record.bond_amount + fee;
  record.wait_for_sync = wait_for_sync;

  auto readiness = db.get_node_runtime_status_snapshot();
  if (readiness.has_value()) record.readiness = *readiness;

  const auto validators = db.load_validators();
  const auto join_requests = db.load_validator_join_requests();
  if (auto it = validators.find(key.pubkey); it != validators.end()) {
    record.validator_status = validator_status_name_for_rpc(std::optional<consensus::ValidatorInfo>(it->second));
    if (it->second.status == consensus::ValidatorStatus::ACTIVE) {
      record.state = onboarding::ValidatorOnboardingState::ACTIVE;
      record.activation_height = it->second.joined_height;
      record.finalized_height = tip ? tip->height : 0;
      return record;
    }
    if (it->second.status == consensus::ValidatorStatus::PENDING) {
      record.state = onboarding::ValidatorOnboardingState::PENDING_ACTIVATION;
      record.activation_height = it->second.joined_height + network.validator_warmup_blocks;
      record.finalized_height = tip ? tip->height : 0;
      return record;
    }
  } else {
    record.validator_status = "NOT_REGISTERED";
  }

  const auto own_pkh = crypto::h160(Bytes(key.pubkey.begin(), key.pubkey.end()));
  const auto spendable = wallet::spendable_p2pkh_utxos_for_pubkey_hash(db, own_pkh, nullptr);
  for (const auto& utxo : spendable) record.last_spendable_balance += utxo.prevout.value;
  record.last_deficit = record.last_spendable_balance >= record.required_amount ? 0
                        : record.required_amount - record.last_spendable_balance;

  bool join_request_present = false;
  for (const auto& [_, req] : join_requests) {
    if (req.validator_pubkey == key.pubkey) {
      join_request_present = true;
      break;
    }
  }
  if (join_request_present) {
    record.state = onboarding::ValidatorOnboardingState::PENDING_ACTIVATION;
    record.finalized_height = tip ? tip->height : 0;
    return record;
  }

  if (!tracked_txid_hex.empty()) {
    record.txid_hex = tracked_txid_hex;
    auto txid = parse_hex32(tracked_txid_hex);
    if (!txid) {
      if (err) *err = "bad txid";
      return std::nullopt;
    }
    if (auto loc = db.get_tx_index(*txid); loc.has_value()) record.finalized_height = loc->height;
    record.state = onboarding::ValidatorOnboardingState::WAITING_FOR_FINALIZATION;
    return record;
  }

  std::string readiness_err;
  if (!readiness.has_value()) {
    record.state = wait_for_sync ? onboarding::ValidatorOnboardingState::WAITING_FOR_SYNC
                                 : onboarding::ValidatorOnboardingState::FAILED;
    record.last_error_code = "node_not_ready";
    record.last_error_message = "runtime readiness snapshot unavailable";
    return record;
  }
  if (!readiness_snapshot_allows_registration_for_rpc(*readiness, static_cast<std::uint64_t>(::time(nullptr)) * 1000ULL,
                                                      &readiness_err)) {
    record.state = wait_for_sync ? onboarding::ValidatorOnboardingState::WAITING_FOR_SYNC
                                 : onboarding::ValidatorOnboardingState::FAILED;
    if (!wait_for_sync) {
      record.last_error_code = "node_not_ready";
      record.last_error_message = readiness_err;
    }
    return record;
  }
  if (record.last_spendable_balance < record.required_amount) {
    record.state = onboarding::ValidatorOnboardingState::WAITING_FOR_FUNDS;
    return record;
  }
  record.state = onboarding::ValidatorOnboardingState::CHECKING_PREREQS;
  return record;
}

std::string network_hint_for_hrp(const std::string& hrp) {
  if (hrp == "sc") return "mainnet";
  if (hrp == "tsc") return "test_or_dev";
  return "unknown";
}

std::string server_hrp_for_network(const NetworkConfig& network) {
  return network.name == "mainnet" ? "sc" : "tsc";
}

bool open_fresh_readonly_db(const std::string& db_path, storage::DB* db) {
  return db->open_readonly(db_path);
}

bool read_http_request(int fd, std::string* out_req) {
  std::string req;
  std::array<char, 4096> buf{};
  while (req.find("\r\n\r\n") == std::string::npos) {
    ssize_t n = ::recv(fd, buf.data(), buf.size(), 0);
    if (n <= 0) return false;
    req.append(buf.data(), static_cast<size_t>(n));
    if (req.size() > kMaxHttpHeaderBytes) return false;
  }

  const auto hdr_end = req.find("\r\n\r\n");
  const std::string headers = req.substr(0, hdr_end);
  std::regex cl_re("Content-Length:\\s*([0-9]+)", std::regex_constants::icase);
  std::smatch m;
  size_t content_len = 0;
  if (std::regex_search(headers, m, cl_re)) {
    content_len = static_cast<size_t>(std::stoull(m[1].str()));
  }
  if (content_len > kMaxRpcBodyBytes) return false;
  while (req.size() < hdr_end + 4 + content_len) {
    ssize_t n = ::recv(fd, buf.data(), buf.size(), 0);
    if (n <= 0) return false;
    req.append(buf.data(), static_cast<size_t>(n));
  }
  *out_req = req;
  return true;
}

std::string http_response_json(const std::string& body, int status = 200) {
  const char* status_text = (status == 200) ? "OK" : "Bad Request";
  std::ostringstream oss;
  oss << "HTTP/1.1 " << status << " " << status_text << "\r\n"
      << "Content-Type: application/json\r\n"
      << "Content-Length: " << body.size() << "\r\n"
      << "Connection: close\r\n\r\n"
      << body;
  return oss.str();
}

}  // namespace

Server::Server(Config cfg) : cfg_(std::move(cfg)) {}
Server::~Server() { stop(); }

bool Server::init() {
  cfg_.db_path = expand_user_home(cfg_.db_path);
  if (!db_.open_readonly(cfg_.db_path)) return false;
  chain_id_ = ChainId::from_config_and_db(cfg_.network, db_);
  if (cfg_.max_committee == 0) cfg_.max_committee = cfg_.network.max_committee;
  if (cfg_.tx_relay_port == 0) cfg_.tx_relay_port = cfg_.network.p2p_default_port;
  started_at_unix_ = static_cast<std::uint64_t>(::time(nullptr));
  return true;
}

bool Server::start() {
  listen_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
  if (listen_fd_ < 0) return false;
  int one = 1;
  setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(cfg_.port);
  if (inet_pton(AF_INET, cfg_.bind_ip.c_str(), &addr.sin_addr) != 1) return false;
  if (bind(listen_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) return false;
  sockaddr_in bound{};
  socklen_t blen = sizeof(bound);
  if (::getsockname(listen_fd_, reinterpret_cast<sockaddr*>(&bound), &blen) == 0) {
    bound_port_ = ntohs(bound.sin_port);
  } else {
    bound_port_ = cfg_.port;
  }
  cfg_.port = bound_port_;
  if (listen(listen_fd_, 64) != 0) return false;
  running_ = true;
  accept_thread_ = std::thread([this]() { accept_loop(); });
  return true;
}

void Server::stop() {
  if (!running_.exchange(false)) return;
  if (listen_fd_ >= 0) {
    ::shutdown(listen_fd_, SHUT_RDWR);
    ::close(listen_fd_);
    listen_fd_ = -1;
    bound_port_ = 0;
  }
  if (accept_thread_.joinable()) accept_thread_.join();
}

std::string Server::handle_rpc_for_test(const std::string& body) { return handle_rpc_body(body); }

void Server::accept_loop() {
  while (running_) {
    sockaddr_in addr{};
    socklen_t len = sizeof(addr);
    int fd = accept(listen_fd_, reinterpret_cast<sockaddr*>(&addr), &len);
    if (fd < 0) {
      if (!running_) break;
      continue;
    }
    handle_client(fd);
    ::shutdown(fd, SHUT_RDWR);
    ::close(fd);
  }
}

void Server::handle_client(int fd) {
  std::string req;
  if (!read_http_request(fd, &req)) return;
  const auto first_line_end = req.find("\r\n");
  if (first_line_end == std::string::npos) return;
  const std::string first = req.substr(0, first_line_end);
  if (first.rfind("POST /rpc ", 0) != 0) {
    const std::string body = R"({"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"invalid endpoint"}})";
    const auto resp = http_response_json(body, 400);
    (void)p2p::write_all(fd, reinterpret_cast<const std::uint8_t*>(resp.data()), resp.size());
    return;
  }
  const auto hdr_end = req.find("\r\n\r\n");
  if (hdr_end == std::string::npos) return;
  const std::string body = req.substr(hdr_end + 4);
  const std::string out = handle_rpc_body(body);
  const auto resp = http_response_json(out, 200);
  (void)p2p::write_all(fd, reinterpret_cast<const std::uint8_t*>(resp.data()), resp.size());
}

std::string Server::make_error(const std::string& id_token, int code, const std::string& msg) const {
  std::ostringstream oss;
  oss << "{\"jsonrpc\":\"2.0\",\"id\":" << id_token << ",\"error\":{\"code\":" << code << ",\"message\":\""
      << json_escape(msg) << "\"}}";
  return oss.str();
}

std::string Server::make_result(const std::string& id_token, const std::string& result_json) const {
  std::ostringstream oss;
  oss << "{\"jsonrpc\":\"2.0\",\"id\":" << id_token << ",\"result\":" << result_json << "}";
  return oss.str();
}

std::optional<std::vector<PubKey32>> Server::committee_for_height(std::uint64_t height) {
  auto tip = db_.get_tip();
  if (!tip.has_value()) return std::nullopt;
  if (height == 0 || height > tip->height + 1) return std::nullopt;
  if (height == tip->height + 1) return std::nullopt;

  if (auto cert = db_.get_finality_certificate_by_height(height); cert.has_value() && !cert->committee_members.empty()) {
    return cert->committee_members;
  }
  return std::nullopt;
}

bool Server::relay_tx_to_peer(const Bytes& tx_bytes, std::string* err) {
  if (cfg_.tx_relay_override) return cfg_.tx_relay_override(tx_bytes, err);
  constexpr std::uint32_t kRelayHandshakeTimeoutMs = 2000;
  constexpr std::uint32_t kRelayDrainTimeoutMs = 250;
  addrinfo hints{};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  addrinfo* res = nullptr;
  if (getaddrinfo(cfg_.tx_relay_host.c_str(), std::to_string(cfg_.tx_relay_port).c_str(), &hints, &res) != 0) {
    if (err) *err = "getaddrinfo failed";
    return false;
  }
  int fd = -1;
  for (addrinfo* it = res; it != nullptr; it = it->ai_next) {
    fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
    if (fd < 0) continue;
    if (connect(fd, it->ai_addr, it->ai_addrlen) == 0) break;
    ::close(fd);
    fd = -1;
  }
  freeaddrinfo(res);
  if (fd < 0) {
    if (err) *err = "connect relay peer failed";
    return false;
  }

  auto tip = db_.get_tip();
  p2p::VersionMsg v;
  v.proto_version = static_cast<std::uint32_t>(cfg_.network.protocol_version);
  v.network_id = cfg_.network.network_id;
  v.feature_flags = cfg_.network.feature_flags;
  v.start_height = tip ? tip->height : 0;
  v.start_hash = tip ? tip->hash : zero_hash();
  v.timestamp = static_cast<std::uint64_t>(::time(nullptr));
  v.nonce = 424242;
  v.node_software_version = finalis::lightserver_software_version();
  if (!p2p::write_frame_fd(fd, p2p::Frame{p2p::MsgType::VERSION, p2p::ser_version(v)}, cfg_.network.magic,
                          cfg_.network.protocol_version)) {
    ::close(fd);
    if (err) *err = "send VERSION failed";
    return false;
  }

  bool saw_version = false;
  bool saw_verack = false;
  while (!saw_version || !saw_verack) {
    p2p::FrameReadError read_err = p2p::FrameReadError::NONE;
    auto frame = p2p::read_frame_fd_timed(fd, cfg_.network.max_payload_len, cfg_.network.magic,
                                          cfg_.network.protocol_version, kRelayHandshakeTimeoutMs,
                                          kRelayHandshakeTimeoutMs, &read_err);
    if (!frame.has_value()) {
      ::close(fd);
      if (err) *err = "relay handshake failed: " + p2p::frame_read_error_string(read_err);
      return false;
    }
    if (frame->msg_type == p2p::MsgType::VERSION) {
      saw_version = true;
      if (!p2p::write_frame_fd(fd, p2p::Frame{p2p::MsgType::VERACK, {}}, cfg_.network.magic,
                               cfg_.network.protocol_version)) {
        ::close(fd);
        if (err) *err = "send VERACK failed";
        return false;
      }
      continue;
    }
    if (frame->msg_type == p2p::MsgType::VERACK) {
      saw_verack = true;
      continue;
    }
  }

  if (!p2p::write_frame_fd(fd, p2p::Frame{p2p::MsgType::TX, p2p::ser_tx(p2p::TxMsg{tx_bytes})}, cfg_.network.magic,
                          cfg_.network.protocol_version)) {
    ::close(fd);
    if (err) *err = "send TX failed";
    return false;
  }

  // Keep the relay socket open briefly and drain any post-handshake sync traffic.
  // The node sends FINALIZED_TIP / GET_FINALIZED_TIP as soon as VERACK lands; if
  // we close immediately after TX, it may disconnect the peer before reading TX.
  const auto drain_deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(kRelayDrainTimeoutMs);
  while (std::chrono::steady_clock::now() < drain_deadline) {
    p2p::FrameReadError read_err = p2p::FrameReadError::NONE;
    auto frame = p2p::read_frame_fd_timed(fd, cfg_.network.max_payload_len, cfg_.network.magic,
                                          cfg_.network.protocol_version, kRelayDrainTimeoutMs,
                                          kRelayDrainTimeoutMs, &read_err);
    if (!frame.has_value()) {
      if (read_err == p2p::FrameReadError::TIMEOUT_HEADER || read_err == p2p::FrameReadError::TIMEOUT_BODY ||
          read_err == p2p::FrameReadError::IO_EOF) {
        break;
      }
      break;
    }
  }

  ::shutdown(fd, SHUT_RDWR);
  ::close(fd);
  return true;
}

std::string Server::handle_rpc_body(const std::string& body) {
  if (body.size() > kMaxRpcBodyBytes) return make_error("null", -32600, "request too large");
  auto root = minijson::parse(body);
  if (!root.has_value() || !root->is_object()) return make_error("null", -32600, "invalid json");
  const auto* method_value = root->get("method");
  const auto method = method_value ? method_value->as_string() : std::nullopt;
  const auto* id_value = root->get("id");
  const std::string id = id_value ? minijson::stringify(*id_value) : "null";
  if (!method.has_value()) return make_error(id, -32600, "missing method");
  const minijson::Value* params = params_object(*root);
  storage::DB live_db;
  const storage::DB* view = &db_;
  if (open_fresh_readonly_db(cfg_.db_path, &live_db)) view = &live_db;
  if (*method == "get_tip") {
    auto tip = view->get_tip();
    if (!tip.has_value()) return make_error(id, -32000, "tip unavailable");
    std::ostringstream oss;
    oss << "{\"height\":" << tip->height << ",\"transition_hash\":\"" << hex_encode32(tip->hash)
        << "\",\"hash\":\"" << hex_encode32(tip->hash) << "\"}";
    return make_result(id, oss.str());
  }

  if (*method == "get_status") {
    auto tip = view->get_tip();
    if (!tip.has_value()) return make_error(id, -32000, "tip unavailable");
    const std::uint64_t now = static_cast<std::uint64_t>(::time(nullptr));
    const auto runtime = view->get_node_runtime_status_snapshot();
    const auto adaptive_telemetry = view->load_adaptive_epoch_telemetry();
    const auto adaptive_summary = storage::summarize_adaptive_epoch_telemetry(adaptive_telemetry);
    const auto ticket_pow = compute_ticket_pow_status_view(*view, cfg_.network, tip->height);
    std::size_t latest_committee_size = 0;
    std::size_t latest_quorum_threshold = 0;
    if (auto cert = view->get_finality_certificate_by_height(tip->height); cert.has_value()) {
      latest_committee_size = cert->committee_members.size();
      latest_quorum_threshold = cert->quorum_threshold;
    }
    std::ostringstream oss;
    oss << "{\"network_name\":\"" << cfg_.network.name << "\",\"protocol_version\":"
        << cfg_.network.protocol_version << ",\"feature_flags\":" << cfg_.network.feature_flags
        << ",\"network_id\":\"" << chain_id_.network_id_hex << "\",\"magic\":" << chain_id_.magic
        << ",\"genesis_hash\":\"" << chain_id_.genesis_hash_hex << "\",\"genesis_source\":\""
        << chain_id_.genesis_source << "\",\"chain_id_ok\":" << (chain_id_.chain_id_ok ? "true" : "false")
        << ",\"tip\":{\"height\":" << tip->height << ",\"transition_hash\":\"" << hex_encode32(tip->hash)
        << "\"},\"finalized_tip\":{\"height\":" << tip->height << ",\"transition_hash\":\"" << hex_encode32(tip->hash)
        << "\"},\"finalized_height\":" << tip->height << ",\"finalized_transition_hash\":\"" << hex_encode32(tip->hash)
        << "\",\"peers\":";
    if (runtime.has_value()) oss << runtime->established_peer_count;
    else oss << "null";
    oss << ",\"healthy_peer_count\":";
    if (runtime.has_value()) oss << runtime->healthy_peer_count;
    else oss << "null";
    oss << ",\"established_peer_count\":";
    if (runtime.has_value()) oss << runtime->established_peer_count;
    else oss << "null";
    oss << ",\"protocol_reserve_balance\":";
    if (auto reserve = view->get_protocol_reserve_balance(); reserve.has_value()) oss << *reserve;
    else oss << "null";
    oss << ",\"mempool_size\":";
    if (runtime.has_value()) oss << runtime->mempool_tx_count;
    else oss << "null";
    oss << ",\"mempool\":{";
    oss << "\"tx_count\":";
    if (runtime.has_value()) oss << runtime->mempool_tx_count;
    else oss << "null";
    oss << ",\"bytes\":";
    if (runtime.has_value()) oss << runtime->mempool_bytes;
    else oss << "null";
    oss << ",\"full\":";
    if (runtime.has_value()) oss << (runtime->mempool_full ? "true" : "false");
    else oss << "null";
    oss << ",\"min_fee_rate_to_enter_when_full\":";
    if (runtime.has_value() && runtime->min_fee_rate_to_enter_when_full_milliunits_per_byte.has_value()) {
      oss << *runtime->min_fee_rate_to_enter_when_full_milliunits_per_byte;
    } else {
      oss << "null";
    }
    oss << ",\"min_fee_rate_to_enter_when_full_milliunits_per_byte\":";
    if (runtime.has_value() && runtime->min_fee_rate_to_enter_when_full_milliunits_per_byte.has_value()) {
      oss << *runtime->min_fee_rate_to_enter_when_full_milliunits_per_byte;
    } else {
      oss << "null";
    }
    oss << ",\"rejected_full_not_good_enough\":";
    if (runtime.has_value()) oss << runtime->rejected_full_not_good_enough;
    else oss << "null";
    oss << ",\"evicted_for_better_incoming\":";
    if (runtime.has_value()) oss << runtime->evicted_for_better_incoming;
    else oss << "null";
    oss << ",\"min_relay_fee\":";
    if (runtime.has_value()) oss << runtime->min_relay_fee;
    else oss << "null";
    oss << "},\"availability\":{";
    oss << "\"epoch\":";
    if (runtime.has_value()) oss << runtime->availability_epoch;
    else oss << "null";
    oss << ",\"retained_prefix_count\":";
    if (runtime.has_value()) oss << runtime->availability_retained_prefix_count;
    else oss << "null";
    oss << ",\"tracked_operator_count\":";
    if (runtime.has_value()) oss << runtime->availability_tracked_operator_count;
    else oss << "null";
    oss << ",\"eligible_operator_count\":";
    if (runtime.has_value()) oss << runtime->availability_eligible_operator_count;
    else oss << "null";
    oss << ",\"below_min_eligible\":";
    if (runtime.has_value()) oss << (runtime->availability_below_min_eligible ? "true" : "false");
    else oss << "null";
    oss << ",\"checkpoint_derivation_mode\":";
    if (runtime.has_value()) {
      switch (static_cast<storage::FinalizedCommitteeDerivationMode>(runtime->availability_checkpoint_derivation_mode)) {
        case storage::FinalizedCommitteeDerivationMode::NORMAL:
          oss << "\"normal\"";
          break;
        case storage::FinalizedCommitteeDerivationMode::FALLBACK:
          oss << "\"fallback\"";
          break;
        default:
          oss << "\"unknown\"";
          break;
      }
    } else {
      oss << "null";
    }
    oss << ",\"checkpoint_fallback_reason\":";
    if (runtime.has_value()) {
      switch (static_cast<storage::FinalizedCommitteeFallbackReason>(runtime->availability_checkpoint_fallback_reason)) {
        case storage::FinalizedCommitteeFallbackReason::NONE:
          oss << "\"none\"";
          break;
        case storage::FinalizedCommitteeFallbackReason::INSUFFICIENT_ELIGIBLE_OPERATORS:
          oss << "\"insufficient_eligible_operators\"";
          break;
        case storage::FinalizedCommitteeFallbackReason::HYSTERESIS_RECOVERY_PENDING:
          oss << "\"hysteresis_recovery_pending\"";
          break;
        default:
          oss << "\"unknown\"";
          break;
      }
    } else {
      oss << "null";
    }
    oss << ",\"fallback_sticky\":";
    if (runtime.has_value()) oss << (runtime->availability_fallback_sticky ? "true" : "false");
    else oss << "null";
    oss << ",\"adaptive_regime\":{";
    oss << "\"qualified_depth\":";
    if (runtime.has_value()) oss << runtime->qualified_depth;
    else oss << "null";
    oss << ",\"adaptive_target_committee_size\":";
    if (runtime.has_value()) oss << runtime->adaptive_target_committee_size;
    else oss << "null";
    oss << ",\"adaptive_min_eligible\":";
    if (runtime.has_value()) oss << runtime->adaptive_min_eligible;
    else oss << "null";
    oss << ",\"adaptive_min_bond\":";
    if (runtime.has_value()) oss << runtime->adaptive_min_bond;
    else oss << "null";
    oss << ",\"slack\":";
    if (runtime.has_value()) oss << runtime->adaptive_slack;
    else oss << "null";
    oss << ",\"target_expand_streak\":";
    if (runtime.has_value()) oss << runtime->target_expand_streak;
    else oss << "null";
    oss << ",\"target_contract_streak\":";
    if (runtime.has_value()) oss << runtime->target_contract_streak;
    else oss << "null";
    oss << ",\"fallback_rate_bps\":";
    if (runtime.has_value()) oss << runtime->adaptive_fallback_rate_bps;
    else oss << "null";
    oss << ",\"sticky_fallback_rate_bps\":";
    if (runtime.has_value()) oss << runtime->adaptive_sticky_fallback_rate_bps;
    else oss << "null";
    oss << ",\"fallback_rate_window_epochs\":";
    if (runtime.has_value()) oss << runtime->adaptive_fallback_window_epochs;
    else oss << "null";
    oss << ",\"near_threshold_operation\":";
    if (runtime.has_value()) oss << (runtime->adaptive_near_threshold_operation ? "true" : "false");
    else oss << "null";
    oss << ",\"prolonged_expand_buildup\":";
    if (runtime.has_value()) oss << (runtime->adaptive_prolonged_expand_buildup ? "true" : "false");
    else oss << "null";
    oss << ",\"prolonged_contract_buildup\":";
    if (runtime.has_value()) oss << (runtime->adaptive_prolonged_contract_buildup ? "true" : "false");
    else oss << "null";
    oss << ",\"repeated_sticky_fallback\":";
    if (runtime.has_value()) oss << (runtime->adaptive_repeated_sticky_fallback ? "true" : "false");
    else oss << "null";
    oss << ",\"depth_collapse_after_bond_increase\":";
    if (runtime.has_value()) oss << (runtime->adaptive_depth_collapse_after_bond_increase ? "true" : "false");
    else oss << "null";
    oss << "}";
    oss << ",\"state_rebuild_triggered\":";
    if (runtime.has_value()) oss << (runtime->availability_state_rebuild_triggered ? "true" : "false");
    else oss << "null";
    oss << ",\"state_rebuild_reason\":";
    if (runtime.has_value()) {
      oss << "\"" << json_escape(runtime->availability_state_rebuild_reason) << "\"";
    } else {
      oss << "null";
    }
    oss << ",\"local_operator\":{";
    oss << "\"known\":";
    if (runtime.has_value()) oss << (runtime->availability_local_operator_known ? "true" : "false");
    else oss << "null";
    oss << ",\"pubkey\":\"";
    if (runtime.has_value() && runtime->availability_local_operator_known) {
      oss << hex_encode(Bytes(runtime->availability_local_operator_pubkey.begin(),
                              runtime->availability_local_operator_pubkey.end()));
    }
    oss << "\",\"status\":\"";
    if (runtime.has_value() && runtime->availability_local_operator_known) {
      switch (static_cast<availability::AvailabilityOperatorStatus>(runtime->availability_local_operator_status)) {
        case availability::AvailabilityOperatorStatus::WARMUP:
          oss << "WARMUP";
          break;
        case availability::AvailabilityOperatorStatus::ACTIVE:
          oss << "ACTIVE";
          break;
        case availability::AvailabilityOperatorStatus::PROBATION:
          oss << "PROBATION";
          break;
        case availability::AvailabilityOperatorStatus::EJECTED:
          oss << "EJECTED";
          break;
      }
    }
    oss << "\",\"service_score\":";
    if (runtime.has_value() && runtime->availability_local_operator_known) oss << runtime->availability_local_service_score;
    else oss << "null";
    oss << ",\"warmup_epochs\":";
    if (runtime.has_value() && runtime->availability_local_operator_known) oss << runtime->availability_local_warmup_epochs;
    else oss << "null";
    oss << ",\"successful_audits\":";
    if (runtime.has_value() && runtime->availability_local_operator_known) {
      oss << runtime->availability_local_successful_audits;
    } else {
      oss << "null";
    }
    oss << ",\"late_audits\":";
    if (runtime.has_value() && runtime->availability_local_operator_known) oss << runtime->availability_local_late_audits;
    else oss << "null";
    oss << ",\"missed_audits\":";
    if (runtime.has_value() && runtime->availability_local_operator_known) oss << runtime->availability_local_missed_audits;
    else oss << "null";
    oss << ",\"invalid_audits\":";
    if (runtime.has_value() && runtime->availability_local_operator_known) oss << runtime->availability_local_invalid_audits;
    else oss << "null";
    oss << ",\"retained_prefix_count\":";
    if (runtime.has_value() && runtime->availability_local_operator_known) {
      oss << runtime->availability_local_retained_prefix_count;
    } else {
      oss << "null";
    }
    oss << ",\"eligibility_score\":";
    if (runtime.has_value() && runtime->availability_local_operator_known) oss << runtime->availability_local_eligibility_score;
    else oss << "null";
    oss << ",\"seat_budget\":";
    if (runtime.has_value() && runtime->availability_local_operator_known) oss << runtime->availability_local_seat_budget;
    else oss << "null";
    oss << "}},\"uptime_s\":" << (now - started_at_unix_)
        << ",\"version\":\"" << finalis::core_software_version() << "\""
        << ",\"binary\":\"finalis-lightserver\""
        << ",\"binary_version\":\"" << finalis::lightserver_software_version() << "\""
        << ",\"release\":\"" << finalis::kReleaseVersion << "\""
        << ",\"wallet_api_version\":\"" << finalis::kWalletApiVersion << "\""
        << ",\"consensus_model\":\"finalized-checkpoint-operator-committee-bft\""
        << ",\"ticket_pow\":" << ticket_pow_status_json(ticket_pow)
        << ",\"latest_finality_committee_size\":" << latest_committee_size
        << ",\"latest_finality_quorum_threshold\":" << latest_quorum_threshold
        << ",\"sync\":{\"mode\":\"finalized_only\",\"snapshot_present\":"
        << (runtime.has_value() ? "true" : "false")
        << ",\"local_finalized_height\":" << tip->height
        << ",\"observed_network_height_known\":";
    if (runtime.has_value()) oss << (runtime->observed_network_height_known ? "true" : "false");
    else oss << "null";
    oss << ",\"observed_network_finalized_height\":";
    if (runtime.has_value() && runtime->observed_network_height_known) oss << runtime->observed_network_finalized_height;
    else oss << "null";
    oss << ",\"finalized_lag\":";
    if (runtime.has_value()) oss << runtime->finalized_lag;
    else oss << "null";
    oss << ",\"bootstrap_sync_incomplete\":";
    if (runtime.has_value()) oss << (runtime->bootstrap_sync_incomplete ? "true" : "false");
    else oss << "null";
    oss << ",\"peer_height_disagreement\":";
    if (runtime.has_value()) oss << (runtime->peer_height_disagreement ? "true" : "false");
    else oss << "null";
    oss << ",\"next_height_committee_available\":";
    if (runtime.has_value()) oss << (runtime->next_height_committee_available ? "true" : "false");
    else oss << "null";
    oss << ",\"next_height_proposer_available\":";
    if (runtime.has_value()) oss << (runtime->next_height_proposer_available ? "true" : "false");
    else oss << "null";
    oss << "},\"adaptive_telemetry_summary\":{"
        << "\"window_epochs\":" << adaptive_summary.window_epochs
        << ",\"sample_count\":" << adaptive_summary.sample_count
        << ",\"fallback_epochs\":" << adaptive_summary.fallback_epochs
        << ",\"sticky_fallback_epochs\":" << adaptive_summary.sticky_fallback_epochs
        << ",\"fallback_rate_bps\":" << adaptive_summary.fallback_rate_bps
        << ",\"sticky_fallback_rate_bps\":" << adaptive_summary.sticky_fallback_rate_bps
        << ",\"near_threshold_operation\":" << (adaptive_summary.near_threshold_operation ? "true" : "false")
        << ",\"prolonged_expand_buildup\":" << (adaptive_summary.prolonged_expand_buildup ? "true" : "false")
        << ",\"prolonged_contract_buildup\":" << (adaptive_summary.prolonged_contract_buildup ? "true" : "false")
        << ",\"repeated_sticky_fallback\":" << (adaptive_summary.repeated_sticky_fallback ? "true" : "false")
        << ",\"depth_collapse_after_bond_increase\":"
        << (adaptive_summary.depth_collapse_after_bond_increase ? "true" : "false") << "}}";
    return make_result(id, oss.str());
  }

  if (*method == "get_adaptive_telemetry") {
    const auto limit = field_u64(params, "limit").value_or(16);
    const auto telemetry = view->load_adaptive_epoch_telemetry();
    const auto summary =
        storage::summarize_adaptive_epoch_telemetry(telemetry, static_cast<std::size_t>(std::max<std::uint64_t>(1, limit)));
    std::vector<const storage::AdaptiveEpochTelemetry*> ordered;
    ordered.reserve(telemetry.size());
    for (const auto& [_, snapshot] : telemetry) ordered.push_back(&snapshot);
    const std::size_t count = ordered.size();
    const std::size_t begin = count > limit ? (count - static_cast<std::size_t>(limit)) : 0;
    std::ostringstream oss;
    oss << "{\"window_epochs\":" << summary.window_epochs << ",\"summary\":{"
        << "\"sample_count\":" << summary.sample_count
        << ",\"fallback_epochs\":" << summary.fallback_epochs
        << ",\"sticky_fallback_epochs\":" << summary.sticky_fallback_epochs
        << ",\"fallback_rate_bps\":" << summary.fallback_rate_bps
        << ",\"sticky_fallback_rate_bps\":" << summary.sticky_fallback_rate_bps
        << ",\"near_threshold_operation\":" << (summary.near_threshold_operation ? "true" : "false")
        << ",\"prolonged_expand_buildup\":" << (summary.prolonged_expand_buildup ? "true" : "false")
        << ",\"prolonged_contract_buildup\":" << (summary.prolonged_contract_buildup ? "true" : "false")
        << ",\"repeated_sticky_fallback\":" << (summary.repeated_sticky_fallback ? "true" : "false")
        << ",\"depth_collapse_after_bond_increase\":"
        << (summary.depth_collapse_after_bond_increase ? "true" : "false") << "},\"snapshots\":[";
    for (std::size_t i = begin; i < count; ++i) {
      const auto& entry = *ordered[i];
      if (i != begin) oss << ",";
      oss << "{\"epoch_start_height\":" << entry.epoch_start_height
          << ",\"derivation_height\":" << entry.derivation_height
          << ",\"qualified_depth\":" << entry.qualified_depth
          << ",\"adaptive_target_committee_size\":" << entry.adaptive_target_committee_size
          << ",\"adaptive_min_eligible\":" << entry.adaptive_min_eligible
          << ",\"adaptive_min_bond\":" << entry.adaptive_min_bond
          << ",\"slack\":" << entry.slack
          << ",\"target_expand_streak\":" << entry.target_expand_streak
          << ",\"target_contract_streak\":" << entry.target_contract_streak
          << ",\"checkpoint_derivation_mode\":\""
          << (entry.derivation_mode == storage::FinalizedCommitteeDerivationMode::NORMAL ? "normal" : "fallback") << "\""
          << ",\"checkpoint_fallback_reason\":\"";
      switch (entry.fallback_reason) {
        case storage::FinalizedCommitteeFallbackReason::NONE:
          oss << "none";
          break;
        case storage::FinalizedCommitteeFallbackReason::INSUFFICIENT_ELIGIBLE_OPERATORS:
          oss << "insufficient_eligible_operators";
          break;
        case storage::FinalizedCommitteeFallbackReason::HYSTERESIS_RECOVERY_PENDING:
          oss << "hysteresis_recovery_pending";
          break;
        default:
          oss << "unknown";
          break;
      }
      oss << "\",\"fallback_sticky\":" << (entry.fallback_sticky ? "true" : "false")
          << ",\"committee_size_selected\":" << entry.committee_size_selected
          << ",\"eligible_operator_count\":" << entry.eligible_operator_count << "}";
    }
    oss << "]}";
    return make_result(id, oss.str());
  }

  if (*method == "get_transition") {
    auto hash_hex = field_string(params, "hash");
    if (!hash_hex) return make_error(id, -32602, "missing hash");
    auto h = parse_hex32(*hash_hex);
    if (!h) return make_error(id, -32602, "bad hash");
    auto bytes = canonical_transition_bytes_by_hash(*view, *h);
    if (!bytes.has_value()) return make_error(id, -32001, "not found");
    return make_result(id,
                       std::string("{\"transition_hash\":\"") + hex_encode32(*h) + "\",\"hash\":\"" + hex_encode32(*h) +
                           "\",\"transition_hex\":\"" + hex_encode(*bytes) + "\"}");
  }

  if (*method == "get_transition_by_height") {
    auto height = field_u64(params, "height");
    if (!height) return make_error(id, -32602, "missing height");
    Hash32 transition_hash{};
    auto bytes = canonical_transition_bytes_by_height(*view, *height, &transition_hash);
    if (!bytes.has_value()) return make_error(id, -32001, "not found");
    std::ostringstream oss;
    oss << "{\"height\":" << *height << ",\"transition_hash\":\"" << hex_encode32(transition_hash)
        << "\",\"hash\":\"" << hex_encode32(transition_hash) << "\",\"transition_hex\":\"" << hex_encode(*bytes) << "\"}";
    return make_result(id, oss.str());
  }

  if (*method == "get_ingress_tip") {
    const auto ingress_tip = db_.get_finalized_ingress_tip().value_or(0);
    std::ostringstream oss;
    oss << "{\"ingress_tip\":" << ingress_tip << "}";
    return make_result(id, oss.str());
  }

  if (*method == "get_ingress_lane_tip") {
    auto lane = field_u64(params, "lane");
    if (!lane || *lane >= INGRESS_LANE_COUNT) return make_error(id, -32602, "missing/invalid lane");
    return make_result(id, ingress_lane_tip_json(db_, static_cast<std::uint32_t>(*lane)));
  }

  if (*method == "get_ingress_record") {
    auto lane = field_u64(params, "lane");
    auto seq = field_u64(params, "seq");
    if (lane.has_value()) {
      if (!seq || *lane >= INGRESS_LANE_COUNT) return make_error(id, -32602, "missing/invalid lane,seq");
      return make_result(id, ingress_lane_record_json(db_, static_cast<std::uint32_t>(*lane), *seq));
    }
    if (!seq) return make_error(id, -32602, "missing seq");
    return make_result(id, ingress_record_json(*seq, db_.get_ingress_record(*seq)));
  }

  if (*method == "get_ingress_range") {
    auto lane = field_u64(params, "lane");
    if (lane.has_value()) {
      auto from = field_u64(params, "from_seq");
      auto to = field_u64(params, "to_seq");
      if (!from || !to || *lane >= INGRESS_LANE_COUNT || *to < *from || *from == 0) {
        return make_error(id, -32602, "missing/invalid lane,from_seq,to_seq");
      }
      std::ostringstream oss;
      oss << "{\"lane\":" << *lane << ",\"from_seq\":" << *from << ",\"to_seq\":" << *to << ",\"records\":[";
      bool first = true;
      bool complete = true;
      for (std::uint64_t seq = *from; seq <= *to; ++seq) {
        auto cert = db_.get_ingress_certificate(static_cast<std::uint32_t>(*lane), seq);
        if (!cert.has_value()) complete = false;
        if (!first) oss << ",";
        first = false;
        oss << ingress_lane_record_json(db_, static_cast<std::uint32_t>(*lane), seq);
      }
      oss << "],\"complete\":" << (complete ? "true" : "false") << "}";
      return make_result(id, oss.str());
    }
    auto start = field_u64(params, "start");
    auto end = field_u64(params, "end");
    if (!start || !end || *end < *start) return make_error(id, -32602, "missing/invalid start,end");
    std::ostringstream oss;
    bool complete = true;
    std::vector<Bytes> present_records;
    const auto expected_count = (*end - *start) + 1;
    present_records.reserve(static_cast<std::size_t>(expected_count));
    oss << "{\"start\":" << *start << ",\"end\":" << *end << ",\"records\":[";
    bool first = true;
    for (std::uint64_t seq = *start; seq <= *end; ++seq) {
      auto record = db_.get_ingress_record(seq);
      if (!record.has_value()) {
        complete = false;
      } else {
        present_records.push_back(*record);
      }
      if (!first) oss << ",";
      first = false;
      oss << ingress_record_json(seq, record);
    }
    oss << "],\"complete\":" << (complete ? "true" : "false");
    if (complete) {
      const auto commitment =
          consensus::frontier_ordered_slice_commitment(present_records);
      oss << ",\"slice_commitment\":\"" << hex_encode32(commitment) << "\"";
    }
    oss << "}";
    return make_result(id, oss.str());
  }

  if (*method == "verify_ingress_slice") {
    auto lane = field_u64(params, "lane");
    if (lane.has_value()) {
      auto from = field_u64(params, "from_seq");
      auto to = field_u64(params, "to_seq");
      if (!from || !to || *lane >= INGRESS_LANE_COUNT || *to < *from || *from == 0) {
        return make_error(id, -32602, "missing/invalid lane,from_seq,to_seq");
      }
      bool ok = true;
      std::string failure;
      std::optional<Hash32> expected_prev_root;
      if (*from > 1) {
        auto prev_cert_bytes = db_.get_ingress_certificate(static_cast<std::uint32_t>(*lane), *from - 1);
        if (!prev_cert_bytes.has_value()) {
          ok = false;
          failure = "missing-prev-seq-" + std::to_string(*from - 1);
        } else {
          auto prev_cert = IngressCertificate::parse(*prev_cert_bytes);
          if (!prev_cert.has_value()) {
            ok = false;
            failure = "invalid-prev-cert";
          } else {
            auto prev_bytes = db_.get_ingress_bytes(prev_cert->txid);
            if (!prev_bytes.has_value()) {
              ok = false;
              failure = "missing-prev-bytes";
            } else {
              expected_prev_root = consensus::compute_lane_root_append(prev_cert->prev_lane_root, prev_cert->tx_hash);
            }
          }
        }
      }
      std::ostringstream oss;
      oss << "{\"lane\":" << *lane << ",\"from_seq\":" << *from << ",\"to_seq\":" << *to
          << ",\"verified\":" << (ok ? "true" : "false") << ",\"records\":[";
      bool first = true;
      Hash32 running_root = expected_prev_root.value_or(zero_hash());
      for (std::uint64_t seq = *from; seq <= *to; ++seq) {
        if (!first) oss << ",";
        first = false;
        oss << ingress_lane_record_json(db_, static_cast<std::uint32_t>(*lane), seq);
        if (!ok) continue;
        auto cert_bytes = db_.get_ingress_certificate(static_cast<std::uint32_t>(*lane), seq);
        if (!cert_bytes.has_value()) {
          ok = false;
          failure = "missing-seq-" + std::to_string(seq);
          continue;
        }
        auto cert = IngressCertificate::parse(*cert_bytes);
        if (!cert.has_value()) {
          ok = false;
          failure = "invalid-cert-seq-" + std::to_string(seq);
          continue;
        }
        if (cert->lane != *lane || cert->seq != seq) {
          ok = false;
          failure = "lane-seq-mismatch-" + std::to_string(seq);
          continue;
        }
        if (cert->prev_lane_root != running_root) {
          ok = false;
          failure = "prev-root-mismatch-" + std::to_string(seq);
          continue;
        }
        auto tx_bytes = db_.get_ingress_bytes(cert->txid);
        if (!tx_bytes.has_value()) {
          ok = false;
          failure = "missing-bytes-" + std::to_string(seq);
          continue;
        }
        running_root = consensus::compute_lane_root_append(running_root, cert->tx_hash);
      }
      oss << "]";
      if (!ok) oss << ",\"failure\":\"" << json_escape(failure) << "\"";
      oss << "}";
      return make_result(id, oss.str());
    }
    auto start = field_u64(params, "start");
    auto end = field_u64(params, "end");
    if (!start || !end || *end < *start || *start == 0) return make_error(id, -32602, "missing/invalid start,end");
    std::vector<Bytes> ordered_records;
    std::string mismatch_detail;
    const bool ok = verify_exact_ingress_slice(db_, *start, *end, &ordered_records, &mismatch_detail);
    std::ostringstream oss;
    oss << "{\"start\":" << *start << ",\"end\":" << *end << ",\"verified\":" << (ok ? "true" : "false")
        << ",\"continuous\":" << (ok ? "true" : "false")
        << ",\"ordered\":" << (ok ? "true" : "false")
        << ",\"complete\":" << (ok ? "true" : "false") << ",\"records\":[";
    bool first = true;
    for (std::uint64_t seq = *start; seq <= *end; ++seq) {
      if (!first) oss << ",";
      first = false;
      oss << ingress_record_json(seq, db_.get_ingress_record(seq));
    }
    oss << "]";
    if (ok) {
      const auto commitment = consensus::frontier_ordered_slice_commitment(ordered_records);
      oss << ",\"slice_commitment\":\"" << hex_encode32(commitment) << "\"";
    } else {
      oss << ",\"failure\":\"" << json_escape(mismatch_detail) << "\"";
    }
    oss << "}";
    return make_result(id, oss.str());
  }

  if (*method == "get_finality_certificate") {
    std::optional<FinalityCertificate> cert;
    if (auto height = field_u64(params, "height"); height.has_value()) {
      cert = db_.get_finality_certificate_by_height(*height);
      if (cert.has_value() && cert->committee_members.empty()) {
        if (auto committee = committee_for_height(cert->height); committee.has_value()) {
          cert->committee_members = *committee;
          cert->quorum_threshold = static_cast<std::uint32_t>(consensus::quorum_threshold(committee->size()));
        }
      }
    } else if (auto hash_hex = field_string(params, "hash"); hash_hex.has_value()) {
      auto h = parse_hex32(*hash_hex);
      if (!h) return make_error(id, -32602, "bad hash");
      if (auto transition_bytes = db_.get_frontier_transition(*h); transition_bytes.has_value()) {
        auto transition = FrontierTransition::parse(*transition_bytes);
        if (!transition.has_value()) return make_error(id, -32003, "stored transition corrupt");
        cert = db_.get_finality_certificate_by_height(transition->height);
        if (cert.has_value() && cert->frontier_transition_id != *h) cert.reset();
      }
      if (cert.has_value() && cert->committee_members.empty()) {
        if (auto committee = committee_for_height(cert->height); committee.has_value()) {
          cert->committee_members = *committee;
          cert->quorum_threshold = static_cast<std::uint32_t>(consensus::quorum_threshold(committee->size()));
        }
      }
    } else {
      auto tip = db_.get_tip();
      if (!tip.has_value()) return make_error(id, -32602, "tip unavailable");
      cert = db_.get_finality_certificate_by_height(tip->height);
      if (cert.has_value() && cert->committee_members.empty()) {
        if (auto committee = committee_for_height(cert->height); committee.has_value()) {
          cert->committee_members = *committee;
          cert->quorum_threshold = static_cast<std::uint32_t>(consensus::quorum_threshold(committee->size()));
        }
      }
    }

    if (!cert.has_value()) return make_error(id, -32001, "not found");
    return make_result(id, finality_certificate_json(*cert));
  }

  if (*method == "get_tx") {
    auto txid_hex = field_string(params, "txid");
    if (!txid_hex) return make_error(id, -32602, "missing txid");
    auto txid = parse_hex32(*txid_hex);
    if (!txid) return make_error(id, -32602, "bad txid");
    auto loc = view->get_tx_index(*txid);
    if (!loc.has_value()) return make_error(id, -32001, "not found");
    std::ostringstream oss;
    oss << "{\"height\":" << loc->height << ",\"tx_hex\":\"" << hex_encode(loc->tx_bytes) << "\"}";
    return make_result(id, oss.str());
  }

  if (*method == "get_tx_status") {
    auto txid_hex = field_string(params, "txid");
    if (!txid_hex) return make_error(id, -32602, "missing txid");
    auto txid = parse_hex32(*txid_hex);
    if (!txid) return make_error(id, -32602, "bad txid");
    auto tip = view->get_tip();
    auto loc = view->get_tx_index(*txid);
    return make_result(id, tx_status_json(*txid, loc, tip, *view));
  }

  if (*method == "validator_onboarding_status") {
    auto key_file = field_string(params, "key_file");
    if (!key_file) return make_error(id, -32602, "missing key_file");
    const std::string passphrase = field_string(params, "passphrase").value_or("");
    const std::uint64_t fee = field_u64(params, "fee").value_or(10'000);
    const bool wait_for_sync = field_bool(params, "wait_for_sync").value_or(true);
    const std::string tracked_txid_hex = field_string(params, "txid_hex").value_or("");
    std::string err;
    auto key = load_validator_key_for_rpc(*key_file, passphrase, &err);
    if (!key.has_value()) return make_result(id, std::string("{\"state\":\"failed\",\"last_error_message\":\"") + json_escape(err) + "\"}");
    storage::DB live_db;
    if (!open_fresh_readonly_db(cfg_.db_path, &live_db)) {
      return make_result(
          id, std::string("{\"state\":\"failed\",\"last_error_message\":\"failed to open db\"}"));
    }
    auto record =
        onboarding_status_from_readonly_db(cfg_.network, live_db, *key, fee, wait_for_sync, tracked_txid_hex, &err);
    if (!record.has_value()) return make_result(id, std::string("{\"state\":\"failed\",\"last_error_message\":\"") + json_escape(err) + "\"}");
    return make_result(id, onboarding_record_json(*record));
  }

  if (*method == "validator_onboarding_start") {
    auto key_file = field_string(params, "key_file");
    if (!key_file) return make_error(id, -32602, "missing key_file");
    const std::string passphrase = field_string(params, "passphrase").value_or("");
    const std::uint64_t fee = field_u64(params, "fee").value_or(10'000);
    const bool wait_for_sync = field_bool(params, "wait_for_sync").value_or(true);
    std::string err;
    auto key = load_validator_key_for_rpc(*key_file, passphrase, &err);
    if (!key.has_value()) return make_result(id, std::string("{\"state\":\"failed\",\"last_error_message\":\"") + json_escape(err) + "\"}");
    storage::DB live_db;
    if (!open_fresh_readonly_db(cfg_.db_path, &live_db)) {
      return make_result(
          id, std::string("{\"state\":\"failed\",\"last_error_message\":\"failed to open db\"}"));
    }
    auto record = onboarding_status_from_readonly_db(cfg_.network, live_db, *key, fee, wait_for_sync, "", &err);
    if (!record.has_value()) return make_result(id, std::string("{\"state\":\"failed\",\"last_error_message\":\"") + json_escape(err) + "\"}");
    if (record->state != onboarding::ValidatorOnboardingState::CHECKING_PREREQS) {
      return make_result(id, onboarding_record_json(*record));
    }

    const auto own_pkh = crypto::h160(Bytes(key->pubkey.begin(), key->pubkey.end()));
    const auto spendable = wallet::spendable_p2pkh_utxos_for_pubkey_hash(live_db, own_pkh, nullptr);
    auto selection = wallet::select_deterministic_utxos(spendable, record->required_amount, &err);
    if (!selection.has_value()) {
      record->state = onboarding::ValidatorOnboardingState::FAILED;
      record->last_error_code = "selection_failed";
      record->last_error_message = err;
      return make_result(id, onboarding_record_json(*record));
    }
    std::vector<std::pair<OutPoint, TxOut>> prevs;
    prevs.reserve(selection->selected.size());
    for (const auto& utxo : selection->selected) prevs.push_back({utxo.outpoint, utxo.prevout});
    auto own_address = address::decode(key->address);
    if (!own_address.has_value()) {
      record->state = onboarding::ValidatorOnboardingState::FAILED;
      record->last_error_code = "build_failed";
      record->last_error_message = "invalid wallet address";
      return make_result(id, onboarding_record_json(*record));
    }
    auto tx = build_validator_join_request_tx(prevs, Bytes(key->privkey.begin(), key->privkey.end()), key->pubkey,
                                              Bytes(key->privkey.begin(), key->privkey.end()), key->pubkey,
                                              record->bond_amount, record->fee,
                                              address::p2pkh_script_pubkey(own_address->pubkey_hash), &err);
    if (!tx.has_value()) {
      record->state = onboarding::ValidatorOnboardingState::FAILED;
      record->last_error_code = "build_failed";
      record->last_error_message = err;
      return make_result(id, onboarding_record_json(*record));
    }
    const Bytes tx_bytes = tx->serialize();
    const Hash32 txid = tx->txid();
    const auto utxos = db_.load_utxos();
    const auto validators = db_.load_validators();
    consensus::ValidatorRegistry vr;
    for (const auto& [pub, info] : validators) vr.upsert(pub, info);
    auto tip = db_.get_tip();
    SpecialValidationContext ctx{
        .validators = &vr,
        .current_height = tip ? (tip->height + 1) : 1,
        .is_committee_member =
            [this](const PubKey32& pk, std::uint64_t h, std::uint32_t /*round*/) {
              auto committee = committee_for_height(h);
              if (!committee.has_value()) return false;
              return std::find(committee->begin(), committee->end(), pk) != committee->end();
            },
    };
    auto vrx = validate_tx(*tx, 1, utxos, &ctx);
    if (!vrx.ok) {
      record->state = onboarding::ValidatorOnboardingState::FAILED;
      record->last_error_code = "tx_rejected";
      record->last_error_message = vrx.error;
      record->txid_hex = hex_encode32(txid);
      return make_result(id, onboarding_record_json(*record));
    }
    if (!relay_tx_to_peer(tx_bytes, &err)) {
      record->state = onboarding::ValidatorOnboardingState::FAILED;
      record->last_error_code = "tx_rejected";
      record->last_error_message = err;
      record->txid_hex = hex_encode32(txid);
      return make_result(id, onboarding_record_json(*record));
    }
    record->state = onboarding::ValidatorOnboardingState::WAITING_FOR_FINALIZATION;
    record->txid_hex = hex_encode32(txid);
    record->last_error_code.clear();
    record->last_error_message.clear();
    return make_result(id, onboarding_record_json(*record));
  }

  if (*method == "validate_address") {
    auto addr = field_string(params, "address");
    if (!addr) return make_error(id, -32602, "missing address");
    const auto validated = address::validate(*addr);
    const std::string server_hrp = server_hrp_for_network(cfg_.network);
    std::ostringstream oss;
    oss << "{\"valid\":" << (validated.valid ? "true" : "false")
        << ",\"server_network_hrp\":\"" << server_hrp << "\"";
    if (!validated.valid) {
      oss << ",\"normalized_address\":null,\"network_hint\":null,\"server_network_match\":null"
          << ",\"addr_type\":null,\"pubkey_hash_hex\":null,\"script_pubkey_hex\":null,\"scripthash_hex\":null"
          << ",\"error\":\"" << json_escape(validated.error) << "\"}";
      return make_result(id, oss.str());
    }

    const auto& decoded = *validated.decoded;
    const auto script_pubkey = address::p2pkh_script_pubkey(decoded.pubkey_hash);
    const auto scripthash = crypto::sha256(script_pubkey);
    oss << ",\"normalized_address\":\"" << json_escape(*validated.normalized_address)
        << "\",\"hrp\":\"" << decoded.hrp
        << "\",\"network_hint\":\"" << network_hint_for_hrp(decoded.hrp)
        << "\",\"server_network_match\":" << (decoded.hrp == server_hrp ? "true" : "false")
        << ",\"addr_type\":\"p2pkh\""
        << ",\"pubkey_hash_hex\":\"" << hex_encode(Bytes(decoded.pubkey_hash.begin(), decoded.pubkey_hash.end()))
        << "\",\"script_pubkey_hex\":\"" << hex_encode(script_pubkey)
        << "\",\"scripthash_hex\":\"" << hex_encode32(scripthash)
        << "\",\"error\":null}";
    return make_result(id, oss.str());
  }

  if (*method == "get_utxos") {
    auto sh_hex = field_string(params, "scripthash_hex");
    if (!sh_hex) return make_error(id, -32602, "missing scripthash_hex");
    auto sh = parse_hex32(*sh_hex);
    if (!sh) return make_error(id, -32602, "bad scripthash");
    const auto utxos = reconciled_script_utxos(*view, *sh);
    std::ostringstream oss;
    oss << "[";
    for (size_t i = 0; i < utxos.size(); ++i) {
      if (i) oss << ",";
      const auto& u = utxos[i];
      oss << "{\"txid\":\"" << hex_encode32(u.outpoint.txid) << "\",\"vout\":" << u.outpoint.index
          << ",\"value\":" << u.value << ",\"height\":" << u.height
          << ",\"script_pubkey_hex\":\"" << hex_encode(u.script_pubkey) << "\"}";
    }
    oss << "]";
    return make_result(id, oss.str());
  }

  if (*method == "get_history") {
    auto sh_hex = field_string(params, "scripthash_hex");
    if (!sh_hex) return make_error(id, -32602, "missing scripthash_hex");
    auto sh = parse_hex32(*sh_hex);
    if (!sh) return make_error(id, -32602, "bad scripthash");
    auto history = view->get_script_history(*sh);
    std::ostringstream oss;
    oss << "[";
    for (size_t i = 0; i < history.size(); ++i) {
      if (i) oss << ",";
      oss << "{\"txid\":\"" << hex_encode32(history[i].txid) << "\",\"height\":" << history[i].height << "}";
    }
    oss << "]";
    return make_result(id, oss.str());
  }

  if (*method == "get_history_page") {
    auto sh_hex = field_string(params, "scripthash_hex");
    if (!sh_hex) return make_error(id, -32602, "missing scripthash_hex");
    auto sh = parse_hex32(*sh_hex);
    if (!sh) return make_error(id, -32602, "bad scripthash");
    const auto limit = field_u64(params, "limit").value_or(100);
    if (limit == 0 || limit > 1000) return make_error(id, -32602, "bad limit");
    const auto from_height = field_u64(params, "from_height").value_or(0);
    const auto start_after = field_object(params, "start_after");
    auto start_after_height = field_u64(start_after, "height");
    auto start_after_txid_hex = field_string(start_after, "txid");
    std::optional<Hash32> start_after_txid;
    if (start_after_txid_hex.has_value()) {
      start_after_txid = parse_hex32(*start_after_txid_hex);
      if (!start_after_txid.has_value()) return make_error(id, -32602, "bad start_after.txid");
    }
    if (start_after_height.has_value() != start_after_txid.has_value()) {
      return make_error(id, -32602, "start_after requires height and txid");
    }

    const auto history = view->get_script_history(*sh);
    std::vector<storage::DB::ScriptHistoryEntry> filtered;
    filtered.reserve(history.size());
    for (const auto& entry : history) {
      if (entry.height < from_height) continue;
      if (start_after_height.has_value()) {
        if (entry.height < *start_after_height) continue;
        if (entry.height == *start_after_height && entry.txid <= *start_after_txid) continue;
      }
      filtered.push_back(entry);
    }

    const std::size_t page_size = static_cast<std::size_t>(limit);
    const bool has_more = filtered.size() > page_size;
    const std::size_t emit = std::min(filtered.size(), page_size);

    std::ostringstream oss;
    oss << "{\"items\":[";
    for (std::size_t i = 0; i < emit; ++i) {
      if (i) oss << ",";
      oss << "{\"txid\":\"" << hex_encode32(filtered[i].txid) << "\",\"height\":" << filtered[i].height << "}";
    }
    oss << "],\"has_more\":" << (has_more ? "true" : "false")
        << ",\"ordering\":\"height_asc_txid_asc\",\"next_start_after\":";
    if (has_more && emit > 0) {
      const auto& last = filtered[emit - 1];
      oss << "{\"height\":" << last.height << ",\"txid\":\"" << hex_encode32(last.txid) << "\"}";
    } else {
      oss << "null";
    }
    oss << "}";
    return make_result(id, oss.str());
  }

  if (*method == "get_committee") {
    auto h = field_u64(params, "height");
    if (!h) return make_error(id, -32602, "missing height");
    const bool verbose = field_bool(params, "verbose").value_or(false);
    const auto epoch_start = consensus::committee_epoch_start(*h, cfg_.network.committee_epoch_blocks);
    const auto checkpoint = view->get_finalized_committee_checkpoint(epoch_start);
    std::optional<std::vector<PubKey32>> committee;
    if (checkpoint.has_value() && !checkpoint->ordered_members.empty()) {
      committee = checkpoint->ordered_members;
    } else {
      committee = committee_for_height(*h);
    }
    if (!committee.has_value()) return make_error(id, -32001, "height unavailable");
    if (!verbose) {
      std::ostringstream oss;
      oss << "[";
      for (size_t i = 0; i < committee->size(); ++i) {
        if (i) oss << ",";
        oss << "\"" << hex_encode(Bytes((*committee)[i].begin(), (*committee)[i].end())) << "\"";
      }
      oss << "]";
      return make_result(id, oss.str());
    }

    const auto& econ = active_economics_policy(cfg_.network, epoch_start);
    const auto ticket_pow = compute_ticket_pow_status_view(*view, cfg_.network, *h);
    const auto validators = view->load_validators();
    std::ostringstream oss;
    oss << "{\"height\":" << *h << ",\"epoch_start_height\":" << epoch_start
        << ",\"checkpoint_derivation_mode\":";
    if (checkpoint.has_value()) {
      oss << "\"" << (checkpoint->derivation_mode == storage::FinalizedCommitteeDerivationMode::NORMAL ? "normal" : "fallback")
          << "\"";
    } else {
      oss << "null";
    }
    oss << ",\"availability_eligible_operator_count\":";
    if (checkpoint.has_value()) oss << checkpoint->availability_eligible_operator_count;
    else oss << "null";
    oss << ",\"availability_min_eligible_operators\":";
    if (checkpoint.has_value()) oss << checkpoint->availability_min_eligible_operators;
    else oss << "null";
    oss << ",\"adaptive_target_committee_size\":";
    if (checkpoint.has_value()) oss << checkpoint->adaptive_target_committee_size;
    else oss << "null";
    oss << ",\"adaptive_min_eligible\":";
    if (checkpoint.has_value()) oss << checkpoint->adaptive_min_eligible;
    else oss << "null";
    oss << ",\"adaptive_min_bond\":";
    if (checkpoint.has_value()) oss << checkpoint->adaptive_min_bond;
    else oss << "null";
    oss << ",\"qualified_depth\":";
    if (checkpoint.has_value()) oss << checkpoint->qualified_depth;
    else oss << "null";
    oss << ",\"slack\":";
    if (checkpoint.has_value()) {
      oss << (static_cast<std::int64_t>(checkpoint->qualified_depth) -
              static_cast<std::int64_t>(checkpoint->adaptive_min_eligible));
    } else {
      oss << "null";
    }
    oss << ",\"target_expand_streak\":";
    if (checkpoint.has_value()) oss << checkpoint->target_expand_streak;
    else oss << "null";
    oss << ",\"target_contract_streak\":";
    if (checkpoint.has_value()) oss << checkpoint->target_contract_streak;
    else oss << "null";
    oss << ",\"checkpoint_fallback_reason\":";
    if (checkpoint.has_value()) {
      switch (checkpoint->fallback_reason) {
        case storage::FinalizedCommitteeFallbackReason::NONE:
          oss << "\"none\"";
          break;
        case storage::FinalizedCommitteeFallbackReason::INSUFFICIENT_ELIGIBLE_OPERATORS:
          oss << "\"insufficient_eligible_operators\"";
          break;
        case storage::FinalizedCommitteeFallbackReason::HYSTERESIS_RECOVERY_PENDING:
          oss << "\"hysteresis_recovery_pending\"";
          break;
        default:
          oss << "\"unknown\"";
          break;
      }
    } else {
      oss << "null";
    }
    oss << ",\"fallback_sticky\":";
    if (checkpoint.has_value()) {
      oss << (checkpoint->fallback_reason == storage::FinalizedCommitteeFallbackReason::HYSTERESIS_RECOVERY_PENDING
                  ? "true"
                  : "false");
    } else {
      oss << "null";
    }
    oss
        << ",\"ticket_pow\":" << ticket_pow_status_json(ticket_pow)
        << ",\"members\":[";
    for (size_t i = 0; i < committee->size(); ++i) {
      if (i) oss << ",";
      const auto& representative_pubkey = (*committee)[i];
      std::optional<PubKey32> operator_id;
      std::optional<std::uint64_t> base_weight;
      std::optional<std::uint32_t> ticket_bonus_bps;
      std::optional<std::uint64_t> final_weight;
      std::optional<Hash32> ticket_hash;
      std::optional<std::uint64_t> ticket_nonce;
      if (checkpoint.has_value()) {
        if (i < checkpoint->ordered_operator_ids.size()) operator_id = checkpoint->ordered_operator_ids[i];
        if (i < checkpoint->ordered_base_weights.size()) base_weight = checkpoint->ordered_base_weights[i];
        if (i < checkpoint->ordered_ticket_bonus_bps.size()) ticket_bonus_bps = checkpoint->ordered_ticket_bonus_bps[i];
        if (i < checkpoint->ordered_final_weights.size()) final_weight = checkpoint->ordered_final_weights[i];
        if (i < checkpoint->ordered_ticket_hashes.size()) ticket_hash = checkpoint->ordered_ticket_hashes[i];
        if (i < checkpoint->ordered_ticket_nonces.size()) ticket_nonce = checkpoint->ordered_ticket_nonces[i];
      }
      if (!operator_id.has_value()) {
        auto it = validators.find(representative_pubkey);
        if (it != validators.end()) {
          operator_id = it->second.operator_id == PubKey32{} ? representative_pubkey : it->second.operator_id;
        }
      }
      if (!ticket_bonus_bps.has_value() && ticket_hash.has_value()) {
        consensus::EpochTicket ticket;
        ticket.work_hash = *ticket_hash;
        ticket_bonus_bps = consensus::ticket_pow_bonus_bps(ticket, ticket_pow.difficulty, econ.ticket_bonus_cap_bps);
      }
      oss << "{\"operator_id\":";
      if (operator_id.has_value()) oss << "\"" << hex_encode(Bytes(operator_id->begin(), operator_id->end())) << "\"";
      else oss << "null";
      oss << ",\"representative_pubkey\":\""
          << hex_encode(Bytes(representative_pubkey.begin(), representative_pubkey.end())) << "\""
          << ",\"base_weight\":";
      if (base_weight.has_value()) oss << *base_weight;
      else oss << "null";
      oss << ",\"ticket_bonus_bps\":";
      if (ticket_bonus_bps.has_value()) oss << *ticket_bonus_bps;
      else oss << "null";
      oss << ",\"final_weight\":";
      if (final_weight.has_value()) oss << *final_weight;
      else oss << "null";
      oss << ",\"ticket_hash\":";
      if (ticket_hash.has_value()) oss << "\"" << hex_encode(Bytes(ticket_hash->begin(), ticket_hash->end())) << "\"";
      else oss << "null";
      oss << ",\"ticket_nonce\":";
      if (ticket_nonce.has_value()) oss << *ticket_nonce;
      else oss << "null";
      oss << "}";
    }
    oss << "],\"finalized_only\":true}";
    return make_result(id, oss.str());
  }

  if (*method == "get_roots") {
    auto h = field_u64(params, "height");
    if (!h) return make_error(id, -32602, "missing height");
    auto ur = db_.get(storage::key_root_index("UTXO", *h));
    auto vr = db_.get(storage::key_root_index("VAL", *h));
    if (!ur.has_value() || ur->size() != 32 || !vr.has_value() || vr->size() != 32) {
      return make_error(id, -32001, "roots unavailable");
    }
    Hash32 u{};
    Hash32 v{};
    std::copy(ur->begin(), ur->end(), u.begin());
    std::copy(vr->begin(), vr->end(), v.begin());
    std::ostringstream oss;
    oss << "{\"height\":" << *h << ",\"utxo_root\":\"" << hex_encode32(u) << "\",\"validators_root\":\"" << hex_encode32(v)
        << "\"}";
    return make_result(id, oss.str());
  }

  if (*method == "get_utxo_proof") {
    auto txid_hex = field_string(params, "txid");
    auto vout = field_u64(params, "vout");
    if (!txid_hex || !vout) return make_error(id, -32602, "missing txid/vout");
    auto txid = parse_hex32(*txid_hex);
    if (!txid) return make_error(id, -32602, "bad txid");
    auto tip = db_.get_tip();
    if (!tip.has_value()) return make_error(id, -32000, "tip unavailable");
    std::uint64_t h = tip->height;
    if (auto hopt = field_u64(params, "height"); hopt.has_value()) {
      h = *hopt;
      if (h != tip->height) return make_error(id, -32602, "proofs only supported at finalized tip");
    }

    const OutPoint op{*txid, static_cast<std::uint32_t>(*vout)};
    const Hash32 key = consensus::utxo_commitment_key(op);
    crypto::SparseMerkleTree tree(db_, "utxo");
    const auto value = tree.get_value(key);
    const auto proof = tree.get_proof(key);
    auto ur = db_.get(storage::key_root_index("UTXO", h));
    if (!ur.has_value() || ur->size() != 32) return make_error(id, -32001, "utxo_root unavailable");
    Hash32 root{};
    std::copy(ur->begin(), ur->end(), root.begin());

    std::ostringstream oss;
    oss << "{\"proof_format\":\"smt_v0\",\"height\":" << h << ",\"key_hex\":\"" << hex_encode32(key)
        << "\",\"root_hex\":\"" << hex_encode32(root) << "\",\"utxo_root\":\"" << hex_encode32(root) << "\",";
    if (value.has_value()) oss << "\"value_hex\":\"" << hex_encode(*value) << "\",";
    else oss << "\"value_hex\":null,";
    oss << "\"siblings_hex\":[";
    for (size_t i = 0; i < proof.siblings.size(); ++i) {
      if (i) oss << ",";
      oss << "\"" << hex_encode32(proof.siblings[i]) << "\"";
    }
    oss << "],\"siblings\":[";
    for (size_t i = 0; i < proof.siblings.size(); ++i) {
      if (i) oss << ",";
      oss << "\"" << hex_encode32(proof.siblings[i]) << "\"";
    }
    oss << "]}";
    return make_result(id, oss.str());
  }

  if (*method == "get_validator_proof") {
    auto pub_hex = field_string(params, "pubkey_hex");
    if (!pub_hex) return make_error(id, -32602, "missing pubkey_hex");
    auto pub = parse_pubkey32(*pub_hex);
    if (!pub) return make_error(id, -32602, "bad pubkey");
    auto tip = db_.get_tip();
    if (!tip.has_value()) return make_error(id, -32000, "tip unavailable");
    std::uint64_t h = tip->height;
    if (auto hopt = field_u64(params, "height"); hopt.has_value()) {
      h = *hopt;
      if (h != tip->height) return make_error(id, -32602, "proofs only supported at finalized tip");
    }

    const Hash32 key = consensus::validator_commitment_key(*pub);
    crypto::SparseMerkleTree tree(db_, "validators");
    const auto value = tree.get_value(key);
    const auto proof = tree.get_proof(key);
    auto vr = db_.get(storage::key_root_index("VAL", h));
    if (!vr.has_value() || vr->size() != 32) return make_error(id, -32001, "validators_root unavailable");
    Hash32 root{};
    std::copy(vr->begin(), vr->end(), root.begin());

    std::ostringstream oss;
    oss << "{\"proof_format\":\"smt_v0\",\"height\":" << h << ",\"key_hex\":\"" << hex_encode32(key)
        << "\",\"root_hex\":\"" << hex_encode32(root) << "\",\"validators_root\":\"" << hex_encode32(root) << "\",";
    if (value.has_value()) oss << "\"value_hex\":\"" << hex_encode(*value) << "\",";
    else oss << "\"value_hex\":null,";
    oss << "\"siblings_hex\":[";
    for (size_t i = 0; i < proof.siblings.size(); ++i) {
      if (i) oss << ",";
      oss << "\"" << hex_encode32(proof.siblings[i]) << "\"";
    }
    oss << "],\"siblings\":[";
    for (size_t i = 0; i < proof.siblings.size(); ++i) {
      if (i) oss << ",";
      oss << "\"" << hex_encode32(proof.siblings[i]) << "\"";
    }
    oss << "]}";
    return make_result(id, oss.str());
  }

  if (*method == "broadcast_tx") {
    auto tx_hex = field_string(params, "tx_hex");
    if (!tx_hex) return make_error(id, -32602, "missing tx_hex");
    auto tx_bytes = hex_decode(*tx_hex);
    if (!tx_bytes) {
      return make_result(id, broadcast_result_json(false, "", "rejected", "", std::string("tx_invalid"),
                                                   std::string("bad tx hex"), false, "none", false, std::nullopt));
    }
    auto tx = Tx::parse(*tx_bytes);
    if (!tx.has_value()) {
      return make_result(id, broadcast_result_json(false, "", "rejected", "", std::string("tx_invalid"),
                                                   std::string("tx parse failed"), false, "none", false, std::nullopt));
    }
    const Hash32 txid = tx->txid();
    const std::string txid_hex = hex_encode32(txid);
    if (view->get_tx_index(txid).has_value()) {
      return make_result(id, broadcast_result_json(
                                 false, txid_hex, "rejected", "", std::string("tx_duplicate"),
                                 std::string("This transaction is already finalized or was previously submitted."),
                                 false, "none", false, std::nullopt));
    }
    const auto utxos = db_.load_utxos();
    const auto validators = db_.load_validators();
    consensus::ValidatorRegistry vr;
    for (const auto& [pub, info] : validators) vr.upsert(pub, info);
    auto tip = db_.get_tip();
    const auto runtime = view->get_node_runtime_status_snapshot();
    SpecialValidationContext ctx{
        .validators = &vr,
        .current_height = tip ? (tip->height + 1) : 1,
        .is_committee_member =
            [this](const PubKey32& pk, std::uint64_t h, std::uint32_t /*round*/) {
              auto committee = committee_for_height(h);
              if (!committee.has_value()) return false;
              return std::find(committee->begin(), committee->end(), pk) != committee->end();
            },
    };
    auto vrx = validate_tx(*tx, 1, utxos, &ctx);
    if (!vrx.ok) {
      const auto code = validation_error_code(vrx.error);
      const bool retryable = code == "tx_missing_or_unconfirmed_input";
      return make_result(id, broadcast_result_json(false, txid_hex, "rejected", "", code,
                                                   validation_error_message(vrx.error), retryable,
                                                   retry_class_for_error_code(code), false, std::nullopt));
    }
    if (runtime.has_value() && runtime->min_relay_fee != 0 && vrx.fee < runtime->min_relay_fee) {
      return make_result(id, broadcast_result_json(false, txid_hex, "rejected", "",
                                                   std::string("tx_fee_below_min_relay"),
                                                   std::string("Transaction fee is below the current minimum relay fee."),
                                                   true, retry_class_for_error_code("tx_fee_below_min_relay"),
                                                   false, std::nullopt));
    }
    if (runtime.has_value() && runtime->mempool_full &&
        runtime->min_fee_rate_to_enter_when_full_milliunits_per_byte.has_value() &&
        fee_rate_below_threshold(vrx.fee, tx_bytes->size(), *runtime->min_fee_rate_to_enter_when_full_milliunits_per_byte)) {
      return make_result(id, broadcast_result_json(
                                 false, txid_hex, "rejected", "", std::string("mempool_full_not_good_enough"),
                                 std::string("Network is busy. Transaction fee rate is too low for current mempool pressure."),
                                 true, retry_class_for_error_code("mempool_full_not_good_enough"), true,
                                 runtime->min_fee_rate_to_enter_when_full_milliunits_per_byte));
    }
    std::string err;
    if (!relay_tx_to_peer(*tx_bytes, &err)) {
      return make_result(id, broadcast_result_json(false, txid_hex, "rejected", "", std::string("relay_unavailable"), err,
                                                   true, retry_class_for_error_code("relay_unavailable"), false,
                                                   runtime.has_value() ? runtime->min_fee_rate_to_enter_when_full_milliunits_per_byte
                                                                       : std::nullopt));
    }
    return make_result(id, broadcast_result_json(true, txid_hex, "accepted_for_relay", "accepted_for_relay",
                                                 std::nullopt, std::nullopt, false, "none", false,
                                                 runtime.has_value() ? runtime->min_fee_rate_to_enter_when_full_milliunits_per_byte
                                                                     : std::nullopt));
  }

  return make_error(id, -32601, "method not found");
}

std::optional<Config> parse_args(int argc, char** argv) {
  Config cfg;
  cfg.network = mainnet_network();
  cfg.db_path = default_db_dir_for_network(cfg.network.name);
  cfg.port = cfg.network.lightserver_default_port;
  cfg.tx_relay_port = cfg.network.p2p_default_port;
  cfg.max_committee = cfg.network.max_committee;
  bool db_explicit = false;
  for (int i = 1; i < argc; ++i) {
    std::string a = argv[i];
    auto next = [&]() -> std::optional<std::string> {
      if (i + 1 >= argc) return std::nullopt;
      return std::string(argv[++i]);
    };
    if (a == "--db") {
      auto v = next();
      if (!v) return std::nullopt;
      cfg.db_path = *v;
      db_explicit = true;
    } else if (a == "--bind") {
      auto v = next();
      if (!v) return std::nullopt;
      cfg.bind_ip = *v;
    } else if (a == "--port") {
      auto v = next();
      if (!v) return std::nullopt;
      cfg.port = static_cast<std::uint16_t>(std::stoul(*v));
    } else if (a == "--relay-host") {
      auto v = next();
      if (!v) return std::nullopt;
      cfg.tx_relay_host = *v;
    } else if (a == "--relay-port") {
      auto v = next();
      if (!v) return std::nullopt;
      cfg.tx_relay_port = static_cast<std::uint16_t>(std::stoul(*v));
    } else if (a == "--mainnet") {
      std::cerr << "--mainnet is not needed in mainnet-only build; remove this flag\n";
      return std::nullopt;
    } else if (a == "--max-committee") {
      auto v = next();
      if (!v) return std::nullopt;
      cfg.max_committee = static_cast<std::size_t>(std::stoull(*v));
    } else {
      return std::nullopt;
    }
  }
  if (!db_explicit) cfg.db_path = default_db_dir_for_network(cfg.network.name);
  return cfg;
}

}  // namespace finalis::lightserver
