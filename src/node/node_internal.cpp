// SPDX-License-Identifier: MIT

#include "node_internal.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <limits>
#include <set>
#include <sstream>
#include <string_view>

#include "codec/bytes.hpp"
#include "consensus/state_commitment.hpp"
#include "crypto/hash.hpp"
#include "crypto/smt.hpp"

namespace finalis::node::detail {

std::mutex g_local_bus_mu;
std::vector<Node*> g_local_bus_nodes;

std::string short_pub_hex(const PubKey32& pub) {
  Bytes b(pub.begin(), pub.begin() + 4);
  return hex_encode(b);
}

std::string short_hash_hex(const Hash32& h) {
  Bytes b(h.begin(), h.begin() + 4);
  return hex_encode(b);
}

const char* msg_type_name(std::uint16_t msg_type) {
  switch (msg_type) {
    case p2p::MsgType::VERSION:
      return "VERSION";
    case p2p::MsgType::VERACK:
      return "VERACK";
    case p2p::MsgType::GET_FINALIZED_TIP:
      return "GET_FINALIZED_TIP";
    case p2p::MsgType::FINALIZED_TIP:
      return "FINALIZED_TIP";
    case p2p::MsgType::PROPOSE:
      return "PROPOSE";
    case p2p::MsgType::VOTE:
      return "VOTE";
    case p2p::MsgType::TIMEOUT_VOTE:
      return "TIMEOUT_VOTE";
    case p2p::MsgType::GET_TRANSITION:
      return "GET_TRANSITION";
    case p2p::MsgType::TRANSITION:
      return "TRANSITION";
    case p2p::MsgType::TX:
      return "TX";
    case p2p::MsgType::GETADDR:
      return "GETADDR";
    case p2p::MsgType::ADDR:
      return "ADDR";
    case p2p::MsgType::PING:
      return "PING";
    case p2p::MsgType::PONG:
      return "PONG";
    case p2p::MsgType::GET_TRANSITION_BY_HEIGHT:
      return "GET_TRANSITION_BY_HEIGHT";
    case p2p::MsgType::EPOCH_TICKET:
      return "EPOCH_TICKET";
    case p2p::MsgType::GET_EPOCH_TICKETS:
      return "GET_EPOCH_TICKETS";
    case p2p::MsgType::EPOCH_TICKETS:
      return "EPOCH_TICKETS";
    case p2p::MsgType::INGRESS_RECORD:
      return "INGRESS_RECORD";
    case p2p::MsgType::GET_INGRESS_TIPS:
      return "GET_INGRESS_TIPS";
    case p2p::MsgType::INGRESS_TIPS:
      return "INGRESS_TIPS";
    case p2p::MsgType::GET_INGRESS_RANGE:
      return "GET_INGRESS_RANGE";
    case p2p::MsgType::INGRESS_RANGE:
      return "INGRESS_RANGE";
    default:
      return "UNKNOWN";
  }
}

const char* availability_status_name(availability::AvailabilityOperatorStatus status) {
  switch (status) {
    case availability::AvailabilityOperatorStatus::WARMUP:
      return "WARMUP";
    case availability::AvailabilityOperatorStatus::ACTIVE:
      return "ACTIVE";
    case availability::AvailabilityOperatorStatus::PROBATION:
      return "PROBATION";
    case availability::AvailabilityOperatorStatus::EJECTED:
      return "EJECTED";
  }
  return "UNKNOWN";
}

const char* checkpoint_derivation_mode_name(storage::FinalizedCommitteeDerivationMode mode) {
  switch (mode) {
    case storage::FinalizedCommitteeDerivationMode::NORMAL:
      return "normal";
    case storage::FinalizedCommitteeDerivationMode::FALLBACK:
      return "fallback";
  }
  return "unknown";
}

const char* checkpoint_fallback_reason_name(storage::FinalizedCommitteeFallbackReason reason) {
  switch (reason) {
    case storage::FinalizedCommitteeFallbackReason::NONE:
      return "none";
    case storage::FinalizedCommitteeFallbackReason::INSUFFICIENT_ELIGIBLE_OPERATORS:
      return "insufficient_eligible_operators";
    case storage::FinalizedCommitteeFallbackReason::HYSTERESIS_RECOVERY_PENDING:
      return "hysteresis_recovery_pending";
    case storage::FinalizedCommitteeFallbackReason::EMERGENCY_PRIOR_COMMITTEE:
      return "emergency_prior_committee";
  }
  return "unknown";
}

std::size_t ingress_record_wire_size(const p2p::IngressRecordMsg& record) {
  constexpr std::size_t kIngressRecordOverhead = 24;
  const std::size_t cert_size = record.certificate.serialize().size();
  if (cert_size > std::numeric_limits<std::size_t>::max() - record.tx_bytes.size()) {
    return std::numeric_limits<std::size_t>::max();
  }
  const std::size_t payload_size = cert_size + record.tx_bytes.size();
  if (payload_size > std::numeric_limits<std::size_t>::max() - kIngressRecordOverhead) {
    return std::numeric_limits<std::size_t>::max();
  }
  return payload_size + kIngressRecordOverhead;
}

std::size_t ingress_range_wire_size(const p2p::IngressRangeMsg& msg) {
  std::size_t total = 32;
  for (const auto& record : msg.records) {
    const std::size_t record_size = ingress_record_wire_size(record);
    if (record_size > std::numeric_limits<std::size_t>::max() - total) {
      return std::numeric_limits<std::size_t>::max();
    }
    total += record_size;
  }
  return total;
}

bool load_certified_ingress_record_from_db(const storage::DB& db, std::uint32_t lane, std::uint64_t seq,
                                           consensus::CertifiedIngressRecord* out, std::string* error) {
  if (!out) {
    if (error) *error = "missing-certified-ingress-output";
    return false;
  }
  const auto cert_bytes = db.get_ingress_certificate(lane, seq);
  if (!cert_bytes.has_value()) {
    if (error) *error = "missing-certified-lane-record lane=" + std::to_string(lane) + " seq=" + std::to_string(seq);
    return false;
  }
  const auto cert = IngressCertificate::parse(*cert_bytes);
  if (!cert.has_value() || cert->lane != lane || cert->seq != seq) {
    if (error) *error = "invalid-certified-lane-record lane=" + std::to_string(lane) + " seq=" + std::to_string(seq);
    return false;
  }
  const auto tx_bytes = db.get_ingress_bytes(cert->txid);
  if (!tx_bytes.has_value()) {
    if (error) *error = "missing-certified-ingress-bytes lane=" + std::to_string(lane) +
                        " seq=" + std::to_string(seq);
    return false;
  }
  *out = consensus::CertifiedIngressRecord{*cert, *tx_bytes};
  return true;
}

std::vector<std::string> parse_endpoint_list(const std::string& raw) {
  std::vector<std::string> out;
  std::string current;
  current.reserve(raw.size());
  bool escaping = false;
  for (char ch : raw) {
    if (escaping) {
      current.push_back(ch);
      escaping = false;
      continue;
    }
    if (ch == '\\') {
      escaping = true;
      continue;
    }
    if (ch == ',') {
      if (!current.empty()) out.push_back(current);
      current.clear();
      continue;
    }
    current.push_back(ch);
  }
  if (escaping) current.push_back('\\');
  if (!current.empty()) out.push_back(current);
  return out;
}

bool is_local_only_bind(const std::string& host) {
  return host == "127.0.0.1" || host == "localhost" || host == "::1";
}

bool is_unroutable_ip_literal(const std::string& ip) {
  in_addr v4{};
  if (inet_pton(AF_INET, ip.c_str(), &v4) == 1) {
    const std::uint32_t host = ntohl(v4.s_addr);
    const std::uint8_t a = static_cast<std::uint8_t>((host >> 24) & 0xFF);
    const std::uint8_t b = static_cast<std::uint8_t>((host >> 16) & 0xFF);
    if (a == 0 || a == 10 || a == 127) return true;
    if (a == 169 && b == 254) return true;
    if (a == 172 && b >= 16 && b <= 31) return true;
    if (a == 192 && b == 168) return true;
    if (a == 100 && b >= 64 && b <= 127) return true;  // 100.64.0.0/10 (CGNAT)
    if (a >= 224) return true;
    return false;
  }
  in6_addr v6{};
  if (inet_pton(AF_INET6, ip.c_str(), &v6) == 1) {
    if (IN6_IS_ADDR_UNSPECIFIED(&v6) || IN6_IS_ADDR_LOOPBACK(&v6) || IN6_IS_ADDR_MULTICAST(&v6)) return true;
    const std::uint8_t first = v6.s6_addr[0];
    const std::uint8_t second = v6.s6_addr[1];
    if ((first & 0xFE) == 0xFC) return true;                // fc00::/7
    if (first == 0xFE && (second & 0xC0) == 0x80) return true;  // fe80::/10
    return false;
  }
  return false;
}

bool endpoint_fingerprint_safe(const std::string& endpoint) {
  return endpoint.find(';') == std::string::npos;
}

bool advertised_endpoint_likely_public(const p2p::NetAddress& addr) {
  if (addr.ip.empty() || addr.port == 0) return false;
  if (is_unroutable_ip_literal(addr.ip)) return false;
  return true;
}

std::optional<std::pair<std::uint32_t, std::uint64_t>> parse_lane_seq_from_error(const std::string& error) {
  const std::string lane_marker = "lane=";
  const std::string seq_marker = "seq=";
  const auto lane_pos = error.find(lane_marker);
  const auto seq_pos = error.find(seq_marker);
  if (lane_pos == std::string::npos || seq_pos == std::string::npos) return std::nullopt;
  const std::size_t lane_start = lane_pos + lane_marker.size();
  std::size_t lane_end = lane_start;
  while (lane_end < error.size() && error[lane_end] >= '0' && error[lane_end] <= '9') ++lane_end;
  if (lane_end == lane_start) return std::nullopt;
  const std::size_t seq_start = seq_pos + seq_marker.size();
  std::size_t seq_end = seq_start;
  while (seq_end < error.size() && error[seq_end] >= '0' && error[seq_end] <= '9') ++seq_end;
  if (seq_end == seq_start) return std::nullopt;
  try {
    const auto lane = static_cast<std::uint32_t>(std::stoul(error.substr(lane_start, lane_end - lane_start)));
    const auto seq = static_cast<std::uint64_t>(std::stoull(error.substr(seq_start, seq_end - seq_start)));
    if (lane >= INGRESS_LANE_COUNT || seq == 0) return std::nullopt;
    return std::make_pair(lane, seq);
  } catch (...) {
    return std::nullopt;
  }
}

bool same_epoch_committee_snapshot(const consensus::EpochCommitteeSnapshot& a,
                                   const consensus::EpochCommitteeSnapshot& b) {
  if (a.epoch != b.epoch || a.challenge_anchor != b.challenge_anchor || a.ordered_members != b.ordered_members ||
      a.selected_winners.size() != b.selected_winners.size()) {
    return false;
  }
  for (std::size_t i = 0; i < a.selected_winners.size(); ++i) {
    const auto& lhs = a.selected_winners[i];
    const auto& rhs = b.selected_winners[i];
    if (lhs.participant_pubkey != rhs.participant_pubkey || lhs.work_hash != rhs.work_hash || lhs.nonce != rhs.nonce ||
        lhs.source_height != rhs.source_height) {
      return false;
    }
  }
  return true;
}

std::string endpoint_to_ip(std::string endpoint) {
  const auto pos = endpoint.find(':');
  if (pos == std::string::npos) return endpoint;
  return endpoint.substr(0, pos);
}

std::string token_value(const std::string& s, const std::string& key) {
  const std::string needle = key + "=";
  const auto pos = s.find(needle);
  if (pos == std::string::npos) return "";
  auto end = s.find(' ', pos + needle.size());
  if (end == std::string::npos) end = s.size();
  return s.substr(pos + needle.size(), end - (pos + needle.size()));
}

std::string ascii_lower(std::string s) {
  for (auto& ch : s) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
  return s;
}

std::string network_id_hex(const NetworkConfig& cfg) {
  return hex_encode(Bytes(cfg.network_id.begin(), cfg.network_id.end()));
}

std::string consensus_rules_fingerprint(const NetworkConfig& cfg, const ChainId& chain_id, std::uint32_t cv) {
  codec::ByteWriter w;
  w.bytes_fixed(cfg.network_id);
  w.u32le(cfg.protocol_version);
  w.u64le(cfg.feature_flags);
  w.u64le(cfg.magic);
  w.u64le(cfg.committee_epoch_blocks);
  w.u32le(cfg.max_committee);
  w.u32le(cv);
  const auto genesis = hex_decode(chain_id.genesis_hash_hex);
  if (genesis.has_value() && genesis->size() == 32) {
    Hash32 g{};
    std::copy(genesis->begin(), genesis->end(), g.begin());
    w.bytes_fixed(g);
  } else {
    w.bytes_fixed(zero_hash());
  }
  return hex_encode32(crypto::sha256d(w.data()));
}

bool debug_economics_logs_enabled() {
  const char* enabled = std::getenv("FINALIS_DEBUG_ECONOMICS");
  return enabled && std::string_view(enabled) == "1";
}

bool debug_finality_logs_enabled() {
  const char* enabled = std::getenv("FINALIS_DEBUG_FINALITY");
  return enabled && std::string_view(enabled) == "1";
}

bool debug_liveness_logs_enabled() {
  const char* enabled = std::getenv("FINALIS_DEBUG_LIVENESS");
  return enabled && std::string_view(enabled) == "1";
}

consensus::ValidatorBestTicket checkpoint_best_ticket_for_member(
    const NetworkConfig& network, const consensus::ValidatorRegistry& validators,
    const storage::FinalizedCommitteeCheckpoint& checkpoint, std::size_t index) {
  const auto& pub = checkpoint.ordered_members[index];
  if (index < checkpoint.ordered_ticket_hashes.size() && index < checkpoint.ordered_ticket_nonces.size()) {
    return consensus::ValidatorBestTicket{pub, checkpoint.ordered_ticket_hashes[index], checkpoint.ordered_ticket_nonces[index]};
  }

  const auto epoch = checkpoint.epoch_start_height;
  PubKey32 operator_id = pub;
  if (index < checkpoint.ordered_operator_ids.size() && checkpoint.ordered_operator_ids[index] != PubKey32{}) {
    operator_id = checkpoint.ordered_operator_ids[index];
      } else if (auto it = validators.all().find(pub); it != validators.all().end()) {
    operator_id = consensus::canonical_operator_id(pub, it->second);
  }
  auto ticket =
      consensus::best_epoch_ticket_for_operator_id(epoch, checkpoint.epoch_seed, operator_id, epoch,
                                                   consensus::EPOCH_TICKET_MAX_NONCE);
  if (ticket.has_value() && consensus::epoch_ticket_meets_difficulty(*ticket, checkpoint.ticket_difficulty_bits)) {
    return consensus::ValidatorBestTicket{pub, ticket->work_hash, ticket->nonce};
  }
  return consensus::ValidatorBestTicket{pub, Hash32{}, 0};
}

std::vector<consensus::ValidatorBestTicket> checkpoint_winners(
    const NetworkConfig& network, const consensus::ValidatorRegistry& validators,
    const storage::FinalizedCommitteeCheckpoint& checkpoint) {
  std::vector<consensus::ValidatorBestTicket> winners;
  winners.reserve(checkpoint.ordered_members.size());
  for (std::size_t i = 0; i < checkpoint.ordered_members.size(); ++i) {
    winners.push_back(checkpoint_best_ticket_for_member(network, validators, checkpoint, i));
  }
  return winners;
}

std::vector<PubKey32> proposer_schedule_from_checkpoint(const NetworkConfig& network,
                                                        const consensus::ValidatorRegistry& validators,
                                                        const storage::FinalizedCommitteeCheckpoint& checkpoint,
                                                        std::uint64_t height) {
  const auto winners = checkpoint_winners(network, validators, checkpoint);
  return consensus::proposer_schedule_from_committee(
      winners, consensus::compute_proposer_seed(checkpoint.epoch_seed, height, consensus::compute_committee_root(winners)));
}

bool finalized_checkpoint_matches_epoch_snapshot(const storage::FinalizedCommitteeCheckpoint& checkpoint,
                                                 const consensus::EpochCommitteeSnapshot& snapshot) {
  if (checkpoint.ordered_members != snapshot.ordered_members) return false;
  if (checkpoint.ordered_ticket_hashes.size() != snapshot.selected_winners.size()) return false;
  if (checkpoint.ordered_ticket_nonces.size() != snapshot.selected_winners.size()) return false;
  for (std::size_t i = 0; i < snapshot.selected_winners.size(); ++i) {
    if (checkpoint.ordered_members[i] != snapshot.selected_winners[i].participant_pubkey) return false;
    if (checkpoint.ordered_ticket_hashes[i] != snapshot.selected_winners[i].work_hash) return false;
    if (checkpoint.ordered_ticket_nonces[i] != snapshot.selected_winners[i].nonce) return false;
  }
  return true;
}

consensus::EpochCommitteeSnapshot epoch_committee_snapshot_from_checkpoint(
    const storage::FinalizedCommitteeCheckpoint& checkpoint) {
  consensus::EpochCommitteeSnapshot snapshot;
  snapshot.epoch = checkpoint.epoch_start_height;
  snapshot.challenge_anchor = checkpoint.epoch_seed;
  snapshot.ordered_members = checkpoint.ordered_members;
  snapshot.selected_winners.reserve(checkpoint.ordered_members.size());
  for (std::size_t i = 0; i < checkpoint.ordered_members.size(); ++i) {
    if (i >= checkpoint.ordered_ticket_hashes.size() || i >= checkpoint.ordered_ticket_nonces.size()) break;
    snapshot.selected_winners.push_back(consensus::EpochCommitteeMember{
        .participant_pubkey = checkpoint.ordered_members[i],
        .work_hash = checkpoint.ordered_ticket_hashes[i],
        .nonce = checkpoint.ordered_ticket_nonces[i],
        .source_height = checkpoint.epoch_start_height,
    });
  }
  return snapshot;
}

bool same_validator_info(const consensus::ValidatorInfo& a, const consensus::ValidatorInfo& b) {
  return a.status == b.status && a.joined_height == b.joined_height && a.bonded_amount == b.bonded_amount &&
         a.operator_id == b.operator_id && a.has_bond == b.has_bond && a.bond_outpoint.txid == b.bond_outpoint.txid &&
         a.bond_outpoint.index == b.bond_outpoint.index && a.unbond_height == b.unbond_height &&
         a.eligible_count_window == b.eligible_count_window && a.participated_count_window == b.participated_count_window &&
         a.liveness_window_start == b.liveness_window_start && a.suspended_until_height == b.suspended_until_height &&
         a.last_join_height == b.last_join_height && a.last_exit_height == b.last_exit_height &&
         a.penalty_strikes == b.penalty_strikes;
}

bool same_validator_maps(const std::map<PubKey32, consensus::ValidatorInfo>& a,
                         const std::map<PubKey32, consensus::ValidatorInfo>& b) {
  if (a.size() != b.size()) return false;
  auto ita = a.begin();
  auto itb = b.begin();
  for (; ita != a.end(); ++ita, ++itb) {
    if (ita->first != itb->first) return false;
    if (!same_validator_info(ita->second, itb->second)) return false;
  }
  return true;
}

bool maybe_reactivate_single_exiting_validator_for_startup_migration(
    const NetworkConfig& network, consensus::CanonicalDerivedState* state, PubKey32* reactivated_pubkey) {
  if (state == nullptr) return false;
  const std::uint64_t next_height = state->finalized_height + 1;
  if (deferred_exit_fork_active(network, next_height)) return false;
  if (next_height > network.deferred_exit_activation_height) return false;
  if (!state->validators.active_sorted(next_height).empty()) return false;

  std::optional<PubKey32> chosen;
  for (const auto& [pub, info] : state->validators.all()) {
    if (info.status != consensus::ValidatorStatus::EXITING) continue;
    if (!info.has_bond || info.bonded_amount == 0) continue;
    if (!chosen.has_value() || pub < *chosen) chosen = pub;
  }
  if (!chosen.has_value()) return false;

  auto& all = state->validators.mutable_all();
  auto it = all.find(*chosen);
  if (it == all.end()) return false;
  it->second.status = consensus::ValidatorStatus::ACTIVE;
  if (reactivated_pubkey != nullptr) *reactivated_pubkey = *chosen;
  return true;
}

bool is_non_genesis_zero_bond_outpoint(const consensus::ValidatorInfo& info) {
  return info.has_bond && zero_outpoint(info.bond_outpoint) && info.joined_height != 0;
}

std::size_t repair_invalid_exiting_zero_bond_outpoints(consensus::ValidatorRegistry* validators, std::uint64_t height,
                                                       std::uint64_t unbond_delay_blocks,
                                                       const std::function<void(const std::string&)>& log_fn) {
  if (validators == nullptr) return 0;
  std::size_t repaired = 0;
  for (auto& [pub, info] : validators->mutable_all()) {
    if (info.status != consensus::ValidatorStatus::EXITING) continue;
    if (!is_non_genesis_zero_bond_outpoint(info)) continue;
    if (info.unbond_height == 0) continue;
    if (info.unbond_height > std::numeric_limits<std::uint64_t>::max() - unbond_delay_blocks) continue;
    if (height < info.unbond_height + unbond_delay_blocks) continue;
    if (validators->finalize_withdrawal(pub)) {
      ++repaired;
      log_fn("validator-exit-repair source=auto height=" + std::to_string(height) + " pub=" + short_pub_hex(pub) +
             " reason=non-genesis-zero-bond-outpoint-matured-unbond");
    }
  }
  return repaired;
}

std::size_t repair_matured_bootstrap_exiting_records(const NetworkConfig& network, consensus::ValidatorRegistry* validators,
                                                     std::uint64_t height, std::uint64_t unbond_delay_blocks,
                                                     const std::function<void(const std::string&)>& log_fn) {
  if (validators == nullptr) return 0;
  const std::uint64_t gate_height = height == std::numeric_limits<std::uint64_t>::max() ? height : (height + 1);
  if (!bootstrap_penalty_exit_protection_active_at_height(network, gate_height)) return 0;
  std::size_t repaired = 0;
  for (auto& [pub, info] : validators->mutable_all()) {
    const bool bootstrap_record =
        info.joined_height == 0 && info.has_bond && info.bond_outpoint.txid == zero_hash() && info.bond_outpoint.index == 0;
    if (!bootstrap_record) continue;
    if (info.status != consensus::ValidatorStatus::EXITING) continue;
    if (info.unbond_height == 0) continue;
    if (info.unbond_height > std::numeric_limits<std::uint64_t>::max() - unbond_delay_blocks) continue;
    if (height < info.unbond_height + unbond_delay_blocks) continue;
    if (validators->finalize_withdrawal(pub)) {
      ++repaired;
      log_fn("validator-bootstrap-exit-repair source=auto height=" + std::to_string(height) + " pub=" + short_pub_hex(pub) +
             " reason=bootstrap-exiting-matured-unbond");
    }
  }
  return repaired;
}

std::string validator_info_debug_string(const consensus::ValidatorInfo& info) {
  std::ostringstream oss;
  oss << "{status=" << static_cast<int>(info.status) << ",joined=" << info.joined_height
      << ",bonded=" << info.bonded_amount << ",operator=" << short_pub_hex(info.operator_id)
      << ",has_bond=" << (info.has_bond ? "1" : "0")
      << ",bond_outpoint=" << short_hash_hex(info.bond_outpoint.txid) << ":" << info.bond_outpoint.index
      << ",unbond=" << info.unbond_height << ",eligible=" << info.eligible_count_window
      << ",participated=" << info.participated_count_window << ",liveness=" << info.liveness_window_start
      << ",suspended_until=" << info.suspended_until_height << ",last_join=" << info.last_join_height
      << ",last_exit=" << info.last_exit_height << ",penalties=" << info.penalty_strikes << "}";
  return oss.str();
}

std::string validator_map_mismatch_reason(const std::map<PubKey32, consensus::ValidatorInfo>& a,
                                          const std::map<PubKey32, consensus::ValidatorInfo>& b) {
  if (a.size() != b.size()) {
    return "size persisted=" + std::to_string(a.size()) + " derived=" + std::to_string(b.size());
  }
  auto ita = a.begin();
  auto itb = b.begin();
  for (; ita != a.end(); ++ita, ++itb) {
    if (ita->first != itb->first) {
      return "pubkey persisted=" + short_pub_hex(ita->first) + " derived=" + short_pub_hex(itb->first);
    }
    if (!same_validator_info(ita->second, itb->second)) {
      return "info pubkey=" + short_pub_hex(ita->first) + " persisted=" + validator_info_debug_string(ita->second) +
             " derived=" + validator_info_debug_string(itb->second);
    }
  }
  return "unknown";
}

bool same_join_request(const ValidatorJoinRequest& a, const ValidatorJoinRequest& b) {
  return a.request_txid == b.request_txid && a.validator_pubkey == b.validator_pubkey &&
         a.payout_pubkey == b.payout_pubkey && a.bond_outpoint.txid == b.bond_outpoint.txid &&
         a.bond_outpoint.index == b.bond_outpoint.index && a.bond_amount == b.bond_amount &&
         a.requested_height == b.requested_height && a.approved_height == b.approved_height && a.status == b.status;
}

bool same_join_request_maps(const std::map<Hash32, ValidatorJoinRequest>& a,
                            const std::map<Hash32, ValidatorJoinRequest>& b) {
  if (a.size() != b.size()) return false;
  auto ita = a.begin();
  auto itb = b.begin();
  for (; ita != a.end(); ++ita, ++itb) {
    if (ita->first != itb->first) return false;
    if (!same_join_request(ita->second, itb->second)) return false;
  }
  return true;
}

bool same_epoch_reward_state(const storage::EpochRewardSettlementState& a, const storage::EpochRewardSettlementState& b) {
  return a.epoch_start_height == b.epoch_start_height && a.total_reward_units == b.total_reward_units &&
         a.fee_pool_units == b.fee_pool_units && a.reserve_accrual_units == b.reserve_accrual_units &&
         a.reserve_subsidy_units == b.reserve_subsidy_units &&
         a.settled == b.settled && a.reward_score_units == b.reward_score_units &&
         a.onboarding_score_units == b.onboarding_score_units &&
         a.expected_participation_units == b.expected_participation_units &&
         a.observed_participation_units == b.observed_participation_units;
}

bool same_epoch_reward_maps(const std::map<std::uint64_t, storage::EpochRewardSettlementState>& a,
                            const std::map<std::uint64_t, storage::EpochRewardSettlementState>& b) {
  if (a.size() != b.size()) return false;
  auto ita = a.begin();
  auto itb = b.begin();
  for (; ita != a.end(); ++ita, ++itb) {
    if (ita->first != itb->first) return false;
    if (!same_epoch_reward_state(ita->second, itb->second)) return false;
  }
  return true;
}

bool same_finalized_checkpoint(const storage::FinalizedCommitteeCheckpoint& a,
                               const storage::FinalizedCommitteeCheckpoint& b) {
  return a.epoch_start_height == b.epoch_start_height && a.epoch_seed == b.epoch_seed &&
         a.ticket_difficulty_bits == b.ticket_difficulty_bits && a.derivation_mode == b.derivation_mode &&
         a.fallback_reason == b.fallback_reason &&
         a.availability_eligible_operator_count == b.availability_eligible_operator_count &&
         a.availability_min_eligible_operators == b.availability_min_eligible_operators &&
         a.adaptive_target_committee_size == b.adaptive_target_committee_size &&
         a.adaptive_min_eligible == b.adaptive_min_eligible && a.adaptive_min_bond == b.adaptive_min_bond &&
         a.qualified_depth == b.qualified_depth && a.target_expand_streak == b.target_expand_streak &&
         a.target_contract_streak == b.target_contract_streak &&
         a.ordered_members == b.ordered_members &&
         a.ordered_operator_ids == b.ordered_operator_ids && a.ordered_base_weights == b.ordered_base_weights &&
         a.ordered_ticket_bonus_bps == b.ordered_ticket_bonus_bps && a.ordered_final_weights == b.ordered_final_weights &&
         a.ordered_ticket_hashes == b.ordered_ticket_hashes && a.ordered_ticket_nonces == b.ordered_ticket_nonces;
}

bool same_finalized_checkpoint_maps(const std::map<std::uint64_t, storage::FinalizedCommitteeCheckpoint>& a,
                                    const std::map<std::uint64_t, storage::FinalizedCommitteeCheckpoint>& b) {
  if (a.size() != b.size()) return false;
  auto ita = a.begin();
  auto itb = b.begin();
  for (; ita != a.end(); ++ita, ++itb) {
    if (ita->first != itb->first) return false;
    if (!same_finalized_checkpoint(ita->second, itb->second)) return false;
  }
  return true;
}

consensus::FinalizedIdentity finalized_identity_for_runtime_tip(std::uint64_t height, const Hash32& id) {
  // Tip persistence is intentionally type-erased. Runtime rehydrates the
  // semantic kind from finalized height in the frontier-only runtime.
  if (height == 0) return consensus::FinalizedIdentity::genesis(id);
  return consensus::FinalizedIdentity::transition(id);
}

bool finalized_identity_valid_for_frontier_runtime(std::uint64_t finalized_height,
                                                   const consensus::FinalizedIdentity& identity) {
  if (identity.is_transition()) return true;
  return finalized_height == 0 && identity.is_genesis();
}

FinalityCertificate make_finality_certificate(std::uint64_t height, std::uint32_t round, const Hash32& transition_id,
                                              std::size_t quorum_threshold, const std::vector<PubKey32>& committee,
                                              const std::vector<FinalitySig>& signatures) {
  FinalityCertificate cert;
  cert.height = height;
  cert.round = round;
  cert.frontier_transition_id = transition_id;
  cert.quorum_threshold = static_cast<std::uint32_t>(quorum_threshold);
  cert.committee_members = committee;
  cert.signatures = signatures;
  return cert;
}

// Core: all reads (scan_prefix, to diff stale rows) stay against `db`'s
// committed state, exactly as before; every write stages into `batch`
// instead of hitting the WAL immediately.
bool persist_canonical_cache_rows(storage::DB& db, storage::DB::Batch& batch, const consensus::CanonicalDerivedState& state) {
  const std::string utxo_prefix = storage::key_utxo_prefix();
  std::set<std::string> desired_utxos;
  desired_utxos.clear();
  for (const auto& [op, _] : state.utxos) desired_utxos.insert(storage::key_utxo(op));
  std::vector<std::string> utxos_to_erase;
  for (const auto& [key, _] : db.scan_prefix(utxo_prefix)) {
    if (desired_utxos.find(key) == desired_utxos.end()) {
      utxos_to_erase.push_back(key);
    }
  }
  for (const auto& key : utxos_to_erase) batch.erase(key);
  for (const auto& [op, entry] : state.utxos) batch.put_utxo_v2(op, entry);

  const std::string script_utxo_prefix = storage::key_script_utxo_prefix(Hash32{}).substr(0, 3);
  std::set<std::string> desired_script_utxos;
  desired_script_utxos.clear();
  for (const auto& [op, entry] : state.utxos) {
    const auto transparent = transparent_txout_from_utxo_entry(entry);
    if (!transparent.has_value()) continue;
    const auto scripthash = crypto::sha256(transparent->script_pubkey);
    desired_script_utxos.insert(storage::key_script_utxo(scripthash, op));
  }
  std::vector<std::string> script_utxos_to_erase;
  for (const auto& [key, _] : db.scan_prefix(script_utxo_prefix)) {
    if (desired_script_utxos.find(key) == desired_script_utxos.end()) {
      script_utxos_to_erase.push_back(key);
    }
  }
  for (const auto& key : script_utxos_to_erase) batch.erase(key);
  for (const auto& [op, entry] : state.utxos) {
    const auto transparent = transparent_txout_from_utxo_entry(entry);
    if (!transparent.has_value()) continue;
    const auto scripthash = crypto::sha256(transparent->script_pubkey);
    batch.put_script_utxo(scripthash, op, *transparent, state.finalized_height);
  }

  for (const auto& [pub, info] : state.validators.all()) batch.put_validator(pub, info);
  for (const auto& [txid, req] : state.validator_join_requests) batch.put_validator_join_request(txid, req);
  for (const auto& [epoch, reward_state] : state.epoch_reward_states) {
    (void)epoch;
    batch.put_epoch_reward_settlement(reward_state);
  }
  batch.put_protocol_reserve_balance(state.protocol_reserve_balance_units);
  std::set<std::uint64_t> desired_checkpoint_epochs;
  for (const auto& [epoch, _] : state.finalized_committee_checkpoints) {
    desired_checkpoint_epochs.insert(epoch);
  }
  std::vector<std::string> checkpoint_keys_to_erase;
  for (const auto& [key, _] : db.scan_prefix("CE:")) {
    const auto epoch_bytes = hex_decode(key.substr(3));
    if (!epoch_bytes.has_value() || epoch_bytes->size() != sizeof(std::uint64_t)) {
      checkpoint_keys_to_erase.push_back(key);
      continue;
    }
    codec::ByteReader r(*epoch_bytes);
    const auto epoch = r.u64le();
    if (!epoch.has_value() || desired_checkpoint_epochs.find(*epoch) == desired_checkpoint_epochs.end()) {
      checkpoint_keys_to_erase.push_back(key);
    }
  }
  for (const auto& key : checkpoint_keys_to_erase) batch.erase(key);
  for (const auto& [epoch, checkpoint] : state.finalized_committee_checkpoints) {
    (void)epoch;
    batch.put_finalized_committee_checkpoint(checkpoint);
  }
  batch.put(kFinalizedRandomnessKey, Bytes(state.finalized_randomness.begin(), state.finalized_randomness.end()));
  codec::ByteWriter w_start;
  w_start.u64le(state.validator_join_window_start_height);
  batch.put(kValidatorJoinWindowStartKey, w_start.take());
  codec::ByteWriter w_count;
  w_count.u32le(state.validator_join_count_in_window);
  batch.put(kValidatorJoinWindowCountKey, w_count.take());
  codec::ByteWriter w_liveness;
  w_liveness.u64le(state.validator_liveness_window_start_height);
  batch.put(kValidatorLivenessWindowStartKey, w_liveness.take());
  return true;
}

// Convenience wrapper for non-hot-path callers (genesis/rebuild/fast-sync
// fixups): stages into a throwaway batch and commits it immediately.
bool persist_canonical_cache_rows(storage::DB& db, const consensus::CanonicalDerivedState& state) {
  storage::DB::Batch batch(db);
  if (!persist_canonical_cache_rows(db, batch, state)) return false;
  return db.write_batch(batch);
}

bool certificate_matches_checkpoint_committee(const FinalityCertificate& cert,
                                              const storage::FinalizedCommitteeCheckpoint& checkpoint) {
  if (cert.committee_members == consensus::checkpoint_committee_for_round(checkpoint, cert.round)) return true;
  if (cert.round == 0) return false;
  if (auto legacy = consensus::legacy_checkpoint_ticket_pow_fallback_member_for_round(checkpoint, cert.round);
      legacy.has_value()) {
    return cert.committee_members.size() == 1 && cert.committee_members.front() == *legacy;
  }
  return false;
}

Hash32 consensus_payload_id(const FrontierTransition& transition) {
  codec::ByteWriter w;
  w.bytes(Bytes{'S', 'C', '-', 'F', 'R', 'O', 'N', 'T', 'I', 'E', 'R', '-', 'L', 'O', 'C', 'K', '-', 'P', 'A', 'Y',
                'L', 'O', 'A', 'D', '-', 'V', '1'});
  w.bytes_fixed(transition.prev_finalized_hash);
  w.bytes_fixed(transition.prev_finality_link_hash);
  w.u64le(transition.height);
  w.varbytes(transition.prev_vector.serialize());
  w.varbytes(transition.next_vector.serialize());
  w.bytes_fixed(transition.ingress_commitment);
  w.u64le(transition.prev_frontier);
  w.u64le(transition.next_frontier);
  w.bytes_fixed(transition.prev_state_root);
  w.bytes_fixed(transition.next_state_root);
  w.bytes_fixed(transition.ordered_slice_commitment);
  w.bytes_fixed(transition.decisions_commitment);
  w.bytes_fixed(transition.settlement_commitment);
  return crypto::sha256d(w.data());
}

std::string key_consensus_locked_proposal(std::uint64_t height) {
  codec::ByteWriter w;
  w.u64le(height);
  return std::string(kConsensusLockedProposalPrefix) + hex_encode(w.data());
}

bool parse_consensus_safety_state(const Bytes& b, std::optional<std::pair<Hash32, std::uint32_t>>* lock_state,
                                  std::optional<QuorumCertificate>* qc_state, std::optional<Hash32>* qc_payload_id) {
  std::optional<std::pair<Hash32, std::uint32_t>> parsed_lock;
  std::optional<QuorumCertificate> parsed_qc;
  std::optional<Hash32> parsed_payload;
  const bool ok = codec::parse_exact(b, [&](codec::ByteReader& r) {
    auto has_lock = r.u8();
    if (!has_lock) return false;
    if (*has_lock != 0) {
      auto lock_block = r.bytes_fixed<32>();
      auto lock_round = r.u32le();
      if (!lock_block || !lock_round) return false;
      parsed_lock = std::make_pair(*lock_block, *lock_round);
    }
    auto has_qc = r.u8();
    if (!has_qc) return false;
    if (*has_qc != 0) {
      QuorumCertificate qc;
      auto height = r.u64le();
      auto round = r.u32le();
      auto transition_id = r.bytes_fixed<32>();
      auto has_payload = r.u8();
      if (!height || !round || !transition_id || !has_payload) return false;
      qc.height = *height;
      qc.round = *round;
      qc.frontier_transition_id = *transition_id;
      if (*has_payload != 0) {
        auto payload = r.bytes_fixed<32>();
        if (!payload) return false;
        parsed_payload = *payload;
      }
      auto sig_count = r.varint();
      if (!sig_count) return false;
      qc.signatures.reserve(*sig_count);
      for (std::uint64_t i = 0; i < *sig_count; ++i) {
        auto pub = r.bytes_fixed<32>();
        auto sig = r.bytes_fixed<64>();
        if (!pub || !sig) return false;
        qc.signatures.push_back(FinalitySig{*pub, *sig});
      }
      parsed_qc = qc;
    }
    return true;
  });
  if (!ok) return false;
  if (lock_state) *lock_state = parsed_lock;
  if (qc_state) *qc_state = parsed_qc;
  if (qc_payload_id) *qc_payload_id = parsed_payload;
  return true;
}

void sync_smt_tree(storage::DB& db, storage::DB::Batch& batch, const std::string& tree_id,
                   const std::vector<std::pair<Hash32, Bytes>>& leaves) {
  const std::string prefix = storage::key_smt_leaf_prefix(tree_id);
  std::set<std::string> desired;
  desired.clear();
  for (const auto& [k, _] : leaves) desired.insert(storage::key_smt_leaf(tree_id, k));
  for (const auto& [k, _] : db.scan_prefix(prefix)) {
    if (desired.find(k) == desired.end()) batch.put(k, {});
  }
  for (const auto& [k, v] : leaves) batch.put(storage::key_smt_leaf(tree_id, k), v);
}

// Core: stages every root/leaf write into `batch` instead of writing immediately.
// `db` is still needed for the scan_prefix reads sync_smt_tree uses to diff stale leaves.
StateRoots persist_state_roots(storage::DB& db, storage::DB::Batch& batch, std::uint64_t height, const UtxoSetV2& utxos,
                               const consensus::ValidatorRegistry& validators, std::uint32_t validation_rules_version) {
  std::vector<std::pair<Hash32, Bytes>> utxo_leaves;
  utxo_leaves.reserve(utxos.size());
  for (const auto& [op, ue] : utxos) {
    utxo_leaves.push_back({consensus::utxo_commitment_key(op), consensus::utxo_commitment_value(ue)});
  }
  std::vector<std::pair<Hash32, Bytes>> validator_leaves;
  validator_leaves.reserve(validators.all().size());
  for (const auto& [pub, info] : validators.all()) {
    validator_leaves.push_back(
        {consensus::validator_commitment_key(pub), consensus::validator_commitment_value(info, validation_rules_version)});
  }

  sync_smt_tree(db, batch, kSmtTreeUtxo, utxo_leaves);
  sync_smt_tree(db, batch, kSmtTreeValidators, validator_leaves);

  StateRoots roots{};
  roots.utxo_root = crypto::SparseMerkleTree::compute_root_from_leaves(utxo_leaves);
  roots.validators_root = crypto::SparseMerkleTree::compute_root_from_leaves(validator_leaves);
  // SparseMerkleTree::set_root_for_height is just storage::key_smt_root(tree_id, height) -> db.put;
  // stage it directly rather than constructing a tree object bound to the immediate-write db.
  batch.put(storage::key_smt_root(kSmtTreeUtxo, height), Bytes(roots.utxo_root.begin(), roots.utxo_root.end()));
  batch.put(storage::key_smt_root(kSmtTreeValidators, height), Bytes(roots.validators_root.begin(), roots.validators_root.end()));
  batch.put(storage::key_root_index("UTXO", height), Bytes(roots.utxo_root.begin(), roots.utxo_root.end()));
  batch.put(storage::key_root_index("VAL", height), Bytes(roots.validators_root.begin(), roots.validators_root.end()));
  return roots;
}

// Convenience wrapper for the non-hot-path callers (genesis/rebuild/fast-sync
// fixups): stages into a throwaway batch and commits it immediately, so
// callers that don't share a batch with surrounding writes still get a single
// atomic commit instead of the previous handful of separate Put calls.
StateRoots persist_state_roots(storage::DB& db, std::uint64_t height, const UtxoSetV2& utxos,
                               const consensus::ValidatorRegistry& validators, std::uint32_t validation_rules_version) {
  storage::DB::Batch batch(db);
  StateRoots roots = persist_state_roots(db, batch, height, utxos, validators, validation_rules_version);
  (void)db.write_batch(batch);
  return roots;
}

}  // namespace finalis::node::detail
