#include "node.hpp"

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <limits>
#include <cerrno>
#include <signal.h>
#include <cstdlib>
#include <set>
#include <sstream>
#include <string_view>

#ifndef _WIN32
#include <ifaddrs.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#include "address/address.hpp"
#include "codec/bytes.hpp"
#include "consensus/canonical_derivation.hpp"
#include "consensus/randomness.hpp"
#include "consensus/state_commitment.hpp"
#include "consensus/finalized_committee.hpp"
#include "consensus/ingress.hpp"
#include "consensus/validator_registry.hpp"
#include "consensus/monetary.hpp"
#include "common/paths.hpp"
#include "common/socket_compat.hpp"
#include "common/wide_arith.hpp"
#include "common/version.hpp"
#include "crypto/ed25519.hpp"
#include "crypto/hash.hpp"
#include "crypto/smt.hpp"
#include "genesis/embedded_mainnet.hpp"
#include "genesis/genesis.hpp"
#include "keystore/validator_keystore.hpp"
#include "merkle/merkle.hpp"
#include "utxo/confidential_tx.hpp"
#include "utxo/signing.hpp"

namespace finalis::node {
namespace {
constexpr std::uint32_t kFixedValidationRulesVersion = 7;

constexpr std::size_t kMaxBlockTxs = 1000;
constexpr std::size_t kMaxBlockBytes = 1 * 1024 * 1024;
constexpr std::size_t kMaxIngressRangeRequestRecords = 1024;
constexpr std::size_t kMaxIngressRangeResponseRecords = 1024;
constexpr std::size_t kMaxIngressRangeResponseBytes = 512 * 1024;
constexpr std::size_t kMaxIngressPrevalidationBytes = 512 * 1024;
constexpr std::size_t kMaxOutstandingIngressRequestsPerPeer = 8;
constexpr std::uint64_t kDefaultPolicyMinRelayFeeUnits = 1'000ULL;
constexpr std::size_t kMaxCandidateBlocks = 512;
constexpr std::size_t kMaxCandidateBlockBytes = 32 * 1024 * 1024;
constexpr std::uint32_t kProposalRoundWindow = 32;
constexpr std::uint64_t kForwardSyncWindow = 16;
constexpr std::size_t kAdaptiveTelemetryWindowEpochs = 16;

std::string short_pub_hex(const PubKey32& pub) {
  Bytes b(pub.begin(), pub.begin() + 4);
  return hex_encode(b);
}

std::string short_hash_hex(const Hash32& h) {
  Bytes b(h.begin(), h.begin() + 4);
  return hex_encode(b);
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
  }
  return "unknown";
}

struct AvailabilityCommitteeDecision {
  storage::FinalizedCommitteeDerivationMode mode{storage::FinalizedCommitteeDerivationMode::NORMAL};
  storage::FinalizedCommitteeFallbackReason fallback_reason{storage::FinalizedCommitteeFallbackReason::NONE};
  std::uint64_t eligible_operator_count{0};
  std::uint64_t min_eligible_operators{0};
  std::uint64_t effective_committee_size{0};
  consensus::AdaptiveCheckpointParameters adaptive{};
};

std::optional<storage::FinalizedCommitteeCheckpoint> previous_checkpoint_for_epoch(
    const std::map<std::uint64_t, storage::FinalizedCommitteeCheckpoint>& checkpoints, std::uint64_t epoch_start_height,
    std::uint64_t epoch_blocks) {
  if (epoch_start_height <= epoch_blocks) return std::nullopt;
  const auto previous_epoch_start = epoch_start_height - epoch_blocks;
  auto it = checkpoints.find(previous_epoch_start);
  if (it == checkpoints.end()) return std::nullopt;
  return it->second;
}

AvailabilityCommitteeDecision decide_availability_committee_mode(
    const availability::AvailabilityPersistentState* availability_state,
    const availability::AvailabilityConfig& availability_cfg,
    const std::optional<storage::FinalizedCommitteeCheckpoint>& previous_checkpoint,
    const consensus::ValidatorRegistry& validators, std::uint64_t height) {
  AvailabilityCommitteeDecision decision;
  const auto previous = consensus::adaptive_checkpoint_parameters_from_metadata(previous_checkpoint);
  const auto qualified_cfg = consensus::availability_config_with_min_bond(availability_cfg, previous.min_bond);
  if (availability_state) {
    decision.adaptive.qualified_depth = consensus::qualified_depth_at_checkpoint(validators, height, previous.min_bond,
                                                                                 *availability_state, qualified_cfg);
  }
  decision.adaptive = consensus::derive_adaptive_checkpoint_parameters(previous_checkpoint, decision.adaptive.qualified_depth);
  if (consensus::bootstrap_availability_grace_active(validators, height)) {
    decision.adaptive.target_committee_size = 1;
    decision.adaptive.min_eligible_operators = 1;
    decision.adaptive.min_bond = consensus::genesis_validator_bond_amount();
    decision.adaptive.qualified_depth = std::max<std::uint64_t>(1, decision.adaptive.qualified_depth);
    decision.adaptive.target_expand_streak = 0;
    decision.adaptive.target_contract_streak = 0;
  }
  decision.min_eligible_operators = decision.adaptive.min_eligible_operators;
  if (availability_state) {
    decision.eligible_operator_count = consensus::count_eligible_operators_at_checkpoint(
        validators, height, *availability_state,
        consensus::availability_config_with_min_bond(availability_cfg, decision.adaptive.min_bond));
  }
  if (decision.min_eligible_operators == 0) return decision;
  decision.effective_committee_size =
      std::max<std::uint64_t>(1, std::min(decision.eligible_operator_count, decision.adaptive.target_committee_size));
  if (decision.eligible_operator_count < decision.min_eligible_operators) {
    decision.mode = storage::FinalizedCommitteeDerivationMode::FALLBACK;
    decision.fallback_reason = storage::FinalizedCommitteeFallbackReason::INSUFFICIENT_ELIGIBLE_OPERATORS;
    return decision;
  }
  const auto previous_mode =
      previous_checkpoint.has_value() ? std::optional<storage::FinalizedCommitteeDerivationMode>(previous_checkpoint->derivation_mode)
                                      : std::nullopt;
  const std::uint64_t recovery_threshold = decision.adaptive.target_committee_size <= 3
                                               ? decision.adaptive.target_committee_size
                                               : (decision.adaptive.target_committee_size <= 7
                                                      ? decision.adaptive.target_committee_size + 1ULL
                                                      : decision.adaptive.target_committee_size + 2ULL);
  if (previous_mode == storage::FinalizedCommitteeDerivationMode::FALLBACK &&
      decision.eligible_operator_count < recovery_threshold) {
    decision.mode = storage::FinalizedCommitteeDerivationMode::FALLBACK;
    decision.fallback_reason = storage::FinalizedCommitteeFallbackReason::HYSTERESIS_RECOVERY_PENDING;
  }
  return decision;
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

p2p::MisbehaviorReason ingress_fault_reason_for(const std::string& error) {
  if (error == "ingress-equivocation-detected" || error == "ingress-equivocation-evidence-store-failed") {
    return p2p::MisbehaviorReason::INGRESS_EQUIVOCATION;
  }
  return p2p::MisbehaviorReason::INVALID_INGRESS;
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

bool restart_debug_enabled() {
  const char* v = std::getenv("FINALIS_RESTART_DEBUG");
  if (!v) return false;
  return std::string(v) == "1" || std::string(v) == "true" || std::string(v) == "yes";
}

bool is_loopback_seed_host(const std::string& host) {
  if (host == "localhost") return true;
  if (host == "::1") return true;
  return host == "127.0.0.1" || host.rfind("127.", 0) == 0;
}

struct FrontierBuildSelection {
  FrontierVector next_vector{};
  consensus::CertifiedIngressLaneRecords lane_records;
  std::vector<Bytes> ordered_records;
};

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

bool inspect_frontier_ordered_record_supported(const Bytes& raw_record, std::size_t index, Hash32* txid_out,
                                               std::string* error) {
  const auto tx = parse_any_tx(raw_record);
  if (!tx.has_value()) {
    if (error) *error = "frontier-ordered-record-parse-failed index=" + std::to_string(index);
    return false;
  }
  if (txid_out) *txid_out = txid_any(*tx);
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

std::vector<std::string> resolve_ipv4_addresses(const std::string& host) {
  addrinfo hints{};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  addrinfo* res = nullptr;
  if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0 || res == nullptr) return {};

  std::set<std::string> unique;
  for (addrinfo* it = res; it != nullptr; it = it->ai_next) {
    if (!it->ai_addr || it->ai_family != AF_INET) continue;
    char buf[INET_ADDRSTRLEN] = {};
    const auto* sin = reinterpret_cast<const sockaddr_in*>(it->ai_addr);
    if (::inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf)) != nullptr) unique.insert(buf);
  }
  freeaddrinfo(res);
  return std::vector<std::string>(unique.begin(), unique.end());
}

std::set<std::string> local_ipv4_addresses() {
  std::set<std::string> ips;
#ifdef _WIN32
  char hostname[256] = {};
  if (::gethostname(hostname, sizeof(hostname) - 1) == 0) {
    for (const auto& ip : resolve_ipv4_addresses(hostname)) ips.insert(ip);
  }
#else
  ifaddrs* ifaddr = nullptr;
  if (::getifaddrs(&ifaddr) == 0 && ifaddr != nullptr) {
    for (ifaddrs* it = ifaddr; it != nullptr; it = it->ifa_next) {
      if (!it->ifa_addr || it->ifa_addr->sa_family != AF_INET) continue;
      char buf[INET_ADDRSTRLEN] = {};
      const auto* sin = reinterpret_cast<const sockaddr_in*>(it->ifa_addr);
      if (::inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf)) != nullptr) ips.insert(buf);
    }
    freeifaddrs(ifaddr);
  }
#endif
  ips.insert("127.0.0.1");
  return ips;
}

bool same_epoch_ticket(const consensus::EpochTicket& a, const consensus::EpochTicket& b) {
  return a.epoch == b.epoch && a.participant_pubkey == b.participant_pubkey && a.challenge_anchor == b.challenge_anchor &&
         a.nonce == b.nonce && a.work_hash == b.work_hash && a.source_height == b.source_height && a.origin == b.origin;
}

bool same_epoch_best_map(const std::map<PubKey32, consensus::EpochBestTicket>& a,
                         const std::map<PubKey32, consensus::EpochBestTicket>& b) {
  if (a.size() != b.size()) return false;
  for (const auto& [pub, ticket] : a) {
    auto it = b.find(pub);
    if (it == b.end() || !same_epoch_ticket(ticket, it->second)) return false;
  }
  return true;
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

std::string launch_mode_name(LightserverLaunchMode mode) {
  switch (mode) {
    case LightserverLaunchMode::Explicit:
      return "explicit";
    default:
      return "disabled";
  }
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

std::string local_software_version_fingerprint(const NetworkConfig& cfg, const ChainId& chain_id, std::uint32_t cv) {
  std::ostringstream oss;
  oss << finalis::node_software_version()
      << ";genesis=" << chain_id.genesis_hash_hex << ";network_id=" << network_id_hex(cfg) << ";cv=" << cv;
  return oss.str();
}

std::optional<std::string> software_fingerprint_value(const std::string& ua, const std::string& key) {
  const std::string needle = key + "=";
  std::size_t start = 0;
  while (start <= ua.size()) {
    std::size_t end = ua.find(';', start);
    if (end == std::string::npos) end = ua.size();
    const std::string part = ua.substr(start, end - start);
    if (part.rfind(needle, 0) == 0) return part.substr(needle.size());
    if (end == ua.size()) break;
    start = end + 1;
  }
  return std::nullopt;
}

std::mutex g_local_bus_mu;
std::vector<Node*> g_local_bus_nodes;

constexpr const char* kSmtTreeUtxo = "utxo";
constexpr const char* kSmtTreeValidators = "validators";

bool debug_economics_logs_enabled();
bool debug_finality_logs_enabled();

bool runtime_logs_enabled() {
  if (debug_economics_logs_enabled() || debug_finality_logs_enabled()) return true;
  const char* quiet = std::getenv("FINALIS_TEST_QUIET_LOGS");
  return !(quiet && std::string_view(quiet) == "1");
}

bool debug_economics_logs_enabled() {
  const char* enabled = std::getenv("FINALIS_DEBUG_ECONOMICS");
  return enabled && std::string_view(enabled) == "1";
}

bool debug_finality_logs_enabled() {
  const char* enabled = std::getenv("FINALIS_DEBUG_FINALITY");
  return enabled && std::string_view(enabled) == "1";
}

bool debug_checkpoint_logs_enabled() {
  const char* enabled = std::getenv("FINALIS_DEBUG_CHECKPOINTS");
  return enabled && std::string_view(enabled) == "1";
}

storage::SlashingRecord make_onchain_slash_record(const SlashEvidence& ev, const Hash32& txid, std::uint64_t observed_height);

std::string finalized_write_marker_key() { return "FW:PENDING"; }

std::string justify_summary(const std::optional<QuorumCertificate>& qc, const std::optional<TimeoutCertificate>& tc) {
  if (qc.has_value()) {
    return "qc(height=" + std::to_string(qc->height) + ",round=" + std::to_string(qc->round) +
           ",transition=" + short_hash_hex(qc->frontier_transition_id) + ")";
  }
  if (tc.has_value()) {
    return "tc(height=" + std::to_string(tc->height) + ",round=" + std::to_string(tc->round) + ")";
  }
  return "none";
}

std::string signer_set_summary(const std::vector<FinalitySig>& sigs) {
  std::ostringstream oss;
  bool first = true;
  for (const auto& sig : sigs) {
    if (!first) oss << ",";
    first = false;
    oss << short_pub_hex(sig.validator_pubkey);
  }
  return oss.str();
}

Bytes serialize_finalized_write_marker(std::uint64_t height, const Hash32& block_id) {
  codec::ByteWriter w;
  w.u64le(height);
  w.bytes_fixed(block_id);
  return w.take();
}

bool parse_finalized_write_marker(const Bytes& bytes, std::uint64_t* height, Hash32* block_id) {
  if (!height || !block_id) return false;
  return codec::parse_exact(bytes, [&](codec::ByteReader& r) {
    auto parsed_height = r.u64le();
    auto parsed_block_id = r.bytes_fixed<32>();
    if (!parsed_height || !parsed_block_id) return false;
    *height = *parsed_height;
    *block_id = *parsed_block_id;
    return true;
  });
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

std::optional<PubKey32> leader_from_checkpoint(const NetworkConfig& network, const consensus::ValidatorRegistry& validators,
                                               const storage::FinalizedCommitteeCheckpoint& checkpoint,
                                               std::uint64_t height, std::uint32_t round) {
  if (auto fallback = consensus::checkpoint_ticket_pow_fallback_member_for_round(checkpoint, round); fallback.has_value()) {
    return fallback;
  }
  const auto schedule = proposer_schedule_from_checkpoint(network, validators, checkpoint, height);
  if (schedule.empty()) return std::nullopt;
  return schedule[static_cast<std::size_t>(round) % schedule.size()];
}

std::vector<consensus::FinalizedCommitteeCandidate> finalized_committee_candidates_from_best_tickets(
    const NetworkConfig& network, const consensus::ValidatorRegistry& validators, std::uint64_t height,
    const Hash32& epoch_seed, std::uint8_t ticket_difficulty_bits,
    const std::map<PubKey32, consensus::EpochBestTicket>* persisted_best_tickets,
    const availability::AvailabilityPersistentState* availability_state, const availability::AvailabilityConfig& availability_cfg,
    const consensus::AdaptiveCheckpointParameters& adaptive,
    std::optional<storage::FinalizedCommitteeDerivationMode> previous_derivation_mode,
    storage::FinalizedCommitteeDerivationMode* derivation_mode_out = nullptr,
    storage::FinalizedCommitteeFallbackReason* fallback_reason_out = nullptr,
    std::uint64_t* eligible_operator_count_out = nullptr) {
  std::vector<consensus::OperatorCommitteeInput> operator_inputs;
  const auto epoch_start = consensus::committee_epoch_start(height, network.committee_epoch_blocks);
  const auto& econ = active_economics_policy(network, height);
  (void)persisted_best_tickets;
  std::map<PubKey32, const availability::AvailabilityOperatorState*> availability_by_operator;
  if (availability_state) {
    for (const auto& operator_state : availability_state->operators) {
      availability_by_operator[operator_state.operator_pubkey] = &operator_state;
    }
  }
  const auto adaptive_availability_cfg = consensus::availability_config_with_min_bond(availability_cfg, adaptive.min_bond);
  AvailabilityCommitteeDecision decision;
  decision.adaptive = adaptive;
  decision.min_eligible_operators = adaptive.min_eligible_operators;
  if (availability_state) {
    decision.eligible_operator_count =
        consensus::count_eligible_operators_at_checkpoint(validators, height, *availability_state, adaptive_availability_cfg);
  }
  decision.effective_committee_size =
      std::max<std::uint64_t>(1, std::min(decision.eligible_operator_count, adaptive.target_committee_size));
  if (decision.min_eligible_operators != 0 && decision.eligible_operator_count < decision.min_eligible_operators) {
    decision.mode = storage::FinalizedCommitteeDerivationMode::FALLBACK;
    decision.fallback_reason = storage::FinalizedCommitteeFallbackReason::INSUFFICIENT_ELIGIBLE_OPERATORS;
  } else if (previous_derivation_mode == storage::FinalizedCommitteeDerivationMode::FALLBACK &&
             decision.eligible_operator_count < (adaptive.target_committee_size <= 3
                                                     ? adaptive.target_committee_size
                                                     : (adaptive.target_committee_size <= 7 ? adaptive.target_committee_size + 1ULL
                                                                                            : adaptive.target_committee_size + 2ULL))) {
    decision.mode = storage::FinalizedCommitteeDerivationMode::FALLBACK;
    decision.fallback_reason = storage::FinalizedCommitteeFallbackReason::HYSTERESIS_RECOVERY_PENDING;
  }
  const bool enforce_availability = decision.mode == storage::FinalizedCommitteeDerivationMode::NORMAL;
  if (eligible_operator_count_out) *eligible_operator_count_out = decision.eligible_operator_count;
  if (derivation_mode_out) *derivation_mode_out = decision.mode;
  if (fallback_reason_out) *fallback_reason_out = decision.fallback_reason;

  auto adaptive_econ = econ;
  adaptive_econ.target_validators = adaptive.target_committee_size;

  struct OperatorSeed {
    PubKey32 representative_pub{};
    std::uint64_t bonded_amount{0};
    bool has_representative{false};
  };
  std::map<PubKey32, OperatorSeed> by_operator;
  for (const auto& [pub, info] : validators.all()) {
    const auto operator_id = consensus::canonical_operator_id(pub, info);
    const auto availability_it = availability_by_operator.find(operator_id);
    const auto eligibility = consensus::committee_eligibility_at_checkpoint(
        validators, pub, info, height, adaptive.min_bond,
        availability_it == availability_by_operator.end() ? nullptr : availability_it->second, adaptive_availability_cfg,
        enforce_availability);
    if (!eligibility.eligible) continue;
    auto& seed = by_operator[operator_id];
    seed.bonded_amount += info.bonded_amount;
    if (!seed.has_representative || pub < seed.representative_pub) {
      seed.representative_pub = pub;
      seed.has_representative = true;
    }
  }
  operator_inputs.reserve(by_operator.size());
  for (const auto& [operator_id, seed] : by_operator) {
    if (!seed.has_representative) continue;
    consensus::OperatorCommitteeInput input;
    input.pubkey = seed.representative_pub;
    input.operator_id = operator_id;
    input.bonded_amount = seed.bonded_amount;
    auto ticket = consensus::best_epoch_ticket_for_operator_id(epoch_start, epoch_seed, operator_id, epoch_start,
                                                               consensus::EPOCH_TICKET_MAX_NONCE);
    if (ticket.has_value()) {
      input.ticket_work_hash = ticket->work_hash;
      input.ticket_nonce = ticket->nonce;
      input.ticket_bonus_bps =
          consensus::ticket_pow_bonus_bps(*ticket, ticket_difficulty_bits, econ.ticket_bonus_cap_bps);
    }
    operator_inputs.push_back(input);
  }
  std::sort(operator_inputs.begin(), operator_inputs.end(),
            [](const consensus::OperatorCommitteeInput& a, const consensus::OperatorCommitteeInput& b) {
              const auto a_id = a.operator_id == PubKey32{} ? a.pubkey : a.operator_id;
              const auto b_id = b.operator_id == PubKey32{} ? b.pubkey : b.operator_id;
              if (a_id != b_id) return a_id < b_id;
              if (a.pubkey != b.pubkey) return a.pubkey < b.pubkey;
              if (a.bonded_amount != b.bonded_amount) return a.bonded_amount < b.bonded_amount;
              if (a.ticket_work_hash != b.ticket_work_hash) return a.ticket_work_hash < b.ticket_work_hash;
              if (a.ticket_nonce != b.ticket_nonce) return a.ticket_nonce < b.ticket_nonce;
              return a.ticket_bonus_bps < b.ticket_bonus_bps;
            });
  return consensus::aggregate_operator_committee_candidates(operator_inputs, adaptive_econ, height,
                                                           std::max<std::size_t>(1, adaptive.qualified_depth));
}

storage::FinalizedCommitteeCheckpoint build_finalized_committee_checkpoint_from_candidates(
    std::uint64_t epoch_start_height, const Hash32& epoch_seed, std::uint8_t ticket_difficulty_bits,
    const std::vector<consensus::FinalizedCommitteeCandidate>& active, std::size_t max_committee,
    storage::FinalizedCommitteeDerivationMode derivation_mode,
    storage::FinalizedCommitteeFallbackReason fallback_reason, std::uint64_t eligible_operator_count,
    std::uint64_t min_eligible_operators, std::uint64_t effective_committee_size,
    const consensus::AdaptiveCheckpointParameters& adaptive) {
  storage::FinalizedCommitteeCheckpoint checkpoint;
  checkpoint.epoch_start_height = epoch_start_height;
  checkpoint.epoch_seed = epoch_seed;
  checkpoint.ticket_difficulty_bits = ticket_difficulty_bits;
  checkpoint.derivation_mode = derivation_mode;
  checkpoint.fallback_reason = fallback_reason;
  checkpoint.availability_eligible_operator_count = eligible_operator_count;
  checkpoint.availability_min_eligible_operators = min_eligible_operators;
  checkpoint.adaptive_target_committee_size = adaptive.target_committee_size;
  checkpoint.adaptive_min_eligible = adaptive.min_eligible_operators;
  checkpoint.adaptive_min_bond = adaptive.min_bond;
  checkpoint.qualified_depth = adaptive.qualified_depth;
  checkpoint.target_expand_streak = adaptive.target_expand_streak;
  checkpoint.target_contract_streak = adaptive.target_contract_streak;
  const auto take =
      std::min<std::size_t>({max_committee, static_cast<std::size_t>(effective_committee_size), active.size()});
  checkpoint.ordered_members = consensus::select_finalized_committee(active, checkpoint.epoch_seed, take);
  checkpoint.ordered_operator_ids.reserve(checkpoint.ordered_members.size());
  checkpoint.ordered_base_weights.reserve(checkpoint.ordered_members.size());
  checkpoint.ordered_ticket_bonus_bps.reserve(checkpoint.ordered_members.size());
  checkpoint.ordered_final_weights.reserve(checkpoint.ordered_members.size());
  checkpoint.ordered_ticket_hashes.reserve(checkpoint.ordered_members.size());
  checkpoint.ordered_ticket_nonces.reserve(checkpoint.ordered_members.size());
  for (const auto& pub : checkpoint.ordered_members) {
    auto it = std::find_if(active.begin(), active.end(), [&](const auto& candidate) { return candidate.pubkey == pub; });
    if (it == active.end()) continue;
    checkpoint.ordered_operator_ids.push_back(it->selection_id == PubKey32{} ? it->pubkey : it->selection_id);
    checkpoint.ordered_base_weights.push_back(it->effective_weight);
    checkpoint.ordered_ticket_bonus_bps.push_back(it->ticket_bonus_bps);
    checkpoint.ordered_final_weights.push_back(consensus::finalized_committee_candidate_strength(*it));
    checkpoint.ordered_ticket_hashes.push_back(it->ticket_work_hash);
    checkpoint.ordered_ticket_nonces.push_back(it->ticket_nonce);
  }
  return checkpoint;
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

struct StateRoots {
  Hash32 utxo_root{};
  Hash32 validators_root{};
};

struct DeterministicEpochRewardInputs {
  std::map<PubKey32, std::uint64_t> reward_score_units;
  std::map<PubKey32, std::uint64_t> expected_participation_units;
  std::map<PubKey32, std::uint64_t> observed_participation_units;
};

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

bool same_tx_out(const TxOut& a, const TxOut& b) {
  return a.value == b.value && a.script_pubkey == b.script_pubkey;
}

bool same_utxos(const UtxoSetV2& a, const UtxoSetV2& b) {
  if (a.size() != b.size()) return false;
  auto ita = a.begin();
  auto itb = b.begin();
  for (; ita != a.end(); ++ita, ++itb) {
    if (ita->first.txid != itb->first.txid || ita->first.index != itb->first.index || ita->second != itb->second) {
      return false;
    }
  }
  return true;
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

bool same_finalized_checkpoint_schedule_material(const storage::FinalizedCommitteeCheckpoint& a,
                                                 const storage::FinalizedCommitteeCheckpoint& b) {
  return a.epoch_start_height == b.epoch_start_height && a.epoch_seed == b.epoch_seed &&
         a.ticket_difficulty_bits == b.ticket_difficulty_bits && a.derivation_mode == b.derivation_mode &&
         a.fallback_reason == b.fallback_reason &&
         a.availability_eligible_operator_count == b.availability_eligible_operator_count &&
         a.availability_min_eligible_operators == b.availability_min_eligible_operators &&
         a.adaptive_target_committee_size == b.adaptive_target_committee_size &&
         a.adaptive_min_eligible == b.adaptive_min_eligible && a.adaptive_min_bond == b.adaptive_min_bond &&
         a.qualified_depth == b.qualified_depth && a.target_expand_streak == b.target_expand_streak &&
         a.target_contract_streak == b.target_contract_streak && a.ordered_members == b.ordered_members &&
         a.ordered_operator_ids == b.ordered_operator_ids && a.ordered_base_weights == b.ordered_base_weights &&
         a.ordered_ticket_bonus_bps == b.ordered_ticket_bonus_bps && a.ordered_final_weights == b.ordered_final_weights;
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

bool same_consensus_state_commitment_cache(const storage::ConsensusStateCommitmentCache& a,
                                           const storage::ConsensusStateCommitmentCache& b) {
  return a.height == b.height && a.hash == b.hash && a.commitment == b.commitment;
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

DeterministicEpochRewardInputs compute_deterministic_epoch_reward_inputs(
    const NetworkConfig& network, const consensus::ValidatorRegistry& validators, std::uint64_t height,
    const PubKey32& leader_pubkey, const std::vector<PubKey32>& committee, const std::vector<FinalitySig>& finality_sigs) {
  DeterministicEpochRewardInputs out;
  std::set<PubKey32> canonical_members(committee.begin(), committee.end());
  const auto observed_members = consensus::committee_participants_from_finality(committee, finality_sigs);
  std::set<PubKey32> observed_set(observed_members.begin(), observed_members.end());
  std::set<PubKey32> operators;
  for (const auto& [pub, info] : validators.all()) {
    if (!validators.is_active_for_height(pub, height)) continue;
    operators.insert(consensus::canonical_operator_id(pub, info));
  }
  const std::size_t active_operator_count = operators.size();

  for (const auto& pub : canonical_members) {
    out.expected_participation_units[pub] += 1;
    if (observed_set.find(pub) != observed_set.end()) out.observed_participation_units[pub] += 1;
    auto it = validators.all().find(pub);
    if (it == validators.all().end()) continue;
    out.reward_score_units[pub] +=
        consensus::reward_weight(network, height, active_operator_count, it->second.bonded_amount);
  }
  if (auto it = validators.all().find(leader_pubkey); it != validators.all().end()) {
    out.reward_score_units[leader_pubkey] +=
        consensus::reward_weight(network, height, active_operator_count, it->second.bonded_amount);
  }
  return out;
}

void mark_epoch_reward_settled_for_height(const NetworkConfig& network, std::uint64_t height, std::uint64_t epoch_blocks,
                                          std::map<std::uint64_t, storage::EpochRewardSettlementState>& reward_states,
                                          std::uint64_t* protocol_reserve_balance_units, storage::DB* db) {
  const auto epoch_start = consensus::committee_epoch_start(height, epoch_blocks);
  if (height != epoch_start || epoch_start <= 1 || epoch_start <= epoch_blocks) return;
  const auto settlement_epoch = epoch_start - epoch_blocks;
  auto& state = reward_states[settlement_epoch];
  state.epoch_start_height = settlement_epoch;
  if (state.settled) return;
  state.reserve_subsidy_units = 0;
  if (height >= consensus::EMISSION_BLOCKS) {
    const auto threshold_bps = active_economics_policy(network, height).participation_threshold_bps;
    std::size_t eligible_validator_count = 0;
    for (const auto& [pub, raw_score] : state.reward_score_units) {
      const auto expected_it = state.expected_participation_units.find(pub);
      const auto observed_it = state.observed_participation_units.find(pub);
      const std::uint64_t expected = expected_it == state.expected_participation_units.end() ? 0 : expected_it->second;
      const std::uint64_t observed = observed_it == state.observed_participation_units.end() ? 0 : observed_it->second;
      const std::uint32_t participation_bps =
          expected == 0 ? 10'000U
                        : static_cast<std::uint32_t>(wide::mul_div_u64(std::min(observed, expected), 10'000ULL, expected));
      const auto adjusted_score = consensus::apply_participation_penalty_bps(raw_score, participation_bps, threshold_bps);
      if (adjusted_score > 0) ++eligible_validator_count;
    }
    const auto reserve_after_accrual = (protocol_reserve_balance_units ? *protocol_reserve_balance_units : 0) + state.reserve_accrual_units;
    state.reserve_subsidy_units =
        consensus::post_cap_reserve_subsidy_units(eligible_validator_count, state.fee_pool_units, reserve_after_accrual);
  }
  state.settled = true;
  if (protocol_reserve_balance_units) {
    *protocol_reserve_balance_units += state.reserve_accrual_units;
    if (*protocol_reserve_balance_units >= state.reserve_subsidy_units) {
      *protocol_reserve_balance_units -= state.reserve_subsidy_units;
    } else {
      *protocol_reserve_balance_units = 0;
    }
    if (db) (void)db->put_protocol_reserve_balance(*protocol_reserve_balance_units);
  }
  if (db) (void)db->put_epoch_reward_settlement(state);
}

void accrue_epoch_reward_state_for_block(
    const NetworkConfig& network, const consensus::ValidatorRegistry& validators, std::uint64_t epoch_blocks,
    std::map<std::uint64_t, storage::EpochRewardSettlementState>& reward_states, const Block& block,
    const std::vector<PubKey32>& committee, const std::vector<FinalitySig>& finality_sigs,
    std::uint64_t finalized_fee_units, storage::DB* db) {
  const auto epoch_start = consensus::committee_epoch_start(block.header.height, epoch_blocks);
  auto& state = reward_states[epoch_start];
  state.epoch_start_height = epoch_start;
  const auto gross_reward = consensus::reward_units(block.header.height);
  const auto next_gross_reward = state.total_reward_units + state.reserve_accrual_units + gross_reward;
  const auto next_reserve = wide::mul_div_u64(next_gross_reward, static_cast<std::uint64_t>(consensus::RESERVE_ACCRUAL_BPS),
                                              10'000ULL);
  const auto reserve_delta = next_reserve - state.reserve_accrual_units;
  state.reserve_accrual_units = next_reserve;
  state.total_reward_units += gross_reward - reserve_delta;
  if (block.header.height >= consensus::EMISSION_BLOCKS) state.fee_pool_units += finalized_fee_units;
  const auto inputs =
      compute_deterministic_epoch_reward_inputs(network, validators, block.header.height, block.header.leader_pubkey, committee,
                                                finality_sigs);
  for (const auto& [pub, units] : inputs.expected_participation_units) state.expected_participation_units[pub] += units;
  for (const auto& [pub, units] : inputs.observed_participation_units) state.observed_participation_units[pub] += units;
  for (const auto& [pub, units] : inputs.reward_score_units) state.reward_score_units[pub] += units;
  if (db) (void)db->put_epoch_reward_settlement(state);
}

void update_validator_liveness_from_finality_impl(consensus::ValidatorRegistry& validators, std::uint64_t height,
                                                  const std::vector<PubKey32>& committee,
                                                  const std::vector<FinalitySig>& finality_sigs,
                                                  std::uint64_t* liveness_window_start_height,
                                                  std::uint64_t liveness_window_blocks,
                                                  std::uint32_t miss_rate_suspend_threshold_percent,
                                                  std::uint32_t miss_rate_exit_threshold_percent,
                                                  std::uint64_t suspend_duration_blocks,
                                                  std::size_t* last_participation_eligible_signers, storage::DB* db) {
  if (committee.empty() || !liveness_window_start_height) return;
  const auto participants = consensus::committee_participants_from_finality(committee, finality_sigs);
  std::set<PubKey32> participant_set(participants.begin(), participants.end());
  if (last_participation_eligible_signers) *last_participation_eligible_signers = participant_set.size();

  auto& all = validators.mutable_all();
  for (const auto& pub : committee) {
    auto it = all.find(pub);
    if (it == all.end()) continue;
    auto& info = it->second;
    if (info.status != consensus::ValidatorStatus::ACTIVE && info.status != consensus::ValidatorStatus::SUSPENDED) continue;
    info.liveness_window_start = *liveness_window_start_height;
    ++info.eligible_count_window;
    if (participant_set.find(pub) != participant_set.end()) ++info.participated_count_window;
  }

  const bool evaluate = consensus::validator_liveness_window_should_rollover(height, *liveness_window_start_height,
                                                                             liveness_window_blocks);
  if (!evaluate) return;

  for (auto& [pub, info] : all) {
    const std::uint64_t eligible = info.eligible_count_window;
    const std::uint64_t participated = info.participated_count_window;
    if (eligible >= 10) {
      const std::uint64_t miss = (eligible >= participated) ? (eligible - participated) : 0;
      const std::uint32_t miss_rate = static_cast<std::uint32_t>((miss * 100) / eligible);
      if (miss_rate >= miss_rate_exit_threshold_percent) {
        info.status = consensus::ValidatorStatus::EXITING;
        info.last_exit_height = height;
        info.unbond_height = height;
        info.penalty_strikes += 1;
      } else if (miss_rate >= miss_rate_suspend_threshold_percent) {
        info.status = consensus::ValidatorStatus::SUSPENDED;
        info.suspended_until_height = height + suspend_duration_blocks;
        info.penalty_strikes += 1;
      }
    }
    info.eligible_count_window = 0;
    info.participated_count_window = 0;
    info.liveness_window_start = height + 1;
    if (db) (void)db->put_validator(pub, info);
  }
  *liveness_window_start_height =
      consensus::validator_liveness_next_window_start(height, *liveness_window_start_height, liveness_window_blocks);
}

void apply_validator_state_changes_impl(consensus::ValidatorRegistry& validators,
                                        std::map<Hash32, ValidatorJoinRequest>& validator_join_requests,
                                        const Block& block, const UtxoSet& pre_utxos, std::uint64_t height,
                                        std::uint64_t min_bond, std::uint64_t warmup_blocks,
                                        std::uint64_t cooldown_blocks, std::uint64_t join_limit_window_blocks,
                                        std::uint32_t join_limit_max_new,
                                        std::uint64_t* join_window_start_height, std::uint32_t* join_count_in_window,
                                        storage::DB* db) {
  validators.set_rules(consensus::ValidatorRules{
      .min_bond = min_bond,
      .warmup_blocks = warmup_blocks,
      .cooldown_blocks = cooldown_blocks,
  });
  if (join_window_start_height && join_count_in_window && join_limit_window_blocks > 0) {
    consensus::advance_validator_join_window(height, join_limit_window_blocks, join_window_start_height, join_count_in_window);
  }

  for (size_t txi = 1; txi < block.txs.size(); ++txi) {
    const auto& tx = block.txs[txi];
    for (const auto& in : tx.inputs) {
      OutPoint op{in.prev_txid, in.prev_index};
      auto it = pre_utxos.find(op);
      if (it == pre_utxos.end()) continue;
      PubKey32 pub{};
      SlashEvidence evidence;
      if (is_validator_register_script(it->second.out.script_pubkey, &pub)) {
        if (parse_slash_script_sig(in.script_sig, &evidence)) {
          if (db) (void)db->put_slashing_record(make_onchain_slash_record(evidence, tx.txid(), height));
          validators.ban(pub, height);
          (void)validators.finalize_withdrawal(pub);
        } else {
          validators.request_unbond(pub, height);
        }
        continue;
      }
      if (is_validator_unbond_script(it->second.out.script_pubkey, &pub)) {
        if (parse_slash_script_sig(in.script_sig, &evidence)) {
          if (db) (void)db->put_slashing_record(make_onchain_slash_record(evidence, tx.txid(), height));
          validators.ban(pub, height);
        }
        (void)validators.finalize_withdrawal(pub);
      }
    }
  }

  for (const auto& tx : block.txs) {
    const Hash32 txid = tx.txid();
    for (std::uint32_t out_i = 0; out_i < tx.outputs.size(); ++out_i) {
      const auto& out = tx.outputs[out_i];
      PubKey32 onboarding_validator_pub{};
      PubKey32 onboarding_payout_pub{};
      Sig64 onboarding_pop{};
      if (is_onboarding_registration_script(out.script_pubkey, &onboarding_validator_pub, &onboarding_payout_pub,
                                            &onboarding_pop)) {
        std::string err;
        (void)validators.register_onboarding(onboarding_validator_pub, height, &err,
                                             consensus::canonical_operator_id_from_join_request(onboarding_payout_pub));
        continue;
      }
      PubKey32 validator_pub{};
      PubKey32 payout_pub{};
      Sig64 pop{};
      if (!is_validator_join_request_script(out.script_pubkey, &validator_pub, &payout_pub, &pop)) continue;

      for (std::uint32_t bond_i = 0; bond_i < tx.outputs.size(); ++bond_i) {
        PubKey32 bond_pub{};
        if (!is_validator_register_script(tx.outputs[bond_i].script_pubkey, &bond_pub) || bond_pub != validator_pub) continue;
        ValidatorJoinRequest req;
        req.request_txid = txid;
        req.validator_pubkey = validator_pub;
        req.payout_pubkey = payout_pub;
        req.bond_outpoint = OutPoint{txid, bond_i};
        req.bond_amount = tx.outputs[bond_i].value;
        req.requested_height = height;
        if (join_count_in_window && join_limit_window_blocks > 0 && join_limit_max_new > 0 &&
            *join_count_in_window >= join_limit_max_new) {
          break;
        }
        std::string err;
        if (validators.register_bond(req.validator_pubkey, req.bond_outpoint, height, req.bond_amount, &err,
                                     consensus::canonical_operator_id_from_join_request(req.payout_pubkey))) {
          req.status = ValidatorJoinRequestStatus::APPROVED;
          req.approved_height = height;
          validator_join_requests[txid] = req;
          if (db) (void)db->put_validator_join_request(txid, req);
          if (join_count_in_window && join_limit_window_blocks > 0) ++(*join_count_in_window);
        }
        break;
      }
    }
  }
}

bool deterministic_epoch_reward_inputs_equal(const DeterministicEpochRewardInputs& a,
                                             const DeterministicEpochRewardInputs& b) {
  return a.reward_score_units == b.reward_score_units &&
         a.expected_participation_units == b.expected_participation_units &&
         a.observed_participation_units == b.observed_participation_units;
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

StateRoots compute_roots_for_state(const UtxoSetV2& utxos, const consensus::ValidatorRegistry& validators,
                                   std::uint32_t validation_rules_version) {
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

  StateRoots roots;
  roots.utxo_root = crypto::SparseMerkleTree::compute_root_from_leaves(utxo_leaves);
  roots.validators_root = crypto::SparseMerkleTree::compute_root_from_leaves(validator_leaves);
  return roots;
}

constexpr const char* kValidatorJoinWindowStartKey = "PVAL:JOIN_WINDOW_START";
constexpr const char* kValidatorJoinWindowCountKey = "PVAL:JOIN_WINDOW_COUNT";
constexpr const char* kValidatorLivenessWindowStartKey = "PVAL:LIVENESS_WINDOW_START";
constexpr const char* kFinalizedRandomnessKey = "PRAND:FINALIZED";
constexpr const char* kStartupReplayModeKey = "REPLAY:MODE";
constexpr const char* kConsensusSafetyStatePrefix = "CSAFE:";

bool replay_mode_is_frontier(const Bytes& bytes) { return std::string(bytes.begin(), bytes.end()) == "frontier"; }

bool persist_canonical_cache_rows(storage::DB& db, const consensus::CanonicalDerivedState& state) {
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
  for (const auto& key : utxos_to_erase) {
    if (!db.erase(key)) return false;
  }
  for (const auto& [op, entry] : state.utxos) {
    if (!db.put_utxo_v2(op, entry)) return false;
  }

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
  for (const auto& key : script_utxos_to_erase) {
    if (!db.erase(key)) return false;
  }
  for (const auto& [op, entry] : state.utxos) {
    const auto transparent = transparent_txout_from_utxo_entry(entry);
    if (!transparent.has_value()) continue;
    const auto scripthash = crypto::sha256(transparent->script_pubkey);
    if (!db.put_script_utxo(scripthash, op, *transparent, state.finalized_height)) return false;
  }

  for (const auto& [pub, info] : state.validators.all()) {
    if (!db.put_validator(pub, info)) return false;
  }
  for (const auto& [txid, req] : state.validator_join_requests) {
    if (!db.put_validator_join_request(txid, req)) return false;
  }
  for (const auto& [epoch, reward_state] : state.epoch_reward_states) {
    (void)epoch;
    if (!db.put_epoch_reward_settlement(reward_state)) return false;
  }
  if (!db.put_protocol_reserve_balance(state.protocol_reserve_balance_units)) return false;
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
  for (const auto& key : checkpoint_keys_to_erase) {
    if (!db.erase(key)) return false;
  }
  for (const auto& [epoch, checkpoint] : state.finalized_committee_checkpoints) {
    (void)epoch;
    if (!db.put_finalized_committee_checkpoint(checkpoint)) return false;
  }
  if (!db.put(kFinalizedRandomnessKey, Bytes(state.finalized_randomness.begin(), state.finalized_randomness.end()))) return false;
  codec::ByteWriter w_start;
  w_start.u64le(state.validator_join_window_start_height);
  if (!db.put(kValidatorJoinWindowStartKey, w_start.take())) return false;
  codec::ByteWriter w_count;
  w_count.u32le(state.validator_join_count_in_window);
  if (!db.put(kValidatorJoinWindowCountKey, w_count.take())) return false;
  codec::ByteWriter w_liveness;
  w_liveness.u64le(state.validator_liveness_window_start_height);
  if (!db.put(kValidatorLivenessWindowStartKey, w_liveness.take())) return false;
  return true;
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

Bytes make_coinbase_script_sig(std::uint64_t height, std::uint32_t round) {
  std::ostringstream oss;
  oss << "cb:" << height << ":" << round;
  const auto s = oss.str();
  return Bytes(s.begin(), s.end());
}

Bytes block_proposal_signing_message(const BlockHeader& header) {
  const Hash32 bid = header.block_id();
  return Bytes(bid.begin(), bid.end());
}

std::string key_consensus_safety_state(std::uint64_t height) {
  codec::ByteWriter w;
  w.u64le(height);
  return std::string(kConsensusSafetyStatePrefix) + hex_encode(w.data());
}

Hash32 consensus_payload_id(const Block& block) {
  codec::ByteWriter w;
  w.bytes(Bytes{'S', 'C', '-', 'L', 'O', 'C', 'K', '-', 'P', 'A', 'Y', 'L', 'O', 'A', 'D', '-', 'V', '1'});
  w.bytes_fixed(block.header.prev_finalized_hash);
  w.u64le(block.header.height);
  const std::size_t non_coinbase = block.txs.size() > 1 ? (block.txs.size() - 1) : 0;
  w.varint(non_coinbase);
  for (std::size_t i = 1; i < block.txs.size(); ++i) {
    w.bytes(block.txs[i].serialize_without_hashcash());
  }
  return crypto::sha256d(w.data());
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

Bytes serialize_consensus_safety_state(const std::optional<std::pair<Hash32, std::uint32_t>>& lock_state,
                                       const std::optional<QuorumCertificate>& qc_state,
                                       const std::optional<Hash32>& qc_payload_id) {
  codec::ByteWriter w;
  w.u8(lock_state.has_value() ? 1 : 0);
  if (lock_state.has_value()) {
    w.bytes_fixed(lock_state->first);
    w.u32le(lock_state->second);
  }
  w.u8(qc_state.has_value() ? 1 : 0);
  if (qc_state.has_value()) {
    w.u64le(qc_state->height);
    w.u32le(qc_state->round);
    w.bytes_fixed(qc_state->frontier_transition_id);
    w.u8(qc_payload_id.has_value() ? 1 : 0);
    if (qc_payload_id.has_value()) w.bytes_fixed(*qc_payload_id);
    w.varint(qc_state->signatures.size());
    for (const auto& sig : qc_state->signatures) {
      w.bytes_fixed(sig.validator_pubkey);
      w.bytes_fixed(sig.signature);
    }
  }
  return w.take();
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

QuorumCertificate make_quorum_certificate(std::uint64_t height, std::uint32_t round, const Hash32& transition_id,
                                          const std::vector<FinalitySig>& signatures) {
  QuorumCertificate qc;
  qc.height = height;
  qc.round = round;
  qc.frontier_transition_id = transition_id;
  qc.signatures = signatures;
  return qc;
}

Hash32 message_payload_id(const Bytes& payload) { return crypto::sha256(payload); }

Hash32 vote_equivocation_record_id(const EquivocationEvidence& ev) {
  codec::ByteWriter w;
  w.bytes(Bytes{'S', 'L', 'V', 'O', 'T', 'E'});
  w.u64le(ev.a.height);
  w.u32le(ev.a.round);
  w.bytes_fixed(ev.a.validator_pubkey);
  w.bytes_fixed(ev.a.frontier_transition_id);
  w.bytes_fixed(ev.a.signature);
  w.bytes_fixed(ev.b.frontier_transition_id);
  w.bytes_fixed(ev.b.signature);
  return crypto::sha256d(w.data());
}

Hash32 proposer_equivocation_record_id(const BlockHeader& a, const BlockHeader& b) {
  codec::ByteWriter w;
  w.bytes(Bytes{'S', 'L', 'P', 'R', 'O', 'P'});
  w.u64le(a.height);
  w.u32le(a.round);
  w.bytes_fixed(a.leader_pubkey);
  w.bytes_fixed(a.block_id());
  w.bytes_fixed(b.block_id());
  return crypto::sha256d(w.data());
}

storage::SlashingRecord make_vote_equivocation_record(const EquivocationEvidence& ev, std::uint64_t observed_height) {
  storage::SlashingRecord rec;
  rec.record_id = vote_equivocation_record_id(ev);
  rec.kind = storage::SlashingRecordKind::VOTE_EQUIVOCATION;
  rec.validator_pubkey = ev.a.validator_pubkey;
  rec.height = ev.a.height;
  rec.round = ev.a.round;
  rec.observed_height = observed_height;
  rec.object_a = ev.a.block_id;
  rec.object_b = ev.b.block_id;
  return rec;
}

storage::SlashingRecord make_proposer_equivocation_record(const PubKey32& leader_pubkey, std::uint64_t height,
                                                          std::uint32_t round, const Hash32& object_a,
                                                          const Hash32& object_b, std::uint64_t observed_height) {
  storage::SlashingRecord rec;
  codec::ByteWriter w;
  w.bytes_fixed(leader_pubkey);
  w.u64le(height);
  w.u32le(round);
  w.bytes_fixed(object_a);
  w.bytes_fixed(object_b);
  rec.record_id = crypto::sha256d(w.data());
  rec.kind = storage::SlashingRecordKind::PROPOSER_EQUIVOCATION;
  rec.validator_pubkey = leader_pubkey;
  rec.height = height;
  rec.round = round;
  rec.observed_height = observed_height;
  rec.object_a = object_a;
  rec.object_b = object_b;
  return rec;
}

storage::SlashingRecord make_onchain_slash_record(const SlashEvidence& ev, const Hash32& txid, std::uint64_t observed_height) {
  storage::SlashingRecord rec;
  const Hash32 evidence_hash = crypto::sha256d(ev.raw_blob);
  rec.record_id = evidence_hash;
  rec.kind = storage::SlashingRecordKind::ONCHAIN_SLASH;
  rec.validator_pubkey = ev.a.validator_pubkey;
  rec.height = ev.a.height;
  rec.round = ev.a.round;
  rec.observed_height = observed_height;
  rec.object_a = ev.a.block_id;
  rec.object_b = ev.b.block_id;
  rec.txid = txid;
  return rec;
}

void sync_smt_tree(storage::DB& db, const std::string& tree_id, const std::vector<std::pair<Hash32, Bytes>>& leaves) {
  const std::string prefix = storage::key_smt_leaf_prefix(tree_id);
  std::set<std::string> desired;
  desired.clear();
  for (const auto& [k, _] : leaves) desired.insert(storage::key_smt_leaf(tree_id, k));
  for (const auto& [k, _] : db.scan_prefix(prefix)) {
    if (desired.find(k) == desired.end()) (void)db.put(k, {});
  }
  for (const auto& [k, v] : leaves) (void)db.put(storage::key_smt_leaf(tree_id, k), v);
}

StateRoots persist_state_roots(storage::DB& db, std::uint64_t height, const UtxoSetV2& utxos,
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

  sync_smt_tree(db, kSmtTreeUtxo, utxo_leaves);
  sync_smt_tree(db, kSmtTreeValidators, validator_leaves);

  StateRoots roots{};
  roots.utxo_root = crypto::SparseMerkleTree::compute_root_from_leaves(utxo_leaves);
  roots.validators_root = crypto::SparseMerkleTree::compute_root_from_leaves(validator_leaves);
  crypto::SparseMerkleTree utxo_tree(db, kSmtTreeUtxo);
  crypto::SparseMerkleTree validators_tree(db, kSmtTreeValidators);
  (void)utxo_tree.set_root_for_height(height, roots.utxo_root);
  (void)validators_tree.set_root_for_height(height, roots.validators_root);
  (void)db.put(storage::key_root_index("UTXO", height), Bytes(roots.utxo_root.begin(), roots.utxo_root.end()));
  (void)db.put(storage::key_root_index("VAL", height), Bytes(roots.validators_root.begin(), roots.validators_root.end()));
  return roots;
}

}  // namespace

Node::Node(NodeConfig cfg) : cfg_(std::move(cfg)) {
  finalized_identity_ = finalized_identity_for_runtime_tip(0, zero_hash());
  finalized_randomness_ = zero_hash();
  confidential_policy_.activation_height = cfg_.network.confidential_utxo_activation_height;
  restart_debug_ = restart_debug_enabled();
}

Node::~Node() noexcept {
  try {
    stop();
  } catch (const std::exception& e) {
    try {
      log_line(std::string("node-destructor-stop-exception error=\"") + e.what() + "\"");
    } catch (...) {
    }
  } catch (...) {
    try {
      log_line("node-destructor-stop-exception error=unknown");
    } catch (...) {
    }
  }
}

std::vector<crypto::KeyPair> Node::deterministic_test_keypairs() {
  std::vector<crypto::KeyPair> out;
  for (int i = 1; i <= 16; ++i) {
    std::array<std::uint8_t, 32> seed{};
    for (size_t j = 0; j < seed.size(); ++j) seed[j] = static_cast<std::uint8_t>(i * 19 + j);
    auto kp = crypto::keypair_from_seed32(seed);
    if (kp.has_value()) out.push_back(*kp);
  }
  return out;
}

bool Node::init() {
  // systemd/journald captures stdout via a pipe, which is block-buffered by
  // default. Force line flushing so quiet followers still emit live handshake
  // and sync diagnostics instead of holding them until process exit.
  std::cout.setf(std::ios::unitbuf);
  if (cfg_.max_committee == 0) cfg_.max_committee = cfg_.network.max_committee;
  genesis_source_hint_ = cfg_.genesis_path.empty() ? "embedded" : "file";
  cfg_.db_path = expand_user_home(cfg_.db_path);
  const std::filesystem::path dbp(cfg_.db_path);
  const auto parent = dbp.parent_path();
  if (!parent.empty()) (void)ensure_private_dir(parent.string());
  (void)ensure_private_dir(cfg_.db_path);
  mining_log_path_ = (dbp / "MiningLOG").string();
  startup_ms_ = now_ms();
  if (runtime_logs_enabled()) {
    std::cout << "[node " << cfg_.node_id << "] db-dir=" << cfg_.db_path << "\n";
    std::cout << "[node " << cfg_.node_id << "] mining-log=" << mining_log_path_ << "\n";
  }
  if (cfg_.public_mode && runtime_logs_enabled()) {
    std::cout << "[node " << cfg_.node_id
              << "] warning: public mode enabled (listening for inbound peers on " << cfg_.bind_ip << ":"
              << cfg_.p2p_port << ")\n";
  }
  discipline_ = p2p::PeerDiscipline(30, 100, cfg_.ban_seconds, cfg_.invalid_frame_ban_threshold,
                                    cfg_.invalid_frame_window_seconds);
  validator_min_bond_ = cfg_.network.validator_min_bond;
  validator_bond_min_amount_ = cfg_.network.validator_bond_min_amount;
  validator_bond_max_amount_ = cfg_.network.validator_bond_max_amount;
  validator_warmup_blocks_ = cfg_.network.validator_warmup_blocks;
  validator_cooldown_blocks_ = cfg_.network.validator_cooldown_blocks;
  validator_join_limit_window_blocks_ = cfg_.network.validator_join_limit_window_blocks;
  validator_join_limit_max_new_ = cfg_.network.validator_join_limit_max_new;
  validator_liveness_window_blocks_ = cfg_.network.liveness_window_blocks;
  validator_miss_rate_suspend_threshold_percent_ = cfg_.network.miss_rate_suspend_threshold_percent;
  validator_miss_rate_exit_threshold_percent_ = cfg_.network.miss_rate_exit_threshold_percent;
  validator_suspend_duration_blocks_ = cfg_.network.suspend_duration_blocks;
  if (cfg_.validator_min_bond_override.has_value()) validator_min_bond_ = *cfg_.validator_min_bond_override;
  if (cfg_.validator_bond_min_amount_override.has_value())
    validator_bond_min_amount_ = *cfg_.validator_bond_min_amount_override;
  if (cfg_.validator_bond_max_amount_override.has_value())
    validator_bond_max_amount_ = *cfg_.validator_bond_max_amount_override;
  if (validator_bond_max_amount_ < validator_bond_min_amount_) validator_bond_max_amount_ = validator_bond_min_amount_;
  if (cfg_.validator_warmup_blocks_override.has_value()) validator_warmup_blocks_ = *cfg_.validator_warmup_blocks_override;
  if (cfg_.validator_cooldown_blocks_override.has_value()) validator_cooldown_blocks_ = *cfg_.validator_cooldown_blocks_override;
  if (cfg_.validator_join_limit_window_blocks_override.has_value())
    validator_join_limit_window_blocks_ = *cfg_.validator_join_limit_window_blocks_override;
  if (cfg_.validator_join_limit_max_new_override.has_value())
    validator_join_limit_max_new_ = *cfg_.validator_join_limit_max_new_override;
  if (cfg_.liveness_window_blocks_override.has_value())
    validator_liveness_window_blocks_ = *cfg_.liveness_window_blocks_override;
  if (cfg_.miss_rate_suspend_threshold_percent_override.has_value())
    validator_miss_rate_suspend_threshold_percent_ = *cfg_.miss_rate_suspend_threshold_percent_override;
  if (cfg_.miss_rate_exit_threshold_percent_override.has_value())
    validator_miss_rate_exit_threshold_percent_ = *cfg_.miss_rate_exit_threshold_percent_override;
  if (cfg_.suspend_duration_blocks_override.has_value())
    validator_suspend_duration_blocks_ = *cfg_.suspend_duration_blocks_override;
  mempool_.set_network(cfg_.network);
  mempool_.set_hashcash_config(policy::HashcashConfig{
      .enabled = cfg_.hashcash_enabled,
      .base_bits = cfg_.hashcash_base_bits,
      .max_bits = cfg_.hashcash_max_bits,
      .epoch_seconds = cfg_.hashcash_epoch_seconds,
      .fee_exempt_min = cfg_.hashcash_fee_exempt_min,
      .pressure_tx_threshold = cfg_.hashcash_pressure_tx_threshold,
      .pressure_step_txs = cfg_.hashcash_pressure_step_txs,
      .pressure_bits_per_step = cfg_.hashcash_pressure_bits_per_step,
      .large_tx_bytes = cfg_.hashcash_large_tx_bytes,
      .large_tx_extra_bits = cfg_.hashcash_large_tx_extra_bits,
  });

  validators_.set_rules(consensus::ValidatorRules{
      .min_bond = effective_validator_min_bond_for_height(0),
      .warmup_blocks = validator_warmup_blocks_,
      .cooldown_blocks = validator_cooldown_blocks_,
  });
  if (!init_local_validator_key()) return false;
  p2p::AddrPolicy addr_policy;
  addr_policy.required_port = cfg_.network.p2p_default_port;
  addr_policy.reject_unroutable = true;
  addrman_.set_policy(addr_policy);
  if (!db_.open(cfg_.db_path)) {
    std::cerr << "db open failed: " << cfg_.db_path << "\n";
    return false;
  }
  if (cfg_.reindex_on_start) {
    const bool erased = db_.erase(storage::key_consensus_state_commitment_cache());
    if (erased) log_line("startup-reindex cleared=consensus-state-commitment-cache");
  }
  if (!init_mainnet_genesis()) {
    std::cerr << "mainnet genesis init failed\n";
    return false;
  }
  chain_id_ =
      ChainId::from_config_and_db(cfg_.network, db_, std::nullopt, genesis_source_hint_, expected_genesis_hash_);
  if (!load_state()) {
    std::cerr << "load_state failed\n";
    return false;
  }
  {
    std::ostringstream oss;
    oss << "chain-id network=" << chain_id_.network_name << " proto=" << chain_id_.protocol_version
        << " network_id=" << chain_id_.network_id_hex << " magic=" << chain_id_.magic
        << " genesis_hash=" << chain_id_.genesis_hash_hex << " genesis_source=" << chain_id_.genesis_source
        << " chain_id_ok=" << (chain_id_.chain_id_ok ? 1 : 0) << " db_dir=" << cfg_.db_path;
    log_line(oss.str());
  }
  log_line("consensus-path mode=finalized-checkpoint-committee");
  if (auto checkpoint = finalized_committee_checkpoint_for_height_locked(finalized_height_ + 1); checkpoint.has_value()) {
    log_line("epoch-committee-startup next_height=" + std::to_string(finalized_height_ + 1) +
             " source=finalized-checkpoint committee=" + std::to_string(checkpoint->ordered_members.size()));
  } else {
    log_line("epoch-committee-startup next_height=" + std::to_string(finalized_height_ + 1) +
             " reason=missing-finalized-committee-checkpoint");
  }

  {
    std::lock_guard<std::mutex> lk(mu_);
    // Ensure no stale in-memory state survives re-init.
    current_round_ = 0;
    round_started_ms_ = now_ms();
    candidate_block_sizes_.clear();
    proposed_in_round_.clear();
    logged_committee_rounds_.clear();
    votes_.clear_height(finalized_height_ + 1);
    timeout_votes_.clear_height(finalized_height_ + 1);
    highest_tc_by_height_.erase(finalized_height_ + 1);
    local_timeout_vote_reservations_.clear();
  }
  if (restart_debug_) {
    log_line("restart-debug startup-state height=" + std::to_string(finalized_height_) + " round=" +
             std::to_string(current_round_) + " transition=" + hex_encode32(finalized_identity_.id));
  }

  is_validator_ = validators_.is_active_for_height(local_key_.public_key, finalized_height_ + 1);

  round_started_ms_ = now_ms();
  last_finalized_progress_ms_ = now_ms();
  last_finalized_tip_poll_ms_ = 0;
  {
    std::lock_guard<std::mutex> lk(mu_);
    (void)db_.put_node_runtime_status_snapshot(build_runtime_status_snapshot_locked(now_unix() * 1000));
  }

  load_persisted_peers();
  load_addrman();
  for (const auto& p : cfg_.peers) bootstrap_peers_.push_back(p);
  for (const auto& s : cfg_.seeds) bootstrap_peers_.push_back(s);
  const bool allow_default_seed_fallback = !bootstrap_template_mode_;
  if (cfg_.seeds.empty() && allow_default_seed_fallback) {
    for (const auto& s : cfg_.network.default_seeds) bootstrap_peers_.push_back(s);
  }
  if (cfg_.dns_seeds) {
    dns_seed_peers_ = resolve_dns_seeds_once();
    for (const auto& d : dns_seed_peers_) bootstrap_peers_.push_back(d);
  }

  if (!cfg_.disable_p2p) {
    p2p_.configure_network(cfg_.network.magic, cfg_.network.protocol_version, cfg_.network.max_payload_len);
    p2p_.configure_limits(
        p2p::PeerManager::Limits{cfg_.handshake_timeout_ms, cfg_.frame_timeout_ms, cfg_.idle_timeout_ms,
                                 cfg_.peer_queue_max_bytes, cfg_.peer_queue_max_msgs, cfg_.max_inbound});
    p2p_.set_on_message([this](int peer_id, std::uint16_t msg_type, const Bytes& payload) {
      handle_message(peer_id, msg_type, payload);
    });
    p2p_.set_accept_filter([this](const std::string& ip) {
      return !discipline_.is_banned(ip, now_unix());
    });
    p2p_.set_read_timeout_override([this](int peer_id, const p2p::PeerInfo& info) -> std::optional<std::uint32_t> {
      if (!info.established()) return std::nullopt;
      std::lock_guard<std::mutex> lk(mu_);
      bool sync_incomplete = bootstrap_sync_incomplete_locked(peer_id);
      bool local_sync_backlog = !requested_sync_artifacts_.empty() || !requested_sync_heights_.empty();
      bool peer_tip_diverged = false;
      if (auto it = peer_finalized_tips_.find(peer_id); it != peer_finalized_tips_.end()) {
        peer_tip_diverged = it->second.height != finalized_height_ || it->second.hash != finalized_identity_.id;
      }
      if (!sync_incomplete && !local_sync_backlog && !peer_tip_diverged) return std::nullopt;
      return std::max<std::uint32_t>(cfg_.idle_timeout_ms, 600'000u);
    });
    p2p_.set_on_event([this](int peer_id, p2p::PeerManager::PeerEventType type, const std::string& detail) {
      if (type == p2p::PeerManager::PeerEventType::CONNECTED) {
        {
          std::lock_guard<std::mutex> lk(mu_);
          peer_ip_cache_[peer_id] = endpoint_to_ip(detail);
          peer_inbound_cache_[peer_id] = p2p_.get_peer_info(peer_id).inbound;
          peer_keepalive_ms_[peer_id] = now_ms();
        }
        const auto info = p2p_.get_peer_info(peer_id);
        log_line("peer-connected peer_id=" + std::to_string(peer_id) + " dir=" + (info.inbound ? "inbound" : "outbound") +
                 " endpoint=" + detail);
        if (discipline_.is_banned(endpoint_to_ip(detail), now_unix())) {
          p2p_.disconnect_peer(peer_id);
          return;
        }
        if (!info.version_tx) send_version(peer_id);
        return;
      }
      if (type == p2p::PeerManager::PeerEventType::DISCONNECTED) {
        std::lock_guard<std::mutex> lk(mu_);
        const bool inbound = [&]() {
          auto it = peer_inbound_cache_.find(peer_id);
          if (it != peer_inbound_cache_.end()) return it->second;
          return false;
        }();
        log_line("peer-disconnected peer_id=" + std::to_string(peer_id) + " dir=" + (inbound ? "inbound" : "outbound") +
                 " detail=" + detail);
        const bool had_round_activity =
            proposed_in_round_.find(std::make_pair(finalized_height_ + 1, current_round_)) != proposed_in_round_.end() ||
            local_vote_reservations_.find(std::make_pair(finalized_height_ + 1, current_round_)) !=
                local_vote_reservations_.end() ||
            local_timeout_vote_reservations_.find(std::make_pair(finalized_height_ + 1, current_round_)) !=
                local_timeout_vote_reservations_.end() ||
            !votes_.participants_for(finalized_height_ + 1, current_round_).empty() ||
            !timeout_votes_.signatures_for(finalized_height_ + 1, current_round_).empty();
        peer_ip_cache_.erase(peer_id);
        peer_inbound_cache_.erase(peer_id);
        peer_keepalive_ms_.erase(peer_id);
        peer_validator_pubkeys_.erase(peer_id);
        peer_finalized_tips_.erase(peer_id);
        peer_ingress_tips_.erase(peer_id);
        getaddr_requested_peers_.erase(peer_id);
        msg_rate_buckets_.erase(peer_id);
        vote_verify_buckets_.erase(peer_id);
        tx_verify_buckets_.erase(peer_id);
        for (auto it = requested_ingress_ranges_.begin(); it != requested_ingress_ranges_.end();) {
          if (it->first.first == peer_id) {
            it = requested_ingress_ranges_.erase(it);
          } else {
            ++it;
          }
        }
        requested_sync_artifacts_.clear();
        requested_sync_heights_.clear();
        const auto current_height = finalized_height_ + 1;
        if (established_peer_count() == 0 && !single_node_bootstrap_active_locked(current_height)) {
          reconnect_round_reset_pending_ = true;
        }
        const bool should_reset_round_state =
            established_peer_count() == 0 && !single_node_bootstrap_active_locked(current_height) &&
            (current_round_ > 0 || had_round_activity);
        if (should_reset_round_state) {
          current_round_ = 0;
          proposed_in_round_.clear();
          local_vote_reservations_.clear();
          local_timeout_vote_reservations_.clear();
          votes_.clear_height(current_height);
          timeout_votes_.clear_height(current_height);
          round_started_ms_ = now_ms();
          log_line("peer-loss-reset height=" + std::to_string(current_height) + " reason=no-established-peers");
        }
        return;
      }
      if (type == p2p::PeerManager::PeerEventType::FRAME_INVALID) {
        const auto pi = p2p_.get_peer_info(peer_id);
        const std::string ip = pi.ip.empty() ? endpoint_to_ip(pi.endpoint) : pi.ip;
        const std::uint64_t tms = now_ms();
        bool should_log = false;
        {
          std::lock_guard<std::mutex> lk(mu_);
          auto& last = invalid_frame_log_ms_[ip];
          if (tms > last + 10'000) {
            should_log = true;
            last = tms;
          }
        }
        const std::string klass = token_value(detail, "class");
        if (should_log) {
          std::ostringstream oss;
          oss << "frame-parse-fail peer_id=" << peer_id << " dir=" << (pi.inbound ? "inbound" : "outbound")
              << " endpoint=" << pi.endpoint << " " << detail;
          log_line(oss.str());
          if (klass == "HTTP" || klass == "JSON") {
            log_line("peer sent HTTP/JSON bytes; likely dialing lightserver port (19444) instead of P2P");
          } else if (klass == "TLS") {
            log_line("peer sent TLS handshake bytes; do not place TLS/proxy in front of P2P port");
          } else if (token_value(detail, "reason") == "MAGIC_MISMATCH") {
            log_line("magic mismatch: peer is likely on a different network");
          }
        }
        score_peer(peer_id, p2p::MisbehaviorReason::INVALID_FRAME, "invalid-frame");
      } else if (type == p2p::PeerManager::PeerEventType::FRAME_TIMEOUT ||
                 type == p2p::PeerManager::PeerEventType::HANDSHAKE_TIMEOUT) {
        const auto pi = p2p_.get_peer_info(peer_id);
        const std::string ip = pi.ip.empty() ? endpoint_to_ip(pi.endpoint) : pi.ip;
        log_line("peer-timeout peer_id=" + std::to_string(peer_id) + " dir=" + (pi.inbound ? "inbound" : "outbound") +
                 " endpoint=" + pi.endpoint + " detail=" + detail + " stage=" +
                 (type == p2p::PeerManager::PeerEventType::HANDSHAKE_TIMEOUT ? "handshake" : "frame"));
        if (bootstrap_template_mode_ && !bootstrap_validator_pubkey_.has_value() && is_bootstrap_peer_ip(ip)) {
          log_line("bootstrap-timeout peer_id=" + std::to_string(peer_id) + " ip=" + ip + " note=timeout");
          return;
        }
        score_peer(peer_id, type == p2p::PeerManager::PeerEventType::HANDSHAKE_TIMEOUT
                                ? p2p::MisbehaviorReason::HANDSHAKE_TIMEOUT
                                : p2p::MisbehaviorReason::INVALID_FRAME,
                   type == p2p::PeerManager::PeerEventType::HANDSHAKE_TIMEOUT ? "handshake-timeout" : "timeout");
      } else if (type == p2p::PeerManager::PeerEventType::QUEUE_OVERFLOW) {
        score_peer(peer_id, p2p::MisbehaviorReason::RATE_LIMIT, "queue-overflow");
      }
    });
    if (cfg_.listen) {
      if (!p2p_.start_listener(cfg_.bind_ip, cfg_.p2p_port)) {
        const int err = errno;
        std::cerr << "listener start failed " << cfg_.bind_ip << ":" << cfg_.p2p_port << " errno=" << err
                  << " err=\"" << std::strerror(err) << "\"\n";
        return false;
      }
      cfg_.p2p_port = p2p_.listener_port();
    }
    try_connect_bootstrap_peers();
  }

  if (bootstrap_template_mode_ && !bootstrap_validator_pubkey_.has_value() && finalized_height_ == 0 &&
      validators_.active_sorted(1).empty()) {
    const bool has_bootstrap_sources = !cfg_.disable_p2p && (!bootstrap_peers_.empty() || !dns_seed_peers_.empty());
    if (!has_bootstrap_sources && bootstrap_template_bind_validator(local_key_.public_key, true)) {
      log_line("bootstrap single-node genesis from local validator pubkey=" +
               hex_encode(Bytes(local_key_.public_key.begin(), local_key_.public_key.end())) + " action=init-self-bind");
    }
  }

  if (!ensure_required_epoch_committee_state_startup()) {
    std::cerr << "required epoch committee state repair failed db=" << cfg_.db_path
              << " finalized_height=" << finalized_height_
              << " bootstrap_template=" << (bootstrap_template_mode_ ? "yes" : "no")
              << " bootstrap_bound=" << (bootstrap_validator_pubkey_.has_value() ? "yes" : "no") << "\n";
    return false;
  }

  return true;
}

bool Node::init_local_validator_key() {
  const std::string key_path = expand_user_home(cfg_.validator_key_file.empty()
                                                    ? keystore::default_validator_keystore_path(cfg_.db_path)
                                                    : cfg_.validator_key_file);
  keystore::ValidatorKey vk;
  std::string kerr;
  if (keystore::keystore_exists(key_path)) {
    if (!keystore::load_validator_keystore(key_path, cfg_.validator_passphrase, &vk, &kerr)) {
      std::cerr << "failed to load validator keystore: " << kerr << "\n";
      return false;
    }
  } else {
    if (!keystore::create_validator_keystore(key_path, cfg_.validator_passphrase, cfg_.network.name,
                                             keystore::hrp_for_network(cfg_.network.name), std::nullopt, &vk, &kerr)) {
      std::cerr << "failed to create validator keystore: " << kerr << "\n";
      return false;
    }
    log_line("created validator keystore path=" + key_path);
  }
  local_key_.private_key.assign(vk.privkey.begin(), vk.privkey.end());
  local_key_.public_key = vk.pubkey;
  log_line("validator pubkey=" + hex_encode(Bytes(vk.pubkey.begin(), vk.pubkey.end())) + " address=" + vk.address);
  return true;
}

bool Node::bootstrap_template_bind_validator(const PubKey32& pub, bool local_validator) {
  if (bootstrap_handoff_complete_locked()) {
    log_line("bootstrap-bind-skip reason=handoff-complete height=" + std::to_string(finalized_height_));
    return false;
  }
  genesis::Document effective;
  effective.version = 1;
  effective.network_name = cfg_.network.name;
  effective.protocol_version = cfg_.network.protocol_version;
  effective.network_id = cfg_.network.network_id;
  effective.magic = cfg_.network.magic;
  effective.genesis_time_unix = 1735689600ULL;
  effective.initial_height = 0;
  effective.initial_validators = {pub};
  effective.initial_active_set_size = 1;
  effective.initial_committee_params.min_committee = 1;
  effective.initial_committee_params.max_committee = static_cast<std::uint32_t>(cfg_.network.max_committee);
  effective.initial_committee_params.sizing_rule = "min(MAX_COMMITTEE,ACTIVE_SIZE)";
  effective.initial_committee_params.c = 1;
  effective.monetary_params_ref = "README.md#monetary-policy-7m-hard-cap";
  effective.note = local_validator ? "single-node bootstrap bound to local validator"
                                   : "bootstrap validator adopted from network";
  const auto json = genesis::to_json(effective);
  if (!db_.put(storage::key_genesis_json(), Bytes(json.begin(), json.end()))) return false;

  consensus::CanonicalGenesisState rebound_genesis;
  rebound_genesis.genesis_artifact_id = genesis::block_id(effective);
  if (auto stored_genesis_artifact = db_.get(storage::key_genesis_artifact());
      stored_genesis_artifact.has_value() && stored_genesis_artifact->size() == 32) {
    std::copy(stored_genesis_artifact->begin(), stored_genesis_artifact->end(), rebound_genesis.genesis_artifact_id.begin());
  }
  rebound_genesis.initial_validators = {pub};

  consensus::CanonicalDerivedState rebound_state;
  std::string rebound_error;
  if (!consensus::build_genesis_canonical_state(canonical_derivation_config_locked(), rebound_genesis, &rebound_state,
                                                &rebound_error)) {
    log_line("bootstrap-bind-canonical-rebuild-failed detail=" + rebound_error);
    return false;
  }

  validators_ = rebound_state.validators;
  finalized_randomness_ = rebound_state.finalized_randomness;
  committee_epoch_randomness_cache_ = rebound_state.committee_epoch_randomness_cache;
  protocol_reserve_balance_units_ = rebound_state.protocol_reserve_balance_units;
  finalized_committee_checkpoints_ = rebound_state.finalized_committee_checkpoints;
  canonical_state_ = rebound_state;
  if (!persist_canonical_cache_rows(db_, rebound_state)) return false;
  (void)db_.erase(storage::key_consensus_state_commitment_cache());
  if (!verify_and_persist_consensus_state_commitment_locked(rebound_state)) return false;

  const UtxoSetV2 empty_utxos;
  (void)persist_state_roots(db_, 0, empty_utxos, validators_, kFixedValidationRulesVersion);
  (void)db_.put(kFinalizedRandomnessKey, Bytes(finalized_randomness_.begin(), finalized_randomness_.end()));
  if (!db_.flush()) return false;

  bootstrap_validator_pubkey_ = pub;
  is_validator_ = local_validator;
  return true;
}

bool Node::maybe_adopt_bootstrap_validator_from_peer(int peer_id, const PubKey32& pub, std::uint64_t peer_height,
                                                     const char* source) {
  const auto info = p2p_.get_peer_info(peer_id);
  const std::string ip = info.ip.empty() ? endpoint_to_ip(info.endpoint) : info.ip;
  // Trust boundary: height-0 bootstrap adoption is only allowed from an explicitly
  // configured bootstrap peer that advertises bootstrap_validator in VERSION.
  const bool explicit_bootstrap_advertisement = std::string(source) == "version-bootstrap";
  if (!bootstrap_template_mode_) return false;
  if (bootstrap_handoff_complete_locked()) {
    log_line("bootstrap-adopt-skip peer_id=" + std::to_string(peer_id) + " source=" + source +
             " reason=handoff-complete height=" + std::to_string(finalized_height_));
    return false;
  }
  if (bootstrap_validator_pubkey_.has_value()) {
    log_line("bootstrap-adopt-skip peer_id=" + std::to_string(peer_id) + " source=" + source +
             " reason=already-bound");
    return false;
  }
  if (finalized_height_ != 0) {
    log_line("bootstrap-adopt-skip peer_id=" + std::to_string(peer_id) + " source=" + source +
             " reason=already-synced height=" + std::to_string(finalized_height_));
    return false;
  }
  if (!validators_.active_sorted(1).empty()) {
    log_line("bootstrap-adopt-skip peer_id=" + std::to_string(peer_id) + " source=" + source +
             " reason=validators-present");
    return false;
  }
  if (!is_bootstrap_peer_ip(ip)) {
    log_line("bootstrap-adopt-skip peer_id=" + std::to_string(peer_id) + " source=" + source +
             " reason=peer-not-bootstrap ip=" + ip);
    return false;
  }
  if (peer_height == 0 && !explicit_bootstrap_advertisement) {
    log_line("bootstrap-adopt-skip peer_id=" + std::to_string(peer_id) + " source=" + source +
             " reason=peer-height-zero");
    return false;
  }
  if (!bootstrap_template_bind_validator(pub, pub == local_key_.public_key)) {
    log_line("bootstrap-adopt-skip peer_id=" + std::to_string(peer_id) + " source=" + source +
             " reason=bind-failed");
    return false;
  }
  log_line(std::string("adopted bootstrap validator from peer pubkey=") +
           hex_encode(Bytes(pub.begin(), pub.end())) + " source=" + source + " peer_id=" + std::to_string(peer_id) +
           " peer_height=" + std::to_string(peer_height));
  return true;
}

void Node::maybe_self_bootstrap_template(std::uint64_t now_ms) {
  if (!bootstrap_template_mode_ || bootstrap_validator_pubkey_.has_value()) return;
  if (bootstrap_handoff_complete_locked()) return;
  if (finalized_height_ != 0) return;
  if (!validators_.active_sorted(1).empty()) return;
  const bool has_bootstrap_sources = !cfg_.disable_p2p && (!bootstrap_peers_.empty() || !dns_seed_peers_.empty());
  if (has_bootstrap_sources) return;
  const std::uint64_t wait_ms = cfg_.disable_p2p ? 0ULL : 5000ULL;
  if (now_ms < startup_ms_ + wait_ms) return;
  if (bootstrap_template_bind_validator(local_key_.public_key, true)) {
    log_line("bootstrap single-node genesis from local validator pubkey=" +
             hex_encode(Bytes(local_key_.public_key.begin(), local_key_.public_key.end())));
    if (!cfg_.disable_p2p) {
      // Safe: duplicate VERSION handling is idempotent and is used here to refresh
      // already-connected peers with the newly-bound bootstrap validator identity.
      for (int peer_id : p2p_.peer_ids()) send_version(peer_id);
    }
  }
}

std::optional<Hash32> Node::pending_join_request_for_validator_locked(const PubKey32& pub) const {
  for (const auto& [request_txid, req] : validator_join_requests_) {
    if (req.validator_pubkey != pub) continue;
    if (req.status != ValidatorJoinRequestStatus::REQUESTED) continue;
    return request_txid;
  }
  return std::nullopt;
}

std::size_t Node::pending_join_request_count_locked() const {
  std::size_t count = 0;
  for (const auto& [_, req] : validator_join_requests_) {
    if (req.status == ValidatorJoinRequestStatus::REQUESTED) ++count;
  }
  return count;
}

bool Node::bootstrap_joiner_ready_locked(const PubKey32& pub) const {
  for (const auto& [peer_id, peer_pub] : peer_validator_pubkeys_) {
    if (peer_pub != pub) continue;
    const auto tip_it = peer_finalized_tips_.find(peer_id);
    if (tip_it == peer_finalized_tips_.end()) continue;
    if (tip_it->second.height != finalized_height_ || tip_it->second.hash != finalized_identity_.id) continue;
    if (!p2p_.get_peer_info(peer_id).established()) continue;
    return true;
  }
  return false;
}

bool Node::bootstrap_sync_incomplete_locked(int peer_id) const {
  if (!bootstrap_template_mode_) return false;
  if (is_validator_) return false;
  if (finalized_height_ == 0) return true;
  const auto it = peer_finalized_tips_.find(peer_id);
  if (it == peer_finalized_tips_.end()) return false;
  return it->second.height > finalized_height_ || it->second.hash != finalized_identity_.id;
}

void Node::start() {
  if (running_.exchange(true)) return;
  {
    std::lock_guard<std::mutex> lk(mu_);
    const auto now = now_ms();
    round_started_ms_ = now;
    last_finalized_progress_ms_ = now;
    last_finalized_tip_poll_ms_ = 0;
  }
  if (cfg_.disable_p2p) {
    std::lock_guard<std::mutex> lk(g_local_bus_mu);
    g_local_bus_nodes.push_back(this);
  }
  loop_thread_ = std::thread([this]() { event_loop(); });
  if (!start_lightserver_child()) {
    log_line("lightserver not running mode=" + lightserver_mode_name() + " reason=start-failed");
  }
}

void Node::stop() {
  if (restart_debug_) {
    std::lock_guard<std::mutex> lk(mu_);
    log_line("restart-debug shutdown-begin height=" + std::to_string(finalized_height_) + " round=" +
             std::to_string(current_round_) + " transition=" + hex_encode32(finalized_identity_.id));
  }
  const bool was_running = running_.exchange(false);
  stop_lightserver_child();
  if (!was_running) {
    join_local_bus_tasks();
    persist_peers();
    persist_addrman();
    p2p_.stop();
    db_.close();
    return;
  }
  if (cfg_.disable_p2p) {
    std::lock_guard<std::mutex> lk(g_local_bus_mu);
    g_local_bus_nodes.erase(std::remove(g_local_bus_nodes.begin(), g_local_bus_nodes.end(), this), g_local_bus_nodes.end());
  }
  if (loop_thread_.joinable()) {
    try {
      loop_thread_.join();
    } catch (const std::system_error& e) {
      log_line(std::string("shutdown-join-exception source=event-loop error=\"") + e.what() + "\"");
    }
  }
  if (restart_debug_) log_line("restart-debug event-loop-joined");
  if (restart_debug_) log_line("restart-debug round-timer-cancelled");
  join_local_bus_tasks();
  if (restart_debug_) log_line("restart-debug local-bus-tasks-joined");
  std::vector<p2p::PeerInfo> persisted_peers;
  persisted_peers.reserve(p2p_.peer_ids().size());
  for (int id : p2p_.peer_ids()) persisted_peers.push_back(p2p_.get_peer_info(id));
  p2p_.stop();
  if (restart_debug_) log_line("restart-debug p2p-stopped");
  persist_peers(persisted_peers);
  persist_addrman();
  if (restart_debug_) log_line("restart-debug peers-persisted");
  {
    std::lock_guard<std::mutex> lk(mu_);
    (void)db_.flush();
    if (restart_debug_) log_line("restart-debug db-flushed");
    db_.close();
    if (restart_debug_) log_line("restart-debug db-closed");
  }
}

bool Node::start_lightserver_child() {
  if (cfg_.lightserver_mode == LightserverLaunchMode::Disabled) {
    log_line("lightserver disabled mode=disabled");
    return true;
  }

  {
    std::lock_guard<std::mutex> lk(lightserver_mu_);
    if (lightserver_pid_ > 0) {
      log_line("lightserver startup skipped reason=already-running pid=" + std::to_string(lightserver_pid_));
      return true;
    }
  }

  const std::string mode = lightserver_mode_name();
  const bool public_lightserver = lightserver_is_public();
  const std::string exposure = public_lightserver ? "public" : "local-only";
  bool sibling_found = false;
  const std::string binary = lightserver_binary_path(&sibling_found);
  {
    std::lock_guard<std::mutex> lk(lightserver_mu_);
    lightserver_exec_path_ = binary;
  }
  log_line("lightserver enabled mode=" + mode + " exec=" + binary +
           " exec_source=" + (sibling_found ? "sibling" : "PATH") + " bind=" + cfg_.lightserver_bind +
           " port=" + std::to_string(cfg_.lightserver_port) + " exposure=" + exposure);

  if (!public_lightserver) {
    if (auto detected_ip = detect_possible_public_ip(); detected_ip.has_value()) {
      log_line("detected possible public IP: " + *detected_ip);
      log_line("lightserver is bound to " + cfg_.lightserver_bind +
               "; to expose publicly use: --public --lightserver-bind 0.0.0.0");
    }
  }

  std::string bind_error;
  if (!preflight_lightserver_bind(&bind_error)) {
    log_line("lightserver startup failed mode=" + mode + " reason=" + bind_error);
    return false;
  }

#ifdef _WIN32
  log_line("lightserver child launch unsupported on windows; start finalis-lightserver.exe separately");
  return true;
#else

  std::vector<std::string> args{
      binary,
      "--db",
      cfg_.db_path,
      "--bind",
      cfg_.lightserver_bind,
      "--port",
      std::to_string(cfg_.lightserver_port),
      "--relay-host",
      "127.0.0.1",
      "--relay-port",
      std::to_string(cfg_.p2p_port),
  };

  std::vector<char*> argv;
  argv.reserve(args.size() + 1);
  for (auto& arg : args) argv.push_back(arg.data());
  argv.push_back(nullptr);

  const pid_t pid = fork();
  if (pid < 0) {
    log_line("lightserver startup failed mode=" + mode + " reason=fork");
    return false;
  }
  if (pid == 0) {
    execv(binary.c_str(), argv.data());
    argv[0] = const_cast<char*>("finalis-lightserver");
    execvp("finalis-lightserver", argv.data());
    std::perror("finalis-lightserver exec");
    _exit(127);
  }

  {
    std::lock_guard<std::mutex> lk(lightserver_mu_);
    lightserver_pid_ = static_cast<int>(pid);
  }
  ::usleep(200 * 1000);
  int status = 0;
  const pid_t waited = ::waitpid(pid, &status, WNOHANG);
  if (waited == pid) {
    std::lock_guard<std::mutex> lk(lightserver_mu_);
    lightserver_pid_ = -1;
    std::ostringstream oss;
    oss << "lightserver startup failed mode=" << mode << " pid=" << pid;
    if (WIFEXITED(status)) {
      const int code = WEXITSTATUS(status);
      oss << " exit_code=" << code;
      if (code == 1) oss << " note=check bind/db/init in child";
    } else if (WIFSIGNALED(status)) {
      oss << " signal=" << WTERMSIG(status);
    }
    log_line(oss.str());
    return false;
  }
  log_line("lightserver startup success mode=" + mode + " pid=" + std::to_string(pid));
  if (!cfg_.listen || cfg_.disable_p2p) {
    log_line("lightserver note: node listener is disabled; read RPC works, but tx relay to the node may fail");
  }
  return true;
#endif
}

void Node::stop_lightserver_child() {
#ifdef _WIN32
  std::lock_guard<std::mutex> lk(lightserver_mu_);
  lightserver_pid_ = -1;
  return;
#else
  pid_t pid = -1;
  {
    std::lock_guard<std::mutex> lk(lightserver_mu_);
    if (lightserver_pid_ <= 0) return;
    pid = static_cast<pid_t>(lightserver_pid_);
    lightserver_pid_ = -1;
  }
  int status = 0;
  const pid_t already = ::waitpid(pid, &status, WNOHANG);
  if (already == pid) {
    log_line("lightserver exit observed during stop pid=" + std::to_string(pid));
    return;
  }
  log_line("stopping lightserver pid=" + std::to_string(pid));
  if (::kill(pid, SIGTERM) != 0 && errno == ESRCH) {
    (void)::waitpid(pid, &status, WNOHANG);
    return;
  }
  for (int i = 0; i < 20; ++i) {
    const pid_t waited = ::waitpid(pid, &status, WNOHANG);
    if (waited == pid) return;
    ::usleep(100 * 1000);
  }
  if (::kill(pid, SIGKILL) != 0 && errno == ESRCH) {
    (void)::waitpid(pid, &status, WNOHANG);
    return;
  }
  (void)::waitpid(pid, &status, 0);
#endif
}

bool Node::reap_lightserver_child(bool verbose) {
#ifdef _WIN32
  (void)verbose;
  return false;
#else
  pid_t pid = -1;
  {
    std::lock_guard<std::mutex> lk(lightserver_mu_);
    if (lightserver_pid_ <= 0) return false;
    pid = static_cast<pid_t>(lightserver_pid_);
  }
  int status = 0;
  const pid_t waited = ::waitpid(pid, &status, WNOHANG);
  if (waited == 0) return false;
  if (waited < 0) {
    if (errno == ECHILD) {
      std::lock_guard<std::mutex> lk(lightserver_mu_);
      if (lightserver_pid_ == pid) lightserver_pid_ = -1;
    }
    return false;
  }
  {
    std::lock_guard<std::mutex> lk(lightserver_mu_);
    if (lightserver_pid_ == pid) lightserver_pid_ = -1;
  }
  if (verbose) {
    std::ostringstream oss;
    oss << "lightserver exited pid=" << pid;
    if (WIFEXITED(status)) {
      oss << " exit_code=" << WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
      oss << " signal=" << WTERMSIG(status);
    }
    log_line(oss.str());
  }
  return true;
#endif
}

bool Node::preflight_lightserver_bind(std::string* err) const {
  if (!net::ensure_sockets()) {
    if (err) *err = "socket-init";
    return false;
  }
  const auto fd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (!net::valid_socket(fd)) {
    if (err) *err = "socket-open";
    return false;
  }
  (void)net::set_reuseaddr(fd);
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(cfg_.lightserver_port);
  if (::inet_pton(AF_INET, cfg_.lightserver_bind.c_str(), &addr.sin_addr) != 1) {
    if (err) *err = "invalid-bind-address";
    net::close_socket(fd);
    return false;
  }
  if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
    if (err) {
      std::ostringstream oss;
      const int code = net::socket_last_error();
      oss << "bind-failed errno=" << code << " (" << net::socket_error_string(code) << ")";
      *err = oss.str();
    }
    net::close_socket(fd);
    return false;
  }
  net::close_socket(fd);
  return true;
}

std::optional<std::string> Node::detect_possible_public_ip() const {
  char hostname[256] = {};
  if (::gethostname(hostname, sizeof(hostname) - 1) != 0) return std::nullopt;
  addrinfo hints{};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  addrinfo* result = nullptr;
  if (::getaddrinfo(hostname, nullptr, &hints, &result) != 0) return std::nullopt;
  std::optional<std::string> out;
  for (addrinfo* it = result; it != nullptr; it = it->ai_next) {
    auto* sin = reinterpret_cast<sockaddr_in*>(it->ai_addr);
    char buf[INET_ADDRSTRLEN] = {};
    if (!::inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf))) continue;
    const std::string ip(buf);
    if (is_local_only_bind(ip) || ip.rfind("127.", 0) == 0) continue;
    out = ip;
    break;
  }
  ::freeaddrinfo(result);
  return out;
}

std::string Node::lightserver_mode_name() const {
  return launch_mode_name(cfg_.lightserver_mode);
}

std::string Node::lightserver_binary_path(bool* sibling_found) const {
  if (sibling_found) *sibling_found = false;
#ifdef _WIN32
  return "finalis-lightserver.exe";
#else
  char exe_path[4096] = {};
  const ssize_t n = ::readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
  if (n > 0) {
    exe_path[n] = '\0';
    std::filesystem::path p(exe_path);
    const std::filesystem::path sibling = p.parent_path() / "finalis-lightserver";
    std::error_code ec;
    if (std::filesystem::exists(sibling, ec) && !ec) {
      if (sibling_found) *sibling_found = true;
      return sibling.string();
    }
  }
  return "finalis-lightserver";
#endif
}

bool Node::lightserver_is_public() const {
  return !is_local_only_bind(cfg_.lightserver_bind) && cfg_.lightserver_bind != "127.0.0.1";
}

NodeStatus Node::status() const {
  std::lock_guard<std::mutex> lk(mu_);
  NodeStatus s;
  s.network_name = cfg_.network.name;
  s.protocol_version = cfg_.network.protocol_version;
  s.magic = cfg_.network.magic;
  s.genesis_hash = chain_id_.genesis_hash_hex;
  s.genesis_source = chain_id_.genesis_source;
  s.chain_id_ok = chain_id_.chain_id_ok;
  s.db_dir = cfg_.db_path;
  s.network_id_short = hex_encode(Bytes(cfg_.network.network_id.begin(), cfg_.network.network_id.begin() + 4));
  s.height = finalized_height_;
  s.round = current_round_;
  s.transition_hash = finalized_identity_.id;
  s.transition_hash_short = short_hash_hex(finalized_identity_.id);
  auto leader = leader_for_height_round(finalized_height_ + 1, current_round_);
  if (leader.has_value()) s.leader = *leader;
  s.votes_for_current = 0;
  s.peers = peer_count();
  s.established_peers = established_peer_count();
  s.mempool_size = mempool_.size();
  const auto committee = committee_for_height_round(finalized_height_ + 1, current_round_);
  s.committee_size = committee.size();
  s.quorum_threshold = consensus::quorum_threshold(committee.size());
  s.addrman_size = addrman_.size();
  s.inbound_connected = cfg_.disable_p2p ? 0 : p2p_.inbound_count();
  s.outbound_connected = cfg_.disable_p2p ? peer_count() : p2p_.outbound_count();
  s.consensus_state = consensus_state_locked(now_ms(), &s.observed_signers, &s.quorum_threshold);
  s.last_bootstrap_source = last_bootstrap_source_;
  s.rejected_network_id = rejected_network_id_;
  s.rejected_protocol_version = rejected_protocol_version_;
  s.rejected_pre_handshake = rejected_pre_handshake_;
  s.consensus_version = kFixedValidationRulesVersion;
  s.participation_eligible_signers = static_cast<std::uint64_t>(last_participation_eligible_signers_);
  s.bootstrap_template_mode = bootstrap_template_mode_;
  if (bootstrap_validator_pubkey_.has_value()) {
    s.bootstrap_validator_pubkey =
        hex_encode(Bytes(bootstrap_validator_pubkey_->begin(), bootstrap_validator_pubkey_->end()));
  }
  s.pending_bootstrap_joiners = pending_join_request_count_locked();
  s.consensus_model = "finalized-checkpoint-committee-bft";
  s.current_round_slot = current_round_;
  if (auto checkpoint = finalized_committee_checkpoint_for_height_locked(finalized_height_ + 1); checkpoint.has_value()) {
    s.active_epoch_committee_size = checkpoint->ordered_members.size();
    s.availability_checkpoint_derivation_mode = checkpoint_derivation_mode_name(checkpoint->derivation_mode);
    s.availability_checkpoint_fallback_reason = checkpoint_fallback_reason_name(checkpoint->fallback_reason);
    s.availability_fallback_sticky =
        checkpoint->fallback_reason == storage::FinalizedCommitteeFallbackReason::HYSTERESIS_RECOVERY_PENDING;
    s.adaptive_target_committee_size = checkpoint->adaptive_target_committee_size;
    s.adaptive_min_eligible = checkpoint->adaptive_min_eligible;
    s.adaptive_min_bond = checkpoint->adaptive_min_bond;
    s.qualified_depth = checkpoint->qualified_depth;
    s.adaptive_slack = static_cast<std::int64_t>(checkpoint->qualified_depth) -
                       static_cast<std::int64_t>(checkpoint->adaptive_min_eligible);
    s.target_expand_streak = checkpoint->target_expand_streak;
    s.target_contract_streak = checkpoint->target_contract_streak;
    std::ostringstream committee;
    for (std::size_t i = 0; i < checkpoint->ordered_members.size(); ++i) {
      if (i) committee << ",";
      committee << short_pub_hex(checkpoint->ordered_members[i]);
    }
    s.active_epoch_committee_members_short = committee.str();
  }
  s.availability_epoch = availability_state_.current_epoch;
  s.availability_retained_prefix_count = availability_state_.retained_prefixes.size();
  s.availability_tracked_operator_count = availability_state_.operators.size();
  auto status_availability_cfg = cfg_.availability;
  if (auto checkpoint = finalized_committee_checkpoint_for_height_locked(finalized_height_ + 1); checkpoint.has_value()) {
    status_availability_cfg = consensus::availability_config_with_min_bond(cfg_.availability, checkpoint->adaptive_min_bond);
    s.availability_eligible_operator_count = consensus::count_eligible_operators_at_checkpoint(
        validators_, finalized_height_ + 1, availability_state_, status_availability_cfg);
    s.availability_below_min_eligible =
        s.adaptive_min_eligible != 0 && s.availability_eligible_operator_count < s.adaptive_min_eligible;
  } else {
    s.availability_eligible_operator_count =
        consensus::count_eligible_operators_at_checkpoint(validators_, finalized_height_ + 1, availability_state_,
                                                          status_availability_cfg);
    s.availability_below_min_eligible = false;
  }
  s.availability_state_rebuild_triggered = availability_state_rebuild_triggered_;
  s.availability_state_rebuild_reason = availability_state_rebuild_reason_;
  if (auto local_operator = local_operator_pubkey_locked(); local_operator.has_value()) {
    for (const auto& operator_state : availability_state_.operators) {
      if (operator_state.operator_pubkey != *local_operator) continue;
      s.availability_local_operator_known = true;
      s.availability_local_operator_pubkey =
          hex_encode(Bytes(operator_state.operator_pubkey.begin(), operator_state.operator_pubkey.end()));
      s.availability_local_operator_status = availability_status_name(operator_state.status);
      s.availability_local_service_score = operator_state.service_score;
      s.availability_local_warmup_epochs = operator_state.warmup_epochs;
      s.availability_local_successful_audits = operator_state.successful_audits;
      s.availability_local_late_audits = operator_state.late_audits;
      s.availability_local_missed_audits = operator_state.missed_audits;
      s.availability_local_invalid_audits = operator_state.invalid_audits;
      s.availability_local_retained_prefix_count = operator_state.retained_prefix_count;
      s.availability_local_eligibility_score =
          availability::operator_eligibility_score(operator_state, cfg_.availability);
      s.availability_local_seat_budget = availability::operator_seat_budget(operator_state, cfg_.availability);
      break;
    }
  }
  const auto adaptive_telemetry = db_.load_adaptive_epoch_telemetry();
  const auto adaptive_summary =
      storage::summarize_adaptive_epoch_telemetry(adaptive_telemetry, kAdaptiveTelemetryWindowEpochs);
  s.adaptive_fallback_rate_bps = adaptive_summary.fallback_rate_bps;
  s.adaptive_sticky_fallback_rate_bps = adaptive_summary.sticky_fallback_rate_bps;
  s.adaptive_fallback_window_epochs = adaptive_summary.sample_count;
  s.adaptive_near_threshold_operation = adaptive_summary.near_threshold_operation;
  s.adaptive_prolonged_expand_buildup = adaptive_summary.prolonged_expand_buildup;
  s.adaptive_prolonged_contract_buildup = adaptive_summary.prolonged_contract_buildup;
  s.adaptive_repeated_sticky_fallback = adaptive_summary.repeated_sticky_fallback;
  s.adaptive_depth_collapse_after_bond_increase = adaptive_summary.depth_collapse_after_bond_increase;
  if (auto runtime = db_.get_node_runtime_status_snapshot(); runtime.has_value()) {
    s.healthy_peer_count = runtime->healthy_peer_count;
    s.observed_network_height_known = runtime->observed_network_height_known;
    s.observed_network_finalized_height = runtime->observed_network_finalized_height;
    s.finalized_lag = runtime->finalized_lag;
    s.peer_height_disagreement = runtime->peer_height_disagreement;
    s.next_height_committee_available = runtime->next_height_committee_available;
    s.next_height_proposer_available = runtime->next_height_proposer_available;
    s.registration_ready = runtime->registration_ready;
    s.registration_readiness_stable_samples = runtime->readiness_stable_samples;
    s.registration_readiness_blockers = runtime->readiness_blockers_csv;
  }
  return s;
}

storage::NodeRuntimeStatusSnapshot Node::build_runtime_status_snapshot_locked(std::uint64_t now_ms) {
  storage::NodeRuntimeStatusSnapshot snapshot;
  snapshot.chain_id_ok = chain_id_.chain_id_ok;
  snapshot.db_open = true;
  snapshot.local_finalized_height = finalized_height_;
  snapshot.established_peer_count = established_peer_count();
  snapshot.next_height_committee_available = !committee_for_height_round(finalized_height_ + 1, current_round_).empty();
  snapshot.next_height_proposer_available = leader_for_height_round(finalized_height_ + 1, current_round_).has_value();
  snapshot.captured_at_unix_ms = now_ms;
  snapshot.mempool_tx_count = static_cast<std::uint64_t>(mempool_.size());
  snapshot.mempool_bytes = static_cast<std::uint64_t>(mempool_.total_bytes());
  const auto mempool_stats = mempool_.policy_stats();
  snapshot.mempool_full =
      snapshot.mempool_tx_count >= mempool::Mempool::kMaxTxCount || snapshot.mempool_bytes >= mempool::Mempool::kMaxPoolBytes;
  if (mempool_stats.min_fee_rate_to_enter_when_full.has_value()) {
    snapshot.min_fee_rate_to_enter_when_full_milliunits_per_byte =
        static_cast<std::uint64_t>((*mempool_stats.min_fee_rate_to_enter_when_full * 1000.0) + 0.5);
  }
  snapshot.rejected_full_not_good_enough = static_cast<std::uint64_t>(mempool_stats.rejected_full_not_good_enough);
  snapshot.evicted_for_better_incoming = static_cast<std::uint64_t>(mempool_stats.evicted_for_better_incoming);
  snapshot.min_relay_fee = effective_min_relay_fee_for_height(finalized_height_ + 1);
  snapshot.availability_epoch = availability_state_.current_epoch;
  snapshot.availability_retained_prefix_count =
      static_cast<std::uint64_t>(availability_state_.retained_prefixes.size());
  snapshot.availability_tracked_operator_count = static_cast<std::uint64_t>(availability_state_.operators.size());
  snapshot.availability_state_rebuild_triggered = availability_state_rebuild_triggered_;
  snapshot.availability_state_rebuild_reason = availability_state_rebuild_reason_;
  if (auto checkpoint = finalized_committee_checkpoint_for_height_locked(finalized_height_ + 1); checkpoint.has_value()) {
    const auto adaptive_availability_cfg =
        consensus::availability_config_with_min_bond(cfg_.availability, checkpoint->adaptive_min_bond);
    snapshot.adaptive_target_committee_size = checkpoint->adaptive_target_committee_size;
    snapshot.adaptive_min_eligible = checkpoint->adaptive_min_eligible;
    snapshot.adaptive_min_bond = checkpoint->adaptive_min_bond;
    snapshot.qualified_depth = checkpoint->qualified_depth;
    snapshot.adaptive_slack = static_cast<std::int64_t>(checkpoint->qualified_depth) -
                              static_cast<std::int64_t>(checkpoint->adaptive_min_eligible);
    snapshot.target_expand_streak = checkpoint->target_expand_streak;
    snapshot.target_contract_streak = checkpoint->target_contract_streak;
    snapshot.availability_eligible_operator_count = consensus::count_eligible_operators_at_checkpoint(
        validators_, finalized_height_ + 1, availability_state_, adaptive_availability_cfg);
    snapshot.availability_below_min_eligible =
        snapshot.availability_eligible_operator_count < checkpoint->adaptive_min_eligible;
    snapshot.availability_checkpoint_derivation_mode = static_cast<std::uint8_t>(checkpoint->derivation_mode);
    snapshot.availability_checkpoint_fallback_reason = static_cast<std::uint8_t>(checkpoint->fallback_reason);
    snapshot.availability_fallback_sticky =
        checkpoint->fallback_reason == storage::FinalizedCommitteeFallbackReason::HYSTERESIS_RECOVERY_PENDING;
  } else {
    snapshot.availability_eligible_operator_count =
        consensus::count_eligible_operators_at_checkpoint(validators_, finalized_height_ + 1, availability_state_,
                                                          cfg_.availability);
    snapshot.availability_below_min_eligible = false;
  }
  const auto adaptive_summary =
      storage::summarize_adaptive_epoch_telemetry(db_.load_adaptive_epoch_telemetry(), kAdaptiveTelemetryWindowEpochs);
  snapshot.adaptive_fallback_rate_bps = adaptive_summary.fallback_rate_bps;
  snapshot.adaptive_sticky_fallback_rate_bps = adaptive_summary.sticky_fallback_rate_bps;
  snapshot.adaptive_fallback_window_epochs = adaptive_summary.sample_count;
  snapshot.adaptive_near_threshold_operation = adaptive_summary.near_threshold_operation;
  snapshot.adaptive_prolonged_expand_buildup = adaptive_summary.prolonged_expand_buildup;
  snapshot.adaptive_prolonged_contract_buildup = adaptive_summary.prolonged_contract_buildup;
  snapshot.adaptive_repeated_sticky_fallback = adaptive_summary.repeated_sticky_fallback;
  snapshot.adaptive_depth_collapse_after_bond_increase = adaptive_summary.depth_collapse_after_bond_increase;
  if (auto local_operator = local_operator_pubkey_locked(); local_operator.has_value()) {
    for (const auto& operator_state : availability_state_.operators) {
      if (operator_state.operator_pubkey != *local_operator) continue;
      snapshot.availability_local_operator_known = true;
      snapshot.availability_local_operator_pubkey = operator_state.operator_pubkey;
      snapshot.availability_local_operator_status = static_cast<std::uint8_t>(operator_state.status);
      snapshot.availability_local_service_score = operator_state.service_score;
      snapshot.availability_local_warmup_epochs = operator_state.warmup_epochs;
      snapshot.availability_local_successful_audits = operator_state.successful_audits;
      snapshot.availability_local_late_audits = operator_state.late_audits;
      snapshot.availability_local_missed_audits = operator_state.missed_audits;
      snapshot.availability_local_invalid_audits = operator_state.invalid_audits;
      snapshot.availability_local_retained_prefix_count = operator_state.retained_prefix_count;
      snapshot.availability_local_eligibility_score =
          availability::operator_eligibility_score(operator_state, cfg_.availability);
      snapshot.availability_local_seat_budget = availability::operator_seat_budget(operator_state, cfg_.availability);
      break;
    }
  }

  const bool isolated_mode = cfg_.disable_p2p;
  std::vector<std::uint64_t> healthy_peer_heights;
  bool bootstrap_sync_incomplete = false;
  for (const auto& [peer_id, tip] : peer_finalized_tips_) {
    if (!p2p_.get_peer_info(peer_id).established()) continue;
    healthy_peer_heights.push_back(tip.height);
    if (bootstrap_sync_incomplete_locked(peer_id)) bootstrap_sync_incomplete = true;
  }
  snapshot.bootstrap_sync_incomplete = bootstrap_sync_incomplete;
  snapshot.healthy_peer_count = healthy_peer_heights.size();
  if (isolated_mode) {
    snapshot.observed_network_height_known = true;
    snapshot.observed_network_finalized_height = finalized_height_;
  } else if (!healthy_peer_heights.empty()) {
    std::sort(healthy_peer_heights.begin(), healthy_peer_heights.end());
    const auto min_height = healthy_peer_heights.front();
    const auto max_height = healthy_peer_heights.back();
    snapshot.peer_height_disagreement =
        healthy_peer_heights.size() > 1 && max_height > min_height && (max_height - min_height) > 2;
    snapshot.observed_network_height_known = true;
    snapshot.observed_network_finalized_height = healthy_peer_heights[healthy_peer_heights.size() / 2];
  }
  if (snapshot.observed_network_height_known && snapshot.observed_network_finalized_height > finalized_height_) {
    snapshot.finalized_lag = snapshot.observed_network_finalized_height - finalized_height_;
  }

  std::vector<std::string> blockers;
  if (!snapshot.chain_id_ok) blockers.push_back("chain_id_mismatch");
  if (!isolated_mode && snapshot.healthy_peer_count == 0) blockers.push_back("no_healthy_peers");
  if (!isolated_mode && !snapshot.observed_network_height_known) blockers.push_back("observed_height_unknown");
  if (snapshot.peer_height_disagreement) blockers.push_back("peer_height_disagreement");
  if (snapshot.finalized_lag > 2) blockers.push_back("lag_exceeds_threshold");
  if (!snapshot.next_height_committee_available) blockers.push_back("next_height_committee_unavailable");
  if (!snapshot.next_height_proposer_available) blockers.push_back("next_height_proposer_unavailable");
  if (snapshot.bootstrap_sync_incomplete) blockers.push_back("bootstrap_sync_incomplete");

  snapshot.registration_ready_preflight = blockers.empty();
  if (snapshot.registration_ready_preflight) {
    ++registration_ready_streak_;
  } else {
    registration_ready_streak_ = 0;
  }
  snapshot.readiness_stable_samples = registration_ready_streak_;
  snapshot.registration_ready = snapshot.registration_ready_preflight && registration_ready_streak_ >= 2;
  for (std::size_t i = 0; i < blockers.size(); ++i) {
    if (i) snapshot.readiness_blockers_csv += ",";
    snapshot.readiness_blockers_csv += blockers[i];
  }
  return snapshot;
}

std::string Node::consensus_state_locked(std::uint64_t now_ms, std::size_t* observed_signers,
                                         std::size_t* quorum_threshold) const {
  if (repair_mode_) {
    if (observed_signers) *observed_signers = 0;
    if (quorum_threshold) *quorum_threshold = 0;
    return "REPAIRING";
  }
  const std::uint64_t h = finalized_height_ + 1;
  const auto committee = committee_for_height_round(h, current_round_);
  const std::size_t quorum = consensus::quorum_threshold(committee.size());
  if (quorum_threshold) *quorum_threshold = quorum;

  std::size_t observed = 0;
  if (!committee.empty()) {
    const auto participants = votes_.participants_for(h, current_round_);
    for (const auto& pub : committee) {
      if (participants.find(pub) != participants.end()) ++observed;
    }
    if (is_committee_member_for(local_key_.public_key, h, current_round_)) observed = std::max<std::size_t>(observed, 1);
  }
  if (observed_signers) *observed_signers = observed;

  const std::size_t peers = peer_count();
  const bool single_node_bootstrap = single_node_bootstrap_active_locked(h);
  if (!single_node_bootstrap && (peers == 0 || (finalized_height_ == 0 && observed == 0))) return "SYNCING";
  if (single_node_bootstrap && observed < quorum) return "WAITING_FOR_QUORUM";

  const std::uint64_t stale_ms = cfg_.network.round_timeout_ms * 2ULL;
  if (now_ms > last_finalized_progress_ms_ + stale_ms) {
    if (observed < quorum) return "WAITING_FOR_QUORUM";
    return single_node_bootstrap ? "FINALIZING" : "SYNCING";
  }
  return "FINALIZING";
}

bool Node::next_height_requires_repair_locked(std::string* reason) const {
  const std::uint64_t height = finalized_height_ + 1;
  if (bootstrap_template_mode_ && finalized_height_ == 0 && bootstrap_validator_pubkey_.has_value()) {
    const auto active = validators_.active_sorted(1);
    if (active.size() == 1 && active.front() == *bootstrap_validator_pubkey_) {
      if (reason) reason->clear();
      return false;
    }
  }
  if (bootstrap_template_mode_ && finalized_height_ == 0 && !bootstrap_validator_pubkey_.has_value() &&
      validators_.active_sorted(1).empty()) {
    const bool has_bootstrap_sources = !cfg_.disable_p2p && (!bootstrap_peers_.empty() || !dns_seed_peers_.empty());
    if (!has_bootstrap_sources) {
      if (reason) reason->clear();
      return false;
    }
  }
  const auto checkpoint = finalized_committee_checkpoint_for_height_locked(height);
  if (!checkpoint.has_value() || checkpoint->ordered_members.empty()) {
    if (reason) *reason = "missing-finalized-committee-checkpoint";
    return true;
  }

  const auto committee = epoch_committee_for_next_height_locked(height, 0);
  if (committee.empty()) {
    if (reason) *reason = "empty-committee";
    return true;
  }

  if (!cfg_.disable_p2p && established_peer_count() == 0 && current_round_ > 0 &&
      !single_node_bootstrap_active_locked(height)) {
    if (reason) *reason = "no-established-peers";
    return true;
  }

  const auto schedule = proposer_schedule_from_checkpoint(cfg_.network, validators_, *checkpoint, height);
  if (schedule.empty()) {
    if (reason) *reason = "empty-proposer-schedule";
    return true;
  }
  return false;
}

bool Node::maybe_repair_next_height_locked(std::uint64_t now_ms, std::string* reason) {
  std::string local_reason;
  if (!next_height_requires_repair_locked(&local_reason)) {
    if (repair_mode_) {
      log_line("consensus-repair-exit target_height=" + std::to_string(finalized_height_ + 1) + " status=ok");
    }
    repair_mode_ = false;
    repair_target_height_ = 0;
    repair_reason_.clear();
    repair_started_ms_ = 0;
    last_repair_log_ms_ = 0;
    if (reason) reason->clear();
    return true;
  }

  const std::uint64_t target_height = finalized_height_ + 1;
  const bool entering = !repair_mode_ || repair_target_height_ != target_height;
  repair_mode_ = true;
  repair_target_height_ = target_height;
  repair_reason_ = local_reason;
  if (entering) {
    repair_started_ms_ = now_ms;
    current_round_ = 0;
    round_started_ms_ = now_ms;
    log_line("consensus-repair-enter target_height=" + std::to_string(target_height) +
             " parent_height=" + std::to_string(target_height - 1) + " reason=" + repair_reason_);
  }

  maybe_finalize_epoch_committees_locked();
  const auto required_epoch = epoch_committee_snapshot_epoch_for_height_locked(target_height);
  if (required_epoch.has_value() && !frozen_epoch_committee_snapshot_for_height_locked(target_height).has_value()) {
    rebuild_epoch_committee_state_locked(*required_epoch, "runtime-repair", true);
    if (!frozen_epoch_committee_snapshot_for_height_locked(target_height).has_value()) {
      const auto tickets = db_.load_epoch_tickets(*required_epoch);
      if (tickets.empty()) (void)recover_single_validator_epoch_committee_locked(*required_epoch, "runtime-repair");
    }
  }
  if (!cfg_.disable_p2p) {
    maybe_request_epoch_ticket_reconciliation_locked(now_ms);
    (void)maybe_request_forward_sync_block_locked();
  }

  if (!next_height_requires_repair_locked(&local_reason)) {
    repair_mode_ = false;
    repair_target_height_ = 0;
    repair_reason_.clear();
    repair_started_ms_ = 0;
    last_repair_log_ms_ = 0;
    current_round_ = 0;
    round_started_ms_ = now_ms;
    log_line("consensus-repair-exit target_height=" + std::to_string(target_height) + " status=ok");
    if (reason) reason->clear();
    return true;
  }

  repair_reason_ = local_reason;
  if (reason) *reason = repair_reason_;
  if (now_ms >= last_repair_log_ms_ + 5000) {
    last_repair_log_ms_ = now_ms;
    log_line("consensus-repair-wait target_height=" + std::to_string(target_height) +
             " parent_height=" + std::to_string(target_height - 1) + " reason=" + repair_reason_);
  }
  return false;
}

bool Node::inject_vote_for_test(const Vote& vote) { return handle_vote(vote, false, 0); }

bool Node::inject_timeout_vote_for_test(const TimeoutVote& vote) { return handle_timeout_vote(vote, false, 0); }

std::string Node::inject_network_vote_result_for_test(const Vote& vote) {
  switch (handle_vote_result(vote, true, 1)) {
    case VoteHandlingResult::Accepted:
      return "accepted";
    case VoteHandlingResult::SoftReject:
      return "soft-reject";
    case VoteHandlingResult::HardReject:
      return "hard-reject";
  }
  return "unknown";
}

std::string Node::inject_network_vote_diagnostic_for_test(const Vote& vote) {
  std::string reject_reason;
  switch (handle_vote_result(vote, true, 1, &reject_reason)) {
    case VoteHandlingResult::Accepted:
      return "accepted";
    case VoteHandlingResult::SoftReject:
      return "soft-reject" + (reject_reason.empty() ? std::string() : ":" + reject_reason);
    case VoteHandlingResult::HardReject:
      return "hard-reject" + (reject_reason.empty() ? std::string() : ":" + reject_reason);
  }
  return "unknown";
}

std::string Node::inject_network_propose_result_for_test(const p2p::ProposeMsg& msg) {
  switch (handle_propose_result(msg, true, nullptr)) {
    case ProposeHandlingResult::Accepted:
      return "accepted";
    case ProposeHandlingResult::SoftReject:
      return "soft-reject";
    case ProposeHandlingResult::HardReject:
      return "hard-reject";
  }
  return "unknown";
}

std::string Node::inject_network_propose_diagnostic_for_test(const p2p::ProposeMsg& msg) {
  std::string reject_reason;
  switch (handle_propose_result(msg, true, &reject_reason)) {
    case ProposeHandlingResult::Accepted:
      return "accepted";
    case ProposeHandlingResult::SoftReject:
      return "soft-reject" + (reject_reason.empty() ? std::string() : ":" + reject_reason);
    case ProposeHandlingResult::HardReject:
      return "hard-reject" + (reject_reason.empty() ? std::string() : ":" + reject_reason);
  }
  return "unknown";
}

bool Node::inject_frontier_transition_for_test(const FrontierProposal& proposal, const FinalityCertificate& certificate) {
  std::lock_guard<std::mutex> lk(mu_);
  return handle_frontier_block_locked(proposal, certificate, 0, false);
}

bool Node::inject_propose_msg_for_test(const p2p::ProposeMsg& msg) { return handle_propose(msg, false); }
bool Node::observe_frontier_proposal_for_test(const FrontierProposal& proposal) {
  std::lock_guard<std::mutex> lk(mu_);
  return check_and_record_proposer_equivocation_locked(proposal.transition);
}
bool Node::inject_frontier_block_for_test(const FrontierProposal& proposal, const std::vector<FinalitySig>& finality_signatures) {
  std::lock_guard<std::mutex> lk(mu_);
  last_test_hook_error_.clear();
  if (!running_) {
    last_test_hook_error_ = "node-not-running";
    return false;
  }
  if (!finalized_identity_valid_for_frontier_runtime(finalized_height_, finalized_identity_)) {
    last_test_hook_error_ = "frontier-parent-identity-kind-mismatch";
    return false;
  }
  const auto committee = committee_for_height_round(proposal.transition.height, proposal.transition.round);
  if (committee.empty()) {
    last_test_hook_error_ = "empty-committee";
    return false;
  }
  const auto quorum = consensus::quorum_threshold(committee.size());
  const auto canonical_sigs = canonicalize_finality_signatures_locked(finality_signatures, quorum);
  if (canonical_sigs.size() < quorum) {
    last_test_hook_error_ = "insufficient-signatures";
    return false;
  }
  const auto cert = make_finality_certificate(proposal.transition.height, proposal.transition.round,
                                              proposal.transition.transition_id(), quorum, committee, canonical_sigs);
  std::string validation_error;
  if (!validate_frontier_proposal_locked(proposal, &validation_error)) {
    last_test_hook_error_ = "validate-frontier-proposal-failed:" + validation_error;
    return false;
  }
  std::string lock_error;
  if (!can_accept_frontier_with_lock_locked(proposal.transition, &lock_error)) {
    last_test_hook_error_ = "frontier-lock-reject:" + lock_error;
    return false;
  }
  std::vector<FinalitySig> verified_sigs;
  std::string cert_error;
  if (!verify_finality_certificate_for_frontier_locked(cert, proposal.transition, &verified_sigs, &cert_error)) {
    last_test_hook_error_ = "frontier-certificate-reject:" + cert_error;
    return false;
  }
  consensus::CanonicalFrontierRecord certified_record;
  std::string frontier_record_error;
  if (!consensus::load_certified_frontier_record_from_storage(db_, proposal.transition, &certified_record,
                                                              &frontier_record_error)) {
    last_test_hook_error_ = "load-certified-frontier-record-failed:" + frontier_record_error;
    return false;
  }
  certified_record.ordered_records = proposal.ordered_records;
  std::string apply_error;
  consensus::CanonicalDerivedState next_state;
  if (!canonical_state_.has_value()) {
    last_test_hook_error_ = "missing-canonical-state";
    return false;
  }
  if (!consensus::apply_frontier_record(canonical_derivation_config_locked(), *canonical_state_, certified_record,
                                        &next_state, &apply_error)) {
    last_test_hook_error_ = "apply-finalized-frontier-failed:" + apply_error;
    return false;
  }
  if (handle_frontier_block_locked(proposal, cert, 0, false)) return true;
  last_test_hook_error_ = "handle-frontier-block-rejected";
  return false;
}
Hash32 Node::committee_epoch_randomness_for_height_locked(std::uint64_t height) const {
  const auto epoch_start = consensus::committee_epoch_start(height, cfg_.network.committee_epoch_blocks);
  auto it = committee_epoch_randomness_cache_.find(epoch_start);
  if (it != committee_epoch_randomness_cache_.end()) return it->second;
  return consensus::initial_finalized_randomness(cfg_.network, chain_id_);
}

std::optional<storage::FinalizedCommitteeCheckpoint> Node::finalized_committee_checkpoint_for_height_locked(
    std::uint64_t height) const {
  if (height == 0) return std::nullopt;
  const auto epoch_start = consensus::committee_epoch_start(height, cfg_.network.committee_epoch_blocks);
  auto it = finalized_committee_checkpoints_.find(epoch_start);
  if (it != finalized_committee_checkpoints_.end()) {
    if (canonical_state_.has_value() && epoch_start == finalized_height_ + 1) {
      std::string error;
      if (!consensus::validate_next_epoch_checkpoint_from_state(canonical_derivation_config_locked(), *canonical_state_,
                                                                epoch_start, it->second, &error)) {
        log_line("finalized-state-invariant-violation source=checkpoint-next-height-recompute-mismatch epoch=" +
                 std::to_string(epoch_start) + " detail=" + error);
        return std::nullopt;
      }
      if (!consensus::validate_checkpoint_schedule_for_height(canonical_derivation_config_locked(), *canonical_state_,
                                                              it->second, height, &error)) {
        log_line("finalized-state-invariant-violation source=checkpoint-schedule-mismatch epoch=" +
                 std::to_string(epoch_start) + " detail=" + error);
        return std::nullopt;
      }
    }
    return it->second;
  }
  return std::nullopt;
}

storage::FinalizedCommitteeCheckpoint Node::build_finalized_committee_checkpoint_locked(
    std::uint64_t epoch_start_height, std::size_t active_validator_count,
    const std::vector<consensus::FinalizedCommitteeCandidate>& active,
    const Hash32& epoch_randomness) const {
  const auto previous_checkpoint =
      previous_checkpoint_for_epoch(finalized_committee_checkpoints_, epoch_start_height, cfg_.network.committee_epoch_blocks);
  const auto decision = decide_availability_committee_mode(&availability_state_, cfg_.availability, previous_checkpoint,
                                                           validators_, epoch_start_height);
  return build_finalized_committee_checkpoint_from_candidates(
      epoch_start_height, consensus::committee_epoch_seed(epoch_randomness, epoch_start_height),
      ticket_difficulty_bits_for_epoch_locked(epoch_start_height, active_validator_count), active, cfg_.max_committee,
      decision.mode, decision.fallback_reason, decision.eligible_operator_count, decision.min_eligible_operators,
      decision.effective_committee_size, decision.adaptive);
}

void Node::persist_finalized_committee_checkpoint_locked(std::uint64_t epoch_start_height,
                                                         std::size_t active_validator_count,
                                                         const std::vector<consensus::FinalizedCommitteeCandidate>& active,
                                                         const Hash32& epoch_randomness) {
  auto checkpoint =
      build_finalized_committee_checkpoint_locked(epoch_start_height, active_validator_count, active, epoch_randomness);
  if (canonical_state_.has_value() && epoch_start_height == finalized_height_ + 1) {
    std::string error;
    if (!consensus::validate_next_epoch_checkpoint_from_state(canonical_derivation_config_locked(), *canonical_state_,
                                                              epoch_start_height, checkpoint, &error)) {
      log_line("finalized-state-invariant-violation source=checkpoint-persist-recompute-mismatch epoch=" +
               std::to_string(epoch_start_height) + " detail=" + error);
      return;
    }
  }
  finalized_committee_checkpoints_[epoch_start_height] = checkpoint;
  if (debug_checkpoint_logs_enabled()) {
    std::ostringstream oss;
    oss << "checkpoint-build finalized_height=" << finalized_height_ << " target_height=" << epoch_start_height
        << " epoch=" << checkpoint.epoch_start_height << " active=" << active_validator_count
        << " mode=" << checkpoint_derivation_mode_name(checkpoint.derivation_mode)
        << " fallback_reason=" << checkpoint_fallback_reason_name(checkpoint.fallback_reason)
        << " fallback_sticky="
        << (checkpoint.fallback_reason == storage::FinalizedCommitteeFallbackReason::HYSTERESIS_RECOVERY_PENDING ? "true"
                                                                                                                  : "false")
        << " availability_eligible=" << checkpoint.availability_eligible_operator_count
        << " availability_min=" << checkpoint.availability_min_eligible_operators
        << " adaptive_target=" << checkpoint.adaptive_target_committee_size
        << " adaptive_min_bond=" << checkpoint.adaptive_min_bond
        << " qualified_depth=" << checkpoint.qualified_depth
        << " epoch_seed=" << short_hash_hex(checkpoint.epoch_seed) << " committee=";
    for (std::size_t i = 0; i < checkpoint.ordered_members.size(); ++i) {
      if (i) oss << ",";
      oss << short_pub_hex(checkpoint.ordered_members[i]);
      if (i < checkpoint.ordered_operator_ids.size()) oss << ":" << short_pub_hex(checkpoint.ordered_operator_ids[i]);
      if (i < checkpoint.ordered_ticket_hashes.size()) oss << ":" << short_hash_hex(checkpoint.ordered_ticket_hashes[i]);
      if (i < checkpoint.ordered_ticket_nonces.size()) oss << ":" << checkpoint.ordered_ticket_nonces[i];
    }
    const auto leader = leader_from_checkpoint(cfg_.network, validators_, checkpoint, epoch_start_height, 0);
    if (leader.has_value()) oss << " leader0=" << short_pub_hex(*leader);
    log_line(oss.str());
  }
  (void)db_.put_finalized_committee_checkpoint(checkpoint);
  storage::AdaptiveEpochTelemetry telemetry;
  telemetry.epoch_start_height = checkpoint.epoch_start_height;
  telemetry.derivation_height = checkpoint.epoch_start_height > 0 ? (checkpoint.epoch_start_height - 1) : 0;
  telemetry.qualified_depth = checkpoint.qualified_depth;
  telemetry.adaptive_target_committee_size = checkpoint.adaptive_target_committee_size;
  telemetry.adaptive_min_eligible = checkpoint.adaptive_min_eligible;
  telemetry.adaptive_min_bond = checkpoint.adaptive_min_bond;
  telemetry.slack = static_cast<std::int64_t>(checkpoint.qualified_depth) -
                    static_cast<std::int64_t>(checkpoint.adaptive_min_eligible);
  telemetry.target_expand_streak = checkpoint.target_expand_streak;
  telemetry.target_contract_streak = checkpoint.target_contract_streak;
  telemetry.derivation_mode = checkpoint.derivation_mode;
  telemetry.fallback_reason = checkpoint.fallback_reason;
  telemetry.fallback_sticky =
      checkpoint.fallback_reason == storage::FinalizedCommitteeFallbackReason::HYSTERESIS_RECOVERY_PENDING;
  telemetry.committee_size_selected = checkpoint.ordered_members.size();
  telemetry.eligible_operator_count = checkpoint.availability_eligible_operator_count;
  (void)db_.put_adaptive_epoch_telemetry(telemetry);
}

std::uint8_t Node::ticket_difficulty_bits_for_epoch_locked(std::uint64_t epoch_start_height,
                                                           std::size_t active_validator_count) const {
  std::uint8_t previous_bits = consensus::DEFAULT_TICKET_DIFFICULTY_BITS;
  const auto epoch_blocks = std::max<std::uint64_t>(1, cfg_.network.committee_epoch_blocks);
  const auto& econ = active_economics_policy(cfg_.network, epoch_start_height);
  if (epoch_start_height > 1) {
    const auto previous_epoch_start = epoch_start_height > epoch_blocks ? (epoch_start_height - epoch_blocks) : 1;
    if (auto checkpoint = finalized_committee_checkpoint_for_height_locked(previous_epoch_start); checkpoint.has_value()) {
      previous_bits = checkpoint->ticket_difficulty_bits;
    }
  }

  constexpr std::size_t kWindowEpochs = 6;
  std::size_t consecutive_healthy_epochs = 0;
  std::size_t consecutive_unhealthy_epochs = 0;
  std::size_t inspected_epochs = 0;
  for (std::uint64_t epoch = epoch_start_height; epoch > 1 && inspected_epochs < kWindowEpochs;) {
    if (epoch <= epoch_blocks) break;
    epoch -= epoch_blocks;
    ++inspected_epochs;
    std::uint64_t blocks = 0;
    std::uint64_t total_round_x1000 = 0;
    std::uint64_t total_participation_bps = 0;
    for (std::uint64_t h = epoch; h < epoch + epoch_blocks && h <= finalized_height_; ++h) {
      auto cert = db_.get_finality_certificate_by_height(h);
      if (!cert.has_value()) continue;
      ++blocks;
      total_round_x1000 += static_cast<std::uint64_t>(cert->round) * 1000ULL;
      total_participation_bps +=
          consensus::quorum_relative_participation_bps(cert->signatures.size(), cert->quorum_threshold);
    }
    const std::uint32_t average_round_x1000 =
        blocks == 0 ? 0U : static_cast<std::uint32_t>(total_round_x1000 / blocks);
    const std::uint32_t average_participation_bps =
        blocks == 0 ? 10'000U : static_cast<std::uint32_t>(total_participation_bps / blocks);
    const bool healthy = consensus::ticket_difficulty_epoch_is_healthy(active_validator_count, cfg_.max_committee,
                                                                       average_round_x1000, average_participation_bps);
    const bool unhealthy =
        consensus::ticket_difficulty_epoch_is_unhealthy(average_round_x1000, average_participation_bps);
    if (healthy && consecutive_unhealthy_epochs == 0) {
      ++consecutive_healthy_epochs;
    } else if (unhealthy && consecutive_healthy_epochs == 0) {
      ++consecutive_unhealthy_epochs;
    } else {
      break;
    }
  }
  return consensus::adjust_bounded_ticket_difficulty_bits(previous_bits, active_validator_count, cfg_.max_committee,
                                                          consecutive_healthy_epochs, consecutive_unhealthy_epochs);
}

std::vector<consensus::FinalizedCommitteeCandidate> Node::finalized_committee_candidates_for_height_locked(
    std::uint64_t height, std::uint8_t ticket_difficulty_bits) const {
  const auto epoch_start = consensus::committee_epoch_start(height, cfg_.network.committee_epoch_blocks);
  const auto epoch_seed = consensus::committee_epoch_seed(committee_epoch_randomness_for_height_locked(height), epoch_start);
  const auto previous_checkpoint =
      previous_checkpoint_for_epoch(finalized_committee_checkpoints_, epoch_start, cfg_.network.committee_epoch_blocks);
  const auto decision =
      decide_availability_committee_mode(&availability_state_, cfg_.availability, previous_checkpoint, validators_, height);
  const auto previous_mode =
      previous_checkpoint.has_value() ? std::optional<storage::FinalizedCommitteeDerivationMode>(previous_checkpoint->derivation_mode)
                                      : std::nullopt;
  auto candidates = finalized_committee_candidates_from_best_tickets(
      cfg_.network, validators_, height, epoch_seed, ticket_difficulty_bits, nullptr, &availability_state_, cfg_.availability,
      decision.adaptive, previous_mode);
  if (debug_economics_logs_enabled()) {
    const auto active_operator_count = active_operator_count_for_height_locked(height);
    for (const auto& candidate : candidates) {
      std::ostringstream oss;
      oss << "economics-committee-candidate height=" << height
          << " operator=" << short_pub_hex(candidate.selection_id == PubKey32{} ? candidate.pubkey : candidate.selection_id)
          << " pubkey=" << short_pub_hex(candidate.pubkey)
          << " active_operators=" << active_operator_count
          << " actual_bond=" << candidate.bonded_amount
          << " capped_bond=" << candidate.capped_bonded_amount
          << " effective_weight=" << candidate.effective_weight
          << " ticket_bonus_bps=" << candidate.ticket_bonus_bps
          << " ticket_bonus_cap_bps=" << candidate.ticket_bonus_cap_bps
          << " strength=" << consensus::finalized_committee_candidate_strength(candidate);
      log_line(oss.str());
    }
  }
  return candidates;
}

std::optional<std::uint64_t> Node::settlement_epoch_for_block_height_locked(std::uint64_t height) const {
  const auto epoch_blocks = std::max<std::uint64_t>(1, cfg_.network.committee_epoch_blocks);
  const auto epoch_start = consensus::committee_epoch_start(height, epoch_blocks);
  if (height != epoch_start || epoch_start <= 1 || epoch_start <= epoch_blocks) return std::nullopt;
  return epoch_start - epoch_blocks;
}

storage::EpochRewardSettlementState Node::epoch_reward_state_for_epoch_locked(std::uint64_t epoch_start_height) const {
  auto it = epoch_reward_states_.find(epoch_start_height);
  if (it != epoch_reward_states_.end()) return it->second;
  storage::EpochRewardSettlementState empty;
  empty.epoch_start_height = epoch_start_height;
  return empty;
}

consensus::DeterministicCoinbasePayout Node::coinbase_payout_for_height_locked(std::uint64_t height,
                                                                               const PubKey32& leader_pubkey,
                                                                               std::uint64_t fees_units) const {
  std::map<PubKey32, std::uint64_t> settlement_scores;
  std::map<PubKey32, std::uint64_t> onboarding_scores;
  std::uint64_t settlement_rewards = 0;
  std::uint64_t distributed_fee_units = height >= consensus::EMISSION_BLOCKS ? 0 : fees_units;
  std::uint64_t reserve_subsidy_units = 0;
  if (auto settlement_epoch = settlement_epoch_for_block_height_locked(height); settlement_epoch.has_value()) {
    const auto state = epoch_reward_state_for_epoch_locked(*settlement_epoch);
    if (!state.settled) {
      settlement_rewards = state.total_reward_units;
      distributed_fee_units = height >= consensus::EMISSION_BLOCKS ? state.fee_pool_units : fees_units;
      reserve_subsidy_units = height >= consensus::EMISSION_BLOCKS ? state.reserve_subsidy_units : 0;
      settlement_scores = state.reward_score_units;
      onboarding_scores = state.onboarding_score_units;
      const auto& econ = active_economics_policy(cfg_.network, height);
      const auto threshold_bps = econ.participation_threshold_bps;
      for (auto& [pub, score] : settlement_scores) {
        const auto expected_it = state.expected_participation_units.find(pub);
        const auto observed_it = state.observed_participation_units.find(pub);
        const std::uint64_t expected = expected_it == state.expected_participation_units.end() ? 0 : expected_it->second;
        const std::uint64_t observed = observed_it == state.observed_participation_units.end() ? 0 : observed_it->second;
        const std::uint32_t participation_bps =
            expected == 0 ? 10'000U
                          : static_cast<std::uint32_t>(wide::mul_div_u64(std::min(observed, expected), 10'000ULL, expected));
        const auto raw_score = score;
        score = consensus::apply_participation_penalty_bps(score, participation_bps, threshold_bps);
        if (debug_economics_logs_enabled()) {
          std::ostringstream oss;
          oss << "economics-settlement-participation epoch_start=" << *settlement_epoch
              << " height=" << height
              << " validator=" << short_pub_hex(pub)
              << " expected=" << expected
              << " observed=" << observed
              << " participation_bps=" << participation_bps
              << " raw_reward_weight=" << raw_score
              << " adjusted_reward_weight=" << score
              << " threshold_bps=" << threshold_bps;
          log_line(oss.str());
        }
      }
    }
  }
  return consensus::compute_epoch_settlement_payout(settlement_rewards, distributed_fee_units, reserve_subsidy_units,
                                                    leader_pubkey, settlement_scores, onboarding_scores);
}

std::map<PubKey32, std::uint64_t> Node::compute_onboarding_score_units_for_epoch_locked(std::uint64_t epoch_start_height) const {
  std::map<PubKey32, std::uint64_t> out;
  const auto tickets = db_.load_epoch_tickets(epoch_start_height);
  const auto best_tickets = consensus::best_epoch_tickets_by_pubkey(tickets);
  for (const auto& [pub, info] : validators_.all()) {
    if (info.status != consensus::ValidatorStatus::ONBOARDING) continue;
    auto it = best_tickets.find(pub);
    if (it == best_tickets.end()) continue;
    const auto score = static_cast<std::uint64_t>(
        std::max<std::uint8_t>(1, consensus::leading_zero_bits(it->second.work_hash)));
    out[pub] = score;
  }
  return out;
}

std::vector<TxOut> Node::coinbase_outputs_for_height_locked(std::uint64_t height, const PubKey32& leader_pubkey,
                                                            std::uint64_t fees_units) const {
  const auto payout = coinbase_payout_for_height_locked(height, leader_pubkey, fees_units);
  std::vector<TxOut> outputs;
  outputs.reserve(payout.outputs.size());
  for (const auto& [pub, units] : payout.outputs) {
    const auto pkh = crypto::h160(Bytes(pub.begin(), pub.end()));
    outputs.push_back(TxOut{units, address::p2pkh_script_pubkey(pkh)});
  }
  return outputs;
}

void Node::accrue_epoch_reward_for_finalized_block_locked(const Block& block, const std::vector<FinalitySig>& finality_sigs,
                                                          std::uint64_t finalized_fee_units) {
  const auto committee = committee_for_height_round(block.header.height, block.header.round);
  const auto inputs =
      compute_deterministic_epoch_reward_inputs(cfg_.network, validators_, block.header.height, block.header.leader_pubkey,
                                                committee, finality_sigs);
  if (debug_economics_logs_enabled()) {
    const auto inputs_check = compute_deterministic_epoch_reward_inputs(cfg_.network, validators_, block.header.height,
                                                                        block.header.leader_pubkey, committee, finality_sigs);
    if (!deterministic_epoch_reward_inputs_equal(inputs, inputs_check)) {
      log_line("economics-determinism-mismatch height=" + std::to_string(block.header.height) + " reason=recompute-mismatch");
    }
  }

  // The dormant classical block path must pool validated block fees after the
  // cap instead of trying to infer them from coinbase totals, because post-cap
  // coinbase may contain prior-epoch settlement fees and reserve subsidy.
  accrue_epoch_reward_state_for_block(cfg_.network, validators_, cfg_.network.committee_epoch_blocks, epoch_reward_states_, block,
                                      committee, finality_sigs, finalized_fee_units, &db_);

  if (debug_economics_logs_enabled()) {
    const auto epoch_start = consensus::committee_epoch_start(block.header.height, cfg_.network.committee_epoch_blocks);
    const auto& state = epoch_reward_states_[epoch_start];
    std::set<PubKey32> logged;
    for (const auto& pub : committee) {
      if (!logged.insert(pub).second) continue;
      auto it = validators_.all().find(pub);
      if (it == validators_.all().end()) continue;
      const auto expected_it = state.expected_participation_units.find(pub);
      const auto observed_it = state.observed_participation_units.find(pub);
      std::ostringstream oss;
      oss << "economics-participation-accrual height=" << block.header.height
          << " validator=" << short_pub_hex(pub)
          << " actual_bond=" << it->second.bonded_amount
          << " capped_bond=" << consensus::capped_effective_bond_units(cfg_.network, block.header.height,
                                                                        active_operator_count_for_height_locked(block.header.height),
                                                                        it->second.bonded_amount)
          << " reward_weight="
          << consensus::reward_weight(cfg_.network, block.header.height,
                                      active_operator_count_for_height_locked(block.header.height), it->second.bonded_amount)
          << " expected=" << (expected_it == state.expected_participation_units.end() ? 0 : expected_it->second)
          << " observed=" << (observed_it == state.observed_participation_units.end() ? 0 : observed_it->second)
          << " source=committee-finalized";
      log_line(oss.str());
    }
    if (auto leader_it = validators_.all().find(block.header.leader_pubkey); leader_it != validators_.all().end()) {
      std::ostringstream oss;
      oss << "economics-leader-reward height=" << block.header.height
          << " validator=" << short_pub_hex(block.header.leader_pubkey)
          << " actual_bond=" << leader_it->second.bonded_amount
          << " capped_bond=" << consensus::capped_effective_bond_units(cfg_.network, block.header.height,
                                                                        active_operator_count_for_height_locked(block.header.height),
                                                                        leader_it->second.bonded_amount)
          << " reward_weight="
          << consensus::reward_weight(cfg_.network, block.header.height,
                                      active_operator_count_for_height_locked(block.header.height),
                                      leader_it->second.bonded_amount);
      log_line(oss.str());
    }
  }
}

void Node::mark_epoch_reward_settled_if_needed_locked(std::uint64_t height) {
  const auto epoch_start = consensus::committee_epoch_start(height, cfg_.network.committee_epoch_blocks);
  if (height == epoch_start && epoch_start > cfg_.network.committee_epoch_blocks && epoch_start > 1) {
    const auto settlement_epoch = epoch_start - cfg_.network.committee_epoch_blocks;
    auto& state = epoch_reward_states_[settlement_epoch];
    state.epoch_start_height = settlement_epoch;
    if (!state.settled) {
      state.onboarding_score_units = compute_onboarding_score_units_for_epoch_locked(settlement_epoch);
    }
  }
  mark_epoch_reward_settled_for_height(cfg_.network, height, cfg_.network.committee_epoch_blocks, epoch_reward_states_,
                                       &protocol_reserve_balance_units_, &db_);
}

std::vector<FinalitySig> Node::canonicalize_finality_signatures_locked(const std::vector<FinalitySig>& signatures,
                                                                       std::size_t quorum) const {
  std::vector<FinalitySig> out = signatures;
  std::sort(out.begin(), out.end(), [](const FinalitySig& a, const FinalitySig& b) {
    if (a.validator_pubkey != b.validator_pubkey) return a.validator_pubkey < b.validator_pubkey;
    return a.signature < b.signature;
  });
  out.erase(std::unique(out.begin(), out.end(), [](const FinalitySig& a, const FinalitySig& b) {
              return a.validator_pubkey == b.validator_pubkey;
            }),
            out.end());
  if (out.size() > quorum) out.resize(quorum);
  return out;
}

bool Node::inject_tx_for_test(const AnyTx& tx, bool relay) {
  if (relay) return handle_tx(tx, false);
  std::lock_guard<std::mutex> lk(mu_);
  const auto min_bond_amount = effective_validator_min_bond_for_height(finalized_height_ + 1);
  mempool_.set_validation_context(
      SpecialValidationContext{
          .network = &cfg_.network,
          .chain_id = &chain_id_,
          .validators = &validators_,
          .current_height = finalized_height_ + 1,
          .enforce_variable_bond_range = true,
          .min_bond_amount = min_bond_amount,
          .max_bond_amount = effective_validator_bond_max_for_height(finalized_height_ + 1),
          .unbond_delay_blocks = cfg_.network.unbond_delay_blocks,
          .is_committee_member = [this](const PubKey32& pub, std::uint64_t h, std::uint32_t round) {
            return is_committee_member_for(pub, h, round);
          },
          .finalized_hash_at_height = [this](std::uint64_t anchor_height) -> std::optional<Hash32> {
            if (anchor_height == 0) return zero_hash();
            return db_.get_height_hash(anchor_height);
          },
          .confidential_policy = &confidential_policy_});
  std::string err;
  return mempool_.accept_tx(tx, utxos_, &err);
}
bool Node::pause_proposals_for_test(bool pause) {
  pause_proposals_.store(pause);
  std::lock_guard<std::mutex> lk(mu_);
  const auto now = now_ms();
  round_started_ms_ = now;
  last_finalized_progress_ms_ = now;
  return true;
}

bool Node::advance_round_for_test(std::uint64_t expected_height, std::uint32_t target_round) {
  std::lock_guard<std::mutex> lk(mu_);
  if (!running_) return false;
  if (expected_height != finalized_height_ + 1) return false;
  current_round_ = target_round;
  round_started_ms_ = now_ms();
  return true;
}

bool Node::apply_finalized_frontier_effects_locked(const consensus::CanonicalFrontierRecord& record,
                                                   std::vector<FinalitySig> finality_signatures,
                                                   bool clear_requested_sync,
                                                   const std::vector<PubKey32>* effective_committee) {
  const auto committee =
      effective_committee != nullptr ? *effective_committee : committee_for_height_round(record.transition.height, record.transition.round);
  if (committee.empty()) return false;
  const std::size_t quorum = consensus::quorum_threshold(committee.size());
  const auto canonical_sigs = canonicalize_finality_signatures_locked(finality_signatures, quorum);
  if (canonical_sigs.size() < quorum) return false;

  const auto transition_id = record.transition.transition_id();
  const FinalityCertificate certificate = make_finality_certificate(record.transition.height, record.transition.round,
                                                                    transition_id, quorum, committee, canonical_sigs);

  if (!canonical_state_.has_value()) return false;
  consensus::CanonicalDerivedState next_state;
  std::string derivation_error;
  if (!consensus::apply_frontier_record(canonical_derivation_config_locked(), *canonical_state_, record, &next_state,
                                        &derivation_error)) {
    log_line("finalized-state-invariant-violation source=live-frontier-apply height=" +
             std::to_string(record.transition.height) + " detail=" + derivation_error);
    return false;
  }

  if (!persist_finalized_frontier_record(record, utxos_)) return false;
  if (!db_.put_finality_certificate(certificate)) return false;

  highest_qc_by_height_[record.transition.height] =
      make_quorum_certificate(record.transition.height, record.transition.round, transition_id, canonical_sigs);
  highest_qc_payload_by_height_[record.transition.height] = consensus_payload_id(record.transition);
  persist_consensus_safety_state_locked(record.transition.height);

  std::vector<Hash32> confirmed_txids;
  for (const auto& raw : record.ordered_records) {
    auto tx = parse_any_tx(raw);
    if (tx.has_value()) confirmed_txids.push_back(txid_any(*tx));
  }
  mempool_.remove_confirmed(confirmed_txids);
  hydrate_runtime_from_canonical_state_locked(next_state);
  mempool_.prune_against_utxo(utxos_);
  const auto now = now_ms();
  current_round_ = 0;
  round_started_ms_ = now;
  last_finalized_progress_ms_ = now;

  if (!persist_canonical_cache_rows(db_, next_state)) return false;
  if (!verify_and_persist_consensus_state_commitment_locked(next_state)) return false;
  (void)persist_state_roots(db_, finalized_height_, utxos_, validators_, kFixedValidationRulesVersion);

  if (clear_requested_sync) {
    requested_sync_artifacts_.erase(transition_id);
    requested_sync_heights_.erase(record.transition.height);
  }
  candidate_frontier_proposals_.clear();
  candidate_block_sizes_.clear();
  votes_.clear_height(record.transition.height);
  timeout_votes_.clear_height(record.transition.height);
  if (finalized_height_ > 0) {
    clear_consensus_safety_state_locked(finalized_height_);
    local_vote_locks_.erase(finalized_height_);
    highest_qc_by_height_.erase(finalized_height_);
    highest_qc_payload_by_height_.erase(finalized_height_);
    highest_tc_by_height_.erase(finalized_height_);
  }
  (void)db_.erase(finalized_write_marker_key());
  maybe_finalize_epoch_committees_locked();
  (void)persist_availability_state_locked();
  (void)db_.put_node_runtime_status_snapshot(build_runtime_status_snapshot_locked(now_unix() * 1000));
  return true;
}
bool Node::mempool_contains_for_test(const Hash32& txid) const {
  std::lock_guard<std::mutex> lk(mu_);
  return mempool_.contains(txid);
}
std::optional<TxOut> Node::find_utxo_by_pubkey_hash_for_test(const std::array<std::uint8_t, 20>& pkh,
                                                              OutPoint* outpoint) const {
  std::lock_guard<std::mutex> lk(mu_);
  for (const auto& [op, e] : utxos_) {
    const auto txout = transparent_txout_from_utxo_entry(e);
    if (!txout.has_value()) continue;
    std::array<std::uint8_t, 20> got{};
    if (!is_p2pkh_script_pubkey(txout->script_pubkey, &got)) continue;
    if (got != pkh) continue;
    if (outpoint) *outpoint = op;
    return *txout;
  }
  return std::nullopt;
}
std::vector<std::pair<OutPoint, TxOut>> Node::find_utxos_by_pubkey_hash_for_test(
    const std::array<std::uint8_t, 20>& pkh) const {
  std::vector<std::pair<OutPoint, TxOut>> out;
  std::lock_guard<std::mutex> lk(mu_);
  for (const auto& [op, e] : utxos_) {
    const auto txout = transparent_txout_from_utxo_entry(e);
    if (!txout.has_value()) continue;
    std::array<std::uint8_t, 20> got{};
    if (!is_p2pkh_script_pubkey(txout->script_pubkey, &got)) continue;
    if (got != pkh) continue;
    out.push_back({op, *txout});
  }
  return out;
}
bool Node::has_utxo_for_test(const OutPoint& op, TxOut* out) const {
  std::lock_guard<std::mutex> lk(mu_);
  auto it = utxos_.find(op);
  if (it == utxos_.end()) return false;
  const auto txout = transparent_txout_from_utxo_entry(it->second);
  if (!txout.has_value()) return false;
  if (out) *out = *txout;
  return true;
}
std::string Node::proposer_path_for_next_height_for_test() const {
  return "finalized-checkpoint-proposer-schedule";
}
std::string Node::committee_path_for_next_height_for_test() const {
  return "finalized-committee-checkpoint";
}
std::string Node::vote_path_for_next_height_for_test() const {
  return "committee-membership";
}
std::size_t Node::quorum_threshold_for_next_height_for_test() const {
  std::lock_guard<std::mutex> lk(mu_);
  const auto committee = committee_for_height_round(finalized_height_ + 1, current_round_);
  return consensus::quorum_threshold(committee.size());
}
std::vector<PubKey32> Node::active_validators_for_next_height_for_test() const {
  std::lock_guard<std::mutex> lk(mu_);
  return validators_.active_sorted(finalized_height_ + 1);
}
std::vector<PubKey32> Node::committee_for_next_height_for_test() const {
  std::lock_guard<std::mutex> lk(mu_);
  return committee_for_height_round(finalized_height_ + 1, current_round_);
}
std::vector<PubKey32> Node::committee_for_height_round_for_test(std::uint64_t height, std::uint32_t round) const {
  std::lock_guard<std::mutex> lk(mu_);
  return committee_for_height_round(height, round);
}
std::optional<PubKey32> Node::proposer_for_height_round_for_test(std::uint64_t height, std::uint32_t round) const {
  std::lock_guard<std::mutex> lk(mu_);
  return leader_for_height_round(height, round);
}
std::optional<QuorumCertificate> Node::highest_qc_for_height_for_test(std::uint64_t height) const {
  std::lock_guard<std::mutex> lk(mu_);
  return highest_qc_for_height_locked(height);
}
std::optional<TimeoutCertificate> Node::highest_tc_for_height_for_test(std::uint64_t height) const {
  std::lock_guard<std::mutex> lk(mu_);
  return highest_tc_for_height_locked(height);
}
std::size_t Node::timeout_vote_count_for_height_round_for_test(std::uint64_t height, std::uint32_t round) const {
  std::lock_guard<std::mutex> lk(mu_);
  return timeout_votes_.signatures_for(height, round).size();
}
bool Node::local_timeout_vote_reserved_for_test(std::uint64_t height, std::uint32_t round) const {
  std::lock_guard<std::mutex> lk(mu_);
  return local_timeout_vote_reservations_.find({height, round}) != local_timeout_vote_reservations_.end();
}
bool Node::local_is_committee_member_for_test(std::uint64_t height, std::uint32_t round) const {
  std::lock_guard<std::mutex> lk(mu_);
  return is_committee_member_for(local_key_.public_key, height, round);
}
std::uint64_t Node::round_age_ms_for_test() const {
  std::lock_guard<std::mutex> lk(mu_);
  const auto now = now_ms();
  return now > round_started_ms_ ? (now - round_started_ms_) : 0;
}
Hash32 Node::epoch_ticket_challenge_anchor_for_test(std::uint64_t height) const {
  std::lock_guard<std::mutex> lk(mu_);
  return epoch_ticket_challenge_anchor_locked(height);
}
PubKey32 Node::local_validator_pubkey_for_test() const {
  std::lock_guard<std::mutex> lk(mu_);
  return local_key_.public_key;
}
std::optional<consensus::ValidatorInfo> Node::validator_info_for_test(const PubKey32& pub) const {
  std::lock_guard<std::mutex> lk(mu_);
  return validators_.get(pub);
}
bool Node::seed_bonded_validator_for_test(const PubKey32& pub, const OutPoint& bond_outpoint, std::uint64_t bond_amount) {
  std::lock_guard<std::mutex> lk(mu_);
  auto info = validators_.get(pub);
  if (!info.has_value()) return false;

  Bytes reg_spk{'S', 'C', 'V', 'A', 'L', 'R', 'E', 'G'};
  reg_spk.insert(reg_spk.end(), pub.begin(), pub.end());
  TxOut bond_out{bond_amount, reg_spk};

  info->has_bond = true;
  info->bonded_amount = bond_amount;
  info->bond_outpoint = bond_outpoint;
  validators_.upsert(pub, *info);

  if (!canonical_state_.has_value()) return false;
  auto updated = *canonical_state_;
  updated.validators.upsert(pub, *info);
  updated.utxos[bond_outpoint] = UtxoEntryV2{bond_out};
  updated.state_commitment = consensus::consensus_state_commitment(canonical_derivation_config_locked(), updated);

  if (!db_.put_utxo_v2(bond_outpoint, UtxoEntryV2{bond_out})) return false;
  if (!db_.put_validator(pub, *info)) return false;
  if (!persist_canonical_cache_rows(db_, updated)) return false;
  (void)db_.erase(storage::key_consensus_state_commitment_cache());
  if (!verify_and_persist_consensus_state_commitment_locked(updated)) return false;
  canonical_state_ = updated;
  utxos_ = updated.utxos;
  return true;
}
Hash32 Node::canonical_state_commitment_for_test() const {
  std::lock_guard<std::mutex> lk(mu_);
  if (!canonical_state_.has_value()) return zero_hash();
  return canonical_state_->state_commitment;
}
std::uint64_t Node::canonical_state_height_for_test() const {
  std::lock_guard<std::mutex> lk(mu_);
  if (!canonical_state_.has_value()) return 0;
  return canonical_state_->finalized_height;
}
std::uint16_t Node::p2p_port_for_test() const { return cfg_.p2p_port; }
bool Node::endpoint_is_obvious_self_for_test(const std::string& host, std::uint16_t port) const {
  return endpoint_matches_local_listener(host, port, nullptr);
}
bool Node::self_endpoint_suppressed_for_test(const std::string& host, std::uint16_t port) const {
  std::lock_guard<std::mutex> lk(mu_);
  return is_self_endpoint_suppressed_locked(host + ":" + std::to_string(port));
}

std::optional<FrontierProposal> Node::build_frontier_proposal_for_test(std::uint64_t height, std::uint32_t round) {
  std::lock_guard<std::mutex> lk(mu_);
  last_test_hook_error_.clear();
  return build_frontier_transition_locked(height, round);
}

std::string Node::last_test_hook_error_for_test() const {
  std::lock_guard<std::mutex> lk(mu_);
  return last_test_hook_error_;
}

bool Node::inject_ingress_tips_for_test(const p2p::IngressTipsMsg& msg, int peer_id) {
  std::lock_guard<std::mutex> lk(mu_);
  return handle_ingress_tips_locked(peer_id, msg);
}

bool Node::inject_ingress_range_for_test(const p2p::IngressRangeMsg& msg, int peer_id) {
  std::lock_guard<std::mutex> lk(mu_);
  return handle_ingress_range_locked(peer_id, msg);
}

std::string Node::inject_ingress_range_result_for_test(const p2p::IngressRangeMsg& msg, int peer_id) {
  std::lock_guard<std::mutex> lk(mu_);
  std::string error;
  if (handle_ingress_range_locked(peer_id, msg, &error)) return {};
  return error.empty() ? "unknown" : error;
}

void Node::set_requested_ingress_range_for_test(int peer_id, const p2p::GetIngressRangeMsg& msg) {
  std::lock_guard<std::mutex> lk(mu_);
  requested_ingress_ranges_[{peer_id, msg.lane}] = msg;
}

std::optional<p2p::GetIngressRangeMsg> Node::requested_ingress_range_for_test(int peer_id, std::uint32_t lane) const {
  std::lock_guard<std::mutex> lk(mu_);
  auto it = requested_ingress_ranges_.find({peer_id, lane});
  if (it == requested_ingress_ranges_.end()) return std::nullopt;
  return it->second;
}

bool Node::overwrite_runtime_next_height_checkpoint_for_test(const storage::FinalizedCommitteeCheckpoint& checkpoint) {
  std::lock_guard<std::mutex> lk(mu_);
  const auto target_epoch = consensus::committee_epoch_start(finalized_height_ + 1, cfg_.network.committee_epoch_blocks);
  if (checkpoint.epoch_start_height != target_epoch) return false;
  finalized_committee_checkpoints_[target_epoch] = checkpoint;
  return true;
}

bool Node::overwrite_runtime_frontier_cursor_for_test(std::uint64_t finalized_frontier) {
  std::lock_guard<std::mutex> lk(mu_);
  if (!canonical_state_.has_value()) return false;
  canonical_state_->finalized_frontier = finalized_frontier;
  return true;
}

bool Node::verify_quorum_certificate_locked(const QuorumCertificate& qc, std::vector<FinalitySig>* filtered,
                                            std::string* error) const {
  const auto committee = committee_for_height_round(qc.height, qc.round);
  if (committee.empty()) {
    if (error) *error = "empty-committee";
    return false;
  }
  const std::size_t quorum = consensus::quorum_threshold(committee.size());
  std::set<PubKey32> committee_set(committee.begin(), committee.end());
  std::set<PubKey32> seen;
  std::vector<FinalitySig> valid;
  valid.reserve(qc.signatures.size());
  const auto msg = vote_signing_message(qc.height, qc.round, qc.frontier_transition_id);
  for (const auto& sig : qc.signatures) {
    if (committee_set.find(sig.validator_pubkey) == committee_set.end()) continue;
    if (!seen.insert(sig.validator_pubkey).second) continue;
    if (!crypto::ed25519_verify(msg, sig.signature, sig.validator_pubkey)) continue;
    valid.push_back(sig);
  }
  if (valid.size() < quorum) {
    if (error) *error = "insufficient-valid-signatures";
    return false;
  }
  if (filtered) *filtered = std::move(valid);
  return true;
}

bool Node::verify_timeout_certificate_locked(const TimeoutCertificate& tc, std::vector<FinalitySig>* filtered,
                                             std::string* error) const {
  const auto committee = committee_for_height_round(tc.height, tc.round);
  if (committee.empty()) {
    if (error) *error = "empty-committee";
    return false;
  }
  const std::size_t quorum = consensus::quorum_threshold(committee.size());
  std::set<PubKey32> committee_set(committee.begin(), committee.end());
  std::set<PubKey32> seen;
  std::vector<FinalitySig> valid;
  valid.reserve(tc.signatures.size());
  const auto msg = timeout_vote_signing_message(tc.height, tc.round);
  for (const auto& sig : tc.signatures) {
    if (committee_set.find(sig.validator_pubkey) == committee_set.end()) continue;
    if (!seen.insert(sig.validator_pubkey).second) continue;
    if (!crypto::ed25519_verify(msg, sig.signature, sig.validator_pubkey)) continue;
    valid.push_back(sig);
  }
  if (valid.size() < quorum) {
    if (error) *error = "insufficient-valid-signatures";
    return false;
  }
  if (filtered) *filtered = std::move(valid);
  return true;
}

bool Node::verify_finality_certificate_for_frontier_locked(const FinalityCertificate& cert,
                                                           const FrontierTransition& transition,
                                                           std::vector<FinalitySig>* canonical_signatures,
                                                           std::string* error) const {
  if (cert.height != transition.height) {
    if (error) *error = "certificate-height-mismatch";
    return false;
  }
  if (cert.round != transition.round) {
    if (error) *error = "certificate-round-mismatch";
    return false;
  }
  const auto transition_id = transition.transition_id();
  if (cert.frontier_transition_id != transition_id) {
    if (error) *error = "certificate-transition-id-mismatch";
    return false;
  }
  if (cert.committee_members.empty()) {
    if (error) *error = "certificate-empty-committee";
    return false;
  }
  const std::size_t expected_quorum = consensus::quorum_threshold(cert.committee_members.size());
  if (cert.quorum_threshold != expected_quorum) {
    if (error) *error = "certificate-quorum-mismatch";
    return false;
  }

  std::set<PubKey32> committee_set(cert.committee_members.begin(), cert.committee_members.end());
  if (committee_set.size() != cert.committee_members.size()) {
    if (error) *error = "certificate-duplicate-committee-members";
    return false;
  }

  std::set<PubKey32> seen;
  std::vector<FinalitySig> valid;
  valid.reserve(cert.signatures.size());
  const auto msg = vote_signing_message(cert.height, cert.round, cert.frontier_transition_id);
  for (const auto& sig : cert.signatures) {
    if (committee_set.find(sig.validator_pubkey) == committee_set.end()) continue;
    if (!seen.insert(sig.validator_pubkey).second) continue;
    if (!crypto::ed25519_verify(msg, sig.signature, sig.validator_pubkey)) continue;
    valid.push_back(sig);
  }
  if (valid.size() < expected_quorum) {
    if (error) *error = "certificate-insufficient-valid-signatures";
    return false;
  }

  const auto canonical = canonicalize_finality_signatures_locked(valid, expected_quorum);
  if (canonical.size() != expected_quorum) {
    if (error) *error = "certificate-canonicalization-failed";
    return false;
  }
  if (canonical_signatures) *canonical_signatures = canonical;
  return true;
}

std::optional<Hash32> Node::quorum_certificate_payload_id_locked(const QuorumCertificate& qc) const {
  auto it = highest_qc_by_height_.find(qc.height);
  if (it != highest_qc_by_height_.end() && it->second.round == qc.round &&
      it->second.frontier_transition_id == qc.frontier_transition_id) {
    auto pit = highest_qc_payload_by_height_.find(qc.height);
    if (pit != highest_qc_payload_by_height_.end()) return pit->second;
  }
  auto frontier_it = candidate_frontier_proposals_.find(qc.frontier_transition_id);
  if (frontier_it != candidate_frontier_proposals_.end()) return consensus_payload_id(frontier_it->second.transition);
  return std::nullopt;
}

std::optional<QuorumCertificate> Node::highest_qc_for_height_locked(std::uint64_t height) const {
  auto it = highest_qc_by_height_.find(height);
  if (it == highest_qc_by_height_.end()) return std::nullopt;
  return it->second;
}

std::optional<TimeoutCertificate> Node::highest_tc_for_height_locked(std::uint64_t height) const {
  auto it = highest_tc_by_height_.find(height);
  if (it == highest_tc_by_height_.end()) return std::nullopt;
  return it->second;
}

void Node::maybe_record_quorum_certificate_locked(const Hash32& transition_id, std::uint64_t height, std::uint32_t round) {
  QuorumCertificate qc =
      make_quorum_certificate(height, round, transition_id, votes_.signatures_for(height, round, transition_id));
  std::vector<FinalitySig> filtered;
  if (!verify_quorum_certificate_locked(qc, &filtered, nullptr)) return;
  qc.signatures = std::move(filtered);
  auto frontier_it = candidate_frontier_proposals_.find(transition_id);
  if (frontier_it == candidate_frontier_proposals_.end()) return;
  const auto payload_id = consensus_payload_id(frontier_it->second.transition);
  auto it = highest_qc_by_height_.find(height);
  if (it == highest_qc_by_height_.end() || qc.round > it->second.round ||
      (qc.round == it->second.round && qc.frontier_transition_id != it->second.frontier_transition_id)) {
    highest_qc_by_height_[height] = std::move(qc);
    highest_qc_payload_by_height_[height] = payload_id;
    persist_consensus_safety_state_locked(height);
  }
}

void Node::maybe_record_timeout_certificate_locked(std::uint64_t height, std::uint32_t round) {
  TimeoutCertificate tc;
  tc.height = height;
  tc.round = round;
  tc.signatures = timeout_votes_.signatures_for(height, round);
  std::vector<FinalitySig> filtered;
  if (!verify_timeout_certificate_locked(tc, &filtered, nullptr)) return;
  tc.signatures = std::move(filtered);
  auto it = highest_tc_by_height_.find(height);
  if (it == highest_tc_by_height_.end() || tc.round > it->second.round) {
    highest_tc_by_height_[height] = std::move(tc);
    if (height == finalized_height_ + 1 && current_round_ <= round) {
      current_round_ = round + 1;
      round_started_ms_ = now_ms();
      log_line("round-catchup height=" + std::to_string(height) + " old_round=" + std::to_string(round) +
               " new_round=" + std::to_string(current_round_) + " reason=timeout-certificate");
    }
  }
}

bool Node::can_vote_for_frontier_locked(const FrontierTransition& transition,
                                        const std::optional<QuorumCertificate>& justify_qc,
                                        const std::optional<TimeoutCertificate>& justify_tc,
                                        std::string* reason) const {
  const auto payload_id = consensus_payload_id(transition);
  const auto height = transition.height;
  const auto round = transition.round;
  auto it = local_vote_locks_.find(height);
  if (it == local_vote_locks_.end()) return true;
  const auto& [locked_payload_id, locked_round] = it->second;
  if (payload_id == locked_payload_id) return true;
  if (justify_tc.has_value()) {
    if (reason) *reason = "tc-cannot-unlock";
    return false;
  }
  if (!justify_qc.has_value()) {
    if (reason) *reason = "missing-qc";
    return false;
  }
  std::vector<FinalitySig> filtered;
  std::string qc_error;
  if (!verify_quorum_certificate_locked(*justify_qc, &filtered, &qc_error)) {
    if (reason) *reason = "invalid-qc detail=" + qc_error;
    return false;
  }
  if (justify_qc->height != height) {
    if (reason) *reason = "wrong-qc-height";
    return false;
  }
  if (justify_qc->round >= round) {
    if (reason) *reason = "non-lower-qc-round";
    return false;
  }
  if (justify_qc->round < locked_round) {
    if (reason) *reason = "stale-qc";
    return false;
  }
  auto qc_payload_id = quorum_certificate_payload_id_locked(*justify_qc);
  if (!qc_payload_id.has_value()) {
    if (reason) *reason = "unknown-qc-transition";
    return false;
  }
  if (*qc_payload_id != payload_id) {
    if (reason) *reason = "qc-mismatch";
    return false;
  }
  return true;
}

bool Node::can_accept_frontier_with_lock_locked(const FrontierTransition& transition, std::string* reason) const {
  const auto payload_id = consensus_payload_id(transition);
  auto it = local_vote_locks_.find(transition.height);
  if (it == local_vote_locks_.end()) return true;
  const auto& [locked_payload_id, locked_round] = it->second;
  if (payload_id == locked_payload_id) return true;
  if (transition.round < locked_round) {
    if (reason) *reason = "lock-round-regression";
    return false;
  }
  return false;
}

void Node::update_local_vote_lock_locked(std::uint64_t height, std::uint32_t round, const Hash32& payload_id) {
  auto it = local_vote_locks_.find(height);
  if (it == local_vote_locks_.end() || round >= it->second.second) {
    local_vote_locks_[height] = {payload_id, round};
    persist_consensus_safety_state_locked(height);
  }
}

void Node::persist_consensus_safety_state_locked(std::uint64_t height) {
  std::optional<std::pair<Hash32, std::uint32_t>> lock_state;
  if (auto it = local_vote_locks_.find(height); it != local_vote_locks_.end()) lock_state = it->second;
  std::optional<QuorumCertificate> qc_state;
  if (auto it = highest_qc_by_height_.find(height); it != highest_qc_by_height_.end()) qc_state = it->second;
  std::optional<Hash32> qc_payload_id;
  if (auto it = highest_qc_payload_by_height_.find(height); it != highest_qc_payload_by_height_.end()) qc_payload_id = it->second;
  if (!lock_state.has_value() && !qc_state.has_value()) {
    (void)db_.erase(key_consensus_safety_state(height));
    return;
  }
  (void)db_.put(key_consensus_safety_state(height), serialize_consensus_safety_state(lock_state, qc_state, qc_payload_id));
}

void Node::clear_consensus_safety_state_locked(std::uint64_t height) {
  local_vote_locks_.erase(height);
  highest_qc_by_height_.erase(height);
  highest_qc_payload_by_height_.erase(height);
  highest_tc_by_height_.erase(height);
  for (auto it = local_timeout_vote_reservations_.begin(); it != local_timeout_vote_reservations_.end();) {
    if (it->first == height) {
      it = local_timeout_vote_reservations_.erase(it);
    } else {
      ++it;
    }
  }
  (void)db_.erase(key_consensus_safety_state(height));
}

void Node::event_loop() {
  while (running_) {
    (void)reap_lightserver_child(true);
    std::optional<FrontierProposal> frontier_to_propose;
    std::optional<TimeoutVote> timeout_vote_to_broadcast;
    std::vector<int> keepalive_peers;
    bool should_build_proposal = false;
    std::uint64_t build_height = 0;
    std::uint32_t build_round = 0;
    {
      std::lock_guard<std::mutex> lk(mu_);
      const std::uint64_t h = finalized_height_ + 1;
      validators_.advance_height(h);
      const std::uint32_t cv = kFixedValidationRulesVersion;
      const auto min_bond_amount = effective_validator_min_bond_for_height(h);
      mempool_.set_validation_context(
          SpecialValidationContext{
              .network = &cfg_.network,
              .chain_id = &chain_id_,
              .validators = &validators_,
              .current_height = h,
              .enforce_variable_bond_range = true,
              .min_bond_amount = min_bond_amount,
              .max_bond_amount = effective_validator_bond_max_for_height(h),
              .unbond_delay_blocks = cfg_.network.unbond_delay_blocks,
              .is_committee_member = [this](const PubKey32& pub, std::uint64_t ch, std::uint32_t round) {
                return is_committee_member_for(pub, ch, round);
              },
              .finalized_hash_at_height = [this](std::uint64_t anchor_height) -> std::optional<Hash32> {
                if (anchor_height == 0) return zero_hash();
                return db_.get_height_hash(anchor_height);
              },
              .confidential_policy = &confidential_policy_});
      const std::uint64_t now_ms = this->now_ms();
      const std::uint64_t now_unix_ms = now_unix() * 1000;
      if (now_ms >= last_runtime_status_persist_ms_ + 1000) {
        auto runtime = build_runtime_status_snapshot_locked(now_unix_ms);
        (void)db_.put_node_runtime_status_snapshot(runtime);
        last_runtime_status_persist_ms_ = now_ms;
      }
      const std::uint64_t min_block_interval_ms = static_cast<std::uint64_t>(cfg_.network.min_block_interval_ms);
      const std::uint64_t ticket_window_floor_ms = std::min<std::uint64_t>(1000, min_block_interval_ms);
      const std::uint64_t ticket_window_ms =
          std::max<std::uint64_t>(ticket_window_floor_ms, min_block_interval_ms / 2);
      const bool ticket_window_elapsed = now_ms >= last_finalized_progress_ms_ + ticket_window_ms;
      const bool block_interval_elapsed =
          now_ms >= last_finalized_progress_ms_ + min_block_interval_ms;
      if (current_round_ == 0 && ticket_window_elapsed) {
        const std::uint64_t round0_start = last_finalized_progress_ms_ + ticket_window_ms;
        if (round_started_ms_ < round0_start) round_started_ms_ = round0_start;
      }
      maybe_self_bootstrap_template(now_ms);
      std::string repair_reason;
      (void)maybe_repair_next_height_locked(now_ms, &repair_reason);

      if (now_ms > last_summary_log_ms_ + 30'000) {
        const auto committee = committee_for_height_round(h, current_round_);
        const std::size_t quorum = consensus::quorum_threshold(committee.size());
        std::size_t observed = 0;
        std::size_t q = quorum;
        const auto state = consensus_state_locked(now_ms, &observed, &q);
      if (!runtime_logs_enabled()) {
        last_summary_log_ms_ = now_ms;
      } else if (cfg_.log_json) {
        std::ostringstream j;
          j << "{\"type\":\"summary\",\"network\":\"" << cfg_.network.name << "\",\"protocol_version\":"
            << cfg_.network.protocol_version << ",\"network_id\":\""
            << hex_encode(Bytes(cfg_.network.network_id.begin(), cfg_.network.network_id.begin() + 4)) << "\",\"magic\":"
            << cfg_.network.magic << ",\"db_dir\":\"" << cfg_.db_path << "\",\"height\":" << finalized_height_
            << ",\"transition\":\"" << short_hash_hex(finalized_identity_.id) << "\",\"genesis_hash\":\""
            << chain_id_.genesis_hash_hex << "\",\"genesis_source\":\"" << chain_id_.genesis_source
            << "\",\"chain_id_ok\":" << (chain_id_.chain_id_ok ? "true" : "false") << ",\"peers\":" << peer_count()
            << ",\"established_peers\":" << established_peer_count()
            << ",\"outbound_connected\":" << (cfg_.disable_p2p ? peer_count() : p2p_.outbound_count())
            << ",\"inbound_connected\":" << (cfg_.disable_p2p ? 0 : p2p_.inbound_count())
            << ",\"outbound_target\":" << cfg_.outbound_target << ",\"addrman_size\":" << addrman_.size()
            << ",\"bootstrap_source_last\":\"" << last_bootstrap_source_ << "\",\"committee_size\":" << committee.size()
            << ",\"quorum_threshold\":" << q << ",\"observed_signers\":" << observed
            << ",\"consensus_state\":\"" << state << "\",\"consensus_version\":" << kFixedValidationRulesVersion
            << ",\"bootstrap_template_mode\":" << (bootstrap_template_mode_ ? "true" : "false")
            << ",\"pending_bootstrap_joiners\":" << pending_join_request_count_locked();
          if (bootstrap_validator_pubkey_.has_value()) {
            j << ",\"bootstrap_validator_pubkey\":\""
              << hex_encode(Bytes(bootstrap_validator_pubkey_->begin(), bootstrap_validator_pubkey_->end())) << "\"";
          }
          j << "}";
          std::cout << j.str() << "\n";
        } else {
          std::cout << cfg_.network.name << " h=" << finalized_height_ << " transition=" << short_hash_hex(finalized_identity_.id)
                    << " gen=" << chain_id_.genesis_hash_hex.substr(0, 8) << " peers=" << peer_count()
                    << " outbound=" << (cfg_.disable_p2p ? peer_count() : p2p_.outbound_count()) << "/"
                    << cfg_.outbound_target << " inbound=" << (cfg_.disable_p2p ? 0 : p2p_.inbound_count())
                    << " established=" << established_peer_count() << " addrman=" << addrman_.size()
                    << " cv=" << kFixedValidationRulesVersion << " state=" << state;
          if (bootstrap_template_mode_) {
            std::cout << " bootstrap=template";
            if (bootstrap_validator_pubkey_.has_value()) {
              std::cout << " validator=" << short_pub_hex(*bootstrap_validator_pubkey_);
            }
            if (!last_bootstrap_source_.empty()) {
              std::cout << " source=" << last_bootstrap_source_;
            }
            const auto pending_joiners = pending_join_request_count_locked();
            if (pending_joiners != 0) {
              std::cout << " pending_joiners=" << pending_joiners;
            }
          }
          std::cout << "\n";
        }
        last_summary_log_ms_ = now_ms;
      }

      const std::uint64_t keepalive_interval_ms =
          std::max<std::uint64_t>(200, static_cast<std::uint64_t>(cfg_.idle_timeout_ms) / 3);
      const std::uint64_t sync_poll_interval_ms =
          std::max<std::uint64_t>(3000, static_cast<std::uint64_t>(cfg_.network.round_timeout_ms));
      for (int peer_id : p2p_.peer_ids()) {
        const auto info = p2p_.get_peer_info(peer_id);
        if (!info.established()) continue;
        auto& last = peer_keepalive_ms_[peer_id];
        if (now_ms >= last + keepalive_interval_ms) {
          keepalive_peers.push_back(peer_id);
          last = now_ms;
        }
      }

      if (!cfg_.disable_p2p && established_peer_count() > 0 &&
          now_ms >= last_finalized_progress_ms_ + sync_poll_interval_ms &&
          now_ms >= last_finalized_tip_poll_ms_ + sync_poll_interval_ms) {
        for (int peer_id : p2p_.peer_ids()) {
          const auto info = p2p_.get_peer_info(peer_id);
          if (!info.established()) continue;
          keepalive_peers.push_back(peer_id);
        }
        last_finalized_tip_poll_ms_ = now_ms;
      }

      if (!repair_mode_) {
        maybe_finalize_epoch_committees_locked();
        if (!cfg_.disable_p2p) maybe_request_epoch_ticket_reconciliation_locked(now_ms);
      }

      if (!repair_mode_) {
        if (auto epoch_ticket = mine_local_epoch_ticket_locked(h); epoch_ticket.has_value()) {
        auto it = local_epoch_tickets_.find(epoch_ticket->epoch);
        const bool improved = it == local_epoch_tickets_.end() || consensus::epoch_ticket_better(*epoch_ticket, it->second);
        if (improved) {
          const bool accepted = handle_epoch_ticket_locked(*epoch_ticket, false, 0);
          if (accepted) {
            log_line("epoch-ticket-local-mined epoch=" + std::to_string(epoch_ticket->epoch) +
                     " participant=" + short_pub_hex(epoch_ticket->participant_pubkey) +
                     " work=" + short_hash_hex(epoch_ticket->work_hash));
            broadcast_epoch_ticket(*epoch_ticket);
          }
        }
      }
      }

      const auto committee = committee_for_height_round(h, current_round_);
      const bool committee_ready = !committee.empty();
      const std::size_t quorum = consensus::quorum_threshold(committee.size());
      const auto hr = std::make_pair(h, current_round_);
      prune_caches_locked(h, current_round_);
      if (committee_ready && logged_committee_rounds_.insert(hr).second) {
        std::ostringstream coss;
        coss << "committee height=" << h << " round=" << current_round_ << " size=" << committee.size()
             << " quorum=" << quorum << " members=";
        for (std::size_t i = 0; i < committee.size(); ++i) {
          if (i) coss << ",";
          coss << short_pub_hex(committee[i]);
        }
        log_line(coss.str());
        if (cfg_.log_json) {
          std::ostringstream j;
          j << "{\"type\":\"status\",\"network\":\"" << cfg_.network.name << "\",\"height\":" << finalized_height_
            << ",\"transition_hash\":\"" << hex_encode32(finalized_identity_.id) << "\",\"round\":" << current_round_
            << ",\"peers\":" << peer_count() << ",\"established_peers\":" << established_peer_count()
            << ",\"mempool_size\":" << mempool_.size()
            << ",\"committee_size\":" << committee.size() << ",\"addrman_size\":" << addrman_.size()
            << ",\"consensus_version\":" << kFixedValidationRulesVersion
            << ",\"genesis_hash\":\"" << chain_id_.genesis_hash_hex << "\""
            << ",\"genesis_source\":\"" << chain_id_.genesis_source << "\""
            << ",\"chain_id_ok\":" << (chain_id_.chain_id_ok ? "true" : "false")
            << ",\"outbound_connected\":" << (cfg_.disable_p2p ? peer_count() : p2p_.outbound_count())
            << ",\"inbound_connected\":" << (cfg_.disable_p2p ? 0 : p2p_.inbound_count())
            << ",\"last_bootstrap_source\":\"" << last_bootstrap_source_ << "\""
            << ",\"bootstrap_template_mode\":" << (bootstrap_template_mode_ ? "true" : "false")
            << ",\"pending_bootstrap_joiners\":" << pending_join_request_count_locked();
          if (bootstrap_validator_pubkey_.has_value()) {
            j << ",\"bootstrap_validator_pubkey\":\""
              << hex_encode(Bytes(bootstrap_validator_pubkey_->begin(), bootstrap_validator_pubkey_->end())) << "\"";
          }
          j << ",\"rejected_network_id\":" << rejected_network_id_
            << ",\"rejected_protocol_version\":" << rejected_protocol_version_
            << ",\"rejected_pre_handshake\":" << rejected_pre_handshake_ << "}";
          std::cout << j.str() << "\n";
        }
      }

      bool can_propose = false;
      const auto leader = leader_for_height_round(h, current_round_);
      const auto highest_qc = highest_qc_for_height_locked(h);
      const auto highest_tc = highest_tc_for_height_locked(h);
      const bool ticket_pow_fallback_round = current_round_ > 0 && committee.size() == 1;
      const bool round_justification_ready =
          ticket_pow_fallback_round || highest_qc.has_value() ||
          (highest_tc.has_value() && highest_tc->round < current_round_) || current_round_ == 0;
      can_propose = leader.has_value() && *leader == local_key_.public_key;
      if (!repair_mode_ && !pause_proposals_.load() && can_propose && committee_ready && block_interval_elapsed && ticket_window_elapsed &&
          !committee.empty() && round_justification_ready) {
        auto key = std::make_pair(h, current_round_);
        if (proposed_in_round_.find(key) == proposed_in_round_.end()) {
          should_build_proposal = true;
          build_height = h;
          build_round = current_round_;
        }
      } else if (!repair_mode_ && !pause_proposals_.load() && ticket_window_elapsed && block_interval_elapsed &&
                 now_ms > round_started_ms_ + cfg_.network.round_timeout_ms) {
        const auto timeout_round = current_round_;
        const auto timeout_committee = committee_for_height_round(h, timeout_round);
        const auto timeout_vote_key = std::make_pair(h, timeout_round);
        const bool local_timeout_reserved =
            local_timeout_vote_reservations_.find(timeout_vote_key) != local_timeout_vote_reservations_.end();
        const bool local_timeout_member =
            std::find(timeout_committee.begin(), timeout_committee.end(), local_key_.public_key) != timeout_committee.end();
        bool timeout_evidence_progressed = local_timeout_reserved;
        if (local_timeout_member && !local_timeout_reserved) {
          if (auto sig = crypto::ed25519_sign(timeout_vote_signing_message(h, timeout_round), local_key_.private_key);
              sig.has_value()) {
            local_timeout_vote_reservations_.insert(timeout_vote_key);
            timeout_vote_to_broadcast = TimeoutVote{h, timeout_round, local_key_.public_key, *sig};
            timeout_evidence_progressed = true;
            log_line("round-timeout-vote height=" + std::to_string(h) + " round=" + std::to_string(timeout_round));
          } else {
            log_line("round-timeout-vote-skip height=" + std::to_string(h) + " round=" + std::to_string(timeout_round) +
                     " reason=sign-failed");
          }
        } else if (!local_timeout_member) {
          log_line("round-timeout-vote-skip height=" + std::to_string(h) + " round=" + std::to_string(timeout_round) +
                   " reason=not-committee-member");
        }
        if (!timeout_committee.empty()) {
          const auto old_round = current_round_;
          current_round_ = timeout_round + 1;
          round_started_ms_ = now_ms;
          log_line("round-catchup height=" + std::to_string(h) + " old_round=" + std::to_string(old_round) +
                   " new_round=" + std::to_string(current_round_) + " reason=ticket-pow-fallback-timeout");
        } else if (timeout_evidence_progressed) {
          // Round advancement remains TC-driven outside the deterministic
          // deterministic ticket-pow fallback path.
          if (timeout_evidence_progressed) round_started_ms_ = now_ms;
        }
      }
    }

    if (should_build_proposal) {
      std::optional<FrontierProposal> built;
      std::string build_error;
      {
        std::lock_guard<std::mutex> lk(mu_);
        built = build_frontier_transition_locked(build_height, build_round);
        build_error = last_test_hook_error_;
      }
      if (built.has_value()) {
        std::lock_guard<std::mutex> lk(mu_);
        const auto key = std::make_pair(build_height, build_round);
        if (finalized_height_ + 1 == build_height && current_round_ == build_round &&
            proposed_in_round_.find(key) == proposed_in_round_.end()) {
          proposed_in_round_[key] = true;
          candidate_frontier_proposals_[built->transition.transition_id()] = *built;
          candidate_block_sizes_[built->transition.transition_id()] = built->serialize().size();
          frontier_to_propose = *built;
        }
      } else {
        log_line("proposal-build-skip height=" + std::to_string(build_height) + " round=" + std::to_string(build_round) +
                 " reason=" + (build_error.empty() ? std::string("unknown") : build_error));
      }
    }

    if (frontier_to_propose.has_value()) {
      std::optional<QuorumCertificate> justify_qc;
      std::optional<TimeoutCertificate> justify_tc;
      {
        std::lock_guard<std::mutex> lk(mu_);
        if (frontier_to_propose->transition.round > 0) {
          justify_qc = highest_qc_for_height_locked(frontier_to_propose->transition.height);
          if (!justify_qc.has_value()) justify_tc = highest_tc_for_height_locked(frontier_to_propose->transition.height);
        }
      }
      p2p::ProposeMsg local_msg;
      local_msg.height = frontier_to_propose->transition.height;
      local_msg.round = frontier_to_propose->transition.round;
      local_msg.prev_finalized_hash = frontier_to_propose->transition.prev_finalized_hash;
      local_msg.frontier_proposal_bytes = frontier_to_propose->serialize();
      local_msg.justify_qc = justify_qc;
      local_msg.justify_tc = justify_tc;
      broadcast_propose(*frontier_to_propose, justify_qc, justify_tc);
      handle_propose(local_msg, false);
    }

    if (timeout_vote_to_broadcast.has_value()) {
      broadcast_timeout_vote(*timeout_vote_to_broadcast);
      const bool ok = handle_timeout_vote(*timeout_vote_to_broadcast, false, 0);
      (void)ok;
    }

    {
      std::sort(keepalive_peers.begin(), keepalive_peers.end());
      keepalive_peers.erase(std::unique(keepalive_peers.begin(), keepalive_peers.end()), keepalive_peers.end());
    }
    for (int peer_id : keepalive_peers) {
      send_ping(peer_id);
      const std::uint64_t now_ms = this->now_ms();
      const std::uint64_t sync_poll_interval_ms =
          std::max<std::uint64_t>(3000, static_cast<std::uint64_t>(cfg_.network.round_timeout_ms));
      if (!cfg_.disable_p2p && now_ms >= last_finalized_progress_ms_ + sync_poll_interval_ms) {
        request_finalized_tip(peer_id);
      }
    }

    if (cfg_.disable_p2p) join_local_bus_tasks();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    (void)reap_lightserver_child(true);
    if (!cfg_.disable_p2p) {
      const std::uint64_t now_ms = this->now_ms();
      if (outbound_peer_count() < cfg_.outbound_target && now_ms > last_seed_attempt_ms_ + 3000) {
        try_connect_bootstrap_peers();
        last_seed_attempt_ms_ = now_ms;
      }
      if (now_ms > last_addrman_save_ms_ + 10'000) {
        persist_addrman();
        last_addrman_save_ms_ = now_ms;
      }
    }
  }
}

void Node::send_version(int peer_id) {
  auto tip = db_.get_tip();
  p2p::VersionMsg v;
  v.timestamp = now_unix();
  v.proto_version = static_cast<std::uint32_t>(cfg_.network.protocol_version);
  v.network_id = cfg_.network.network_id;
  v.feature_flags = cfg_.network.feature_flags;
  v.nonce = static_cast<std::uint32_t>(cfg_.node_id + 1000);
  v.start_height = tip ? tip->height : 0;
  v.start_hash = tip ? tip->hash : zero_hash();
  v.node_software_version = local_software_version_fingerprint(cfg_.network, chain_id_, kFixedValidationRulesVersion);
  if (bootstrap_validator_pubkey_.has_value()) {
    v.node_software_version +=
        ";bootstrap_validator=" + hex_encode(Bytes(bootstrap_validator_pubkey_->begin(), bootstrap_validator_pubkey_->end()));
  }
  v.node_software_version +=
      ";validator_pubkey=" + hex_encode(Bytes(local_key_.public_key.begin(), local_key_.public_key.end()));

  const bool ok = p2p_.send_to(peer_id, p2p::MsgType::VERSION, p2p::ser_version(v));
  log_line(std::string("send ") + msg_type_name(p2p::MsgType::VERSION) + " peer_id=" + std::to_string(peer_id) +
           " start_height=" + std::to_string(v.start_height) + " start_hash=" + short_hash_hex(v.start_hash) +
           " status=" + (ok ? "ok" : "failed"));
  if (ok) p2p_.mark_handshake_tx(peer_id, true, false);
}

void Node::maybe_send_verack(int peer_id) {
  const bool ok = p2p_.send_to(peer_id, p2p::MsgType::VERACK, {});
  log_line(std::string("send ") + msg_type_name(p2p::MsgType::VERACK) + " peer_id=" + std::to_string(peer_id) +
           " status=" + (ok ? "ok" : "failed"));
  if (ok) p2p_.mark_handshake_tx(peer_id, false, true);
}

void Node::send_ping(int peer_id) {
  const p2p::PingMsg ping{now_ms()};
  const bool ok = p2p_.send_to(peer_id, p2p::MsgType::PING, p2p::ser_ping(ping), true);
  log_line(std::string("send ") + msg_type_name(p2p::MsgType::PING) + " peer_id=" + std::to_string(peer_id) +
           " nonce=" + std::to_string(ping.nonce) + " status=" + (ok ? "ok" : "failed"));
}

Hash32 Node::epoch_ticket_challenge_anchor_locked(std::uint64_t height) const {
  if (height == 0) return zero_hash();
  if (auto checkpoint = finalized_committee_checkpoint_for_height_locked(height); checkpoint.has_value()) {
    return checkpoint->epoch_seed;
  }
  const auto epoch_start = consensus::committee_epoch_start(height, cfg_.network.committee_epoch_blocks);
  return consensus::committee_epoch_seed(committee_epoch_randomness_for_height_locked(height), epoch_start);
}

std::uint64_t Node::current_epoch_ticket_epoch_locked() const {
  return consensus::committee_epoch_start(finalized_height_ + 1, cfg_.network.committee_epoch_blocks);
}

std::optional<PubKey32> Node::local_operator_pubkey_locked() const {
  auto info = validators_.get(local_key_.public_key);
  if (!info.has_value()) return std::nullopt;
  return consensus::canonical_operator_id(local_key_.public_key, *info);
}

bool Node::persist_availability_state_locked() {
  return db_.put_availability_persistent_state(availability_state_);
}

bool Node::validate_availability_state_locked(const char* source) const {
  std::string error;
  if (availability::validate_availability_persistent_state_for_live_derivation(availability_state_, cfg_.availability, &error)) {
    return true;
  }
  log_line(std::string("availability-state-invariant-violation source=") + (source ? source : "unknown") +
           " detail=" + error);
  return false;
}

bool Node::finalize_availability_restore_locked(const char* source) {
  availability::normalize_availability_persistent_state(&availability_state_);
  if (!validate_availability_state_locked(source)) return false;
  log_line(std::string("availability-state-ready source=") + (source ? source : "unknown") +
           " epoch=" + std::to_string(availability_state_.current_epoch) +
           " operators=" + std::to_string(availability_state_.operators.size()) +
           " retained_prefixes=" + std::to_string(availability_state_.retained_prefixes.size()));
  return persist_availability_state_locked();
}

void Node::rebuild_availability_retained_prefixes_from_finalized_frontier_locked() {
  std::map<Hash32, availability::RetainedPrefix> merged;
  for (std::uint64_t height = 1; height <= finalized_height_; ++height) {
    auto transition_id = db_.get_frontier_transition_by_height(height);
    if (!transition_id.has_value()) continue;
    auto transition_bytes = db_.get_frontier_transition(*transition_id);
    if (!transition_bytes.has_value()) continue;
    auto transition = FrontierTransition::parse(*transition_bytes);
    if (!transition.has_value()) continue;
    consensus::CanonicalFrontierRecord record;
    std::string error;
    if (!consensus::load_certified_frontier_record_from_storage(db_, *transition, &record, &error)) {
      log_line("availability-backfill-skip height=" + std::to_string(height) + " detail=" + error);
      continue;
    }
    for (const auto& payload : availability::build_retained_prefix_payloads_from_lane_records(
             record.lane_records, record.transition.height, cfg_.availability.audit_chunk_size)) {
      merged[payload.prefix.prefix_id] = payload.prefix;
    }
  }
  availability_state_.retained_prefixes.clear();
  availability_state_.retained_prefixes.reserve(merged.size());
  for (const auto& [_, prefix] : merged) availability_state_.retained_prefixes.push_back(prefix);
  availability::normalize_availability_persistent_state(&availability_state_);
}

void Node::refresh_availability_operator_state_locked(bool advance_epoch) {
  std::map<PubKey32, std::uint64_t> operator_bonds;
  for (const auto& [validator_pubkey, info] : validators_.all()) {
    operator_bonds[consensus::canonical_operator_id(validator_pubkey, info)] += info.bonded_amount;
  }
  availability::refresh_live_availability_state(finalized_identity_.id, operator_bonds, advance_epoch, &availability_state_,
                                                cfg_.availability, cfg_.network.availability_recovery_activation_height);
  (void)validate_availability_state_locked(advance_epoch ? "availability-advance-epoch" : "availability-refresh");
}

void Node::advance_availability_epoch_locked(std::uint64_t epoch) {
  std::map<PubKey32, std::uint64_t> operator_bonds;
  for (const auto& [validator_pubkey, info] : validators_.all()) {
    operator_bonds[consensus::canonical_operator_id(validator_pubkey, info)] += info.bonded_amount;
  }
  availability::advance_live_availability_epoch(finalized_identity_.id, operator_bonds, epoch, &availability_state_,
                                                cfg_.availability, cfg_.network.availability_recovery_activation_height);
  (void)validate_availability_state_locked("availability-advance-epoch");
}

void Node::update_availability_from_finalized_frontier_locked(const consensus::CanonicalFrontierRecord& record) {
  const auto retained =
      availability::build_retained_prefix_payloads_from_lane_records(record.lane_records, record.transition.height,
                                                                     cfg_.availability.audit_chunk_size);
  if (retained.empty()) return;
  std::map<Hash32, availability::RetainedPrefix> merged;
  for (const auto& prefix : availability_state_.retained_prefixes) merged[prefix.prefix_id] = prefix;
  for (const auto& payload : retained) merged[payload.prefix.prefix_id] = payload.prefix;
  availability_state_.retained_prefixes.clear();
  availability_state_.retained_prefixes.reserve(merged.size());
  for (const auto& [_, prefix] : merged) availability_state_.retained_prefixes.push_back(prefix);
  availability::normalize_availability_persistent_state(&availability_state_);
  refresh_availability_operator_state_locked(false);
}

bool Node::load_availability_state_locked() {
  availability_state_rebuild_triggered_ = false;
  availability_state_rebuild_reason_.clear();
  if (canonical_state_.has_value()) {
    availability_state_ = canonical_state_->availability_state;
    return finalize_availability_restore_locked("canonical-replay");
  }
  const auto current_epoch = current_epoch_ticket_epoch_locked();
  const auto persisted_raw = db_.get(storage::key_availability_persistent_state());
  auto persisted = db_.get_availability_persistent_state();
  if (!persisted.has_value()) {
    if (persisted_raw.has_value()) {
      log_line("availability-snapshot-invalid action=reset");
      availability_state_rebuild_triggered_ = true;
      availability_state_rebuild_reason_ = "invalid_persisted_state";
    } else {
      availability_state_rebuild_triggered_ = true;
      availability_state_rebuild_reason_ = "missing_persisted_state";
    }
    availability_state_ = {};
    availability_state_.current_epoch = current_epoch;
    if (finalized_height_ > 0) {
      rebuild_availability_retained_prefixes_from_finalized_frontier_locked();
    }
    refresh_availability_operator_state_locked(false);
    return finalize_availability_restore_locked("frontier-replay");
  }
  availability_state_ = *persisted;
  availability::normalize_availability_persistent_state(&availability_state_);
  if (finalized_height_ > 0 && availability_state_.retained_prefixes.empty()) {
    availability_state_rebuild_triggered_ = true;
    availability_state_rebuild_reason_ = "missing_retained_prefix_snapshot";
    rebuild_availability_retained_prefixes_from_finalized_frontier_locked();
  }
  availability_state_.retained_prefixes =
      availability::expire_retained_prefixes(availability_state_.retained_prefixes, current_epoch,
                                             cfg_.availability.retention_window_min_epochs);
  if (availability_state_.current_epoch < current_epoch) {
    advance_availability_epoch_locked(current_epoch);
  } else {
    availability_state_.current_epoch = current_epoch;
    refresh_availability_operator_state_locked(false);
  }
  return finalize_availability_restore_locked("persisted-restore");
}

bool Node::epoch_committee_closed_locked(std::uint64_t epoch) const {
  if (epoch == 0) return false;
  return epoch < current_epoch_ticket_epoch_locked();
}

bool Node::epoch_committee_frozen_locked(std::uint64_t epoch) const {
  if (!epoch_committee_closed_locked(epoch)) return false;
  auto marker = db_.get_epoch_committee_freeze_marker(epoch);
  if (!marker.has_value()) return false;
  auto snapshot = db_.get_epoch_committee_snapshot(epoch);
  if (!snapshot.has_value()) return false;
  if (snapshot->ordered_members.empty()) return false;
  return marker->challenge_anchor == snapshot->challenge_anchor &&
         marker->member_count == snapshot->ordered_members.size();
}

std::optional<std::uint64_t> Node::epoch_committee_snapshot_epoch_for_height_locked(std::uint64_t height) const {
  if (height == 0) return std::nullopt;
  const auto epoch = consensus::committee_epoch_start(height, cfg_.network.committee_epoch_blocks);
  const auto step = std::max<std::uint64_t>(1, cfg_.network.committee_epoch_blocks);
  if (epoch <= step) return std::nullopt;
  return epoch - step;
}

std::optional<consensus::EpochCommitteeSnapshot> Node::frozen_epoch_committee_snapshot_for_height_locked(
    std::uint64_t height) const {
  auto snapshot_epoch = epoch_committee_snapshot_epoch_for_height_locked(height);
  if (!snapshot_epoch.has_value()) return std::nullopt;
  if (!epoch_committee_frozen_locked(*snapshot_epoch)) return std::nullopt;
  auto snapshot = db_.get_epoch_committee_snapshot(*snapshot_epoch);
  if (!snapshot.has_value() || snapshot->ordered_members.empty()) return std::nullopt;
  return snapshot;
}

std::vector<PubKey32> Node::epoch_bootstrap_committee_for_height_locked(std::uint64_t height) const {
  if (height == 0) return {};
  std::vector<PubKey32> bootstrap_members;
  if (auto gj = db_.get(storage::key_genesis_json()); gj.has_value()) {
    const std::string js(gj->begin(), gj->end());
    if (auto gd = genesis::parse_json(js); gd.has_value()) {
      for (const auto& pub : gd->initial_validators) {
        auto it = validators_.all().find(pub);
        if (it == validators_.all().end()) continue;
        if (!it->second.has_bond) continue;
        if (it->second.status == consensus::ValidatorStatus::BANNED) continue;
        bootstrap_members.push_back(pub);
      }
    }
  }
  std::sort(bootstrap_members.begin(), bootstrap_members.end());
  bootstrap_members.erase(std::unique(bootstrap_members.begin(), bootstrap_members.end()), bootstrap_members.end());
  if (bootstrap_members.size() > cfg_.max_committee) bootstrap_members.resize(cfg_.max_committee);
  return bootstrap_members;
}

bool Node::bootstrap_handoff_complete_locked() const {
  if (finalized_height_ == 0) return false;
  return validators_.active_sorted(finalized_height_ + 1).size() >= 2;
}

bool Node::single_node_bootstrap_active_locked(std::uint64_t height) const {
  if (!bootstrap_template_mode_) return false;
  if (bootstrap_handoff_complete_locked()) return false;
  if (cfg_.disable_p2p) return false;
  if (cfg_.outbound_target != 0) return false;
  if (!bootstrap_validator_pubkey_.has_value()) return false;
  const auto bootstrap_committee = epoch_bootstrap_committee_for_height_locked(height);
  return bootstrap_committee.size() == 1 && bootstrap_committee.front() == *bootstrap_validator_pubkey_;
}

std::vector<PubKey32> Node::epoch_committee_for_next_height_locked(std::uint64_t height, std::uint32_t round) const {
  if (height == 0 || height != finalized_height_ + 1) return {};
  auto checkpoint = finalized_committee_checkpoint_for_height_locked(height);
  if (!checkpoint.has_value() || checkpoint->ordered_members.empty()) {
    log_line("epoch-committee-unavailable height=" + std::to_string(height) +
             " reason=missing-finalized-committee-checkpoint");
    return {};
  }
  return consensus::checkpoint_committee_for_round(*checkpoint, round);
}

std::optional<PubKey32> Node::epoch_leader_for_next_height_locked(std::uint64_t height, std::uint32_t round) const {
  if (height == 0 || height != finalized_height_ + 1) return std::nullopt;
  auto checkpoint = finalized_committee_checkpoint_for_height_locked(height);
  if (!checkpoint.has_value() || checkpoint->ordered_members.empty()) return std::nullopt;
  if (auto fallback = consensus::checkpoint_ticket_pow_fallback_member_for_round(*checkpoint, round); fallback.has_value()) {
    return fallback;
  }
  const auto schedule = proposer_schedule_from_checkpoint(cfg_.network, validators_, *checkpoint, height);
  if (schedule.empty()) {
    log_line("epoch-proposer-unavailable height=" + std::to_string(height) + " round=" + std::to_string(round) +
             " reason=empty-schedule");
    return std::nullopt;
  }
  return schedule[static_cast<std::size_t>(round) % schedule.size()];
}

bool Node::recover_single_validator_epoch_committee_locked(std::uint64_t epoch, const char* reason) {
  auto checkpoint = finalized_committee_checkpoint_for_height_locked(epoch);
  if (!checkpoint.has_value()) return false;
  if (checkpoint->ordered_members.size() != 1) return false;

  consensus::EpochCommitteeSnapshot snapshot;
  snapshot.epoch = epoch;
  snapshot.challenge_anchor = checkpoint->epoch_seed;

  const auto& pub = checkpoint->ordered_members.front();
  const auto best = checkpoint_best_ticket_for_member(cfg_.network, validators_, *checkpoint, 0);
  snapshot.selected_winners.push_back(consensus::EpochCommitteeMember{
      .participant_pubkey = pub,
      .work_hash = best.best_ticket_hash,
      .nonce = best.nonce,
      .source_height = epoch,
  });
  snapshot.ordered_members.push_back(pub);

  const auto marker = make_epoch_committee_freeze_marker_locked(snapshot);
  const bool ok = db_.put_epoch_committee_snapshot(snapshot) && db_.put_epoch_committee_freeze_marker(marker);
  if (ok) {
    log_line(std::string("epoch-committee-recovered reason=") + reason + " epoch=" + std::to_string(epoch) +
             " source=single-validator-finalized-checkpoint committee=1");
  }
  return ok;
}

storage::EpochCommitteeFreezeMarker Node::make_epoch_committee_freeze_marker_locked(
    const consensus::EpochCommitteeSnapshot& snapshot) const {
  return storage::EpochCommitteeFreezeMarker{
      .epoch = snapshot.epoch,
      .challenge_anchor = snapshot.challenge_anchor,
      .member_count = static_cast<std::uint64_t>(snapshot.ordered_members.size()),
  };
}

void Node::rebuild_epoch_committee_state_locked(std::uint64_t epoch, const char* reason, bool log_summary) {
  if (epoch == 0) return;
  auto checkpoint = finalized_committee_checkpoint_for_height_locked(epoch);
  if (!checkpoint.has_value() || checkpoint->ordered_members.empty()) {
    if (log_summary) {
      log_line(std::string("epoch-committee-rebuilt reason=") + reason + " epoch=" + std::to_string(epoch) +
               " status=skipped missing_finalized_checkpoint");
    }
    return;
  }

  auto effective_checkpoint = *checkpoint;

  auto snapshot = epoch_committee_snapshot_from_checkpoint(effective_checkpoint);
  auto existing = db_.get_epoch_committee_snapshot(epoch);
  const bool same_snapshot = existing.has_value() && same_epoch_committee_snapshot(*existing, snapshot);
  const bool should_be_frozen = epoch_committee_closed_locked(epoch);
  const auto expected_marker = make_epoch_committee_freeze_marker_locked(snapshot);
  auto existing_marker = db_.get_epoch_committee_freeze_marker(epoch);
  const bool same_marker = existing_marker.has_value() && existing_marker->epoch == expected_marker.epoch &&
                           existing_marker->challenge_anchor == expected_marker.challenge_anchor &&
                           existing_marker->member_count == expected_marker.member_count;

  (void)db_.put_epoch_committee_snapshot(snapshot);
  if (should_be_frozen) (void)db_.put_epoch_committee_freeze_marker(expected_marker);

  if (log_summary) {
    log_line(std::string("epoch-committee-rebuilt reason=") + reason + " epoch=" + std::to_string(epoch) +
             " committee=" + std::to_string(snapshot.ordered_members.size()) +
             " closed=" + (should_be_frozen ? "yes" : "no") +
             " snapshot=" + (same_snapshot ? "verified" : "rewritten") +
             " best_index=ignored-for-finalized-checkpoint" +
             " freeze_marker=" + (should_be_frozen ? (same_marker ? "verified" : "rewritten") : "open"));
  }
  local_epoch_tickets_.erase(epoch);
}

void Node::maybe_finalize_epoch_committees_locked() {
  const std::uint64_t current_epoch = current_epoch_ticket_epoch_locked();
  if (last_open_epoch_ticket_epoch_ == 0) {
    last_open_epoch_ticket_epoch_ = current_epoch;
    return;
  }
  if (current_epoch <= last_open_epoch_ticket_epoch_) return;
  const std::uint64_t step = std::max<std::uint64_t>(1, cfg_.network.committee_epoch_blocks);
  for (std::uint64_t epoch = last_open_epoch_ticket_epoch_; epoch < current_epoch; epoch += step) {
    rebuild_epoch_committee_state_locked(epoch, "epoch-closed", true);
    auto snapshot = db_.get_epoch_committee_snapshot(epoch);
    const std::size_t members = snapshot.has_value() ? snapshot->ordered_members.size() : 0;
    log_line("epoch-committee-closed epoch=" + std::to_string(epoch) + " frozen=" +
             (epoch_committee_frozen_locked(epoch) ? "yes" : "no") + " committee=" + std::to_string(members));
  }
  last_open_epoch_ticket_epoch_ = current_epoch;
}

bool Node::ensure_required_epoch_committee_state_locked() {
  const std::uint64_t height = finalized_height_ + 1;
  if (bootstrap_template_mode_ && finalized_height_ == 0 && bootstrap_validator_pubkey_.has_value()) {
    const auto active = validators_.active_sorted(1);
    if (active.size() == 1 && active.front() == *bootstrap_validator_pubkey_) return true;
  }
  if (bootstrap_template_mode_ && finalized_height_ == 0 && !bootstrap_validator_pubkey_.has_value()) return true;
  if (epoch_committee_for_next_height_locked(height, 0).empty()) {
    log_line("epoch-committee-startup next_height=" + std::to_string(height) +
             " reason=missing-finalized-committee-checkpoint");
    return false;
  }
  return true;
}

std::string Node::required_epoch_committee_state_reason_locked(std::uint64_t epoch) const {
  auto snapshot = db_.get_epoch_committee_snapshot(epoch);
  auto marker = db_.get_epoch_committee_freeze_marker(epoch);
  const auto tickets = db_.load_epoch_tickets(epoch);
  if (!snapshot.has_value() && !marker.has_value() && tickets.empty()) return "missing-snapshot-freeze-marker-and-tickets";
  if (!snapshot.has_value()) return "missing-snapshot";
  if (snapshot->ordered_members.empty()) return "empty-committee";
  if (!marker.has_value()) return "missing-freeze-marker";
  if (marker->challenge_anchor != snapshot->challenge_anchor) return "freeze-marker-anchor-mismatch";
  if (marker->member_count != snapshot->ordered_members.size()) return "freeze-marker-member-count-mismatch";
  if (tickets.empty()) return "tickets-missing";
  return "unknown";
}

bool Node::ensure_required_epoch_committee_state_startup() {
  std::lock_guard<std::mutex> lk(mu_);
  return ensure_required_epoch_committee_state_locked();
}

void Node::request_epoch_tickets(int peer_id, std::uint64_t epoch, std::uint32_t max_tickets) {
  const bool ok =
      p2p_.send_to(peer_id, p2p::MsgType::GET_EPOCH_TICKETS, p2p::ser_get_epoch_tickets(p2p::GetEpochTicketsMsg{epoch, max_tickets}));
  log_line("epoch-reconcile-request peer_id=" + std::to_string(peer_id) + " epoch=" + std::to_string(epoch) +
           " max_tickets=" + std::to_string(max_tickets) + " status=" + (ok ? "ok" : "failed"));
}

void Node::maybe_request_epoch_ticket_reconciliation_locked(std::uint64_t now_ms) {
  const std::uint64_t open_epoch = current_epoch_ticket_epoch_locked();
  const std::uint64_t step = std::max<std::uint64_t>(1, cfg_.network.committee_epoch_blocks);
  std::vector<std::uint64_t> epochs;
  if (auto required = epoch_committee_snapshot_epoch_for_height_locked(finalized_height_ + 1); required.has_value()) {
    for (std::uint64_t epoch = *required; epoch <= open_epoch; epoch += step) {
      epochs.push_back(epoch);
      if (epochs.size() >= 4) break;
    }
  }
  if (epochs.empty() || epochs.back() != open_epoch) epochs.push_back(open_epoch);
  const std::uint64_t interval = std::max<std::uint64_t>(3000, static_cast<std::uint64_t>(cfg_.network.round_timeout_ms));
  for (int peer_id : p2p_.peer_ids()) {
    const auto info = p2p_.get_peer_info(peer_id);
    if (!info.established()) continue;
    for (const auto epoch : epochs) {
      if (epoch != open_epoch && epoch_committee_frozen_locked(epoch) && db_.get_epoch_committee_snapshot(epoch).has_value()) {
        auto snapshot = db_.get_epoch_committee_snapshot(epoch);
        if (snapshot.has_value() && !snapshot->ordered_members.empty()) continue;
      }
      auto key = std::make_pair(peer_id, epoch);
      auto it = epoch_ticket_request_ms_.find(key);
      if (it != epoch_ticket_request_ms_.end() && now_ms < it->second + interval) continue;
      epoch_ticket_request_ms_[key] = now_ms;
      request_epoch_tickets(peer_id, epoch, 512);
    }
  }
}

std::optional<consensus::EpochTicket> Node::mine_local_epoch_ticket_locked(std::uint64_t height) const {
  if (!validators_.is_active_for_height(local_key_.public_key, height)) return std::nullopt;
  const auto epoch = consensus::committee_epoch_start(height, cfg_.network.committee_epoch_blocks);
  const auto anchor = epoch_ticket_challenge_anchor_locked(height);
  auto local_info = validators_.get(local_key_.public_key);
  if (!local_info.has_value()) return std::nullopt;
  auto ticket = consensus::best_epoch_ticket_for_operator_id(
      epoch, anchor, consensus::canonical_operator_id(local_key_.public_key, *local_info), height);
  if (!ticket.has_value()) return std::nullopt;
  const auto difficulty_bits = ticket_difficulty_bits_for_epoch_locked(epoch, validators_.active_sorted(height).size());
  if (!consensus::epoch_ticket_meets_difficulty(*ticket, difficulty_bits)) return std::nullopt;
  return ticket;
}

bool Node::handle_epoch_ticket_locked(const consensus::EpochTicket& ticket, bool from_network, int from_peer_id,
                                      std::string* reject_reason, bool allow_closed_epoch_reconcile) {
  consensus::EpochTicket stored = ticket;
  stored.origin = from_network ? consensus::EpochTicketOrigin::NETWORK : consensus::EpochTicketOrigin::LOCAL;
  const std::uint64_t current_epoch = current_epoch_ticket_epoch_locked();
  if (!from_network) {
    auto local_info = validators_.get(local_key_.public_key);
    if (!local_info.has_value()) {
      if (reject_reason) *reject_reason = "local-validator-missing";
      return false;
    }
    const auto expected_participant = consensus::canonical_operator_id(local_key_.public_key, *local_info);
    if (stored.participant_pubkey != expected_participant) {
      if (reject_reason) *reject_reason = "local-participant-mismatch";
      return false;
    }
    if (!validators_.is_active_for_height(local_key_.public_key, finalized_height_ + 1)) {
      if (reject_reason) *reject_reason = "local-non-active";
      return false;
    }
  }
  if (stored.epoch == 0) {
    if (reject_reason) *reject_reason = "epoch-zero";
    return false;
  }
  if (epoch_committee_closed_locked(stored.epoch)) {
    if (allow_closed_epoch_reconcile && !epoch_committee_frozen_locked(stored.epoch)) {
      // Explicit reconciliation may refill a missing closed epoch before the
      // local node has reconstructed and frozen that epoch.
    } else {
      if (reject_reason) *reject_reason = "epoch-closed";
      return false;
    }
  }
  if (stored.epoch > current_epoch) {
    if (reject_reason) *reject_reason = "future-epoch";
    return false;
  }
  if (stored.epoch != current_epoch && !allow_closed_epoch_reconcile) {
    if (reject_reason) *reject_reason = "wrong-open-epoch";
    return false;
  }
  if (allow_closed_epoch_reconcile && stored.epoch != current_epoch && !epoch_committee_closed_locked(stored.epoch)) {
    if (reject_reason) *reject_reason = "reconcile-nonclosed-epoch";
    return false;
  }
  if (stored.challenge_anchor != epoch_ticket_challenge_anchor_locked(stored.epoch)) {
    if (reject_reason) *reject_reason = "bad-anchor";
    return false;
  }
  if (!consensus::validate_epoch_ticket(stored)) {
    if (reject_reason) *reject_reason = "bad-work";
    return false;
  }
  const auto difficulty_bits =
      ticket_difficulty_bits_for_epoch_locked(stored.epoch, validators_.active_sorted(stored.epoch).size());
  if (!consensus::epoch_ticket_meets_difficulty(stored, difficulty_bits)) {
    if (reject_reason) *reject_reason = "below-difficulty";
    return false;
  }

  auto best = db_.load_best_epoch_tickets(stored.epoch);
  auto it = best.find(stored.participant_pubkey);
  const bool improved = it == best.end() || consensus::epoch_ticket_better(stored, it->second);
  if (!improved) {
    if (reject_reason) *reject_reason = "not-best";
    return false;
  }

  (void)db_.put_epoch_ticket(stored);
  best[stored.participant_pubkey] = stored;
  (void)db_.put_best_epoch_ticket(stored);
  const auto snapshot = consensus::derive_epoch_committee_snapshot(stored.epoch, stored.challenge_anchor, best,
                                                                   cfg_.max_committee, &validators_.all(), true);
  (void)db_.put_epoch_committee_snapshot(snapshot);

  if (!from_network) {
    local_epoch_tickets_[stored.epoch] = stored;
  }
  (void)from_peer_id;
  return true;
}

bool Node::handle_epoch_ticket(const consensus::EpochTicket& ticket, bool from_network, int from_peer_id,
                               bool allow_closed_epoch_reconcile) {
  std::lock_guard<std::mutex> lk(mu_);
  std::string reject_reason;
  const bool accepted =
      handle_epoch_ticket_locked(ticket, from_network, from_peer_id, &reject_reason, allow_closed_epoch_reconcile);
  if (!accepted) {
    log_line("epoch-ticket-rejected peer_id=" + std::to_string(from_peer_id) + " epoch=" + std::to_string(ticket.epoch) +
             " participant=" + short_pub_hex(ticket.participant_pubkey) + " reason=" + reject_reason);
  } else {
    log_line(std::string(from_network ? "epoch-ticket-recv-accepted" : "epoch-ticket-local-accepted") +
             " peer_id=" + std::to_string(from_peer_id) + " epoch=" + std::to_string(ticket.epoch) +
             " participant=" + short_pub_hex(ticket.participant_pubkey) + " work=" + short_hash_hex(ticket.work_hash));
  }
  return accepted;
}

void Node::handle_message(int peer_id, std::uint16_t msg_type, const Bytes& payload) {
  if (!p2p::is_known_message_type(msg_type)) {
    score_peer(peer_id, p2p::MisbehaviorReason::INVALID_PAYLOAD, "unknown-msg-type");
    return;
  }

  const Hash32 payload_id = message_payload_id(payload);
  bool known_invalid = false;
  bool rate_limited = false;
  {
    std::lock_guard<std::mutex> lk(mu_);
    if (invalid_message_payloads_.contains(payload_id)) {
      known_invalid = true;
    } else {
      rate_limited = !check_rate_limit_locked(peer_id, msg_type);
    }
  }
  if (known_invalid) {
    score_peer(peer_id, p2p::MisbehaviorReason::DUPLICATE_SPAM, "known-invalid-payload");
    return;
  }
  if (rate_limited) {
    score_peer(peer_id, p2p::MisbehaviorReason::RATE_LIMIT, "msg-rate");
    return;
  }

  if (msg_type == p2p::MsgType::VERSION) {
    auto v = p2p::de_version(payload);
    if (!v.has_value()) {
      score_peer(peer_id, p2p::MisbehaviorReason::INVALID_PAYLOAD, "bad-version");
      return;
    }
    // Duplicate VERSION on an established connection is intentional in bootstrap-template
    // mode: after self-bootstrap, the node refreshes peer metadata with the bound
    // bootstrap validator identity. This handler keeps VERSION processing idempotent.
    log_line("recv " + std::string(msg_type_name(msg_type)) + " peer_id=" + std::to_string(peer_id) +
             " start_height=" + std::to_string(v->start_height) + " start_hash=" + short_hash_hex(v->start_hash));
    if (v->network_id != cfg_.network.network_id) {
      {
        std::lock_guard<std::mutex> lk(mu_);
        ++rejected_network_id_;
      }
      log_line("reject-version peer_id=" + std::to_string(peer_id) + " reason=network-id-mismatch");
      score_peer(peer_id, p2p::MisbehaviorReason::INVALID_PAYLOAD, "network-id-mismatch");
      p2p_.disconnect_peer(peer_id);
      return;
    }
    if (v->proto_version != static_cast<std::uint32_t>(cfg_.network.protocol_version)) {
      {
        std::lock_guard<std::mutex> lk(mu_);
        ++rejected_protocol_version_;
      }
      log_line("reject-version peer_id=" + std::to_string(peer_id) + " reason=unsupported-protocol peer_proto=" +
               std::to_string(v->proto_version) + " local_proto=" + std::to_string(cfg_.network.protocol_version));
      p2p_.disconnect_peer(peer_id);
      return;
    }
    const std::string local_genesis = ascii_lower(chain_id_.genesis_hash_hex);
    const std::string local_nid = ascii_lower(network_id_hex(cfg_.network));
    const auto peer_genesis = software_fingerprint_value(v->node_software_version, "genesis");
    const auto peer_nid = software_fingerprint_value(v->node_software_version, "network_id");
    const auto peer_bootstrap = software_fingerprint_value(v->node_software_version, "bootstrap_validator");
    const auto peer_validator = software_fingerprint_value(v->node_software_version, "validator_pubkey");
    if (peer_genesis.has_value() && ascii_lower(*peer_genesis) != local_genesis) {
      log_line("reject-version peer_id=" + std::to_string(peer_id) + " reason=genesis-fingerprint-mismatch");
      p2p_.disconnect_peer(peer_id);
      return;
    }
    if (peer_nid.has_value() && ascii_lower(*peer_nid) != local_nid) {
      log_line("reject-version peer_id=" + std::to_string(peer_id) + " reason=network-id-fingerprint-mismatch");
      p2p_.disconnect_peer(peer_id);
      return;
    }
    if (peer_bootstrap.has_value()) {
      auto b = hex_decode(*peer_bootstrap);
      if (b && b->size() == 32) {
        PubKey32 pub{};
        std::copy(b->begin(), b->end(), pub.begin());
        (void)maybe_adopt_bootstrap_validator_from_peer(peer_id, pub, v->start_height, "version-bootstrap");
      }
    }
    if (peer_validator.has_value()) {
      auto b = hex_decode(*peer_validator);
      if (b && b->size() == 32) {
        PubKey32 pub{};
        std::copy(b->begin(), b->end(), pub.begin());
        {
          std::lock_guard<std::mutex> lk(mu_);
          peer_validator_pubkeys_[peer_id] = pub;
        }
        if (!peer_bootstrap.has_value()) {
          (void)maybe_adopt_bootstrap_validator_from_peer(peer_id, pub, v->start_height, "version-validator-fallback");
        }
        if (pub == local_key_.public_key) {
          const auto info = p2p_.get_peer_info(peer_id);
          bool should_log = false;
          std::string display_endpoint = info.endpoint;
          {
            std::lock_guard<std::mutex> lk(mu_);
            peer_validator_pubkeys_.erase(peer_id);
            should_log = suppress_self_endpoint_locked(info.endpoint);
            if (!info.ip.empty()) {
              should_log = suppress_self_endpoint_locked(info.ip + ":" + std::to_string(cfg_.p2p_port)) || should_log;
              if (display_endpoint.empty()) display_endpoint = info.ip + ":" + std::to_string(cfg_.p2p_port);
            }
          }
          if (should_log) {
            log_line("self-peer-rejected endpoint=" + display_endpoint + " reason=identity-match");
          }
          p2p_.disconnect_peer(peer_id);
          return;
        }
      }
    }
    p2p_.set_peer_handshake_meta(peer_id, v->proto_version, v->network_id, v->feature_flags);
    p2p_.mark_handshake_rx(peer_id, true, false);

    auto info = p2p_.get_peer_info(peer_id);
    if (!info.version_tx) send_version(peer_id);

    {
      auto i = p2p_.get_peer_info(peer_id);
      (void)i;
    }

    maybe_send_verack(peer_id);
    return;
  }

  if (msg_type == p2p::MsgType::VERACK) {
    log_line("recv " + std::string(msg_type_name(msg_type)) + " peer_id=" + std::to_string(peer_id));
    p2p_.mark_handshake_rx(peer_id, false, true);
    maybe_request_getaddr(peer_id);
    send_finalized_tip(peer_id);
    request_finalized_tip(peer_id);
    send_ingress_tips(peer_id);
    request_ingress_tips(peer_id);
    {
      std::lock_guard<std::mutex> lk(mu_);
      const auto current_height = finalized_height_ + 1;
      if (reconnect_round_reset_pending_ && !single_node_bootstrap_active_locked(current_height)) {
        reconnect_round_reset_pending_ = false;
        current_round_ = 0;
        proposed_in_round_.clear();
        local_vote_reservations_.clear();
        local_timeout_vote_reservations_.clear();
        votes_.clear_height(current_height);
        timeout_votes_.clear_height(current_height);
        round_started_ms_ = now_ms();
        log_line("peer-reconnect-reset height=" + std::to_string(current_height) + " reason=peers-restored");
      }
    }
    auto pi = p2p_.get_peer_info(peer_id);
    auto na = addrman_address_for_peer(pi);
    if (na.has_value()) {
      std::lock_guard<std::mutex> lk(mu_);
      addrman_.mark_success(*na, now_unix());
    }
    return;
  }

  const auto info = p2p_.get_peer_info(peer_id);
  if (!info.established()) {
    const bool bootstrap_sync_msg =
        msg_type == p2p::MsgType::GET_FINALIZED_TIP || msg_type == p2p::MsgType::FINALIZED_TIP ||
        msg_type == p2p::MsgType::GET_TRANSITION || msg_type == p2p::MsgType::TRANSITION ||
        msg_type == p2p::MsgType::GET_INGRESS_TIPS || msg_type == p2p::MsgType::INGRESS_TIPS ||
        msg_type == p2p::MsgType::GET_INGRESS_RANGE || msg_type == p2p::MsgType::INGRESS_RANGE;
    // After VERSION exchange and our VERACK transmit, the peer may already start
    // sync bootstrap traffic before we have observed its VERACK locally. Allow
    // these messages through instead of misclassifying them as pre-handshake
    // consensus traffic and dropping the first finalized-tip/block sync step.
    if (bootstrap_sync_msg && info.version_rx && info.version_tx && info.verack_tx) {
      // fall through
    } else {
      if (msg_type == p2p::MsgType::ADDR || msg_type == p2p::MsgType::GETADDR) {
        log_line("drop-addr peer_id=" + std::to_string(peer_id) + " reason=pre-handshake");
      }
      {
        std::lock_guard<std::mutex> lk(mu_);
        ++rejected_pre_handshake_;
      }
      score_peer(peer_id, p2p::MisbehaviorReason::PRE_HANDSHAKE_CONSENSUS, "pre-handshake-msg");
      return;
    }
  }

  switch (msg_type) {
    case p2p::MsgType::GET_FINALIZED_TIP: {
      log_line("recv " + std::string(msg_type_name(msg_type)) + " peer_id=" + std::to_string(peer_id));
      send_finalized_tip(peer_id);
      break;
    }
    case p2p::MsgType::FINALIZED_TIP: {
      auto tip = p2p::de_finalized_tip(payload);
      if (!tip.has_value()) {
        score_peer(peer_id, p2p::MisbehaviorReason::INVALID_PAYLOAD, "bad-finalized-tip");
        return;
      }
      log_line("recv " + std::string(msg_type_name(msg_type)) + " peer_id=" + std::to_string(peer_id) +
               " height=" + std::to_string(tip->height) + " hash=" + short_hash_hex(tip->hash));
      {
        std::lock_guard<std::mutex> lk(mu_);
        peer_finalized_tips_[peer_id] = *tip;
      }
      {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = peer_validator_pubkeys_.find(peer_id);
        if (it != peer_validator_pubkeys_.end()) {
          (void)maybe_adopt_bootstrap_validator_from_peer(peer_id, it->second, tip->height, "finalized-tip-fallback");
        }
        (void)maybe_request_forward_sync_block_locked(peer_id);
        const std::uint64_t retry_ms =
            std::max<std::uint64_t>(3000, static_cast<std::uint64_t>(cfg_.network.round_timeout_ms));
        const std::uint64_t tms = now_ms();
        auto req_it = requested_sync_artifacts_.find(tip->hash);
        const bool request_stale = req_it == requested_sync_artifacts_.end() || tms >= req_it->second + retry_ms;
        const bool have_tip_artifact = db_.get_frontier_transition(tip->hash).has_value();
        if (tip->height > finalized_height_ && !have_tip_artifact && request_stale) {
          log_line("request-sync-tip-transition peer_id=" + std::to_string(peer_id) + " remote_height=" +
                   std::to_string(tip->height) + " remote_hash=" + short_hash_hex(tip->hash));
          requested_sync_artifacts_[tip->hash] = tms;
          auto req = p2p::GetTransitionMsg{tip->hash};
          (void)p2p_.send_to(peer_id, p2p::MsgType::GET_TRANSITION, p2p::ser_get_transition(req));
        }
      }
      request_ingress_tips(peer_id);
      break;
    }
    case p2p::MsgType::GET_INGRESS_TIPS: {
      auto req = p2p::de_get_ingress_tips(payload);
      if (!req.has_value()) {
        score_peer(peer_id, p2p::MisbehaviorReason::INVALID_PAYLOAD, "bad-get-ingress-tips");
        return;
      }
      log_line("recv " + std::string(msg_type_name(msg_type)) + " peer_id=" + std::to_string(peer_id));
      send_ingress_tips(peer_id);
      break;
    }
    case p2p::MsgType::INGRESS_TIPS: {
      auto tips = p2p::de_ingress_tips(payload);
      if (!tips.has_value()) {
        score_peer(peer_id, p2p::MisbehaviorReason::INVALID_PAYLOAD, "bad-ingress-tips");
        return;
      }
      std::ostringstream oss;
      oss << "recv " << msg_type_name(msg_type) << " peer_id=" << peer_id << " tips=";
      for (std::size_t lane = 0; lane < tips->lane_tips.size(); ++lane) {
        if (lane) oss << ",";
        oss << lane << ":" << tips->lane_tips[lane];
      }
      log_line(oss.str());
      std::lock_guard<std::mutex> lk(mu_);
      (void)handle_ingress_tips_locked(peer_id, *tips);
      break;
    }
    case p2p::MsgType::GET_INGRESS_RANGE: {
      auto req = p2p::de_get_ingress_range(payload);
      if (!req.has_value() || req->lane >= INGRESS_LANE_COUNT || req->from_seq == 0 || req->to_seq < req->from_seq) {
        score_peer(peer_id, p2p::MisbehaviorReason::INVALID_INGRESS, "bad-get-ingress-range");
        return;
      }
      const std::uint64_t requested_count = req->to_seq - req->from_seq + 1;
      if (requested_count > kMaxIngressRangeRequestRecords) {
        log_line("ingress-range-request-clamped peer_id=" + std::to_string(peer_id) + " lane=" +
                 std::to_string(req->lane) + " requested=[" + std::to_string(req->from_seq) + "," +
                 std::to_string(req->to_seq) + "] limit=" + std::to_string(kMaxIngressRangeRequestRecords));
        req->to_seq = req->from_seq + static_cast<std::uint64_t>(kMaxIngressRangeRequestRecords) - 1;
      }
      log_line("recv " + std::string(msg_type_name(msg_type)) + " peer_id=" + std::to_string(peer_id) +
               " lane=" + std::to_string(req->lane) + " range=[" + std::to_string(req->from_seq) + "," +
               std::to_string(req->to_seq) + "]");
      p2p::IngressRangeMsg msg;
      msg.lane = req->lane;
      msg.from_seq = req->from_seq;
      msg.to_seq = req->to_seq;
      bool complete = true;
      for (std::uint64_t seq = req->from_seq; seq <= req->to_seq; ++seq) {
        auto cert_bytes = db_.get_ingress_certificate(req->lane, seq);
        if (!cert_bytes.has_value()) {
          complete = false;
          break;
        }
        auto cert = IngressCertificate::parse(*cert_bytes);
        if (!cert.has_value()) {
          complete = false;
          break;
        }
        auto tx_bytes = db_.get_ingress_bytes(cert->txid);
        if (!tx_bytes.has_value()) {
          complete = false;
          break;
        }
        msg.records.push_back(p2p::IngressRecordMsg{*cert, *tx_bytes});
        if (msg.records.size() > kMaxIngressRangeResponseRecords ||
            ingress_range_wire_size(msg) > kMaxIngressRangeResponseBytes) {
          complete = false;
          break;
        }
      }
      if (!complete) {
        log_line("ingress-range-response-skipped peer_id=" + std::to_string(peer_id) + " lane=" +
                 std::to_string(req->lane) + " range=[" + std::to_string(req->from_seq) + "," +
                 std::to_string(req->to_seq) + "] reason=incomplete-local-range");
        return;
      }
      const bool ok = p2p_.send_to(peer_id, p2p::MsgType::INGRESS_RANGE, p2p::ser_ingress_range(msg), true);
      log_line("send-ingress-range peer_id=" + std::to_string(peer_id) + " lane=" + std::to_string(req->lane) +
               " range=[" + std::to_string(req->from_seq) + "," + std::to_string(req->to_seq) +
               "] status=" + (ok ? "ok" : "failed"));
      break;
    }
    case p2p::MsgType::INGRESS_RANGE: {
      auto range = p2p::de_ingress_range(payload);
      if (!range.has_value()) {
        score_peer(peer_id, p2p::MisbehaviorReason::INVALID_INGRESS, "bad-ingress-range");
        return;
      }
      log_line("recv " + std::string(msg_type_name(msg_type)) + " peer_id=" + std::to_string(peer_id) +
               " lane=" + std::to_string(range->lane) + " range=[" + std::to_string(range->from_seq) + "," +
               std::to_string(range->to_seq) + "] records=" + std::to_string(range->records.size()));
      std::lock_guard<std::mutex> lk(mu_);
      std::string ingress_error;
      if (!handle_ingress_range_locked(peer_id, *range, &ingress_error)) {
        const auto reason = ingress_fault_reason_for(ingress_error);
        const std::string note = ingress_error.empty() ? "invalid-ingress-range" : ingress_error;
        score_peer_locked(peer_id, reason, note);
      }
      break;
    }
    case p2p::MsgType::INGRESS_RECORD: {
      auto record = p2p::de_ingress_record(payload);
      if (!record.has_value()) {
        score_peer(peer_id, p2p::MisbehaviorReason::INVALID_INGRESS, "bad-ingress-record");
        return;
      }
      log_line("recv " + std::string(msg_type_name(msg_type)) + " peer_id=" + std::to_string(peer_id) +
               " lane=" + std::to_string(record->certificate.lane) +
               " seq=" + std::to_string(record->certificate.seq) +
               " txid=" + short_hash_hex(record->certificate.txid));
      std::lock_guard<std::mutex> lk(mu_);
      std::string ingress_error;
      bool appended = false;
      if (!handle_ingress_record_locked(peer_id, *record, &appended, &ingress_error)) {
        const auto reason = ingress_fault_reason_for(ingress_error);
        const std::string note = ingress_error.empty() ? "invalid-ingress-record" : ingress_error;
        score_peer_locked(peer_id, reason, note);
        return;
      }
      if (appended) broadcast_ingress_record(record->certificate, record->tx_bytes, peer_id);
      break;
    }
    case p2p::MsgType::GET_TRANSITION: {
      auto gb = p2p::de_get_transition(payload);
      if (!gb.has_value()) {
        score_peer(peer_id, p2p::MisbehaviorReason::INVALID_PAYLOAD, "bad-get-transition");
        return;
      }
      log_line("recv " + std::string(msg_type_name(msg_type)) + " peer_id=" + std::to_string(peer_id) +
               " hash=" + short_hash_hex(gb->hash));
      auto transition_bytes = db_.get_frontier_transition(gb->hash);
      if (!transition_bytes.has_value()) return;
      auto transition = FrontierTransition::parse(*transition_bytes);
      if (!transition.has_value()) return;
      auto ordered_records = db_.load_ingress_slice(transition->prev_frontier, transition->next_frontier);
      if (ordered_records.size() != transition->next_frontier - transition->prev_frontier) return;
      p2p::TransitionMsg msg;
      msg.frontier_proposal_bytes = FrontierProposal{*transition, ordered_records}.serialize();
      msg.certificate = db_.get_finality_certificate_by_height(transition->height);
      const bool ok = p2p_.send_to(peer_id, p2p::MsgType::TRANSITION, p2p::ser_transition(msg));
      log_line("send-frontier peer_id=" + std::to_string(peer_id) + " height=" + std::to_string(transition->height) +
               " hash=" + short_hash_hex(gb->hash) + " status=" + (ok ? "ok" : "failed"));
      break;
    }
    case p2p::MsgType::GET_TRANSITION_BY_HEIGHT: {
      auto gbh = p2p::de_get_transition_by_height(payload);
      if (!gbh.has_value()) {
        score_peer(peer_id, p2p::MisbehaviorReason::INVALID_PAYLOAD, "bad-get-transition-by-height");
        return;
      }
      log_line("recv " + std::string(msg_type_name(msg_type)) + " peer_id=" + std::to_string(peer_id) +
               " height=" + std::to_string(gbh->height));
      auto bh = db_.get_height_hash(gbh->height);
      if (!bh.has_value()) return;
      auto transition_bytes = db_.get_frontier_transition(*bh);
      if (!transition_bytes.has_value()) return;
      auto transition = FrontierTransition::parse(*transition_bytes);
      if (!transition.has_value()) return;
      auto ordered_records = db_.load_ingress_slice(transition->prev_frontier, transition->next_frontier);
      if (ordered_records.size() != transition->next_frontier - transition->prev_frontier) return;
      p2p::TransitionMsg msg;
      msg.frontier_proposal_bytes = FrontierProposal{*transition, ordered_records}.serialize();
      msg.certificate = db_.get_finality_certificate_by_height(transition->height);
      const bool ok = p2p_.send_to(peer_id, p2p::MsgType::TRANSITION, p2p::ser_transition(msg));
      log_line("send-frontier-by-height peer_id=" + std::to_string(peer_id) +
               " requested_height=" + std::to_string(gbh->height) + " hash=" + short_hash_hex(*bh) +
               " status=" + (ok ? "ok" : "failed"));
      break;
    }
    case p2p::MsgType::EPOCH_TICKET: {
      auto t = p2p::de_epoch_ticket(payload);
      if (!t.has_value()) {
        score_peer(peer_id, p2p::MisbehaviorReason::INVALID_PAYLOAD, "bad-epoch-ticket");
        return;
      }
      log_line("recv " + std::string(msg_type_name(msg_type)) + " peer_id=" + std::to_string(peer_id) +
               " epoch=" + std::to_string(t->ticket.epoch) + " participant=" + short_pub_hex(t->ticket.participant_pubkey));
      (void)handle_epoch_ticket(t->ticket, true, peer_id);
      break;
    }
    case p2p::MsgType::GET_EPOCH_TICKETS: {
      auto req = p2p::de_get_epoch_tickets(payload);
      if (!req.has_value()) {
        score_peer(peer_id, p2p::MisbehaviorReason::INVALID_PAYLOAD, "bad-get-epoch-tickets");
        return;
      }
      std::vector<consensus::EpochTicket> tickets;
      bool closed = false;
      {
        std::lock_guard<std::mutex> lk(mu_);
        tickets = db_.load_epoch_tickets(req->epoch);
        closed = epoch_committee_closed_locked(req->epoch);
      }
      const std::size_t limit = std::min<std::size_t>(tickets.size(), std::max<std::uint32_t>(1, req->max_tickets));
      tickets.resize(limit);
      const bool ok = p2p_.send_to(
          peer_id, p2p::MsgType::EPOCH_TICKETS, p2p::ser_epoch_tickets(p2p::EpochTicketsMsg{req->epoch, closed, tickets}));
      log_line("epoch-reconcile-response peer_id=" + std::to_string(peer_id) + " epoch=" + std::to_string(req->epoch) +
               " tickets=" + std::to_string(tickets.size()) + " closed=" + (closed ? "yes" : "no") +
               " status=" + (ok ? "ok" : "failed"));
      break;
    }
    case p2p::MsgType::EPOCH_TICKETS: {
      auto resp = p2p::de_epoch_tickets(payload);
      if (!resp.has_value()) {
        score_peer(peer_id, p2p::MisbehaviorReason::INVALID_PAYLOAD, "bad-epoch-tickets");
        return;
      }
      std::size_t accepted = 0;
      std::size_t rejected = 0;
      for (const auto& ticket : resp->tickets) {
        if (handle_epoch_ticket(ticket, true, peer_id, resp->epoch_closed)) {
          ++accepted;
        } else {
          ++rejected;
        }
      }
      if (resp->epoch_closed) {
        std::lock_guard<std::mutex> lk(mu_);
        rebuild_epoch_committee_state_locked(resp->epoch, "reconcile-closed", true);
      }
      log_line("epoch-reconcile-recv peer_id=" + std::to_string(peer_id) + " epoch=" + std::to_string(resp->epoch) +
               " tickets=" + std::to_string(resp->tickets.size()) + " accepted=" + std::to_string(accepted) +
               " rejected=" + std::to_string(rejected) + " closed=" + (resp->epoch_closed ? "yes" : "no"));
      break;
    }
    case p2p::MsgType::TRANSITION: {
      auto b = p2p::de_transition(payload);
      if (!b.has_value()) {
        std::lock_guard<std::mutex> lk(mu_);
        invalid_message_payloads_.insert(payload_id);
        score_peer_locked(peer_id, p2p::MisbehaviorReason::INVALID_PAYLOAD, "bad-block-msg");
        return;
      }
      {
        std::lock_guard<std::mutex> lk(mu_);
        if (accepted_block_payloads_.contains(payload_id)) return;
      }
      auto proposal = FrontierProposal::parse(b->frontier_proposal_bytes);
      if (!proposal.has_value()) {
        std::lock_guard<std::mutex> lk(mu_);
        invalid_message_payloads_.insert(payload_id);
        score_peer_locked(peer_id, p2p::MisbehaviorReason::INVALID_PAYLOAD, "bad-frontier-parse");
        return;
      }
      log_line("recv " + std::string(msg_type_name(msg_type)) + " peer_id=" + std::to_string(peer_id) +
               " height=" + std::to_string(proposal->transition.height) + " hash=" +
               short_hash_hex(proposal->transition.transition_id()) + " prev=" +
               short_hash_hex(proposal->transition.prev_finalized_hash));
      {
        std::lock_guard<std::mutex> lk(mu_);
        bool accepted = false;
        if (proposal->transition.height > finalized_height_ + 1 && b->certificate.has_value()) {
          accepted = maybe_buffer_sync_frontier_locked(*proposal, b->certificate, peer_id);
          if (accepted) (void)maybe_apply_buffered_sync_frontiers_locked(peer_id);
        } else {
          accepted = handle_frontier_block_locked(*proposal, b->certificate, peer_id, true);
          if (accepted) (void)maybe_apply_buffered_sync_frontiers_locked(peer_id);
        }
        if (accepted) accepted_block_payloads_.insert(payload_id);
      }
      break;
    }
    case p2p::MsgType::PROPOSE: {
      auto p = p2p::de_propose(payload);
      if (!p.has_value()) {
        std::lock_guard<std::mutex> lk(mu_);
        invalid_message_payloads_.insert(payload_id);
        score_peer_locked(peer_id, p2p::MisbehaviorReason::INVALID_PAYLOAD, "bad-propose-msg");
        return;
      }
      log_line("recv " + std::string(msg_type_name(msg_type)) + " peer_id=" + std::to_string(peer_id) +
               " height=" + std::to_string(p->height) + " round=" + std::to_string(p->round));
      {
        std::lock_guard<std::mutex> lk(mu_);
        if (bootstrap_sync_incomplete_locked(peer_id)) {
          log_line("defer-consensus peer_id=" + std::to_string(peer_id) + " type=PROPOSE reason=bootstrap-sync-incomplete" +
                   " local_height=" + std::to_string(finalized_height_));
          return;
        }
      }
      {
        std::lock_guard<std::mutex> lk(mu_);
        if (accepted_propose_payloads_.contains(payload_id)) {
          Hash32 block_id{};
          if (auto proposal = FrontierProposal::parse(p->frontier_proposal_bytes); proposal.has_value()) {
            block_id = proposal->transition.transition_id();
          }
          const std::string result_name = "duplicate";
          log_line("proposal-duplicate-skip peer_id=" + std::to_string(peer_id) +
                   " height=" + std::to_string(p->height) + " round=" + std::to_string(p->round) +
                   " transition=" + short_hash_hex(block_id) + " payload=" +
                   hex_encode(Bytes(payload_id.begin(), payload_id.end())) + " result=" + result_name);
          return;
        }
      }
      const auto propose_result = handle_propose_result(*p, true);
      Hash32 block_id{};
      if (auto proposal = FrontierProposal::parse(p->frontier_proposal_bytes); proposal.has_value()) {
        block_id = proposal->transition.transition_id();
      }
      const char* result_name = propose_result == ProposeHandlingResult::Accepted
                                    ? "accepted"
                                    : (propose_result == ProposeHandlingResult::SoftReject ? "soft-reject" : "hard-reject");
      log_line("proposal-dispatch-result peer_id=" + std::to_string(peer_id) +
               " height=" + std::to_string(p->height) + " round=" + std::to_string(p->round) +
               " transition=" + short_hash_hex(block_id) + " result=" + result_name);
      if (propose_result == ProposeHandlingResult::HardReject) {
        std::lock_guard<std::mutex> lk(mu_);
        invalid_message_payloads_.insert(payload_id);
        score_peer_locked(peer_id, p2p::MisbehaviorReason::INVALID_PROPOSE, "invalid-propose");
      } else if (propose_result == ProposeHandlingResult::Accepted) {
        std::lock_guard<std::mutex> lk(mu_);
        accepted_propose_payloads_.insert(payload_id);
      }
      break;
    }
    case p2p::MsgType::VOTE: {
      auto v = p2p::de_vote(payload);
      if (!v.has_value()) {
        std::lock_guard<std::mutex> lk(mu_);
        invalid_message_payloads_.insert(payload_id);
        score_peer_locked(peer_id, p2p::MisbehaviorReason::INVALID_PAYLOAD, "bad-vote-msg");
        return;
      }
      log_line("recv " + std::string(msg_type_name(msg_type)) + " peer_id=" + std::to_string(peer_id) +
               " height=" + std::to_string(v->vote.height) + " round=" + std::to_string(v->vote.round) +
               " transition=" + short_hash_hex(v->vote.frontier_transition_id));
      {
        std::lock_guard<std::mutex> lk(mu_);
        if (bootstrap_sync_incomplete_locked(peer_id)) {
          log_line("defer-consensus peer_id=" + std::to_string(peer_id) + " type=VOTE reason=bootstrap-sync-incomplete" +
                   " local_height=" + std::to_string(finalized_height_));
          return;
        }
      }
      const auto vote_result = handle_vote_result(v->vote, true, peer_id);
      if (vote_result == VoteHandlingResult::HardReject) {
        std::lock_guard<std::mutex> lk(mu_);
        invalid_message_payloads_.insert(payload_id);
        score_peer_locked(peer_id, p2p::MisbehaviorReason::INVALID_VOTE_SIGNATURE, "invalid-vote");
      }
      break;
    }
    case p2p::MsgType::TIMEOUT_VOTE: {
      auto v = p2p::de_timeout_vote(payload);
      if (!v.has_value()) {
        std::lock_guard<std::mutex> lk(mu_);
        invalid_message_payloads_.insert(payload_id);
        score_peer_locked(peer_id, p2p::MisbehaviorReason::INVALID_PAYLOAD, "bad-timeout-vote-msg");
        return;
      }
      log_line("recv " + std::string(msg_type_name(msg_type)) + " peer_id=" + std::to_string(peer_id) +
               " height=" + std::to_string(v->vote.height) + " round=" + std::to_string(v->vote.round));
      {
        std::lock_guard<std::mutex> lk(mu_);
        if (bootstrap_sync_incomplete_locked(peer_id)) {
          log_line("defer-consensus peer_id=" + std::to_string(peer_id) +
                   " type=TIMEOUT_VOTE reason=bootstrap-sync-incomplete" +
                   " local_height=" + std::to_string(finalized_height_));
          return;
        }
      }
      const auto timeout_result = handle_timeout_vote_result(v->vote, true, peer_id);
      if (timeout_result == TimeoutVoteHandlingResult::HardReject) {
        std::lock_guard<std::mutex> lk(mu_);
        invalid_message_payloads_.insert(payload_id);
        score_peer_locked(peer_id, p2p::MisbehaviorReason::INVALID_VOTE_SIGNATURE, "invalid-timeout-vote");
      }
      break;
    }
    case p2p::MsgType::TX: {
      auto m = p2p::de_tx(payload);
      if (!m.has_value()) {
        std::lock_guard<std::mutex> lk(mu_);
        invalid_message_payloads_.insert(payload_id);
        score_peer_locked(peer_id, p2p::MisbehaviorReason::INVALID_PAYLOAD, "bad-tx-msg");
        return;
      }
      {
        std::lock_guard<std::mutex> lk(mu_);
        if (accepted_tx_payloads_.contains(payload_id)) return;
      }
      auto tx = parse_any_tx(m->tx_bytes);
      if (!tx.has_value()) {
        std::lock_guard<std::mutex> lk(mu_);
        invalid_message_payloads_.insert(payload_id);
        score_peer_locked(peer_id, p2p::MisbehaviorReason::INVALID_PAYLOAD, "bad-tx-parse");
        return;
      }
      if (!handle_tx(*tx, true, peer_id)) {
        std::lock_guard<std::mutex> lk(mu_);
        invalid_message_payloads_.insert(payload_id);
        score_peer_locked(peer_id, p2p::MisbehaviorReason::DUPLICATE_SPAM, "tx-rejected");
      } else {
        std::lock_guard<std::mutex> lk(mu_);
        accepted_tx_payloads_.insert(payload_id);
      }
      break;
    }
    case p2p::MsgType::GETADDR: {
      auto req = p2p::de_getaddr(payload);
      if (!req.has_value()) {
        score_peer(peer_id, p2p::MisbehaviorReason::INVALID_PAYLOAD, "bad-getaddr");
        return;
      }
      p2p::AddrMsg msg;
      {
        std::lock_guard<std::mutex> lk(mu_);
        const auto addrs = addrman_.select_candidates(256, now_unix());
        msg.entries.reserve(addrs.size());
        for (const auto& a : addrs) {
          p2p::AddrEntryMsg e;
          std::array<std::uint8_t, 16> bin{};
          if (inet_pton(AF_INET, a.ip.c_str(), bin.data()) == 1) {
            e.ip_version = 4;
          } else if (inet_pton(AF_INET6, a.ip.c_str(), bin.data()) == 1) {
            e.ip_version = 6;
          } else {
            continue;
          }
          e.ip = bin;
          e.port = a.port;
          e.last_seen_unix = now_unix();
          msg.entries.push_back(e);
        }
      }
      (void)p2p_.send_to(peer_id, p2p::MsgType::ADDR, p2p::ser_addr(msg), true);
      break;
    }
    case p2p::MsgType::ADDR: {
      auto msg = p2p::de_addr(payload);
      if (!msg.has_value()) {
        score_peer(peer_id, p2p::MisbehaviorReason::INVALID_PAYLOAD, "bad-addr");
        return;
      }
      std::lock_guard<std::mutex> lk(mu_);
      for (const auto& e : msg->entries) {
        char ipbuf[INET6_ADDRSTRLEN]{};
        const char* s = nullptr;
        if (e.ip_version == 4) {
          s = inet_ntop(AF_INET, e.ip.data(), ipbuf, sizeof(ipbuf));
        } else if (e.ip_version == 6) {
          s = inet_ntop(AF_INET6, e.ip.data(), ipbuf, sizeof(ipbuf));
        }
        if (!s || e.port == 0) continue;
        const p2p::NetAddress na{std::string(ipbuf), e.port};
        const auto reject = addrman_.validate(na);
        if (reject != p2p::AddrRejectReason::NONE) {
          const std::string reason = (reject == p2p::AddrRejectReason::PORT_MISMATCH)   ? "port"
                                     : (reject == p2p::AddrRejectReason::UNROUTABLE_IP) ? "unroutable"
                                                                                         : "invalid";
          const std::string log_key = reason + ":" + na.ip;
          auto& last = addr_drop_log_ms_[log_key];
          const std::uint64_t now = now_ms();
          if (now > last + 10'000) {
            last = now;
            log_line("drop-addr peer_id=" + std::to_string(peer_id) + " ip=" + na.ip + ":" + std::to_string(na.port) +
                     " reason=" + reason);
          }
          continue;
        }
        addrman_.add_or_update(na, e.last_seen_unix);
      }
      break;
    }
    case p2p::MsgType::PING: {
      auto ping = p2p::de_ping(payload);
      if (!ping.has_value()) {
        score_peer(peer_id, p2p::MisbehaviorReason::INVALID_PAYLOAD, "bad-ping");
        return;
      }
      log_line("recv " + std::string(msg_type_name(msg_type)) + " peer_id=" + std::to_string(peer_id) +
               " nonce=" + std::to_string(ping->nonce));
      const bool ok = p2p_.send_to(peer_id, p2p::MsgType::PONG, p2p::ser_ping(*ping), true);
      log_line(std::string("send ") + msg_type_name(p2p::MsgType::PONG) + " peer_id=" + std::to_string(peer_id) +
               " nonce=" + std::to_string(ping->nonce) + " status=" + (ok ? "ok" : "failed"));
      break;
    }
    case p2p::MsgType::PONG: {
      auto pong = p2p::de_ping(payload);
      if (!pong.has_value()) {
        score_peer(peer_id, p2p::MisbehaviorReason::INVALID_PAYLOAD, "bad-pong");
        return;
      }
      log_line("recv " + std::string(msg_type_name(msg_type)) + " peer_id=" + std::to_string(peer_id) +
               " nonce=" + std::to_string(pong->nonce));
      break;
    }
    default:
      break;
  }
}

Node::ProposeHandlingResult Node::handle_propose_result(const p2p::ProposeMsg& msg, bool from_network,
                                                        std::string* reject_reason) {
  if (from_network && !running_) return ProposeHandlingResult::SoftReject;
  std::optional<Vote> maybe_vote;
  {
    std::lock_guard<std::mutex> lk(mu_);
    auto set_reject_reason = [&](const std::string& reason) {
      if (reject_reason != nullptr) *reject_reason = reason;
    };
    auto log_propose_soft_reject = [&](const std::string& reason, const std::string& extra = std::string()) {
      set_reject_reason(reason);
      log_line("propose-soft-reject height=" + std::to_string(msg.height) + " round=" + std::to_string(msg.round) +
               " reason=" + reason + extra);
    };
    auto log_propose_hard_reject = [&](const std::string& reason, const std::string& extra = std::string()) {
      set_reject_reason(reason);
      log_line("propose-hard-reject height=" + std::to_string(msg.height) + " round=" + std::to_string(msg.round) +
               " reason=" + reason + extra);
    };
    if (from_network && !running_) return ProposeHandlingResult::SoftReject;
    if (msg.height != finalized_height_ + 1) {
      if (msg.height > finalized_height_ + 1) {
        log_propose_soft_reject("future-height", " local_next=" + std::to_string(finalized_height_ + 1));
        return ProposeHandlingResult::SoftReject;
      }
      log_propose_hard_reject("unexpected-height", " local_next=" + std::to_string(finalized_height_ + 1));
      return ProposeHandlingResult::HardReject;
    }
    const bool allow_late_round0_after_first_timeout =
        from_network && msg.round == 0 && current_round_ == 1 && msg.height == finalized_height_ + 1;
    if (msg.round < current_round_ && !allow_late_round0_after_first_timeout) {
      log_propose_soft_reject("stale-round", " local_round=" + std::to_string(current_round_) +
                                                 " justify=" + justify_summary(msg.justify_qc, msg.justify_tc));
      return ProposeHandlingResult::SoftReject;
    }
    if (msg.prev_finalized_hash != finalized_identity_.id) {
      log_propose_hard_reject("prev-hash-mismatch",
                              " local_transition=" + short_hash_hex(finalized_identity_.id) +
                                  " remote_prev=" + short_hash_hex(msg.prev_finalized_hash));
      return ProposeHandlingResult::HardReject;
    }
    auto proposal = FrontierProposal::parse(msg.frontier_proposal_bytes);
    if (!proposal.has_value()) {
      log_propose_hard_reject("frontier-proposal-parse-failed");
      return ProposeHandlingResult::HardReject;
    }
    const auto& transition = proposal->transition;
    if (transition.height != msg.height || transition.round != msg.round) {
      log_propose_hard_reject("header-mismatch", " transition_height=" + std::to_string(transition.height) +
                                                     " transition_round=" + std::to_string(transition.round));
      return ProposeHandlingResult::HardReject;
    }
    if (transition.prev_finalized_hash != msg.prev_finalized_hash) {
      log_propose_hard_reject("prev-hash-mismatch");
      return ProposeHandlingResult::HardReject;
    }
    std::string validation_error;
    if (!validate_frontier_proposal_locked(*proposal, &validation_error)) {
      log_propose_hard_reject(validation_error);
      return ProposeHandlingResult::HardReject;
    }
    if (msg.round > 0 && !msg.justify_qc.has_value() && !msg.justify_tc.has_value()) {
      log_propose_hard_reject("missing-justify", " local_round=" + std::to_string(current_round_) +
                                                   " justify=" + justify_summary(msg.justify_qc, msg.justify_tc));
      return ProposeHandlingResult::HardReject;
    }
    if (msg.justify_qc.has_value()) {
      std::vector<FinalitySig> filtered_qc;
      std::string qc_error;
      if (!verify_quorum_certificate_locked(*msg.justify_qc, &filtered_qc, &qc_error)) {
        log_propose_hard_reject("invalid-qc", " detail=" + qc_error);
        return ProposeHandlingResult::HardReject;
      }
      if (msg.justify_qc->height != msg.height) {
        log_propose_hard_reject("wrong-qc-height");
        return ProposeHandlingResult::HardReject;
      }
      if (msg.justify_qc->round >= msg.round) {
        log_propose_hard_reject("non-lower-qc-round");
        return ProposeHandlingResult::HardReject;
      }
      auto qc_payload_id = quorum_certificate_payload_id_locked(*msg.justify_qc);
      if (!qc_payload_id.has_value()) {
        log_propose_hard_reject("unknown-qc-transition");
        return ProposeHandlingResult::HardReject;
      }
      if (*qc_payload_id != consensus_payload_id(transition)) {
        log_propose_hard_reject("qc-mismatch");
        return ProposeHandlingResult::HardReject;
      }
    }
    if (msg.justify_tc.has_value()) {
      std::vector<FinalitySig> filtered_tc;
      std::string tc_error;
      if (!verify_timeout_certificate_locked(*msg.justify_tc, &filtered_tc, &tc_error)) {
        log_propose_hard_reject("invalid-tc", " detail=" + tc_error);
        return ProposeHandlingResult::HardReject;
      }
      if (msg.justify_tc->height != msg.height) {
        log_propose_hard_reject("wrong-tc-height");
        return ProposeHandlingResult::HardReject;
      }
      if (msg.justify_tc->round >= msg.round) {
        log_propose_hard_reject("non-lower-tc-round");
        return ProposeHandlingResult::HardReject;
      }
    }
    if (msg.round > current_round_) {
      log_line("round-catchup height=" + std::to_string(msg.height) + " old_round=" + std::to_string(current_round_) +
               " new_round=" + std::to_string(msg.round) +
               " reason=justified-propose justify=" + justify_summary(msg.justify_qc, msg.justify_tc));
      current_round_ = msg.round;
    }

    const auto transition_id = transition.transition_id();
    if (candidate_frontier_proposals_.find(transition_id) == candidate_frontier_proposals_.end()) {
      const std::size_t sz = msg.frontier_proposal_bytes.size();
      std::size_t total = 0;
      for (const auto& [_, s] : candidate_block_sizes_) total += s;
      if (candidate_frontier_proposals_.size() >= kMaxCandidateBlocks || total + sz > kMaxCandidateBlockBytes) {
        log_propose_hard_reject("candidate-cache-full");
        return ProposeHandlingResult::HardReject;
      }
      candidate_block_sizes_[transition_id] = sz;
    }
    candidate_frontier_proposals_[transition_id] = *proposal;
    prune_caches_locked(msg.height, msg.round);
    (void)finalize_if_quorum(transition_id, msg.height, msg.round);

    std::string vote_reason;
    const auto local_vote_key = std::make_pair(msg.height, msg.round);
    const bool local_is_committee_member = is_committee_member_for(local_key_.public_key, msg.height, msg.round);
    const bool local_vote_reserved = local_vote_reservations_.find(local_vote_key) != local_vote_reservations_.end();
    const bool local_can_vote = local_is_committee_member && !local_vote_reserved &&
                                can_vote_for_frontier_locked(transition, msg.justify_qc, msg.justify_tc, &vote_reason);
    if (local_can_vote) {
      auto sig = crypto::ed25519_sign(vote_signing_message(msg.height, msg.round, transition_id), local_key_.private_key);
      if (!sig.has_value()) {
        log_propose_hard_reject("local-vote-sign-failed");
        return ProposeHandlingResult::HardReject;
      }
      local_vote_reservations_.insert(local_vote_key);
      log_line("local-vote-emit height=" + std::to_string(msg.height) + " round=" + std::to_string(msg.round) +
               " transition=" + short_hash_hex(transition_id) + " current_round=" + std::to_string(current_round_) +
               " committee_member=yes");
      maybe_vote = Vote{msg.height, msg.round, transition_id, local_key_.public_key, *sig};
    } else {
      if (!local_is_committee_member) vote_reason = "not-committee-member";
      else if (local_vote_reserved) vote_reason = "vote-already-reserved";
      else if (vote_reason.empty()) vote_reason = "not-votable";
      log_line("proposal-local-vote-skip height=" + std::to_string(msg.height) + " round=" + std::to_string(msg.round) +
               " transition=" + short_hash_hex(transition_id) + " current_round=" + std::to_string(current_round_) +
               " committee_member=" + std::string(local_is_committee_member ? "yes" : "no") +
               " reserved=" + std::string(local_vote_reserved ? "yes" : "no") + " reason=" + vote_reason);
    }
  }

propose_done:

  if (maybe_vote.has_value()) {
    broadcast_vote(*maybe_vote);
    const bool ok = handle_vote(*maybe_vote, false, 0);
    {
      std::lock_guard<std::mutex> lk(mu_);
      local_vote_reservations_.erase(std::make_pair(maybe_vote->height, maybe_vote->round));
    }
    return ok ? ProposeHandlingResult::Accepted : ProposeHandlingResult::HardReject;
  }
  return ProposeHandlingResult::Accepted;
}

bool Node::handle_propose(const p2p::ProposeMsg& msg, bool from_network) {
  return handle_propose_result(msg, from_network, nullptr) == ProposeHandlingResult::Accepted;
}

Node::VoteHandlingResult Node::handle_vote_result(const Vote& vote, bool from_network, int from_peer_id,
                                                  std::string* reject_reason) {
  if (from_network && !running_) {
    if (reject_reason) *reject_reason = "not-running";
    return VoteHandlingResult::SoftReject;
  }
  bool relay_vote = false;
  bool finalize_ok = false;
  bool accepted = false;
  {
    std::lock_guard<std::mutex> lk(mu_);
    auto log_vote_soft_reject = [&](const std::string& reason, const std::string& extra = std::string()) {
      log_line("vote-soft-reject height=" + std::to_string(vote.height) + " round=" + std::to_string(vote.round) +
               " reason=" + reason + extra);
    };
    auto log_vote_hard_reject = [&](const std::string& reason, const std::string& extra = std::string()) {
      log_line("vote-hard-reject height=" + std::to_string(vote.height) + " round=" + std::to_string(vote.round) +
               " reason=" + reason + extra);
    };
    if (from_network && !running_) {
      if (reject_reason) *reject_reason = "not-running";
      return VoteHandlingResult::SoftReject;
    }
    if (vote.height != finalized_height_ + 1) {
      if (vote.height <= finalized_height_) {
        // Late duplicate votes are expected under broadcast races once a block is finalized.
        // Ignore them without peer penalty, but keep a precise operator-visible reason.
        log_vote_soft_reject("stale-finalized-height", " local_finalized=" + std::to_string(finalized_height_));
        if (reject_reason) *reject_reason = "stale-finalized-height";
        return VoteHandlingResult::SoftReject;
      } else {
        log_vote_soft_reject("future-height", " local_next=" + std::to_string(finalized_height_ + 1));
        if (reject_reason) *reject_reason = "future-height";
        return VoteHandlingResult::SoftReject;
      }
    }
    if (vote.round > current_round_) {
      log_vote_soft_reject("future-round", " local_round=" + std::to_string(current_round_));
      if (reject_reason) *reject_reason = "future-round";
      return VoteHandlingResult::SoftReject;
    }
    if (!is_committee_member_for(vote.validator_pubkey, vote.height, vote.round)) {
      log_vote_hard_reject("non-member", " validator=" + short_pub_hex(vote.validator_pubkey));
      if (reject_reason) *reject_reason = "non-member";
      return VoteHandlingResult::HardReject;
    }

    const auto nowm = now_ms();
    auto& verify_bucket = vote_verify_buckets_[from_peer_id];
    verify_bucket.configure(cfg_.vote_verify_capacity, cfg_.vote_verify_refill);
    if (from_network && !verify_bucket.consume(1.0, nowm)) {
      log_vote_soft_reject("rate-limited", " peer_id=" + std::to_string(from_peer_id));
      if (reject_reason) *reject_reason = "rate-limited";
      return VoteHandlingResult::SoftReject;
    }

    const p2p::VoteVerifyCache::Key vkey{vote.height, vote.round, vote.frontier_transition_id, vote.validator_pubkey};
    if (invalid_vote_verify_cache_.contains(vkey)) {
      log_vote_hard_reject("cached-invalid-signature", " validator=" + short_pub_hex(vote.validator_pubkey));
      if (reject_reason) *reject_reason = "cached-invalid-signature";
      return VoteHandlingResult::HardReject;
    }
    if (!vote_verify_cache_.contains(vkey)) {
      const auto msg = vote_signing_message(vote.height, vote.round, vote.frontier_transition_id);
      if (!crypto::ed25519_verify(msg, vote.signature, vote.validator_pubkey)) {
        log_vote_hard_reject("invalid-signature", " validator=" + short_pub_hex(vote.validator_pubkey));
        invalid_vote_verify_cache_.insert(vkey);
        if (reject_reason) *reject_reason = "invalid-signature";
        return VoteHandlingResult::HardReject;
      }
      vote_verify_cache_.insert(vkey);
    }

    if (locally_observed_equivocators_.find(vote.validator_pubkey) != locally_observed_equivocators_.end()) {
      log_vote_hard_reject("known-equivocator", " validator=" + short_pub_hex(vote.validator_pubkey));
      if (reject_reason) *reject_reason = "known-equivocator";
      return VoteHandlingResult::HardReject;
    }

    auto tr = votes_.add_vote(vote);
    if (tr.equivocation && tr.evidence.has_value()) {
      locally_observed_equivocators_.insert(vote.validator_pubkey);
      (void)db_.put_slashing_record(make_vote_equivocation_record(*tr.evidence, finalized_height_));
      log_line("equivocation-observed validator=" +
               hex_encode(Bytes(vote.validator_pubkey.begin(), vote.validator_pubkey.end())) +
               " height=" + std::to_string(vote.height) + " round=" + std::to_string(vote.round));
    }

    if (!tr.accepted) {
      if (!tr.duplicate) {
        log_vote_hard_reject("tracker-rejected", " transition=" + short_hash_hex(vote.frontier_transition_id) +
                                                    " validator=" + short_pub_hex(vote.validator_pubkey));
        if (reject_reason) *reject_reason = "tracker-rejected";
        return VoteHandlingResult::HardReject;
      }
      log_vote_soft_reject("duplicate", " transition=" + short_hash_hex(vote.frontier_transition_id) +
                                           " validator=" + short_pub_hex(vote.validator_pubkey) +
                                           " peer_id=" + std::to_string(from_peer_id));
      if (reject_reason) *reject_reason = "duplicate";
      return VoteHandlingResult::SoftReject;
    }
    accepted = true;

    if (vote.validator_pubkey == local_key_.public_key) {
      auto frontier_it = candidate_frontier_proposals_.find(vote.frontier_transition_id);
      if (frontier_it != candidate_frontier_proposals_.end()) {
        update_local_vote_lock_locked(vote.height, vote.round, consensus_payload_id(frontier_it->second.transition));
      }
    }
    relay_vote = from_network && !should_mute_peer_locked(from_peer_id);
    if (candidate_frontier_proposals_.find(vote.frontier_transition_id) == candidate_frontier_proposals_.end()) {
      (void)maybe_request_candidate_transition_locked(from_peer_id, vote.frontier_transition_id);
    }
    maybe_record_quorum_certificate_locked(vote.frontier_transition_id, vote.height, vote.round);
    finalize_ok = finalize_if_quorum(vote.frontier_transition_id, vote.height, vote.round);
    if (!finalize_ok) {
      log_line("vote-accepted-waiting height=" + std::to_string(vote.height) + " round=" + std::to_string(vote.round) +
               " transition=" + short_hash_hex(vote.frontier_transition_id) +
               " validator=" + short_pub_hex(vote.validator_pubkey));
    }
  }

  if (relay_vote) broadcast_vote(vote);
  // A valid vote may arrive before the candidate block body. That is an accepted
  // network message and should not be treated as peer misbehavior just because
  // finalization must wait for block fetch/reassembly.
  return accepted ? VoteHandlingResult::Accepted : VoteHandlingResult::SoftReject;
}

bool Node::handle_vote(const Vote& vote, bool from_network, int from_peer_id) {
  return handle_vote_result(vote, from_network, from_peer_id) == VoteHandlingResult::Accepted;
}

Node::TimeoutVoteHandlingResult Node::handle_timeout_vote_result(const TimeoutVote& vote, bool from_network, int from_peer_id) {
  if (from_network && !running_) return TimeoutVoteHandlingResult::SoftReject;
  bool relay_vote = false;
  bool accepted = false;
  {
    std::lock_guard<std::mutex> lk(mu_);
    auto log_timeout_soft_reject = [&](const std::string& reason, const std::string& extra = std::string()) {
      log_line("timeout-vote-soft-reject height=" + std::to_string(vote.height) + " round=" + std::to_string(vote.round) +
               " reason=" + reason + extra);
    };
    auto log_timeout_hard_reject = [&](const std::string& reason, const std::string& extra = std::string()) {
      log_line("timeout-vote-hard-reject height=" + std::to_string(vote.height) + " round=" + std::to_string(vote.round) +
               " reason=" + reason + extra);
    };
    if (vote.height != finalized_height_ + 1) {
      if (vote.height <= finalized_height_) {
        log_timeout_soft_reject("stale-finalized-height", " local_finalized=" + std::to_string(finalized_height_));
      } else {
        log_timeout_soft_reject("future-height", " local_next=" + std::to_string(finalized_height_ + 1));
      }
      return TimeoutVoteHandlingResult::SoftReject;
    }
    if (vote.round > current_round_ + 1) {
      log_timeout_soft_reject("future-round", " local_round=" + std::to_string(current_round_));
      return TimeoutVoteHandlingResult::SoftReject;
    }
    if (!is_committee_member_for(vote.validator_pubkey, vote.height, vote.round)) {
      log_timeout_hard_reject("non-member", " validator=" + short_pub_hex(vote.validator_pubkey));
      return TimeoutVoteHandlingResult::HardReject;
    }
    const auto msg = timeout_vote_signing_message(vote.height, vote.round);
    if (!crypto::ed25519_verify(msg, vote.signature, vote.validator_pubkey)) {
      log_timeout_hard_reject("invalid-signature", " validator=" + short_pub_hex(vote.validator_pubkey));
      return TimeoutVoteHandlingResult::HardReject;
    }
    const auto tr = timeout_votes_.add_vote(vote);
    if (!tr.accepted) {
      if (!tr.duplicate) {
        log_timeout_hard_reject("tracker-rejected");
        return TimeoutVoteHandlingResult::HardReject;
      }
      log_timeout_soft_reject("duplicate");
      return TimeoutVoteHandlingResult::SoftReject;
    }
    accepted = true;
    relay_vote = from_network && !should_mute_peer_locked(from_peer_id);
    maybe_record_timeout_certificate_locked(vote.height, vote.round);
  }
  if (relay_vote) broadcast_timeout_vote(vote);
  return accepted ? TimeoutVoteHandlingResult::Accepted : TimeoutVoteHandlingResult::SoftReject;
}

bool Node::handle_timeout_vote(const TimeoutVote& vote, bool from_network, int from_peer_id) {
  return handle_timeout_vote_result(vote, from_network, from_peer_id) == TimeoutVoteHandlingResult::Accepted;
}

bool Node::handle_frontier_block_locked(const FrontierProposal& proposal,
                                        const std::optional<FinalityCertificate>& certificate, int from_peer_id,
                                        bool from_network) {
  if (!running_ && from_network) return false;
  if (!finalized_identity_valid_for_frontier_runtime(finalized_height_, finalized_identity_)) return false;
  const auto& transition = proposal.transition;
  const auto transition_id = transition.transition_id();
  requested_sync_artifacts_.erase(transition_id);
  requested_sync_heights_.erase(transition.height);
  // Frontier runtime accepts either a transition parent or the explicit
  // genesis block handoff at height 0, so the parent link intentionally uses
  // the raw finalized identity value here.
  if (transition.height <= finalized_height_) {
    return transition.height == finalized_height_ && transition_id == finalized_identity_.id;
  }
  if (transition.height > finalized_height_ + 1 || transition.prev_finalized_hash != finalized_identity_.id) {
    return false;
  }
  if (certificate.has_value()) {
    if (!canonical_state_.has_value()) {
      log_line("frontier-block-reject height=" + std::to_string(transition.height) + " round=" +
               std::to_string(transition.round) + " transition=" + short_hash_hex(transition_id) +
               " reason=missing-canonical-state");
      return false;
    }
    std::vector<FinalitySig> canonical_sigs;
    std::string cert_error;
    if (!verify_finality_certificate_for_frontier_locked(*certificate, transition, &canonical_sigs, &cert_error)) {
      log_line("frontier-block-reject height=" + std::to_string(transition.height) + " round=" +
               std::to_string(transition.round) + " transition=" + short_hash_hex(transition_id) +
               " reason=" + cert_error);
      return false;
    }
    consensus::CanonicalFrontierRecord certified_record{transition, proposal.ordered_records};
    consensus::FrontierExecutionResult recomputed;
    std::string validation_error;
    if (!consensus::verify_frontier_record_against_state(canonical_derivation_config_locked(), *canonical_state_,
                                                         certified_record, &recomputed, &validation_error)) {
      log_line("frontier-block-reject height=" + std::to_string(transition.height) + " round=" +
               std::to_string(transition.round) + " transition=" + short_hash_hex(transition_id) +
               " reason=" + validation_error);
      return false;
    }
    const auto expected_committee = recomputed.effective_committee;
    const std::size_t expected_quorum = consensus::quorum_threshold(expected_committee.size());
    if (certificate->committee_members != expected_committee || certificate->quorum_threshold != expected_quorum) {
      log_line("frontier-block-reject height=" + std::to_string(transition.height) + " round=" +
               std::to_string(transition.round) + " transition=" + short_hash_hex(transition_id) +
               " reason=certificate-committee-mismatch");
      return false;
    }
    if (!apply_finalized_frontier_effects_locked(certified_record, canonical_sigs, true, &expected_committee)) {
      return false;
    }
    broadcast_finalized_tip();
    if (from_peer_id != 0) (void)maybe_request_forward_sync_block_locked(from_peer_id);
    return true;
  }

  std::string validation_error;
  if (!validate_frontier_proposal_locked(proposal, &validation_error)) {
    log_line("frontier-block-reject height=" + std::to_string(transition.height) + " round=" +
             std::to_string(transition.round) + " transition=" + short_hash_hex(transition_id) +
             " reason=" + validation_error);
    return false;
  }
  std::string lock_error;
  if (!can_accept_frontier_with_lock_locked(transition, &lock_error)) {
    log_line("frontier-block-reject height=" + std::to_string(transition.height) + " round=" +
             std::to_string(transition.round) + " transition=" + short_hash_hex(transition_id) +
             " reason=" + lock_error);
    return false;
  }
  candidate_frontier_proposals_[transition_id] = proposal;
  candidate_block_sizes_[transition_id] = proposal.serialize().size();

  (void)finalize_if_quorum(transition_id, transition.height, transition.round);
  return true;
}

bool Node::maybe_buffer_sync_frontier_locked(const FrontierProposal& proposal,
                                             const std::optional<FinalityCertificate>& certificate, int from_peer_id) {
  if (!certificate.has_value()) return false;
  const auto& transition = proposal.transition;
  const auto transition_id = transition.transition_id();
  if (transition.height <= finalized_height_) {
    return transition.height == finalized_height_ && transition_id == finalized_identity_.id;
  }
  if (transition.height == finalized_height_ + 1) return false;
  if (auto existing = db_.get_height_hash(transition.height); existing.has_value()) return *existing == transition_id;

  auto [it, inserted] = buffered_sync_frontiers_.try_emplace(
      transition.height, BufferedSyncFrontier{proposal, certificate, from_peer_id});
  if (!inserted) {
    const auto existing_id = it->second.proposal.transition.transition_id();
    if (existing_id != transition_id) {
      log_line("buffer-sync-conflict height=" + std::to_string(transition.height) + " existing=" +
               short_hash_hex(existing_id) + " incoming=" + short_hash_hex(transition_id));
      return false;
    }
    if (it->second.from_peer_id == 0) it->second.from_peer_id = from_peer_id;
    return true;
  }

  log_line("buffer-sync-transition peer_id=" + std::to_string(from_peer_id) + " height=" +
           std::to_string(transition.height) + " hash=" + short_hash_hex(transition_id) + " prev=" +
           short_hash_hex(transition.prev_finalized_hash));
  return true;
}

bool Node::maybe_apply_buffered_sync_frontiers_locked(int preferred_peer_id) {
  bool advanced = false;
  while (true) {
    auto it = buffered_sync_frontiers_.find(finalized_height_ + 1);
    if (it == buffered_sync_frontiers_.end()) break;
    BufferedSyncFrontier buffered = it->second;
    buffered_sync_frontiers_.erase(it);
    const auto expected_height = finalized_height_ + 1;
    if (!handle_frontier_block_locked(buffered.proposal, buffered.certificate,
                                      buffered.from_peer_id != 0 ? buffered.from_peer_id : preferred_peer_id, true)) {
      log_line("buffer-sync-apply-failed height=" + std::to_string(expected_height) + " hash=" +
               short_hash_hex(buffered.proposal.transition.transition_id()));
      break;
    }
    advanced = true;
  }
  return advanced;
}

bool Node::verify_block_proposer_locked(const Block& block) const {
  const Bytes bid = block_proposal_signing_message(block.header);
  if (!crypto::ed25519_verify(bid, block.header.leader_signature, block.header.leader_pubkey)) return false;
  auto expected = leader_for_height_round(block.header.height, block.header.round);
  return expected.has_value() && block.header.leader_pubkey == *expected;
}

bool Node::validate_prev_finality_cert_hash_locked(const Block& block, std::string* error) const {
  if (!finality_binding_active_at_height(cfg_.network, block.header.height)) {
    if (block.header.prev_finality_cert_hash != zero_hash()) {
      if (error) *error = "prev-finality-cert-hash-must-be-zero";
      return false;
    }
    return true;
  }
  if (block.header.height <= 1) {
    if (block.header.prev_finality_cert_hash != zero_hash()) {
      if (error) *error = "prev-finality-cert-hash-must-be-zero";
      return false;
    }
    return true;
  }

  Hash32 expected = zero_hash();
  if (block.header.height == finalized_height_ + 1) {
    if (!canonical_state_.has_value()) {
      if (error) *error = "missing-canonical-state";
      return false;
    }
    expected = canonical_state_->last_finality_certificate_hash;
  } else {
    auto cert = db_.get_finality_certificate_by_height(block.header.height - 1);
    if (!cert.has_value()) {
      if (error) *error = "missing-prev-finality-certificate";
      return false;
    }
    expected = consensus::canonical_finality_certificate_hash(*cert);
  }
  if (block.header.prev_finality_cert_hash != expected) {
    if (error) *error = "prev-finality-cert-hash-mismatch";
    return false;
  }
  return true;
}

bool Node::validate_frontier_proposal_locked(const FrontierProposal& proposal, std::string* error) const {
  if (!canonical_state_.has_value()) {
    if (error) *error = "missing-canonical-state";
    return false;
  }
  if (!finalized_identity_valid_for_frontier_runtime(finalized_height_, finalized_identity_)) {
    if (error) *error = "frontier-parent-identity-kind-mismatch";
    return false;
  }
  const auto& transition = proposal.transition;
  const auto finalized_transition_id = finalized_identity_.id;
  if (transition.height != finalized_height_ + 1) {
    if (error) *error = "frontier-height-mismatch";
    return false;
  }
  if (transition.prev_finalized_hash != finalized_transition_id) {
    if (error) *error = "frontier-prev-finalized-hash-mismatch";
    return false;
  }
  for (std::size_t i = 0; i < proposal.ordered_records.size(); ++i) {
    std::string ordered_record_error;
    if (!inspect_frontier_ordered_record_supported(proposal.ordered_records[i], i, nullptr, &ordered_record_error)) {
      if (error) *error = ordered_record_error;
      return false;
    }
  }
  if (auto expected = leader_for_height_round(transition.height, transition.round); !expected.has_value() ||
                                                                      *expected != transition.leader_pubkey) {
    if (error) *error = "invalid-proposer";
    return false;
  }
  for (std::size_t lane = 0; lane < finalis::INGRESS_LANE_COUNT; ++lane) {
    if (transition.next_vector.lane_max_seq[lane] < transition.prev_vector.lane_max_seq[lane]) {
      log_line("frontier-validation-vector-rewind transition=" + short_hash_hex(transition.transition_id()) +
               " lane=" + std::to_string(lane) + " prev=" +
               std::to_string(transition.prev_vector.lane_max_seq[lane]) + " next=" +
               std::to_string(transition.next_vector.lane_max_seq[lane]));
      if (error) *error = "frontier-vector-rewind";
      return false;
    }
  }
  consensus::CanonicalFrontierRecord certified_record{transition, proposal.ordered_records};
  consensus::FrontierExecutionResult recomputed;
  if (!consensus::verify_frontier_record_against_state(canonical_derivation_config_locked(), *canonical_state_,
                                                       certified_record, &recomputed, error)) {
    log_line("frontier-validation-failed transition=" + short_hash_hex(transition.transition_id()) + " range=(" +
             std::to_string(transition.prev_frontier + 1) + "," + std::to_string(transition.next_frontier) +
             "] detail=" + (error ? *error : std::string("unknown")));
    if (error && error->empty()) *error = "frontier-verification-failed";
    return false;
  }
  return true;
}

bool Node::check_and_record_proposer_equivocation_locked(const FrontierTransition& transition) {
  constexpr std::uint64_t kObservedProposalRetentionDepth = 512;
  const std::uint64_t min_height_to_keep =
      finalized_height_ > kObservedProposalRetentionDepth ? (finalized_height_ - kObservedProposalRetentionDepth) : 0;
  for (auto it = observed_proposals_.begin(); it != observed_proposals_.end();) {
    if (std::get<0>(it->first) < min_height_to_keep) {
      it = observed_proposals_.erase(it);
    } else {
      ++it;
    }
  }
  const auto key = std::make_tuple(transition.height, transition.round, transition.leader_pubkey);
  const auto new_transition_id = transition.transition_id();
  auto it = observed_proposals_.find(key);
  if (it == observed_proposals_.end()) {
    observed_proposals_[key] = new_transition_id;
    return false;
  }
  const auto old_transition_id = it->second;
  if (old_transition_id == new_transition_id) return false;

  locally_observed_equivocators_.insert(transition.leader_pubkey);
  (void)db_.put_slashing_record(make_proposer_equivocation_record(transition.leader_pubkey, transition.height,
                                                                  transition.round, old_transition_id,
                                                                  new_transition_id, finalized_height_));
  log_line("proposer-equivocation-observed validator=" +
           hex_encode(Bytes(transition.leader_pubkey.begin(), transition.leader_pubkey.end())) +
           " height=" + std::to_string(transition.height) + " round=" + std::to_string(transition.round) +
           " block_a=" + hex_encode32(old_transition_id) + " block_b=" + hex_encode32(new_transition_id));
  return true;
}

bool Node::handle_tx(const AnyTx& tx, bool from_network, int from_peer_id) {
  if (from_network && !running_) return false;
  Hash32 txid{};
  {
    std::lock_guard<std::mutex> lk(mu_);
    if (from_network && !running_) return false;
    auto& verify_bucket = tx_verify_buckets_[from_peer_id];
    verify_bucket.configure(cfg_.tx_verify_capacity, cfg_.tx_verify_refill);
    const auto input_count = std::visit([](const auto& value) { return value.inputs.size(); }, tx);
    if (from_network && !verify_bucket.consume(static_cast<double>(std::max<std::size_t>(1, input_count)), now_ms())) {
      return false;
    }
    const auto next_height = finalized_height_ + 1;
    const auto min_bond_amount = effective_validator_min_bond_for_height(next_height);
    mempool_.set_validation_context(
        SpecialValidationContext{
            .network = &cfg_.network,
            .chain_id = &chain_id_,
            .validators = &validators_,
            .current_height = next_height,
            .enforce_variable_bond_range = true,
            .min_bond_amount = min_bond_amount,
            .max_bond_amount = effective_validator_bond_max_for_height(next_height),
            .unbond_delay_blocks = cfg_.network.unbond_delay_blocks,
            .is_committee_member = [this](const PubKey32& pub, std::uint64_t h, std::uint32_t round) {
              return is_committee_member_for(pub, h, round);
            },
            .finalized_hash_at_height = [this](std::uint64_t anchor_height) -> std::optional<Hash32> {
              if (anchor_height == 0) return zero_hash();
              return db_.get_height_hash(anchor_height);
            },
            .confidential_policy = &confidential_policy_});
    std::string err;
    std::uint64_t fee = 0;
    const auto min_relay_fee = effective_min_relay_fee_for_height(next_height);
    if (!mempool_.accept_tx(tx, utxos_, &err, min_relay_fee, &fee)) {
      if (debug_economics_logs_enabled()) {
        PubKey32 reg_pub{};
        std::optional<std::uint64_t> offered_bond;
        if (std::holds_alternative<Tx>(tx)) {
          for (const auto& out : std::get<Tx>(tx).outputs) {
            if (!is_validator_register_script(out.script_pubkey, &reg_pub)) continue;
            offered_bond = out.value;
            break;
          }
        }
        if (offered_bond.has_value()) {
          std::ostringstream oss;
          oss << "economics-admission-reject height=" << next_height
              << " validator=" << short_pub_hex(reg_pub)
              << " offered_bond=" << *offered_bond
              << " required_min_bond=" << min_bond_amount
              << " max_bond=" << effective_validator_bond_max_for_height(next_height)
              << " active_operators=" << active_operator_count_for_height_locked(next_height)
              << " reason=" << err;
          log_line(oss.str());
        }
      }
      return false;
    }
    if (fee < min_relay_fee) return false;
    txid = txid_any(tx);
    std::string ingress_error;
    if (!maybe_certify_locally_accepted_tx_locked(tx, &ingress_error) && !ingress_error.empty()) {
      log_line("ingress-local-certify-skip txid=" + hex_encode32(txid) + " reason=" + ingress_error);
    }
    maybe_forward_tx_to_designated_certifier_locked(tx, from_network ? from_peer_id : 0);
    log_line("mempool-accept txid=" + hex_encode32(txid) + " mempool_size=" + std::to_string(mempool_.size()));
  }

  if (from_network && !should_mute_peer(from_peer_id)) broadcast_tx(tx, from_peer_id);
  return true;
}

bool Node::handle_ingress_record_locked(int peer_id, const p2p::IngressRecordMsg& msg, bool* appended, std::string* error) {
  if (appended) *appended = false;
  if (msg.certificate.lane >= INGRESS_LANE_COUNT || msg.certificate.seq == 0) {
    if (error) *error = "invalid-ingress-record";
    return false;
  }

  if (auto existing_cert_bytes = db_.get_ingress_certificate(msg.certificate.lane, msg.certificate.seq);
      existing_cert_bytes.has_value()) {
    auto existing_cert = IngressCertificate::parse(*existing_cert_bytes);
    if (!existing_cert.has_value()) {
      if (error) *error = "stored-cert-invalid";
      return false;
    }
    if (*existing_cert == msg.certificate) {
      if (auto existing_tx = db_.get_ingress_bytes(msg.certificate.txid);
          existing_tx.has_value() && *existing_tx == msg.tx_bytes) {
        if (error) error->clear();
        return true;
      }
      if (error) *error = "ingress-bytes-conflict";
      return false;
    }
    std::string equivocation_error;
    if (consensus::detect_ingress_equivocation(existing_cert, msg.certificate, &equivocation_error)) {
      std::string persist_error;
      if (!consensus::persist_ingress_equivocation_evidence(db_, *existing_cert, msg.certificate, &persist_error)) {
        equivocation_error = persist_error;
      }
      if (error) *error = equivocation_error;
      return false;
    }
  }

  auto committee = ingress_committee_locked(msg.certificate.epoch);
  std::string append_error;
  if (!consensus::append_validated_ingress_record(db_, msg.certificate, msg.tx_bytes, committee, &append_error)) {
    if (error) *error = append_error;
    return false;
  }

  if (appended) *appended = true;
  if (error) error->clear();
  log_line("ingress-record-accepted peer_id=" + std::to_string(peer_id) +
           " lane=" + std::to_string(msg.certificate.lane) +
           " seq=" + std::to_string(msg.certificate.seq) +
           " txid=" + short_hash_hex(msg.certificate.txid));
  return true;
}

bool Node::maybe_certify_locally_accepted_tx_locked(const AnyTx& tx, std::string* error) {
  if (!is_validator_) {
    if (error) *error = "local-not-validator";
    return false;
  }

  const std::uint64_t next_height = finalized_height_ + 1;
  auto committee = ingress_committee_locked(next_height);
  if (committee.empty()) {
    if (error) *error = "empty-ingress-committee";
    return false;
  }

  const std::uint32_t lane = consensus::assign_ingress_lane(tx);
  const PubKey32& designated_certifier = committee[static_cast<std::size_t>(lane) % committee.size()];
  if (designated_certifier != local_key_.public_key) {
    if (error) *error = "local-not-designated-ingress-certifier";
    return false;
  }

  const auto txid = txid_any(tx);
  if (db_.get_ingress_bytes(txid).has_value()) {
    if (error) error->clear();
    return true;
  }

  const auto lane_state = db_.get_lane_state(lane);
  const Bytes tx_bytes = serialize_any_tx(tx);

  IngressCertificate cert;
  cert.epoch = consensus::committee_epoch_start(next_height, cfg_.network.committee_epoch_blocks);
  cert.lane = lane;
  cert.seq = lane_state.has_value() ? (lane_state->max_seq + 1) : 1;
  cert.txid = txid;
  cert.tx_hash = crypto::sha256d(tx_bytes);
  cert.prev_lane_root = lane_state.has_value() ? lane_state->lane_root : zero_hash();

  const auto signing_hash = cert.signing_hash();
  const Bytes msg(signing_hash.begin(), signing_hash.end());
  auto sig = crypto::ed25519_sign(msg, local_key_.private_key);
  if (!sig.has_value()) {
    if (error) *error = "ingress-sign-failed";
    return false;
  }
  cert.sigs.push_back(FinalitySig{local_key_.public_key, *sig});

  std::string append_error;
  if (!consensus::append_validated_ingress_record(db_, cert, tx_bytes, committee, &append_error)) {
    if (error) *error = append_error;
    return false;
  }

  if (error) error->clear();
  log_line("ingress-local-certified txid=" + hex_encode32(txid) + " lane=" + std::to_string(lane) +
           " seq=" + std::to_string(cert.seq) + " epoch=" + std::to_string(cert.epoch));
  broadcast_ingress_record(cert, tx_bytes);
  return true;
}

bool Node::finalize_if_quorum(const Hash32& block_id, std::uint64_t height, std::uint32_t round) {
  auto proposal_it = candidate_frontier_proposals_.find(block_id);
  if (proposal_it == candidate_frontier_proposals_.end()) {
    const bool in_flight = requested_sync_artifacts_.find(block_id) != requested_sync_artifacts_.end();
    log_line(std::string(in_flight ? "finalize-wait" : "finalize-skip") + " height=" + std::to_string(height) +
             " round=" + std::to_string(round) + " transition=" + short_hash_hex(block_id) + " reason=" +
             (in_flight ? "candidate-pending" : "missing-candidate"));
    return false;
  }
  FrontierProposal finalized_proposal = proposal_it->second;

  const auto committee = committee_for_height_round(height, round);
  if (committee.empty()) {
    log_line("finalize-skip height=" + std::to_string(height) + " round=" + std::to_string(round) +
             " transition=" + short_hash_hex(block_id) + " reason=empty-committee");
    return false;
  }
  const std::size_t quorum = consensus::quorum_threshold(committee.size());
  auto sigs = votes_.signatures_for(height, round, block_id);
  std::set<PubKey32> committee_set;
  committee_set.insert(committee.begin(), committee.end());
  if (sigs.size() < quorum) {
    std::ostringstream oss;
    oss << "finalize-skip height=" << height << " round=" << round << " transition=" << short_hash_hex(block_id)
        << " reason=insufficient-votes votes=" << sigs.size() << " quorum=" << quorum
        << " signers=" << signer_set_summary(sigs);
    if (debug_finality_logs_enabled()) {
      oss << " committee_size=" << committee.size();
      if (auto proposer = leader_for_height_round(height, round); proposer.has_value()) {
        oss << " proposer=" << short_pub_hex(*proposer);
      }
    }
    log_line(oss.str());
    return false;
  }

  std::set<PubKey32> seen;
  std::vector<FinalitySig> filtered;
  const auto vote_msg = vote_signing_message(height, round, block_id);
  for (const auto& s : sigs) {
    if (!committee_set.empty() && committee_set.find(s.validator_pubkey) == committee_set.end()) continue;
    if (!seen.insert(s.validator_pubkey).second) continue;
    if (!crypto::ed25519_verify(vote_msg, s.signature, s.validator_pubkey)) continue;
    filtered.push_back(s);
  }
  if (filtered.size() < quorum) {
    log_line("finalize-skip height=" + std::to_string(height) + " round=" + std::to_string(round) +
             " transition=" + short_hash_hex(block_id) + " reason=insufficient-valid-signatures valid=" +
             std::to_string(filtered.size()) + " quorum=" + std::to_string(quorum));
    return false;
  }

  std::string lock_error;
  if (!can_accept_frontier_with_lock_locked(proposal_it->second.transition, &lock_error)) {
    log_line("finalize-skip height=" + std::to_string(height) + " round=" + std::to_string(round) +
             " transition=" + short_hash_hex(block_id) + " reason=" + lock_error);
    return false;
  }
  const auto canonical_sigs = canonicalize_finality_signatures_locked(filtered, quorum);
  consensus::CanonicalFrontierRecord certified_record;
  std::string frontier_record_error;
  if (!consensus::load_certified_frontier_record_from_storage(db_, finalized_proposal.transition, &certified_record,
                                                              &frontier_record_error)) {
    log_line("finalize-skip height=" + std::to_string(height) + " round=" + std::to_string(round) +
             " transition=" + short_hash_hex(block_id) + " reason=" + frontier_record_error);
    return false;
  }
  certified_record.ordered_records = finalized_proposal.ordered_records;
  if (!apply_finalized_frontier_effects_locked(certified_record, canonical_sigs)) {
    log_line("finalize-skip height=" + std::to_string(height) + " round=" + std::to_string(round) +
             " transition=" + short_hash_hex(block_id) + " reason=apply-failed");
    return false;
  }

  const FinalityCertificate cert =
      make_finality_certificate(height, round, block_id, quorum, committee, canonical_sigs);
  broadcast_finalized_frontier(finalized_proposal, cert);
  broadcast_finalized_tip();
  return true;
}

std::optional<FrontierProposal> Node::build_frontier_transition_locked(std::uint64_t height, std::uint32_t round) {
  if (!canonical_state_.has_value()) {
    last_test_hook_error_ = "missing-canonical-state";
    return std::nullopt;
  }
  if (canonical_state_->finalized_frontier != canonical_state_->finalized_frontier_vector.total_count()) {
    std::string repair_error;
    log_line("finalized-state-invariant-violation source=frontier-build-runtime-cursor-mismatch height=" +
             std::to_string(height) + " finalized_frontier=" + std::to_string(canonical_state_->finalized_frontier) +
             " vector_total=" + std::to_string(canonical_state_->finalized_frontier_vector.total_count()));
    if (!refresh_runtime_from_frontier_storage_locked("frontier-build-runtime-cursor-mismatch", &repair_error)) {
      last_test_hook_error_ = "frontier-build-runtime-refresh-failed:" + repair_error;
      return std::nullopt;
    }
    if (!canonical_state_.has_value() ||
        canonical_state_->finalized_frontier != canonical_state_->finalized_frontier_vector.total_count()) {
      last_test_hook_error_ = "frontier-build-runtime-cursor-mismatch-persisted";
      return std::nullopt;
    }
  }
  if (!finalized_identity_valid_for_frontier_runtime(finalized_height_, finalized_identity_)) {
    last_test_hook_error_ = "frontier-parent-identity-kind-mismatch";
    return std::nullopt;
  }
  FrontierBuildSelection selection;
  selection.next_vector = canonical_state_->finalized_frontier_vector;
  std::array<std::uint64_t, finalis::INGRESS_LANE_COUNT> lane_tips{};
  std::uint64_t max_delta = 0;
  for (std::size_t lane = 0; lane < finalis::INGRESS_LANE_COUNT; ++lane) {
    if (auto state = db_.get_lane_state(static_cast<std::uint32_t>(lane)); state.has_value()) {
      lane_tips[lane] = state->max_seq;
    } else {
      lane_tips[lane] = 0;
    }
    if (lane_tips[lane] < canonical_state_->finalized_frontier_vector.lane_max_seq[lane]) {
      last_test_hook_error_ = "frontier-build-lane-tip-rewind lane=" + std::to_string(lane);
      return std::nullopt;
    }
    max_delta = std::max(max_delta, lane_tips[lane] - canonical_state_->finalized_frontier_vector.lane_max_seq[lane]);
  }

  std::size_t total_bytes = 0;
  bool capped = false;
  for (std::uint64_t r = 1; r <= max_delta && !capped; ++r) {
    for (std::size_t lane = 0; lane < finalis::INGRESS_LANE_COUNT; ++lane) {
      const auto seq = canonical_state_->finalized_frontier_vector.lane_max_seq[lane] + r;
      if (seq > lane_tips[lane]) continue;
      consensus::CertifiedIngressRecord ingress;
      std::string ingress_error;
      if (!load_certified_ingress_record_from_db(db_, static_cast<std::uint32_t>(lane), seq, &ingress, &ingress_error)) {
        last_test_hook_error_ = "frontier-build-ingress-load-failed:" + ingress_error;
        log_line("frontier-build-failed height=" + std::to_string(height) + " round=" + std::to_string(round) +
                 " lane=" + std::to_string(lane) + " seq=" + std::to_string(seq) +
                 " reason=" + ingress_error);
        return std::nullopt;
      }
      std::string ordered_record_error;
      if (!inspect_frontier_ordered_record_supported(ingress.tx_bytes, selection.ordered_records.size(), nullptr,
                                                     &ordered_record_error)) {
        last_test_hook_error_ = "frontier-build-ordered-record-invalid:" + ordered_record_error;
        log_line("frontier-build-failed height=" + std::to_string(height) + " round=" + std::to_string(round) +
                 " lane=" + std::to_string(lane) + " seq=" + std::to_string(seq) +
                 " reason=" + ordered_record_error);
        return std::nullopt;
      }
      if (selection.ordered_records.size() >= kMaxBlockTxs ||
          total_bytes + ingress.tx_bytes.size() > kMaxBlockBytes) {
        capped = true;
        break;
      }
      selection.next_vector.lane_max_seq[lane] = seq;
      selection.lane_records[lane].push_back(ingress);
      selection.ordered_records.push_back(ingress.tx_bytes);
      total_bytes += ingress.tx_bytes.size();
    }
  }

  SpecialValidationContext vctx{
      .network = &cfg_.network,
      .chain_id = &chain_id_,
      .validators = &validators_,
      .current_height = height,
      .enforce_variable_bond_range = true,
      .min_bond_amount = effective_validator_min_bond_for_height(height),
      .max_bond_amount = effective_validator_bond_max_for_height(height),
      .unbond_delay_blocks = cfg_.network.unbond_delay_blocks,
      .is_committee_member = [this](const PubKey32& pub, std::uint64_t h, std::uint32_t r) {
        return is_committee_member_for(pub, h, r);
      },
      .finalized_hash_at_height = [this](std::uint64_t anchor_height) -> std::optional<Hash32> {
        if (anchor_height == 0) return zero_hash();
        return db_.get_height_hash(anchor_height);
      },
      .confidential_policy = &confidential_policy_};

  consensus::FrontierExecutionResult result;
  std::string validation_error;
  if (!consensus::execute_frontier_lane_prefix(canonical_state_->utxos, canonical_state_->finalized_frontier_vector,
                                               selection.next_vector, selection.lane_records,
                                               canonical_state_->finalized_lane_roots, &vctx, &result, &validation_error)) {
    last_test_hook_error_ = "frontier-build-execution-failed:" + validation_error;
    return std::nullopt;
  }
  if (!consensus::populate_frontier_transition_metadata(canonical_derivation_config_locked(), *canonical_state_, height, round,
                                                        local_key_.public_key, {}, result.accepted_fee_units,
                                                        result.next_utxos, &result.transition, &validation_error)) {
    last_test_hook_error_ = "frontier-build-metadata-failed:" + validation_error;
    return std::nullopt;
  }
  last_test_hook_error_.clear();
  return FrontierProposal{result.transition, selection.ordered_records};
}

bool Node::refresh_runtime_from_frontier_storage_locked(const char* reason, std::string* error) {
  auto genesis_json = db_.get(storage::key_genesis_json());
  if (!genesis_json.has_value()) {
    if (error) *error = "missing-genesis-json";
    return false;
  }
  const std::string js(genesis_json->begin(), genesis_json->end());
  auto genesis_doc = genesis::parse_json(js);
  if (!genesis_doc.has_value()) {
    if (error) *error = "invalid-genesis-json";
    return false;
  }

  consensus::CanonicalGenesisState genesis_state;
  genesis_state.genesis_artifact_id = genesis::block_id(*genesis_doc);
  if (auto stored_genesis_artifact = db_.get(storage::key_genesis_artifact());
      stored_genesis_artifact.has_value() && stored_genesis_artifact->size() == 32) {
    std::copy(stored_genesis_artifact->begin(), stored_genesis_artifact->end(), genesis_state.genesis_artifact_id.begin());
  }
  genesis_state.initial_validators = genesis_doc->initial_validators;
  if (bootstrap_template_mode_ && finalized_height_ == 0 && bootstrap_validator_pubkey_.has_value()) {
    genesis_state.initial_validators = {*bootstrap_validator_pubkey_};
  }

  const auto derivation_cfg = canonical_derivation_config_locked();
  consensus::CanonicalDerivedState canonical_genesis_state;
  std::string canonical_error;
  if (!consensus::build_genesis_canonical_state(derivation_cfg, genesis_state, &canonical_genesis_state, &canonical_error)) {
    if (error) *error = "canonical-genesis-failed:" + canonical_error;
    return false;
  }

  consensus::CanonicalDerivedState derived_state;
  std::string derivation_error;
  if (!consensus::derive_canonical_state_from_frontier_storage(derivation_cfg, canonical_genesis_state, db_, &derived_state,
                                                               &derivation_error)) {
    if (error) *error = "frontier-derive-failed:" + derivation_error;
    return false;
  }
  if (derived_state.finalized_height != finalized_height_ || derived_state.finalized_identity.id != finalized_identity_.id) {
    if (error) {
      *error = "frontier-derive-tip-mismatch local_height=" + std::to_string(finalized_height_) +
               " derived_height=" + std::to_string(derived_state.finalized_height);
    }
    return false;
  }

  hydrate_runtime_from_canonical_state_locked(derived_state);
  log_line(std::string("canonical-runtime-refresh source=") + reason + " height=" + std::to_string(finalized_height_) +
           " finalized_frontier=" + std::to_string(canonical_state_->finalized_frontier) + " vector_total=" +
           std::to_string(canonical_state_->finalized_frontier_vector.total_count()));
  return true;
}

void Node::broadcast_propose(const FrontierProposal& proposal, const std::optional<QuorumCertificate>& justify_qc,
                             const std::optional<TimeoutCertificate>& justify_tc) {
  p2p::ProposeMsg p;
  p.height = proposal.transition.height;
  p.round = proposal.transition.round;
  p.prev_finalized_hash = proposal.transition.prev_finalized_hash;
  p.frontier_proposal_bytes = proposal.serialize();
  p.justify_qc = justify_qc;
  p.justify_tc = justify_tc;
  if (cfg_.disable_p2p) {
    if (!running_) return;
    std::vector<Node*> peers;
    {
      std::lock_guard<std::mutex> lk(g_local_bus_mu);
      peers = g_local_bus_nodes;
    }
    for (Node* peer : peers) {
      if (peer == this) continue;
      spawn_local_bus_task([peer, p]() { peer->handle_propose(p, true); });
    }
  } else {
    p2p_.broadcast(p2p::MsgType::PROPOSE, p2p::ser_propose(p));
  }
}

void Node::broadcast_epoch_ticket(const consensus::EpochTicket& ticket) {
  if (cfg_.disable_p2p) {
    if (!running_) return;
    std::vector<Node*> peers;
    {
      std::lock_guard<std::mutex> lk(g_local_bus_mu);
      peers = g_local_bus_nodes;
    }
    for (Node* peer : peers) {
      if (peer == this) continue;
      spawn_local_bus_task([peer, ticket]() { (void)peer->handle_epoch_ticket(ticket, true, 0); });
    }
  } else {
    p2p_.broadcast(p2p::MsgType::EPOCH_TICKET, p2p::ser_epoch_ticket(p2p::EpochTicketMsg{ticket}));
  }
}

void Node::broadcast_vote(const Vote& vote) {
  p2p::VoteMsg vm;
  vm.vote = vote;
  if (cfg_.disable_p2p) {
    if (!running_) return;
    std::vector<Node*> peers;
    {
      std::lock_guard<std::mutex> lk(g_local_bus_mu);
      peers = g_local_bus_nodes;
    }
    for (Node* peer : peers) {
      if (peer == this) continue;
      spawn_local_bus_task([peer, vm]() { (void)peer->handle_vote(vm.vote, true, 0); });
    }
  } else {
    p2p_.broadcast(p2p::MsgType::VOTE, p2p::ser_vote(vm));
  }
}

void Node::broadcast_timeout_vote(const TimeoutVote& vote) {
  p2p::TimeoutVoteMsg vm;
  vm.vote = vote;
  if (cfg_.disable_p2p) {
    if (!running_) return;
    std::vector<Node*> peers;
    {
      std::lock_guard<std::mutex> lk(g_local_bus_mu);
      peers = g_local_bus_nodes;
    }
    for (Node* peer : peers) {
      if (peer == this) continue;
      spawn_local_bus_task([peer, vm]() { (void)peer->handle_timeout_vote(vm.vote, true, 0); });
    }
  } else {
    p2p_.broadcast(p2p::MsgType::TIMEOUT_VOTE, p2p::ser_timeout_vote(vm));
  }
}

void Node::broadcast_finalized_frontier(const FrontierProposal& proposal, const FinalityCertificate& certificate) {
  last_broadcast_finalized_frontier_ = proposal;
  last_broadcast_finality_certificate_ = certificate;
  if (cfg_.disable_p2p) {
    if (!running_) return;
    std::vector<Node*> peers;
    {
      std::lock_guard<std::mutex> lk(g_local_bus_mu);
      peers = g_local_bus_nodes;
    }
    for (Node* peer : peers) {
      if (peer == this) continue;
      spawn_local_bus_task([peer, proposal, certificate]() {
        std::lock_guard<std::mutex> lk(peer->mu_);
        (void)peer->handle_frontier_block_locked(proposal, certificate, 0, true);
      });
    }
  } else {
    p2p::TransitionMsg msg;
    msg.frontier_proposal_bytes = proposal.serialize();
    msg.certificate = certificate;
    p2p_.broadcast(p2p::MsgType::TRANSITION, p2p::ser_transition(msg));
  }
}

void Node::broadcast_tx(const AnyTx& tx, int skip_peer_id) {
  if (cfg_.disable_p2p) {
    if (!running_) return;
    std::vector<Node*> peers;
    {
      std::lock_guard<std::mutex> lk(g_local_bus_mu);
      peers = g_local_bus_nodes;
    }
    for (Node* peer : peers) {
      if (peer == this) continue;
      spawn_local_bus_task([peer, tx]() { peer->handle_tx(tx, true); });
    }
  } else {
    const auto payload = p2p::ser_tx(p2p::TxMsg{serialize_any_tx(tx)});
    for (int id : p2p_.peer_ids()) {
      if (id == skip_peer_id) continue;
      (void)p2p_.send_to(id, p2p::MsgType::TX, payload, true);
    }
  }
}

void Node::broadcast_ingress_record(const IngressCertificate& cert, const Bytes& tx_bytes, int skip_peer_id) {
  if (cfg_.disable_p2p) {
    if (!running_) return;
    std::vector<Node*> peers;
    {
      std::lock_guard<std::mutex> lk(g_local_bus_mu);
      peers = g_local_bus_nodes;
    }
    const p2p::IngressRecordMsg msg{cert, tx_bytes};
    for (Node* peer : peers) {
      if (peer == this) continue;
      spawn_local_bus_task([peer, msg]() {
        std::lock_guard<std::mutex> lk(peer->mu_);
        bool appended = false;
        std::string ingress_error;
        if (!peer->handle_ingress_record_locked(0, msg, &appended, &ingress_error)) return;
        if (appended) peer->broadcast_ingress_record(msg.certificate, msg.tx_bytes);
      });
    }
  } else {
    const auto payload = p2p::ser_ingress_record(p2p::IngressRecordMsg{cert, tx_bytes});
    for (int id : p2p_.peer_ids()) {
      if (id == skip_peer_id) continue;
      (void)p2p_.send_to(id, p2p::MsgType::INGRESS_RECORD, payload, true);
    }
  }
}

void Node::maybe_forward_tx_to_designated_certifier_locked(const AnyTx& tx, int skip_peer_id) {
  const std::uint64_t next_height = finalized_height_ + 1;
  auto committee = ingress_committee_locked(next_height);
  if (committee.empty()) return;

  const std::uint32_t lane = consensus::assign_ingress_lane(tx);
  const PubKey32& designated_certifier = committee[static_cast<std::size_t>(lane) % committee.size()];
  if (designated_certifier == local_key_.public_key) return;

  if (cfg_.disable_p2p) {
    if (!running_) return;
    std::vector<Node*> peers;
    {
      std::lock_guard<std::mutex> lk(g_local_bus_mu);
      peers = g_local_bus_nodes;
    }
    for (Node* peer : peers) {
      if (peer == this) continue;
      if (peer->local_validator_pubkey_for_test() != designated_certifier) continue;
      spawn_local_bus_task([peer, tx]() { (void)peer->handle_tx(tx, true); });
      log_line("tx-forward-designated lane=" + std::to_string(lane) +
               " designated=" + short_pub_hex(designated_certifier) + " transport=local-bus");
      return;
    }
    return;
  }

  if (skip_peer_id != 0) {
    auto it = peer_validator_pubkeys_.find(skip_peer_id);
    if (it != peer_validator_pubkeys_.end() && it->second == designated_certifier) return;
  }

  const auto payload = p2p::ser_tx(p2p::TxMsg{serialize_any_tx(tx)});
  for (const auto& [peer_id, peer_pub] : peer_validator_pubkeys_) {
    if (peer_id == skip_peer_id) continue;
    if (peer_pub != designated_certifier) continue;
    const auto info = p2p_.get_peer_info(peer_id);
    if (!info.established()) continue;
    const bool ok = p2p_.send_to(peer_id, p2p::MsgType::TX, payload, true);
    log_line("tx-forward-designated peer_id=" + std::to_string(peer_id) + " lane=" + std::to_string(lane) +
             " designated=" + short_pub_hex(designated_certifier) + " status=" + (ok ? "ok" : "failed"));
    return;
  }
}

bool Node::persist_finalized_frontier_record(const consensus::CanonicalFrontierRecord& record, const UtxoSetV2& prev_utxos) {
  if (record.transition.next_frontier !=
      record.transition.prev_frontier + static_cast<std::uint64_t>(record.ordered_records.size())) {
    log_line("finalized-state-invariant-violation source=runtime-write-frontier-continuity height=" +
             std::to_string(record.transition.height));
    return false;
  }

  std::uint64_t seq = record.transition.prev_frontier;
  std::uint32_t tx_index = 0;
  for (const auto& ordered_record : record.ordered_records) {
    ++seq;
    if (!db_.put_ingress_record(seq, ordered_record)) return false;
    auto tx = parse_any_tx(ordered_record);
    if (!tx.has_value()) {
      log_line("finalized-state-invariant-violation source=runtime-write-frontier-tx-parse height=" +
               std::to_string(record.transition.height));
      return false;
    }
    const Hash32 txid = txid_any(*tx);
    if (!db_.put_tx_index(txid, record.transition.height, tx_index++, ordered_record)) return false;
    if (std::holds_alternative<Tx>(*tx)) {
      const auto& legacy = std::get<Tx>(*tx);
      for (const auto& input : legacy.inputs) {
        const auto prev_it = prev_utxos.find(OutPoint{input.prev_txid, input.prev_index});
        if (prev_it == prev_utxos.end()) continue;
        const auto spent_out = transparent_txout_from_utxo_entry(prev_it->second);
        if (!spent_out.has_value()) continue;
        const auto spent_scripthash = crypto::sha256(spent_out->script_pubkey);
        if (!db_.add_script_history(spent_scripthash, record.transition.height, txid)) return false;
      }
      for (const auto& output : legacy.outputs) {
        const auto received_scripthash = crypto::sha256(output.script_pubkey);
        if (!db_.add_script_history(received_scripthash, record.transition.height, txid)) return false;
      }
    }
  }
  if (!db_.set_finalized_ingress_tip(record.transition.next_frontier)) return false;
  if (!db_.put_frontier_transition(record.transition.transition_id(), record.transition.serialize())) return false;
  if (!db_.map_height_to_frontier_transition(record.transition.height, record.transition.transition_id())) return false;
  if (!db_.set_finalized_frontier_height(record.transition.height)) return false;
  if (!db_.set_height_hash(record.transition.height, record.transition.transition_id())) return false;
  if (!db_.set_tip(storage::TipState{record.transition.height, record.transition.transition_id()})) return false;
  if (!db_.put(kStartupReplayModeKey, Bytes{'f', 'r', 'o', 'n', 't', 'i', 'e', 'r'})) return false;
  return true;
}

bool Node::begin_finalized_write(const Block& block) {
  if (!db_.put(finalized_write_marker_key(), serialize_finalized_write_marker(block.header.height, block.header.block_id()))) {
    return false;
  }
  return db_.flush();
}

bool Node::finish_finalized_write(const Block& block) {
  std::uint64_t marker_height = 0;
  Hash32 marker_block_id{};
  auto marker = db_.get(finalized_write_marker_key());
  if (!marker.has_value() || !parse_finalized_write_marker(*marker, &marker_height, &marker_block_id) ||
      marker_height != block.header.height || marker_block_id != block.header.block_id()) {
    return false;
  }
  if (!db_.erase(finalized_write_marker_key())) return false;
  return db_.flush();
}

bool Node::check_no_incomplete_finalized_write() const {
  auto marker = db_.get(finalized_write_marker_key());
  if (!marker.has_value()) return true;
  std::uint64_t height = 0;
  Hash32 block_id{};
  if (!parse_finalized_write_marker(*marker, &height, &block_id)) {
    std::cerr << "incomplete finalized write marker is malformed\n";
    return false;
  }
  std::cerr << "incomplete finalized write marker detected for height " << height << " block " << hex_encode32(block_id)
            << "\n";
  return false;
}

consensus::CanonicalDerivationConfig Node::canonical_derivation_config_locked() const {
  consensus::CanonicalDerivationConfig cfg;
  cfg.network = cfg_.network;
  cfg.chain_id = chain_id_;
  cfg.max_committee = cfg_.max_committee;
  cfg.validator_min_bond_override = validator_min_bond_;
  cfg.validator_bond_min_amount = validator_bond_min_amount_;
  cfg.validator_bond_max_amount = validator_bond_max_amount_;
  cfg.validator_warmup_blocks = validator_warmup_blocks_;
  cfg.validator_cooldown_blocks = validator_cooldown_blocks_;
  cfg.validator_join_limit_window_blocks = validator_join_limit_window_blocks_;
  cfg.validator_join_limit_max_new = validator_join_limit_max_new_;
  cfg.validator_liveness_window_blocks = validator_liveness_window_blocks_;
  cfg.validator_miss_rate_suspend_threshold_percent = validator_miss_rate_suspend_threshold_percent_;
  cfg.validator_miss_rate_exit_threshold_percent = validator_miss_rate_exit_threshold_percent_;
  cfg.validator_suspend_duration_blocks = validator_suspend_duration_blocks_;
  cfg.availability = cfg_.availability;
  cfg.availability_min_eligible_operators = cfg_.availability_min_eligible_operators;
  cfg.validation_rules_version = kFixedValidationRulesVersion;
  cfg.confidential_policy = confidential_policy_;
  cfg.finalized_hash_at_height = [this](std::uint64_t height) -> std::optional<Hash32> {
    if (height == 0) return zero_hash();
    return db_.get_height_hash(height);
  };
  return cfg;
}

void Node::hydrate_runtime_from_canonical_state_locked(const consensus::CanonicalDerivedState& state) {
  canonical_state_ = state;
  finalized_height_ = state.finalized_height;
  finalized_identity_ = state.finalized_identity;
  utxos_ = state.utxos;
  validators_ = state.validators;
  validator_join_requests_ = state.validator_join_requests;
  finalized_randomness_ = state.finalized_randomness;
  committee_epoch_randomness_cache_ = state.committee_epoch_randomness_cache;
  protocol_reserve_balance_units_ = state.protocol_reserve_balance_units;
  epoch_reward_states_ = state.epoch_reward_states;
  finalized_committee_checkpoints_ = state.finalized_committee_checkpoints;
  validator_join_window_start_height_ = state.validator_join_window_start_height;
  validator_join_count_in_window_ = state.validator_join_count_in_window;
  validator_liveness_window_start_height_ = state.validator_liveness_window_start_height;
  last_participation_eligible_signers_ = state.last_participation_eligible_signers;
  availability_state_ = state.availability_state;
}

bool Node::verify_and_persist_consensus_state_commitment_locked(const consensus::CanonicalDerivedState& state) {
  const auto commitment = consensus::consensus_state_commitment(canonical_derivation_config_locked(), state);
  if (commitment != state.state_commitment) {
    std::cerr << "consensus state commitment recomputation mismatch\n";
    return false;
  }
  auto persisted = db_.get_consensus_state_commitment_cache();
  // This cache intentionally commits only the finalized identity value. The
  // DB boundary remains kind-erased for compatibility.
  if (persisted.has_value() && persisted->height == state.finalized_height &&
      persisted->hash == state.finalized_identity.id &&
      persisted->commitment != commitment) {
    std::cerr << "persisted consensus state commitment mismatch at height " << state.finalized_height << "\n";
    return false;
  }
  return db_.put_consensus_state_commitment_cache(
      storage::ConsensusStateCommitmentCache{state.finalized_height, state.finalized_identity.id, commitment});
}

bool Node::init_mainnet_genesis() {
  const bool use_embedded = cfg_.genesis_path.empty();
  std::string err;
  std::optional<genesis::Document> doc;
  Hash32 ghash{};
  if (use_embedded) {
    const Bytes bin(genesis::MAINNET_GENESIS_BIN, genesis::MAINNET_GENESIS_BIN + genesis::MAINNET_GENESIS_BIN_LEN);
    doc = genesis::decode_bin(bin, &err);
    if (doc.has_value()) ghash = genesis::hash_bin(bin);
  } else {
    doc = genesis::load_from_path(cfg_.genesis_path, &err);
    if (doc.has_value()) ghash = genesis::hash_doc(*doc);
  }
  if (!doc.has_value()) {
    std::cerr << "genesis load failed: " << err << "\n";
    return false;
  }
  bootstrap_template_mode_ = (!use_embedded && doc->initial_validators.empty());
  if (!genesis::validate_document(*doc, cfg_.network, &err, bootstrap_template_mode_ ? 0 : 1)) {
    std::cerr << "genesis validation failed: " << err << "\n";
    return false;
  }
  if (use_embedded && ghash != genesis::MAINNET_GENESIS_HASH) {
    std::cerr << "embedded genesis hash mismatch; binary may be corrupted\n";
    return false;
  }
  expected_genesis_hash_ = ghash;

  const Bytes ghash_b(ghash.begin(), ghash.end());
  const Hash32 gblock = genesis::block_id(*doc);
  const Bytes gblock_b(gblock.begin(), gblock.end());
  const auto stored = db_.get(storage::key_genesis_hash());
  if (stored.has_value()) {
    if (stored->size() != 32 || !std::equal(stored->begin(), stored->end(), ghash_b.begin())) {
      std::cerr << "genesis mismatch against existing database\n";
      return false;
    }
    if (!db_.get(storage::key_genesis_json()).has_value()) {
      const auto json = genesis::to_json(*doc);
      (void)db_.put(storage::key_genesis_json(), Bytes(json.begin(), json.end()));
    }
    if (bootstrap_template_mode_) {
      const auto all = db_.scan_prefix(storage::key_validator_prefix());
      if (all.size() == 1) {
        const auto& key = all.begin()->first;
        if (key.size() > 2) {
          auto b = hex_decode(key.substr(2));
          if (b && b->size() == 32) {
            PubKey32 pub{};
            std::copy(b->begin(), b->end(), pub.begin());
            bootstrap_validator_pubkey_ = pub;
          }
        }
      }
    }
    const auto tip = db_.get_tip();
  if (tip.has_value() && tip->height == 0 && tip->hash != gblock) {
    std::cerr << "genesis block id mismatch against existing database tip\n";
    return false;
  }
  availability_state_ = {};
  availability_state_.current_epoch = current_epoch_ticket_epoch_locked();
  return true;
}

  if (!db_.put(storage::key_genesis_hash(), ghash_b)) return false;
  if (!db_.put(storage::key_genesis_artifact(), gblock_b)) return false;
  {
    const auto json = genesis::to_json(*doc);
    if (!db_.put(storage::key_genesis_json(), Bytes(json.begin(), json.end()))) return false;
  }
  auto tip = db_.get_tip();
  if (!tip.has_value()) {
    if (!db_.set_tip(storage::TipState{0, gblock})) return false;
  } else if (!(tip->height == 0 && tip->hash == zero_hash()) && tip->height != 0) {
    std::cerr << "existing non-empty database is missing genesis marker\n";
    return false;
  } else if (tip->height == 0 && tip->hash == zero_hash()) {
    if (!db_.set_tip(storage::TipState{0, gblock})) return false;
  } else if (tip->height == 0 && tip->hash != gblock) {
    std::cerr << "height-0 tip does not match provided genesis\n";
    return false;
  }

  for (const auto& pub : doc->initial_validators) {
    consensus::ValidatorInfo vi;
    vi.status = consensus::ValidatorStatus::ACTIVE;
    vi.joined_height = 0;
    vi.bonded_amount = consensus::genesis_validator_bond_amount();
    vi.operator_id = pub;
    vi.has_bond = true;
    vi.bond_outpoint = OutPoint{zero_hash(), 0};
    vi.unbond_height = 0;
    if (!db_.put_validator(pub, vi)) return false;
  }
  {
    consensus::ValidatorRegistry vr;
    for (const auto& pub : doc->initial_validators) {
      consensus::ValidatorInfo vi;
      vi.status = consensus::ValidatorStatus::ACTIVE;
      vi.joined_height = 0;
      vi.bonded_amount = consensus::genesis_validator_bond_amount();
      vi.operator_id = pub;
      vi.has_bond = true;
      vi.bond_outpoint = OutPoint{zero_hash(), 0};
      vi.unbond_height = 0;
      vr.upsert(pub, vi);
    }
    const UtxoSetV2 empty_utxos;
    (void)persist_state_roots(db_, 0, empty_utxos, vr, kFixedValidationRulesVersion);
  }
  {
    codec::ByteWriter w0;
    w0.u64le(0);
    (void)db_.put(kValidatorJoinWindowStartKey, w0.take());
    codec::ByteWriter w1;
    w1.u32le(0);
    (void)db_.put(kValidatorJoinWindowCountKey, w1.take());
    codec::ByteWriter w2;
    w2.u64le(0);
    (void)db_.put(kValidatorLivenessWindowStartKey, w2.take());
  }
  chain_id_ =
      ChainId::from_config_and_db(cfg_.network, db_, std::nullopt, genesis_source_hint_, expected_genesis_hash_);
  consensus::CanonicalGenesisState genesis_state;
  genesis_state.genesis_artifact_id = gblock;
  genesis_state.initial_validators = doc->initial_validators;
  consensus::CanonicalDerivedState canonical_genesis_state;
  std::string canonical_error;
  if (!consensus::build_genesis_canonical_state(canonical_derivation_config_locked(), genesis_state,
                                                &canonical_genesis_state, &canonical_error)) {
    std::cerr << "canonical genesis derivation failed: " << canonical_error << "\n";
    return false;
  }
  finalized_randomness_ = canonical_genesis_state.finalized_randomness;
  committee_epoch_randomness_cache_ = canonical_genesis_state.committee_epoch_randomness_cache;
  protocol_reserve_balance_units_ = canonical_genesis_state.protocol_reserve_balance_units;
  finalized_committee_checkpoints_ = canonical_genesis_state.finalized_committee_checkpoints;
  epoch_reward_states_ = canonical_genesis_state.epoch_reward_states;
  canonical_state_ = canonical_genesis_state;
  if (!persist_canonical_cache_rows(db_, canonical_genesis_state)) return false;
  if (!verify_and_persist_consensus_state_commitment_locked(canonical_genesis_state)) return false;
  return db_.flush();
}

bool Node::load_state() {
  if (!check_no_incomplete_finalized_write()) return false;
  auto tip = db_.get_tip();
  if (!tip.has_value()) {
    finalized_height_ = 0;
    finalized_identity_ = finalized_identity_for_runtime_tip(0, zero_hash());
    db_.set_tip(storage::TipState{0, finalized_identity_.id});
  } else {
    finalized_height_ = tip->height;
    finalized_identity_ = finalized_identity_for_runtime_tip(tip->height, tip->hash);
    if (finalized_height_ > 0) {
      auto indexed = db_.get_height_hash(finalized_height_);
      if (!indexed.has_value() || *indexed != finalized_identity_.id) {
        log_line("finalized-state-invariant-violation source=load-state-tip height=" +
                 std::to_string(finalized_height_) + " existing_transition=" +
                 (indexed.has_value() ? hex_encode(Bytes(indexed->begin(), indexed->end())) : std::string("missing")) +
                 " conflicting_transition=" + hex_encode(Bytes(finalized_identity_.id.begin(), finalized_identity_.id.end())));
        return false;
      }
    }
  }

  auto genesis_json = db_.get(storage::key_genesis_json());
  if (!genesis_json.has_value()) {
    log_line("finalized-state-invariant-violation source=load-state-missing-genesis-json");
    std::cerr << "load_state: missing genesis json\n";
    return false;
  }
  const std::string js(genesis_json->begin(), genesis_json->end());
  auto genesis_doc = genesis::parse_json(js);
  if (!genesis_doc.has_value()) {
    log_line("finalized-state-invariant-violation source=load-state-invalid-genesis-json");
    std::cerr << "load_state: invalid genesis json\n";
    return false;
  }
  consensus::CanonicalGenesisState genesis_state;
  genesis_state.genesis_artifact_id = genesis::block_id(*genesis_doc);
  if (auto stored_genesis_artifact = db_.get(storage::key_genesis_artifact());
      stored_genesis_artifact.has_value() && stored_genesis_artifact->size() == 32) {
    std::copy(stored_genesis_artifact->begin(), stored_genesis_artifact->end(), genesis_state.genesis_artifact_id.begin());
  }
  genesis_state.initial_validators = genesis_doc->initial_validators;
  if (bootstrap_template_mode_ && finalized_height_ == 0 && bootstrap_validator_pubkey_.has_value()) {
    genesis_state.initial_validators = {*bootstrap_validator_pubkey_};
  }

  const auto stored_replay_mode_bytes = db_.get(kStartupReplayModeKey);
  if (stored_replay_mode_bytes.has_value() && !replay_mode_is_frontier(*stored_replay_mode_bytes)) {
    log_line("finalized-state-invariant-violation source=load-state-invalid-replay-mode");
    std::cerr << "load_state: invalid replay mode\n";
    return false;
  }
  const bool frontier_storage_present =
      db_.get_finalized_frontier_height().has_value() || !db_.scan_prefix(storage::key_frontier_transition_prefix()).empty() ||
      !db_.scan_prefix(storage::key_frontier_height_prefix()).empty();
  const bool obsolete_block_storage_present = !db_.scan_prefix("B:").empty();
  if (!frontier_storage_present && obsolete_block_storage_present) {
    log_line("finalized-state-invariant-violation source=load-state-missing-frontier-storage");
    std::cerr << "load_state: missing frontier storage in frontier-only runtime\n";
    return false;
  }
  const bool using_frontier_replay = true;

  const auto derivation_cfg = canonical_derivation_config_locked();
  consensus::CanonicalDerivedState canonical_genesis_state;
  std::string canonical_error;
  if (!consensus::build_genesis_canonical_state(derivation_cfg, genesis_state, &canonical_genesis_state,
                                                &canonical_error)) {
    log_line("finalized-state-invariant-violation source=load-state-canonical-genesis detail=" + canonical_error);
    std::cerr << "load_state: canonical genesis failed: " << canonical_error << "\n";
    return false;
  }

  consensus::CanonicalDerivedState derived_state;
  std::string derivation_error;
  consensus::CanonicalDerivedState frontier_state;
  if (!consensus::derive_canonical_state_from_frontier_storage(derivation_cfg, canonical_genesis_state, db_,
                                                               &frontier_state, &derivation_error)) {
    log_line("finalized-state-invariant-violation source=load-state-frontier-derive detail=" + derivation_error);
    std::cerr << "load_state: frontier derive failed: " << derivation_error << "\n";
    return false;
  }
  derived_state = std::move(frontier_state);
  if (derived_state.finalized_height > 0 && !derived_state.finalized_identity.is_transition()) {
    log_line("finalized-state-invariant-violation source=load-state-frontier-kind-mismatch");
    std::cerr << "load_state: frontier replay produced non-transition finalized identity\n";
    return false;
  }
  if (derived_state.finalized_height != finalized_height_ || derived_state.finalized_identity.id != finalized_identity_.id) {
    log_line("finalized-state-invariant-violation source=load-state-frontier-tip-mismatch");
    std::cerr << "load_state: frontier replay tip mismatch\n";
    return false;
  }
  if (!db_.put(kStartupReplayModeKey, Bytes{'f', 'r', 'o', 'n', 't', 'i', 'e', 'r'})) return false;

  const auto persisted_commitment = db_.get_consensus_state_commitment_cache();
  const auto derived_commitment = consensus::consensus_state_commitment(derivation_cfg, derived_state);
  const storage::ConsensusStateCommitmentCache expected_commitment{derived_state.finalized_height,
                                                                   derived_state.finalized_identity.id,
                                                                   derived_commitment};
  const bool stale_canonical_cache_tip =
      !persisted_commitment.has_value() || persisted_commitment->height != expected_commitment.height ||
      persisted_commitment->hash != expected_commitment.hash;
  bool canonical_cache_rewrite_needed = stale_canonical_cache_tip;

  const auto persisted_utxos = db_.load_utxos_v2();
  if (!persisted_utxos.empty() && !same_utxos(persisted_utxos, derived_state.utxos)) {
    if (using_frontier_replay) {
      log_line("canonical-cache-rewrite source=load-state-utxo-cache-mismatch");
      canonical_cache_rewrite_needed = true;
    } else {
      log_line("finalized-state-invariant-violation source=load-state-utxo-cache-mismatch");
      std::cerr << "load_state: utxo cache mismatch\n";
      return false;
    }
  }
  const auto persisted_validators = db_.load_validators();
  if (!persisted_validators.empty() && !same_validator_maps(persisted_validators, derived_state.validators.all())) {
    if (stale_canonical_cache_tip) {
      log_line("canonical-cache-rewrite source=load-state-validator-cache-mismatch");
      canonical_cache_rewrite_needed = true;
    } else {
      log_line("finalized-state-invariant-violation source=load-state-validator-cache-mismatch");
      std::cerr << "load_state: validator cache mismatch "
                << validator_map_mismatch_reason(persisted_validators, derived_state.validators.all()) << "\n";
      return false;
    }
  }
  const auto persisted_join_requests = db_.load_validator_join_requests();
  if (!persisted_join_requests.empty() &&
      !same_join_request_maps(persisted_join_requests, derived_state.validator_join_requests)) {
    log_line("canonical-cache-rewrite source=load-state-join-request-cache-mismatch");
    canonical_cache_rewrite_needed = true;
  }
  const auto persisted_checkpoints = db_.load_finalized_committee_checkpoints();
  if (!persisted_checkpoints.empty() &&
      !same_finalized_checkpoint_maps(persisted_checkpoints, derived_state.finalized_committee_checkpoints)) {
    log_line("canonical-cache-rewrite source=load-state-checkpoint-cache-mismatch");
    canonical_cache_rewrite_needed = true;
  }
  const auto persisted_rewards = db_.load_epoch_reward_settlements();
  if (!persisted_rewards.empty() && !same_epoch_reward_maps(persisted_rewards, derived_state.epoch_reward_states)) {
    log_line("canonical-cache-rewrite source=load-state-reward-cache-mismatch");
    canonical_cache_rewrite_needed = true;
  }
  if (auto persisted_reserve = db_.get_protocol_reserve_balance(); persisted_reserve.has_value()) {
    if (*persisted_reserve != derived_state.protocol_reserve_balance_units) {
      if (stale_canonical_cache_tip) {
        log_line("canonical-cache-rewrite source=load-state-protocol-reserve-balance-mismatch");
        canonical_cache_rewrite_needed = true;
      } else {
        log_line("finalized-state-invariant-violation source=load-state-protocol-reserve-balance-mismatch");
        std::cerr << "load_state: protocol reserve balance mismatch\n";
        return false;
      }
    }
  }
  if (auto persisted_randomness = db_.get(kFinalizedRandomnessKey); persisted_randomness.has_value()) {
    if (persisted_randomness->size() != 32 ||
        !std::equal(persisted_randomness->begin(), persisted_randomness->end(), derived_state.finalized_randomness.begin())) {
      log_line("canonical-cache-rewrite source=load-state-randomness-cache-mismatch");
      canonical_cache_rewrite_needed = true;
    }
  }

  if (persisted_commitment.has_value()) {
    if (!same_consensus_state_commitment_cache(*persisted_commitment, expected_commitment)) {
      if (canonical_cache_rewrite_needed) {
        log_line("canonical-cache-rewrite source=load-state-consensus-state-commitment-cache-mismatch");
      } else {
        log_line("finalized-state-invariant-violation source=load-state-consensus-state-commitment-cache-mismatch");
        std::cerr << "load_state: consensus state commitment cache mismatch\n";
        return false;
      }
    }
  }
  if (using_frontier_replay) (void)db_.erase(storage::key_consensus_state_commitment_cache());
  if (!verify_and_persist_consensus_state_commitment_locked(derived_state)) return false;
  hydrate_runtime_from_canonical_state_locked(derived_state);
  if (!persist_canonical_cache_rows(db_, derived_state)) return false;

  const auto existing = db_.get(storage::key_root_index("UTXO", finalized_height_));
  if (!existing.has_value() || existing->size() != 32) {
    (void)persist_state_roots(db_, finalized_height_, utxos_, validators_, kFixedValidationRulesVersion);
  }

  local_epoch_tickets_.clear();
  local_vote_locks_.clear();
  highest_qc_by_height_.clear();
  highest_qc_payload_by_height_.clear();
  highest_tc_by_height_.clear();
  std::set<std::uint64_t> rebuild_epochs;
  for (const auto epoch : db_.load_epoch_ticket_epochs()) rebuild_epochs.insert(epoch);
  for (const auto& [epoch, _] : db_.load_epoch_committee_snapshots()) rebuild_epochs.insert(epoch);
  for (const auto& [epoch, _] : db_.load_epoch_committee_freeze_markers()) rebuild_epochs.insert(epoch);
  for (const auto epoch : rebuild_epochs) {
    rebuild_epoch_committee_state_locked(epoch, "startup", true);
  }
  for (auto& [epoch_start, checkpoint] : finalized_committee_checkpoints_) {
    auto snapshot = db_.get_epoch_committee_snapshot(epoch_start);
    if (!snapshot.has_value() || snapshot->ordered_members.empty()) continue;
    if (!finalized_checkpoint_matches_epoch_snapshot(checkpoint, *snapshot)) {
      log_line("canonical-cache-rewrite source=load-state-checkpoint-snapshot-mismatch epoch=" +
               std::to_string(epoch_start));
      const auto rewritten_snapshot = epoch_committee_snapshot_from_checkpoint(checkpoint);
      if (!db_.put_epoch_committee_snapshot(rewritten_snapshot)) {
        log_line("finalized-state-invariant-violation source=load-state-checkpoint-snapshot-rewrite-failed epoch=" +
                 std::to_string(epoch_start));
        std::cerr << "load_state: checkpoint snapshot rewrite failed epoch=" << epoch_start << "\n";
        return false;
      }
      if (epoch_committee_closed_locked(epoch_start)) {
        const auto marker = make_epoch_committee_freeze_marker_locked(rewritten_snapshot);
        if (!db_.put_epoch_committee_freeze_marker(marker)) {
          log_line("finalized-state-invariant-violation source=load-state-checkpoint-freeze-marker-rewrite-failed epoch=" +
                   std::to_string(epoch_start));
          std::cerr << "load_state: checkpoint freeze marker rewrite failed epoch=" << epoch_start << "\n";
          return false;
        }
      }
    }
  }
  for (const auto& [key, value] : db_.scan_prefix(kConsensusSafetyStatePrefix)) {
    if (key.size() <= std::strlen(kConsensusSafetyStatePrefix)) continue;
    auto height_bytes = hex_decode(key.substr(std::strlen(kConsensusSafetyStatePrefix)));
    if (!height_bytes.has_value() || height_bytes->size() != 8) continue;
    std::uint64_t height = 0;
    for (std::size_t i = 0; i < 8; ++i) height |= static_cast<std::uint64_t>((*height_bytes)[i]) << (8 * i);
    std::optional<std::pair<Hash32, std::uint32_t>> lock_state;
    std::optional<QuorumCertificate> qc_state;
    std::optional<Hash32> qc_payload_id;
    if (!parse_consensus_safety_state(value, &lock_state, &qc_state, &qc_payload_id)) {
      (void)db_.erase(key);
      continue;
    }
    if (height != finalized_height_ + 1) {
      (void)db_.erase(key);
      continue;
    }
    bool valid = true;
    if (qc_state.has_value()) {
      if (qc_state->height != height || !qc_payload_id.has_value()) {
        valid = false;
      } else {
        std::vector<FinalitySig> filtered;
        valid = verify_quorum_certificate_locked(*qc_state, &filtered, nullptr);
      }
    } else if (qc_payload_id.has_value()) {
      valid = false;
    }
    if (!valid) {
      (void)db_.erase(key);
      continue;
    }
    if (lock_state.has_value()) local_vote_locks_[height] = *lock_state;
    if (qc_state.has_value()) highest_qc_by_height_[height] = *qc_state;
    if (qc_payload_id.has_value()) highest_qc_payload_by_height_[height] = *qc_payload_id;
  }
  last_open_epoch_ticket_epoch_ = current_epoch_ticket_epoch_locked();
  if (!load_availability_state_locked()) {
    log_line("availability-init-reset reason=load-or-parse-failed");
    availability_state_rebuild_triggered_ = true;
    availability_state_rebuild_reason_ = "load_or_parse_failed";
    availability_state_ = {};
    availability_state_.current_epoch = current_epoch_ticket_epoch_locked();
    if (finalized_height_ > 0) {
      rebuild_availability_retained_prefixes_from_finalized_frontier_locked();
    }
    refresh_availability_operator_state_locked(false);
    (void)finalize_availability_restore_locked("load-failure-rebuild");
  }

  return true;
}

std::vector<PubKey32> Node::committee_for_height(std::uint64_t height) const {
  return committee_for_height_round(height, 0);
}

std::vector<consensus::WeightedParticipant> Node::reward_participants_for_height_round(std::uint64_t height,
                                                                                       std::uint32_t round) const {
  const auto active_operator_count = active_operator_count_for_height_locked(height);
  if (height <= finalized_height_) {
    if (auto cert = db_.get_finality_certificate_by_height(height); cert.has_value()) {
      std::set<PubKey32> rewarded;
      std::vector<consensus::WeightedParticipant> out;
      out.reserve(cert->signatures.size());
      for (const auto& sig : cert->signatures) {
        if (!rewarded.insert(sig.validator_pubkey).second) continue;
        auto it = validators_.all().find(sig.validator_pubkey);
        if (it == validators_.all().end()) continue;
        out.push_back(consensus::WeightedParticipant{
            .pubkey = sig.validator_pubkey,
            .bonded_amount = it->second.bonded_amount,
            .effective_weight =
                consensus::reward_weight(cfg_.network, height, active_operator_count, it->second.bonded_amount),
            .participation_bps = 10'000,
        });
      }
      if (!out.empty()) return out;
    }
  }

  auto committee = committee_for_height_round(height, round);
  std::vector<consensus::WeightedParticipant> committee_participants;
  committee_participants.reserve(committee.size());
  for (const auto& pub : committee) {
    auto it = validators_.all().find(pub);
    if (it == validators_.all().end()) continue;
    committee_participants.push_back(consensus::WeightedParticipant{
        .pubkey = pub,
        .bonded_amount = it->second.bonded_amount,
        .effective_weight = consensus::reward_weight(cfg_.network, height, active_operator_count, it->second.bonded_amount),
        .participation_bps = 10'000,
    });
  }
  std::vector<consensus::WeightedParticipant> out;
  out.reserve(committee.size());
  for (const auto& pub : committee) {
    auto it = validators_.all().find(pub);
    if (it == validators_.all().end()) continue;
    const auto& vi = it->second;
    if (vi.status == consensus::ValidatorStatus::SUSPENDED) continue;
    if (vi.eligible_count_window == 0 || vi.participated_count_window > 0) {
      out.push_back(consensus::WeightedParticipant{
          .pubkey = pub,
          .bonded_amount = vi.bonded_amount,
          .effective_weight = consensus::reward_weight(cfg_.network, height, active_operator_count, vi.bonded_amount),
          .participation_bps = 10'000,
      });
    }
  }
  if (out.empty()) return committee_participants;
  return out;
}

std::vector<PubKey32> Node::committee_for_height_round(std::uint64_t height, std::uint32_t round) const {
  if (height == finalized_height_ + 1) {
    if (canonical_state_.has_value()) {
      const auto canonical =
          consensus::canonical_committee_for_height_round(canonical_derivation_config_locked(), *canonical_state_, height, round);
      if (!canonical.empty()) return canonical;
    }
    return epoch_committee_for_next_height_locked(height, round);
  }

  if (height == 0 || height > finalized_height_ + 1) return {};
  if (auto cert = db_.get_finality_certificate_by_height(height); cert.has_value()) {
    if (auto checkpoint = finalized_committee_checkpoint_for_height_locked(height); checkpoint.has_value()) {
      if (!certificate_matches_checkpoint_committee(*cert, *checkpoint)) {
        log_line("finalized-state-invariant-violation source=persisted-committee-checkpoint-mismatch height=" +
                 std::to_string(height));
        return {};
      }
    }
    return cert->committee_members;
  }
  return {};
}

std::optional<PubKey32> Node::leader_for_height_round(std::uint64_t height, std::uint32_t round) const {
  if (height == finalized_height_ + 1) {
    if (canonical_state_.has_value()) {
      if (auto canonical =
              consensus::canonical_leader_for_height_round(canonical_derivation_config_locked(), *canonical_state_, height, round);
          canonical.has_value()) {
        return canonical;
      }
    }
    return epoch_leader_for_next_height_locked(height, round);
  }

  if (height == 0 || height > finalized_height_ + 1) return std::nullopt;
  if (auto checkpoint = finalized_committee_checkpoint_for_height_locked(height); checkpoint.has_value()) {
    if (auto cert = db_.get_finality_certificate_by_height(height); cert.has_value()) {
      if (!certificate_matches_checkpoint_committee(*cert, *checkpoint)) {
        log_line("finalized-state-invariant-violation source=persisted-proposer-checkpoint-mismatch height=" +
                 std::to_string(height));
        return std::nullopt;
      }
    }
    if (canonical_state_.has_value()) {
      std::string error;
      if (!consensus::validate_checkpoint_schedule_for_height(canonical_derivation_config_locked(), *canonical_state_,
                                                              *checkpoint, height, &error)) {
        log_line("finalized-state-invariant-violation source=persisted-proposer-schedule-invalid height=" +
                 std::to_string(height) + " detail=" + error);
        return std::nullopt;
      }
    }
    if (auto leader = leader_from_checkpoint(cfg_.network, validators_, *checkpoint, height, round); leader.has_value()) {
      return leader;
    }
  }
  return std::nullopt;
}

bool Node::is_committee_member_for(const PubKey32& pub, std::uint64_t height, std::uint32_t round) const {
  const auto committee = committee_for_height_round(height, round);
  return std::find(committee.begin(), committee.end(), pub) != committee.end();
}

std::size_t Node::active_operator_count_for_height_locked(std::uint64_t height) const {
  std::set<PubKey32> operators;
  for (const auto& [pub, info] : validators_.all()) {
    if (!validators_.is_active_for_height(pub, height)) continue;
    operators.insert(info.operator_id == PubKey32{} ? pub : info.operator_id);
  }
  return operators.size();
}

std::uint64_t Node::effective_validator_min_bond_for_height(std::uint64_t height) const {
  if (cfg_.validator_min_bond_override.has_value() || cfg_.validator_bond_min_amount_override.has_value()) {
    return std::max(validator_min_bond_, validator_bond_min_amount_);
  }
  const auto active_operator_count = active_operator_count_for_height_locked(height);
  return std::max<std::uint64_t>(validator_bond_min_amount_,
                                 consensus::validator_min_bond_units(cfg_.network, height, active_operator_count));
}

std::uint64_t Node::effective_validator_bond_max_for_height(std::uint64_t height) const {
  return std::max<std::uint64_t>(validator_bond_max_amount_, effective_validator_min_bond_for_height(height));
}

std::uint64_t Node::effective_min_relay_fee_for_height(std::uint64_t height) const {
  if (cfg_.min_relay_fee_explicit) return cfg_.min_relay_fee;
  // Relay fee remains a local policy choice, not a consensus rule. When no
  // explicit operator override is present, the fork enables a small default
  // floor to avoid fee-free relay as the chain moves toward fee-funded security.
  if (consensus::economics_fork_active(height)) return kDefaultPolicyMinRelayFeeUnits;
  return 0;
}

bool Node::validate_validator_registration_rules(const Block& block, std::uint64_t height) const {
  std::uint64_t window_start = validator_join_window_start_height_;
  std::uint32_t window_count = validator_join_count_in_window_;
  consensus::advance_validator_join_window(height, validator_join_limit_window_blocks_, &window_start, &window_count);

  auto registry = validators_;
  registry.set_rules(consensus::ValidatorRules{
      .min_bond = effective_validator_min_bond_for_height(height),
      .warmup_blocks = validator_warmup_blocks_,
      .cooldown_blocks = validator_cooldown_blocks_,
  });
  const auto min_bond_amount = effective_validator_min_bond_for_height(height);
  const auto max_bond_amount = effective_validator_bond_max_for_height(height);
  std::size_t new_regs = 0;
  for (std::size_t txi = 0; txi < block.txs.size(); ++txi) {
    const auto& tx = block.txs[txi];
    const Hash32 txid = tx.txid();
    std::map<PubKey32, PubKey32> join_request_operator_ids;
    for (const auto& out : tx.outputs) {
      PubKey32 validator_pub{};
      PubKey32 payout_pub{};
      Sig64 pop{};
      if (!is_validator_join_request_script(out.script_pubkey, &validator_pub, &payout_pub, &pop)) continue;
      join_request_operator_ids[validator_pub] = consensus::canonical_operator_id_from_join_request(payout_pub);
    }
    for (std::uint32_t out_i = 0; out_i < tx.outputs.size(); ++out_i) {
      const auto& out = tx.outputs[out_i];
      PubKey32 pub{};
      if (!is_validator_register_script(out.script_pubkey, &pub)) continue;
      if (out.value < min_bond_amount || out.value > max_bond_amount) return false;

      std::string err;
      if (!registry.can_register_bond(pub, height, out.value, &err)) return false;
      if (validator_join_limit_window_blocks_ > 0 && validator_join_limit_max_new_ > 0 &&
          window_count + static_cast<std::uint32_t>(new_regs + 1) > validator_join_limit_max_new_) {
        return false;
      }
      auto operator_it = join_request_operator_ids.find(pub);
      if (operator_it == join_request_operator_ids.end()) return false;
      if (!registry.register_bond(pub, OutPoint{txid, out_i}, height, out.value, &err, operator_it->second)) return false;
      ++new_regs;
    }
  }
  return true;
}

void Node::update_validator_liveness_from_finality(std::uint64_t height, std::uint32_t round,
                                            const std::vector<FinalitySig>& finality_sigs) {
  std::vector<PubKey32> committee = committee_for_height_round(height, round);
  update_validator_liveness_from_finality_impl(
      validators_, height, committee, finality_sigs, &validator_liveness_window_start_height_, validator_liveness_window_blocks_,
      validator_miss_rate_suspend_threshold_percent_, validator_miss_rate_exit_threshold_percent_, validator_suspend_duration_blocks_,
      &last_participation_eligible_signers_, &db_);
}

void Node::apply_validator_state_changes(const Block& block, const UtxoSet& pre_utxos, std::uint64_t height) {
  apply_validator_state_changes_impl(validators_, validator_join_requests_, block, pre_utxos, height,
                                     effective_validator_min_bond_for_height(height), validator_warmup_blocks_,
                                     validator_cooldown_blocks_, validator_join_limit_window_blocks_,
                                     validator_join_limit_max_new_,
                                     &validator_join_window_start_height_, &validator_join_count_in_window_, &db_);
  validators_.advance_height(height + 1);
  codec::ByteWriter w_start;
  w_start.u64le(validator_join_window_start_height_);
  (void)db_.put(kValidatorJoinWindowStartKey, w_start.take());
  codec::ByteWriter w_count;
  w_count.u32le(validator_join_count_in_window_);
  (void)db_.put(kValidatorJoinWindowCountKey, w_count.take());
  codec::ByteWriter w_epoch;
  w_epoch.u64le(validator_liveness_window_start_height_);
  (void)db_.put(kValidatorLivenessWindowStartKey, w_epoch.take());
  for (const auto& [pub, info] : validators_.all()) {
    db_.put_validator(pub, info);
  }
}

std::uint64_t Node::now_unix() const {
  using namespace std::chrono;
  return duration_cast<seconds>(system_clock::now().time_since_epoch()).count();
}

std::uint64_t Node::now_ms() const {
  using namespace std::chrono;
  return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

void Node::log_line(const std::string& s) const {
  if (!runtime_logs_enabled()) return;
  if (cfg_.log_json) {
    std::cout << "{\"type\":\"log\",\"node_id\":" << cfg_.node_id << ",\"network\":\"" << cfg_.network.name
              << "\",\"msg\":\"" << s << "\"}\n";
    return;
  }
  std::cout << "[node " << cfg_.node_id << "] " << s << "\n";
}

void Node::append_mining_log(const Block& block, std::uint32_t round, std::size_t votes, std::size_t quorum) {
  if (mining_log_path_.empty()) return;
  if (block.txs.empty()) return;

  const std::size_t committee_size = committee_for_height_round(block.header.height, round).size();

  std::uint64_t coinbase_total = 0;
  for (const auto& out : block.txs[0].outputs) coinbase_total += out.value;
  const std::uint64_t generated_coin = consensus::reward_units(block.header.height);
  const std::uint64_t validator_generated_coin = consensus::validator_reward_units(block.header.height);
  const std::uint64_t reserve_generated_coin = consensus::reserve_reward_units(block.header.height);
  const std::uint64_t fees = (coinbase_total > validator_generated_coin) ? (coinbase_total - validator_generated_coin) : 0;
  const std::size_t active_validators = validators_.active_sorted(block.header.height + 1).size();

  std::time_t ts = static_cast<std::time_t>(block.header.timestamp);
  std::tm tm_utc{};
#if defined(_WIN32)
  gmtime_s(&tm_utc, &ts);
#else
  gmtime_r(&ts, &tm_utc);
#endif
  std::ostringstream iso;
  iso << std::put_time(&tm_utc, "%Y-%m-%dT%H:%M:%SZ");

  std::ofstream out(mining_log_path_, std::ios::app);
  if (!out.good()) return;
  out << block.header.timestamp << " | " << iso.str() << " | h=" << block.header.height << " | round=" << round
      << " | generated_coin=" << generated_coin << " | validator_generated_coin=" << validator_generated_coin
      << " | reserve_generated_coin=" << reserve_generated_coin << " | fees=" << fees
      << " | coinbase_total=" << coinbase_total
      << " | active_validators=" << active_validators << " | committee=" << committee_size << " | votes=" << votes
      << "/" << quorum << " | transition_hash=" << hex_encode32(block.header.block_id()) << "\n";
}

void Node::spawn_local_bus_task(std::function<void()> fn) {
  std::lock_guard<std::mutex> lk(local_bus_tasks_mu_);
  local_bus_tasks_.emplace_back([f = std::move(fn)]() { f(); });
}

void Node::join_local_bus_tasks() {
  std::vector<std::thread> tasks;
  {
    std::lock_guard<std::mutex> lk(local_bus_tasks_mu_);
    tasks.swap(local_bus_tasks_);
  }
  for (auto& t : tasks) {
    if (!t.joinable()) continue;
    try {
      t.join();
    } catch (const std::system_error& e) {
      log_line(std::string("shutdown-join-exception source=local-bus error=\"") + e.what() + "\"");
    }
  }
}

void Node::load_persisted_peers() {
  if (bootstrap_template_mode_ && !bootstrap_validator_pubkey_.has_value()) return;
  const std::filesystem::path p = std::filesystem::path(cfg_.db_path) / "peers.dat";
  std::ifstream in(p);
  if (!in.good()) return;
  std::string line;
  while (std::getline(in, line)) {
    if (line.empty()) continue;
    for (const auto& ep : parse_endpoint_list(line)) {
      if (!ep.empty()) cfg_.peers.push_back(ep);
    }
  }
}

void Node::persist_peers() const {
  std::vector<p2p::PeerInfo> peers;
  peers.reserve(p2p_.peer_ids().size());
  for (int id : p2p_.peer_ids()) peers.push_back(p2p_.get_peer_info(id));
  persist_peers(peers);
}

void Node::persist_peers(const std::vector<p2p::PeerInfo>& peers) const {
  const std::filesystem::path p = std::filesystem::path(cfg_.db_path) / "peers.dat";
  std::ofstream out(p, std::ios::trunc);
  if (!out.good()) return;

  std::set<std::string> seen;
  for (const auto& ep : cfg_.peers) seen.insert(ep);
  for (const auto& ep : cfg_.seeds) seen.insert(ep);
  for (const auto& pi : peers) {
    if (auto na = addrman_address_for_peer(pi); na.has_value()) {
      seen.insert(na->key());
    }
  }
  for (const auto& ep : seen) out << ep << "\n";
}

void Node::load_addrman() {
  if (bootstrap_template_mode_ && !bootstrap_validator_pubkey_.has_value()) return;
  const std::filesystem::path p = std::filesystem::path(cfg_.db_path) / "addrman.dat";
  (void)addrman_.load(p.string());
}

void Node::persist_addrman() const {
  const std::filesystem::path p = std::filesystem::path(cfg_.db_path) / "addrman.dat";
  (void)addrman_.save(p.string());
}

std::vector<std::string> Node::resolve_dns_seeds_once() const {
  std::vector<std::string> out;
  std::set<std::string> dedup;
  for (const auto& ep : cfg_.network.default_seeds) {
    const auto pos = ep.rfind(':');
    if (pos == std::string::npos) continue;
    const std::string host = ep.substr(0, pos);
    const std::string port = ep.substr(pos + 1);
    if (host.empty() || port.empty()) continue;
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    if (getaddrinfo(host.c_str(), port.c_str(), &hints, &res) != 0) continue;
    for (addrinfo* it = res; it != nullptr; it = it->ai_next) {
      char ipbuf[INET6_ADDRSTRLEN]{};
      if (it->ai_family == AF_INET) {
        auto* sa = reinterpret_cast<sockaddr_in*>(it->ai_addr);
        if (!inet_ntop(AF_INET, &sa->sin_addr, ipbuf, sizeof(ipbuf))) continue;
      } else if (it->ai_family == AF_INET6) {
        auto* sa = reinterpret_cast<sockaddr_in6*>(it->ai_addr);
        if (!inet_ntop(AF_INET6, &sa->sin6_addr, ipbuf, sizeof(ipbuf))) continue;
      } else {
        continue;
      }
      dedup.insert(std::string(ipbuf) + ":" + port);
    }
    freeaddrinfo(res);
  }
  out.assign(dedup.begin(), dedup.end());
  return out;
}

void Node::maybe_request_getaddr(int peer_id) {
  std::lock_guard<std::mutex> lk(mu_);
  if (!getaddr_requested_peers_.insert(peer_id).second) return;
  (void)p2p_.send_to(peer_id, p2p::MsgType::GETADDR, p2p::ser_getaddr(p2p::GetAddrMsg{}), true);
}

std::vector<PubKey32> Node::ingress_committee_locked(std::uint64_t height) const {
  if (height == 0) return {};
  if (auto checkpoint = finalized_committee_checkpoint_for_height_locked(height); checkpoint.has_value()) {
    return consensus::checkpoint_committee_for_round(*checkpoint, 0);
  }
  auto committee = validators_.active_sorted(height);
  if (committee.empty()) committee = validators_.active_sorted(1);
  return committee;
}

std::array<std::uint64_t, INGRESS_LANE_COUNT> Node::local_ingress_lane_tips_locked() const {
  std::array<std::uint64_t, INGRESS_LANE_COUNT> tips{};
  for (std::uint32_t lane = 0; lane < INGRESS_LANE_COUNT; ++lane) {
    if (auto state = db_.get_lane_state(lane); state.has_value()) tips[lane] = state->max_seq;
  }
  return tips;
}

void Node::request_ingress_tips(int peer_id) {
  log_line("request-ingress-tips peer_id=" + std::to_string(peer_id));
  (void)p2p_.send_to(peer_id, p2p::MsgType::GET_INGRESS_TIPS, p2p::ser_get_ingress_tips(p2p::GetIngressTipsMsg{}), true);
}

void Node::send_ingress_tips(int peer_id) {
  p2p::IngressTipsMsg msg;
  {
    std::lock_guard<std::mutex> lk(mu_);
    msg.lane_tips = local_ingress_lane_tips_locked();
  }
  const bool ok = p2p_.send_to(peer_id, p2p::MsgType::INGRESS_TIPS, p2p::ser_ingress_tips(msg), true);
  std::ostringstream oss;
  oss << "send-ingress-tips peer_id=" << peer_id << " status=" << (ok ? "ok" : "failed") << " tips=";
  for (std::size_t lane = 0; lane < msg.lane_tips.size(); ++lane) {
    if (lane) oss << ",";
    oss << lane << ":" << msg.lane_tips[lane];
  }
  log_line(oss.str());
}

void Node::request_finalized_tip(int peer_id) {
  log_line("request-finalized-tip peer_id=" + std::to_string(peer_id) + " local_height=" + std::to_string(finalized_height_) +
           " local_transition=" + short_hash_hex(finalized_identity_.id));
  (void)p2p_.send_to(peer_id, p2p::MsgType::GET_FINALIZED_TIP,
                     p2p::ser_finalized_tip(p2p::FinalizedTipMsg{}), true);
}

void Node::send_finalized_tip(int peer_id) {
  // FINALIZED_TIP stays type-erased on the wire for compatibility; peers
  // exchange only the finalized identity value and reconstruct semantics
  // from mode/context locally.
  p2p::FinalizedTipMsg tip{finalized_height_, finalized_identity_.id};
  const bool ok = p2p_.send_to(peer_id, p2p::MsgType::FINALIZED_TIP, p2p::ser_finalized_tip(tip));
  log_line("send-finalized-tip peer_id=" + std::to_string(peer_id) + " height=" + std::to_string(tip.height) +
           " transition=" + short_hash_hex(tip.hash) + " status=" + (ok ? "ok" : "failed"));
}

void Node::broadcast_finalized_tip() {
  if (cfg_.disable_p2p) return;
  p2p::FinalizedTipMsg tip{finalized_height_, finalized_identity_.id};
  const Bytes payload = p2p::ser_finalized_tip(tip);
  for (int peer_id : p2p_.peer_ids()) {
    if (!p2p_.get_peer_info(peer_id).established()) continue;
    (void)p2p_.send_to(peer_id, p2p::MsgType::FINALIZED_TIP, payload, true);
  }
}

bool Node::handle_ingress_tips_locked(int peer_id, const p2p::IngressTipsMsg& msg) {
  peer_ingress_tips_[peer_id] = msg;
  const auto local_tips = local_ingress_lane_tips_locked();
  bool requested_any = false;
  std::size_t outstanding_for_peer = 0;
  for (const auto& [key, _] : requested_ingress_ranges_) {
    if (key.first == peer_id) ++outstanding_for_peer;
  }
  for (std::uint32_t lane = 0; lane < INGRESS_LANE_COUNT; ++lane) {
    const auto local_tip = local_tips[lane];
    const auto peer_tip = msg.lane_tips[lane];
    if (peer_tip <= local_tip) continue;
    if (outstanding_for_peer >= kMaxOutstandingIngressRequestsPerPeer) {
      log_line("request-ingress-range-skipped peer_id=" + std::to_string(peer_id) + " lane=" + std::to_string(lane) +
               " local_tip=" + std::to_string(local_tip) + " peer_tip=" + std::to_string(peer_tip) +
               " reason=too-many-outstanding-ingress-requests");
      continue;
    }
    const std::uint64_t unclamped_to = peer_tip;
    const std::uint64_t max_to = local_tip + static_cast<std::uint64_t>(kMaxIngressRangeRequestRecords);
    const p2p::GetIngressRangeMsg req{lane, local_tip + 1, std::min(unclamped_to, max_to)};
    requested_ingress_ranges_[{peer_id, lane}] = req;
    const bool ok = p2p_.send_to(peer_id, p2p::MsgType::GET_INGRESS_RANGE, p2p::ser_get_ingress_range(req), true);
    std::ostringstream oss;
    oss << "request-ingress-range peer_id=" << peer_id << " lane=" << lane << " local_tip=" << local_tip
        << " peer_tip=" << peer_tip << " range=[" << req.from_seq << "," << req.to_seq << "] status="
        << (ok ? "ok" : "failed");
    if (req.to_seq != unclamped_to) oss << " clamped=1";
    log_line(oss.str());
    requested_any = true;
    ++outstanding_for_peer;
  }
  if (!requested_any) {
    log_line("ingress-tips-in-sync peer_id=" + std::to_string(peer_id));
  }
  return true;
}

bool Node::handle_ingress_range_locked(int peer_id, const p2p::IngressRangeMsg& msg, std::string* error) {
  if (msg.lane >= INGRESS_LANE_COUNT || msg.from_seq == 0 || msg.to_seq < msg.from_seq) {
    if (error) *error = "invalid-range";
    log_line("ingress-range-reject peer_id=" + std::to_string(peer_id) + " lane=" + std::to_string(msg.lane) +
             " reason=invalid-range");
    return false;
  }
  const auto requested_it = requested_ingress_ranges_.find({peer_id, msg.lane});
  if (requested_it == requested_ingress_ranges_.end() || requested_it->second.from_seq != msg.from_seq ||
      requested_it->second.to_seq != msg.to_seq) {
    if (error) *error = "unexpected-range";
    log_line("ingress-range-reject peer_id=" + std::to_string(peer_id) + " lane=" + std::to_string(msg.lane) +
             " range=[" + std::to_string(msg.from_seq) + "," + std::to_string(msg.to_seq) + "] reason=unexpected-range");
    return false;
  }
  const auto expected_count = msg.to_seq - msg.from_seq + 1;
  if (msg.records.size() != expected_count) {
    if (error) *error = "incomplete-range";
    log_line("ingress-range-reject peer_id=" + std::to_string(peer_id) + " lane=" + std::to_string(msg.lane) +
             " range=[" + std::to_string(msg.from_seq) + "," + std::to_string(msg.to_seq) +
             "] reason=incomplete-range records=" + std::to_string(msg.records.size()));
    return false;
  }
  if (expected_count > kMaxIngressRangeResponseRecords || msg.records.size() > kMaxIngressRangeResponseRecords) {
    if (error) *error = "too-many-records";
    log_line("ingress-range-reject peer_id=" + std::to_string(peer_id) + " lane=" + std::to_string(msg.lane) +
             " range=[" + std::to_string(msg.from_seq) + "," + std::to_string(msg.to_seq) +
             "] reason=too-many-records records=" + std::to_string(msg.records.size()));
    return false;
  }
  const auto wire_bytes = ingress_range_wire_size(msg);
  if (wire_bytes > kMaxIngressRangeResponseBytes) {
    if (error) *error = "response-bytes-exceeded";
    log_line("ingress-range-reject peer_id=" + std::to_string(peer_id) + " lane=" + std::to_string(msg.lane) +
             " range=[" + std::to_string(msg.from_seq) + "," + std::to_string(msg.to_seq) +
             "] reason=response-bytes-exceeded bytes=" + std::to_string(wire_bytes));
    return false;
  }

  auto simulated_state = db_.get_lane_state(msg.lane);
  std::string validation_error;
  std::size_t prevalidation_bytes = 0;
  for (std::size_t i = 0; i < msg.records.size(); ++i) {
    const auto& record = msg.records[i];
    const auto expected_seq = msg.from_seq + static_cast<std::uint64_t>(i);
    prevalidation_bytes += ingress_record_wire_size(record);
    if (prevalidation_bytes > kMaxIngressPrevalidationBytes) {
      if (error) *error = "prevalidation-bytes-exceeded";
      log_line("ingress-range-reject peer_id=" + std::to_string(peer_id) + " lane=" + std::to_string(msg.lane) +
               " range=[" + std::to_string(msg.from_seq) + "," + std::to_string(msg.to_seq) +
               "] reason=prevalidation-bytes-exceeded bytes=" + std::to_string(prevalidation_bytes));
      return false;
    }
    if (record.certificate.lane != msg.lane || record.certificate.seq != expected_seq) {
      if (error) *error = "range-seq-mismatch";
      log_line("ingress-range-reject peer_id=" + std::to_string(peer_id) + " lane=" + std::to_string(msg.lane) +
               " seq=" + std::to_string(expected_seq) + " reason=range-seq-mismatch");
      return false;
    }
    if (auto existing_bytes = db_.get_ingress_certificate(msg.lane, expected_seq); existing_bytes.has_value()) {
      auto existing = IngressCertificate::parse(*existing_bytes);
      if (!existing.has_value()) {
        if (error) *error = "stored-cert-invalid";
        log_line("ingress-range-reject peer_id=" + std::to_string(peer_id) + " lane=" + std::to_string(msg.lane) +
                 " seq=" + std::to_string(expected_seq) + " reason=stored-cert-invalid");
        return false;
      }
      validation_error.clear();
      if (consensus::detect_ingress_equivocation(existing, record.certificate, &validation_error)) {
        std::string persist_error;
        if (!consensus::persist_ingress_equivocation_evidence(db_, *existing, record.certificate, &persist_error)) {
          validation_error = persist_error;
        }
        if (error) *error = validation_error;
        log_line("ingress-range-reject peer_id=" + std::to_string(peer_id) + " lane=" + std::to_string(msg.lane) +
                 " seq=" + std::to_string(expected_seq) + " reason=" + validation_error);
        return false;
      }
    }
    validation_error.clear();
    if (!consensus::validate_ingress_append(simulated_state, record.certificate, record.tx_bytes, &validation_error)) {
      if (error) *error = validation_error;
      log_line("ingress-range-reject peer_id=" + std::to_string(peer_id) + " lane=" + std::to_string(msg.lane) +
               " seq=" + std::to_string(expected_seq) + " reason=" + validation_error);
      return false;
    }
    validation_error.clear();
    const auto committee = ingress_committee_locked(record.certificate.epoch);
    if (!consensus::verify_ingress_certificate(record.certificate, committee, &validation_error)) {
      if (error) *error = validation_error;
      log_line("ingress-range-reject peer_id=" + std::to_string(peer_id) + " lane=" + std::to_string(msg.lane) +
               " seq=" + std::to_string(expected_seq) + " reason=" + validation_error);
      return false;
    }
    if (auto existing_tx = db_.get_ingress_bytes(record.certificate.txid);
        existing_tx.has_value() && *existing_tx != record.tx_bytes) {
      if (error) *error = "ingress-bytes-conflict";
      log_line("ingress-range-reject peer_id=" + std::to_string(peer_id) + " lane=" + std::to_string(msg.lane) +
               " seq=" + std::to_string(expected_seq) + " reason=ingress-bytes-conflict");
      return false;
    }
    simulated_state = LaneState{record.certificate.epoch,
                                record.certificate.lane,
                                record.certificate.seq,
                                consensus::compute_lane_root_append(
                                    simulated_state.has_value() ? simulated_state->lane_root : zero_hash(),
                                    record.certificate.tx_hash)};
  }

  for (const auto& record : msg.records) {
    validation_error.clear();
    const auto committee = ingress_committee_locked(record.certificate.epoch);
    if (!consensus::append_validated_ingress_record(db_, record.certificate, record.tx_bytes, committee, &validation_error)) {
      if (error) *error = validation_error;
      log_line("ingress-range-append-failed peer_id=" + std::to_string(peer_id) + " lane=" +
               std::to_string(msg.lane) + " seq=" + std::to_string(record.certificate.seq) + " reason=" + validation_error);
      return false;
    }
  }
  requested_ingress_ranges_.erase(requested_it);
  const auto local_tip = db_.get_lane_state(msg.lane).value_or(LaneState{}).max_seq;
  log_line("ingress-range-accepted peer_id=" + std::to_string(peer_id) + " lane=" + std::to_string(msg.lane) +
           " range=[" + std::to_string(msg.from_seq) + "," + std::to_string(msg.to_seq) + "] local_tip=" +
           std::to_string(local_tip) + " bytes=" + std::to_string(wire_bytes));
  return true;
}

bool Node::maybe_request_forward_sync_block_locked(int preferred_peer_id) {
  const std::uint64_t next_height = finalized_height_ + 1;
  const std::uint64_t retry_ms =
      std::max<std::uint64_t>(3000, static_cast<std::uint64_t>(cfg_.network.round_timeout_ms));
  const std::uint64_t tms = now_ms();

  auto eligible_peer = [&](int peer_id) {
    const auto info = p2p_.get_peer_info(peer_id);
    if (!info.established()) return false;
    auto tip_it = peer_finalized_tips_.find(peer_id);
    if (tip_it == peer_finalized_tips_.end()) return false;
    return tip_it->second.height >= next_height;
  };

  int target_peer = 0;
  if (preferred_peer_id != 0 && eligible_peer(preferred_peer_id)) {
    target_peer = preferred_peer_id;
  } else {
    std::uint64_t best_height = 0;
    for (const auto& [peer_id, tip] : peer_finalized_tips_) {
      if (!eligible_peer(peer_id)) continue;
      if (tip.height >= best_height) {
        best_height = tip.height;
        target_peer = peer_id;
      }
    }
  }
  if (target_peer == 0) return false;

  const auto tip_it = peer_finalized_tips_.find(target_peer);
  if (tip_it == peer_finalized_tips_.end()) return false;

  const std::uint64_t window_end = std::min(tip_it->second.height, finalized_height_ + kForwardSyncWindow);
  bool requested_any = false;
  for (std::uint64_t height = next_height; height <= window_end; ++height) {
    if (db_.get_height_hash(height).has_value()) continue;
    if (auto it = requested_sync_heights_.find(height); it != requested_sync_heights_.end() &&
        tms < it->second + retry_ms) {
      continue;
    }

    requested_sync_heights_[height] = tms;
    log_line("request-sync-next-height peer_id=" + std::to_string(target_peer) + " next_height=" +
             std::to_string(height));
    (void)p2p_.send_to(target_peer, p2p::MsgType::GET_TRANSITION_BY_HEIGHT,
                       p2p::ser_get_transition_by_height(p2p::GetTransitionByHeightMsg{height}), true);
    requested_any = true;
  }
  return requested_any;
}

bool Node::maybe_request_candidate_transition_locked(int peer_id, const Hash32& transition_id) {
  if (peer_id == 0 || cfg_.disable_p2p) return false;
  if (db_.get_frontier_transition(transition_id).has_value()) return false;
  if (candidate_frontier_proposals_.find(transition_id) != candidate_frontier_proposals_.end()) return false;

  const std::uint64_t retry_ms =
      std::max<std::uint64_t>(3000, static_cast<std::uint64_t>(cfg_.network.round_timeout_ms));
  const std::uint64_t tms = now_ms();
  if (auto it = requested_sync_artifacts_.find(transition_id); it != requested_sync_artifacts_.end() && tms < it->second + retry_ms) {
    return false;
  }

  requested_sync_artifacts_[transition_id] = tms;
  const bool ok = p2p_.send_to(peer_id, p2p::MsgType::GET_TRANSITION,
                               p2p::ser_get_transition(p2p::GetTransitionMsg{transition_id}), true);
  log_line("request-candidate-transition peer_id=" + std::to_string(peer_id) +
           " transition=" + short_hash_hex(transition_id) + " status=" + (ok ? "ok" : "failed"));
  return ok;
}

bool Node::seed_preflight_ok(const std::string& host, std::uint16_t port) {
  const std::string key = host + ":" + std::to_string(port);
  {
    std::lock_guard<std::mutex> lk(mu_);
    if (preflight_checked_seeds_.find(key) != preflight_checked_seeds_.end()) return true;
    preflight_checked_seeds_.insert(key);
  }

  // Avoid sacrificial TCP probes against public seeds. They look like real
  // inbound peers to a bootstrap node, trigger VERSION sends, and then close
  // before the actual handshake connection is attempted.
  if (!is_loopback_seed_host(host)) return true;

  addrinfo hints{};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  addrinfo* res = nullptr;
  if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res) != 0) return true;
  auto fd = net::kInvalidSocket;
  for (addrinfo* it = res; it != nullptr; it = it->ai_next) {
    fd = ::socket(it->ai_family, it->ai_socktype, it->ai_protocol);
    if (!net::valid_socket(fd)) continue;
    (void)net::set_socket_timeouts(fd, 1'000);
    if (::connect(fd, it->ai_addr, it->ai_addrlen) == 0) break;
    net::close_socket(fd);
    fd = net::kInvalidSocket;
  }
  freeaddrinfo(res);
  if (!net::valid_socket(fd)) return true;

  Bytes prefix;
  if (net::wait_readable(fd, 200) > 0) {
    std::array<std::uint8_t, 16> tmp{};
    const ssize_t n = net::recv_nonblocking(fd, tmp.data(), tmp.size());
    if (n > 0) prefix.assign(tmp.begin(), tmp.begin() + n);
  }
  net::shutdown_socket(fd);
  net::close_socket(fd);

  if (prefix.empty()) return true;
  const auto kind = p2p::classify_prefix(prefix);
  if (kind == p2p::PrefixKind::HTTP || kind == p2p::PrefixKind::JSON) {
    log_line("seed preflight warning " + key + " appears HTTP/JSON; likely lightserver port");
    return false;
  }
  if (kind == p2p::PrefixKind::TLS) {
    log_line("seed preflight warning " + key + " appears TLS; do not put TLS/proxy in front of P2P");
    return false;
  }
  return true;
}

bool Node::endpoint_matches_local_listener(const std::string& host, std::uint16_t port,
                                           std::vector<std::string>* resolved_endpoints) const {
  if (!cfg_.listen || port != cfg_.p2p_port) return false;

  const auto resolved_ips = resolve_ipv4_addresses(host);
  if (resolved_ips.empty()) return false;

  auto local_ips = local_ipv4_addresses();
  const auto bind_ips = resolve_ipv4_addresses(cfg_.bind_ip);
  local_ips.insert(bind_ips.begin(), bind_ips.end());

  bool matched = false;
  for (const auto& ip : resolved_ips) {
    if (resolved_endpoints) resolved_endpoints->push_back(ip + ":" + std::to_string(port));
    if (local_ips.find(ip) != local_ips.end()) matched = true;
  }
  return matched;
}

void Node::try_connect_bootstrap_peers() {
  struct Candidate {
    std::string peer;
    const char* source;
  };
  std::vector<Candidate> candidates;
  std::set<std::string> seen;
  {
    std::lock_guard<std::mutex> lk(mu_);
    for (const auto& p : bootstrap_peers_) {
      if (seen.insert(p).second) candidates.push_back({p, "seeds"});
    }
    for (const auto& p : dns_seed_peers_) {
      if (seen.insert(p).second) candidates.push_back({p, "dns"});
    }
    if (!bootstrap_template_mode_ || bootstrap_validator_pubkey_.has_value()) {
      for (const auto& a : addrman_.select_candidates(cfg_.outbound_target * 2, now_unix())) {
        if (seen.insert(a.key()).second) candidates.push_back({a.key(), "addrman"});
      }
    }
  }

  for (const auto& candidate : candidates) {
    const auto& peer = candidate.peer;
    const auto pos = peer.find(':');
    if (pos == std::string::npos) continue;
    const std::string host = peer.substr(0, pos);
    std::uint16_t port = 0;
    try {
      port = static_cast<std::uint16_t>(std::stoi(peer.substr(pos + 1)));
    } catch (...) {
      continue;
    }
    std::vector<std::string> resolved_self_endpoints;
    if (endpoint_matches_local_listener(host, port, &resolved_self_endpoints)) {
      bool should_log = false;
      {
        std::lock_guard<std::mutex> lk(mu_);
        should_log = suppress_self_endpoint_locked(peer);
        for (const auto& endpoint : resolved_self_endpoints) {
          should_log = suppress_self_endpoint_locked(endpoint) || should_log;
        }
      }
      if (should_log) {
        log_line("self-peer-skip endpoint=" + peer + " reason=local-endpoint-match");
      }
      continue;
    }
    {
      std::lock_guard<std::mutex> lk(mu_);
      if (is_self_endpoint_suppressed_locked(peer)) continue;
    }
    if (has_peer_endpoint(host, port)) continue;
    if (discipline_.is_banned(host, now_unix())) continue;
    if (!seed_preflight_ok(host, port)) continue;
    log_line("peer-connect-attempt endpoint=" + peer + " source=" + candidate.source);
    {
      std::lock_guard<std::mutex> lk(mu_);
      addrman_.mark_attempt(p2p::NetAddress{host, port}, now_unix());
    }
    if (!p2p_.connect_to(host, port)) {
      log_line("peer-connect-failed endpoint=" + peer + " source=" + candidate.source + " reason=tcp-connect-failed");
      continue;
    }
    {
      std::lock_guard<std::mutex> lk(mu_);
      last_bootstrap_source_ = candidate.source;
      addrman_.mark_success(p2p::NetAddress{host, port}, now_unix());
    }
  }
}

bool Node::has_peer_endpoint(const std::string& host, std::uint16_t port) const {
  const std::string endpoint = host + ":" + std::to_string(port);
  for (int pid : p2p_.peer_ids()) {
    const auto info = p2p_.get_peer_info(pid);
    if (info.endpoint == endpoint) return true;
    if (info.ip == host && !info.inbound) return true;
  }
  return false;
}

std::size_t Node::peer_count() const { return static_cast<std::size_t>(p2p_.peer_ids().size()); }

std::size_t Node::established_peer_count() const {
  std::size_t n = 0;
  for (int id : p2p_.peer_ids()) {
    if (p2p_.get_peer_info(id).established()) ++n;
  }
  return n;
}

std::size_t Node::outbound_peer_count() const {
  if (cfg_.disable_p2p) return peer_count();
  return p2p_.outbound_count();
}

std::string Node::peer_ip_for(int peer_id) const {
  std::lock_guard<std::mutex> lk(mu_);
  return peer_ip_for_locked(peer_id);
}

std::string Node::peer_ip_for_locked(int peer_id) const {
  auto it = peer_ip_cache_.find(peer_id);
  if (it != peer_ip_cache_.end()) return it->second;
  const auto pi = p2p_.get_peer_info(peer_id);
  if (!pi.ip.empty()) return pi.ip;
  return endpoint_to_ip(pi.endpoint);
}

bool Node::suppress_self_endpoint_locked(const std::string& endpoint) {
  if (endpoint.empty()) return false;
  return self_peer_endpoints_.insert(endpoint).second;
}

bool Node::is_self_endpoint_suppressed_locked(const std::string& endpoint) const {
  return !endpoint.empty() && self_peer_endpoints_.find(endpoint) != self_peer_endpoints_.end();
}

bool Node::is_bootstrap_peer_ip(const std::string& ip) const {
  if (ip.empty()) return false;
  auto matches_host = [&](const std::string& peer) {
    const auto pos = peer.find(':');
    const std::string host = (pos == std::string::npos) ? peer : peer.substr(0, pos);
    return host == ip;
  };
  for (const auto& peer : cfg_.peers) {
    if (matches_host(peer)) return true;
  }
  for (const auto& seed : cfg_.seeds) {
    if (matches_host(seed)) return true;
  }
  for (const auto& peer : bootstrap_peers_) {
    if (matches_host(peer)) return true;
  }
  return false;
}

std::optional<p2p::NetAddress> Node::addrman_address_for_peer(const p2p::PeerInfo& info) const {
  if (info.ip.empty()) return std::nullopt;
  if (info.inbound) return std::nullopt;
  if (!info.inbound) {
    auto parsed = p2p::parse_endpoint(info.endpoint);
    if (parsed.has_value()) return *parsed;
  }
  return std::nullopt;
}

void Node::score_peer(int peer_id, p2p::MisbehaviorReason reason, const std::string& note) {
  std::lock_guard<std::mutex> lk(mu_);
  score_peer_locked(peer_id, reason, note);
}

void Node::score_peer_locked(int peer_id, p2p::MisbehaviorReason reason, const std::string& note) {
  const std::string ip = peer_ip_for_locked(peer_id);
  if (ip.empty()) return;
  const p2p::PeerScoreStatus st = discipline_.add_score(ip, reason, now_unix());
  if (st.banned) {
    log_line("peer-banned ip=" + ip + " score=" + std::to_string(st.score) + " note=" + note);
    p2p_.disconnect_peer(peer_id);
  } else if (st.soft_muted) {
    log_line("peer-soft-muted ip=" + ip + " score=" + std::to_string(st.score) + " note=" + note);
  }
}

bool Node::should_mute_peer(int peer_id) const {
  if (peer_id <= 0) return false;
  std::lock_guard<std::mutex> lk(mu_);
  return should_mute_peer_locked(peer_id);
}

bool Node::should_mute_peer_locked(int peer_id) const {
  if (peer_id <= 0) return false;
  const std::string ip = peer_ip_for_locked(peer_id);
  if (ip.empty()) return false;
  return discipline_.status(ip, now_unix()).soft_muted;
}

void Node::prune_caches_locked(std::uint64_t height, std::uint32_t round) {
  for (auto it = proposed_in_round_.begin(); it != proposed_in_round_.end();) {
    if (it->first.first < height || (it->first.first == height && it->first.second + kProposalRoundWindow < round)) {
      it = proposed_in_round_.erase(it);
    } else {
      ++it;
    }
  }
  for (auto it = logged_committee_rounds_.begin(); it != logged_committee_rounds_.end();) {
    if (it->first < height || (it->first == height && it->second + kProposalRoundWindow < round)) {
      it = logged_committee_rounds_.erase(it);
    } else {
      ++it;
    }
  }
}

bool Node::check_rate_limit_locked(int peer_id, std::uint16_t msg_type) {
  if (peer_id <= 0) return true;
  auto& buckets = msg_rate_buckets_[peer_id];
  auto get = [&](std::uint16_t type, double cap, double refill) -> p2p::TokenBucket& {
    auto it = buckets.find(type);
    if (it == buckets.end()) {
      it = buckets.emplace(type, p2p::TokenBucket(cap, refill)).first;
    }
    return it->second;
  };

  const auto nms = now_ms();
  switch (msg_type) {
    case p2p::MsgType::TX:
      return get(msg_type, cfg_.tx_rate_capacity, cfg_.tx_rate_refill).consume(1.0, nms);
    case p2p::MsgType::PROPOSE:
      return get(msg_type, cfg_.propose_rate_capacity, cfg_.propose_rate_refill).consume(1.0, nms);
    case p2p::MsgType::VOTE:
      return get(msg_type, cfg_.vote_rate_capacity, cfg_.vote_rate_refill).consume(1.0, nms);
    case p2p::MsgType::TIMEOUT_VOTE:
      return get(msg_type, cfg_.vote_rate_capacity, cfg_.vote_rate_refill).consume(1.0, nms);
    case p2p::MsgType::TRANSITION:
      return get(msg_type, cfg_.block_rate_capacity, cfg_.block_rate_refill).consume(1.0, nms);
    case p2p::MsgType::GET_TRANSITION:
      return get(msg_type, 30.0, 15.0).consume(1.0, nms);
    case p2p::MsgType::GET_FINALIZED_TIP:
      return get(msg_type, 20.0, 10.0).consume(1.0, nms);
    case p2p::MsgType::GET_INGRESS_TIPS:
      return get(msg_type, 20.0, 10.0).consume(1.0, nms);
    case p2p::MsgType::INGRESS_TIPS:
      return get(msg_type, 20.0, 10.0).consume(1.0, nms);
    case p2p::MsgType::GET_INGRESS_RANGE:
      return get(msg_type, 15.0, 8.0).consume(1.0, nms);
    case p2p::MsgType::INGRESS_RANGE:
      return get(msg_type, 15.0, 8.0).consume(1.0, nms);
    case p2p::MsgType::GETADDR:
      return get(msg_type, 4.0, 1.0).consume(1.0, nms);
    case p2p::MsgType::ADDR:
      return get(msg_type, 8.0, 2.0).consume(1.0, nms);
    case p2p::MsgType::PING:
      return get(msg_type, 20.0, 10.0).consume(1.0, nms);
    case p2p::MsgType::PONG:
      return get(msg_type, 20.0, 10.0).consume(1.0, nms);
    case p2p::MsgType::INGRESS_RECORD:
      return get(msg_type, 20.0, 10.0).consume(1.0, nms);
    case p2p::MsgType::EPOCH_TICKET:
      return get(msg_type, 20.0, 10.0).consume(1.0, nms);
    case p2p::MsgType::GET_TRANSITION_BY_HEIGHT:
      return get(msg_type, 30.0, 15.0).consume(1.0, nms);
    case p2p::MsgType::GET_EPOCH_TICKETS:
      return get(msg_type, 10.0, 5.0).consume(1.0, nms);
    case p2p::MsgType::EPOCH_TICKETS:
      return get(msg_type, 10.0, 5.0).consume(1.0, nms);
    default:
      return true;
  }
}

std::optional<NodeConfig> parse_args(int argc, char** argv) {
  NodeConfig cfg;
  cfg.listen = false;  // safe CLI default: outbound-only unless --listen is set
  cfg.network = mainnet_network();
  cfg.p2p_port = cfg.network.p2p_default_port;
  cfg.lightserver_port = cfg.network.lightserver_default_port;
  cfg.max_committee = cfg.network.max_committee;
  cfg.db_path = default_db_dir_for_network(cfg.network.name);
  bool bind_explicit = false;
  bool db_explicit = false;
  std::string validator_passphrase_env;

  for (int i = 1; i < argc; ++i) {
    std::string a = argv[i];
    auto next = [&](const std::string& name) -> std::optional<std::string> {
      if (i + 1 >= argc) {
        std::cerr << "missing value for " << name << "\n";
        return std::nullopt;
      }
      return std::string(argv[++i]);
    };

    if (a == "--mainnet") {
      std::cerr << "--mainnet is not needed in mainnet-only build; remove this flag\n";
      return std::nullopt;
    } else if (a == "--node-id") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.node_id = std::stoi(*v);
    } else if (a == "--port") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.p2p_port = static_cast<std::uint16_t>(std::stoi(*v));
    } else if (a == "--listen") {
      cfg.listen = true;
    } else if (a == "--with-lightserver") {
      cfg.lightserver_mode = LightserverLaunchMode::Explicit;
    } else if (a == "--lightserver-bind") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.lightserver_bind = *v;
    } else if (a == "--lightserver-port") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.lightserver_port = static_cast<std::uint16_t>(std::stoi(*v));
    } else if (a == "--bind") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.bind_ip = *v;
      bind_explicit = true;
    } else if (a == "--db") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.db_path = *v;
      db_explicit = true;
    } else if (a == "--validator-key-file") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.validator_key_file = *v;
    } else if (a == "--validator-passphrase") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.validator_passphrase = *v;
    } else if (a == "--validator-passphrase-env") {
      auto v = next(a);
      if (!v) return std::nullopt;
      validator_passphrase_env = *v;
    } else if (a == "--genesis") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.genesis_path = *v;
    } else if (a == "--peers") {
      auto v = next(a);
      if (!v) return std::nullopt;
      for (const auto& item : parse_endpoint_list(*v)) cfg.peers.push_back(item);
    } else if (a == "--disable-p2p") {
      cfg.disable_p2p = true;
    } else if (a == "--no-reindex") {
      cfg.reindex_on_start = false;
    } else if (a == "--seeds") {
      auto v = next(a);
      if (!v) return std::nullopt;
      for (const auto& item : parse_endpoint_list(*v)) cfg.seeds.push_back(item);
    } else if (a == "--allow-unsafe-genesis-override") {
      cfg.allow_unsafe_genesis_override = true;
    } else if (a == "--outbound-target") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.outbound_target = static_cast<std::size_t>(std::stoull(*v));
    } else if (a == "--dns-seeds") {
      cfg.dns_seeds = true;
    } else if (a == "--no-dns-seeds") {
      cfg.dns_seeds = false;
    } else if (a == "--public") {
      cfg.public_mode = true;
      cfg.listen = true;
    } else if (a == "--max-committee") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.max_committee = static_cast<std::size_t>(std::stoull(*v));
    } else if (a == "--min-block-interval-ms") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.network.min_block_interval_ms = static_cast<std::uint32_t>(std::stoul(*v));
    } else if (a == "--round-timeout-ms") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.network.round_timeout_ms = static_cast<std::uint32_t>(std::stoul(*v));
    } else if (a == "--log-json") {
      cfg.log_json = true;
    } else if (a == "--handshake-timeout-ms") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.handshake_timeout_ms = static_cast<std::uint32_t>(std::stoul(*v));
    } else if (a == "--frame-timeout-ms") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.frame_timeout_ms = static_cast<std::uint32_t>(std::stoul(*v));
    } else if (a == "--idle-timeout-ms") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.idle_timeout_ms = static_cast<std::uint32_t>(std::stoul(*v));
    } else if (a == "--peer-queue-max-bytes") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.peer_queue_max_bytes = static_cast<std::size_t>(std::stoull(*v));
    } else if (a == "--peer-queue-max-msgs") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.peer_queue_max_msgs = static_cast<std::size_t>(std::stoull(*v));
    } else if (a == "--max-inbound") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.max_inbound = static_cast<std::size_t>(std::stoull(*v));
    } else if (a == "--ban-seconds") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.ban_seconds = static_cast<std::uint64_t>(std::stoull(*v));
    } else if (a == "--invalid-frame-ban-threshold") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.invalid_frame_ban_threshold = std::max(1, std::stoi(*v));
    } else if (a == "--invalid-frame-window-seconds") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.invalid_frame_window_seconds = std::max<std::uint64_t>(1, std::stoull(*v));
      } else if (a == "--min-relay-fee") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.min_relay_fee = static_cast<std::uint64_t>(std::stoull(*v));
      cfg.min_relay_fee_explicit = true;
    } else if (a == "--hashcash-enabled") {
      cfg.hashcash_enabled = true;
    } else if (a == "--hashcash-base-bits") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.hashcash_base_bits = static_cast<std::uint32_t>(std::stoul(*v));
      cfg.hashcash_enabled = (cfg.hashcash_base_bits != 0);
    } else if (a == "--hashcash-max-bits") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.hashcash_max_bits = static_cast<std::uint32_t>(std::stoul(*v));
    } else if (a == "--hashcash-epoch-seconds") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.hashcash_epoch_seconds = std::max<std::uint64_t>(1, std::stoull(*v));
    } else if (a == "--hashcash-fee-exempt-min") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.hashcash_fee_exempt_min = static_cast<std::uint64_t>(std::stoull(*v));
    } else if (a == "--hashcash-pressure-tx-threshold") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.hashcash_pressure_tx_threshold = static_cast<std::size_t>(std::stoull(*v));
    } else if (a == "--hashcash-pressure-step-txs") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.hashcash_pressure_step_txs = std::max<std::size_t>(1, static_cast<std::size_t>(std::stoull(*v)));
    } else if (a == "--hashcash-pressure-bits-per-step") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.hashcash_pressure_bits_per_step = static_cast<std::uint32_t>(std::stoul(*v));
    } else if (a == "--hashcash-large-tx-bytes") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.hashcash_large_tx_bytes = static_cast<std::size_t>(std::stoull(*v));
    } else if (a == "--hashcash-large-tx-extra-bits") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.hashcash_large_tx_extra_bits = static_cast<std::uint32_t>(std::stoul(*v));
    } else if (a == "--activation-enabled" || a == "--activation-max-version" || a == "--activation-window-blocks" ||
               a == "--activation-threshold-percent" || a == "--activation-delay-blocks") {
      std::cerr << "activation flags are not supported in fixed-cv7 mode\n";
      return std::nullopt;
    } else if (a == "--validator-min-bond") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.validator_min_bond_override = static_cast<std::uint64_t>(std::stoull(*v));
    } else if (a == "--validator-warmup-blocks") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.validator_warmup_blocks_override = static_cast<std::uint64_t>(std::stoull(*v));
    } else if (a == "--validator-cooldown-blocks") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.validator_cooldown_blocks_override = static_cast<std::uint64_t>(std::stoull(*v));
    } else if (a == "--validator-join-limit-window-blocks") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.validator_join_limit_window_blocks_override = static_cast<std::uint64_t>(std::stoull(*v));
    } else if (a == "--validator-join-limit-max-new") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.validator_join_limit_max_new_override = static_cast<std::uint32_t>(std::stoul(*v));
    } else if (a == "--liveness-window-blocks") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.liveness_window_blocks_override = static_cast<std::uint64_t>(std::stoull(*v));
    } else if (a == "--miss-rate-suspend-threshold-percent") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.miss_rate_suspend_threshold_percent_override = static_cast<std::uint32_t>(std::stoul(*v));
    } else if (a == "--miss-rate-exit-threshold-percent") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.miss_rate_exit_threshold_percent_override = static_cast<std::uint32_t>(std::stoul(*v));
    } else if (a == "--suspend-duration-blocks") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.suspend_duration_blocks_override = static_cast<std::uint64_t>(std::stoull(*v));
    } else {
      std::cerr << "unknown arg: " << a << "\n";
      return std::nullopt;
    }
  }

  if (!cfg.genesis_path.empty() && !cfg.allow_unsafe_genesis_override) {
    std::cerr << "--genesis override on mainnet requires --allow-unsafe-genesis-override\n";
    return std::nullopt;
  }
  if (cfg.validator_passphrase.empty() && !validator_passphrase_env.empty()) {
    const char* pv = std::getenv(validator_passphrase_env.c_str());
    if (pv) cfg.validator_passphrase = pv;
  }
  if (!db_explicit) cfg.db_path = default_db_dir_for_network(cfg.network.name);
  if (cfg.public_mode && !bind_explicit) cfg.bind_ip = "0.0.0.0";
  return cfg;
}

}  // namespace finalis::node
