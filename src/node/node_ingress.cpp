// SPDX-License-Identifier: MIT

// Transaction admission and certified ingress lanes: tx handling, local certification, designated-
// certifier forwarding, ingress tips/range sync.

#include "node.hpp"
#include "node_internal.hpp"

#include <algorithm>
#include <array>
#include <sstream>

#include "consensus/canonical_derivation.hpp"
#include "consensus/randomness.hpp"
#include "consensus/ingress.hpp"
#include "consensus/validator_registry.hpp"
#include "crypto/ed25519.hpp"
#include "crypto/hash.hpp"
#include "utxo/confidential_tx.hpp"

namespace finalis::node {
using namespace detail;

namespace {

constexpr std::size_t kMaxIngressPrevalidationBytes = 512 * 1024;
constexpr std::size_t kMaxOutstandingIngressRequestsPerPeer = 8;
constexpr std::uint64_t kDefaultPolicyMinRelayFeeUnits = 1'000ULL;

p2p::MisbehaviorReason ingress_fault_reason_for(const std::string& error) {
  if (error == "ingress-equivocation-detected" || error == "ingress-equivocation-evidence-store-failed") {
    return p2p::MisbehaviorReason::INGRESS_EQUIVOCATION;
  }
  return p2p::MisbehaviorReason::INVALID_INGRESS;
}

}  // namespace

void Node::on_get_ingress_tips(int peer_id, const Bytes& payload) {
  constexpr std::uint16_t msg_type = p2p::MsgType::GET_INGRESS_TIPS;
  auto req = p2p::de_get_ingress_tips(payload);
  if (!req.has_value()) {
    score_peer(peer_id, p2p::MisbehaviorReason::INVALID_PAYLOAD, "bad-get-ingress-tips");
    return;
  }
  log_line("recv " + std::string(msg_type_name(msg_type)) + " peer_id=" + std::to_string(peer_id));
  send_ingress_tips(peer_id);
  return;
}

void Node::on_ingress_tips(int peer_id, const Bytes& payload) {
  constexpr std::uint16_t msg_type = p2p::MsgType::INGRESS_TIPS;
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
  return;
}

void Node::on_get_ingress_range(int peer_id, const Bytes& payload) {
  constexpr std::uint16_t msg_type = p2p::MsgType::GET_INGRESS_RANGE;
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
  return;
}

void Node::on_ingress_range(int peer_id, const Bytes& payload) {
  constexpr std::uint16_t msg_type = p2p::MsgType::INGRESS_RANGE;
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
    // ingress-epoch-mismatch is not peer misbehavior: it occurs when the peer
    // is in a different committee epoch (i.e., they are ahead of us in chain
    // sync). Scoring them would cause them to be banned before we can catch up.
    if (ingress_error != "ingress-epoch-mismatch") {
      const auto reason = ingress_fault_reason_for(ingress_error);
      const std::string note = ingress_error.empty() ? "invalid-ingress-range" : ingress_error;
      score_peer_locked(peer_id, reason, note);
    }
  }
  return;
}

void Node::on_ingress_record(int peer_id, const Bytes& payload) {
  constexpr std::uint16_t msg_type = p2p::MsgType::INGRESS_RECORD;
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
    // Same epoch-mismatch guard as INGRESS_RANGE: don't penalise a peer
    // whose certificates belong to a later committee epoch.
    if (ingress_error != "ingress-epoch-mismatch") {
      const auto reason = ingress_fault_reason_for(ingress_error);
      const std::string note = ingress_error.empty() ? "invalid-ingress-record" : ingress_error;
      score_peer_locked(peer_id, reason, note);
    }
    return;
  }
  if (appended) broadcast_ingress_record(record->certificate, record->tx_bytes, peer_id);
  return;
}

void Node::on_tx(int peer_id, const Bytes& payload, const Hash32& payload_id) {
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
  return;
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
    mempool_.set_validation_context(special_validation_context_locked(next_height));
    (void)mempool_.set_confidential_pool_value(mempool_confidential_pool_value_locked());
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

  const auto expected_ingress_epoch = consensus::committee_epoch_start(finalized_height_ + 1, cfg_.network.committee_epoch_blocks);
  auto committee = ingress_committee_locked(expected_ingress_epoch);
  std::string append_error;
  if (!consensus::append_validated_ingress_record(db_, msg.certificate, msg.tx_bytes, committee,
                                                  expected_ingress_epoch, &append_error)) {
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
  if (!consensus::append_validated_ingress_record(db_, cert, tx_bytes, committee, cert.epoch, &append_error)) {
    if (error) *error = append_error;
    return false;
  }

  if (error) error->clear();
  log_line("ingress-local-certified txid=" + hex_encode32(txid) + " lane=" + std::to_string(lane) +
           " seq=" + std::to_string(cert.seq) + " epoch=" + std::to_string(cert.epoch));
  broadcast_ingress_record(cert, tx_bytes);
  return true;
}

void Node::maybe_forward_tx_to_designated_certifier_locked(const AnyTx& tx, int skip_peer_id) {
  const std::uint64_t next_height = finalized_height_ + 1;
  auto committee = ingress_committee_locked(next_height);
  if (committee.empty()) return;

  const std::uint32_t lane = consensus::assign_ingress_lane(tx);
  const PubKey32& designated_certifier = committee[static_cast<std::size_t>(lane) % committee.size()];
  if (designated_certifier == local_key_.public_key) return;

  if (cfg_.disable_p2p) {
    for_each_local_bus_peer([&](Node* peer) {
      if (peer->local_validator_pubkey_for_test() != designated_certifier) return false;
      spawn_local_bus_task([peer, tx]() { (void)peer->handle_tx(tx, true); });
      log_line("tx-forward-designated lane=" + std::to_string(lane) +
               " designated=" + short_pub_hex(designated_certifier) + " transport=local-bus");
      return true;
    });
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

std::uint64_t Node::effective_min_relay_fee_for_height(std::uint64_t height) const {
  if (cfg_.min_relay_fee_explicit) return cfg_.min_relay_fee;
  // CLEANSLATE: The fee-relay floor applies from genesis without fork gating.
  (void)height;
  return kDefaultPolicyMinRelayFeeUnits;
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

bool Node::handle_ingress_tips_locked(int peer_id, const p2p::IngressTipsMsg& msg) {
  peer_ingress_tips_[peer_id] = msg;
  // Do not request ingress from a peer that is in a different committee epoch.
  // Their certificates carry an epoch we cannot validate against our local
  // finalized state, which would cause spurious ingress-epoch-mismatch errors
  // and incorrectly ban the peer before chain sync completes.
  const auto local_epoch =
      consensus::committee_epoch_start(finalized_height_ + 1, cfg_.network.committee_epoch_blocks);
  if (const auto tip_it = peer_finalized_tips_.find(peer_id); tip_it != peer_finalized_tips_.end()) {
    const auto peer_epoch = consensus::committee_epoch_start(tip_it->second.height + 1,
                                                             cfg_.network.committee_epoch_blocks);
    if (peer_epoch != local_epoch) {
      log_line("ingress-tips-epoch-skipped peer_id=" + std::to_string(peer_id) +
               " local_epoch=" + std::to_string(local_epoch) +
               " peer_epoch=" + std::to_string(peer_epoch) +
               " reason=epoch-mismatch-chain-sync-pending");
      return true;
    }
    std::uint64_t max_peer_height = tip_it->second.height;
    for (const auto& [id, tip] : peer_finalized_tips_) {
      const auto info = p2p_.get_peer_info(id);
      if (!info.established()) continue;
      max_peer_height = std::max(max_peer_height, tip.height);
    }
    if (max_peer_height > tip_it->second.height && (max_peer_height - tip_it->second.height) > 2) {
      log_line("ingress-tips-stale-skipped peer_id=" + std::to_string(peer_id) +
               " peer_height=" + std::to_string(tip_it->second.height) +
               " max_peer_height=" + std::to_string(max_peer_height) +
               " reason=stale-finalized-tip");
      return true;
    }
  }
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

  const auto expected_ingress_epoch = consensus::committee_epoch_start(finalized_height_ + 1, cfg_.network.committee_epoch_blocks);
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
    bool already_held = false;
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
      already_held = *existing == record.certificate;
    }
    if (already_held) {
      // Already appended, typically via gossip racing this range response: a no-op, as in
      // append_validated_ingress_record, not a discontinuity to score the peer for. The local tip
      // already covers this seq, so simulated_state stays put. The payload must still match.
      validation_error.clear();
      if (!consensus::validate_ingress_payload(record.certificate, record.tx_bytes, &validation_error)) {
        if (error) *error = validation_error;
        log_line("ingress-range-reject peer_id=" + std::to_string(peer_id) + " lane=" + std::to_string(msg.lane) +
                 " seq=" + std::to_string(expected_seq) + " reason=" + validation_error);
        return false;
      }
      continue;
    }
    validation_error.clear();
    if (!consensus::validate_ingress_append(simulated_state, record.certificate, record.tx_bytes,
                                            expected_ingress_epoch, &validation_error)) {
      if (error) *error = validation_error;
      log_line("ingress-range-reject peer_id=" + std::to_string(peer_id) + " lane=" + std::to_string(msg.lane) +
               " seq=" + std::to_string(expected_seq) + " reason=" + validation_error);
      return false;
    }
    validation_error.clear();
    const auto committee = ingress_committee_locked(expected_ingress_epoch);
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
    const auto committee = ingress_committee_locked(expected_ingress_epoch);
    if (!consensus::append_validated_ingress_record(db_, record.certificate, record.tx_bytes, committee,
                                                    expected_ingress_epoch, &validation_error)) {
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

}  // namespace finalis::node
