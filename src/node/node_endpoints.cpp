// SPDX-License-Identifier: MIT

// Public lightserver discovery: this node's signed endpoint announcement, the table of endpoints it
// learned, pull-based exchange with peers, and the copy in the DB its lightserver serves
// (get_lightserver_endpoints). See p2p/endpoints.hpp; nothing here is consensus.

#include "node.hpp"
#include "node_internal.hpp"

#include "lightserver/client.hpp"

namespace finalis::node {
using namespace detail;

namespace {
constexpr std::uint64_t kEndpointPullIntervalMs = 30ULL * 60 * 1000;
constexpr std::uint64_t kEndpointPersistIntervalMs = 60ULL * 1000;
constexpr std::uint64_t kEndpointSelfCheckDelayMs = 5ULL * 1000;
constexpr std::uint64_t kEndpointSelfCheckRetryMs = 10ULL * 60 * 1000;
enum EndpointCheck : int { kCheckIdle = 0, kCheckRunning = 1, kCheckOk = 2, kCheckFailed = 3 };
}  // namespace

void Node::maybe_request_endpoints(int peer_id) {
  std::lock_guard<std::mutex> lk(mu_);
  if (!endpoints_requested_peers_.insert(peer_id).second) return;
  (void)p2p_.send_to(peer_id, p2p::MsgType::GET_ENDPOINTS, p2p::ser_get_endpoints(p2p::GetEndpointsMsg{}), true);
}

void Node::on_get_endpoints(int peer_id, const Bytes& payload) {
  if (!p2p::de_get_endpoints(payload).has_value()) {
    score_peer(peer_id, p2p::MisbehaviorReason::INVALID_PAYLOAD, "bad-get-endpoints");
    return;
  }
  p2p::EndpointsMsg msg;
  {
    std::lock_guard<std::mutex> lk(mu_);
    msg.entries = endpoints_.sample(p2p::kMaxEndpointsPerMsg - 1, endpoint_rng_);
    if (own_endpoint_.has_value() && own_endpoint_verified_) msg.entries.push_back(*own_endpoint_);
  }
  if (msg.entries.empty()) return;
  (void)p2p_.send_to(peer_id, p2p::MsgType::ENDPOINTS, p2p::ser_endpoints(msg), true);
}

void Node::on_endpoints(int peer_id, const Bytes& payload) {
  const auto msg = p2p::de_endpoints(payload);
  if (!msg.has_value()) {
    score_peer(peer_id, p2p::MisbehaviorReason::INVALID_PAYLOAD, "bad-endpoints");
    return;
  }
  const auto now = now_unix();
  std::size_t added = 0;
  std::size_t invalid = 0;
  {
    std::lock_guard<std::mutex> lk(mu_);
    for (const auto& a : msg->entries) {
      if (own_endpoint_.has_value() && a.pubkey == own_endpoint_->pubkey) continue;
      // An expired or slightly-ahead entry can be an honest relay of an old announcement; only a bad
      // signature or URL counts against the sender.
      if (!p2p::verify_endpoint_announcement(consensus_domain_, a, now, endpoints_allow_private())) {
        const bool timing = a.issued_unix + p2p::kEndpointTtlSeconds < now ||
                            a.issued_unix > now + p2p::kEndpointMaxFutureSkewSeconds;
        if (!timing) ++invalid;
        continue;
      }
      const auto r = endpoints_.insert(a, now);
      if (r == p2p::EndpointTable::InsertResult::Added || r == p2p::EndpointTable::InsertResult::Updated) {
        ++added;
        endpoints_dirty_ = true;
      }
    }
  }
  if (invalid > 0) score_peer(peer_id, p2p::MisbehaviorReason::INVALID_PAYLOAD, "invalid-endpoint-announcement");
  if (added > 0) {
    log_line("endpoints-learned peer_id=" + std::to_string(peer_id) + " added=" + std::to_string(added));
  }
}

// This node's own announcement: signed and stored (so its lightserver's get_status reports the key),
// then gossiped once the URL is seen to reach this node's lightserver. A registered validator does not
// announce unless asked to (--announce-endpoint-as-validator): a published validator address invites
// attacks that can halt the chain, while losing a plain public node costs one data source.
void Node::maintain_endpoints() {
  if (cfg_.disable_p2p) return;
  const auto now = now_unix();
  const auto nms = now_ms();
  std::optional<p2p::EndpointAnnouncement> to_announce;
  std::optional<std::string> self_check_url;
  std::optional<int> pull_peer;
  {
    std::lock_guard<std::mutex> lk(mu_);
    if (!cfg_.public_lightserver_url.empty() &&
        !p2p::valid_endpoint_url(cfg_.public_lightserver_url, endpoints_allow_private())) {
      log_line("endpoint-announce-disabled reason=url-not-public url=" + cfg_.public_lightserver_url);
      cfg_.public_lightserver_url.clear();
    }
    bool may_announce = endpoint_key_.has_value() && !cfg_.public_lightserver_url.empty();
    if (may_announce && !cfg_.announce_endpoint_as_validator) {
      const auto info = validators_.get(local_key_.public_key);
      if (info.has_value() && info->status != consensus::ValidatorStatus::BANNED) {
        may_announce = false;
        if (own_endpoint_.has_value()) {
          own_endpoint_.reset();
          own_endpoint_verified_ = false;
          endpoints_dirty_ = true;
          last_endpoint_persist_ms_ = 0;
          log_line("endpoint-withdrawn reason=local-validator (pass --announce-endpoint-as-validator to announce)");
        }
      }
    }
    if (may_announce &&
        (!own_endpoint_.has_value() || now >= own_endpoint_->issued_unix + p2p::kEndpointReannounceSeconds)) {
      const bool was_verified = own_endpoint_.has_value() && own_endpoint_verified_;
      own_endpoint_ = p2p::sign_endpoint_announcement(consensus_domain_, *endpoint_key_, cfg_.public_lightserver_url, now);
      if (own_endpoint_.has_value()) {
        endpoints_dirty_ = true;
        last_endpoint_persist_ms_ = 0;  // stored now, so the self-check finds the key
        // A refresh of a URL already seen working goes out at once.
        own_endpoint_verified_ = was_verified;
        if (was_verified) to_announce = own_endpoint_;
        next_endpoint_self_check_ms_ = nms + kEndpointSelfCheckDelayMs;
      }
    }
    if (own_endpoint_.has_value() && !own_endpoint_verified_) {
      const int check = endpoint_self_check_.load();
      if (check == kCheckOk) {
        endpoint_self_check_ = kCheckIdle;
        own_endpoint_verified_ = true;
        to_announce = own_endpoint_;
      } else if (check == kCheckFailed) {
        endpoint_self_check_ = kCheckIdle;
        next_endpoint_self_check_ms_ = nms + kEndpointSelfCheckRetryMs;
        log_line("endpoint-self-check-failed url=" + own_endpoint_->url + " detail=" + endpoint_self_check_detail_ +
                 " (not announced; retry in 10 min)");
      } else if (check == kCheckIdle && nms >= next_endpoint_self_check_ms_) {
        endpoint_self_check_ = kCheckRunning;
        self_check_url = own_endpoint_->url;
      }
    }
    const auto before = endpoints_.size();
    endpoints_.expire(now);
    if (endpoints_.size() != before) endpoints_dirty_ = true;
    if (nms >= last_endpoint_pull_ms_ + kEndpointPullIntervalMs) {
      last_endpoint_pull_ms_ = nms;
      const auto peers = p2p_.peer_ids();
      if (!peers.empty()) {
        pull_peer = peers[std::uniform_int_distribution<std::size_t>(0, peers.size() - 1)(endpoint_rng_)];
      }
    }
    if (endpoints_dirty_ && nms >= last_endpoint_persist_ms_ + kEndpointPersistIntervalMs) {
      last_endpoint_persist_ms_ = nms;
      persist_endpoints_locked();
    }
  }
  if (self_check_url.has_value()) {
    // The check is network I/O with a 15 s socket timeout: off the event loop.
    if (endpoint_self_check_thread_.joinable()) endpoint_self_check_thread_.join();
    const std::string expected =
        hex_encode(Bytes(endpoint_key_->public_key.begin(), endpoint_key_->public_key.end()));
    endpoint_self_check_thread_ = std::thread([this, url = *self_check_url, expected]() {
      std::string err;
      const auto status = lightserver::rpc_get_status(url, &err);
      std::string detail;
      if (!status) {
        detail = "unreachable:" + err;
      } else if (status->endpoint_pubkey_hex != expected) {
        detail = "url-reaches-another-server";
      }
      {
        std::lock_guard<std::mutex> lk(mu_);
        endpoint_self_check_detail_ = detail;
      }
      endpoint_self_check_ = detail.empty() ? kCheckOk : kCheckFailed;
    });
  }
  if (to_announce.has_value()) {
    p2p_.broadcast(p2p::MsgType::ENDPOINTS, p2p::ser_endpoints(p2p::EndpointsMsg{{*to_announce}}));
    log_line("endpoint-announced url=" + to_announce->url +
             " pubkey=" + short_pub_hex(to_announce->pubkey));
  }
  if (pull_peer.has_value()) {
    (void)p2p_.send_to(*pull_peer, p2p::MsgType::GET_ENDPOINTS, p2p::ser_get_endpoints(p2p::GetEndpointsMsg{}), true);
  }
}

void Node::persist_endpoints_locked() {
  endpoints_dirty_ = false;
  storage::DB::Batch batch(db_);
  std::set<std::string> keep;
  for (const auto& a : endpoints_.all()) {
    const auto key = storage::key_lightserver_endpoint(a.pubkey);
    keep.insert(key);
    batch.put(key, p2p::ser_endpoint_announcement(a));
  }
  for (const auto& [key, _] : db_.scan_prefix(storage::key_lightserver_endpoint_prefix())) {
    if (!keep.contains(key)) batch.erase(key);
  }
  if (own_endpoint_.has_value()) {
    batch.put(storage::key_own_lightserver_endpoint(), p2p::ser_endpoint_announcement(*own_endpoint_));
  } else {
    batch.erase(storage::key_own_lightserver_endpoint());
  }
  if (!db_.write_batch(batch)) log_line("endpoint-persist-failed");
}

}  // namespace finalis::node
