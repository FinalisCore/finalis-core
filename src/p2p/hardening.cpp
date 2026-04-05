#include "p2p/hardening.hpp"

#include <algorithm>

namespace finalis::p2p {

TokenBucket::TokenBucket(double capacity, double refill_per_sec) { configure(capacity, refill_per_sec); }

void TokenBucket::configure(double capacity, double refill_per_sec) {
  capacity_ = std::max(0.0, capacity);
  refill_per_sec_ = std::max(0.0, refill_per_sec);
  tokens_ = capacity_;
  initialized_ = false;
}

void TokenBucket::refill(std::uint64_t now_ms) {
  if (!initialized_) {
    initialized_ = true;
    last_refill_ms_ = now_ms;
    tokens_ = capacity_;
    return;
  }
  if (now_ms <= last_refill_ms_) return;
  const double dt = static_cast<double>(now_ms - last_refill_ms_) / 1000.0;
  tokens_ = std::min(capacity_, tokens_ + dt * refill_per_sec_);
  last_refill_ms_ = now_ms;
}

bool TokenBucket::consume(double tokens, std::uint64_t now_ms) {
  refill(now_ms);
  if (tokens <= 0.0) return true;
  if (tokens_ + 1e-9 < tokens) return false;
  tokens_ -= tokens;
  if (tokens_ < 0.0) tokens_ = 0.0;
  return true;
}

double TokenBucket::available(std::uint64_t now_ms) const {
  const_cast<TokenBucket*>(this)->refill(now_ms);
  return tokens_;
}

PeerDiscipline::PeerDiscipline(int soft_mute_score, int ban_score, std::uint64_t ban_seconds,
                               int invalid_frame_ban_threshold, std::uint64_t invalid_frame_window_seconds)
    : soft_mute_score_(soft_mute_score),
      ban_score_(ban_score),
      ban_seconds_(ban_seconds),
      invalid_frame_ban_threshold_(std::max(1, invalid_frame_ban_threshold)),
      invalid_frame_window_seconds_(std::max<std::uint64_t>(1, invalid_frame_window_seconds)) {}

int PeerDiscipline::reason_score(MisbehaviorReason reason) const {
  switch (reason) {
    case MisbehaviorReason::INVALID_FRAME:
      return 35;
    case MisbehaviorReason::PRE_HANDSHAKE_CONSENSUS:
      return 20;
    case MisbehaviorReason::INVALID_PAYLOAD:
      return 15;
    case MisbehaviorReason::INVALID_INGRESS:
      return 18;
    case MisbehaviorReason::INGRESS_EQUIVOCATION:
      return 30;
    case MisbehaviorReason::INVALID_VOTE_SIGNATURE:
      return 20;
    case MisbehaviorReason::INVALID_PROPOSE:
      return 20;
    case MisbehaviorReason::DUPLICATE_SPAM:
      return 2;
    case MisbehaviorReason::RATE_LIMIT:
      return 5;
  }
  return 1;
}

PeerScoreStatus PeerDiscipline::add_score(const std::string& ip, MisbehaviorReason reason, std::uint64_t now_unix) {
  auto& e = entries_[ip];
  if (e.last_update > 0 && now_unix > e.last_update) {
    const std::uint64_t elapsed = now_unix - e.last_update;
    const int decay = static_cast<int>(elapsed / 30);
    if (decay > 0) e.score = std::max(0, e.score - decay);
  }
  e.last_update = now_unix;
  if (reason == MisbehaviorReason::INVALID_FRAME) {
    e.invalid_frame_strikes.push_back(now_unix);
    while (!e.invalid_frame_strikes.empty() &&
           e.invalid_frame_strikes.front() + invalid_frame_window_seconds_ < now_unix) {
      e.invalid_frame_strikes.pop_front();
    }
    if (static_cast<int>(e.invalid_frame_strikes.size()) >= invalid_frame_ban_threshold_) {
      const int s = reason_score(reason);
      if (static_cast<int>(e.invalid_frame_strikes.size()) == invalid_frame_ban_threshold_) {
        e.score += s * invalid_frame_ban_threshold_;
      } else {
        e.score += s;
      }
    }
  } else {
    e.score += reason_score(reason);
  }
  if (e.score >= ban_score_) e.ban_until = std::max(e.ban_until, now_unix + ban_seconds_);
  return status(ip, now_unix);
}

PeerScoreStatus PeerDiscipline::status(const std::string& ip, std::uint64_t now_unix) const {
  auto it = entries_.find(ip);
  if (it == entries_.end()) return {};
  PeerScoreStatus out;
  out.score = it->second.score;
  out.soft_muted = out.score >= soft_mute_score_;
  out.ban_until = it->second.ban_until;
  out.banned = now_unix < out.ban_until;
  return out;
}

bool PeerDiscipline::is_banned(const std::string& ip, std::uint64_t now_unix) const {
  auto it = entries_.find(ip);
  if (it == entries_.end()) return false;
  return now_unix < it->second.ban_until;
}

void PeerDiscipline::decay(std::uint64_t now_unix) {
  for (auto& [_, e] : entries_) {
    if (e.last_update == 0 || now_unix <= e.last_update) continue;
    const std::uint64_t elapsed = now_unix - e.last_update;
    const int decay = static_cast<int>(elapsed / 30);
    if (decay > 0) {
      e.score = std::max(0, e.score - decay);
      e.last_update = now_unix;
    }
  }
}

VoteVerifyCache::VoteVerifyCache(std::size_t capacity) : capacity_(capacity ? capacity : 1) {}

bool VoteVerifyCache::contains(const Key& key) const { return seen_.find(key) != seen_.end(); }

void VoteVerifyCache::insert(const Key& key) {
  if (seen_.find(key) != seen_.end()) return;
  seen_[key] = true;
  order_.push_back(key);
  while (order_.size() > capacity_) {
    const Key& k = order_.front();
    seen_.erase(k);
    order_.pop_front();
  }
}

void VoteVerifyCache::clear_height(std::uint64_t height) {
  while (!order_.empty()) {
    const Key& k = order_.front();
    if (std::get<0>(k) >= height) break;
    seen_.erase(k);
    order_.pop_front();
  }
}

RecentHashCache::RecentHashCache(std::size_t capacity) : capacity_(capacity ? capacity : 1) {}

bool RecentHashCache::contains(const Hash32& key) const { return seen_.find(key) != seen_.end(); }

void RecentHashCache::insert(const Hash32& key) {
  if (seen_.find(key) != seen_.end()) return;
  seen_[key] = true;
  order_.push_back(key);
  while (order_.size() > capacity_) {
    const Hash32& oldest = order_.front();
    seen_.erase(oldest);
    order_.pop_front();
  }
}

void RecentHashCache::clear() {
  seen_.clear();
  order_.clear();
}

}  // namespace finalis::p2p
