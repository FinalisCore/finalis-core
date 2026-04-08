#include "p2p/addrman.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <sstream>

namespace finalis::p2p {
namespace {

bool is_unroutable_ip(const std::string& ip) {
  in_addr v4{};
  if (inet_pton(AF_INET, ip.c_str(), &v4) == 1) {
    const std::uint32_t host = ntohl(v4.s_addr);
    const std::uint8_t a = static_cast<std::uint8_t>((host >> 24) & 0xFF);
    const std::uint8_t b = static_cast<std::uint8_t>((host >> 16) & 0xFF);
    if (a == 0 || a == 10 || a == 127) return true;
    if (a == 169 && b == 254) return true;
    if (a == 172 && b >= 16 && b <= 31) return true;
    if (a == 192 && b == 168) return true;
    if (a >= 224) return true;  // multicast/reserved/broadcast.
    return false;
  }

  in6_addr v6{};
  if (inet_pton(AF_INET6, ip.c_str(), &v6) == 1) {
    if (IN6_IS_ADDR_UNSPECIFIED(&v6) || IN6_IS_ADDR_LOOPBACK(&v6) || IN6_IS_ADDR_MULTICAST(&v6)) return true;
    const std::uint8_t first = v6.s6_addr[0];
    const std::uint8_t second = v6.s6_addr[1];
    if ((first & 0xFE) == 0xFC) return true;  // fc00::/7
    if (first == 0xFE && (second & 0xC0) == 0x80) return true;  // fe80::/10
    return false;
  }

  return true;
}

}  // namespace

std::string NetAddress::key() const { return ip + ":" + std::to_string(port); }

std::optional<NetAddress> parse_endpoint(const std::string& endpoint) {
  const auto pos = endpoint.rfind(':');
  if (pos == std::string::npos) return std::nullopt;
  const std::string host = endpoint.substr(0, pos);
  const std::string port_s = endpoint.substr(pos + 1);
  if (host.empty() || port_s.empty()) return std::nullopt;
  try {
    const auto p = static_cast<std::uint16_t>(std::stoul(port_s));
    return NetAddress{host, p};
  } catch (...) {
    return std::nullopt;
  }
}

void AddrMan::set_policy(AddrPolicy policy) {
  policy_ = std::move(policy);
  prune_invalid_locked();
  enforce_limit();
}

AddrRejectReason AddrMan::validate(const NetAddress& addr) const {
  if (addr.ip.empty()) return AddrRejectReason::EMPTY_IP;
  if (addr.port == 0) return AddrRejectReason::ZERO_PORT;
  if (policy_.required_port.has_value() && addr.port != *policy_.required_port) return AddrRejectReason::PORT_MISMATCH;
  if (policy_.reject_unroutable && is_unroutable_ip(addr.ip)) return AddrRejectReason::UNROUTABLE_IP;
  return AddrRejectReason::NONE;
}

void AddrMan::add_or_update(const NetAddress& addr, std::uint64_t last_seen) {
  if (!accepts(addr)) return;
  auto& e = entries_[addr.key()];
  if (e.addr.ip.empty()) e.addr = addr;
  e.last_seen = std::max(e.last_seen, last_seen);
  enforce_limit();
}

void AddrMan::mark_attempt(const NetAddress& addr, std::uint64_t now) {
  if (!accepts(addr)) return;
  auto& e = entries_[addr.key()];
  e.addr = addr;
  e.last_attempt = now;
}

void AddrMan::mark_success(const NetAddress& addr, std::uint64_t now) {
  if (!accepts(addr)) return;
  auto& e = entries_[addr.key()];
  e.addr = addr;
  e.last_seen = std::max(e.last_seen, now);
  e.last_attempt = now;
  e.success_count += 1;
  if (e.score < 1000) e.score += 10;
  if (e.fail_count > 0) e.fail_count -= 1;
}

void AddrMan::mark_fail(const NetAddress& addr, std::uint64_t now, const std::string& err) {
  if (!accepts(addr)) return;
  auto& e = entries_[addr.key()];
  e.addr = addr;
  e.last_attempt = now;
  e.fail_count += 1;
  e.last_error = err;
  if (e.score > -1000) e.score -= 20;
}

std::uint64_t AddrMan::backoff_seconds(const AddrEntry& e) {
  const std::uint32_t exp = std::min<std::uint32_t>(e.fail_count, 10U);
  const std::uint64_t base = (1ULL << exp) * 5ULL;
  return std::min<std::uint64_t>(base, 3600ULL);
}

std::vector<NetAddress> AddrMan::select_candidates(std::size_t n, std::uint64_t now) const {
  std::vector<const AddrEntry*> all;
  all.reserve(entries_.size());
  for (const auto& [_, e] : entries_) {
    if (!accepts(e.addr)) continue;
    const auto bo = backoff_seconds(e);
    if (e.last_attempt > 0 && now < e.last_attempt + bo) continue;
    all.push_back(&e);
  }

  std::sort(all.begin(), all.end(), [](const AddrEntry* a, const AddrEntry* b) {
    if (a->score != b->score) return a->score > b->score;
    if (a->last_seen != b->last_seen) return a->last_seen > b->last_seen;
    return a->addr.key() < b->addr.key();
  });

  std::vector<NetAddress> out;
  out.reserve(std::min(n, all.size()));
  for (std::size_t i = 0; i < all.size() && out.size() < n; ++i) out.push_back(all[i]->addr);
  return out;
}

void AddrMan::prune_invalid_locked() {
  for (auto it = entries_.begin(); it != entries_.end();) {
    if (accepts(it->second.addr)) {
      ++it;
    } else {
      it = entries_.erase(it);
    }
  }
}

void AddrMan::enforce_limit() {
  if (entries_.size() <= max_entries_) return;
  std::vector<std::reference_wrapper<const AddrEntry>> vals;
  vals.reserve(entries_.size());
  for (const auto& [_, e] : entries_) vals.emplace_back(e);
  std::sort(vals.begin(), vals.end(), [](const AddrEntry& a, const AddrEntry& b) {
    if (a.score != b.score) return a.score < b.score;
    if (a.last_seen != b.last_seen) return a.last_seen < b.last_seen;
    return a.addr.key() < b.addr.key();
  });
  const std::size_t drop = entries_.size() - max_entries_;
  for (std::size_t i = 0; i < drop; ++i) {
    entries_.erase(vals[i].get().addr.key());
  }
}

bool AddrMan::save(const std::string& path) const {
  std::filesystem::create_directories(std::filesystem::path(path).parent_path());
  std::ofstream out(path, std::ios::trunc);
  if (!out.good()) return false;
  for (const auto& [_, e] : entries_) {
    out << e.addr.ip << '\t' << e.addr.port << '\t' << e.last_seen << '\t' << e.last_attempt << '\t'
        << e.success_count << '\t' << e.fail_count << '\t' << e.score << '\t' << e.last_error << '\n';
  }
  return out.good();
}

bool AddrMan::load(const std::string& path) {
  entries_.clear();
  std::ifstream in(path);
  if (!in.good()) return true;
  std::string line;
  while (std::getline(in, line)) {
    if (line.empty()) continue;
    std::stringstream ss(line);
    AddrEntry e;
    std::string port, last_seen, last_attempt, succ, fail, score;
    if (!std::getline(ss, e.addr.ip, '\t')) continue;
    if (!std::getline(ss, port, '\t')) continue;
    if (!std::getline(ss, last_seen, '\t')) continue;
    if (!std::getline(ss, last_attempt, '\t')) continue;
    if (!std::getline(ss, succ, '\t')) continue;
    if (!std::getline(ss, fail, '\t')) continue;
    if (!std::getline(ss, score, '\t')) continue;
    std::getline(ss, e.last_error);
    try {
      e.addr.port = static_cast<std::uint16_t>(std::stoul(port));
      e.last_seen = std::stoull(last_seen);
      e.last_attempt = std::stoull(last_attempt);
      e.success_count = static_cast<std::uint32_t>(std::stoul(succ));
      e.fail_count = static_cast<std::uint32_t>(std::stoul(fail));
      e.score = std::stoi(score);
    } catch (...) {
      continue;
    }
    if (!accepts(e.addr)) continue;
    entries_[e.addr.key()] = std::move(e);
  }
  prune_invalid_locked();
  enforce_limit();
  return true;
}

std::vector<AddrEntry> AddrMan::all() const {
  std::vector<AddrEntry> out;
  out.reserve(entries_.size());
  for (const auto& [_, e] : entries_) out.push_back(e);
  return out;
}

}  // namespace finalis::p2p
