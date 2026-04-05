#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <tuple>
#include <vector>

namespace finalis::p2p {

struct NetAddress {
  std::string ip;
  std::uint16_t port{0};

  std::string key() const;
  bool operator<(const NetAddress& o) const { return std::tie(ip, port) < std::tie(o.ip, o.port); }
  bool operator==(const NetAddress& o) const { return ip == o.ip && port == o.port; }
};

struct AddrEntry {
  NetAddress addr;
  std::uint64_t last_seen{0};
  std::uint64_t last_attempt{0};
  std::uint32_t success_count{0};
  std::uint32_t fail_count{0};
  std::string last_error;
  int score{0};
};

struct AddrPolicy {
  std::optional<std::uint16_t> required_port;
  bool reject_unroutable{false};
};

enum class AddrRejectReason : std::uint8_t {
  NONE = 0,
  EMPTY_IP,
  ZERO_PORT,
  PORT_MISMATCH,
  UNROUTABLE_IP,
};

class AddrMan {
 public:
  explicit AddrMan(std::size_t max_entries = 10'000) : max_entries_(max_entries) {}

  void set_policy(AddrPolicy policy);
  const AddrPolicy& policy() const { return policy_; }
  AddrRejectReason validate(const NetAddress& addr) const;
  bool accepts(const NetAddress& addr) const { return validate(addr) == AddrRejectReason::NONE; }

  void add_or_update(const NetAddress& addr, std::uint64_t last_seen);
  void mark_attempt(const NetAddress& addr, std::uint64_t now);
  void mark_success(const NetAddress& addr, std::uint64_t now);
  void mark_fail(const NetAddress& addr, std::uint64_t now, const std::string& err = {});

  std::vector<NetAddress> select_candidates(std::size_t n, std::uint64_t now) const;
  std::size_t size() const { return entries_.size(); }

  bool save(const std::string& path) const;
  bool load(const std::string& path);

  std::vector<AddrEntry> all() const;

 private:
  void prune_invalid_locked();
  void enforce_limit();
  static std::uint64_t backoff_seconds(const AddrEntry& e);

  std::size_t max_entries_{10'000};
  AddrPolicy policy_{};
  std::map<std::string, AddrEntry> entries_;
};

std::optional<NetAddress> parse_endpoint(const std::string& endpoint);

}  // namespace finalis::p2p
