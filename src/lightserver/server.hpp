// SPDX-License-Identifier: MIT

#pragma once

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "common/chain_id.hpp"
#include "common/network.hpp"
#include "common/socket_compat.hpp"
#include "storage/db.hpp"

namespace finalis::lightserver {

// Admin RPC (keystore unlock / validator onboarding) is served only on this Unix socket, never TCP.
inline constexpr const char* kDefaultAdminSocketPath = "/var/run/finalis/admin.sock";

// Public TCP rate limits (token buckets, per minute).
inline constexpr std::uint32_t kPublicReadRequestsPerMinutePerIp = 100;
inline constexpr std::uint32_t kBroadcastTxPerMinutePerIp = 10;
inline constexpr std::uint32_t kGlobalRequestsPerMinute = 1000;

enum class RpcSurface : std::uint8_t {
  Public,  // TCP: read methods + broadcast_tx
  Admin,   // Unix socket: everything, including admin methods
};

bool is_admin_rpc_method(const std::string& method);

// Token bucket rate limiter for the public surface. Thread-safe.
class RateLimiter {
 public:
  enum class Class : std::uint8_t { Read, BroadcastTx };
  struct Decision {
    bool allowed{true};
    std::uint32_t retry_after_seconds{0};
  };
  Decision check(const std::string& ip, Class cls, std::uint64_t now_ms);

 private:
  struct Bucket {
    double tokens{0};
    std::uint64_t updated_ms{0};
    bool initialized{false};
  };
  struct IpState {
    Bucket read;
    Bucket broadcast;
    std::uint64_t last_seen_ms{0};
  };
  static bool take(Bucket* bucket, double per_minute, std::uint64_t now_ms, std::uint32_t* retry_after_seconds);
  void prune_locked(std::uint64_t now_ms);

  std::mutex mu_;
  Bucket global_;
  std::map<std::string, IpState> per_ip_;
};

struct Config {
  NetworkConfig network{mainnet_network()};
  std::string bind_ip{"127.0.0.1"};
  std::uint16_t port{0};
  std::string db_path{"~/.finalis/mainnet"};
  std::size_t max_committee{MAX_COMMITTEE};
  std::string tx_relay_host{"127.0.0.1"};
  std::uint16_t tx_relay_port{0};
  std::function<bool(const Bytes&, std::string*)> tx_relay_override;
  // Empty disables the admin surface. Not supported on Windows.
  std::string admin_socket_path{kDefaultAdminSocketPath};
  std::size_t worker_threads{0};  // 0 = clamp(hardware_concurrency, 4, 8)
  std::size_t max_queued_connections{64};
  // Loopback peers (explorer, mint service, local wallet) skip the public rate limits. Set false
  // when a same-host reverse proxy fronts the lightserver, or every client shares 127.0.0.1.
  bool exempt_loopback_from_rate_limits{true};
};

class Server {
 public:
  explicit Server(Config cfg);
  ~Server();

  bool init();
  bool start();
  void stop();
  std::string handle_rpc_for_test(const std::string& body);
  std::string handle_admin_rpc_for_test(const std::string& body);
  std::uint16_t bound_port() const { return bound_port_; }
  bool admin_socket_active() const { return net::valid_socket(admin_fd_); }

 private:
  struct Job {
    net::SocketHandle fd{net::kInvalidSocket};
    std::string peer_ip;
    RpcSurface surface{RpcSurface::Public};
  };

  bool start_admin_socket();
  void accept_loop(net::SocketHandle listen_fd, RpcSurface surface);
  void worker_loop();
  void handle_client(const Job& job);
  std::string handle_rpc_body(const std::string& body, RpcSurface surface);

  std::string make_error(const std::string& id_token, int code, const std::string& msg) const;
  std::string make_result(const std::string& id_token, const std::string& result_json) const;

  std::optional<std::vector<PubKey32>> committee_for_height(std::uint64_t height);
  bool relay_tx_to_peer(const Bytes& tx_bytes, std::string* err);

  Config cfg_;
  storage::DB db_;
  net::SocketHandle listen_fd_{net::kInvalidSocket};
  net::SocketHandle admin_fd_{net::kInvalidSocket};
  std::string admin_socket_bound_path_;
  std::uint16_t bound_port_{0};
  std::atomic<bool> running_{false};
  std::thread accept_thread_;
  std::thread admin_accept_thread_;
  std::vector<std::thread> workers_;
  std::mutex queue_mu_;
  std::condition_variable queue_cv_;
  std::deque<Job> queue_;
  RateLimiter rate_limiter_;
  std::uint64_t started_at_unix_{0};
  ChainId chain_id_{};
};

std::optional<Config> parse_args(int argc, char** argv);

}  // namespace finalis::lightserver
