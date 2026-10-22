// SPDX-License-Identifier: MIT

#pragma once

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <mutex>
#include <shared_mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "common/chain_id.hpp"
#include "common/network.hpp"
#include "common/paths.hpp"
#include "common/socket_compat.hpp"
#include "common/trusted_proxy.hpp"
#include "crypto/smt.hpp"
#include "storage/db.hpp"

namespace finalis::lightserver {

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

// The local node's verdict on a relayed transaction.
struct TxRelayResult {
  enum class Outcome { Accepted, Rejected, Unavailable };
  Outcome outcome{Outcome::Unavailable};
  std::string detail;  // node reject reason, or the transport error
};

struct Config {
  NetworkConfig network{mainnet_network()};
  std::string bind_ip{"127.0.0.1"};
  std::uint16_t port{0};
  std::string db_path{"~/.finalis/mainnet"};
  // The lightserver reads db_path as a RocksDB secondary; its own files go here. Empty: db_path/lightserver-secondary.
  std::string secondary_path;
  std::size_t max_committee{MAX_COMMITTEE};
  std::string tx_relay_host{"127.0.0.1"};
  std::uint16_t tx_relay_port{0};
  std::function<TxRelayResult(const Bytes&)> tx_relay_override;
  // Admin RPC (keystore unlock / validator onboarding) is served only on this Unix socket, never TCP.
  // Empty disables the admin surface. Not supported on Windows.
  std::string admin_socket_path{default_admin_socket_path("mainnet")};
  std::size_t worker_threads{0};  // 0 = clamp(hardware_concurrency, 4, 8)
  std::size_t max_queued_connections{64};
  // Loopback peers (explorer, local wallet) skip the public rate limits. Set false
  // when a same-host reverse proxy fronts the lightserver, or every client shares 127.0.0.1.
  bool exempt_loopback_from_rate_limits{true};
  // Peers whose X-Real-IP names the client (a same-host reverse proxy). A request forwarded this way
  // is limited by that client's address and never gets the loopback exemption.
  std::vector<net::Ipv4Cidr> trusted_proxies;
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
  TxRelayResult relay_tx_to_peer(const Bytes& tx_bytes);
  // Proof for `key` from an in-memory UTXO commitment tree kept at `height` (the finalized tip) by
  // applying the node's per-height change rows; rebuilt from the stored leaves when it cannot catch up.
  // Empty if the tree's root does not match `expected_root`.
  std::optional<crypto::SmtProof> utxo_proof_at(std::uint64_t height, const Hash32& expected_root, const Hash32& key);

  Config cfg_;
  storage::DB db_;
  // Exclusive while db_ catches up with the node, shared while a request reads it.
  std::shared_mutex view_mu_;
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
  std::mutex utxo_tree_mu_;
  std::optional<crypto::PersistentSmt> utxo_tree_;
  std::uint64_t utxo_tree_height_{0};
};

std::optional<Config> parse_args(int argc, char** argv);

}  // namespace finalis::lightserver
