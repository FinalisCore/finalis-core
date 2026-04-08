#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "common/chain_id.hpp"
#include "common/network.hpp"
#include "common/socket_compat.hpp"
#include "storage/db.hpp"

namespace finalis::lightserver {

struct Config {
  NetworkConfig network{mainnet_network()};
  std::string bind_ip{"127.0.0.1"};
  std::uint16_t port{0};
  std::string db_path{".finalis/mainnet"};
  std::size_t max_committee{MAX_COMMITTEE};
  std::string tx_relay_host{"127.0.0.1"};
  std::uint16_t tx_relay_port{0};
  std::function<bool(const Bytes&, std::string*)> tx_relay_override;
};

class Server {
 public:
  explicit Server(Config cfg);
  ~Server();

  bool init();
  bool start();
  void stop();
  std::string handle_rpc_for_test(const std::string& body);
  std::uint16_t bound_port() const { return bound_port_; }

 private:
  void accept_loop();
  void handle_client(net::SocketHandle fd);
  std::string handle_rpc_body(const std::string& body);

  std::string make_error(const std::string& id_token, int code, const std::string& msg) const;
  std::string make_result(const std::string& id_token, const std::string& result_json) const;

  std::optional<std::vector<PubKey32>> committee_for_height(std::uint64_t height);
  bool relay_tx_to_peer(const Bytes& tx_bytes, std::string* err);

  Config cfg_;
  storage::DB db_;
  net::SocketHandle listen_fd_{net::kInvalidSocket};
  std::uint16_t bound_port_{0};
  std::atomic<bool> running_{false};
  std::thread accept_thread_;
  std::uint64_t started_at_unix_{0};
  ChainId chain_id_{};
};

std::optional<Config> parse_args(int argc, char** argv);

}  // namespace finalis::lightserver
