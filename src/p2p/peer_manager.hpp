#pragma once

#include <atomic>
#include <array>
#include <condition_variable>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "p2p/framing.hpp"

namespace finalis::p2p {

struct PeerInfo {
  int id{0};
  std::string endpoint;
  std::string ip;
  bool inbound{false};
  bool version_rx{false};
  bool verack_rx{false};
  bool version_tx{false};
  bool verack_tx{false};
  std::uint32_t proto_version{0};
  std::array<std::uint8_t, 16> network_id{};
  std::uint64_t feature_flags{0};

  bool established() const { return version_rx && verack_rx && version_tx && verack_tx; }
};

class PeerManager {
 public:
  ~PeerManager() { stop(); }

  using MessageHandler = std::function<void(int peer_id, std::uint16_t msg_type, const Bytes& payload)>;
  using ReadTimeoutOverride = std::function<std::optional<std::uint32_t>(int peer_id, const PeerInfo& info)>;
  enum class PeerEventType {
    CONNECTED,
    DISCONNECTED,
    FRAME_INVALID,
    FRAME_TIMEOUT,
    HANDSHAKE_TIMEOUT,
    QUEUE_OVERFLOW,
  };
  using PeerEventHandler = std::function<void(int peer_id, PeerEventType type, const std::string& detail)>;

  struct Limits {
    std::uint32_t handshake_timeout_ms{10'000};
    std::uint32_t frame_timeout_ms{3'000};
    std::uint32_t idle_timeout_ms{120'000};
    std::size_t max_outbound_queue_bytes{2 * 1024 * 1024};
    std::size_t max_outbound_queue_msgs{2'000};
    std::size_t max_inbound{64};
  };

  void configure_network(std::uint32_t magic, std::uint16_t proto_version, std::size_t max_payload_len);
  void configure_limits(Limits limits) { limits_ = limits; }
  bool start_listener(const std::string& bind_ip, std::uint16_t port);
  bool connect_to(const std::string& host, std::uint16_t port);
  void stop();

  void set_on_message(MessageHandler fn) { on_message_ = std::move(fn); }
  void set_on_event(PeerEventHandler fn) { on_event_ = std::move(fn); }
  void set_read_timeout_override(ReadTimeoutOverride fn) { read_timeout_override_ = std::move(fn); }
  bool send_to(int peer_id, std::uint16_t msg_type, const Bytes& payload, bool low_priority = false);
  void broadcast(std::uint16_t msg_type, const Bytes& payload);
  void disconnect_peer(int peer_id);

  std::vector<int> peer_ids() const;
  PeerInfo get_peer_info(int peer_id) const;
  std::size_t inbound_count() const;
  std::size_t outbound_count() const;
  std::uint16_t listener_port() const { return listen_port_; }
  bool mark_handshake_tx(int peer_id, bool version, bool verack);
  bool mark_handshake_rx(int peer_id, bool version, bool verack);
  bool set_peer_handshake_meta(int peer_id, std::uint32_t proto_version, const std::array<std::uint8_t, 16>& network_id,
                               std::uint64_t feature_flags);

 private:
  struct PeerConn {
    int fd{-1};
    bool inbound{false};
    PeerInfo info;
    mutable std::mutex write_mu;
    mutable std::mutex start_mu;
    std::condition_variable start_cv;
    bool reader_started{false};
    std::atomic<std::size_t> queued_bytes{0};
    std::atomic<std::size_t> queued_msgs{0};
  };

  void accept_loop();
  void start_peer(int fd, const std::string& endpoint, const std::string& ip, bool inbound);
  void read_loop(int peer_id);
  void emit_event(int peer_id, PeerEventType type, const std::string& detail) const;

  int listen_fd_{-1};
  std::uint16_t listen_port_{0};
  std::thread accept_thread_;
  std::atomic<bool> running_{false};

  mutable std::mutex mu_;
  int next_peer_id_{1};
  std::map<int, std::shared_ptr<PeerConn>> peers_;

  MessageHandler on_message_;
  PeerEventHandler on_event_;
  ReadTimeoutOverride read_timeout_override_;
  std::uint32_t magic_{MAGIC};
  std::uint16_t proto_version_{PROTOCOL_VERSION};
  std::size_t max_payload_len_{8 * 1024 * 1024};
  Limits limits_{};
  std::atomic<std::size_t> active_readers_{0};
  mutable std::mutex reader_wait_mu_;
  std::condition_variable reader_wait_cv_;
  mutable std::mutex reader_threads_mu_;
  std::vector<std::thread> reader_threads_;
};

}  // namespace finalis::p2p
