// SPDX-License-Identifier: MIT

#include "p2p/peer_manager.hpp"

#include <chrono>
#include <cerrno>
#include <cstring>
#include <sstream>

#include "p2p/messages.hpp"

namespace finalis::p2p {
namespace {

std::string bytes_to_hex_prefix(const Bytes& in, std::size_t n = 16) {
  const std::size_t take = std::min(n, in.size());
  return hex_encode(Bytes(in.begin(), in.begin() + take));
}

std::string u32_hex(std::uint32_t v) {
  std::ostringstream oss;
  oss << "0x" << std::hex << std::nouppercase << v;
  return oss.str();
}

std::string frame_fail_detail(const FrameFailureInfo& fi) {
  std::ostringstream oss;
  oss << "reason=" << frame_read_error_string(fi.reason) << " class=" << prefix_kind_string(fi.prefix_kind)
      << " expected_magic=" << u32_hex(fi.expected_magic)
      << " expected_proto=" << std::to_string(fi.expected_proto_version)
      << " hdr_read=" << fi.header_bytes_read << " body_read=" << fi.body_bytes_read
      << " checksum_read=" << fi.checksum_bytes_read << " eof=" << (fi.saw_eof ? "1" : "0")
      << " first16=" << bytes_to_hex_prefix(fi.first_bytes);
  if (fi.received_magic.has_value()) oss << " received_magic=" << u32_hex(*fi.received_magic);
  if (fi.payload_len.has_value()) oss << " payload_len=" << *fi.payload_len;
  return oss.str();
}

bool connect_with_timeout(net::SocketHandle fd, const sockaddr* addr, socklen_t addrlen, std::uint32_t timeout_ms) {
  if (!net::set_nonblocking(fd, true)) return false;

  const int rc = ::connect(fd, addr, addrlen);
  if (rc == 0) {
    (void)net::set_nonblocking(fd, false);
    return true;
  }
  const int err = net::socket_last_error();
#ifdef _WIN32
  if (err != WSAEWOULDBLOCK && err != WSAEINPROGRESS) {
#else
  if (err != EINPROGRESS) {
#endif
    (void)net::set_nonblocking(fd, false);
    return false;
  }
  if (!net::wait_writable(fd, timeout_ms)) {
    (void)net::set_nonblocking(fd, false);
    return false;
  }

  int so_error = 0;
  socklen_t so_error_len = sizeof(so_error);
  if (::getsockopt(fd, SOL_SOCKET, SO_ERROR,
#ifdef _WIN32
                   reinterpret_cast<char*>(&so_error),
#else
                   &so_error,
#endif
                   &so_error_len) != 0) {
    (void)net::set_nonblocking(fd, false);
    return false;
  }
  (void)net::set_nonblocking(fd, false);
  return so_error == 0;
}

std::string peer_state_detail(const PeerInfo& info) {
  std::ostringstream oss;
  oss << "state="
      << "version_tx=" << (info.version_tx ? "1" : "0")
      << ",version_rx=" << (info.version_rx ? "1" : "0")
      << ",verack_tx=" << (info.verack_tx ? "1" : "0")
      << ",verack_rx=" << (info.verack_rx ? "1" : "0")
      << ",established=" << (info.established() ? "1" : "0")
      << ",proto=" << info.proto_version;
  return oss.str();
}

}  // namespace

void PeerManager::configure_network(std::uint32_t magic, std::uint16_t proto_version, std::size_t max_payload_len) {
  magic_ = magic;
  proto_version_ = proto_version;
  max_payload_len_ = max_payload_len;
}

bool PeerManager::start_listener(const std::string& bind_ip, std::uint16_t port) {
  if (!net::ensure_sockets()) return false;
  listen_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
  if (!net::valid_socket(listen_fd_)) return false;
  net::set_close_on_exec(listen_fd_);
  (void)net::set_reuseaddr(listen_fd_);

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  if (inet_pton(AF_INET, bind_ip.c_str(), &addr.sin_addr) != 1) {
    net::close_socket(listen_fd_);
    listen_fd_ = net::kInvalidSocket;
    return false;
  }

  if (bind(listen_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
    net::close_socket(listen_fd_);
    listen_fd_ = net::kInvalidSocket;
    return false;
  }
  sockaddr_in bound{};
  socklen_t blen = sizeof(bound);
  if (::getsockname(listen_fd_, reinterpret_cast<sockaddr*>(&bound), &blen) == 0) {
    listen_port_ = ntohs(bound.sin_port);
  } else {
    listen_port_ = port;
  }
  if (listen(listen_fd_, 64) != 0) {
    net::close_socket(listen_fd_);
    listen_fd_ = net::kInvalidSocket;
    return false;
  }

  running_ = true;
  accept_thread_ = std::thread([this]() { accept_loop(); });
  return true;
}

bool PeerManager::connect_to(const std::string& host, std::uint16_t port) {
  if (!net::ensure_sockets()) return false;
  if (!running_) running_ = true;

  addrinfo hints{};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  addrinfo* res = nullptr;
  if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res) != 0) return false;

  net::SocketHandle fd = net::kInvalidSocket;
  for (addrinfo* it = res; it != nullptr; it = it->ai_next) {
    fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
    if (!net::valid_socket(fd)) continue;
    net::set_close_on_exec(fd);
    if (connect_with_timeout(fd, it->ai_addr, static_cast<socklen_t>(it->ai_addrlen), limits_.handshake_timeout_ms)) break;
    net::close_socket(fd);
    fd = net::kInvalidSocket;
  }
  freeaddrinfo(res);
  if (!net::valid_socket(fd)) return false;

  start_peer(fd, host + ":" + std::to_string(port), host, false);
  return true;
}

void PeerManager::stop() {
  const bool was_running = running_.exchange(false);

  if (net::valid_socket(listen_fd_)) {
    net::shutdown_socket(listen_fd_);
    net::close_socket(listen_fd_);
    listen_fd_ = net::kInvalidSocket;
    listen_port_ = 0;
  }

  if (accept_thread_.joinable()) accept_thread_.join();

  std::vector<std::shared_ptr<PeerConn>> peers;
  {
    std::lock_guard<std::mutex> lk(mu_);
    for (auto& [_, p] : peers_) peers.push_back(p);
    peers_.clear();
  }

  for (auto& p : peers) {
    if (net::valid_socket(p->fd)) {
      net::shutdown_socket(p->fd);
      net::close_socket(p->fd);
      p->fd = net::kInvalidSocket;
    }
  }

  if (was_running || active_readers_.load() != 0) {
    std::unique_lock<std::mutex> lk(reader_wait_mu_);
    reader_wait_cv_.wait_for(lk, std::chrono::seconds(5), [this]() { return active_readers_.load() == 0; });
  }

  std::vector<std::thread> reader_threads;
  {
    std::lock_guard<std::mutex> threads_lk(reader_threads_mu_);
    reader_threads.swap(reader_threads_);
  }
  for (auto& t : reader_threads) {
    if (t.joinable()) t.join();
  }
}

bool PeerManager::send_to(int peer_id, std::uint16_t msg_type, const Bytes& payload, bool low_priority) {
  std::shared_ptr<PeerConn> p;
  {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = peers_.find(peer_id);
    if (it == peers_.end()) return false;
    p = it->second;
  }

  if (p->queued_msgs.load() >= limits_.max_outbound_queue_msgs ||
      p->queued_bytes.load() + payload.size() > limits_.max_outbound_queue_bytes) {
    if (low_priority) {
      emit_event(peer_id, PeerEventType::QUEUE_OVERFLOW, "drop-low-priority");
      return false;
    }
    emit_event(peer_id, PeerEventType::QUEUE_OVERFLOW, "disconnect");
    disconnect_peer(peer_id);
    return false;
  }

  p->queued_msgs.fetch_add(1);
  p->queued_bytes.fetch_add(payload.size());
  bool ok = false;
  int send_errno = 0;
  {
    std::lock_guard<std::mutex> wl(p->write_mu);
    if (!net::valid_socket(p->fd)) {
      p->queued_msgs.fetch_sub(1);
      p->queued_bytes.fetch_sub(payload.size());
      return false;
    }
    ok = write_frame_fd_timed(p->fd, Frame{msg_type, payload}, limits_.frame_timeout_ms, magic_, proto_version_);
    if (!ok) send_errno = net::socket_last_error();
  }
  p->queued_msgs.fetch_sub(1);
  p->queued_bytes.fetch_sub(payload.size());
  if (!ok) {
    if (!running_.load()) return false;
    const auto info = get_peer_info(peer_id);
    std::ostringstream oss;
    oss << "send-failed errno=" << send_errno << " err=\"" << net::socket_error_string(send_errno) << "\" "
        << peer_state_detail(info);
    emit_event(peer_id, PeerEventType::DISCONNECTED, oss.str());
    disconnect_peer(peer_id);
  }
  return ok;
}

void PeerManager::broadcast(std::uint16_t msg_type, const Bytes& payload) {
  const bool low_priority = (msg_type == MsgType::TX);
  for (int id : peer_ids()) {
    (void)send_to(id, msg_type, payload, low_priority);
  }
}

void PeerManager::disconnect_peer(int peer_id) {
  std::shared_ptr<PeerConn> p;
  {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = peers_.find(peer_id);
    if (it == peers_.end()) return;
    p = it->second;
  }
  std::lock_guard<std::mutex> wl(p->write_mu);
  if (net::valid_socket(p->fd)) {
    net::shutdown_socket(p->fd);
    net::close_socket(p->fd);
    p->fd = net::kInvalidSocket;
  }
}

std::vector<int> PeerManager::peer_ids() const {
  std::vector<int> ids;
  std::lock_guard<std::mutex> lk(mu_);
  for (const auto& [id, _] : peers_) ids.push_back(id);
  return ids;
}

PeerInfo PeerManager::get_peer_info(int peer_id) const {
  std::lock_guard<std::mutex> lk(mu_);
  auto it = peers_.find(peer_id);
  if (it == peers_.end()) return {};
  return it->second->info;
}

std::size_t PeerManager::inbound_count() const {
  std::size_t n = 0;
  std::lock_guard<std::mutex> lk(mu_);
  for (const auto& [_, p] : peers_) {
    if (p->inbound) ++n;
  }
  return n;
}

std::size_t PeerManager::outbound_count() const {
  std::size_t n = 0;
  std::lock_guard<std::mutex> lk(mu_);
  for (const auto& [_, p] : peers_) {
    if (!p->inbound) ++n;
  }
  return n;
}

bool PeerManager::mark_handshake_tx(int peer_id, bool version, bool verack) {
  std::lock_guard<std::mutex> lk(mu_);
  auto it = peers_.find(peer_id);
  if (it == peers_.end()) return false;
  if (version) it->second->info.version_tx = true;
  if (verack) it->second->info.verack_tx = true;
  return true;
}

bool PeerManager::mark_handshake_rx(int peer_id, bool version, bool verack) {
  std::lock_guard<std::mutex> lk(mu_);
  auto it = peers_.find(peer_id);
  if (it == peers_.end()) return false;
  if (version) it->second->info.version_rx = true;
  if (verack) it->second->info.verack_rx = true;
  return true;
}

bool PeerManager::set_peer_handshake_meta(int peer_id, std::uint32_t proto_version,
                                          const std::array<std::uint8_t, 16>& network_id, std::uint64_t feature_flags) {
  std::lock_guard<std::mutex> lk(mu_);
  auto it = peers_.find(peer_id);
  if (it == peers_.end()) return false;
  it->second->info.proto_version = proto_version;
  it->second->info.network_id = network_id;
  it->second->info.feature_flags = feature_flags;
  return true;
}

void PeerManager::accept_loop() {
  while (running_) {
    sockaddr_in addr{};
    socklen_t len = sizeof(addr);
    net::SocketHandle fd = accept(listen_fd_, reinterpret_cast<sockaddr*>(&addr), &len);
    if (!net::valid_socket(fd)) {
      if (!running_) break;
      continue;
    }
    net::set_close_on_exec(fd);
    char ipbuf[64]{};
    inet_ntop(AF_INET, &addr.sin_addr, ipbuf, sizeof(ipbuf));
    bool allowed = true;
    {
      std::lock_guard<std::mutex> lk(mu_);
      std::size_t inbound = 0;
      for (const auto& [_, p] : peers_) {
        if (p->inbound) ++inbound;
      }
      if (inbound >= limits_.max_inbound) allowed = false;
    }
    if (!allowed) {
      net::shutdown_socket(fd);
      net::close_socket(fd);
      continue;
    }
    if (accept_filter_ && !accept_filter_(std::string(ipbuf))) {
      net::shutdown_socket(fd);
      net::close_socket(fd);
      continue;
    }
    start_peer(fd, std::string(ipbuf) + ":" + std::to_string(ntohs(addr.sin_port)), ipbuf, true);
  }
}

void PeerManager::start_peer(net::SocketHandle fd, const std::string& endpoint, const std::string& ip, bool inbound) {
  auto p = std::make_shared<PeerConn>();
  p->fd = fd;
  p->inbound = inbound;
  {
    std::lock_guard<std::mutex> lk(mu_);
    p->info.id = next_peer_id_++;
    p->info.endpoint = endpoint;
    p->info.ip = ip;
    p->info.inbound = inbound;
    peers_[p->info.id] = p;
  }
  active_readers_.fetch_add(1);
  {
    std::lock_guard<std::mutex> lk(reader_threads_mu_);
    reader_threads_.emplace_back([this, peer_id = p->info.id, p]() {
      {
        std::lock_guard<std::mutex> lk(p->start_mu);
        p->reader_started = true;
      }
      p->start_cv.notify_all();
      read_loop(peer_id);
      active_readers_.fetch_sub(1);
      reader_wait_cv_.notify_all();
    });
  }
  {
    std::unique_lock<std::mutex> lk(p->start_mu);
    p->start_cv.wait(lk, [&p]() { return p->reader_started; });
  }
  emit_event(p->info.id, PeerEventType::CONNECTED, endpoint);
}

void PeerManager::read_loop(int peer_id) {
  std::shared_ptr<PeerConn> p;
  {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = peers_.find(peer_id);
    if (it == peers_.end()) return;
    p = it->second;
  }

  while (running_) {
    const auto fd = p->fd;
    if (!net::valid_socket(fd)) break;
    const auto info = get_peer_info(peer_id);
    std::uint32_t header_timeout = info.established() ? limits_.idle_timeout_ms : limits_.handshake_timeout_ms;
    if (info.established() && read_timeout_override_) {
      if (auto override_timeout = read_timeout_override_(peer_id, info); override_timeout.has_value()) {
        header_timeout = *override_timeout;
      }
    }
    FrameReadError ferr = FrameReadError::NONE;
    FrameFailureInfo finfo;
    auto frame = read_frame_fd_timed(fd, max_payload_len_, magic_, proto_version_, header_timeout, limits_.frame_timeout_ms,
                                     &ferr, &finfo);
    if (!frame.has_value()) {
      if (!running_.load()) break;
      const std::string detail = frame_fail_detail(finfo) + " " + peer_state_detail(info);
      if (ferr == FrameReadError::TIMEOUT_HEADER) {
        emit_event(peer_id, info.established() ? PeerEventType::FRAME_TIMEOUT : PeerEventType::HANDSHAKE_TIMEOUT,
                   detail);
      } else if (ferr == FrameReadError::TIMEOUT_BODY) {
        emit_event(peer_id, PeerEventType::FRAME_TIMEOUT, detail);
      } else if (ferr != FrameReadError::NONE && ferr != FrameReadError::IO_EOF) {
        emit_event(peer_id, PeerEventType::FRAME_INVALID, detail);
      }
      break;
    }
    if (on_message_) on_message_(peer_id, frame->msg_type, frame->payload);
  }

  net::shutdown_socket(p->fd);
  net::close_socket(p->fd);
  p->fd = net::kInvalidSocket;
  const std::string endpoint = p->info.endpoint;
  const std::string disconnect_detail = "endpoint=" + endpoint + " " + peer_state_detail(p->info);
  {
    std::lock_guard<std::mutex> lk(mu_);
    peers_.erase(peer_id);
  }
  if (running_.load()) emit_event(peer_id, PeerEventType::DISCONNECTED, disconnect_detail);
}

void PeerManager::emit_event(int peer_id, PeerEventType type, const std::string& detail) const {
  if (on_event_) on_event_(peer_id, type, detail);
}

}  // namespace finalis::p2p
