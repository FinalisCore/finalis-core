// SPDX-License-Identifier: MIT

#include "test_framework.hpp"

#include <atomic>
#include <chrono>
#include <cerrno>
#include <condition_variable>
#include <mutex>
#include <thread>

#ifndef _WIN32
#include <fcntl.h>
#include <unistd.h>
#endif

#include "common/network.hpp"
#include "common/socket_compat.hpp"
#include "codec/bytes.hpp"
#include "p2p/peer_manager.hpp"
#include "p2p/framing.hpp"
#include "p2p/messages.hpp"

using namespace finalis;

namespace {

std::uint16_t reserve_test_port() {
  if (!finalis::net::ensure_sockets()) return 0;
  auto fd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (!finalis::net::valid_socket(fd)) return 0;
  (void)finalis::net::set_reuseaddr(fd);
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(0);
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
    finalis::net::close_socket(fd);
    return 0;
  }
  sockaddr_in bound{};
  socklen_t len = sizeof(bound);
  std::uint16_t port = 0;
  if (::getsockname(fd, reinterpret_cast<sockaddr*>(&bound), &len) == 0) {
    port = ntohs(bound.sin_port);
  }
  finalis::net::close_socket(fd);
  return port;
}

bool can_open_loopback_listener_for_test() {
  if (!finalis::net::ensure_sockets()) return false;
  auto fd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (!finalis::net::valid_socket(fd)) return false;
  (void)finalis::net::set_reuseaddr(fd);
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(0);
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  const bool bound = (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0);
  const bool listening = bound && (::listen(fd, 1) == 0);
  finalis::net::close_socket(fd);
  return listening;
}

}  // namespace

TEST(test_version_message_v07_roundtrip) {
  p2p::VersionMsg v;
  v.proto_version = 7;
  v.network_id = mainnet_network().network_id;
  v.feature_flags = 0xA5A5;
  v.services = 11;
  v.timestamp = 22;
  v.nonce = 33;
  v.node_software_version = "finalis-tests/0.7";
  v.start_height = 44;
  v.start_hash.fill(0x55);

  const Bytes b = p2p::ser_version(v);
  auto d = p2p::de_version(b);
  ASSERT_TRUE(d.has_value());
  ASSERT_EQ(d->proto_version, v.proto_version);
  ASSERT_EQ(d->network_id, v.network_id);
  ASSERT_EQ(d->feature_flags, v.feature_flags);
  ASSERT_EQ(d->services, v.services);
  ASSERT_EQ(d->timestamp, v.timestamp);
  ASSERT_EQ(d->nonce, v.nonce);
  ASSERT_EQ(d->node_software_version, v.node_software_version);
  ASSERT_EQ(d->start_height, v.start_height);
  ASSERT_EQ(d->start_hash, v.start_hash);
}

TEST(test_version_message_accepts_bootstrap_fingerprint_length) {
  p2p::VersionMsg v;
  v.proto_version = PROTOCOL_VERSION;
  v.network_id = mainnet_network().network_id;
  v.feature_flags = 0;
  v.services = 0;
  v.timestamp = 1;
  v.nonce = 2;
  v.node_software_version =
      "finalis-node/0.7;genesis=ad1eb4a5a0b1ee0e2f062539542b972d35bd216edd702e345fae76475a759a77;"
      "network_id=192d26a3e3decbc1919afbbe9d849149;cv=7;"
      "bootstrap_validator=f7b672871002c9286fab332251a82e2c7339dbf21fc8e8350ed1bcbeb671775f;"
      "validator_pubkey=be71f29a6c3fa5f32cff5a2977ca38394a386183e48046190a52bcaaca5b1090";
  v.start_height = 3;
  v.start_hash.fill(0x44);

  const Bytes b = p2p::ser_version(v);
  auto d = p2p::de_version(b);
  ASSERT_TRUE(d.has_value());
  ASSERT_EQ(d->node_software_version, v.node_software_version);
}

TEST(test_prefix_classification) {
  ASSERT_EQ(p2p::classify_prefix(Bytes{'H', 'T', 'T', 'P'}), p2p::PrefixKind::HTTP);
  ASSERT_EQ(p2p::classify_prefix(Bytes{'{', '"', 'a'}), p2p::PrefixKind::JSON);
  ASSERT_EQ(p2p::classify_prefix(Bytes{0x16, 0x03, 0x01, 0x00}), p2p::PrefixKind::TLS);
  ASSERT_EQ(p2p::classify_prefix(Bytes{0x01, 0x02, 0x03}), p2p::PrefixKind::UNKNOWN);
}

TEST(test_propose_codec_roundtrip) {
  p2p::ProposeMsg p;
  p.height = 10;
  p.round = 3;
  p.prev_finalized_hash.fill(0x11);
  p.frontier_proposal_bytes = Bytes{0xAA, 0xBB, 0xCC};

  const Bytes b = p2p::ser_propose(p);
  auto d = p2p::de_propose(b);
  ASSERT_TRUE(d.has_value());
  ASSERT_EQ(d->height, p.height);
  ASSERT_EQ(d->round, p.round);
  ASSERT_EQ(d->prev_finalized_hash, p.prev_finalized_hash);
  ASSERT_EQ(d->frontier_proposal_bytes, p.frontier_proposal_bytes);
}

TEST(test_vote_codec_roundtrip) {
  p2p::VoteMsg m;
  m.vote.height = 7;
  m.vote.round = 2;
  m.vote.block_id.fill(0x31);
  m.vote.validator_pubkey.fill(0x41);
  m.vote.signature.fill(0x51);

  const Bytes b = p2p::ser_vote(m);
  auto d = p2p::de_vote(b);
  ASSERT_TRUE(d.has_value());
  ASSERT_EQ(d->vote.height, m.vote.height);
  ASSERT_EQ(d->vote.round, m.vote.round);
  ASSERT_EQ(d->vote.block_id, m.vote.block_id);
  ASSERT_EQ(d->vote.validator_pubkey, m.vote.validator_pubkey);
  ASSERT_EQ(d->vote.signature, m.vote.signature);
}

TEST(test_version_message_rejects_oversized_software_string) {
  codec::ByteWriter w;
  w.u32le(PROTOCOL_VERSION);
  w.bytes_fixed(mainnet_network().network_id);
  w.u64le(0);
  w.u64le(0);
  w.u64le(0);
  w.u32le(0);
  Bytes sw(600, 'x');
  w.varbytes(sw);
  w.u64le(0);
  Hash32 zero{};
  w.bytes_fixed(zero);
  ASSERT_TRUE(!p2p::de_version(w.take()).has_value());
}

TEST(test_peer_manager_starts_reader_before_connected_event) {
  if (!can_open_loopback_listener_for_test()) return;
  const auto net = mainnet_network();
  const std::uint16_t port = reserve_test_port();
  if (port == 0) return;

  p2p::PeerManager listener;
  p2p::PeerManager dialer;
  listener.configure_network(net.magic, net.protocol_version, net.max_payload_len);
  dialer.configure_network(net.magic, net.protocol_version, net.max_payload_len);
  listener.configure_limits({3000, 3000, 3000, 1024 * 1024, 100, 8});
  dialer.configure_limits({3000, 3000, 3000, 1024 * 1024, 100, 8});

  std::mutex mu;
  std::condition_variable cv;
  bool listener_received_version = false;
  bool listener_saw_connected = false;
  bool listener_callback_observed_read = false;

  p2p::VersionMsg v;
  v.proto_version = net.protocol_version;
  v.network_id = net.network_id;
  v.feature_flags = net.feature_flags;
  v.timestamp = 1;
  v.nonce = 2;
  v.node_software_version = "finalis-tests/0.7";
  v.start_height = 0;
  v.start_hash.fill(0x11);

  listener.set_on_message([&](int, std::uint16_t msg_type, const Bytes&) {
    if (msg_type != p2p::MsgType::VERSION) return;
    {
      std::lock_guard<std::mutex> lk(mu);
      listener_received_version = true;
    }
    cv.notify_all();
  });
  dialer.set_on_message([](int, std::uint16_t, const Bytes&) {});

  listener.set_on_event([&](int peer_id, p2p::PeerManager::PeerEventType type, const std::string&) {
    if (type != p2p::PeerManager::PeerEventType::CONNECTED) return;
    listener_saw_connected = true;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(500);
    std::unique_lock<std::mutex> lk(mu);
    listener_callback_observed_read = cv.wait_until(lk, deadline, [&]() { return listener_received_version; });
    (void)peer_id;
  });
  dialer.set_on_event([&](int peer_id, p2p::PeerManager::PeerEventType type, const std::string&) {
    if (type != p2p::PeerManager::PeerEventType::CONNECTED) return;
    ASSERT_TRUE(dialer.send_to(peer_id, p2p::MsgType::VERSION, p2p::ser_version(v)));
  });

  ASSERT_TRUE(listener.start_listener("127.0.0.1", port));
  ASSERT_TRUE(dialer.connect_to("127.0.0.1", port));

  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
  while (std::chrono::steady_clock::now() < deadline) {
    {
      std::lock_guard<std::mutex> lk(mu);
      if (listener_received_version) break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }

  listener.stop();
  dialer.stop();

  ASSERT_TRUE(listener_saw_connected);
  ASSERT_TRUE(listener_received_version);
  ASSERT_TRUE(listener_callback_observed_read);
}

TEST(test_tx_message_rejects_oversized_payload) {
  codec::ByteWriter w;
  Bytes tx_bytes(300 * 1024, 0xAA);
  w.varbytes(tx_bytes);
  ASSERT_TRUE(!p2p::de_tx(w.take()).has_value());
}

TEST(test_write_frame_fd_timed_times_out_against_nonreading_peer) {
#ifdef _WIN32
  return;
#else
  int fds[2]{-1, -1};
  ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);

  int sndbuf = 4096;
  (void)::setsockopt(fds[0], SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));

  const int flags = ::fcntl(fds[0], F_GETFL, 0);
  ASSERT_TRUE(flags >= 0);
  ASSERT_EQ(::fcntl(fds[0], F_SETFL, flags | O_NONBLOCK), 0);

  Bytes fill(4096, 0xCD);
  while (true) {
    const ssize_t wrote = ::send(fds[0], reinterpret_cast<const char*>(fill.data()), static_cast<int>(fill.size()), 0);
    if (wrote > 0) continue;
    ASSERT_TRUE(wrote < 0);
    if (errno == EINTR) continue;
    if (errno != EAGAIN && errno != EWOULDBLOCK && errno != ENOBUFS) {
      ::close(fds[0]);
      ::close(fds[1]);
      return;
    }
    break;
  }

  ASSERT_EQ(::fcntl(fds[0], F_SETFL, flags), 0);

  p2p::Frame frame;
  frame.msg_type = p2p::MsgType::TX;
  frame.payload.assign(256, 0xAB);

  const auto start = std::chrono::steady_clock::now();
  ASSERT_TRUE(!p2p::write_frame_fd_timed(fds[0], frame, 50));
  const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start);
  ASSERT_TRUE(elapsed.count() < 500);

  ::close(fds[0]);
  ::close(fds[1]);
#endif
}

TEST(test_peer_manager_send_to_closed_peer_returns_false_without_duplicate_disconnect) {
  if (!can_open_loopback_listener_for_test()) return;
  const auto net = mainnet_network();
  const std::uint16_t port = reserve_test_port();
  if (port == 0) return;

  p2p::PeerManager listener;
  p2p::PeerManager dialer;
  listener.configure_network(net.magic, net.protocol_version, net.max_payload_len);
  dialer.configure_network(net.magic, net.protocol_version, net.max_payload_len);
  listener.configure_limits({3000, 3000, 3000, 1024 * 1024, 100, 8});
  dialer.configure_limits({3000, 3000, 3000, 1024 * 1024, 100, 8});

  std::mutex mu;
  std::condition_variable cv;
  int connected_peer_id = 0;
  int disconnect_events = 0;

  listener.set_on_message([](int, std::uint16_t, const Bytes&) {});
  dialer.set_on_message([](int, std::uint16_t, const Bytes&) {});

  dialer.set_on_event([&](int peer_id, p2p::PeerManager::PeerEventType type, const std::string&) {
    std::lock_guard<std::mutex> lk(mu);
    if (type == p2p::PeerManager::PeerEventType::CONNECTED) {
      connected_peer_id = peer_id;
      cv.notify_all();
    } else if (type == p2p::PeerManager::PeerEventType::DISCONNECTED) {
      ++disconnect_events;
      cv.notify_all();
    }
  });
  listener.set_on_event([](int, p2p::PeerManager::PeerEventType, const std::string&) {});

  ASSERT_TRUE(listener.start_listener("127.0.0.1", port));
  ASSERT_TRUE(dialer.connect_to("127.0.0.1", port));

  {
    std::unique_lock<std::mutex> lk(mu);
    ASSERT_TRUE(cv.wait_for(lk, std::chrono::seconds(2), [&]() { return connected_peer_id != 0; }));
  }

  dialer.disconnect_peer(connected_peer_id);
  ASSERT_TRUE(!dialer.send_to(connected_peer_id, p2p::MsgType::PING, p2p::ser_ping(p2p::PingMsg{123})));

  {
    std::unique_lock<std::mutex> lk(mu);
    ASSERT_TRUE(cv.wait_for(lk, std::chrono::seconds(2), [&]() { return disconnect_events >= 1; }));
  }

  std::this_thread::sleep_for(std::chrono::milliseconds(200));

  listener.stop();
  dialer.stop();

  ASSERT_EQ(disconnect_events, 1);
}

void register_p2p_tests() {}
