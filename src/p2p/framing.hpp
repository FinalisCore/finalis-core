// SPDX-License-Identifier: MIT

#pragma once

#include <cstdint>
#include <optional>

#include "common/socket_compat.hpp"
#include "common/types.hpp"

namespace finalis::p2p {

struct Frame {
  std::uint16_t msg_type{0};
  Bytes payload;
};

enum class FrameReadError {
  NONE = 0,
  IO_EOF,
  TIMEOUT_HEADER,
  TIMEOUT_BODY,
  MAGIC_MISMATCH,
  VERSION_MISMATCH,
  INVALID_HEADER,
  INVALID_LENGTH,
  INVALID_CHECKSUM,
};

enum class PrefixKind {
  UNKNOWN = 0,
  HTTP,
  JSON,
  TLS,
};

struct FrameFailureInfo {
  FrameReadError reason{FrameReadError::NONE};
  Bytes first_bytes;
  std::optional<std::uint32_t> received_magic;
  std::optional<std::uint32_t> payload_len;
  std::uint32_t expected_magic{0};
  std::uint16_t expected_proto_version{0};
  PrefixKind prefix_kind{PrefixKind::UNKNOWN};
  std::size_t header_bytes_read{0};
  std::size_t body_bytes_read{0};
  std::size_t checksum_bytes_read{0};
  bool saw_eof{false};
};

std::string frame_read_error_string(FrameReadError e);
PrefixKind classify_prefix(const Bytes& prefix);
std::string prefix_kind_string(PrefixKind k);

Bytes encode_frame(const Frame& f, std::uint32_t magic = MAGIC, std::uint16_t proto_version = PROTOCOL_VERSION);
std::optional<Frame> decode_frame(const Bytes& b, std::size_t max_payload_len = 8 * 1024 * 1024,
                                  std::uint32_t magic = MAGIC, std::uint16_t proto_version = PROTOCOL_VERSION);

bool read_exact(net::SocketHandle fd, std::uint8_t* dst, std::size_t n);
bool write_all(net::SocketHandle fd, const std::uint8_t* src, std::size_t n);
bool write_all_timed(net::SocketHandle fd, const std::uint8_t* src, std::size_t n, std::uint32_t timeout_ms);
std::optional<Frame> read_frame_fd(net::SocketHandle fd, std::size_t max_payload_len = 8 * 1024 * 1024,
                                   std::uint32_t magic = MAGIC, std::uint16_t proto_version = PROTOCOL_VERSION);
std::optional<Frame> read_frame_fd_timed(net::SocketHandle fd, std::size_t max_payload_len, std::uint32_t expected_magic,
                                         std::uint16_t expected_proto_version, std::uint32_t header_timeout_ms,
                                         std::uint32_t body_timeout_ms, FrameReadError* err,
                                         FrameFailureInfo* fail_info = nullptr);
bool write_frame_fd(net::SocketHandle fd, const Frame& f, std::uint32_t magic = MAGIC,
                    std::uint16_t proto_version = PROTOCOL_VERSION);
bool write_frame_fd_timed(net::SocketHandle fd, const Frame& f, std::uint32_t timeout_ms, std::uint32_t magic = MAGIC,
                          std::uint16_t proto_version = PROTOCOL_VERSION);

}  // namespace finalis::p2p
