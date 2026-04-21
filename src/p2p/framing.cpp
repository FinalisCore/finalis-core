// SPDX-License-Identifier: MIT

#include "p2p/framing.hpp"

#include <chrono>

#include "codec/bytes.hpp"
#include "crypto/hash.hpp"

namespace finalis::p2p {

std::string frame_read_error_string(FrameReadError e) {
  switch (e) {
    case FrameReadError::NONE:
      return "NONE";
    case FrameReadError::IO_EOF:
      return "IO_EOF";
    case FrameReadError::TIMEOUT_HEADER:
      return "TIMEOUT_HEADER";
    case FrameReadError::TIMEOUT_BODY:
      return "TIMEOUT_BODY";
    case FrameReadError::MAGIC_MISMATCH:
      return "MAGIC_MISMATCH";
    case FrameReadError::VERSION_MISMATCH:
      return "VERSION_MISMATCH";
    case FrameReadError::INVALID_HEADER:
      return "INVALID_HEADER";
    case FrameReadError::INVALID_LENGTH:
      return "LEN_TOO_BIG";
    case FrameReadError::INVALID_CHECKSUM:
      return "CHECKSUM_FAIL";
  }
  return "UNKNOWN";
}

PrefixKind classify_prefix(const Bytes& prefix) {
  if (prefix.size() >= 4 && prefix[0] == 'H' && prefix[1] == 'T' && prefix[2] == 'T' && prefix[3] == 'P') {
    return PrefixKind::HTTP;
  }
  if (!prefix.empty() && prefix[0] == '{') return PrefixKind::JSON;
  if (prefix.size() >= 3 && prefix[0] == 0x16 && prefix[1] == 0x03 && (prefix[2] == 0x01 || prefix[2] == 0x03)) {
    return PrefixKind::TLS;
  }
  return PrefixKind::UNKNOWN;
}

std::string prefix_kind_string(PrefixKind k) {
  switch (k) {
    case PrefixKind::HTTP:
      return "HTTP";
    case PrefixKind::JSON:
      return "JSON";
    case PrefixKind::TLS:
      return "TLS";
    case PrefixKind::UNKNOWN:
      return "UNKNOWN";
  }
  return "UNKNOWN";
}

Bytes encode_frame(const Frame& f, std::uint32_t magic, std::uint16_t proto_version) {
  codec::ByteWriter w;
  w.u32le(magic);
  w.u16le(proto_version);
  w.u16le(f.msg_type);
  w.u32le(static_cast<std::uint32_t>(f.payload.size()));
  w.bytes(f.payload);
  const Hash32 chk = crypto::sha256d(f.payload);
  w.bytes_fixed(chk);
  return w.take();
}

std::optional<Frame> decode_frame(const Bytes& b, std::size_t max_payload_len, std::uint32_t expected_magic,
                                  std::uint16_t expected_proto_version) {
  Frame f;
  if (!codec::parse_exact(b, [&](codec::ByteReader& r) {
        auto magic = r.u32le();
        auto version = r.u16le();
        auto msg_type = r.u16le();
        auto payload_len = r.u32le();
        if (!magic || !version || !msg_type || !payload_len) return false;
        if (*magic != expected_magic || *version != expected_proto_version) return false;
        if (*payload_len > max_payload_len) return false;
        auto payload = r.bytes(*payload_len);
        auto checksum = r.bytes_fixed<32>();
        if (!payload || !checksum) return false;
        if (crypto::sha256d(*payload) != *checksum) return false;
        f.msg_type = *msg_type;
        f.payload = *payload;
        return true;
      })) {
    return std::nullopt;
  }
  return f;
}

bool read_exact(net::SocketHandle fd, std::uint8_t* dst, std::size_t n) {
  (void)net::ensure_sockets();
  size_t off = 0;
  while (off < n) {
    ssize_t k = ::recv(fd, reinterpret_cast<char*>(dst + off), static_cast<int>(n - off), 0);
    if (k <= 0) return false;
    off += static_cast<size_t>(k);
  }
  return true;
}

bool write_all(net::SocketHandle fd, const std::uint8_t* src, std::size_t n) {
  (void)net::ensure_sockets();
  size_t off = 0;
  while (off < n) {
    int flags = 0;
#ifdef MSG_NOSIGNAL
    flags |= MSG_NOSIGNAL;
#endif
    ssize_t k = ::send(fd, reinterpret_cast<const char*>(src + off), static_cast<int>(n - off), flags);
    if (k <= 0) return false;
    off += static_cast<size_t>(k);
  }
  return true;
}

namespace {

bool wait_readable(net::SocketHandle fd, std::uint32_t timeout_ms) {
  return net::wait_readable(fd, timeout_ms);
}

bool wait_writable(net::SocketHandle fd, std::uint32_t timeout_ms) {
  return net::wait_writable(fd, timeout_ms);
}

bool read_exact_timed(net::SocketHandle fd, std::uint8_t* dst, std::size_t n, std::uint32_t timeout_ms, std::size_t* bytes_read,
                      bool* eof) {
  if (bytes_read) *bytes_read = 0;
  if (eof) *eof = false;
  const auto start = std::chrono::steady_clock::now();
  std::size_t off = 0;
  while (off < n) {
    const auto now = std::chrono::steady_clock::now();
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - start).count();
    if (elapsed >= static_cast<long long>(timeout_ms)) {
      if (bytes_read) *bytes_read = off;
      return false;
    }
    const std::uint32_t remain = static_cast<std::uint32_t>(timeout_ms - elapsed);
    if (!wait_readable(fd, remain)) {
      if (bytes_read) *bytes_read = off;
      return false;
    }
    const ssize_t k = ::recv(fd, reinterpret_cast<char*>(dst + off), static_cast<int>(n - off), 0);
    if (k <= 0) {
      if (bytes_read) *bytes_read = off;
      if (eof && k == 0) *eof = true;
      return false;
    }
    off += static_cast<std::size_t>(k);
  }
  if (bytes_read) *bytes_read = off;
  return true;
}

bool write_exact_timed(net::SocketHandle fd, const std::uint8_t* src, std::size_t n, std::uint32_t timeout_ms) {
  const auto start = std::chrono::steady_clock::now();
  std::size_t off = 0;
  while (off < n) {
    const auto now = std::chrono::steady_clock::now();
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - start).count();
    if (elapsed >= static_cast<long long>(timeout_ms)) return false;
    const std::uint32_t remain = static_cast<std::uint32_t>(timeout_ms - elapsed);
    if (!wait_writable(fd, remain)) return false;
    int flags = 0;
#ifdef MSG_NOSIGNAL
    flags |= MSG_NOSIGNAL;
#endif
    const ssize_t k = ::send(fd, reinterpret_cast<const char*>(src + off), static_cast<int>(n - off), flags);
    if (k <= 0) return false;
    off += static_cast<std::size_t>(k);
  }
  return true;
}

}  // namespace

std::optional<Frame> read_frame_fd(net::SocketHandle fd, std::size_t max_payload_len, std::uint32_t expected_magic,
                                   std::uint16_t expected_proto_version) {
  return read_frame_fd_timed(fd, max_payload_len, expected_magic, expected_proto_version, 120000, 3000, nullptr, nullptr);
}

std::optional<Frame> read_frame_fd_timed(net::SocketHandle fd, std::size_t max_payload_len, std::uint32_t expected_magic,
                                         std::uint16_t expected_proto_version, std::uint32_t header_timeout_ms,
                                         std::uint32_t body_timeout_ms, FrameReadError* err, FrameFailureInfo* fail_info) {
  if (err) *err = FrameReadError::NONE;
  if (fail_info) {
    *fail_info = FrameFailureInfo{};
    fail_info->expected_magic = expected_magic;
    fail_info->expected_proto_version = expected_proto_version;
  }
  std::array<std::uint8_t, 12> hdr{};
  std::size_t hdr_read = 0;
  bool hdr_eof = false;
  if (!read_exact_timed(fd, hdr.data(), hdr.size(), header_timeout_ms, &hdr_read, &hdr_eof)) {
    if (err) *err = hdr_eof ? FrameReadError::IO_EOF : FrameReadError::TIMEOUT_HEADER;
    if (fail_info) {
      fail_info->reason = hdr_eof ? FrameReadError::IO_EOF : FrameReadError::TIMEOUT_HEADER;
      fail_info->header_bytes_read = hdr_read;
      fail_info->saw_eof = hdr_eof;
      fail_info->first_bytes.assign(hdr.begin(), hdr.begin() + std::min<std::size_t>(hdr_read, 16));
      fail_info->prefix_kind = classify_prefix(fail_info->first_bytes);
    }
    return std::nullopt;
  }
  if (fail_info) {
    fail_info->first_bytes.assign(hdr.begin(), hdr.begin() + std::min<std::size_t>(hdr.size(), 16));
    fail_info->prefix_kind = classify_prefix(fail_info->first_bytes);
  }

  // Keep backing storage alive for ByteReader; avoid binding to a temporary.
  const Bytes hdr_bytes(hdr.begin(), hdr.end());
  codec::ByteReader r(hdr_bytes);
  auto magic = r.u32le();
  auto version = r.u16le();
  auto msg = r.u16le();
  auto len = r.u32le();
  if (!magic || !version || !msg || !len) {
    if (err) *err = FrameReadError::INVALID_HEADER;
    if (fail_info) fail_info->reason = FrameReadError::INVALID_HEADER;
    return std::nullopt;
  }
  if (fail_info) {
    fail_info->received_magic = *magic;
    fail_info->payload_len = *len;
  }
  if (*magic != expected_magic) {
    if (err) *err = FrameReadError::MAGIC_MISMATCH;
    if (fail_info) fail_info->reason = FrameReadError::MAGIC_MISMATCH;
    return std::nullopt;
  }
  if (*version != expected_proto_version) {
    if (err) *err = FrameReadError::VERSION_MISMATCH;
    if (fail_info) fail_info->reason = FrameReadError::VERSION_MISMATCH;
    return std::nullopt;
  }
  if (*len > max_payload_len) {
    if (err) *err = FrameReadError::INVALID_LENGTH;
    if (fail_info) fail_info->reason = FrameReadError::INVALID_LENGTH;
    return std::nullopt;
  }

  Bytes payload(*len);
  std::size_t body_read = 0;
  bool body_eof = false;
  if (*len > 0 && !read_exact_timed(fd, payload.data(), payload.size(), body_timeout_ms, &body_read, &body_eof)) {
    if (err) *err = body_eof ? FrameReadError::IO_EOF : FrameReadError::TIMEOUT_BODY;
    if (fail_info) {
      fail_info->reason = body_eof ? FrameReadError::IO_EOF : FrameReadError::TIMEOUT_BODY;
      fail_info->body_bytes_read = body_read;
      fail_info->saw_eof = body_eof;
    }
    return std::nullopt;
  }
  Hash32 checksum{};
  std::size_t csum_read = 0;
  bool csum_eof = false;
  if (!read_exact_timed(fd, checksum.data(), checksum.size(), body_timeout_ms, &csum_read, &csum_eof)) {
    if (err) *err = csum_eof ? FrameReadError::IO_EOF : FrameReadError::TIMEOUT_BODY;
    if (fail_info) {
      fail_info->reason = csum_eof ? FrameReadError::IO_EOF : FrameReadError::TIMEOUT_BODY;
      fail_info->checksum_bytes_read = csum_read;
      fail_info->saw_eof = csum_eof;
    }
    return std::nullopt;
  }

  if (crypto::sha256d(payload) != checksum) {
    if (err) *err = FrameReadError::INVALID_CHECKSUM;
    if (fail_info) fail_info->reason = FrameReadError::INVALID_CHECKSUM;
    return std::nullopt;
  }
  if (fail_info) fail_info->reason = FrameReadError::NONE;
  return Frame{*msg, payload};
}

bool write_frame_fd(net::SocketHandle fd, const Frame& f, std::uint32_t magic, std::uint16_t proto_version) {
  const Bytes raw = encode_frame(f, magic, proto_version);
  return write_all(fd, raw.data(), raw.size());
}

bool write_all_timed(net::SocketHandle fd, const std::uint8_t* src, std::size_t n, std::uint32_t timeout_ms) {
  return write_exact_timed(fd, src, n, timeout_ms);
}

bool write_frame_fd_timed(net::SocketHandle fd, const Frame& f, std::uint32_t timeout_ms, std::uint32_t magic,
                          std::uint16_t proto_version) {
  const Bytes raw = encode_frame(f, magic, proto_version);
  return write_exact_timed(fd, raw.data(), raw.size(), timeout_ms);
}

}  // namespace finalis::p2p
