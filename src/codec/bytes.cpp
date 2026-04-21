// SPDX-License-Identifier: MIT

#include "codec/bytes.hpp"

#include <functional>

#include "codec/varint.hpp"

namespace finalis::codec {

void ByteWriter::u8(std::uint8_t v) { out_.push_back(v); }

void ByteWriter::u16le(std::uint16_t v) {
  out_.push_back(static_cast<std::uint8_t>(v & 0xFF));
  out_.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
}

void ByteWriter::u32le(std::uint32_t v) {
  for (int i = 0; i < 4; ++i) out_.push_back(static_cast<std::uint8_t>((v >> (8 * i)) & 0xFF));
}

void ByteWriter::u64le(std::uint64_t v) {
  for (int i = 0; i < 8; ++i) out_.push_back(static_cast<std::uint8_t>((v >> (8 * i)) & 0xFF));
}

void ByteWriter::bytes(const Bytes& b) { out_.insert(out_.end(), b.begin(), b.end()); }

void ByteWriter::varint(std::uint64_t v) {
  const auto enc = encode_uleb128(v);
  out_.insert(out_.end(), enc.begin(), enc.end());
}

void ByteWriter::varbytes(const Bytes& b) {
  varint(b.size());
  bytes(b);
}

std::optional<std::uint8_t> ByteReader::u8() {
  if (off_ + 1 > in_.size()) return std::nullopt;
  return in_[off_++];
}

std::optional<std::uint16_t> ByteReader::u16le() {
  if (off_ + 2 > in_.size()) return std::nullopt;
  std::uint16_t v = static_cast<std::uint16_t>(in_[off_]) |
                    (static_cast<std::uint16_t>(in_[off_ + 1]) << 8);
  off_ += 2;
  return v;
}

std::optional<std::uint32_t> ByteReader::u32le() {
  if (off_ + 4 > in_.size()) return std::nullopt;
  std::uint32_t v = 0;
  for (int i = 0; i < 4; ++i) v |= static_cast<std::uint32_t>(in_[off_ + i]) << (8 * i);
  off_ += 4;
  return v;
}

std::optional<std::uint64_t> ByteReader::u64le() {
  if (off_ + 8 > in_.size()) return std::nullopt;
  std::uint64_t v = 0;
  for (int i = 0; i < 8; ++i) v |= static_cast<std::uint64_t>(in_[off_ + i]) << (8 * i);
  off_ += 8;
  return v;
}

std::optional<Bytes> ByteReader::bytes(size_t n) {
  if (off_ + n > in_.size()) return std::nullopt;
  Bytes b(in_.begin() + static_cast<long>(off_), in_.begin() + static_cast<long>(off_ + n));
  off_ += n;
  return b;
}

std::optional<std::uint64_t> ByteReader::varint(bool minimal) {
  const size_t before = off_;
  const auto d = decode_uleb128(in_, off_, minimal);
  if (!d.has_value()) {
    off_ = before;
    return std::nullopt;
  }
  return d.value();
}

std::optional<Bytes> ByteReader::varbytes() {
  const auto n = varint();
  if (!n.has_value()) return std::nullopt;
  return bytes(static_cast<size_t>(n.value()));
}

bool parse_exact(const Bytes& in, const std::function<bool(ByteReader&)>& fn) {
  ByteReader r(in);
  if (!fn(r)) return false;
  return r.eof();
}

}  // namespace finalis::codec
