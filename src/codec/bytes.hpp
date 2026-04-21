// SPDX-License-Identifier: MIT

#pragma once

#include <array>
#include <cstdint>
#include <functional>
#include <optional>
#include <stdexcept>
#include <string>

#include "common/types.hpp"

namespace finalis::codec {

class ByteWriter {
 public:
  void u8(std::uint8_t v);
  void u16le(std::uint16_t v);
  void u32le(std::uint32_t v);
  void u64le(std::uint64_t v);
  void bytes(const Bytes& b);
  template <size_t N>
  void bytes_fixed(const std::array<std::uint8_t, N>& b) {
    out_.insert(out_.end(), b.begin(), b.end());
  }
  void varint(std::uint64_t v);
  void varbytes(const Bytes& b);

  const Bytes& data() const { return out_; }
  Bytes take() { return std::move(out_); }

 private:
  Bytes out_;
};

class ByteReader {
 public:
  explicit ByteReader(const Bytes& in) : in_(in) {}

  std::optional<std::uint8_t> u8();
  std::optional<std::uint16_t> u16le();
  std::optional<std::uint32_t> u32le();
  std::optional<std::uint64_t> u64le();
  std::optional<Bytes> bytes(size_t n);
  template <size_t N>
  std::optional<std::array<std::uint8_t, N>> bytes_fixed() {
    if (off_ + N > in_.size()) return std::nullopt;
    std::array<std::uint8_t, N> out{};
    for (size_t i = 0; i < N; ++i) out[i] = in_[off_ + i];
    off_ += N;
    return out;
  }
  std::optional<std::uint64_t> varint(bool minimal = true);
  std::optional<Bytes> varbytes();

  bool eof() const { return off_ == in_.size(); }
  size_t remaining() const { return in_.size() - off_; }

 private:
  const Bytes& in_;
  size_t off_{0};
};

bool parse_exact(const Bytes& in, const std::function<bool(ByteReader&)>& fn);

}  // namespace finalis::codec
