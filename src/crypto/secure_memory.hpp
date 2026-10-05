// SPDX-License-Identifier: MIT

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <tuple>
#include <utility>

#include <openssl/crypto.h>

#include "common/types.hpp"

namespace finalis::crypto {

// OPENSSL_cleanse cannot be optimized away, unlike memset on a dying buffer.
inline void secure_wipe(void* p, std::size_t n) {
  if (p != nullptr && n != 0) OPENSSL_cleanse(p, n);
}

inline void secure_wipe(Bytes& b) {
  secure_wipe(b.data(), b.size());
  b.clear();
}

inline void secure_wipe(std::string& s) {
  secure_wipe(s.data(), s.size());
  s.clear();
}

template <std::size_t N>
inline void secure_wipe(std::array<std::uint8_t, N>& a) {
  secure_wipe(a.data(), a.size());
}

// Wipes the referenced buffers when the scope exits, on every return path.
template <typename... Ts>
class ScopedWipe {
 public:
  explicit ScopedWipe(Ts&... refs) : refs_(refs...) {}
  ScopedWipe(const ScopedWipe&) = delete;
  ScopedWipe& operator=(const ScopedWipe&) = delete;
  ~ScopedWipe() {
    std::apply([](auto&... r) { (secure_wipe(r), ...); }, refs_);
  }

 private:
  std::tuple<Ts&...> refs_;
};

// Best-effort: keep a secret's pages out of swap. Failure (e.g. RLIMIT_MEMLOCK) is non-fatal.
bool lock_memory(const void* p, std::size_t n);
void unlock_memory(const void* p, std::size_t n);

}  // namespace finalis::crypto
