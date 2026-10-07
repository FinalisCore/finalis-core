// SPDX-License-Identifier: MIT

#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <string>

#ifdef _WIN32
#include <process.h>
#else
#include <unistd.h>
#endif

namespace finalis::test {

// "<prefix>_<pid>_<steady-ns>_<counter>": unique across concurrent test processes (ctest -j) and
// across calls within one process. Callers own creating/removing the path.
inline std::string unique_test_base(const std::string& prefix) {
  static std::atomic<std::uint64_t> counter{0};
#ifdef _WIN32
  const auto pid = static_cast<std::uint64_t>(::_getpid());
#else
  const auto pid = static_cast<std::uint64_t>(::getpid());
#endif
  const auto now = std::chrono::steady_clock::now().time_since_epoch().count();
  const auto seq = counter.fetch_add(1, std::memory_order_relaxed);
  return prefix + "_" + std::to_string(pid) + "_" + std::to_string(now) + "_" + std::to_string(seq);
}

}  // namespace finalis::test
