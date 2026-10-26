// SPDX-License-Identifier: MIT

#include "storage_fault_injection.hpp"

#ifdef FINALIS_STORAGE_FAULTS

#include <atomic>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <mutex>

#include <csignal>

#include <dlfcn.h>
#include <execinfo.h>
#include <unistd.h>

namespace finalis::test::storage_faults {
namespace {

std::atomic<bool> g_armed{false};
std::mutex g_mu;
std::string g_dir;
Mode g_mode = Mode::Off;
int g_remaining = 0;
std::atomic<int> g_injected{0};

template <typename Fn>
Fn real(const char* name) {
  return reinterpret_cast<Fn>(::dlsym(RTLD_NEXT, name));
}

bool is_wal_fd_under(int fd, const std::string& dir) {
  char link[64];
  std::snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
  char path[4096];
  const ssize_t n = ::readlink(link, path, sizeof(path) - 1);
  if (n <= 0) return false;
  const std::string p(path, static_cast<std::size_t>(n));
  return p.size() > 4 && p.compare(0, dir.size(), dir) == 0 && p.compare(p.size() - 4, 4, ".log") == 0;
}

// Returns the mode to inject for this call on `fd` (Off: pass through), consuming one fault.
Mode take(int fd, bool sync_call) {
  if (!g_armed.load(std::memory_order_acquire)) return Mode::Off;
  std::lock_guard<std::mutex> lk(g_mu);
  if (g_mode == Mode::Off || g_remaining == 0) return Mode::Off;
  const bool write_mode = g_mode == Mode::FailWalWrite || g_mode == Mode::FailWalWriteNoSpace;
  if (write_mode == sync_call) return Mode::Off;
  if (!is_wal_fd_under(fd, g_dir)) return Mode::Off;
  if (g_remaining > 0) --g_remaining;
  g_injected.fetch_add(1);
  return g_mode;
}

int sync_with(int fd, const char* name) {
  using SyncFn = int (*)(int);
  static SyncFn real_fdatasync = real<SyncFn>("fdatasync");
  static SyncFn real_fsync = real<SyncFn>("fsync");
  SyncFn fn = std::strcmp(name, "fsync") == 0 ? real_fsync : real_fdatasync;
  switch (take(fd, true)) {
    case Mode::FailWalSync:
      errno = EIO;
      return -1;
    case Mode::SyncThenFailWal:
      (void)fn(fd);
      errno = EIO;
      return -1;
    default:
      return fn(fd);
  }
}

// Ubuntu's librocksdb is built with assertions; some WAL-error interleavings abort inside it. Print
// the aborting thread's stack (test diagnostics only), then let the default action run.
void on_abort(int sig) {
  void* frames[64];
  const int n = ::backtrace(frames, 64);
  static const char kHeader[] = "\n[storage-faults] SIGABRT while faults were armed; backtrace:\n";
  (void)!::write(2, kHeader, sizeof(kHeader) - 1);
  ::backtrace_symbols_fd(frames, n, 2);
  std::signal(sig, SIG_DFL);
  std::raise(sig);
}

}  // namespace

void arm(const std::string& db_dir, Mode mode, int count) {
  static const bool handler_installed = [] {
    std::signal(SIGABRT, on_abort);
    return true;
  }();
  (void)handler_installed;
  std::lock_guard<std::mutex> lk(g_mu);
  std::error_code ec;
  const auto canonical = std::filesystem::weakly_canonical(db_dir, ec);
  g_dir = ec ? db_dir : canonical.string();
  g_mode = mode;
  g_remaining = count;
  g_injected.store(0);
  g_armed.store(mode != Mode::Off, std::memory_order_release);
}

void disarm() {
  std::lock_guard<std::mutex> lk(g_mu);
  g_armed.store(false, std::memory_order_release);
  g_mode = Mode::Off;
  g_remaining = 0;
}

int injected() { return g_injected.load(); }

}  // namespace finalis::test::storage_faults

using namespace finalis::test::storage_faults;

extern "C" ssize_t write(int fd, const void* buf, size_t count) {
  using WriteFn = ssize_t (*)(int, const void*, size_t);
  static WriteFn real_write = real<WriteFn>("write");
  switch (take(fd, false)) {
    case Mode::FailWalWrite:
      errno = EIO;
      return -1;
    case Mode::FailWalWriteNoSpace:
      errno = ENOSPC;
      return -1;
    default:
      break;
  }
  return real_write(fd, buf, count);
}

extern "C" int fdatasync(int fd) { return sync_with(fd, "fdatasync"); }
extern "C" int fsync(int fd) { return sync_with(fd, "fsync"); }

#else

namespace finalis::test::storage_faults {
void arm(const std::string&, Mode, int) {}
void disarm() {}
int injected() { return 0; }
}  // namespace finalis::test::storage_faults

#endif
