// SPDX-License-Identifier: MIT

#pragma once

// Test-only storage fault injection. The test executable defines write(), fdatasync() and fsync();
// librocksdb.so resolves them through the dynamic linker, so these definitions interpose libc's for
// RocksDB's WAL I/O. Nothing in src/ is changed or aware of it. Linux + RocksDB builds only.

#include <cstdint>
#include <string>

#if defined(__linux__) && defined(SC_HAS_ROCKSDB)
#define FINALIS_STORAGE_FAULTS 1
#endif

namespace finalis::test::storage_faults {

enum class Mode {
  Off,
  // write() to a WAL file fails with EIO and writes nothing: the batch is neither visible nor on
  // disk ("failed before applying").
  FailWalWrite,
  // As FailWalWrite, with ENOSPC (disk full) instead of EIO.
  FailWalWriteNoSpace,
  // fdatasync()/fsync() of a WAL file fails with EIO without syncing: the bytes sit in the page
  // cache, so they survive a process restart (not a power loss). Real fsync-EIO behaviour.
  FailWalSync,
  // The WAL is really synced, then EIO is returned: durable, but the caller sees a failure.
  SyncThenFailWal,
};

// Injects into the next `count` matching calls (count < 0: every call) on files whose path starts
// with `db_dir`. RocksDB enters its background-error state on the first one, whatever the count.
void arm(const std::string& db_dir, Mode mode, int count = 1);
void disarm();
// Number of faults injected since the last arm().
int injected();

// RAII: disarms on scope exit so a failing assertion cannot leak faults into later tests.
struct Scoped {
  Scoped(const std::string& db_dir, Mode mode, int count = 1) { arm(db_dir, mode, count); }
  ~Scoped() { disarm(); }
  Scoped(const Scoped&) = delete;
  Scoped& operator=(const Scoped&) = delete;
};

}  // namespace finalis::test::storage_faults
