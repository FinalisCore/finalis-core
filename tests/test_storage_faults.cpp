// SPDX-License-Identifier: MIT

// Characterization of storage::DB::write_batch_durable under injected WAL faults (RocksDB build,
// Linux). These pin what the consensus persistence-failure tests in test_integration.cpp rely on:
// whether a failed durable write is visible, whether later writes succeed, and whether the batch
// reappears after the DB is reopened (a process restart; the page cache survives, power is not lost).

#include "test_framework.hpp"
#include "support/storage_fault_injection.hpp"
#include "support/test_paths.hpp"

#include <filesystem>
#include <iostream>

#include "storage/db.hpp"

using namespace finalis;
namespace faults = finalis::test::storage_faults;

#ifdef FINALIS_STORAGE_FAULTS

namespace {

struct FaultOutcome {
  bool write_ok{false};
  int injected{0};
  bool visible_before_reopen{false};
  bool later_write_ok{false};
  bool visible_after_reopen{false};
  bool later_key_after_reopen{false};
  bool write_after_reopen_ok{false};
};

FaultOutcome run_fault(const std::string& tag, faults::Mode mode) {
  const std::string dir = finalis::test::unique_test_base("/tmp/finalis_storage_fault_" + tag);
  std::filesystem::create_directories(dir);
  FaultOutcome out;
  {
    storage::DB db;
    if (!db.open(dir)) throw std::runtime_error("open failed");
    storage::DB::Batch warm(db);
    warm.put("warm", Bytes{1});
    if (!db.write_batch_durable(warm)) throw std::runtime_error("warm-up write failed");
    {
      faults::Scoped arm(dir, mode, 1);
      storage::DB::Batch b(db);
      b.put("k", Bytes{0x42});
      out.write_ok = db.write_batch_durable(b);
      out.injected = faults::injected();
    }
    out.visible_before_reopen = db.get("k").has_value();
    storage::DB::Batch later(db);
    later.put("later", Bytes{7});
    out.later_write_ok = db.write_batch_durable(later);
    db.close();
  }
  {
    storage::DB db;
    if (!db.open(dir)) throw std::runtime_error("reopen failed");
    out.visible_after_reopen = db.get("k").has_value();
    out.later_key_after_reopen = db.get("later").has_value();
    storage::DB::Batch b(db);
    b.put("after", Bytes{9});
    out.write_after_reopen_ok = db.write_batch_durable(b);
    db.close();
  }
  std::cerr << "[storage-fault] mode=" << tag << " write_ok=" << out.write_ok << " injected=" << out.injected
            << " visible_before_reopen=" << out.visible_before_reopen << " later_write_ok=" << out.later_write_ok
            << " visible_after_reopen=" << out.visible_after_reopen
            << " later_key_after_reopen=" << out.later_key_after_reopen
            << " write_after_reopen_ok=" << out.write_after_reopen_ok << "\n";
  return out;
}

}  // namespace

// Every injected WAL fault: write_batch_durable returns false, the batch is not visible, and the DB
// refuses every later write until it is reopened (RocksDB background error, no auto-resume here).
// So within one process lifetime a failed safety-state write is never healed by a later one.
TEST(test_storage_failed_durable_write_blocks_all_later_writes_until_reopen) {
  for (const auto& [tag, mode] : {std::pair{"wal_write", faults::Mode::FailWalWrite},
                                  std::pair{"wal_enospc", faults::Mode::FailWalWriteNoSpace},
                                  std::pair{"wal_sync", faults::Mode::FailWalSync},
                                  std::pair{"sync_then_fail", faults::Mode::SyncThenFailWal}}) {
    const auto o = run_fault(tag, mode);
    ASSERT_EQ(o.injected, 1);
    ASSERT_TRUE(!o.write_ok);
    ASSERT_TRUE(!o.visible_before_reopen);
    ASSERT_TRUE(!o.later_write_ok);
    ASSERT_TRUE(!o.later_key_after_reopen);
    ASSERT_TRUE(o.write_after_reopen_ok);
  }
}

// A failed WAL write() (EIO or disk full): the batch is lost for good.
TEST(test_storage_failed_wal_write_batch_absent_after_reopen) {
  ASSERT_TRUE(!run_fault("wal_write_absent", faults::Mode::FailWalWrite).visible_after_reopen);
  ASSERT_TRUE(!run_fault("wal_enospc_absent", faults::Mode::FailWalWriteNoSpace).visible_after_reopen);
}

// A failed WAL sync is ambiguous: reported as failed and invisible in this process, yet the batch
// is replayed from the WAL when the DB is reopened (process restart; the page cache survives).
TEST(test_storage_failed_wal_sync_batch_reappears_after_reopen) {
  ASSERT_TRUE(run_fault("wal_sync_reappears", faults::Mode::FailWalSync).visible_after_reopen);
  ASSERT_TRUE(run_fault("sync_then_fail_reappears", faults::Mode::SyncThenFailWal).visible_after_reopen);
}

// Control: a fault armed for another directory never touches this DB (the path filter isolates
// the target node from every other node in the same test process).
TEST(test_storage_fault_harness_is_transparent_when_disarmed) {
  const std::string dir = finalis::test::unique_test_base("/tmp/finalis_storage_fault_control");
  std::filesystem::create_directories(dir);
  faults::Scoped other(finalis::test::unique_test_base("/tmp/finalis_storage_fault_elsewhere"), faults::Mode::FailWalWrite, -1);
  {
    storage::DB db;
    ASSERT_TRUE(db.open(dir));
    storage::DB::Batch b(db);
    b.put("k", Bytes{1});
    ASSERT_TRUE(db.write_batch_durable(b));
    ASSERT_TRUE(db.get("k").has_value());
    db.close();
  }
  storage::DB db;
  ASSERT_TRUE(db.open(dir));
  ASSERT_TRUE(db.get("k").has_value());
  ASSERT_EQ(faults::injected(), 0);
}

#endif
