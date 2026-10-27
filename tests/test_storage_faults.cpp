// SPDX-License-Identifier: MIT

// Characterization of storage::DB::write_batch_durable under injected WAL faults (RocksDB build,
// Linux). These pin what the consensus persistence-failure tests in test_integration.cpp rely on:
// whether a failed durable write is visible, whether later writes succeed, and whether the batch
// reappears after the DB is reopened (a process restart; the page cache survives, power is not lost).

#include "test_framework.hpp"
#include "support/storage_fault_injection.hpp"
#include "support/test_paths.hpp"

#include <array>
#include <atomic>
#include <csignal>
#include <cstdio>
#include <filesystem>
#include <functional>
#include <fstream>
#include <iostream>
#include <map>
#include <thread>

#include "consensus/epoch_committee.hpp"
#include "storage/db.hpp"

#ifdef FINALIS_STORAGE_FAULTS
#include <execinfo.h>

#include <rocksdb/db.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

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
TEST_TAGS(test_storage_failed_durable_write_blocks_all_later_writes_until_reopen, "isolate,storage-faults");
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
TEST_TAGS(test_storage_failed_wal_write_batch_absent_after_reopen, "isolate,storage-faults");
TEST(test_storage_failed_wal_write_batch_absent_after_reopen) {
  ASSERT_TRUE(!run_fault("wal_write_absent", faults::Mode::FailWalWrite).visible_after_reopen);
  ASSERT_TRUE(!run_fault("wal_enospc_absent", faults::Mode::FailWalWriteNoSpace).visible_after_reopen);
}

// A failed WAL sync is ambiguous: reported as failed and invisible in this process, yet the batch
// is replayed from the WAL when the DB is reopened (process restart; the page cache survives).
TEST_TAGS(test_storage_failed_wal_sync_batch_reappears_after_reopen, "isolate,storage-faults");
TEST(test_storage_failed_wal_sync_batch_reappears_after_reopen) {
  ASSERT_TRUE(run_fault("wal_sync_reappears", faults::Mode::FailWalSync).visible_after_reopen);
  ASSERT_TRUE(run_fault("sync_then_fail_reappears", faults::Mode::SyncThenFailWal).visible_after_reopen);
}

// Control: a fault armed for another directory never touches this DB (the path filter isolates
// the target node from every other node in the same test process).
TEST_TAGS(test_storage_fault_harness_is_transparent_when_disarmed, "isolate,storage-faults");
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


namespace {

// Child process body: `cycles` times, a durable write that takes an injected WAL fault while another
// thread keeps issuing ordinary writes (as a node's event loop does next to the consensus path),
// then the flush + close that Node::stop() performs. A watchdog turns a phase that makes no progress
// for 10 s into exit code 10 + phase (1 durable writes, 2 background join, 3 flush, 4 close).
[[noreturn]] void concurrent_fault_child(const std::string& base, faults::Mode mode, int cycles) {
  static std::atomic<int> phase{0};
  static std::atomic<std::uint64_t> progress{0};
  std::thread([] {
    std::uint64_t last = progress.load();
    int still = 0;
    for (;;) {
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
      const std::uint64_t now = progress.load();
      still = now == last ? still + 1 : 0;
      last = now;
      if (still >= 100) _exit(10 + phase.load());
    }
  }).detach();
  for (int i = 0; i < cycles; ++i) {
    const std::string dir = base + "/c" + std::to_string(i);
    std::filesystem::create_directories(dir);
    storage::DB db;
    if (!db.open(dir)) _exit(3);
    std::atomic<bool> stop{false};
    std::thread background([&] {
      for (int k = 0; !stop.load(); ++k) {
        storage::DB::Batch b(db);
        b.put("bg" + std::to_string(k % 64), Bytes{static_cast<std::uint8_t>(k)});
        (void)db.write_batch(b);
      }
    });
    std::this_thread::sleep_for(std::chrono::microseconds(200));
    phase = 1;
    faults::arm(dir, mode, -1);
    for (int k = 0; k < 4; ++k) {
      storage::DB::Batch b(db);
      b.put("fg" + std::to_string(k), Bytes{1});
      (void)db.write_batch_durable(b);
      ++progress;
    }
    faults::disarm();
    phase = 2;
    stop.store(true);
    background.join();
    ++progress;
    phase = 3;
    (void)db.flush();  // Node::stop() flushes before closing
    ++progress;
    phase = 4;
    db.close();
    ++progress;
    phase = 0;
    std::filesystem::remove_all(dir);
  }
  _exit(0);
}

// Runs the child; returns its wait status.
int run_concurrent_fault_child(const std::string& tag, faults::Mode mode, int cycles) {
  const std::string base = finalis::test::unique_test_base("/tmp/finalis_storage_fault_concurrent_" + tag);
  std::filesystem::create_directories(base);
  std::cout.flush();
  std::cerr.flush();
  const pid_t pid = ::fork();
  if (pid == 0) concurrent_fault_child(base, mode, cycles);
  int status = 0;
  (void)::waitpid(pid, &status, 0);
  std::error_code ec;
  std::filesystem::remove_all(base, ec);
  return status;
}

}  // namespace

// E2: before the storage::DB write fence, an ENOSPC on a WAL write while another thread kept writing
// left DB::close() blocked (a shutdown hang; 4/4 runs, 200 cycles each). With the fence the
// concurrent writer stops reaching RocksDB after the first failure and close() returns in every mode.
// Children keep the runner alive; a hang is reported by phase.
TEST_TAGS(test_storage_enospc_wal_fault_with_concurrent_writer_closes, "isolate,storage-faults");
TEST(test_storage_enospc_wal_fault_with_concurrent_writer_closes) {
  std::map<std::string, std::string> outcome;
  for (const auto& [tag, mode] : {std::pair{"wal_write", faults::Mode::FailWalWrite},
                                  std::pair{"wal_enospc", faults::Mode::FailWalWriteNoSpace},
                                  std::pair{"wal_sync", faults::Mode::FailWalSync},
                                  std::pair{"sync_then_fail", faults::Mode::SyncThenFailWal}}) {
    const int status = run_concurrent_fault_child(tag, mode, 200);
    static const char* kPhase[] = {"durable-write", "background-write", "flush", "close"};
    std::string o;
    if (WIFSIGNALED(status)) {
      o = WTERMSIG(status) == SIGABRT ? "SIGABRT" : "signal " + std::to_string(WTERMSIG(status));
    } else if (WEXITSTATUS(status) >= 11 && WEXITSTATUS(status) <= 14) {
      o = std::string("hang in ") + kPhase[WEXITSTATUS(status) - 11];
    } else {
      o = "exit " + std::to_string(WEXITSTATUS(status));
    }
    std::cerr << "[storage-fault] concurrent mode=" << tag << " child=" << o << "\n";
    outcome[tag] = o;
  }
  ASSERT_EQ(outcome["wal_enospc"], std::string("exit 0"));
  ASSERT_EQ(outcome["wal_write"], std::string("exit 0"));
  ASSERT_EQ(outcome["wal_sync"], std::string("exit 0"));
  ASSERT_EQ(outcome["sync_then_fail"], std::string("exit 0"));
}



namespace {
// Outcome of a forked storage child, kept apart so an abort is never read as handled:
//   "handled"            exit 0: every check in the child held (errors returned, nothing more written)
//   "check-failed:<n>"   exit n: the child returned normally but a check failed
//   "SIGABRT" / "signal" the process died (e.g. a RocksDB assertion)
//   "inconclusive"       the child's 60 s watchdog fired (a hang)
std::string run_storage_child(const std::function<int()>& body) {
  std::cout.flush();
  std::cerr.flush();
  const pid_t pid = ::fork();
  if (pid == 0) {
    std::signal(SIGABRT, [](int) {
      void* frames[64];
      ::backtrace_symbols_fd(frames, ::backtrace(frames, 64), 2);
      std::signal(SIGABRT, SIG_DFL);
      std::abort();
    });
    std::thread([] {
      std::this_thread::sleep_for(std::chrono::seconds(60));
      _exit(99);
    }).detach();
    _exit(body());
  }
  int status = 0;
  (void)::waitpid(pid, &status, 0);
  if (WIFSIGNALED(status)) return WTERMSIG(status) == SIGABRT ? "SIGABRT" : "signal " + std::to_string(WTERMSIG(status));
  if (WEXITSTATUS(status) == 0) return "handled";
  if (WEXITSTATUS(status) == 99) return "inconclusive";
  return "check-failed:" + std::to_string(WEXITSTATUS(status));
}

bool rocksdb_lib_has_assertions() {
  // Same probe as CMakeLists.txt: the shared library imports __assert_fail unless built with NDEBUG.
  const std::string cmd = "nm -D $(ldd /proc/" + std::to_string(::getpid()) +
                          "/exe | awk '/librocksdb/ {print $3}') 2>/dev/null | grep -c ' U __assert_fail'";
  FILE* p = ::popen(cmd.c_str(), "r");
  if (!p) return false;
  char buf[16] = {0};
  const bool yes = std::fgets(buf, sizeof buf, p) != nullptr && std::atoi(buf) > 0;
  ::pclose(p);
  return yes;
}

// One write of the given kind through storage::DB.
enum class WriteOp { DurableBatch, Batch, Put, PutMany, Erase, SlashingRecord, EpochSnapshot, Flush };
const char* write_op_name(WriteOp op) {
  switch (op) {
    case WriteOp::DurableBatch: return "write_batch_durable";
    case WriteOp::Batch: return "write_batch";
    case WriteOp::Put: return "put";
    case WriteOp::PutMany: return "put_many";
    case WriteOp::Erase: return "erase";
    case WriteOp::SlashingRecord: return "put_slashing_record";
    case WriteOp::EpochSnapshot: return "put_epoch_committee_snapshot";
    case WriteOp::Flush: return "flush";
  }
  return "?";
}
bool do_write(storage::DB& db, WriteOp op, int i) {
  const std::string k = "k" + std::to_string(i);
  switch (op) {
    case WriteOp::DurableBatch: {
      storage::DB::Batch b(db);
      b.put(k, Bytes{1});
      return db.write_batch_durable(b);
    }
    case WriteOp::Batch: {
      storage::DB::Batch b(db);
      b.put(k, Bytes{1});
      return db.write_batch(b);
    }
    case WriteOp::Put: return db.put(k, Bytes{1});
    case WriteOp::PutMany: return db.put_many({{k, Bytes{1}}, {k + "b", Bytes{2}}});
    case WriteOp::Erase: return db.erase("warm");
    case WriteOp::SlashingRecord: {
      storage::SlashingRecord rec;
      rec.record_id[0] = static_cast<std::uint8_t>(i);
      rec.height = static_cast<std::uint64_t>(i) + 1;
      return db.put_slashing_record(rec);
    }
    case WriteOp::EpochSnapshot: {
      consensus::EpochCommitteeSnapshot snap;
      snap.epoch = static_cast<std::uint64_t>(i) + 1;
      return db.put_epoch_committee_snapshot(snap);
    }
    case WriteOp::Flush: return db.flush();
  }
  return false;
}
constexpr std::array<WriteOp, 8> kAllWriteOps = {WriteOp::DurableBatch, WriteOp::Batch, WriteOp::Put,
                                                 WriteOp::PutMany, WriteOp::Erase, WriteOp::SlashingRecord,
                                                 WriteOp::EpochSnapshot, WriteOp::Flush};
}  // namespace

// Characterization of the linked librocksdb itself (raw API, no storage::DB): under a disk that stays
// full, RocksDB 8.9 auto-recovers from an ENOSPC WAL failure and resumes writes within milliseconds;
// the next write fails on the WAL again, and the one after appends to the WAL writer that already
// failed. An assertion-enabled build (the
// Ubuntu package) aborts there (E1); an NDEBUG build returns "Writer has previous error". EIO stops
// writes after the first failure and never aborts. Asserted as observed so a library change shows.
TEST_TAGS(test_storage_raw_rocksdb_enospc_reuses_failed_wal_writer, "isolate,storage-faults");
TEST(test_storage_raw_rocksdb_enospc_reuses_failed_wal_writer) {
  const bool asserts = rocksdb_lib_has_assertions();
  std::map<std::string, std::string> outcome;
  for (const auto& [tag, mode] : {std::pair{"enospc", faults::Mode::FailWalWriteNoSpace}, std::pair{"eio", faults::Mode::FailWalWrite}}) {
    const std::string dir = finalis::test::unique_test_base(std::string("/tmp/finalis_e1_raw_") + tag);
    outcome[tag] = run_storage_child([&, mode = mode]() -> int {
      std::filesystem::create_directories(dir);
      rocksdb::Options opts;
      opts.create_if_missing = true;
      rocksdb::DB* raw = nullptr;
      if (!rocksdb::DB::Open(opts, dir, &raw).ok()) return 2;
      std::unique_ptr<rocksdb::DB> db(raw);
      rocksdb::WriteOptions sync;
      sync.sync = true;
      if (!db->Put(sync, "warm", "1").ok()) return 3;
      faults::arm(dir, mode, -1);
      // 250 ms apart: RocksDB's NoSpace auto-recovery resumes writes in between (an immediate retry is
      // refused by the background error and never reaches the WAL).
      for (int i = 0; i < 5; ++i) {
        if (i > 0) std::this_thread::sleep_for(std::chrono::milliseconds(250));
        const auto s = db->Put(sync, "k" + std::to_string(i), "v");
        std::cerr << "[e1-raw] " << tag << " write#" << i << " status=" << s.ToString() << " injected=" << faults::injected() << "\n";
        if (s.ok()) return 4;  // a write on a failing disk must not report success
      }
      return 0;
    });
    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
    std::cerr << "[e1-raw] " << tag << " outcome=" << outcome[tag] << " lib_assertions=" << asserts << "\n";
  }
  ASSERT_EQ(outcome["eio"], std::string("handled"));
  ASSERT_EQ(outcome["enospc"], std::string(asserts ? "SIGABRT" : "handled"));
}

// The fix (storage::DB write fence): the first failed write or flush of any kind fences the DB; every
// later write of every kind returns false without reaching RocksDB (no further WAL write attempt),
// also after the disk recovers and RocksDB auto-resumes, and the process never aborts. A reopen
// starts unfenced. Every fault mode x every first-write kind; ENOSPC repeated 10 times.
TEST_TAGS(test_storage_failed_write_fences_every_later_write, "isolate,storage-faults");
TEST(test_storage_failed_write_fences_every_later_write) {
  struct Mode {
    const char* tag;
    faults::Mode mode;
    int repeats;
  };
  const Mode modes[] = {{"enospc", faults::Mode::FailWalWriteNoSpace, 10},
                        {"eio", faults::Mode::FailWalWrite, 1},
                        {"sync_eio", faults::Mode::FailWalSync, 1},
                        {"sync_then_eio", faults::Mode::SyncThenFailWal, 1}};
  std::map<std::string, int> counts;
  std::vector<std::string> bad;
  for (const auto& m : modes) {
    for (const auto first : kAllWriteOps) {
      if (first == WriteOp::Flush) continue;  // a flush writes SST files, not the WAL the harness faults
      for (int rep = 0; rep < m.repeats; ++rep) {
        const std::string name = std::string(m.tag) + "/" + write_op_name(first) + "#" + std::to_string(rep);
        const std::string dir = finalis::test::unique_test_base("/tmp/finalis_e1_fence");
        const auto outcome = run_storage_child([&]() -> int {
          std::filesystem::create_directories(dir);
          {
            storage::DB db;
            if (!db.open(dir)) return 2;
            if (!db.put("warm", Bytes{1}) || !db.flush()) return 3;
            faults::arm(dir, m.mode, -1);  // the disk stays failed
            // Sync faults only hit a sync write: a non-sync first write succeeds, the durable one fails.
            bool first_ok = do_write(db, first, 0);
            if (first_ok && !do_write(db, WriteOp::DurableBatch, 1)) first_ok = false;
            if (first_ok) return 4;
            if (!db.writes_fenced()) return 5;
            if (db.write_fence_reason().empty()) return 6;
            const int at_fence = faults::injected();
            for (int i = 0; i < 16; ++i) {
              if (do_write(db, kAllWriteOps[static_cast<std::size_t>(i) % kAllWriteOps.size()], 100 + i)) return 7;
            }
            faults::disarm();  // the disk recovers; RocksDB may auto-resume, the fence does not lift
            std::this_thread::sleep_for(std::chrono::milliseconds(600));
            for (const auto op : kAllWriteOps) {
              if (do_write(db, op, 200)) return 8;
            }
            if (faults::injected() != at_fence) return 9;  // a later write reached the WAL
            db.close();
          }
          storage::DB db;
          if (!db.open(dir)) return 10;
          if (db.writes_fenced()) return 11;
          if (!do_write(db, WriteOp::DurableBatch, 300)) return 12;
          db.close();
          return 0;
        });
        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
        ++counts[outcome];
        if (outcome != "handled") bad.push_back(name + "=" + outcome);
      }
    }
  }
  for (const auto& [o, n] : counts) std::cerr << "[e1-fence] outcome=" << o << " cases=" << n << "\n";
  for (const auto& b : bad) std::cerr << "[e1-fence] NOT HANDLED " << b << "\n";
  ASSERT_TRUE(bad.empty());
}

#endif

// Fail-stop write fence (storage::DB::fence_writes): every write path and flush refuses without
// reaching the engine, reads still work, and nothing written after the fence survives a reopen.
TEST(test_storage_write_fence_blocks_every_write) {
  const auto dir = finalis::test::unique_test_base("/tmp/finalis_storage_fence");
  std::filesystem::remove_all(dir);
  {
    storage::DB db;
    ASSERT_TRUE(db.open(dir));
    ASSERT_TRUE(db.put("before", Bytes{1}));
    db.fence_writes();
    ASSERT_TRUE(db.writes_fenced());
    ASSERT_TRUE(!db.put("after-put", Bytes{2}));
    ASSERT_TRUE(!db.put_many({{"after-many", Bytes{3}}}));
    ASSERT_TRUE(!db.erase("before"));
    storage::DB::Batch batch(db);
    batch.put("after-batch", Bytes{4});
    ASSERT_TRUE(!db.write_batch(batch));
    std::string error;
    ASSERT_TRUE(!db.write_batch_durable(batch, &error));
    ASSERT_EQ(error, std::string("writes-fenced"));
    ASSERT_TRUE(!db.flush());
    ASSERT_TRUE(db.get("before").has_value());
    db.close();
  }
  storage::DB db;
  ASSERT_TRUE(db.open(dir));
  ASSERT_TRUE(!db.writes_fenced());
  ASSERT_TRUE(db.get("before").has_value());
  for (const char* key : {"after-put", "after-many", "after-batch"}) ASSERT_TRUE(!db.get(key).has_value());
  db.close();
}

// Fail-stop audit, static half: in src/node every use of the validator private key for signing goes
// through Node::sign_consensus_locked / vrf_prove_consensus_locked / bls_time_sign_consensus_locked,
// which refuse after fail-stop. Allowed elsewhere: loading and wiping the key (node_validator_ops.cpp)
// and the three guarded helpers.
TEST(test_failstop_validator_key_signing_has_one_guarded_entry) {
  const auto src = std::filesystem::path(__FILE__).parent_path().parent_path() / "src" / "node";
  ASSERT_TRUE(std::filesystem::is_directory(src));
  std::size_t helper_uses = 0;
  for (const auto& entry : std::filesystem::directory_iterator(src)) {
    std::ifstream in(entry.path());
    std::string line;
    for (int no = 1; std::getline(in, line); ++no) {
      if (line.find("local_key_.private_key") == std::string::npos) continue;
      const auto file = entry.path().filename().string();
      if (file == "node_validator_ops.cpp") continue;  // key load / wipe / mlock
      const bool helper = file == "node_consensus.cpp" &&
                          (line.find("crypto::ed25519_sign(msg, local_key_.private_key)") != std::string::npos ||
                           line.find("crypto::vrf_prove(local_key_.private_key, alpha)") != std::string::npos ||
                           line.find("crypto::bls_key_from_validator_seed(local_key_.private_key)") != std::string::npos);
      if (helper) {
        ++helper_uses;
        continue;
      }
      std::cerr << "unguarded validator-key use: " << file << ":" << no << ": " << line << "\n";
      ASSERT_TRUE(false);
    }
  }
  ASSERT_EQ(helper_uses, static_cast<std::size_t>(3));
}
