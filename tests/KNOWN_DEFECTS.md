# Known-defect regression tests

Tests tagged `known-defect` (`TEST_TAGS`) reproduce open production defects. Their assertions state the
required invariant, so they **fail until the defect is fixed**. Do not weaken, skip or delete them; when a
fix lands, drop the `known-defect` tag so they join the gating suite.

## Running

| What | Command |
|---|---|
| Gating suite (known-defect tests excluded, skipped count printed) | `./build/finalis-tests` or `ctest --test-dir build -LE known-defect` |
| Known-defect tests only | `FINALIS_TEST_KNOWN_DEFECTS=only ./build/finalis-tests`, `ctest --test-dir build -L known-defect`, or `cmake --build build --target run-known-defect-tests` |
| Everything | `FINALIS_TEST_KNOWN_DEFECTS=include ./build/finalis-tests` |
| One test | `./build/finalis-tests --run <name>` (ignores the tag) |

CI (`linux-ci.yml`, release job) runs the known-defect ctest entry and the fuzz reproducers
(`fuzz/replay_known_defects.sh`) on every run with `continue-on-error: true`: reported in the step and in
the run summary ("OPEN DEFECTS REPRODUCED"), not a gate.

Tests tagged `isolate` inject storage faults and run in a child process (`finalis-tests --run NAME`), so
an abort inside librocksdb (E1 below) fails that one test with its signal instead of ending the run.

## Consensus persistence failures (red-team round 2, 2026-10-25, commit 9467c05)

Spec rule broken: TWO_PHASE_FINALITY.md §3.2, safety state is durable before the vote leaves the process.
Faults are injected into one node's RocksDB WAL by `tests/support/storage_fault_injection.cpp` (Linux,
RocksDB builds; the tests compile out elsewhere). `tests/test_storage_faults.cpp` pins the RocksDB
behaviour they rely on.

| Id | Defect | Tests (`tests/test_integration.cpp`) |
|---|---|---|
| D1 | `lock_on_polka_locked` returns true for a lock whose write failed; a later prevote, a re-delivered proposal body, or a live peer's echo emits the precommit | `test_pf_lock_write_failure_new_prevote_must_not_emit_precommit`, `..._proposal_redelivery_must_not_emit_precommit`, `..._on_live_cluster_must_not_emit_precommit`, `..._precommit_must_not_reach_peer` |
| D2 | `local_votes_for_rebroadcast_locked` signs a precommit for the in-memory lock | `test_pf_lock_write_failure_rebroadcast_must_not_sign_precommit` |
| D3 | `reseed_local_votes_locked` (peer-loss / reconnect reset) records a precommit for the in-memory lock | `test_pf_lock_write_failure_peer_loss_reseed_must_not_record_precommit` |
| D4 | after D1, a restart forgets the lock of a precommit that was sent | `test_pf_emitted_precommit_lock_must_survive_restart` |
| D5 | D1 + crash + 1 Byzantine validator: two transitions finalize at one height | `test_pf_lock_write_failure_crash_must_not_allow_conflicting_finality` |
| D6 | the stall rebroadcast sends a prevote whose write failed; after a restart the honest node prevotes another value in that round (slashable `PREVOTE_EQUIVOCATION`) | `test_pf_prevote_write_failure_rebroadcast_must_not_send_prevote`, `test_pf_rebroadcast_prevote_must_be_remembered_after_restart` |
| D7 | `apply_finalized_frontier_effects_locked` updates the runtime state before its (non-durable) batch write and does not undo it when the write fails: the in-memory finalized tip (status, tip replies to peers) advances to a height a restart rolls back (the finalize path itself does not broadcast it: that flag is set only after success) | `test_pf_failed_disk_finalization_is_not_reported_unless_persisted`; fuzz `D7-finality-rollback.bin` |
| R1 | the live finalization path accepts a certificate from a round below the transition's round, the startup derivation rejects it: the node cannot restart. Needs > f signers (outside the BFT fault model) | `test_pf_finalized_state_must_reload_after_restart` (tag `beyond-fault-model`) |
| G1 | design gap: both safety rows missing after a vote restores unrestricted voting | `test_pf_recovery_both_rows_missing_after_precommit_must_not_vote_freely` |
| G2 | design gap: a stale-but-valid primary row wins over a newer mirror | `test_pf_recovery_stale_primary_newer_mirror_must_keep_lock` |

Fuzz reproducers (`fuzz/known_defects/fuzz_consensus_persistence/`, see `fuzz/README.md`):
`D4-precommit-durable.bin`, `D6-prevote-durable.bin`, `D7-finality-rollback.bin`.

### Storage library behaviour (system librocksdb 8.9, Ubuntu package, built with assertions)

| Id | Behaviour | Evidence |
|---|---|---|
| E1 | Mechanism (pinned in P5): the linked Ubuntu `librocksdb8.9` is built without `NDEBUG`, so RocksDB's internal asserts are live. After an ENOSPC WAL failure RocksDB treats the error as recoverable and auto-resumes writes within milliseconds; the next write fails on the WAL again, and the one after appends to the WAL writer that already failed, which trips `assert(sync_without_flush_called_)` in `WritableFileWriter::AssertFalseAndGetStatusForPrevError` (an NDEBUG build returns `IOError("Writer has previous error")` there). So the abort is never the first failing write: it is the third write while the disk stays full, after an auto-resume. Not a caller contract violation (the API allows writing after an error); EIO and sync faults stop writes after the first failure and never abort. Any write could be the first failure (campaign: slashing records, epoch snapshots, finalization, prevote records). **Closed by P5 on our side**: `storage::DB` fences itself on the first failed write or flush of any kind and never calls RocksDB for a write again in that process; the node fail-stops on it. The library itself is unchanged and still aborts when driven this way, and other asserts stay reachable in principle (CMake warns when the found library imports `__assert_fail`). Production consequence before P5: the shipped systemd unit treats SIGABRT as corruption and does not restart. | library: `test_storage_raw_rocksdb_enospc_reuses_failed_wal_writer` (raw RocksDB API: SIGABRT on the 3rd write, asserted as observed); fix: `test_storage_failed_write_fences_every_later_write`, `test_pf_enospc_wal_failure_must_not_abort_node`, `test_pf_failstop_non_safety_write_failure_halts_node` |
| E2 | an ENOSPC on a WAL write while another thread writes left `DB::close()` blocked (shutdown hang). With the P5 write fence the concurrent writer stops reaching RocksDB after the first failure and `close()` returns (200 cycles, every mode); the RocksDB behaviour without the fence is not re-tested | `test_storage_enospc_wal_fault_with_concurrent_writer_closes` (renamed from `..._hangs_close`; asserts the new behaviour) |

### Fail-stop (remediation P2, `docs/reports/CONSENSUS_PERSISTENCE_REMEDIATION_DESIGN.md`)

A failed write of the consensus safety row (vote lock, prevote record, valid polka) sets
`Node::safety_storage_failed_` and fences the DB under `mu_`; every validator-key signature goes
through `Node::sign_consensus_locked` / `vrf_prove_consensus_locked`, which refuse afterwards; the
consensus send helpers, the stall rebroadcast and the reseed send nothing; the event loop exits;
`Node::stop()` skips peers / addrman / flush; `finalis-node` exits 75 with a 30 s watchdog. Tests
`test_pf_failstop_*` (tag `fail-stop`), `test_storage_write_fence_blocks_every_write`,
`test_failstop_validator_key_signing_has_one_guarded_entry`; fuzz oracle `signed-after-fail-stop`.
Not covered by P2: the finalization batch (D7, P3) and the quorum-1 self-vote ordering (H1, P7) do
not enter fail-stop on their own write failures. Two D-tests now see fail-stop and changed only their
controls: D3 probes the vote tracker instead of the (now empty) rebroadcast set; D6's
`..._remembered_after_restart` control 1 accepts "fail-stopped with an empty rebroadcast set" in place
of "the stall rebroadcast reached the observer".

### Durable finalization (remediation P3)

`apply_finalized_frontier_effects_locked` stages the whole finalization batch, writes it with
`write_batch_durable` and publishes only after success: the hydrated runtime fields are held aside
(`take_` / `restore_canonical_runtime_locked`) and put back exactly on failure; mempool, round and
vote state, safety-row memory and the epoch closeout run only after the write; a failed write enters
P2 fail-stop as `finalization height=H`. Tests: `test_pf_failed_disk_finalization_is_not_reported_unless_persisted`
(rewritten: the finalization batch is the first failing write; status, GET_FINALIZED_TIP replies and
TRANSITION broadcasts observed), `test_pf_failed_disk_delivered_finalization_is_not_reported`,
`test_pf_successful_finalization_is_durable_across_restart`. Fail-stop cannot act on a RocksDB abort
(E1): the process is gone before the write returns. The D6a control (`test_pf_prevote_write_failure_rebroadcast_must_not_send_prevote`)
was self-fulfilling (its probe injected the marker it then found as a duplicate); it now reads the
spy's vote tracker, and on a fail-stopped target checks the empty rebroadcast set instead.

### Storage hardening (remediation P5)

Policy after a storage error: the first failed write or flush through `storage::DB` (any kind:
batch, durable batch, put, put_many, erase, flush; RocksDB or file backend) fences the DB with that
error (`DB::write_fence_reason`). Every later write returns false without reaching the engine, also
after the disk recovers or RocksDB auto-resumes; reads keep working; only a reopen (process restart)
lifts it. The node treats a fenced DB as halted at once (`Node::safety_storage_failed()`: no
signature, no consensus send), and the event loop enters fail-stop as `storage-write: <first error>`
(safety writes and finalization enter it directly with their own operation name), then the process
exits 75. A closed DB (`close()`) is not an error. A RocksDB abort (SIGABRT) is not a fail-stop: the
process dies before any of this runs.

Build: RocksDB is required (configure fails without it). The file backend rewrites `kv.bin` in place
without fsync or rename and is not crash-durable; it is selectable only with
`-DFINALIS_ALLOW_FILE_BACKEND=ON` (ClusterFuzzLite), and a `finalis-node` built that way exits 78 at
startup. Configure warns when the found librocksdb has assertions enabled; the distro packages
(Ubuntu `librocksdb8.9`) do. A release (NDEBUG) RocksDB build for validators is not part of P5.

Formal model: `formal/two_phase_finality_persistence.tla` (current code violates `Agreement`; the
"change memory only after a successful write" fix passes).
