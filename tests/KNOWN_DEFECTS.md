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

## Status (2026-10-28)

**No open defects.** Every row below is fixed and its tests are in the gating suite (tags
`known-defect` dropped; the `finalis-known-defects` ctest entry and `fuzz/replay_known_defects.sh` stay
for the next finding). Fixes: D1-D6 P1, fail-stop P2, D7 P3, R1 P4, E1/E2 P5, G1/G2 P6, H1 P7
(`docs/reports/CONSENSUS_PERSISTENCE_REMEDIATION_DESIGN.md`). The fuzz reproducers under
`fuzz/known_defects/` no longer reproduce and are kept as regression inputs.

Round 5 (2026-10-28) also fixed:

| Id | Defect | Fix and tests |
|---|---|---|
| R1 | the live finalization path accepted a precommit quorum from a round below the transition's round; the derivation rejects it, so the node could not restart (beyond f) | P4: `consensus::vote_round_covers_transition` on the polka/lock path, `finalize_if_quorum` and both certificate checks. `test_pf_finalized_state_must_reload_after_restart` (now: the live path ignores it and the node restarts), control `test_pf_finalized_state_from_transition_round_reloads` |
| G1 | both safety rows missing after a vote read as "never voted" | P6: `CSAFE_HIGHWATER` (highest height with a row, raised in every row batch); a height in (finalized, highwater] without rows is quarantined (abstain). `test_pf_recovery_both_rows_missing_after_precommit_must_not_vote_freely` |
| G2 | a stale-but-valid primary row won over a newer mirror | P6: two readable copies that differ are both untrusted (quarantine, abstain). `test_pf_recovery_stale_primary_newer_mirror_must_keep_lock` (now expects abstention, as the design specifies) |
| H1 | quorum-1 self-vote signed without a lock row | P7: confirmed safe by construction after P2/P3 (the self-vote leaves the process only in the certificate queued after the durable finalization write). `test_pf_quorum1_self_vote_failed_finalization_publishes_nothing` (every WAL fault mode) |
| T1 | a time-locked transfer body was a valid standalone transaction: once its unlock height's time signature circulated (long locks: before a block carried the opening), anyone could relay the decrypted body first, so the settlement found its inputs spent and forfeited the sender's bond | bodies are signed under `timed_body_chain_domain(D)` (CLI, wallet, settlement validation via `SpecialValidationContext::timed_body`). `test_revealed_long_lock_body_is_no_standalone_transaction`; fuzz `fuzz_timed_execution` oracle "a sealed transfer was accepted as a standalone record" |
| T2 | TxTimed admission verified the SWE proof (~45 ms at 128 keys) under the node lock `mu_`, with only a per-peer budget (~1.5 proof checks/s per peer): one funded coin and a few inbound peers sending well-signed envelopes with broken proofs (never pooled, so endlessly repeatable) could hold `mu_` and stall a validator's consensus | `check_timed_inclusion(..., TimedInclusionCheck::SkipSweProof)` under `mu_`, `verify_timed_swe_proof` unlocked, re-check before pooling; node-wide budget `timed_verify_bucket_` (16, 4/s) for network proof checks. `run_timed_transfer_on_cluster` (1 node): broken proof rejected as `swe-proof-invalid`, 40 peers hit the node-wide budget |
| T3 | the lightserver's `relay_tx_to_peer` parsed only Tx / TxV2, so every TxTimed submitted through `broadcast_tx` (finalis-cli `timed_send`, the wallet) was refused with "tx parse failed" before reaching a node; the tests injected envelopes into the node directly, and the lightserver tests stub the relay (`tx_relay_override`). Found by the chaos harness's new timed traffic | relay accepts a TxTimed (txid from `TxTimed::parse`). `run_timed_transfer_on_cluster` (1 node) now submits through a real lightserver relay |
| N1 | `finalis-node` logged `lightserver startup success` for a child that had already exited (the exit monitor reaped it first, so the startup `waitpid` saw ECHILD) | startup treats a child reaped elsewhere as a failed start (`reason=exited-early`) |
| F1 | `fuzz_consensus_persistence` wrote a v1 genesis after genesis v2 and exited 2 before its first op; its node also never got peer time signatures, so it stalled after height 1 | v2 genesis via `test::fill_test_genesis_bls`; the harness delivers the other members' time signatures on each finalized tip (`Node::inject_time_signature_for_test`) |

Round 5 evidence (2026-10-28): full suite green; `fuzz_consensus_persistence` 18 campaigns (faults on, and a
Byzantine majority), ~55k ops, ~950 injected WAL faults, no oracle violation or abort; `fuzz_timed_execution`
8 seeds x 60 scripts, ~1,200 escrows settled, clean (and it caught a planted refund bug);
`formal/timed_release.tla` exhaustive, all four rule mutations violate; `scripts/chaos_devnet.py --nodes 7
--duration 600 --tx-interval 2 --timed-interval 5`: no fork, no stall, 97/100 time-locked transfers opened,
the 3 others forfeited because the harness's own sender spent a body input first (a client race, by design).
Nodes now log every settlement (`timed-settled ... outcome= reason=`).

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
Not covered by P2 alone: the finalization batch (D7) and the quorum-1 self-vote (H1), closed by P3
and P7. Two D-tests now see fail-stop and changed only their
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
