# Consensus persistence remediation design

Status: design only, nothing implemented. Written 2026-10-26 against commit 23fed2b plus the uncommitted
test, fuzz and model artifacts of red-team rounds 2–3 (`tests/KNOWN_DEFECTS.md`,
`tests/VOTE_PATH_INVENTORY.md`, `fuzz/README.md`, `formal/README.md`). Line numbers refer to `src/` at
23fed2b. A passing model of a fix in this document is evidence about the design rule, not about any C++
code; each defect counts as fixed only when the acceptance criteria in section 7 pass against the real
implementation.

## 1. Findings and evidence

Evidence classes: **direct** (reproduced in a running node, not deterministic), **regression** (a
deterministic test fails on every run), **model/fuzz** (only a TLA+ counterexample or a fuzz input),
**inferred** (code reading, not independently reproduced). Every row was re-run for this review with an
external timeout and child-process isolation (log: round-4 scratch runs, 2 runs each, E1 3 runs).

| Id | Finding | Evidence | Re-run (round 4) |
|---|---|---|---|
| D1 | `lock_on_polka_locked` (:829) sets the in-memory lock before its write and returns true on re-entry for a lock whose write failed; a later prevote or a re-delivered proposal body emits the precommit | regression (4 tests); direct on a live cluster (peer echo) | — (rounds 2–3, 3/3) |
| D2 | the stall rebroadcast (`local_votes_for_rebroadcast_locked` :851) signs a precommit from the in-memory lock | regression | — |
| D3 | the peer-loss / reconnect reseed (:925) records a precommit from the in-memory lock | regression (silent raw-socket peer) | — |
| D4 | after D1–D3 and a restart, the lock of a sent precommit is gone | regression (all 4 fault modes); fuzz `D4-precommit-durable.bin`; model (`SentPrecommitDurable`) | fuzz 2/2 |
| D5 | D4 + 1 Byzantine validator: two observer nodes finalize different transitions at one height | regression (real nodes, real certificates); model (`Agreement`, exhaustive at MaxRound 1, simulation at 2) | 2/2 |
| D6 | the stall rebroadcast sends a prevote whose write failed; after a restart the node prevotes another value in that round; a peer records `PREVOTE_EQUIVOCATION` (on-chain slashable) | regression (bus spy, slashing record); fuzz `D6-prevote-durable.bin`; model (`NoHonestDoublePrevote`, and the `Agreement` counterexample of the lock-fix-only model) | 2/2 + 2/2 |
| D7 | `apply_finalized_frontier_effects_locked` (:335) hydrates the runtime state (:~426) before its batch write (:514) and does not undo it on failure: the in-memory finalized tip (status, tip replies to peers) advances, a restart rolls it back. The finalize path itself does not broadcast it (the broadcast flag is set only after success, :2743) | regression; fuzz `D7-finality-rollback.bin` | 2/2 + fuzz 2/2 |
| E1 | with the Ubuntu librocksdb 8.9 package (built with assertions), an ENOSPC WAL failure on the lock path aborts the process: stack `lock_on_polka_locked` → `DB::write_batch_durable` → `DBImpl::Write` → `WritableFileWriter::Append` (assertion `sync_without_flush_called_`) | direct (5 aborts incl. CI run 40223571152, all under ENOSPC); intermittent; no storage-only reproducer | 1 abort in 3 runs |
| E2 | ENOSPC on a WAL write while another thread writes leaves `DB::close()` blocked | regression at storage level (child process + watchdog); at node level **inferred**: `Node::stop` (node.cpp:503-509, flush + close under `mu_`) never hung in the node tests that injected ENOSPC | 2/2 |
| R1 | the live finalization path (`finalize_if_quorum` :2600) accepts a certificate from a round below the transition's round; the startup derivation (`verify_frontier_finality_certificate_against_state`, canonical_derivation.cpp:184) rejects it; the node cannot restart. Needs > f signers | regression | 2/2 |
| G1 | both safety rows missing after a vote: the node restarts with unrestricted voting (missing = "never voted") | regression (design gap) | — |
| G2 | a stale-but-valid primary row wins over a newer mirror | regression (design gap; needs a rollback of one key) | — |
| H1 | new, unverified: the quorum-1 self-vote path (`finalize_if_quorum` :2674-2692) signs a precommit and inserts it into `votes_` without any lock or prevote persistence; with D7 and the stall rebroadcast, a single-validator network (as testnet-2 runs) could sign two precommits at one (h, r) across a restart | inferred | not tested |
| F1 | new, unverified: without RocksDB the build silently uses the file backend (CMakeLists.txt:173-178, no warning), whose `flush_file` (db.cpp:2820) truncates and rewrites `kv.bin` without fsync or rename: `write_batch_durable` is not durable and a crash mid-write can lose all state | inferred | not tested |

Unresolved uncertainties:

- E1 trigger mechanics: every abort followed a failed ENOSPC durable write in the same call; a storage-only
  sequence (ENOSPC, then a second durable write; or with a concurrent writer) did not abort in 60 + 800
  cycles. Whether an NDEBUG RocksDB build returns an error cleanly here is expected (the failing statement
  is an `assert`) but not verified.
- E2 at node level (see above), and whether `DB::close` or a background recovery thread is the blocked party.
- Windows: vcpkg's RocksDB is a Release build, so E1 probably does not occur there (inferred).
- Power loss: all fault tests model a process crash (the page cache survives). After a failed WAL sync a
  power loss would drop the batch instead of replaying it; the designs below do not depend on which.
- RocksDB versions other than 8.9.1 are untested.

## 2. Design principles

1. **Durable before visible.** The in-memory lock, prevote record and valid polka change only after the
   write that contains the new value returned success. Invariant: memory ⊆ disk (`MemoryBackedByDisk`).
2. **Emission from memory is then safe.** The early return, the stall rebroadcast and the reseed send only
   what memory holds; with (1) that is always durable. No per-path "durable" flags are needed.
3. **Fail-stop after a failed safety-critical write.** The node stops signing at every height and exits
   in a bounded time; the restart reloads the disk state. Reasons, from the evidence: RocksDB refuses every
   later write until reopen (test_storage_faults), so continuing gives no liveness; only a reload resolves
   an ambiguous write; crash-stop is the failure model the BFT argument assumes; and stopping before the next
   write removes the observed E1 trigger (a second write after a failed one).
4. **Finality is reported only once durable.** The runtime advances after a durable commit, or the node
   fail-stops.
5. **One certificate check** shared by live finalization, block delivery and startup derivation.
6. **Storage hardening.** Release-built RocksDB, an explicit ENOSPC policy, bounded shutdown, no silent
   non-durable backend.
7. **Recovery distinguishes "never voted" from "history lost".**

### Why the lock and the prevote record need separate handling

They are separate state (`local_vote_locks_`, `local_prevotes_`), written by separate calls
(`lock_on_polka_locked`, `record_local_prevote_locked`), sent by separate paths (precommit from the lock;
prevote from the prevote record) and protect separate rules (the lock rule; one prevote per round and the
vote-round floor). The model confirms both are needed: with only the lock fixed, `Agreement` still fails
through a prevote rebroadcast from memory plus a restart (depth 12); with only the prevote record fixed, it
fails through a precommit from the in-memory lock plus a restart (depth 11)
(`formal/two_phase_finality_persistence_{lockfix,prevotefix}_only_r1.cfg`). The valid polka is liveness
state (re-proposal), but it is written in the same row, so its update follows the same discipline and its
write failure (today `(void)`, :689) must trigger fail-stop.

### Ambiguous writes: why restoring the previous value is safe, and deleting is not

A write that returned failure may still be on disk (WAL sync failure: the batch is replayed on reopen,
`test_storage_failed_wal_sync_batch_reappears_after_reopen`). With principle 1:

- Disk may be **ahead** of memory, never behind. Nothing was sent on the strength of the newer value (it
  never reached memory), so the newer disk value is either a lock justified by a real polka or a prevote
  record that was never sent; both are only more restrictive after a restart.
- On a backend where later writes succeed (file backend; RocksDB auto-recovery if ever enabled), the next
  successful write serializes memory and drops the unsent newer value. Still safe: it was never sent.
- The model checks exactly this (ambiguous outcome in both directions, sticky and non-sticky failure):
  `fix` / `fix_nonsticky` hold exhaustively at MaxRound 1 and 2.

**Deleting** the in-memory lock on failure is unsafe: the entry may hold an *older* lock (T0, r0) that a
sent precommit relies on. Deleting it makes memory less restrictive than both the disk and the votes
already sent. The previous value must be restored exactly (or, equivalently, never overwritten before the
write succeeds).

### Is fail-stop required, or only defense in depth?

With principle 1 alone, safety holds in the model. Fail-stop is still required for this code base because:
the RocksDB backend never accepts another write in-process, so a node that keeps running is a zombie that
proposes and times out but can never vote; D7 leaves runtime state ahead of disk that only a reload
repairs; the E1 abort follows a second write after a failed one; and the file backend (F1) has no
consistent failure semantics. Fail-stop only removes transitions, so it cannot break a safety invariant
that holds without it.

## 3. Vote-path remediation matrix

Paths as numbered in `tests/VOTE_PATH_INVENTORY.md`.

| # | Path | Current behaviour | Failure mode | Invariant | Strategy | Regression test | Restart / ambiguous write |
|---|---|---|---|---|---|---|---|
| 1 | Prevote on a proposal (:1766, :941) | record set, then written; sent on success | record left in memory after failure (sent later by 6) | memory prevote ⊆ disk | write the candidate state; set `local_prevotes_` only on success; on failure fail-stop | `test_pf_prevote_write_failure_*`, `test_pf_rebroadcast_prevote_must_be_remembered_after_restart` | ambiguous record stays unsent; restart may load it (more restrictive) |
| 2 | Precommit, first call (:716, :829) | lock set, then written; precommit only on success | lock left in memory (feeds 3, 4, 6, 7) | memory lock ⊆ disk | build the candidate lock; serialize from the candidate; publish on success; fail-stop on failure | `test_pf_lock_write_failure_first_polka_does_not_precommit` | as 1 |
| 3 | Re-entry: another prevote (:2015 → :832) | early return true | D1 | precommit only for a durable lock | unchanged code; correct by construction once 2 holds (memory lock is durable) | `..._new_prevote_must_not_emit_precommit`, `..._on_live_cluster_...`, `..._precommit_must_not_reach_peer` | — |
| 4 | Re-entry: body (:727 from :1701 and :2302) | same early return via the pending queue | D1 | as 3 | as 3 | `..._proposal_redelivery_must_not_emit_precommit` (add one for the :2302 caller) | — |
| 5 | Peer precommits (:1802) | `votes_` only | none | — | none | `..._peer_precommits_do_not_emit_precommit` | — |
| 6 | Stall rebroadcast (:851-923) | re-signs memory prevotes and the memory lock | D2, D6 | re-send only durable votes | correct by construction once 1 and 2 hold; halted node sends nothing new | `..._rebroadcast_must_not_sign_precommit`, `test_pf_prevote_write_failure_rebroadcast_must_not_send_prevote` | — |
| 7 | Reconnect reseed (:925) | records a precommit from the memory lock | D3 | as 6 | as 6 | `..._peer_loss_reseed_must_not_record_precommit` | — |
| 8 | Startup (node_state.cpp:1229-1303) | loads rows; mirror fallback; quarantine + abstain when unreadable | G1, G2 | no unrestricted voting with unknown history | highwater key (G1); mismatch → abstain (G2) | `test_pf_recovery_*` | rows are the only record; see section 5 |
| 9 | Timeout vote (node.cpp:1532-1560) | memory only, by design | none (modelled safe) | — | blocked while halted | none needed | — |
| 10 | Round change | floor from memory lock + prevotes | none once 1, 2 hold | floor ≥ every durable vote round | none | `..._round_advance_closes_direct_path`, `test_no_vote_below_highest_voted_round_after_round_reset` | — |
| 11 | Finalization (:335-526) | runtime advanced before a non-durable batch write; failure not undone | D7 | reported tip ⊆ durable tip | phase 1: durable write, fail-stop on failure, tip replies only after success; phase 2: compute the whole batch before hydrate and write first | `test_pf_failed_disk_finalization_is_not_reported_unless_persisted` | the failed batch also carried the safety-row erase, so vote history survives the rollback |
| 12 | Valid polka (:684-692) | `(void)` write | silent; first failing write in the natural flow | memory ⊆ disk; failure visible | same discipline as 2; check the result; fail-stop | covered by 2's tests | — |
| 13 | Storage after an error (db.cpp:1630) | every later write fails; E1 abort; E2 hang | E1, E2 | no second write after a failure; bounded shutdown | fail-stop; release RocksDB; shutdown watchdog | `test_pf_enospc_wal_failure_must_not_abort_node`, new node-level stop test | — |
| 14 | Quorum-1 self-vote (:2674-2692) | signs a precommit without persistence | H1 (inferred) | as 2 | persist the lock before signing, as path 2 | new test (section 6) | — |

## 4. Critical review of the remedies

**Persist before publishing (lock, prevote, valid polka).** `persist_consensus_safety_state_locked`
(:1004) serializes from the member maps, so it must take the candidate state explicitly (lock, valid
polka, prevotes for the height) instead of reading members. Everything runs under `mu_`; the candidate is
built, written and published without releasing it. Risks: a caller that mutates a member before calling
the persist helper (today :684-688 and :835) keeps the old bug; review every caller of the helper.
Performance is unchanged (same writes).

**Restore the previous value.** Equivalent to the above when done as "set, write, restore exactly on
failure". More error-prone (three maps, every early exit); prefer never mutating before success.

**Quarantine / fail-stop.** On any failed safety-critical write (lock, prevote, valid polka, finalization
batch, startup rewrite): set a `safety_storage_failed_` flag under `mu_` before releasing it; every signing
site (prevote, precommit, quorum-1 self-vote, timeout vote, proposal, rebroadcast re-signing) checks it;
log `CRITICAL`; request shutdown; exit with a distinct code so the supervisor restarts the node. Risks:
availability (a disk hiccup stops the validator, but RocksDB needs a reopen anyway); a restart loop while
the disk stays full (acceptable, and visible); the shutdown path itself writes (peers, addrman, flush) and
can hang (E2), so the halted shutdown must skip non-essential writes and run under a watchdog that ends
the process after a fixed time. Startup on a failing disk already fails closed (`load_state` aborts init
when its own row rewrite fails, node_state.cpp:1257/1271/1313).

**Atomic finalization.** Phase 1 (small): make the batch write durable, check it, fail-stop on failure, and
keep `pending_finalized_*` after success (already true). The rollback of in-memory state is then moot: the
process ends. Phase 2 (larger): move every batch contribution before `hydrate_runtime_from_canonical_state_locked`
(the safety-row erase can use `record.transition.height`; availability state and the status snapshot must
be computed from `next_state`), write durably, then hydrate. Risks: phase 2 touches a 190-line function
with epoch closeout writes outside the batch (`maybe_finalize_epoch_committees_locked`, its own immediate
writes); keep it a separate, later patch. Durability note: the batch is a non-sync write today; RocksDB's
single WAL is sequential, so the next sync write (a vote at h+1) also persists it (inferred from RocksDB
semantics, not tested); making it sync costs one fsync per block.

**Align live and replay certificate checks.** Add `round >= transition.round` to `finalize_if_quorum` and
to `on_prevotes_changed_locked` (no lock or precommit for a transition at a round below its own), ideally
through one shared helper also used by `verify_finality_certificate_for_frontier_locked` (:594) and the
derivation. Risk: none for honest traffic (honest validators never vote below a transition's round).
Review the other checks of the derivation (committee, quorum threshold) against the live path in the same
patch.

**RocksDB.** (a) Link a RocksDB built with `NDEBUG` (pinned source build in CMake/Docker, or a distro
build without assertions) for release, Docker and `scripts/start.sh` installs; (b) fail-stop removes the
second write; (c) ENOSPC policy: treat as fatal (fail-stop) rather than enabling auto-recovery, which
would reintroduce writes after an error; (d) halted shutdown: no `flush()`, `close()` on a helper thread,
process exit after a timeout; never hold `mu_` across a possibly blocking close. Risk: changing the
RocksDB build affects every node; verify reading existing databases (same major version).

**Missing, corrupt or inconsistent rows.** G2: primary and mirror are written in one atomic batch, so a
difference can only come from outside damage: treat "both valid but different" as unreadable (quarantine
+ abstain) instead of preferring the primary. G1: add a `CSAFE_HIGHWATER` key (highest height with safety
state) written in the same batch as every row; at startup, any height in (finalized, highwater] without
rows is quarantined and abstained. Risks: abstention ends only when the height finalizes (existing
behaviour, needs the rest of the network); losing the highwater key itself requires outside damage too.

**F1.** Require RocksDB for node binaries (`FATAL_ERROR` unless an explicit fuzz/test-only option), and/or
make the file backend durable (temp file, fsync, rename, directory fsync).

**H1.** First write the test (single-validator node, failed finalization write, stall rebroadcast,
restart); if it confirms, give the quorum-1 path the same persist-before-sign rule as path 2.

## 5. Formal verification

Model: `formal/two_phase_finality_persistence.tla` (abstract: 3 honest + 1 Byzantine, quorum 3, two values,
one height, asynchronous delivery, symmetry; not modelled: re-proposal, timed-out rounds, finalization,
storage library behaviour).

| Remedy | Invariants it must establish | Model status |
|---|---|---|
| Persist before publish, lock + prevote (`FixLock`, `FixPrevote`) | `MemoryBackedByDisk`, `SentPrecommitDurable`, `SentPrevoteDurable`, `NoHonestDoublePrevote`, `NoHonestDoublePrecommit`, `Agreement` | exhaustive, hold at MaxRound 1 and 2, sticky and non-sticky failure (26.4M / 12.7M states); non-vacuous (`fix_reach`) |
| Either half alone | `Agreement` | **violated** (exhaustive at MaxRound 1) |
| Current code | all of the above | violated; `Agreement` exhaustive at MaxRound 1, simulation only at MaxRound 2 (the exhaustive MaxRound 2 run is incomplete) |
| Fail-stop | same | not modelled; removes transitions only, so it cannot break the state invariants above |
| D7 finalization | proposed `ReportedFinalizedDurable`: the reported height is ≤ the durable height | needs a model extension (finalization write + runtime height) |
| R1 | proposed `CertRoundAtLeastTransitionRound` | trivial in the model; covered by tests instead |
| G1 / G2 | proposed `NoVoteWithUnknownHistory` (a restart with rows lost must not vote at that height) | needs a model extension (row loss action) |

## 6. Tests, fuzz oracles and models per patch

| Patch | Must start passing (drop `known-defect` only when they do) | Fuzz | Model |
|---|---|---|---|
| P1 persist before publish | D1: `test_pf_lock_write_failure_new_prevote_must_not_emit_precommit`, `..._proposal_redelivery_...`, `..._on_live_cluster_...`, `..._precommit_must_not_reach_peer`; D2: `..._rebroadcast_must_not_sign_precommit`; D3: `..._peer_loss_reseed_must_not_record_precommit`; D4: `test_pf_emitted_precommit_lock_must_survive_restart`; D5: `..._crash_must_not_allow_conflicting_finality`; D6: `test_pf_prevote_write_failure_rebroadcast_must_not_send_prevote`, `test_pf_rebroadcast_prevote_must_be_remembered_after_restart` | `precommit-durable`, `prevote-durable`, `lock-rule`, `double-*`; `D4-precommit-durable.bin`, `D6-prevote-durable.bin` pass | `fix*` configs |
| P2 fail-stop | new: halted node signs nothing at any height (prevote, precommit, timeout, proposal) after a failed write; new: node-level stop after ENOSPC finishes within N s (E2) | new oracle: no own vote after a failed write until restart | — |
| P3 finalization | D7: `test_pf_failed_disk_finalization_is_not_reported_unless_persisted` | `finality`; `D7-finality-rollback.bin` passes | `ReportedFinalizedDurable` (extension) |
| P4 certificate check | R1: `test_pf_finalized_state_must_reload_after_restart` | `restart` with `FINALIS_FUZZ_BYZANTINE_MAJORITY=1` | — |
| P5 storage | E1: `test_pf_enospc_wal_failure_must_not_abort_node`; F1: new test that a node build without RocksDB fails to configure (or file backend survives a crash mid-write) | faults-on campaign shows no process aborts | — |
| P6 recovery | G1: `test_pf_recovery_both_rows_missing_after_precommit_must_not_vote_freely`; G2: `test_pf_recovery_stale_primary_newer_mirror_must_keep_lock` (expectation becomes "abstains" instead of "keeps the lock"; change the test only in the same reviewed patch) | — | `NoVoteWithUnknownHistory` (extension) |
| P7 quorum-1 | new H1 test (first, to confirm) | single-validator fuzz mode (new) | — |

Tests that pass today and must keep passing: all gating `test_pf_*`, `test_storage_*`, the existing two-phase
and recovery tests. Several pass today for a different reason than after the fix (for example
`test_pf_lock_write_failure_running_node_refuses_conflicts` passes because the write of the conflicting
prevote fails; after P2 because the node is halted); review each in the patch that changes the reason.
`test_storage_enospc_wal_fault_with_concurrent_writer_hangs_close` characterizes the library and is
expected to keep passing until the RocksDB build changes; update it in P5 with the new observed behaviour.

## 7. Acceptance criteria

A defect is fixed when, on the implementation:

- every test listed for it in section 6 passes 3 consecutive runs of
  `FINALIS_TEST_KNOWN_DEFECTS=include FINALIS_TEST_FILTER=test_pf_ ./build/finalis-tests` (isolated mode),
  and its `known-defect` tag is removed in the same patch;
- its fuzz reproducer passes `fuzz/replay_known_defects.sh build` and moves to the target's seed corpus;
- a faults-on campaign of 20 seeds × 80 scripts (`FINALIS_FUZZ_SEED=1..20 FINALIS_FUZZ_ITERS=80
  ./build/fuzz_consensus_persistence`) finds no violation of the oracles listed for it;
- the gate (`ctest -LE known-defect`) and the fault-free smoke stay green, and the sanitizer jobs pass;
- E1 specifically: `test_pf_enospc_wal_failure_must_not_abort_node` passes 10 consecutive runs, and
  ENOSPC is added back to `kPfGateFaults`;
- E2 specifically: the new node-level shutdown test finishes within its bound in 10 runs;
- model configs stay as recorded (no change to the TLA+ model is needed for P1; extensions for P3/P6 are
  added before their patches land).

## 8. Proposed patch sequence

1. **P1 — persist before publish** (lock, prevote record, valid polka; the persist helper takes explicit
   state). Fixes D1–D6 by construction. Smallest safety-critical change; land first.
2. **P2 — fail-stop** (`safety_storage_failed_` flag checked at every signing site; CRITICAL log; bounded
   shutdown without flush; exit code for the supervisor). Removes the zombie state and the E1 trigger;
   bounds E2.
3. **P3 — finalization phase 1** (durable, checked batch write; fail-stop on failure). Fixes D7. Phase 2
   (batch before hydrate) as a later, separate refactor.
4. **P4 — certificate check alignment** (shared helper; `round >= transition.round` on the live paths).
   Fixes R1.
5. **P5 — storage** (release-built RocksDB for release/Docker/start.sh; require RocksDB for node builds or
   make the file backend durable). Fixes E1 at the source, F1.
6. **P6 — recovery** (primary/mirror mismatch → abstain; highwater key). Closes G1, G2.
7. **P7 — quorum-1 self-vote**, after the H1 test confirms the hypothesis.

Each patch: its regression tests flip from failing to passing, its tags are removed in the same commit,
nothing else in the known-defect suite changes state, and the gate stays green.
