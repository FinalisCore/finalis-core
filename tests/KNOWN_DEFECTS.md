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

CI (`linux-ci.yml`, release job) runs the known-defect ctest entry on every run with
`continue-on-error: true`: reported, not a gate.

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
| G1 | design gap: both safety rows missing after a vote restores unrestricted voting | `test_pf_recovery_both_rows_missing_after_precommit_must_not_vote_freely` |
| G2 | design gap: a stale-but-valid primary row wins over a newer mirror | `test_pf_recovery_stale_primary_newer_mirror_must_keep_lock` |

Formal model: `formal/two_phase_finality_persistence.tla` (current code violates `Agreement`; the
"change memory only after a successful write" fix passes).
