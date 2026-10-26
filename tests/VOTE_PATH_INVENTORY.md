# Vote-path inventory (PREVOTE / PRECOMMIT)

Every path that creates, persists, signs, sends, re-sends, reseeds or restores a local vote, with the
memory and disk state around it and the test that covers it. Lines refer to `src/` at commit 23fed2b
(unchanged since 9467c05). "Durable" means `DB::write_batch_durable` returned true; a failed write may
still be on disk after a restart (WAL sync failure, see `tests/test_storage_faults.cpp`). Defect ids:
tests/KNOWN_DEFECTS.md.

| # | Path | Code | Memory / disk | Reaches a peer? | Later conflicting vote? | Coverage |
|---|---|---|---|---|---|---|
| 1 | Prevote on a proposal | `handle_propose_result` node_consensus.cpp:1766-1792 → `record_local_prevote_locked` :941 | `local_prevotes_[h,r]` set, then the safety row is written; broadcast + local handle only on success | on success only | on failure the record stays in memory (no retry in that round); after a restart it is gone unless the WAL replayed it | `test_pf_prevote_write_failure_prevote_not_emitted`, `..._blocks_same_round_retry_and_conflict` |
| 2 | Precommit on a polka, first call | `on_prevotes_changed_locked` :669-723 → `lock_on_polka_locked` :829-839 | signature made (:713), then `local_vote_locks_[h]` set and written; precommit returned only on success | on success only | the lock stays in memory after a failure (see 3, 4, 6, 7) | `test_pf_lock_write_failure_first_polka_does_not_precommit` |
| 3 | Precommit on re-entry: another prevote for the same polka | `handle_prevote_result` :2015 → :832 early return | no write: the memory lock alone counts as established | **yes** (D1) | after a restart the lock is gone (D4) → D5 | `..._new_prevote_must_not_emit_precommit`, `..._on_live_cluster_...`, `..._precommit_must_not_reach_peer`, `..._crash_must_not_allow_conflicting_finality` |
| 4 | Precommit on re-entry: proposal body arrives / re-delivered | `on_candidate_body_locked` :727 from `handle_propose_result` :1701 and `handle_frontier_block_locked` :2302 → `pending_local_precommits_` → `flush_pending_finalized_broadcasts` node_network.cpp:1526 | as 3 | **yes** (D1) | as 3 | `..._proposal_redelivery_must_not_emit_precommit` (the :2302 caller, an uncertified frontier block delivered locally, is not tested separately) |
| 5 | Peer precommits arrive | `handle_vote_result` :1802 | `votes_` only; no polka handling | n/a | no | `test_pf_lock_write_failure_peer_precommits_do_not_emit_precommit` |
| 6 | Stall rebroadcast | node.cpp:1429-1440, 1685-1687 → `local_votes_for_rebroadcast_locked` :851-923 | re-signs prevotes from `local_prevotes_` and a precommit from the memory lock; no write | **yes** (D2 precommit, D6 prevote) | D6: after a restart the node prevotes another value in that round (slashable) | `..._rebroadcast_must_not_sign_precommit`, `test_pf_prevote_write_failure_rebroadcast_must_not_send_prevote`, `test_pf_rebroadcast_prevote_must_be_remembered_after_restart` |
| 7 | Peer-loss / reconnect round reset | node_network.cpp:851, 1308 → `reseed_local_votes_locked` :925-939 | own prevotes into the prevote tracker; a precommit from the memory lock into `votes_` + reservation | via 6 | as 6 | `test_pf_lock_write_failure_peer_loss_reseed_must_not_record_precommit` (D3) |
| 8 | Startup | `load_state` node_state.cpp:1229-1303, then node.cpp:338 reseed | memory rebuilt from the durable rows (mirror fallback, quarantine + abstain if both unreadable) | via 6 | missing rows = "never voted" (G1); stale valid primary wins (G2) | `test_pf_crash_after_durable_precommit_before_receipt_is_redelivered`, `test_vote_lock_survives_restart_and_blocks_conflicting_vote`, `test_pf_recovery_*`, `test_unreadable_safety_state_*`, `test_safety_state_mirror_recovers_corrupted_primary` |
| 9 | Timeout vote | node.cpp:1532-1560 | reservation + timed-out round in memory only, by design (two_phase_finality.tla allows it) | yes | a restart may vote in a round it timed out of (modelled as safe) | not fault-tested (no write involved) |
| 10 | Round change | TC / f+1 catch-up node_consensus.cpp ~755-790; reconnect reset to round 0 | `current_round_` only; the vote-round floor (:841) uses the memory lock and prevotes | n/a | the floor protects against lower rounds while memory holds the state | `test_pf_lock_write_failure_round_advance_closes_direct_path`, `test_no_vote_below_highest_voted_round_after_round_reset` |
| 11 | Finalization | `apply_finalized_frontier_effects_locked` :335-526 | runtime state advanced (:~426) before the batch write (:514); not undone on failure. The same batch erases the height's safety rows, so they survive a failed write | the finalized tip is announced | the reported height rolls back after a restart (D7) | `test_pf_failed_disk_finalization_is_not_reported_unless_persisted` |
| 12 | Valid polka | :684-692 | written with the result ignored (`(void)`) | n/a | liveness only (re-proposal) | indirectly (first failing write in the natural flow) |
| 13 | DB error, later writes | db.cpp:1630 | RocksDB refuses every write until reopen; can abort (E1) or hang on close after ENOSPC (E2) | n/a | n/a | `test_storage_*` |

Crash boundaries along path 2: crash after signing but before the lock write: nothing sent, nothing to
remember. Crash after a durable lock but before or after the broadcast: the restored lock is re-sent by
6 after the restart (`test_pf_crash_after_durable_precommit_before_receipt_is_redelivered`). Crash after
a failed lock write and a precommit sent by 3/4/6/7: D4.
