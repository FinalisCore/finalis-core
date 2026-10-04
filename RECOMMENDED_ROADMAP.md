# Recommended Pre-Genesis Roadmap

Source: genesis pre-launch static audit (2026-10-03).

**Process:** items are resolved one at a time, in order. Each item is marked `[x]`
only after its change is applied **and** the project builds clean. An item that is
applied but not yet build-verified is marked `[ ]` with status `applied — pending build`.

---

## A. Network & deployment blockers

- [x] **1. Commit real bootstrap seeds into the binary**
  - `src/common/network.cpp`: `.default_seeds = {"85.217.171.168:19440", "64.23.244.126:19440"}`
  - Status: **applied — builds clean (2026-10-04)**; tests not run
  - Follow-ups:
    - Reconcile `mainnet/SEEDS.md` (still lists `212.58.103.170`, `seed1.gotdns.ch`) with `SEEDS.json`.
    - Move to DNS seeds operated by ≥2 independent organizations before public launch.
    - Default seeds are used whenever `--seeds` is empty (even with `--no-dns-seeds`), so
      in-process tests and the `docker-compose.yml` devnet will now also dial these hosts
      unless they pass `--seeds`/`--disable-p2p`.

- [ ] **2. Make the Docker image boot**
  - `Dockerfile` CMD: added `--allow-unsafe-genesis-override` (required by `parse_args` when `--genesis` is set).
  - Status: **applied — pending build verification**
  - Follow-ups:
    - Alternative: drop `--genesis` entirely; the embedded genesis has the same hash
      (`eaae655a…b78a`) and avoids the "unsafe" flag.
    - Runtime image does not contain `finalis-lightserver`, yet CMD passes `--with-lightserver`.

## B. Consensus parameter correctness

- [x] **3. Decide activation heights and bond figures**
  - 3a. Activation heights — Status: **applied — builds clean (2026-10-04)**; tests not run
    - `src/common/network.cpp`: `deferred_exit`, `bootstrap_penalty_exit_protection`,
      `empty_active_set_epoch_escape` changed from `10017 / 10145 / 10145` to `0`.
    - All three predicates use `height >= activation`, so `0` means active from genesis. The
      deferred-exit startup migration hook (`maybe_reactivate_single_exiting_validator_for_startup_migration`)
      becomes a no-op, which is intended for a fresh chain.
    - ⚠ **Consensus rule change without a genesis change.** `genesis.bin` and its hash are unchanged,
      so nodes with the old heights still pass the handshake with nodes that have the new ones,
      but the two can diverge before height 10145. Any network already running on this genesis
      (the seed hosts, `snapshot.bin`) must be wiped and restarted with the new binary, or genesis regenerated.
  - 3b. Bond figures — Status: **applied — builds clean (2026-10-04)**; tests not run
    - Finding: the "min exceeds max → lock-up" risk from the audit **cannot occur**.
      - Every max-bond consumer already clamps upward: `max(validator_bond_max_amount, min_bond)`
        (`canonical_derivation.cpp:1468`, `node.cpp` `effective_validator_bond_max_for_height`,
        `lightserver/server.cpp:2586,3068`).
      - The adaptive min (`validator_min_bond_units`) = `clamp(1000 FLS × sqrt(16 / active), 1000, ceiling)`,
        so it peaks at 4,000 FLS. The old 10,000 FLS ceiling was unreachable.
    - Change (`src/common/network.cpp`) — no change to current consensus outcomes:
      - `min_bond_ceiling` set from 10,000 FLS to `validator_bond_max_amount` (5,000 FLS).
      - Named constants plus `static_assert`s added: floor ≤ ceiling, ceiling ≤ bond max, and the
        adaptive peak ≤ ceiling. The build now fails if the economics are retuned into an inconsistent state.
    - Not changed: `BOND_AMOUNT` (50 FLS). It is the exact required `SCVALREG` output value
      (`utxo/validate.cpp:142`), the "no override" sentinel in `canonical_derivation.cpp:403`, and the
      bond used for legacy DB records. The effective minimum is already `max(50, adaptive ≥ 1,000)`.
      Retiring it is a separate consensus change.

- [x] **4. Lock consensus params against CLI override on mainnet**
  - Status: **applied — builds clean (2026-10-04)**; tests not run
  - `src/node/node.cpp` `parse_args`: when `cfg.network.name == "mainnet"`, these flags are rejected
    with an error message and `parse_args` returns `nullopt`. That is the existing error path:
    `main` prints usage and exits 1. Throwing was avoided because `main` has no try/catch.
    - `--max-committee`, `--validator-min-bond`, `--validator-warmup-blocks`, `--validator-cooldown-blocks`,
      `--validator-join-limit-window-blocks`, `--validator-join-limit-max-new`, `--liveness-window-blocks`,
      `--miss-rate-suspend-threshold-percent`, `--miss-rate-exit-threshold-percent`,
      `--suspend-duration-blocks`, `--deferred-exit-activation-height`, `--deferred-exit-activation-epoch-start`
  - Not locked: `--round-timeout-ms`, `--min-block-interval-ms`. These only set local
    proposer/round pacing and don't affect block validity.
  - Follow-ups:
    - `scripts/start.sh:821-838` auto-injects `--deferred-exit-activation-height` when
      `SYNC_TURBO_MODE=extreme` and `AUTO_DEFERRED_EXIT_ACTIVATION_EXTREME=1`; nodes launched that way
      now fail to start. Remove that block.
    - `finalis-lightserver` has its own `--max-committee` flag; review whether it needs the same lock.
    - Override paths in `Node::init` (lines ~3122-3143) stay for tests that set `NodeConfig` directly.

## C. Node boot robustness

- [ ] **5. Harden `parse_args`**
  - Status: **partially applied — applied part builds clean (2026-10-04)**
  - Done (`src/node/node.cpp`):
    - The body moved to `parse_args_unchecked`. The public `parse_args` catches `std::invalid_argument` /
      `std::out_of_range`, prints `error: invalid numeric value for <flag>`, and returns `nullopt`.
      `main` then prints usage and exits 1 instead of hitting `std::terminate`.
    - `--port` / `--lightserver-port` use `parse_port_arg`, which rejects trailing characters and
      values outside `[1, 65535]`. `--port abc`, `--port 70000` and `--port 80x` are all rejected.
  - Remaining:
    - Other `static_cast<uint32_t>(std::stoul(...))` flags still truncate values above 2^32 silently
      (timeouts, hashcash bits, and similar).
    - Install SIGINT/SIGTERM handlers before `init()` (`apps/finalis-node/main.cpp`).
    - The same pattern exists in `finalis-lightserver`, `finalis-explorer` and `finalis-cli` argument parsing.

## D. State bootstrap safety

- [ ] **6. Snapshot import safety**
  - `scripts/start.sh`: default `AUTO_FAST_SYNC=0`.
  - `import_snapshot_bundle`: verify manifest genesis hash against the embedded `MAINNET_GENESIS_HASH`.
  - Remove the tracked `snapshot.bin` from the repo.

## E. Public interface

- [ ] **7. Fix dead SDK methods**
  - Status: **applied — pending SDK typecheck / vitest run**
  - Removed from `LightServerClient.ts`: `getHeaders`, `getHeaderRange`, `getBlock`. They called
    `get_headers` / `get_header_range` / `get_block`, which the lightserver does not implement.
    The `HeaderEntry` type was removed, along with the duplicate `FinalitySig` in `src/types/index.ts`
    (the canonical one is in `src/proofs/finality.ts`; both were re-exported via `export *`).
  - All 9 RPC methods the SDK still calls exist in `src/lightserver/server.cpp`:
    `get_status`, `get_tip`, `get_tx`, `get_utxos`, `get_committee`, `get_roots`,
    `get_utxo_proof`, `get_validator_proof`, `broadcast_tx`.
  - `FinalisWallet.getBalanceTrustless` depended on `getHeaderRange`, so it was broken at runtime.
    It now **fails closed** with `TRUSTLESS_NOT_SUPPORTED`. It could not simply be pointed at a renamed method:
    - The SDK's `verifyFinalityProof` checks Ed25519 signatures over a raw 32-byte block hash.
      Validators sign `vote_signing_message(height, round, transition_id)` (`src/utxo/validate.hpp:79`).
    - `get_finality_certificate` returns no `utxo_root`, and `get_roots` is not bound to the signed transition.
  - `test/lightserver-e2e-tamper.test.ts` was rewritten to assert the fail-closed behavior. SMT and finality
    tamper cases remain covered by `smt-proof.test.ts` and `finality-proof.test.ts`. README method list updated.
  - **Breaking public API change** (SDK `1.0.0`): bump the version or note it in the changelog.
  - Follow-ups to restore trustless balance:
    1. Lightserver: expose a finality-bound `utxo_root`, either in `get_finality_certificate` or via a proof
       that `utxo_root` is committed in the transition.
    2. SDK: port `vote_signing_message` and verify the certificate against it; add test vectors generated from C++.
    3. Publish a lightserver JSON-RPC spec. `openapi/finalis-partner-v1.yaml` covers only explorer REST.
       `/api/v1/audit/auth` is implemented in the explorer but undocumented.

## F. Phase 3: Autonomous Liveness & Safety Hardenings (from the 2026-10-04 liveness/safety audit)

Resolved and built clean: **D5** (item 8), **D1** (item 9), **D3** (item 10). No tests run.

- [x] **8. D5 — Persist the vote lock durably before the vote leaves the process**
  - Status: **applied — builds clean (2026-10-04)**; tests not run
  - Problem: the propose path signed and broadcast a vote, and only then updated and persisted the
    lock (inside `handle_vote`), with a non-fsync'd write. A crash in between lost the lock, and on
    restart the node could sign a conflicting payload at the same `(height, round)`.
  - Change:
    - `storage::DB::write_batch_durable()` writes with `rocksdb::WriteOptions::sync = true`.
    - `Node::persist_consensus_safety_state_locked(height)` uses it and returns `bool`.
    - `handle_propose_result` calls `update_local_vote_lock_locked()` after signing and **before**
      the vote is broadcast; if the write fails, the node does not vote. Re-applying an identical
      lock is a no-op, so there is no second fsync.
  - Not covered: the quorum-1 self-vote in `finalize_if_quorum`, which finalizes in the same step.

- [x] **9. D1 — Participation-based liveness and rewards from a verified signer record**
  - Status: **applied — builds clean (2026-10-04)**; tests not run. ⚠ **Consensus format change:
    requires a fresh genesis**; existing frontier history no longer parses or replays.
  - Problem: every frontier transition was built with an empty `observed_signers`, and liveness /
    reward accounting read that list. Every committee member scored a 100% miss rate, so at the
    first 10,000-block window rollover all validators but one were exited. It is masked today
    only because genesis has a single validator protected by the active-set floor. The earlier
    design truncated the list to the quorum lowest pubkeys, which biased eviction by pubkey.
  - Change:
    - `FrontierTransition::observed_signers` (pubkeys) was replaced by `prev_finality_signers`
      (`FinalitySig` = pubkey + signature). Transition `H+1` records the votes observed for its
      finalized parent `H`: `(H, round_H, transition_id_H)`. It is part of the serialization,
      `transition_id()`, and `frontier_finality_link_hash`. The count is capped at `MAX_COMMITTEE` on parse.
    - Verification (`canonicalize_and_verify_prev_finality_signers`, run from both
      `populate_frontier_transition_metadata` variants and therefore from every
      `verify_frontier_record_against_state`): the list must be canonical (sorted, unique), empty iff the
      parent is genesis, every signer a member of the parent committee (canonical, or legacy if all
      signers belong to it), every signature valid, and at least the parent quorum.
    - Accounting (`apply_frontier_record_impl`): liveness and reward participation for `H` are scored
      against the parent committee using the verified signer set. Emission, fees and the leader score
      stay with `H+1`. `finalized_block_metadata[H].signature_count` is completed when `H+1` applies;
      a new tip starts at its quorum (which matches what fast-start restores from the certificate).
    - Node: `finalized_tip_votes_` keeps every verified vote for the finalized tip, and late votes
      for the tip are still recorded (`record_late_finalized_vote_locked`).
      `prev_finality_signers_for_next_height_locked()` merges these with the persisted certificate,
      filters them against the canonical parent committee, and verifies each signature, so a proposal
      always passes verification. It is used by the proposal builder and by lock re-proposal (the lock
      payload id excludes the signer list, so locks are unaffected).
  - Cleanup:
    - The D1 stopgap was removed.
    - `consensus::accrue_frontier_epoch_reward` is now the single reward-accrual function, shared by
      canonical derivation and `Node::rebuild_frozen_epoch_reward_state_from_finalized_chain_locked`.
      That rebuild previously re-derived rewards from quorum-truncated certificates and overrode
      canonical state.
    - Deleted dead duplicates: node `update_validator_liveness_from_finality{,_impl}`,
      `accrue_epoch_reward_for_finalized_block_locked`, `accrue_epoch_reward_state_for_block`, the node
      copy of `compute_deterministic_epoch_reward_inputs` / `deterministic_epoch_reward_inputs_equal`;
      canonical `accrue_epoch_reward_state_for_block`, `accrue_epoch_reward_state_for_frontier`,
      `update_validator_liveness_from_finality`, `canonicalize_signer_pubkeys`.
  - Known limits and follow-ups:
    - A Byzantine proposer can still *omit* honest signers beyond quorum (it cannot forge any). The
      impact is bounded by its share of proposals; a later fix could require the leader's own set to be
      a superset of the certificate.
    - Participation of epoch-end height `H` is booked into the epoch of `H+1` (deterministic, but
      shifted by one block).
    - Pre-existing drift found, not fixed: fast-start restores `finalized_block_metadata` for the tip
      only, while replay holds every height. `ticket_difficulty_bits_for_epoch` reads that map, so
      fast-start and replay nodes can derive different checkpoints.
    - Pre-existing: the frozen-epoch rebuild scores bond weights with the *current* `validators_`
      registry, not the registry at each height.
    - GCC 13 reports a `-Wstringop-overflow` false positive in `canonical_derivation.cpp`: an existing
      vector copy (`legacy_checkpoint_committee_for_round`) is now inlined into
      `resolve_parent_finality_context`.
    - Tests updated to compile (`test_frontier_replay` signs the parent with the single test committee
      key). New coverage is still needed: invalid, forged, non-member, below-quorum and unsorted
      signers; late-vote capture; a 16-validator, 10,000-block no-eviction run.
    - Docs updated: `docs/CONSENSUS.md` (finality certificate vs. participation record) and
      `docs/REWARD-SETTLEMENT.md` (participation source = `prev_finality_signers`).

- [x] **10. D3 — Sliding timeout-vote window and exponential round-timeout backoff**
  - Status: **applied — builds clean (2026-10-04)**; tests not run. Local pacing only: no consensus
    or genesis change, and old and new nodes can run together.
  - Problem: `TimeoutVoteTracker` refused new rounds once a height held 256 round slots, and slots were
    cleared only on finalization. With a fixed 30 s timeout and no backoff, about 2 h without finality
    stopped round advancement until restart. A fixed timeout also never outgrows a sustained delay.
  - Change:
    - `src/consensus/votes.{hpp,cpp}`: at the per-height cap, a vote for a new round evicts that height's
      oldest round (O(log n) `lower_bound` on the contiguous `(height, round)` keys) instead of being
      rejected. A vote older than every retained round returns `stale` and is soft-rejected (no peer
      penalty; it was a hard reject). `evicted_round` is reported and logged (`timeout-window-evict`).
      The current round cannot be evicted, because the node only admits rounds ≤ current + 32
      (`kProposalRoundWindow`). Formed TCs live separately in `highest_tc_by_height_`.
    - `src/common/network.{hpp,cpp}`: `round_timeout_ms_for_round(network, round)` =
      `min(base × (3/2)^round, max_round_timeout_ms)`, integer and saturating, growing ≥1 ms per step.
      New fields `max_round_timeout_ms` (mainnet 300 000), `round_timeout_backoff_num/den` (3/2;
      `num <= den` disables). Mainnet sequence: 30, 45, 67.5, 101, 152, 228, then 300 s.
    - `src/node/node.cpp`: only the round timer (`round_timeout_elapsed`, liveness-debug
      `timeout_elapsed`) uses the per-round value. Stall detection, freshness floors and request
      intervals keep the base value. Liveness log shows `round_timeout_ms`. New local flag
      `--max-round-timeout-ms` (not consensus-locked, like `--round-timeout-ms`).
    - `src/common/types.hpp`: removed the dead `ROUND_TIMEOUT_MS = 5000` constant.
    - Tests added (`test_validator_lifecycle.cpp`): window eviction, stale soft-reject, per-height
      isolation, backoff values / cap / tiny-base growth / disable.
  - Follow-ups:
    - Integration tests set `round_timeout_ms = 200`, so backoff now applies. Multi-round tests may slow
      (round 10 ≈ 11.5 s). If needed, set `round_timeout_backoff_num = round_timeout_backoff_den` in those configs.
    - D4: a peer-loss reset or restart drops to round 0 and restarts the backoff from base.

- [ ] **11. Remaining audit items** — D2 (stall-time inactivity escape), D4 (round persistence and
  TC-based round jumps), D6 (≥4 genesis validators), D7 (post-cap security budget), state growth
  (`CanonicalDerivedState` pruning and per-block copy).

## G. Phase 4: Strict Monetary & Economic Safety (from the 2026-10-04 monetary audit)

Audit summary: consensus economics uses no floating point. Emission sums to exactly
`TOTAL_SUPPLY_UNITS` (12 yearly budgets with exact 4/5 decay; the last year takes the remainder).
Reserve accrual is conserved per epoch. No rounding path can mint above the cap. Two paths
**destroy** supply (items 12 and 14), and one path lets node-local state override canonical
settlement (item 13).

- [x] **12. Post-cap reserve subsidy: units paid must equal units debited**
  - Status: **applied — builds clean (2026-10-04)**; tests not run. Consensus change (effective from
    height 2,102,400); ships with the D1 fresh genesis.
  - Problem: `derive_frontier_settlement_from_state` (`canonical_derivation.cpp:319`) reads the
    settlement epoch's `reserve_subsidy_units` from the pre-block state, where it is still 0. The
    subsidy is computed later, in `mark_epoch_reward_settled_for_height` (`:612-637`), which runs on
    the post-block state during apply and debits the reserve. So the subsidy is never paid, and the
    reserve is destroyed down to the 140,000 FLS floor after the cap.
  - Fix: one pure helper, `epoch_reserve_subsidy_units(cfg, height, reward_state, reserve_before_accrual)`,
    used by both the payout (pre-block state) and the debit (`next` before any other mutation, so the
    inputs are identical). `apply_frontier_record_impl` additionally rejects a transition whose
    `settlement.reserve_subsidy_units` differs from the debited amount (`frontier-reserve-subsidy-mismatch`).
  - Cleanup: deleted the dead node mirror (`node.cpp` `mark_epoch_reward_settled_for_height` +
    `Node::mark_epoch_reward_settled_if_needed_locked`, which had no callers).

- [x] **13. Remove node-local settlement fallback / hotfix acceptance**
  - Status: **applied — builds clean (2026-10-04)**; tests not run. Node-only; no format change.
  - Problem: on `frontier-settlement-commitment-mismatch`, the node retried verification with
    node-local reward states (persisted, runtime, ticket-patched) and **overwrote canonical state** with
    whichever matched. One variant (`apply_and_retry`) wrote canonical state and the DB even when the
    retry failed. It also accepted hard-coded commitments at heights 7009/7041 from the abandoned chain,
    and validated settlement-boundary blocks against a `rebuild_frozen_epoch_reward_state_*` substitute
    instead of canonical state.
  - Fix: delete `should_accept_frozen_settlement_hotfix`, both fallback blocks, the three hotfix
    branches, the frozen-epoch `validation_state` substitutions, and the post-apply canonical overwrite.
    `rebuild_frozen_epoch_reward_state_from_finalized_chain_locked` then has no callers and is deleted.
    Any settlement that fails canonical verification is rejected.
  - Done: all five bypass layers were removed (certified-sync `try_reward_state` fallback, uncertified-path
    `apply_and_retry`, 7009/7041 hotfix at 3 call sites including its committee-check skip, two
    frozen-epoch `validation_state` substitutions, post-apply canonical overwrite in
    `ensure_settlement_onboarding_scores_loaded_locked`). Also deleted `should_accept_frozen_settlement_hotfix`,
    `hash32_from_hex_or_zero`, and the rebuild function.
  - Left in place (not consensus-affecting): `ensure_settlement_onboarding_scores_loaded_locked` still writes
    node-local ticket onboarding scores into canonical reward state. That field is neither in the state
    commitment nor read by the canonical payout, which uses checkpoint members.
  - Watch: if fast-start nodes reject settlement blocks after this change, the cause is the tip-only
    `finalized_block_metadata` reload (item 9 follow-up), which the removed rebuild used to mask.
  - Tests that relied on the fallback will now fail. Fix them by making their settlement canonical;
    do not restore the bypass.

- [ ] **14. Pre-cap transaction fees must not be burned**
  - Status: **open — design decision needed.**
  - Problem: before `EMISSION_BLOCKS`, fees are removed from transaction inputs but never paid
    (`canonical_derivation.cpp:318`, `:348-350`, `:979`). That burns 12 years of fees, leaves validators
    with no fee income, and contradicts `docs/ECONOMICS.md` §4.
  - Requested direction: pay fees to the proposer immediately.
  - ⚠ Conflict: settlement outputs are part of `settlement_commitment`, which is part of
    `consensus_payload_id` (the vote-lock identity). Paying the *current round leader* per block would
    change the payload whenever a different leader re-proposes a locked payload. That breaks lock
    re-proposal, which is the reason fees were kept out of per-block settlement.
  - Recommended alternative: pool fees into the epoch `fee_pool_units` from genesis (drop the
    `height >= EMISSION_BLOCKS` gates) and pay them at epoch settlement by reward score, the same as
    post-cap. The proposer is still credited through its leader score. The payload stays
    leader-independent and nothing is burned.

---

## Status summary

| # | Item | Status |
|---|---|---|
| 1 | Bootstrap seeds | done — builds clean |
| 2 | Docker CMD | applied — pending build |
| 3a | Activation heights → 0 | done — builds clean (requires wiping any chain already on this genesis) |
| 3b | Bond ceiling invariant | done — builds clean |
| 4 | Mainnet consensus-flag lock | done — builds clean (`start.sh:821-838` must be removed) |
| 5 | `parse_args` hardening | partial — applied part builds clean (u32 truncation, signal ordering, other apps) |
| 6 | Snapshot import safety | **open** |
| 7 | SDK dead methods | applied — pending SDK typecheck/tests |
| 8 | D5 durable vote lock | done — builds clean |
| 9 | D1 verified participation record | done — builds clean (**fresh genesis required**) |
| 10 | D3 timeout window + backoff | done — builds clean |
| 11 | D2, D4, D6, D7, state growth | **open** |
| 12 | Post-cap subsidy paid = debited | done — builds clean (consensus; fresh genesis) |
| 13 | Remove settlement fallback / hotfix | done — builds clean |
| 14 | Pre-cap fees not burned | **open — design decision** (epoch pooling recommended) |

2026-10-04: the full tree (`cmake --build build -j`, including the test binaries) builds clean. That
verifies the C++ items 1, 3, 4, 8, 9, 10, 12 and 13. Item 2 needs a `docker build`, item 7 an SDK typecheck. No tests
have been run: in the audit sandbox, every multi-node test fails at node init (listener `errno=2`),
and the original code fails the same way.
Verify with `cmake --build build -j`, `ctest --test-dir build --output-on-failure`, and
`npm test` / `npx tsc --noEmit` in `sdk/finalis-wallet-js`.
