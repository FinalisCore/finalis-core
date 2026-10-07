# `src/node/node.cpp` Decomposition Plan

Status: **proposal** — no source has been split yet.
Line numbers refer to `src/node/node.cpp` at commit `80250d5`; they will drift as code changes.

---

## 1. Executive summary

`src/node/node.cpp` implements the `finalis::node::Node` class: the runtime that ties consensus,
P2P networking, transaction ingress, validator/committee management and finalized-state storage
together. It has grown to a size that makes it hard to read, review and safely change:

| Metric | Value |
|---|---|
| Lines | **12,289** |
| Definitions | **373** (147 anonymous-namespace free functions, 223 `Node::` members, 3 CLI-parsing statics) |
| Named lambdas | 24 |
| Largest function | `Node::handle_message` — **1,112 lines** |
| Unreachable (dead) code | **34 functions, ~714 lines** |

The core problem is not only size but **interleaving**: functions from every logical area are
scattered across the whole file. For example, consensus functions appear anywhere from line 286 to
line 11790, and validator/committee code from line 90 to line 10411. A contributor looking for
"how votes are handled" has no structural cue where to look.

This document proposes splitting `node.cpp` into area-specific translation units of the **same
`Node` class**. C++ allows member functions of one class to be defined across many `.cpp` files,
so the split requires **no public API change** and **no change to `Node`'s private access model**.

---

## 2. Current state

### 2.1 Glossary (for newcomers)

| Term | Meaning |
|---|---|
| **Frontier / transition** | The unit of finalization. A `FrontierTransition` advances the finalized height by one; a `FrontierProposal` wraps it for voting. |
| **QC / TC** | Quorum Certificate (enough votes for a proposal) / Timeout Certificate (enough timeout votes to move to the next round). |
| **Finality certificate** | The set of committee signatures that finalizes a transition. |
| **Ingress lane** | Transactions are certified into numbered lanes by designated certifiers; proposals are built from **certified ingress records**, not directly from the mempool. |
| **Epoch ticket** | A small proof-of-work each validator mines per epoch; the best tickets determine the epoch committee. |
| **Checkpoint** | A persisted `FinalizedCommitteeCheckpoint` describing the committee/proposer schedule for an epoch. |
| **Canonical derived state** | The state (UTXOs, validators, rewards, …) re-derived from finalized frontier storage at startup. |
| **`_locked` suffix** | The function **must be called with `Node::mu_` held**. Functions without the suffix either lock `mu_` themselves or don't touch guarded state. |

### Note A: Local bus topology constraint

The local bus (`g_local_bus_mu` / `g_local_bus_nodes`) is **not** a replacement for real P2P when running multi-validator consensus. A node may only propose a block if `p2p_.get_peer_info(...).established()` returns a sufficient peer count. With `disable_p2p = true` this count is always zero, so a validator on the local bus believes it has no peers and never proposes.

**Consequence:** a local-bus cluster with more than one validator can never finalize blocks. The local bus is only suitable for:

- Single-validator + follower nodes (validator proposes, followers receive via broadcast)
- Tests that exercise broadcast/forward paths without consensus finalization
- Single-node initialization and configuration tests

**For multi-validator consensus tests, use real P2P** (`disable_p2p = false`) with `make_cluster` or equivalent fixtures. This is why `test_local_bus_multi_node_delivers_frontiers_and_forwards_tx_to_designated_certifier` uses one validator and two followers, not three validators.

### 2.2 Area breakdown

Every definition was assigned to one logical area. "LOC" is the sum of function body lengths
(blank lines and constants between functions are excluded). "Span" shows how interleaved the area is.

| Area | What it covers | Definitions | LOC | Span (first → last line) |
|---|---|---:|---:|---|
| **consensus** | proposals, votes, timeout votes, QC/TC, vote locks, finalization, sync buffering, finalized-state persistence | 79 | 2,611 | 286 → 11790 |
| **network** | handshake, broadcasts, peer scoring/rate limits, dialing, addrman, forward sync requests, STUN / NAT-PMP / UPnP | 87 | 2,136 | 142 → 11858 |
| **validator_ops** | bootstrap template, epoch tickets, epoch committees, checkpoints, availability, rewards/settlement, bond rules | 91 | 1,802 | 90 → 10411 |
| **core** | lifecycle, lightserver child process, logging, clock, CLI parsing, small utilities | 42 | 1,109 | 94 → 12287 |
| **mempool / ingress** | tx admission, ingress lane certification and sync | 11 | 508 | 260 → 10996 |
| **cross** | functions that orchestrate several areas (see below) | 8 | **3,231** | 2636 → 10182 |
| **test hooks** | public `*_for_test` methods | 55 | 404 | 2625 → 4974 |

The eight **cross** functions hold more than a quarter of the file:

| Function | Line | LOC | What it does |
|---|---:|---:|---|
| `handle_message` | 6617 | 1,112 | P2P dispatch for every message type |
| `event_loop` | 5332 | 585 | Main tick: housekeeping, epoch tickets, round timer, proposals, timeouts, sync polling, NAT refresh, dialing |
| `load_state` | 9735 | 448 | Startup state derivation: fast-start cache, frontier replay + tail repair, cache verification |
| `init` | 2636 | 423 | Startup: config overrides, keys, genesis, `load_state`, committee checks, P2P callbacks, listener |
| `build_runtime_status_snapshot_locked` | 3749 | 213 | Persisted runtime status snapshot |
| `apply_finalized_frontier_effects_locked` | 4572 | 166 | Applies a finalized frontier: state, mempool, availability, broadcasts |
| `build_frontier_transition_locked` | 8955 | 158 | Builds the next proposal from certified ingress records |
| `status` | 3622 | 126 | Builds the public `NodeStatus` |

### 2.3 Inside `handle_message`

`handle_message` is a dispatcher whose cases contain real domain logic. Each case takes `mu_`
itself (47 separate lock scopes), so cases can be extracted without changing locking.

| Section | Lines | LOC | Owning area |
|---|---|---:|---|
| Pre-dispatch: dedup, rate limit, TRANSITION certificate pre-check | 6617–6665 | ~50 | network / consensus |
| `VERSION` | 6666–6827 | 162 | network |
| `VERACK` | 6828–6874 | 47 | network |
| `GET_FINALIZED_TIP`, `FINALIZED_TIP` | 6888–6929 | 42 | network |
| `GET_INGRESS_TIPS`, `INGRESS_TIPS`, `GET_INGRESS_RANGE`, `INGRESS_RANGE`, `INGRESS_RECORD` | 6930–7061 | 132 | ingress |
| `GET_TRANSITION` | 7062–7094 | 33 | consensus (sync) |
| `GET_TRANSITION_BY_HEIGHT` | 7095–7237 | 143 | consensus (sync) |
| `EPOCH_TICKET`, `GET_EPOCH_TICKETS`, `EPOCH_TICKETS` | 7238–7374 | 137 | validator_ops |
| `TRANSITION` | 7375–7498 | 124 | consensus |
| `PROPOSE`, `VOTE`, `TIMEOUT_VOTE` | 7499–7606 | 108 | consensus |
| `TX` | 7607–7635 | 29 | ingress |
| `GETADDR`, `ADDR`, `PING`, `PONG` | 7636–7724 | 89 | network |

---

## 3. Dead code inventory

These 34 functions are **unreachable**: no path leads to them from any public method, P2P
callback, thread entry point or test hook. References were checked across `src/`, `apps/` and
`tests/`. Together they are ~714 lines. All private `Node::` members in this list also have a
declaration in `src/node/node.hpp` that should be removed with them.

**Reason codes**

- **Unreferenced** — the name appears only at its own definition.
- **Dead caller** — only referenced from another function in this list.
- **Superseded** — a live implementation exists elsewhere.

| # | Lines | Function | Kind | Reason |
|---:|---|---|---|---|
| 1 | 1232–1235 | `same_epoch_ticket` | anon | Dead caller (`same_epoch_best_map`) |
| 2 | 1237–1245 | `same_epoch_best_map` | anon | Unreferenced |
| 3 | 1370–1373 | `debug_checkpoint_logs_enabled` | anon | Unreferenced |
| 4 | 1401–1406 | `serialize_finalized_write_marker` | anon | Dead caller (`begin_finalized_write`) — see note A |
| 5 | 1564–1571 | `infer_exit_reason` | anon | Dead caller (`emit_exit_transition_logs`) |
| 6 | 1573–1592 | `emit_exit_transition_logs` | anon | Dead caller (`Node::apply_validator_state_changes`) |
| 7 | 1670–1672 | `same_tx_out` | anon | Unreferenced |
| 8 | 1744–1757 | `same_finalized_checkpoint_schedule_material` | anon | Unreferenced |
| 9 | 1789–1919 | `apply_validator_state_changes_impl` | anon | Dead caller + **Superseded** by `apply_validator_state_changes` in `src/consensus/canonical_derivation.cpp:851` |
| 10 | 1934–1953 | `compute_roots_for_state` | anon | Unreferenced |
| 11 | 2209–2278 | `rollback_frontier_tail_to_tip` | anon | Unreferenced (startup uses `rollback_frontier_tail_from_transition`) |
| 12 | 2280–2320 | `load_latest_trusted_runtime_checkpoint_from_cache` | anon | Unreferenced (startup uses `load_trusted_runtime_checkpoint_from_cache`) |
| 13 | 2333–2338 | `make_coinbase_script_sig` | anon | Unreferenced |
| 14 | 2340–2343 | `block_proposal_signing_message` | anon | Dead caller (`verify_block_proposer_locked`) |
| 15 | 2485–2494 | `proposer_equivocation_record_id` | anon | Unreferenced |
| 16 | 2530–2543 | `make_onchain_slash_record` | anon | Dead caller (`apply_validator_state_changes_impl`; also forward-declared at line 1375) |
| 17 | 3235–3242 | `Node::pending_join_request_for_validator_locked` | member | Unreferenced |
| 18 | 3252–3262 | `Node::bootstrap_joiner_ready_locked` | member | Unreferenced |
| 19 | 4345–4351 | `Node::epoch_reward_state_for_epoch_locked` | member | Dead caller (`coinbase_payout_for_height_locked`) |
| 20 | 4353–4399 | `Node::coinbase_payout_for_height_locked` | member | Dead caller (`coinbase_outputs_for_height_locked`) |
| 21 | 4490–4500 | `Node::coinbase_outputs_for_height_locked` | member | Unreferenced |
| 22 | 6055–6068 | `Node::update_availability_from_finalized_frontier_locked` | member | Unreferenced |
| 23 | 6331–6343 | `Node::required_epoch_committee_state_reason_locked` | member | Unreferenced |
| 24 | 8512–8517 | `Node::verify_block_proposer_locked` | member | Unreferenced |
| 25 | 8519–8555 | `Node::validate_prev_finality_cert_hash_locked` | member | Unreferenced |
| 26 | 9470–9475 | `Node::begin_finalized_write` | member | Unreferenced — see note A |
| 27 | 9477–9487 | `Node::finish_finalized_write` | member | Unreferenced — see note A |
| 28 | 10184–10186 | `Node::committee_for_height` | member | Unreferenced (the lightserver has its own, unrelated `committee_for_height`) |
| 29 | 10188–10243 | `Node::reward_participants_for_height_round` | member | Unreferenced |
| 30 | 10337–10381 | `Node::validate_validator_registration_rules` | member | Unreferenced |
| 31 | 10383–10411 | `Node::apply_validator_state_changes` | member | Unreferenced; **Superseded** by `canonical_derivation.cpp:851` |
| 32 | 10448–10480 | `Node::append_mining_log` | member | Unreferenced |
| 33 | 10750–10758 | `Node::broadcast_finalized_tip` | member | Unreferenced |
| 34 | 11666–11669 | `Node::peer_ip_for` | member | Unreferenced (`peer_ip_for_locked` is live) |

> **Note A — finalized-write marker.** `check_no_incomplete_finalized_write()` (line 9489) is
> still called on startup and reads the marker, but nothing ever **writes** it, because
> `begin_finalized_write` / `finish_finalized_write` are never called. The crash-safety check is
> therefore inert today. Before deleting these functions, a maintainer should decide whether the
> marker was intentionally retired (then remove the check too) or accidentally disconnected (then
> wire it back in). Do not silently delete without that decision.

After deletion, also check for member variables used only by dead code (e.g. `mining_log_path_`).
The compiler will not flag unused private members.

---

## 4. Proposed file split

All files below live in `src/node/` and define members of the same `Node` class (except
`node_internal.*`, which holds free functions). LOC figures are approximate and exclude dead code.

```
src/node/
├── node.hpp                    # class Node (unchanged public API; private section regrouped by area)
├── node_internal.hpp           # NEW: shared free helpers + constants (namespace finalis::node::detail)
├── node_internal.cpp           # NEW: bodies of non-trivial shared helpers
├── node.cpp                    # lifecycle, event loop, status, lightserver, logging   (~2,300)
├── node_consensus.cpp          # BFT voting, certificates, finalization, proposals      (~2,100)
├── node_ingress.cpp            # tx admission + ingress lanes                           (~660)
├── node_network.cpp            # P2P dispatch, peers, broadcasts, sync requests, NAT    (~2,650)
├── node_validator_ops.cpp      # bootstrap, epoch tickets, committees, availability     (~1,800)
├── node_state.cpp              # startup derivation, persistence, genesis               (~1,470)
├── node_test_hooks.cpp         # public *_for_test methods                              (~400)
└── node_args.cpp               # CLI parsing (parse_args)                               (~420)
```

> Why not `node_mempool_integration.cpp`? Only 6 functions touch `mempool_` directly, and
> proposals are built from **certified ingress records**, not from the mempool. `node_ingress.cpp`
> names what the code actually does.

### 4.1 `node.cpp` — lifecycle and orchestration (~2,300 LOC)

| Functions | Current lines |
|---|---|
| `Node::Node`, `~Node` | 2602–2623 |
| `init` (after extracting the peer-event callback, see §6) | 2636–3058 |
| `start`, `stop` | 3272–3339 |
| Lightserver child: `start_/stop_/reap_lightserver_child`, `preflight_lightserver_bind`, `lightserver_mode_name`, `lightserver_binary_path`, `lightserver_is_public` | 3341–3620 |
| `status`, `build_runtime_status_snapshot_locked` | 3622–3961 |
| `event_loop` (split into tick phases, see §6) | 5332–5916 |
| `now_unix`, `now_ms`, `log_line`, `spawn_local_bus_task`, `join_local_bus_tasks` | 10413–10501 |
| Anon helpers used only here: `restart_debug_enabled`, `is_dangerous_db_root_path`, `launch_mode_name`, `runtime_logs_enabled`, … | various |

### 4.2 `node_consensus.cpp` — BFT logic (~2,100 LOC)

| Group | Functions | Current lines |
|---|---|---|
| Message handling | `handle_propose(_result)`, `handle_vote(_result)`, `handle_timeout_vote(_result)` | 7730–8234 |
| Frontier acceptance + sync buffer | `handle_frontier_block_locked`, `maybe_buffer_sync_frontier_locked`, `insert_buffered_sync_frontier_locked`, `maybe_apply_buffered_sync_frontiers_locked` | 8236–8510 |
| Validation / equivocation | `validate_frontier_proposal_locked`, `check_and_record_proposer_equivocation_locked` | 8557–8647 |
| Finalization | `finalize_if_quorum`, `apply_finalized_frontier_effects_locked`, `canonicalize_finality_signatures_locked` | 8834–8953, 4572–4737, 4502–4515 |
| Proposal building | `build_frontier_transition_locked` | 8955–9112 |
| Certificates | `verify_quorum/timeout_certificate_locked`, `verify_finality_certificate_for_frontier_locked`, `precheck_finality_certificate`, `quorum_certificate_payload_id_locked`, `highest_qc/tc_for_height_locked`, `maybe_record_quorum/timeout_certificate_locked` | 4976–5172 |
| Vote locks / safety state | `can_vote_for_frontier_locked`, `can_accept_frontier_with_lock_locked`, `update_local_vote_lock_locked`, `prev_finality_signers_for_next_height_locked`, `record_late_finalized_vote_locked`, `persist/clear_consensus_safety_state_locked` | 5174–5330 |
| Round / repair | `consensus_state_locked`, `next_height_requires_repair_locked`, `maybe_repair_next_height_locked`, `arm_round0_deadline_locked`, `prune_caches_locked` | 3963–4106, 4562–4570, 11756–11790 |
| Extracted message cases | `on_transition`, `on_get_transition`, `on_get_transition_by_height`, `on_propose`, `on_vote`, `on_timeout_vote` | from 7062–7606 |
| Anon helpers | `justify_summary`, `signer_set_summary`, `make_finality_certificate`, `make_quorum_certificate`, `consensus_payload_id`, `key_consensus_safety_state`, `serialize/parse_consensus_safety_state`, `vote_equivocation_record_id`, `make_vote/proposer_equivocation_record`, `certificate_matches_checkpoint_committee`, `inspect_frontier_ordered_record_supported` | 1379–1399, 1921–1932, 2322–2528 |

### 4.3 `node_ingress.cpp` — transaction admission and ingress lanes (~660 LOC)

| Functions | Current lines |
|---|---|
| `handle_tx` | 8649–8721 |
| `handle_ingress_record_locked`, `maybe_certify_locally_accepted_tx_locked` | 8723–8832 |
| `maybe_forward_tx_to_designated_certifier_locked` | 9354–9397 |
| `ingress_committee_locked`, `local_ingress_lane_tips_locked` | 10685–10701 |
| `handle_ingress_tips_locked`, `handle_ingress_range_locked` | 10784–10996 |
| `effective_min_relay_fee_for_height` | 10330–10335 |
| Extracted message cases: `on_ingress_tips`, `on_get_ingress_range`, `on_ingress_range`, `on_ingress_record`, `on_tx` | from 6930–7061, 7607–7635 |
| Anon helpers: `load_certified_ingress_record_from_db`, `parse_lane_seq_from_error` | 260–284, 1026–1048 |

### 4.4 `node_network.cpp` — P2P (~2,650 LOC; ~2,060 if NAT helpers move out)

| Group | Functions | Current lines |
|---|---|---|
| Dispatch | `handle_message` (thin dispatcher: dedup, rate limit, flush guard, `switch`) + `on_version`, `on_verack`, `on_addr`, `on_getaddr`, `on_ping`, `on_pong`, `on_finalized_tip` | 6617–7728 |
| Peer events | `on_peer_event` (extracted from the `set_on_event` lambda in `init`) | 2878–3027 |
| Handshake | `send_version`, `maybe_send_verack`, `send_ping` | 5918–5958 |
| Broadcasts | `broadcast_propose/epoch_ticket/vote/timeout_vote/finalized_frontier/tx/ingress_record`, `flush_pending_finalized_broadcasts` | 9168–9352 |
| Requests | `request_epoch_tickets`, `request_ingress_tips`, `send_ingress_tips`, `request_finalized_tip`, `send_finalized_tip`, `maybe_request_getaddr` | various |
| Forward sync | `maybe_request_forward_sync_block_locked`, `maybe_request_candidate_transition_locked`, `peer_is_fresh_for_epoch_reconcile_locked` | 10760–10782, 10998–11212 |
| Peer persistence | `load/persist_peers`, `load/persist_addrman`, `load/persist_validators_addrman`, `resolve_dns_seeds_once` | 10503–10677 |
| Dialing / endpoints | `seed_preflight_ok`, `endpoint_matches_local_listener`, `try_connect_bootstrap_peers`, `advertised_endpoint_locked`, `current_advertised_endpoint`, `detect_possible_public_ip` | 11214–11423, 3571–3591 |
| NAT refresh | `maybe_refresh_nat_pmp/upnp_igd/stun_external_endpoint` | 11425–11636 |
| Peer state / discipline | `has_peer_endpoint`, `peer_count`, `established_peer_count`, `outbound_peer_count`, `peer_ip_for_locked`, `(is_)suppress(ed)_self_endpoint_locked`, `is_bootstrap_peer_ip`, `addrman_address_for_peer`, `score_peer(_locked)`, `should_mute_peer(_locked)`, `check_rate_limit_locked`, `check_sync_transition_rate_limit_locked` | 11638–11858 |
| Anon helpers | `msg_type_name`, `message_payload_id`, endpoint/IP helpers, fingerprint helpers, `ingress_fault_reason_for` | 142–379, 979–995, 1209–1337 |
| NAT free functions (optional move to `src/p2p/nat_traversal.cpp`) | STUN, NAT-PMP, UPnP, mini HTTP/XML | 381–977 |

The NAT free functions do not touch `Node` at all, so `src/p2p/` is their natural long-term home.

### 4.5 `node_validator_ops.cpp` — validators, committees, availability (~1,800 LOC)

| Group | Functions | Current lines |
|---|---|---|
| Local key + bootstrap | `init_local_validator_key`, `bootstrap_template_bind_validator`, `maybe_adopt_bootstrap_validator_from_peer`, `maybe_self_bootstrap_template`, `pending_join_request_count_locked`, `bootstrap_sync_incomplete_locked` | 3060–3270 |
| Committee / leader | `committee_for_height_round`, `leader_for_height_round`, `is_committee_member_for`, `active_operator_count_for_height_locked`, `effective_validator_min_bond/bond_max_for_height` | 10245–10328 |
| Checkpoints / rewards | `committee_epoch_randomness_for_height_locked`, `finalized_committee_checkpoint_for_height_locked`, `ticket_difficulty_bits_for_epoch_locked`, `settlement_epoch_for_block_height_locked`, `compute_onboarding_score_units_for_epoch_locked`, `ensure_settlement_onboarding_scores_loaded_locked` | 4242–4488 |
| Epoch tickets / committees | `epoch_ticket_challenge_anchor_locked` … `handle_epoch_ticket` (excluding availability) | 5960–6615 |
| Availability | `local_operator_pubkey_locked`, `persist/validate/load_availability_state_locked`, `finalize_availability_restore_locked`, `rebuild_availability_retained_prefixes_…`, `refresh_availability_operator_state_locked`, `advance_availability_epoch_locked` | 5973–6114 |
| Extracted message cases | `on_epoch_ticket`, `on_get_epoch_tickets`, `on_epoch_tickets` | from 7238–7374 |
| Anon helpers | checkpoint helpers, `same_*` comparators, validator repair helpers, enum→string names, `deferred_exit_fork_active` | 90–140, 1232–1262, 1420–1668, 1686–1769 |

### 4.6 `node_state.cpp` — finalized-state persistence and startup (~1,470 LOC)

| Functions | Current lines |
|---|---|
| `load_state`, `init_mainnet_genesis` | 9735–10182, 9590–9733 |
| `persist_finalized_frontier_record`, `check_no_incomplete_finalized_write` | 9399–9468, 9489–9501 |
| `canonical_derivation_config_locked`, `hydrate_runtime_from_canonical_state_locked`, `verify_and_persist_consensus_state_commitment_locked`, `refresh_runtime_from_frontier_storage_locked` | 9503–9588, 9114–9166 |
| Anon: startup repair (`compute_startup_frontier_repair_cap/floor`, `rollback_frontier_tail_from_transition`, `parse_transition_hash/height_from_error`) | 997–1207 |
| Anon: cache + roots (`persist_canonical_cache_rows`, `load_trusted_runtime_checkpoint_from_cache`, `sync_smt_tree`, `persist_state_roots`, `replay_mode_is_frontier`, `same_utxos`, finalized-write marker helpers, finalized-identity helpers) | 1377–1418, 1674–1787, 1962–2207, 2545–2598 |

### 4.7 `node_test_hooks.cpp` (~400 LOC) and `node_args.cpp` (~420 LOC)

- `node_test_hooks.cpp`: all 55 public `*_for_test` methods plus `deterministic_test_keypairs`
  (currently scattered across 4108–4974).
- `node_args.cpp`: `parse_port_arg`, `parse_args_unchecked`, `parse_args` (11861–12287).

### 4.8 `node_internal.hpp` / `node_internal.cpp` — shared helpers and constants

Anything currently in the anonymous namespace that is used by **two or more** of the new files
must move here, because an anonymous namespace is private to one `.cpp`.

```cpp
// src/node/node_internal.hpp
#pragma once
namespace finalis::node::detail {

// Constants used across files
inline constexpr std::uint32_t kFixedValidationRulesVersion = 7;
inline constexpr std::size_t kMaxIngressRangeRequestRecords = 1024;
// ...

// Local in-process bus (disable_p2p mode); defined once in node_internal.cpp
extern std::mutex g_local_bus_mu;
extern std::vector<Node*> g_local_bus_nodes;

// Logging helpers
std::string short_pub_hex(const PubKey32& pub);
std::string short_hash_hex(const Hash32& h);

// ...
}  // namespace finalis::node::detail
```

**Shared helpers (46 total), grouped by who uses them:**

| Used by | Helpers |
|---|---|
| ≥4 files | `short_pub_hex`, `short_hash_hex`, `persist_canonical_cache_rows`, `persist_state_roots`, `kFixedValidationRulesVersion` |
| state + validator_ops | `same_validator_maps`, `same_join_request_maps`, `same_epoch_reward_maps`, `same_finalized_checkpoint_maps`, `validator_map_mismatch_reason`, `repair_invalid_exiting_zero_bond_outpoints`, `repair_matured_bootstrap_exiting_records`, `maybe_reactivate_single_exiting_validator_for_startup_migration`, `finalized_checkpoint_matches_epoch_snapshot`, `kValidatorJoinWindow*Key`, `kValidatorLivenessWindowStartKey`, `kFinalizedRandomnessKey` |
| consensus + state | `parse_consensus_safety_state`, `finalized_write_marker_key`, `finalized_identity_valid_for_frontier_runtime`, `kConsensusSafetyStatePrefix` |
| consensus + validator_ops | `certificate_matches_checkpoint_committee`, `proposer_schedule_from_checkpoint` |
| consensus + ingress | `load_certified_ingress_record_from_db`, `parse_lane_seq_from_error` |
| network + ingress | `ingress_record_wire_size`, `ingress_range_wire_size`, `kMaxIngressRange*` |
| network + validator_ops | `epoch_committee_snapshot_from_checkpoint`, `same_epoch_committee_snapshot`, `endpoint_to_ip` |
| network + node / args | `endpoint_fingerprint_safe`, `parse_endpoint_list`, `is_local_only_bind`, `advertised_endpoint_likely_public`, `network_id_hex`, `token_value`, `ascii_lower`, `kFinalizedTipFreshnessFloorMs` |
| node + validator_ops | `availability_status_name`, `checkpoint_derivation_mode_name`, `checkpoint_fallback_reason_name`, `zero_outpoint` |
| several | `debug_economics_logs_enabled`, `debug_finality_logs_enabled`, `consensus_payload_id`, `consensus_rules_fingerprint`, `make_finality_certificate`, `finalized_identity_for_runtime_tip`, `g_local_bus_mu`, `g_local_bus_nodes` |

Only trivial one-liners should be `inline` in the header; everything else is declared in the
header and defined in `node_internal.cpp` (avoids ODR issues and header bloat).

### 4.9 What stays where, and why nothing needs to become public

- **No member needs to become public.** Splitting member definitions across `.cpp` files does not
  change access: every `Node::` member still sees every private field.
- **High-fan-in members** (called from 3+ areas) stay private members in their owning file, because
  they read `mu_`-guarded state:
  - `committee_for_height_round`, `leader_for_height_round`, `is_committee_member_for`,
    `finalized_committee_checkpoint_for_height_locked` → `node_validator_ops.cpp`
  - `canonical_derivation_config_locked` → `node_state.cpp`
  - `score_peer(_locked)`, `peer_count`, `established_peer_count` → `node_network.cpp`
  - `log_line`, `now_ms`, `now_unix` → `node.cpp`

### 4.10 `node.hpp`

- Keep one `class Node`; a class cannot be split across headers.
- Regroup the **private** declarations by destination file with section comments, e.g.
  `// --- consensus (node_consensus.cpp) ---`. Today they are interleaved (availability
  declarations sit between peer and seed declarations).
- Keep nested private types nested (they need private access):

| Type | Used by |
|---|---|
| `CertificateCheck` | consensus + network dispatcher (pre-check before taking `mu_`) |
| `FinalizedBroadcastFlushGuard` | network (`handle_message`) + consensus (`handle_propose/vote_result`) |
| `ProposeHandlingResult`, `VoteHandlingResult`, `TimeoutVoteHandlingResult` | consensus + network dispatcher |
| `BufferedSyncFrontier`, `kMaxBufferedSync*`, `FinalizedTipVotes` | consensus only |
| `NextEpochCheckpointValidation` | validator_ops only |
| `StunServerBackoffState` | network only |

- Optional: move `NodeConfig`, `LightserverLaunchMode` and `parse_args` to `node_config.hpp`.

---

## 5. Cross-area dependencies

Calls to core utilities (`log_line`, `now_ms`, `short_*_hex`) are omitted. Arrows read
"caller → callee [callee area]".

### 5.1 consensus → others

| Caller | Calls into |
|---|---|
| `consensus_state_locked` | `committee_for_height_round`, `is_committee_member_for`, `single_node_bootstrap_active_locked` [validator_ops]; `peer_count` [network] |
| `next_height_requires_repair_locked` | `epoch_committee_for_next_height_locked`, `finalized_committee_checkpoint_for_height_locked`, `proposer_schedule_from_checkpoint`, `single_node_bootstrap_active_locked` [validator_ops]; `established_peer_count` [network] |
| `maybe_repair_next_height_locked` | `epoch_committee_snapshot_epoch_for_height_locked`, `frozen_epoch_committee_snapshot_for_height_locked`, `maybe_finalize_epoch_committees_locked`, `maybe_request_epoch_ticket_reconciliation_locked`, `rebuild_epoch_committee_state_locked`, `recover_single_validator_epoch_committee_locked` [validator_ops]; `maybe_request_forward_sync_block_locked` [network] |
| `verify_quorum_certificate_locked`, `verify_timeout_certificate_locked` | `committee_for_height_round` [validator_ops] |
| `handle_propose_result` | `committee_for_height_round`, `is_committee_member_for`, `leader_for_height_round` [validator_ops]; `broadcast_vote` [network] |
| `handle_vote_result` | `is_committee_member_for` [validator_ops]; `broadcast_vote`, `maybe_request_candidate_transition_locked`, `should_mute_peer_locked` [network] |
| `handle_timeout_vote_result` | `is_committee_member_for`, `leader_for_height_round` [validator_ops]; `broadcast_timeout_vote`, `should_mute_peer_locked` [network] |
| `handle_frontier_block_locked` | `ensure_settlement_onboarding_scores_loaded_locked` [validator_ops]; `maybe_request_forward_sync_block_locked` [network] |
| `maybe_apply_buffered_sync_frontiers_locked` | `score_peer_locked` [network] |
| `validate_frontier_proposal_locked`, `finalize_if_quorum` | `leader_for_height_round` [validator_ops] |
| `apply_finalized_frontier_effects_locked` | state persistence (`persist_*`, `hydrate_*`, `verify_and_persist_*`) [state]; `committee_for_height_round`, `maybe_finalize_epoch_committees_locked`, `persist_availability_state_locked` [validator_ops]; `mempool_` [ingress] |
| `build_frontier_transition_locked` | `canonical_derivation_config_locked`, `refresh_runtime_from_frontier_storage_locked` [state]; bond limits, `is_committee_member_for`, `ensure_settlement_onboarding_scores_loaded_locked` [validator_ops]; `load_certified_ingress_record_from_db`, `parse_lane_seq_from_error` [ingress] |
| `hydrate_runtime_from_canonical_state_locked` (→ state) | `repair_invalid_exiting_zero_bond_outpoints`, `repair_matured_bootstrap_exiting_records` [validator_ops] |

### 5.2 ingress → others

| Caller | Calls into |
|---|---|
| `handle_tx` | `active_operator_count_for_height_locked`, `effective_validator_min_bond/bond_max_for_height`, `is_committee_member_for` [validator_ops]; `broadcast_tx`, `should_mute_peer` [network] |
| `maybe_certify_locally_accepted_tx_locked` | `broadcast_ingress_record` [network] |
| `ingress_committee_locked` | `finalized_committee_checkpoint_for_height_locked` [validator_ops] |
| `handle_ingress_range_locked` | `ingress_record_wire_size`, `ingress_range_wire_size` [shared] |

### 5.3 network → others

| Caller | Calls into |
|---|---|
| `send_ingress_tips` | `local_ingress_lane_tips_locked` [ingress] |
| `maybe_request_forward_sync_block_locked` | `build_runtime_status_snapshot_locked` [node] |
| `handle_message` | every area — after extraction it calls one `on_<msg>` per case |

### 5.4 validator_ops → others

| Caller | Calls into |
|---|---|
| `bootstrap_template_bind_validator` | `canonical_derivation_config_locked`, `persist_canonical_cache_rows`, `persist_state_roots`, `verify_and_persist_consensus_state_commitment_locked` [state] |
| `finalized_committee_checkpoint_for_height_locked`, `handle_epoch_ticket_locked` | `canonical_derivation_config_locked` [state] |
| `committee_for_height_round`, `leader_for_height_round` | `canonical_derivation_config_locked` [state]; `certificate_matches_checkpoint_committee` [consensus] |
| `ensure_settlement_onboarding_scores_loaded_locked` | `canonical_derivation_config_locked` [state]; `request_epoch_tickets` [network] |
| `maybe_request_epoch_ticket_reconciliation_locked` | `peer_is_fresh_for_epoch_reconcile_locked`, `request_epoch_tickets` [network] |
| `maybe_adopt_bootstrap_validator_from_peer` | `endpoint_to_ip`, `is_bootstrap_peer_ip` [network] |
| `maybe_self_bootstrap_template` | `send_version` [network] |

### 5.5 core (`node.cpp`) → others

| Caller | Calls into |
|---|---|
| `init` | key/bootstrap/committee startup [validator_ops]; peers/addrman/DNS/dialing/scoring [network]; `arm_round0_deadline_locked` [consensus]; `load_state`, `init_mainnet_genesis` [state] |
| `event_loop` | round/proposal/timeout logic [consensus]; epoch tickets and committees [validator_ops]; broadcasts, sync polling, NAT refresh, dialing [network]; `mempool_` [ingress] |
| `status`, `build_runtime_status_snapshot_locked` | read-only queries into every area |
| `stop` | `persist_peers`, `persist_addrman`, `persist_validators_addrman` [network] |
| `start_lightserver_child`, `lightserver_is_public` | `detect_possible_public_ip`, `is_local_only_bind` [network] |

### 5.6 Most-called functions across areas

| Function | Home | Called from areas |
|---|---|---|
| `finalized_committee_checkpoint_for_height_locked` | validator_ops | consensus, ingress, validator_ops, node |
| `committee_for_height_round` | validator_ops | consensus, node, validator_ops |
| `canonical_derivation_config_locked` | state | consensus, node, validator_ops, state |
| `is_committee_member_for` | validator_ops | consensus, ingress, node |
| `score_peer_locked`, `peer_count` | network | consensus, network, node |

---

## 6. Execution order

Each step should be a separate commit (or PR) that **builds and passes the full test suite** before
the next one starts. Steps 1–3 change no file boundaries and are the riskiest to skip.

```bash
cmake --build build -j && ctest --test-dir build --output-on-failure
```

| Step | Change | Risk | Notes |
|---:|---|---|---|
| 1 | **Resolve note A**, then delete the 34 dead functions and their `node.hpp` declarations | Low | Also remove member variables that become unused. |
| 2 | Extract `special_validation_context_locked(height)` to replace the 4 copies of the `SpecialValidationContext{…}` builder (lines 4521, 5350, 8663, 9064) | Low | Pure de-duplication. |
| 3 | Extract `for_each_local_bus_peer(fn)` to replace the 7 local-bus loops in `broadcast_*` (9168–9373) | Low | Pure de-duplication. |
| 4 | Create `node_internal.hpp/.cpp`; move shared helpers, constants and `g_local_bus_*` into `namespace finalis::node::detail` | Low | Update `CMakeLists.txt`. Leave single-file helpers in their anonymous namespace. |
| 5 | Move test hooks → `node_test_hooks.cpp`; CLI parsing → `node_args.cpp` | Low | Cut-and-paste only. |
| 6 | Move state persistence and startup derivation → `node_state.cpp` | Medium | `load_state` stays one function for now. |
| 7 | Break up `handle_message`: one private `on_<msg>(int peer_id, const Bytes& payload)` per case; the dispatcher keeps dedup, rate limiting and the `FinalizedBroadcastFlushGuard` | **Medium–High** | Keep each case's locking exactly as-is: each case takes `mu_` itself. Never call an `on_*` method with `mu_` held. |
| 8 | Extract `Node::on_peer_event` from the `set_on_event` lambda in `init` (2878–3027) | Medium | The lambda then becomes a one-line forwarder. |
| 9 | Split by area: `node_consensus.cpp`, `node_ingress.cpp`, `node_network.cpp`, `node_validator_ops.cpp` (move the `on_*` handlers along with their areas) | Low per file | Pure moves after steps 4 and 7. Do one file per commit. |
| 10 | Regroup `node.hpp` private declarations by destination file | Low | Comments and ordering only. |
| 11 | Split `event_loop` into tick phases: `tick_housekeeping_locked`, `tick_epoch_tickets_locked`, `tick_round_and_proposal_locked` (≈5580–5860), `tick_network_maintenance` | Medium | Optional. The round/proposal phase could later move to `node_consensus.cpp`. |
| 12 | (Optional) Move STUN / NAT-PMP / UPnP free functions to `src/p2p/nat_traversal.cpp` | Low | They don't depend on `Node`. |

Review tips:
- For pure-move commits, `git diff --color-moved=dimmed-zebra` makes unchanged moved code easy to skip.
- Never combine a move with a behavior change in the same commit.

---

## 7. Notes for contributors

### 7.1 Where does my new code go?

| If your code… | Put it in |
|---|---|
| handles proposals, votes, timeout votes, QC/TC, vote locks, finalization or proposal building | `node_consensus.cpp` |
| admits transactions, certifies them into ingress lanes, or syncs ingress records | `node_ingress.cpp` |
| sends or receives P2P messages, manages peers, scoring, dialing, addrman or NAT | `node_network.cpp` |
| deals with validator keys, bootstrap, epoch tickets, committees, checkpoints, availability, rewards or bond rules | `node_validator_ops.cpp` |
| persists or re-derives finalized state, or runs at startup to load state or genesis | `node_state.cpp` |
| is a `*_for_test` hook | `node_test_hooks.cpp` |
| is a CLI flag | `node_args.cpp` (and the field in `NodeConfig`) |
| is node lifecycle, event-loop scheduling or status reporting | `node.cpp` |

If a function genuinely orchestrates several areas, put it in the file of the area whose **state it
mutates**, and call the other areas through their existing member functions.

### 7.2 Adding a new P2P message

1. Add the type and (de)serializer in `src/p2p/messages.*`.
2. Add a private `void on_<msg_name>(int peer_id, const Bytes& payload);` to `node.hpp` in the
   section of the owning area.
3. Implement it in that area's `.cpp`. Take `mu_` inside the handler and keep the critical section small.
4. Add one `case` line to the `handle_message` dispatcher in `node_network.cpp`. **No logic in the
   dispatcher.**

### 7.3 Naming and locking conventions

- **`_locked` suffix** — caller must hold `mu_`. Never lock `mu_` inside a `_locked` function
  (`std::mutex` is not recursive; that deadlocks).
- **Wrapper pattern** — when a function is needed both with and without the lock, write
  `foo_locked()` with the logic and a thin `foo()` that takes `mu_` and calls it
  (e.g. `score_peer` / `score_peer_locked`).
- **No network sends while holding `mu_`** where avoidable. A blocked socket can stall the node, and
  a failed send re-enters the peer-event callback, which takes `mu_`. Queue the send (see
  `pending_finalized_broadcasts_`) and flush it after releasing the lock.
- **`maybe_` prefix** — the function checks a condition and may do nothing.
- **`handle_*_result`** functions return a tri-state (`Accepted` / `SoftReject` / `HardReject`);
  the plain `handle_*` wrapper returns `bool`. Hard rejects should score the peer; soft rejects should not.
- **Test hooks** end in `_for_test`, are public, and must not be called from production code.

### 7.4 When to add something to `node_internal.hpp`

Add a helper or constant to `node_internal.hpp` **only when** all of these hold:

1. It is used, or about to be used, by **two or more** `node_*.cpp` files.
2. It does **not** need `Node` private state. If it does, make it a private `Node` member instead.
3. It is specific to the node runtime. Generally useful code belongs in `src/common/`,
   `src/consensus/`, `src/p2p/`, etc.

Otherwise keep it in an anonymous namespace at the top of the single `.cpp` that uses it.
Declare non-trivial helpers in the header and define them in `node_internal.cpp`; reserve
`inline` for one-liners.

### 7.5 Keeping files healthy

- Aim for files under ~2,500 lines and functions under ~200 lines. If a function grows past
  that, split it into named phases (as proposed for `event_loop`).
- Don't add dead code "for later". Unused private members and helpers are not caught by the
  compiler, which is how ~700 lines accumulated here.
