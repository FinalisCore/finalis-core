# Contributing To Finalis Core

This guide focuses on codebase readability, discoverability, and safe changes.

## Principles

- Keep behavior changes and structure changes in separate pull requests when possible.
- Prefer clear component boundaries over convenience includes.
- Document intent at module level, not only in commit messages.
- Avoid introducing new folders unless they represent a stable architectural boundary.

## Before You Start

1. Read `README.md` for project context.
2. Read `docs/CODEBASE_MAP.md` for layout and ownership guidance.
3. Read `docs/ARCHITECTURE_ORIENTATION.md` for execution model and boundaries.
4. For protocol-sensitive work, read `docs/LIVE_PROTOCOL.md` and relevant docs in `docs/spec/`.

## Pull Request Checklist

- Scope is clear: protocol change, runtime change, refactor, docs, or tooling.
- Affected module README files are updated when ownership or behavior changes.
- New folders are justified in the PR description with boundary rationale.
- New source files follow the repository license policy in `docs/LICENSE_POLICY.md`.
- Tests are updated or rationale is provided for unchanged tests.

## Documentation Expectations

For each new module or folder, add a short README that states:

- Purpose and non-goals.
- Primary public interfaces.
- Dependency direction (what it can import and what can import it).
- Threading and ownership assumptions if relevant.

## Physical Design Guidance

We follow Lakos-inspired physical design principles:

- Components should have clear, minimal responsibilities.
- Dependency direction should be intentional and easy to explain.
- Physical layout should help new contributors answer: "Where does this belong?"

See `docs/PHYSICAL_DESIGN_GUIDELINES.md` for details.

## Folder Structure Consolidation

An ongoing proposal to consolidate low-entity and redundant folders is documented in
`docs/STRUCTURE_CONSOLIDATION_PROPOSAL.md`. This is our roadmap for improving folder navigability
and eliminating shallow directory fragmentation. Refer to this doc when creating new folders or
evaluating refactors.

## Code Organization: `src/node/`

### Overview

`src/node/` holds the node runtime: the `Node` class that ties consensus, P2P, mempool/ingress,
storage and validator lifecycle together. Until recently almost all of it lived in one file,
`node.cpp`, which had grown to more than 12,000 lines. That file has been split into
area-specific translation units. The split was a pure move: no logic, signatures or locking
changed.

`Node` is still one class declared in one header (`node.hpp`). The `.cpp` files below only
divide up where its methods are *defined*.

| File | ~Lines | What belongs here | Examples |
|---|---|---|---|
| `node.hpp` | 830 | The single declaration of `class Node`: public API, private methods, member state. | `Node::init`, `Node::status`, member fields such as `finalized_height_` |
| `node.cpp` | 1,800 | Core lifecycle: init, start, stop, the event loop and status reporting. Also methods called from many area files. | `init`, `start`, `stop`, `event_loop`, `status`, `build_runtime_status_snapshot_locked`, `log_line`, `now_ms`, lightserver child management |
| `node_consensus.cpp` | 2,450 | BFT consensus: proposals, votes, timeout votes, QCs/TCs, vote locks, finalization and frontier application. | `on_propose`, `on_vote`, `on_timeout_vote`, `handle_propose`, `finalize_if_quorum`, `verify_quorum_certificate_locked`, `update_local_vote_lock_locked`, `build_frontier_transition_locked` |
| `node_network.cpp` | 2,630 | P2P: peer events, handshake, the message dispatcher, broadcasts, addrman, peer scoring, NAT/UPnP/STUN endpoint discovery. | `handle_message`, `on_peer_event`, `on_version`, `on_ping`, `broadcast_vote`, `broadcast_tx`, `score_peer`, `try_connect_bootstrap_peers` |
| `node_validator_ops.cpp` | 1,270 | Validator lifecycle: local validator key, bootstrap/onboarding, join requests, epoch committees, epoch tickets, availability state. | `init_local_validator_key`, `maybe_self_bootstrap_template`, `pending_join_request_count_locked`, `epoch_committee_for_next_height_locked`, `on_epoch_ticket`, `leader_for_height_round` |
| `node_ingress.cpp` | 660 | Transaction intake: `TX` messages, ingress lanes and records, local certification and forwarding. | `on_tx`, `handle_tx`, `on_ingress_record`, `on_ingress_tips`, `maybe_certify_locally_accepted_tx_locked`, `effective_min_relay_fee_for_height` |
| `node_state.cpp` | 1,140 | Loading and persisting runtime state: startup state load, genesis, frontier storage, hydration from canonical state. | `load_state`, `init_mainnet_genesis`, `persist_finalized_frontier_record`, `hydrate_runtime_from_canonical_state_locked` |
| `node_test_hooks.cpp` | 450 | Methods that exist only for tests (`*_for_test`). | `inject_tx_for_test`, `advance_round_for_test`, `committee_for_height_round_for_test`, `seed_bonded_validator_for_test` |
| `node_args.cpp` | 450 | Command-line argument parsing into `NodeConfig`. | `parse_args`, `parse_args_unchecked`, `parse_port_arg` |
| `node_internal.hpp` / `.cpp` | 140 / 870 | Free helper functions and constants used by two or more node files (namespace `finalis::node::detail`). | `short_hash_hex`, `msg_type_name`, `parse_consensus_safety_state`, `make_finality_certificate`, `consensus_rules_fingerprint`, `debug_finality_logs_enabled` |

Line counts are approximate and will drift. For the full analysis behind the split, see the
detailed technical decomposition analysis in
[`docs/NODE_CPP_DECOMPOSITION.md`](docs/NODE_CPP_DECOMPOSITION.md).

### Which file should I edit?

| You are adding… | Edit |
|---|---|
| BFT proposal, vote, timeout, QC/TC or finalization logic | `node_consensus.cpp` |
| P2P message handling, handshake, broadcast, peer management | `node_network.cpp` |
| Validator onboarding, join/exit, committees, epoch tickets | `node_validator_ops.cpp` |
| Mempool, transaction intake, ingress lanes | `node_ingress.cpp` |
| State loading or persistence at startup / on finalization | `node_state.cpp` |
| A `*_for_test` hook | `node_test_hooks.cpp` |
| A CLI flag or argument parsing | `node_args.cpp` |
| A free helper or constant needed by 2+ node files | `node_internal.hpp` / `node_internal.cpp` |
| Not sure | `node.cpp` if it is core lifecycle; otherwise ask in the PR |

Any new `Node` method, wherever it is defined, must also be declared in `node.hpp`.

### Rules

- **Keep `node.cpp` small.** Only add code there if it is part of the core event loop, `init`,
  `start`, `stop` or status reporting.
- **Shared code.** If a free function is used by several area files, put it in
  `node_internal.hpp/.cpp`. If a `Node` method is called from several area files, leave it in
  `node.cpp`.
- **Per-message handlers live in their area file.** Each P2P message has an `on_*` method
  (for example `on_vote` in `node_consensus.cpp`, `on_tx` in `node_ingress.cpp`).
- **Keep the dispatcher thin.** `handle_message` in `node_network.cpp` only routes messages.
  For a new message type, add a one-line `case` that returns `on_<msg>(...)`, and put all of
  the logic in that `on_*` method in the right area file.
- **Do not split `Node` across headers.** `node.hpp` stays the single declaration of the class.
- **Build after every change:** `cmake --build build -j`.
- **Before opening a PR,** run the relevant tests:
  `ctest --test-dir build --output-on-failure` (or a subset with `-R <pattern>`).

### Architectural notes

- **The local bus is not a substitute for P2P in multi-validator consensus.** With
  `disable_p2p = true`, nodes in one process exchange messages through an in-process
  "local bus" (`g_local_bus_nodes`). But the event loop and consensus code decide whether a
  validator can propose using the *established peer count* from the real P2P manager
  (`established_peer_count()`, backed by `p2p_`). On the local bus that count is always zero,
  so a cluster with more than one validator never finalizes. Use the local bus only for
  single-validator setups (for example one validator plus followers). Use real P2P
  (`disable_p2p = false`) for multi-validator tests. See the "local bus" section of
  `docs/NODE_CPP_DECOMPOSITION.md`.
- **Shared helpers and constants** for all node files come from `node_internal.hpp`.
- **One class, one header:** `node.hpp` declares all of `Node`; the `.cpp` files are just a
  physical split of its definitions.

### How to read the code

1. **Start with `node.cpp`.** Read `init` → `start` → `event_loop` to see startup and the
   main loop that drives rounds, sync and timers.
2. **Follow one message end to end.** Open `handle_message` in `node_network.cpp`, pick a
   message type (for example `VOTE`), and follow it to its `on_*` handler (`on_vote` in
   `node_consensus.cpp`) and then to the `handle_*` method that does the work.
3. **Look up helpers in `node_internal.hpp`.** Formatting helpers (`short_hash_hex`,
   `msg_type_name`), debug-log switches and shared constants are declared there.
4. **Use `node.hpp` as the index.** Each method is declared there; grep for `Node::<name>`
   in `src/node/*.cpp` to find which file defines it.
