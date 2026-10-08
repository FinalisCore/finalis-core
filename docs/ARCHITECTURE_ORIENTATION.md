# Architecture Orientation

This document provides a quick orientation for developers new to the repository.

## System Shape

Finalis Core is a finalized-state BFT blockchain implementation with deterministic committee and checkpoint derivation from finalized history.

The runtime model is intentionally narrow:

- Process only `height = finalized_height + 1`.
- Bind consensus artifacts to precise `(height, round, block_id)` coordinates.
- Expose finalized-state read APIs through lightserver and explorer.

## Runtime Boundaries

- Consensus and committee rules live in consensus-oriented modules.
- Node orchestration coordinates execution and state transitions.
- P2P handles transport, not protocol truth.
- Storage persists finalized state and required indexes.
- Application surfaces present finalized state for users and integrators.

## Dependency Direction (Intent)

At a high level, dependencies should trend from:

- applications -> node/runtime/public APIs
- orchestration -> consensus/state/network subsystems
- subsystem internals -> common/crypto primitives

Avoid reverse coupling where low-level utilities depend on application or orchestration code.

## Node Module Structure

The node runtime (`src/node/`) is a single `Node` class, declared once in `node.hpp`, with its
method definitions split by area:

| File | Area |
|---|---|
| `node.cpp` | Lifecycle (init/start/stop), event loop, status; methods shared across areas |
| `node_consensus.cpp` | BFT proposals, votes, timeouts, QC/TC, vote locks, finalization |
| `node_network.cpp` | P2P handshake, message dispatcher (`handle_message`), broadcasts, peers, NAT/endpoint discovery |
| `node_validator_ops.cpp` | Validator key, onboarding/join, epoch committees, epoch tickets, availability |
| `node_ingress.cpp` | Transaction intake, ingress lanes, certification |
| `node_state.cpp` | Startup state loading, genesis, frontier persistence |
| `node_args.cpp` | Command-line parsing |
| `node_test_hooks.cpp` | `*_for_test` hooks |
| `node_internal.hpp/.cpp` | Free helpers and constants shared by the files above |

Incoming P2P messages enter through `handle_message` in `node_network.cpp`, which forwards
each message type to an `on_*` handler in the area file that owns it.

For guidance on where to put new code, see "Code Organization: `src/node/`" in
`CONTRIBUTING.md`. For the detailed technical decomposition analysis, see
`docs/NODE_CPP_DECOMPOSITION.md`.

## Design Expectations

- Keep responsibilities cohesive at module level.
- Keep interfaces narrow and explicit.
- Keep public behavior deterministic across nodes.
- Prefer readability and boundary clarity over ad-hoc placement.

## What This Document Is Not

- Not a full protocol spec.
- Not a replacement for the docs in `docs/spec/`.
- Not a line-by-line code walkthrough.

Use this as a map, then dive into component README files under `src/` and protocol docs under `docs/`.
