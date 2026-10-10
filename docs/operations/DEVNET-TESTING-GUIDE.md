# Devnet Testing Guide

Current mainnet identity reference for comparison against local test
deployments:

- `network_name = mainnet`
- `network_id = fe561911730912cced1e83bc273fab13`
- `genesis_hash = eaae655a1eec3c876bd2e66d899fc8da93d205a5df36a2665f736387aa3cb78a`

## Purpose

This guide is for validating current `finalis-core` runtime invariants on a
small local network.

Use it to test:

- finalized-path equivalence
- restart determinism
- checkpoint reconstruction
- adaptive checkpoint observability
- reward settlement replay
- QC and lock safety behavior
- supported confidential `TxV2` execution on a fresh network
- wallet / explorer local-first behavior across restart

Do not mix abandoned-chain DBs or stale embedded-genesis binaries into these
tests if the goal is to simulate the current mainnet.

## Basic Commands

Build:

```bash
cmake --build build -j4
```

Dependency notes:
- If `third_party/secp256k1-zkp` is missing, CMake will auto-fetch it (network required).
- For offline builds, disable auto-fetch and provide the vendored tree:
  `cmake -S . -B build -G Ninja -DFINALIS_AUTO_FETCH_DEPS=OFF`
  `git submodule update --init --recursive`

Run the test suite:

```bash
./build/finalis-tests
```

Run a node:

```bash
./build/finalis-node --db /tmp/finalis-node0 --node-id 0 --port 19440 --listen
```

## Minimal Multi-Node Layout

For a small local network:

1. create a shared genesis file or use the same devnet genesis
2. run multiple nodes with distinct:
   - `--db`
   - `--node-id`
   - `--port`
3. connect nodes with:
   - `--peers host:port,...`
   - or `--seeds host:port,...`

Use loopback bindings for local-only tests.

## Scenarios To Test

### 1. Restart At Epoch Boundary

Goal:

- verify finalized checkpoint rebuild
- verify adaptive checkpoint metadata rebuild
- verify reward settlement rebuild

Procedure:

1. run the network until just before an epoch boundary
2. stop one node
3. let the network finalize across the boundary
4. restart the stopped node
5. verify it reconstructs:
   - the same finalized height
   - the same next-epoch checkpoint
   - the same adaptive target / min eligible / min bond metadata
   - the same epoch settlement outputs

Expected invariant:

- same finalized chain implies same checkpoint, adaptive metadata, and
  settlement state

### 2. Delayed Finalized Transition Delivery

Goal:

- verify direct finalized transition delivery equals local quorum finalization

Procedure:

1. let one node finalize locally
2. deliver the finalized transition and matching certificate to another node later
3. compare finalized state across nodes

Expected invariant:

- both nodes pass through identical finalized effects

### 3. Quorum Path vs Direct Finalized Delivery

Goal:

- verify all finalized paths call the same transition

Procedure:

1. finalize one transition by collecting local votes
2. finalize another by delivering an already-finalized transition artifact
3. inspect persisted tip, finality certificate, settlement state, checkpoint,
   and adaptive telemetry

Expected invariant:

- all finalized paths converge through the same finalized transition logic

### 4. Settlement Replay

Goal:

- verify epoch settlement is exactly once and restart-safe

Procedure:

1. run across at least one full epoch
2. stop the node after several finalized transitions
3. restart
4. verify reward-settlement rows and next-boundary payout match replay from
   finalized transitions

Expected invariant:

- restart rebuild reproduces the same settlement state

### 5. Same-Operator Split Behavior

Goal:

- verify operator aggregation removes same-owner split gains from committee
  economics

Procedure:

1. create several validators sharing the same operator payout key
2. compare checkpoint behavior against one validator with the same total
   operator bond

Expected invariant:

- same operator, same total bond, same primary committee influence

### 6. Adaptive Regime Observability

Goal:

- verify live observability matches canonical checkpoint state

Procedure:

1. run across several epochs
2. query `get_status`, verbose `get_committee`, and `get_adaptive_telemetry`
3. confirm:
   - `qualified_depth`
   - adaptive target / min eligible / min bond
   - checkpoint mode / fallback reason
   - expansion / contraction streaks
   - rolling fallback metrics
4. restart one node and confirm the same telemetry summary is reconstructed

Expected invariant:

- observability fields are replay-safe and derived from canonical checkpoint
  state or persisted telemetry only

### 7. Confidential `TxV2` Fresh-Network Path

Goal:

- verify the supported confidential subset works from fresh genesis
- verify replay / restart preserve versioned UTXO state

Procedure:

1. start a fresh network with wiped DBs (`TxV2` is valid from genesis; nothing to activate)
2. submit:
   - transparent -> confidential `TxV2`
   - confidential -> transparent `TxV2`
3. restart one node
4. compare finalized height, tx status, and resulting UTXO state after replay

Expected invariant:

- `TxV2` replay is deterministic
- versioned UTXO state is restart-stable

### 8. Wallet / Explorer Local-First Surfaces

Goal:

- verify UI startup remains usable without synchronous RPC dependence

Procedure:

1. start wallet and explorer once against a healthy lightserver
2. confirm local snapshots / caches are written
3. stop or firewall the lightserver
4. restart wallet and explorer
5. confirm:
   - cached state renders immediately
   - freshness / stale-state markers are visible
   - cached finalized data is distinguished from fresh RPC data

Expected invariant:

- product startup is local-first
- endpoint failure does not blank the surface
- stale finalized cache is labeled explicitly

### 9. Consensus Chaos (Liveness And Safety Under Faults)

`scripts/chaos_devnet.py` runs N local validator processes with fast timing and routes every
directed link through an in-process TCP proxy (nodes only dial configured peers; addrman rejects
loopback addresses). It alternates fault windows with healed windows:

- crash (SIGKILL up to `f` nodes) and graceful restart
- partitions (random splits, including ones with no quorum on either side)
- isolation flaps of one node (exercises the reconnect round reset)
- link latency
- crash combined with a partition

Pass criteria:

- no fork: every `finalized height=H transition=T` log line agrees across nodes (exit 3 otherwise)
- after each heal, a new height finalizes within `--recovery-deadline` (exit 2 otherwise)
- at the end, every node reaches the same tip

```bash
cmake --build build -j
scripts/chaos_devnet.py --nodes 7 --duration 900 --seed 7 --workdir /tmp/finalis-chaos
```

Each node appears to its peers under its own loopback address (`127.0.0.<10+i>`), so peer
scoring and IP bans behave as on a real network.

Options:

- `--tx-interval S`: a payment every S seconds between validators (funded by the first reward
  settlement), sent through a random running node's lightserver and tracked to finality. Reported:
  accepted, finalized, lost (not finalized within `--tx-lost-s`), finality latency.
- `--byzantine K` (K <= f): the first K validators are Byzantine. Needs a separate build:
  `cmake -S . -B build-chaos -G Ninja -DFINALIS_CHAOS_BYZANTINE=ON` and `--build-dir build-chaos`.
  They prevote and precommit every proposal they see, ignoring every rule, and as leader send two
  different valid proposals to different peers. The option compiles nothing into normal builds.

```bash
scripts/chaos_devnet.py --nodes 7 --byzantine 2 --build-dir build-chaos --tx-interval 1 --duration 1200
```

It generates a genesis with `scripts/generate_fresh_genesis.sh` (or reuses `--genesis-dir`) and
writes `report.md`, `report.json` and `node<i>.log` to the workdir. Use different `--seed` values
for different fault schedules; a failing seed reproduces the same schedule.

## Useful Existing Tests

Targeted checks already exist in:

- [tests/test_committee_schedule.cpp](../../tests/test_committee_schedule.cpp)
- [tests/test_codec.cpp](../../tests/test_codec.cpp)
- [tests/test_integration.cpp](../../tests/test_integration.cpp)
- [tests/test_lightserver.cpp](../../tests/test_lightserver.cpp)

Examples include:

- restart committee determinism
- operator aggregation invariance
- canonical finalized transition behavior
- adaptive observability surface checks
- confidential transaction validation / execution
- wallet local-first snapshot persistence
- explorer startup cache hydration

## Core Invariants To Watch

- only `finalized_height + 1` is processed in live consensus
- no conflicting finalization
- canonical finality-proof persistence
- deterministic next-epoch checkpoint
- deterministic adaptive target / min eligible / min bond
- exactly-once reward settlement at epoch boundary
- finalized chain remains the only source of truth for derived state
