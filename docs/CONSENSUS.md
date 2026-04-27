# Consensus

Current mainnet identity:

- `network_name = mainnet`
- `network_id = fe561911730912cced1e83bc273fab13`
- `genesis_hash = eaae655a1eec3c876bd2e66d899fc8da93d205a5df36a2665f736387aa3cb78a`

This document describes the live finalized-tip BFT path at a high level.

It is not the normative source for checkpoint derivation. For that, use:

- [spec/CHECKPOINT_DERIVATION_SPEC.md](spec/CHECKPOINT_DERIVATION_SPEC.md)
- [spec/AVAILABILITY_STATE_COMPLETENESS.md](spec/AVAILABILITY_STATE_COMPLETENESS.md)

## Active Height Rule

The live consensus path only accepts work for:

`height = finalized_height + 1`

That means:

- there is no live longest-chain competition
- there is no non-finalized fork-choice rule
- proposals, votes, and QCs are only meaningful for the next finalized height

Relevant implementation:

- [src/node/node.cpp](../src/node/node.cpp)

After the fresh-genesis reset, consensus artifacts from the abandoned chain are
not valid inputs to the current live path. Only the current genesis identity
and current finalized history are authoritative.

Consensus execution is version-aware:

- legacy transparent transactions use `Tx`
- confidential-capable transactions use `TxV2`
- runtime dispatch uses `AnyTx`

## Committee Source

The active committee for a height is taken from the finalized checkpoint for the
epoch containing that height.

That checkpoint is derived only from finalized state at the prior epoch
boundary. It already incorporates:

- finalized validator lifecycle
- availability eligibility
- explicit `normal` / `fallback` checkpoint mode
- adaptive checkpoint target committee size
- adaptive checkpoint minimum eligible threshold
- adaptive checkpoint minimum bond

Consensus does not recompute those policy decisions in the live proposal/vote
path. It consumes the finalized checkpoint output.

## Proposal

A proposal consists of:

- `height`
- `round`
- `prev_finalized_hash`
- serialized block bytes
- optional `justify_qc`

The serialized payload may contain either transparent-only transactions or the
currently supported confidential-capable `TxV2` subset.

The node accepts a proposal only if:

- `height == finalized_height + 1`
- `round == current_round`
- `prev_finalized_hash` matches the current finalized tip hash
- the proposer matches the deterministic proposer for `(height, round)`
- the proposer signature is valid
- block transaction validation succeeds
- if a QC is present, it is valid for the proposal

Important boundary:

- proposer selection is deterministic from the finalized checkpoint
- if the checkpoint was derived in `fallback` mode, the live consensus path
  still uses that already-finalized committee output directly

## Vote

A vote is over:

`(height, round, block_id)`

The signed message is the canonical vote-signing message for that exact tuple.

Vote acceptance requires:

- `height == finalized_height + 1`
- validator is in the committee for `(height, round)`
- signature verifies over the canonical vote-signing message
- the vote tracker accepts it under the lock / relock rules

Votes are not over a generic height-only or block-only object. They are bound
to the exact round and block identifier.

## Quorum Certificate

A QC contains:

- `height`
- `round`
- `block_id`
- quorum signatures

QC validation requires:

- committee lookup for `(height, round)`
- deduplication by signer pubkey
- all signatures verify over `(height, round, block_id)`
- signer count after filtering is at least quorum

Finality threshold remains:

`floor(2N/3) + 1`

where `N` is the committee size for that height.

## Lock Rules

Each node keeps:

- a local vote lock per height
- a highest known QC for that height

The node may vote for block `B` at height `H` only if one of the following
holds:

1. no local lock exists at `H`
2. the local lock already points to the same consensus payload as `B`
3. a valid QC is supplied and:
   - `QC.height == H`
   - `QC.round < proposal.round`
   - `QC` resolves to the same payload as `B`
   - `QC.round >= locked_round`

The lock is updated when the node votes.

This preserves the live safety property that a QC cannot unlock a conflicting
payload.

## Finalization

A block finalizes when the node has:

- the block body
- the effective committee recomputed for the certified frontier transition at
  `(height, round)`
- at least quorum valid signatures for the same `(height, round, block_id)`

Before applying finality effects, the node re-verifies the certified frontier
record against current canonical state and derives the expected committee/quorum
from that recomputation. Signature filtering and quorum counting are performed
against this expected committee.

The finality proof is canonicalized before persistence:

- signatures sorted by signer pubkey
- duplicates removed
- truncated to exactly quorum

The finalized transition then drives:

- finalized tip advancement
- deterministic state transition
- reward / settlement progression
- validator lifecycle replay state
- availability replay state
- checkpoint rebuild at epoch boundaries when required

Finalized execution remains validator-signature-driven even when confidential
transactions are present; `TxV2` does not change the validator-key consensus
model.

## `PROPOSE` And Finalized Transition Delivery

`PROPOSE` is the live current-round proposal path.

Finalized artifact delivery on the live path is frontier-transition based.

Both converge through the same finalized application path.

That unified path:

- canonicalizes signatures
- persists the finalized frontier transition and the height-indexed finality
  certificate
- updates finalized tip and randomness
- applies deterministic state transition
- updates validator and availability state
- rebuilds the next epoch checkpoint when the epoch boundary is crossed
- applies version-aware transaction effects to version-aware UTXO state

Certified ingress that feeds the transition is validated as epoch-pinned input:

- certificate epoch must match the active epoch start for
  `finalized_height + 1`
- signer set must be signature-valid and committee-valid
- stale-epoch ingress certificates are rejected on receive and on replay

## Checkpoint Boundary

The most important live consensus boundary is:

- consensus for height `H` consumes the finalized checkpoint already derived for
  `epoch_of_height(H)`
- checkpoint derivation for the next epoch is itself a deterministic function of
  finalized state at the prior epoch boundary

So the protocol is split cleanly:

- finalized-tip BFT decides the next transition
- finalized epoch-boundary derivation decides the next epoch committee and
  proposer schedule

The second part is still consensus-critical, but it is not recomputed from
local heuristics during proposal/vote handling.

## Invariants

- only `finalized_height + 1` is processed in the live path
- votes are bound to `(height, round, block_id)`
- the committee for a height comes from the finalized checkpoint for that
  height's epoch
- checkpoint output is deterministic from finalized state only
- a QC cannot unlock a conflicting payload
- finalized transition delivery and local quorum finalization use the same
  state transition
- local finalization rechecks committee/quorum from recomputed transition state
- finalized transitions are applied deterministically
- restart and replay must reconstruct the same validator state, availability
  state, checkpoints, committees, and proposer schedule
