# Node Execution Model

Current restarted mainnet identity:

- `network_name = mainnet`
- `network_id = 258038c123a1c9b08475216e5f53a503`
- `genesis_hash = fd5570810b163e43a90ef5e8203e8aef34c89072f5f261c4de74aa724a615211`

This document describes the live finalized application path in the node.

It is the runtime complement to:

- [CONSENSUS.md](CONSENSUS.md)
- [spec/CHECKPOINT_DERIVATION_SPEC.md](spec/CHECKPOINT_DERIVATION_SPEC.md)
- [spec/AVAILABILITY_STATE_COMPLETENESS.md](spec/AVAILABILITY_STATE_COMPLETENESS.md)

## Unified Finalized Transition

All finalized frontier artifacts converge through one canonical finalized
transition path in the node.

That path is used by:

- direct finalized transition delivery
- local quorum finalization
- replay / restart rebuild
- buffered sync application

This is the runtime source of truth for deterministic finalized execution.

## What The Unified Path Does

For every finalized transition it:

1. canonicalizes finality signatures
2. persists the finalized frontier transition and the height-indexed finality certificate
3. updates persisted consensus safety state
4. updates epoch settlement bookkeeping
5. accrues finalized reward score
6. updates validator liveness accounting
7. applies validator lifecycle changes from finalized history
8. applies finalized transition effects to the UTXO state
9. updates finalized tip
10. advances finalized randomness
11. rebuilds the next epoch checkpoint if an epoch boundary is crossed
12. persists state roots and other derived finalized artifacts

Important boundary:

- validator lifecycle and availability state are updated only from finalized
  history
- next-epoch checkpoint derivation is performed only when the finalized epoch
  boundary is crossed
- finalized transaction application is version-aware and feeds `UtxoSetV2`

## Signature Canonicalization

Before persistence:

- signatures are sorted by signer pubkey
- duplicates are removed
- signatures are truncated to exactly quorum

This keeps finalized proofs deterministic across honest nodes.

## Persistence Ordering

The finalized frontier transition and its matching height-indexed certificate
are persisted before later derived safety/runtime state is updated.

This preserves the finalized chain as the root truth and prevents derived
next-height state from getting ahead of committed finalized state.

## Restart Model

On startup, the node restores persisted chain state and then rebuilds or
validates derived finalized state from history.

By default, startup clears the consensus state commitment cache to guarantee
replay rebuilds a canonical view even if a previous cache was corrupted. Use
`--no-reindex` to keep the cache when you are confident it is consistent.

Derived state rebuilt or validated on startup includes:

- finalized randomness
- validator registry and lifecycle state
- availability state and checkpoint-relevant projection
- finalized committee checkpoints
- adaptive checkpoint metadata
- epoch settlement state

After the fresh-genesis reset, persisted state from the abandoned chain must
fail closed rather than being treated as replay input for this execution model.
- consensus safety state for the current next height
- adaptive epoch telemetry derived from finalized checkpoints
- version-aware UTXO/state-root consistency for the live transaction mix

The same finalized chain must reconstruct the same derived state.

## Consensus Safety State

Consensus safety state stores:

- local vote lock for the current next height
- highest known QC for that height
- associated payload identity

On restart:

- stale or invalid local safety state is cleared
- restored safety state must validate against the current finalized chain and
  next-height committee data

This state is operationally important, but it is subordinate to finalized chain
truth.

## Checkpoint Boundary

The epoch-boundary checkpoint rebuild is part of the finalized execution model.

At the boundary the node deterministically derives:

- checkpoint derivation mode
- fallback reason
- eligible operator count
- committee membership and proposer schedule
- adaptive target committee size
- adaptive minimum eligible threshold
- adaptive minimum bond

from:

- finalized validator lifecycle state
- finalized projected availability state
- previous checkpoint metadata

No local caches, wall-clock inputs, or observability-only evidence may change
that output.

## Determinism Guarantees

- the same finalized chain yields the same finalized randomness
- the same finalized chain yields the same validator lifecycle state
- the same finalized chain yields the same projected availability state
- the same finalized chain yields the same committee checkpoint
- the same finalized chain yields the same adaptive checkpoint metadata
- the same finalized chain yields the same reward settlement state
- all finalized paths apply the same state mutation sequence

This is the core runtime determinism guarantee of the current node.
