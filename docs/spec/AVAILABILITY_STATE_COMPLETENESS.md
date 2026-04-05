# Availability State Completeness

## Scope

This document defines which live availability fields are consensus-relevant for checkpoint derivation, how they are reconstructed, and what replay/restart equivalence the implementation guarantees.

It is normative for the live availability-gated checkpoint path together with [CHECKPOINT_DERIVATION_SPEC.md](/home/greendragon/Desktop/selfcoin-core-clean/docs/spec/CHECKPOINT_DERIVATION_SPEC.md).
A bounded formal model for replay-equivalent availability projection and evidence isolation is provided in [../../formal/checkpoint_availability.tla](../../formal/checkpoint_availability.tla), with reproducible TLC suite configurations under [../../formal/](../../formal/).

## Consensus-relevant availability fields

The following fields can affect live checkpoint derivation and are therefore consensus-relevant.

### Persisted consensus-relevant state

`AvailabilityPersistentState.current_epoch`
- Used to determine the live availability epoch.
- Affects retained-prefix expiry and epoch-advance audit application.

`AvailabilityPersistentState.operators[*].operator_pubkey`
- Canonical operator identity key.
- Used for operator indexing, eligibility, and deterministic ordering.

`AvailabilityPersistentState.operators[*].bond`
- Used by `operator_is_eligible(...)`.

`AvailabilityPersistentState.operators[*].status`
- Used directly by `operator_is_eligible(...)`.

`AvailabilityPersistentState.operators[*].service_score`
- Used by `operator_eligibility_score(...)` and therefore `operator_is_eligible(...)`.

`AvailabilityPersistentState.operators[*].successful_audits`
`AvailabilityPersistentState.operators[*].late_audits`
`AvailabilityPersistentState.operators[*].missed_audits`
`AvailabilityPersistentState.operators[*].invalid_audits`
- Feed status evolution at epoch advance.

`AvailabilityPersistentState.operators[*].warmup_epochs`
- Feeds status evolution at epoch advance.

`AvailabilityPersistentState.operators[*].retained_prefix_count`
- Used by `operator_eligibility_score(...)`.
- Recomputed during live restore/refresh before checkpoint use.

`AvailabilityPersistentState.retained_prefixes[*]`
- Determines retained-prefix membership, future expiry, future assigned-prefix counts, and therefore future audit outcomes and future `retained_prefix_count`.

### Deterministically re-derived from finalized frontier history

Here, `finalized frontier history` means the canonical sequence of finalized
frontier transitions together with the persisted finality certificate for each
finalized height and the committed frontier storage required to validate those
transitions.

Assigned prefix counts per operator
- Derived from:
  - finalized identity
  - current epoch
  - canonically ordered retained prefixes
  - canonically ordered operator ids
  - deterministic `assigned_operators_for_prefix(...)`

Checkpoint eligible operator count
- Derived from the canonical operator vector via `count_eligible_operators(...)`.

Checkpoint derivation mode / fallback reason / fallback sticky
- Derived from:
  - previous checkpoint mode
  - eligible operator count
  - checkpoint adaptive minimum eligible metadata

Checkpoint qualified depth and adaptive regime metadata
- Derived from:
  - finalized validator lifecycle state
  - finalized projected availability state
  - prior checkpoint adaptive metadata
- Includes:
  - `qualified_depth`
  - `adaptive_target_committee_size`
  - `adaptive_min_eligible`
  - `adaptive_min_bond`
  - `target_expand_streak`
  - `target_contract_streak`

### Observability-only / not consensus-relevant

`AvailabilityPersistentState.evidence`
- Persisted for audit/evidence visibility only.
- Does not affect `operator_is_eligible(...)`, checkpoint mode, checkpoint reason, or committee selection.
- Is intentionally excluded from live availability validation for checkpoint derivation.
- Is intentionally excluded from the canonical state commitment and finalized checkpoint bytes.

Runtime status snapshot fields
- Derived from persisted/replayed state.
- Never feed back into checkpoint derivation.

Structured rebuild observability
- `availability.state_rebuild_triggered`
- `availability.state_rebuild_reason`
- These are operator-facing observability fields only.
- They indicate that the node rebuilt live availability state from finalized frontier history instead of trusting the persisted snapshot.

## Canonical normalization

Before live derivation use, availability state is canonically normalized by:

1. sorting operators by `operator_pubkey`
2. sorting retained prefixes by:
   - `certified_height`
   - `lane_id`
   - `start_seq`
   - `prefix_id`
3. sorting evidence by:
   - `challenge.challenge_id`
   - `challenge.operator_pubkey`
   - `response.operator_pubkey`
   - `violation`
4. removing exact duplicates

Conflicting duplicate operator entries and conflicting duplicate retained-prefix entries are invalid.

## Live derivation invariants

The live implementation validates:

1. operator entries are canonically sorted and unique by `operator_pubkey`
2. retained prefixes are canonically sorted and unique by `prefix_id`
3. evidence is canonically sorted
4. each operator status is idempotent under `update_operator_status(...)` with the live availability config

The idempotence requirement means persisted operator lifecycle state must already be internally consistent before it is trusted for live checkpoint derivation.

The live implementation does not require evidence ordering or evidence contents to validate consensus-relevant availability state. Evidence normalization exists only for persistence and observability stability.

## Replay and restart equivalence

The live availability state used by checkpoint derivation may come from exactly two sources:

1. replay from finalized frontier history / canonical derived state
2. persisted `AvailabilityPersistentState` restored from disk

Both sources are forced through the same normalization and validation boundary before reuse.
If persisted availability state is missing, invalid, or missing retained-prefix material needed for frontier-mode replay, the node rebuilds deterministically from finalized frontier history and exposes that fact through the structured rebuild observability fields.
The resulting availability projection feeds the same qualified-depth computation used to derive adaptive target, adaptive min eligible, and adaptive min bond for the next checkpoint epoch.

Adaptive regime observability derived from that checkpoint path may expose:

- qualified depth
- adaptive min bond / min eligible / target committee size
- slack relative to min eligible
- rolling fallback and sticky-fallback rates
- telemetry summary counts such as:
  - sample count
  - fallback epochs
  - sticky-fallback epochs
- observability-only alert flags

These surfaces are derived from canonical checkpoint/runtime state or persisted epoch telemetry only. They are not additional consensus inputs.

The live implementation uses shared availability evolution helpers for both node runtime and canonical derivation:

- `refresh_live_availability_state(...)`
- `advance_live_availability_epoch(...)`

This removes parallel epoch-advance logic from the live path.

In frontier mode, retained prefixes may be rebuilt from finalized frontier storage when the persisted snapshot is missing or incomplete. That rebuild is deterministic because it consumes only:

- finalized frontier transitions
- one canonical finality certificate per finalized height
- stored certified lane records
- deterministic retained-prefix construction

## Auditor-facing guarantee

For two honest nodes with identical:

- genesis
- finalized frontier history
- live availability config

the following are identical after replay or persisted restore:

- normalized availability operators
- normalized retained prefixes
- eligible operator count
- checkpoint derivation mode
- checkpoint fallback reason
- sticky fallback exposure
- resulting checkpoint bytes

There is no live checkpoint dependency on local wall-clock state, local caches, hydration order, or runtime status snapshots.
There is also no live checkpoint dependency on persisted availability evidence contents or evidence ordering; that boundary is enforced by dedicated eligibility, checkpoint, replay/restart, and long-horizon isolation tests.
