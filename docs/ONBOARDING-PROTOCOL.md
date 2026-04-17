# Onboarding Protocol

Current restarted mainnet identity:

- `network_name = mainnet`
- `network_id = 258038c123a1c9b08475216e5f53a503`
- `genesis_hash = fd5570810b163e43a90ef5e8203e8aef34c89072f5f261c4de74aa724a615211`

This document describes the live pre-validator onboarding path implemented in
`finalis-core`.

It covers:

- `ValidatorStatus::ONBOARDING`
- `SCONBREG` finalized admission
- admission PoW gating
- `ONBOARDING -> PENDING -> ACTIVE`
- the `3%` onboarding reward carve-out

Primary implementation paths:

- [src/consensus/validator_registry.cpp](../src/consensus/validator_registry.cpp)
- [src/utxo/tx.cpp](../src/utxo/tx.cpp)
- [src/utxo/validate.cpp](../src/utxo/validate.cpp)
- [src/utxo/signing.cpp](../src/utxo/signing.cpp)
- [src/node/node.cpp](../src/node/node.cpp)
- [src/consensus/monetary.cpp](../src/consensus/monetary.cpp)

## 1. Purpose

The onboarding path exists so a new participant can become a recognized
pre-validator operator before full validator admission.

`ONBOARDING` is not a validator role.

It allows:

- deterministic on-chain admission
- epoch ticket submission
- eligibility for the onboarding reward bucket

It does not allow:

- voting
- proposing
- committee membership
- quorum weight
- normal validator reward settlement

## 2. Lifecycle

The intended lifecycle is:

- unknown follower
- `ONBOARDING`
- `PENDING`
- `ACTIVE`
- `EXITING` / `SUSPENDED` / `BANNED`

The live transition rules are:

- unknown -> `ONBOARDING`:
  only by finalized `SCONBREG`
- `ONBOARDING` -> `PENDING`:
  only by finalized bonded validator join
- `PENDING` -> `ACTIVE`:
  only by the normal warmup rule

Important boundary:

- `ONBOARDING` does not auto-activate by waiting
- `ONBOARDING` has no bond and cannot use bonded exit paths before join

## 3. `SCONBREG`

`SCONBREG` is the dedicated onboarding registration output script.

Its finalized effect is:

- insert validator registry entry for `validator_pubkey`
- set `status = ONBOARDING`
- set `operator_id` from `payout_pubkey`
- set `bonded_amount = 0`
- set `has_bond = false`

Minimal payload carried by the script:

- `validator_pubkey`
- `payout_pubkey`
- proof of possession over the validator key
- optional admission PoW fields when admission PoW is enabled:
  - `pow_epoch`
  - `pow_nonce`

Live implementation accepts:

- legacy `SCONBREG` without embedded admission PoW only when onboarding
  admission PoW is disabled by network policy
- PoW-bearing `SCONBREG` when onboarding admission PoW is enabled

`SCONBREG` script validation is version-consistent:

- the same semantic checks are enforced when the output appears in legacy `Tx`
  or in transparent outputs of `TxV2`
- output value must be zero in both transaction versions
- proof-of-possession and policy-gated admission-PoW checks are enforced through
  the same validation context in both versions

## 4. Admission PoW

On restarted mainnet, onboarding admission is PoW-gated.

The onboarding admission PoW is:

- bounded
- epoch-scoped
- finalized-anchor-bound
- identity-bound

It is an admission filter, not a mining system.

It does not:

- grant extra influence for stronger work
- change reward weight directly
- replace Ticket PoW
- replace finalized-state safety

The witness is bound to:

- chain identity
- admission epoch
- finalized anchor
- `validator_pubkey`
- `payout_pubkey`
- nonce

So the same work is not reusable:

- across networks
- across epochs
- across different validator identities
- across different payout bindings

Current live policy uses separate network knobs for:

- `onboarding_admission_pow_difficulty_bits`
- `validator_join_admission_pow_difficulty_bits`

This keeps onboarding admission and full validator join admission independent.

## 5. Duplicate And Re-entry Rules

The live protocol rejects `SCONBREG` if:

- the validator pubkey is already present in registry
- the validator pubkey is banned
- the transaction mixes onboarding registration with validator join outputs
- the admission PoW is invalid when required
- ingress certification for the containing transaction is stale for the current
  expected epoch

This means:

- duplicate onboarding registration is rejected
- `PENDING` or `ACTIVE` validators cannot re-enter through onboarding
- banned validator pubkeys cannot re-enter through onboarding

## 6. `ONBOARDING -> PENDING`

Upgrade from `ONBOARDING` to `PENDING` happens only through the existing bonded
validator join path.

That path requires:

- a valid bond output
- a valid validator join request
- valid join admission PoW when enabled by network policy

On finalize:

- the registry entry becomes `PENDING`
- the bond is attached
- normal warmup rules apply

No local runtime shortcut is permitted.

## 7. `PENDING -> ACTIVE`

`PENDING` becomes `ACTIVE` only through the normal warmup rule already used by
the validator lifecycle.

Important boundary:

- a validator that becomes `ACTIVE` mid-epoch does not rewrite the already
  derived committee for that epoch
- future checkpoint eligibility changes only through finalized epoch-boundary
  derivation

## 8. Onboarding Rewards

The live settlement path contains a separate onboarding reward bucket.

Current rule:

- `3%` of settlement rewards are carved from the validator settlement reward
  slice
- reserve accrual remains `10%` of gross issuance
- fees and reserve subsidy are not shared with onboarding rewards

The onboarding reward bucket is paid only to:

- validators in `ONBOARDING`
- with at least one valid finalized epoch ticket

Only the best finalized epoch ticket per onboarding validator counts.

The reward score is derived from that best ticket only.

If the onboarding set is empty for a settlement epoch:

- the onboarding slice remains in the validator settlement pool

It is not burned, and it is not paid to nonexistent onboarding recipients.

## 9. Determinism Boundaries

The onboarding path is derived only from finalized state.

It must not depend on:

- local wallet-only registration
- local runtime peer counts
- mempool visibility
- unfinalized network observations

That means:

- unknown -> `ONBOARDING` is on-chain only
- reward eligibility is computed from finalized registry state and finalized
  epoch tickets only
- explorer / lightserver visibility is observational and finalized-only

Ingress boundary used by the live onboarding path:

- onboarding transactions are admitted through certified ingress records that are
  epoch-pinned to `committee_epoch_start(finalized_height + 1)`
- stale-epoch ingress certificates are rejected before onboarding state changes
  can be applied
- replay re-validates certificate signatures, lane continuity, and lane-root
  chaining before deterministic state transition

## 10. Safety Boundaries

The onboarding path does not modify the core safety model.

Safety still depends on:

- finalized-state committee derivation
- validator signatures
- quorum certificates bound to exact context

`SCONBREG` admission PoW is only an admission gate.

Ticket PoW remains a bounded secondary mechanism used in committee selection and
recovery pressure. It is not the primary basis of finality safety.

## 11. External Surfaces

Current external surfaces include:

- CLI onboarding registration
- wallet onboarding registration
- lightserver visibility for:
  - `ONBOARDING` status
  - onboarding reward eligibility / score visibility
  - decoded `SCONBREG` fields
- explorer visibility for decoded `SCONBREG` outputs and admission PoW fields

These surfaces are informational.

The source of truth remains finalized chain state.
