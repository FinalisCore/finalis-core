# Economics

`Finalis Core` now separates:

- a height-gated economics policy schedule
- an adaptive checkpoint control plane

This document explains both and their boundary.

## 1. Height-gated policy schedule

Consensus code reads schedule-driven economics through:

- `active_economics_policy(network, height)`

The canonical schedule lives in:

- [src/common/network.hpp](../src/common/network.hpp)
- [src/common/network.cpp](../src/common/network.cpp)

Consensus activation is based on block height only. Wall clock time is not used
for economics activation.

### 1.1 Schedule fields

Each schedule entry contains:

- `activation_height`
- `target_validators`
- `base_min_bond`
- `min_bond_floor`
- `min_bond_ceiling`
- `max_effective_bond_multiple`
- `participation_threshold_bps`
- `ticket_bonus_cap_bps`

For a given height, the active entry is the one with the greatest
`activation_height <= height`.

### 1.2 Current configured schedule

The mainnet schedule currently exposes one live active entry from
genesis:

- `activation_height = 0`
- `target_validators = 16`
- `base_min_bond = 100 FLS`
- `min_bond_floor = 50 FLS`
- `min_bond_ceiling = 500 FLS`
- `max_effective_bond_multiple = 10`
- `participation_threshold_bps = 8000`
- `ticket_bonus_cap_bps = 1000`

Future policy changes are implementation details until they are explicitly
activated and documented as live protocol changes.

Important boundary:

- these scheduled entries still matter for reward policy and ticket bonus caps
- they no longer directly step checkpoint committee target / checkpoint minimum
  eligible / checkpoint minimum bond

## 2. Adaptive checkpoint control plane

Checkpoint derivation now uses a deterministic no-fork adaptive regime.

It derives, at epoch boundaries only:

- `adaptive_target_committee_size`
- `adaptive_min_eligible`
- `adaptive_min_bond`

from finalized qualified operator depth.

### 2.1 Qualified depth

`qualified_depth` counts distinct operators that are:

- lifecycle-active
- checkpoint-bond-qualified
- availability-eligible

This uses finalized validator state plus finalized projected availability state
only.

### 2.2 Live adaptive rule

The live adaptive checkpoint rule is:

- allowed targets: `{16, 24}`
- initial target: `16`
- expand `16 -> 24` if `qualified_depth >= 30` for `4` consecutive epochs
- contract `24 -> 16` if `qualified_depth <= 22` for `6` consecutive epochs
- `adaptive_min_eligible = adaptive_target_committee_size + 3`
- `adaptive_min_bond = clamp(150 * sqrt(adaptive_target_committee_size / max(qualified_depth, 1)), 150, 500)`
- availability minimum bond = adaptive minimum bond

All arithmetic is deterministic integer arithmetic in base units. No floating
point is used in consensus.

## 3. Security resource

The primary scarce resource remains bonded stake aggregated at the operator
level.

Let:

`operator_total_bond = sum(active validator bonds under one operator)`

The canonical reward/admission helpers derive:

`min_bond(height) = clamp(min_bond_floor, min_bond_ceiling, base_min_bond * sqrt(target_validators / max(1, active_operators)))`

`max_effective_bond(height) = max_effective_bond_multiple * min_bond(height)`

`capped_effective_bond = min(actual_bond, max_effective_bond(height))`

`effective_weight = max(1, floor(sqrt(capped_effective_bond)))`

These helpers are implemented in:

- [src/consensus/monetary.hpp](../src/consensus/monetary.hpp)
- [src/consensus/monetary.cpp](../src/consensus/monetary.cpp)

Important boundary:

- checkpoint minimum bond for future committee derivation is adaptive

## 4. Fees and issuance

Fees, issuance, and reserve support are epoch-settled.

For each finalized transition:

- before the emission cap:
  - gross issuance accrues deterministically by height
  - `10%` of gross issuance is accrued into protocol reserve
  - the remaining `90%` enters epoch settlement rewards
  - within epoch settlement rewards, `3%` is carved into the onboarding bucket
    when eligible onboarding recipients exist
- after the emission cap:
  - new issuance is zero
  - finalized transaction fees are pooled into the closed epoch instead of being
    paid immediately
- settlement at the next epoch boundary applies finalized participation
  adjustment using the live policy and distributes the closed epoch pool

So the live mainnet settlement split is:

- `10%` reserve accrual from gross issuance
- `87.3%` validator settlement rewards from gross issuance when onboarding is
  populated
- `2.7%` onboarding rewards from gross issuance when onboarding is populated

Important boundary:

- the `3%` onboarding carve-out is taken from settlement rewards, not from
  reserve accrual
- if the onboarding score set is empty, that `3%` remains in the validator
  settlement pool

Primary emission constants:

- `TOTAL_SUPPLY_COINS = 7,000,000`
- `EMISSION_YEARS = 12`
- `BLOCKS_PER_YEAR_365 = 175,200`
- `EMISSION_BLOCKS = 2,102,400`
- `EMISSION_DECAY_NUM = 4`
- `EMISSION_DECAY_DEN = 5`
- `RESERVE_ACCRUAL_BPS = 1,000`
- `BLOCK_TIME_TARGET_SECONDS = 180`

So the current code has:

- exact primary emission total: `7,000,000 FLS`
- annual issuance declines by `20%` year-over-year
- yearly budgets are precomputed deterministically and sum exactly to the cap
- reserve accrual during emission totals `10%` of gross issuance
- zero new issuance after that

It is therefore a strict hard-cap system in the current implementation.

Post-cap continuity support is deterministic, not discretionary:

- epoch fees remain pooled and distributed at settlement
- reserve subsidy is only available after the cap
- reserve subsidy is computed from:
  - eligible validator count after participation penalty
  - the closed epoch fee pool
  - a hard reserve floor
  - a minimum reserve runway cap
- reserve is protocol state, not a validator-controlled treasury wallet

## 5. Participation and rewards

On the live path:

- capped bond is used for reward scoring
- the participation penalty threshold is taken from
  `active_economics_policy(height).participation_threshold_bps`
- `ONBOARDING` recipients are excluded from validator participation accounting
  and validator reward scoring
- onboarding rewards are derived from a separate finalized score map based on
  best finalized epoch ticket only, independent of registry onboarding status

Relevant code:

- [src/node/node.cpp](../src/node/node.cpp)
- [src/consensus/monetary.cpp](../src/consensus/monetary.cpp)

Onboarding-specific rules are specified in:

- [docs/ONBOARDING-PROTOCOL.md](ONBOARDING-PROTOCOL.md)

## 6. Ticket PoW

Ticket PoW is secondary. It does not define committee membership by itself.

Its live cap remains schedule-driven:

- `active_economics_policy(height).ticket_bonus_cap_bps`

Relevant code:

- [src/consensus/epoch_tickets.cpp](../src/consensus/epoch_tickets.cpp)
- [src/consensus/finalized_committee.cpp](../src/consensus/finalized_committee.cpp)

## 7. Admission boundary

Validator admission and script validation still read the canonical monetary bond
helpers used by reward logic.

Current code preserves historical behavior for already-active validators.
Dynamic minimum bond affects admission checks and economics-dependent helper
outputs; it does not introduce a new forced-eviction rule for incumbents.

Checkpoint minimum bond is separate and adaptive for future checkpoint
eligibility only.

Consensus boundary for economics-facing operators:

- economic policy does not relax ingress validity rules
- certified ingress remains epoch-pinned to
  `committee_epoch_start(finalized_height + 1)`
- stale-epoch ingress is rejected before any economics effects from contained
  transactions can be applied
- script-level admission rules (`SCONBREG`, `SCVALJRQ`, `SCVALREG`) are enforced
  with aligned semantics across legacy `Tx` and transparent outputs in `TxV2`

## 8. Operator visibility

`finalis-cli economics_status` reports the active policy fields, including:

- `economics_activation_height`
- `ticket_policy`
- `target_validators`
- `base_min_bond`
- `min_bond_floor`
- `min_bond_ceiling`
- `max_effective_bond_multiple`
- `participation_threshold_bps`
- `ticket_bonus_cap_bps`

That CLI output is derived from the same resolver used by consensus.

Checkpoint-adaptive observability is exposed separately through:

- node runtime status
- lightserver `get_status`
- verbose `get_committee`
- persisted adaptive epoch telemetry
