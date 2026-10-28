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
- `base_min_bond = 150 FLS`
- `min_bond_floor = 150 FLS`
- `min_bond_ceiling = 5,000 FLS`
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

The minimum bond a validator posts **when it joins** follows the network, from finalized state only
(no price, no setting, nobody adjusts it):

`B_N = base_min_bond * sqrt(min(active_operators, 512) / target_validators)` (validators competing
for the 128 committee seats; counted up to 512, so faked operators cannot price newcomers out)

`B_S = emitted_supply(height) / 12,800` (128 minimum bonds lock 1 % of the supply)

`min_bond(height) = clamp(min_bond_floor, min_bond_ceiling, (B_N + 2 * B_S) / 3)`

It starts at the 150 FLS floor and rises with the supply and the validator count (about 280 FLS
after 2 years and 470 after 6 on a network growing to 128-200 validators). A bond already posted is
never asked to grow: committee eligibility requires 150 FLS, the lowest any registration ever
required, so no validator that joined legally is shut out later. Joins beyond 64 per 1,000 blocks
wait in a committed queue and are admitted oldest first.

`max_effective_bond(height) = max_effective_bond_multiple * min_bond(height)`

`capped_effective_bond = min(actual_bond, max_effective_bond(height))`

`effective_weight = max(1, floor(sqrt(capped_effective_bond)))`

These helpers are implemented in:

- [src/consensus/monetary.hpp](../src/consensus/monetary.hpp)
- [src/consensus/monetary.cpp](../src/consensus/monetary.cpp)

Important boundary:

- checkpoint minimum bond for future committee derivation is adaptive

## 4. Fees, issuance and the reserve

The supply is fixed at 7,000,000 FLS and is never exceeded. Validators are paid for ever without
new coins, from a protocol reserve that cannot run dry:

- **Emission (years 1-12):** gross issuance accrues by height on a schedule declining 20 % a year;
  `30 %` of it is saved into the protocol reserve (`RESERVE_ACCRUAL_BPS = 3,000`), the remaining
  `70 %` enters epoch settlement rewards, of which `3 %` goes to onboarding rewards when eligible
  onboarding recipients exist.
- **Fees, from block 1:** every finalized fee is pooled into its epoch. At settlement half is paid
  to the epoch's validators with the rewards and half returns to the reserve
  (`FEE_RESERVE_BPS = 5,000`).
- **Burns:** slashed bonds (SCBURN outputs) are not destroyed: their value returns to the reserve
  at settlement; burn outputs do not stay in the coin set.
- **Reserve payout (after year 12):** each epoch pays out `RESERVE_PAYOUT_BPS_PER_YEAR = 500` (5 %
  a year) of the reserve's balance, a fixed fraction, never a fixed amount, so it never empties; fees
  and burns keep refilling it. In the long run validators earn what users pay in fees, and the
  reserve smooths that over decades.
- **Base fee:** every transaction pays at least `base_fee_per_kib` per started KiB of its size. After
  each block it moves by at most 1/8 towards keeping blocks half full (fullness is the larger of the
  byte and record shares), with a floor of 1 unit. It follows demand only, so it works at any FLS
  price without anyone setting it. Timed transactions' bodies are exempt (their fee is prepaid).
  `get_status` reports it; `finalis-cli send` pays it automatically.

Primary emission constants:

- `TOTAL_SUPPLY_COINS = 7,000,000`
- `EMISSION_YEARS = 12`
- `BLOCKS_PER_YEAR_365 = 175,200`
- `EMISSION_BLOCKS = 2,102,400`
- `EMISSION_DECAY_NUM = 4`, `EMISSION_DECAY_DEN = 5`
- `RESERVE_ACCRUAL_BPS = 3,000`, `FEE_RESERVE_BPS = 5,000`, `RESERVE_PAYOUT_BPS_PER_YEAR = 500`
- `BLOCK_TIME_TARGET_SECONDS = 180`

Per validator (no fees assumed): about 64,000 FLS in year 1 with 16 validators (8,000 with 128),
6,600 in year 13, 2,700 in year 30 and 1,000 in year 50 with 16 validators. The reserve is protocol
state, not a wallet: nobody can spend it.

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
