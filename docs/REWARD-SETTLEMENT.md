# Reward Settlement

Mainnet identity (pre-launch):

- `network_name = mainnet`
- `network_id = fe561911730912cced1e83bc273fab13`
- `genesis_hash`: published at launch (mainnet has not launched)

`docs/ECONOMICS.md` is the source of truth for economics policy. This document
describes how finalized transition accrual and epoch settlement consume the
active economics policy.

All economics-sensitive settlement logic resolves through:

- `active_economics_policy(network, height)`
- `reward_weight(network, height, ...)`

Relevant code:

- [src/common/network.cpp](../src/common/network.cpp)
- [src/consensus/monetary.cpp](../src/consensus/monetary.cpp)
- [src/node/node.cpp](../src/node/node.cpp)

## Model

Fees and issuance are separated.

- before the cap:
  - current-block fees remain immediate on the frontier transition path
  - issuance accrues during the epoch
  - `30%` of gross issuance is diverted into protocol reserve accrual
  - `90%` of gross issuance accrues into validator settlement rewards
- after the cap:
  - new issuance is zero
  - finalized epoch fees are pooled and settled at the first finalized height of
    the next epoch
  - reserve subsidy may top up the pooled epoch fees, subject to deterministic
    caps

This remains necessary because the final QC signer set is only known after the
transition is finalized.

## Per-Transition Accrual

For each finalized transition:

1. determine the containing settlement epoch
2. add the validator portion of `reward_units(height)` to
   `state.total_reward_units`
3. add the reserve portion of `reward_units(height)` to
   `state.reserve_accrual_units`
4. after the cap, add finalized transaction fees to `state.fee_pool_units`
5. for each finalized committee member:
   - add `reward_weight(network, height, finalized_active_operators, bonded_amount)`
6. for the proposer:
   - add another `reward_weight(...)`

The active schedule entry for that height determines:

- schedule-driven effective-bond inputs
- capped effective bond
- reward weighting behavior
- participation threshold used later at settlement time

Settlement uses the capped-bond helper flow:

`actual_bond -> validator_min_bond_units -> validator_max_effective_bond_units -> capped_effective_bond_units -> reward_weight`

## Settlement Boundary

Settlement happens at the first finalized height of the next epoch.

The rule is:

- if height `H` is the first finalized height of epoch `E + 1`
- settle the rewards accrued for epoch `E`

Boundary lookup lives in:

- [src/node/node.cpp](../src/node/node.cpp)

## Persisted State

Settlement is persisted as `EpochRewardSettlementState` with:

- `epoch_start_height`
- `total_reward_units`
- `fee_pool_units`
- `reserve_accrual_units`
- `reserve_subsidy_units`
- `settled`
- `reward_score_units`
- `onboarding_score_units`
- `expected_participation_units`
- `observed_participation_units`

Persistence lives in:

- [src/storage/db.hpp](../src/storage/db.hpp)
- [src/storage/db.cpp](../src/storage/db.cpp)

## Participation Adjustment

Settlement applies a finalized participation adjustment using the active
schedule entry:

- if `participation_bps >= participation_threshold_bps`, no penalty applies
- otherwise:
  - `adjusted_score = base_score * participation_bps / participation_threshold_bps`

The threshold is taken from:

- `active_economics_policy(network, height).participation_threshold_bps`

Participation inputs are derived only from finalized committee data:

- participation of height `H` is recorded by its child transition `H+1` in
  `prev_finality_signers`: the votes the `H+1` proposer observed for
  `(H, round_H, transition_id_H)`, as pubkey and signature pairs, sorted and
  unique, all verified, at least the quorum of `H`'s committee (empty only when
  `H` is genesis)
- `expected_participation_units` counts, for each member of `H`'s committee, one
  unit when `H+1` is applied
- `observed_participation_units` counts one unit for each of those members that
  appears in `H+1`'s `prev_finality_signers`
- these units are booked into the epoch of `H+1`; emission, fees and the
  leader score for `H+1` are booked there too

This keeps settlement replay-safe: the participation input is part of the
finalized transition itself, so every node replays the same set. It does not
depend on whichever valid quorum signature subset happened to arrive first on
one node, nor on the quorum-truncated finality certificate (which would always
drop the highest-sorting pubkeys). Validator liveness (suspend / exit miss-rate
windows) uses the same participation record.

## Onboarding Settlement Slice

The live settlement path contains a separate onboarding reward slice.

Current rule:

- `3%` of settlement rewards are carved from the validator settlement reward
  slice
- the onboarding slice is distributed only over `onboarding_score_units`
- the onboarding score map is derived from finalized epoch tickets only
- fees and reserve subsidy are not shared with the onboarding slice

Operational consequence:

- a participant may appear in `onboarding_score_units` without first entering registry status `ONBOARDING`
- registry onboarding and onboarding reward eligibility are separate concerns

If `onboarding_score_units` is empty:

- the onboarding carve-out is suppressed
- the full settlement reward remains in the validator pool

This keeps total payout exact while avoiding payment to nonexistent onboarding
recipients.

## Fees, recycling and the reserve payout

At every height the closed epoch payout pool is:

- `settlement_rewards + settled_epoch_fees + reserve_subsidy_units`

with

- `settled_epoch_fees = fee_pool - fee_reserve_share(fee_pool)`: validators get half of the epoch's
  fees (from block 1, not only after the cap); `fee_reserve_share = fee_pool * FEE_RESERVE_BPS / 10,000`
- `reserve_subsidy_units = reserve_payout_units(height, reserve_balance + reserve_accrual)`: zero
  before `EMISSION_BLOCKS`, then `balance * RESERVE_PAYOUT_BPS_PER_YEAR / (10,000 * EPOCHS_PER_YEAR_365)`

At settlement the reserve becomes:

- `reserve + reserve_accrual + fee_reserve_share(fee_pool) + recycled_units - reserve_subsidy_units`

where `recycled_units` is the value of the epoch's burn (SCBURN) outputs, which do not stay in the
coin set. A fixed fraction never empties the reserve, and the supply never exceeds 7,000,000 FLS.

Distribution uses the same adjusted reward scores already used for normal epoch
settlement. There is no equal split and no validator-controlled treasury key.

## Exactly-Once Rule

All finalized paths converge through the unified finalized transition in
[src/node/node.cpp](../src/node/node.cpp).

That path does both:

- settlement boundary transition
- finalized transition reward accrual

This keeps settlement behavior identical whether finalization arrived through:

- local quorum
- direct finalized transition delivery
- buffered sync application

## Restart And Replay

Settlement rows are treated as derived state.

On restart:

- the node rebuilds settlement state from finalized frontier history
- stale derived rows are erased and rewritten

The finalized chain remains the source of truth.

## Guarantee

- settlement remains exactly once per epoch boundary
- reward attribution remains deterministic
- reserve accrual and reserve subsidy remain replayable derived state
- settlement uses the same canonical economics helpers as validator admission
  and committee influence
