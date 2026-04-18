# Reward Settlement

Current restarted mainnet identity:

- `network_name = mainnet`
- `network_id = 258038c123a1c9b08475216e5f53a503`
- `genesis_hash = fd5570810b163e43a90ef5e8203e8aef34c89072f5f261c4de74aa724a615211`

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
  - `10%` of gross issuance is diverted into protocol reserve accrual
  - `90%` of gross issuance accrues into validator settlement rewards
- after the cap:
  - new issuance is zero
  - finalized epoch fees are pooled and settled at the first finalized height of
    the next epoch
  - reserve subsidy may top up the pooled epoch fees, subject to deterministic
    caps

This remains necessary because the final QC signer set is only known after the
transition is finalized.

After the fresh-genesis reset, settlement rows, reward accrual expectations,
and reserve accounting from the abandoned chain are not valid inputs to the
current restarted mainnet.

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

- `expected_participation_units` counts blocks where a validator was in the
  finalized committee and expected to sign
- `observed_participation_units` counts finalized committee-member credit for
  that validator on that block

This keeps settlement replay-safe. It does not depend on whichever valid quorum
signature subset happened to arrive first on one node.

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

## Post-Cap Subsidy

After `EMISSION_BLOCKS`, the closed epoch payout pool is:

- `settled_epoch_fees + reserve_subsidy_units`

Reserve subsidy is deterministic:

- `target_support = eligible_validator_count * POST_CAP_SUPPORT_UNITS_PER_ELIGIBLE_VALIDATOR_PER_EPOCH`
- `support_gap = max(0, target_support - settled_epoch_fees)`
- `spendable_reserve = max(0, reserve_balance - POST_CAP_RESERVE_FLOOR_UNITS)`
- `runway_cap = reserve_balance / POST_CAP_MIN_RESERVE_RUNWAY_EPOCHS`
- `reserve_subsidy = min(support_gap, spendable_reserve, runway_cap)`

Eligibility is derived from the adjusted reward-score map:

- validators with post-penalty score `> 0` are eligible

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
