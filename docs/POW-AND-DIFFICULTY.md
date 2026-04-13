# Ticket PoW And Difficulty

Current restarted mainnet identity:

- `network_name = mainnet`
- `network_id = 258038c123a1c9b08475216e5f53a503`
- `genesis_hash = fd5570810b163e43a90ef5e8203e8aef34c89072f5f261c4de74aa724a615211`

`docs/ECONOMICS.md` is the economics source of truth. This document describes
the live Ticket PoW behavior that remains consensus-adjacent but secondary.

## Role

Ticket PoW is secondary.

It does not define committee membership by itself.

Its role is:

- bounded extra pressure on participation
- bounded secondary modifier on committee ranking
- deterministic tie pressure within the operator-weighted model

Ticket PoW state must be interpreted relative to the current finalized history
only. Old-chain difficulty or ticket observations from the abandoned network do
not carry over after the genesis reset.

## Ticket Construction

Ticket construction on the live network is operator-based:

`sha256d("SC-EPOCH-TICKET-V2" || epoch || challenge_anchor || operator_id || nonce)`

Relevant code:

- [src/consensus/epoch_tickets.cpp](../src/consensus/epoch_tickets.cpp)

## Bounded Search

The live protocol searches exactly once per operator.

The bounded nonce range remains:

`nonce in [0, 4095]`

This keeps generation and validation cost bounded per epoch.

## Bonus Function

Let:

- `zeros = leading_zero_bits(work_hash)`
- `difficulty_bits = current epoch target`

Then:

- if `zeros < difficulty_bits`, bonus is `0`
- otherwise:

`surplus = zeros - difficulty_bits`

`smooth = floor(sqrt(surplus + 1))`

`bonus_bps = min(ticket_bonus_cap_bps, 500 + 400 * smooth)`

The active `ticket_bonus_cap_bps` is always read from:

- `active_economics_policy(network, height).ticket_bonus_cap_bps`

That means the active cap is always taken from the canonical economics policy.

## Operator Restriction

Only one PoW contribution counts per operator.

In the live protocol:

- the ticket owner is `operator_id`
- one bounded search is performed per operator
- validator splitting under the same operator adds no extra search surface
- the representative pubkey is chosen separately by a deterministic epoch-variant rule
- the operator ticket bonus becomes the operator bonus

Relevant code:

- [src/consensus/finalized_committee.cpp](../src/consensus/finalized_committee.cpp)

## Difficulty Update

Difficulty is derived per epoch from finalized history.

The live node reads:

- previous epoch difficulty from the prior finalized checkpoint
- per-epoch finalized round averages over recent finalized epochs
- quorum-relative finalized participation over recent finalized epochs

Runtime path:

- [src/node/node.cpp](../src/node/node.cpp)

The live protocol uses a conservative streak controller:

- healthy epoch:
  - active validator count exceeds committee capacity
  - average finalized round `<= 1.25`
  - average participation `>= 9500 bps`
- unhealthy epoch:
  - average finalized round `>= 2.5`
  - average participation `< 8500 bps`
- mixed signals hold difficulty unchanged

Adjustment rule:

- increase by `+1` bit only after `2` consecutive healthy epochs
- decrease by `-1` bit only after `3` consecutive unhealthy epochs
- otherwise hold

Elevated rounds alone do not soften difficulty.
Weak participation must also be present.

## Clamps

The live protocol uses a narrower bounded-search clamp:

- `MIN_BOUNDED_TICKET_DIFFICULTY_BITS = 8`
- `MAX_BOUNDED_TICKET_DIFFICULTY_BITS = 12`

Reason:

- the nonce budget is fixed at `4096` trials
- at `12` bits the expected hit count is about `1`
- above `12` bits meaningful qualifying tickets become too sparse for a bounded search
- below `8` bits tickets become too easy and the bounded bonus loses tie-break discipline

The live update still changes by at most one bit per epoch.

## Challenge Anchor

The ticket challenge anchor is finalized-state-derived.

It is not taken from:

- pending transactions
- local mempool state
- non-finalized fork state

Only finalized chain inputs affect the epoch challenge anchor.

## Full-Range Search

Ticket search evaluates the full bounded nonce range and keeps the best result.

It does not stop on the first qualifying nonce.

## Explicit Limits

- PoW does not define committee membership by itself
- PoW cannot override primary bond weighting
- PoW is attenuated by capped operator-level bond weighting in candidate strength
- PoW is counted once per operator, not once per validator identity
- the ordering bonus cap remains height-gated by the canonical economics
  schedule
- adaptive checkpoint target / minimum eligible / minimum bond are separate and
  are not controlled by Ticket PoW
- the live protocol removes best-of-N validator ticket gain under one operator

## Bounded Ticket PoW

- one operator gets one bounded search
- the nonce budget is fixed at `4096` trials
- the ticket bonus is capped by the active economics schedule
- the difficulty band is clamped to `8..12`
- the controller increases only after `2` healthy epochs
- the controller decreases only after `3` unhealthy epochs
- mixed signals hold difficulty unchanged
- representative validator selection is deterministic and ticket-independent
- the challenge anchor comes from finalized state only
- search evaluates the full bounded nonce range and keeps the best result
- bond remains primary in committee strength
- Ticket PoW remains secondary and does not define finality

For operator and exchange surfaces, the useful live fields are:

- difficulty
- difficulty clamp
- epoch health
- adjustment streaks
- nonce budget
- bonus cap

These are finalized-state observability fields. They are not additional
consensus levers.
