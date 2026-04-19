# Committee Selection

Current restarted mainnet identity:

- `network_name = mainnet`
- `network_id = fe561911730912cced1e83bc273fab13`
- `genesis_hash = eaae655a1eec3c876bd2e66d899fc8da93d205a5df36a2665f736387aa3cb78a`

## Source Of Truth

The live committee comes from the finalized committee checkpoint:

- [src/node/node.cpp](../src/node/node.cpp#L1567)
- [src/storage/db.hpp](../src/storage/db.hpp)

Checkpoint fields:

- `epoch_start_height`
- `epoch_seed`
- `ticket_difficulty_bits`
- `ordered_members`
- `ordered_ticket_hashes`
- `ordered_ticket_nonces`

`ordered_members` is the live committee member list for that epoch.

After the fresh-genesis reset, committee checkpoints from the abandoned chain
are irrelevant. Only checkpoints derived from the current finalized history and
current genesis identity are valid inputs.

## Candidate Construction

At epoch start, active validators are transformed into operator-level candidates.

Runtime path:

- [src/node/node.cpp](../src/node/node.cpp#L1635)
- [src/consensus/finalized_committee.cpp](../src/consensus/finalized_committee.cpp#L40)

For each active validator:

- `operator_id` is read from finalized validator state
- `bonded_amount` is read from finalized validator state

Then validators are grouped by `operator_id`.

Ticket ownership on the live network is operator-based:

- one bounded ticket search per operator

Important boundary:

- checkpoint committee target / checkpoint minimum eligible / checkpoint
  minimum bond are now derived from adaptive checkpoint metadata
- committee ranking still consumes the finalized checkpoint output and
  operator-based ticket model described here

## Operator Aggregation

For each operator:

`total_operator_bond = sum(validator bonded_amount under operator_id)`

`effective_weight = max(1, floor(sqrt(total_operator_bond)))`

Only one PoW contribution is kept:

- the operator ticket is generated once from `operator_id`
- the representative validator is chosen separately by a deterministic epoch-variant hash over the operator's active validator pubkeys
- representative selection does not depend on ticket grinding

The result is one committee candidate per operator.

## Deterministic Lottery

Committee ranking uses:

- `epoch_seed`
- `selection_id`
- candidate strength

The lottery hash is keyed by `selection_id`, which is the operator ID in the aggregated model.

The weighted comparator is implemented in:

- [src/consensus/finalized_committee.cpp](../src/consensus/finalized_committee.cpp#L145)

The ordering rule is:

1. compute candidate hash `sha256d("SC-COMMITTEE-V3" || seed || selection_id)`
2. compute `hash64 = first_8_bytes(candidate_hash)`
3. compute weighted ordering by cross-multiplication:

`hash64_a * strength_b < hash64_b * strength_a`

4. tie-break by full hash
5. tie-break by representative pubkey

## Candidate Strength

Strength is:

`base_weight = effective_weight(total_operator_bond)`

`bounded_bonus = min(ticket_bonus_bps, 2500)`

`bonus_scale = 1 + floor(sqrt(max(1, total_operator_bond / BASE_UNITS_PER_COIN)))`

`adjusted_bonus = bounded_bonus / bonus_scale`

`strength = max(1, base_weight * (10000 + adjusted_bonus))`

This keeps bond primary and PoW secondary.

## Operator To Validator Mapping

Committee selection happens at the operator level, but the runtime still needs validator pubkeys.

The winning operator is mapped to one concrete validator deterministically:

- the representative validator is the operator member with the best deterministic representative hash for that epoch
- that validator pubkey is stored in `ordered_members`

The checkpoint also stores the selected ticket hashes and nonces used for proposer ordering.

## Determinism Guarantees

- The same finalized validator set yields the same operator aggregation.
- The same epoch seed yields the same operator lottery ordering.
- The same winning operators and epoch yield the same representative validator pubkeys.
- Restart reconstructs the same checkpoint from finalized state.

## Anti-Split Property

Validator splitting under the same operator does not increase primary committee influence.

Reason:

- all bond under the same `operator_id` is aggregated before `sqrt` is applied
- the lottery hash is keyed by `operator_id`, not by validator pubkey
- only one PoW contribution is counted per operator

Therefore splitting under one operator changes neither:

- total operator bond
- effective operator weight
- operator lottery key

The live protocol removes that remaining split edge:

- one operator gets one ticket search
- one operator gets one ticket bonus
- representative selection is independent of ticket grinding

## Bounded Ticket PoW

- one operator maps to one bounded ticket search
- validator splitting does not add search surface
- the ticket search budget stays fixed at `4096` nonces
- ticket bonus stays bounded by the active cap
- representative selection is deterministic, epoch-variant, and ticket-independent
- committee ranking stays bond-primary through capped effective weight
- Ticket PoW only modifies ordering inside that bond-primary model
- Ticket PoW does not admit validators, set quorum, or define finality
