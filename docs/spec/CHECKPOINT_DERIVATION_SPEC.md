# CHECKPOINT_DERIVATION_SPEC

Current restarted mainnet identity:

- `network_name = mainnet`
- `network_id = 258038c123a1c9b08475216e5f53a503`
- `genesis_hash = fd5570810b163e43a90ef5e8203e8aef34c89072f5f261c4de74aa724a615211`

## 1. Scope

This specification defines canonical derivation of the next epoch finalized committee checkpoint from finalized frontier state, specifically finalized validator lifecycle state, finalized projected availability state, and prior checkpoint metadata at the canonical epoch boundary.

It covers:

- checkpoint boundary selection
- validator/operator eligibility
- availability gating
- fallback and hysteresis
- candidate aggregation
- deterministic committee selection
- proposer schedule derivation
- checkpoint metadata
- replay and restart invariants

This specification is normative for the live checkpoint derivation path.
Availability state completeness, persistence, and replay equivalence for the live checkpoint inputs are specified in [AVAILABILITY_STATE_COMPLETENESS.md](AVAILABILITY_STATE_COMPLETENESS.md).
A bounded formal model for determinism, replay equivalence, hysteresis, evidence isolation, and ordering independence is provided in [../../formal/checkpoint_availability.tla](../../formal/checkpoint_availability.tla), with reproducible TLC suite configurations under [../../formal/](../../formal/).
Adaptive regime observability is exposed operationally through node/lightserver status and persisted epoch telemetry, but those observability fields are not additional derivation inputs.

After the deliberate genesis reset, checkpoints or replay artifacts from the
abandoned chain are outside this specification’s canonical input domain for the
current deployment.

## 2. Primitive Types

```text
type Height                = uint64
type Epoch                 = uint64
type Round                 = uint32
type ValidatorPubKey       = bytes[32]
type OperatorId            = bytes[32]
type Hash256               = bytes[32]
type Hash64                = uint64
type Amount                = uint64
type BasisPoints           = uint32
type Nonce                 = uint64
type Bool                  = { false, true }

type DerivationMode        = { NORMAL, FALLBACK }
type FallbackReason        = {
    NONE,
    INSUFFICIENT_ELIGIBLE_OPERATORS,
    HYSTERESIS_RECOVERY_PENDING
}

type AvailabilityStateEnum = {
    WARMUP,
    ACTIVE,
    PROBATION,
    EJECTED
}
```

All arithmetic is integer-only.

## 2.1 Operational Observability

The live implementation persists one adaptive telemetry snapshot per epoch and derives fixed-window rolling observability metrics from that persisted history only.

Operational fields include:

- `qualified_depth`
- `adaptive_target_committee_size`
- `adaptive_min_eligible`
- `adaptive_min_bond`
- `slack`
- `target_expand_streak`
- `target_contract_streak`
- `checkpoint_derivation_mode`
- `checkpoint_fallback_reason`
- `fallback_rate_bps`
- `sticky_fallback_rate_bps`
- persisted telemetry summary fields such as `sample_count`,
  `fallback_epochs`, and `sticky_fallback_epochs`

These fields are observability-only and must not influence canonical checkpoint derivation.

## 3. Helpers

```text
epoch_size() -> uint64 = 32

epoch_of_height(h: Height) -> Epoch =
    if h == 0 then 0 else ((h - 1) / 32) + 1

epoch_start_height(e: Epoch) -> Height =
    if e == 0 then 0 else ((e - 1) * 32) + 1

epoch_end_height(e: Epoch) -> Height =
    if e == 0 then 0 else e * 32

checkpoint_derivation_height_for_epoch(e: Epoch) -> Height =
    epoch_end_height(e)
```

The checkpoint for epoch `E+1` is derived from finalized state at height `epoch_end_height(E)`.

## 4. Canonical Inputs

Derivation of `CP[E+1]` consumes exactly:

```text
InputState(E):
    finalized_tip_height               = H = epoch_end_height(E)
    finalized_frontier_state_at_H
    validator_registry_state_at_H
    availability_state_at_H
    active_economics_policy_at_H
    previous_checkpoint                = CP[E]
```

No local clocks, peer observations, mempool state, or wall-clock state may affect derivation.

`active_economics_policy_at_H` is the single live economics policy resolved at
height `H`. It supplies schedule-owned fields that remain consensus-relevant
for checkpoint derivation, such as `ticket_bonus_cap_bps`. Adaptive checkpoint
fields such as `dynamic_min_bond`, `committee_size`, and
`availability_min_eligible_operators` are not read from a version ladder; they
are derived canonically from finalized checkpoint inputs and the previous
checkpoint metadata.

`finalized_frontier_state_at_H` is not a generic opaque chain snapshot. For
checkpoint derivation it matters only insofar as it determines:

- finalized validator lifecycle state at `H`
- finalized projected availability state at `H`
- the canonical previous checkpoint and its adaptive metadata

`availability_state_at_H` means that finalized projected availability view
after normalization and live validation. It is not arbitrary persisted
`AvailabilityPersistentState` bytes. Persisted availability state is admissible
only after passing the replay/restore boundary defined in
[AVAILABILITY_STATE_COMPLETENESS.md](AVAILABILITY_STATE_COMPLETENESS.md) and
yielding the same canonical projected availability state that replay from
finalized frontier history would produce.

## 5. Normative State Objects

### 5.1 Validator Registry View

```text
ValidatorRecord:
    validator_pubkey: ValidatorPubKey
    operator_id: OperatorId
    bonded_amount: Amount
    has_bond: Bool
    joined_height: Height
    status: lifecycle-derived registry state
```

### 5.2 Availability View

```text
AvailabilityRecord:
    operator_id: OperatorId
    state: AvailabilityStateEnum
    bond: Amount
    service_score: int64
    warmup_epochs: uint64
    retained_prefix_count: uint64
    audit-derived counters used by operator_is_eligible
```

These records are elements of the canonical finalized projected availability
view consumed by checkpoint derivation, not a direct dump of arbitrary
persisted availability storage.

Any field that affects availability checkpoint eligibility must be either fully committed/persisted or fully recomputable from finalized frontier history.

Here, `finalized frontier history` means the canonical sequence of finalized
frontier transitions together with the persisted finality certificate for each
finalized height and the committed frontier storage required to validate those
transitions.

### 5.3 Economics View

```text
EconomicsState:
    dynamic_min_bond: Amount
    committee_size: uint32
    availability_min_eligible_operators: uint32
    qualified_depth: uint64
    target_expand_streak: uint32
    target_contract_streak: uint32
    ticket_bonus_cap_bps: BasisPoints
    difficulty_bits: uint8
```

Adaptive live rule:

```text
allowed_targets = {16, 24}
initial_target = 16
expand 16 -> 24 if qualified_depth >= 30 for 4 consecutive epochs
contract 24 -> 16 if qualified_depth <= 22 for 6 consecutive epochs
availability_min_eligible_operators = committee_size + 3
dynamic_min_bond = clamp(150 * sqrt(committee_size / max(qualified_depth, 1)), 150, 500)
availability_min_bond = dynamic_min_bond
```

All amounts above are in whole-coin units conceptually and are implemented in deterministic integer base-unit arithmetic.

### 5.4 Operator Committee Input

```text
OperatorCommitteeInput:
    operator_id: OperatorId
    validator_pubkey: ValidatorPubKey
    bonded_amount: Amount
    ticket_work_hash: Hash256
    ticket_nonce: Nonce
    ticket_bonus_bps: BasisPoints
```

### 5.5 Aggregated Candidate

```text
FinalizedCommitteeCandidate:
    representative_pubkey: ValidatorPubKey
    selection_id: bytes[32]
    bonded_amount: Amount
    capped_bonded_amount: Amount
    effective_weight: uint64
    ticket_work_hash: Hash256
    ticket_nonce: Nonce
    ticket_bonus_bps: BasisPoints
    ticket_bonus_cap_bps: BasisPoints
```

Candidate normalization requirement:

```text
candidate.ticket_bonus_bps <= candidate.ticket_bonus_cap_bps
```

During aggregation, the stored candidate bonus must already be capped to the
active policy cap. The later `strength(candidate)` definition still applies
`min(ticket_bonus_bps, ticket_bonus_cap_bps)` defensively, but conformant
aggregation must not emit over-cap candidate bonus values in the first place.

Representative ticket-field requirement:

For each aggregated operator candidate, the carried ticket fields:

- `ticket_work_hash`
- `ticket_nonce`
- `ticket_bonus_bps`

must be taken from the same canonical representative pubkey chosen for that
operator during aggregation. They are not independently re-selected from some
other validator under the same operator.

Representative selection rule:

For each operator, choose the canonical representative pubkey by:

```text
operator_representative_hash(operator_id, height, pubkey) =
    sha256d("SC-REP-V1" || operator_id || u64le(height) || pubkey)
```

The canonical representative is the validator pubkey with the smallest
`operator_representative_hash(operator_id, height, pubkey)`. If multiple
validator pubkeys produce the same hash, choose the lexicographically smallest
pubkey.

Selection-id normalization requirement:

```text
effective_selection_id(candidate) =
    if candidate.selection_id == 0x00..00:
        candidate.representative_pubkey
    else:
        candidate.selection_id
```

All selection-hash computation and all ordering rules that refer to
`selection_id` must use `effective_selection_id(candidate)`, not the raw stored
field.

### 5.6 Candidate Strength

The final committee comparator does not use raw ticket bonus directly. It uses
the live candidate strength function:

```text
base_weight(candidate) =
    if candidate.effective_weight != 0:
        candidate.effective_weight
    else:
        effective_weight(candidate.bonded_amount)

bounded_bonus(candidate) =
    min(candidate.ticket_bonus_bps, candidate.ticket_bonus_cap_bps)

bonded_coins(candidate) =
    max(1, floor(candidate.bonded_amount / BASE_UNITS_PER_COIN))

bonus_scale(candidate) =
    1 + integer_sqrt(bonded_coins(candidate))

adjusted_bonus(candidate) =
    floor(bounded_bonus(candidate) / bonus_scale(candidate))

strength(candidate) =
    max(1, base_weight(candidate) * (10_000 + adjusted_bonus(candidate)))
```

This bonus damping is consensus-significant. Any implementation that compares
selection hashes against raw ticket bonus, or against a differently scaled
bonus term, is not conformant.

## 6. Canonical Eligibility

Canonical helper:

```text
committee_eligibility_at_checkpoint(
    validator_record,
    availability_record_or_none,
    economics_state,
    derivation_mode,
    checkpoint_height
) -> Bool
```

### 6.1 Base Lifecycle-And-Bond Eligibility

```text
validator_lifecycle_active(v, checkpoint_height) =
    ValidatorRegistry::is_active_for_height(v, checkpoint_height)

base_eligible(v, econ, checkpoint_height) =
    validator_lifecycle_active(v, checkpoint_height)
    AND v.has_bond
    AND (
        v.joined_height == 0
        OR v.bonded_amount >= econ.dynamic_min_bond
    )
```

This captures current live behavior:

- genesis/bootstrap validators are grandfathered below later dynamic bond floors
- post-genesis joins are re-gated by the checkpoint bond floor

### 6.2 Availability Eligibility

```text
availability_eligible(a) =
    a exists
    AND a.state == ACTIVE
    AND operator_is_eligible(a) == true
```

### 6.3 Mode-Conditioned Final Eligibility

```text
committee_eligibility_at_checkpoint(v, a, econ, mode, checkpoint_height) =
    if NOT base_eligible(v, econ, checkpoint_height):
        false
    else if mode == FALLBACK:
        true
    else:
        availability_eligible(a)
```

The function consumes `mode` as input. It must not recompute fallback mode internally.

## 7. Eligible Operator Counting

Let:

```text
availability_eligible_operator_count(H) =
    availability::count_eligible_operators(
        CanonicalAvailabilityStateAtH,
        availability_config_with_min_bond(live_availability_config, dynamic_min_bond_at_H)
    )
```

This count is computed from the canonical projected availability view at `H`,
not from final committee membership and not by re-aggregating validator
records. The availability view consumed here is already normalized and unique
by operator id, so the count is exactly the live
`availability::count_eligible_operators(...)` result on that canonical view.

## 8. Fallback And Hysteresis

Let:

```text
eligible = availability_eligible_operator_count(H)
min      = economics_state_at_H.availability_min_eligible_operators
prev     = CP[E].derivation_mode
```

Normative rule:

```text
if prev == NORMAL:
    if eligible < min:
        mode   = FALLBACK
        reason = INSUFFICIENT_ELIGIBLE_OPERATORS
    else:
        mode   = NORMAL
        reason = NONE

if prev == FALLBACK:
    if eligible >= min + 1:
        mode   = NORMAL
        reason = NONE
    else if eligible == min:
        mode   = FALLBACK
        reason = HYSTERESIS_RECOVERY_PENDING
    else:
        mode   = FALLBACK
        reason = INSUFFICIENT_ELIGIBLE_OPERATORS
```

Derived observability flag:

```text
fallback_sticky(mode, reason) =
    (mode == FALLBACK AND reason == HYSTERESIS_RECOVERY_PENDING)
```

## 9. Canonical Ordering Requirements

### 9.1 Operator Id Ordering

```text
sort operator ids ascending lexicographically by bytes
deduplicate exact duplicates
```

### 9.2 Pre-Aggregation Input Ordering

`OperatorCommitteeInput` entries are sorted by:

```text
1. operator_id ascending
2. validator_pubkey ascending
3. bonded_amount ascending
4. ticket_work_hash ascending
5. ticket_nonce ascending
6. ticket_bonus_bps ascending
```

### 9.3 Aggregated Candidate Ordering Before Selection

Aggregated candidates are sorted by:

```text
1. effective_selection_id(candidate) ascending
2. representative_pubkey ascending
```

### 9.4 Final Selection Comparator

Derived values:

```text
candidate_hash(candidate, seed) =
    sha256d("SC-COMMITTEE-V3" || seed || effective_selection_id(candidate))

selection_hash64(candidate, seed) =
    uint64_big_endian(candidate_hash(candidate, seed)[0..7])
```

For candidates `A` and `B`, `A outranks B` by:

```text
1. Compare (selection_hash64(A, seed) / strength(A)) vs (selection_hash64(B, seed) / strength(B))
   using exact widened integer cross-multiplication only.
2. If equal, compare candidate_hash(A, seed) vs candidate_hash(B, seed) ascending.
3. If equal, compare effective_selection_id(candidate) ascending.
4. If equal, compare representative_pubkey ascending.
5. If equal, compare effective_weight descending.
6. If equal, compare capped_bonded_amount descending.
7. If equal, compare bonded_amount descending.
8. If equal, compare ticket_bonus_bps descending.
9. If equal, compare ticket_work_hash ascending.
10. If equal, compare ticket_nonce ascending.
11. If equal, compare ticket_bonus_cap_bps ascending.
```

The comparator must define a total order.

## 10. Candidate Construction And Aggregation

For each validator record at `H`:

1. compute canonical operator id
2. join with availability record if any
3. evaluate `committee_eligibility_at_checkpoint(...)`
4. if eligible, emit one `OperatorCommitteeInput`
5. aggregate operator-level inputs using live economics
   During aggregation, choose the canonical representative pubkey for each
   operator by the live `operator_representative_hash(operator_id, height, pubkey)`
   ordering, tie-broken by pubkey ascending.
   Carry the representative pubkey's ticket fields into the aggregated
   candidate.
6. produce one canonical candidate per operator selection entry

If multiple validator records map to one operator, aggregation must be deterministic and operator-based.

## 11. Committee Selection

Given candidate list `C` and target committee size `K`:

```text
committee = first min(K, len(C)) candidates under the final total-order comparator
```

Unstable top-K selection is forbidden.

## 12. Proposer Schedule Derivation

The proposer schedule for epoch `E+1` is derived exclusively from `CP[E+1]`:

```text
proposer_schedule(E+1) =
    deterministic_permutation(CP[E+1].committee_members, CP[E+1].seed_material)
```

The proposer schedule inherits committee filtering automatically.

## 13. Checkpoint Artifact

The checkpoint for epoch `E+1` contains at least:

```text
FinalizedCommitteeCheckpoint:
    epoch_start_height: Height
    derivation_mode: DerivationMode
    fallback_reason: FallbackReason
    availability_eligible_operator_count: uint64
    availability_min_eligible_operators: uint64
    adaptive_target_committee_size: uint64
    adaptive_min_eligible: uint64
    adaptive_min_bond: uint64
    qualified_depth: uint64
    target_expand_streak: uint32
    target_contract_streak: uint32
    committee_members: ordered list
    committee operator ids: ordered list
    committee weight/ticket metadata: ordered lists
```

`fallback_sticky` may be stored or derived, but must be explicit in status surfaces.

Genesis checkpoints must carry the same derivation metadata fields as later checkpoints.

## 14. Serialization And Compatibility

### 14.1 Consensus Artifacts

Unknown enum values for checkpoint derivation mode or fallback reason must not be silently reinterpreted in checkpoint artifacts.

Current safe codec policy:

- reject unknown derivation mode values
- reject unknown fallback reason values

### 14.2 DB Roundtrip

Checkpoint DB parsing must remain backward-compatible for already stored checkpoint records without fallback-reason bytes, while remaining exact and deterministic for all fields now committed.

## 15. Replay And Restart Invariants

For identical:

- genesis
- finalized frontier history
- persisted checkpoint DB consistent with finalized frontier history

the following must be identical after replay or restart:

```text
- validator registry state at H
- canonical projected availability state at H
- derivation_mode
- fallback_reason
- availability_eligible_operator_count
- committee member set
- committee member ordering
- proposer schedule
- checkpoint commitment
```

Runtime status snapshot fields are one-way observability only:

```text
checkpoint -> runtime status
not runtime status -> checkpoint
```

## 16. Reference Pseudocode

```text
function DeriveCheckpointForEpoch(next_epoch, S):
    H       := epoch_end_height(next_epoch - 1)
    prev_cp := CP[next_epoch - 1]
    V       := CanonicallyOrderedValidatorRecords(S.validator_registry_state_at_H)
    AIndex  := CanonicalAvailabilityIndex(S.availability_state_at_H)
    prior_min_bond := if prev_cp exists then prev_cp.adaptive_min_bond else 150
    prev_mode := if prev_cp exists then prev_cp.derivation_mode else NORMAL

    qualified_depth :=
        count(distinct operator_id) such that:
            lifecycle-active
            bond-qualified at prior_min_bond
            availability-eligible under availability_min_bond = prior_min_bond

    next_target, expand_streak, contract_streak :=
        AdaptiveTargetFrom(prev_cp, qualified_depth)

    econ.committee_size := next_target
    econ.availability_min_eligible_operators := next_target + 3
    econ.dynamic_min_bond := clamp(150 * sqrt(next_target / max(qualified_depth, 1)), 150, 500)

    eligible_cnt := count_eligible_operators(
        CanonicalAvailabilityStateAtH = S.availability_state_at_H,
        cfg = availability_config_with_min_bond(live_availability_config, econ.dynamic_min_bond)
    )
    min_ops      := econ.availability_min_eligible_operators

    if prev_mode == NORMAL:
        if eligible_cnt < min_ops:
            mode   := FALLBACK
            reason := INSUFFICIENT_ELIGIBLE_OPERATORS
        else:
            mode   := NORMAL
            reason := NONE
    else:
        if eligible_cnt >= min_ops + 1:
            mode   := NORMAL
            reason := NONE
        else if eligible_cnt == min_ops:
            mode   := FALLBACK
            reason := HYSTERESIS_RECOVERY_PENDING
        else:
            mode   := FALLBACK
            reason := INSUFFICIENT_ELIGIBLE_OPERATORS

    raw_inputs := []
    for v in V:
        a := AIndex.get(v.operator_id, none)
        if committee_eligibility_at_checkpoint(v, a, econ, mode, H):
            raw_inputs.append(BuildOperatorCommitteeInput(v, a, econ, H))

    raw_inputs := SortOperatorCommitteeInputs(raw_inputs)
    candidates := AggregateOperatorCandidates(raw_inputs, econ)
    candidates := SortAggregatedCandidatesBySelectionIdThenPubkey(candidates)
    candidates := FullDeterministicSortByFinalComparator(candidates)

    K := econ.committee_size
    selected := candidates[0 : min(K, len(candidates))]
    schedule := DeterministicProposerPermutation(selected)

    return FinalizedCommitteeCheckpoint(
        epoch_start_height = epoch_start_height(next_epoch),
        derivation_mode = mode,
        fallback_reason = reason,
        availability_eligible_operator_count = eligible_cnt,
        availability_min_eligible_operators = min_ops,
        adaptive_target_committee_size = econ.committee_size,
        adaptive_min_eligible = econ.availability_min_eligible_operators,
        adaptive_min_bond = econ.dynamic_min_bond,
        qualified_depth = qualified_depth,
        target_expand_streak = expand_streak,
        target_contract_streak = contract_streak,
        committee_members = selected,
        proposer_schedule = schedule
    )
```

## 17. Conformance Properties

```text
P1. Determinism:
    Same finalized frontier history => same checkpoint bytes

P2. Ordering independence:
    Same semantic inputs under different insertion orders => same checkpoint bytes

P3. Boundary uniqueness:
    Eligibility changes affect only checkpoints derived from the unique canonical epoch boundary

P4. Hysteresis correctness:
    Mode transitions follow Section 8 exactly

P5. Unified eligibility:
    No candidate may bypass Section 6 through alternate filtering paths

P6. Replay equivalence:
    Replay from genesis and restart from persisted finalized frontier state produce identical checkpoint outputs

P7. Genesis continuity:
    Genesis checkpoint metadata fields match later checkpoint semantics
```
