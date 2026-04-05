# Sybil Resistance

## Scope

This document describes the live protocol’s current sybil-resistance shape.

It is specifically about:

- same-owner splitting under one `operator_id`
- distinct-operator fragmentation pressure
- checkpoint admission and availability gating

It is not a claim of real-world identity uniqueness.

## Same-Operator Split Resistance

Consider an attacker with fixed total bond `B`.

If influence were computed per validator and then summed under a square-root
rule, splitting would be profitable:

`sum sqrt(b_i) > sqrt(sum b_i)`

The live protocol closes that path by aggregating by operator first:

`B_op = sum b_i for validators under one operator_id`

`W_op = sqrt(B_op)`

Primary committee influence is therefore computed from operator aggregate bond,
not from separately transformed validator fragments.

## What The Live Protocol Now Uses

The live path is operator-based for:

- primary effective weight
- bounded ticket search
- committee candidate construction
- qualified-depth counting

That means same-operator splitting does not create:

- extra primary weight
- extra bounded-ticket search lanes
- extra qualified-depth contribution

## Availability And Checkpoint Gating

Sybil resistance now sits on more than weight alone.

Future committee eligibility also depends on:

- finalized validator lifecycle activity
- checkpoint bond qualification
- finalized projected availability eligibility

Adaptive checkpoint expansion/contraction is driven only by:

`qualified_depth = count(distinct operator_id)` such that the operator is:

- lifecycle-active
- checkpoint-bond-qualified
- availability-eligible

So cheap or unavailable operator fragments do not contribute to the adaptive
growth signal unless they satisfy the full finalized eligibility rule.

## Adaptive Bond Floor

The live checkpoint regime also derives a deterministic adaptive checkpoint
minimum bond.

That matters because distinct operators near the threshold can be filtered out
before they contribute to:

- qualified depth
- checkpoint eligibility
- next-epoch committee derivation

This does not eliminate multi-operator fragmentation, but it raises its cost in
binding regimes.

## What Is Protected

Protected:

- splitting many validators under one `operator_id`
- additive same-operator ticket gain
- same-operator qualified-depth inflation
- future checkpoint participation by operators that fail finalized lifecycle,
  bond, or availability gates

Not protected:

- one actor controlling many genuinely distinct `operator_id` values
- off-chain identity duplication outside the protocol

The protocol intentionally treats different operator IDs as different economic
entities because there is no stronger native identity layer.

## Empirical Layer

The repo now has two complementary analysis layers:

- exploratory quantitative modeling in [scripts/attack_model.py](/home/greendragon/Desktop/selfcoin-core-clean/scripts/attack_model.py)
- live-faithful adversarial simulation in [scripts/protocol_attack_sim.py](/home/greendragon/Desktop/selfcoin-core-clean/scripts/protocol_attack_sim.py)

The simulator is the more faithful current guide for:

- split amplification
- fallback fragility
- committee concentration
- adaptive-threshold sensitivity

## Practical Conclusion

The live protocol closes the strong same-owner split-bond sybil path at the
committee-economics layer and further constrains eligibility through finalized
availability and adaptive checkpoint rules.

It does not claim to solve identity outside the finalized `operator_id`
abstraction.
