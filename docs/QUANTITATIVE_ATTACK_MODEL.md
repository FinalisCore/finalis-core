# Quantitative Attack Model

## 1. Purpose

This document describes the repository’s quantitative attack-analysis layer.

There are now two distinct analysis tools:

- exploratory attack/economics modeling:
  - [scripts/attack_model.py](/home/greendragon/Desktop/selfcoin-core-clean/scripts/attack_model.py)
- live-faithful adversarial checkpoint simulation:
  - [scripts/protocol_attack_sim.py](/home/greendragon/Desktop/selfcoin-core-clean/scripts/protocol_attack_sim.py)

The second tool is closer to the live protocol. This document is mainly about
the exploratory quantitative model and its role.

## 2. What The Quantitative Model Is For

The quantitative model is used to compare adversarial pressure under simplified
economic families and committee assumptions.

It measures things such as:

- halt threshold
- unilateral quorum threshold
- byzantine-risk boundary
- operator-splitting amplification
- bounded ticket-work influence
- committee capture probability under different capital distributions
- liveness degradation under proposer failure or delivery loss

It is useful for directional comparison.

It is not:

- a formal proof
- a replacement for the live checkpoint derivation model
- a replacement for replay-faithful simulator results
- a complete model of real-world collusion, identity, or operator behavior

## 3. Relationship To The Live Protocol

The live protocol now has an adaptive checkpoint regime driven by finalized
qualified depth.

That means the most live-faithful questions about:

- committee concentration
- fallback frequency
- sticky fallback persistence
- split amplification under bond-threshold edge cases
- boundary timing

should be answered first with:

- [scripts/protocol_attack_sim.py](/home/greendragon/Desktop/selfcoin-core-clean/scripts/protocol_attack_sim.py)

The simpler quantitative model remains useful for broad parameter-family
comparison and sanity checks.

## 4. Core Variables

The quantitative model uses variables such as:

- `K`: committee size
- `Q`: quorum threshold
- `H`: halt threshold in seats
- `S`: unilateral quorum-control threshold in seats
- `R`: byzantine-risk threshold in seats
- `N`: active operator count
- `B_i`: raw bond for operator `i`
- `m`: minimum qualifying bond
- `C`: effective-bond cap
- `E_i`: effective bond for operator `i`
- `w_i`: effective weight derived from `E_i`
- `T_i`: bounded ticket contribution
- `W_i`: committee-selection strength for operator `i`

The model remains operator-level. `operator_id` is an economics grouping key,
not a real-world identity oracle.

## 5. Consensus Thresholds

The model uses the live repository quorum rule:

```text
Q = floor(2K/3) + 1
```

Reported boundaries:

Halt threshold:

```text
H = K - Q + 1
```

Interpretation:

- if an adversary controls at least `H` seats and withholds them, the remaining
  seats cannot form quorum

Unilateral quorum-control threshold:

```text
S = Q
```

Interpretation:

- if an adversary controls `Q` seats, it can certify without honest help

Secondary byzantine-risk threshold:

```text
R = ceil(K/3)
```

Interpretation:

- this is not treated as unilateral finalization
- it is a risk boundary for safety-adjacent and liveness-adjacent cases

## 6. Economic Families

The exploratory model can compare explicit economics families such as:

- `current`
- `threshold_sqrt`
- `threshold_seatbudget_sqrt`

The `current` family approximates the schedule-driven bond/cap helper shape:

```text
m(N) = clamp(
    min_bond_coins * sqrt(target_validators / max(1, N)),
    min_bond_floor_coins,
    min_bond_ceiling_coins
)
```

with capped effective bond and square-root weighting after thresholding.

This is only an approximation layer. It does not encode the full live adaptive
checkpoint regime.

## 7. Ticket Contribution

Ticket work in the quantitative model is optional and bounded.

When enabled:

- it remains operator-level
- it adjusts selection strength only
- it does not turn the model into a proof-of-work race

This mirrors the live protocol’s intent that ticket work is secondary to bond
weighting and finality.

## 8. Split-Amplification Interpretation

The key split question is inter-operator fragmentation, not many validators
under one operator.

The model therefore distinguishes:

- intra-operator splitting
- inter-operator fragmentation under one controlling actor

Split amplification is interpreted as:

```text
expected_adversarial_seats(split_count=s) /
expected_adversarial_seats(split_count=1)
```

Interpretation:

- `1` means splitting gives no expected seat gain
- larger values mean the modeled economics still rewards multi-operator
  fragmentation

## 9. Where To Use Which Tool

Use the quantitative model when you want:

- quick comparison of economics-family shapes
- simplified seat-probability analysis
- broad sensitivity exploration

Use the live-faithful simulator when you want:

- checkpoint-mode correctness under adversarial behavior
- fallback / sticky fallback dynamics
- adaptive-threshold sensitivity
- replay-constrained concentration analysis
- parameter recommendation work

## 10. Bottom Line

The repo’s quantitative attack layer is now intentionally split:

- `attack_model.py` for simplified analytical / Monte Carlo comparison
- `protocol_attack_sim.py` for protocol-faithful adversarial simulation

Do not treat the simpler model as the final authority on live parameter
recommendations once the protocol behavior depends on finalized checkpoint
adaptation.
