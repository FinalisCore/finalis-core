# Operator Model

## Definition

The live protocol aggregates committee economics by `operator_id`.

Build note:

- CMake auto-fetches `secp256k1-zkp` if the vendored tree is missing (network required)
- for offline builds, disable auto-fetch and provide the vendored tree:
  `cmake -S . -B build -G Ninja -DFINALIS_AUTO_FETCH_DEPS=OFF`
  `git submodule update --init --recursive`

This model applies unchanged on the restarted mainnet with identity:

- `network_id = 258038c123a1c9b08475216e5f53a503`
- `genesis_hash = fd5570810b163e43a90ef5e8203e8aef34c89072f5f261c4de74aa724a615211`

Onboarding lifecycle and admission rules are specified separately in:

- [docs/ONBOARDING-PROTOCOL.md](ONBOARDING-PROTOCOL.md)

In finalized validator state:

- `ValidatorInfo::operator_id` is persisted in the validator registry
- validators may share one operator
- committee economics, availability qualification, and qualified-depth counting
  are operator-based on the live path

## Source Of `operator_id`

For finalized join approvals:

- `operator_id` is derived from the join request payout pubkey

For finalized onboarding admission:

- `operator_id` is derived from the onboarding registration payout pubkey

For bootstrap or legacy validators:

- `operator_id` falls back to the validator pubkey itself

That means the operator layer is a deterministic on-chain grouping rule, not a
local label.

## Why The Operator Layer Exists

Without operator aggregation, splitting one bond across many validator pubkeys
can increase influence under square-root weighting.

The live protocol avoids that by aggregating bond at operator level first:

`W_op = sqrt(sum bond_i under one operator)`

instead of summing per-validator transformed weights.

## What Uses Operator Aggregation

Operator aggregation affects:

- effective bond / primary weight
- qualified-depth counting
- checkpoint eligibility grouping
- bounded ticket search in the live protocol
- committee candidate construction

It does not remove validator pubkeys from runtime finality.

Consensus still uses validator pubkeys for:

- proposer signatures
- vote signatures
- committee membership entries
- finality certificates

This remains true even after `TxV2` / confidential-UTXO support. Confidential
transaction support does not replace validator-key-based consensus identity.

The operator layer is an economics and committee-formation layer, not a
replacement for validator keys.

## Representative Selection

When an operator contributes a committee candidate, the implementation selects a
deterministic representative validator pubkey for that operator-level entry.

Important boundary:

- the representative is chosen by canonical live rules
- it is not a free local choice
- it is not a separate identity concept from `operator_id`

The exact representative/tie-break behavior is implementation-defined by the
canonical candidate construction and ordering logic. Do not re-specify it
loosely in integrations; consume the finalized checkpoint output.

## Qualified Depth

Adaptive checkpoint control uses:

`qualified_depth = count(distinct operator_id)` such that the operator is:

- lifecycle-active
- checkpoint-bond-qualified
- availability-eligible

This is the only operator-count signal that now drives adaptive checkpoint
target expansion/contraction.

## Limitations

The operator model does not solve real-world identity.

It protects against:

- splitting many validators under one `operator_id`
- additive same-operator ticket gain
- changing qualified depth by validator-count inflation alone inside one
  operator

It does not protect against:

- one actor controlling many genuinely distinct `operator_id` values
- off-chain identity duplication outside the protocol’s operator abstraction

That remains outside the protocol’s identity model.
