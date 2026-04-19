# Live Protocol

`finalis-core` is a finalized-state BFT chain.

Current restarted mainnet identity:

- `network_name = mainnet`
- `network_id = fe561911730912cced1e83bc273fab13`
- `genesis_hash = eaae655a1eec3c876bd2e66d899fc8da93d205a5df36a2665f736387aa3cb78a`
- `magic = 0x499602D2`

Normative checkpoint derivation semantics are defined in [docs/spec/CHECKPOINT_DERIVATION_SPEC.md](spec/CHECKPOINT_DERIVATION_SPEC.md).
Normative availability state completeness and replay semantics are defined in [docs/spec/AVAILABILITY_STATE_COMPLETENESS.md](spec/AVAILABILITY_STATE_COMPLETENESS.md).
A bounded formal verification artifact for checkpoint derivation and availability equivalence is provided in [formal/checkpoint_availability.tla](../formal/checkpoint_availability.tla), with a reproducible TLC suite runner at [scripts/run_tlc.sh](../scripts/run_tlc.sh).
A live-protocol-faithful adversarial/economic simulator for committee concentration, fallback dynamics, and operator strategies is provided in [scripts/protocol_attack_sim.py](../scripts/protocol_attack_sim.py), documented in [docs/PROTOCOL_ATTACK_SIMULATOR.md](PROTOCOL_ATTACK_SIMULATOR.md).

## Finality

- The chain advances only at `finalized_height + 1`.
- Finality requires `floor(2N/3) + 1` valid signatures over the exact `(height, round, block_id)` payload.
- The active committee for a height comes from the finalized checkpoint for that height's epoch.
- Epochs are fixed-width and currently `32` blocks on mainnet unless a test fixture overrides that network setting.
- Proposer order is deterministic from the finalized epoch checkpoint.

## Frontier Storage

- The live node persists finalized frontier transitions, not finalized block
  bodies.
- Finality certificates are persisted canonically by finalized height.
- A transition hash may be used as an external lookup key, but the certificate
  source of truth is still the height-indexed certificate row for that
  finalized height.
- Restart must fail closed if frontier transition storage or its matching
  finalized certificate is missing or inconsistent.
- Ingress records are accepted and replayed only when certificate epoch matches
  `committee_epoch_start(finalized_height + 1)`.
- Ingress equivocation at fixed `(epoch, lane, seq)` is rejected and recorded
  as persisted evidence.
- Frontier ingress replay revalidates certificate signatures, lane assignment,
  and lane-root chaining before transition execution.

## Validator Lifecycle

- Validator lifecycle is derived only from finalized history.
- A finalized join request and bond register the validator immediately in registry state.
- Warmup, cooldown, liveness penalties, unbond state, and join-window accounting are replayed deterministically from finalized history.
- Committee eligibility changes only at epoch-boundary checkpoint derivation.
- A validator that becomes active mid-epoch does not alter the already-derived in-epoch committee.
- A finalized exit, cooldown transition, or liveness-triggered exit affects future checkpoints only.

Canonical boundary rule:

- Checkpoint derivation for epoch `E+1` uses finalized validator and availability state after the finalized tip at height `E_end`.
- That derived checkpoint becomes the only committee source for heights in epoch `E+1`.

## Operator Model

- Economics and committee weighting are operator-based on the live path.
- Multiple validators may map to one operator.
- Bond is tracked per validator, while effective committee weight aggregates per operator.
- One bounded best-ticket search is performed per operator.
- Committee target, checkpoint minimum eligible count, and checkpoint minimum bond now adapt at epoch boundaries from finalized qualified operator depth only.
- Qualified depth counts distinct operators that are lifecycle-active, checkpoint-bond-qualified, and availability-eligible at the derivation boundary.
- The adaptive target regime is hysteretic and replay-safe:
  - expand `16 -> 24` only after `qualified_depth >= 30` for `4` consecutive epochs
  - contract `24 -> 16` only after `qualified_depth <= 22` for `6` consecutive epochs
- Checkpoint minimum eligible is fixed as `target + 3`.
- Checkpoint minimum bond and availability minimum bond are the same deterministic integer-derived value for that epoch.

## Live BPoAR Enforcement

- Availability state is derived deterministically from finalized history and persisted.
- `WARMUP`, `PROBATION`, and `EJECTED` operators are not committee-eligible.
- Only `ACTIVE` operators that also satisfy the configured bond and eligibility-score thresholds are committee-eligible.
- Checkpoint derivation for the next epoch filters operator candidates through this availability eligibility rule.
- If eligible operator count is below the configured minimum, the checkpoint enters explicit `fallback` derivation mode and does not apply availability filtering for that checkpoint.
- `normal` and `fallback` checkpoint derivation modes are serialized in the finalized checkpoint artifact together with the eligible/minimum counts that triggered the decision.

Current live subset:

- Retained-prefix tracking is live.
- Epoch audit advancement is deterministic and finalized-history-derived.
- Committee gating is live.
- Persisted availability evidence is observability-only and is excluded from live eligibility, finalized checkpoint output, and consensus state commitment semantics.

Not live:

- Off-chain or subjective availability evidence.
- Non-finalized availability observations.
- Reward weighting adjustments from BPoAR beyond committee eligibility.

## Replay and Restart

- Validator state, availability state, finalized checkpoints, proposer schedule inputs, and the consensus state commitment are all reconstructed from finalized frontier history.
- Restart and resync must reproduce the same validator registry, availability state, checkpoints, and proposer schedule.
- On restart, the node clears the consensus state commitment cache by default so the rebuild is authoritative; use `--no-reindex` to keep the cache when intentionally preserving it.

Replay authority is:

- genesis configuration and genesis artifact identity
- finalized frontier transitions in height order
- one canonical finality certificate per finalized height
- committed finalized ingress/state storage needed to verify those transitions

After the deliberate genesis reset, old chain DB contents, frontier caches, and
endpoint assumptions are outside this replay authority and must not be reused
as if they belonged to the current network.

## Adaptive Observability

- Adaptive observability is operational only. It does not feed checkpoint derivation.
- The node runtime snapshot, lightserver `get_status`, verbose `get_committee`, and `get_adaptive_telemetry` expose:
  - `qualified_depth`
  - `adaptive_target_committee_size`
  - `adaptive_min_eligible`
  - `adaptive_min_bond`
  - `slack = qualified_depth - adaptive_min_eligible`
  - expansion / contraction streak counters
  - current checkpoint derivation mode and fallback reason
- Per-epoch adaptive telemetry is persisted deterministically from finalized checkpoint metadata.
- Rolling `fallback_rate_bps` and `sticky_fallback_rate_bps` are derived only from persisted epoch snapshots over a fixed recent window.
- Lightserver `get_status` also exposes a separate `adaptive_telemetry_summary`
  block with:
  - `window_epochs`
  - `sample_count`
  - `fallback_epochs`
  - `sticky_fallback_epochs`
- Alert flags such as near-threshold operation, repeated sticky fallback, and depth collapse after bond increase are observability signals only.

## External Semantics

- External read surfaces remain finalized-only.
- Lightserver and explorer expose finalized state, current finalized
  availability/committee status, and adaptive telemetry observability only.
- The wallet remains finalized-state-driven for settlement decisions, but the
  merged UI now includes confidential account creation/import, confidential
  receive request generation, confidential coin import/tracking, pending
  confidential reservation state, and cached-first pending tx inspection.
- Explorer and wallet both use local-first caches and surface freshness /
  provenance explicitly instead of assuming every view is a fresh RPC read.
