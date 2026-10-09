# Formal Models

Current mainnet identity context:

- `network_name = mainnet`
- `network_id = fe561911730912cced1e83bc273fab13`
- `genesis_hash = eaae655a1eec3c876bd2e66d899fc8da93d205a5df36a2665f736387aa3cb78a`

## Checkpoint / Availability Model

- Spec: [checkpoint_availability.tla](checkpoint_availability.tla)
- TLC configs:
  - [checkpoint_availability.cfg](checkpoint_availability.cfg)
  - [checkpoint_availability_sticky.cfg](checkpoint_availability_sticky.cfg)
  - [checkpoint_availability_ordering.cfg](checkpoint_availability_ordering.cfg)
  - [checkpoint_availability_long_horizon.cfg](checkpoint_availability_long_horizon.cfg)
  - [checkpoint_availability_emergency.cfg](checkpoint_availability_emergency.cfg)

This model formalizes the live checkpoint derivation pipeline at the bounded semantic level.

It models:

- finalized-history-driven validator lifecycle
- consensus-relevant availability projection
- explicit fallback / hysteresis mode transitions
- deterministic total-order committee selection
- replay / restore / rebuild schedule equivalence
- evidence isolation from consensus outputs
- fallback committee sizing: `min(K, len(C))` in every mode, never shrunk to the eligible count
- per-operator bond aggregation with saturating addition (one seat per operator)
- audit evidence attributed only when signed by the challenged operator
- emergency committee recovery from the two prior committees when no candidate survives

It abstracts away:

- byte-level serialization
- full ticket-work and bond arithmetic
- intra-operator representative selection beyond one secondary validator (`v4` of `o2`,
  mirroring `v2`'s lifecycle facts, with a bond at the saturation ceiling `MaxBond`)
- concrete proposer permutation bytes

The model uses one representative validator per operator as a bounded abstraction of the live operator-native committee path. This preserves unified eligibility, fallback/hysteresis behavior, replay equivalence, and deterministic selection properties without modeling the full validator-to-operator aggregation mechanics.

The abstraction preserves the properties that matter here:

- determinism
- replay equivalence
- hysteresis correctness
- evidence isolation
- ordering independence

This formal layer is about the restarted live checkpoint regime, not the
abandoned pre-reset chain. Old-chain DBs or old genesis assumptions are outside
the model’s intended deployment context.

## Run TLC

With `tla2tools.jar` available locally:

```bash
java -cp /path/to/tla2tools.jar tlc2.TLC \
  -config formal/checkpoint_availability.cfg \
  formal/checkpoint_availability.tla
```

Repo-local helper:

```bash
./scripts/run_tlc.sh
```

GitHub Actions runs the same suite in [.github/workflows/formal-verification.yml](../.github/workflows/formal-verification.yml).

Optional overrides:

```bash
TLA_JAR=$HOME/tools/tla/tla2tools.jar ./scripts/run_tlc.sh
./scripts/run_tlc.sh --list
./scripts/run_tlc.sh --config formal/checkpoint_availability_ordering.cfg
./scripts/run_tlc.sh --out-dir formal/tlc_runs_ci -- -deadlock
```

The runner uses a fixed TLC seed and one worker by default so bounded checks are reproducible across runs. Logs and TLC metadirs are written under `formal/tlc_runs/`.

## Built-in Model Suite

- `checkpoint_availability.cfg`
  - baseline determinism, replay-equivalence, hysteresis, and evidence-isolation coverage
- `checkpoint_availability_sticky.cfg`
  - sticky fallback and hysteresis-threshold focused scenario
- `checkpoint_availability_ordering.cfg`
  - deterministic total-order committee selection under exact rank ties
- `checkpoint_availability_long_horizon.cfg`
  - longer replay/restart schedule equivalence scenario
- `checkpoint_availability_emergency.cfg`
  - no lifecycle-active validator for two epochs: emergency prior-committee recovery, then hysteresis

## Checked Properties

The TLC configuration checks:

- `TypeOK`
- `ProjectionIdempotent`
- `EvidenceProjectionIdempotent`
- `EvidenceIsolation`
- `ProjectedMatchesExpected`
- `ProjectedReplayEquivalence`
- `CheckpointMatchesExpected`
- `CheckpointReplayEquivalence`
- `HysteresisConformance`
- `StyleIndependence`
- `CommitteeEligibilitySoundness`
- `CommitteeBounded`
- `StickyFallbackDefinition`
- `NonEmptyCommittee`
- `FallbackCommitteeSizing`
- `BondAggregationPerOperator`
- `EmergencyCommitteeSoundness`
- `AuditEvidenceAttributed`

## Normative Mapping

This model corresponds directly to:

- [docs/spec/CHECKPOINT_DERIVATION_SPEC.md](../docs/spec/CHECKPOINT_DERIVATION_SPEC.md)
- [docs/spec/AVAILABILITY_STATE_COMPLETENESS.md](../docs/spec/AVAILABILITY_STATE_COMPLETENESS.md)

It is a bounded formal verification artifact, not a proof of the full implementation or byte-level codec.

## Two-Phase Finality Model

- Spec: [two_phase_finality.tla](two_phase_finality.tla), bindings in
  [MC_two_phase_finality.tla](MC_two_phase_finality.tla)
- TLC configs:
  - [two_phase_finality.cfg](two_phase_finality.cfg): `TypeOK`, `Agreement` (must hold)
  - [two_phase_finality_reach.cfg](two_phase_finality_reach.cfg): `NothingFinalizes` (must be violated: finality is reachable)
  - [two_phase_finality_reach_cross.cfg](two_phase_finality_reach_cross.cfg): `NoCrossRoundFinality` (must be violated: later-round finality is reachable)
  - [two_phase_finality_mutation.cfg](two_phase_finality_mutation.cfg): `LockRule = FALSE`, `Agreement` (must be violated: the model detects forks)

Exhaustive check: [two_phase_finality_abstract.tla](two_phase_finality_abstract.tla), an
over-approximation of the detailed model (it drops the local round, timed-out rounds and honest
proposal rules, each of which only restricts honest behaviour, so Agreement there implies Agreement
here). Rounds 0..3, 3 honest + 1 Byzantine, two values:

- [two_phase_finality_abstract.cfg](two_phase_finality_abstract.cfg): `TypeOK`, `Agreement` hold
  (complete search, 2,395,836 distinct states, depth 25, under a minute)
- `_reach`, `_reach_cross`: violated as expected (finality and later-round finality reachable)
- `_lock_mutation` (`LockRule = FALSE`), `_floor_mutation` (`FloorRule = FALSE`): `Agreement`
  violated, i.e. both rules are necessary

The detailed model is too large to finish (stopped past 150M distinct states without a
counterexample); it is the readable mapping onto the code. Without the vote-round floor it produced
the counterexample that led to `local_vote_round_floor_locked` (see
[two_phase_finality_floor_mutation.cfg](two_phase_finality_floor_mutation.cfg)).

Run: `./scripts/run_tlc.sh --spec formal/two_phase_finality_abstract.tla --config formal/two_phase_finality_abstract.cfg`

It models the voting rules of [docs/spec/TWO_PHASE_FINALITY.md](../docs/spec/TWO_PHASE_FINALITY.md) at
one height as implemented in `src/node/node_consensus.cpp`: 4 validators (1 Byzantine, quorum 3),
two values, rounds 0..2 with a Byzantine leader in round 1. The Byzantine validator has signed every
prevote and precommit and proposed every value with every proof-of-lock round. Honest nodes act on
quorums in any order, time out, catch up rounds, reset on reconnect, and restart (losing the
in-memory timed-out rounds; lock, valid value and own prevotes are durable).

It abstracts away (each abstraction only adds behaviours): transition ids as abstract values that a
fresh proposal may reuse, body availability, TC formation, the per-round reservations that a reset
clears, and the once-per-round limit on honest proposals. Liveness is not checked.
