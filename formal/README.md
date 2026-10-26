# Formal Models

Current mainnet identity context:

- `network_name = mainnet`
- `network_id = fe561911730912cced1e83bc273fab13`
- `genesis_hash`: published at launch (mainnet has not launched)

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
(about 3 minutes with one TLC worker). For the reachability and mutation configs add
`--expect-violation <invariant>`, which passes only if TLC reports that invariant violated. CI
(`.github/workflows/formal-verification.yml`) runs all five abstract configs this way; the detailed
model is too large for CI.

It models the voting rules of [docs/spec/TWO_PHASE_FINALITY.md](../docs/spec/TWO_PHASE_FINALITY.md) at
one height as implemented in `src/node/node_consensus.cpp`: 4 validators (1 Byzantine, quorum 3),
two values, rounds 0..2 with a Byzantine leader in round 1. The Byzantine validator has signed every
prevote and precommit and proposed every value with every proof-of-lock round. Honest nodes act on
quorums in any order, time out, catch up rounds, reset on reconnect, and restart (losing the
in-memory timed-out rounds; lock, valid value and own prevotes are durable).

It abstracts away (each abstraction only adds behaviours): transition ids as abstract values that a
fresh proposal may reuse, body availability, TC formation, the per-round reservations that a reset
clears, and the once-per-round limit on honest proposals. Liveness is not checked.

## Two-Phase Finality Persistence Model

[two_phase_finality_persistence.tla](two_phase_finality_persistence.tla) adds the persistence layer to
the abstract model: per-node in-memory and durable copies of the lock and prevote record, ambiguous
write failures (the batch may or may not survive a restart), optional sticky failure (RocksDB's
background error: every later write fails until restart), restarts that reload memory from disk, and
the code paths that send votes from memory without a write (`lock_on_polka_locked`'s early return,
the stall rebroadcast, the reconnect reseed). Only sent votes count toward polkas and commits.

- Current code: `FixLock = FixPrevote = FALSE` (the code at 9467c05 / 23fed2b).
- Candidate fix (hypothetical, not implemented): `FixLock` / `FixPrevote` = TRUE change memory only after
  a successful write, for the lock and the prevote record separately.
- Assumptions: 3 honest + 1 Byzantine validator (the Byzantine one counts toward every polka and commit),
  quorum `2N/3 + 1` = 3, two values, one height; asynchronous delivery (a quorum is acted on whenever it
  exists); a write serializes the node's whole safety state for the height; symmetry over values and
  honest nodes. Not modelled: valid-value re-proposal, timed-out rounds, finalization writes (D7), the
  RocksDB abort / hang behaviours (E1, E2).
- Invariants: `Agreement`, `NoHonestDoublePrevote`, `NoHonestDoublePrecommit`, `SentPrecommitDurable`,
  `SentPrevoteDurable`, `MemoryBackedByDisk`; reachability `NothingFinalizes` (must be violated).

| Config | Expected | Result (2026-10-26, TLC 4 workers) |
|---|---|---|
| `_current_durable.cfg` (rounds 0..2) | `SentPrecommitDurable` violated | violated, depth 5 |
| `_current_prevote.cfg` (rounds 0..2) | `NoHonestDoublePrevote` violated | violated, depth 5 |
| `_current_memory_r1.cfg` | `MemoryBackedByDisk` violated | violated, depth 2 |
| `_current_r1.cfg` (rounds 0..1) | `Agreement` violated | violated, depth 12 (2,007,734 states, 30 s) |
| `_current.cfg` (rounds 0..2), exhaustive | `Agreement` violated | **incomplete** (stopped at 20 min, ~7.7M states) |
| `_current.cfg` with `-simulate num=2000000 -depth 40 -seed 20261025` | `Agreement` violated | violated (simulation, not exhaustive) |
| `_lockfix_only_r1.cfg` | `Agreement` violated | violated, depth 12, via a prevote sent from memory + restart |
| `_prevotefix_only_r1.cfg` | `Agreement` violated | violated, depth 11, via a precommit from the memory lock + restart |
| `_fix_r1.cfg`, `_fix_nonsticky_r1.cfg` | all invariants hold | hold, complete (128,082 / 63,411 states, depth 18) |
| `_fix.cfg`, `_fix_nonsticky.cfg` (rounds 0..2) | all invariants hold | hold, complete (26,435,096 / 12,744,290 states, depth 25; 22 / 12 min) |
| `_fix_reach.cfg` | `NothingFinalizes` violated | violated (finality reachable: the fix results are not vacuous) |

A passing fix model shows the design rule is sufficient within these bounds; it is not evidence that a
C++ implementation of it is correct. Both halves are needed (the partial-fix rows).

Run: `./scripts/run_tlc.sh --spec formal/two_phase_finality_persistence.tla --config <cfg>` (add
`--expect-violation <invariant>` for the `_current*`, `_*fix_only*` and `_reach` configs). The tests that
reproduce the same defects in the node are listed in [tests/KNOWN_DEFECTS.md](../tests/KNOWN_DEFECTS.md).
