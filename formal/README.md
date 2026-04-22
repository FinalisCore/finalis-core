# Formal Models

Current restarted mainnet identity context:

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

This model formalizes the live checkpoint derivation pipeline at the bounded semantic level.

It models:

- finalized-history-driven validator lifecycle
- consensus-relevant availability projection
- explicit fallback / hysteresis mode transitions
- deterministic total-order committee selection
- replay / restore / rebuild schedule equivalence
- evidence isolation from consensus outputs

It abstracts away:

- byte-level serialization
- full ticket-work and bond arithmetic
- intra-operator multi-validator aggregation details
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

## Normative Mapping

This model corresponds directly to:

- [docs/spec/CHECKPOINT_DERIVATION_SPEC.md](../docs/spec/CHECKPOINT_DERIVATION_SPEC.md)
- [docs/spec/AVAILABILITY_STATE_COMPLETENESS.md](../docs/spec/AVAILABILITY_STATE_COMPLETENESS.md)

It is a bounded formal verification artifact, not a proof of the full implementation or byte-level codec.
