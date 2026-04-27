# Protocol Attack Simulator

This document describes the live-protocol-faithful adversarial simulator in [scripts/protocol_attack_sim.py](../scripts/protocol_attack_sim.py).

## Purpose

The simulator stress-tests the live finalized checkpoint path under adversarial and strategic operator behavior. It is intended for protocol review and parameter sensitivity work, not for consensus or on-chain execution.

The simulator reflects the live protocol semantics documented in:

- [docs/spec/CHECKPOINT_DERIVATION_SPEC.md](spec/CHECKPOINT_DERIVATION_SPEC.md)
- [docs/spec/AVAILABILITY_STATE_COMPLETENESS.md](spec/AVAILABILITY_STATE_COMPLETENESS.md)
- [docs/LIVE_PROTOCOL.md](LIVE_PROTOCOL.md)

The current live deployment context after the genesis reset is:

- `network_name = mainnet`
- `network_id = fe561911730912cced1e83bc273fab13`
- `genesis_hash = eaae655a1eec3c876bd2e66d899fc8da93d205a5df36a2665f736387aa3cb78a`

## Live Rules Modeled

- finalized-history-driven validator lifecycle
- operator-based committee derivation
- unified checkpoint eligibility
- BPoAR-gated future checkpoint eligibility
- explicit `NORMAL` / `FALLBACK`
- explicit fallback reasons:
  - `NONE`
  - `INSUFFICIENT_ELIGIBLE_OPERATORS`
  - `HYSTERESIS_RECOVERY_PENDING`
- adaptive checkpoint regime:
  - target set `{16, 24}`
  - qualified-depth-driven expansion/contraction
  - `adaptive_min_eligible = target + 3`
  - deterministic adaptive checkpoint minimum bond
- live hysteresis:
  - `NORMAL -> FALLBACK` if eligible `< min`
  - `FALLBACK -> NORMAL` only if eligible `>= min + 1`
  - sticky fallback at exact threshold
- deterministic committee selection and proposer ordering via the live-faithful
  local mirror in [scripts/protocol_attack_sim.py](../scripts/protocol_attack_sim.py)
- non-consensus evidence excluded from derivation
- golden-fixture conformance against C++ canonical checkpoint and comparator outputs under [tests/fixtures/](../tests/fixtures)

## Explicit Abstractions

The simulator is faithful at the checkpoint-policy layer, but it is still an analysis model. It intentionally abstracts:

- block-by-block finalization into epoch-boundary derivation steps
- validator warmup/cooldown blocks into epoch lags using:
  - `ceil(blocks / epoch_size)`
- raw retained-prefix assignment and audit-response bytes into deterministic operator availability state plans
- byte-level checkpoint serialization and state commitments

The simulator does not prove the live implementation. It measures protocol behavior under bounded, reproducible adversarial scenarios.

It must not be used as if it were replay input for the abandoned pre-reset
chain; the current deployment context is the mainnet identity above.

The committed fixture bridge constrains simulator drift:

- C++ canonical code emits the fixture corpus
- Python loads those fixtures and must reproduce:
  - eligible operator count
  - derivation mode
  - fallback reason
  - committee membership
  - committee ordering
  - proposer schedule
  - comparator sorted order
  - comparator top-k selection

C++ is authoritative. Python does not compute expected outputs independently.

## Scenario Inputs

Scenarios are defined with Python dataclasses and may also be loaded from JSON.

Each scenario specifies:

- protocol parameters
- actors
- operators
- validators
- epochs to simulate
- strategy family metadata

Built-in scenarios include:

- `honest_baseline`
- `coalition_unsplit_baseline`
- `split_operator_adversary`
- `availability_griefing_adversary`
- `sticky_fallback_threshold_manipulator`
- `join_exit_boundary_adversary`
- `marginal_eligible_pool`
- `bond_threshold_edge`
- `mixed_depth_population`
- `boundary_activation_edge`

## Outputs

Per run the simulator computes:

- committee share by coalition
- proposer share by coalition
- committee concentration:
  - `HHI`
  - top-1 share
  - top-3 share
  - maximum operator committee share
- fallback frequency
- fallback duration
- sticky fallback duration
- recovery time
- activation latency for post-genesis joins
- eligibility churn
- threshold-sensitive metrics such as:
  - `epochs_at_exact_threshold`
  - `epochs_below_threshold`
  - `fallback_entry_count`
  - `sticky_fallback_entry_count`
  - `operators_filtered_by_bond_floor`
  - `bond_threshold_binding_rate`
  - `warmup_blocking_rate`
  - `cooldown_blocking_rate`

Report outputs:

- machine-readable JSON summary
- machine-readable CSV epoch table
- human-readable Markdown report

## Sensitivity Analysis

One-parameter-at-a-time sweeps are supported for:

- `committee_size`
- `min_eligible`
- `dynamic_min_bond_coins`
- `availability_min_bond_coins`
- `validator_warmup_blocks`
- `validator_cooldown_blocks`
- `adversary_bond_share`
- `operator_split_count`

## Usage

List built-in scenarios:

```bash
python3 scripts/protocol_attack_sim.py list-scenarios
```

Run baseline and adversarial comparison:

```bash
python3 scripts/protocol_attack_sim.py run \
  --scenario coalition_unsplit_baseline \
  --scenario split_operator_adversary \
  --json-out /tmp/finalis_sim.json \
  --md-out /tmp/finalis_sim.md \
  --csv-out /tmp/finalis_sim.csv
```

Run a sensitivity sweep:

```bash
python3 scripts/protocol_attack_sim.py sweep \
  --scenario split_operator_adversary \
  --parameter operator_split_count \
  --values 1,2,3,4
```

## Test Coverage

The Python tests in [scripts/tests/test_protocol_attack_sim.py](../scripts/tests/test_protocol_attack_sim.py) check:

- deterministic outputs for identical scenarios
- sticky fallback semantics against the live hysteresis table
- split-operator scenario sanity
- scenario parsing and validation
- report stability and parseability
- parameter sweep support

The C++ ↔ Python bridge tests in [scripts/tests/test_cpp_fixture_conformance.py](../scripts/tests/test_cpp_fixture_conformance.py) check:

- checkpoint-step conformance against committed C++ golden fixtures
- comparator-ordering conformance against committed C++ golden fixtures
- fixture version/schema rejection on malformed inputs

## Fixture Regeneration

Regenerate the committed fixture corpus with:

```bash
./scripts/generate_checkpoint_fixtures.sh
```

Check that committed fixtures match the current C++ exporter with:

```bash
./scripts/check_checkpoint_fixtures.sh
```
