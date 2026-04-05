<p align="center">
  <img src="branding/web/logo-horizontal-dark.svg" alt="Finalis Core" width="560">
</p>

# Finalis Core

`finalis-core` is a finalized-state BFT blockchain in which validator lifecycle, operator-native committee formation, adaptive checkpoint derivation, and future committee eligibility are all derived deterministically from finalized history..

In the current codebase it consists of:

- a UTXO ledger
- a validator committee
- quorum finality
- deterministic epoch-boundary checkpoint derivation
- finalized-state read surfaces

The live runtime processes only:

`height = finalized_height + 1`

There is no live longest-chain fork-choice path in the node runtime.

## Repository Components

- `finalis-node`
  - full node
  - validation
  - finalized execution
  - committee / finality runtime
- `finalis-lightserver`
  - finalized-state JSON-RPC service
- `finalis-explorer`
  - HTTP UI and REST layer on top of lightserver
- `finalis-wallet`
  - Qt desktop wallet

This repository also contains:

- formal TLA+ checkpoint / availability models under [formal/](formal/)
- adversarial simulation under [scripts/protocol_attack_sim.py](scripts/protocol_attack_sim.py)
- C++ fixture export and Python conformance tests under
  [tests/fixtures/](tests/fixtures)

## Protocol Facts

- blocks finalize with `floor(2N/3) + 1` valid signatures
- votes and quorum certificates are bound to `(height, round, block_id)`
- the committee for a height comes from the finalized checkpoint for that
  height's epoch
- validator lifecycle changes come only from finalized history
- future checkpoint eligibility is gated by finalized projected availability
- checkpoint target committee size, checkpoint minimum eligible threshold, and
  checkpoint minimum bond are derived deterministically from finalized qualified
  operator depth
- Ticket PoW is bounded and secondary inside committee selection

## Read Surfaces

`finalis-lightserver` exposes finalized-state RPC methods such as:

- `get_status`
- `get_tx_status`
- `get_tx`
- `validate_address`
- `get_utxos`
- `get_history_page`
- `broadcast_tx`

`finalis-explorer` exposes thin finalized-state HTTP routes such as:

- `/api/status`
- `/api/committee`
- `/api/tx/<txid>`
- `/api/transition/<height_or_hash>`
- `/api/address/<address>`

`broadcast_tx` is a relay-submission surface. Finalized visibility still comes
from finalized-state lookup.

## Addresses And Keys

The current key / address model is:

- Ed25519 private keys
- Ed25519 32-byte public keys
- P2PKH addresses
- `HASH160(pubkey)` address payload
- `sc` / `tsc` HRP-based address encoding

See [docs/ADDRESSES.md](docs/ADDRESSES.md).

## Economics

The current code implements:

- deterministic reward settlement
- a height-gated economics schedule in `src/common/network.cpp`
- adaptive checkpoint target / minimum eligible / minimum bond derivation
- exact hard cap of `7,000,000 FLS`
- deterministic `12`-year emission schedule with annual `20%` decay
- `10%` reserve accrual during the emission era
- zero new issuance after the cap
- post-cap epoch fee pooling with deterministic reserve subsidy support

## Build

Minimum packages for Ubuntu / Debian:

```bash
apt update
apt install -y build-essential cmake ninja-build pkg-config libssl-dev \
  qtbase5-dev qtchooser qt5-qmake qtbase5-dev-tools \
  libsodium-dev librocksdb-dev curl jq
```

Build:

```bash
cmake -S . -B build -G Ninja
cmake --build build -j
```

## Run

Run a node with lightserver:

```bash
./build/finalis-node --db ~/.finalis/mainnet --with-lightserver
```

Default ports from the current mainnet config:

- P2P: `19440`
- lightserver: `19444`

Helper script:

```bash
./scripts/start.sh
```

## Testing

```bash
ctest --test-dir build --output-on-failure
```

## Documentation

- General documentation: [docs/](docs/)
- Exchange integration: [docs/EXCHANGE_INTEGRATION.md](docs/EXCHANGE_INTEGRATION.md)
- Live protocol: [docs/LIVE_PROTOCOL.md](docs/LIVE_PROTOCOL.md)
- Consensus overview: [docs/CONSENSUS.md](docs/CONSENSUS.md)
- Checkpoint derivation spec: [docs/spec/CHECKPOINT_DERIVATION_SPEC.md](docs/spec/CHECKPOINT_DERIVATION_SPEC.md)
- Availability completeness spec: [docs/spec/AVAILABILITY_STATE_COMPLETENESS.md](docs/spec/AVAILABILITY_STATE_COMPLETENESS.md)

## License

[LICENSE](LICENSE)
