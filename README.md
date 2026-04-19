<p align="center">
  <img src="branding/web/logo-horizontal-dark.svg" alt="Finalis Core" width="560">
</p>

# Finalis Core

`finalis-core` is a finalized-state BFT blockchain in which validator lifecycle, operator-native committee formation, adaptive checkpoint derivation, and future committee eligibility are all derived deterministically from finalized history..

Current restarted mainnet identity:

- `network_name = mainnet`
- `network_id = fe561911730912cced1e83bc273fab13`
- `genesis_hash = eaae655a1eec3c876bd2e66d899fc8da93d205a5df36a2665f736387aa3cb78a`
- `magic = 0x499602D2`

In the current codebase it consists of:

- a UTXO ledger
- versioned transaction handling through `Tx`, `TxV2`, and `AnyTx`
- versioned UTXO state through `UtxoSetV2`
- a validator committee
- quorum finality
- deterministic epoch-boundary checkpoint derivation
- finalized-state read surfaces

The live runtime processes only:

`height = finalized_height + 1`

There is no live longest-chain fork-choice path in the node runtime.

After the deliberate genesis reset, old chain DBs, old endpoint assumptions,
and abandoned-chain artifacts are not valid inputs to this live network.

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
  - local-first cached homepage / tx / transition views with freshness and
    provenance markers
- `finalis-wallet`
  - Qt desktop wallet
  - local-first cached runtime/view state
  - confidential account, receive-request, and imported-coin UX for the
    supported confidential subset

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

The current codebase also supports a bounded confidential transaction subset
through `TxV2`:

- transparent -> confidential
- confidential -> transparent

Public read surfaces stay finalized-only and do not expose confidential output
amounts or recipients as if they were transparent fields.

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

## Run A Node

## Quick Start (Non-Developers)

### Windows

1. Download the latest Windows installer from the releases page.
2. Install and launch `finalis-node` (and `finalis-lightserver` if you want wallet/explorer access).
3. Verify identity with:
   ```
   curl -s http://127.0.0.1:19444/rpc -d '{"jsonrpc":"2.0","id":1,"method":"get_status","params":{}}'
   ```
   Confirm `network_id`, `magic`, and `genesis_hash` match the values above.

### Linux

If a Linux binary release is available, download and run it. Otherwise use the
build steps below (requires a C++ toolchain).

For Windows builds/releases, use:

- [finalis-core releases](https://github.com/FinalisCore/finalis-core/releases)

```bash
apt install -y build-essential cmake ninja-build pkg-config libssl-dev \
  qtbase5-dev qtchooser qt5-qmake qtbase5-dev-tools \
  libsodium-dev librocksdb-dev curl jq
```
```bash
git clone https://github.com/FinalisCore/finalis-core.git
```
```bash
cd finalis-core
```
Build:

```bash
cmake -S . -B build -G Ninja && cmake --build build -j
```

Dependency notes:
- If `third_party/secp256k1-zkp` is missing, CMake will auto-fetch it (network required).
- To force offline builds, disable auto-fetch and provide the vendored tree:
  `cmake -S . -B build -G Ninja -DFINALIS_AUTO_FETCH_DEPS=OFF`
  `git submodule update --init --recursive`

## Run

Before first startup on the restarted mainnet:

- wipe old chain DBs
- ensure your local validator key is actually present in the intended genesis
  validator set
- ensure your binaries embed the same canonical `genesis.bin` used for launch

```bash
./scripts/start.sh
```

Default ports from the current mainnet config:

- P2P: `19440`
- lightserver: `19444`

Always verify live endpoint identity with `get_status` before relying on public
infrastructure.

## Community Help Wanted

If you can make a clear, step-by-step installation and launch video (Linux and/or Windows),
post it publicly and share the link. I can sponsor the best tutorials with enough FLS
to cover validator registration requirements.


## Testing

```bash
ctest --test-dir build --output-on-failure
```

## Documentation

- General documentation: [docs/](docs/)
- Exchange integration: [docs/EXCHANGE_INTEGRATION.md](docs/EXCHANGE_INTEGRATION.md)
- Live protocol: [docs/LIVE_PROTOCOL.md](docs/LIVE_PROTOCOL.md)
- Consensus overview: [docs/CONSENSUS.md](docs/CONSENSUS.md)
- Confidential UTXO spec: [docs/spec/CONFIDENTIAL_UTXO_SPEC.md](docs/spec/CONFIDENTIAL_UTXO_SPEC.md)
- Checkpoint derivation spec: [docs/spec/CHECKPOINT_DERIVATION_SPEC.md](docs/spec/CHECKPOINT_DERIVATION_SPEC.md)
- Availability completeness spec: [docs/spec/AVAILABILITY_STATE_COMPLETENESS.md](docs/spec/AVAILABILITY_STATE_COMPLETENESS.md)

## License

[LICENSE](LICENSE)
