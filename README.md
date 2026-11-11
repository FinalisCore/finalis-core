<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="branding/web/logo-horizontal-dark.svg">
    <img src="branding/web/logo-horizontal-light.svg" alt="Finalis Core" width="480">
  </picture>
</p>

<p align="center">
  <b>A blockchain where a block is final the moment validators sign it,<br>
  with confidential transactions from genesis and a wallet that trusts no server.</b>
</p>

<p align="center">
  <a href="https://github.com/FinalisCore/finalis-core/actions/workflows/linux-ci.yml"><img src="https://github.com/FinalisCore/finalis-core/actions/workflows/linux-ci.yml/badge.svg" alt="Linux CI"></a>
  <a href="https://github.com/FinalisCore/finalis-core/actions/workflows/formal-verification.yml"><img src="https://github.com/FinalisCore/finalis-core/actions/workflows/formal-verification.yml/badge.svg" alt="TLA+ model checking"></a>
  <a href="https://github.com/FinalisCore/finalis-core/actions/workflows/cflite-batch.yml"><img src="https://github.com/FinalisCore/finalis-core/actions/workflows/cflite-batch.yml/badge.svg" alt="Fuzzing"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="MIT license"></a>
  <a href="testnet/JOIN.md"><img src="https://img.shields.io/badge/testnet--3-live-brightgreen.svg" alt="testnet-3 live"></a>
  <a href="https://discord.gg/8rKfKc7QR9"><img src="https://img.shields.io/badge/chat-Discord-5865F2.svg" alt="Discord"></a>
</p>

<p align="center">
  <a href="https://www.finaliscore.org"><b>Website</b></a> ·
  <a href="docs/WHAT_IS_FINALIS.md"><b>What is Finalis?</b></a> ·
  <a href="testnet/JOIN.md"><b>Run a node</b></a> ·
  <a href="https://finalis.self-link.com"><b>Live explorer</b></a> ·
  <a href="docs/REVIEWING.md"><b>Break these claims</b></a> ·
  <a href="docs/whitepaper/WHITEPAPER.md"><b>Whitepaper</b></a> ·
  <a href="https://discord.gg/8rKfKc7QR9"><b>Discord</b></a>
</p>

---

## Why Finalis

- **Final means final.** A block is final once more than two-thirds of the
  validator committee precommits to it. There is no fork choice, no reorgs and
  no "wait for 6 confirmations": the node only ever builds on
  `finalized_height + 1`.
- **Confidential from genesis.** Amounts in confidential transfers are hidden
  with Pedersen commitments and Bulletproof range proofs (secp256k1-zkp), and
  each payment goes to a one-time key from a fresh receive request. Privacy is
  part of the base layer, not an add-on. The transaction graph stays public;
  everything else that does is stated in
  [the spec](docs/spec/CONFIDENTIAL_UTXO_SPEC.md) (§3.3).
- **Your wallet checks, not trusts.** The wallet starts from the genesis
  compiled into it, follows each committee handoff, and checks its balance
  against validator signatures. A server cannot invent coins, and one honest
  server is enough to expose a hidden one ([LIGHT_CLIENT.md](docs/spec/LIGHT_CLIENT.md)).
- **Deterministic from finalized history.** Committees, validator lifecycle,
  checkpoints and rewards are all derived from finalized state, so every honest
  node computes the same result with no off-chain coordination.
- **Fixed supply.** 7,000,000 FLS hard cap, emitted over 12 years with 20%
  annual decay, then validators are paid from fees and a protocol reserve
  ([ECONOMICS.md](docs/ECONOMICS.md)).

## Built To Be Checked

- **TLA+ models** of two-phase finality, checkpoint availability and
  time-locked release, including mutation configs that must fail
  ([formal/](formal/)), model-checked in CI.
- **Continuous fuzzing** of consensus messages and node state, P2P framing,
  wire codecs, transaction parsing, sync, the sparse Merkle tree, confidential
  transactions and time-locked settlement ([fuzz/](fuzz/)).
- **Nightly chaos runs** with crashing and Byzantine validators, plus an
  [adversarial protocol simulator](docs/PROTOCOL_ATTACK_SIMULATOR.md).
- **Explicit claims.** [docs/REVIEWING.md](docs/REVIEWING.md) lists the safety,
  liveness and privacy claims I want broken, with the spec section and code
  for each.

## Get Involved

**Run a node or become a validator.** testnet-3 has been running since 2026-10-29,
06:00 UTC, on mainnet's rules. Its coins have no value, and validator bonds are free
from the faucet. Every independent validator makes the chain harder to stop.
Mainnet will start the same way: one bootstrap validator, and everyone else
joins by bonding coins from the faucet, with no reserved slots
([mainnet/MAINNET_PLAN.md](mainnet/MAINNET_PLAN.md#launch-model)).
→ **[testnet/JOIN.md](testnet/JOIN.md)**: one command with the prebuilt Linux
package or Docker (x86_64 and ARM64), or Windows installers from the
[releases page](https://github.com/FinalisCore/finalis-core/releases).

**Review the protocol or the cryptography.** Finalis is pre-launch, so a
finding can still change the protocol itself. Start with
[docs/REVIEWING.md](docs/REVIEWING.md) and report vulnerabilities privately per
[SECURITY.md](SECURITY.md).

**Contribute code.** C++20 node, Qt wallet, explorer and a JavaScript SDK.
See [CONTRIBUTING.md](CONTRIBUTING.md) and the
[codebase map](docs/CODEBASE_MAP.md).

## Official Channels

The [website](https://www.finaliscore.org), GitHub (this repo), [Discord](https://discord.gg/8rKfKc7QR9), the
[explorer](https://finalis.self-link.com) and [X](https://x.com/finalis_core). Nothing else is official.

**There is no official Telegram, token sale, presale, airdrop, whitelist or "team wallet".** Nobody can
sell you FLS before mainnet, and nobody from Finalis will ask for coins, keys or a seed phrase. If
someone does, it's a scam: report it in Discord. Community-run groups are welcome but unofficial.

> **Status: pre-launch.** Mainnet has not launched, so there are no user funds
> and no legacy state. Mainnet genesis is not frozen yet
> ([mainnet/MAINNET_PLAN.md](mainnet/MAINNET_PLAN.md)), so the identity below
> can still change.

## Network Identity

Mainnet (pre-launch):

- `network_name = mainnet`
- `network_id = fe561911730912cced1e83bc273fab13`
- `genesis_hash`: published at launch (mainnet has not launched)
- `magic = 0x499602D2`

Testnet identity and parameters: [testnet/README.md](testnet/README.md).

## What The Code Implements

- a UTXO ledger
- two transaction formats, both valid from genesis: `Tx` (transparent) and
  `TxV2` (confidential-capable), parsed together as `AnyTx`, plus `TxTimed`
  (time-locked sends and sealed data, encrypted until their unlock height)
- UTXO state (`UtxoSetV2`) holding transparent and confidential outputs
- a validator committee
- two-phase quorum finality
- deterministic epoch-boundary checkpoint derivation
- finalized-state read surfaces, with proofs that let clients verify them

Databases and artifacts from earlier development networks are not valid inputs
to mainnet; start from an empty data directory.

## Repository Components

- `finalis-node`
  - full node
  - validation
  - finalized execution
  - committee / finality runtime
- `finalis-lightserver`
  - finalized-state JSON-RPC service
  - runs standalone or as a child of the node (`--with-lightserver`)
- `finalis-explorer`
  - HTTP UI and REST layer on top of lightserver
  - local-first cached homepage / tx / transition views with freshness and
    provenance markers
  - versioned partner API (`/api/v1`) for exchanges and integrators
- `finalis-wallet`
  - Qt desktop wallet
  - local-first cached runtime/view state
  - confidential account, receive-request, and imported-coin UX for the
    supported confidential subset
  - balances verified against validator signatures (see "Read Surfaces")
- `finalis-cli`
  - command-line wallet, validator registration, genesis tooling, RPC queries
    and release signing (`release-keygen`, `release-manifest`, `release-sign`)
- `finalis-nodetest`
  - testnet traffic tool for validators, with its own throwaway wallet; refuses
    mainnet ([apps/finalis-nodetest/README.md](apps/finalis-nodetest/README.md))
- `finalis-updater`
  - checks that a release is signed by the keys in the operator's trust policy
    and reports newer trusted releases; installs nothing yet
    ([docs/operations/UPDATER.md](docs/operations/UPDATER.md))

This repository also contains:

- formal TLA+ models (two-phase finality, checkpoint availability, time-locked
  release) under [formal/](formal/)
- adversarial simulation under [scripts/protocol_attack_sim.py](scripts/protocol_attack_sim.py)
- C++ fixture export and Python conformance tests under
  [tests/fixtures/](tests/fixtures)
- a JavaScript wallet SDK under [sdk/finalis-wallet-js/](sdk/finalis-wallet-js)
- an Nginx reverse-proxy template for public hosts under [packaging/nginx/](packaging/nginx)

## Protocol Facts

- finality is two-phase (prevote, then precommit); a block finalizes with
  `floor(2N/3) + 1` valid precommits ([TWO_PHASE_FINALITY.md](docs/spec/TWO_PHASE_FINALITY.md))
- prevotes and precommits are bound to `(height, round, transition_id)` in
  separate signing domains, and every signature commits to the chain
  (network id and genesis hash)
- minimum block interval: 3 minutes (blocks never come faster; a stalled
  round makes them slower)
- the committee for a height comes from the finalized checkpoint for that
  height's epoch (32 blocks)
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
- `get_committee_handoffs`, `get_utxo_proofs` (light-client proofs)

`finalis-explorer` exposes thin finalized-state HTTP routes such as:

- `/api/status`
- `/api/committee`
- `/api/tx/<txid>`
- `/api/transition/<height_or_hash>`
- `/api/address/<address>`

and the stable partner API under `/api/v1` ([PARTNER_API_V1.md](docs/integrations/PARTNER_API_V1.md)).

`broadcast_tx` is a relay-submission surface. Finalized visibility still comes
from finalized-state lookup.

Clients need not trust a lightserver. A wallet starts from the genesis compiled
into it, follows each epoch's committee through signed handoffs, and checks its
coins against the validators' signatures on the finalized tip. It combines the
coins every configured server reports, so no server can invent a coin, and one
honest server is enough to reveal a coin another hides. See
[LIGHT_CLIENT.md](docs/spec/LIGHT_CLIENT.md).

Confidential transactions use `TxV2`. The wallet supports:

- transparent -> confidential (shield)
- confidential -> confidential (amounts hidden; only the fee is public)
- confidential -> transparent (unshield)

It also supports transparent sends that are time-locked or locked by height:

- time-locked: recipient and amount stay encrypted on-chain until a chosen height, then the payment
  opens by itself. The sender's bond comes back if the payment applies, or if the network never
  opens it (a long lock past its grace period); it is forfeited if the opened payment cannot apply,
  for example because the sender spent the coin it depends on
- sealed data: the same, for data instead of a payment
- height lock: visible at once, but the recipient cannot spend it before a chosen height
- inheritance lock: the owner can spend at any height, the heir from a chosen height

Amounts are private only in confidential -> confidential transfers: shield and
unshield amounts can be computed from their public parts, and the transaction
graph is always public. See
[CONFIDENTIAL_UTXO_SPEC.md §3.3](docs/spec/CONFIDENTIAL_UTXO_SPEC.md).

Public read surfaces stay finalized-only and do not expose confidential output
amounts or recipients as if they were transparent fields.

## Addresses And Keys

The current key / address model is:

- Ed25519 private keys
- Ed25519 32-byte public keys
- P2PKH addresses
- `HASH160(pubkey)` address payload
- `sc` (mainnet) / `tsc` (testnet) HRP-based address encoding

See [docs/ADDRESSES.md](docs/ADDRESSES.md).

## Economics

The current code implements:

- deterministic reward settlement
- a height-gated economics schedule in `src/common/network.cpp`
- adaptive checkpoint target / minimum eligible / minimum bond derivation
- exact hard cap of `7,000,000 FLS`
- deterministic `12`-year emission schedule with annual `20%` decay
- `30%` reserve accrual during the emission era; half of every fee and every slashed bond return to
  the reserve, which pays 5 % of itself a year after emission ends (fixed 7M supply, paid for ever)
- zero new issuance after the cap
- an automatic base fee that follows block fullness (no price, no setting)

## Run A Node

Mainnet has not launched. To run a node today, join the testnet:
**[testnet/JOIN.md](testnet/JOIN.md)** (run a node, then optionally become a
validator).

Default ports:

| | mainnet | testnet |
|---|---|---|
| P2P | `19440` | `19540` |
| lightserver RPC | `19444` | `19544` |
| data directory | `~/.finalis/mainnet` | `~/.finalis/testnet` |

Always verify a node's identity with `get_status` before relying on it, for example:

```bash
curl -s http://127.0.0.1:19544/rpc -d '{"jsonrpc":"2.0","id":1,"method":"get_status","params":{}}'
```

It must report the expected `network_name`, `network_id`, `genesis_hash` and
`chain_id_ok: true`.

### Linux

Prebuilt package (x86_64 or ARM64; Ubuntu 24.04+, Debian 13+, Fedora 40+, Arch):

```bash
curl -fsSL https://raw.githubusercontent.com/FinalisCore/finalis-core/main/scripts/install.sh | bash
```

Docker (any distro):

```bash
docker run -d --name finalis --restart on-failure:5 \
  -p 19540:19540 -p 127.0.0.1:19544:19544 -v finalis-data:/var/lib/finalis \
  ghcr.io/finaliscore/finalis-core:latest
```

From source, [scripts/start.sh](scripts/start.sh) installs dependencies, builds,
and installs systemd services for the node, lightserver and explorer:

```bash
git clone https://github.com/FinalisCore/finalis-core.git
cd finalis-core
FINALIS_NETWORK=testnet SERVICE_NAME=finalis-testnet ./scripts/start.sh
```

Its options (ports, binding, firewall, explorer) are listed in
[testnet/README.md](testnet/README.md#run-a-node). To serve the explorer and RPC
publicly over HTTPS behind Nginx, see [DEPLOYMENT.md](DEPLOYMENT.md).

### Windows

Installers are published on the
[releases page](https://github.com/FinalisCore/finalis-core/releases). Mainnet
has not launched, so run a testnet node as shown in
[testnet/README.md](testnet/README.md#windows). The installer's
`Start-Finalis.ps1` starts mainnet only and is for use after launch.

### Mainnet (at launch)

The bootstrap validator starts before `genesis_time_unix`; everyone else runs a
node and joins as a validator by bonding, exactly as on the testnet
([testnet/JOIN.md](testnet/JOIN.md),
[mainnet/MAINNET_PLAN.md](mainnet/MAINNET_PLAN.md#launch-model)). Check that
your binaries embed the canonical `genesis.bin` (`finalis-cli genesis_print_embedded`).

## Build From Source

Dependencies (Debian/Ubuntu; [scripts/bootstrap_deps.sh](scripts/bootstrap_deps.sh)
installs them on apt, dnf and pacman systems):

```bash
sudo apt install -y build-essential cmake ninja-build pkg-config git python3 libssl-dev \
  libsodium-dev librocksdb-dev nlohmann-json3-dev \
  qtbase5-dev qtbase5-dev-tools   # Qt only for the desktop wallet
```

Build:

```bash
cmake -S . -B build -G Ninja && cmake --build build -j
```

Dependency notes:

- If `third_party/secp256k1-zkp` or `third_party/blst` is missing, CMake fetches it (network
  required).
- For offline builds, provide both vendored trees at their pinned commits and disable auto-fetch:
  ```bash
  git clone https://github.com/ElementsProject/secp256k1-zkp.git third_party/secp256k1-zkp
  git -C third_party/secp256k1-zkp checkout 08d1cd0c9c35a5a151ba80c226d49ea949e90374
  git clone https://github.com/supranational/blst.git third_party/blst
  git -C third_party/blst checkout 54e6e55674722fc2797ebb4bbb71b26d881eb4b8  # v0.3.17
  cmake -S . -B build -G Ninja -DFINALIS_AUTO_FETCH_DEPS=OFF -DFINALIS_BUILD_NGINX=OFF
  ```
- On Linux the default build also downloads and compiles a local Nginx (reverse proxy for public
  RPC/explorer hosts). Validators and offline builds can skip it with `-DFINALIS_BUILD_NGINX=OFF`.
- Without Qt5 Widgets the desktop wallet target is skipped; everything else builds.

## Testing

```bash
ctest --test-dir build --output-on-failure -LE known-defect
```

`-LE known-defect` skips the reproducers of open defects, which are expected to fail
([tests/KNOWN_DEFECTS.md](tests/KNOWN_DEFECTS.md)). Run a subset of the main suite with `FINALIS_TEST_FILTER=<substring> ./build/finalis-tests`.

## Documentation

- Security policy: [SECURITY.md](SECURITY.md)
- Reviewer guide: [docs/REVIEWING.md](docs/REVIEWING.md)
- Documentation index: [docs/README.md](docs/README.md)
- Codebase map: [docs/CODEBASE_MAP.md](docs/CODEBASE_MAP.md)
- Architecture orientation: [docs/ARCHITECTURE_ORIENTATION.md](docs/ARCHITECTURE_ORIENTATION.md)
- Physical design guidance: [docs/PHYSICAL_DESIGN_GUIDELINES.md](docs/PHYSICAL_DESIGN_GUIDELINES.md)
- License policy: [docs/LICENSE_POLICY.md](docs/LICENSE_POLICY.md)
- Contributing guide: [CONTRIBUTING.md](CONTRIBUTING.md)
- Testnet: [testnet/README.md](testnet/README.md), [joining guide](testnet/JOIN.md)
- Deployment (systemd, Nginx/HTTPS): [DEPLOYMENT.md](DEPLOYMENT.md)
- Exchange integration: [docs/integrations/EXCHANGE_INTEGRATION.md](docs/integrations/EXCHANGE_INTEGRATION.md)
- Live protocol: [docs/LIVE_PROTOCOL.md](docs/LIVE_PROTOCOL.md)
- Consensus overview: [docs/CONSENSUS.md](docs/CONSENSUS.md)
- Two-phase finality: [docs/spec/TWO_PHASE_FINALITY.md](docs/spec/TWO_PHASE_FINALITY.md)
- Light-client verification: [docs/spec/LIGHT_CLIENT.md](docs/spec/LIGHT_CLIENT.md)
- Confidential UTXO spec: [docs/spec/CONFIDENTIAL_UTXO_SPEC.md](docs/spec/CONFIDENTIAL_UTXO_SPEC.md)
- Checkpoint derivation spec: [docs/spec/CHECKPOINT_DERIVATION_SPEC.md](docs/spec/CHECKPOINT_DERIVATION_SPEC.md)
- Availability completeness spec: [docs/spec/AVAILABILITY_STATE_COMPLETENESS.md](docs/spec/AVAILABILITY_STATE_COMPLETENESS.md)

## License

[LICENSE](LICENSE)
