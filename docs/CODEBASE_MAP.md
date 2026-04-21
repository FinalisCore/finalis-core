# Codebase Map

This document helps contributors quickly identify where to read and where to add code.

## Top-Level Areas

- `src/`: Core C++ implementation for consensus, node runtime, storage, mempool, crypto, wallet primitives, and supporting subsystems.
- `apps/`: End-user applications and binaries (`finalis-node`, `finalis-lightserver`, `finalis-explorer`, `finalis-wallet`, `finalis-cli`).
- `services/`: Service-oriented components and operational services.
- `docs/`: Protocol and operational documentation.
- `tests/`: Unit, integration, fixture, and conformance tests.
- `formal/`: Formal models and model-checking inputs.
- `scripts/`: Operational and developer scripts.
- `sdk/`: External integration SDKs and API bindings.

## Core Runtime Path (High Level)

1. Node runtime executes finalized-state progression at `height = finalized_height + 1`.
2. Consensus and committee logic determine validator participation and finality.
3. Storage and state layers persist finalized transitions.
4. Public read surfaces expose finalized state via lightserver and explorer.

## Main Source Components Under `src/`

- `src/node/`: Node orchestration and finalized execution lifecycle.
- `src/consensus/`: Voting, quorum/finality, committee epoch and checkpoint mechanics.
- `src/p2p/`: Peer-to-peer networking and message transport.
- `src/storage/`: Persistence and state storage glue.
- `src/mempool/`: Transaction admission and pending transaction handling.
- `src/wallet/`: Wallet-facing primitives and related functionality.
- `src/common/`: Shared types, config, and cross-cutting helpers.
- `src/crypto/`: Cryptographic primitives and wrappers.

## Where To Add New Code

- Add runtime behavior to the most specific existing component first.
- Add cross-cutting helpers to `src/common/` only when truly shared.
- Avoid creating new top-level folders for one-off entities.
- If a new folder is required, document its boundary and ownership in a README.

## Related Reading

- `docs/ARCHITECTURE_ORIENTATION.md`
- `docs/PHYSICAL_DESIGN_GUIDELINES.md`
- `CONTRIBUTING.md`

## Documentation Coverage Status

Current `src/` component README coverage is complete for all first-level
components.

- `src/address/README.md`
- `src/availability/README.md`
- `src/codec/README.md`
- `src/common/README.md`
- `src/consensus/README.md`
- `src/crypto/README.md`
- `src/genesis/README.md`
- `src/keystore/README.md`
- `src/lightserver/README.md`
- `src/mempool/README.md`
- `src/merkle/README.md`
- `src/node/README.md`
- `src/onboarding/README.md`
- `src/p2p/README.md`
- `src/policy/README.md`
- `src/privacy/README.md`
- `src/storage/README.md`
- `src/utxo/README.md`
- `src/wallet/README.md`
