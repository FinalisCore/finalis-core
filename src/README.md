# Source Tree Overview

This README explains the purpose of major source components under `src/`.

## Component Overview

- `address/`: Address formatting and related primitives.
- `availability/`: Availability and checkpoint-related runtime support.
- `codec/`: Encoding and decoding infrastructure.
- `common/`: Shared foundational types, constants, and helpers.
- `consensus/`: Core consensus, committee, and finality logic.
- `crypto/`: Cryptographic operations and wrappers.
- `genesis/`: Genesis state and initialization data handling.
- `keystore/`: Key management support.
- `lightserver/`: Finalized-state RPC support components.
- `mempool/`: Transaction admission and pending transaction management.
- `merkle/`: Merkle structures and proofs.
- `node/`: Node runtime orchestration and execution flow.
- `onboarding/`: Validator/operator onboarding support.
- `p2p/`: Peer networking and protocol transport.
- `policy/`: Policy-level validation and gatekeeping logic.
- `privacy/`: Confidential/privacy-oriented transaction support.
- `storage/`: Persistent storage and state indexing.
- `utxo/`: UTXO model and state transitions.
- `wallet/`: Wallet-facing core logic.

## Placement Guidance

- Add code to the narrowest existing component that matches responsibility.
- Avoid creating a new component unless there is a stable long-term boundary.
- If adding a new component, include a README with purpose and dependency direction.

## See Also

- `docs/CODEBASE_MAP.md`
- `docs/ARCHITECTURE_ORIENTATION.md`
- `docs/PHYSICAL_DESIGN_GUIDELINES.md`
