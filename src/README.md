# Source Tree Overview

This README explains the purpose of major source components under `src/`.

## Component Overview

- [`address/`](address/README.md): Address formatting and related primitives.
- [`availability/`](availability/README.md): Availability and checkpoint-related runtime support.
- [`codec/`](codec/README.md): Encoding and decoding infrastructure.
- [`common/`](common/README.md): Shared foundational types, constants, and helpers.
- [`consensus/`](consensus/README.md): Core consensus, committee, and finality logic.
- [`crypto/`](crypto/README.md): Cryptographic operations and wrappers.
- [`genesis/`](genesis/README.md): Genesis state and initialization data handling.
- [`keystore/`](keystore/README.md): Key management support.
- [`lightserver/`](lightserver/README.md): Finalized-state RPC support components.
- [`mempool/`](mempool/README.md): Transaction admission and pending transaction handling.
- [`merkle/`](merkle/README.md): Merkle structures and proofs.
- [`node/`](node/README.md): Node runtime orchestration and execution flow.
- [`onboarding/`](onboarding/README.md): Validator/operator onboarding support.
- [`p2p/`](p2p/README.md): Peer networking and protocol transport.
- [`policy/`](policy/README.md): Policy-level validation and gatekeeping logic.
- [`privacy/`](privacy/README.md): Confidential/privacy-oriented transaction support.
- [`storage/`](storage/README.md): Persistent storage and state indexing.
- [`utxo/`](utxo/README.md): UTXO model and state transitions.
- [`wallet/`](wallet/README.md): Wallet-facing core logic.

## Placement Guidance

- Add code to the narrowest existing component that matches responsibility.
- Avoid creating a new component unless there is a stable long-term boundary.
- If adding a new component, include a README with purpose and dependency direction.

## See Also

- `docs/CODEBASE_MAP.md`
- `docs/ARCHITECTURE_ORIENTATION.md`
- `docs/PHYSICAL_DESIGN_GUIDELINES.md`
