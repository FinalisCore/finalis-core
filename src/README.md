# Source Tree Overview

This README explains the purpose of major source components under `src/`.

## Component Overview

- [`codec/`](codec/README.md): Encoding and decoding infrastructure.
- [`common/`](common/README.md): Shared foundational types, constants, and helpers.
- [`consensus/`](consensus/README.md): Core consensus, committee, and finality logic.
- [`crypto/`](crypto/README.md): Cryptographic operations and wrappers.
- [`genesis/`](genesis/README.md): Genesis state and initialization data handling.
- [`lightserver/`](lightserver/README.md): Finalized-state RPC support components.
- [`mempool/`](mempool/README.md): Transaction admission and pending transaction handling.
- [`node/`](node/README.md): Node runtime orchestration and execution flow.
- [`onboarding/`](onboarding/README.md): Validator/operator onboarding support.
- [`p2p/`](p2p/README.md): Peer networking and protocol transport.
- [`privacy/`](privacy/README.md): Index of where confidential transaction code lives (no code here).
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
