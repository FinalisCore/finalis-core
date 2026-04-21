# Physical Structure Audit & Consolidation Proposal

This document proposes targeted folder consolidations to improve navigability and reduce low-cohesion directory fragmentation, following [PHYSICAL_DESIGN_GUIDELINES.md](PHYSICAL_DESIGN_GUIDELINES.md).

## Audit Methodology

Folders were evaluated on:
1. **Entity count**: single-file or two-file folders are candidates for consolidation.
2. **Cohesion**: are the files in a folder tightly coupled and single-purpose?
3. **Boundary clarity**: does the folder represent a stable architectural component or an incidental grouping?
4. **Dependency patterns**: do consolidation targets import heavily from a single parent component?

## Consolidation Candidates (Priority Order)

### Tier 1: High-Confidence Consolidations (No behavior risk, immediate clarity gain)

#### 1. Merge `src/address/` → `src/common/`
- **Current state**: 2 source files (address.cpp, address.hpp).
- **Rationale**: Address primitives are foundational shared utilities used across wallet, lightserver, and core components. No architectural boundary justifies a separate folder.
- **Acceptance criteria**:
  - Files: `src/common/address.cpp`, `src/common/address.hpp`
  - Update includes: `#include "common/address.hpp"` instead of `#include "address/address.hpp"`
  - Test includes unchanged in practice (typically use indirect includes)
  - `src/README.md` updated to remove address/ link, reference address utilities under common
- **Impact**: Reduced shallow folders by 1; clearer signal that address is a foundational utility.

#### 2. Merge `src/keystore/` → `src/common/`
- **Current state**: 2 source files (validator_keystore.cpp, validator_keystore.hpp).
- **Rationale**: Key storage support is a foundational utility for node initialization and wallet flows, not a boundary-defining component.
- **Acceptance criteria**:
  - Files: `src/common/keystore.cpp`, `src/common/keystore.hpp` (rename to avoid collision)
  - Update includes: `#include "common/keystore.hpp"` (rename header reference)
  - `src/README.md` updated to remove keystore/ link
- **Impact**: Clearer signal that key management is a shared utility; reduces folder count.

#### 3. Merge `src/policy/` → `src/consensus/`
- **Current state**: 2 source files (hashcash.cpp, hashcash.hpp).
- **Rationale**: Hashcash/proof-of-work policy is integral to consensus epoch-ticket validation; no boundary justifies separation.
- **Acceptance criteria**:
  - Files: `src/consensus/policy_hashcash.cpp`, `src/consensus/policy_hashcash.hpp`
  - Update includes: `#include "consensus/policy_hashcash.hpp"`
  - `src/README.md` updated to remove policy/ link; note this in consensus/README.md
- **Impact**: Clearer signal that admission policy is part of consensus decision-making; reduces folders.

#### 4. Merge `src/availability/` → `src/consensus/`
- **Current state**: 2 source files (retention.cpp, retention.hpp).
- **Rationale**: Availability retention logic is tightly coupled to checkpoint derivation and committee eligibility, both consensus concerns. Current separation is historical, not boundary-driven.
- **Acceptance criteria**:
  - Files: `src/consensus/availability_retention.cpp`, `src/consensus/availability_retention.hpp`
  - Update includes: `#include "consensus/availability_retention.hpp"`
  - `src/README.md` updated to remove availability/ link; note this in consensus/README.md
- **Impact**: Reduces folder count; aligns availability with consensus responsibility domain.

#### 5. Merge `src/merkle/` → `src/common/`
- **Current state**: 2 source files (merkle.cpp, merkle.hpp).
- **Rationale**: Merkle tree helpers are cross-cutting utilities used by storage and consensus, not a boundary-defining component. Belongs with shared data structures.
- **Acceptance criteria**:
  - Files: `src/common/merkle.cpp`, `src/common/merkle.hpp`
  - Update includes: `#include "common/merkle.hpp"`
  - `src/README.md` updated to remove merkle/ link
- **Impact**: Signal clarity: merkle utilities are foundational.

### Tier 2: Medium-Confidence Consolidations (Validate with maintainers)

#### 6. Merge `src/mempool/` → `src/node/`
- **Current state**: 2 source files (mempool.cpp, mempool.hpp).
- **Rationale**: Mempool is a tight single-entity component, but it's called exclusively by node orchestration and tightly coupled to node lifecycle. Could be a submodule of node.
- **Consideration**: Some teams prefer mempool isolation for independent testing; validate with codebase owner.
- **Acceptance criteria** (if approved):
  - Files: `src/node/mempool.cpp`, `src/node/mempool.hpp` (or `node_mempool.*`)
  - Update includes and callers
  - `src/README.md` updated; note in node/README.md
- **Decision deferred**: Consult primary maintainers before execution.

#### 7. Merge `src/onboarding/` → `src/consensus/`
- **Current state**: 2 source files (validator_onboarding.cpp, validator_onboarding.hpp).
- **Rationale**: Validator onboarding is a consensus-driven state machine; minimal separation value.
- **Consideration**: Onboarding may grow into a larger subsystem in future; this consolidation could be revisited.
- **Acceptance criteria** (if approved):
  - Files: `src/consensus/validator_onboarding.cpp`, `src/consensus/validator_onboarding.hpp`
  - Update includes
  - `src/README.md` updated; note in consensus/README.md
- **Decision deferred**: Confirm onboarding is not expected to grow independently.

### Tier 3: Keep As-Is (Justified Isolation)

#### ✓ `src/node/`
- Single-entity but critical orchestrator deserves isolation for clarity and test independence.
- **Decision**: Keep as-is.

#### ✓ `src/consensus/`
- Multi-entity component with clear boundary; already well-organized.
- **Decision**: Keep as-is.

#### ✓ `src/p2p/`
- Multiple entities with clear networking focus; stable boundary.
- **Decision**: Keep as-is.

#### ✓ `src/crypto/`
- Multiple entities with clear cryptographic focus; stable boundary.
- **Decision**: Keep as-is.

#### ✓ `src/utxo/`
- Multiple entities with clear UTXO-model focus; stable boundary.
- **Decision**: Keep as-is.

#### ✓ `src/storage/`
- Multiple entities with clear persistence focus; stable boundary.
- **Decision**: Keep as-is.

#### ✓ `src/wallet/`
- Multiple entities with clear wallet-facing focus; stable boundary.
- **Decision**: Keep as-is.

#### ✓ `src/common/`
- Intentionally multi-entity shared utility bucket; already acknowledged as foundational.
- **Decision**: Keep as-is (target for consolidations from Tier 1).

#### ✓ `src/lightserver/`, `src/codec/`, `src/genesis/`, `src/privacy/`
- Each has 4-5 closely related files with clear cohesion.
- **Decision**: Keep as-is for now; re-evaluate if further growth makes consolidation valuable.

## Proposed Migration Order

### Phase 1: Immediate (Tier 1, lowest risk)
1. Merge `src/address/` → `src/common/`
2. Merge `src/keystore/` → `src/common/`
3. Merge `src/merkle/` → `src/common/`
4. Merge `src/policy/` → `src/consensus/`
5. Merge `src/availability/` → `src/consensus/`

**Rationale**: These consolidations are purely structural with no logic changes; they reduce shallow folder count and improve signal clarity.

**Separate PR strategy**:
- Create a new PR branch: `refactor/structure-phase-1`
- Execute all five moves in one commit.
- Update include paths, CMakeLists.txt, build scripts.
- Run full test suite; confirm zero behavioral changes.
- Link to this audit document in PR description.

### Phase 2: Deferred (Tier 2, validate with maintainers first)
- Consolidate mempool and/or onboarding after team consensus.

## Acceptance Criteria (All Consolidations)

For each consolidation, verify:

1. **Include paths updated**: All callers use new #include paths; old paths removed from codebase.
2. **Build green**: `cmake -S . -B build && cmake --build build -j` succeeds.
3. **Tests unchanged**: All tests pass with exit code 0; no test rewrites needed.
4. **CMakeLists.txt updated**: Build targets reflect new file structure.
5. **src/README.md refreshed**: Component listing reflects consolidated structure; links updated.
6. **No logic changes**: Diff should show only file moves and include updates; no functional changes.

## Expected Outcome

After Phase 1 consolidations:
- `src/` folder count: reduced from 19 → 14
- Shallow single/dual-entity folders: eliminated
- Navigability: significantly improved ("where does X belong?" becomes obvious faster)
- Codebase surface clarity: enhanced (foundational utilities grouped in common; policy/availability in consensus)

## Future Monitoring

Add a check to repository policy/CI (via CONTRIBUTING.md and physical design guidelines):
- Discourage creation of new single-entity folders.
- If a new folder is created, it must be explicitly justified in the PR with expected growth/stability timeline.
