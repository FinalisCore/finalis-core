# Finalis Core v1.0.0 Release Notes

Finalis Core v1.0.0 is the first production release line for the repository and introduces validator onboarding admission controls, stricter consensus validation behavior, and updated operational packaging defaults.

- Repository: https://github.com/FinalisCore/finalis-core
- Version: `v1.0.0`
- License: BUSL-1.1

## Highlights

- Validator onboarding with explicit lifecycle state and admission gating.
- Consensus ingress epoch validation hardening for live traffic.
- Replay compatibility for historical database state.
- Default outbound peering target aligned to public network bootstrap.
- Cross-platform packaging and runbook updates for Linux and Windows.

## Feature Summary

### Validator Onboarding

- Introduces onboarding validator status handling in registry lifecycle.
- Enforces admission PoW configuration for onboarding and join-path controls.
- Keeps onboarding identities out of active-validator assumptions until eligibility criteria are met.
- Onboarding reward eligibility is ticket-based: finalized valid epoch tickets can participate in the `3%` onboarding reward bucket even before funded on-chain onboarding registration.

### Consensus and Ingress Hardening

- Tightens ingress certificate epoch checks for live message paths.
- Derives committee context from canonical frontier state during finalization-sensitive flows.
- Preserves replay acceptance logic for legacy lane genesis/early-sequence records to avoid startup failures on existing mainnet data.

### P2P and Bootstrap Behavior

- Uses seed-driven peer bootstrap via `mainnet/SEEDS.json`.
- Aligns default outbound connectivity target for healthier peer formation in fresh deployments.
- Maintains explicit operator control through CLI flags for deployment-specific overrides.

### Storage and Compatibility

- Extends settlement state serialization with additive, optional fields.
- Preserves backward parsing behavior for prior records.
- Avoids migration-only release requirements for standard node upgrades.

## Validation Results

### Multi-Node Network Validation

- Multi-node consensus validation completed with stable finalized height progression.
- Finalized transitions remained consistent across participating nodes.
- Peer sessions remained established without sustained connectivity regressions.

### Test Suite

- Integration suite executed with all tests passing in the validated run.
- Load-sensitive waits were adjusted in selected integration paths to reduce environment-induced flakiness.

### Mainnet Database Replay

- Replay startup path validated against existing mainnet database state.
- No blocking replay compatibility regressions observed after patch set.

## Operational Impact

### Default Behavior

- Deployments inherit updated peering defaults where release packaging scripts are used.
- Seed list entries should reflect production bootstrap nodes before publication.

### Upgrade Path

1. Backup existing data directory.
2. Deploy v1.0.0 binary set.
3. Restart node services.
4. Confirm peer establishment and finalized height progression.

### Coordinated Upgrade Requirement

- This release changes onboarding reward attribution semantics.
- Mixed-version validating networks are not the intended rollout mode for this change.
- Upgrade validator and lightserver fleets in a coordinated window so reward eligibility and reporting remain consistent across the network.

### Recommended Checks

```bash
journalctl -u finalis-node -f | grep "peers="
journalctl -u finalis-node -f | grep "^mainnet h="
```

## Artifact Distribution

Expected release artifacts:

- `finalis-node` (Linux)
- `finalis-lightserver` (Linux)
- `finalis-node.exe` (Windows)
- `finalis-lightserver.exe` (Windows)
- `finalis-core_installer.exe` (Windows installer)
- `CHECKSUMS.txt`

Container distribution tags:

- `finalis/finalis-core:v1.0.0`
- `finalis/finalis-core:latest`

## Rollback Guidance

If a critical regression is confirmed in production:

1. Halt rollout announcements.
2. Revert service binaries to prior known-good release.
3. Restore data from backup if any state corruption is detected.
4. Resume rollout only after root-cause validation and patched artifact publication.

## Known Issues

No release-blocking known issues are declared at publication time.

Issue reports:

- https://github.com/FinalisCore/finalis-core/issues
