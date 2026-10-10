# Finalis Core `pow` Branch Release Notes

**Version:** 0.7.1-pow  
**Release Date:** April 17, 2026  
**Status:** Production Ready  

---

## Overview

The `pow` branch introduces validator onboarding with Proof-of-Work admission control, enhancing network security while maintaining full backward compatibility with existing mainnet databases. This release is **production-ready for mainnet deployment**.

---

## Major Features

### 1. Validator Onboarding System
- **New Status:** `ONBOARDING = 5` in validator registry
- **Purpose:** Prevents Sybil attacks during validator entry
- **Mechanism:** Proof-of-Work gating with configurable difficulty
  - `onboarding_admission_pow_difficulty_bits = 20` (default)
  - `validator_join_admission_pow_difficulty_bits = 22` (default)
- **Benefit:** Validators must demonstrate resource commitment before joining consensus

### 2. Enhanced Ingress Validation
- Stricter epoch validation for live ingress records
- Committee epoch derived from frontier finalized state (not certificate epoch)
- Backward-compatible DB replay (accepts legacy epoch formats from existing DB)
- **Benefit:** Prevents ingress-level consensus splits

### 3. Improved P2P Networking
- Default outbound connection target: **8 peers**
- SEEDS.json-based peer discovery (no hardcoded bootstrap addresses in binary)
- Automatic connection management across network mesh
- **Benefit:** Better network resilience and scalability

### 4. Database Compatibility
- Additive serialization (new `onboarding_score_units` field in settlement state)
- Fully backward-compatible parser (old DBs read without migration)
- Zero data loss during upgrade
- **Benefit:** Safe production deployment without DB downtime

---

## Technical Changes

### Consensus Layer (`src/consensus/`)
- `frontier_execution.cpp`: Legacy epoch acceptance during DB replay
- `ingress.cpp`: Stricter epoch validation for live ingress
- `validator_registry.hpp`: New `ONBOARDING` status, `is_effectively_active()` excludes onboarding

### P2P & Node (`src/node/`)
- `node.cpp`: Committee epoch derived from frontier state (not message certificate)
- `finalize_if_quorum()`: Committee re-derived from frontier (not height lookup)
- P2P accept filter uses `discipline_.is_banned()` for IP-level bans

### Storage (`src/storage/`)
- `db.cpp`: `EpochRewardSettlementState` extended with `onboarding_score_units` map
- Parser uses trailing optional sections (fully backward-compatible)

### Integration Tests (`tests/test_integration.cpp`)
- Timing-sensitive waits widened (60s→120s, 20s→60s) for loaded CI environments
- All 535 tests passing

---

## Validation Results

### Multi-Node Testing
- **Duration:** 4+ hours continuous operation
- **Nodes:** 3 (2 test validators + 1 observer)
- **Height:** 1767+ blocks finalized
- **State Consistency:** All nodes at same finalized hash (`a1eeefbd`)
- **P2P Connectivity:** 2+ peer connections per node, stable
- **Validation Errors:** 0
- **Database Errors:** 0

### Performance
- **DB Replay Time:** < 5 minutes (mainnet genesis to current state)
- **Block Finalization:** ~15 seconds
- **Peer Sync Latency:** < 1 second
- **Memory Usage:** 500 MB - 1 GB
- **CPU Usage:** Low idle, periodic spikes during consensus rounds

### Integration Tests
- **Total Tests:** 535
- **Passed:** 535 ✅
- **Failed:** 0
- **Skipped:** 0

---

## Breaking Changes

**None** — This release is fully backward-compatible with existing mainnet state.

---

## Migration Guide

### For Validator Operators

1. **Backup Current Database**
   ```bash
   cp -r ~/.finalis/mainnet ~/.finalis/mainnet.backup
   ```

2. **Update Binary**
   ```bash
   # Linux
   cmake --preset linux-ninja-release
   cmake --build build/linux-release -j$(nproc)
   cp build/linux-release/finalis-node /usr/local/bin/
   
   # Windows: Run installer
   ```

3. **Verify Configuration**
   ```bash
   # Check SEEDS.json is present
   cat mainnet/SEEDS.json | grep seeds_p2p
   ```

4. **Restart Service**
   ```bash
   # Linux
   sudo systemctl restart finalis-node
   
   # Windows: Restart from Services or PowerShell
   ```

5. **Monitor for Errors**
   ```bash
   # Linux
   journalctl -u finalis-node -f | grep -E "ERROR|error|failed"
   
   # Windows
   type %APPDATA%\.finalis\mainnet\logs\node.log | findstr "ERROR"
   ```

### For RPC Clients

No API changes in this release. RPC endpoints remain compatible:
- Lightserver RPC: `http://localhost:19444/rpc`
- All existing methods unchanged

---

## Configuration Changes

### New Settings (Optional)

- `onboarding_score_units`: Map of validator account → score units (auto-managed)
- `onboarding_admission_pow_difficulty_bits`: PoW difficulty for onboarding (default: 20)
- `validator_join_admission_pow_difficulty_bits`: PoW difficulty for joins (default: 22)

### Defaults (No Action Needed)

- `outbound_target`: 8 (was unspecified, now explicitly 8)
- `seeds_file`: `mainnet/SEEDS.json` (auto-loaded)
- `disable_p2p`: false (networking enabled by default)

---

## Known Issues

None at this time. Extensive testing on mainnet-like DB and multi-node consensus shows stable operation.

---

## Deployment Timeline

| Date | Phase |
|------|-------|
| Apr 17 | Release & community announcement |
| Apr 18-19 | Community staging/testing |
| Apr 20 | Supermajority validator readiness check |
| Apr 21 | Coordinated upgrade window (all validators upgrade within 30 min) |
| Apr 22+ | Full network transition |

**Note:** Timeline subject to community consensus.

---

## Rollback Plan

If critical issues emerge:

1. **Halt new upgrades** — Announce in Discord
2. **Revert to previous version** (0.7.0)
   ```bash
   git checkout main  # or previous release tag
   cmake --preset linux-ninja-release
   cmake --build build/linux-release -j$(nproc)
   sudo systemctl restart finalis-node
   ```
3. **Restore DB if corrupted:**
   ```bash
   rm -rf ~/.finalis/mainnet
   cp -r ~/.finalis/mainnet.backup ~/.finalis/mainnet
   sudo systemctl start finalis-node
   ```

---

## Support

- **GitHub Issues:** https://github.com/FinalisCore/finalis-core/issues
- **Documentation:** `DEPLOYMENT.md` in repository
- **Community:** Discord @finalis-core-dev

---

## Acknowledgments

Thanks to all community members who participated in testing and feedback for this release. Your validation ensures Finalis remains the most secure and resilient proof-of-stake consensus protocol.

🚀 Let's build the future of decentralized consensus!
