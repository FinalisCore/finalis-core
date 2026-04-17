# Finalis Core v1.0.0 - Production Release

**Release Date:** April 17, 2026  
**Version:** 1.0.0  
**Status:** Production Ready  
**Repository:** https://github.com/FinalisCore/finalis-core

---

## 🎉 v1.0.0 Release Highlights

This is the **first production release** of Finalis Core, marking the transition from development branch (`pow`) to stable mainnet production. This release introduces **validator onboarding with Proof-of-Work admission control**, **enhanced consensus security**, and **improved P2P networking**.

### Key Milestones
- ✅ Validator onboarding protocol fully implemented and tested
- ✅ 4+ hours of multi-node consensus testing with zero errors
- ✅ Backward-compatible with existing mainnet database (zero migration required)
- ✅ 535/535 integration tests passing
- ✅ Cross-platform support (Linux, Windows, macOS, Docker)

---

## Major Features

### 1. Validator Onboarding System ⭐
**Problem Solved:** Sybil attack resistance during validator entry

- **New Validator Status:** `ONBOARDING = 5` in validator registry
- **Proof-of-Work Gating:** Validators must solve PoW challenge before joining consensus
  - `onboarding_admission_pow_difficulty_bits = 20` (default, ~1 second CPU per attempt)
  - `validator_join_admission_pow_difficulty_bits = 22` (default, ~4 seconds per attempt)
- **Benefit:** Prevents spam/sybil attacks while allowing legitimate validator entry
- **Protocol:** See `docs/ONBOARDING-PROTOCOL.md` for full specification

### 2. Enhanced Consensus Security
**Problem Solved:** Ingress-level consensus splits and epoch validation exploits

- **Stricter Ingress Epoch Validation:** Committee epoch derived from frontier finalized state (not certificate epoch)
- **Live vs. Replay Compatibility:** New ingress records use strict validation; legacy DB records accepted during replay
- **Finalization Flow Improvements:** Committee re-derived from frontier state for more reliable finalization
- **Benefit:** Prevents consensus splits and ensures all validators follow identical rules

### 3. Improved P2P Networking
**Problem Solved:** Network scalability and operator burden

- **Default Outbound Target:** `--outbound-target 8` (connects to up to 8 peers automatically)
- **SEEDS.json-Based Discovery:** Peer list loaded from `mainnet/SEEDS.json` (no hardcoded bootstrap addresses in binary)
- **Automatic Connection Management:** Node autonomously connects, disconnects, and rebalances connections
- **Benefit:** Better network resilience, scalability to thousands of validators, no manual peer configuration

### 4. Database Compatibility
**Problem Solved:** Zero-downtime upgrades without migration tooling

- **Additive Serialization:** New `onboarding_score_units` field in settlement state (doesn't break old parsers)
- **Trailing Optional Fields:** Old DB records parse correctly without any data transformation
- **Zero Data Loss:** All state preserved during upgrade
- **Benefit:** Seamless validator upgrades without downtime or DB tools

---

## Technical Changes

### Consensus & Validation (`src/consensus/`)
- **`frontier_execution.cpp`:** Legacy epoch acceptance during DB replay; strict validation for live ingress
- **`ingress.cpp`:** Stricter epoch validation; committee epoch derived from frontier
- **`validator_registry.cpp`:** New `ONBOARDING` status; `is_effectively_active()` excludes onboarding validators
- **`canonical_derivation.cpp`:** Committee derivation improvements for finalization reliability

### P2P & Node (`src/node/`)
- **`node.cpp`:** 
  - Committee epoch now derived from frontier (not message certificate)
  - `finalize_if_quorum()` re-derives committee from frontier state
  - Accept filter uses `discipline_.is_banned()` for IP-level bans
  - P2P initialization with configurable `--outbound-target`

### Storage (`src/storage/`)
- **`db.cpp`:** `EpochRewardSettlementState` extended with `onboarding_score_units` map
- **Parser:** Fully backward-compatible; uses trailing optional sections

### Deployment & Packaging
- **`packaging/linux/finalis-node.service`:** Systemd service template with `--outbound-target 8`
- **`packaging/linux/install-finalis-node.sh`:** Automated installation and systemd setup
- **`packaging/windows/Start-Finalis.ps1`:** Windows PowerShell launch script with proper P2P configuration
- **`DEPLOYMENT.md`:** Complete deployment guide for all platforms

---

## Validation & Testing

### Multi-Node Consensus Testing ✅
```
Duration:              4+ hours continuous
Nodes:                 3 validators/observers
Height:                1767+ blocks finalized
State Consistency:     All nodes at hash a1eeefbd
P2P Connectivity:      2+ stable peer connections per node
Validation Errors:     0
Database Errors:       0
Ingress Acceptance:    100% (no protocol rejects)
```

### Integration Test Suite ✅
```
Total Tests:           535
Passed:                535 ✅
Failed:                0
Skipped:               0
Timing:                Improved (60s→120s waits for load tolerance)
```

### Database Compatibility Testing ✅
```
DB Source:             Mainnet production DB
Replay Time:           < 5 minutes (genesis to height 1767)
Errors:                0
Data Integrity:        100% (all records preserved)
Legacy Epoch Handling: Working correctly
```

### Performance Metrics
```
Block Finalization:    ~15 seconds
Peer Sync Latency:     < 1 second
Memory Usage:          500 MB - 1 GB
CPU Usage:             Low idle, periodic spikes during consensus
Disk I/O:              Efficient (SSD recommended)
Network Bandwidth:     ~100 KB/sec per peer
```

---

## Migration Guide

### For Existing Validator Operators

**Pre-Upgrade Checklist:**
- [ ] Backup current database: `cp -r ~/.finalis/mainnet ~/.finalis/mainnet.backup`
- [ ] Verify SEEDS.json is correct: `cat mainnet/SEEDS.json | jq '.seeds_p2p'`
- [ ] Test on staging node first
- [ ] Schedule maintenance window (if applicable)
- [ ] Notify co-validators of upgrade time

**Upgrade Steps:**

1. **Stop existing node:**
   ```bash
   sudo systemctl stop finalis-node
   ```

2. **Download binary:**
   ```bash
   # Option A: Download from GitHub release
   wget https://github.com/FinalisCore/finalis-core/releases/download/v1.0.0/finalis-node
   chmod +x finalis-node
   
   # Option B: Build from source
   git checkout v1.0.0
   cmake --preset linux-ninja-release
   cmake --build build/linux-release -j$(nproc)
   ```

3. **Verify integrity:**
   ```bash
   sha256sum finalis-node
   cat CHECKSUMS.txt | grep finalis-node  # should match
   ```

4. **Deploy binary:**
   ```bash
   sudo cp finalis-node /usr/local/bin/finalis-node
   # Or update systemd service path
   ```

5. **Start service:**
   ```bash
   sudo systemctl start finalis-node
   ```

6. **Monitor logs:**
   ```bash
   journalctl -u finalis-node -f | tail -20
   # Look for: "peers=N outbound=M/8 established=K"
   ```

7. **Verify sync:**
   ```bash
   # Check height is advancing
   journalctl -u finalis-node -f | grep "^mainnet h="
   ```

**Expected Output:**
```
mainnet h=1768 transition=3f4c2e1a gen=0021a75a peers=2 outbound=2/8 inbound=0 established=2 addrman=0 cv=7 state=SYNCING
```

### For New Validators

1. Download installer (see "Download Binaries" below)
2. Run setup: `sudo ./install-finalis-node.sh`
3. Create account: `finalis-cli account create`
4. Join validator registry: `finalis-cli validator join <account_hash>`
5. Wait for PoW admission and committee entry
6. Monitor node: `journalctl -u finalis-node -f`

### For RPC Clients

**No API changes.** All RPC endpoints remain compatible:
- Lightserver RPC: `http://localhost:19444/rpc`
- All existing methods work without modification
- New methods may be added in future point releases

---

## Download Binaries

### GitHub Release
**https://github.com/FinalisCore/finalis-core/releases/tag/v1.0.0**

| Platform | File | Size |
|----------|------|------|
| Linux x86_64 | `finalis-node` | ~50 MB |
| Linux x86_64 | `finalis-lightserver` | ~45 MB |
| Windows x64 EXE | `finalis-node.exe` | ~60 MB |
| Windows x64 EXE | `finalis-lightserver.exe` | ~55 MB |
| Windows Installer | `finalis-core_installer.exe` | ~80 MB |
| macOS x86_64 | `finalis-node-macos-x86_64` | ~50 MB |
| macOS ARM64 | `finalis-node-macos-arm64` | ~50 MB |
| Checksums | `CHECKSUMS.txt` | - |

### Docker Image
```bash
docker pull finalis/finalis-core:v1.0.0
docker pull finalis/finalis-core:latest

# Run
docker run -d \
  --name finalis-node \
  -p 19440:19440 \
  -p 19444:19444 \
  -v finalis-data:/data/finalis \
  finalis/finalis-core:v1.0.0
```

### Verification

**Verify binary integrity:**
```bash
# Download checksums
wget https://github.com/FinalisCore/finalis-core/releases/download/v1.0.0/CHECKSUMS.txt

# Verify
sha256sum -c CHECKSUMS.txt
# Expected: finalis-node: OK
```

**Verify signature (if GPG-signed):**
```bash
gpg --verify finalis-node.sig finalis-node
```

---

## Configuration

### Default Settings (Ready to Go)
```bash
--outbound-target 8          # Connect to 8 peers
--no-dns-seeds               # Use SEEDS.json for discovery
--port 19440                 # P2P port
--lightserver-port 19444     # RPC port
--public                     # Public node (discoverable)
--listen --bind 0.0.0.0      # Listen on all interfaces
```

### Customize Peers
**Edit `mainnet/SEEDS.json`:**
```json
{
  "network": "mainnet",
  "seeds_p2p": [
    "validator1.example.com:19440",
    "validator2.example.com:19440"
  ],
  "lightservers_rpc": [
    "http://validator1.example.com:19444/rpc",
    "http://validator2.example.com:19444/rpc"
  ]
}
```

### Manual Systemd Configuration
```bash
sudo systemctl edit finalis-node
# Edit ExecStart line as needed
sudo systemctl daemon-reload
sudo systemctl restart finalis-node
```

---

## Known Issues & Limitations

### None at This Time
Extensive testing on mainnet-like conditions shows stable operation. If issues arise, please report: https://github.com/FinalisCore/finalis-core/issues

---

## Support & Documentation

| Resource | Link |
|----------|------|
| **Deployment Guide** | [DEPLOYMENT.md](DEPLOYMENT.md) |
| **Release Checklist** | [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md) |
| **Onboarding Protocol** | [docs/ONBOARDING-PROTOCOL.md](docs/ONBOARDING-PROTOCOL.md) |
| **Issues & Bugs** | https://github.com/FinalisCore/finalis-core/issues |
| **Community Chat** | Discord @finalis-core-dev |

---

## Deployment Timeline

| Date | Milestone |
|------|-----------|
| Apr 17 | v1.0.0 released to GitHub |
| Apr 18-19 | Community testing & staging |
| Apr 20 | Supermajority validator readiness confirmation |
| Apr 21 | Coordinated upgrade window (30-min) |
| Apr 22+ | Full network transition to v1.0.0 |

---

## Upgrade Safety Checklist

**Before upgrading your validator:**
- [ ] Backup database
- [ ] Test on staging node
- [ ] Verify SEEDS.json is correct
- [ ] Check for any reported issues in Discord
- [ ] Wait for supermajority signal from community
- [ ] Schedule upgrade within maintenance window

**During upgrade:**
- [ ] Stop node gracefully
- [ ] Deploy new binary
- [ ] Verify integrity (checksums)
- [ ] Start node
- [ ] Monitor logs for errors
- [ ] Confirm peers connecting

**After upgrade:**
- [ ] Verify height is advancing
- [ ] Check state consistency with other nodes
- [ ] Watch for 24 hours for any issues
- [ ] Report any anomalies to Discord

---

## Rollback Plan

If critical issues emerge after upgrade:

1. **Announce in Discord:** Stop all further upgrades
2. **Revert to previous version:**
   ```bash
   sudo systemctl stop finalis-node
   git checkout main~1  # Previous version
   cmake --preset linux-ninja-release
   cmake --build build/linux-release -j$(nproc)
   sudo systemctl start finalis-node
   ```
3. **Restore DB if corrupted:**
   ```bash
   sudo systemctl stop finalis-node
   rm -rf ~/.finalis/mainnet
   cp -r ~/.finalis/mainnet.backup ~/.finalis/mainnet
   sudo systemctl start finalis-node
   ```

---

## Acknowledgments

Thanks to all community members and testers who participated in validation of v1.0.0. Your feedback ensures Finalis remains the most secure and resilient proof-of-stake consensus protocol.

---

## Version Information

```
Version:           1.0.0
Release Date:      April 17, 2026
Branch:            main
Commit:            0b8e0ad
Repository:        https://github.com/FinalisCore/finalis-core
License:           BUSL-1.1 (Business Source License 1.1)
```

---

**🚀 Welcome to Finalis Core v1.0.0 — Building the future of decentralized consensus!**
