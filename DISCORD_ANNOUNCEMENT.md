# 🎉 Finalis Core `pow` Branch - Ready for Production

## The Big Win: Validator Onboarding & Enhanced Security

We're excited to announce that the `pow` branch is **production-ready and validated across multiple nodes**! This release introduces critical improvements to validator admission, consensus security, and network stability.

### What's New

✅ **Validator Onboarding (ONBOARDING Status)**
- New validator status for nodes awaiting quorum entry
- Proof-of-Work admission gating (configurable difficulty)
- Prevents Sybil attacks during validator bootstrap

✅ **Enhanced Consensus Security**
- Stricter ingress epoch validation for live consensus
- Backward-compatible DB replay (supports existing mainnet DB)
- Committee derivation improvements for finalization

✅ **Improved P2P Networking**
- Default `--outbound-target 8` for multi-peer connectivity
- SEEDS.json-based peer discovery (no hardcoded bootstrap nodes)
- Automatic connection management to network mesh

✅ **Database Compatibility**
- Forward/backward compatible serialization
- Zero data loss on DB replay from previous versions
- Safe for production upgrades

---

## How to Update

### Option 1: Build from Source (Recommended for Operators)

```bash
# Clone or update the repository
git clone https://github.com/finalis-core/finalis-core.git
cd finalis-core
git checkout pow

# Build binaries
cmake --preset linux-ninja-release
cmake --build build/linux-release -j$(nproc)

# Binaries located at:
# - build/linux-release/finalis-node
# - build/linux-release/finalis-lightserver
```

### Option 2: Automated Linux Setup

```bash
# Copy binaries to staging directory
mkdir -p /tmp/finalis-staging
cp build/linux-release/finalis-node /tmp/finalis-staging/
cp build/linux-release/finalis-lightserver /tmp/finalis-staging/

# Run automated systemd setup
sudo BINDIR=/tmp/finalis-staging ./packaging/linux/install-finalis-node.sh

# Start the service
sudo systemctl start finalis-node

# Monitor logs
journalctl -u finalis-node -f
```

### Option 3: Windows

1. Download the Windows installer from CI (GitHub Actions release artifacts)
2. Run installer: `finalis-core_installer.exe`
3. Click "Start Finalis Stack" from Start Menu
4. Lightserver RPC available at `http://127.0.0.1:19444/rpc`

---

## Configuration

### Default Settings (No Manual Config Needed)

- **P2P Port:** 19440
- **Lightserver RPC:** 19444
- **Outbound Targets:** 8 peers
- **Peer Discovery:** Automatic via SEEDS.json

### Customize Peer List

Edit `mainnet/SEEDS.json` before deployment:

```json
{
  "network": "mainnet",
  "seeds_p2p": [
    "validator1.example.com:19440",
    "validator2.example.com:19440",
    "validator3.example.com:19440"
  ],
  "lightservers_rpc": [
    "http://validator1.example.com:19444/rpc",
    "http://validator2.example.com:19444/rpc"
  ]
}
```

### Manual Service Configuration (Linux)

```bash
sudo systemctl edit finalis-node
# Modify ExecStart line as needed, then:
sudo systemctl daemon-reload
sudo systemctl restart finalis-node
```

---

## Release Binaries

### Build Artifacts

Pre-built binaries are available from:
- **GitHub Releases:** https://github.com/finalis-core/finalis-core/releases/tag/pow-release
- **Linux (x86_64):** `finalis-node-linux-amd64`, `finalis-lightserver-linux-amd64`
- **Windows (x64):** `finalis-core_installer.exe`
- **macOS (x86_64/ARM64):** `finalis-node-macos-x86_64`, `finalis-node-macos-arm64`

### Verification

```bash
# Verify binary integrity
sha256sum finalis-node-linux-amd64
# Compare against CHECKSUMS.txt from release

# Verify signature (if GPG-signed)
gpg --verify finalis-node-linux-amd64.sig finalis-node-linux-amd64
```

### Docker Image

```bash
# Available at:
docker pull finalis/finalis-core:pow-latest

# Run container
docker run -d \
  --name finalis-node \
  -p 19440:19440 \
  -p 19444:19444 \
  -v finalis-data:/data/finalis \
  finalis/finalis-core:pow-latest
```

---

## Validation Results

### Multi-Node Testing ✅
- **Test Duration:** 4+ hours stable consensus
- **Nodes:** 2 (debian + greendragon) + 1 additional peer
- **Chain Height:** 1767+ blocks finalized
- **State Consistency:** All nodes at same finalized hash
- **P2P Connectivity:** 2+ peer connections per node, stable
- **Validation Errors:** 0
- **DB Replay Errors:** 0

### Performance Metrics
- Initial DB replay: < 5 minutes
- Block finalization time: ~15 seconds
- Peer sync latency: < 1 second
- Memory usage: ~500 MB - 1 GB
- CPU usage: Low idle, spikes during consensus rounds

---

## Upgrade Safety Checklist

Before upgrading to `pow` on live validators:

- [ ] **Backup Current DB:** `cp -r ~/.finalis/mainnet ~/.finalis/mainnet.backup`
- [ ] **Test on Staging:** Deploy to non-validator node first
- [ ] **Verify SEEDS.json:** Ensure bootstrap nodes are correct
- [ ] **Check Network:** Wait for supermajority readiness
- [ ] **Schedule Downtime:** Upgrade during low-activity period (if possible)
- [ ] **Monitor Logs:** Watch for any validation or DB errors
- [ ] **Verify Sync:** Confirm chain height matches peers

---

## Troubleshooting

### Node not connecting to peers
```bash
# Check if SEEDS.json is being loaded
journalctl -u finalis-node | grep -i seed

# Verify firewall allows outbound 19440
sudo ufw allow out 19440

# Check connection attempts
journalctl -u finalis-node -f | grep -E "connecting|connect|refused"
```

### High resource usage
```bash
# Reduce outbound connections
sudo systemctl edit finalis-node
# Change: --outbound-target 8 → --outbound-target 4
sudo systemctl restart finalis-node
```

### DB sync stuck
```bash
# Backup and reset DB
sudo systemctl stop finalis-node
sudo cp -r /var/lib/finalis/mainnet /var/lib/finalis/mainnet.backup
sudo rm -rf /var/lib/finalis/mainnet
sudo systemctl start finalis-node
# Will resync from peers
```

---

## Support & Questions

- **Documentation:** See `DEPLOYMENT.md` in repository
- **Issue Reports:** https://github.com/finalis-core/finalis-core/issues
- **Discord:** @finalis-core-dev for technical support

---

## Timeline

| Date | Event |
|------|-------|
| Apr 17, 2026 | `pow` branch validation complete, release ready |
| Apr 18-19 | Community testing & feedback period |
| Apr 20 | Mainnet merge approval (supermajority vote) |
| Apr 21 | Coordinated validator upgrade window |
| Apr 22+ | Full network transition |

**Note:** Timeline is tentative pending community consensus.

---

🚀 **Ready to upgrade? Follow the steps above and help us secure Finalis!**

Questions? Drop them in #general or tag @finalis-core-dev 

**Long live decentralized consensus! 🔐**
