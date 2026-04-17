# Discord Community Announcement (Short Version)

Copy/paste into Discord:

---

🎉 **BIG WIN: `pow` Branch is Production-Ready!** 🎉

After extensive testing across multiple nodes, we're proud to announce that the `pow` branch is **validated and ready to merge into mainnet**.

**What's in this update:**
✅ Validator Onboarding (ONBOARDING status + PoW admission gating)
✅ Enhanced Consensus Security (strict ingress epoch validation)
✅ Better P2P Networking (8-peer target, SEEDS.json discovery)
✅ Database Compatibility (backward-compatible DB replay)

**Test Results:**
✅ 4+ hours stable 2-node consensus
✅ 1767+ blocks finalized consistently
✅ Zero validation or DB errors
✅ All nodes synced to same finalized hash

---

## 📥 How to Update

**Linux (Automated):**
```bash
git checkout pow
cmake --preset linux-ninja-release
cmake --build build/linux-release -j$(nproc)
sudo BINDIR=./build/linux-release ./packaging/linux/install-finalis-node.sh
sudo systemctl start finalis-node
```

**Windows:**
1. Download installer from CI (GitHub Actions)
2. Run `finalis-core_installer.exe`
3. Click "Start Finalis Stack"

**Verify it's working:**
- Linux: `journalctl -u finalis-node -f | grep "peers="`
- Windows: Check `%APPDATA%\.finalis\mainnet\logs\node.log`

Expected: `peers=N outbound=M/8 established=K` (should see peer connections)

---

## 📦 Binaries

Available at:
- **GitHub Releases:** https://github.com/finalis-core/finalis-core/releases/tag/pow-release
- **Docker:** `docker pull finalis/finalis-core:pow-latest`

---

## ⚠️ Before Upgrading Validators

1. Backup your DB: `cp -r ~/.finalis/mainnet ~/.finalis/mainnet.backup`
2. Test on staging node first
3. Verify SEEDS.json is correct
4. Wait for supermajority community signal

---

**Questions?** Tag @finalis-core-dev or check `DEPLOYMENT.md` in the repo!

**Ready to upgrade?** Let's go! 🚀

---
