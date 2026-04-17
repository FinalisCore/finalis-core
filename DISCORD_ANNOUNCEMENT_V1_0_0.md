# Discord Announcement: Finalis Core v1.0.0 Production Release

**Copy-paste directly to Discord #announcements channel:**

---

🎉 **FINALIS CORE v1.0.0 IS LIVE** 🎉

We're thrilled to announce the **first production release** of Finalis Core! After rigorous validation, consensus testing, and community feedback, v1.0.0 is now available for all validators.

**What This Means:**
✅ Validator onboarding protocol fully operational
✅ Enhanced consensus security (strict ingress validation)
✅ Automatic P2P networking (8-peer target, auto-discovery)
✅ Database compatibility (zero-downtime upgrade)
✅ Production-ready for mainnet deployment

**Test Results:**
- 4+ hours of multi-node consensus with 0 errors
- 1767+ blocks finalized consistently across 3 nodes
- 535/535 integration tests passing
- Zero database corruption or data loss

**📥 Download v1.0.0:**
https://github.com/FinalisCore/finalis-core/releases/tag/v1.0.0

Available for:
- Linux (x86_64)
- Windows (x64 + installer)
- macOS (x86_64 & ARM64)
- Docker: `docker pull finalis/finalis-core:v1.0.0`

**🚀 Quick Update (Linux):**
```bash
wget https://github.com/FinalisCore/finalis-core/releases/download/v1.0.0/finalis-node
chmod +x finalis-node
sudo cp finalis-node /usr/local/bin/
sudo systemctl restart finalis-node
```

**⚠️ Before Upgrading:**
1. Backup DB: `cp -r ~/.finalis/mainnet ~/.finalis/mainnet.backup`
2. Verify SEEDS.json is correct
3. Test on staging first
4. Wait for supermajority signal

**📅 Timeline:**
- **Now:** v1.0.0 available in GitHub
- **Apr 18-19:** Community staging & testing
- **Apr 20:** Supermajority confirmation
- **Apr 21:** Coordinated upgrade (30 min window)
- **Apr 22+:** Full network on v1.0.0

**❓ Questions?**
See DEPLOYMENT.md in repo or tag @finalis-core-dev

**Let's build the future together!** 🔐

---
