# Quick Release Command Guide

**Repository:** https://github.com/FinalisCore/finalis-core  
**Release Version:** `v0.7.1-pow`

## TL;DR - Release in 10 Steps

### Step 1: Build Linux Binaries
```bash
cd /home/greendragon/Desktop/finalis-organization/finalis-core
rm -rf build
cmake --preset linux-ninja-release
cmake --build build/linux-release -j$(nproc)
mkdir -p release-artifacts/linux-x86_64
cp build/linux-release/finalis-node release-artifacts/linux-x86_64/
cp build/linux-release/finalis-lightserver release-artifacts/linux-x86_64/
```

### Step 2: Build Windows Binaries
*On Windows machine:*
```powershell
cd finalis-core
Remove-Item -Recurse -Force build -ErrorAction SilentlyContinue
cmake --preset windows-ninja-release
cmake --build build/windows-release -j $env:NUMBER_OF_PROCESSORS
New-Item -ItemType Directory -Path "release-artifacts\windows-x64" -Force
Copy-Item build/windows-release/Release/finalis-node.exe release-artifacts/windows-x64/
Copy-Item build/windows-release/Release/finalis-lightserver.exe release-artifacts/windows-x64/
cd packaging/windows
iscc finalis-core.iss  # Creates installer
```

### Step 3: Generate Checksums
```bash
cd release-artifacts
sha256sum linux-x86_64/finalis-node > CHECKSUMS.txt
sha256sum linux-x86_64/finalis-lightserver >> CHECKSUMS.txt
sha256sum windows-x64/finalis-node.exe >> CHECKSUMS.txt
sha256sum windows-x64/finalis-lightserver.exe >> CHECKSUMS.txt
cat CHECKSUMS.txt
```

### Step 4: Create Git Tag
```bash
cd /home/greendragon/Desktop/finalis-organization/finalis-core
git tag -a v0.7.1-pow -m "Finalis Core v0.7.1 - Validator Onboarding & Enhanced Security"
git push origin v0.7.1-pow
```

### Step 5: Create GitHub Release via Web UI
1. Go to: https://github.com/FinalisCore/finalis-core/releases/new
2. **Tag version:** `v0.7.1-pow`
3. **Target:** `pow` branch
4. **Title:** "Finalis Core v0.7.1 - Validator Onboarding & Enhanced Security"
5. **Description:** Paste content from `RELEASE_NOTES_POW.md`
6. **Upload files:** Select from `release-artifacts/`
   - `linux-x86_64/finalis-node`
   - `linux-x86_64/finalis-lightserver`
   - `windows-x64/finalis-node.exe`
   - `windows-x64/finalis-lightserver.exe`
   - `windows-x64/finalis-core_installer.exe`
   - `CHECKSUMS.txt`
7. Click **Publish release**

### Step 6: Build & Push Docker Image
```bash
cd /home/greendragon/Desktop/finalis-organization/finalis-core
docker build -t finalis/finalis-core:v0.7.1-pow -t finalis/finalis-core:pow-latest .
docker login
docker push finalis/finalis-core:v0.7.1-pow
docker push finalis/finalis-core:pow-latest
```

### Step 7: Verify Release
```bash
# Check GitHub release
curl -s https://api.github.com/repos/FinalisCore/finalis-core/releases/latest | jq '.tag_name'

# Test binary download
wget https://github.com/FinalisCore/finalis-core/releases/download/v0.7.1-pow/finalis-node
./finalis-node --version
```

### Step 8: Post Discord Announcement
**Channel:** #announcements

```
🎉 **Finalis Core v0.7.1 - PRODUCTION READY** 🎉

After extensive validation on multi-node consensus, the `pow` branch is ready for mainnet!

**Features:**
✅ Validator Onboarding with PoW gating
✅ Enhanced Consensus Security
✅ Better P2P Networking (8-peer target)
✅ Full DB Compatibility

**Download:** https://github.com/FinalisCore/finalis-core/releases/tag/v0.7.1-pow

**Quick Update:**
```
git checkout pow && cmake --preset linux-ninja-release && cmake --build build/linux-release -j$(nproc)
```

**Before Updating:**
1. Backup: cp -r ~/.finalis/mainnet ~/.finalis/mainnet.backup
2. Test on staging first
3. Verify SEEDS.json

**Upgrade Timeline:**
📅 Apr 18-19: Community testing
📅 Apr 20: Supermajority vote
📅 Apr 21: Coordinated upgrade

Questions? See DEPLOYMENT.md or tag @finalis-core-dev

🚀
```

Then right-click → **Pin message**

### Step 9: Monitor Upgrades
- Watch Discord for questions
- Check node logs: `journalctl -u finalis-node -f | grep -E "peers=|error"`
- Monitor height increase: `tail -f ~/.finalis/mainnet/node.log | grep "^mainnet"`

### Step 10: Confirm Success
✅ 50%+ validators upgraded  
✅ All nodes at same height/hash  
✅ No critical errors reported  
✅ P2P connectivity stable  

---

## File Downloads (After Step 5)

Once GitHub release is created, share these links:

| File | URL |
|------|-----|
| Linux x86_64 | `https://github.com/FinalisCore/finalis-core/releases/download/v0.7.1-pow/finalis-node` |
| Lightserver | `https://github.com/FinalisCore/finalis-core/releases/download/v0.7.1-pow/finalis-lightserver` |
| Windows EXE | `https://github.com/FinalisCore/finalis-core/releases/download/v0.7.1-pow/finalis-node.exe` |
| Windows Installer | `https://github.com/FinalisCore/finalis-core/releases/download/v0.7.1-pow/finalis-core_installer.exe` |
| Docker | `docker pull finalis/finalis-core:v0.7.1-pow` |
| Checksums | `https://github.com/FinalisCore/finalis-core/releases/download/v0.7.1-pow/CHECKSUMS.txt` |

---

## Verification Commands (for users)

```bash
# Verify binary integrity
sha256sum finalis-node
cat CHECKSUMS.txt | grep finalis-node  # should match

# Test binary
./finalis-node --version
./finalis-node --help

# Check config is correct
cat mainnet/SEEDS.json | jq '.seeds_p2p'
```

---

## If Something Goes Wrong

### Release not showing on GitHub
```bash
# Make sure tag was pushed
git push origin v0.7.1-pow

# Check it exists
git tag -l | grep v0.7.1-pow
```

### Binary corrupted during upload
- Re-upload from `release-artifacts/` folder
- Delete and recreate release if needed

### Docker push failed
```bash
docker login  # Make sure you're logged in
docker push finalis/finalis-core:v0.7.1-pow
```

### Validators not connecting
- Check SEEDS.json has correct peer IPs/ports
- Verify firewall allows port 19440
- Wait 5-10 minutes for DNS propagation

---

**Status: Ready to Release** ✅  
**All validation complete.** Follow steps 1-10 in order, you'll be done in ~30 minutes!
