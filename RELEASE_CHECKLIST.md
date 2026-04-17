# Release Checklist: `pow` → Production

**Repository:** https://github.com/FinalisCore/finalis-core  
**Branch:** `pow`  
**Release Tag:** `v0.7.1-pow` (or your version)

---

## Phase 1: Pre-Release Validation ✅ (COMPLETE)

- [x] Multi-node consensus testing (4+ hours)
- [x] DB replay validation (mainnet DB)
- [x] Integration tests passing (535/535)
- [x] Peer connectivity working
- [x] Zero validation errors
- [x] Documentation updated (DEPLOYMENT.md, RELEASE_NOTES_POW.md)

---

## Phase 2: Build Release Binaries 🔨

### Linux Build

```bash
# From repository root
cd /path/to/finalis-core

# Clean build
rm -rf build
cmake --preset linux-ninja-release
cmake --build build/linux-release -j$(nproc)

# Output binaries
ls -lh build/linux-release/finalis-node
ls -lh build/linux-release/finalis-lightserver
ls -lh build/linux-release/finalis-wallet  # if included

# Create release staging directory
mkdir -p release-artifacts/linux-x86_64
cp build/linux-release/finalis-node release-artifacts/linux-x86_64/
cp build/linux-release/finalis-lightserver release-artifacts/linux-x86_64/
```

### Windows Build (on Windows machine)

```powershell
# From repository root
cd finalis-core

# Clean build
Remove-Item -Recurse -Force build -ErrorAction SilentlyContinue
cmake --preset windows-ninja-release
cmake --build build/windows-release -j $env:NUMBER_OF_PROCESSORS

# Output binaries
Get-ChildItem build/windows-release/Release/finalis-node.exe
Get-ChildItem build/windows-release/Release/finalis-lightserver.exe
Get-ChildItem build/windows-release/Release/finalis-wallet.exe

# Create release staging directory
New-Item -ItemType Directory -Path "release-artifacts\windows-x64" -Force
Copy-Item build/windows-release/Release/finalis-node.exe release-artifacts/windows-x64/
Copy-Item build/windows-release/Release/finalis-lightserver.exe release-artifacts/windows-x64/

# Build installer
cd packaging/windows
iscc finalis-core.iss  # Requires Inno Setup
# Output: dist/installer/finalis-core_installer.exe
```

### macOS Build (on macOS)

```bash
cd /path/to/finalis-core

# Clean build
rm -rf build
cmake --preset macos-ninja-release
cmake --build build/macos-release -j$(nproc)

# Create universal binary (x86_64 + ARM64)
# If cross-compilation needed:
cmake --preset macos-ninja-release-universal
cmake --build build/macos-release-universal -j$(nproc)

# Output
ls -lh build/macos-release/finalis-node
mkdir -p release-artifacts/macos-universal
cp build/macos-release/finalis-node release-artifacts/macos-universal/
```

---

## Phase 3: Generate Checksums & Signatures

```bash
cd release-artifacts

# Generate checksums
sha256sum linux-x86_64/finalis-node > CHECKSUMS.txt
sha256sum linux-x86_64/finalis-lightserver >> CHECKSUMS.txt
sha256sum windows-x64/finalis-node.exe >> CHECKSUMS.txt
sha256sum windows-x64/finalis-lightserver.exe >> CHECKSUMS.txt
sha256sum macos-universal/finalis-node >> CHECKSUMS.txt

cat CHECKSUMS.txt
```

Optional: Sign binaries with GPG (if you have a signing key):
```bash
gpg --armor --detach-sign linux-x86_64/finalis-node
gpg --armor --detach-sign windows-x64/finalis-node.exe
gpg --armor --detach-sign macos-universal/finalis-node
```

---

## Phase 4: Create GitHub Release

### Option A: Using GitHub Web UI

1. Go to: https://github.com/FinalisCore/finalis-core/releases/new
2. **Tag version:** `v0.7.1-pow`
3. **Target:** `pow` branch
4. **Release title:** "Finalis Core v0.7.1 - Validator Onboarding & Enhanced Security"
5. **Description:** Copy from [RELEASE_NOTES_POW.md](../RELEASE_NOTES_POW.md)
6. **Attach files:** Drag & drop or upload:
   - `release-artifacts/linux-x86_64/finalis-node`
   - `release-artifacts/linux-x86_64/finalis-lightserver`
   - `release-artifacts/windows-x64/finalis-node.exe`
   - `release-artifacts/windows-x64/finalis-lightserver.exe`
   - `release-artifacts/windows-x64/finalis-core_installer.exe`
   - `release-artifacts/macos-universal/finalis-node`
   - `release-artifacts/CHECKSUMS.txt`
7. **Set as pre-release:** If not fully live yet, check "Set as a pre-release"
8. **Publish release**

### Option B: Using GitHub CLI

```bash
# Install gh if needed
# brew install gh  (macOS)
# apt install gh    (Ubuntu)

# Authenticate
gh auth login

# Create release with artifacts
gh release create v0.7.1-pow \
  --title "Finalis Core v0.7.1 - Validator Onboarding & Enhanced Security" \
  --notes-file RELEASE_NOTES_POW.md \
  release-artifacts/linux-x86_64/finalis-node \
  release-artifacts/linux-x86_64/finalis-lightserver \
  release-artifacts/windows-x64/finalis-node.exe \
  release-artifacts/windows-x64/finalis-lightserver.exe \
  release-artifacts/windows-x64/finalis-core_installer.exe \
  release-artifacts/macos-universal/finalis-node \
  release-artifacts/CHECKSUMS.txt
```

### Option C: Using git (and GitHub creates release from tag)

```bash
# Create annotated tag
git tag -a v0.7.1-pow -m "Finalis Core v0.7.1 - Validator Onboarding & Enhanced Security"

# Push tag to GitHub
git push origin v0.7.1-pow

# Then create GitHub release via web UI or gh CLI
```

---

## Phase 5: Build & Upload Docker Image

```bash
# Build Docker image
docker build -t finalis/finalis-core:v0.7.1-pow \
             -t finalis/finalis-core:pow-latest \
             -f Dockerfile .

# Tag for registry
docker tag finalis/finalis-core:v0.7.1-pow finalis/finalis-core:v0.7.1-pow
docker tag finalis/finalis-core:pow-latest finalis/finalis-core:pow-latest

# Push to Docker Hub (requires docker login)
docker login
docker push finalis/finalis-core:v0.7.1-pow
docker push finalis/finalis-core:pow-latest

# Verify
docker pull finalis/finalis-core:v0.7.1-pow
docker run --rm finalis/finalis-core:v0.7.1-pow finalis-node --version
```

---

## Phase 6: Announce to Discord

Copy & paste to Discord #announcements:

```
🎉 **Finalis Core v0.7.1 - PRODUCTION READY** 🎉

After extensive validation (4+ hours, 3-node consensus, 1767+ blocks finalized), we're proud to announce that the `pow` branch is **ready for mainnet deployment**.

**What's New:**
✅ Validator Onboarding (PoW-gated entry, Sybil attack prevention)
✅ Enhanced Consensus Security (strict ingress epoch validation)
✅ Better P2P Networking (8-peer target, auto-discovery via SEEDS.json)
✅ Full Database Compatibility (zero data loss on upgrade)

**Download Binaries:**
📥 https://github.com/FinalisCore/finalis-core/releases/tag/v0.7.1-pow

**Update Instructions:**
Linux: git checkout pow && cmake --preset linux-ninja-release && cmake --build build/linux-release -j$(nproc)
Windows: Download installer from releases page
Docker: docker pull finalis/finalis-core:pow-latest

**Before Upgrading:**
1. Backup DB: cp -r ~/.finalis/mainnet ~/.finalis/mainnet.backup
2. Test on staging node first
3. Check SEEDS.json is correct

**Timeline:**
📅 Apr 18-19: Community staging & testing
📅 Apr 20: Supermajority readiness vote
📅 Apr 21: Coordinated validator upgrade window

**Questions?** See DEPLOYMENT.md or tag @finalis-core-dev

Let's go! 🚀
```

---

## Phase 7: Verify Release Availability

```bash
# Check GitHub API
curl -s https://api.github.com/repos/FinalisCore/finalis-core/releases/latest | jq '.tag_name, .assets | length'

# Test download links
wget -O finalis-node https://github.com/FinalisCore/finalis-core/releases/download/v0.7.1-pow/finalis-node
./finalis-node --version

# Verify Docker image
docker pull finalis/finalis-core:pow-latest
docker inspect finalis/finalis-core:pow-latest
```

---

## Phase 8: Pin Announcement

After posting to Discord:
1. Right-click message → Pin message
2. Keep pinned for 1 week during testing period

---

## Phase 9: Monitor Feedback

- Watch Discord for issues/questions
- Check GitHub Issues for bug reports
- Monitor node logs from early adopters
- Be ready to hotfix if issues emerge

---

## Rollback Plan (if needed)

```bash
# If critical issue found:
# 1. Announce in Discord to halt upgrades
# 2. All validators revert:
git checkout main
cmake --preset linux-ninja-release
cmake --build build/linux-release -j$(nproc)
sudo systemctl restart finalis-node

# 3. Restore DB if corrupted:
rm -rf ~/.finalis/mainnet
cp -r ~/.finalis/mainnet.backup ~/.finalis/mainnet
sudo systemctl start finalis-node
```

---

## Success Criteria

✅ Release created on GitHub with all binaries  
✅ Discord announcement posted & pinned  
✅ Download links working  
✅ 50%+ validators have upgraded within 24 hours  
✅ No critical validation errors reported  
✅ All test nodes maintaining consensus at same height/hash  
✅ P2P connectivity stable across network  

---

**Ready to execute? Follow the steps in order.** Any blockers, let me know! 🚀
