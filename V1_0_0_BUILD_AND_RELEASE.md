# v1.0.0 Release Build & Deploy Guide

**Version:** 1.0.0  
**Repository:** https://github.com/FinalisCore/finalis-core  
**Date:** April 17, 2026

---

## Step 1: Verify You're on Main with v1.0.0 Code

```bash
cd /home/greendragon/Desktop/finalis-organization/finalis-core
git branch -v  # Should show: main 0b8e0ad
git log --oneline -1  # Should show: Merge pow branch...
```

---

## Step 2: Create Git Tag for v1.0.0

```bash
# Create annotated tag on current commit
git tag -a v1.0.0 -m "Finalis Core v1.0.0 - Production Release
- Validator onboarding with PoW-gated admission
- Enhanced consensus security (strict ingress validation)
- Automatic P2P networking (8-peer target, SEEDS.json discovery)
- Database compatibility (backward compatible replay)
- Validated on multi-node consensus (4+ hours, 1767+ blocks, 0 errors)
- 535/535 integration tests passing
- Production-ready for mainnet deployment"

# Push tag to GitHub
git push origin v1.0.0
```

---

## Step 3: Build Linux Binaries

```bash
# Clean previous builds
rm -rf build

# Build with release preset
cmake --preset linux-ninja-release
cmake --build build/linux-release -j$(nproc)

# Verify binaries exist
ls -lh build/linux-release/finalis-node
ls -lh build/linux-release/finalis-lightserver

# Create staging directory
mkdir -p release-artifacts/linux-x86_64
cp build/linux-release/finalis-node release-artifacts/linux-x86_64/
cp build/linux-release/finalis-lightserver release-artifacts/linux-x86_64/

echo "✅ Linux binaries built and staged"
```

---

## Step 4: Build Windows Binaries (Windows Machine)

**Run this on Windows 10/11 machine:**

```powershell
# Navigate to repo
cd C:\Path\To\finalis-core

# Clean build
Remove-Item -Recurse -Force build -ErrorAction SilentlyContinue

# Build with release preset
cmake --preset windows-ninja-release
cmake --build build/windows-release -j $env:NUMBER_OF_PROCESSORS

# Verify
Get-ChildItem build/windows-release/Release/finalis-node.exe
Get-ChildItem build/windows-release/Release/finalis-lightserver.exe

# Stage binaries
New-Item -ItemType Directory -Path "release-artifacts\windows-x64" -Force
Copy-Item build/windows-release/Release/finalis-node.exe release-artifacts/windows-x64/
Copy-Item build/windows-release/Release/finalis-lightserver.exe release-artifacts/windows-x64/

# Build installer
cd packaging/windows
iscc finalis-core.iss
# Output: ...\dist\installer\finalis-core_installer.exe
Copy-Item ..\..\dist\installer\finalis-core_installer.exe ..\..\release-artifacts\windows-x64\

Write-Host "✅ Windows binaries built and staged"
```

---

## Step 5: Generate Checksums

```bash
cd release-artifacts

# Create checksums file
sha256sum linux-x86_64/finalis-node > CHECKSUMS.txt
sha256sum linux-x86_64/finalis-lightserver >> CHECKSUMS.txt
sha256sum windows-x64/finalis-node.exe >> CHECKSUMS.txt
sha256sum windows-x64/finalis-lightserver.exe >> CHECKSUMS.txt
sha256sum windows-x64/finalis-core_installer.exe >> CHECKSUMS.txt

# Display for verification
echo "=== Checksums ==="
cat CHECKSUMS.txt

# Expected output:
# a1b2c3d4e5f6... linux-x86_64/finalis-node
# f6e5d4c3b2a1... linux-x86_64/finalis-lightserver
# ...etc
```

---

## Step 6: Verify Binary Integrity

```bash
# Test each binary
cd release-artifacts

# Linux
sha256sum -c CHECKSUMS.txt | grep linux-x86_64
# Expected: OK

# Windows (on Windows machine)
Get-FileHash windows-x64/finalis-node.exe -Algorithm SHA256
# Compare against CHECKSUMS.txt
```

---

## Step 7: Create GitHub Release

### Option A: Using GitHub Web UI (Easiest)

1. Go to: **https://github.com/FinalisCore/finalis-core/releases/new**

2. Fill in the form:
   - **Tag version:** `v1.0.0`
   - **Target:** `main` branch
   - **Title:** `Finalis Core v1.0.0 - Production Release`
   - **Description:** Copy from `RELEASE_NOTES_V1_0_0.md`

3. **Upload files** from `release-artifacts/`:
   - `linux-x86_64/finalis-node`
   - `linux-x86_64/finalis-lightserver`
   - `windows-x64/finalis-node.exe`
   - `windows-x64/finalis-lightserver.exe`
   - `windows-x64/finalis-core_installer.exe`
   - `CHECKSUMS.txt`

4. **Uncheck** "This is a pre-release" (it's production-ready!)

5. Click **Publish release**

### Option B: Using GitHub CLI

```bash
# Install GitHub CLI if needed
# brew install gh (macOS)
# apt install gh (Ubuntu)

# Authenticate
gh auth login

# Create release
gh release create v1.0.0 \
  --title "Finalis Core v1.0.0 - Production Release" \
  --notes-file RELEASE_NOTES_V1_0_0.md \
  release-artifacts/linux-x86_64/finalis-node \
  release-artifacts/linux-x86_64/finalis-lightserver \
  release-artifacts/windows-x64/finalis-node.exe \
  release-artifacts/windows-x64/finalis-lightserver.exe \
  release-artifacts/windows-x64/finalis-core_installer.exe \
  release-artifacts/CHECKSUMS.txt
```

---

## Step 8: Build & Push Docker Image

```bash
# Build Docker image
docker build \
  -t finalis/finalis-core:v1.0.0 \
  -t finalis/finalis-core:latest \
  .

# Verify image
docker images | grep finalis-core

# Login to Docker Hub
docker login

# Push images
docker push finalis/finalis-core:v1.0.0
docker push finalis/finalis-core:latest

# Verify
docker pull finalis/finalis-core:v1.0.0
```

---

## Step 9: Verify Release on GitHub

```bash
# Check release exists
curl -s https://api.github.com/repos/FinalisCore/finalis-core/releases/latest | jq '.tag_name, .name'
# Expected: "v1.0.0", "Finalis Core v1.0.0 - Production Release"

# Test binary download
wget https://github.com/FinalisCore/finalis-core/releases/download/v1.0.0/finalis-node
./finalis-node --version

# Verify checksums
wget https://github.com/FinalisCore/finalis-core/releases/download/v1.0.0/CHECKSUMS.txt
sha256sum -c CHECKSUMS.txt
# Expected: All OK
```

---

## Step 10: Announce to Community

### Post to Discord #announcements

Copy content from `DISCORD_ANNOUNCEMENT_V1_0_0.md`:

```
🎉 **FINALIS CORE v1.0.0 IS LIVE** 🎉

[Full announcement text from DISCORD_ANNOUNCEMENT_V1_0_0.md]
```

Then:
1. Right-click message → **Pin message**
2. Keep pinned for entire upgrade period (Apr 18-21)

### Post to GitHub Discussions (optional)

Create discussion in "Announcements" category with same content

---

## Step 11: Monitor Validator Upgrades

```bash
# Track adoption in Discord #upgrades-status channel
# Check validator nodes connecting to your nodes
journalctl -u finalis-node -f | grep "peers="

# Expected progression:
# Apr 18: First validators upgrade (5-10%)
# Apr 19: More validators upgrade (20-50%)
# Apr 21: Supermajority window (70%+)
```

---

## Rollback Procedure (If Needed)

If critical issues emerge:

1. **Announce halt in Discord:** "PAUSE all v1.0.0 upgrades"

2. **Revert to previous version:**
   ```bash
   git checkout main~1
   cmake --preset linux-ninja-release
   cmake --build build/linux-release -j$(nproc)
   sudo systemctl restart finalis-node
   ```

3. **Restore DB if corrupted:**
   ```bash
   sudo systemctl stop finalis-node
   rm -rf ~/.finalis/mainnet
   cp -r ~/.finalis/mainnet.backup ~/.finalis/mainnet
   sudo systemctl start finalis-node
   ```

---

## Success Checklist

After completing all steps:

- [ ] Git tag `v1.0.0` created and pushed
- [ ] Linux binaries built and tested
- [ ] Windows binaries built and tested
- [ ] Checksums generated and verified
- [ ] GitHub release created with all binaries
- [ ] Docker images pushed to Docker Hub
- [ ] Discord announcement posted & pinned
- [ ] Validators able to download from GitHub
- [ ] First validator upgrades within 12 hours
- [ ] Network reaches supermajority on v1.0.0
- [ ] No critical errors reported after 24 hours

---

**v1.0.0 Release Complete!** 🎉

Your Finalis Core production release is now live. Monitor Discord and node logs for any issues during the upgrade period. Excellent work! 🚀
