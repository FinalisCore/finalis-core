# v1.0.0 Release - Next Steps Checklist

**Status:** ✅ Git tag created and pushed  
**Tag:** `v1.0.0`  
**Commit:** 6227717  
**URL:** https://github.com/FinalisCore/finalis-core/releases/tag/v1.0.0

---

## 📋 Remaining Tasks (11 Steps)

### ✅ COMPLETED
- [x] Merge `pow` branch → `main`
- [x] Create v1.0.0 release documentation
- [x] Create git tag `v1.0.0`
- [x] Push to GitHub

### ⏳ PENDING

#### Step 1: Build Linux Binaries
```bash
cd /path/to/finalis-core
rm -rf build
cmake --preset linux-ninja-release
cmake --build build/linux-release -j$(nproc)
mkdir -p release-artifacts/linux-x86_64
cp build/linux-release/finalis-node release-artifacts/linux-x86_64/
cp build/linux-release/finalis-lightserver release-artifacts/linux-x86_64/
```

#### Step 2: Build Windows Binaries
*On Windows machine:*
```powershell
cmake --preset windows-ninja-release
cmake --build build/windows-release -j $env:NUMBER_OF_PROCESSORS
New-Item -ItemType Directory -Path "release-artifacts\windows-x64" -Force
Copy-Item build/windows-release/Release/finalis-node.exe release-artifacts/windows-x64/
Copy-Item build/windows-release/Release/finalis-lightserver.exe release-artifacts/windows-x64/
cd packaging/windows && iscc finalis-core.iss
Copy-Item ..\..\dist\installer\finalis-core_installer.exe ..\..\release-artifacts\windows-x64\
```

#### Step 3: Generate Checksums
```bash
cd release-artifacts
sha256sum linux-x86_64/finalis-node > CHECKSUMS.txt
sha256sum linux-x86_64/finalis-lightserver >> CHECKSUMS.txt
sha256sum windows-x64/finalis-node.exe >> CHECKSUMS.txt
sha256sum windows-x64/finalis-lightserver.exe >> CHECKSUMS.txt
sha256sum windows-x64/finalis-core_installer.exe >> CHECKSUMS.txt
cat CHECKSUMS.txt
```

#### Step 4: Create GitHub Release with Binaries
**Go to:** https://github.com/FinalisCore/finalis-core/releases/new

**Fill in:**
- **Tag version:** `v1.0.0` (already exists)
- **Target:** `main` branch
- **Title:** `Finalis Core v1.0.0 - Production Release`
- **Description:** Copy from `RELEASE_NOTES_V1_0_0.md`
- **Upload files:** Select from `release-artifacts/`:
  - `linux-x86_64/finalis-node`
  - `linux-x86_64/finalis-lightserver`
  - `windows-x64/finalis-node.exe`
  - `windows-x64/finalis-lightserver.exe`
  - `windows-x64/finalis-core_installer.exe`
  - `CHECKSUMS.txt`
- **Uncheck:** "This is a pre-release"
- **Click:** Publish release

#### Step 5: Build & Push Docker Image
```bash
docker build -t finalis/finalis-core:v1.0.0 -t finalis/finalis-core:latest .
docker login
docker push finalis/finalis-core:v1.0.0
docker push finalis/finalis-core:latest
```

#### Step 6: Verify Release
```bash
# Check GitHub release
curl -s https://api.github.com/repos/FinalisCore/finalis-core/releases/latest | jq '.tag_name, .name, .assets | length'

# Test binary download
wget https://github.com/FinalisCore/finalis-core/releases/download/v1.0.0/finalis-node
./finalis-node --version
```

#### Step 7: Announce to Discord
**Post to #announcements:**
- Copy content from `DISCORD_ANNOUNCEMENT_V1_0_0.md`
- Pin the message (right-click → Pin message)

#### Step 8: Create GitHub Discussion (optional)
- Category: Announcements
- Title: "Finalis Core v1.0.0 Released - Production Ready"
- Content: Copy from announcement

#### Step 9: Monitor Community Feedback
- Watch Discord #announcements for questions
- Check GitHub Issues for bug reports
- Be ready to provide support/hotfixes

#### Step 10: Track Validator Upgrades
- Monitor #upgrades-status in Discord
- Track adoption: Apr 18-19 (testing), Apr 20 (decision), Apr 21 (upgrade)

#### Step 11: Confirm Success
- [ ] 50%+ validators upgraded by Apr 21
- [ ] All validators at same height/hash
- [ ] Zero validation errors reported
- [ ] P2P connectivity stable across network

---

## 📦 Release Files Location

### Local Staging
```
release-artifacts/
├── linux-x86_64/
│   ├── finalis-node
│   └── finalis-lightserver
├── windows-x64/
│   ├── finalis-node.exe
│   ├── finalis-lightserver.exe
│   └── finalis-core_installer.exe
└── CHECKSUMS.txt
```

### After GitHub Release Created
```
https://github.com/FinalisCore/finalis-core/releases/download/v1.0.0/
├── finalis-node
├── finalis-lightserver
├── finalis-node.exe
├── finalis-lightserver.exe
├── finalis-core_installer.exe
└── CHECKSUMS.txt
```

### Docker Hub
```
docker pull finalis/finalis-core:v1.0.0
docker pull finalis/finalis-core:latest
```

---

## 📋 Documentation Created

All files committed to `main` branch:

| File | Purpose |
|------|---------|
| `RELEASE_NOTES_V1_0_0.md` | Complete v1.0.0 release notes |
| `DISCORD_ANNOUNCEMENT_V1_0_0.md` | Discord announcement text |
| `V1_0_0_BUILD_AND_RELEASE.md` | Step-by-step build & release guide |
| `DEPLOYMENT.md` | Deployment instructions |
| `RELEASE_CHECKLIST.md` | Detailed release checklist |

---

## 🔗 Important Links

| Resource | URL |
|----------|-----|
| **GitHub Repo** | https://github.com/FinalisCore/finalis-core |
| **v1.0.0 Tag** | https://github.com/FinalisCore/finalis-core/releases/tag/v1.0.0 |
| **Release Draft** | https://github.com/FinalisCore/finalis-core/releases/new (use existing tag) |
| **Discord** | #announcements (pin message) |
| **Releases API** | https://api.github.com/repos/FinalisCore/finalis-core/releases |

---

## ⏰ Timeline

| Date | Action | Owner |
|------|--------|-------|
| **Today (Apr 17)** | Binaries built, GitHub release created | You |
| **Apr 18-19** | Community testing on staging nodes | Community |
| **Apr 20** | Supermajority confirmation vote | Validators |
| **Apr 21** | Coordinated upgrade window (30 min) | All Validators |
| **Apr 22+** | Network fully on v1.0.0 | - |

---

## 🚀 You're 60% Done!

**Completed:** Code, tests, documentation, tagging ✅  
**Remaining:** Build binaries, create GitHub release, announce ⏳

**Est. Time to Complete:** 60-90 minutes

**Next Action:** Follow "Step 1" above to build Linux binaries, then continue through Step 7.

---

**Ready? Start with Step 1 above!** 🎉
