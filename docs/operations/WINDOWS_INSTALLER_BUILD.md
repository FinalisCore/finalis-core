# Windows Installer Build Guide (v1.0.2)

This guide walks you through rebuilding the Finalis Core Windows installer from current main branch on Windows 10/11.

## Prerequisites

Install these on your Windows machine:

1. **CMake** (3.21+)
   - Download: https://cmake.org/download/
   - Add to PATH during installation

2. **Visual Studio 2022** (or 2019)
   - Download: https://visualstudio.microsoft.com/downloads/
   - Select: "Desktop development with C++" workload
   - Includes MSVC compiler and build tools

3. **Git** for Windows
   - Download: https://git-scm.com/download/win
   - Default settings are fine

4. **Inno Setup 6** (for packaging)
   - Download: https://jrsoftware.org/isinfo.php
   - Install to default location (C:\Program Files (x86)\Inno Setup 6)

5. **Qt 6.x** (for finalis-wallet GUI)
   - Download: https://www.qt.io/download
   - Install to stable location (e.g., `C:\Qt\6.7.0`)
   - During installation, select MSVC 2022 64-bit component

6. **vcpkg** (C++ dependency manager)
   - Clone: `git clone https://github.com/Microsoft/vcpkg.git C:\vcpkg`
   - Bootstrap: `cd C:\vcpkg && .\bootstrap-vcpkg.bat`

## Step 1: Get Latest Source

```powershell
cd C:\path\to\finalis-core
git fetch origin
git checkout main
git pull origin main
git rev-parse --short HEAD      # Verify you're at latest commit
```

## Step 2: Clean Previous Build

```powershell
cd C:\path\to\finalis-core
Remove-Item -Recurse -Force build -ErrorAction SilentlyContinue
```

## Step 3: Generate CMake Build Configuration

```powershell
$QtPath = "C:\Qt\6.7.0\msvc2022_64"  # Adjust version if different
$VcpkgPath = "C:\vcpkg"

cmake --preset windows-ninja-release `
  -DCMAKE_PREFIX_PATH="$QtPath" `
  -DVCPKG_ROOT="$VcpkgPath"
```

If you get errors about Qt or compiler:
- Verify Qt path exists: `Test-Path $QtPath\bin\qmake.exe`
- Verify vcpkg exists: `Test-Path $VcpkgPath\bootstrap-vcpkg.bat`
- Run from Visual Studio 2022 Developer PowerShell (search "Developer PowerShell" in Windows Start menu)

## Step 4: Build All Binaries

```powershell
cd C:\path\to\finalis-core
cmake --build build\windows-release -j $env:NUMBER_OF_PROCESSORS
```

Expected output:
- ✅ `build\windows-release\Release\finalis-node.exe`
- ✅ `build\windows-release\Release\finalis-lightserver.exe`
- ✅ `build\windows-release\Release\finalis-explorer.exe`
- ✅ `build\windows-release\Release\finalis-wallet.exe`
- ✅ `build\windows-release\Release\finalis-cli.exe`

Build time: 5-15 minutes depending on machine

## Step 5: Stage Installer Payload

```powershell
$QtPath = "C:\Qt\6.7.0\msvc2022_64"
$StageRoot = "C:\path\to\dist\windows"

.\packaging\windows\Stage-WindowsRelease.ps1 `
  -BuildDir "C:\path\to\finalis-core\build\windows-release" `
  -Configuration Release `
  -StageRoot $StageRoot `
  -QtRootDir $QtPath `
  -VcpkgInstalledDir "C:\vcpkg\installed\x64-windows"
```

Verify output: `$StageRoot\payload\app\bin\finalis-node.exe` should exist

## Step 6: Build Windows Installer Executable

```powershell
$iscc = "C:\Program Files (x86)\Inno Setup 6\iscc.exe"
cd C:\path\to\finalis-core\packaging\windows

& $iscc finalis-core.iss `
  /DMyAppVersion="1.0.2" `
  /DSourceDir="C:\path\to\dist\windows\payload" `
  /DOutputDir="C:\path\to\dist\installer"
```

Expected output: `C:\path\to\dist\installer\finalis-core_installer.exe`

## Step 7: Test the Installer

1. Open `finalis-core_installer.exe` 
2. Click through wizard
3. Accept license and defaults (or customize data dir if needed)
4. **Check "Configure Firewall"** during install
5. **Check "Start Finalis Stack"** at end to auto-launch

Expected result:
- Shortcuts created in Start Menu: "Finalis Wallet", "Finalis Explorer", "Start Finalis Stack"
- Node starts and connects to peers
- Explorer opens in browser at http://127.0.0.1:18080

## Troubleshooting

### CMake configure fails: "Qt not found"
- Solution: Update Qt path in command, or verify Visual Studio Developer PowerShell is active

### Build fails: "MSVC compiler not found"
- Solution: Open "Visual Studio 2022 Developer PowerShell" from Start Menu instead of regular PowerShell

### Inno Setup build fails: "iscc.exe not found"
- Solution: Install Inno Setup from https://jrsoftware.org/isinfo.php or adjust path in step 6

### finalis-node.exe not found during staging
- Solution: Rebuild with `cmake --build build\windows-release` first

### Settlement state mismatch after install
- Cause: Your builder binary was from old code. This guide rebuilds from current main, which fixes it.
- Verify: Check node.log shows settlement matching peers (no "frontier-settlement-commitment-mismatch")

## Distribution

Once tested:

1. **Rename for release:**
   ```powershell
   Copy-Item C:\path\to\dist\installer\finalis-core_installer.exe `
     -Destination C:\path\to\dist\installer\finalis-core-v1.0.2-windows-installer.exe
   ```

2. **Generate checksum:**
   ```powershell
   $file = "C:\path\to\dist\installer\finalis-core-v1.0.2-windows-installer.exe"
   (Get-FileHash $file -Algorithm SHA256).Hash + " " + (Split-Path $file -Leaf) | Out-File checksum.txt
   ```

3. **Upload to GitHub Release** https://github.com/FinalisCore/finalis-core/releases/

## Quick Command Recap

Copy-paste these in order (update paths as needed):

```powershell
# Terminal 1: Clone/update repo
cd C:\path\to\finalis-core
git fetch origin && git checkout main && git pull

# Terminal 2 (Developer PowerShell): Build
Remove-Item -Recurse -Force build -ErrorAction SilentlyContinue
$QtPath = "C:\Qt\6.7.0\msvc2022_64"
cmake --preset windows-ninja-release -DCMAKE_PREFIX_PATH="$QtPath" -DVCPKG_ROOT="C:\vcpkg"
cmake --build build\windows-release -j $env:NUMBER_OF_PROCESSORS

# Terminal 3: Stage & Package
.\packaging\windows\Stage-WindowsRelease.ps1 `
  -BuildDir ".\build\windows-release" `
  -Configuration Release `
  -StageRoot "C:\dist\windows" `
  -QtRootDir $QtPath `
  -VcpkgInstalledDir "C:\vcpkg\installed\x64-windows"

$iscc = "C:\Program Files (x86)\Inno Setup 6\iscc.exe"
cd .\packaging\windows
& $iscc finalis-core.iss /DMyAppVersion="1.0.2" /DSourceDir="C:\dist\windows\payload" /DOutputDir="C:\dist\installer"

# Test
C:\dist\installer\finalis-core_installer.exe
```

## Notes

- All paths use backslashes (`\`) for Windows PowerShell
- If using WSL, use forward slashes (`/`) instead
- Build artifacts are ~500 MB, installer is ~50 MB
- Complete build time: 15-30 minutes depending on machine speed
