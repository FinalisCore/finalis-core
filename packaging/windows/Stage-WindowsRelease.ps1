[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$BuildDir,

    [string]$Configuration = "Release",

    [Parameter(Mandatory = $true)]
    [string]$StageRoot,

    [Parameter(Mandatory = $true)]
    [string]$QtRootDir,

    [Parameter(Mandatory = $true)]
    [string]$VcpkgInstalledDir
)

$ErrorActionPreference = "Stop"

function Copy-OptionalFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Source,
        [Parameter(Mandatory = $true)]
        [string]$Destination
    )

    if (Test-Path $Source) {
        Copy-Item -Path $Source -Destination $Destination -Force
    }
}

function Convert-PngToBmp {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Source,
        [Parameter(Mandatory = $true)]
        [string]$Destination
    )

    if (-not (Test-Path $Source)) {
        return
    }

    Add-Type -AssemblyName System.Drawing
    $bitmap = New-Object System.Drawing.Bitmap $Source
    try {
        $bitmap.Save($Destination, [System.Drawing.Imaging.ImageFormat]::Bmp)
    } finally {
        $bitmap.Dispose()
    }
}

function Get-BinaryDependents {
    param(
        [Parameter(Mandatory = $true)]
        [string]$BinaryPath
    )

    $dlls = @()
    try {
        $output = & dumpbin.exe /DEPENDENTS $BinaryPath 2>$null
        foreach ($line in $output) {
            $trimmed = $line.Trim()
            if ($trimmed -match '^[A-Za-z0-9._-]+\.dll$') {
                $dlls += $trimmed
            }
        }
    } catch {
    }
    return $dlls
}

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$resolvedBuildDir = Resolve-Path $BuildDir
$resolvedStageRoot = Join-Path $StageRoot "payload"
$installRoot = Join-Path $resolvedStageRoot "app"
$binDir = Join-Path $installRoot "bin"
$scriptsDir = Join-Path $installRoot "scripts"
$docsDir = Join-Path $installRoot "share\doc\finalis-core"
$mainnetDir = Join-Path $installRoot "mainnet"
$installerAssetsDir = Join-Path $resolvedStageRoot "installer-assets"
$qtDeployExe = Join-Path $QtRootDir "bin\windeployqt.exe"
$vcpkgBinCandidates = @()
if ($VcpkgInstalledDir) {
    $vcpkgBinCandidates += (Join-Path $VcpkgInstalledDir "bin")
}
$buildLocalVcpkgInstalledDir = Join-Path $resolvedBuildDir "vcpkg_installed\x64-windows"
$vcpkgBinCandidates += (Join-Path $buildLocalVcpkgInstalledDir "bin")

if (-not (Test-Path $qtDeployExe) -and (Test-Path $QtRootDir)) {
    $qtDeployCandidate = Get-ChildItem -Path $QtRootDir -Filter windeployqt.exe -Recurse -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($qtDeployCandidate) {
        $qtDeployExe = $qtDeployCandidate.FullName
    }
}

if (Test-Path $StageRoot) {
    Remove-Item -Recurse -Force $StageRoot
}

New-Item -ItemType Directory -Force -Path $resolvedStageRoot | Out-Null
New-Item -ItemType Directory -Force -Path $installRoot | Out-Null
New-Item -ItemType Directory -Force -Path $mainnetDir | Out-Null
New-Item -ItemType Directory -Force -Path $installerAssetsDir | Out-Null

cmake --install $resolvedBuildDir --config $Configuration --prefix $installRoot

New-Item -ItemType Directory -Force -Path $scriptsDir | Out-Null
Copy-Item -Path (Join-Path $PSScriptRoot "Start-Finalis.ps1") -Destination (Join-Path $scriptsDir "Start-Finalis.ps1") -Force

if (Test-Path (Join-Path $binDir "finalis-wallet.exe")) {
    if (-not (Test-Path $qtDeployExe)) {
        throw "windeployqt.exe not found at $qtDeployExe"
    }
    & $qtDeployExe --release --no-translations --compiler-runtime (Join-Path $binDir "finalis-wallet.exe")
}

$vcpkgDllMap = @{}
foreach ($candidate in ($vcpkgBinCandidates | Select-Object -Unique)) {
    if (Test-Path $candidate) {
        Get-ChildItem -Path $candidate -Filter *.dll | ForEach-Object {
            $key = $_.Name.ToLowerInvariant()
            if (-not $vcpkgDllMap.ContainsKey($key)) {
                $vcpkgDllMap[$key] = $_.FullName
            }
        }
    }
}

$seedBinaries = @(
    (Join-Path $binDir "finalis-node.exe"),
    (Join-Path $binDir "finalis-lightserver.exe"),
    (Join-Path $binDir "finalis-explorer.exe"),
    (Join-Path $binDir "finalis-cli.exe"),
    (Join-Path $binDir "finalis-wallet.exe")
) | Where-Object { Test-Path $_ }

$dumpbinAvailable = $null -ne (Get-Command dumpbin.exe -ErrorAction SilentlyContinue)
if ($dumpbinAvailable -and $seedBinaries.Count -gt 0 -and $vcpkgDllMap.Count -gt 0) {
    $visited = New-Object 'System.Collections.Generic.HashSet[string]'
    $queue = New-Object System.Collections.Queue
    foreach ($binary in $seedBinaries) {
        $queue.Enqueue($binary)
    }

    while ($queue.Count -gt 0) {
        $current = [string]$queue.Dequeue()
        foreach ($dll in (Get-BinaryDependents -BinaryPath $current)) {
            $dllKey = $dll.ToLowerInvariant()
            if (-not $visited.Add($dllKey)) {
                continue
            }
            if ($vcpkgDllMap.ContainsKey($dllKey)) {
                $sourcePath = $vcpkgDllMap[$dllKey]
                Copy-Item -Path $sourcePath -Destination $binDir -Force
                $queue.Enqueue((Join-Path $binDir $dll))
            }
        }
    }
} else {
    foreach ($candidate in ($vcpkgBinCandidates | Select-Object -Unique)) {
        if (Test-Path $candidate) {
            Get-ChildItem -Path $candidate -Filter *.dll | ForEach-Object {
                Copy-Item -Path $_.FullName -Destination $binDir -Force
            }
        }
    }
}

Copy-OptionalFile -Source (Join-Path $repoRoot "branding\finalis-app-icon.png") -Destination (Join-Path $installRoot "finalis-app-icon.png")
Copy-OptionalFile -Source (Join-Path $repoRoot "branding\finalis-token-badge-gold-dark.ico") -Destination (Join-Path $installRoot "finalis-app-icon.ico")
Copy-OptionalFile -Source (Join-Path $repoRoot "branding\finalis-token-badge-gold-light.ico") -Destination (Join-Path $installRoot "finalis-app-icon-gold-light.ico")
Copy-OptionalFile -Source (Join-Path $repoRoot "branding\finalis-token-badge-silver-dark.ico") -Destination (Join-Path $installRoot "finalis-app-icon-silver-dark.ico")
Copy-OptionalFile -Source (Join-Path $repoRoot "branding\finalis-token-badge-silver-light.ico") -Destination (Join-Path $installRoot "finalis-app-icon-silver-light.ico")
Copy-OptionalFile -Source (Join-Path $repoRoot "branding\finalis-logo-horizontal.png") -Destination (Join-Path $installRoot "finalis-logo-horizontal.png")
Copy-OptionalFile -Source (Join-Path $repoRoot "mainnet\SEEDS.json") -Destination (Join-Path $mainnetDir "SEEDS.json")
Convert-PngToBmp -Source (Join-Path $repoRoot "branding\finalis-splash-lockup.png") -Destination (Join-Path $installerAssetsDir "finalis-wizard.bmp")
Convert-PngToBmp -Source (Join-Path $repoRoot "branding\finalis-logo-horizontal.png") -Destination (Join-Path $installerAssetsDir "finalis-wizard-small.bmp")
Copy-OptionalFile -Source (Join-Path $repoRoot "branding\finalis-token-badge-gold-dark.ico") -Destination (Join-Path $installerAssetsDir "finalis-app.ico")

$launcherReadme = @"
Finalis Core for Windows
========================

Installed binaries live under:
  bin\

To start a network-listening node + lightserver + explorer:
  powershell -ExecutionPolicy Bypass -File .\scripts\Start-Finalis.ps1

To keep the node local-only:
  powershell -ExecutionPolicy Bypass -File .\scripts\Start-Finalis.ps1 -PublicNode 0
  (from PowerShell you can also use: -PublicNode:`$false)

If sync appears stuck on an old height, clear peer discovery cache and restart:
  powershell -ExecutionPolicy Bypass -File .\scripts\Start-Finalis.ps1 -ResetPeerDiscovery

If startup fails with frontier lane-tip corruption, Start-Finalis automatically
resets local chain state once (keystore/logs preserved) and retries.
Manual one-shot repair command:
  .\bin\finalis-cli.exe repair_state --db "$env:APPDATA\.finalis\mainnet" --force

Windows joiner mode uses:
  mainnet\SEEDS.json

Wallet:
  bin\finalis-wallet.exe

Explorer:
  http://<this-machine-ip>:18080

Lightserver RPC:
  http://<this-machine-ip>:19444/rpc

Explorer will also open in your default browser when the stack starts.
Windows firewall should allow inbound TCP on:
  19440 (P2P), 19444 (Lightserver RPC), 18080 (Explorer)
"@

Set-Content -Path (Join-Path $installRoot "WINDOWS-RUN.txt") -Value $launcherReadme -Encoding ASCII

Write-Host "Staged Windows payload at $resolvedStageRoot"
