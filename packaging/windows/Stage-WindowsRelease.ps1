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

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$resolvedBuildDir = Resolve-Path $BuildDir
$resolvedStageRoot = Join-Path $StageRoot "payload"
$installRoot = Join-Path $resolvedStageRoot "app"
$binDir = Join-Path $installRoot "bin"
$scriptsDir = Join-Path $installRoot "scripts"
$docsDir = Join-Path $installRoot "share\doc\finalis-core"
$qtDeployExe = Join-Path $QtRootDir "bin\windeployqt.exe"
$vcpkgBinDir = Join-Path $VcpkgInstalledDir "bin"

if (Test-Path $StageRoot) {
    Remove-Item -Recurse -Force $StageRoot
}

New-Item -ItemType Directory -Force -Path $resolvedStageRoot | Out-Null
New-Item -ItemType Directory -Force -Path $installRoot | Out-Null

cmake --install $resolvedBuildDir --config $Configuration --prefix $installRoot

New-Item -ItemType Directory -Force -Path $scriptsDir | Out-Null
Copy-Item -Path (Join-Path $PSScriptRoot "Start-Finalis.ps1") -Destination (Join-Path $scriptsDir "Start-Finalis.ps1") -Force

if (Test-Path (Join-Path $binDir "finalis-wallet.exe")) {
    if (-not (Test-Path $qtDeployExe)) {
        throw "windeployqt.exe not found at $qtDeployExe"
    }
    & $qtDeployExe --release --no-translations --compiler-runtime (Join-Path $binDir "finalis-wallet.exe")
}

if (Test-Path $vcpkgBinDir) {
    Get-ChildItem -Path $vcpkgBinDir -Filter *.dll | ForEach-Object {
        Copy-Item -Path $_.FullName -Destination $binDir -Force
    }
}

Copy-OptionalFile -Source (Join-Path $repoRoot "branding\finalis-app-icon.png") -Destination (Join-Path $installRoot "finalis-app-icon.png")
Copy-OptionalFile -Source (Join-Path $repoRoot "branding\finalis-logo-horizontal.png") -Destination (Join-Path $installRoot "finalis-logo-horizontal.png")

$launcherReadme = @"
Finalis Core for Windows
========================

Installed binaries live under:
  bin\

To start a local node + lightserver + explorer:
  powershell -ExecutionPolicy Bypass -File .\scripts\Start-Finalis.ps1

Wallet:
  bin\finalis-wallet.exe

Explorer:
  http://127.0.0.1:18080

Lightserver RPC:
  http://127.0.0.1:19444/rpc
"@

Set-Content -Path (Join-Path $installRoot "WINDOWS-RUN.txt") -Value $launcherReadme -Encoding ASCII

Write-Host "Staged Windows payload at $resolvedStageRoot"
