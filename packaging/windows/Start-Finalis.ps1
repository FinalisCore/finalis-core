[CmdletBinding()]
param(
    [string]$DataDir = "$env:LOCALAPPDATA\Finalis\mainnet",
    [int]$P2PPort = 19440,
    [int]$LightserverPort = 19444,
    [int]$ExplorerPort = 18080,
    [string]$LightserverBind = "127.0.0.1",
    [string]$ExplorerBind = "127.0.0.1",
    [bool]$WithExplorer = $true,
    [switch]$PublicNode,
    [ValidateSet("auto", "bootstrap", "joiner")]
    [string]$NodeRole = "auto"
)

$ErrorActionPreference = "Stop"

$appRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$binDir = Join-Path $appRoot "bin"
$nodeExe = Join-Path $binDir "finalis-node.exe"
$explorerExe = Join-Path $binDir "finalis-explorer.exe"
$seedsJson = Join-Path $appRoot "mainnet\SEEDS.json"
$logDir = Join-Path $DataDir "logs"

New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
New-Item -ItemType Directory -Force -Path $logDir | Out-Null

if (-not (Test-Path $nodeExe)) {
    throw "finalis-node.exe not found at $nodeExe"
}

$nodeArgs = @(
    "--db", $DataDir,
    "--port", $P2PPort,
    "--with-lightserver",
    "--lightserver-bind", $LightserverBind,
    "--lightserver-port", $LightserverPort
)

if ($PublicNode.IsPresent) {
    $nodeArgs += "--public"
}

switch ($NodeRole) {
    "bootstrap" {
        $nodeArgs += @("--listen", "--bind", "0.0.0.0", "--no-dns-seeds", "--outbound-target", "0")
    }
    "joiner" {
        $nodeArgs += @("--no-dns-seeds", "--outbound-target", "1")
    }
    default {
        if (Test-Path $seedsJson) {
            $nodeArgs += @("--no-dns-seeds", "--outbound-target", "1")
        } else {
            $nodeArgs += @("--listen", "--bind", "127.0.0.1", "--no-dns-seeds", "--outbound-target", "0")
        }
    }
}

if ((Test-Path $seedsJson) -and $NodeRole -ne "bootstrap") {
    $seedList = Get-Content $seedsJson -Raw | ConvertFrom-Json
    foreach ($seed in $seedList) {
        if ($seed) {
            $nodeArgs += @("--peers", [string]$seed)
        }
    }
}

$nodeLog = Join-Path $logDir "node.log"
$nodeErr = Join-Path $logDir "node.err.log"
Start-Process -FilePath $nodeExe -ArgumentList $nodeArgs -WorkingDirectory $appRoot -RedirectStandardOutput $nodeLog -RedirectStandardError $nodeErr | Out-Null

if ($WithExplorer -and (Test-Path $explorerExe)) {
    $explorerArgs = @(
        "--bind", $ExplorerBind,
        "--port", $ExplorerPort,
        "--rpc-url", "http://127.0.0.1:$LightserverPort/rpc"
    )
    $explorerLog = Join-Path $logDir "explorer.log"
    $explorerErr = Join-Path $logDir "explorer.err.log"
    Start-Process -FilePath $explorerExe -ArgumentList $explorerArgs -WorkingDirectory $appRoot -RedirectStandardOutput $explorerLog -RedirectStandardError $explorerErr | Out-Null
}

Write-Host "Finalis node started."
Write-Host "Data dir: $DataDir"
Write-Host "Lightserver RPC: http://127.0.0.1:$LightserverPort/rpc"
if ($WithExplorer -and (Test-Path $explorerExe)) {
    Write-Host "Explorer: http://127.0.0.1:$ExplorerPort"
}
