[CmdletBinding()]
param(
    [string]$DataDir = "",
    [int]$P2PPort = 19440,
    [int]$LightserverPort = 19444,
    [int]$ExplorerPort = 18080,
    [string]$LightserverBind = "0.0.0.0",
    [string]$ExplorerBind = "0.0.0.0",
    [bool]$WithExplorer = $true,
    [switch]$ConfigureFirewall,
    [switch]$NoStart,
    [switch]$PublicNode
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($DataDir)) {
    if (-not [string]::IsNullOrWhiteSpace($env:APPDATA)) {
        $DataDir = Join-Path $env:APPDATA ".finalis\mainnet"
    } elseif (-not [string]::IsNullOrWhiteSpace($env:USERPROFILE)) {
        $DataDir = Join-Path $env:USERPROFILE ".finalis\mainnet"
    } else {
        $DataDir = ".finalis\mainnet"
    }
}

$appRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$binDir = Join-Path $appRoot "bin"
$nodeExe = Join-Path $binDir "finalis-node.exe"
$lightserverExe = Join-Path $binDir "finalis-lightserver.exe"
$explorerExe = Join-Path $binDir "finalis-explorer.exe"
$seedsJson = Join-Path $appRoot "mainnet\SEEDS.json"
$logDir = Join-Path $DataDir "logs"

New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $DataDir "keystore") | Out-Null

if (-not (Test-Path $nodeExe)) {
    throw "finalis-node.exe not found at $nodeExe"
}
if (-not (Test-Path $lightserverExe)) {
    throw "finalis-lightserver.exe not found at $lightserverExe"
}

function Ensure-FirewallRule {
    param(
        [string]$DisplayName,
        [int]$Port,
        [string]$ProgramPath
    )

    $existing = Get-NetFirewallRule -DisplayName $DisplayName -ErrorAction SilentlyContinue
    if ($existing) {
        return
    }

    $params = @{
        DisplayName = $DisplayName
        Direction   = "Inbound"
        Action      = "Allow"
        Enabled     = "True"
        Profile     = "Any"
        Protocol    = "TCP"
        LocalPort   = $Port
    }
    if ($ProgramPath -and (Test-Path $ProgramPath)) {
        $params["Program"] = $ProgramPath
    }
    New-NetFirewallRule @params | Out-Null
}

function Ensure-FinalisFirewallRules {
    try {
        Ensure-FirewallRule -DisplayName "Finalis P2P ($P2PPort)" -Port $P2PPort -ProgramPath $nodeExe
        Ensure-FirewallRule -DisplayName "Finalis Lightserver RPC ($LightserverPort)" -Port $LightserverPort -ProgramPath $lightserverExe
        if ($WithExplorer -and (Test-Path $explorerExe)) {
            Ensure-FirewallRule -DisplayName "Finalis Explorer ($ExplorerPort)" -Port $ExplorerPort -ProgramPath $explorerExe
        }
    } catch {
        Write-Warning "Firewall rule setup failed: $($_.Exception.Message)"
    }
}

function Stop-FinalisProcessIfRunning {
    param(
        [string]$ProcessName
    )

    Get-Process -Name $ProcessName -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
}

function Wait-ForTcpPort {
    param(
        [string]$Host,
        [int]$Port,
        [int]$TimeoutSeconds = 15
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        try {
            $client = New-Object System.Net.Sockets.TcpClient
            $async = $client.BeginConnect($Host, $Port, $null, $null)
            if ($async.AsyncWaitHandle.WaitOne(500)) {
                $client.EndConnect($async)
                $client.Close()
                return $true
            }
            $client.Close()
        } catch {
        }
        Start-Sleep -Milliseconds 250
    }
    return $false
}

if ($ConfigureFirewall.IsPresent) {
    Ensure-FinalisFirewallRules
}

if ($NoStart.IsPresent) {
    Write-Host "Finalis firewall configuration complete."
    Write-Host "Data dir: $DataDir"
    exit 0
}

$nodeArgs = @(
    "--db", $DataDir,
    "--port", $P2PPort,
    "--lightserver-bind", $LightserverBind,
    "--lightserver-port", $LightserverPort
)
$nodeArgs += @("--public", "--listen", "--bind", "0.0.0.0", "--outbound-target", "1")

if (Test-Path $seedsJson) {
    $seedList = Get-Content $seedsJson -Raw | ConvertFrom-Json
    foreach ($seed in $seedList) {
        if ($seed) {
            $nodeArgs += @("--peers", [string]$seed)
        }
    }
}

Ensure-FinalisFirewallRules

Stop-FinalisProcessIfRunning -ProcessName "finalis-explorer"
Stop-FinalisProcessIfRunning -ProcessName "finalis-lightserver"
Stop-FinalisProcessIfRunning -ProcessName "finalis-node"

$nodeLog = Join-Path $logDir "node.log"
$nodeErr = Join-Path $logDir "node.err.log"
Start-Process -FilePath $nodeExe -ArgumentList $nodeArgs -WorkingDirectory $appRoot -RedirectStandardOutput $nodeLog -RedirectStandardError $nodeErr | Out-Null

$lightserverArgs = @(
    "--db", $DataDir,
    "--bind", $LightserverBind,
    "--port", $LightserverPort,
    "--relay-host", "127.0.0.1",
    "--relay-port", $P2PPort
)
$lightserverLog = Join-Path $logDir "lightserver.log"
$lightserverErr = Join-Path $logDir "lightserver.err.log"
Start-Process -FilePath $lightserverExe -ArgumentList $lightserverArgs -WorkingDirectory $appRoot -RedirectStandardOutput $lightserverLog -RedirectStandardError $lightserverErr | Out-Null

if (-not (Wait-ForTcpPort -Host "127.0.0.1" -Port $LightserverPort -TimeoutSeconds 15)) {
    throw "finalis-lightserver.exe did not start listening on 127.0.0.1:$LightserverPort"
}

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
Write-Host "Lightserver RPC: http://$LightserverBind`:$LightserverPort/rpc"
if ($WithExplorer -and (Test-Path $explorerExe)) {
    Write-Host "Explorer: http://$ExplorerBind`:$ExplorerPort"
}
