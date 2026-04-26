[CmdletBinding()]
param(
    [string]$DataDir = "",
    [int]$P2PPort = 19440,
    [int]$LightserverPort = 19444,
    [int]$ExplorerPort = 18080,
    [string]$LightserverBind = "0.0.0.0",
    [string]$ExplorerBind = "0.0.0.0",
    [bool]$WithExplorer = $true,
    [bool]$OpenExplorer = $true,
    [object]$PublicNode = $true,
    [switch]$ResetPeerDiscovery,
    [switch]$ConfigureFirewall,
    [switch]$NoStart
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
$cliExe = Join-Path $binDir "finalis-cli.exe"
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

function Set-FinalisFirewallRule {
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

function ConvertTo-Boolean {
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [object]$Value,
        [bool]$Default = $true
    )

    if ($null -eq $Value) {
        return $Default
    }
    if ($Value -is [bool]) {
        return [bool]$Value
    }
    if ($Value -is [int] -or $Value -is [long]) {
        return ([int64]$Value) -ne 0
    }

    $text = ([string]$Value).Trim()
    if ([string]::IsNullOrWhiteSpace($text)) {
        return $Default
    }

    switch -Regex ($text.ToLowerInvariant()) {
        '^(1|true|t|yes|y|on)$' { return $true }
        '^(0|false|f|no|n|off)$' { return $false }
        '^\$(true|false)$' { return ($text.TrimStart('$').ToLowerInvariant() -eq 'true') }
        default {
            throw "Invalid boolean value '$Value'. Use true/false or 1/0 (for cmd.exe, prefer -PublicNode 0)."
        }
    }
}

function Set-FinalisFirewallRules {
    param(
        [bool]$Required = $false
    )

    try {
        Set-FinalisFirewallRule -DisplayName "Finalis P2P ($P2PPort)" -Port $P2PPort -ProgramPath $nodeExe
        Set-FinalisFirewallRule -DisplayName "Finalis Lightserver RPC ($LightserverPort)" -Port $LightserverPort -ProgramPath $lightserverExe
        if ($WithExplorer -and (Test-Path $explorerExe)) {
            Set-FinalisFirewallRule -DisplayName "Finalis Explorer ($ExplorerPort)" -Port $ExplorerPort -ProgramPath $explorerExe
        }
        return $true
    } catch {
        if ($Required) {
            throw "Firewall rule setup failed: $($_.Exception.Message)"
        }
        Write-Warning "Firewall rule setup failed: $($_.Exception.Message)"
        return $false
    }
}

function Test-IsAdministrator {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}

function Invoke-FinalisFirewallElevation {
    if ([string]::IsNullOrWhiteSpace($PSCommandPath) -or (-not (Test-Path $PSCommandPath))) {
        Write-Warning "Unable to locate script path for elevated firewall setup."
        return $false
    }

    $elevatedArgs = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", $PSCommandPath,
        "-ConfigureFirewall",
        "-NoStart",
        "-P2PPort", $P2PPort,
        "-LightserverPort", $LightserverPort,
        "-ExplorerPort", $ExplorerPort,
        "-WithExplorer:$WithExplorer"
    )

    try {
        $proc = Start-Process -FilePath "powershell.exe" -Verb RunAs -ArgumentList $elevatedArgs -Wait -PassThru
        if ($proc.ExitCode -eq 0) {
            return $true
        }
        Write-Warning "Elevated firewall setup exited with code $($proc.ExitCode)."
        return $false
    } catch {
        if ($_.Exception.Message -match "cancel") {
            Write-Warning "Firewall elevation was canceled by the user."
        } else {
            Write-Warning "Unable to request elevated firewall setup: $($_.Exception.Message)"
        }
        return $false
    }
}

function Stop-FinalisProcessIfRunning {
    param(
        [string]$ProcessName,
        [string]$ExpectedPath
    )

    Get-Process -Name $ProcessName -ErrorAction SilentlyContinue | ForEach-Object {
        $matchesPath = $false
        try {
            if ($_.Path -and $ExpectedPath) {
                $matchesPath = ([System.IO.Path]::GetFullPath($_.Path) -eq [System.IO.Path]::GetFullPath($ExpectedPath))
            }
        } catch {
            $matchesPath = $false
        }
        if ($matchesPath) {
            Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-ResetPeerDiscoveryAutomatically {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetDataDir
    )

    $addrmanPath = Join-Path $TargetDataDir "addrman.dat"
    $peersPath = Join-Path $TargetDataDir "peers.dat"

    if ((-not (Test-Path $addrmanPath)) -and (-not (Test-Path $peersPath))) {
        return $false
    }

    # If either cache file exists but is effectively empty, force a reset.
    foreach ($p in @($addrmanPath, $peersPath)) {
        if (Test-Path $p) {
            try {
                $item = Get-Item $p -ErrorAction Stop
                if ($item.Length -le 0) {
                    return $true
                }
            } catch {
                return $true
            }
        }
    }

    return $false
}

function Reset-FinalisChainState {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetDataDir
    )

    if (-not (Test-Path $TargetDataDir)) {
        return
    }

    $preserve = @("keystore", "logs")
    Get-ChildItem -Path $TargetDataDir -Force -ErrorAction SilentlyContinue | ForEach-Object {
        if ($preserve -contains $_.Name.ToLowerInvariant()) {
            return
        }
        Remove-Item -Path $_.FullName -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-FinalisRepairState {
    param(
        [Parameter(Mandatory = $true)]
        [string]$CliPath,
        [Parameter(Mandatory = $true)]
        [string]$TargetDataDir
    )

    if (-not (Test-Path $CliPath)) {
        Write-Warning "finalis-cli not found at $CliPath, using script fallback chain-state reset."
        Reset-FinalisChainState -TargetDataDir $TargetDataDir
        return $true
    }

    try {
        $proc = Start-Process -FilePath $CliPath `
            -ArgumentList @("repair_state", "--db", $TargetDataDir, "--force") `
            -WorkingDirectory $binDir `
            -Wait -PassThru -NoNewWindow
        if ($proc.ExitCode -eq 0) {
            return $true
        }
        Write-Warning "finalis-cli repair_state exited with code $($proc.ExitCode); using script fallback reset."
    } catch {
        Write-Warning "finalis-cli repair_state failed: $($_.Exception.Message); using script fallback reset."
    }

    Reset-FinalisChainState -TargetDataDir $TargetDataDir
    return $true
}

function Test-NodeErrorContains {
    param(
        [Parameter(Mandatory = $true)]
        [string]$NodeErrPath,
        [Parameter(Mandatory = $true)]
        [string]$Pattern
    )

    if (-not (Test-Path $NodeErrPath)) {
        return $false
    }
    try {
        $errText = Get-Content $NodeErrPath -Raw -ErrorAction Stop
        return $errText -match $Pattern
    } catch {
        return $false
    }
}

function Start-FinalisNodeProcess {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ExePath,
        [Parameter(Mandatory = $true)]
        [string]$WorkingDir,
        [Parameter(Mandatory = $true)]
        [object[]]$Arguments,
        [Parameter(Mandatory = $true)]
        [string]$StdOutPath,
        [Parameter(Mandatory = $true)]
        [string]$StdErrPath
    )

    return Start-Process -FilePath $ExePath -ArgumentList $Arguments -WorkingDirectory $WorkingDir `
        -RedirectStandardOutput $StdOutPath -RedirectStandardError $StdErrPath -PassThru
}

function Reset-LogFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )
    New-Item -ItemType Directory -Force -Path ([System.IO.Path]::GetDirectoryName($Path)) | Out-Null
    Set-Content -Path $Path -Value "" -Encoding UTF8 -ErrorAction SilentlyContinue
}

function Wait-ForTcpPort {
    param(
        [string]$TargetAddress,
        [int]$Port,
        [int]$TimeoutSeconds = 15
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        try {
            $client = New-Object System.Net.Sockets.TcpClient
            $async = $client.BeginConnect($TargetAddress, $Port, $null, $null)
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
    [void](Set-FinalisFirewallRules -Required $true)
}

if ($NoStart.IsPresent) {
    Write-Host "Finalis firewall configuration complete."
    Write-Host "Data dir: $DataDir"
    exit 0
}

if ((-not $ResetPeerDiscovery.IsPresent) -and (Test-ResetPeerDiscoveryAutomatically -TargetDataDir $DataDir)) {
    Write-Warning "Detected stale/empty peer cache in $DataDir. Resetting addrman.dat and peers.dat automatically."
    $ResetPeerDiscovery = $true
}

$PublicNode = ConvertTo-Boolean -Value $PublicNode -Default $true

if ($ResetPeerDiscovery.IsPresent) {
    $addrmanPath = Join-Path $DataDir "addrman.dat"
    $peersPath = Join-Path $DataDir "peers.dat"
    Remove-Item -Path $addrmanPath -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $peersPath -Force -ErrorAction SilentlyContinue
}

$nodeArgs = @(
    "--db", $DataDir,
    "--port", $P2PPort,
    "--lightserver-bind", $LightserverBind,
    "--lightserver-port", $LightserverPort
)
if ($PublicNode) {
    $nodeArgs += @("--public", "--listen", "--bind", "0.0.0.0")
} else {
    $nodeArgs += @("--listen", "--bind", "127.0.0.1")
}
$nodeArgs += @("--outbound-target", "8")

if (Test-Path $seedsJson) {
    $seedDoc = Get-Content $seedsJson -Raw | ConvertFrom-Json
    $seedList = @()
    if ($seedDoc -is [System.Collections.IEnumerable] -and -not ($seedDoc -is [string])) {
        foreach ($entry in $seedDoc) {
            if ($entry) { $seedList += [string]$entry }
        }
    } elseif ($seedDoc.PSObject.Properties.Name -contains "seeds_p2p") {
        foreach ($entry in $seedDoc.seeds_p2p) {
            if ($entry) { $seedList += [string]$entry }
        }
    }
    if ($seedList.Count -gt 0) {
        $nodeArgs += @("--no-dns-seeds")
        foreach ($seed in ($seedList | Sort-Object -Unique)) {
            $nodeArgs += @("--peers", $seed)
        }
    }
}

$firewallConfigured = Set-FinalisFirewallRules -Required $false
if ((-not $firewallConfigured) -and (-not (Test-IsAdministrator))) {
    Write-Host "Firewall rules require administrator approval. Prompting for elevation..."
    if (Invoke-FinalisFirewallElevation) {
        [void](Set-FinalisFirewallRules -Required $false)
    } else {
        Write-Warning "Continuing without automatic firewall rule configuration."
    }
}

Stop-FinalisProcessIfRunning -ProcessName "finalis-explorer" -ExpectedPath $explorerExe
Stop-FinalisProcessIfRunning -ProcessName "finalis-lightserver" -ExpectedPath $lightserverExe
Stop-FinalisProcessIfRunning -ProcessName "finalis-node" -ExpectedPath $nodeExe

$nodeLog = Join-Path $logDir "node.log"
$nodeErr = Join-Path $logDir "node.err.log"
Reset-LogFile -Path $nodeLog
Reset-LogFile -Path $nodeErr
$nodeProc = Start-FinalisNodeProcess -ExePath $nodeExe -WorkingDir $appRoot -Arguments $nodeArgs -StdOutPath $nodeLog -StdErrPath $nodeErr

# Auto-recover one known startup corruption mode by rebuilding chain state from peers.
Start-Sleep -Milliseconds 1200
if ($nodeProc.HasExited -and (Test-NodeErrorContains -NodeErrPath $nodeErr -Pattern "frontier-storage-lane-tip-too-low")) {
    Write-Warning "Detected frontier lane-tip corruption in persisted state. Resetting local chain state and retrying startup once."
    [void](Invoke-FinalisRepairState -CliPath $cliExe -TargetDataDir $DataDir)
    New-Item -ItemType Directory -Force -Path $logDir | Out-Null
    Reset-LogFile -Path $nodeLog
    Reset-LogFile -Path $nodeErr
    $nodeProc = Start-FinalisNodeProcess -ExePath $nodeExe -WorkingDir $appRoot -Arguments $nodeArgs -StdOutPath $nodeLog -StdErrPath $nodeErr
}

$lightserverArgs = @(
    "--db", $DataDir,
    "--bind", $LightserverBind,
    "--port", $LightserverPort,
    "--relay-host", "127.0.0.1",
    "--relay-port", $P2PPort
)
$lightserverLog = Join-Path $logDir "lightserver.log"
$lightserverErr = Join-Path $logDir "lightserver.err.log"
$lightserverProc = Start-Process -FilePath $lightserverExe -ArgumentList $lightserverArgs -WorkingDirectory $appRoot -RedirectStandardOutput $lightserverLog -RedirectStandardError $lightserverErr -PassThru

Start-Sleep -Milliseconds 750
if ($nodeProc.HasExited) {
    throw "finalis-node.exe exited before lightserver startup completed. See $nodeErr"
}

if (-not (Wait-ForTcpPort -TargetAddress "127.0.0.1" -Port $LightserverPort -TimeoutSeconds 15)) {
    if ($lightserverProc.HasExited) {
        throw "finalis-lightserver.exe exited before listening on 127.0.0.1:$LightserverPort. See $lightserverErr"
    }
    if ($nodeProc.HasExited) {
        throw "finalis-node.exe exited before lightserver became reachable. See $nodeErr"
    }
    throw "finalis-lightserver.exe did not start listening on 127.0.0.1:$LightserverPort. See $lightserverErr"
}

if ($WithExplorer -and (Test-Path $explorerExe)) {
    $explorerArgs = @(
        "--bind", $ExplorerBind,
        "--port", $ExplorerPort,
        "--rpc-url", "http://127.0.0.1:$LightserverPort/rpc"
    )
    $explorerLog = Join-Path $logDir "explorer.log"
    $explorerErr = Join-Path $logDir "explorer.err.log"
    $explorerProc = Start-Process -FilePath $explorerExe -ArgumentList $explorerArgs -WorkingDirectory $appRoot -RedirectStandardOutput $explorerLog -RedirectStandardError $explorerErr -PassThru
    if (-not (Wait-ForTcpPort -TargetAddress "127.0.0.1" -Port $ExplorerPort -TimeoutSeconds 20)) {
        if ($explorerProc.HasExited) {
            throw "finalis-explorer.exe exited before listening on 127.0.0.1:$ExplorerPort. See $explorerErr"
        }
        if ($nodeProc.HasExited) {
            throw "finalis-node.exe exited before explorer became reachable. See $nodeErr"
        }
        throw "finalis-explorer.exe did not start listening on 127.0.0.1:$ExplorerPort. See $explorerErr"
    }
    if ($OpenExplorer) {
        Start-Process "http://127.0.0.1:$ExplorerPort"
    }
}

if ($nodeProc.HasExited) {
    throw "finalis-node.exe exited during startup. See $nodeErr"
}

# Ensure node remains alive after dependent services are up.
Start-Sleep -Milliseconds 1250
if ($nodeProc.HasExited) {
    throw "finalis-node.exe exited shortly after startup. See $nodeErr"
}

Write-Host "Finalis node started."
Write-Host "Data dir: $DataDir"
Write-Host "Public node: $PublicNode"
Write-Host "Firewall ports: P2P $P2PPort, Lightserver $LightserverPort, Explorer $ExplorerPort"
Write-Host "Lightserver RPC: http://127.0.0.1:$LightserverPort/rpc"
if ($WithExplorer -and (Test-Path $explorerExe)) {
    Write-Host "Explorer: http://127.0.0.1:$ExplorerPort"
}
