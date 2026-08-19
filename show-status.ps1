param(
    [string]$BaseDirectory = "C:\ProgramData\RdpGuard"
)

$logFile = Join-Path $BaseDirectory "rdpguard.log"
$stateFile = Join-Path $BaseDirectory "state.json"
$since = (Get-Date).AddHours(-24)

$applied = 0
$pending = 0
if (Test-Path $stateFile) {
    try {
        $state = @(Get-Content $stateFile -Raw -Encoding UTF8 | ConvertFrom-Json)
        $applied = @($state | Where-Object { $_.Status -eq 'Applied' }).Count
        $pending = @($state | Where-Object { $_.Status -eq 'Pending' }).Count
    } catch {
        Write-Warning "Cannot read state.json: $($_.Exception.Message)"
    }
}

$detections24h = 0
$realBlocks24h = 0
$pendingBlocks24h = 0
$attackerIps = New-Object 'System.Collections.Generic.HashSet[string]'

if (Test-Path $logFile) {
    Get-Content $logFile -Encoding UTF8 | ForEach-Object {
        $line = $_
        if ($line.Length -lt 19) { return }
        $stamp = [datetime]::MinValue
        if (-not [datetime]::TryParseExact($line.Substring(0,19), 'yyyy-MM-dd HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$stamp)) { return }
        if ($stamp -lt $since) { return }

        if ($line -like '*| ATTACK DETECTED |*') {
            $detections24h++
            if ($line -match '(?:^|\|\s)IP=([^\s|]+)') { [void]$attackerIps.Add($Matches[1]) }
            if ($line -like '*State=Applied*') { $realBlocks24h++ }
            if ($line -like '*State=PendingFirewall*') { $pendingBlocks24h++ }
        }
        if ($line -like '*| FIREWALL RECOVERED |*' -and $line -match 'AppliedPending=(\d+)') {
            $realBlocks24h += [int]$Matches[1]
        }
    }
}

Write-Host "RdpGuard status" -ForegroundColor Cyan
Write-Host "24H STATS | Detections24h=$detections24h | UniqueAttackIPs24h=$($attackerIps.Count) | RealBlocks24h=$realBlocks24h | PendingBlocks24h=$pendingBlocks24h | CurrentlyBlocked=$applied"
Write-Host "Current state | Applied=$applied | Pending=$pending | Total=$($applied + $pending)"
