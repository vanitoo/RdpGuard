# RdpGuard

Windows Service for Windows Server 2019+ that watches the **Security** event log for Event ID **4625** and only processes **LogonType 10 (RDP)** failures. When an IP crosses an adaptive threshold, it is added to a Windows Firewall block rule for the configured RDP port.

## Defaults

- Dry-run: **enabled**
- RDP port: **3389**
- Fast threshold: 3 failures / 30 sec
- Medium threshold: 5 failures / 5 min
- Hard threshold: 10 failures / 10 min
- Auto-unblock: 3 days
- State/log: `C:\ProgramData\RdpGuard`
- Service account: `LocalSystem`

## Build

On a development PC/server with .NET 8 SDK:

```powershell
.\publish-win-x64.ps1
```

Output appears in `publish\` as a self-contained win-x64 single-file application.

## Test interactively

From an elevated PowerShell in `publish\`:

```powershell
.\RdpGuard.exe
Get-Content C:\ProgramData\RdpGuard\rdpguard.log -Wait -Tail 30
```

Keep `DryRun=true` initially.

## Install as service

Copy the contents of `publish\` to e.g. `C:\RdpGuard`, then run elevated PowerShell:

```powershell
C:\RdpGuard\install-service.ps1
```

The service runs as `LocalSystem`, which is appropriate because it must read the Security event log and update Windows Firewall.

## Enable real blocking

Edit `appsettings.json`:

```json
"DryRun": false
```

Then restart:

```powershell
Restart-Service RdpGuard
```

## Important

Before disabling DryRun, put every management/admin address or subnet into `TrustedNetworks`. CIDR is supported for IPv4 and IPv6.

The program watches new events in real time; it does not repeatedly rescan the last 10 minutes of the Security log.

## Logging / diagnostics

New diagnostics options in `appsettings.json`:

- `LogEveryFailure`: when `true`, every new RDP logon failure (Security Event ID 4625, LogonType 10) is logged with IP, target username, workstation, source port and Event RecordId.
- `HeartbeatSeconds`: writes a `DEBUG | HEARTBEAT` line periodically so you can confirm the service and EventLogWatcher are alive even when no new failures occur.

Example:

```text
2026-08-18 14:18:02 | INFO | RDP FAILURE | IP=185.12.34.56 | User=Administrator | Workstation=- | SourcePort=50123 | RecordId=123456
2026-08-18 14:18:10 | WARN | ATTACK DETECTED | IP=185.12.34.56 | User=Administrator | Reason=3 failures/30s | RecordId=123458 | BlockedTotal=1 | DryRun=True
2026-08-18 14:19:00 | DEBUG | HEARTBEAT | Service alive | Watcher=ON | Blocked=1 | DryRun=True
```

`EventLogWatcher` is real-time and processes new matching events after the watcher starts; it does not poll the Security log every minute. `CleanupIntervalSeconds` controls expired-block cleanup, not event detection.


## v3 diagnostic logging

Every new Security Event ID 4625 is now logged **before** the LogonType filter. This is useful on Windows Server 2019 with NLA, where a failed RDP authentication can be represented differently depending on the authentication stage. The service still blocks only LogonType 10 in this build; other 4625 events are logged and skipped so unrelated network logons are not accidentally blocked.

Example:
```text
INFO | 4625 DETECTED | LogonType=3 | IP=203.0.113.10 | User=Administrator | ...
DEBUG | 4625 SKIPPED | Reason=LogonTypeNotRdp | LogonType=3 | ...
```


## Windows Server 2019 / NLA note

On some Windows Server 2019 systems with Network Level Authentication (NLA), failed RDP authentication is recorded as Security Event 4625 with `LogonType=3` instead of `LogonType=10`.

This build has `AcceptNlaLogonType3=true` by default because this behavior was observed on the target server. **LogonType 3 is not exclusive to RDP**; SMB and other network authentication can also generate it. Keep `DryRun=true` while validating that the events seen on your server correspond to RDP attempts.

The log file is written as UTF-8 with BOM so Windows PowerShell 5.1 `Get-Content` displays Cyrillic usernames correctly.

## NLA / LogonType 3 correlation (safer mode)

Windows Server with NLA can write failed RDP authentication as Security Event 4625 with LogonType=3. LogonType 3 is also used by non-RDP network authentication (for example SMB), so RdpGuard does not blindly count every LogonType=3 event.

With the default settings:

- LogonType=10 is accepted directly as RemoteInteractive/RDP.
- LogonType=3 is accepted only if the same source IP is also observed within the correlation window in one of these RDP-specific Operational logs:
  - Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational
  - Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational
- If the RDP event arrives slightly after Security 4625, RdpGuard waits 2 seconds and checks again.
- If no RDP correlation is found, the 4625 event is logged as `NlaNotCorrelatedWithRdp` and is NOT counted toward blocking.

Relevant settings:

```json
"AcceptNlaLogonType3": true,
"RequireRdpCorrelationForNla": true,
"LogRdpCorrelationEvents": true,
"RdpCorrelationWindowSeconds": 15,
"NlaCorrelationDelayMilliseconds": 2000
```

Keep `DryRun=true` until the log shows `RDP FAILURE ACCEPTED | Mode=NLA-LogonType3-Correlated` for real failed RDP attempts.

## Firewall unavailable / retry behavior

This build separates detected attacks from successfully applied firewall blocks.

- `Applied`: the desired IP set was successfully written to the Windows Firewall rule.
- `Pending`: an attack was detected, but the firewall change failed (for example, `MpsSvc` is stopped).
- Pending entries are persisted in `%ProgramData%\RdpGuard\state.json` together with `LastAttemptUtc` and `LastError`.
- The service does **not** stop if Windows Firewall is disabled. Event watchers, detection, correlation and logging continue.
- Every `FirewallRetryIntervalSeconds` (default 60 seconds) RdpGuard checks `MpsSvc` and reconciles the complete desired block list. Once the service is available, pending entries are applied and changed to `Applied`.
- Heartbeat includes `BlockedApplied`, `BlockedPending` and `Firewall=RUNNING/UNAVAILABLE`.
- In `DryRun=true`, detected IPs are not persisted into state and no firewall changes are performed.

Old state files created by earlier builds did not distinguish DryRun detections from real firewall blocks. Entries without a `Status` property are therefore ignored on migration to avoid accidentally blocking a test/client IP.

## Startup information and 24-hour statistics

On startup RdpGuard now logs the effective RDP port, attack thresholds, unblock period,
firewall retry interval, correlation window, trusted network count, and current Applied/Pending state.
It also reconstructs the previous 24 hours of statistics from `rdpguard.log` and then maintains
the rolling 24-hour counters in memory.

Example:

```
STARTUP CONFIG | RDP port=3389 | Fast=3/30s | Medium=5/5m | Hard=10/10m | UnblockAfter=3d ...
STARTUP STATE | BlockedApplied=12 | BlockedPending=1 | StateTotal=13 ...
24H STATS | Trigger=startup | Raw4625=284 | RdpFailuresAccepted=117 | AttacksDetected=19 | UniqueAttackerIPs=14 | FirewallApplied=18 | FirewallPending=1
```

The same 24-hour summary is written with the heartbeat when `Log24HourStatistics=true`.
For an on-demand console summary on Windows PowerShell 5.1, run:

```powershell
.\show-status.ps1
```

The helper reads `state.json` and the last 24 hours from the UTF-8 log without modifying service state.
