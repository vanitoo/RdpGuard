using System.Collections.Concurrent;
using System.Diagnostics.Eventing.Reader;
using System.Net;
using System.Reflection;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using Microsoft.Extensions.Options;
using RdpGuard.Options;
using RdpGuard.Services;

namespace RdpGuard;

public sealed class Worker : BackgroundService
{
    private readonly FileLogger _log;
    private readonly StateStore _state;
    private readonly FirewallManager _firewall;
    private readonly AttackDetector _detector;
    private readonly StatisticsTracker _stats;
    private readonly RdpGuardOptions _options;

    private EventLogWatcher? _securityWatcher;
    private readonly List<EventLogWatcher> _rdpWatchers = new();
    private readonly ConcurrentDictionary<string, DateTime> _recentRdpIps = new(StringComparer.OrdinalIgnoreCase);

    private static readonly string[] RdpOperationalLogs =
    {
        "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
        "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational"
    };

    private static readonly Regex Ipv4Regex = new(
        @"(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9.])",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    public Worker(FileLogger log, StateStore state, FirewallManager firewall, AttackDetector detector, StatisticsTracker stats, IOptions<RdpGuardOptions> options)
    {
        _log = log;
        _state = state;
        _firewall = firewall;
        _detector = detector;
        _stats = stats;
        _options = options.Value;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var informationalVersion = Assembly.GetExecutingAssembly()
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
            ?? Assembly.GetExecutingAssembly().GetName().Version?.ToString()
            ?? "unknown";
        var plus = informationalVersion.IndexOf('+');
        var version = plus >= 0 ? informationalVersion[..plus] : informationalVersion;
        var commit = plus >= 0 && plus + 1 < informationalVersion.Length
            ? informationalVersion[(plus + 1)..]
            : "unknown";
        if (commit.Length > 7) commit = commit[..7];

        _log.BlankLine();
        _log.Info($"Version={version}");
        _log.Info($"Commit={commit}");
        _log.Info($"SERVICE STARTED | Version={version} | DryRun={_options.DryRun} | RDP port={_options.RdpLocalPort} | LogEveryFailure={_options.LogEveryFailure} | AcceptNlaLogonType3={_options.AcceptNlaLogonType3} | RequireRdpCorrelation={_options.RequireRdpCorrelationForNla} | CorrelationWindow={_options.RdpCorrelationWindowSeconds}s | Heartbeat={_options.HeartbeatSeconds}s");

        var startupState = _state.Snapshot();
        var startupApplied = startupState.Count(x => string.Equals(x.Status, "Applied", StringComparison.OrdinalIgnoreCase));
        var startupPending = startupState.Count - startupApplied;
        _log.Info($"STARTUP CONFIG | Version={version} | RDP port={_options.RdpLocalPort} | Fast={_options.FastAttackAttempts}/{_options.FastAttackSeconds}s | Medium={_options.MediumAttackAttempts}/{_options.MediumAttackMinutes}m | Hard={_options.HardLimitAttempts}/{_options.HardLimitWindowMinutes}m | UnblockAfter={_options.UnblockAfterDays}d | FirewallRetry={_options.FirewallRetryIntervalSeconds}s | CorrelationWindow={_options.RdpCorrelationWindowSeconds}s | TrustedNetworks={_options.TrustedNetworks.Count} | LogEveryFailure={_options.LogEveryFailure} | LogRdpCorrelationEvents={_options.LogRdpCorrelationEvents} | Heartbeat={_options.HeartbeatSeconds}s | MaxLog={_options.MaxLogFileSizeMb}MB | Retention={_options.LogRetentionDays}d");
        _log.Info($"STARTUP STATE | BlockedApplied={startupApplied} | BlockedPending={startupPending} | StateTotal={startupState.Count} | BaseDirectory={_options.BaseDirectory} | FirewallRule={_options.FirewallRuleName}");
        Log24HourStats("startup");

        ReconcileFirewallState("startup");

        try
        {
            StartSecurityWatcher();
            StartRdpCorrelationWatchers();
        }
        catch (Exception ex)
        {
            _log.Error($"Event watcher startup failed: {ex}");
            throw;
        }

        var heartbeatEvery = TimeSpan.FromSeconds(Math.Max(10, _options.HeartbeatSeconds));
        var cleanupEvery = TimeSpan.FromSeconds(Math.Max(10, _options.CleanupIntervalSeconds));
        var firewallRetryEvery = TimeSpan.FromSeconds(Math.Max(10, _options.FirewallRetryIntervalSeconds));
        var tickEvery = new[] { heartbeatEvery, cleanupEvery, firewallRetryEvery }.Min();
        var nextHeartbeat = DateTime.UtcNow.Add(heartbeatEvery);
        var nextCleanup = DateTime.UtcNow.Add(cleanupEvery);
        var nextFirewallRetry = DateTime.UtcNow.Add(firewallRetryEvery);

        using var timer = new PeriodicTimer(tickEvery);
        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken))
            {
                var now = DateTime.UtcNow;

                if (now >= nextCleanup)
                {
                    CleanupExpiredBlocks();
                    CleanupCorrelationCache(now);
                    nextCleanup = now.Add(cleanupEvery);
                }

                if (now >= nextFirewallRetry)
                {
                    ReconcileFirewallState("periodic-retry");
                    nextFirewallRetry = now.Add(firewallRetryEvery);
                }

                if (now >= nextHeartbeat)
                {
                    var snapshot = _state.Snapshot();
                    var applied = snapshot.Count(x => string.Equals(x.Status, "Applied", StringComparison.OrdinalIgnoreCase));
                    var pending = snapshot.Count - applied;
                    var rdpWatchersOn = _rdpWatchers.Count(x => x.Enabled);
                    var firewallStatus = _options.DryRun
                        ? "DRY-RUN"
                        : (_firewall.TryCheckFirewallService(out var fwDetail) ? "RUNNING" : $"UNAVAILABLE ({fwDetail})");
                    _log.Debug($"HEARTBEAT | Version={version} | Service alive | RDP port={_options.RdpLocalPort} | SecurityWatcher={(_securityWatcher?.Enabled == true ? "ON" : "OFF")} | RdpWatchers={rdpWatchersOn}/{_rdpWatchers.Count} | RecentRdpIPs={_recentRdpIps.Count} | BlockedApplied={applied} | BlockedPending={pending} | Firewall={firewallStatus} | DryRun={_options.DryRun}");
                    Log24HourStats("heartbeat");
                    nextHeartbeat = now.Add(heartbeatEvery);
                }
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
        finally
        {
            DisposeWatchers();
            _log.Info("SERVICE STOPPED");
        }
    }

    private void StartSecurityWatcher()
    {
        const string query = "*[System[(EventID=4625)]]";
        var eventQuery = new EventLogQuery("Security", PathType.LogName, query)
        {
            ReverseDirection = false,
            TolerateQueryErrors = false
        };

        _securityWatcher = new EventLogWatcher(eventQuery);
        _securityWatcher.EventRecordWritten += OnSecurityEventRecordWritten;
        _securityWatcher.Enabled = true;
        _log.Info("Security EventLogWatcher enabled | EventID=4625 | mode=real-time (new events only)");
    }

    private void StartRdpCorrelationWatchers()
    {
        foreach (var logName in RdpOperationalLogs)
        {
            try
            {
                var eventQuery = new EventLogQuery(logName, PathType.LogName, "*")
                {
                    ReverseDirection = false,
                    TolerateQueryErrors = true
                };

                var watcher = new EventLogWatcher(eventQuery);
                watcher.EventRecordWritten += OnRdpOperationalEventWritten;
                watcher.Enabled = true;
                _rdpWatchers.Add(watcher);
                _log.Info($"RDP correlation watcher enabled | Log={logName}");
            }
            catch (Exception ex)
            {
                _log.Warn($"RDP correlation watcher unavailable | Log={logName} | {ex.Message}");
            }
        }

        if (_options.RequireRdpCorrelationForNla && _rdpWatchers.Count == 0)
        {
            _log.Warn("NLA LogonType=3 correlation is REQUIRED but no RDP Operational watcher could be started. LogonType=3 events will NOT be counted.");
        }
    }

    private void OnSecurityEventRecordWritten(object? sender, EventRecordWrittenEventArgs e)
    {
        if (e.EventException is not null)
        {
            _log.Error($"Security EventLogWatcher error: {e.EventException.Message}");
            return;
        }

        if (e.EventRecord is null) return;
        using (e.EventRecord)
        {
            try
            {
                ProcessSecurityEvent(e.EventRecord);
            }
            catch (Exception ex)
            {
                _log.Error($"Event processing failed | RecordId={e.EventRecord.RecordId} | {ex.Message}");
            }
        }
    }

    private void OnRdpOperationalEventWritten(object? sender, EventRecordWrittenEventArgs e)
    {
        if (e.EventException is not null)
        {
            _log.Warn($"RDP Operational watcher error: {e.EventException.Message}");
            return;
        }

        if (e.EventRecord is null) return;
        using (e.EventRecord)
        {
            try
            {
                var xml = e.EventRecord.ToXml();
                var found = ExtractIpAddresses(xml).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
                foreach (var ip in found)
                {
                    if (IPAddress.TryParse(ip, out var parsed) && !IPAddress.IsLoopback(parsed))
                    {
                        _recentRdpIps[ip] = (e.EventRecord.TimeCreated ?? DateTime.Now).ToUniversalTime();
                        if (_options.LogRdpCorrelationEvents)
                        {
                            _log.Debug($"RDP CORRELATION SEEN | IP={ip} | Provider={e.EventRecord.ProviderName} | EventID={e.EventRecord.Id} | RecordId={e.EventRecord.RecordId}");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _log.Debug($"RDP correlation event parse failed | {ex.Message}");
            }
        }
    }

    private void ProcessSecurityEvent(EventRecord record)
    {
        var xml = XDocument.Parse(record.ToXml());
        XNamespace ns = "http://schemas.microsoft.com/win/2004/08/events/event";
        var data = xml.Descendants(ns + "Data")
            .Select(x => new { Name = (string?)x.Attribute("Name"), Value = x.Value })
            .Where(x => !string.IsNullOrWhiteSpace(x.Name))
            .GroupBy(x => x.Name!, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.Last().Value, StringComparer.OrdinalIgnoreCase);

        data.TryGetValue("LogonType", out var logonType);
        data.TryGetValue("IpAddress", out var rawIp);
        data.TryGetValue("IpPort", out var rawSourcePort);
        data.TryGetValue("TargetUserName", out var rawUserName);
        data.TryGetValue("WorkstationName", out var rawWorkstation);
        data.TryGetValue("Status", out var status);
        data.TryGetValue("SubStatus", out var subStatus);
        data.TryGetValue("AuthenticationPackageName", out var authPackage);

        static string V(string? value) => string.IsNullOrWhiteSpace(value) ? "-" : value;

        _stats.RecordRaw4625(rawIp);

        if (_options.LogEveryFailure)
        {
            _log.Info($"4625 DETECTED | LogonType={V(logonType)} | IP={V(rawIp)} | User={V(rawUserName)} | Workstation={V(rawWorkstation)} | SourcePort={V(rawSourcePort)} | Auth={V(authPackage)} | Status={V(status)} | SubStatus={V(subStatus)} | RecordId={record.RecordId}");
        }

        var ip = rawIp;
        if (string.IsNullOrWhiteSpace(ip) || ip == "-" || ip == "::1") return;
        if (!IPAddress.TryParse(ip, out _))
        {
            _log.Warn($"Invalid IpAddress in event ignored | IP={ip} | RecordId={record.RecordId}");
            return;
        }

        var eventUtc = (record.TimeCreated ?? DateTime.Now).ToUniversalTime();
        var candidate = new FailureCandidate(
            ip,
            V(rawUserName),
            V(rawWorkstation),
            V(rawSourcePort),
            V(authPackage),
            V(status),
            V(subStatus),
            V(logonType),
            record.RecordId,
            eventUtc);

        if (logonType == "10")
        {
            AcceptFailure(candidate, "RDP-LogonType10", "LogonType=10 RemoteInteractive");
            return;
        }

        if (!_options.AcceptNlaLogonType3 || logonType != "3")
        {
            _log.Debug($"4625 SKIPPED | Reason=UnsupportedLogonType | LogonType={V(logonType)} | IP={ip} | RecordId={record.RecordId}");
            return;
        }

        if (!_options.RequireRdpCorrelationForNla)
        {
            AcceptFailure(candidate, "NLA-LogonType3", "Correlation disabled by configuration");
            return;
        }

        if (HasRecentRdpCorrelation(ip, eventUtc, out var delta))
        {
            AcceptFailure(candidate, "NLA-LogonType3-Correlated", $"RDP Operational correlation delta={delta.TotalSeconds:F1}s");
            return;
        }

        _log.Debug($"NLA PENDING | IP={ip} | RecordId={record.RecordId} | waiting={_options.NlaCorrelationDelayMilliseconds}ms for RDP correlation");
        _ = RetryNlaCorrelationAsync(candidate);
    }

    private async Task RetryNlaCorrelationAsync(FailureCandidate candidate)
    {
        try
        {
            await Task.Delay(Math.Max(100, _options.NlaCorrelationDelayMilliseconds));
            if (HasRecentRdpCorrelation(candidate.Ip, candidate.EventUtc, out var delta))
            {
                AcceptFailure(candidate, "NLA-LogonType3-Correlated", $"Delayed RDP Operational correlation delta={delta.TotalSeconds:F1}s");
            }
            else
            {
                _log.Debug($"4625 SKIPPED | Reason=NlaNotCorrelatedWithRdp | LogonType=3 | IP={candidate.Ip} | User={candidate.UserName} | RecordId={candidate.RecordId}");
            }
        }
        catch (Exception ex)
        {
            _log.Debug($"NLA correlation retry failed | IP={candidate.Ip} | RecordId={candidate.RecordId} | {ex.Message}");
        }
    }

    private bool HasRecentRdpCorrelation(string ip, DateTime securityEventUtc, out TimeSpan delta)
    {
        delta = TimeSpan.MaxValue;
        if (!_recentRdpIps.TryGetValue(ip, out var rdpEventUtc)) return false;

        delta = (securityEventUtc - rdpEventUtc).Duration();
        return delta <= TimeSpan.FromSeconds(Math.Max(1, _options.RdpCorrelationWindowSeconds));
    }

    private void AcceptFailure(FailureCandidate candidate, string detectionMode, string correlationReason)
    {
        _stats.RecordAcceptedFailure(candidate.Ip);
        if (_options.LogEveryFailure)
        {
            _log.Info($"RDP FAILURE ACCEPTED | Mode={detectionMode} | Correlation={correlationReason} | IP={candidate.Ip} | User={candidate.UserName} | Workstation={candidate.WorkstationName} | SourcePort={candidate.SourcePort} | LogonType={candidate.LogonType} | Auth={candidate.AuthPackage} | Status={candidate.Status} | SubStatus={candidate.SubStatus} | RecordId={candidate.RecordId}");
        }

        if (_detector.IsTrusted(candidate.Ip))
        {
            _log.Debug($"TRUSTED | IP={candidate.Ip} | User={candidate.UserName} | RecordId={candidate.RecordId}");
            return;
        }

        if (_state.Contains(candidate.Ip))
        {
            var existing = _state.Snapshot().FirstOrDefault(x => string.Equals(x.Ip, candidate.Ip, StringComparison.OrdinalIgnoreCase));
            _log.Debug($"ALREADY TRACKED | IP={candidate.Ip} | State={existing?.Status ?? "Unknown"} | User={candidate.UserName} | RecordId={candidate.RecordId}");
            return;
        }

        if (!_detector.RegisterFailure(candidate.Ip, candidate.EventUtc, out var reason)) return;

        if (_options.DryRun)
        {
            _firewall.TryBlock(candidate.Ip, Array.Empty<string>(), out _);
            _stats.RecordAttackDetected(candidate.Ip);
            _log.Warn($"ATTACK DETECTED | Mode={detectionMode} | IP={candidate.Ip} | User={candidate.UserName} | Reason={reason} | Correlation={correlationReason} | LogonType={candidate.LogonType} | RecordId={candidate.RecordId} | State=DryRunOnly | DryRun=True");
            _detector.Forget(candidate.Ip);
            return;
        }

        _stats.RecordAttackDetected(candidate.Ip);
        var detectedAt = DateTime.UtcNow;
        _state.AddPending(candidate.Ip, detectedAt);
        var desiredIps = _state.Snapshot().Select(x => x.Ip).ToArray();

        if (_firewall.TryBlock(candidate.Ip, desiredIps, out var firewallDetail))
        {
            var pendingIps = _state.PendingSnapshot().Select(x => x.Ip).ToArray();
            _state.MarkApplied(pendingIps, DateTime.UtcNow);
            _stats.RecordFirewallApplied(candidate.Ip, pendingIps.Length);
            var snapshot = _state.Snapshot();
            _log.Warn($"ATTACK DETECTED | Mode={detectionMode} | IP={candidate.Ip} | User={candidate.UserName} | Reason={reason} | Correlation={correlationReason} | LogonType={candidate.LogonType} | RecordId={candidate.RecordId} | State=Applied | BlockedTotal={snapshot.Count} | Firewall={firewallDetail} | DryRun=False");
        }
        else
        {
            var pendingIps = _state.PendingSnapshot().Select(x => x.Ip).ToArray();
            _state.MarkPending(pendingIps, DateTime.UtcNow, firewallDetail);
            _stats.RecordFirewallPending(candidate.Ip);
            _log.Error($"FIREWALL BLOCK PENDING | IP={candidate.Ip} | Reason={firewallDetail} | PendingTotal={pendingIps.Length} | Service continues running and will retry every {_options.FirewallRetryIntervalSeconds}s");
            _log.Warn($"ATTACK DETECTED | Mode={detectionMode} | IP={candidate.Ip} | User={candidate.UserName} | Reason={reason} | Correlation={correlationReason} | LogonType={candidate.LogonType} | RecordId={candidate.RecordId} | State=PendingFirewall | DryRun=False");
        }

        _detector.Forget(candidate.Ip);
    }

    private static IEnumerable<string> ExtractIpAddresses(string text)
    {
        var results = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (Match match in Ipv4Regex.Matches(text))
        {
            if (IPAddress.TryParse(match.Value, out var parsed) &&
                parsed.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            {
                results.Add(parsed.ToString());
            }
        }

        try
        {
            var doc = XDocument.Parse(text);
            foreach (var value in doc.Descendants().Where(x => !x.HasElements).Select(x => x.Value.Trim()))
            {
                if (IPAddress.TryParse(value, out var parsed) &&
                    parsed.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
                {
                    results.Add(parsed.ToString());
                }
            }
        }
        catch
        {
        }

        return results;
    }

    private void CleanupCorrelationCache(DateTime nowUtc)
    {
        var cutoff = nowUtc.AddSeconds(-Math.Max(30, _options.RdpCorrelationWindowSeconds * 4));
        foreach (var pair in _recentRdpIps)
        {
            if (pair.Value < cutoff)
            {
                _recentRdpIps.TryRemove(pair.Key, out _);
            }
        }
    }

    private void CleanupExpiredBlocks()
    {
        var cutoff = DateTime.UtcNow.AddDays(-_options.UnblockAfterDays);
        foreach (var entry in _state.Snapshot().Where(x => x.BlockedAtUtc <= cutoff))
        {
            if (_options.DryRun)
            {
                _state.Remove(entry.Ip);
                continue;
            }

            var remaining = _state.Snapshot()
                .Where(x => !string.Equals(x.Ip, entry.Ip, StringComparison.OrdinalIgnoreCase))
                .Select(x => x.Ip)
                .ToArray();

            if (_firewall.TryUnblock(entry.Ip, remaining, out var detail))
            {
                _state.Remove(entry.Ip);
                _log.Info($"EXPIRED BLOCK REMOVED | IP={entry.Ip} | Firewall={detail}");
            }
            else
            {
                _log.Error($"UNBLOCK PENDING | IP={entry.Ip} | Reason={detail} | State retained for safety");
            }
        }
    }

    private void ReconcileFirewallState(string trigger)
    {
        if (_options.DryRun) return;

        try
        {
            var snapshot = _state.Snapshot();
            var desiredIps = snapshot.Select(x => x.Ip).ToArray();
            if (_firewall.TryEnsureRule(desiredIps, out var detail))
            {
                var pendingIps = snapshot
                    .Where(x => string.Equals(x.Status, "Pending", StringComparison.OrdinalIgnoreCase))
                    .Select(x => x.Ip)
                    .ToArray();

                if (pendingIps.Length > 0)
                {
                    _state.MarkApplied(pendingIps, DateTime.UtcNow);
                    _stats.RecordFirewallApplied(null, pendingIps.Length);
                    _log.Warn($"FIREWALL RECOVERED | Trigger={trigger} | AppliedPending={pendingIps.Length} | TotalBlocked={desiredIps.Length} | {detail}");
                }
                else if (trigger == "startup")
                {
                    _log.Info($"FIREWALL STATE RESTORED | TotalBlocked={desiredIps.Length} | {detail}");
                }
            }
            else
            {
                var pendingIps = snapshot
                    .Where(x => string.Equals(x.Status, "Pending", StringComparison.OrdinalIgnoreCase))
                    .Select(x => x.Ip)
                    .ToArray();
                if (pendingIps.Length > 0)
                {
                    _state.MarkPending(pendingIps, DateTime.UtcNow, detail);
                }
                _log.Error($"FIREWALL UNAVAILABLE | Trigger={trigger} | Reason={detail} | AppliedState={snapshot.Count - pendingIps.Length} | Pending={pendingIps.Length} | Service continues running");
            }
        }
        catch (Exception ex)
        {
            _log.Error($"FIREWALL RECONCILE ERROR | Trigger={trigger} | {ex.GetType().Name}: {ex.Message} | Service continues running");
        }
    }

    private void Log24HourStats(string trigger)
    {
        if (!_options.Log24HourStatistics) return;
        var stats = _stats.Snapshot24Hours();
        var current = _state.Snapshot();
        var currentlyBlocked = current.Count(x => string.Equals(x.Status, "Applied", StringComparison.OrdinalIgnoreCase));
        _log.Info($"24H STATS | Trigger={trigger} | Detections24h={stats.AttacksDetected} | UniqueAttackIPs24h={stats.UniqueAttackerIps} | RealBlocks24h={stats.FirewallApplied} | PendingBlocks24h={stats.FirewallPending} | CurrentlyBlocked={currentlyBlocked}");
    }

    private void DisposeWatchers()
    {
        if (_securityWatcher is not null)
        {
            _securityWatcher.Enabled = false;
            _securityWatcher.Dispose();
        }

        foreach (var watcher in _rdpWatchers)
        {
            try
            {
                watcher.Enabled = false;
                watcher.Dispose();
            }
            catch
            {
            }
        }
        _rdpWatchers.Clear();
    }

    private sealed record FailureCandidate(
        string Ip,
        string UserName,
        string WorkstationName,
        string SourcePort,
        string AuthPackage,
        string Status,
        string SubStatus,
        string LogonType,
        long? RecordId,
        DateTime EventUtc);
}