using System.Collections.Concurrent;
using System.Globalization;
using System.Text.RegularExpressions;

namespace RdpGuard.Services;

public sealed class StatisticsTracker
{
    private readonly object _sync = new();
    private readonly List<StatEvent> _events = new();
    private readonly FileLogger _log;

    private static readonly Regex IpRegex = new(@"(?:^|\|\s)IP=([^\s|]+)", RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex AppliedPendingRegex = new(@"AppliedPending=(\d+)", RegexOptions.Compiled | RegexOptions.CultureInvariant);

    public StatisticsTracker(FileLogger log)
    {
        _log = log;
        LoadRecentFromLog();
    }

    public void RecordRaw4625(string? ip = null) => Add(StatKind.Raw4625, ip, 1);
    public void RecordAcceptedFailure(string? ip = null) => Add(StatKind.AcceptedFailure, ip, 1);
    public void RecordAttackDetected(string? ip = null) => Add(StatKind.AttackDetected, ip, 1);
    public void RecordFirewallApplied(string? ip = null, int count = 1) => Add(StatKind.FirewallApplied, ip, Math.Max(1, count));
    public void RecordFirewallPending(string? ip = null) => Add(StatKind.FirewallPending, ip, 1);

    public StatsSnapshot Snapshot24Hours()
    {
        lock (_sync)
        {
            PruneUnsafe(DateTime.UtcNow.AddHours(-24));
            var items = _events.ToArray();
            return new StatsSnapshot(
                items.Where(x => x.Kind == StatKind.Raw4625).Sum(x => x.Count),
                items.Where(x => x.Kind == StatKind.AcceptedFailure).Sum(x => x.Count),
                items.Where(x => x.Kind == StatKind.AttackDetected).Sum(x => x.Count),
                items.Where(x => x.Kind == StatKind.FirewallApplied).Sum(x => x.Count),
                items.Where(x => x.Kind == StatKind.FirewallPending).Sum(x => x.Count),
                items.Where(x => x.Kind == StatKind.AttackDetected && !string.IsNullOrWhiteSpace(x.Ip))
                     .Select(x => x.Ip!)
                     .Distinct(StringComparer.OrdinalIgnoreCase)
                     .Count());
        }
    }

    private void Add(StatKind kind, string? ip, int count)
    {
        lock (_sync)
        {
            _events.Add(new StatEvent(DateTime.UtcNow, kind, NormalizeIp(ip), count));
            PruneUnsafe(DateTime.UtcNow.AddHours(-24));
        }
    }

    private void LoadRecentFromLog()
    {
        try
        {
            var path = _log.LogFilePath;
            if (!File.Exists(path)) return;

            var cutoff = DateTime.Now.AddHours(-24);
            foreach (var line in File.ReadLines(path))
            {
                if (line.Length < 19) continue;
                if (!DateTime.TryParseExact(line.AsSpan(0, 19), "yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeLocal, out var localTime)) continue;
                if (localTime < cutoff) continue;

                var utc = localTime.ToUniversalTime();
                var ip = ExtractIp(line);

                if (line.Contains("| 4625 DETECTED |", StringComparison.Ordinal))
                    _events.Add(new StatEvent(utc, StatKind.Raw4625, ip, 1));

                if (line.Contains("| RDP FAILURE ACCEPTED |", StringComparison.Ordinal))
                    _events.Add(new StatEvent(utc, StatKind.AcceptedFailure, ip, 1));

                if (line.Contains("| ATTACK DETECTED |", StringComparison.Ordinal))
                {
                    _events.Add(new StatEvent(utc, StatKind.AttackDetected, ip, 1));
                    if (line.Contains("State=Applied", StringComparison.Ordinal))
                        _events.Add(new StatEvent(utc, StatKind.FirewallApplied, ip, 1));
                    else if (line.Contains("State=PendingFirewall", StringComparison.Ordinal))
                        _events.Add(new StatEvent(utc, StatKind.FirewallPending, ip, 1));
                }

                if (line.Contains("| FIREWALL RECOVERED |", StringComparison.Ordinal))
                {
                    var m = AppliedPendingRegex.Match(line);
                    if (m.Success && int.TryParse(m.Groups[1].Value, out var recovered) && recovered > 0)
                        _events.Add(new StatEvent(utc, StatKind.FirewallApplied, null, recovered));
                }
            }

            PruneUnsafe(DateTime.UtcNow.AddHours(-24));
        }
        catch
        {
            // Statistics must never prevent the service from starting.
            _events.Clear();
        }
    }

    private void PruneUnsafe(DateTime cutoffUtc) => _events.RemoveAll(x => x.Utc < cutoffUtc);

    private static string? ExtractIp(string line)
    {
        var m = IpRegex.Match(line);
        return m.Success ? NormalizeIp(m.Groups[1].Value) : null;
    }

    private static string? NormalizeIp(string? ip)
        => string.IsNullOrWhiteSpace(ip) || ip == "-" ? null : ip.Trim();

    private enum StatKind
    {
        Raw4625,
        AcceptedFailure,
        AttackDetected,
        FirewallApplied,
        FirewallPending
    }

    private sealed record StatEvent(DateTime Utc, StatKind Kind, string? Ip, int Count);
}

public sealed record StatsSnapshot(
    int Raw4625,
    int AcceptedFailures,
    int AttacksDetected,
    int FirewallApplied,
    int FirewallPending,
    int UniqueAttackerIps);
