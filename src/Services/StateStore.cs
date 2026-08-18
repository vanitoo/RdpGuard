using System.Text.Json;
using Microsoft.Extensions.Options;
using RdpGuard.Models;
using RdpGuard.Options;

namespace RdpGuard.Services;

public sealed class StateStore
{
    private readonly object _sync = new();
    private readonly string _stateFile;
    private readonly FileLogger _log;
    private Dictionary<string, BlockedEntry> _entries = new(StringComparer.OrdinalIgnoreCase);

    public StateStore(IOptions<RdpGuardOptions> options, FileLogger log)
    {
        _log = log;
        var dir = Environment.ExpandEnvironmentVariables(options.Value.BaseDirectory);
        Directory.CreateDirectory(dir);
        _stateFile = Path.Combine(dir, "state.json");
        Load();
    }

    public bool Contains(string ip)
    {
        lock (_sync) return _entries.ContainsKey(ip);
    }

    public void AddPending(string ip, DateTime blockedAtUtc)
    {
        lock (_sync)
        {
            _entries[ip] = new BlockedEntry
            {
                Ip = ip,
                BlockedAtUtc = blockedAtUtc,
                Status = "Pending",
                LastAttemptUtc = null,
                LastError = null
            };
            SaveUnsafe();
        }
    }

    public void MarkApplied(IEnumerable<string> ips, DateTime attemptUtc)
    {
        lock (_sync)
        {
            foreach (var ip in ips)
            {
                if (!_entries.TryGetValue(ip, out var entry)) continue;
                entry.Status = "Applied";
                entry.LastAttemptUtc = attemptUtc;
                entry.LastError = null;
            }
            SaveUnsafe();
        }
    }

    public void MarkPending(IEnumerable<string> ips, DateTime attemptUtc, string error)
    {
        lock (_sync)
        {
            foreach (var ip in ips)
            {
                if (!_entries.TryGetValue(ip, out var entry)) continue;
                entry.Status = "Pending";
                entry.LastAttemptUtc = attemptUtc;
                entry.LastError = error;
            }
            SaveUnsafe();
        }
    }

    public void AddOrRestore(BlockedEntry source)
    {
        lock (_sync)
        {
            _entries[source.Ip] = Clone(source);
            SaveUnsafe();
        }
    }

    public void Remove(string ip)
    {
        lock (_sync)
        {
            if (_entries.Remove(ip)) SaveUnsafe();
        }
    }

    public IReadOnlyList<BlockedEntry> Snapshot()
    {
        lock (_sync) return _entries.Values.Select(Clone).ToList();
    }

    public IReadOnlyList<BlockedEntry> PendingSnapshot()
    {
        lock (_sync) return _entries.Values
            .Where(x => string.Equals(x.Status, "Pending", StringComparison.OrdinalIgnoreCase))
            .Select(Clone).ToList();
    }

    public IReadOnlyList<BlockedEntry> AppliedSnapshot()
    {
        lock (_sync) return _entries.Values
            .Where(x => string.Equals(x.Status, "Applied", StringComparison.OrdinalIgnoreCase))
            .Select(Clone).ToList();
    }

    private void Load()
    {
        try
        {
            if (!File.Exists(_stateFile)) return;
            var json = File.ReadAllText(_stateFile);
            var items = JsonSerializer.Deserialize<List<BlockedEntry>>(json) ?? new();

            var legacy = items.Count(x => !string.IsNullOrWhiteSpace(x.Ip) && string.IsNullOrWhiteSpace(x.Status));
            if (legacy > 0)
            {
                _log.Warn($"Legacy state entries ignored | Count={legacy} | Reason=old state format has no Applied/Pending status; this avoids accidentally blocking DryRun test IPs");
            }

            _entries = items
                .Where(x => !string.IsNullOrWhiteSpace(x.Ip))
                .Where(x => string.Equals(x.Status, "Applied", StringComparison.OrdinalIgnoreCase) ||
                            string.Equals(x.Status, "Pending", StringComparison.OrdinalIgnoreCase))
                .ToDictionary(x => x.Ip, StringComparer.OrdinalIgnoreCase);

            var applied = _entries.Values.Count(x => string.Equals(x.Status, "Applied", StringComparison.OrdinalIgnoreCase));
            var pending = _entries.Count - applied;
            _log.Info($"State loaded | Total={_entries.Count} | Applied={applied} | Pending={pending}");
        }
        catch (Exception ex)
        {
            _entries = new(StringComparer.OrdinalIgnoreCase);
            _log.Error($"State load failed: {ex.Message}");
        }
    }

    private void SaveUnsafe()
    {
        var tmp = _stateFile + ".tmp";
        var json = JsonSerializer.Serialize(_entries.Values.OrderBy(x => x.Ip), new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(tmp, json, new System.Text.UTF8Encoding(false));
        File.Move(tmp, _stateFile, true);
    }

    private static BlockedEntry Clone(BlockedEntry x) => new()
    {
        Ip = x.Ip,
        BlockedAtUtc = x.BlockedAtUtc,
        Status = x.Status,
        LastAttemptUtc = x.LastAttemptUtc,
        LastError = x.LastError
    };
}
