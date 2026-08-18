using System.Collections.Concurrent;
using System.Net;
using Microsoft.Extensions.Options;
using RdpGuard.Options;

namespace RdpGuard.Services;

public sealed class AttackDetector
{
    private readonly ConcurrentDictionary<string, Queue<DateTime>> _attempts = new(StringComparer.OrdinalIgnoreCase);
    private readonly RdpGuardOptions _options;
    private readonly List<IpNetwork> _trusted;
    private readonly FileLogger _log;

    public AttackDetector(IOptions<RdpGuardOptions> options, FileLogger log)
    {
        _options = options.Value;
        _log = log;
        _trusted = new();
        foreach (var item in _options.TrustedNetworks)
        {
            if (IpNetwork.TryParse(item, out var n) && n is not null) _trusted.Add(n);
            else _log.Warn($"Invalid trusted network ignored: {item}");
        }
    }

    public bool IsTrusted(string ip)
    {
        return IPAddress.TryParse(ip, out var address) && _trusted.Any(n => n.Contains(address));
    }

    public bool RegisterFailure(string ip, DateTime timeUtc, out string reason)
    {
        reason = string.Empty;
        var queue = _attempts.GetOrAdd(ip, _ => new Queue<DateTime>());
        lock (queue)
        {
            queue.Enqueue(timeUtc);
            var oldestAllowed = timeUtc.AddMinutes(-Math.Max(_options.HardLimitWindowMinutes, _options.MediumAttackMinutes));
            while (queue.Count > 0 && queue.Peek() < oldestAllowed) queue.Dequeue();

            var arr = queue.ToArray();
            var fast = arr.Count(t => t >= timeUtc.AddSeconds(-_options.FastAttackSeconds));
            if (fast >= _options.FastAttackAttempts)
            {
                reason = $"{fast} failures/{_options.FastAttackSeconds}s";
                return true;
            }

            var medium = arr.Count(t => t >= timeUtc.AddMinutes(-_options.MediumAttackMinutes));
            if (medium >= _options.MediumAttackAttempts)
            {
                reason = $"{medium} failures/{_options.MediumAttackMinutes}m";
                return true;
            }

            var hard = arr.Count(t => t >= timeUtc.AddMinutes(-_options.HardLimitWindowMinutes));
            if (hard >= _options.HardLimitAttempts)
            {
                reason = $"{hard} failures/{_options.HardLimitWindowMinutes}m";
                return true;
            }

            return false;
        }
    }

    public void Forget(string ip) => _attempts.TryRemove(ip, out _);
}
