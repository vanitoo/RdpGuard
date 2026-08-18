using System.Diagnostics;
using System.ServiceProcess;
using Microsoft.Extensions.Options;
using RdpGuard.Options;

namespace RdpGuard.Services;

public sealed class FirewallManager
{
    private readonly RdpGuardOptions _options;
    private readonly FileLogger _log;
    private readonly object _sync = new();

    public FirewallManager(IOptions<RdpGuardOptions> options, FileLogger log)
    {
        _options = options.Value;
        _log = log;
    }

    public bool TryEnsureRule(IEnumerable<string> blockedIps, out string detail)
    {
        lock (_sync)
        {
            if (_options.DryRun)
            {
                detail = "DryRun=True";
                return true;
            }

            if (!TryCheckFirewallService(out detail)) return false;

            var ips = blockedIps.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            if (ips.Length == 0)
            {
                return TryDeleteRuleIfExists(out detail);
            }

            return TryApplyRule(ips, out detail);
        }
    }

    public bool TryBlock(string ip, IEnumerable<string> desiredBlockedIps, out string detail)
    {
        if (_options.DryRun)
        {
            _log.Warn($"DRY-RUN BLOCK | {ip}");
            detail = "DryRun=True";
            return true;
        }

        lock (_sync)
        {
            if (!TryCheckFirewallService(out detail)) return false;
            if (!TryApplyRule(desiredBlockedIps.Distinct(StringComparer.OrdinalIgnoreCase).ToArray(), out detail)) return false;
        }

        _log.Warn($"BLOCK | {ip}");
        return true;
    }

    public bool TryUnblock(string ip, IEnumerable<string> remainingIps, out string detail)
    {
        if (_options.DryRun)
        {
            _log.Info($"DRY-RUN UNBLOCK | {ip}");
            detail = "DryRun=True";
            return true;
        }

        lock (_sync)
        {
            if (!TryCheckFirewallService(out detail)) return false;
            var ips = remainingIps.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            var ok = ips.Length == 0 ? TryDeleteRuleIfExists(out detail) : TryApplyRule(ips, out detail);
            if (!ok) return false;
        }

        _log.Info($"UNBLOCK | {ip}");
        return true;
    }

    public bool TryCheckFirewallService(out string detail)
    {
        try
        {
            using var service = new ServiceController("MpsSvc");
            service.Refresh();
            if (service.Status != ServiceControllerStatus.Running)
            {
                detail = $"Windows Firewall service MpsSvc is not running | Status={service.Status}";
                return false;
            }

            detail = "MpsSvc=Running";
            return true;
        }
        catch (Exception ex)
        {
            detail = $"Cannot query Windows Firewall service MpsSvc: {ex.GetType().Name}: {ex.Message}";
            return false;
        }
    }

    private bool TryApplyRule(string[] ips, out string detail)
    {
        if (ips.Length == 0)
        {
            detail = "No IPs to apply";
            return true;
        }

        try
        {
            var remoteIp = string.Join(',', ips);
            var args = $"advfirewall firewall set rule name=\"{_options.FirewallRuleName}\" new remoteip={remoteIp}";
            var result = RunNetsh(args);

            if (result.ExitCode != 0 || result.Output.Contains("No rules match", StringComparison.OrdinalIgnoreCase))
            {
                args = $"advfirewall firewall add rule name=\"{_options.FirewallRuleName}\" dir=in action=block protocol=TCP localport={_options.RdpLocalPort} remoteip={remoteIp} enable=yes profile=any";
                result = RunNetsh(args);
            }

            if (result.ExitCode != 0)
            {
                detail = $"netsh failed | ExitCode={result.ExitCode} | Output={Sanitize(result.Output)}";
                return false;
            }

            detail = $"Firewall rule applied | Rule={_options.FirewallRuleName} | IPs={ips.Length}";
            return true;
        }
        catch (Exception ex)
        {
            detail = $"Firewall apply exception | {ex.GetType().Name}: {ex.Message}";
            return false;
        }
    }

    private bool TryDeleteRuleIfExists(out string detail)
    {
        try
        {
            var result = RunNetsh($"advfirewall firewall delete rule name=\"{_options.FirewallRuleName}\"");
            // Deleting a non-existent rule is harmless for our state reconciliation.
            detail = result.ExitCode == 0
                ? $"Firewall rule deleted | Rule={_options.FirewallRuleName}"
                : $"Firewall delete returned ExitCode={result.ExitCode} | Output={Sanitize(result.Output)}";
            return true;
        }
        catch (Exception ex)
        {
            detail = $"Firewall delete exception | {ex.GetType().Name}: {ex.Message}";
            return false;
        }
    }

    private static (int ExitCode, string Output) RunNetsh(string arguments)
    {
        var psi = new ProcessStartInfo
        {
            FileName = Path.Combine(Environment.SystemDirectory, "netsh.exe"),
            Arguments = arguments,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };

        using var p = Process.Start(psi) ?? throw new InvalidOperationException("Cannot start netsh.exe");
        var stdout = p.StandardOutput.ReadToEnd();
        var stderr = p.StandardError.ReadToEnd();
        p.WaitForExit();
        return (p.ExitCode, (stdout + Environment.NewLine + stderr).Trim());
    }

    private static string Sanitize(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return "-";
        return value.Replace("\r", " ").Replace("\n", " ").Trim();
    }
}
