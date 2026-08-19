namespace RdpGuard.Options;

public sealed class RdpGuardOptions
{
    public bool DryRun { get; set; } = true;
    public bool LogEveryFailure { get; set; } = false;
    public bool AcceptNlaLogonType3 { get; set; } = true;
    public bool RequireRdpCorrelationForNla { get; set; } = true;
    public bool LogRdpCorrelationEvents { get; set; } = false;
    public int RdpCorrelationWindowSeconds { get; set; } = 15;
    public int NlaCorrelationDelayMilliseconds { get; set; } = 2000;
    public int HeartbeatSeconds { get; set; } = 600;
    public bool Log24HourStatistics { get; set; } = true;
    public int MaxLogFileSizeMb { get; set; } = 25;
    public int LogRetentionDays { get; set; } = 14;
    public int RdpLocalPort { get; set; } = 13389;
    public int FastAttackAttempts { get; set; } = 3;
    public int FastAttackSeconds { get; set; } = 30;
    public int MediumAttackAttempts { get; set; } = 5;
    public int MediumAttackMinutes { get; set; } = 5;
    public int HardLimitAttempts { get; set; } = 10;
    public int HardLimitWindowMinutes { get; set; } = 10;
    public int UnblockAfterDays { get; set; } = 3;
    public int CleanupIntervalSeconds { get; set; } = 60;
    public int FirewallRetryIntervalSeconds { get; set; } = 60;
    public string BaseDirectory { get; set; } = @"C:\ProgramData\RdpGuard";
    public string FirewallRuleName { get; set; } = "RdpGuard_Block_RDP";
    public List<string> TrustedNetworks { get; set; } = new()
    {
        "127.0.0.1/32",
        "::1/128",
        "10.0.0.0/8",
        "192.168.0.0/16"
    };
}
