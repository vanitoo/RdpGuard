namespace RdpGuard.Models;

public sealed class BlockedEntry
{
    public string Ip { get; set; } = string.Empty;
    public DateTime BlockedAtUtc { get; set; }

    public string Status { get; set; } = string.Empty; // Pending | Applied
    public DateTime? LastAttemptUtc { get; set; }
    public string? LastError { get; set; }
}
