using Microsoft.Extensions.Options;
using RdpGuard.Options;
using System.Reflection;
using System.Text;

namespace RdpGuard.Services;

public sealed class FileLogger
{
    private readonly object _sync = new();
    private readonly string _logFile;
    private readonly string _logDirectory;
    private readonly long _maxLogFileBytes;
    private readonly int _retentionDays;
    private static readonly byte[] Utf8Bom = new byte[] { 0xEF, 0xBB, 0xBF };

    public FileLogger(IOptions<RdpGuardOptions> options)
    {
        var cfg = options.Value;
        _logDirectory = Environment.ExpandEnvironmentVariables(cfg.BaseDirectory);
        Directory.CreateDirectory(_logDirectory);
        _logFile = Path.Combine(_logDirectory, "rdpguard.log");
        _maxLogFileBytes = Math.Max(1, cfg.MaxLogFileSizeMb) * 1024L * 1024L;
        _retentionDays = Math.Max(1, cfg.LogRetentionDays);
        EnsureUtf8Bom();
        CleanupOldLogs();

        // Visually separate each process/service start in the log.
        BlankLine();
        var assembly = Assembly.GetEntryAssembly() ?? Assembly.GetExecutingAssembly();
        var version = assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
            ?? assembly.GetName().Version?.ToString()
            ?? "unknown";
        var commit = assembly.GetCustomAttributes<AssemblyMetadataAttribute>()
            .FirstOrDefault(x => string.Equals(x.Key, "CommitHash", StringComparison.OrdinalIgnoreCase))?.Value
            ?? "unknown";
        if (commit.Length > 7) commit = commit[..7];
        Info($"Version={version}");
        Info($"Commit={commit}");
    }

    public string LogFilePath => _logFile;

    public void Info(string message) => Write("INFO", message);
    public void Warn(string message) => Write("WARN", message);
    public void Error(string message) => Write("ERROR", message);
    public void Debug(string message) => Write("DEBUG", message);
    public void BlankLine() => WriteRaw(Environment.NewLine);

    private void EnsureUtf8Bom()
    {
        lock (_sync)
        {
            if (!File.Exists(_logFile))
            {
                File.WriteAllBytes(_logFile, Utf8Bom);
                return;
            }

            using var read = new FileStream(_logFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            if (read.Length >= 3)
            {
                Span<byte> prefix = stackalloc byte[3];
                _ = read.Read(prefix);
                if (prefix[0] == 0xEF && prefix[1] == 0xBB && prefix[2] == 0xBF)
                    return;
            }

            var bytes = File.ReadAllBytes(_logFile);
            using var stream = new FileStream(_logFile, FileMode.Create, FileAccess.Write, FileShare.Read);
            stream.Write(Utf8Bom, 0, Utf8Bom.Length);
            stream.Write(bytes, 0, bytes.Length);
        }
    }

    private void Write(string level, string message)
    {
        WriteRaw($"{DateTime.Now:yyyy-MM-dd HH:mm:ss} | {level} | {message}{Environment.NewLine}");
    }

    private void WriteRaw(string text)
    {
        var bytes = new UTF8Encoding(false).GetBytes(text);
        lock (_sync)
        {
            RotateIfNeeded(bytes.Length);
            using var stream = new FileStream(_logFile, FileMode.Append, FileAccess.Write, FileShare.ReadWrite);
            stream.Write(bytes, 0, bytes.Length);
        }
    }

    private void RotateIfNeeded(int nextWriteBytes)
    {
        try
        {
            var currentLength = File.Exists(_logFile) ? new FileInfo(_logFile).Length : 0;
            if (currentLength + nextWriteBytes <= _maxLogFileBytes)
                return;

            var stamp = DateTime.Now.ToString("yyyyMMdd-HHmmss");
            var rotated = Path.Combine(_logDirectory, $"rdpguard-{stamp}.log");
            var suffix = 1;
            while (File.Exists(rotated))
            {
                rotated = Path.Combine(_logDirectory, $"rdpguard-{stamp}-{suffix++}.log");
            }

            if (File.Exists(_logFile))
                File.Move(_logFile, rotated);

            File.WriteAllBytes(_logFile, Utf8Bom);
            CleanupOldLogs();
        }
        catch
        {
            // Logging must never crash the service. If rotation fails,
            // continue appending to the active log file.
        }
    }

    private void CleanupOldLogs()
    {
        try
        {
            var cutoff = DateTime.Now.AddDays(-_retentionDays);
            foreach (var file in Directory.EnumerateFiles(_logDirectory, "rdpguard-*.log"))
            {
                try
                {
                    if (File.GetLastWriteTime(file) < cutoff)
                        File.Delete(file);
                }
                catch
                {
                    // Retention cleanup is best-effort only.
                }
            }
        }
        catch
        {
            // Never fail service startup because old logs cannot be enumerated.
        }
    }
}
