using Microsoft.Extensions.Options;
using RdpGuard.Options;
using System.Text;

namespace RdpGuard.Services;

public sealed class FileLogger
{
    private readonly object _sync = new();
    private readonly string _logFile;
    private static readonly byte[] Utf8Bom = new byte[] { 0xEF, 0xBB, 0xBF };

    public FileLogger(IOptions<RdpGuardOptions> options)
    {
        var dir = Environment.ExpandEnvironmentVariables(options.Value.BaseDirectory);
        Directory.CreateDirectory(dir);
        _logFile = Path.Combine(dir, "rdpguard.log");
        EnsureUtf8Bom();
    }

    public string LogFilePath => _logFile;

    public void Info(string message) => Write("INFO", message);
    public void Warn(string message) => Write("WARN", message);
    public void Error(string message) => Write("ERROR", message);
    public void Debug(string message) => Write("DEBUG", message);

    private void EnsureUtf8Bom()
    {
        lock (_sync)
        {
            if (!File.Exists(_logFile))
            {
                File.WriteAllBytes(_logFile, Utf8Bom);
                return;
            }

            var bytes = File.ReadAllBytes(_logFile);
            if (bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF)
                return;

            // Existing versions wrote valid UTF-8 without BOM. Prefixing BOM makes
            // Windows PowerShell 5.1 Get-Content detect the encoding correctly.
            using var stream = new FileStream(_logFile, FileMode.Create, FileAccess.Write, FileShare.Read);
            stream.Write(Utf8Bom, 0, Utf8Bom.Length);
            stream.Write(bytes, 0, bytes.Length);
        }
    }

    private void Write(string level, string message)
    {
        var line = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} | {level} | {message}";
        var bytes = new UTF8Encoding(false).GetBytes(line + Environment.NewLine);

        lock (_sync)
        {
            using var stream = new FileStream(_logFile, FileMode.Append, FileAccess.Write, FileShare.ReadWrite);
            stream.Write(bytes, 0, bytes.Length);
        }
    }
}
