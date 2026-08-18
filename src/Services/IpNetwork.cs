using System.Net;
using System.Net.Sockets;

namespace RdpGuard.Services;

public sealed class IpNetwork
{
    private readonly IPAddress _network;
    private readonly int _prefixLength;

    private IpNetwork(IPAddress network, int prefixLength)
    {
        _network = network;
        _prefixLength = prefixLength;
    }

    public static bool TryParse(string value, out IpNetwork? network)
    {
        network = null;
        if (string.IsNullOrWhiteSpace(value)) return false;
        var parts = value.Split('/', 2);
        if (!IPAddress.TryParse(parts[0], out var ip)) return false;
        var max = ip.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
        var prefix = max;
        if (parts.Length == 2 && (!int.TryParse(parts[1], out prefix) || prefix < 0 || prefix > max)) return false;
        network = new IpNetwork(ip, prefix);
        return true;
    }

    public bool Contains(IPAddress candidate)
    {
        if (candidate.AddressFamily != _network.AddressFamily) return false;
        var a = _network.GetAddressBytes();
        var b = candidate.GetAddressBytes();
        var fullBytes = _prefixLength / 8;
        var remainingBits = _prefixLength % 8;
        for (var i = 0; i < fullBytes; i++) if (a[i] != b[i]) return false;
        if (remainingBits == 0) return true;
        var mask = (byte)(0xFF << (8 - remainingBits));
        return (a[fullBytes] & mask) == (b[fullBytes] & mask);
    }
}
