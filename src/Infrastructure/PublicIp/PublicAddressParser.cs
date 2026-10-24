using System.Net;
using System.Net.Sockets;
using System.Text;

namespace IPGuard.Infrastructure.PublicIp;

/// <summary>Accepts a bounded ASCII address using a conservative reviewed public-unicast range snapshot.</summary>
internal static class PublicAddressParser
{
    /// <summary>Limits the complete plaintext response, including surrounding ASCII whitespace.</summary>
    internal const int MaximumBodyBytes = 128;

    // Reviewed against IANA on 2026-10-24. Special-purpose anycast is intentionally rejected too.
    private static readonly IPNetwork[] Ipv4Excluded = Networks(
        "0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 " +
        "192.0.0.0/24 192.0.2.0/24 192.31.196.0/24 192.52.193.0/24 192.88.99.0/24 " +
        "192.168.0.0/16 192.175.48.0/24 198.18.0.0/15 198.51.100.0/24 203.0.113.0/24 224.0.0.0/4 240.0.0.0/4");

    // An allowlist avoids treating reserved portions of 2000::/3 as allocated global unicast.
    private static readonly IPNetwork[] Ipv6Allocated = Networks(
        "2001:200::/23 2001:400::/23 2001:600::/23 2001:800::/22 2001:c00::/23 2001:e00::/23 " +
        "2001:1200::/23 2001:1400::/22 2001:1800::/23 2001:1a00::/23 2001:1c00::/22 2001:2000::/19 " +
        "2001:4000::/23 2001:4200::/23 2001:4400::/23 2001:4600::/23 2001:4800::/23 2001:4a00::/23 " +
        "2001:4c00::/23 2001:5000::/20 2001:8000::/19 2001:a000::/20 2001:b000::/20 2003::/18 " +
        "2400::/12 2410::/12 2600::/12 2610::/23 2620::/23 2630::/12 2800::/12 2a00::/12 2a10::/12 2c00::/12");

    private static readonly IPNetwork[] Ipv6Excluded = Networks("2001:db8::/32 2620:4f:8000::/48");

    /// <summary>Rejects malformed, scoped, mapped, special-purpose, and unsupported-family addresses.</summary>
    internal static IPAddress? Parse(ReadOnlySpan<byte> body, AddressFamily family)
    {
        if (body.Length is 0 or > MaximumBodyBytes || family is not (AddressFamily.InterNetwork or AddressFamily.InterNetworkV6))
        {
            return null;
        }

        foreach (byte value in body)
        {
            if (value > 127)
            {
                return null;
            }
        }

        string text = Encoding.ASCII.GetString(body).Trim(' ', '\t', '\r', '\n');
        if (text.IndexOfAny(['%', '[', ']']) >= 0 || !IPAddress.TryParse(text, out IPAddress? address)
            || address.AddressFamily != family || address.IsIPv4MappedToIPv6)
        {
            return null;
        }

        if (family == AddressFamily.InterNetwork)
        {
            string[] parts = text.Split('.');
            if (parts.Length != 4 || parts.Any(part => part.Length == 0 || !part.All(char.IsAsciiDigit)
                || (part.Length > 1 && part[0] == '0')))
            {
                return null;
            }

            return Ipv4Excluded.Any(network => network.Contains(address)) ? null : address;
        }

        return address.ScopeId == 0 && Ipv6Allocated.Any(network => network.Contains(address))
            && !Ipv6Excluded.Any(network => network.Contains(address)) ? address : null;
    }

    /// <summary>Parses a reviewed space-separated range snapshot once, without runtime registry downloads.</summary>
    private static IPNetwork[] Networks(string ranges) => ranges.Split(' ').Select(IPNetwork.Parse).ToArray();
}
