using System.Net.Sockets;
using IPGuard.Application.PublicIp;

namespace IPGuard.Infrastructure.PublicIp;

/// <summary>Provides independent operator defaults without making any requests during initialization.</summary>
public static class PublicIpSources
{
    /// <summary>Gets two configured operators per family; operator aliases must share the same identity.</summary>
    public static IReadOnlyList<PublicIpSource> Defaults { get; } = Array.AsReadOnly<PublicIpSource>(
    [
        new("ipify", new Uri("https://api.ipify.org/"), AddressFamily.InterNetwork),
        new("ident.me", new Uri("https://4.ident.me/"), AddressFamily.InterNetwork),
        new("ipify", new Uri("https://api6.ipify.org/"), AddressFamily.InterNetworkV6),
        new("ident.me", new Uri("https://6.ident.me/"), AddressFamily.InterNetworkV6)
    ]);
}
