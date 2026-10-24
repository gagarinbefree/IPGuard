using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using IPGuard.Domain;

namespace IPGuard.Windows.Network;

/// <summary>Reads local configuration without promoting absent candidates to proven family unavailability.</summary>
internal static class WindowsNetworkFamilies
{
    /// <summary>Reads Windows interfaces only; no DNS, HTTPS, route changes, or filter writes occur.</summary>
    internal static NetworkFamilyState Read()
    {
        if (!OperatingSystem.IsWindows()) { throw new PlatformNotSupportedException("Windows network monitoring requires Windows."); }
        var interfaces = new List<NetworkInterfaceState>();
        foreach (var adapter in NetworkInterface.GetAllNetworkInterfaces())
        {
            var up = adapter.OperationalStatus == OperationalStatus.Up;
            var loopback = adapter.NetworkInterfaceType == NetworkInterfaceType.Loopback;
            IPAddress[] addresses = up && !loopback
                ? adapter.GetIPProperties().UnicastAddresses.Select(address => address.Address).ToArray()
                : [];
            interfaces.Add(new NetworkInterfaceState(up, loopback, addresses));
        }
        return Classify(interfaces);
    }

    /// <summary>Finds configured non-loopback family candidates; missing candidates remain unknown.</summary>
    internal static NetworkFamilyState Classify(IEnumerable<NetworkInterfaceState> interfaces)
    {
        var ipv4 = IpFamilyAvailability.Unknown;
        var ipv6 = IpFamilyAvailability.Unknown;
        foreach (var adapter in interfaces)
        {
            if (!adapter.IsUp || adapter.IsLoopback) { continue; }
            foreach (var address in adapter.Addresses)
            {
                if (IPAddress.IsLoopback(address) || address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any)
                    || address.IsIPv4MappedToIPv6) { continue; }
                if (address.AddressFamily == AddressFamily.InterNetwork) { ipv4 = IpFamilyAvailability.Available; }
                if (address.AddressFamily == AddressFamily.InterNetworkV6) { ipv6 = IpFamilyAvailability.Available; }
            }
        }
        return new NetworkFamilyState(ipv4, ipv6);
    }
}
