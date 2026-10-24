using IPGuard.Domain;

namespace IPGuard.Windows.Network;

/// <summary>Holds conservative family candidates read from local interface configuration.</summary>
internal sealed class NetworkFamilyState
{
    /// <summary>Creates immutable input for one monitor read.</summary>
    internal NetworkFamilyState(IpFamilyAvailability ipv4, IpFamilyAvailability ipv6)
    {
        Ipv4 = ipv4;
        Ipv6 = ipv6;
    }

    /// <summary>Gets IPv4 configuration, without asserting Internet reachability.</summary>
    internal IpFamilyAvailability Ipv4 { get; }

    /// <summary>Gets IPv6 configuration, without asserting Internet reachability.</summary>
    internal IpFamilyAvailability Ipv6 { get; }
}
