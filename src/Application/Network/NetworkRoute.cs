using System.Net;
using System.Net.Sockets;

namespace IPGuard.Application.Network;

/// <summary>Stores immutable local routing diagnostics without claiming that a route is usable or enforced.</summary>
public sealed class NetworkRoute
{
    /// <summary>Copies address text so mutable IPAddress instances cannot alter published diagnostics.</summary>
    public NetworkRoute(IPNetwork destination, IPAddress nextHop, string interfaceId, uint interfaceIndex,
        uint routeMetric, uint interfaceMetric, bool connected, bool defaultRoutesDisabled, uint validLifetimeSeconds, bool loopback)
    {
        ArgumentNullException.ThrowIfNull(nextHop);
        ArgumentException.ThrowIfNullOrWhiteSpace(interfaceId);
        Family = destination.BaseAddress.AddressFamily;
        if (Family is not (AddressFamily.InterNetwork or AddressFamily.InterNetworkV6)
            || nextHop.AddressFamily != Family || nextHop.IsIPv4MappedToIPv6 || destination.BaseAddress.IsIPv4MappedToIPv6)
        {
            throw new ArgumentException("Route destination and next hop must use the same IPv4 or IPv6 family.");
        }
        ArgumentOutOfRangeException.ThrowIfZero(interfaceIndex);
        Destination = destination.ToString();
        NextHop = nextHop.ToString();
        InterfaceId = interfaceId;
        InterfaceIndex = interfaceIndex;
        RouteMetric = routeMetric;
        InterfaceMetric = interfaceMetric;
        Connected = connected;
        DefaultRoutesDisabled = defaultRoutesDisabled;
        ValidLifetimeSeconds = validLifetimeSeconds;
        Loopback = loopback;
    }

    /// <summary>Gets the address family, independently of any public IP observation.</summary>
    public AddressFamily Family { get; }

    /// <summary>Gets the destination CIDR, including specific routes which a default-route-only view would miss.</summary>
    public string Destination { get; }

    /// <summary>Gets the next-hop address; zero denotes an on-link route and IPv6 scope is retained.</summary>
    public string NextHop { get; }

    /// <summary>Gets the adapter-supplied interface identity within this local diagnostic context.</summary>
    public string InterfaceId { get; }

    /// <summary>Gets the current interface index, which is not a persistent installation identifier.</summary>
    public uint InterfaceIndex { get; }

    /// <summary>Gets the route metric offset; uint.MaxValue means the metric is not used.</summary>
    public uint RouteMetric { get; }

    /// <summary>Gets the separately read interface metric.</summary>
    public uint InterfaceMetric { get; }

    /// <summary>Gets an overflow-safe metric sum, or null for an unspecified component; this does not select a route.</summary>
    public ulong? TotalMetric => RouteMetric == uint.MaxValue || InterfaceMetric == uint.MaxValue
        ? null : (ulong)RouteMetric + InterfaceMetric;

    /// <summary>Gets the reported interface connection flag, without asserting Internet reachability.</summary>
    public bool Connected { get; }

    /// <summary>Gets whether use of default routes is disabled on this interface.</summary>
    public bool DefaultRoutesDisabled { get; }

    /// <summary>Gets remaining route validity at read time, in seconds; uint.MaxValue denotes infinite validity.</summary>
    public uint ValidLifetimeSeconds { get; }

    /// <summary>Gets whether Windows marked this route as a local loopback route.</summary>
    public bool Loopback { get; }
}
