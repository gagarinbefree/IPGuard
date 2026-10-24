using System.Net;

namespace IPGuard.Windows.Network;

/// <summary>Contains the interface facts needed to select family probes, without framework inheritance in tests.</summary>
internal sealed class NetworkInterfaceState
{
    /// <summary>Captures operational status, loopback identity, and configured unicast addresses.</summary>
    internal NetworkInterfaceState(bool isUp, bool isLoopback, IReadOnlyList<IPAddress> addresses)
    {
        IsUp = isUp;
        IsLoopback = isLoopback;
        Addresses = addresses;
    }

    /// <summary>Gets whether Windows reports the interface as operationally up.</summary>
    internal bool IsUp { get; }

    /// <summary>Gets whether this interface is a local loopback device.</summary>
    internal bool IsLoopback { get; }

    /// <summary>Gets configured unicast addresses, which do not establish a public exit.</summary>
    internal IReadOnlyList<IPAddress> Addresses { get; }
}
