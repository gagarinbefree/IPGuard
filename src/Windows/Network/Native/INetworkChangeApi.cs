using System.Runtime.InteropServices;

namespace IPGuard.Windows.Network.Native;

/// <summary>Identifies the three independent Windows notification registrations.</summary>
internal enum NetworkChangeKind
{
    /// <summary>Tracks route-only changes, including metric and next-hop updates.</summary>
    Route,
    /// <summary>Tracks IP interface changes, including operational changes.</summary>
    Interface,
    /// <summary>Tracks changes to local unicast IPv4 and IPv6 addresses.</summary>
    Address
}

/// <summary>Matches all three Windows callback ABIs; borrowed row pointers are never dereferenced or retained.</summary>
[UnmanagedFunctionPointer(CallingConvention.Winapi)]
internal delegate void NativeNetworkChanged(nint context, nint row, uint notificationType);

/// <summary>Separates read-only native registration and cleanup from subscription lifetime tests.</summary>
internal interface INetworkChangeApi
{
    /// <summary>Registers both families without requesting a synthetic initial notification.</summary>
    uint Register(NetworkChangeKind kind, NativeNetworkChanged callback, out nint handle);

    /// <summary>Unregisters a handle on a thread outside its callback, waiting for outstanding native callbacks.</summary>
    uint Cancel(nint handle);
}
