using System.Runtime.InteropServices;

namespace IPGuard.Windows.Network.Native;

/// <summary>Registers both IP families through Windows IP Helper without reading callback row memory.</summary>
internal sealed class NativeNetworkChangeApi : INetworkChangeApi
{
    /// <summary>Rejects other operating systems before loading Windows libraries.</summary>
    internal NativeNetworkChangeApi()
    {
        if (!OperatingSystem.IsWindows()) { throw new PlatformNotSupportedException("Windows network notifications require Windows."); }
    }

    /// <summary>Requests real changes only, using AF_UNSPEC and a one-byte false BOOLEAN.</summary>
    public uint Register(NetworkChangeKind kind, NativeNetworkChanged callback, out nint handle) => kind switch
    {
        NetworkChangeKind.Route => NotifyRouteChange2(0, callback, 0, 0, out handle),
        NetworkChangeKind.Interface => NotifyIpInterfaceChange(0, callback, 0, 0, out handle),
        NetworkChangeKind.Address => NotifyUnicastIpAddressChange(0, callback, 0, 0, out handle),
        _ => throw new ArgumentOutOfRangeException(nameof(kind))
    };

    /// <summary>Waits for outstanding native callbacks and unregisters one notification handle.</summary>
    public uint Cancel(nint handle) => CancelMibChangeNotify2(handle);

    /// <summary>Registers route changes; ADDRESS_FAMILY is a USHORT and BOOLEAN is one byte.</summary>
    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern uint NotifyRouteChange2(ushort family, NativeNetworkChanged callback, nint context, byte initial, out nint handle);

    /// <summary>Registers IPv4 and IPv6 IP interface changes.</summary>
    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern uint NotifyIpInterfaceChange(ushort family, NativeNetworkChanged callback, nint context, byte initial, out nint handle);

    /// <summary>Registers local unicast address changes.</summary>
    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern uint NotifyUnicastIpAddressChange(ushort family, NativeNetworkChanged callback, nint context, byte initial, out nint handle);

    /// <summary>Unregisters a notification outside its callback context.</summary>
    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern uint CancelMibChangeNotify2(nint handle);
}
