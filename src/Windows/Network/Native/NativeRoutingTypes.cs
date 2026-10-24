using System.Runtime.InteropServices;

namespace IPGuard.Windows.Network.Native;

/// <summary>Matches the 28-byte, four-byte-aligned SOCKADDR_INET union from the Windows SDK.</summary>
[StructLayout(LayoutKind.Explicit, Size = 28, Pack = 4)]
internal struct NativeRouteAddress
{
    [FieldOffset(0)] public ushort Family;
    [FieldOffset(4)] public uint Ipv4;
    [FieldOffset(8)] public ulong Ipv6First;
    [FieldOffset(16)] public ulong Ipv6Second;
    [FieldOffset(24)] public uint ScopeId;
}

/// <summary>Preserves the complete 104-byte MIB_IPFORWARD_ROW2 stride while exposing diagnostic fields.</summary>
[StructLayout(LayoutKind.Explicit, Size = 104, Pack = 8)]
internal struct NativeRouteRow
{
    [FieldOffset(0)] public ulong InterfaceLuid;
    [FieldOffset(8)] public uint InterfaceIndex;
    [FieldOffset(12)] public NativeRouteAddress Prefix;
    [FieldOffset(40)] public byte PrefixLength;
    [FieldOffset(44)] public NativeRouteAddress NextHop;
    [FieldOffset(76)] public uint ValidLifetime;
    [FieldOffset(84)] public uint Metric;
    [FieldOffset(92)] public byte Loopback;
}

/// <summary>Preserves the alignment gap between the count and the first route row.</summary>
[StructLayout(LayoutKind.Sequential, Pack = 8)]
internal struct NativeRouteTable
{
    public uint Count;
    public NativeRouteRow FirstRow;
}

/// <summary>Reserves the full 168-byte output buffer for GetIpInterfaceEntry, including unexposed fields.</summary>
[StructLayout(LayoutKind.Explicit, Size = 168, Pack = 8)]
internal struct NativeRouteInterface
{
    [FieldOffset(0)] public ushort Family;
    [FieldOffset(8)] public ulong InterfaceLuid;
    [FieldOffset(16)] public uint InterfaceIndex;
    [FieldOffset(148)] public uint Metric;
    [FieldOffset(156)] public byte Connected;
    [FieldOffset(166)] public byte DisableDefaultRoutes;
}
