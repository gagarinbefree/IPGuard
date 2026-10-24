using System.Runtime.InteropServices;

namespace IPGuard.Windows.Network.Native;

/// <summary>Calls only read and release functions from Windows IP Helper.</summary>
internal sealed class NativeRoutingApi : IRoutingApi
{
    /// <summary>Restricts this verified native layout to the current Windows x64 target.</summary>
    internal NativeRoutingApi()
    {
        if (!OperatingSystem.IsWindows() || RuntimeInformation.ProcessArchitecture != Architecture.X64)
        {
            throw new PlatformNotSupportedException("Windows route diagnostics currently support Windows x64 only.");
        }
    }

    /// <summary>Retrieves both IPv4 and IPv6 route rows without changing the thread's network context.</summary>
    public uint ReadTable(out nint table) => GetIpForwardTable2(0, out table);

    /// <summary>Retrieves metadata for the requested interface and IP family.</summary>
    public uint ReadInterface(ref NativeRouteInterface row) => GetIpInterfaceEntry(ref row);

    /// <summary>Releases one complete IP Helper allocation.</summary>
    public void FreeTable(nint table) => FreeMibTable(table);

    /// <summary>Allocates an SDK-aligned table for the selected address family.</summary>
    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern uint GetIpForwardTable2(ushort family, out nint table);

    /// <summary>Fills the entire native interface row without changing its configuration.</summary>
    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern uint GetIpInterfaceEntry(ref NativeRouteInterface row);

    /// <summary>Frees a native table buffer, including all inline rows.</summary>
    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern void FreeMibTable(nint table);
}
