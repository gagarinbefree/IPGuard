using System.Runtime.InteropServices;

namespace IPGuard.Windows.Network.Native;

/// <summary>Calls RAS enumeration and status APIs without exposing dial, hang-up, or handle-close operations.</summary>
internal sealed class NativeRemoteAccessApi : IRemoteAccessApi
{
    /// <summary>Restricts verified native layouts to Windows x64.</summary>
    internal NativeRemoteAccessApi()
    {
        if (!OperatingSystem.IsWindows() || RuntimeInformation.ProcessArchitecture != Architecture.X64)
        {
            throw new PlatformNotSupportedException("Windows remote-access diagnostics require Windows x64.");
        }
    }

    /// <summary>Enumerates into caller-owned UTF-16 RASCONNW buffers.</summary>
    public uint Enumerate(nint buffer, ref uint bytes, out uint count) => RasEnumConnectionsW(buffer, ref bytes, out count);

    /// <summary>Reads status without taking ownership of the RAS connection.</summary>
    public uint ReadStatus(nint connection, ref NativeRemoteStatus status) => RasGetConnectStatusW(connection, ref status);

    /// <summary>Retrieves visible RAS connections using the version selected by the first row's dwSize.</summary>
    [DllImport("rasapi32.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern uint RasEnumConnectionsW(nint buffer, ref uint bytes, out uint count);

    /// <summary>Fills the complete RASCONNSTATUSW buffer for a borrowed connection handle.</summary>
    [DllImport("rasapi32.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern uint RasGetConnectStatusW(nint connection, ref NativeRemoteStatus status);
}
