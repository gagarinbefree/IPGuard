using System.Runtime.InteropServices;

namespace IPGuard.Windows.Network.Native;

/// <summary>Reads WinHTTP configuration and releases its strings through their documented allocator.</summary>
internal sealed class NativeProxyApi : IProxyApi
{
    /// <summary>Restricts native layouts to the supported Windows x64 target.</summary>
    internal NativeProxyApi()
    {
        if (!OperatingSystem.IsWindows() || RuntimeInformation.ProcessArchitecture != Architecture.X64)
        {
            throw new PlatformNotSupportedException("Windows proxy diagnostics require Windows x64.");
        }
    }

    /// <summary>Captures the error before any other native call can overwrite it.</summary>
    public uint ReadUser(out NativeUserProxy settings) => WinHttpGetIEProxyConfigForCurrentUser(out settings) ? 0 : LastError();

    /// <summary>Reads legacy registry defaults without opening a WinHTTP session.</summary>
    public uint ReadDefault(out NativeDefaultProxy settings) => WinHttpGetDefaultProxyConfiguration(out settings) ? 0 : LastError();

    /// <summary>Checks GlobalFree's return value instead of assuming cleanup succeeded.</summary>
    public uint Free(nint memory) => GlobalFree(memory) == 0 ? 0 : LastError();

    /// <summary>Preserves the captured error, using ERROR_GEN_FAILURE when a failed API supplied none.</summary>
    private static uint LastError()
    {
        uint error = unchecked((uint)Marshal.GetLastPInvokeError());
        return error == 0 ? 31u : error;
    }

    /// <summary>Retrieves the current user's active-connection proxy configuration.</summary>
    [DllImport("winhttp.dll", ExactSpelling = true, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WinHttpGetIEProxyConfigForCurrentUser(out NativeUserProxy settings);

    /// <summary>Retrieves legacy WinHTTP registry defaults, independently of per-session overrides.</summary>
    [DllImport("winhttp.dll", ExactSpelling = true, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WinHttpGetDefaultProxyConfiguration(out NativeDefaultProxy settings);

    /// <summary>Releases one string allocated by a WinHTTP configuration read.</summary>
    [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern nint GlobalFree(nint memory);
}
