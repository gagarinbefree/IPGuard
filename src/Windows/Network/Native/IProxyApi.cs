namespace IPGuard.Windows.Network.Native;

/// <summary>Separates read-only WinHTTP configuration and GlobalFree ownership from deterministic tests.</summary>
internal interface IProxyApi
{
    /// <summary>Returns zero on success, otherwise the captured Win32 error, preserving any returned allocations.</summary>
    uint ReadUser(out NativeUserProxy settings);

    /// <summary>Reads registry defaults, not the configuration of an existing WinHTTP session.</summary>
    uint ReadDefault(out NativeDefaultProxy settings);

    /// <summary>Releases one owned string, returning zero on success or a captured Win32 failure.</summary>
    uint Free(nint memory);
}
