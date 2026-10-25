using System.Runtime.InteropServices;

namespace IPGuard.Windows.Network.Native;

/// <summary>Matches the current-user WinHTTP configuration with a four-byte BOOL and three owned string pointers.</summary>
[StructLayout(LayoutKind.Sequential)]
internal struct NativeUserProxy
{
    public int AutoDetect;
    public nint AutoConfigUrl;
    public nint Proxy;
    public nint Bypass;
}

/// <summary>Matches the legacy default WinHTTP configuration and its two owned strings.</summary>
[StructLayout(LayoutKind.Sequential)]
internal struct NativeDefaultProxy
{
    public uint AccessType;
    public nint Proxy;
    public nint Bypass;
}
