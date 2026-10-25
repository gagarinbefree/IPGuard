using System.Runtime.InteropServices;
using IPGuard.Windows.Network.Native;
using Xunit;

namespace UnitTests;

/// <summary>Protects Windows x64 layout values independently verified by a native Windows SDK probe.</summary>
public sealed class EnvironmentNativeLayoutTests
{
    /// <summary>RAS uses four-byte packing even for handles; WinHTTP uses pointer alignment after a four-byte BOOL.</summary>
    [Fact]
    public void LayoutsMatchWindowsSdk()
    {
        Assert.Equal(32, Marshal.SizeOf<NativeUserProxy>());
        Assert.Equal(24, Marshal.SizeOf<NativeDefaultProxy>());
        Assert.Equal(8, Marshal.OffsetOf<NativeUserProxy>(nameof(NativeUserProxy.AutoConfigUrl)).ToInt32());
        Assert.Equal(1388, Marshal.SizeOf<NativeRemoteConnection>());
        Assert.Equal(4, Marshal.OffsetOf<NativeRemoteConnection>(nameof(NativeRemoteConnection.Handle)).ToInt32());
        Assert.Equal(1372, Marshal.OffsetOf<NativeRemoteConnection>(nameof(NativeRemoteConnection.CorrelationId)).ToInt32());
        Assert.Equal(608, Marshal.SizeOf<NativeRemoteStatus>());
        Assert.Equal(604, Marshal.OffsetOf<NativeRemoteStatus>(nameof(NativeRemoteStatus.Substate)).ToInt32());
    }
}
