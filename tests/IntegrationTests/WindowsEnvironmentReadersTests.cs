using System.ComponentModel;
using IPGuard.Application.Network;
using IPGuard.Windows.Network;
using Xunit;

namespace IntegrationTests;

/// <summary>Exercises read-only native settings and RAS enumeration without requests, dialing, or configuration changes.</summary>
public sealed class WindowsEnvironmentReadersTests
{
    /// <summary>Actual WinHTTP configuration reads either succeed or explicitly report a missing current-user profile.</summary>
    [Fact]
    public void ProxyReaderReadsLocalConfiguration()
    {
        var reader = new WindowsProxySettingsReader();
        try
        {
            for (int index = 0; index < 3; index++)
            {
                ProxySettings result = reader.Read(TestContext.Current.CancellationToken);
                Assert.NotNull(result);
            }
        }
        catch (Win32Exception error) when (error.NativeErrorCode == 2 && error.Message == "Cannot read current-user proxy settings.")
        {
            // Missing user settings are documented API failure, not evidence that the machine uses no proxy.
            Assert.Equal(2, error.NativeErrorCode);
        }
    }

    /// <summary>Actual RAS enumeration preserves provider states without assuming there is a configured VPN.</summary>
    [Fact]
    public void RemoteAccessReaderReadsVisibleConnections()
    {
        var reader = new WindowsRemoteAccessReader();
        var first = reader.Read(TestContext.Current.CancellationToken);
        Assert.InRange(first.Count, 0, 1024);
        Assert.All(first, connection => Assert.True(Enum.IsDefined(connection.State)));
        var saved = first.Select(connection => (connection.CorrelationId, connection.StateCode, connection.SubstateCode)).ToArray();
        _ = reader.Read(TestContext.Current.CancellationToken);
        Assert.Equal(saved, first.Select(connection => (connection.CorrelationId, connection.StateCode, connection.SubstateCode)));
    }
}
