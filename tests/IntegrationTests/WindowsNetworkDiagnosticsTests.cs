using System.ComponentModel;
using IPGuard.Application.Network;
using IPGuard.Windows.Network;
using Xunit;

namespace IntegrationTests;

/// <summary>Composes local Windows readers and cached notifications without modifying the machine or contacting HTTPS services.</summary>
public sealed class WindowsNetworkDiagnosticsTests
{
    /// <summary>Collects generation-bound diagnostics or reports the documented missing-user-profile outcome without fabricating settings.</summary>
    [Fact]
    public async Task CollectReadsOnlyLocalWindowsState()
    {
        using var network = new WindowsNetworkMonitor();
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(10));
        while (network.Capture() is null && network.LastError is null) await Task.Delay(1, timeout.Token);
        Assert.Null(network.LastError);
        var collector = new NetworkDiagnosticsCollector(new WindowsRoutingTableReader(), new WindowsProxySettingsReader(),
            new WindowsRemoteAccessReader(), network, TimeSpan.FromSeconds(30));
        var result = await Task.Run(() => collector.Collect(timeout.Token), timeout.Token);
        if (result.Status == NetworkDiagnosticsStatus.Failed && result.Error is Win32Exception { NativeErrorCode: 2 } missing)
        {
            Assert.Equal("Cannot read current-user proxy settings.", missing.Message);
            Assert.Null(result.Snapshot);
            return;
        }
        Assert.Equal(NetworkDiagnosticsStatus.Completed, result.Status);
        var snapshot = Assert.IsType<NetworkDiagnosticsSnapshot>(result.Snapshot);
        Assert.Null(result.Error);
        Assert.NotEqual(Guid.Empty, snapshot.Network.Version);
        Assert.True(snapshot.Network.Invalidated.CanBeCanceled);
        Assert.True(snapshot.StartedAt <= snapshot.CompletedAt);
        Assert.NotNull(snapshot.Proxy);
        Assert.All(snapshot.Connections, connection => Assert.True(Enum.IsDefined(connection.State)));
    }
}
