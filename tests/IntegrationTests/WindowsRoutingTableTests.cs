using System.Net;
using IPGuard.Application.Network;
using IPGuard.Windows.Network;
using Xunit;

namespace IntegrationTests;

/// <summary>Exercises actual read-only routing APIs without changing routes, interfaces, VPNs, or filters.</summary>
public sealed class WindowsRoutingTableTests
{
    /// <summary>Actual Windows route and interface buffers decode into privately owned, canonical diagnostics.</summary>
    [Fact]
    public void NativeReaderCopiesLocalRoutes()
    {
        var reader = new WindowsRoutingTableReader();
        var routes = reader.Read(TestContext.Current.CancellationToken);
        Assert.NotEmpty(routes);
        Assert.All(routes, route =>
        {
            Assert.Equal(route.Family, IPAddress.Parse(route.NextHop).AddressFamily);
            Assert.Equal(route.Family, IPNetwork.Parse(route.Destination).BaseAddress.AddressFamily);
            Assert.NotEqual(0u, route.InterfaceIndex);
            Assert.Equal(16, route.InterfaceId.Length);
        });
        // A second independent read cannot take ownership of or mutate the first result.
        string[] destinations = routes.Select(route => route.Destination).ToArray();
        _ = reader.Read(TestContext.Current.CancellationToken);
        Assert.Equal(destinations, routes.Select(route => route.Destination));
    }

    /// <summary>Real monitoring and native reads compose into diagnostics whose latch survives return.</summary>
    [Fact]
    public async Task MonitorInvalidatesCompletedRouteDiagnostics()
    {
        using var monitor = new WindowsNetworkMonitor();
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(10));
        while (monitor.Capture() is null) { await Task.Delay(10, timeout.Token); }
        var collector = new RouteDiagnosticsCollector(new WindowsRoutingTableReader(), monitor);
        var result = await Task.Run(() => collector.Collect(timeout.Token), timeout.Token);
        Assert.Equal(RouteDiagnosticsStatus.Completed, result.Status);
        var snapshot = Assert.IsType<RouteDiagnosticsSnapshot>(result.Snapshot);
        Assert.NotEmpty(snapshot.Routes);
        Assert.True(snapshot.CompletedAt >= snapshot.StartedAt);
        monitor.Refresh();
        Assert.True(snapshot.Network.Invalidated.IsCancellationRequested);
        monitor.Dispose();
        await monitor.Completion.WaitAsync(timeout.Token);
        Assert.Null(monitor.LastError);
    }
}
