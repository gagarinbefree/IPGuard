using System.Net;
using System.Net.Sockets;
using IPGuard.Application.Network;
using IPGuard.Application.PublicIp;
using IPGuard.Domain;
using IPGuard.Infrastructure.GeoIp;
using IPGuard.Infrastructure.PublicIp;
using IPGuard.Windows.Network;
using IPGuard.Windows.Network.Native;
using Xunit;

namespace IntegrationTests;

/// <summary>Checks real read-only registration and monitor/application composition without changing host networking.</summary>
public sealed class WindowsNetworkMonitorTests
{
    /// <summary>The native Windows adapter registers, reads, refreshes, and closes without administrator writes.</summary>
    [Fact]
    public async Task NativeMonitorPublishesAndDisposes()
    {
        using var monitor = new WindowsNetworkMonitor();
        var first = await WaitForSnapshotAsync(monitor);
        Assert.NotEqual(Guid.Empty, first.Version);
        Assert.True(first.Invalidated.CanBeCanceled);
        Assert.Contains(first.Ipv4, new[] { IpFamilyAvailability.Unknown, IpFamilyAvailability.Available });
        Assert.Contains(first.Ipv6, new[] { IpFamilyAvailability.Unknown, IpFamilyAvailability.Available });
        monitor.Refresh();
        Assert.True(first.Invalidated.IsCancellationRequested);
        var next = await WaitForSnapshotAsync(monitor);
        Assert.NotEqual(first.Version, next.Version);
        monitor.Dispose();
        await monitor.Completion.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
        Assert.True(next.Invalidated.IsCancellationRequested);
        Assert.Null(monitor.Capture());
        Assert.Null(monitor.LastError);
    }

    /// <summary>Repeated actual notification registrations release all three native handle kinds safely.</summary>
    [Fact]
    public void NativeSubscriptionsCanBeRepeatedlyClosed()
    {
        for (int index = 0; index < 8; index++)
        {
            using var subscription = new WindowsNetworkChangeSubscription(_ => { });
            subscription.Dispose();
        }
    }

    /// <summary>Each native notification category reaches the real monitor and cancels in-flight collection.</summary>
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    public async Task NotificationCancelsCollector(int category)
    {
        var api = new ChangeApi();
        using var monitor = ControlledMonitor(api);
        var first = await WaitForSnapshotAsync(monitor);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var probe = new Probe(async (_, token) =>
        {
            entered.TrySetResult();
            await Task.Delay(Timeout.InfiniteTimeSpan, token);
            return [];
        });
        var collector = new PublicIpCollector(probe, monitor, PublicIpSources.Defaults);
        var collecting = collector.CollectAsync(TestContext.Current.CancellationToken);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
        api.Raise((NetworkChangeKind)category);
        Assert.True(first.Invalidated.IsCancellationRequested);
        var result = await collecting.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
        Assert.Equal(PublicIpCollectionStatus.NetworkChanged, result.Status);
        Assert.Null(result.Snapshot);
        Assert.NotEqual(first.Version, (await WaitForSnapshotAsync(monitor)).Version);
    }

    /// <summary>A token consumer can dispose the real native subscription wrapper from its asynchronous callback.</summary>
    [Fact]
    public async Task InvalidationConsumerCanCloseNativeSubscription()
    {
        var api = new ChangeApi();
        using var monitor = ControlledMonitor(api);
        var snapshot = await WaitForSnapshotAsync(monitor);
        var completed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var registration = snapshot.Invalidated.Register(() =>
        {
            try
            {
                monitor.Dispose();
                completed.TrySetResult();
            }
            catch (Exception error) { completed.TrySetException(error); }
        });
        api.Raise(NetworkChangeKind.Route);
        await completed.Task.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
        Assert.Equal(3, api.Cancelled);
        Assert.Null(monitor.Capture());
        Assert.Null(monitor.LastError);
    }

    /// <summary>A completed real MMDB assessment retains a latch invalidated by subsequent monitor changes.</summary>
    [Fact]
    public async Task CompletedAssessmentIsInvalidatedAfterReturn()
    {
        var api = new ChangeApi();
        using var monitor = ControlledMonitor(api);
        _ = await WaitForSnapshotAsync(monitor);
        string fixture = Path.Combine(AppContext.BaseDirectory, "GeoIp", "GeoIP2-Country-Test.mmdb");
        var age = TimeSpan.FromDays(45);
        using var metadata = MmdbCountryDatabase.Open(fixture, age);
        var now = metadata.Info.BuiltAt.AddDays(1);
        var probe = new Probe((sources, _) => Task.FromResult<IReadOnlyList<PublicIpReadResult>>(sources.Select(source =>
            new PublicIpReadResult(source, PublicIpReadStatus.Success, IPAddress.Parse(
                source.Family == AddressFamily.InterNetwork ? "149.101.100.1" : "2001:218::1"))).ToArray()));
        var assessor = new NetworkAssessor(probe, monitor, PublicIpSources.Defaults,
            () => MmdbCountryDatabase.Open(fixture, age), new PublicIpPolicy(TimeSpan.FromMinutes(5), ["US", "JP"]), () => now);
        var result = await assessor.AssessAsync(TestContext.Current.CancellationToken);
        var assessment = Assert.IsType<NetworkAssessmentSnapshot>(result.Snapshot);
        Assert.True(assessment.Decision.IsEligible);
        Assert.Equal(PublicIpDecisionReason.EligibleForRouteValidation, assessment.Decision.Reason);
        api.Raise(NetworkChangeKind.Address);
        Assert.True(assessment.Network.Invalidated.IsCancellationRequested);
        var next = await WaitForSnapshotAsync(monitor);
        Assert.NotEqual(assessment.Network.Version, next.Version);
        Assert.True(assessment.Network.Invalidated.IsCancellationRequested);
    }

    /// <summary>Composes the actual subscription wrapper and monitor with controlled Windows input.</summary>
    private static WindowsNetworkMonitor ControlledMonitor(ChangeApi api) => new(
        changed => new WindowsNetworkChangeSubscription(changed, api),
        () => new NetworkFamilyState(IpFamilyAvailability.Available, IpFamilyAvailability.Available));

    /// <summary>Waits for cached publication without issuing network requests.</summary>
    private static async Task<NetworkSnapshot> WaitForSnapshotAsync(WindowsNetworkMonitor monitor)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(10));
        NetworkSnapshot? snapshot;
        while ((snapshot = monitor.Capture()) is null)
        {
            await Task.Delay(10, timeout.Token);
        }
        return snapshot;
    }

    /// <summary>Supplies controlled application replies and observes cooperative cancellation.</summary>
    private sealed class Probe : IPublicIpProbe
    {
        private readonly Func<IEnumerable<PublicIpSource>, CancellationToken, Task<IReadOnlyList<PublicIpReadResult>>> read;

        /// <summary>Captures reply behavior without public DNS, sockets, or HTTPS.</summary>
        internal Probe(Func<IEnumerable<PublicIpSource>, CancellationToken, Task<IReadOnlyList<PublicIpReadResult>>> read) => this.read = read;

        /// <summary>Passes the collector's linked token through the controlled operation.</summary>
        public Task<IReadOnlyList<PublicIpReadResult>> ReadAllAsync(IEnumerable<PublicIpSource> sources, CancellationToken cancellationToken) =>
            read(sources, cancellationToken);
    }

    /// <summary>Replaces only the Windows API while retaining the real subscription and monitor code.</summary>
    private sealed class ChangeApi : INetworkChangeApi
    {
        private readonly Dictionary<NetworkChangeKind, NativeNetworkChanged> callbacks = [];

        /// <summary>Gets how many owned native registrations were released.</summary>
        internal int Cancelled { get; private set; }

        /// <summary>Captures native callbacks separately for route, interface, and address changes.</summary>
        public uint Register(NetworkChangeKind kind, NativeNetworkChanged callback, out nint handle)
        {
            callbacks.Add(kind, callback);
            handle = (nint)(callbacks.Count);
            return 0;
        }

        /// <summary>Records native handle release without changing Windows state.</summary>
        public uint Cancel(nint handle)
        {
            Cancelled++;
            return 0;
        }

        /// <summary>Delivers a native-shaped change with an intentionally unusable borrowed row pointer.</summary>
        internal void Raise(NetworkChangeKind kind) => callbacks[kind](0, (nint)1, 0);
    }
}
