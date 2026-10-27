using System.Net;
using IPGuard.Application.GeoIp;
using IPGuard.Application.Network;
using IPGuard.Application.PublicIp;
using IPGuard.Domain;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace UnitTests;

/// <summary>Checks periodic address/country changes and asynchronous cancellation through the shared refresh loop.</summary>
public sealed class NetworkCheckMonitorTests
{
    /// <summary>Address and country changes behind NAT are rediscovered without any local generation notification.</summary>
    [Fact]
    public async Task PeriodicCheckDetectsNatAndCountryChange()
    {
        await using var rig = new Rig();
        var first = await rig.ObservationAsync();
        Assert.True(first.Snapshot.Assessment!.Decision.IsEligible);
        rig.Setup.Ipv4 = "8.8.8.8";
        rig.Setup.Ipv6 = "2606:4700:4700::1111";
        rig.Setup.Country = "CA";
        rig.Time.Advance(TimeSpan.FromSeconds(5));
        Assert.True(first.Invalidated.IsCancellationRequested);
        var second = await rig.ObservationAsync();
        Assert.NotSame(first, second);
        Assert.Same(first.Snapshot.Network, second.Snapshot.Network);
        Assert.Equal("8.8.8.8", second.Snapshot.Assessment!.Evidence.Ipv4!.GeoIp!.Address);
        Assert.Equal("2606:4700:4700::1111", second.Snapshot.Assessment.Evidence.Ipv6!.GeoIp!.Address);
        Assert.Equal(PublicIpDecisionReason.CountryNotAllowed, second.Snapshot.Assessment.Decision.Reason);
        Assert.Equal(2, rig.Setup.ProbeCalls);
        Assert.Equal(2, rig.Setup.Disposals);
    }

    /// <summary>A failed periodic source cannot retain the previous positive country prerequisites.</summary>
    [Theory]
    [InlineData(PublicIpReadStatus.NameResolutionFailed)]
    [InlineData(PublicIpReadStatus.TlsFailed)]
    [InlineData(PublicIpReadStatus.TimedOut)]
    public async Task PeriodicSourceErrorReplacesPositiveDecision(PublicIpReadStatus failure)
    {
        await using var rig = new Rig();
        var first = await rig.ObservationAsync();
        rig.Setup.Reply = source => new(source, failure);
        rig.Time.Advance(TimeSpan.FromSeconds(5));
        Assert.True(first.Invalidated.IsCancellationRequested);
        var second = await rig.ObservationAsync();
        Assert.Equal(PublicIpDecisionReason.SourceFailed, second.Snapshot.Assessment!.Decision.Reason);
        Assert.False(second.Snapshot.Assessment.Decision.IsEligible);
    }

    /// <summary>GeoIP failure after success exposes diagnostics without retaining any usable combined snapshot.</summary>
    [Fact]
    public async Task PeriodicGeoIpFailureRetainsReasonAndCanRecover()
    {
        await using var rig = new Rig();
        var first = await rig.ObservationAsync();
        rig.Setup.LookupStatus = GeoIpLookupStatus.UnknownCountry;
        rig.Time.Advance(TimeSpan.FromSeconds(5));
        await WaitForAsync(() => rig.Monitor.LastStatus == NetworkDiagnosticsStatus.Failed);
        Assert.True(first.Invalidated.IsCancellationRequested);
        Assert.Null(rig.Monitor.Capture());
        Assert.Equal(GeoIpLookupStatus.UnknownCountry, rig.Monitor.LastFailure!.Assessment!.GeoIpFailure!.Status);
        rig.Setup.LookupStatus = GeoIpLookupStatus.Found;
        rig.Time.Advance(TimeSpan.FromSeconds(5));
        var second = await rig.ObservationAsync();
        Assert.True(second.Snapshot.Assessment!.Decision.IsEligible);
        Assert.Null(rig.Monitor.LastFailure);
    }

    /// <summary>A database deadline earlier than the refresh interval retires held data even without a Capture call.</summary>
    [Fact]
    public async Task CaptureRejectsDatabaseExpiryBeforePeriodicTick()
    {
        await using var rig = new Rig(databaseDeadline: NetworkCheckSetup.Start.AddSeconds(3));
        var first = await rig.ObservationAsync();
        rig.Time.Advance(TimeSpan.FromSeconds(3));
        Assert.True(first.Invalidated.IsCancellationRequested);
        Assert.Null(rig.Monitor.Capture());
        await WaitForAsync(() => rig.Monitor.LastStatus == NetworkDiagnosticsStatus.Failed);
        Assert.Equal(NetworkAssessmentStatus.GeoIpUnavailable, rig.Monitor.LastFailure!.Assessment!.Status);
    }

    /// <summary>A late uncooperative HTTPS batch cannot publish after manual refresh, and collections never overlap.</summary>
    [Fact]
    public async Task RefreshDiscardsLateAsyncReply()
    {
        var entered = Signal();
        var release = Signal();
        CancellationToken retired = default;
        var calls = 0;
        await using var rig = new Rig(beforeProbe: async token =>
        {
            if (Interlocked.Increment(ref calls) == 1)
            {
                retired = token;
                entered.SetResult();
                await release.Task.WaitAsync(TestContext.Current.CancellationToken);
            }
        });
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
            rig.Monitor.Refresh();
            await WaitForAsync(() => retired.IsCancellationRequested);
            Assert.Null(rig.Monitor.Capture());
            Assert.Equal(1, rig.Setup.ProbeCalls);
            rig.Setup.Ipv4 = "8.8.8.8";
            rig.Setup.Country = "CA";
        }
        finally { release.TrySetResult(); }
        var observation = await rig.ObservationAsync();
        Assert.Equal(2, rig.Setup.ProbeCalls);
        Assert.Equal("8.8.8.8", observation.Snapshot.Assessment!.Evidence.Ipv4!.GeoIp!.Address);
        Assert.Equal(PublicIpDecisionReason.CountryNotAllowed, observation.Snapshot.Assessment.Decision.Reason);
    }

    /// <summary>Timeout retires an asynchronous request even when it ignores cancellation.</summary>
    [Fact]
    public async Task DeadlineDiscardsLateAsyncReply()
    {
        var entered = Signal();
        var release = Signal();
        CancellationToken retired = default;
        var calls = 0;
        await using var rig = new Rig(beforeProbe: async token =>
        {
            if (Interlocked.Increment(ref calls) == 1)
            {
                retired = token;
                entered.SetResult();
                await release.Task.WaitAsync(TestContext.Current.CancellationToken);
            }
        }, interval: TimeSpan.FromSeconds(30));
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
            rig.Time.Advance(TimeSpan.FromSeconds(10));
            await WaitForAsync(() => retired.IsCancellationRequested);
            Assert.Equal(1, rig.Setup.ProbeCalls);
            Assert.Null(rig.Monitor.Capture());
        }
        finally { release.TrySetResult(); }
        var observation = await rig.ObservationAsync();
        Assert.Equal(rig.Time.GetUtcNow(), observation.Snapshot.StartedAt);
        Assert.Equal(2, rig.Setup.ProbeCalls);
    }

    /// <summary>Exit invalidates held data immediately and waits for no uncooperative asynchronous reply.</summary>
    [Fact]
    public async Task DisposeWhileCheckingCannotPublishLateResult()
    {
        var entered = Signal();
        var release = Signal();
        var calls = 0;
        await using var rig = new Rig(beforeProbe: async _ =>
        {
            if (Interlocked.Increment(ref calls) == 2)
            {
                entered.SetResult();
                await release.Task.WaitAsync(TestContext.Current.CancellationToken);
            }
        });
        var first = await rig.ObservationAsync();
        try
        {
            rig.Monitor.Refresh();
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
            rig.Monitor.Dispose();
            Assert.True(first.Invalidated.IsCancellationRequested);
            Assert.Null(rig.Monitor.Capture());
            Assert.False(rig.Monitor.Completion.IsCompleted);
        }
        finally { release.TrySetResult(); }
        await rig.Monitor.Completion.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
        Assert.Null(rig.Monitor.Capture());
    }

    /// <summary>Creates a non-inline barrier for deterministic source interleavings.</summary>
    private static TaskCompletionSource Signal() => new(TaskCreationOptions.RunContinuationsAsynchronously);

    /// <summary>Waits for observable state with a bounded watchdog independent of diagnostic time.</summary>
    private static async Task WaitForAsync(Func<bool> predicate)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(10));
        while (!predicate()) await Task.Delay(1, timeout.Token);
    }

    /// <summary>Composes full application orchestration with deterministic timers and no public requests.</summary>
    private sealed class Rig : IAsyncDisposable
    {
        /// <summary>Starts a full-check monitor after configuring any initial asynchronous or database behavior.</summary>
        internal Rig(Func<CancellationToken, Task>? beforeProbe = null, TimeSpan? interval = null, DateTimeOffset? databaseDeadline = null)
        {
            if (beforeProbe is not null) Setup.BeforeProbe = beforeProbe;
            if (databaseDeadline.HasValue) Setup.DatabaseDeadline = databaseDeadline.Value;
            Monitor = new NetworkDiagnosticsMonitor(Setup.Collector(Time.GetUtcNow), interval ?? TimeSpan.FromSeconds(5), Time);
        }

        /// <summary>Gets controlled network and evidence boundaries.</summary>
        internal NetworkCheckSetup Setup { get; } = new();

        /// <summary>Gets deterministic scheduling and UTC time.</summary>
        internal FakeTimeProvider Time { get; } = new(NetworkCheckSetup.Start);

        /// <summary>Gets the shared serial refresh loop.</summary>
        internal NetworkDiagnosticsMonitor Monitor { get; }

        /// <summary>Waits for complete current observations.</summary>
        internal async Task<NetworkDiagnosticsObservation> ObservationAsync()
        {
            NetworkDiagnosticsObservation? observation = null;
            await WaitForAsync(() => (observation = Monitor.Capture()) is not null);
            return observation!;
        }

        /// <summary>Stops the worker before releasing test-owned generation state.</summary>
        public async ValueTask DisposeAsync()
        {
            Monitor.Dispose();
            await Monitor.Completion.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
            Setup.Dispose();
        }
    }
}
