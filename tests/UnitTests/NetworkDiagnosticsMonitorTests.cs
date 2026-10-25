using IPGuard.Application.Network;
using IPGuard.Domain;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace UnitTests;

/// <summary>Checks refresh, expiry, and shutdown races with controlled time and local readers.</summary>
public sealed class NetworkDiagnosticsMonitorTests
{
    /// <summary>Initial collection runs on a background thread and publishes only complete local observations.</summary>
    [Fact]
    public async Task InitialCollectionDoesNotBlockCaller()
    {
        using var entered = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        await using var rig = new Rig((_, _) => { entered.Set(); release.Wait(TestContext.Current.CancellationToken); return []; });
        try
        {
            Assert.True(entered.Wait(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken));
            Assert.Null(rig.Monitor.Capture());
        }
        finally { release.Set(); }
        var observation = await rig.ObservationAsync();
        Assert.Equal(NetworkDiagnosticsStatus.Completed, rig.Monitor.LastStatus);
        Assert.Null(rig.Monitor.LastError);
        Assert.False(observation.Invalidated.IsCancellationRequested);
        Assert.Empty(observation.Snapshot.Connections);
    }

    /// <summary>Periodic refresh retires data before rereading proxy and RAS, without a network notification.</summary>
    [Fact]
    public async Task PeriodicRefreshReadsChangedSettings()
    {
        using var entered = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        await using var rig = new Rig((attempt, _) =>
        {
            if (attempt == 2) { entered.Set(); release.Wait(TestContext.Current.CancellationToken); }
            return [];
        });
        var first = await rig.ObservationAsync();
        try
        {
            rig.Setup.Proxy = new(true, false, false, false, false, false, true, false);
            rig.Setup.ReadConnections = _ => [new(null, true, RemoteAccessState.Connected, 0, 8192, 0)];
            rig.Time.Advance(TimeSpan.FromSeconds(5));
            Assert.True(first.Invalidated.IsCancellationRequested);
            Assert.True(entered.Wait(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken));
            Assert.Null(rig.Monitor.Capture());
        }
        finally { release.Set(); }
        var second = await rig.ObservationAsync();
        Assert.NotSame(first, second);
        Assert.Same(first.Snapshot.Network, second.Snapshot.Network);
        Assert.True(second.Snapshot.Proxy.ProcessProxy);
        Assert.Equal(RemoteAccessState.Connected, Assert.Single(second.Snapshot.Connections).State);
    }

    /// <summary>Refreshes coalesce while an uncooperative reader runs, and its late output cannot be published.</summary>
    [Fact]
    public async Task ManualRefreshCancelsLateReadWithoutOverlap()
    {
        using var entered = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        CancellationToken retired = default;
        await using var rig = new Rig((attempt, token) =>
        {
            if (attempt == 1) { retired = token; entered.Set(); release.Wait(TestContext.Current.CancellationToken); }
            return [];
        });
        try
        {
            Assert.True(entered.Wait(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken));
            for (var index = 0; index < 30; index++) rig.Monitor.Refresh();
            await WaitForAsync(() => retired.IsCancellationRequested);
            Assert.Equal(1, rig.Attempts);
            Assert.Null(rig.Monitor.Capture());
        }
        finally { release.Set(); }
        await rig.ObservationAsync();
        Assert.Equal(2, rig.Attempts);
    }

    /// <summary>A deadline invalidates an in-flight read even when the periodic interval has not elapsed.</summary>
    [Fact]
    public async Task DeadlineCancelsBlockedRead()
    {
        using var entered = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        CancellationToken retired = default;
        await using var rig = new Rig((attempt, token) =>
        {
            if (attempt == 1) { retired = token; entered.Set(); release.Wait(TestContext.Current.CancellationToken); }
            return [];
        }, interval: TimeSpan.FromSeconds(30));
        try
        {
            Assert.True(entered.Wait(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken));
            rig.Time.Advance(TimeSpan.FromSeconds(10));
            await WaitForAsync(() => retired.IsCancellationRequested);
            Assert.Null(rig.Monitor.Capture());
            Assert.Equal(1, rig.Attempts);
        }
        finally { release.Set(); }
        var observation = await rig.ObservationAsync();
        Assert.Equal(rig.Time.GetUtcNow(), observation.Snapshot.StartedAt);
        Assert.Equal(2, rig.Attempts);
    }

    /// <summary>Published data expires independently of the refresh interval and never refreshes its own age.</summary>
    [Fact]
    public async Task DeadlineRetiresPublishedSnapshot()
    {
        using var entered = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        await using var rig = new Rig((attempt, _) =>
        {
            if (attempt == 2) { entered.Set(); release.Wait(TestContext.Current.CancellationToken); }
            return [];
        }, interval: TimeSpan.FromSeconds(30));
        var first = await rig.ObservationAsync();
        try
        {
            rig.Time.Advance(TimeSpan.FromSeconds(9));
            Assert.Same(first, rig.Monitor.Capture());
            rig.Time.Advance(TimeSpan.FromSeconds(1));
            Assert.True(first.Invalidated.IsCancellationRequested);
            Assert.True(entered.Wait(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken));
            Assert.Null(rig.Monitor.Capture());
        }
        finally { release.Set(); }
    }

    /// <summary>Generation cancellation retires published observations and does not resurrect them on reconnect.</summary>
    [Fact]
    public async Task NetworkDisconnectAndReconnectUseNewObservation()
    {
        await using var rig = new Rig();
        var first = await rig.ObservationAsync();
        rig.Setup.Changed.Cancel();
        Assert.Null(rig.Monitor.Capture());
        Assert.True(first.Invalidated.IsCancellationRequested);
        await WaitForAsync(() => rig.Monitor.LastStatus == NetworkDiagnosticsStatus.NetworkUnavailable);
        using var next = new CancellationTokenSource();
        rig.Setup.Current = new(Guid.NewGuid(), IpFamilyAvailability.Available, IpFamilyAvailability.Available, next.Token);
        rig.Time.Advance(TimeSpan.FromSeconds(5));
        var second = await rig.ObservationAsync();
        Assert.NotEqual(first.Snapshot.Network.Version, second.Snapshot.Network.Version);
        Assert.True(first.Invalidated.IsCancellationRequested);
        Assert.False(second.Invalidated.IsCancellationRequested);
    }

    /// <summary>Capture catches a changed generation even if a broken provider omitted its notification.</summary>
    [Fact]
    public async Task CaptureRechecksGeneration()
    {
        await using var rig = new Rig();
        var first = await rig.ObservationAsync();
        rig.Setup.Current = null;
        Assert.Null(rig.Monitor.Capture());
        Assert.True(first.Invalidated.IsCancellationRequested);
        await WaitForAsync(() => rig.Monitor.LastStatus == NetworkDiagnosticsStatus.NetworkUnavailable);
    }

    /// <summary>Wall-clock freshness remains enforced when only the wall clock advances, without timer delivery.</summary>
    [Theory]
    [InlineData("expired")]
    [InlineData("backward")]
    [InlineData("throw")]
    public async Task CaptureRejectsClockFailure(string condition)
    {
        var wall = new DateTimeOffset(2026, 10, 25, 8, 0, 0, TimeSpan.Zero);
        var broken = false;
        await using var rig = new Rig(clock: () => broken ? throw new IOException("Clock failed.") : wall);
        var first = await rig.ObservationAsync();
        wall = wall.AddSeconds(2);
        Assert.Same(first, rig.Monitor.Capture());
        if (condition == "throw") broken = true;
        else wall = wall.AddSeconds(condition == "expired" ? 8 : -1);
        Assert.Null(rig.Monitor.Capture());
        Assert.True(first.Invalidated.IsCancellationRequested);
    }

    /// <summary>A refresh or disposal inside a final boundary cannot return or dereference retired observations.</summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CaptureRejectsReentrantRetirement(bool dispose)
    {
        NetworkDiagnosticsMonitor? monitor = null;
        var armed = false;
        await using var rig = new Rig(clock: () =>
        {
            if (armed)
            {
                armed = false;
                if (dispose) monitor!.Dispose();
                else monitor!.Refresh();
            }
            return new DateTimeOffset(2026, 10, 25, 8, 0, 0, TimeSpan.Zero);
        });
        monitor = rig.Monitor;
        var first = await rig.ObservationAsync();
        armed = true;
        Assert.Null(monitor.Capture());
        Assert.True(first.Invalidated.IsCancellationRequested);
    }

    /// <summary>Failures after refresh expose no previous snapshot and a later periodic success can recover.</summary>
    [Fact]
    public async Task ReaderFailureCannotRetainPreviousData()
    {
        var fail = false;
        var error = new IOException("Proxy unavailable.");
        await using var rig = new Rig();
        rig.Setup.BeforeRead = part => { if (part == "proxy" && fail) throw error; };
        var first = await rig.ObservationAsync();
        fail = true;
        rig.Monitor.Refresh();
        await WaitForAsync(() => rig.Monitor.LastStatus == NetworkDiagnosticsStatus.Failed);
        Assert.Null(rig.Monitor.Capture());
        Assert.True(first.Invalidated.IsCancellationRequested);
        Assert.Same(error, rig.Monitor.LastError);
        fail = false;
        rig.Time.Advance(TimeSpan.FromSeconds(5));
        var second = await rig.ObservationAsync();
        Assert.NotSame(first, second);
        Assert.Null(rig.Monitor.LastError);
    }

    /// <summary>Dispose invalidates held data, stops timers, and is safe to repeat.</summary>
    [Fact]
    public async Task DisposeStopsRefreshAndInvalidatesData()
    {
        await using var rig = new Rig();
        var observation = await rig.ObservationAsync();
        rig.Monitor.Dispose();
        rig.Monitor.Dispose();
        await rig.Monitor.Completion.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
        Assert.True(observation.Invalidated.IsCancellationRequested);
        Assert.Null(rig.Monitor.Capture());
        rig.Time.Advance(TimeSpan.FromMinutes(1));
        Assert.Equal(1, rig.Attempts);
        Assert.Throws<ObjectDisposedException>(rig.Monitor.Refresh);
    }

    /// <summary>Shutdown does not wait for an uninterruptible local call or allow its eventual result to publish.</summary>
    [Fact]
    public async Task DisposeDuringReadDiscardsLateOutput()
    {
        using var entered = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        await using var rig = new Rig((_, _) => { entered.Set(); release.Wait(TestContext.Current.CancellationToken); return []; });
        try
        {
            Assert.True(entered.Wait(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken));
            rig.Monitor.Dispose();
            Assert.Null(rig.Monitor.Capture());
            Assert.False(rig.Monitor.Completion.IsCompleted);
        }
        finally { release.Set(); }
        await rig.Monitor.Completion.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
        Assert.Null(rig.Monitor.Capture());
    }

    /// <summary>Consumer callbacks may reenter disposal or fail without blocking refresh or escaping unobserved.</summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ConsumerCallbacksDoNotBlockRefresh(bool throws)
    {
        await using var rig = new Rig();
        var first = await rig.ObservationAsync();
        var called = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var registration = first.Invalidated.Register(() =>
        {
            if (!throws) rig.Monitor.Dispose();
            called.SetResult();
            if (throws) throw new InvalidOperationException("Consumer failed.");
        });
        rig.Monitor.Refresh();
        Assert.True(first.Invalidated.IsCancellationRequested);
        await called.Task.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
        if (throws) await WaitForAsync(() => rig.Monitor.LastError is AggregateException);
        else await rig.Monitor.Completion.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
    }

    /// <summary>Rejects intervals outside the supported positive timer range instead of starting a broken loop.</summary>
    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(0.5)]
    [InlineData(4294967295d)]
    public void InvalidIntervalDoesNotStart(double milliseconds)
    {
        using var setup = new NetworkDiagnosticsCollectorTests.Setup();
        Assert.Throws<ArgumentOutOfRangeException>(() => new NetworkDiagnosticsMonitor(setup.Collector(), TimeSpan.FromMilliseconds(milliseconds)));
    }

    /// <summary>Waits for observable state with a real bounded watchdog, independently of the controlled diagnostic clock.</summary>
    private static async Task WaitForAsync(Func<bool> predicate)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(10));
        while (!predicate()) await Task.Delay(1, timeout.Token);
    }

    /// <summary>Composes real orchestration with local fakes, controlled time, and bounded async cleanup.</summary>
    private sealed class Rig : IAsyncDisposable
    {
        private int attempts;

        /// <summary>Starts a monitor whose route reader can coordinate deterministic interleavings.</summary>
        internal Rig(Func<int, CancellationToken, IReadOnlyList<NetworkRoute>>? read = null,
            TimeSpan? interval = null, Func<DateTimeOffset>? clock = null)
        {
            Setup.ReadRoutes = token => (read ?? ((_, _) => []))(Interlocked.Increment(ref attempts), token);
            var collector = new NetworkDiagnosticsCollector(Setup, Setup, Setup, Setup, TimeSpan.FromSeconds(10), clock ?? Time.GetUtcNow);
            Monitor = new NetworkDiagnosticsMonitor(collector, interval ?? TimeSpan.FromSeconds(5), Time);
        }

        /// <summary>Gets local generation and reader controls.</summary>
        internal NetworkDiagnosticsCollectorTests.Setup Setup { get; } = new();

        /// <summary>Gets deterministic timers and UTC time without a custom TimeProvider subclass.</summary>
        internal FakeTimeProvider Time { get; } = new(new DateTimeOffset(2026, 10, 25, 8, 0, 0, TimeSpan.Zero));

        /// <summary>Gets the running background monitor.</summary>
        internal NetworkDiagnosticsMonitor Monitor { get; }

        /// <summary>Gets the number of started route reads.</summary>
        internal int Attempts => Volatile.Read(ref attempts);

        /// <summary>Waits for a currently valid observation.</summary>
        internal async Task<NetworkDiagnosticsObservation> ObservationAsync()
        {
            NetworkDiagnosticsObservation? result = null;
            await WaitForAsync(() => (result = Monitor.Capture()) is not null);
            return result!;
        }

        /// <summary>Stops the monitor and waits for its worker before disposing test-owned sources.</summary>
        public async ValueTask DisposeAsync()
        {
            Monitor.Dispose();
            await Monitor.Completion.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
            Setup.Dispose();
        }
    }
}
