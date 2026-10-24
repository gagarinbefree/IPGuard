using IPGuard.Application.Network;
using IPGuard.Domain;
using IPGuard.Windows.Network;
using Xunit;

namespace UnitTests;

/// <summary>Exercises generation changes and races without touching the host network.</summary>
public sealed class WindowsNetworkMonitorTests
{
    /// <summary>Publishes one stable cached generation with a cancellable latch.</summary>
    [Fact]
    public async Task InitialReadIsCached()
    {
        var source = new ChangeSource();
        var reads = 0;
        using var monitor = new WindowsNetworkMonitor(source.Subscribe, () =>
        {
            Interlocked.Increment(ref reads);
            return BothFamilies();
        });
        var first = await WaitForSnapshotAsync(monitor);
        Assert.NotEqual(Guid.Empty, first.Version);
        Assert.True(first.Invalidated.CanBeCanceled);
        Assert.False(first.Invalidated.IsCancellationRequested);
        Assert.Equal(IpFamilyAvailability.Available, first.Ipv4);
        Assert.Equal(IpFamilyAvailability.Available, first.Ipv6);
        for (var index = 0; index < 100; index++)
        {
            Assert.Same(first, monitor.Capture());
        }
        Assert.Equal(1, reads);
    }

    /// <summary>Cancels the old generation before reading replacement configuration.</summary>
    [Fact]
    public async Task ChangeInvalidatesBeforeRefreshAndNeverReusesVersion()
    {
        var source = new ChangeSource();
        using var entered = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        var reads = 0;
        using var monitor = new WindowsNetworkMonitor(source.Subscribe, () =>
        {
            if (Interlocked.Increment(ref reads) == 2)
            {
                entered.Set();
                Assert.True(release.Wait(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken));
            }
            return BothFamilies();
        });
        var first = await WaitForSnapshotAsync(monitor);
        try
        {
            source.Change();
            Assert.True(first.Invalidated.IsCancellationRequested);
            Assert.Null(monitor.Capture());
            Assert.True(entered.Wait(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken));
        }
        finally
        {
            release.Set();
        }
        var second = await WaitForSnapshotAsync(monitor);
        Assert.NotEqual(first.Version, second.Version);
        Assert.NotEqual(first.Invalidated, second.Invalidated);
        source.Change();
        var third = await WaitForSnapshotAsync(monitor);
        Assert.NotEqual(second.Version, third.Version);
        Assert.NotEqual(first.Version, third.Version);
        Assert.True(first.Invalidated.IsCancellationRequested);
        Assert.True(second.Invalidated.IsCancellationRequested);
    }

    /// <summary>Subscribes before reading and discards configuration invalidated during a read.</summary>
    [Fact]
    public async Task ChangeDuringReadDiscardsOldConfiguration()
    {
        var source = new ChangeSource();
        var reads = 0;
        using var monitor = new WindowsNetworkMonitor(source.Subscribe, () =>
        {
            Assert.True(source.Subscribed);
            if (Interlocked.Increment(ref reads) == 1)
            {
                source.Change();
                return new(IpFamilyAvailability.Unavailable, IpFamilyAvailability.Unavailable);
            }
            return BothFamilies();
        });
        var snapshot = await WaitForSnapshotAsync(monitor);
        Assert.Equal(IpFamilyAvailability.Available, snapshot.Ipv4);
        Assert.Equal(2, reads);
    }

    /// <summary>Handles notifications received before subscription construction returns.</summary>
    [Fact]
    public async Task ChangeDuringSubscriptionIsNotLost()
    {
        var source = new ChangeSource { ChangeOnSubscribe = true };
        using var monitor = new WindowsNetworkMonitor(source.Subscribe, BothFamilies);
        Assert.NotNull(await WaitForSnapshotAsync(monitor));
    }

    /// <summary>Keeps failed reads unknown and permits an explicit retry without a new OS event.</summary>
    [Fact]
    public async Task ReadFailureFailsClosedAndRefreshRecovers()
    {
        var source = new ChangeSource();
        var failure = new InvalidOperationException("Cannot read interfaces.");
        var fail = false;
        using var monitor = new WindowsNetworkMonitor(source.Subscribe, () => fail ? throw failure : BothFamilies());
        var first = await WaitForSnapshotAsync(monitor);
        fail = true;
        source.Change();
        await WaitUntilAsync(() => ReferenceEquals(monitor.LastError, failure));
        Assert.Null(monitor.Capture());
        Assert.True(first.Invalidated.IsCancellationRequested);
        fail = false;
        monitor.Refresh();
        var next = await WaitForSnapshotAsync(monitor);
        Assert.NotEqual(first.Version, next.Version);
        Assert.Null(monitor.LastError);
    }

    /// <summary>Never promotes missing family information to proven unavailability.</summary>
    [Fact]
    public async Task UnknownFamiliesRemainUnknown()
    {
        var source = new ChangeSource();
        using var monitor = new WindowsNetworkMonitor(source.Subscribe, () => new(IpFamilyAvailability.Unknown, IpFamilyAvailability.Unknown));
        var snapshot = await WaitForSnapshotAsync(monitor);
        Assert.Equal(IpFamilyAvailability.Unknown, snapshot.Ipv4);
        Assert.Equal(IpFamilyAvailability.Unknown, snapshot.Ipv6);
    }

    /// <summary>Reentrant invalidation consumers can capture and dispose without blocking the notification thread.</summary>
    [Fact]
    public async Task ConsumerCanDisposeDuringInvalidation()
    {
        var source = new ChangeSource();
        using var monitor = new WindowsNetworkMonitor(source.Subscribe, BothFamilies);
        var first = await WaitForSnapshotAsync(monitor);
        var completed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var registration = first.Invalidated.Register(() =>
        {
            _ = monitor.Capture();
            monitor.Dispose();
            completed.TrySetResult();
        });
        source.Change();
        await completed.Task.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
        await monitor.Completion.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
        Assert.True(source.Disposed);
        Assert.Null(monitor.Capture());
        Assert.True(first.Invalidated.IsCancellationRequested);
    }

    /// <summary>Observes faulty consumer callbacks while preserving cancellation of every consumer.</summary>
    [Fact]
    public async Task CallbackFailureIsObserved()
    {
        var source = new ChangeSource();
        using var monitor = new WindowsNetworkMonitor(source.Subscribe, BothFamilies);
        var first = await WaitForSnapshotAsync(monitor);
        using var reached = new ManualResetEventSlim();
        using var observed = first.Invalidated.Register(reached.Set);
        using var faulty = first.Invalidated.Register(() => throw new InvalidOperationException("Consumer failure."));
        monitor.Dispose();
        await WaitUntilAsync(() => monitor.LastError is AggregateException);
        Assert.True(reached.IsSet);
        Assert.True(first.Invalidated.IsCancellationRequested);
        Assert.Null(monitor.Capture());
    }

    /// <summary>Disposal invalidates cached evidence, stops the worker, and rejects manual refreshes.</summary>
    [Fact]
    public async Task DisposeIsIdempotentAndLateEventsDoNothing()
    {
        var source = new ChangeSource();
        using var monitor = new WindowsNetworkMonitor(source.Subscribe, BothFamilies);
        var first = await WaitForSnapshotAsync(monitor);
        monitor.Dispose();
        monitor.Dispose();
        source.Change();
        await monitor.Completion.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
        Assert.Null(monitor.Capture());
        Assert.True(first.Invalidated.IsCancellationRequested);
        Assert.Throws<ObjectDisposedException>(monitor.Refresh);
    }

    /// <summary>Does not publish a read which completes after disposal.</summary>
    [Fact]
    public async Task DisposeDuringReadPreventsPublication()
    {
        var source = new ChangeSource();
        using var entered = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        using var monitor = new WindowsNetworkMonitor(source.Subscribe, () =>
        {
            entered.Set();
            Assert.True(release.Wait(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken));
            return BothFamilies();
        });
        try
        {
            Assert.True(entered.Wait(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken));
            monitor.Dispose();
            Assert.Null(monitor.Capture());
        }
        finally
        {
            release.Set();
        }
        await monitor.Completion.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
        Assert.Null(monitor.Capture());
    }

    /// <summary>Rejects subscription failure instead of returning an apparently live monitor.</summary>
    [Fact]
    public void SubscriptionFailureIsNotHidden()
    {
        var failure = new InvalidOperationException("Cannot register notifications.");
        Assert.Same(failure, Assert.Throws<InvalidOperationException>(() => new WindowsNetworkMonitor(_ => throw failure, BothFamilies)));
    }

    /// <summary>A queued initial refresh cannot conceal a notification fault reported during registration.</summary>
    [Fact]
    public async Task NotificationFaultRemainsClosedUntilManualRetry()
    {
        var failure = new InvalidOperationException("The notification callback failed.");
        var source = new ChangeSource { ChangeOnSubscribe = true, FailureOnSubscribe = failure };
        using var monitor = new WindowsNetworkMonitor(source.Subscribe, BothFamilies);
        await Task.Delay(150, TestContext.Current.CancellationToken);
        Assert.Same(failure, monitor.LastError);
        Assert.Null(monitor.Capture());
        monitor.Refresh();
        Assert.NotNull(await WaitForSnapshotAsync(monitor));
        Assert.Null(monitor.LastError);
    }

    /// <summary>Supplies two configured families for controlled lifecycle tests.</summary>
    private static NetworkFamilyState BothFamilies() => new(IpFamilyAvailability.Available, IpFamilyAvailability.Available);

    /// <summary>Waits for a published generation using a bounded test deadline.</summary>
    private static async Task<NetworkSnapshot> WaitForSnapshotAsync(WindowsNetworkMonitor monitor)
    {
        await WaitUntilAsync(() => monitor.Capture() is not null);
        return Assert.IsType<NetworkSnapshot>(monitor.Capture());
    }

    /// <summary>Waits for an observable condition without changing the host network.</summary>
    private static async Task WaitUntilAsync(Func<bool> condition)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(10));
        while (!condition())
        {
            await Task.Delay(10, timeout.Token);
        }
    }

    /// <summary>Delivers controlled notifications without any operating-system subscription.</summary>
    private sealed class ChangeSource : IDisposable
    {
        private Action<Exception?>? _changed;

        /// <summary>Gets whether registration occurred before reading configuration.</summary>
        internal bool Subscribed { get; private set; }

        /// <summary>Gets whether the monitor released this source.</summary>
        internal bool Disposed { get; private set; }

        /// <summary>Gets or sets whether registration immediately delivers a real change.</summary>
        internal bool ChangeOnSubscribe { get; init; }

        /// <summary>Gets a notification fault to deliver before returning from registration.</summary>
        internal Exception? FailureOnSubscribe { get; init; }

        /// <summary>Registers the monitor callback and optionally simulates an early change.</summary>
        internal IDisposable Subscribe(Action<Exception?> changed)
        {
            Subscribed = true;
            _changed = changed;
            if (ChangeOnSubscribe)
            {
                changed(null);
            }
            if (FailureOnSubscribe is not null) { changed(FailureOnSubscribe); }
            return this;
        }

        /// <summary>Delivers a change even after disposal to test late callback handling.</summary>
        internal void Change() => _changed?.Invoke(null);

        /// <summary>Records subscription cleanup.</summary>
        public void Dispose() => Disposed = true;
    }
}
