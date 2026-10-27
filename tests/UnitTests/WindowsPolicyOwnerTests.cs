using IPGuard.Windows.Filtering;
using Xunit;

namespace UnitTests;

/// <summary>Checks thread affinity, cancellation, contention, and cleanup through controlled mutex operations.</summary>
public sealed class WindowsPolicyOwnerTests
{
    /// <summary>Acquisition and release run on the same dedicated thread even when disposal comes from a continuation.</summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task OwnerPreservesThreadAffinity(bool abandoned)
    {
        var mutex = new TestMutex { Acquisition = abandoned };
        var owner = Assert.IsType<WindowsPolicyOwner>(await WindowsPolicyOwner.TryAcquireAsync(() => mutex, TestContext.Current.CancellationToken));
        Assert.Equal(abandoned, owner.WasAbandoned);
        Assert.False(owner.Lost.IsCancellationRequested);
        await Task.Run(async () => await owner.DisposeAsync(), TestContext.Current.CancellationToken);
        Assert.True(owner.Lost.IsCancellationRequested);
        Assert.Equal(mutex.AcquiringThread, mutex.ReleasingThread);
        Assert.Equal(mutex.AcquiringThread, mutex.ClosingThread);
        Assert.Equal(1, mutex.Releases);
        await owner.DisposeAsync();
        Assert.Equal(1, mutex.Releases);
    }

    /// <summary>Contention closes the non-owning handle and returns no lease without releasing another thread's mutex.</summary>
    [Fact]
    public async Task BusyReturnsNoOwner()
    {
        var mutex = new TestMutex { Acquisition = null };
        Assert.Null(await WindowsPolicyOwner.TryAcquireAsync(() => mutex, TestContext.Current.CancellationToken));
        Assert.Equal(0, mutex.Releases);
        Assert.Equal(1, mutex.Closes);
    }

    /// <summary>Pre-cancelled acquisition does not create a mutex or worker-side native resource.</summary>
    [Fact]
    public async Task PreCancellationDoesNotOpen()
    {
        using var caller = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        caller.Cancel();
        var opened = false;
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => WindowsPolicyOwner.TryAcquireAsync(() =>
        {
            opened = true;
            return new TestMutex();
        }, caller.Token));
        Assert.False(opened);
    }

    /// <summary>Cancellation during a native boundary waits for cleanup and cannot leak newly acquired ownership.</summary>
    [Fact]
    public async Task CancelledAcquisitionReleasesLateOwner()
    {
        using var caller = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        var mutex = new TestMutex { BeforeAcquire = () => caller.Cancel() };
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => WindowsPolicyOwner.TryAcquireAsync(() => mutex, caller.Token));
        Assert.Equal(1, mutex.Releases);
        Assert.Equal(1, mutex.Closes);
    }

    /// <summary>The acquisition token does not become a hidden lifetime token after a successful handoff.</summary>
    [Fact]
    public async Task CancellationAfterHandoffDoesNotReleaseOwner()
    {
        using var caller = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        var mutex = new TestMutex();
        var owner = Assert.IsType<WindowsPolicyOwner>(await WindowsPolicyOwner.TryAcquireAsync(() => mutex, caller.Token));
        caller.Cancel();
        Assert.False(owner.Lost.IsCancellationRequested);
        Assert.Equal(0, mutex.Releases);
        await owner.DisposeAsync();
    }

    /// <summary>Open and acquire failures retain their original exceptions and close every created handle.</summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AcquisitionFailuresRemainObservable(bool opening)
    {
        var error = new IOException("Ownership failed.");
        var mutex = new TestMutex { BeforeAcquire = () => throw error };
        var failure = await Assert.ThrowsAsync<IOException>(() => WindowsPolicyOwner.TryAcquireAsync(() => opening ? throw error : mutex,
            TestContext.Current.CancellationToken));
        Assert.Same(error, failure);
        Assert.Equal(opening ? 0 : 1, mutex.Closes);
    }

    /// <summary>Failed release still attempts handle cleanup and cannot be retried as a confirmed owner.</summary>
    [Fact]
    public async Task ReleaseFailureRetainsUnconfirmedState()
    {
        var error = new IOException("Release failed.");
        var mutex = new TestMutex { ReleaseError = error };
        var owner = Assert.IsType<WindowsPolicyOwner>(await WindowsPolicyOwner.TryAcquireAsync(() => mutex, TestContext.Current.CancellationToken));
        Assert.Same(error, await Assert.ThrowsAsync<IOException>(() => owner.DisposeAsync().AsTask()));
        Assert.True(owner.Lost.IsCancellationRequested);
        Assert.Equal(1, mutex.Closes);
        Assert.Same(error, await Assert.ThrowsAsync<IOException>(() => owner.DisposeAsync().AsTask()));
        Assert.Equal(1, mutex.Releases);
    }

    /// <summary>A loss callback may await disposal without blocking the worker that must release the mutex.</summary>
    [Fact]
    public async Task ReentrantLossCallbackCannotDeadlockRelease()
    {
        var owner = Assert.IsType<WindowsPolicyOwner>(await WindowsPolicyOwner.TryAcquireAsync(() => new TestMutex(), TestContext.Current.CancellationToken));
        var called = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var registration = owner.Lost.Register(() =>
        {
            owner.DisposeAsync().AsTask().GetAwaiter().GetResult();
            called.SetResult();
        });
        await owner.DisposeAsync();
        await called.Task.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
    }

    /// <summary>Records native-shaped ownership operations and their executing threads.</summary>
    private sealed class TestMutex : IPolicyMutex
    {
        /// <summary>Gets or sets normal, abandoned, or busy acquisition.</summary>
        internal bool? Acquisition { get; init; } = false;
        /// <summary>Gets or sets a boundary hook before acquisition finishes.</summary>
        internal Action? BeforeAcquire { get; init; }
        /// <summary>Gets or sets a simulated release failure.</summary>
        internal Exception? ReleaseError { get; init; }
        /// <summary>Gets the acquiring thread identifier.</summary>
        internal int AcquiringThread { get; private set; }
        /// <summary>Gets the releasing thread identifier.</summary>
        internal int ReleasingThread { get; private set; }
        /// <summary>Gets the handle-cleanup thread identifier.</summary>
        internal int ClosingThread { get; private set; }
        /// <summary>Gets the number of release requests.</summary>
        internal int Releases { get; private set; }
        /// <summary>Gets the number of handle closes.</summary>
        internal int Closes { get; private set; }
        /// <summary>Records thread-affine acquisition and injects cancellation or failure.</summary>
        public bool? TryAcquire() { AcquiringThread = Environment.CurrentManagedThreadId; BeforeAcquire?.Invoke(); return Acquisition; }
        /// <summary>Records release on its executing thread.</summary>
        public void Release()
        {
            Releases++;
            ReleasingThread = Environment.CurrentManagedThreadId;
            if (ReleaseError is not null) throw ReleaseError;
        }
        /// <summary>Records cleanup independently of release success.</summary>
        public void Dispose() { Closes++; ClosingThread = Environment.CurrentManagedThreadId; }
    }
}
