using IPGuard.Application.Protection;
using Xunit;

namespace UnitTests;

/// <summary>Checks ownership loss and draining without operating-system policy changes.</summary>
public sealed class OwnedBlockPolicyTests
{
    /// <summary>Live ownership forwards ensure and readback through the existing backend.</summary>
    [Fact]
    public async Task LiveOwnerForwardsOperations()
    {
        using var owner = new Owner();
        var backend = new Backend();
        await using var policy = new OwnedBlockPolicy(backend, owner);
        await policy.EnsureAsync(TestContext.Current.CancellationToken);
        var report = await policy.InspectAsync(TestContext.Current.CancellationToken);
        Assert.Equal(BlockPolicyState.Present, report.State);
        Assert.Equal(2, backend.Calls);
        Assert.Equal(0, owner.Releases);
    }

    /// <summary>A missing or already retired ownership latch cannot represent authority.</summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void InvalidOwnershipIsRejected(bool cancelled)
    {
        using var owner = new Owner { MissingToken = !cancelled };
        if (cancelled) owner.Changed.Cancel();
        Assert.Throws<ArgumentException>(() => new OwnedBlockPolicy(new Backend(), owner));
    }

    /// <summary>Ownership loss prevents both new reads and writes before entering the backend.</summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task LostOwnerCannotEnterBackend(bool inspect)
    {
        using var owner = new Owner();
        var backend = new Backend();
        await using var policy = new OwnedBlockPolicy(backend, owner);
        owner.Changed.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => inspect
            ? policy.InspectAsync(TestContext.Current.CancellationToken) : policy.EnsureAsync(TestContext.Current.CancellationToken));
        Assert.Equal(0, backend.Calls);
    }

    /// <summary>A late native result is discarded when ownership is lost during the call.</summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task LossDuringOperationDiscardsResult(bool inspect)
    {
        using var owner = new Owner();
        var backend = new Backend { Run = _ => { owner.Changed.Cancel(); return Task.CompletedTask; } };
        await using var policy = new OwnedBlockPolicy(backend, owner);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => inspect
            ? policy.InspectAsync(TestContext.Current.CancellationToken) : policy.EnsureAsync(TestContext.Current.CancellationToken));
        Assert.Equal(1, backend.Calls);
    }

    /// <summary>Disposal rejects queued/new work and retains the owner until an uninterruptible call has returned.</summary>
    [Fact]
    public async Task DisposalDrainsBeforeReleasingOwner()
    {
        using var owner = new Owner();
        var entered = Signal();
        var release = Signal();
        var backend = new Backend { Run = async _ => { entered.SetResult(); await release.Task.WaitAsync(TestContext.Current.CancellationToken); } };
        var policy = new OwnedBlockPolicy(backend, owner);
        var active = policy.EnsureAsync(TestContext.Current.CancellationToken);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
        var queued = policy.InspectAsync(TestContext.Current.CancellationToken);
        var disposing = policy.DisposeAsync().AsTask();
        Assert.Equal(0, owner.Releases);
        Assert.False(disposing.IsCompleted);
        await Assert.ThrowsAsync<ObjectDisposedException>(() => policy.EnsureAsync(TestContext.Current.CancellationToken));
        release.SetResult();
        await Assert.ThrowsAsync<ObjectDisposedException>(() => active);
        await Assert.ThrowsAsync<ObjectDisposedException>(() => queued);
        await disposing;
        await policy.DisposeAsync();
        Assert.Equal(1, owner.Releases);
        Assert.Equal(1, backend.Calls);
    }

    /// <summary>Caller cancellation remains distinct from relinquishing machine-wide ownership.</summary>
    [Fact]
    public async Task CallerCancellationDoesNotReleaseOwner()
    {
        using var owner = new Owner();
        using var caller = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        var backend = new Backend { Run = _ => { caller.Cancel(); return Task.CompletedTask; } };
        await using var policy = new OwnedBlockPolicy(backend, owner);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => policy.EnsureAsync(caller.Token));
        Assert.False(owner.Lost.IsCancellationRequested);
        Assert.Equal(0, owner.Releases);
    }

    /// <summary>Original backend and release failures remain observable; release is never retried on an uncertain owner.</summary>
    [Fact]
    public async Task FailuresRemainObservable()
    {
        using var owner = new Owner();
        var write = new IOException("Backend failed.");
        var close = new IOException("Owner release failed.");
        var backend = new Backend { Run = _ => throw write };
        var policy = new OwnedBlockPolicy(backend, owner);
        Assert.Same(write, await Assert.ThrowsAsync<IOException>(() => policy.EnsureAsync(TestContext.Current.CancellationToken)));
        owner.CloseError = close;
        Assert.Same(close, await Assert.ThrowsAsync<IOException>(() => policy.DisposeAsync().AsTask()));
        Assert.Same(close, await Assert.ThrowsAsync<IOException>(() => policy.DisposeAsync().AsTask()));
        Assert.Equal(1, owner.Releases);
        owner.CloseError = null;
    }

    /// <summary>Creates a non-inline signal for deterministic policy interleavings.</summary>
    private static TaskCompletionSource Signal() => new(TaskCreationOptions.RunContinuationsAsynchronously);

    /// <summary>Supplies an independently controlled ownership latch.</summary>
    private sealed class Owner : IPolicyOwnership, IDisposable
    {
        /// <summary>Gets the permanent ownership-loss signal source.</summary>
        internal CancellationTokenSource Changed { get; } = new();
        /// <summary>Gets or sets an intentionally invalid ownership contract.</summary>
        internal bool MissingToken { get; init; }
        /// <summary>Gets the number of ownership-release requests.</summary>
        internal int Releases { get; private set; }
        /// <summary>Gets or sets a simulated native release failure.</summary>
        internal Exception? CloseError { get; set; }
        /// <summary>Gets the stable ownership token.</summary>
        public CancellationToken Lost => MissingToken ? default : Changed.Token;
        /// <summary>Records release and simulates the native owner's close result.</summary>
        public ValueTask DisposeAsync()
        {
            Releases++;
            Changed.Cancel();
            if (CloseError is not null) throw CloseError;
            return ValueTask.CompletedTask;
        }
        /// <summary>Disposes only fixture resources; lease release remains the wrapper's responsibility.</summary>
        public void Dispose() => Changed.Dispose();
    }

    /// <summary>Exposes controlled backend behavior without granting permits.</summary>
    private sealed class Backend : IBlockPolicy
    {
        /// <summary>Gets the number of actual backend entries.</summary>
        internal int Calls { get; private set; }
        /// <summary>Gets or sets an asynchronous native-shaped boundary.</summary>
        internal Func<CancellationToken, Task> Run { get; set; } = _ => Task.CompletedTask;
        /// <summary>Records one block write.</summary>
        public async Task EnsureAsync(CancellationToken cancellationToken) { Calls++; await Run(cancellationToken); }
        /// <summary>Records one block inspection.</summary>
        public async Task<BlockPolicyInspection> InspectAsync(CancellationToken cancellationToken)
        {
            Calls++;
            await Run(cancellationToken);
            return new(BlockPolicyState.Present, 4, 4);
        }
    }
}
