using IPGuard.Application.Network;
using IPGuard.Application.Protection;
using Xunit;
using Microsoft.Extensions.Time.Testing;

namespace UnitTests;

/// <summary>Checks terminal policy work and cleanup ordering without native policy changes.</summary>
public sealed class ProtectionRuntimeTests
{
    /// <summary>A tick reconciles persistent blocks independently of GUI status polling.</summary>
    [Fact]
    public async Task PeriodicCheckReconcilesWithoutGuiCommand()
    {
        using var setup = new Setup();
        var time = new FakeTimeProvider();
        var entered = Signal();
        setup.Ensure = _ => { entered.TrySetResult(); return Task.CompletedTask; };
        await using var runtime = setup.Create();
        runtime.StartPeriodicChecks(TimeSpan.FromSeconds(1), time);
        Assert.Empty(setup.Events);
        time.Advance(TimeSpan.FromSeconds(1));
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
        var final = await runtime.StopAsync(TestContext.Current.CancellationToken);
        Assert.Equal(BlockPolicyState.Present, final.Policy?.State);
        Assert.True(setup.Events.Count(item => item == "ensure") >= 2);
        Assert.Equal("owner", setup.Events[^1]);
    }

    /// <summary>Terminal cleanup drains an executing periodic native-shaped call before releasing ownership.</summary>
    [Fact]
    public async Task ShutdownDrainsPeriodicCall()
    {
        using var setup = new Setup();
        var time = new FakeTimeProvider();
        var entered = Signal();
        var release = Signal();
        setup.Ensure = async _ => { entered.TrySetResult(); await release.Task; };
        await using var runtime = setup.Create();
        try
        {
            runtime.StartPeriodicChecks(TimeSpan.FromSeconds(1), time);
            time.Advance(TimeSpan.FromSeconds(1));
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
            var stopping = runtime.StopAsync(TestContext.Current.CancellationToken);
            Assert.False(stopping.IsCompleted);
            Assert.DoesNotContain("owner", setup.Events);
        }
        finally { release.TrySetResult(); }
        await runtime.StopAsync(TestContext.Current.CancellationToken);
        Assert.Equal("owner", setup.Events[^1]);
        int count = setup.Events.Count;
        time.Advance(TimeSpan.FromMinutes(1));
        Assert.Equal(count, setup.Events.Count);
    }

    /// <summary>The scheduler has one lifetime and cannot be restarted after terminal cleanup.</summary>
    [Fact]
    public async Task PeriodicChecksCannotBeDuplicatedOrRestarted()
    {
        using var setup = new Setup();
        await using var runtime = setup.Create();
        runtime.StartPeriodicChecks(TimeSpan.FromSeconds(1), new FakeTimeProvider());
        Assert.Throws<InvalidOperationException>(() => runtime.StartPeriodicChecks(TimeSpan.FromSeconds(1)));
        await runtime.StopAsync(TestContext.Current.CancellationToken);
        Assert.Throws<ObjectDisposedException>(() => runtime.StartPeriodicChecks(TimeSpan.FromSeconds(1)));
    }

    /// <summary>Unbounded or overly frequent scheduling is rejected without starting native work.</summary>
    [Theory]
    [InlineData(0)]
    [InlineData(0.5)]
    [InlineData(3601)]
    [InlineData(-1)]
    public async Task InvalidPeriodicIntervalIsRejected(double seconds)
    {
        using var setup = new Setup();
        await using var runtime = setup.Create();
        Assert.Throws<ArgumentOutOfRangeException>(() => runtime.StartPeriodicChecks(TimeSpan.FromSeconds(seconds)));
        Assert.Empty(setup.Events);
    }

    /// <summary>Final block ensure and readback precede diagnostic cleanup and exclusive owner release.</summary>
    [Fact]
    public async Task StopPreservesBaselineAndReleasesOwnerLast()
    {
        using var setup = new Setup();
        var runtime = setup.Create();
        await runtime.RecheckAsync(TestContext.Current.CancellationToken);
        setup.Events.Clear();
        var final = await runtime.StopAsync(TestContext.Current.CancellationToken);
        Assert.Equal(new[] { "ensure", "inspect", "diagnostics", "owner" }, setup.Events);
        Assert.Equal(ProtectionPhase.Stopped, final.Phase);
        Assert.Equal(BlockPolicyState.Present, final.Policy?.State);
        Assert.Null(final.Error);
        await runtime.StopAsync(TestContext.Current.CancellationToken);
        await runtime.DisposeAsync();
        Assert.Equal(4, setup.Events.Count);
    }

    /// <summary>Cancelling a shutdown waiter cannot cancel final policy work or release a still-used owner.</summary>
    [Fact]
    public async Task CancelledWaiterDoesNotCancelCleanup()
    {
        using var setup = new Setup();
        var entered = Signal();
        var release = Signal();
        setup.Ensure = async token => { entered.SetResult(); await release.Task; Assert.False(token.IsCancellationRequested); };
        var runtime = setup.Create();
        using var waiter = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        var stopping = runtime.StopAsync(waiter.Token);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
        waiter.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => stopping);
        Assert.DoesNotContain("owner", setup.Events);
        Assert.Equal(ProtectionPhase.Stopping, runtime.Capture().Phase);
        await Assert.ThrowsAsync<ObjectDisposedException>(() => runtime.RecheckAsync(TestContext.Current.CancellationToken));
        release.SetResult();
        await runtime.StopAsync(TestContext.Current.CancellationToken);
        Assert.Equal("owner", setup.Events[^1]);
    }

    /// <summary>Failures in each cleanup boundary remain observable and do not suppress later cleanup attempts.</summary>
    [Fact]
    public async Task CleanupFailuresArePreserved()
    {
        using var setup = new Setup();
        var policy = new IOException("Policy failed.");
        var diagnostics = new IOException("Diagnostics failed.");
        var owner = new IOException("Owner failed.");
        setup.Ensure = _ => throw policy;
        setup.DiagnosticError = diagnostics;
        setup.OwnerError = owner;
        var runtime = setup.Create();
        var final = await runtime.StopAsync(TestContext.Current.CancellationToken);
        var errors = Assert.IsType<AggregateException>(final.Error).Flatten().InnerExceptions;
        Assert.Contains(policy, errors);
        Assert.Contains(diagnostics, errors);
        Assert.Contains(owner, errors);
        Assert.Equal(new[] { "ensure", "inspect", "diagnostics", "owner" }, setup.Events);
        await Assert.ThrowsAsync<AggregateException>(() => runtime.DisposeAsync().AsTask());
        Assert.Equal(4, setup.Events.Count);
    }

    /// <summary>Loss of the exclusive owner retires old successful inspection data without another backend call.</summary>
    [Fact]
    public async Task OwnershipLossRetiresCachedPolicy()
    {
        using var setup = new Setup();
        var runtime = setup.Create();
        await runtime.RecheckAsync(TestContext.Current.CancellationToken);
        setup.Changed.Cancel();
        var report = runtime.Capture();
        Assert.Null(report.Policy);
        Assert.Null(report.PolicyObservedAt);
        Assert.Equal(ProtectionReason.PolicyUnavailable, report.Reason);
        Assert.Equal(2, setup.Events.Count);
        var final = await runtime.StopAsync(TestContext.Current.CancellationToken);
        Assert.NotNull(final.Error);
        Assert.Equal("owner", setup.Events[^1]);
    }

    /// <summary>A native call finishes before terminal reconciliation and ownership release.</summary>
    [Fact]
    public async Task StopDrainsAnInFlightRecheck()
    {
        using var setup = new Setup();
        var entered = Signal();
        var release = Signal();
        var calls = 0;
        setup.Ensure = async _ => { if (Interlocked.Increment(ref calls) == 1) { entered.SetResult(); await release.Task; } };
        var runtime = setup.Create();
        var checking = runtime.RecheckAsync(TestContext.Current.CancellationToken);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
        var stopping = runtime.StopAsync(TestContext.Current.CancellationToken);
        Assert.DoesNotContain("owner", setup.Events);
        release.SetResult();
        await checking;
        await stopping;
        Assert.Equal(new[] { "ensure", "ensure", "inspect", "diagnostics", "owner" }, setup.Events);
    }

    /// <summary>A cached diagnostic reader may request shutdown on another thread without deadlocking Capture.</summary>
    [Fact]
    public async Task CaptureDoesNotHoldRuntimeGateAcrossReader()
    {
        using var setup = new Setup();
        var runtime = setup.Create();
        await runtime.RecheckAsync(TestContext.Current.CancellationToken);
        setup.Read = () =>
        {
            // Capture is synchronous; this boundary deliberately waits for a reentrant host-side exit request.
            Task.Run(() => runtime.StopAsync(TestContext.Current.CancellationToken), TestContext.Current.CancellationToken)
                .WaitAsync(TimeSpan.FromSeconds(3), TestContext.Current.CancellationToken).GetAwaiter().GetResult();
            return null;
        };
        try { Assert.Equal(ProtectionPhase.Stopped, runtime.Capture().Phase); }
        finally { await runtime.StopAsync(TestContext.Current.CancellationToken); }
    }

    /// <summary>Creates a signal whose continuations cannot run inline inside a fake backend.</summary>
    private static TaskCompletionSource Signal() => new(TaskCreationOptions.RunContinuationsAsynchronously);

    /// <summary>Composes controlled native-shaped boundaries without class inheritance.</summary>
    private sealed class Setup : IBlockPolicy, IPolicyOwnership, INetworkDiagnosticsReader, IDisposable
    {
        /// <summary>Gets ordered significant lifecycle effects.</summary>
        internal List<string> Events { get; } = [];
        /// <summary>Gets the externally controlled ownership retirement source.</summary>
        internal CancellationTokenSource Changed { get; } = new();
        /// <summary>Gets or sets the uninterruptible-shaped block write boundary.</summary>
        internal Func<CancellationToken, Task> Ensure { get; set; } = _ => Task.CompletedTask;
        /// <summary>Gets or sets a diagnostic cleanup failure.</summary>
        internal Exception? DiagnosticError { get; set; }
        /// <summary>Gets or sets an ownership cleanup failure.</summary>
        internal Exception? OwnerError { get; set; }
        /// <summary>Gets or sets a synchronous cached-reader callback for reentrant host behavior.</summary>
        internal Func<NetworkDiagnosticsObservation?>? Read { get; set; }
        /// <summary>Gets the stable ownership retirement token.</summary>
        public CancellationToken Lost => Changed.Token;
        /// <summary>Gets no completed diagnostic attempt in this fixture.</summary>
        public NetworkDiagnosticsStatus? LastStatus => null;
        /// <summary>Gets no source failure in this fixture.</summary>
        public NetworkDiagnosticsResult? LastFailure => null;
        /// <summary>Gets no diagnostic read failure in this fixture.</summary>
        public Exception? LastError => null;
        /// <summary>Creates the real runtime with explicit diagnostic lifetime composition.</summary>
        internal ProtectionRuntime Create() => new(this, this, this, CloseDiagnostics);
        /// <summary>Records persistent block work.</summary>
        public Task EnsureAsync(CancellationToken cancellationToken) { Events.Add("ensure"); return Ensure(cancellationToken); }
        /// <summary>Returns an object observation without claiming effective filtering.</summary>
        public Task<BlockPolicyInspection> InspectAsync(CancellationToken cancellationToken)
        { Events.Add("inspect"); return Task.FromResult(new BlockPolicyInspection(BlockPolicyState.Present, 4, 4)); }
        /// <summary>Provides no current geographic evidence.</summary>
        public NetworkDiagnosticsObservation? Capture() => Read?.Invoke();
        /// <summary>Accepts a refresh request without creating a second scheduler.</summary>
        public void Refresh() { }
        /// <summary>Records owner release independently of diagnostic or block failures.</summary>
        public ValueTask DisposeAsync()
        {
            Events.Add("owner"); Changed.Cancel();
            if (OwnerError is not null) throw OwnerError;
            return ValueTask.CompletedTask;
        }
        /// <summary>Records cleanup while ownership is still held.</summary>
        private ValueTask CloseDiagnostics()
        {
            Events.Add("diagnostics"); Assert.DoesNotContain("owner", Events);
            if (DiagnosticError is not null) throw DiagnosticError;
            return ValueTask.CompletedTask;
        }
        /// <summary>Releases only fixture resources after runtime completion.</summary>
        public void Dispose() => Changed.Dispose();
    }
}
