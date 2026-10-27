using IPGuard.Application.Network;
using IPGuard.Application.Protection;
using Xunit;

namespace UnitTests;

/// <summary>Checks blocking intent, honest inspection reports, and terminal reconciliation without WFP writes.</summary>
public sealed class BlockProtectionControllerTests
{
    private static readonly DateTimeOffset Now = NetworkCheckSetup.Start;

    /// <summary>Construction and initial capture perform no policy operation or diagnostics read.</summary>
    [Fact]
    public void ConstructionIsLazy()
    {
        var setup = new Setup();
        var state = setup.Controller.Capture();
        Assert.Equal(ProtectionPhase.NotStarted, state.Phase);
        Assert.Equal(ProtectionReason.NotStarted, state.Reason);
        Assert.Null(state.Policy);
        Assert.Empty(setup.Calls);
    }

    /// <summary>Matching objects remain distinct from effective blocking and require a current assessment.</summary>
    [Fact]
    public async Task ReconcileEnsuresThenReadsBack()
    {
        var setup = new Setup();
        var state = await setup.Controller.ReconcileAsync(TestContext.Current.CancellationToken);
        Assert.Equal(["refresh", "ensure", "inspect"], setup.Calls);
        Assert.Equal(ProtectionPhase.Running, state.Phase);
        Assert.Equal(ProtectionReason.AssessmentUnavailable, state.Reason);
        Assert.Equal(BlockPolicyState.Present, state.Policy!.State);
        Assert.Equal(Now, state.PolicyObservedAt);
        Assert.Null(state.Error);
    }

    /// <summary>Both US eligibility and country rejection retain a block-only application reason.</summary>
    [Theory]
    [InlineData("US", ProtectionReason.RouteUnverified)]
    [InlineData("CA", ProtectionReason.AddressRejected)]
    public async Task GeographicDecisionCannotOpenPermit(string country, ProtectionReason expected)
    {
        using var network = new NetworkCheckSetup { Country = country };
        using var monitor = new NetworkDiagnosticsMonitor(network.Collector(), TimeSpan.FromSeconds(30));
        var setup = new Setup();
        setup.Read = monitor.Capture;
        await setup.Controller.ReconcileAsync(TestContext.Current.CancellationToken);
        await WaitForAsync(() => monitor.Capture() is not null);
        var state = setup.Controller.Capture();
        Assert.Equal(expected, state.Reason);
        Assert.Equal(country, state.Network!.Snapshot.Assessment!.Evidence.Ipv4!.GeoIp!.CountryCode);
        Assert.Equal(BlockPolicyState.Present, state.Policy!.State);
        Assert.Equal(["refresh", "ensure", "inspect"], setup.Calls);
    }

    /// <summary>Retired evidence and diagnostics failures cannot retain a preliminary positive reason.</summary>
    [Theory]
    [InlineData("observation")]
    [InlineData("network")]
    [InlineData("throw")]
    [InlineData("error")]
    public async Task CaptureRejectsInvalidDiagnostics(string defect)
    {
        using var network = new NetworkCheckSetup();
        using var monitor = new NetworkDiagnosticsMonitor(network.Collector(), TimeSpan.FromSeconds(30));
        var setup = new Setup();
        await setup.Controller.ReconcileAsync(TestContext.Current.CancellationToken);
        await WaitForAsync(() => monitor.Capture() is not null);
        var observation = monitor.Capture()!;
        setup.Read = () => observation;
        if (defect == "observation") monitor.Refresh();
        if (defect == "network") network.Changed.Cancel();
        if (defect == "throw") setup.Read = () => throw new IOException("Diagnostics read failed.");
        if (defect == "error") setup.DiagnosticError = new IOException("Observer failed.");
        var state = setup.Controller.Capture();
        Assert.Equal(ProtectionReason.AssessmentUnavailable, state.Reason);
        Assert.Null(state.Network);
        Assert.Equal(BlockPolicyState.Present, state.Policy!.State);
    }

    /// <summary>Readback rather than successful installation determines object presence.</summary>
    [Theory]
    [InlineData(BlockPolicyState.Unknown)]
    [InlineData(BlockPolicyState.Incomplete)]
    public async Task UnconfirmedReadbackRemainsUnavailable(BlockPolicyState state)
    {
        var setup = new Setup { Inspection = new(state, 4, 0) };
        var result = await setup.Controller.ReconcileAsync(TestContext.Current.CancellationToken);
        Assert.Equal(ProtectionReason.PolicyUnavailable, result.Reason);
        Assert.Equal(state, result.Policy!.State);
    }

    /// <summary>A malformed backend result cannot be promoted to a confirmed baseline.</summary>
    [Theory]
    [InlineData("null")]
    [InlineData("count")]
    [InlineData("zero")]
    [InlineData("enum")]
    [InlineData("error")]
    public async Task InvalidInspectionIsRejected(string defect)
    {
        var setup = new Setup
        {
            Inspection = defect switch
            {
                "null" => null!,
                "count" => new(BlockPolicyState.Present, 4, 3),
                "zero" => new(BlockPolicyState.Present, 0, 0),
                "enum" => new((BlockPolicyState)999, 4, 4),
                _ => new(BlockPolicyState.Present, 4, 4, new IOException("Invalid success."))
            }
        };
        var result = await setup.Controller.ReconcileAsync(TestContext.Current.CancellationToken);
        Assert.Equal(ProtectionReason.PolicyUnavailable, result.Reason);
        Assert.Null(result.Policy);
        Assert.IsType<InvalidDataException>(result.Error);
    }

    /// <summary>Operational failures retain the original exception and never reuse an earlier inspection.</summary>
    [Theory]
    [InlineData("ensure")]
    [InlineData("inspect")]
    [InlineData("clock")]
    public async Task FailureRetiresPreviousReadback(string boundary)
    {
        var setup = new Setup();
        await setup.Controller.ReconcileAsync(TestContext.Current.CancellationToken);
        var error = new IOException("Policy failed.");
        if (boundary == "ensure") setup.Ensure = _ => throw error;
        if (boundary == "inspect") setup.Inspect = _ => throw error;
        if (boundary == "clock") setup.Clock = () => throw error;
        var result = await setup.Controller.ReconcileAsync(TestContext.Current.CancellationToken);
        Assert.Equal(ProtectionReason.PolicyUnavailable, result.Reason);
        Assert.Null(result.Policy);
        Assert.Null(result.PolicyObservedAt);
        Assert.Same(error, result.Error);
    }

    /// <summary>Diagnostics refresh failure does not prevent required baseline work or misreport confirmed objects.</summary>
    [Fact]
    public async Task RefreshFailureStillReconcilesBaseline()
    {
        var setup = new Setup();
        var error = new IOException("Refresh failed.");
        setup.Refresh = () => throw error;
        var result = await setup.Controller.ReconcileAsync(TestContext.Current.CancellationToken);
        Assert.Equal(ProtectionReason.AssessmentUnavailable, result.Reason);
        Assert.Equal(BlockPolicyState.Present, result.Policy!.State);
        Assert.Same(error, result.Error);
        Assert.Equal(["refresh", "ensure", "inspect"], setup.Calls);
    }

    /// <summary>Concurrent reconciliation calls never overlap policy operations.</summary>
    [Fact]
    public async Task PolicyOperationsAreSerialized()
    {
        var setup = new Setup();
        var entered = Signal();
        var release = Signal();
        var calls = 0;
        setup.Ensure = async _ =>
        {
            if (Interlocked.Increment(ref calls) == 1) { entered.SetResult(); await release.Task.WaitAsync(TestContext.Current.CancellationToken); }
        };
        var first = setup.Controller.ReconcileAsync(TestContext.Current.CancellationToken);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
        var second = setup.Controller.ReconcileAsync(TestContext.Current.CancellationToken);
        Assert.Equal(1, calls);
        Assert.Equal(ProtectionPhase.Reconciling, setup.Controller.Capture().Phase);
        Assert.Null(setup.Controller.Capture().Policy);
        release.SetResult();
        await Task.WhenAll(first, second);
        Assert.Equal(2, calls);
    }

    /// <summary>Caller cancellation propagates without leaving an old policy inspection usable.</summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ReconcileCancellationPropagates(bool during)
    {
        var setup = new Setup();
        using var caller = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        if (!during) caller.Cancel();
        setup.Ensure = token => { caller.Cancel(); return Task.CompletedTask; };
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => setup.Controller.ReconcileAsync(caller.Token));
        Assert.Null(setup.Controller.Capture().Policy);
    }

    /// <summary>Stop performs one final ensure/readback without uninstalling or refreshing diagnostics, and is terminal.</summary>
    [Fact]
    public async Task StopPreservesBaselineAndCannotRestart()
    {
        var setup = new Setup();
        await setup.Controller.ReconcileAsync(TestContext.Current.CancellationToken);
        setup.Calls.Clear();
        var state = await setup.Controller.StopAsync(TestContext.Current.CancellationToken);
        Assert.Equal(ProtectionPhase.Stopped, state.Phase);
        Assert.Equal(ProtectionReason.Stopped, state.Reason);
        Assert.Equal(BlockPolicyState.Present, state.Policy!.State);
        Assert.Null(state.Network);
        Assert.Equal(["ensure", "inspect"], setup.Calls);
        Assert.Same(state, await setup.Controller.StopAsync(TestContext.Current.CancellationToken));
        await Assert.ThrowsAsync<ObjectDisposedException>(() => setup.Controller.ReconcileAsync(TestContext.Current.CancellationToken));
    }

    /// <summary>An in-flight ensure may finish, but no late result can republish a running session after exit.</summary>
    [Fact]
    public async Task StopRetiresPendingInspectionImmediately()
    {
        var setup = new Setup();
        var entered = Signal();
        var release = Signal();
        var calls = 0;
        setup.Ensure = async _ =>
        {
            if (Interlocked.Increment(ref calls) == 1) { entered.SetResult(); await release.Task.WaitAsync(TestContext.Current.CancellationToken); }
        };
        var pending = setup.Controller.ReconcileAsync(TestContext.Current.CancellationToken);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
        var stop = setup.Controller.StopAsync(TestContext.Current.CancellationToken);
        Assert.Equal(ProtectionPhase.Stopping, setup.Controller.Capture().Phase);
        Assert.Null(setup.Controller.Capture().Policy);
        release.SetResult();
        await pending;
        var final = await stop;
        Assert.Equal(ProtectionPhase.Stopped, final.Phase);
        Assert.Equal(2, calls);
        Assert.Equal(ProtectionPhase.Stopped, setup.Controller.Capture().Phase);
    }

    /// <summary>Cancelling a shutdown waiter cannot abandon the controller-owned final baseline reconciliation.</summary>
    [Fact]
    public async Task StopWaitCancellationDoesNotCancelCleanup()
    {
        var setup = new Setup();
        var entered = Signal();
        var release = Signal();
        setup.Ensure = async token =>
        {
            Assert.False(token.CanBeCanceled);
            entered.SetResult();
            await release.Task.WaitAsync(TestContext.Current.CancellationToken);
        };
        using var caller = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        var waiting = setup.Controller.StopAsync(caller.Token);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
        caller.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => waiting);
        Assert.Equal(ProtectionPhase.Stopping, setup.Controller.Capture().Phase);
        release.SetResult();
        Assert.Equal(ProtectionReason.Stopped, (await setup.Controller.StopAsync(TestContext.Current.CancellationToken)).Reason);
    }

    /// <summary>A diagnostic refresh finishing after exit cannot contaminate the final policy-only shutdown result.</summary>
    [Fact]
    public async Task StopIgnoresLateRefreshFailure()
    {
        var setup = new Setup();
        Task<ProtectionSnapshot>? stop = null;
        setup.Refresh = () =>
        {
            stop = setup.Controller.StopAsync(TestContext.Current.CancellationToken);
            throw new IOException("Retired refresh failed.");
        };
        await setup.Controller.ReconcileAsync(TestContext.Current.CancellationToken);
        var state = await stop!;
        Assert.Equal(ProtectionReason.Stopped, state.Reason);
        Assert.Null(state.Error);
        Assert.Equal(BlockPolicyState.Present, state.Policy!.State);
    }

    /// <summary>Shutdown readback runs even after ensure failure and preserves both errors without declaring protection verified.</summary>
    [Fact]
    public async Task StopPreservesEnsureAndReadbackFailures()
    {
        var setup = new Setup();
        var first = new IOException("Ensure failed.");
        var second = new IOException("Inspect failed.");
        setup.Ensure = _ => throw first;
        setup.Inspect = _ => throw second;
        var state = await setup.Controller.StopAsync(TestContext.Current.CancellationToken);
        Assert.Equal(ProtectionPhase.Stopped, state.Phase);
        Assert.Equal(ProtectionReason.PolicyUnavailable, state.Reason);
        Assert.Null(state.Policy);
        var error = Assert.IsType<AggregateException>(state.Error);
        Assert.Equal([first, second], error.InnerExceptions);
        Assert.Equal(["ensure", "inspect"], setup.Calls);
    }

    /// <summary>Creates a non-inline barrier for policy interleavings.</summary>
    private static TaskCompletionSource Signal() => new(TaskCreationOptions.RunContinuationsAsynchronously);

    /// <summary>Waits for cached state under a bounded watchdog without changing the diagnostic clock.</summary>
    private static async Task WaitForAsync(Func<bool> predicate)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(10));
        while (!predicate()) await Task.Delay(1, timeout.Token);
    }

    /// <summary>Composes controlled policy and cached diagnostics without platform inheritance.</summary>
    private sealed class Setup : IBlockPolicy, INetworkDiagnosticsReader
    {
        /// <summary>Creates a lazy controller with an explicit UTC clock.</summary>
        internal Setup() => Controller = new(this, this, () => Clock());

        /// <summary>Gets the coordinator under test.</summary>
        internal BlockProtectionController Controller { get; }

        /// <summary>Gets recorded policy and refresh operations.</summary>
        internal List<string> Calls { get; } = [];

        /// <summary>Gets or sets controlled baseline work.</summary>
        internal Func<CancellationToken, Task> Ensure { get; set; } = _ => Task.CompletedTask;

        /// <summary>Gets or sets controlled readback work.</summary>
        internal Func<CancellationToken, Task>? Inspect { get; set; }

        /// <summary>Gets or sets the returned object snapshot.</summary>
        internal BlockPolicyInspection Inspection { get; set; } = new(BlockPolicyState.Present, 4, 4);

        /// <summary>Gets or sets the cache capture boundary.</summary>
        internal Func<NetworkDiagnosticsObservation?> Read { get; set; } = () => null;

        /// <summary>Gets or sets refresh behavior.</summary>
        internal Action Refresh { get; set; } = () => { };

        /// <summary>Gets or sets the inspection clock.</summary>
        internal Func<DateTimeOffset> Clock { get; set; } = () => Now;

        /// <summary>Gets or sets a diagnostic observer failure.</summary>
        internal Exception? DiagnosticError { get; set; }

        /// <summary>Records persistent baseline application.</summary>
        public async Task EnsureAsync(CancellationToken cancellationToken) { Calls.Add("ensure"); await Ensure(cancellationToken); }

        /// <summary>Records actual readback independently of ensure success.</summary>
        public async Task<BlockPolicyInspection> InspectAsync(CancellationToken cancellationToken)
        {
            Calls.Add("inspect");
            if (Inspect is not null) await Inspect(cancellationToken);
            return Inspection;
        }

        /// <summary>Returns only controlled cached diagnostics.</summary>
        NetworkDiagnosticsObservation? INetworkDiagnosticsReader.Capture() => Read();

        /// <summary>Records refresh separately from baseline application.</summary>
        void INetworkDiagnosticsReader.Refresh() { Calls.Add("refresh"); Refresh(); }

        /// <summary>Gets the unavailable cache status used when no controlled observation exists.</summary>
        public NetworkDiagnosticsStatus? LastStatus => NetworkDiagnosticsStatus.NetworkUnavailable;

        /// <summary>Gets no unavailable child outcome in the default scenario.</summary>
        public NetworkDiagnosticsResult? LastFailure => null;

        /// <summary>Gets the controlled diagnostics failure.</summary>
        public Exception? LastError => DiagnosticError;
    }
}
