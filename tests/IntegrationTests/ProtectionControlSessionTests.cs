using System.Buffers.Binary;
using System.Diagnostics;
using IPGuard.Application.Network;
using IPGuard.Application.Protection;
using IPGuard.Infrastructure.Control;
using IPGuard.Windows.Control;
using Xunit;

namespace IntegrationTests;

/// <summary>Combines real bound pipes, framing, runtime, and controller with a non-native block backend.</summary>
public sealed class ProtectionControlSessionTests
{
    /// <summary>Status is read-only, recheck ensures blocks, and stop acknowledges only completed final cleanup.</summary>
    [Fact]
    public async Task CommandsUseSharedRuntimeAndStopSafely()
    {
        using var fixture = new Fixture();
        await using var pair = await Pair.CreateAsync(fixture.Token);
        var runtime = fixture.CreateRuntime();
        var serving = ProtectionControlServer.RunAsync(pair.Helper, runtime, TimeSpan.FromSeconds(10), fixture.Token);
        await using var client = new ProtectionControlClient(pair.Gui, TimeSpan.FromSeconds(10));
        var status = await client.SendAsync(ProtectionCommand.Status, fixture.Token);
        Assert.Equal(BlockPolicyState.Present, status.PolicyState);
        Assert.Equal(ProtectionReason.AssessmentUnavailable, status.Reason);
        Assert.Equal(1, fixture.Writes);
        await client.SendAsync(ProtectionCommand.Recheck, fixture.Token);
        Assert.Equal(2, fixture.Writes);
        var stopped = await client.SendAsync(ProtectionCommand.Stop, fixture.Token);
        Assert.Equal(ProtectionPhase.Stopped, stopped.Phase);
        Assert.True(fixture.DiagnosticsClosed);
        Assert.Equal(1, fixture.OwnerReleases);
        var completion = await serving.WaitAsync(fixture.Token);
        Assert.Null(completion.Error);
        Assert.Equal(3, fixture.Writes);
        await Assert.ThrowsAsync<ObjectDisposedException>(() => client.SendAsync(ProtectionCommand.Status, fixture.Token));
    }

    /// <summary>GUI disappearance and malformed input both finish persistent blocking before releasing ownership.</summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task DisconnectOrMalformedInputStopsRuntime(bool malformed)
    {
        using var fixture = new Fixture();
        await using var pair = await Pair.CreateAsync(fixture.Token);
        var runtime = fixture.CreateRuntime();
        var serving = ProtectionControlServer.RunAsync(pair.Helper, runtime, TimeSpan.FromSeconds(10), fixture.Token);
        if (malformed)
        {
            var header = new byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(header, uint.MaxValue);
            await pair.Gui.WriteAsync(header, fixture.Token);
        }
        else await pair.Gui.DisposeAsync();
        var completion = await serving.WaitAsync(fixture.Token);
        Assert.NotNull(completion.Error);
        Assert.Equal(ProtectionPhase.Stopped, completion.Shutdown.Phase);
        Assert.Equal(BlockPolicyState.Present, completion.Shutdown.Policy?.State);
        Assert.Equal(2, fixture.Writes);
        Assert.Equal(1, fixture.OwnerReleases);
    }

    /// <summary>A stalled GUI cannot keep the helper command session alive beyond its input deadline.</summary>
    [Fact]
    public async Task IdleDeadlineStopsRuntime()
    {
        using var fixture = new Fixture();
        await using var pair = await Pair.CreateAsync(fixture.Token);
        var completion = await ProtectionControlServer.RunAsync(pair.Helper, fixture.CreateRuntime(), TimeSpan.FromMilliseconds(250), fixture.Token);
        Assert.IsAssignableFrom<OperationCanceledException>(completion.Error);
        Assert.Equal(1, fixture.OwnerReleases);
        Assert.Equal(2, fixture.Writes);
    }

    /// <summary>Client timeout closes the ambiguous transaction; a late reply cannot satisfy another request.</summary>
    [Fact]
    public async Task ClientTimeoutRetiresConnection()
    {
        using var fixture = new Fixture();
        await using var pair = await Pair.CreateAsync(fixture.Token);
        await using var client = new ProtectionControlClient(pair.Gui, TimeSpan.FromMilliseconds(100));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => client.SendAsync(ProtectionCommand.Status, fixture.Token));
        await Assert.ThrowsAsync<ObjectDisposedException>(() => client.SendAsync(ProtectionCommand.Status, fixture.Token));
    }

    /// <summary>Cancellation while queued does not abort the preceding exchange or corrupt the next frame.</summary>
    [Fact]
    public async Task QueuedCancellationDoesNotRetireHealthyConnection()
    {
        using var fixture = new Fixture();
        await using var pair = await Pair.CreateAsync(fixture.Token);
        await using var client = new ProtectionControlClient(pair.Gui, TimeSpan.FromSeconds(10));
        var first = client.SendAsync(ProtectionCommand.Status, fixture.Token);
        Assert.Equal(ProtectionCommand.Status, await ProtectionControlProtocol.ReadCommandAsync(pair.Helper, fixture.Token));
        using var queued = CancellationTokenSource.CreateLinkedTokenSource(fixture.Token);
        var cancelled = client.SendAsync(ProtectionCommand.Recheck, queued.Token);
        queued.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => cancelled);
        await ProtectionControlProtocol.WriteReportAsync(pair.Helper, Unavailable(), fixture.Token);
        await first;
        var next = client.SendAsync(ProtectionCommand.Status, fixture.Token);
        Assert.Equal(ProtectionCommand.Status, await ProtectionControlProtocol.ReadCommandAsync(pair.Helper, fixture.Token));
        await ProtectionControlProtocol.WriteReportAsync(pair.Helper, Unavailable(), fixture.Token);
        await next;
    }

    /// <summary>Explicit disposal closes active I/O, rejects queued calls, and waits for the active transaction to drain.</summary>
    [Fact]
    public async Task DisposalInterruptsActiveExchange()
    {
        using var fixture = new Fixture();
        await using var pair = await Pair.CreateAsync(fixture.Token);
        var client = new ProtectionControlClient(pair.Gui, TimeSpan.FromSeconds(10));
        var active = client.SendAsync(ProtectionCommand.Status, fixture.Token);
        await ProtectionControlProtocol.ReadCommandAsync(pair.Helper, fixture.Token);
        var queued = client.SendAsync(ProtectionCommand.Recheck, fixture.Token);
        await client.DisposeAsync();
        Assert.NotNull(await Record.ExceptionAsync(() => active));
        await Assert.ThrowsAsync<ObjectDisposedException>(() => queued);
    }

    /// <summary>Shutdown failures are present in both the terminal report and the host completion result.</summary>
    [Fact]
    public async Task CleanupFailureIsNotAcknowledgedAsSuccess()
    {
        using var fixture = new Fixture { CloseError = new IOException("Diagnostic close failed.") };
        await using var pair = await Pair.CreateAsync(fixture.Token);
        var serving = ProtectionControlServer.RunAsync(pair.Helper, fixture.CreateRuntime(), TimeSpan.FromSeconds(10), fixture.Token);
        await using var client = new ProtectionControlClient(pair.Gui, TimeSpan.FromSeconds(10));
        var report = await client.SendAsync(ProtectionCommand.Stop, fixture.Token);
        Assert.True(report.HasError);
        Assert.Equal(ProtectionPhase.Stopped, report.Phase);
        Assert.Same(fixture.CloseError, (await serving).Error);
        Assert.Equal(1, fixture.OwnerReleases);
    }

    /// <summary>A nonterminal reply to Stop cannot be shown as a completed helper shutdown or reused for another call.</summary>
    [Fact]
    public async Task PrematureStopAcknowledgementRetiresClient()
    {
        using var fixture = new Fixture();
        await using var pair = await Pair.CreateAsync(fixture.Token);
        await using var client = new ProtectionControlClient(pair.Gui, TimeSpan.FromSeconds(10));
        var stopping = client.SendAsync(ProtectionCommand.Stop, fixture.Token);
        Assert.Equal(ProtectionCommand.Stop, await ProtectionControlProtocol.ReadCommandAsync(pair.Helper, fixture.Token));
        await ProtectionControlProtocol.WriteReportAsync(pair.Helper, Unavailable(), fixture.Token);
        await Assert.ThrowsAsync<InvalidDataException>(() => stopping);
        await Assert.ThrowsAsync<ObjectDisposedException>(() => client.SendAsync(ProtectionCommand.Status, fixture.Token));
    }

    /// <summary>Returns a report that makes no geographic or filtering success claim.</summary>
    private static ProtectionControlReport Unavailable()
        => new(ProtectionPhase.Running, ProtectionReason.PolicyUnavailable, null, 0, 0, null, true);

    /// <summary>Owns a real GUI-server/helper-client pipe pair after mutual process binding.</summary>
    private sealed class Pair : IAsyncDisposable
    {
        /// <summary>Captures transferred endpoint ownership for test cleanup.</summary>
        private Pair(Stream gui, Stream helper) { Gui = gui; Helper = helper; }
        /// <summary>Gets the GUI endpoint that sends logical commands.</summary>
        internal Stream Gui { get; }
        /// <summary>Gets the helper endpoint that serves logical commands.</summary>
        internal Stream Helper { get; }
        /// <summary>Creates unique local endpoints without elevation or WFP calls.</summary>
        internal static async Task<Pair> CreateAsync(CancellationToken token)
        {
            using var process = Process.GetCurrentProcess();
            using var listener = WindowsControlPipe.Create();
            var accepting = listener.AcceptAsync(process, TimeSpan.FromSeconds(10), token);
            var helper = await WindowsControlPipe.ConnectAsync(listener.Name, process, TimeSpan.FromSeconds(10), token);
            try { return new(await accepting, helper); }
            catch { await helper.DisposeAsync(); throw; }
        }
        /// <summary>Closes only these test-owned pipe handles.</summary>
        public async ValueTask DisposeAsync() { await Gui.DisposeAsync(); await Helper.DisposeAsync(); }
    }

    /// <summary>Supplies a bounded test lifetime and controlled non-native policy and diagnostic boundaries.</summary>
    private sealed class Fixture : IBlockPolicy, IPolicyOwnership, INetworkDiagnosticsReader, IDisposable
    {
        private readonly CancellationTokenSource deadline = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        private readonly CancellationTokenSource lost = new();
        /// <summary>Bounds the complete integration scenario independently of command deadlines.</summary>
        internal Fixture() => deadline.CancelAfter(TimeSpan.FromSeconds(20));
        /// <summary>Gets the bounded scenario token.</summary>
        internal CancellationToken Token => deadline.Token;
        /// <summary>Gets how many persistent block writes were requested.</summary>
        internal int Writes { get; private set; }
        /// <summary>Gets the number of owner release attempts.</summary>
        internal int OwnerReleases { get; private set; }
        /// <summary>Gets whether diagnostic cleanup ran before ownership release.</summary>
        internal bool DiagnosticsClosed { get; private set; }
        /// <summary>Gets or sets a controlled diagnostic cleanup failure.</summary>
        internal Exception? CloseError { get; init; }
        /// <summary>Gets the permanent ownership signal.</summary>
        public CancellationToken Lost => lost.Token;
        /// <summary>Gets no completed address diagnostics.</summary>
        public NetworkDiagnosticsStatus? LastStatus => null;
        /// <summary>Gets no source failure in this fixture.</summary>
        public NetworkDiagnosticsResult? LastFailure => null;
        /// <summary>Gets no read failure in this fixture.</summary>
        public Exception? LastError => null;
        /// <summary>Creates the real lifecycle with controlled side effects.</summary>
        internal ProtectionRuntime CreateRuntime() => new(this, this, this, CloseDiagnostics);
        /// <summary>Records blocking intent without calling native APIs.</summary>
        public Task EnsureAsync(CancellationToken token) { Writes++; return Task.CompletedTask; }
        /// <summary>Supplies a completed object observation, not effective packet validation.</summary>
        public Task<BlockPolicyInspection> InspectAsync(CancellationToken token) => Task.FromResult(new BlockPolicyInspection(BlockPolicyState.Present, 4, 4));
        /// <summary>Supplies no geographic evidence.</summary>
        public NetworkDiagnosticsObservation? Capture() => null;
        /// <summary>Accepts refresh requests without network access.</summary>
        public void Refresh() { }
        /// <summary>Records diagnostic shutdown while policy ownership is retained.</summary>
        private ValueTask CloseDiagnostics()
        {
            Assert.Equal(0, OwnerReleases); DiagnosticsClosed = true;
            if (CloseError is not null) throw CloseError;
            return ValueTask.CompletedTask;
        }
        /// <summary>Records exactly one owner release after diagnostic cleanup.</summary>
        public ValueTask DisposeAsync() { Assert.True(DiagnosticsClosed); OwnerReleases++; lost.Cancel(); return ValueTask.CompletedTask; }
        /// <summary>Releases fixture resources independently of transferred runtime ownership.</summary>
        public void Dispose() { deadline.Dispose(); lost.Dispose(); }
    }
}
