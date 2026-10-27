using System.Collections.Concurrent;
using IPGuard.Application.Protection;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace UnitTests;

/// <summary>Checks deferred startup, reply retirement, polling and shutdown through controlled session boundaries.</summary>
public sealed class ProtectionSessionControllerTests
{
    /// <summary>A cancellation callback may await the same shutdown without creating a callback/cleanup cycle.</summary>
    [Fact]
    public async Task CancellationCallbackCanAwaitShutdown()
    {
        var session = new Session();
        var completed = Signal();
        CancellationTokenRegistration registration = default;
        ProtectionSessionController? controller = null;
        await using var owner = controller = new ProtectionSessionController(token =>
        {
            registration = token.Register(() =>
            {
                controller!.StopAsync(CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(2), TestContext.Current.CancellationToken)
                    .GetAwaiter().GetResult();
                completed.TrySetResult();
            });
            return Task.FromResult<IProtectionSession>(session);
        });
        try
        {
            await controller.StartAsync();
            await controller.StopAsync(TestContext.Current.CancellationToken);
            Assert.Null(controller.Capture().Error);
            await completed.Task.WaitAsync(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken);
        }
        finally { registration.Dispose(); }
    }

    /// <summary>A poll failure removes old data before slow transport disposal can finish.</summary>
    [Fact]
    public async Task FailureRetiresReplyBeforeCleanupCompletes()
    {
        var time = new FakeTimeProvider();
        var closing = Signal();
        var released = Signal();
        var session = new Session { Close = async () => { closing.TrySetResult(); await released.Task; } };
        await using var controller = Controller(session, time);
        await controller.StartAsync();
        session.Send = (_, _) => throw new IOException("Poll failed.");
        time.Advance(TimeSpan.FromSeconds(1));
        try
        {
            await closing.Task.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
            Assert.Null(controller.Capture().Report);
            Assert.NotNull(controller.Capture().Error);
        }
        finally { released.TrySetResult(); }
    }

    /// <summary>An older pending status reply cannot republish data retired by a queued manual recheck.</summary>
    [Fact]
    public async Task PollReplyCannotUndoPendingRecheck()
    {
        var time = new FakeTimeProvider();
        var polling = Signal();
        var releasePoll = Signal();
        var checking = Signal();
        var releaseCheck = Signal();
        var session = new Session();
        await using var controller = Controller(session, time);
        await controller.StartAsync();
        session.Send = async (command, _) =>
        {
            if (command == ProtectionCommand.Status) { polling.TrySetResult(); await releasePoll.Task; }
            if (command == ProtectionCommand.Recheck) { checking.TrySetResult(); await releaseCheck.Task; }
            return Report(command);
        };
        time.Advance(TimeSpan.FromSeconds(1));
        await polling.Task.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
        var recheck = controller.RecheckAsync();
        releasePoll.TrySetResult();
        try
        {
            await checking.Task.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
            Assert.Null(controller.Capture().Report);
            Assert.Equal(ProtectionSessionState.Rechecking, controller.Capture().State);
        }
        finally { releaseCheck.TrySetResult(); }
        await recheck;
    }

    /// <summary>Construction is passive and a synchronous connector never blocks the caller of StartAsync.</summary>
    [Fact]
    public async Task StartupIsExplicitAndRunsOffCaller()
    {
        using var entered = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        var session = new Session();
        int calls = 0;
        await using var controller = new ProtectionSessionController(_ =>
        { Interlocked.Increment(ref calls); entered.Set(); release.Wait(TestContext.Current.CancellationToken); return Task.FromResult<IProtectionSession>(session); });
        Assert.Equal(0, calls);
        Assert.Equal(ProtectionSessionState.Idle, controller.Capture().State);
        Task starting = controller.StartAsync();
        try
        {
            Assert.True(entered.Wait(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken));
            Assert.False(starting.IsCompleted);
            Assert.Equal(ProtectionSessionState.Starting, controller.Capture().State);
            Assert.Same(starting, controller.StartAsync());
        }
        finally { release.Set(); }
        await starting;
        Assert.Equal(1, calls);
        Assert.Equal(ProtectionSessionState.Connected, controller.Capture().State);
        Assert.NotNull(controller.Capture().Report);
        Assert.Equal([ProtectionCommand.Status], session.Commands);
    }

    /// <summary>Controlled time polls status without issuing policy writes and stale replies expire independently.</summary>
    [Fact]
    public async Task PollingUsesStatusAndExpiresOldReply()
    {
        var time = new FakeTimeProvider();
        var session = new Session();
        var entered = Signal();
        var release = Signal();
        await using var controller = Controller(session, time);
        await controller.StartAsync();
        session.Send = async (command, _) => { entered.TrySetResult(); await release.Task; return Report(command); };
        time.Advance(TimeSpan.FromSeconds(4));
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
            Assert.Null(controller.Capture().Report);
            Assert.NotNull(controller.Capture().Error);
            Assert.Equal([ProtectionCommand.Status, ProtectionCommand.Status], session.Commands);
        }
        finally { release.TrySetResult(); }
    }

    /// <summary>A failed exchange removes the old reply, disposes the connection, and permits explicit retry only.</summary>
    [Fact]
    public async Task RecheckFailureRetiresReplyAndAllowsExplicitRetry()
    {
        var first = new Session();
        var second = new Session();
        var failure = new IOException("Connection lost.");
        int calls = 0;
        await using var controller = new ProtectionSessionController(_ => Task.FromResult<IProtectionSession>(++calls == 1 ? first : second));
        await controller.StartAsync();
        first.Send = (_, _) => throw failure;
        await controller.RecheckAsync();
        Assert.Equal(ProtectionSessionState.Failed, controller.Capture().State);
        Assert.Null(controller.Capture().Report);
        Assert.Same(failure, controller.Capture().Error);
        Assert.Equal(1, first.Disposals);
        Assert.Equal(1, calls);
        await controller.StartAsync();
        Assert.Equal(2, calls);
        Assert.Equal(ProtectionSessionState.Connected, controller.Capture().State);
    }

    /// <summary>Pending recheck retires a successful reply before a new command completes.</summary>
    [Fact]
    public async Task RecheckRetiresObservationImmediately()
    {
        var session = new Session();
        var entered = Signal();
        var release = Signal();
        await using var controller = Controller(session);
        await controller.StartAsync();
        session.Send = async (command, _) => { entered.TrySetResult(); await release.Task; return Report(command); };
        Task rechecking = controller.RecheckAsync();
        try
        {
            Assert.Null(controller.Capture().Report);
            Assert.Equal(ProtectionSessionState.Rechecking, controller.Capture().State);
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
        }
        finally { release.TrySetResult(); }
        await rechecking;
        Assert.NotNull(controller.Capture().Report);
    }

    /// <summary>Exit latches immediately, drains a current exchange, then sends Stop and disposes exactly once.</summary>
    [Fact]
    public async Task StopDrainsBeforeAcknowledgementAndCannotRestart()
    {
        var session = new Session();
        var entered = Signal();
        var release = Signal();
        await using var controller = Controller(session);
        await controller.StartAsync();
        session.Send = async (command, _) =>
        { if (command == ProtectionCommand.Recheck) { entered.TrySetResult(); await release.Task; } return Report(command); };
        Task rechecking = controller.RecheckAsync();
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
        Task stopping = controller.StopAsync(TestContext.Current.CancellationToken);
        try
        {
            Assert.Equal(ProtectionSessionState.Stopping, controller.Capture().State);
            Assert.Null(controller.Capture().Report);
            Assert.False(stopping.IsCompleted);
            Assert.DoesNotContain(ProtectionCommand.Stop, session.Commands);
        }
        finally { release.TrySetResult(); }
        await rechecking;
        await stopping;
        Assert.Equal([ProtectionCommand.Status, ProtectionCommand.Recheck, ProtectionCommand.Stop], session.Commands);
        Assert.Equal(1, session.Disposals);
        Assert.Equal(ProtectionSessionState.Stopped, controller.Capture().State);
        Assert.Null(controller.Capture().Report);
        await Assert.ThrowsAsync<ObjectDisposedException>(() => controller.StartAsync());
    }

    /// <summary>A cancelled waiter does not abandon a late connection or let shutdown finish before its cleanup.</summary>
    [Fact]
    public async Task LateStartupIsDisposedBeforeStopCompletes()
    {
        var entered = Signal();
        var connected = new TaskCompletionSource<IProtectionSession>(TaskCreationOptions.RunContinuationsAsynchronously);
        var session = new Session();
        CancellationToken startupToken = default;
        await using var controller = new ProtectionSessionController(token => { startupToken = token; entered.TrySetResult(); return connected.Task; });
        Task starting = controller.StartAsync();
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
        using var waiter = new CancellationTokenSource();
        Task stopping = controller.StopAsync(waiter.Token);
        waiter.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => stopping);
        Assert.True(startupToken.IsCancellationRequested);
        connected.TrySetResult(session);
        await starting;
        await controller.StopAsync(TestContext.Current.CancellationToken);
        Assert.Equal(1, session.Disposals);
        Assert.Equal(ProtectionSessionState.Stopped, controller.Capture().State);
        Assert.Null(controller.Capture().Report);
    }

    /// <summary>A terminal or error reply never becomes the normal connected state.</summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task UnhealthyInitialReportIsRejected(bool stopped)
    {
        var session = new Session
        {
            Send = (_, _) => Task.FromResult(new ProtectionControlReport(
            stopped ? ProtectionPhase.Stopped : ProtectionPhase.Running, ProtectionReason.PolicyUnavailable, null, 0, 0, null, !stopped))
        };
        await using var controller = Controller(session);
        await controller.StartAsync();
        Assert.Equal(ProtectionSessionState.Failed, controller.Capture().State);
        Assert.Null(controller.Capture().Report);
        Assert.NotNull(controller.Capture().Error);
        Assert.Equal(1, session.Disposals);
    }

    /// <summary>Missing acknowledgement and disposal errors are retained without publishing a filtering success.</summary>
    [Fact]
    public async Task ShutdownFailuresRemainObservable()
    {
        var session = new Session();
        var send = new IOException("No stop acknowledgement.");
        var close = new IOException("Close failed.");
        await using var controller = Controller(session);
        await controller.StartAsync();
        session.Send = (_, _) => throw send;
        session.CloseError = close;
        await controller.StopAsync(TestContext.Current.CancellationToken);
        var errors = Assert.IsType<AggregateException>(controller.Capture().Error).Flatten().InnerExceptions;
        Assert.Contains(send, errors);
        Assert.Contains(close, errors);
        Assert.Equal(1, session.Disposals);
        Assert.Null(controller.Capture().Report);
    }

    /// <summary>Creates a passive controller with a one-second cadence for controlled time.</summary>
    private static ProtectionSessionController Controller(Session session, TimeProvider? time = null)
        => new(_ => Task.FromResult<IProtectionSession>(session), TimeSpan.FromSeconds(1), time);
    /// <summary>Creates a non-inline lifecycle signal.</summary>
    private static TaskCompletionSource Signal() => new(TaskCreationOptions.RunContinuationsAsynchronously);
    /// <summary>Supplies valid block-object observations without touching native filtering.</summary>
    private static ProtectionControlReport Report(ProtectionCommand command)
        => new(command == ProtectionCommand.Stop ? ProtectionPhase.Stopped : ProtectionPhase.Running,
            command == ProtectionCommand.Stop ? ProtectionReason.Stopped : ProtectionReason.AssessmentUnavailable,
            BlockPolicyState.Present, 4, 4, DateTimeOffset.UtcNow, false);

    /// <summary>Records ordered exchanges and cleanup with injected asynchronous behavior.</summary>
    private sealed class Session : IProtectionSession
    {
        /// <summary>Gets commands admitted by the controller.</summary>
        internal ConcurrentQueue<ProtectionCommand> Commands { get; } = new();
        /// <summary>Gets or sets the exchange boundary.</summary>
        internal Func<ProtectionCommand, CancellationToken, Task<ProtectionControlReport>> Send { get; set; }
            = (command, _) => Task.FromResult(Report(command));
        /// <summary>Gets or sets a cleanup failure.</summary>
        internal Exception? CloseError { get; set; }
        /// <summary>Gets or sets a controlled slow cleanup boundary.</summary>
        internal Func<Task>? Close { get; init; }
        /// <summary>Gets the number of disposal attempts.</summary>
        internal int Disposals { get; private set; }
        /// <summary>Records one command and forwards its controlled behavior.</summary>
        public Task<ProtectionControlReport> SendAsync(ProtectionCommand command, CancellationToken token)
        { Commands.Enqueue(command); return Send(command, token); }
        /// <summary>Records cleanup without closing any real process or transport.</summary>
        public async ValueTask DisposeAsync()
        { Disposals++; if (Close is not null) await Close(); if (CloseError is not null) throw CloseError; }
    }
}
