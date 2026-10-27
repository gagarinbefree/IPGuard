namespace IPGuard.Application.Protection;

/// <summary>Describes connection activity without claiming effective network enforcement.</summary>
public enum ProtectionSessionState
{
    /// <summary>No helper startup has been requested.</summary>
    Idle,
    /// <summary>Installation validation, consent, or authentication is pending.</summary>
    Starting,
    /// <summary>A helper session is available for bounded commands.</summary>
    Connected,
    /// <summary>A manual reconciliation is pending and previous observations are retired.</summary>
    Rechecking,
    /// <summary>The connection failed; an explicit new startup may be requested.</summary>
    Failed,
    /// <summary>Exit is terminal and waits for admitted work and connection cleanup.</summary>
    Stopping,
    /// <summary>Cleanup completed, possibly without an acknowledged helper shutdown.</summary>
    Stopped
}

/// <summary>Pairs connection activity with a current reply or the reason it is unavailable.</summary>
public sealed class ProtectionSessionSnapshot
{
    /// <summary>Captures last exchange data independently of actual traffic filtering.</summary>
    internal ProtectionSessionSnapshot(ProtectionSessionState state, ProtectionControlReport? report, Exception? error)
    { State = state; Report = report; Error = error; }
    /// <summary>Gets session activity.</summary>
    public ProtectionSessionState State { get; }
    /// <summary>Gets a non-expired reply, or null after retirement, error, or shutdown.</summary>
    public ProtectionControlReport? Report { get; }
    /// <summary>Gets the original connection or cleanup failure for diagnostics.</summary>
    public Exception? Error { get; }
}

/// <summary>Serializes explicit startup, status polling, recheck, and terminal shutdown without UI or Windows dependencies.</summary>
public sealed class ProtectionSessionController : IDisposable, IAsyncDisposable
{
    private readonly object gate = new();
    private readonly SemaphoreSlim operations = new(1, 1);
    private readonly CancellationTokenSource startupCancellation = new();
    private readonly Func<CancellationToken, Task<IProtectionSession>> connect;
    private readonly TimeSpan interval;
    private readonly TimeProvider time;
    private ProtectionSessionSnapshot current = new(ProtectionSessionState.Idle, null, null);
    private Run? active;
    private Task? starting;
    private Task? stopping;
    private long lastReply;

    /// <summary>Composes a deferred connector and bounded polling cadence without starting any work.</summary>
    /// <param name="connect">Transfers one owned session after explicit startup; late results must remain transferable for cleanup.</param>
    /// <param name="pollInterval">A cadence from one millisecond through ten seconds; five seconds by default.</param>
    /// <param name="timeProvider">The scheduling and monotonic reply-expiry clock.</param>
    public ProtectionSessionController(Func<CancellationToken, Task<IProtectionSession>> connect, TimeSpan? pollInterval = null,
        TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(connect);
        interval = pollInterval ?? TimeSpan.FromSeconds(5);
        if (interval < TimeSpan.FromMilliseconds(1) || interval > TimeSpan.FromSeconds(10))
            throw new ArgumentOutOfRangeException(nameof(pollInterval));
        this.connect = connect;
        time = timeProvider ?? TimeProvider.System;
    }
    /// <summary>Returns cached state only; an old reply never becomes a current filtering claim.</summary>
    public ProtectionSessionSnapshot Capture()
    {
        lock (gate)
        {
            if (current.Report is not null)
            {
                var elapsed = time.GetElapsedTime(lastReply);
                if (elapsed < TimeSpan.Zero || elapsed >= interval * 3)
                    return new(current.State, null, new TimeoutException("The helper reply has expired."));
            }
            return current;
        }
    }
    /// <summary>Starts once off the caller thread; repeated pending requests share the same attempt.</summary>
    public Task StartAsync()
    {
        lock (gate)
        {
            ObjectDisposedException.ThrowIf(stopping is not null, this);
            if (current.State == ProtectionSessionState.Starting) return starting!;
            if (active is not null) return Task.CompletedTask;
            current = new(ProtectionSessionState.Starting, null, null);
            starting = Task.Run(StartCoreAsync);
            return starting;
        }
    }
    /// <summary>Requests one serialized helper reconciliation, retiring the previous reply first.</summary>
    public Task RecheckAsync()
    {
        lock (gate)
        {
            ObjectDisposedException.ThrowIf(stopping is not null, this);
            if (current.State != ProtectionSessionState.Connected || active is null)
                throw new InvalidOperationException("A connected helper is required.");
            current = new(ProtectionSessionState.Rechecking, null, null);
            var run = active;
            return Task.Run(() => ExchangeAsync(run, ProtectionCommand.Recheck));
        }
    }
    /// <summary>Starts terminal cleanup; cancellation affects only the caller's wait.</summary>
    public Task StopAsync(CancellationToken cancellationToken)
    {
        Task pending;
        lock (gate)
        {
            if (stopping is null)
            {
                current = new(ProtectionSessionState.Stopping, null, current.Error);
                active?.Timer.Dispose();
                var cancellation = startupCancellation.CancelAsync();
                stopping = Task.Run(StopCoreAsync);
                _ = FinishCancellationAsync(cancellation, stopping);
            }
            pending = stopping;
        }
        return pending.WaitAsync(cancellationToken);
    }
    /// <summary>Requests terminal cleanup without blocking a synchronous lifetime event.</summary>
    public void Dispose() => _ = StopAsync(CancellationToken.None);
    /// <summary>Waits for terminal cleanup without reopening or killing a helper.</summary>
    public ValueTask DisposeAsync() => new(StopAsync(CancellationToken.None));

    /// <summary>Owns a late connection even if cancellation arrived during a non-interruptible consent operation.</summary>
    private async Task StartCoreAsync()
    {
        await operations.WaitAsync().ConfigureAwait(false);
        Run? run = null;
        try
        {
            startupCancellation.Token.ThrowIfCancellationRequested();
            var session = await connect(startupCancellation.Token).ConfigureAwait(false)
                ?? throw new InvalidDataException("The connector returned no session.");
            run = new(session, new PeriodicTimer(interval, time));
            lock (gate) active = run;
            startupCancellation.Token.ThrowIfCancellationRequested();
            var report = await session.SendAsync(ProtectionCommand.Status, startupCancellation.Token).ConfigureAwait(false);
            ValidateRunning(report);
            lock (gate)
            {
                if (stopping is not null) return;
                Publish(report);
                run.Polling = Task.Run(() => PollAsync(run));
            }
        }
        catch (Exception error)
        {
            bool shuttingDown;
            lock (gate) shuttingDown = stopping is not null;
            if (shuttingDown) return; // StopCore owns the late session and sends its final command after this attempt drains.
            lock (gate) current = new(stopping is null ? ProtectionSessionState.Failed : ProtectionSessionState.Stopping, null, error);
            var cleanup = await RetireAsync(run).ConfigureAwait(false);
            lock (gate) current = new(stopping is null ? ProtectionSessionState.Failed : ProtectionSessionState.Stopping, null, Combine(error, cleanup));
        }
        finally { operations.Release(); }
    }

    /// <summary>Coalesces ticks and serializes status reads with explicit commands.</summary>
    private async Task PollAsync(Run run)
    {
        while (await run.Timer.WaitForNextTickAsync().ConfigureAwait(false))
        {
            await ExchangeAsync(run, ProtectionCommand.Status).ConfigureAwait(false);
            lock (gate) { if (active != run || stopping is not null) return; }
        }
    }

    /// <summary>Publishes only replies from the current session and retires every failed transaction.</summary>
    private async Task ExchangeAsync(Run run, ProtectionCommand command)
    {
        await operations.WaitAsync().ConfigureAwait(false);
        try
        {
            lock (gate) { if (active != run || stopping is not null) return; }
            try
            {
                var report = await run.Session.SendAsync(command, CancellationToken.None).ConfigureAwait(false);
                ValidateRunning(report);
                lock (gate)
                {
                    if (stopping is null && (command == ProtectionCommand.Recheck || current.State != ProtectionSessionState.Rechecking))
                        Publish(report);
                }
            }
            catch (Exception error)
            {
                lock (gate) current = new(stopping is null ? ProtectionSessionState.Failed : ProtectionSessionState.Stopping, null, error);
                var cleanup = await RetireAsync(run).ConfigureAwait(false);
                lock (gate) current = new(stopping is null ? ProtectionSessionState.Failed : ProtectionSessionState.Stopping,
                    null, Combine(error, cleanup));
            }
        }
        finally { operations.Release(); }
    }

    /// <summary>Drains admitted exchanges, requests acknowledged shutdown, and closes even when acknowledgement fails.</summary>
    private async Task StopCoreAsync()
    {
        Exception? error = null;
        Run? run = null;
        await operations.WaitAsync().ConfigureAwait(false);
        try
        {
            lock (gate) { error = current.Error; run = active; }
            if (run is not null)
            {
                try
                {
                    var report = await run.Session.SendAsync(ProtectionCommand.Stop, CancellationToken.None).ConfigureAwait(false);
                    if (report.Phase != ProtectionPhase.Stopped || report.HasError)
                        throw new InvalidDataException("The helper did not confirm a clean shutdown.");
                }
                catch (Exception failure) { error = Combine(error, failure); }
                error = Combine(error, await RetireAsync(run).ConfigureAwait(false));
            }
        }
        finally { operations.Release(); }
        // A poller may be queued on the semaphore: release it before awaiting its terminal no-I/O path.
        try { if (run?.Polling is not null) await run.Polling.ConfigureAwait(false); }
        catch (Exception failure) { error = Combine(error, failure); }
        lock (gate) current = new(ProtectionSessionState.Stopped, null, error);
    }

    /// <summary>Observes callbacks without making shutdown wait for code that may itself await shutdown.</summary>
    private async Task FinishCancellationAsync(Task callbacks, Task shutdown)
    {
        Exception? failure = null;
        try { await callbacks.ConfigureAwait(false); } catch (Exception error) { failure = error; }
        try { await shutdown.ConfigureAwait(false); } catch (Exception error) { failure = Combine(failure, error); }
        if (failure is not null)
        {
            lock (gate) current = new(current.State, null, Combine(current.Error, failure));
        }
        startupCancellation.Dispose();
    }

    /// <summary>Closes a session once, without awaiting a poller that may itself own the operation semaphore.</summary>
    private async Task<Exception?> RetireAsync(Run? run)
    {
        if (run is null) return null;
        run.Timer.Dispose();
        lock (gate) { if (active == run) active = null; }
        try { await run.Session.DisposeAsync().ConfigureAwait(false); return null; }
        catch (Exception error) { return error; }
    }

    /// <summary>Stores a fresh response while the caller holds the lifetime gate.</summary>
    private void Publish(ProtectionControlReport report)
    { lastReply = time.GetTimestamp(); current = new(ProtectionSessionState.Connected, report, null); }

    /// <summary>Rejects terminal and operational-error replies without interpreting them as enforcement success.</summary>
    private static void ValidateRunning(ProtectionControlReport report)
    {
        if (report is null || report.Phase != ProtectionPhase.Running || report.HasError)
            throw new InvalidDataException("The helper returned an unavailable or failed policy report.");
    }

    /// <summary>Keeps original failures when both the exchange and cleanup fail.</summary>
    private static Exception? Combine(Exception? first, Exception? second)
        => first is null ? second : second is null ? first : new AggregateException(first, second);

    /// <summary>Owns one session and its coalescing poll timer until retirement.</summary>
    private sealed class Run
    {
        /// <summary>Captures resources only after a connector transfers session ownership.</summary>
        internal Run(IProtectionSession session, PeriodicTimer timer) { Session = session; Timer = timer; }
        /// <summary>Gets the owned connection.</summary>
        internal IProtectionSession Session { get; }
        /// <summary>Gets the timer whose disposal stops future reads.</summary>
        internal PeriodicTimer Timer { get; }
        /// <summary>Gets or sets the worker that observes all normal exchange failures.</summary>
        internal Task? Polling { get; set; }
    }
}
