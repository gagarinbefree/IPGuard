using System.Threading.Channels;

namespace IPGuard.Application.Network;

/// <summary>Publishes bounded local or full observations through one serial background refresh loop.</summary>
public sealed class NetworkDiagnosticsMonitor : INetworkDiagnosticsReader, IDisposable
{
    private readonly object gate = new();
    private readonly INetworkDiagnosticsSource collector;
    private readonly TimeProvider timeProvider;
    private readonly ITimer periodic;
    private readonly Task worker;
    private readonly Channel<bool> refreshes = Channel.CreateBounded<bool>(new BoundedChannelOptions(1)
    {
        SingleReader = true,
        FullMode = BoundedChannelFullMode.DropWrite,
        AllowSynchronousContinuations = false
    });
    private Run? active;
    private NetworkDiagnosticsObservation? current;
    private DateTimeOffset lastTime;
    private NetworkDiagnosticsStatus? lastStatus;
    private Exception? lastError;
    private Exception? callbackError;
    private NetworkDiagnosticsResult? lastFailure;
    private bool disposed;

    /// <summary>Starts periodic full local/public-IP checks using the same serial refresh lifecycle.</summary>
    public NetworkDiagnosticsMonitor(NetworkCheckCollector collector, TimeSpan interval, TimeProvider? timeProvider = null)
        : this((INetworkDiagnosticsSource)collector, interval, timeProvider) { }

    /// <summary>Starts initial collection and periodic refresh with an independent snapshot deadline.</summary>
    public NetworkDiagnosticsMonitor(NetworkDiagnosticsCollector collector, TimeSpan interval, TimeProvider? timeProvider = null)
        : this((INetworkDiagnosticsSource)collector, interval, timeProvider) { }

    /// <summary>Composes only the two existing diagnostic scenarios with shared scheduling and retirement behavior.</summary>
    private NetworkDiagnosticsMonitor(INetworkDiagnosticsSource collector, TimeSpan interval, TimeProvider? timeProvider)
    {
        ArgumentNullException.ThrowIfNull(collector);
        ValidateTimer(interval, nameof(interval));
        ValidateTimer(collector.MaximumAge, nameof(collector));
        this.collector = collector;
        this.timeProvider = timeProvider ?? TimeProvider.System;
        periodic = this.timeProvider.CreateTimer(_ => RequestRefresh(), null, interval, interval);
        refreshes.Writer.TryWrite(true);
        worker = Task.Run(ReadLoopAsync);
    }

    /// <summary>Gets worker completion; disposal does not wait for uninterruptible native reads.</summary>
    public Task Completion => worker;

    /// <summary>Gets the latest attempt's outcome, or null while refreshing.</summary>
    public NetworkDiagnosticsStatus? LastStatus
    {
        get { lock (gate) { return lastStatus; } }
    }

    /// <summary>Gets the latest unavailable outcome and its source/database diagnostics; it never supplies current evidence.</summary>
    public NetworkDiagnosticsResult? LastFailure
    {
        get { lock (gate) { return lastFailure; } }
    }

    /// <summary>Gets the latest read or validation error, with consumer callback failures latched across later successes.</summary>
    public Exception? LastError
    {
        get { lock (gate) { return callbackError ?? lastError; } }
    }

    /// <summary>Returns only current observations, rechecking generation and wall-clock freshness without I/O.</summary>
    public NetworkDiagnosticsObservation? Capture()
    {
        lock (gate)
        {
            if (disposed || current is null) return null;
            var observation = current;
            var run = active!;
            NetworkDiagnosticsStatus? failure;
            Exception? error = null;
            try { failure = collector.CheckCurrent(observation.Snapshot, ref lastTime) ?? CheckElapsedTime(run); }
            catch (Exception caught) { failure = NetworkDiagnosticsStatus.Failed; error = caught; }
            if (disposed || current != observation || active != run) return null;
            if (!failure.HasValue && !observation.Invalidated.IsCancellationRequested) return observation;
            QueueRefresh();
            lastStatus = failure;
            lastError = error;
            lastFailure = new(failure ?? NetworkDiagnosticsStatus.Failed, error: error);
            return null;
        }
    }

    /// <summary>Immediately retires previous observations and requests a coalesced background refresh.</summary>
    public void Refresh()
    {
        lock (gate)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            QueueRefresh();
        }
    }

    /// <summary>Stops scheduling and invalidates observations without waiting for consumer callbacks or local readers.</summary>
    public void Dispose()
    {
        lock (gate)
        {
            if (disposed) return;
            disposed = true;
            RetireActive();
            lastStatus = null;
            periodic.Dispose();
            refreshes.Writer.TryComplete();
        }
    }

    /// <summary>Coalesces timer and generation requests; callbacks from retired runs cannot cancel a replacement.</summary>
    private void RequestRefresh(Run? expected = null)
    {
        lock (gate)
        {
            if (disposed || (expected is not null && active != expected)) return;
            QueueRefresh();
        }
    }

    /// <summary>Invalidates synchronously before scheduling another read; the caller holds the gate.</summary>
    private void QueueRefresh()
    {
        RetireActive();
        lastStatus = null;
        lastFailure = null;
        refreshes.Writer.TryWrite(true);
    }

    /// <summary>Releases registrations without waiting for callbacks and permanently cancels retired observations.</summary>
    private void RetireActive()
    {
        current = null;
        var previous = active;
        active = null;
        if (previous is null) return;
        previous.Deadline?.Dispose();
        previous.NetworkRegistration.Unregister();
        Task cancellation = previous.Source.CancelAsync();
        _ = FinishRetirementAsync(previous, cancellation);
    }

    /// <summary>Keeps the source alive through both its reader and consumer callbacks, observing callback failures.</summary>
    private async Task FinishRetirementAsync(Run previous, Task cancellation)
    {
        try { await cancellation.ConfigureAwait(false); }
        catch (Exception error) { lock (gate) { callbackError = error; } }
        await previous.Finished.Task.ConfigureAwait(false);
        previous.Source.Dispose();
    }

    /// <summary>Serializes local reads and asynchronous source requests on one background worker and drops retired responses.</summary>
    private async Task ReadLoopAsync()
    {
        while (await refreshes.Reader.WaitToReadAsync().ConfigureAwait(false))
        {
            while (refreshes.Reader.TryRead(out _)) { }
            Run run;
            lock (gate)
            {
                if (disposed) return;
                RetireActive();
                lastStatus = null;
                lastFailure = null;
                run = new Run();
                active = run;
            }

            try
            {
                lock (gate)
                {
                    if (active != run) continue;
                    // Arm before collection: elapsed-time expiry must not be extended by a slow read or clock rollback.
                    run.StartedAt = timeProvider.GetTimestamp();
                    run.Deadline = timeProvider.CreateTimer(_ => RequestRefresh(run), null, collector.MaximumAge, Timeout.InfiniteTimeSpan);
                }
                NetworkDiagnosticsResult result = await collector.CollectAsync(run.Token).ConfigureAwait(false);
                lock (gate)
                {
                    if (active != run || disposed || run.Token.IsCancellationRequested) continue;
                    Publish(run, result);
                }
            }
            catch (Exception error)
            {
                lock (gate)
                {
                    if (active == run)
                    {
                        RetireActive();
                        lastStatus = NetworkDiagnosticsStatus.Failed;
                        lastError = error;
                        lastFailure = new(NetworkDiagnosticsStatus.Failed, error: error);
                    }
                }
            }
            finally { run.Finished.TrySetResult(); }
        }
    }

    /// <summary>Rechecks completed evidence and subscribes to its generation before publishing; the caller holds the gate.</summary>
    private void Publish(Run run, NetworkDiagnosticsResult result)
    {
        lastStatus = result.Status;
        lastError = result.Error;
        lastFailure = result.Status == NetworkDiagnosticsStatus.Completed ? null : result;
        if (result.Status != NetworkDiagnosticsStatus.Completed || result.Snapshot is not { } snapshot)
        {
            RetireActive();
            return;
        }
        lastTime = snapshot.CompletedAt;
        NetworkDiagnosticsStatus? failure = collector.CheckCurrent(snapshot, ref lastTime) ?? CheckElapsedTime(run);
        if (active != run || disposed) return;
        if (failure.HasValue)
        {
            RetireActive();
            lastStatus = failure;
            lastFailure = new(failure.Value, assessment: result.Assessment);
            return;
        }
        LimitDatabaseDeadline(run, snapshot);
        if (active != run || run.Token.IsCancellationRequested) return;
        run.NetworkRegistration = snapshot.Network.Invalidated.UnsafeRegister(_ => RequestRefresh(run), null);
        if (active != run || run.Token.IsCancellationRequested || snapshot.Network.Invalidated.IsCancellationRequested) return;
        current = new NetworkDiagnosticsObservation(snapshot, run.Token);
    }

    /// <summary>Shortens the armed deadline for country evidence without extending the original elapsed-time limit.</summary>
    private void LimitDatabaseDeadline(Run run, NetworkDiagnosticsSnapshot snapshot)
    {
        if (snapshot.Assessment?.DatabaseValidUntil is not { } deadline) return;
        var remaining = deadline - lastTime;
        var ageLeft = collector.MaximumAge - timeProvider.GetElapsedTime(run.StartedAt);
        if (remaining >= ageLeft) return;
        if (remaining <= TimeSpan.Zero || !run.Deadline!.Change(remaining, Timeout.InfiniteTimeSpan))
            throw new InvalidOperationException("Cannot arm the country evidence deadline.");
    }

    /// <summary>Checks elapsed age independently of wall time and timer callback scheduling.</summary>
    private NetworkDiagnosticsStatus? CheckElapsedTime(Run run)
    {
        var elapsed = timeProvider.GetElapsedTime(run.StartedAt);
        if (elapsed < TimeSpan.Zero) return NetworkDiagnosticsStatus.InvalidTimestamps;
        return elapsed >= collector.MaximumAge ? NetworkDiagnosticsStatus.Expired : null;
    }

    /// <summary>Rejects sub-millisecond, disabled, or out-of-range timers before starting background work.</summary>
    private static void ValidateTimer(TimeSpan value, string parameter)
    {
        if (value < TimeSpan.FromMilliseconds(1) || value.TotalMilliseconds > uint.MaxValue - 1d)
            throw new ArgumentOutOfRangeException(parameter, "Diagnostic timer intervals must be between 1 and 4294967294 milliseconds.");
    }

    /// <summary>Owns one read and its published lifetime until retirement and reader completion.</summary>
    private sealed class Run
    {
        /// <summary>Creates a permanently addressable token before asynchronous cancellation or source disposal.</summary>
        internal Run() => Token = Source.Token;

        internal readonly CancellationTokenSource Source = new();
        internal readonly CancellationToken Token;
        internal readonly TaskCompletionSource Finished = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal ITimer? Deadline;
        internal long StartedAt;
        internal CancellationTokenRegistration NetworkRegistration;
    }
}

/// <summary>Pairs immutable observations with a monitor-owned retirement signal, independently of enforcement.</summary>
public sealed class NetworkDiagnosticsObservation
{
    /// <summary>Captures complete diagnostics and their additional refresh/deadline lifetime.</summary>
    internal NetworkDiagnosticsObservation(NetworkDiagnosticsSnapshot snapshot, CancellationToken invalidated)
    {
        Snapshot = snapshot;
        Invalidated = invalidated;
    }

    /// <summary>Gets requested observations; country eligibility, false flags, and empty lists do not establish a direct exit.</summary>
    public NetworkDiagnosticsSnapshot Snapshot { get; }

    /// <summary>Gets the permanent signal for refresh, network change, timeout, failure, or disposal.</summary>
    /// <remarks>Consumers must also check Snapshot.Network.Invalidated and freshness immediately before use.</remarks>
    public CancellationToken Invalidated { get; }
}
