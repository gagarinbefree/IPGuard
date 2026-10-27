using IPGuard.Application.Protection;

namespace IPGuard.Windows.Filtering;

/// <summary>Owns a protected global mutex on a dedicated thread without opening WFP or requesting elevation.</summary>
public sealed class WindowsPolicyOwner : IPolicyOwnership
{
    private readonly object lifetime = new();
    private readonly ManualResetEventSlim stop = new();
    private readonly CancellationTokenSource lost = new();
    private readonly CancellationToken lostToken;
    private readonly TaskCompletionSource<WindowsPolicyOwner?> ready = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource completed = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private bool retiring;
    private bool finished;
    private Exception? lossNotificationError;

    /// <summary>Creates a pending owner whose lifetime is completed by its dedicated thread.</summary>
    private WindowsPolicyOwner() => lostToken = lost.Token;

    /// <summary>Acquires the fixed machine-wide owner as an enabled administrator, or returns null when busy.</summary>
    public static Task<WindowsPolicyOwner?> TryAcquireAsync(CancellationToken cancellationToken)
        => TryAcquireAsync(WindowsPolicyMutex.OpenProduction, cancellationToken);

    /// <summary>Injects thread-affine operations for safe lifecycle tests without production kernel objects.</summary>
    internal static async Task<WindowsPolicyOwner?> TryAcquireAsync(Func<IPolicyMutex> open, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(open);
        cancellationToken.ThrowIfCancellationRequested();
        var owner = new WindowsPolicyOwner();
        var thread = new Thread(() => owner.Run(open)) { IsBackground = true, Name = "IPGuard policy owner" };
        try { thread.Start(); }
        catch { owner.stop.Dispose(); owner.lost.Dispose(); throw; }
        try
        {
            var result = await owner.ready.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            return result;
        }
        catch (Exception acquisition)
        {
            try { await owner.DisposeAsync().ConfigureAwait(false); }
            catch (Exception cleanup) when (!ReferenceEquals(acquisition, cleanup))
            { throw new AggregateException(acquisition, cleanup); }
            throw;
        }
    }

    /// <summary>Gets whether the previous acquiring thread abandoned the mutex; baseline state must always be reconciled.</summary>
    public bool WasAbandoned { get; private set; }

    /// <summary>Gets the permanent ownership retirement signal.</summary>
    public CancellationToken Lost => lostToken;

    /// <summary>Gets a consumer callback failure; it does not delay or prevent native release.</summary>
    public Exception? LossNotificationError => Volatile.Read(ref lossNotificationError);

    /// <summary>Invalidates ownership immediately and awaits release/cleanup on the acquiring thread.</summary>
    public ValueTask DisposeAsync()
    {
        RequestStop();
        return new(completed.Task);
    }

    /// <summary>Opens, acquires, holds, and releases the mutex entirely on its owning thread.</summary>
    private void Run(Func<IPolicyMutex> open)
    {
        IPolicyMutex? mutex = null;
        bool acquired = false;
        Exception? error = null;
        try
        {
            mutex = open();
            var abandoned = mutex.TryAcquire();
            acquired = abandoned.HasValue;
            if (acquired)
            {
                WasAbandoned = abandoned!.Value;
                ready.TrySetResult(this);
                stop.Wait();
            }
        }
        catch (Exception failure) { error = failure; }
        finally
        {
            RequestStop();
            if (acquired)
            {
                try { mutex!.Release(); }
                catch (Exception failure) { error = Combine(error, failure); }
            }
            try { mutex?.Dispose(); }
            catch (Exception failure) { error = Combine(error, failure); }
            lock (lifetime) { finished = true; stop.Dispose(); }
            if (error is null)
            {
                completed.TrySetResult();
                ready.TrySetResult(null);
            }
            else
            {
                completed.TrySetException(error);
                ready.TrySetException(error);
            }
        }
    }

    /// <summary>Latches retirement before signaling the worker, without running consumer callbacks inline.</summary>
    private void RequestStop()
    {
        lock (lifetime)
        {
            if (retiring) return;
            retiring = true;
            var notifications = lost.CancelAsync();
            if (!finished) stop.Set();
            // A callback may itself await DisposeAsync; never await it on the owning thread.
            _ = CleanSignalAsync(notifications);
        }
    }

    /// <summary>Observes callback errors and disposes the signal only after callbacks and native cleanup finish.</summary>
    private async Task CleanSignalAsync(Task notifications)
    {
        try { await notifications.ConfigureAwait(false); }
        catch (Exception failure) { Volatile.Write(ref lossNotificationError, failure); }
        try { await completed.Task.ConfigureAwait(false); }
        catch (Exception) { /* The acquisition or disposal caller observes native cleanup failures. */ }
        lost.Dispose();
    }

    /// <summary>Retains both the original failure and any independent cleanup failure.</summary>
    private static Exception Combine(Exception? original, Exception cleanup)
        => original is null ? cleanup : new AggregateException(original, cleanup);
}
