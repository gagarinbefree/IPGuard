using IPGuard.Application.Network;
using System.Threading.Channels;

namespace IPGuard.Windows.Network;

/// <summary>Caches a cancellable generation of Windows interface configuration.</summary>
/// <remarks>This monitor supplies assessment input, not verified routes or permission to open a WFP lease.</remarks>
public sealed class WindowsNetworkMonitor : INetworkSnapshotProvider, IDisposable
{
    private readonly object gate = new();
    private readonly Channel<bool> refreshes = Channel.CreateBounded<bool>(new BoundedChannelOptions(1)
    {
        SingleReader = true,
        FullMode = BoundedChannelFullMode.DropWrite,
        AllowSynchronousContinuations = false
    });
    private readonly Func<NetworkFamilyState> read;
    private readonly IDisposable subscription;
    private readonly Task worker;
    private NetworkSnapshot? current;
    private CancellationTokenSource? invalidation;
    private Exception? lastError;
    private long revision;
    private bool disposed;
    private bool notificationFaulted;

    /// <summary>Starts read-only Windows notifications and an initial background refresh.</summary>
    public WindowsNetworkMonitor() : this(changed => new WindowsNetworkChangeSubscription(changed), WindowsNetworkFamilies.Read) { }

    /// <summary>Composes notifications and local reads for deterministic lifecycle tests.</summary>
    internal WindowsNetworkMonitor(Func<Action<Exception?>, IDisposable> subscribe, Func<NetworkFamilyState> read)
    {
        ArgumentNullException.ThrowIfNull(subscribe);
        ArgumentNullException.ThrowIfNull(read);
        this.read = read;
        subscription = subscribe(OnChanged) ?? throw new InvalidOperationException("The notification subscription is missing.");
        refreshes.Writer.TryWrite(true);
        worker = Task.Run(ReadLoopAsync);
    }

    /// <summary>Gets the most recent refresh, observer, or cleanup failure, if any.</summary>
    public Exception? LastError
    {
        get { lock (gate) { return lastError; } }
    }

    /// <summary>Gets background-reader completion for safe shutdown verification.</summary>
    public Task Completion => worker;

    /// <summary>Returns cached state atomically, without reading interfaces or contacting the network.</summary>
    public NetworkSnapshot? Capture()
    {
        lock (gate) { return current; }
    }

    /// <summary>Invalidates existing evidence and requests another background read.</summary>
    public void Refresh()
    {
        lock (gate)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            Invalidate();
            notificationFaulted = false;
            refreshes.Writer.TryWrite(true);
        }
    }

    /// <summary>Invalidates evidence and unregisters notifications without waiting for arbitrary consumer callbacks.</summary>
    public void Dispose()
    {
        lock (gate)
        {
            if (!disposed)
            {
                disposed = true;
                Invalidate();
                refreshes.Writer.TryComplete();
            }
        }

        // Native cancellation may wait for a notification; never hold the monitor gate here.
        try { subscription.Dispose(); }
        catch (Exception error)
        {
            lock (gate) { lastError = error; }
            throw;
        }
    }

    /// <summary>Retires evidence before scheduling work; source faults remain unknown until an explicit retry.</summary>
    private void OnChanged(Exception? error)
    {
        lock (gate)
        {
            if (disposed) { return; }
            Invalidate();
            if (error is not null)
            {
                notificationFaulted = true;
                lastError = error;
            }
            if (!notificationFaulted) { refreshes.Writer.TryWrite(true); }
        }
    }

    /// <summary>Clears cached evidence and synchronously latches cancellation without running consumers inline.</summary>
    /// <remarks>The caller holds the gate. CancelAsync prevents consumers from running on a native notification stack.</remarks>
    private void Invalidate()
    {
        revision++;
        current = null;
        var previous = invalidation;
        invalidation = null;
        if (previous is not null)
        {
            Task cancellation = previous.CancelAsync();
            _ = FinishInvalidationAsync(previous, cancellation);
        }
    }

    /// <summary>Observes consumer failures and keeps each retired source alive until its callbacks finish.</summary>
    private async Task FinishInvalidationAsync(CancellationTokenSource previous, Task cancellation)
    {
        try { await cancellation.ConfigureAwait(false); }
        catch (Exception error) { lock (gate) { lastError = error; } }
        finally { previous.Dispose(); }
    }

    /// <summary>Coalesces notifications and publishes only a read unaffected by intervening changes.</summary>
    private async Task ReadLoopAsync()
    {
        while (await refreshes.Reader.WaitToReadAsync().ConfigureAwait(false))
        {
            while (refreshes.Reader.TryRead(out _)) { }
            long before;
            lock (gate)
            {
                if (disposed) { return; }
                if (notificationFaulted) { continue; }
                if (current is not null) { continue; }
                before = revision;
            }

            NetworkFamilyState? families = null;
            Exception? failure = null;
            try { families = read() ?? throw new InvalidOperationException("The interface reader returned no state."); }
            catch (Exception error) { failure = error; }

            lock (gate)
            {
                if (disposed) { return; }
                if (before != revision) { continue; }
                lastError = failure;
                if (families is null) { continue; }
                invalidation = new CancellationTokenSource();
                current = new NetworkSnapshot(Guid.NewGuid(), families.Ipv4, families.Ipv6, invalidation.Token);
            }
        }
    }
}
