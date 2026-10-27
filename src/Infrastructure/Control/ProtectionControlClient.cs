using IPGuard.Application.Protection;

namespace IPGuard.Infrastructure.Control;

/// <summary>Serializes bounded command exchanges and retires a connection after any interrupted transaction.</summary>
public sealed class ProtectionControlClient : IAsyncDisposable
{
    private readonly Stream stream;
    private readonly TimeSpan timeout;
    private readonly SemaphoreSlim exchanges = new(1, 1);
    private readonly object lifetime = new();
    private bool closed;
    private Task? closing;
    private Task? disposal;

    /// <summary>Takes ownership of an already authenticated duplex stream without sending data.</summary>
    public ProtectionControlClient(Stream stream, TimeSpan timeout)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ControlCommandDeadline.Validate(timeout);
        if (!stream.CanRead || !stream.CanWrite) throw new ArgumentException("A connected duplex stream is required.", nameof(stream));
        this.stream = stream;
        this.timeout = timeout;
    }
    /// <summary>Sends one fixed operation; queued cancellation leaves a healthy connection intact.</summary>
    public async Task<ProtectionControlReport> SendAsync(ProtectionCommand command, CancellationToken cancellationToken)
    {
        if (!Enum.IsDefined(command)) throw new ArgumentOutOfRangeException(nameof(command));
        ThrowIfClosed();
        await exchanges.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfClosed();
            using var deadline = ControlCommandDeadline.Start(timeout, cancellationToken);
            await ProtectionControlProtocol.WriteCommandAsync(stream, command, deadline.Token).ConfigureAwait(false);
            var report = await ProtectionControlProtocol.ReadReportAsync(stream, deadline.Token).ConfigureAwait(false);
            deadline.Token.ThrowIfCancellationRequested();
            if (command == ProtectionCommand.Stop)
            {
                if (report.Phase != ProtectionPhase.Stopped) throw new InvalidDataException("The helper did not acknowledge completed shutdown.");
                await CloseAsync().ConfigureAwait(false);
            }
            deadline.Token.ThrowIfCancellationRequested();
            ThrowIfInterrupted(command);
            return report;
        }
        catch (Exception original)
        {
            try { await CloseAsync().ConfigureAwait(false); }
            catch (Exception cleanup) when (!ReferenceEquals(original, cleanup))
            { throw new AggregateException(original, cleanup); }
            throw;
        }
        finally { exchanges.Release(); }
    }
    /// <summary>Closes transport, rejects queued work, and drains the active exchange.</summary>
    public ValueTask DisposeAsync()
    {
        lock (lifetime)
        {
            _ = CloseAsync();
            disposal ??= Task.Run(DrainAsync);
            return new(disposal);
        }
    }

    /// <summary>Rejects queued or new work after transport retirement.</summary>
    private void ThrowIfClosed()
    {
        lock (lifetime) ObjectDisposedException.ThrowIf(closed, this);
    }

    /// <summary>Discards a late report after external disposal while allowing a completed explicit stop reply.</summary>
    private void ThrowIfInterrupted(ProtectionCommand command)
    {
        lock (lifetime) ObjectDisposedException.ThrowIf(disposal is not null || (closed && command != ProtectionCommand.Stop), this);
    }

    /// <summary>Closes once without waiting for the semaphore held by an interrupted exchange.</summary>
    private Task CloseAsync()
    {
        lock (lifetime)
        {
            closed = true;
            closing ??= Task.Run(async () => await stream.DisposeAsync().ConfigureAwait(false));
            return closing;
        }
    }

    /// <summary>Waits for active and queued calls to leave their critical section even if transport close failed.</summary>
    private async Task DrainAsync()
    {
        try { await CloseAsync().ConfigureAwait(false); }
        finally
        {
            await exchanges.WaitAsync().ConfigureAwait(false);
            exchanges.Release();
        }
    }
}
