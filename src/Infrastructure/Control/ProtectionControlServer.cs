using IPGuard.Application.Protection;

namespace IPGuard.Infrastructure.Control;

/// <summary>Runs one bounded block-only command session and reconciles persistent blocks on every exit path.</summary>
public static class ProtectionControlServer
{
    /// <summary>Reconciles before connecting and guarantees terminal cleanup even when IPC startup fails.</summary>
    public static Task<ProtectionControlCompletion> ConnectAndRunAsync(Func<CancellationToken, Task<Stream>> connect,
        ProtectionRuntime runtime, TimeSpan commandTimeout, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(connect);
        return RunCoreAsync(null, connect, runtime, commandTimeout, cancellationToken);
    }

    /// <summary>Takes stream ownership, runs commands, closes transport, and stops the runtime even after malformed input.</summary>
    public static Task<ProtectionControlCompletion> RunAsync(Stream stream, ProtectionRuntime runtime, TimeSpan commandTimeout,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        return RunCoreAsync(stream, null, runtime, commandTimeout, cancellationToken);
    }

    /// <summary>Shares reconciliation and cleanup for accepted streams and helper-side deferred connections.</summary>
    private static async Task<ProtectionControlCompletion> RunCoreAsync(Stream? stream, Func<CancellationToken, Task<Stream>>? connect,
        ProtectionRuntime runtime, TimeSpan commandTimeout, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(runtime);
        ControlCommandDeadline.Validate(commandTimeout);
        var errors = new List<Exception>();
        try
        {
            using (var initial = ControlCommandDeadline.Start(commandTimeout, cancellationToken))
            {
                await runtime.RecheckAsync(initial.Token).ConfigureAwait(false);
                if (connect is not null)
                    stream = await connect(initial.Token).ConfigureAwait(false) ?? throw new InvalidDataException("Missing control stream.");
            }
            if (stream is null) throw new InvalidDataException("Missing control stream.");
            while (true)
            {
                using var deadline = ControlCommandDeadline.Start(commandTimeout, cancellationToken);
                var command = await ProtectionControlProtocol.ReadCommandAsync(stream, deadline.Token).ConfigureAwait(false);
                var snapshot = command switch
                {
                    ProtectionCommand.Status => runtime.Capture(),
                    ProtectionCommand.Recheck => await runtime.RecheckAsync(deadline.Token).ConfigureAwait(false),
                    ProtectionCommand.Stop => await runtime.StopAsync(CancellationToken.None).ConfigureAwait(false),
                    _ => throw new InvalidDataException("Unsupported control command.")
                };
                deadline.Token.ThrowIfCancellationRequested();
                await ProtectionControlProtocol.WriteReportAsync(stream, ProtectionControlReport.FromSnapshot(snapshot), deadline.Token).ConfigureAwait(false);
                if (command == ProtectionCommand.Stop) break;
            }
        }
        catch (Exception error) { errors.Add(error); }

        // Retire the transport before potentially uninterruptible final policy and diagnostic cleanup.
        try { if (stream is not null) await stream.DisposeAsync().ConfigureAwait(false); }
        catch (Exception error) { errors.Add(error); }
        var final = await runtime.StopAsync(CancellationToken.None).ConfigureAwait(false);
        if (final.Error is not null) errors.Add(final.Error);
        var combined = errors.Count switch { 0 => null, 1 => errors[0], _ => new AggregateException("Control session failed.", errors) };
        return new(final, combined);
    }
}

/// <summary>Retains final policy observations and all terminal transport/cleanup failures for host logging.</summary>
public sealed class ProtectionControlCompletion
{
    /// <summary>Captures terminal work independently of whether a final acknowledgement reached the GUI.</summary>
    internal ProtectionControlCompletion(ProtectionSnapshot shutdown, Exception? error) { Shutdown = shutdown; Error = error; }
    /// <summary>Gets final object observations, not a proof of effective traffic blocking.</summary>
    public ProtectionSnapshot Shutdown { get; }
    /// <summary>Gets the combined transport, policy, and cleanup failure without discarding original exceptions.</summary>
    public Exception? Error { get; }
}
