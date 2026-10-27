using IPGuard.Application.Network;
using System.Runtime.ExceptionServices;

namespace IPGuard.Application.Protection;

/// <summary>Owns block-only coordination, diagnostics cleanup, and policy ownership in shutdown order.</summary>
public sealed class ProtectionRuntime : IAsyncDisposable
{
    private readonly object lifetime = new();
    private readonly OwnedBlockPolicy policy;
    private readonly BlockProtectionController controller;
    private readonly CancellationToken lost;
    private readonly Func<ValueTask> closeDiagnostics;
    private Task<ProtectionSnapshot>? stopping;

    /// <summary>Takes ownership of the lease and diagnostic cleanup; construction performs no policy I/O.</summary>
    /// <param name="policy">The persistent block backend whose native calls must drain before ownership release.</param>
    /// <param name="ownership">The exclusive lease transferred to this runtime.</param>
    /// <param name="diagnostics">The cached reader used by the shared controller.</param>
    /// <param name="closeDiagnostics">Stops and drains diagnostic workers; it must not await this runtime's shutdown.</param>
    /// <param name="utcNow">An optional UTC clock for last-observed policy timestamps.</param>
    public ProtectionRuntime(IBlockPolicy policy, IPolicyOwnership ownership, INetworkDiagnosticsReader diagnostics,
        Func<ValueTask> closeDiagnostics, Func<DateTimeOffset>? utcNow = null)
    {
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentNullException.ThrowIfNull(ownership);
        ArgumentNullException.ThrowIfNull(diagnostics);
        ArgumentNullException.ThrowIfNull(closeDiagnostics);
        lost = ownership.Lost;
        this.closeDiagnostics = closeDiagnostics;
        this.policy = new OwnedBlockPolicy(policy, ownership);
        controller = new BlockProtectionController(this.policy, diagnostics, utcNow);
    }

    /// <summary>Returns cached observations, retiring policy evidence when live ownership is lost.</summary>
    public ProtectionSnapshot Capture()
    {
        Task<ProtectionSnapshot>? terminal;
        lock (lifetime) terminal = stopping;
        if (terminal is not null) return CaptureTerminal(terminal);
        // Diagnostic readers may reenter host shutdown; never invoke them under the runtime gate.
        var snapshot = controller.Capture();
        lock (lifetime) terminal = stopping;
        if (terminal is not null) return CaptureTerminal(terminal);
        if (!lost.IsCancellationRequested) return snapshot;
        return new(snapshot.Phase, ProtectionReason.PolicyUnavailable, null, null, null, null,
            new OperationCanceledException("Exclusive policy ownership was lost.", lost));
    }

    /// <summary>Reads final cleanup errors after completion or the already terminal controller while work is pending.</summary>
    private ProtectionSnapshot CaptureTerminal(Task<ProtectionSnapshot> terminal)
        => terminal.IsCompletedSuccessfully ? terminal.Result : controller.Capture();

    /// <summary>Reconciles persistent blocks through the common controller without opening permits.</summary>
    public Task<ProtectionSnapshot> RecheckAsync(CancellationToken cancellationToken)
        => controller.ReconcileAsync(cancellationToken);

    /// <summary>Starts one terminal reconciliation and cleanup; caller cancellation only cancels waiting.</summary>
    public Task<ProtectionSnapshot> StopAsync(CancellationToken cancellationToken)
    {
        Task<ProtectionSnapshot> pending;
        lock (lifetime)
        {
            if (stopping is null)
            {
                // StopAsync marks the controller terminal synchronously before any cleanup worker can be delayed.
                var final = controller.StopAsync(CancellationToken.None);
                stopping = Task.Run(() => FinishAsync(final));
            }
            pending = stopping;
        }
        return pending.WaitAsync(cancellationToken);
    }

    /// <summary>Waits for terminal cleanup and rethrows any recorded policy or cleanup failure.</summary>
    public async ValueTask DisposeAsync()
    {
        var final = await StopAsync(CancellationToken.None).ConfigureAwait(false);
        if (final.Error is not null) ExceptionDispatchInfo.Capture(final.Error).Throw();
    }

    /// <summary>Attempts each cleanup boundary once and preserves policy and cleanup errors in the final report.</summary>
    private async Task<ProtectionSnapshot> FinishAsync(Task<ProtectionSnapshot> final)
    {
        var errors = new List<Exception>();
        ProtectionSnapshot snapshot;
        try { snapshot = await final.ConfigureAwait(false); }
        catch (Exception error) { errors.Add(error); snapshot = controller.Capture(); }
        if (snapshot.Error is not null) errors.Add(snapshot.Error);
        try { await closeDiagnostics().ConfigureAwait(false); }
        catch (Exception error) { errors.Add(error); }
        try { await policy.DisposeAsync().ConfigureAwait(false); }
        catch (Exception error) { errors.Add(error); }
        var combined = errors.Count switch { 0 => null, 1 => errors[0], _ => new AggregateException("Protection shutdown failed.", errors) };
        return new(snapshot.Phase, snapshot.Reason, snapshot.Policy, snapshot.PolicyObservedAt,
            null, snapshot.DiagnosticFailure, combined);
    }
}
