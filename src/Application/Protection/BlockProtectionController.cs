using IPGuard.Application.Network;

namespace IPGuard.Application.Protection;

/// <summary>Coordinates persistent blocking intent and truthful diagnostics without granting permits.</summary>
public sealed class BlockProtectionController
{
    private readonly object gate = new();
    private readonly SemaphoreSlim operations = new(1, 1);
    private readonly IBlockPolicy policy;
    private readonly INetworkDiagnosticsReader diagnostics;
    private readonly Func<DateTimeOffset> utcNow;
    private ProtectionPhase phase;
    private BlockPolicyInspection? inspection;
    private DateTimeOffset? observedAt;
    private Exception? policyError;
    private Exception? diagnosticError;
    private long revision;
    private bool stopping;
    private Task<ProtectionSnapshot>? stopTask;

    /// <summary>Composes a block backend and host-owned diagnostic reader without performing I/O.</summary>
    public BlockProtectionController(IBlockPolicy policy, INetworkDiagnosticsReader diagnostics, Func<DateTimeOffset>? utcNow = null)
    {
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentNullException.ThrowIfNull(diagnostics);
        this.policy = policy;
        this.diagnostics = diagnostics;
        this.utcNow = utcNow ?? (() => DateTimeOffset.UtcNow);
    }

    /// <summary>Retires inspection data, requests diagnostics, and serializes ensure/readback operations off the UI thread.</summary>
    public async Task<ProtectionSnapshot> ReconcileAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate) { ObjectDisposedException.ThrowIf(stopping, this); }
        await operations.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            lock (gate)
            {
                ObjectDisposedException.ThrowIf(stopping, this);
                phase = ProtectionPhase.Reconciling;
                RetireInspection();
                policyError = null;
                diagnosticError = null;
            }
            try { diagnostics.Refresh(); }
            catch (Exception error) { lock (gate) { if (!stopping) diagnosticError = error; } }
            lock (gate) { if (stopping) return BuildSnapshot(null, null, null); }

            try
            {
                await policy.EnsureAsync(cancellationToken).ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested();
                lock (gate) { if (stopping) return BuildSnapshot(null, null, null); }
                var result = await policy.InspectAsync(cancellationToken).ConfigureAwait(false);
                Validate(result);
                var completedAt = utcNow();
                cancellationToken.ThrowIfCancellationRequested();
                lock (gate)
                {
                    if (!stopping)
                    {
                        inspection = result;
                        observedAt = completedAt;
                        policyError = result.Error;
                        phase = ProtectionPhase.Running;
                        revision++;
                    }
                }
            }
            catch (Exception error)
            {
                lock (gate)
                {
                    if (!stopping)
                    {
                        RetireInspection();
                        policyError = error;
                        phase = ProtectionPhase.Running;
                    }
                }
                cancellationToken.ThrowIfCancellationRequested();
            }
        }
        finally { operations.Release(); }
        return Capture();
    }

    /// <summary>Returns cached observations and an explicit blocking reason without mutating policy.</summary>
    public ProtectionSnapshot Capture()
    {
        long before;
        lock (gate)
        {
            if (phase != ProtectionPhase.Running || inspection?.State != BlockPolicyState.Present || policyError is not null)
                return BuildSnapshot(null, null, null);
            before = revision;
        }

        NetworkDiagnosticsObservation? network = null;
        NetworkDiagnosticsResult? failure = null;
        Exception? error = null;
        try
        {
            network = diagnostics.Capture();
            failure = diagnostics.LastFailure;
            error = diagnostics.LastError;
        }
        catch (Exception caught) { error = caught; }

        lock (gate)
        {
            if (before != revision) return BuildSnapshot(null, null, null);
            return BuildSnapshot(network, failure, error);
        }
    }

    /// <summary>Starts one terminal reconciliation; caller cancellation cancels only waiting, never the final baseline work.</summary>
    public Task<ProtectionSnapshot> StopAsync(CancellationToken cancellationToken)
    {
        Task<ProtectionSnapshot> pending;
        lock (gate)
        {
            if (stopTask is null)
            {
                stopping = true;
                phase = ProtectionPhase.Stopping;
                RetireInspection();
                policyError = null;
                diagnosticError = null;
                stopTask = Task.Run(StopCoreAsync);
            }
            pending = stopTask;
        }
        return pending.WaitAsync(cancellationToken);
    }

    /// <summary>Finishes an in-flight block write, then ensures and reads the persistent baseline independently of shutdown waiters.</summary>
    private async Task<ProtectionSnapshot> StopCoreAsync()
    {
        var errors = new List<Exception>();
        BlockPolicyInspection? result = null;
        DateTimeOffset? completedAt = null;
        await operations.WaitAsync().ConfigureAwait(false);
        try
        {
            try { await policy.EnsureAsync(CancellationToken.None).ConfigureAwait(false); }
            catch (Exception error) { errors.Add(error); }

            try
            {
                result = await policy.InspectAsync(CancellationToken.None).ConfigureAwait(false);
                Validate(result);
                completedAt = utcNow();
                if (result.Error is not null) errors.Add(result.Error);
            }
            catch (Exception error)
            {
                result = null;
                errors.Add(error);
            }
        }
        finally { operations.Release(); }

        lock (gate)
        {
            inspection = result;
            observedAt = completedAt;
            policyError = errors.Count switch
            {
                0 => null,
                1 => errors[0],
                _ => new AggregateException("Final baseline reconciliation failed.", errors)
            };
            phase = ProtectionPhase.Stopped;
            revision++;
            return BuildSnapshot(null, null, null);
        }
    }

    /// <summary>Forgets old inspection data before another operation or terminal exit; the caller holds the gate.</summary>
    private void RetireInspection()
    {
        inspection = null;
        observedAt = null;
        revision++;
    }

    /// <summary>Builds an explicit block-only reason, checking both evidence latches after all reader boundaries.</summary>
    private ProtectionSnapshot BuildSnapshot(NetworkDiagnosticsObservation? network, NetworkDiagnosticsResult? failure, Exception? readError)
    {
        var error = policyError ?? diagnosticError ?? readError;
        if (error is not null || network?.Invalidated.IsCancellationRequested == true || network?.Snapshot.Network.Invalidated.IsCancellationRequested == true)
            network = null;
        ProtectionReason reason;
        if (phase == ProtectionPhase.NotStarted) reason = ProtectionReason.NotStarted;
        else if (phase == ProtectionPhase.Reconciling) reason = ProtectionReason.ApplyingPolicy;
        else if (phase == ProtectionPhase.Stopping) reason = ProtectionReason.Stopping;
        else if (inspection?.State != BlockPolicyState.Present || policyError is not null) reason = ProtectionReason.PolicyUnavailable;
        else if (phase == ProtectionPhase.Stopped) reason = ProtectionReason.Stopped;
        else if (network?.Snapshot.Assessment is not { } assessment) reason = ProtectionReason.AssessmentUnavailable;
        else reason = assessment.Decision.IsEligible ? ProtectionReason.RouteUnverified : ProtectionReason.AddressRejected;
        return new(phase, reason, inspection, observedAt, network, failure, error);
    }

    /// <summary>Rejects contradictory adapter reports instead of publishing a successful baseline inspection.</summary>
    private static void Validate(BlockPolicyInspection? result)
    {
        if (result is null || !BlockPolicyInspection.HasValidCounts(result.State, result.ExpectedRules, result.MatchingRules)
            || (result.State == BlockPolicyState.Present && result.Error is not null))
            throw new InvalidDataException("The block policy returned an invalid inspection.");
    }
}
