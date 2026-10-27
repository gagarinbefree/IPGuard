using IPGuard.Application.Network;

namespace IPGuard.Application.Protection;

/// <summary>Describes coordinator activity, independently of traffic enforcement.</summary>
public enum ProtectionPhase
{
    /// <summary>No baseline operation has been requested.</summary>
    NotStarted,
    /// <summary>A baseline reconciliation is in progress and previous inspection data is retired.</summary>
    Reconciling,
    /// <summary>The coordinator is available; this does not mean network protection was verified.</summary>
    Running,
    /// <summary>Exit has been requested and a final baseline reconciliation is pending.</summary>
    Stopping,
    /// <summary>Final reconciliation completed, possibly with errors; the coordinator cannot restart.</summary>
    Stopped
}

/// <summary>Explains why this block-only coordinator never requests a network permit.</summary>
public enum ProtectionReason
{
    /// <summary>No baseline reconciliation has run.</summary>
    NotStarted,
    /// <summary>The baseline is being applied or verified.</summary>
    ApplyingPolicy,
    /// <summary>Required blocks or the exclusive block-only namespace could not be confirmed.</summary>
    PolicyUnavailable,
    /// <summary>No complete current address assessment is available, or diagnostics failed.</summary>
    AssessmentUnavailable,
    /// <summary>The current address or country prerequisites rejected the evidence.</summary>
    AddressRejected,
    /// <summary>Address prerequisites passed, but a common enforced PowerShell exit remains unverified.</summary>
    RouteUnverified,
    /// <summary>Exit is pending and no old geographic decision may be used.</summary>
    Stopping,
    /// <summary>The coordinator stopped while preserving the persistent baseline.</summary>
    Stopped
}

/// <summary>Separates workflow, object inspection, geographic diagnostics, and the absence of route authorization.</summary>
/// <remarks>Policy is the last observed object state at PolicyObservedAt, not proof of current effective blocking.</remarks>
public sealed class ProtectionSnapshot
{
    /// <summary>Captures an immutable report without introducing an allow state.</summary>
    internal ProtectionSnapshot(ProtectionPhase phase, ProtectionReason reason, BlockPolicyInspection? policy,
        DateTimeOffset? policyObservedAt, NetworkDiagnosticsObservation? network, NetworkDiagnosticsResult? failure, Exception? error)
    {
        Phase = phase;
        Reason = reason;
        Policy = policy;
        PolicyObservedAt = policyObservedAt;
        Network = network;
        DiagnosticFailure = failure;
        Error = error;
    }

    /// <summary>Gets coordinator activity rather than the operating system's filtering state.</summary>
    public ProtectionPhase Phase { get; }

    /// <summary>Gets the current conservative reason; no value authorizes traffic.</summary>
    public ProtectionReason Reason { get; }

    /// <summary>Gets the last completed object inspection, or null during reconciliation or failure.</summary>
    public BlockPolicyInspection? Policy { get; }

    /// <summary>Gets when that inspection completed, or null when it was not confirmed.</summary>
    public DateTimeOffset? PolicyObservedAt { get; }

    /// <summary>Gets current diagnostics for display; even US eligibility does not establish an enforced route.</summary>
    public NetworkDiagnosticsObservation? Network { get; }

    /// <summary>Gets original unavailable source/database details without treating them as current evidence.</summary>
    public NetworkDiagnosticsResult? DiagnosticFailure { get; }

    /// <summary>Gets the original policy, diagnostics, or combined shutdown failure.</summary>
    public Exception? Error { get; }
}
