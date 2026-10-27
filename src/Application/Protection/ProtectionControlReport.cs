namespace IPGuard.Application.Protection;

/// <summary>Names the fixed block-only operations accepted from a bound GUI process.</summary>
public enum ProtectionCommand
{
    /// <summary>Reads cached observations without writing policy.</summary>
    Status = 1,
    /// <summary>Ensures persistent blocks and requests fresh diagnostics.</summary>
    Recheck = 2,
    /// <summary>Finishes the session while preserving persistent blocks.</summary>
    Stop = 3
}

/// <summary>Transports last-observed policy objects without exceptions, evidence tokens, or an allow state.</summary>
public sealed class ProtectionControlReport
{
    /// <summary>Validates report structure; object presence never proves effective traffic blocking.</summary>
    public ProtectionControlReport(ProtectionPhase phase, ProtectionReason reason, BlockPolicyState? policyState,
        int expectedRules, int matchingRules, DateTimeOffset? policyObservedAt, bool hasError)
    {
        if (!Enum.IsDefined(phase) || !Enum.IsDefined(reason))
            throw new ArgumentException("The report contains an undefined state.");
        if (!policyState.HasValue)
        {
            if (expectedRules != 0 || matchingRules != 0 || policyObservedAt.HasValue)
                throw new ArgumentException("An unavailable inspection cannot carry counts or an observation time.");
        }
        else if (!BlockPolicyInspection.HasValidCounts(policyState.Value, expectedRules, matchingRules) ||
            !policyObservedAt.HasValue || policyObservedAt.Value.Offset != TimeSpan.Zero)
            throw new ArgumentException("The report contains contradictory inspection data.");
        Phase = phase;
        Reason = reason;
        PolicyState = policyState;
        ExpectedRules = expectedRules;
        MatchingRules = matchingRules;
        PolicyObservedAt = policyObservedAt;
        HasError = hasError;
    }

    /// <summary>Gets coordinator activity independently of filtering effectiveness.</summary>
    public ProtectionPhase Phase { get; }
    /// <summary>Gets the conservative application reason; no value authorizes traffic.</summary>
    public ProtectionReason Reason { get; }
    /// <summary>Gets the last object inspection state, or null when unavailable.</summary>
    public BlockPolicyState? PolicyState { get; }
    /// <summary>Gets the required rule count, or zero when no inspection is available.</summary>
    public int ExpectedRules { get; }
    /// <summary>Gets the enabled matching rule count from that inspection.</summary>
    public int MatchingRules { get; }
    /// <summary>Gets the UTC inspection time, never a promise of current enforcement.</summary>
    public DateTimeOffset? PolicyObservedAt { get; }
    /// <summary>Gets whether the helper recorded an operational error without transporting sensitive exception data.</summary>
    public bool HasError { get; }

    /// <summary>Copies only serializable diagnostic fields from a trusted application snapshot.</summary>
    public static ProtectionControlReport FromSnapshot(ProtectionSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        return new(snapshot.Phase, snapshot.Reason, snapshot.Policy?.State, snapshot.Policy?.ExpectedRules ?? 0,
            snapshot.Policy?.MatchingRules ?? 0, snapshot.PolicyObservedAt?.ToUniversalTime(), snapshot.Error is not null);
    }
}
