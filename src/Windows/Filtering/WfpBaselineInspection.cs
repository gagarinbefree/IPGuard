namespace IPGuard.Windows.Filtering;

/// <summary>Describes stored objects, without claiming that traffic enforcement was tested.</summary>
public enum WfpBaselineState
{
    /// <summary>The snapshot could not be read or completed.</summary>
    Unknown,
    /// <summary>At least one required object is absent, disabled, or incompatible.</summary>
    Incomplete,
    /// <summary>All requested baseline objects match in a completed read transaction.</summary>
    Present
}

/// <summary>Reports object presence separately from effective network protection.</summary>
public sealed class WfpBaselineInspection
{
    /// <summary>Creates a diagnostic result for one completed or failed snapshot.</summary>
    public WfpBaselineInspection(WfpBaselineState state, int expectedRules, int matchingRules, string? error = null, Exception? failure = null)
    {
        State = state;
        ExpectedRules = expectedRules;
        MatchingRules = matchingRules;
        Error = error;
        Failure = failure;
    }

    /// <summary>Gets the confidence in the stored baseline's presence.</summary>
    public WfpBaselineState State { get; }

    /// <summary>Gets the number of unique application and layer pairs requested.</summary>
    public int ExpectedRules { get; }

    /// <summary>Gets matching rules, or zero if the snapshot could not be completed.</summary>
    public int MatchingRules { get; }

    /// <summary>Gets the read failure when the result is unknown.</summary>
    public string? Error { get; }

    /// <summary>Gets the original read, transaction, or session cleanup failure when available.</summary>
    public Exception? Failure { get; }
}
