namespace IPGuard.Application.Protection;

/// <summary>Maintains a persistent block baseline without opening permits or removing protection.</summary>
public interface IBlockPolicy
{
    /// <summary>Ensures configured blocks exist atomically, preserving unrelated objects and rejecting conflicts.</summary>
    Task EnsureAsync(CancellationToken cancellationToken);

    /// <summary>Reads exact required blocks and rejects related permits or unknown objects in one consistent snapshot.</summary>
    /// <remarks>Presence is not proof of effective packet blocking, boot coverage, or established-connection termination.</remarks>
    Task<BlockPolicyInspection> InspectAsync(CancellationToken cancellationToken);
}

/// <summary>Describes inspected baseline objects without claiming effective traffic enforcement.</summary>
public enum BlockPolicyState
{
    /// <summary>A complete trustworthy inspection is unavailable.</summary>
    Unknown,
    /// <summary>Required enabled policy objects are missing or incomplete.</summary>
    Incomplete,
    /// <summary>All required blocks match and the related namespace contains only verified baseline blocks.</summary>
    Present
}

/// <summary>Retains one completed or failed object inspection, independently of geographic eligibility.</summary>
public sealed class BlockPolicyInspection
{
    /// <summary>Captures counts and the original inspection failure for diagnostics.</summary>
    public BlockPolicyInspection(BlockPolicyState state, int expectedRules, int matchingRules, Exception? error = null)
    {
        State = state;
        ExpectedRules = expectedRules;
        MatchingRules = matchingRules;
        Error = error;
    }

    /// <summary>Gets the confidence in the inspected baseline's object presence.</summary>
    public BlockPolicyState State { get; }

    /// <summary>Gets the number of required unique application/layer pairs.</summary>
    public int ExpectedRules { get; }

    /// <summary>Gets the number of matching enabled blocks in that inspection.</summary>
    public int MatchingRules { get; }

    /// <summary>Gets the original inspection failure, if any.</summary>
    public Exception? Error { get; }

    /// <summary>Checks the shared object-state/count contract used by backend and transport reports.</summary>
    internal static bool HasValidCounts(BlockPolicyState state, int expectedRules, int matchingRules)
        => Enum.IsDefined(state) && expectedRules > 0 && matchingRules >= 0 && matchingRules <= expectedRules &&
            (state != BlockPolicyState.Unknown || matchingRules == 0) &&
            (state != BlockPolicyState.Present || matchingRules == expectedRules);
}
