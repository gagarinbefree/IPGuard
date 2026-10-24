namespace IPGuard.Application.Network;

/// <summary>Separates collected routing diagnostics from unavailable or invalidated evidence.</summary>
public enum RouteDiagnosticsStatus
{
    /// <summary>Diagnostics were read within one observed generation; no route permission is implied.</summary>
    Completed,
    /// <summary>No usable network generation or cancellable latch was available before reading.</summary>
    NetworkUnavailable,
    /// <summary>The captured generation changed or was cancelled while reading.</summary>
    NetworkChanged,
    /// <summary>The completion clock moved behind the start of collection.</summary>
    InvalidTimestamps,
    /// <summary>The OS reader or another boundary failed; no partial snapshot is published.</summary>
    Failed
}

/// <summary>Retains one complete local route snapshot or the reason it was discarded.</summary>
public sealed class RouteDiagnosticsResult
{
    /// <summary>Creates an outcome independently of any network authorization.</summary>
    internal RouteDiagnosticsResult(RouteDiagnosticsStatus status, RouteDiagnosticsSnapshot? snapshot = null, Exception? error = null)
    {
        Status = status;
        Snapshot = snapshot;
        Error = error;
    }

    /// <summary>Gets the collection outcome, not an enforcement decision.</summary>
    public RouteDiagnosticsStatus Status { get; }

    /// <summary>Gets completed diagnostics, or null when evidence was discarded.</summary>
    public RouteDiagnosticsSnapshot? Snapshot { get; }

    /// <summary>Gets the original boundary failure for diagnostics.</summary>
    public Exception? Error { get; }
}

/// <summary>Binds immutable routing diagnostics to an interval and a live network cancellation latch.</summary>
/// <remarks>This is a local caller-context view, not proof of all compartments, VPN behavior, or a public exit.</remarks>
public sealed class RouteDiagnosticsSnapshot
{
    /// <summary>Captures a private route list for one observed generation.</summary>
    internal RouteDiagnosticsSnapshot(NetworkSnapshot network, DateTimeOffset startedAt, DateTimeOffset completedAt, NetworkRoute[] routes)
    {
        Network = network;
        StartedAt = startedAt;
        CompletedAt = completedAt;
        Routes = Array.AsReadOnly(routes);
    }

    /// <summary>Gets the original generation whose token remains live after collection.</summary>
    public NetworkSnapshot Network { get; }

    /// <summary>Gets the time before network capture and local route reads.</summary>
    public DateTimeOffset StartedAt { get; }

    /// <summary>Gets the time after the final local read and generation capture.</summary>
    public DateTimeOffset CompletedAt { get; }

    /// <summary>Gets the complete observed route list, including defaults, specific routes, and inactive diagnostics.</summary>
    public IReadOnlyList<NetworkRoute> Routes { get; }
}
