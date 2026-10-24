namespace IPGuard.Application.PublicIp;

/// <summary>Separates completed source collection from discarded evidence and operational failures.</summary>
public enum PublicIpCollectionStatus
{
    /// <summary>All expected attempts were collected; country, consensus, and route checks are still required.</summary>
    Completed,
    /// <summary>The initial network generation or either family's availability is unknown.</summary>
    NetworkUnavailable,
    /// <summary>The generation changed or its invalidation signal fired; no snapshot is returned.</summary>
    NetworkChanged,
    /// <summary>The probe omitted, substituted, or reordered configured source results.</summary>
    InvalidProbeResult,
    /// <summary>The completion clock moved behind the beginning of collection.</summary>
    InvalidTimestamps,
    /// <summary>A boundary failed unexpectedly; the original exception is retained for diagnostics.</summary>
    Failed
}

/// <summary>Exposes a snapshot only for a completed collection, independently of any access decision.</summary>
public sealed class PublicIpCollectionResult
{
    /// <summary>Creates the scenario outcome, optionally retaining a complete snapshot or an original failure.</summary>
    internal PublicIpCollectionResult(PublicIpCollectionStatus status, PublicIpSnapshot? snapshot = null, Exception? error = null)
    {
        Status = status;
        Snapshot = snapshot;
        Error = error;
    }

    /// <summary>Gets the collection outcome, which never authorizes traffic.</summary>
    public PublicIpCollectionStatus Status { get; }

    /// <summary>Gets the completed evidence, or null when collection was discarded or failed.</summary>
    public PublicIpSnapshot? Snapshot { get; }

    /// <summary>Gets an unexpected boundary failure for future structured logging, without replacing it with success.</summary>
    public Exception? Error { get; }
}
