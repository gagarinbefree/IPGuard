namespace IPGuard.Application.Network;

/// <summary>Describes local diagnostic availability without granting network access.</summary>
public enum NetworkDiagnosticsStatus
{
    /// <summary>All local observations were collected within one live generation and interval.</summary>
    Completed,
    /// <summary>No live network generation was available before collection.</summary>
    NetworkUnavailable,
    /// <summary>The generation changed while collecting or retaining observations.</summary>
    NetworkChanged,
    /// <summary>The clock moved backward across an observed boundary.</summary>
    InvalidTimestamps,
    /// <summary>The exclusive age limit was reached before observations could be used.</summary>
    Expired,
    /// <summary>A reader failed or returned incomplete observations.</summary>
    Failed
}

/// <summary>Contains complete local diagnostics or the reason no snapshot is available.</summary>
public sealed class NetworkDiagnosticsResult
{
    /// <summary>Captures an outcome without implying route coverage or enforcement.</summary>
    internal NetworkDiagnosticsResult(NetworkDiagnosticsStatus status, NetworkDiagnosticsSnapshot? snapshot = null, Exception? error = null)
    {
        Status = status;
        Snapshot = snapshot;
        Error = error;
    }

    /// <summary>Gets the collection outcome, independently of country eligibility.</summary>
    public NetworkDiagnosticsStatus Status { get; }

    /// <summary>Gets complete observations, or null after any failure.</summary>
    public NetworkDiagnosticsSnapshot? Snapshot { get; }

    /// <summary>Gets the original reader failure when available.</summary>
    public Exception? Error { get; }
}

/// <summary>Binds local routes, configured proxy flags, and limited RAS observations to one interval.</summary>
/// <remarks>Sequential reads are not an OS transaction. Empty lists and false flags do not prove a common exit.</remarks>
public sealed class NetworkDiagnosticsSnapshot
{
    /// <summary>Retains immutable models and private lists for one observed generation.</summary>
    internal NetworkDiagnosticsSnapshot(NetworkSnapshot network, DateTimeOffset startedAt, DateTimeOffset completedAt,
        IReadOnlyList<NetworkRoute> routes, ProxySettings proxy, RemoteAccessConnection[] connections)
    {
        Network = network;
        StartedAt = startedAt;
        CompletedAt = completedAt;
        Routes = Array.AsReadOnly(routes.ToArray());
        Proxy = proxy;
        Connections = Array.AsReadOnly(connections);
    }

    /// <summary>Gets the generation and its permanent network invalidation latch.</summary>
    public NetworkSnapshot Network { get; }

    /// <summary>Gets the time before the first local read; freshness starts here.</summary>
    public DateTimeOffset StartedAt { get; }

    /// <summary>Gets the time after the final local read and generation check.</summary>
    public DateTimeOffset CompletedAt { get; }

    /// <summary>Gets caller-context routes without asserting coverage of every compartment.</summary>
    public IReadOnlyList<NetworkRoute> Routes { get; }

    /// <summary>Gets configured proxy mechanisms without addresses or credentials.</summary>
    public ProxySettings Proxy { get; }

    /// <summary>Gets RAS-visible observations; an empty list does not establish absence of VPNs.</summary>
    public IReadOnlyList<RemoteAccessConnection> Connections { get; }
}
