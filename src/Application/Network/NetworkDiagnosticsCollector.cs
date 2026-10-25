using IPGuard.Domain;

namespace IPGuard.Application.Network;

/// <summary>Collects complete local observations within one live network generation and bounded interval.</summary>
public sealed class NetworkDiagnosticsCollector
{
    private readonly RouteDiagnosticsCollector routes;
    private readonly IProxySettingsReader proxy;
    private readonly IRemoteAccessReader remoteAccess;
    private readonly INetworkSnapshotProvider network;
    private readonly PublicIpPolicy lifetime;
    private readonly Func<DateTimeOffset> utcNow;

    /// <summary>Composes local readers, cached generations, an exclusive age limit, and a UTC clock.</summary>
    public NetworkDiagnosticsCollector(IRoutingTableReader routes, IProxySettingsReader proxy, IRemoteAccessReader remoteAccess,
        INetworkSnapshotProvider network, TimeSpan maximumAge, Func<DateTimeOffset>? utcNow = null)
    {
        ArgumentNullException.ThrowIfNull(proxy);
        ArgumentNullException.ThrowIfNull(remoteAccess);
        ArgumentNullException.ThrowIfNull(network);
        lifetime = new PublicIpPolicy(maximumAge);
        MaximumAge = maximumAge;
        this.proxy = proxy;
        this.remoteAccess = remoteAccess;
        this.network = network;
        this.utcNow = utcNow ?? (() => DateTimeOffset.UtcNow);
        this.routes = new RouteDiagnosticsCollector(routes, network, this.utcNow);
    }

    /// <summary>Gets the exclusive lifetime used to arm the background monitor's independent deadline.</summary>
    internal TimeSpan MaximumAge { get; }

    /// <summary>Collects synchronously off the UI thread and propagates caller cancellation.</summary>
    public NetworkDiagnosticsResult Collect(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        NetworkSnapshot? before = null;
        try
        {
            var startedAt = utcNow();
            before = network.Capture();
            cancellationToken.ThrowIfCancellationRequested();
            if (before is null || before.Version == Guid.Empty || !before.Invalidated.CanBeCanceled || before.Invalidated.IsCancellationRequested)
                return new(NetworkDiagnosticsStatus.NetworkUnavailable);

            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, before.Invalidated);
            var lastTime = startedAt;
            var routeResult = routes.Collect(linked.Token);
            var failure = Checkpoint(before, startedAt, ref lastTime, cancellationToken);
            if (failure.HasValue) return new(failure.Value, error: routeResult.Error);
            if (routeResult.Status != RouteDiagnosticsStatus.Completed)
                return new(MapRouteFailure(routeResult.Status), error: routeResult.Error);
            var routeSnapshot = routeResult.Snapshot ?? throw new InvalidDataException("Completed routing diagnostics have no snapshot.");
            if (!before.MatchesCurrent(routeSnapshot.Network)) return new(NetworkDiagnosticsStatus.NetworkChanged);

            var proxySettings = proxy.Read(linked.Token);
            failure = Checkpoint(before, startedAt, ref lastTime, cancellationToken);
            if (failure.HasValue) return new(failure.Value);
            if (proxySettings is null) throw new InvalidDataException("The proxy reader returned no settings.");

            var connections = remoteAccess.Read(linked.Token)?.ToArray();
            failure = Checkpoint(before, startedAt, ref lastTime, cancellationToken);
            if (failure.HasValue) return new(failure.Value);
            if (connections is null || connections.Any(connection => connection is null || !Enum.IsDefined(connection.State)))
                throw new InvalidDataException("The remote-access reader returned incomplete observations.");

            return new(NetworkDiagnosticsStatus.Completed,
                new NetworkDiagnosticsSnapshot(before, startedAt, lastTime, routeSnapshot.Routes, proxySettings, connections));
        }
        catch (Exception error)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (before?.Invalidated.IsCancellationRequested == true)
                return new(NetworkDiagnosticsStatus.NetworkChanged, error: error is OperationCanceledException ? null : error);
            return new(NetworkDiagnosticsStatus.Failed, error: error);
        }
    }

    /// <summary>Checks retained observations against a fresh cached generation and the shared domain interval rule.</summary>
    internal NetworkDiagnosticsStatus? CheckCurrent(NetworkDiagnosticsSnapshot snapshot, ref DateTimeOffset lastTime)
        => Checkpoint(snapshot.Network, snapshot.StartedAt, ref lastTime, default);

    /// <summary>Checks cancellation after both external boundaries so a final clock callback cannot conceal invalidation.</summary>
    private NetworkDiagnosticsStatus? Checkpoint(NetworkSnapshot before, DateTimeOffset startedAt, ref DateTimeOffset lastTime,
        CancellationToken cancellationToken)
    {
        var current = network.Capture();
        var now = utcNow();
        cancellationToken.ThrowIfCancellationRequested();
        if (!before.MatchesCurrent(current)) return NetworkDiagnosticsStatus.NetworkChanged;
        var failure = lifetime.CheckInterval(startedAt, lastTime, now);
        if (failure == PublicIpDecisionReason.InvalidTimestamps) return NetworkDiagnosticsStatus.InvalidTimestamps;
        if (failure == PublicIpDecisionReason.StaleAssessment) return NetworkDiagnosticsStatus.Expired;
        lastTime = now;
        return null;
    }

    /// <summary>Preserves route-specific failure categories when combining local readers.</summary>
    private static NetworkDiagnosticsStatus MapRouteFailure(RouteDiagnosticsStatus status) => status switch
    {
        RouteDiagnosticsStatus.NetworkUnavailable => NetworkDiagnosticsStatus.NetworkUnavailable,
        RouteDiagnosticsStatus.NetworkChanged => NetworkDiagnosticsStatus.NetworkChanged,
        RouteDiagnosticsStatus.InvalidTimestamps => NetworkDiagnosticsStatus.InvalidTimestamps,
        _ => NetworkDiagnosticsStatus.Failed
    };
}
