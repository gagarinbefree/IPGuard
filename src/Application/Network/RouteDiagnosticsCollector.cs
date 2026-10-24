namespace IPGuard.Application.Network;

/// <summary>Discards routing diagnostics when local reads outlive the captured network generation.</summary>
public sealed class RouteDiagnosticsCollector
{
    private readonly IRoutingTableReader reader;
    private readonly INetworkSnapshotProvider network;
    private readonly Func<DateTimeOffset> utcNow;

    /// <summary>Composes local route reading with cached network generations and an injectable UTC clock.</summary>
    public RouteDiagnosticsCollector(IRoutingTableReader reader, INetworkSnapshotProvider network, Func<DateTimeOffset>? utcNow = null)
    {
        ArgumentNullException.ThrowIfNull(reader);
        ArgumentNullException.ThrowIfNull(network);
        this.reader = reader;
        this.network = network;
        this.utcNow = utcNow ?? (() => DateTimeOffset.UtcNow);
    }

    /// <summary>Collects synchronously off the UI thread, preserving caller cancellation and rejecting partial results.</summary>
    public RouteDiagnosticsResult Collect(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        NetworkSnapshot? before = null;
        try
        {
            var startedAt = utcNow();
            before = network.Capture();
            cancellationToken.ThrowIfCancellationRequested();
            if (before is null || before.Version == Guid.Empty || !before.Invalidated.CanBeCanceled || before.Invalidated.IsCancellationRequested)
            {
                return new(RouteDiagnosticsStatus.NetworkUnavailable);
            }

            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, before.Invalidated);
            var routes = reader.Read(linked.Token)?.ToArray();
            cancellationToken.ThrowIfCancellationRequested();
            var after = network.Capture();
            var completedAt = utcNow();
            cancellationToken.ThrowIfCancellationRequested();
            if (!before.MatchesCurrent(after)) { return new(RouteDiagnosticsStatus.NetworkChanged); }
            if (completedAt < startedAt) { return new(RouteDiagnosticsStatus.InvalidTimestamps); }
            if (routes is null || routes.Any(route => route is null))
            {
                throw new InvalidDataException("The route reader returned an incomplete list.");
            }
            return new(RouteDiagnosticsStatus.Completed, new RouteDiagnosticsSnapshot(before, startedAt, completedAt, routes));
        }
        catch (Exception error)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (before?.Invalidated.IsCancellationRequested == true)
            {
                return new(RouteDiagnosticsStatus.NetworkChanged, error: error is OperationCanceledException ? null : error);
            }
            return new(RouteDiagnosticsStatus.Failed, error: error);
        }
    }
}
