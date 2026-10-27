namespace IPGuard.Application.Network;

/// <summary>Shares refresh lifetime handling between local-only and full diagnostic collection.</summary>
internal interface INetworkDiagnosticsSource
{
    /// <summary>Gets the exclusive lifetime used for the monitor's independent deadline.</summary>
    TimeSpan MaximumAge { get; }

    /// <summary>Collects requested observations off the UI thread and propagates caller cancellation.</summary>
    Task<NetworkDiagnosticsResult> CollectAsync(CancellationToken cancellationToken);

    /// <summary>Rechecks cached generation, observed time order, and all applicable evidence deadlines.</summary>
    NetworkDiagnosticsStatus? CheckCurrent(NetworkDiagnosticsSnapshot snapshot, ref DateTimeOffset lastTime);
}
