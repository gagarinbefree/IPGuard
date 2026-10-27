using IPGuard.Domain;

namespace IPGuard.Application.Network;

/// <summary>Shares generation and interval checkpoints between local and full diagnostic collection.</summary>
internal sealed class NetworkEvidenceLifetime
{
    private readonly INetworkSnapshotProvider network;
    private readonly PublicIpPolicy policy;
    private readonly Func<DateTimeOffset> utcNow;

    /// <summary>Composes cached network state, the domain interval rule, and a UTC clock.</summary>
    internal NetworkEvidenceLifetime(INetworkSnapshotProvider network, PublicIpPolicy policy, Func<DateTimeOffset> utcNow)
    {
        this.network = network;
        this.policy = policy;
        this.utcNow = utcNow;
    }

    /// <summary>Checks cancellation after both boundaries so the final clock cannot conceal an invalidated generation.</summary>
    internal NetworkDiagnosticsStatus? Check(NetworkSnapshot before, DateTimeOffset startedAt, ref DateTimeOffset lastTime,
        CancellationToken cancellationToken)
    {
        var current = network.Capture();
        var now = utcNow();
        cancellationToken.ThrowIfCancellationRequested();
        if (!before.MatchesCurrent(current)) return NetworkDiagnosticsStatus.NetworkChanged;
        var failure = policy.CheckInterval(startedAt, lastTime, now);
        if (failure == PublicIpDecisionReason.InvalidTimestamps) return NetworkDiagnosticsStatus.InvalidTimestamps;
        if (failure == PublicIpDecisionReason.StaleAssessment) return NetworkDiagnosticsStatus.Expired;
        lastTime = now;
        return null;
    }
}
