using IPGuard.Domain;

namespace IPGuard.Application.Network;

/// <summary>Combines local observations and public-address prerequisites under one outer generation and interval.</summary>
public sealed class NetworkCheckCollector : INetworkDiagnosticsSource
{
    private readonly NetworkDiagnosticsCollector local;
    private readonly NetworkAssessor assessor;
    private readonly INetworkSnapshotProvider network;
    private readonly PublicIpPolicy policy;
    private readonly Func<DateTimeOffset> utcNow;
    private readonly NetworkEvidenceLifetime lifetime;

    /// <summary>Composes existing collectors and the final policy without HTTP, Windows, or GUI dependencies.</summary>
    public NetworkCheckCollector(NetworkDiagnosticsCollector local, NetworkAssessor assessor, INetworkSnapshotProvider network,
        PublicIpPolicy policy, Func<DateTimeOffset>? utcNow = null)
    {
        ArgumentNullException.ThrowIfNull(local);
        ArgumentNullException.ThrowIfNull(assessor);
        ArgumentNullException.ThrowIfNull(network);
        ArgumentNullException.ThrowIfNull(policy);
        this.local = local;
        this.assessor = assessor;
        this.network = network;
        this.policy = policy;
        this.utcNow = utcNow ?? (() => DateTimeOffset.UtcNow);
        lifetime = new NetworkEvidenceLifetime(network, policy, this.utcNow);
    }

    /// <summary>Supplies the outer policy's deadline to the shared refresh loop.</summary>
    TimeSpan INetworkDiagnosticsSource.MaximumAge => policy.MaximumEvidenceAge;

    /// <summary>Collects complete diagnostics asynchronously; synchronous local boundaries must run off the UI thread.</summary>
    public async Task<NetworkDiagnosticsResult> CollectAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        NetworkSnapshot? before = null;
        NetworkAssessmentResult? assessment = null;
        try
        {
            var startedAt = utcNow();
            before = network.Capture();
            cancellationToken.ThrowIfCancellationRequested();
            if (before is null || before.Version == Guid.Empty || !before.Invalidated.CanBeCanceled || before.Invalidated.IsCancellationRequested)
                return new(NetworkDiagnosticsStatus.NetworkUnavailable);

            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, before.Invalidated);
            var localResult = local.Collect(linked.Token);
            var lastTime = startedAt;
            var failure = lifetime.Check(before, startedAt, ref lastTime, cancellationToken);
            if (failure.HasValue) return new(failure.Value, error: localResult.Error);
            if (localResult.Status != NetworkDiagnosticsStatus.Completed) return localResult;
            var localSnapshot = localResult.Snapshot ?? throw new InvalidDataException("Completed local diagnostics have no snapshot.");
            if (!before.MatchesCurrent(localSnapshot.Network)) return new(NetworkDiagnosticsStatus.NetworkChanged);
            if (localSnapshot.StartedAt < startedAt || localSnapshot.CompletedAt > lastTime)
                return new(NetworkDiagnosticsStatus.InvalidTimestamps);

            var addressStartedAfter = lastTime;
            assessment = await assessor.AssessAsync(linked.Token).ConfigureAwait(false);
            failure = lifetime.Check(before, startedAt, ref lastTime, cancellationToken);
            if (failure.HasValue) return new(failure.Value, error: assessment.Error, assessment: assessment);
            if (assessment.Status != NetworkAssessmentStatus.Completed)
                return new(MapAssessmentFailure(assessment.Status), error: assessment.Error, assessment: assessment);
            var addressSnapshot = assessment.Snapshot ?? throw new InvalidDataException("Completed address assessment has no snapshot.");
            if (!before.MatchesCurrent(addressSnapshot.Network)) return new(NetworkDiagnosticsStatus.NetworkChanged, assessment: assessment);
            if (addressSnapshot.Evidence.StartedAt < addressStartedAfter || addressSnapshot.Evidence.CompletedAt > lastTime)
                return new(NetworkDiagnosticsStatus.InvalidTimestamps, assessment: assessment);

            var evidence = new NetworkAssessment(before.Version, startedAt, lastTime,
                addressSnapshot.Evidence.Ipv4, addressSnapshot.Evidence.Ipv6);
            var finalAssessment = new NetworkAssessmentSnapshot(evidence, policy.Evaluate(evidence, before.Version, lastTime), before);
            if (finalAssessment.DatabaseValidUntil <= lastTime) return new(NetworkDiagnosticsStatus.Expired, assessment: assessment);
            var snapshot = new NetworkDiagnosticsSnapshot(before, startedAt, lastTime, localSnapshot.Routes, localSnapshot.Proxy,
                localSnapshot.Connections.ToArray(), finalAssessment);
            return new(NetworkDiagnosticsStatus.Completed, snapshot, assessment: assessment);
        }
        catch (Exception error)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (before?.Invalidated.IsCancellationRequested == true)
                return new(NetworkDiagnosticsStatus.NetworkChanged, error: error is OperationCanceledException ? null : error, assessment: assessment);
            return new(NetworkDiagnosticsStatus.Failed, error: error, assessment: assessment);
        }
    }

    /// <summary>Revalidates the entire interval and database lifetime without repeating HTTP or local reads.</summary>
    NetworkDiagnosticsStatus? INetworkDiagnosticsSource.CheckCurrent(NetworkDiagnosticsSnapshot snapshot, ref DateTimeOffset lastTime)
    {
        var failure = lifetime.Check(snapshot.Network, snapshot.StartedAt, ref lastTime, default);
        if (failure.HasValue) return failure;
        if (snapshot.Assessment is null) return NetworkDiagnosticsStatus.Failed;
        return snapshot.Assessment.DatabaseValidUntil <= lastTime ? NetworkDiagnosticsStatus.Expired : null;
    }

    /// <summary>Preserves outer lifetime failures and retains detailed operational causes in Assessment.</summary>
    private static NetworkDiagnosticsStatus MapAssessmentFailure(NetworkAssessmentStatus status) => status switch
    {
        NetworkAssessmentStatus.NetworkChanged => NetworkDiagnosticsStatus.NetworkChanged,
        NetworkAssessmentStatus.InvalidTimestamps => NetworkDiagnosticsStatus.InvalidTimestamps,
        NetworkAssessmentStatus.EvidenceExpired => NetworkDiagnosticsStatus.Expired,
        _ => NetworkDiagnosticsStatus.Failed
    };
}
