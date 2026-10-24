using System.Net.Sockets;
using IPGuard.Application.Network;
using IPGuard.Domain;

namespace IPGuard.Application.PublicIp;

/// <summary>Collects public address attempts only while one known network generation remains current.</summary>
public sealed class PublicIpCollector
{
    private readonly IPublicIpProbe probe;
    private readonly INetworkSnapshotProvider network;
    private readonly PublicIpSource[] sources;
    private readonly Func<DateTimeOffset> utcNow;

    /// <summary>Copies source configuration and composes probing, cached network state, and an explicit clock.</summary>
    public PublicIpCollector(IPublicIpProbe probe, INetworkSnapshotProvider network,
        IEnumerable<PublicIpSource> sources, Func<DateTimeOffset>? utcNow = null)
    {
        ArgumentNullException.ThrowIfNull(probe);
        ArgumentNullException.ThrowIfNull(network);
        ArgumentNullException.ThrowIfNull(sources);
        this.sources = sources.ToArray();
        foreach (PublicIpSource source in this.sources)
        {
            ArgumentNullException.ThrowIfNull(source);
        }

        this.probe = probe;
        this.network = network;
        this.utcNow = utcNow ?? (() => DateTimeOffset.UtcNow);
    }

    /// <summary>Discards evidence on network invalidation or failure; caller cancellation is propagated.</summary>
    public async Task<PublicIpCollectionResult> CollectAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        NetworkSnapshot? before = null;
        try
        {
            DateTimeOffset startedAt = utcNow();
            before = network.Capture();
            cancellationToken.ThrowIfCancellationRequested();
            if (before is null || !IsKnown(before))
            {
                return new(PublicIpCollectionStatus.NetworkUnavailable);
            }

            if (before.Invalidated.IsCancellationRequested)
            {
                return new(PublicIpCollectionStatus.NetworkChanged);
            }

            using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, before.Invalidated);
            PublicIpSource[] expected = sources.Where(source => IsAvailable(source.Family, before)).ToArray();
            IReadOnlyList<PublicIpReadResult>? replies = expected.Length == 0
                ? Array.Empty<PublicIpReadResult>()
                : await probe.ReadAllAsync(Array.AsReadOnly(expected), cancellation.Token).ConfigureAwait(false);
            PublicIpReadResult[]? attempts = replies?.ToArray();
            cancellationToken.ThrowIfCancellationRequested();
            if (before.Invalidated.IsCancellationRequested)
            {
                return new(PublicIpCollectionStatus.NetworkChanged);
            }

            NetworkSnapshot? after = network.Capture();
            DateTimeOffset completedAt = utcNow();
            cancellationToken.ThrowIfCancellationRequested();
            if (!before.MatchesCurrent(after))
            {
                return new(PublicIpCollectionStatus.NetworkChanged);
            }

            if (completedAt < startedAt)
            {
                return new(PublicIpCollectionStatus.InvalidTimestamps);
            }

            if (attempts is null || !HasEveryAttempt(expected, attempts))
            {
                return new(PublicIpCollectionStatus.InvalidProbeResult);
            }

            return new(PublicIpCollectionStatus.Completed, new PublicIpSnapshot(before, startedAt, completedAt, attempts));
        }
        catch (Exception error)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (before?.Invalidated.IsCancellationRequested == true)
            {
                return new(PublicIpCollectionStatus.NetworkChanged, error: error is OperationCanceledException ? null : error);
            }

            return new(PublicIpCollectionStatus.Failed, error: error);
        }
    }

    /// <summary>Requires a version, a usable invalidation signal, and explicit knowledge of both families.</summary>
    private static bool IsKnown(NetworkSnapshot snapshot) => snapshot.Version != Guid.Empty
        && snapshot.Invalidated.CanBeCanceled
        && snapshot.Ipv4 is IpFamilyAvailability.Available or IpFamilyAvailability.Unavailable
        && snapshot.Ipv6 is IpFamilyAvailability.Available or IpFamilyAvailability.Unavailable;

    /// <summary>Selects sources using captured availability without deriving absence from failed requests.</summary>
    private static bool IsAvailable(AddressFamily family, NetworkSnapshot snapshot) =>
        (family == AddressFamily.InterNetwork ? snapshot.Ipv4 : snapshot.Ipv6) == IpFamilyAvailability.Available;

    /// <summary>Verifies complete ordered source coverage without taking over domain consensus or country rules.</summary>
    private static bool HasEveryAttempt(PublicIpSource[] expected, PublicIpReadResult[] attempts)
    {
        if (attempts.Length != expected.Length)
        {
            return false;
        }

        for (int index = 0; index < expected.Length; index++)
        {
            PublicIpReadResult? attempt = attempts[index];
            if (attempt is null || !Enum.IsDefined(attempt.Status)
                || (attempt.Status == PublicIpReadStatus.Success && attempt.Observation.Address is null)
                || attempt.Source.OperatorId != expected[index].OperatorId || attempt.Source.Endpoint != expected[index].Endpoint
                || attempt.Source.Family != expected[index].Family)
            {
                return false;
            }
        }

        return true;
    }
}
