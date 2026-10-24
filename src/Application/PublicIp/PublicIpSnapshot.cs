using IPGuard.Application.Network;

namespace IPGuard.Application.PublicIp;

/// <summary>Records a completed collection interval and every attempted source under one network generation.</summary>
/// <remarks>Consumers must recheck network invalidation and freshness before using this data; it contains no permission.</remarks>
public sealed class PublicIpSnapshot
{
    /// <summary>Copies the validated attempt list while retaining the generation's live invalidation signal.</summary>
    internal PublicIpSnapshot(NetworkSnapshot network, DateTimeOffset startedAt, DateTimeOffset completedAt,
        IEnumerable<PublicIpReadResult> attempts)
    {
        Network = network;
        StartedAt = startedAt;
        CompletedAt = completedAt;
        Attempts = Array.AsReadOnly(attempts.ToArray());
    }

    /// <summary>Gets the captured generation, address-family availability, and invalidation signal.</summary>
    public NetworkSnapshot Network { get; }

    /// <summary>Gets the beginning of collection, before network capture and every source attempt.</summary>
    public DateTimeOffset StartedAt { get; }

    /// <summary>Gets the completion time after all attempts and the final network capture.</summary>
    public DateTimeOffset CompletedAt { get; }

    /// <summary>Gets all attempts in configured order, including failures and conflicting addresses.</summary>
    public IReadOnlyList<PublicIpReadResult> Attempts { get; }
}
