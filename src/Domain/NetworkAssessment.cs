namespace IPGuard.Domain;

/// <summary>Groups one check's evidence under the network version captured before work began.</summary>
/// <remarks>
/// Adapters must include every configured source attempt and bound every included lookup by this interval.
/// Failed probes cannot establish that an address family is unavailable.
/// </remarks>
public sealed class NetworkAssessment
{
    /// <summary>Captures the check interval and both families; missing family evidence remains unknown.</summary>
    public NetworkAssessment(Guid networkVersion, DateTimeOffset startedAt, DateTimeOffset completedAt,
        IpFamilyEvidence? ipv4, IpFamilyEvidence? ipv6)
    {
        NetworkVersion = networkVersion;
        StartedAt = startedAt;
        CompletedAt = completedAt;
        Ipv4 = ipv4;
        Ipv6 = ipv6;
    }

    /// <summary>Gets the network generation, which must change after relevant route, interface, or VPN changes.</summary>
    public Guid NetworkVersion { get; }

    /// <summary>Gets the earliest start of evidence collection, used to bound the entire check's age.</summary>
    public DateTimeOffset StartedAt { get; }

    /// <summary>Gets the end of evidence collection; a future or inverted interval is invalid.</summary>
    public DateTimeOffset CompletedAt { get; }

    /// <summary>Gets IPv4 evidence, or null if the family was not assessed.</summary>
    public IpFamilyEvidence? Ipv4 { get; }

    /// <summary>Gets IPv6 evidence, or null if the family was not assessed.</summary>
    public IpFamilyEvidence? Ipv6 { get; }
}
