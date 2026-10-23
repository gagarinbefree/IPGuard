namespace IPGuard.Domain;

/// <summary>Describes whether a network snapshot has accounted for one address family.</summary>
public enum IpFamilyAvailability
{
    /// <summary>Availability has not been established; failed probes do not establish absence.</summary>
    Unknown,
    /// <summary>The network adapter reports no usable path; route enforcement must confirm this before granting access.</summary>
    Unavailable,
    /// <summary>The family requires independent public address replies and a local country lookup.</summary>
    Available
}

/// <summary>Holds immutable source and country evidence for one address family.</summary>
public sealed class IpFamilyEvidence
{
    /// <summary>Copies the source list so later collection edits cannot change an assessment.</summary>
    public IpFamilyEvidence(IpFamilyAvailability availability, IEnumerable<PublicIpObservation> observations, GeoIpEvidence? geoIp = null)
    {
        ArgumentNullException.ThrowIfNull(observations);
        Availability = availability;
        Observations = Array.AsReadOnly(observations.ToArray());
        GeoIp = geoIp;
    }

    /// <summary>Gets the reported family availability, which is not proof of an enforced route.</summary>
    public IpFamilyAvailability Availability { get; }

    /// <summary>Gets all replies, including failed sources; partial success must remain visible.</summary>
    public IReadOnlyList<PublicIpObservation> Observations { get; }

    /// <summary>Gets the local database result for the agreed address, if available.</summary>
    public GeoIpEvidence? GeoIp { get; }
}
