using System.Net.Sockets;

namespace IPGuard.Domain;

/// <summary>Identifies the first failed prerequisite or readiness for separate route enforcement.</summary>
public enum PublicIpDecisionReason
{
    /// <summary>No completed assessment is available.</summary>
    NoAssessment,
    /// <summary>A missing or different network generation invalidates all collected evidence.</summary>
    NetworkChanged,
    /// <summary>The assessment interval is inverted or lies in the future.</summary>
    InvalidTimestamps,
    /// <summary>The oldest evidence has reached its exclusive age limit.</summary>
    StaleAssessment,
    /// <summary>At least one address family has not been accounted for.</summary>
    UnknownAddressFamily,
    /// <summary>An unavailable family contradicts its attached replies or country lookup.</summary>
    ConflictingFamilyEvidence,
    /// <summary>Neither family has a usable public address.</summary>
    NoAvailableAddressFamily,
    /// <summary>A source operator identity is missing.</summary>
    InvalidSource,
    /// <summary>At least one configured request failed, regardless of other successful replies.</summary>
    SourceFailed,
    /// <summary>Fewer than two independent source operators supplied replies.</summary>
    InsufficientSources,
    /// <summary>A reply has the wrong family, an IPv4 mapping, or an IPv6 scope identifier.</summary>
    AddressFamilyMismatch,
    /// <summary>Source replies disagree on the public address.</summary>
    ConflictingAddresses,
    /// <summary>No usable local database result or freshness deadline is available.</summary>
    GeoIpUnavailable,
    /// <summary>The country lookup belongs to a different address.</summary>
    GeoIpAddressMismatch,
    /// <summary>The local database has reached its exclusive freshness deadline.</summary>
    GeoIpDatabaseExpired,
    /// <summary>The lookup did not produce a two-letter country code.</summary>
    UnknownCountry,
    /// <summary>The observed country is outside the configured allowlist.</summary>
    CountryNotAllowed,
    /// <summary>Address prerequisites passed; this does not authorize network access.</summary>
    EligibleForRouteValidation
}

/// <summary>Reports address eligibility separately from permission and actual filter state.</summary>
public sealed class PublicIpDecision
{
    /// <summary>Creates a policy result and optionally identifies the failing family.</summary>
    internal PublicIpDecision(PublicIpDecisionReason reason, AddressFamily? family = null)
    {
        Reason = reason;
        Family = family;
    }

    /// <summary>Gets a stable diagnostic reason suitable for localization by GUI or CLI.</summary>
    public PublicIpDecisionReason Reason { get; }

    /// <summary>Gets the failing family, or null for assessment-wide results.</summary>
    public AddressFamily? Family { get; }

    /// <summary>Gets whether only the address prerequisites passed; route enforcement is still required.</summary>
    public bool IsEligible => Reason == PublicIpDecisionReason.EligibleForRouteValidation;
}
