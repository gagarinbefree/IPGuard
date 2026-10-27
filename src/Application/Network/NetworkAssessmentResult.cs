using IPGuard.Application.GeoIp;
using IPGuard.Application.PublicIp;
using IPGuard.Domain;

namespace IPGuard.Application.Network;

/// <summary>Distinguishes completed address prerequisites from discarded or unavailable assessment data.</summary>
public enum NetworkAssessmentStatus
{
    /// <summary>A current assessment was evaluated; its decision can still reject the evidence.</summary>
    Completed,
    /// <summary>Public address collection did not produce a complete snapshot.</summary>
    CollectionUnavailable,
    /// <summary>The captured network generation, availability, or invalidation signal changed.</summary>
    NetworkChanged,
    /// <summary>An observed clock moved backward during assessment.</summary>
    InvalidTimestamps,
    /// <summary>The oldest evidence reached its exclusive age limit before publication.</summary>
    EvidenceExpired,
    /// <summary>The local database or an address lookup was unavailable, expired, or built in the future.</summary>
    GeoIpUnavailable,
    /// <summary>The database adapter returned inconsistent metadata or address-bound evidence.</summary>
    InvalidGeoIpResult,
    /// <summary>An unexpected boundary or cleanup failure prevented publication.</summary>
    Failed
}

/// <summary>Keeps operational diagnostics separate from a completed assessment and any permission to send traffic.</summary>
public sealed class NetworkAssessmentResult
{
    /// <summary>Captures a completed snapshot or a discard reason, retaining source and database diagnostics.</summary>
    internal NetworkAssessmentResult(NetworkAssessmentStatus status, NetworkAssessmentSnapshot? snapshot = null,
        PublicIpCollectionResult? collection = null, GeoIpDatabaseInfo? database = null,
        GeoIpLookupResult? geoIpFailure = null, Exception? error = null)
    {
        Status = status;
        Snapshot = snapshot;
        Collection = collection;
        Database = database;
        GeoIpFailure = geoIpFailure;
        Error = error;
    }

    /// <summary>Gets the operational outcome; Completed does not authorize traffic.</summary>
    public NetworkAssessmentStatus Status { get; }

    /// <summary>Gets evaluated evidence only when the complete interval and generation remained current.</summary>
    public NetworkAssessmentSnapshot? Snapshot { get; }

    /// <summary>Gets original source attempts and collection failures for diagnostics.</summary>
    public PublicIpCollectionResult? Collection { get; }

    /// <summary>Gets the database identity used during this assessment, if opening succeeded.</summary>
    public GeoIpDatabaseInfo? Database { get; }

    /// <summary>Gets a validated unsuccessful lookup, if one stopped the assessment.</summary>
    public GeoIpLookupResult? GeoIpFailure { get; }

    /// <summary>Gets the original operational error, including combined assessment and cleanup failures.</summary>
    public Exception? Error { get; }
}

/// <summary>Binds a domain assessment and its preliminary decision to a live network invalidation signal.</summary>
public sealed class NetworkAssessmentSnapshot
{
    /// <summary>Captures completed evidence; consumers must recheck generation and time before subsequent use.</summary>
    internal NetworkAssessmentSnapshot(NetworkAssessment evidence, PublicIpDecision decision, NetworkSnapshot network)
    {
        Evidence = evidence;
        Decision = decision;
        Network = network;
    }

    /// <summary>Gets immutable evidence whose interval includes all lookups and database cleanup.</summary>
    public NetworkAssessment Evidence { get; }

    /// <summary>Gets the address-prerequisite decision at completion, without a route or filter guarantee.</summary>
    public PublicIpDecision Decision { get; }

    /// <summary>Gets the original generation and its permanent invalidation token, which remains live after return.</summary>
    public NetworkSnapshot Network { get; }

    /// <summary>Gets the earliest country-database deadline across either family, or null when no lookup evidence exists.</summary>
    public DateTimeOffset? DatabaseValidUntil
    {
        get
        {
            var ipv4 = Evidence.Ipv4?.GeoIp?.DatabaseValidUntil;
            var ipv6 = Evidence.Ipv6?.GeoIp?.DatabaseValidUntil;
            if (!ipv4.HasValue) return ipv6;
            if (!ipv6.HasValue) return ipv4;
            return ipv4.Value <= ipv6.Value ? ipv4 : ipv6;
        }
    }
}
