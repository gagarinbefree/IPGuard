using IPGuard.Domain;

namespace IPGuard.Application.GeoIp;

/// <summary>Distinguishes usable country data from absent, stale, and failed lookups.</summary>
public enum GeoIpLookupStatus
{
    /// <summary>The requested address has a country in a currently valid database.</summary>
    Found,
    /// <summary>The record or its country is missing or malformed.</summary>
    UnknownCountry,
    /// <summary>The input is outside the supported candidate public address ranges.</summary>
    InvalidAddress,
    /// <summary>The database has reached its exclusive freshness deadline.</summary>
    DatabaseExpired,
    /// <summary>The database was built after the supplied current time.</summary>
    DatabaseFromFuture,
    /// <summary>The snapshot is closed or has experienced a read failure.</summary>
    DatabaseError
}

/// <summary>Preserves a diagnostic outcome and address-bound evidence; failures contain no country.</summary>
public sealed class GeoIpLookupResult
{
    /// <summary>Captures lookup evidence and the original operational error when present.</summary>
    public GeoIpLookupResult(GeoIpLookupStatus status, GeoIpEvidence evidence, Exception? error = null)
    {
        Status = status;
        Evidence = evidence;
        Error = error;
    }

    /// <summary>Gets the lookup outcome, independent of the allowed-country policy.</summary>
    public GeoIpLookupStatus Status { get; }

    /// <summary>Gets evidence bound to the requested address and the loaded database's deadline.</summary>
    public GeoIpEvidence Evidence { get; }

    /// <summary>Gets the original read or closed-snapshot error, if any.</summary>
    public Exception? Error { get; }
}
