using System.Net;

namespace IPGuard.Domain;

/// <summary>Binds a local database lookup to its address and the database's freshness deadline.</summary>
public sealed class GeoIpEvidence
{
    /// <summary>Captures a lookup; missing country or deadline represents unavailable evidence.</summary>
    public GeoIpEvidence(IPAddress address, string? countryCode, DateTimeOffset? databaseValidUntil)
    {
        ArgumentNullException.ThrowIfNull(address);
        Address = address.ToString();
        CountryCode = countryCode;
        DatabaseValidUntil = databaseValidUntil;
    }

    /// <summary>Gets the immutable address actually looked up, rather than the remote service's address.</summary>
    public string Address { get; }

    /// <summary>Gets the database's two-letter country code, or null when the lookup failed.</summary>
    public string? CountryCode { get; }

    /// <summary>Gets the exclusive freshness deadline established by the database adapter.</summary>
    public DateTimeOffset? DatabaseValidUntil { get; }
}
