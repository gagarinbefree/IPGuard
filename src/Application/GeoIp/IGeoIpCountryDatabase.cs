using System.Net;

namespace IPGuard.Application.GeoIp;

/// <summary>Looks up countries in one immutable local database snapshot; never grants network access.</summary>
public interface IGeoIpCountryDatabase : IDisposable
{
    /// <summary>Gets the identity and build-based freshness of the loaded snapshot.</summary>
    GeoIpDatabaseInfo Info { get; }

    /// <summary>Looks up one candidate public address at an explicit time without network requests.</summary>
    GeoIpLookupResult Lookup(IPAddress address, DateTimeOffset now);
}
