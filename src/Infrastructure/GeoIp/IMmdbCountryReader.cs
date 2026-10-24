using System.Net;

namespace IPGuard.Infrastructure.GeoIp;

/// <summary>Isolates MMDB decoding and ownership from freshness and lookup failure handling.</summary>
internal interface IMmdbCountryReader : IDisposable
{
    /// <summary>Gets the country product type validated while opening the file.</summary>
    string DatabaseType { get; }

    /// <summary>Gets the UTC build timestamp stored in the database.</summary>
    DateTimeOffset BuiltAt { get; }

    /// <summary>Gets the digest of exactly the loaded file bytes.</summary>
    string Sha256 { get; }

    /// <summary>Reads only country.iso_code; registered and represented countries are not substitutes.</summary>
    string? ReadCountry(IPAddress address);
}
