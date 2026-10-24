using System.Net;
using IPGuard.Application.GeoIp;
using IPGuard.Domain;
using IPGuard.Infrastructure.PublicIp;

namespace IPGuard.Infrastructure.GeoIp;

/// <summary>Owns one local MMDB snapshot and rejects unavailable or stale country evidence.</summary>
public sealed class MmdbCountryDatabase : IGeoIpCountryDatabase
{
    private readonly object gate = new();
    private readonly IMmdbCountryReader reader;
    private Exception? failure;
    private bool disposed;

    /// <summary>Opens a bounded country database; invalid files and metadata fail before exposing a snapshot.</summary>
    public static MmdbCountryDatabase Open(string path, TimeSpan maximumAge)
    {
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(maximumAge, TimeSpan.Zero);
        return new MmdbCountryDatabase(new MmdbCountryReader(path), maximumAge);
    }

    /// <summary>Takes ownership of a decoder, allowing deterministic tests without filesystem access.</summary>
    internal MmdbCountryDatabase(IMmdbCountryReader reader, TimeSpan maximumAge)
    {
        ArgumentNullException.ThrowIfNull(reader);
        this.reader = reader;
        try
        {
            ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(maximumAge, TimeSpan.Zero);
            Info = new GeoIpDatabaseInfo(reader.DatabaseType, reader.BuiltAt, reader.BuiltAt + maximumAge, reader.Sha256);
        }
        catch (Exception error)
        {
            try
            {
                reader.Dispose();
            }
            catch (Exception cleanupError)
            {
                throw new AggregateException("Opening the GeoIP snapshot and releasing its reader failed.", error, cleanupError);
            }

            throw;
        }
    }

    /// <summary>Gets the loaded byte identity and build-based validity interval.</summary>
    public GeoIpDatabaseInfo Info { get; }

    /// <summary>Reads a country without network access; failed snapshots cannot recover implicitly.</summary>
    public GeoIpLookupResult Lookup(IPAddress address, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(address);
        // IPAddress.ScopeId is mutable; do not retain or pass the caller's object to the decoder.
        IPAddress requested = IPAddress.Parse(address.ToString());
        lock (gate)
        {
            if (failure is not null)
            {
                return Result(GeoIpLookupStatus.DatabaseError, requested, error: failure);
            }

            if (!PublicAddressParser.IsCandidate(requested))
            {
                return Result(GeoIpLookupStatus.InvalidAddress, requested);
            }

            if (now < Info.BuiltAt)
            {
                return Result(GeoIpLookupStatus.DatabaseFromFuture, requested);
            }

            if (now >= Info.ValidUntil)
            {
                return Result(GeoIpLookupStatus.DatabaseExpired, requested);
            }

            try
            {
                string? country = reader.ReadCountry(requested);
                return IsCountryCode(country)
                    ? Result(GeoIpLookupStatus.Found, requested, country)
                    : Result(GeoIpLookupStatus.UnknownCountry, requested);
            }
            catch (Exception error)
            {
                failure = error;
                return Result(GeoIpLookupStatus.DatabaseError, requested, error: error);
            }
        }
    }

    /// <summary>Closes this snapshot once; later lookups cannot return a country.</summary>
    public void Dispose()
    {
        lock (gate)
        {
            if (disposed)
            {
                return;
            }

            disposed = true;
            failure ??= new ObjectDisposedException(nameof(MmdbCountryDatabase));
            reader.Dispose();
        }
    }

    /// <summary>Accepts canonical two-letter codes, excluding common non-country placeholders.</summary>
    private static bool IsCountryCode(string? country) => country is { Length: 2 }
        && country.All(character => character is >= 'A' and <= 'Z')
        && country is not ("XX" or "ZZ" or "EU" or "AP");

    /// <summary>Creates evidence with the snapshot's actual deadline and no cached or fallback country.</summary>
    private GeoIpLookupResult Result(GeoIpLookupStatus status, IPAddress address, string? country = null, Exception? error = null) =>
        new(status, new GeoIpEvidence(address, country, Info.ValidUntil), error);
}
