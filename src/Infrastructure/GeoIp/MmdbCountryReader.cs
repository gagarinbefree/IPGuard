using System.Net;
using System.Security.Cryptography;
using MaxMind.Db;

namespace IPGuard.Infrastructure.GeoIp;

/// <summary>Decodes a bounded private MMDB copy with the official reader and no network fallback.</summary>
internal sealed class MmdbCountryReader : IMmdbCountryReader
{
    private readonly Reader reader;

    /// <summary>Hashes and loads the same write-locked file handle, then releases the source file.</summary>
    internal MmdbCountryReader(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length is <= 0 or > GeoIpFileLimits.MaximumDatabaseBytes)
        {
            throw new InvalidDataException("The MMDB file must contain between 1 byte and 64 MiB.");
        }

        Sha256 = Convert.ToHexString(SHA256.HashData(stream));
        stream.Position = 0;
        Reader? opened = null;
        try
        {
            // The stream constructor makes a private copy rather than mapping the replaceable source file.
            opened = new Reader(stream);
            Metadata metadata = opened.Metadata;
            if (metadata.BinaryFormatMajorVersion != 2 || metadata.BinaryFormatMinorVersion != 0 || metadata.IPVersion != 6
                || metadata.DatabaseType is not ("DBIP-Country-Lite" or "GeoLite2-Country" or "GeoIP2-Country"))
            {
                throw new InvalidDataException("Expected a supported IPv4/IPv6 country database in MMDB format 2.0.");
            }

            DatabaseType = metadata.DatabaseType;
            BuiltAt = new DateTimeOffset(metadata.BuildDate.ToUniversalTime());
            reader = opened;
        }
        catch (Exception error)
        {
            try
            {
                opened?.Dispose();
            }
            catch (Exception cleanupError)
            {
                throw new AggregateException("Loading MMDB and releasing the rejected reader failed.", error, cleanupError);
            }

            throw new InvalidDataException("The MMDB file or its country metadata is invalid.", error);
        }
    }

    /// <summary>Gets the validated country product type.</summary>
    public string DatabaseType { get; }

    /// <summary>Gets the provider's build timestamp, independent of download and modification times.</summary>
    public DateTimeOffset BuiltAt { get; }

    /// <summary>Gets a file identity rather than proof of provider authenticity.</summary>
    public string Sha256 { get; }

    /// <summary>Reads only country.iso_code, preserving absence and rejecting incompatible field types.</summary>
    public string? ReadCountry(IPAddress address)
    {
        Dictionary<string, object>? record = reader.Find<Dictionary<string, object>>(address);
        if (record is null || !record.TryGetValue("country", out object? country))
        {
            return null;
        }

        if (country is not IDictionary<string, object> fields)
        {
            throw new InvalidDataException("The MMDB country field must be a map.");
        }

        if (!fields.TryGetValue("iso_code", out object? code))
        {
            return null;
        }

        return code as string ?? throw new InvalidDataException("The MMDB country ISO code must be a string.");
    }

    /// <summary>Releases the private MMDB snapshot owned by the enclosing database.</summary>
    public void Dispose() => reader.Dispose();
}
