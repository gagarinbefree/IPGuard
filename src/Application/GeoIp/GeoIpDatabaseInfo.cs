namespace IPGuard.Application.GeoIp;

/// <summary>Identifies database bytes and their exclusive freshness deadline, without asserting authenticity.</summary>
public sealed class GeoIpDatabaseInfo
{
    /// <summary>Captures metadata from the database, rather than its filesystem timestamps.</summary>
    public GeoIpDatabaseInfo(string databaseType, DateTimeOffset builtAt, DateTimeOffset validUntil, string sha256)
    {
        DatabaseType = databaseType;
        BuiltAt = builtAt;
        ValidUntil = validUntil;
        Sha256 = sha256;
    }

    /// <summary>Gets the product type recorded in MMDB metadata.</summary>
    public string DatabaseType { get; }

    /// <summary>Gets the provider's UTC build timestamp.</summary>
    public DateTimeOffset BuiltAt { get; }

    /// <summary>Gets the exclusive deadline calculated from the build timestamp and maximum age.</summary>
    public DateTimeOffset ValidUntil { get; }

    /// <summary>Gets the SHA-256 of the loaded bytes; this identifies a file but does not authenticate its provider.</summary>
    public string Sha256 { get; }
}
