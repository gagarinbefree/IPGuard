namespace IPGuard.Application.GeoIp;

/// <summary>Describes a completed update, without implying that the database is connected to network protection.</summary>
public sealed class GeoIpUpdateResult
{
    /// <summary>Captures the published identity and whether a replacement was necessary.</summary>
    public GeoIpUpdateResult(bool changed, GeoIpDatabaseInfo info)
    {
        Changed = changed;
        Info = info;
    }

    /// <summary>Gets whether a validated candidate replaced the active file.</summary>
    public bool Changed { get; }

    /// <summary>Gets the active database's build-based validity and byte identity.</summary>
    public GeoIpDatabaseInfo Info { get; }
}
