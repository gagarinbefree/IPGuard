namespace IPGuard.Application.GeoIp;

/// <summary>Downloads a complete country database from a trusted provider without publishing it.</summary>
public interface IGeoIpDatabaseDownload
{
    /// <summary>Gets the exact MMDB product expected from this provider.</summary>
    string DatabaseType { get; }

    /// <summary>Writes decoded database bytes to a caller-owned stream; partial writes are never usable updates.</summary>
    Task DownloadAsync(Stream destination, DateTimeOffset now, CancellationToken cancellationToken);
}
