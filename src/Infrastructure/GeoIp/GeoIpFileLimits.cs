namespace IPGuard.Infrastructure.GeoIp;

/// <summary>Keeps transfer and decoder limits aligned for country database snapshots.</summary>
internal static class GeoIpFileLimits
{
    internal const int MaximumArchiveBytes = 16 * 1024 * 1024;
    internal const int MaximumDatabaseBytes = 64 * 1024 * 1024;
}
