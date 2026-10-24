using System.Net;
using IPGuard.Application.GeoIp;
using IPGuard.Infrastructure.GeoIp;
using Xunit;

namespace IntegrationTests;

/// <summary>Exercises the real MMDB decoder using synthetic files without external network or policy changes.</summary>
public sealed class MmdbCountryDatabaseTests
{
    private static readonly TimeSpan MaximumAge = TimeSpan.FromDays(45);

    /// <summary>The real decoder reads country for both families and does not substitute registered_country.</summary>
    [Theory]
    [InlineData("149.101.100.1", "US")]
    [InlineData("81.2.69.160", "GB")]
    [InlineData("2001:218::1", "JP")]
    [InlineData("2001:220::", "SE")]
    public void Lookup_RealCountryRecords_AreAddressBound(string address, string expected)
    {
        using var database = MmdbCountryDatabase.Open(Fixture("GeoIP2-Country-Test.mmdb"), MaximumAge);

        GeoIpLookupResult result = database.Lookup(IPAddress.Parse(address), database.Info.BuiltAt.AddDays(1));

        Assert.Equal(GeoIpLookupStatus.Found, result.Status);
        Assert.Equal(expected, result.Evidence.CountryCode);
        Assert.Equal(address, result.Evidence.Address);
        Assert.Equal(database.Info.ValidUntil, result.Evidence.DatabaseValidUntil);
        Assert.Equal("GeoIP2-Country", database.Info.DatabaseType);
        Assert.Equal("FC12D6470B35B70BD3E4534DD433D3E262A6C73F7682F85C344E832D4190F02B", database.Info.Sha256);
    }

    /// <summary>A missing network record produces unknown evidence rather than a fallback country.</summary>
    [Theory]
    [InlineData("8.8.8.8")]
    [InlineData("5.83.124.1")]
    [InlineData("2a02:d500::1")]
    public void Lookup_AbsentCountry_IsUnknown(string address)
    {
        using var database = MmdbCountryDatabase.Open(Fixture("GeoIP2-Country-Test.mmdb"), MaximumAge);

        GeoIpLookupResult result = database.Lookup(IPAddress.Parse(address), database.Info.BuiltAt);

        Assert.Equal(GeoIpLookupStatus.UnknownCountry, result.Status);
        Assert.Null(result.Evidence.CountryCode);
    }

    /// <summary>A current file timestamp cannot refresh an old build; a loaded snapshot does not lock its source file.</summary>
    [Fact]
    public void Open_CopiedFile_UsesBuildDateAndPrivateSnapshot()
    {
        string path = TemporaryPath();
        try
        {
            File.Copy(Fixture("GeoIP2-Country-Test.mmdb"), path);
            File.SetLastWriteTimeUtc(path, DateTime.UtcNow);
            using var database = MmdbCountryDatabase.Open(path, MaximumAge);
            File.WriteAllText(path, "replaced while the snapshot is alive");

            Assert.Equal(GeoIpLookupStatus.Found,
                database.Lookup(IPAddress.Parse("149.101.100.1"), database.Info.BuiltAt).Status);
            Assert.Equal(database.Info.BuiltAt + MaximumAge, database.Info.ValidUntil);
            GeoIpLookupResult expired = database.Lookup(IPAddress.Parse("149.101.100.1"), database.Info.ValidUntil);
            Assert.Equal(GeoIpLookupStatus.DatabaseExpired, expired.Status);
            Assert.Null(expired.Evidence.CountryCode);
        }
        finally
        {
            File.Delete(path);
        }
    }

    /// <summary>Invalid MMDB bytes cannot expose a database snapshot.</summary>
    [Theory]
    [InlineData("")]
    [InlineData("not an MMDB database")]
    public void Open_CorruptFile_IsRejected(string content)
    {
        string path = TemporaryPath();
        try
        {
            File.WriteAllText(path, content);
            Assert.Throws<InvalidDataException>(() => MmdbCountryDatabase.Open(path, MaximumAge));
        }
        finally
        {
            File.Delete(path);
        }
    }

    /// <summary>Missing files fail explicitly rather than loading a bundled or remote fallback.</summary>
    [Fact]
    public void Open_MissingFile_IsRejected() =>
        Assert.Throws<FileNotFoundException>(() => MmdbCountryDatabase.Open(TemporaryPath(), MaximumAge));

    /// <summary>Non-country product metadata is rejected even when some records include a country.</summary>
    [Fact]
    public void Open_CityProduct_IsRejected() =>
        Assert.Throws<InvalidDataException>(() => MmdbCountryDatabase.Open(Fixture("GeoIP2-City-Test.mmdb"), MaximumAge));

    /// <summary>Oversized files are rejected before decoding or copying their content into memory.</summary>
    [Fact]
    public void Open_OversizedFile_IsRejected()
    {
        string path = TemporaryPath();
        try
        {
            using (var stream = File.Create(path))
            {
                stream.SetLength(64 * 1024 * 1024 + 1);
            }

            Assert.Throws<InvalidDataException>(() => MmdbCountryDatabase.Open(path, MaximumAge));
        }
        finally
        {
            File.Delete(path);
        }
    }

    /// <summary>Finds a copied synthetic fixture relative to the test executable.</summary>
    private static string Fixture(string fileName) => Path.Combine(AppContext.BaseDirectory, "GeoIp", fileName);

    /// <summary>Allocates a unique file name without modifying user data.</summary>
    private static string TemporaryPath() => Path.Combine(Path.GetTempPath(), $"ipguard-geoip-{Guid.NewGuid():N}.mmdb");
}
