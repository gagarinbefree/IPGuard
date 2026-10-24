using System.Net;
using IPGuard.Application.GeoIp;
using IPGuard.Infrastructure.GeoIp;
using Xunit;

namespace UnitTests;

/// <summary>Checks local country evidence, build-based expiry, and closed or faulty snapshot handling.</summary>
public sealed class MmdbCountryDatabaseTests
{
    private static readonly DateTimeOffset BuiltAt = new(2026, 10, 1, 0, 0, 0, TimeSpan.Zero);
    private static readonly TimeSpan MaximumAge = TimeSpan.FromDays(45);

    /// <summary>Both IP families preserve the requested address and never treat a foreign country as an error.</summary>
    [Theory]
    [InlineData("8.8.8.8", "US")]
    [InlineData("81.2.69.160", "GB")]
    [InlineData("2001:218::1", "JP")]
    public void Lookup_FreshCountry_PreservesEvidence(string address, string country)
    {
        using var database = new MmdbCountryDatabase(new FakeReader(_ => country), MaximumAge);

        GeoIpLookupResult result = database.Lookup(IPAddress.Parse(address), BuiltAt.AddDays(10));

        Assert.Equal(GeoIpLookupStatus.Found, result.Status);
        Assert.Equal(address, result.Evidence.Address);
        Assert.Equal(country, result.Evidence.CountryCode);
        Assert.Equal(BuiltAt + MaximumAge, result.Evidence.DatabaseValidUntil);
        Assert.Null(result.Error);
        Assert.Equal("GeoIP2-Country", database.Info.DatabaseType);
        Assert.Equal(BuiltAt, database.Info.BuiltAt);
        Assert.Equal(BuiltAt + MaximumAge, database.Info.ValidUntil);
        Assert.Equal(new string('A', 64), database.Info.Sha256);
    }

    /// <summary>Missing, malformed, and pseudo-country codes produce no country evidence.</summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("USA")]
    [InlineData("us")]
    [InlineData(" US ")]
    [InlineData("Uſ")]
    [InlineData("U1")]
    [InlineData("XX")]
    [InlineData("ZZ")]
    [InlineData("EU")]
    [InlineData("AP")]
    public void Lookup_UnknownCountry_DoesNotInventEvidence(string? country)
    {
        using var database = new MmdbCountryDatabase(new FakeReader(_ => country), MaximumAge);

        AssertFailure(database.Lookup(IPAddress.Parse("8.8.8.8"), BuiltAt), GeoIpLookupStatus.UnknownCountry);
    }

    /// <summary>Private, reserved, scoped, and mapped addresses never reach the database.</summary>
    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("10.0.0.1")]
    [InlineData("192.0.2.1")]
    [InlineData("224.0.0.1")]
    [InlineData("::1")]
    [InlineData("2001:db8::1")]
    [InlineData("::ffff:8.8.8.8")]
    [InlineData("2001:218::1%2")]
    public void Lookup_InvalidAddress_DoesNotRead(string address)
    {
        var reader = new FakeReader(_ => "US");
        using var database = new MmdbCountryDatabase(reader, MaximumAge);

        AssertFailure(database.Lookup(IPAddress.Parse(address), BuiltAt), GeoIpLookupStatus.InvalidAddress);
        Assert.Equal(0, reader.Reads);
    }

    /// <summary>Expiry is exclusive; future metadata also prevents decoding a country.</summary>
    [Theory]
    [InlineData(-1, GeoIpLookupStatus.DatabaseFromFuture)]
    [InlineData(45 * 86400, GeoIpLookupStatus.DatabaseExpired)]
    [InlineData(46 * 86400, GeoIpLookupStatus.DatabaseExpired)]
    public void Lookup_InvalidTime_DoesNotRead(int seconds, GeoIpLookupStatus expected)
    {
        var reader = new FakeReader(_ => "US");
        using var database = new MmdbCountryDatabase(reader, MaximumAge);

        AssertFailure(database.Lookup(IPAddress.Parse("8.8.8.8"), BuiltAt.AddSeconds(seconds)), expected);
        Assert.Equal(0, reader.Reads);
    }

    /// <summary>The last tick before expiry remains usable, without refreshing the deadline on access.</summary>
    [Fact]
    public void Lookup_LastFreshTick_IsFound()
    {
        using var database = new MmdbCountryDatabase(new FakeReader(_ => "US"), MaximumAge);

        Assert.Equal(GeoIpLookupStatus.Found,
            database.Lookup(IPAddress.Parse("8.8.8.8"), (BuiltAt + MaximumAge).AddTicks(-1)).Status);
    }

    /// <summary>A decoder error permanently faults that snapshot and retains its original diagnostic.</summary>
    [Fact]
    public void Lookup_ReadFailure_LatchesWithoutReusingPreviousCountry()
    {
        var error = new InvalidDataException("Broken country record");
        int reads = 0;
        var reader = new FakeReader(_ => ++reads == 1 ? "US" : throw error);
        using var database = new MmdbCountryDatabase(reader, MaximumAge);
        var address = IPAddress.Parse("8.8.8.8");
        Assert.Equal(GeoIpLookupStatus.Found, database.Lookup(address, BuiltAt).Status);

        for (int index = 0; index < 2; index++)
        {
            GeoIpLookupResult result = database.Lookup(address, BuiltAt);
            AssertFailure(result, GeoIpLookupStatus.DatabaseError);
            Assert.Same(error, result.Error);
        }

        Assert.Equal(2, reader.Reads);
    }

    /// <summary>Disposal is idempotent and a closed snapshot never reads or returns cached country data.</summary>
    [Fact]
    public void Dispose_ClosesReaderExactlyOnce()
    {
        var reader = new FakeReader(_ => "US");
        var database = new MmdbCountryDatabase(reader, MaximumAge);
        database.Dispose();
        database.Dispose();

        GeoIpLookupResult result = database.Lookup(IPAddress.Parse("8.8.8.8"), BuiltAt);

        AssertFailure(result, GeoIpLookupStatus.DatabaseError);
        Assert.IsType<ObjectDisposedException>(result.Error);
        Assert.Equal(1, reader.Disposals);
        Assert.Equal(0, reader.Reads);
    }

    /// <summary>Cleanup failures remain visible and cannot make a closed snapshot usable again.</summary>
    [Fact]
    public void Dispose_ReaderFailure_IsVisibleAndRemainsClosed()
    {
        var error = new IOException("Snapshot cleanup failed");
        var reader = new FakeReader(_ => "US", () => throw error);
        var database = new MmdbCountryDatabase(reader, MaximumAge);

        Assert.Same(error, Assert.Throws<IOException>(database.Dispose));
        database.Dispose();
        AssertFailure(database.Lookup(IPAddress.Parse("8.8.8.8"), BuiltAt), GeoIpLookupStatus.DatabaseError);
        Assert.Equal(1, reader.Disposals);
        Assert.Equal(0, reader.Reads);
    }

    /// <summary>Opening and cleanup errors are both retained when ownership transfer fails.</summary>
    [Fact]
    public void Constructor_InvalidAgeAndCleanupFailure_PreservesBothErrors()
    {
        var cleanupError = new IOException("Snapshot cleanup failed");
        var reader = new FakeReader(_ => "US", () => throw cleanupError);

        AggregateException result = Assert.Throws<AggregateException>(() => new MmdbCountryDatabase(reader, TimeSpan.Zero));

        Assert.IsType<ArgumentOutOfRangeException>(result.InnerExceptions[0]);
        Assert.Same(cleanupError, result.InnerExceptions[1]);
        Assert.Equal(1, reader.Disposals);
    }

    /// <summary>Mutable caller address objects are neither retained in evidence nor handed to the decoder.</summary>
    [Fact]
    public void Lookup_MutableAddress_IsCopied()
    {
        var address = IPAddress.Parse("2001:218::1");
        var reader = new FakeReader(received => { Assert.NotSame(address, received); return "JP"; });
        using var database = new MmdbCountryDatabase(reader, MaximumAge);

        GeoIpLookupResult result = database.Lookup(address, BuiltAt);
        address.ScopeId = 2;

        Assert.Equal("2001:218::1", result.Evidence.Address);
        Assert.Equal("JP", result.Evidence.CountryCode);
    }

    /// <summary>Invalid freshness settings are rejected while releasing an already transferred decoder.</summary>
    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(long.MaxValue)]
    public void Constructor_InvalidMaximumAge_DisposesReader(long ticks)
    {
        var reader = new FakeReader(_ => "US");

        Assert.Throws<ArgumentOutOfRangeException>(() => new MmdbCountryDatabase(reader, TimeSpan.FromTicks(ticks)));
        Assert.Equal(1, reader.Disposals);
    }

    /// <summary>A failed lookup always clears country data while retaining the actual build-based deadline.</summary>
    private static void AssertFailure(GeoIpLookupResult result, GeoIpLookupStatus expected)
    {
        Assert.Equal(expected, result.Status);
        Assert.Null(result.Evidence.CountryCode);
        Assert.Equal(BuiltAt + MaximumAge, result.Evidence.DatabaseValidUntil);
    }

    /// <summary>Provides deterministic country records and observes decoder ownership without I/O.</summary>
    private sealed class FakeReader : IMmdbCountryReader
    {
        private readonly Func<IPAddress, string?> read;
        private readonly Action? dispose;

        /// <summary>Captures the per-address decoder behavior.</summary>
        internal FakeReader(Func<IPAddress, string?> read, Action? dispose = null)
        {
            this.read = read;
            this.dispose = dispose;
        }

        /// <summary>Gets the supported country product used by these tests.</summary>
        public string DatabaseType => "GeoIP2-Country";

        /// <summary>Gets the fixed database metadata timestamp.</summary>
        public DateTimeOffset BuiltAt => MmdbCountryDatabaseTests.BuiltAt;

        /// <summary>Gets a stable test identity, independent of file timestamps.</summary>
        public string Sha256 => new('A', 64);

        /// <summary>Gets the number of actual decoding attempts.</summary>
        internal int Reads { get; private set; }

        /// <summary>Gets the number of ownership releases.</summary>
        internal int Disposals { get; private set; }

        /// <summary>Observes a read before invoking the configured behavior.</summary>
        public string? ReadCountry(IPAddress address)
        {
            Reads++;
            return read(address);
        }

        /// <summary>Records each ownership release.</summary>
        public void Dispose()
        {
            Disposals++;
            dispose?.Invoke();
        }
    }
}
