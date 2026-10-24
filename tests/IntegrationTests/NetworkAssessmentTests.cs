using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using IPGuard.Application.GeoIp;
using IPGuard.Application.Network;
using IPGuard.Application.PublicIp;
using IPGuard.Domain;
using IPGuard.Infrastructure.GeoIp;
using IPGuard.Infrastructure.PublicIp;
using Xunit;

namespace IntegrationTests;

/// <summary>Combines the real HTTPS response reader, local MMDB decoder, application scenario, and domain policy safely.</summary>
public sealed class NetworkAssessmentTests
{
    private static readonly TimeSpan DatabaseAge = TimeSpan.FromDays(45);

    /// <summary>Actual country records for both families retain their countries and follow the supplied allowlist.</summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AssessAsync_RealBothFamilyLookups_FollowDomainPolicy(bool allowJapan)
    {
        var network = new SnapshotProvider(TestContext.Current.CancellationToken);
        var policy = new PublicIpPolicy(TimeSpan.FromMinutes(5), allowJapan ? ["US", "JP"] : ["US"]);
        NetworkAssessor assessor = Assessor(network, "149.101.100.1", () => MmdbCountryDatabase.Open(Fixture, DatabaseAge), policy: policy);

        NetworkAssessmentResult result = await assessor.AssessAsync(TestContext.Current.CancellationToken);

        NetworkAssessmentSnapshot snapshot = Assert.IsType<NetworkAssessmentSnapshot>(result.Snapshot);
        Assert.Equal(NetworkAssessmentStatus.Completed, result.Status);
        Assert.Equal("US", snapshot.Evidence.Ipv4!.GeoIp!.CountryCode);
        Assert.Equal("JP", snapshot.Evidence.Ipv6!.GeoIp!.CountryCode);
        Assert.Equal(allowJapan, snapshot.Decision.IsEligible);
        Assert.Equal(allowJapan ? PublicIpDecisionReason.EligibleForRouteValidation : PublicIpDecisionReason.CountryNotAllowed,
            snapshot.Decision.Reason);
        Assert.Equal(4, result.Collection!.Snapshot!.Attempts.Count);
        Assert.Equal("FC12D6470B35B70BD3E4534DD433D3E262A6C73F7682F85C344E832D4190F02B", result.Database!.Sha256);
    }

    /// <summary>The unknown-record and registered-country-only cases cannot produce a completed assessment.</summary>
    [Theory]
    [InlineData("8.8.8.8")]
    [InlineData("5.83.124.1")]
    public async Task AssessAsync_RealUnknownCountry_DiscardsAssessment(string address)
    {
        var network = new SnapshotProvider(TestContext.Current.CancellationToken);

        NetworkAssessmentResult result = await Assessor(network, address, () => MmdbCountryDatabase.Open(Fixture, DatabaseAge))
            .AssessAsync(TestContext.Current.CancellationToken);

        Assert.Equal(NetworkAssessmentStatus.GeoIpUnavailable, result.Status);
        Assert.Null(result.Snapshot);
        Assert.Equal(GeoIpLookupStatus.UnknownCountry, result.GeoIpFailure!.Status);
        Assert.Null(result.GeoIpFailure.Evidence.CountryCode);
    }

    /// <summary>A single available family is accounted for without inventing evidence for the unavailable family.</summary>
    [Fact]
    public async Task AssessAsync_Ipv6Unavailable_OnlyLooksUpIpv4()
    {
        var network = new SnapshotProvider(TestContext.Current.CancellationToken, IpFamilyAvailability.Unavailable);

        NetworkAssessmentResult result = await Assessor(network, "149.101.100.1", () => MmdbCountryDatabase.Open(Fixture, DatabaseAge))
            .AssessAsync(TestContext.Current.CancellationToken);

        NetworkAssessmentSnapshot snapshot = Assert.IsType<NetworkAssessmentSnapshot>(result.Snapshot);
        Assert.Equal(PublicIpDecisionReason.EligibleForRouteValidation, snapshot.Decision.Reason);
        Assert.Equal("US", snapshot.Evidence.Ipv4!.GeoIp!.CountryCode);
        Assert.Null(snapshot.Evidence.Ipv6!.GeoIp);
        Assert.Empty(snapshot.Evidence.Ipv6.Observations);
        Assert.Equal(2, result.Collection!.Snapshot!.Attempts.Count);
    }

    /// <summary>Real file-open and MMDB decoding failures preserve the original diagnostic and no usable snapshot.</summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AssessAsync_DatabaseOpenFails_DoesNotPublish(bool corrupt)
    {
        string path = TemporaryPath();
        try
        {
            if (corrupt) File.WriteAllText(path, "invalid MMDB data");
            var network = new SnapshotProvider(TestContext.Current.CancellationToken);

            NetworkAssessmentResult result = await Assessor(network, "149.101.100.1", () => MmdbCountryDatabase.Open(path, DatabaseAge))
                .AssessAsync(TestContext.Current.CancellationToken);

            Assert.Equal(NetworkAssessmentStatus.Failed, result.Status);
            Assert.Null(result.Snapshot);
            if (corrupt) Assert.IsType<InvalidDataException>(result.Error);
            else Assert.IsType<FileNotFoundException>(result.Error);
        }
        finally
        {
            File.Delete(path);
        }
    }

    /// <summary>Replacing the source file between real lookups cannot mix country databases within an assessment.</summary>
    [Fact]
    public async Task AssessAsync_SourceReplacedDuringLookup_UsesPrivateSnapshot()
    {
        string path = TemporaryPath();
        try
        {
            File.Copy(Fixture, path);
            var network = new SnapshotProvider(TestContext.Current.CancellationToken);
            var database = new ObservedDatabase(MmdbCountryDatabase.Open(path, DatabaseAge), () => File.WriteAllText(path, "source replaced"));
            var policy = new PublicIpPolicy(TimeSpan.FromMinutes(5), ["US", "JP"]);

            NetworkAssessmentResult result = await Assessor(network, "149.101.100.1", () => database, policy: policy)
                .AssessAsync(TestContext.Current.CancellationToken);

            NetworkAssessmentSnapshot snapshot = Assert.IsType<NetworkAssessmentSnapshot>(result.Snapshot);
            Assert.Equal(PublicIpDecisionReason.EligibleForRouteValidation, snapshot.Decision.Reason);
            Assert.Equal("US", snapshot.Evidence.Ipv4!.GeoIp!.CountryCode);
            Assert.Equal("JP", snapshot.Evidence.Ipv6!.GeoIp!.CountryCode);
            Assert.Equal(2, database.Reads);
            Assert.Equal(1, database.Disposals);
            Assert.Equal("source replaced", File.ReadAllText(path));
        }
        finally
        {
            File.Delete(path);
        }
    }

    /// <summary>A real successful lookup still cannot publish data after network invalidation.</summary>
    [Fact]
    public async Task AssessAsync_NetworkChangesAfterRealLookup_DiscardsSnapshot()
    {
        using var changed = new CancellationTokenSource();
        var network = new SnapshotProvider(changed.Token);
        var database = new ObservedDatabase(MmdbCountryDatabase.Open(Fixture, DatabaseAge), changed.Cancel);

        NetworkAssessmentResult result = await Assessor(network, "149.101.100.1", () => database)
            .AssessAsync(TestContext.Current.CancellationToken);

        Assert.Equal(NetworkAssessmentStatus.NetworkChanged, result.Status);
        Assert.Null(result.Snapshot);
        Assert.Equal(1, database.Reads);
        Assert.Equal(1, database.Disposals);
    }

    /// <summary>Gets the copied synthetic database rather than any production data.</summary>
    private static string Fixture => Path.Combine(AppContext.BaseDirectory, "GeoIp", "GeoIP2-Country-Test.mmdb");

    /// <summary>Creates a scenario whose public services are replaced by controlled in-memory responses.</summary>
    private static NetworkAssessor Assessor(INetworkSnapshotProvider network, string ipv4, Func<IGeoIpCountryDatabase> open,
        PublicIpPolicy? policy = null)
    {
        using var fixture = MmdbCountryDatabase.Open(Fixture, DatabaseAge);
        DateTimeOffset now = fixture.Info.BuiltAt.AddDays(1);
        var reader = new PublicIpReader(new ResponseTransport(ipv4), TimeSpan.FromSeconds(5));
        return new NetworkAssessor(reader, network, PublicIpSources.Defaults, open,
            policy ?? new PublicIpPolicy(TimeSpan.FromMinutes(5)), () => now);
    }

    /// <summary>Creates a unique temporary file name for this operation only.</summary>
    private static string TemporaryPath() => Path.Combine(Path.GetTempPath(), $"ipguard-assessment-{Guid.NewGuid():N}.mmdb");

    /// <summary>Returns a stable cached generation with an independently controlled invalidation signal.</summary>
    private sealed class SnapshotProvider : INetworkSnapshotProvider
    {
        private readonly NetworkSnapshot snapshot;

        /// <summary>Captures known family availability and a live cancellation latch.</summary>
        internal SnapshotProvider(CancellationToken invalidated, IpFamilyAvailability ipv6 = IpFamilyAvailability.Available) =>
            snapshot = new(Guid.NewGuid(), IpFamilyAvailability.Available, ipv6, invalidated);

        /// <summary>Returns the same atomic state without reading actual interfaces or routes.</summary>
        public NetworkSnapshot Capture() => snapshot;
    }

    /// <summary>Supplies complete plaintext addresses without DNS, TLS overrides, or public requests.</summary>
    private sealed class ResponseTransport : IPublicIpTransport
    {
        private readonly string ipv4;

        /// <summary>Captures the address returned by every IPv4 source.</summary>
        internal ResponseTransport(string ipv4) => this.ipv4 = ipv4;

        /// <summary>Returns agreeing responses for both configured operators within each family.</summary>
        public Task<HttpResponseMessage> SendAsync(PublicIpSource source, CancellationToken cancellationToken)
        {
            var response = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(source.Family == AddressFamily.InterNetwork ? ipv4 : "2001:218::1")
            };
            response.Content.Headers.ContentType = new MediaTypeHeaderValue("text/plain");
            return Task.FromResult(response);
        }
    }

    /// <summary>Composes the real decoder with controlled races, without replacing country decoding.</summary>
    private sealed class ObservedDatabase : IGeoIpCountryDatabase
    {
        private readonly IGeoIpCountryDatabase database;
        private readonly Action afterLookup;

        /// <summary>Takes ownership of a real database and one deterministic post-lookup action.</summary>
        internal ObservedDatabase(IGeoIpCountryDatabase database, Action afterLookup)
        {
            this.database = database;
            this.afterLookup = afterLookup;
        }

        /// <summary>Gets the real private snapshot's metadata.</summary>
        public GeoIpDatabaseInfo Info => database.Info;

        /// <summary>Gets the number of actual MMDB lookup calls.</summary>
        internal int Reads { get; private set; }

        /// <summary>Gets the number of ownership releases.</summary>
        internal int Disposals { get; private set; }

        /// <summary>Reads the actual country before triggering a file or network change.</summary>
        public GeoIpLookupResult Lookup(IPAddress address, DateTimeOffset now)
        {
            Reads++;
            GeoIpLookupResult result = database.Lookup(address, now);
            afterLookup();
            return result;
        }

        /// <summary>Releases the real database and records the lifecycle boundary.</summary>
        public void Dispose()
        {
            Disposals++;
            database.Dispose();
        }
    }
}
