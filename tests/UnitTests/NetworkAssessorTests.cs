using System.Net;
using System.Net.Sockets;
using IPGuard.Application.GeoIp;
using IPGuard.Application.Network;
using IPGuard.Application.PublicIp;
using IPGuard.Domain;
using Xunit;

namespace UnitTests;

/// <summary>Checks assessment composition, freshness, adapter contracts, and lifecycle races without I/O.</summary>
public sealed class NetworkAssessorTests
{
    private static readonly DateTimeOffset StartedAt = new(2026, 10, 24, 8, 0, 0, TimeSpan.Zero);
    private static readonly TimeSpan EvidenceAge = TimeSpan.FromMinutes(5);

    /// <summary>Both families use one owned database and an interval that ends after its disposal.</summary>
    [Fact]
    public async Task AssessAsync_CurrentEvidence_UsesOneSnapshotAndFullInterval()
    {
        using var setup = new Setup();
        int opened = 0;
        setup.Probe = new Probe(sources =>
        {
            setup.Now = StartedAt.AddSeconds(2);
            return Replies(sources);
        });
        setup.Database.Read = address =>
        {
            setup.Now += TimeSpan.FromSeconds(1);
            return setup.Found(address);
        };
        setup.Database.Close = () => setup.Now += TimeSpan.FromSeconds(1);

        NetworkAssessmentResult result = await setup.Assessor(() => { opened++; return setup.Database; })
            .AssessAsync(TestContext.Current.CancellationToken);

        NetworkAssessmentSnapshot snapshot = Assert.IsType<NetworkAssessmentSnapshot>(result.Snapshot);
        Assert.Equal(NetworkAssessmentStatus.Completed, result.Status);
        Assert.Equal(PublicIpDecisionReason.EligibleForRouteValidation, snapshot.Decision.Reason);
        Assert.Equal(StartedAt, snapshot.Evidence.StartedAt);
        Assert.Equal(StartedAt.AddSeconds(5), snapshot.Evidence.CompletedAt);
        Assert.Equal(StartedAt.AddSeconds(2), result.Collection!.Snapshot!.CompletedAt);
        Assert.Equal("149.101.100.1", snapshot.Evidence.Ipv4!.GeoIp!.Address);
        Assert.Equal("US", snapshot.Evidence.Ipv4.GeoIp.CountryCode);
        Assert.Equal("2001:218::1", snapshot.Evidence.Ipv6!.GeoIp!.Address);
        Assert.Equal(2, snapshot.Evidence.Ipv4.Observations.Count);
        Assert.Equal(2, snapshot.Evidence.Ipv6.Observations.Count);
        Assert.Same(setup.Current, snapshot.Network);
        Assert.Same(setup.Database.Metadata, result.Database);
        Assert.Equal(1, opened);
        Assert.Equal(2, setup.Database.Reads);
        Assert.Equal(1, setup.Database.Disposals);
        Assert.Null(result.Error);
    }

    /// <summary>A valid foreign result is preserved and evaluated by the domain rather than treated as a lookup error.</summary>
    [Fact]
    public async Task AssessAsync_ForeignIpv6_RemainsIneligible()
    {
        using var setup = new Setup();
        setup.Database.Read = address => setup.Found(address, address.AddressFamily == AddressFamily.InterNetwork ? "US" : "CA");

        NetworkAssessmentResult result = await setup.Assessor().AssessAsync(TestContext.Current.CancellationToken);

        NetworkAssessmentSnapshot snapshot = Assert.IsType<NetworkAssessmentSnapshot>(result.Snapshot);
        Assert.Equal(NetworkAssessmentStatus.Completed, result.Status);
        Assert.False(snapshot.Decision.IsEligible);
        Assert.Equal(PublicIpDecisionReason.CountryNotAllowed, snapshot.Decision.Reason);
        Assert.Equal(AddressFamily.InterNetworkV6, snapshot.Decision.Family);
        Assert.Equal("CA", snapshot.Evidence.Ipv6!.GeoIp!.CountryCode);
    }

    /// <summary>Source conflicts and failures remain visible and are not repaired through GeoIP.</summary>
    [Theory]
    [InlineData("conflict", PublicIpDecisionReason.ConflictingAddresses)]
    [InlineData("failure", PublicIpDecisionReason.SourceFailed)]
    [InlineData("operator", PublicIpDecisionReason.InsufficientSources)]
    [InlineData("family", PublicIpDecisionReason.AddressFamilyMismatch)]
    public async Task AssessAsync_UnagreedSources_DoNotLookupThatFamily(string invalid, PublicIpDecisionReason reason)
    {
        using var setup = new Setup();
        setup.Current = setup.Snapshot(ipv6: IpFamilyAvailability.Unavailable);
        if (invalid == "operator") setup.Sources = [Source("one", AddressFamily.InterNetwork), Source("one", AddressFamily.InterNetwork)];
        setup.Probe = new Probe(sources =>
        {
            PublicIpReadResult[] replies = Replies(sources).ToArray();
            replies[1] = invalid switch
            {
                "conflict" => new(replies[1].Source, PublicIpReadStatus.Success, IPAddress.Parse("8.8.8.8")),
                "failure" => new(replies[1].Source, PublicIpReadStatus.TlsFailed),
                "family" => new(replies[1].Source, PublicIpReadStatus.Success, IPAddress.Parse("2001:218::1")),
                _ => replies[1]
            };
            return replies;
        });

        NetworkAssessmentResult result = await setup.Assessor(() => throw new InvalidOperationException("Must not open"))
            .AssessAsync(TestContext.Current.CancellationToken);

        NetworkAssessmentSnapshot snapshot = Assert.IsType<NetworkAssessmentSnapshot>(result.Snapshot);
        Assert.Equal(reason, snapshot.Decision.Reason);
        Assert.Equal(2, snapshot.Evidence.Ipv4!.Observations.Count);
        Assert.Null(snapshot.Evidence.Ipv4.GeoIp);
        Assert.Equal(0, setup.Database.Reads);
        Assert.Equal(0, setup.Database.Disposals);
    }

    /// <summary>A family reported unavailable has no invented observations or lookup.</summary>
    [Theory]
    [InlineData(IpFamilyAvailability.Available, IpFamilyAvailability.Unavailable, 1, true)]
    [InlineData(IpFamilyAvailability.Unavailable, IpFamilyAvailability.Available, 1, true)]
    [InlineData(IpFamilyAvailability.Unavailable, IpFamilyAvailability.Unavailable, 0, false)]
    public async Task AssessAsync_Availability_IsAccountedFor(IpFamilyAvailability ipv4, IpFamilyAvailability ipv6, int reads, bool eligible)
    {
        using var setup = new Setup();
        setup.Current = setup.Snapshot(ipv4, ipv6);

        NetworkAssessmentResult result = await setup.Assessor().AssessAsync(TestContext.Current.CancellationToken);

        NetworkAssessmentSnapshot snapshot = Assert.IsType<NetworkAssessmentSnapshot>(result.Snapshot);
        Assert.Equal(reads, setup.Database.Reads);
        Assert.Equal(eligible, snapshot.Decision.IsEligible);
        if (ipv4 == IpFamilyAvailability.Unavailable) Assert.Empty(snapshot.Evidence.Ipv4!.Observations);
        if (ipv6 == IpFamilyAvailability.Unavailable) Assert.Empty(snapshot.Evidence.Ipv6!.Observations);
    }

    /// <summary>Failed or unknown collection does not access a local database.</summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AssessAsync_CollectionUnavailable_DoesNotOpenDatabase(bool failure)
    {
        using var setup = new Setup();
        var error = new IOException("Probe failure");
        if (failure) setup.Probe = new Probe(_ => throw error);
        else setup.Current = null;

        NetworkAssessmentResult result = await setup.Assessor(() => throw new InvalidOperationException("Must not open"))
            .AssessAsync(TestContext.Current.CancellationToken);

        AssertDiscarded(result, NetworkAssessmentStatus.CollectionUnavailable);
        Assert.NotNull(result.Collection);
        if (failure) Assert.Same(error, result.Error);
    }

    /// <summary>Every unsuccessful lookup discards the assessment without reusing a previous country.</summary>
    [Theory]
    [InlineData(GeoIpLookupStatus.UnknownCountry)]
    [InlineData(GeoIpLookupStatus.InvalidAddress)]
    [InlineData(GeoIpLookupStatus.DatabaseExpired)]
    [InlineData(GeoIpLookupStatus.DatabaseFromFuture)]
    [InlineData(GeoIpLookupStatus.DatabaseError)]
    public async Task AssessAsync_FailedLookup_DoesNotPublish(GeoIpLookupStatus status)
    {
        using var setup = new Setup();
        var error = status == GeoIpLookupStatus.DatabaseError ? new IOException("Decoder failed") : null;
        setup.Database.Read = address => new(status, new GeoIpEvidence(address, null, setup.Database.Metadata.ValidUntil), error);

        NetworkAssessmentResult result = await setup.Assessor().AssessAsync(TestContext.Current.CancellationToken);

        AssertDiscarded(result, NetworkAssessmentStatus.GeoIpUnavailable);
        Assert.Equal(status, result.GeoIpFailure!.Status);
        Assert.Same(error, result.Error);
        Assert.Equal(1, setup.Database.Reads);
        Assert.Equal(1, setup.Database.Disposals);
    }

    /// <summary>Malformed or inconsistent adapter results cannot become domain evidence.</summary>
    [Theory]
    [InlineData("address")]
    [InlineData("deadline")]
    [InlineData("missing-deadline")]
    [InlineData("missing-country")]
    [InlineData("error")]
    [InlineData("failed-country")]
    [InlineData("status")]
    [InlineData("null")]
    public async Task AssessAsync_InvalidLookupResult_IsDiscarded(string invalid)
    {
        using var setup = new Setup();
        setup.Database.Read = address => invalid switch
        {
            "address" => setup.Found(IPAddress.Parse("8.8.8.8")),
            "deadline" => new(GeoIpLookupStatus.Found, new GeoIpEvidence(address, "US", setup.Database.Metadata.ValidUntil.AddDays(1))),
            "missing-deadline" => new(GeoIpLookupStatus.Found, new GeoIpEvidence(address, "US", null)),
            "missing-country" => setup.Found(address, null),
            "error" => new(GeoIpLookupStatus.Found, setup.Found(address).Evidence, new IOException("Failure with a country")),
            "failed-country" => new(GeoIpLookupStatus.DatabaseError, setup.Found(address).Evidence),
            "status" => new((GeoIpLookupStatus)999, setup.Found(address).Evidence),
            _ => null!
        };

        NetworkAssessmentResult result = await setup.Assessor().AssessAsync(TestContext.Current.CancellationToken);

        AssertDiscarded(result, NetworkAssessmentStatus.InvalidGeoIpResult);
        Assert.Null(result.GeoIpFailure);
        Assert.Equal(1, setup.Database.Disposals);
    }

    /// <summary>Expired and future metadata prevent country reads; malformed metadata is an adapter failure.</summary>
    [Theory]
    [InlineData("expired", NetworkAssessmentStatus.GeoIpUnavailable)]
    [InlineData("future", NetworkAssessmentStatus.GeoIpUnavailable)]
    [InlineData("interval", NetworkAssessmentStatus.InvalidGeoIpResult)]
    [InlineData("hash", NetworkAssessmentStatus.InvalidGeoIpResult)]
    [InlineData("product", NetworkAssessmentStatus.InvalidGeoIpResult)]
    public async Task AssessAsync_InvalidMetadata_DoesNotRead(string invalid, NetworkAssessmentStatus status)
    {
        using var setup = new Setup();
        GeoIpDatabaseInfo original = setup.Database.Metadata;
        setup.Database.Metadata = new GeoIpDatabaseInfo(invalid == "product" ? "" : original.DatabaseType,
            invalid == "future" ? StartedAt.AddDays(1) : original.BuiltAt,
            invalid == "expired" ? StartedAt : invalid == "interval" ? original.BuiltAt : original.ValidUntil,
            invalid == "hash" ? "invalid" : original.Sha256);

        NetworkAssessmentResult result = await setup.Assessor().AssessAsync(TestContext.Current.CancellationToken);

        AssertDiscarded(result, status);
        Assert.Equal(0, setup.Database.Reads);
        Assert.Equal(1, setup.Database.Disposals);
    }

    /// <summary>Changing the database's identity inside a lookup cannot mix two snapshots.</summary>
    [Fact]
    public async Task AssessAsync_MetadataChangesDuringLookup_IsDiscarded()
    {
        using var setup = new Setup();
        setup.Database.Read = address =>
        {
            GeoIpLookupResult result = setup.Found(address);
            GeoIpDatabaseInfo info = setup.Database.Metadata;
            setup.Database.Metadata = new(info.DatabaseType, info.BuiltAt, info.ValidUntil, new string('B', 64));
            return result;
        };

        AssertDiscarded(await setup.Assessor().AssessAsync(TestContext.Current.CancellationToken), NetworkAssessmentStatus.InvalidGeoIpResult);
        Assert.Equal(1, setup.Database.Reads);
    }

    /// <summary>An adapter cannot change the requested address and make its altered result look correctly bound.</summary>
    [Fact]
    public async Task AssessAsync_AdapterMutatesAddress_IsDiscarded()
    {
        using var setup = new Setup();
        setup.Current = setup.Snapshot(ipv4: IpFamilyAvailability.Unavailable);
        setup.Database.Read = address =>
        {
            address.ScopeId = 2;
            return setup.Found(address);
        };

        AssertDiscarded(await setup.Assessor().AssessAsync(TestContext.Current.CancellationToken), NetworkAssessmentStatus.InvalidGeoIpResult);
    }

    /// <summary>A rollback within the overall interval is detected against the latest observed checkpoint.</summary>
    [Fact]
    public async Task AssessAsync_ClockRollsBackAboveStart_IsDiscarded()
    {
        using var setup = new Setup();
        setup.Database.Read = address =>
        {
            setup.Now = address.AddressFamily == AddressFamily.InterNetwork ? StartedAt.AddSeconds(2) : StartedAt.AddSeconds(1);
            return setup.Found(address);
        };

        AssertDiscarded(await setup.Assessor().AssessAsync(TestContext.Current.CancellationToken), NetworkAssessmentStatus.InvalidTimestamps);
    }

    /// <summary>Malformed non-null country codes remain subject to the domain's normalization rule.</summary>
    [Theory]
    [InlineData("")]
    [InlineData("USA")]
    [InlineData("Uſ")]
    public async Task AssessAsync_MalformedCountry_IsNotEligible(string country)
    {
        using var setup = new Setup();
        setup.Database.Read = address => setup.Found(address, country);

        NetworkAssessmentResult result = await setup.Assessor().AssessAsync(TestContext.Current.CancellationToken);

        NetworkAssessmentSnapshot snapshot = Assert.IsType<NetworkAssessmentSnapshot>(result.Snapshot);
        Assert.False(snapshot.Decision.IsEligible);
        Assert.Equal(PublicIpDecisionReason.UnknownCountry, snapshot.Decision.Reason);
    }

    /// <summary>Age, database expiry, and clock rollback are checked across opening, lookup, and cleanup.</summary>
    [Theory]
    [InlineData("open", "age", NetworkAssessmentStatus.EvidenceExpired)]
    [InlineData("lookup", "age", NetworkAssessmentStatus.EvidenceExpired)]
    [InlineData("dispose", "age", NetworkAssessmentStatus.EvidenceExpired)]
    [InlineData("lookup", "database", NetworkAssessmentStatus.GeoIpUnavailable)]
    [InlineData("dispose", "database", NetworkAssessmentStatus.GeoIpUnavailable)]
    [InlineData("lookup", "rollback", NetworkAssessmentStatus.InvalidTimestamps)]
    [InlineData("dispose", "rollback", NetworkAssessmentStatus.InvalidTimestamps)]
    public async Task AssessAsync_TimeChanges_DiscardWholeInterval(string phase, string change, NetworkAssessmentStatus expected)
    {
        using var setup = new Setup();
        if (change == "database") setup.Database.Metadata = new("GeoIP2-Country", StartedAt.AddDays(-1), StartedAt.AddSeconds(5), new string('A', 64));
        Action updateTime = () => setup.Now = change switch
        {
            "age" => StartedAt + EvidenceAge,
            "database" => setup.Database.Metadata.ValidUntil,
            _ => StartedAt.AddTicks(-1)
        };
        if (phase == "lookup") setup.Database.Read = address => { GeoIpLookupResult result = setup.Found(address); updateTime(); return result; };
        if (phase == "dispose") setup.Database.Close = updateTime;

        NetworkAssessmentResult result = await setup.Assessor(() => { if (phase == "open") updateTime(); return setup.Database; })
            .AssessAsync(TestContext.Current.CancellationToken);

        AssertDiscarded(result, expected);
        Assert.Equal(1, setup.Database.Disposals);
    }

    /// <summary>Late collection is discarded before database opening instead of refreshing its oldest timestamp.</summary>
    [Fact]
    public async Task AssessAsync_CollectionAlreadyStale_DoesNotOpenDatabase()
    {
        using var setup = new Setup();
        setup.Probe = new Probe(sources => { setup.Now = StartedAt + EvidenceAge; return Replies(sources); });

        NetworkAssessmentResult result = await setup.Assessor(() => throw new InvalidOperationException("Must not open"))
            .AssessAsync(TestContext.Current.CancellationToken);

        AssertDiscarded(result, NetworkAssessmentStatus.EvidenceExpired);
    }

    /// <summary>Generation, availability, token identity, and invalidation are all checked after local I/O.</summary>
    [Theory]
    [InlineData("open", "version")]
    [InlineData("lookup", "version")]
    [InlineData("dispose", "version")]
    [InlineData("lookup", "availability")]
    [InlineData("lookup", "token")]
    [InlineData("lookup", "cancel")]
    [InlineData("lookup", "missing")]
    public async Task AssessAsync_NetworkChanges_DoNotPublish(string phase, string change)
    {
        using var setup = new Setup();
        using var replacement = new CancellationTokenSource();
        Action updateNetwork = () =>
        {
            setup.Current = change switch
            {
                "version" => new(Guid.NewGuid(), IpFamilyAvailability.Available, IpFamilyAvailability.Available, setup.Changed.Token),
                "availability" => setup.Snapshot(ipv6: IpFamilyAvailability.Unavailable),
                "token" => new(setup.Version, IpFamilyAvailability.Available, IpFamilyAvailability.Available, replacement.Token),
                "missing" => null,
                _ => setup.Current
            };
            if (change == "cancel") setup.Changed.Cancel();
        };
        if (phase == "lookup") setup.Database.Read = address => { GeoIpLookupResult result = setup.Found(address); updateNetwork(); return result; };
        if (phase == "dispose") setup.Database.Close = updateNetwork;

        NetworkAssessmentResult result = await setup.Assessor(() => { if (phase == "open") updateNetwork(); return setup.Database; })
            .AssessAsync(TestContext.Current.CancellationToken);

        AssertDiscarded(result, NetworkAssessmentStatus.NetworkChanged);
        Assert.Equal(1, setup.Database.Disposals);
    }

    /// <summary>An invalidation triggered by the final clock remains visible after the final capture.</summary>
    [Fact]
    public async Task AssessAsync_InvalidatedDuringFinalClock_IsDiscarded()
    {
        using var setup = new Setup();
        Func<DateTimeOffset> clock = () =>
        {
            if (setup.Database.Disposals > 0) setup.Changed.Cancel();
            return setup.Now;
        };

        AssertDiscarded(await setup.Assessor(clock: clock).AssessAsync(TestContext.Current.CancellationToken), NetworkAssessmentStatus.NetworkChanged);
    }

    /// <summary>Cancellation at each local boundary propagates even when that boundary also throws.</summary>
    [Theory]
    [InlineData("open")]
    [InlineData("lookup")]
    [InlineData("dispose")]
    public async Task AssessAsync_CallerCancelled_Propagates(string phase)
    {
        using var setup = new Setup();
        using var caller = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        if (phase == "lookup") setup.Database.Read = _ => { caller.Cancel(); throw new IOException("Lookup interrupted"); };
        if (phase == "dispose") setup.Database.Close = caller.Cancel;

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => setup.Assessor(() =>
        {
            if (phase == "open") caller.Cancel();
            return setup.Database;
        }).AssessAsync(caller.Token));
        Assert.Equal(1, setup.Database.Disposals);
    }

    /// <summary>Opening, lookup, and cleanup errors never publish partial evidence and retain their diagnostics.</summary>
    [Theory]
    [InlineData("open")]
    [InlineData("lookup")]
    [InlineData("dispose")]
    public async Task AssessAsync_BoundaryFails_PreservesError(string phase)
    {
        using var setup = new Setup();
        var error = new IOException("Local boundary failed");
        if (phase == "lookup") setup.Database.Read = _ => throw error;
        if (phase == "dispose") setup.Database.Close = () => throw error;

        NetworkAssessmentResult result = await setup.Assessor(() => phase == "open" ? throw error : setup.Database)
            .AssessAsync(TestContext.Current.CancellationToken);

        AssertDiscarded(result, NetworkAssessmentStatus.Failed);
        Assert.Same(error, result.Error);
        Assert.Equal(phase == "open" ? 0 : 1, setup.Database.Disposals);
    }

    /// <summary>A second cleanup error does not erase the original lookup failure.</summary>
    [Fact]
    public async Task AssessAsync_LookupAndCleanupFail_RetainsBothErrors()
    {
        using var setup = new Setup();
        var readError = new IOException("Lookup failed");
        var closeError = new IOException("Cleanup failed");
        setup.Database.Read = _ => throw readError;
        setup.Database.Close = () => throw closeError;

        NetworkAssessmentResult result = await setup.Assessor().AssessAsync(TestContext.Current.CancellationToken);

        AssertDiscarded(result, NetworkAssessmentStatus.Failed);
        AggregateException error = Assert.IsType<AggregateException>(result.Error);
        Assert.Same(readError, error.InnerExceptions[0]);
        Assert.Same(closeError, error.InnerExceptions[1]);
    }

    /// <summary>An operational error returned as data is also retained if closing the database then fails.</summary>
    [Fact]
    public async Task AssessAsync_ReturnedErrorAndCleanupFailure_RetainsBothErrors()
    {
        using var setup = new Setup();
        var readError = new IOException("Decoder returned failure");
        var closeError = new IOException("Cleanup failed");
        setup.Database.Read = address => new(GeoIpLookupStatus.DatabaseError,
            new GeoIpEvidence(address, null, setup.Database.Metadata.ValidUntil), readError);
        setup.Database.Close = () => throw closeError;

        NetworkAssessmentResult result = await setup.Assessor().AssessAsync(TestContext.Current.CancellationToken);

        AssertDiscarded(result, NetworkAssessmentStatus.Failed);
        AggregateException error = Assert.IsType<AggregateException>(result.Error);
        Assert.Same(readError, error.InnerExceptions[0]);
        Assert.Same(closeError, error.InnerExceptions[1]);
    }

    /// <summary>The returned signal remains live; a completed snapshot cannot revoke or refresh itself.</summary>
    [Fact]
    public async Task AssessAsync_LaterNetworkChange_InvalidatesReturnedSignal()
    {
        using var setup = new Setup();
        NetworkAssessmentResult result = await setup.Assessor().AssessAsync(TestContext.Current.CancellationToken);
        NetworkAssessmentSnapshot snapshot = Assert.IsType<NetworkAssessmentSnapshot>(result.Snapshot);

        setup.Changed.Cancel();

        Assert.True(snapshot.Network.Invalidated.IsCancellationRequested);
    }

    /// <summary>A pre-cancelled call must not invoke any application boundary.</summary>
    [Fact]
    public async Task AssessAsync_PreCancelled_DoesNotCollect()
    {
        using var setup = new Setup();
        using var caller = new CancellationTokenSource();
        caller.Cancel();
        setup.Probe = new Probe(_ => throw new InvalidOperationException("Must not collect"));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => setup.Assessor().AssessAsync(caller.Token));
        Assert.Equal(0, setup.Database.Disposals);
    }

    /// <summary>A discarded assessment contains no snapshot whose preliminary decision could be reused.</summary>
    private static void AssertDiscarded(NetworkAssessmentResult result, NetworkAssessmentStatus status)
    {
        Assert.Equal(status, result.Status);
        Assert.Null(result.Snapshot);
    }

    /// <summary>Creates a distinct HTTPS endpoint for one configured operator and family.</summary>
    private static PublicIpSource Source(string name, AddressFamily family) => new(name,
        new Uri($"https://{name}-{(family == AddressFamily.InterNetwork ? "v4" : "v6")}.example/"), family);

    /// <summary>Produces agreeing source results while preserving configured source identities.</summary>
    private static IReadOnlyList<PublicIpReadResult> Replies(IEnumerable<PublicIpSource> sources) => sources.Select(source =>
        new PublicIpReadResult(source, PublicIpReadStatus.Success, IPAddress.Parse(source.Family == AddressFamily.InterNetwork
            ? "149.101.100.1" : "2001:218::1"))).ToArray();

    /// <summary>Owns controllable time, cached network state, and an injected local database.</summary>
    private sealed class Setup : INetworkSnapshotProvider, IDisposable
    {
        /// <summary>Initializes stable, fresh evidence for both address families.</summary>
        internal Setup()
        {
            Current = Snapshot();
            Database = new Database();
            Database.Read = address => Found(address);
        }

        /// <summary>Gets a stable generation identifier.</summary>
        internal Guid Version { get; } = Guid.NewGuid();

        /// <summary>Gets the original generation's invalidation latch.</summary>
        internal CancellationTokenSource Changed { get; } = new();

        /// <summary>Gets or sets the clock observed by collection and assessment.</summary>
        internal DateTimeOffset Now { get; set; } = StartedAt;

        /// <summary>Gets or sets the currently visible atomic network state.</summary>
        internal NetworkSnapshot? Current { get; set; }

        /// <summary>Gets or sets the source boundary.</summary>
        internal IPublicIpProbe Probe { get; set; } = new Probe(Replies);

        /// <summary>Gets or sets the exact configured source set.</summary>
        internal PublicIpSource[] Sources { get; set; } = [Source("one", AddressFamily.InterNetwork), Source("two", AddressFamily.InterNetwork),
            Source("one", AddressFamily.InterNetworkV6), Source("two", AddressFamily.InterNetworkV6)];

        /// <summary>Gets the database whose ownership is transferred on opening.</summary>
        internal Database Database { get; }

        /// <summary>Composes the use case without introducing a mock collector abstraction.</summary>
        internal NetworkAssessor Assessor(Func<IGeoIpCountryDatabase>? open = null, Func<DateTimeOffset>? clock = null) =>
            new(Probe, this, Sources, open ?? (() => Database), new PublicIpPolicy(EvidenceAge), clock ?? (() => Now));

        /// <summary>Creates a snapshot sharing the original generation and invalidation signal.</summary>
        internal NetworkSnapshot Snapshot(IpFamilyAvailability ipv4 = IpFamilyAvailability.Available,
            IpFamilyAvailability ipv6 = IpFamilyAvailability.Available) => new(Version, ipv4, ipv6, Changed.Token);

        /// <summary>Creates country evidence bound to the actual queried address and snapshot deadline.</summary>
        internal GeoIpLookupResult Found(IPAddress address, string? country = "US") =>
            new(GeoIpLookupStatus.Found, new GeoIpEvidence(address, country, Database.Metadata.ValidUntil));

        /// <summary>Returns controlled cached state without I/O.</summary>
        public NetworkSnapshot? Capture() => Current;

        /// <summary>Releases the test-owned invalidation source without disposing the transferred database again.</summary>
        public void Dispose() => Changed.Dispose();
    }

    /// <summary>Provides deterministic source replies through the existing probe boundary.</summary>
    private sealed class Probe : IPublicIpProbe
    {
        private readonly Func<IEnumerable<PublicIpSource>, IReadOnlyList<PublicIpReadResult>> read;

        /// <summary>Captures synchronous response behavior for deterministic races.</summary>
        internal Probe(Func<IEnumerable<PublicIpSource>, IReadOnlyList<PublicIpReadResult>> read) => this.read = read;

        /// <summary>Returns all controlled attempts without DNS or HTTPS.</summary>
        public Task<IReadOnlyList<PublicIpReadResult>> ReadAllAsync(IEnumerable<PublicIpSource> sources, CancellationToken cancellationToken) =>
            Task.FromResult(read(sources));
    }

    /// <summary>Simulates one immutable database and intentional contract violations for boundary tests.</summary>
    private sealed class Database : IGeoIpCountryDatabase
    {
        /// <summary>Gets or sets the metadata exposed by this adapter.</summary>
        internal GeoIpDatabaseInfo Metadata { get; set; } = new("GeoIP2-Country", StartedAt.AddDays(-1), StartedAt.AddDays(30), new string('A', 64));

        /// <summary>Gets or sets controlled lookup behavior.</summary>
        internal Func<IPAddress, GeoIpLookupResult> Read { get; set; } = _ => throw new InvalidOperationException("Read not configured");

        /// <summary>Gets or sets cleanup side effects or errors.</summary>
        internal Action? Close { get; set; }

        /// <summary>Gets the number of local lookup calls.</summary>
        internal int Reads { get; private set; }

        /// <summary>Gets the number of ownership releases.</summary>
        internal int Disposals { get; private set; }

        /// <summary>Gets current metadata, which tests can deliberately change to violate the contract.</summary>
        public GeoIpDatabaseInfo Info => Metadata;

        /// <summary>Records the lookup before applying controlled behavior.</summary>
        public GeoIpLookupResult Lookup(IPAddress address, DateTimeOffset now)
        {
            Reads++;
            return Read(address);
        }

        /// <summary>Records cleanup before applying controlled behavior.</summary>
        public void Dispose()
        {
            Disposals++;
            Close?.Invoke();
        }
    }
}
