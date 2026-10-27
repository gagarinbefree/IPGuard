using System.Net;
using System.Net.Sockets;
using IPGuard.Application.GeoIp;
using IPGuard.Application.Network;
using IPGuard.Application.PublicIp;
using IPGuard.Domain;
using Xunit;

namespace UnitTests;

/// <summary>Checks the full diagnostic interval, generation, and negative outcomes without OS or network calls.</summary>
public sealed class NetworkCheckCollectorTests
{
    /// <summary>The outer interval includes local reads, source collection, lookups, and database cleanup.</summary>
    [Fact]
    public async Task CompleteCheckUsesOneOuterInterval()
    {
        using var setup = new NetworkCheckSetup();
        setup.Boundary = part => setup.Now += TimeSpan.FromSeconds(part == "ras" ? 2 : part is "lookup" or "close" ? 1 : 0);
        setup.BeforeProbe = _ => { setup.Now += TimeSpan.FromSeconds(1); return Task.CompletedTask; };
        var result = await setup.Collector().CollectAsync(TestContext.Current.CancellationToken);
        var snapshot = Assert.IsType<NetworkDiagnosticsSnapshot>(result.Snapshot);
        var assessment = Assert.IsType<NetworkAssessmentSnapshot>(snapshot.Assessment);
        Assert.Equal(NetworkDiagnosticsStatus.Completed, result.Status);
        Assert.Null(result.Error);
        Assert.Single(snapshot.Routes);
        Assert.Empty(snapshot.Connections);
        Assert.Same(setup.Current, snapshot.Network);
        Assert.Same(snapshot.Network, assessment.Network);
        Assert.Equal(NetworkCheckSetup.Start, snapshot.StartedAt);
        Assert.Equal(NetworkCheckSetup.Start.AddSeconds(6), snapshot.CompletedAt);
        Assert.Equal(snapshot.StartedAt, assessment.Evidence.StartedAt);
        Assert.Equal(snapshot.CompletedAt, assessment.Evidence.CompletedAt);
        Assert.Equal(PublicIpDecisionReason.EligibleForRouteValidation, assessment.Decision.Reason);
        Assert.Equal(NetworkCheckSetup.Start.AddSeconds(2), result.Assessment!.Snapshot!.Evidence.StartedAt);
        Assert.Equal(4, result.Assessment.Collection!.Snapshot!.Attempts.Count);
        Assert.Equal(1, setup.Disposals);
    }

    /// <summary>Valid country rejection stays explicit and does not become an operational failure or permit.</summary>
    [Theory]
    [InlineData("CA", false)]
    [InlineData("US", true)]
    public async Task FinalPolicyOwnsCountryDecision(string country, bool eligible)
    {
        using var setup = new NetworkCheckSetup { Country = country };
        var result = await setup.Collector().CollectAsync(TestContext.Current.CancellationToken);
        Assert.Equal(NetworkDiagnosticsStatus.Completed, result.Status);
        Assert.Equal(eligible, result.Snapshot!.Assessment!.Decision.IsEligible);
        Assert.Equal(country, result.Snapshot.Assessment.Evidence.Ipv4!.GeoIp!.CountryCode);
    }

    /// <summary>Configured countries replace the default while route validation remains required.</summary>
    [Fact]
    public async Task ConfiguredCountriesReachFinalEvaluation()
    {
        using var setup = new NetworkCheckSetup { Country = "CA" };
        var result = await setup.Collector(allowedCountries: ["CA"]).CollectAsync(TestContext.Current.CancellationToken);
        Assert.Equal(PublicIpDecisionReason.EligibleForRouteValidation, result.Snapshot!.Assessment!.Decision.Reason);
    }

    /// <summary>The maximum age covers the entire sequence even when each child completes below its own limit.</summary>
    [Fact]
    public async Task CumulativeAgeCannotRestartAtPublicCollection()
    {
        using var setup = new NetworkCheckSetup();
        setup.Boundary = part => { if (part == "ras") setup.Now += TimeSpan.FromSeconds(6); };
        setup.BeforeProbe = _ => { setup.Now += TimeSpan.FromSeconds(4); return Task.CompletedTask; };
        var result = await setup.Collector().CollectAsync(TestContext.Current.CancellationToken);
        Assert.Equal(NetworkDiagnosticsStatus.Expired, result.Status);
        Assert.Null(result.Snapshot);
        Assert.Equal(NetworkAssessmentStatus.Completed, result.Assessment!.Status);
    }

    /// <summary>No public requests run when local observations cannot be collected.</summary>
    [Fact]
    public async Task LocalFailureStopsBeforeSources()
    {
        using var setup = new NetworkCheckSetup();
        var error = new IOException("Proxy unavailable.");
        setup.Boundary = part => { if (part == "proxy") throw error; };
        var result = await setup.Collector().CollectAsync(TestContext.Current.CancellationToken);
        Assert.Equal(NetworkDiagnosticsStatus.Failed, result.Status);
        Assert.Null(result.Snapshot);
        Assert.Null(result.Assessment);
        Assert.Same(error, result.Error);
        Assert.Equal(0, setup.ProbeCalls);
    }

    /// <summary>No initial generation, missing identity/latch, or a retired generation prevents all source calls.</summary>
    [Theory]
    [InlineData("missing")]
    [InlineData("version")]
    [InlineData("token")]
    [InlineData("cancelled")]
    public async Task InvalidGenerationPreventsCollection(string defect)
    {
        using var setup = new NetworkCheckSetup();
        setup.Current = defect switch
        {
            "missing" => null,
            "version" => new(Guid.Empty, IpFamilyAvailability.Available, IpFamilyAvailability.Available, setup.Changed.Token),
            "token" => new(Guid.NewGuid(), IpFamilyAvailability.Available, IpFamilyAvailability.Available, default),
            _ => setup.Current
        };
        if (defect == "cancelled") setup.Changed.Cancel();
        var result = await setup.Collector().CollectAsync(TestContext.Current.CancellationToken);
        Assert.Equal(NetworkDiagnosticsStatus.NetworkUnavailable, result.Status);
        Assert.Null(result.Snapshot);
        Assert.Equal(0, setup.ProbeCalls);
    }

    /// <summary>Changes during local reads, country lookup, cleanup, or source requests discard the entire sequence.</summary>
    [Theory]
    [InlineData("ras")]
    [InlineData("probe")]
    [InlineData("lookup")]
    [InlineData("close")]
    [InlineData("version")]
    public async Task ChangedNetworkDiscardsBothParts(string boundary)
    {
        using var setup = new NetworkCheckSetup();
        setup.Boundary = part => { if (part == boundary) setup.Changed.Cancel(); };
        setup.BeforeProbe = _ =>
        {
            if (boundary == "probe") setup.Changed.Cancel();
            if (boundary == "version") setup.Current = new(Guid.NewGuid(), setup.Current!.Ipv4, setup.Current.Ipv6, setup.Changed.Token);
            return Task.CompletedTask;
        };
        var result = await setup.Collector().CollectAsync(TestContext.Current.CancellationToken);
        Assert.Equal(NetworkDiagnosticsStatus.NetworkChanged, result.Status);
        Assert.Null(result.Snapshot);
    }

    /// <summary>Every failed configured source remains present and causes a negative country prerequisite decision.</summary>
    [Theory]
    [InlineData(PublicIpReadStatus.NameResolutionFailed)]
    [InlineData(PublicIpReadStatus.TlsFailed)]
    [InlineData(PublicIpReadStatus.TimedOut)]
    [InlineData(PublicIpReadStatus.TransportFailed)]
    public async Task SourceFailureIsNotHiddenBySuccessfulReplies(PublicIpReadStatus failure)
    {
        using var setup = new NetworkCheckSetup();
        setup.Reply = source => source.OperatorId == "two" ? new(source, failure) : new(source, PublicIpReadStatus.Success,
            IPAddress.Parse(source.Family == AddressFamily.InterNetwork ? setup.Ipv4 : setup.Ipv6));
        var result = await setup.Collector().CollectAsync(TestContext.Current.CancellationToken);
        Assert.Equal(NetworkDiagnosticsStatus.Completed, result.Status);
        Assert.Equal(PublicIpDecisionReason.SourceFailed, result.Snapshot!.Assessment!.Decision.Reason);
        Assert.Equal(4, result.Assessment!.Collection!.Snapshot!.Attempts.Count);
        Assert.Contains(result.Assessment.Collection.Snapshot.Attempts, attempt => attempt.Status == failure);
    }

    /// <summary>Conflicting public addresses remain visible instead of being resolved by country lookup.</summary>
    [Fact]
    public async Task SourceConflictRemainsNegative()
    {
        using var setup = new NetworkCheckSetup();
        setup.Reply = source => new(source, PublicIpReadStatus.Success, IPAddress.Parse(source.Family == AddressFamily.InterNetworkV6
            ? setup.Ipv6 : source.OperatorId == "one" ? setup.Ipv4 : "8.8.8.8"));
        var result = await setup.Collector().CollectAsync(TestContext.Current.CancellationToken);
        Assert.Equal(PublicIpDecisionReason.ConflictingAddresses, result.Snapshot!.Assessment!.Decision.Reason);
        Assert.Equal(4, result.Assessment!.Collection!.Snapshot!.Attempts.Count);
    }

    /// <summary>Unavailable local country data discards the outer snapshot and retains lookup diagnostics.</summary>
    [Fact]
    public async Task UnknownCountryRetainsAssessmentFailure()
    {
        using var setup = new NetworkCheckSetup { LookupStatus = GeoIpLookupStatus.UnknownCountry };
        var result = await setup.Collector().CollectAsync(TestContext.Current.CancellationToken);
        Assert.Equal(NetworkDiagnosticsStatus.Failed, result.Status);
        Assert.Null(result.Snapshot);
        Assert.Equal(NetworkAssessmentStatus.GeoIpUnavailable, result.Assessment!.Status);
        Assert.Equal(GeoIpLookupStatus.UnknownCountry, result.Assessment.GeoIpFailure!.Status);
        Assert.Equal(1, setup.Disposals);
    }

    /// <summary>Database exceptions at open, lookup, and cleanup cannot retain any previous positive snapshot.</summary>
    [Theory]
    [InlineData("open")]
    [InlineData("lookup")]
    [InlineData("close")]
    public async Task DatabaseErrorsRetainOriginalFailure(string boundary)
    {
        using var setup = new NetworkCheckSetup();
        var error = new IOException("Database failed.");
        setup.Boundary = part => { if (part == boundary) throw error; };
        var result = await setup.Collector().CollectAsync(TestContext.Current.CancellationToken);
        Assert.Equal(NetworkDiagnosticsStatus.Failed, result.Status);
        Assert.Null(result.Snapshot);
        Assert.Same(error, result.Error);
        Assert.Same(error, result.Assessment!.Error);
    }

    /// <summary>Caller cancellation remains cancellation at every stage rather than a completed negative assessment.</summary>
    [Theory]
    [InlineData("before")]
    [InlineData("ras")]
    [InlineData("probe")]
    [InlineData("lookup")]
    [InlineData("close")]
    public async Task CallerCancellationPropagates(string boundary)
    {
        using var setup = new NetworkCheckSetup();
        using var caller = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        if (boundary == "before") caller.Cancel();
        setup.Boundary = part => { if (part == boundary) caller.Cancel(); };
        setup.BeforeProbe = _ => { if (boundary == "probe") caller.Cancel(); return Task.CompletedTask; };
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => setup.Collector().CollectAsync(caller.Token));
    }

    /// <summary>The final outer clock cannot conceal network invalidation, rollback, evidence age, or database expiry.</summary>
    [Theory]
    [InlineData("network", NetworkDiagnosticsStatus.NetworkChanged)]
    [InlineData("rollback", NetworkDiagnosticsStatus.InvalidTimestamps)]
    [InlineData("age", NetworkDiagnosticsStatus.Expired)]
    [InlineData("database", NetworkDiagnosticsStatus.Expired)]
    public async Task FinalOuterBoundaryRejectsStaleEvidence(string change, NetworkDiagnosticsStatus expected)
    {
        using var setup = new NetworkCheckSetup();
        if (change == "database") setup.DatabaseDeadline = NetworkCheckSetup.Start.AddSeconds(1);
        var closed = false;
        var finalReads = 0;
        setup.Boundary = part => { if (part == "close") closed = true; };
        var result = await setup.Collector(() =>
        {
            if (closed && ++finalReads == 2)
            {
                if (change == "network") setup.Changed.Cancel();
                if (change == "rollback") return setup.Now.AddSeconds(-1);
                if (change == "age") return setup.Now.AddSeconds(10);
                if (change == "database") return setup.Now.AddSeconds(1);
            }
            return setup.Now;
        }).CollectAsync(TestContext.Current.CancellationToken);
        Assert.Equal(expected, result.Status);
        Assert.Null(result.Snapshot);
        Assert.Equal(NetworkAssessmentStatus.Completed, result.Assessment!.Status);
    }

    /// <summary>Clock rollback observed by a child also invalidates the outer snapshot.</summary>
    [Fact]
    public async Task ClockRollbackDiscardsOuterSnapshot()
    {
        using var setup = new NetworkCheckSetup();
        setup.Boundary = part => { if (part == "ras") setup.Now += TimeSpan.FromSeconds(3); };
        setup.BeforeProbe = _ => { setup.Now -= TimeSpan.FromSeconds(1); return Task.CompletedTask; };
        var result = await setup.Collector().CollectAsync(TestContext.Current.CancellationToken);
        Assert.Equal(NetworkDiagnosticsStatus.InvalidTimestamps, result.Status);
        Assert.Null(result.Snapshot);
    }
}
