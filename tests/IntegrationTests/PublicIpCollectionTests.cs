using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using IPGuard.Application.Network;
using IPGuard.Application.PublicIp;
using IPGuard.Domain;
using IPGuard.Infrastructure.PublicIp;
using Xunit;

namespace IntegrationTests;

/// <summary>Checks composition of application collection, the real bounded reader, and domain policy using controlled HTTP replies.</summary>
public sealed class PublicIpCollectionTests
{
    /// <summary>Conflicting addresses and HTTP failures survive collection and remain ineligible in the domain.</summary>
    [Fact]
    public async Task CollectAsync_ReaderPreservesFailuresAndDomainRejectsConflict()
    {
        Guid version = Guid.NewGuid();
        var network = new NetworkSnapshot(version, IpFamilyAvailability.Available, IpFamilyAvailability.Available, TestContext.Current.CancellationToken);
        var reader = new PublicIpReader(new ResponseTransport(source =>
        {
            if (source.Family == AddressFamily.InterNetworkV6 && source.OperatorId == "ident.me")
            {
                return Reply("Unavailable", HttpStatusCode.ServiceUnavailable);
            }

            return Reply(source.Family == AddressFamily.InterNetworkV6 ? "2606:4700:4700::1111"
                : source.OperatorId == "ipify" ? "1.1.1.1" : "8.8.8.8");
        }), TimeSpan.FromSeconds(5));
        DateTimeOffset now = DateTimeOffset.UtcNow;
        var collector = new PublicIpCollector(reader, new SnapshotProvider(() => network), PublicIpSources.Defaults, () => now);

        PublicIpCollectionResult result = await collector.CollectAsync(TestContext.Current.CancellationToken);

        Assert.Equal(PublicIpCollectionStatus.Completed, result.Status);
        PublicIpSnapshot snapshot = Assert.IsType<PublicIpSnapshot>(result.Snapshot);
        Assert.Equal(4, snapshot.Attempts.Count);
        Assert.Equal(PublicIpReadStatus.HttpRejected, snapshot.Attempts[3].Status);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, snapshot.Attempts[3].HttpStatus);
        Assert.Null(snapshot.Attempts[3].Observation.Address);
        var assessment = new NetworkAssessment(version, snapshot.StartedAt, snapshot.CompletedAt,
            FamilyEvidence(snapshot, AddressFamily.InterNetwork), FamilyEvidence(snapshot, AddressFamily.InterNetworkV6));
        PublicIpDecision decision = new PublicIpPolicy(TimeSpan.FromMinutes(5)).Evaluate(assessment, version, now);
        Assert.False(decision.IsEligible);
        Assert.Equal(PublicIpDecisionReason.ConflictingAddresses, decision.Reason);
    }

    /// <summary>Cancellation from the network snapshot reaches the real reader and prevents partial publication.</summary>
    [Fact]
    public async Task CollectAsync_NetworkInvalidationDuringResponse_DiscardsReaderResults()
    {
        using var changed = new CancellationTokenSource();
        var network = new NetworkSnapshot(Guid.NewGuid(), IpFamilyAvailability.Available, IpFamilyAvailability.Available, changed.Token);
        var reader = new PublicIpReader(new ResponseTransport(_ =>
        {
            changed.Cancel();
            return Reply("1.1.1.1");
        }), TimeSpan.FromSeconds(5));
        var collector = new PublicIpCollector(reader, new SnapshotProvider(() => network), PublicIpSources.Defaults);

        PublicIpCollectionResult result = await collector.CollectAsync(TestContext.Current.CancellationToken);

        Assert.Equal(PublicIpCollectionStatus.NetworkChanged, result.Status);
        Assert.Null(result.Snapshot);
        Assert.Null(result.Error);
    }

    /// <summary>Maps collected source observations into domain evidence without inventing a country lookup.</summary>
    private static IpFamilyEvidence FamilyEvidence(PublicIpSnapshot snapshot, AddressFamily family) =>
        new(family == AddressFamily.InterNetwork ? snapshot.Network.Ipv4 : snapshot.Network.Ipv6,
            snapshot.Attempts.Where(attempt => attempt.Source.Family == family).Select(attempt => attempt.Observation));

    /// <summary>Creates an ordinary streaming-compatible plaintext HTTP response in memory.</summary>
    private static HttpResponseMessage Reply(string body, HttpStatusCode status = HttpStatusCode.OK)
    {
        var response = new HttpResponseMessage(status) { Content = new StringContent(body) };
        response.Content.Headers.ContentType = new MediaTypeHeaderValue("text/plain");
        return response;
    }

    /// <summary>Supplies controlled HTTP responses without subclassing a framework handler.</summary>
    private sealed class ResponseTransport : IPublicIpTransport
    {
        private readonly Func<PublicIpSource, HttpResponseMessage> respond;

        /// <summary>Captures the response factory for individual configured endpoints.</summary>
        internal ResponseTransport(Func<PublicIpSource, HttpResponseMessage> respond) => this.respond = respond;

        /// <summary>Returns one synthetic response without DNS, sockets, or public service access.</summary>
        public Task<HttpResponseMessage> SendAsync(PublicIpSource source, CancellationToken cancellationToken) => Task.FromResult(respond(source));
    }

    /// <summary>Exposes controlled cached network state to the application boundary.</summary>
    private sealed class SnapshotProvider : INetworkSnapshotProvider
    {
        private readonly Func<NetworkSnapshot?> capture;

        /// <summary>Captures one atomic state-read callback.</summary>
        internal SnapshotProvider(Func<NetworkSnapshot?> capture) => this.capture = capture;

        /// <summary>Returns the current synthetic generation.</summary>
        public NetworkSnapshot? Capture() => capture();
    }
}
