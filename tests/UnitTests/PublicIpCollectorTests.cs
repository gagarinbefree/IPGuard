using System.Net;
using System.Net.Sockets;
using IPGuard.Application.Network;
using IPGuard.Application.PublicIp;
using IPGuard.Domain;
using Xunit;

namespace UnitTests;

/// <summary>Checks generation-bound collection with controlled probes, snapshots, and time, without I/O.</summary>
public sealed class PublicIpCollectorTests
{
    private static readonly Guid Version = Guid.Parse("73f9f320-2582-44d2-b785-7406cbdd9b7b");
    private static readonly DateTimeOffset StartedAt = new(2026, 10, 24, 8, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset CompletedAt = StartedAt.AddSeconds(2);

    /// <summary>A stable generation retains every reply, failure, and timestamp without deciding consensus.</summary>
    [Fact]
    public async Task CollectAsync_StableNetwork_PreservesAllEvidence()
    {
        var network = SnapshotDefault();
        PublicIpSource[] sources = Sources();
        var attempts = Replies(sources).ToList();
        attempts[1] = new(sources[1], PublicIpReadStatus.Success, IPAddress.Parse("8.8.8.8"));
        attempts[3] = new(sources[3], PublicIpReadStatus.TlsFailed);
        var collector = Collector(new FakeProbe((_, _) => Task.FromResult<IReadOnlyList<PublicIpReadResult>>(attempts)),
            new FakeNetwork(() => network), sources);

        PublicIpCollectionResult result = await collector.CollectAsync(TestContext.Current.CancellationToken);
        PublicIpSnapshot snapshot = Assert.IsType<PublicIpSnapshot>(result.Snapshot);
        attempts.Clear();

        Assert.Equal(PublicIpCollectionStatus.Completed, result.Status);
        Assert.Null(result.Error);
        Assert.Same(network, snapshot.Network);
        Assert.Equal(StartedAt, snapshot.StartedAt);
        Assert.Equal(CompletedAt, snapshot.CompletedAt);
        Assert.Equal(4, snapshot.Attempts.Count);
        Assert.Equal("8.8.8.8", snapshot.Attempts[1].Observation.Address);
        Assert.Equal(PublicIpReadStatus.TlsFailed, snapshot.Attempts[3].Status);
        Assert.Null(snapshot.Attempts[3].Observation.Address);
    }

    /// <summary>Unknown generations and either unknown family stop collection before probing.</summary>
    [Theory]
    [InlineData("missing")]
    [InlineData("version")]
    [InlineData("ipv4")]
    [InlineData("ipv6")]
    [InlineData("invalid")]
    [InlineData("signal")]
    public async Task CollectAsync_UnknownNetwork_DoesNotProbe(string unknown)
    {
        bool probed = false;
        NetworkSnapshot? network = unknown switch
        {
            "missing" => null,
            "version" => new(Guid.Empty, IpFamilyAvailability.Available, IpFamilyAvailability.Available, default),
            "ipv4" => Snapshot(TestContext.Current.CancellationToken, ipv4: IpFamilyAvailability.Unknown),
            "ipv6" => Snapshot(TestContext.Current.CancellationToken, ipv6: IpFamilyAvailability.Unknown),
            "signal" => new(Version, IpFamilyAvailability.Available, IpFamilyAvailability.Available, CancellationToken.None),
            _ => Snapshot(TestContext.Current.CancellationToken, ipv6: (IpFamilyAvailability)99)
        };
        var probe = new FakeProbe((sources, _) => { probed = true; return Task.FromResult(Replies(sources)); });

        PublicIpCollectionResult result = await Collector(probe, new FakeNetwork(() => network))
            .CollectAsync(TestContext.Current.CancellationToken);

        AssertDiscarded(PublicIpCollectionStatus.NetworkUnavailable, result);
        Assert.False(probed);
    }

    /// <summary>Only families explicitly reported available are probed; no-network collections perform no requests.</summary>
    [Theory]
    [InlineData(IpFamilyAvailability.Available, IpFamilyAvailability.Unavailable, 2)]
    [InlineData(IpFamilyAvailability.Unavailable, IpFamilyAvailability.Available, 2)]
    [InlineData(IpFamilyAvailability.Unavailable, IpFamilyAvailability.Unavailable, 0)]
    public async Task CollectAsync_AccountsForFamilyAvailability(IpFamilyAvailability ipv4, IpFamilyAvailability ipv6, int expected)
    {
        int attempts = 0;
        var probe = new FakeProbe((sources, _) =>
        {
            PublicIpSource[] requested = sources.ToArray();
            attempts += requested.Length;
            Assert.NotEmpty(requested);
            Assert.All(requested, source => Assert.Equal(IpFamilyAvailability.Available,
                source.Family == AddressFamily.InterNetwork ? ipv4 : ipv6));
            return Task.FromResult(Replies(requested));
        });

        PublicIpCollectionResult result = await Collector(probe, new FakeNetwork(() => Snapshot(TestContext.Current.CancellationToken, ipv4: ipv4, ipv6: ipv6)))
            .CollectAsync(TestContext.Current.CancellationToken);

        Assert.Equal(PublicIpCollectionStatus.Completed, result.Status);
        Assert.Equal(expected, attempts);
        Assert.Equal(expected, result.Snapshot!.Attempts.Count);
        Assert.Equal(ipv4, result.Snapshot.Network.Ipv4);
        Assert.Equal(ipv6, result.Snapshot.Network.Ipv6);
    }

    /// <summary>An already invalidated snapshot cannot start any source request.</summary>
    [Fact]
    public async Task CollectAsync_InitiallyInvalidated_DoesNotProbe()
    {
        using var changed = new CancellationTokenSource();
        changed.Cancel();
        bool probed = false;
        var probe = new FakeProbe((sources, _) => { probed = true; return Task.FromResult(Replies(sources)); });

        PublicIpCollectionResult result = await Collector(probe, new FakeNetwork(() => Snapshot(changed.Token)))
            .CollectAsync(TestContext.Current.CancellationToken);

        AssertDiscarded(PublicIpCollectionStatus.NetworkChanged, result);
        Assert.False(probed);
    }

    /// <summary>Network invalidation cancels an in-flight cooperative probe and discards its work.</summary>
    [Fact]
    public async Task CollectAsync_NetworkChanges_CancelsProbe()
    {
        using var changed = new CancellationTokenSource();
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        CancellationToken received = default;
        var probe = new FakeProbe(async (_, token) =>
        {
            received = token;
            started.SetResult();
            await Task.Delay(Timeout.InfiniteTimeSpan, token);
            throw new InvalidOperationException("Unexpected probe completion.");
        });
        var collector = Collector(probe, new FakeNetwork(() => Snapshot(changed.Token)));

        Task<PublicIpCollectionResult> pending = collector.CollectAsync(TestContext.Current.CancellationToken);
        await started.Task.WaitAsync(TestContext.Current.CancellationToken);
        changed.Cancel();
        PublicIpCollectionResult result = await pending;

        AssertDiscarded(PublicIpCollectionStatus.NetworkChanged, result);
        Assert.Null(result.Error);
        Assert.True(received.IsCancellationRequested);
    }

    /// <summary>Late replies cannot revive a cancelled generation, including a disconnect/reconnect cycle.</summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CollectAsync_LateReplyAfterInvalidation_IsDiscarded(bool reconnect)
    {
        using var changed = new CancellationTokenSource();
        using var replacement = new CancellationTokenSource();
        NetworkSnapshot current = Snapshot(changed.Token);
        var probe = new FakeProbe((sources, _) =>
        {
            changed.Cancel();
            if (reconnect)
            {
                current = Snapshot(replacement.Token);
            }

            return Task.FromResult(Replies(sources));
        });

        AssertDiscarded(PublicIpCollectionStatus.NetworkChanged,
            await Collector(probe, new FakeNetwork(() => current)).CollectAsync(TestContext.Current.CancellationToken));
    }

    /// <summary>The final capture detects version, availability, and token changes even without a timely cancellation signal.</summary>
    [Theory]
    [InlineData("version")]
    [InlineData("ipv4")]
    [InlineData("ipv6")]
    [InlineData("token")]
    [InlineData("missing")]
    public async Task CollectAsync_FinalSnapshotDiffers_IsDiscarded(string difference)
    {
        using var changed = new CancellationTokenSource();
        int captures = 0;
        NetworkSnapshot? after = difference switch
        {
            "version" => new(Guid.NewGuid(), IpFamilyAvailability.Available, IpFamilyAvailability.Available, default),
            "ipv4" => Snapshot(TestContext.Current.CancellationToken, ipv4: IpFamilyAvailability.Unavailable),
            "ipv6" => Snapshot(TestContext.Current.CancellationToken, ipv6: IpFamilyAvailability.Unavailable),
            "token" => Snapshot(changed.Token),
            _ => null
        };
        var network = new FakeNetwork(() => ++captures == 1 ? SnapshotDefault() : after);

        AssertDiscarded(PublicIpCollectionStatus.NetworkChanged,
            await Collector(ValidProbe(), network).CollectAsync(TestContext.Current.CancellationToken));
    }

    /// <summary>Invalidation while the finishing clock is read still discards the just-collected replies.</summary>
    [Fact]
    public async Task CollectAsync_ChangesAtCompletion_IsDiscarded()
    {
        using var changed = new CancellationTokenSource();
        int clockReads = 0;
        var collector = new PublicIpCollector(ValidProbe(), new FakeNetwork(() => Snapshot(changed.Token)), Sources(), () =>
        {
            if (++clockReads == 1)
            {
                return StartedAt;
            }

            changed.Cancel();
            return CompletedAt;
        });

        AssertDiscarded(PublicIpCollectionStatus.NetworkChanged, await collector.CollectAsync(TestContext.Current.CancellationToken));
    }

    /// <summary>Callers can detect a generation becoming obsolete after collection has already completed.</summary>
    [Fact]
    public async Task CollectAsync_ResultRetainsLiveInvalidationSignal()
    {
        using var changed = new CancellationTokenSource();
        PublicIpCollectionResult result = await Collector(ValidProbe(), new FakeNetwork(() => Snapshot(changed.Token)))
            .CollectAsync(TestContext.Current.CancellationToken);
        Assert.Equal(PublicIpCollectionStatus.Completed, result.Status);

        changed.Cancel();

        Assert.True(result.Snapshot!.Network.Invalidated.IsCancellationRequested);
    }

    /// <summary>A caller cancelled before collection does not trigger capture, clock, or probe work.</summary>
    [Fact]
    public async Task CollectAsync_AlreadyCancelled_DoesNotCapture()
    {
        bool captured = false;
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        cancellation.Cancel();
        var collector = Collector(ValidProbe(), new FakeNetwork(() => { captured = true; return SnapshotDefault(); }));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => collector.CollectAsync(cancellation.Token));
        Assert.False(captured);
    }

    /// <summary>Caller cancellation takes priority over simultaneous network invalidation or an I/O error.</summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CollectAsync_CallerCancellation_Propagates(bool ioError)
    {
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        using var changed = new CancellationTokenSource();
        var probe = new FakeProbe((_, token) =>
        {
            changed.Cancel();
            cancellation.Cancel();
            if (ioError)
            {
                throw new IOException("Expected cancellation race.");
            }

            throw new OperationCanceledException(token);
        });
        var collector = Collector(probe, new FakeNetwork(() => Snapshot(changed.Token)));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => collector.CollectAsync(cancellation.Token));
    }

    /// <summary>Unexpected failures never expose partial evidence and retain the original error for diagnostics.</summary>
    [Theory]
    [InlineData("capture-before")]
    [InlineData("capture-after")]
    [InlineData("probe")]
    [InlineData("clock-before")]
    [InlineData("clock-after")]
    public async Task CollectAsync_BoundaryFails_RetainsFailure(string boundary)
    {
        var error = new IOException("Expected boundary failure.");
        int captures = 0;
        int clockReads = 0;
        var network = new FakeNetwork(() =>
        {
            if ((++captures == 1 && boundary == "capture-before") || (captures == 2 && boundary == "capture-after"))
            {
                throw error;
            }

            return SnapshotDefault();
        });
        var probe = new FakeProbe((sources, _) => boundary == "probe" ? throw error : Task.FromResult(Replies(sources)));
        var collector = new PublicIpCollector(probe, network, Sources(), () =>
        {
            if ((++clockReads == 1 && boundary == "clock-before") || (clockReads == 2 && boundary == "clock-after"))
            {
                throw error;
            }

            return clockReads == 1 ? StartedAt : CompletedAt;
        });

        PublicIpCollectionResult result = await collector.CollectAsync(TestContext.Current.CancellationToken);

        AssertDiscarded(PublicIpCollectionStatus.Failed, result);
        Assert.Same(error, result.Error);
    }

    /// <summary>Missing, extra, substituted, or reordered results cannot masquerade as complete source coverage.</summary>
    [Theory]
    [InlineData("missing")]
    [InlineData("extra")]
    [InlineData("reordered")]
    [InlineData("operator")]
    [InlineData("endpoint")]
    [InlineData("null-list")]
    [InlineData("null-item")]
    [InlineData("invalid-status")]
    [InlineData("missing-address")]
    public async Task CollectAsync_InvalidProbeOutput_IsDiscarded(string invalid)
    {
        var probe = new FakeProbe((sources, _) =>
        {
            var replies = Replies(sources).ToList();
            switch (invalid)
            {
                case "missing": replies.RemoveAt(0); break;
                case "extra": replies.Add(replies[0]); break;
                case "reordered": replies.Reverse(); break;
                case "operator": replies[0] = new(Source("other", AddressFamily.InterNetwork), PublicIpReadStatus.TimedOut); break;
                case "endpoint": replies[0] = new(new("operator-a", new Uri("https://other.example/"), AddressFamily.InterNetwork), PublicIpReadStatus.TimedOut); break;
                case "null-list": return Task.FromResult<IReadOnlyList<PublicIpReadResult>>(null!);
                case "null-item": replies[0] = null!; break;
                case "invalid-status": replies[0] = new(replies[0].Source, (PublicIpReadStatus)99); break;
                case "missing-address": replies[0] = new(replies[0].Source, PublicIpReadStatus.Success); break;
            }

            return Task.FromResult<IReadOnlyList<PublicIpReadResult>>(replies);
        });

        AssertDiscarded(PublicIpCollectionStatus.InvalidProbeResult,
            await Collector(probe, new FakeNetwork(SnapshotDefault)).CollectAsync(TestContext.Current.CancellationToken));
    }

    /// <summary>Request failures do not establish that either address family is unavailable.</summary>
    [Fact]
    public async Task CollectAsync_AllRequestsFail_DoesNotInferFamilyAbsence()
    {
        var probe = new FakeProbe((sources, _) => Task.FromResult<IReadOnlyList<PublicIpReadResult>>(
            sources.Select(source => new PublicIpReadResult(source, PublicIpReadStatus.NameResolutionFailed)).ToArray()));

        PublicIpCollectionResult result = await Collector(probe, new FakeNetwork(SnapshotDefault))
            .CollectAsync(TestContext.Current.CancellationToken);

        Assert.Equal(PublicIpCollectionStatus.Completed, result.Status);
        Assert.Equal(IpFamilyAvailability.Available, result.Snapshot!.Network.Ipv4);
        Assert.Equal(IpFamilyAvailability.Available, result.Snapshot.Network.Ipv6);
        Assert.All(result.Snapshot.Attempts, attempt => Assert.Null(attempt.Observation.Address));
    }

    /// <summary>Wall clock rollback cannot produce a usable collection interval.</summary>
    [Fact]
    public async Task CollectAsync_ClockMovesBackwards_IsDiscarded()
    {
        int reads = 0;
        var collector = new PublicIpCollector(ValidProbe(), new FakeNetwork(SnapshotDefault), Sources(),
            () => ++reads == 1 ? CompletedAt : StartedAt);

        AssertDiscarded(PublicIpCollectionStatus.InvalidTimestamps, await collector.CollectAsync(TestContext.Current.CancellationToken));
    }

    /// <summary>Configuration edits after construction cannot change the sources used by an existing collector.</summary>
    [Fact]
    public async Task Constructor_CopiesSourceConfiguration()
    {
        PublicIpSource[] sources = Sources();
        var collector = Collector(ValidProbe(), new FakeNetwork(SnapshotDefault), sources);
        sources[0] = Source("replacement", AddressFamily.InterNetwork);

        PublicIpCollectionResult result = await collector.CollectAsync(TestContext.Current.CancellationToken);

        Assert.Equal("operator-a", result.Snapshot!.Attempts[0].Source.OperatorId);
    }

    /// <summary>Checks that unsuccessful collection cannot export reusable evidence.</summary>
    private static void AssertDiscarded(PublicIpCollectionStatus status, PublicIpCollectionResult result)
    {
        Assert.Equal(status, result.Status);
        Assert.Null(result.Snapshot);
    }

    /// <summary>Composes deterministic time and default source configuration for one scenario.</summary>
    private static PublicIpCollector Collector(IPublicIpProbe probe, INetworkSnapshotProvider network, PublicIpSource[]? sources = null)
    {
        int reads = 0;
        return new(probe, network, sources ?? Sources(), () => ++reads == 1 ? StartedAt : CompletedAt);
    }

    /// <summary>Creates a stable two-family network with a chosen invalidation signal.</summary>
    private static NetworkSnapshot Snapshot(CancellationToken invalidated,
        IpFamilyAvailability ipv4 = IpFamilyAvailability.Available, IpFamilyAvailability ipv6 = IpFamilyAvailability.Available) =>
        new(Version, ipv4, ipv6, invalidated);

    /// <summary>Supplies a parameterless stable snapshot factory.</summary>
    private static NetworkSnapshot SnapshotDefault() => Snapshot(TestContext.Current.CancellationToken);

    /// <summary>Defines two source operators for each address family without performing DNS.</summary>
    private static PublicIpSource[] Sources() =>
        [Source("operator-a", AddressFamily.InterNetwork), Source("operator-b", AddressFamily.InterNetwork),
         Source("operator-a", AddressFamily.InterNetworkV6), Source("operator-b", AddressFamily.InterNetworkV6)];

    /// <summary>Builds one trusted source definition with a reserved example hostname.</summary>
    private static PublicIpSource Source(string operatorId, AddressFamily family) => new(operatorId, new Uri($"https://{operatorId}.example/"), family);

    /// <summary>Supplies agreeing successful replies in the requested source order.</summary>
    private static IReadOnlyList<PublicIpReadResult> Replies(IEnumerable<PublicIpSource> sources) => sources.Select(source =>
        new PublicIpReadResult(source, PublicIpReadStatus.Success,
            IPAddress.Parse(source.Family == AddressFamily.InterNetwork ? "1.1.1.1" : "2606:4700:4700::1111"))).ToArray();

    /// <summary>Creates a probe whose observations contain no operating system or HTTP dependencies.</summary>
    private static FakeProbe ValidProbe() => new((sources, _) => Task.FromResult(Replies(sources)));

    /// <summary>Controls source completion and cancellation through composition.</summary>
    private sealed class FakeProbe : IPublicIpProbe
    {
        private readonly Func<IEnumerable<PublicIpSource>, CancellationToken, Task<IReadOnlyList<PublicIpReadResult>>> read;

        /// <summary>Captures the behavior of one batch of source attempts.</summary>
        internal FakeProbe(Func<IEnumerable<PublicIpSource>, CancellationToken, Task<IReadOnlyList<PublicIpReadResult>>> read) => this.read = read;

        /// <summary>Returns controlled source results or failures.</summary>
        public Task<IReadOnlyList<PublicIpReadResult>> ReadAllAsync(IEnumerable<PublicIpSource> sources, CancellationToken cancellationToken) =>
            read(sources, cancellationToken);
    }

    /// <summary>Supplies atomic snapshots or controlled capture failures.</summary>
    private sealed class FakeNetwork : INetworkSnapshotProvider
    {
        private readonly Func<NetworkSnapshot?> capture;

        /// <summary>Captures a cached-state read callback.</summary>
        internal FakeNetwork(Func<NetworkSnapshot?> capture) => this.capture = capture;

        /// <summary>Returns the current test snapshot without I/O.</summary>
        public NetworkSnapshot? Capture() => capture();
    }
}
