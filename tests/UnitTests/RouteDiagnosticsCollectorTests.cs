using System.Net;
using IPGuard.Application.Network;
using IPGuard.Domain;
using Xunit;

namespace UnitTests;

/// <summary>Checks route snapshot lifetime without OS or network access.</summary>
public sealed class RouteDiagnosticsCollectorTests
{
    private static readonly DateTimeOffset Start = new(2026, 10, 24, 9, 0, 0, TimeSpan.Zero);

    /// <summary>Copies complete diagnostics, retaining the original generation and collection interval.</summary>
    [Fact]
    public void StableGenerationPublishesPrivateList()
    {
        using var setup = new Setup();
        var routes = new List<NetworkRoute> { Route() };
        setup.Read = _ => routes;
        var result = setup.Collector().Collect(TestContext.Current.CancellationToken);
        var snapshot = Assert.IsType<RouteDiagnosticsSnapshot>(result.Snapshot);
        routes.Clear();
        Assert.Equal(RouteDiagnosticsStatus.Completed, result.Status);
        Assert.Null(result.Error);
        Assert.Same(setup.Current, snapshot.Network);
        Assert.Single(snapshot.Routes);
        Assert.Equal(Start, snapshot.StartedAt);
        Assert.Equal(Start.AddSeconds(1), snapshot.CompletedAt);
        Assert.False(snapshot.Network.Invalidated.IsCancellationRequested);
        setup.Changed.Cancel();
        Assert.True(snapshot.Network.Invalidated.IsCancellationRequested);
    }

    /// <summary>Routing diagnostics remain useful even when family availability is unknown.</summary>
    [Fact]
    public void UnknownFamiliesDoNotPreventDiagnostics()
    {
        using var setup = new Setup();
        setup.Current = new(Guid.NewGuid(), IpFamilyAvailability.Unknown, IpFamilyAvailability.Unknown, setup.Changed.Token);
        Assert.Equal(RouteDiagnosticsStatus.Completed, setup.Collector().Collect(TestContext.Current.CancellationToken).Status);
    }

    /// <summary>No generation, an empty version, or a missing latch prevents all route I/O.</summary>
    [Theory]
    [InlineData("missing")]
    [InlineData("version")]
    [InlineData("token")]
    [InlineData("cancelled")]
    public void InvalidInitialGenerationDoesNotRead(string condition)
    {
        using var setup = new Setup();
        setup.Current = condition switch
        {
            "missing" => null,
            "version" => new(Guid.Empty, IpFamilyAvailability.Unknown, IpFamilyAvailability.Unknown, setup.Changed.Token),
            "token" => new(Guid.NewGuid(), IpFamilyAvailability.Unknown, IpFamilyAvailability.Unknown, default),
            _ => setup.Current
        };
        if (condition == "cancelled") { setup.Changed.Cancel(); }
        setup.Read = _ => throw new InvalidOperationException("Must not read.");
        var result = setup.Collector().Collect(TestContext.Current.CancellationToken);
        Assert.Equal(RouteDiagnosticsStatus.NetworkUnavailable, result.Status);
        Assert.Null(result.Snapshot);
        Assert.Null(result.Error);
    }

    /// <summary>Changes to any generation component discard route evidence.</summary>
    [Theory]
    [InlineData("cancel")]
    [InlineData("version")]
    [InlineData("availability")]
    [InlineData("signal")]
    [InlineData("missing")]
    public void ChangeDuringReadDiscardsSnapshot(string change)
    {
        using var setup = new Setup();
        setup.Read = _ =>
        {
            var before = setup.Current!;
            switch (change)
            {
                case "cancel": setup.Changed.Cancel(); break;
                case "version": setup.Current = new(Guid.NewGuid(), before.Ipv4, before.Ipv6, before.Invalidated); break;
                case "availability": setup.Current = new(before.Version, IpFamilyAvailability.Unavailable, before.Ipv6, before.Invalidated); break;
                case "signal": setup.Current = new(before.Version, before.Ipv4, before.Ipv6, TestContext.Current.CancellationToken); break;
                case "missing": setup.Current = null; break;
            }
            return [Route()];
        };
        var result = setup.Collector().Collect(TestContext.Current.CancellationToken);
        Assert.Equal(RouteDiagnosticsStatus.NetworkChanged, result.Status);
        Assert.Null(result.Snapshot);
    }

    /// <summary>Failed reads and malformed results cannot publish a partial list.</summary>
    [Theory]
    [InlineData("throw")]
    [InlineData("null")]
    [InlineData("null-row")]
    public void ReaderFailureDiscardsSnapshot(string failure)
    {
        using var setup = new Setup();
        setup.Read = _ => failure switch
        {
            "throw" => throw new IOException("Interface disappeared."),
            "null" => null!,
            _ => [null!]
        };
        var result = setup.Collector().Collect(TestContext.Current.CancellationToken);
        Assert.Equal(RouteDiagnosticsStatus.Failed, result.Status);
        Assert.Null(result.Snapshot);
        Assert.NotNull(result.Error);
    }

    /// <summary>The final time boundary cannot conceal a just-invalidated generation.</summary>
    [Fact]
    public void ChangeInFinalClockDiscardsSnapshot()
    {
        using var setup = new Setup();
        var calls = 0;
        var collector = setup.Collector(() =>
        {
            if (++calls == 2) { setup.Changed.Cancel(); }
            return Start;
        });
        Assert.Equal(RouteDiagnosticsStatus.NetworkChanged, collector.Collect(TestContext.Current.CancellationToken).Status);
    }

    /// <summary>Clock rollback is explicit failure, even with unchanged network state.</summary>
    [Fact]
    public void BackwardClockDiscardsSnapshot()
    {
        using var setup = new Setup();
        var calls = 0;
        var result = setup.Collector(() => calls++ == 0 ? Start : Start.AddSeconds(-1)).Collect(TestContext.Current.CancellationToken);
        Assert.Equal(RouteDiagnosticsStatus.InvalidTimestamps, result.Status);
        Assert.Null(result.Snapshot);
    }

    /// <summary>Caller cancellation before or during reads propagates without masquerading as a network change.</summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void CallerCancellationPropagates(bool during)
    {
        using var setup = new Setup();
        using var caller = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        if (!during) { caller.Cancel(); }
        setup.Read = token => { caller.Cancel(); token.ThrowIfCancellationRequested(); return []; };
        Assert.ThrowsAny<OperationCanceledException>(() => setup.Collector().Collect(caller.Token));
    }

    /// <summary>Provides a default route with distinct route and interface metrics.</summary>
    internal static NetworkRoute Route() => new(new IPNetwork(IPAddress.Any, 0), IPAddress.Parse("192.168.1.1"),
        "interface-a", 12, 5, 20, true, false, uint.MaxValue, false);

    /// <summary>Owns deterministic network, route, and clock boundaries.</summary>
    private sealed class Setup : INetworkSnapshotProvider, IRoutingTableReader, IDisposable
    {
        /// <summary>Creates an initially live generation.</summary>
        internal Setup() => Current = new(Guid.NewGuid(), IpFamilyAvailability.Available, IpFamilyAvailability.Available, Changed.Token);

        /// <summary>Gets the generation invalidation source.</summary>
        internal CancellationTokenSource Changed { get; } = new();

        /// <summary>Gets or sets cached network state.</summary>
        internal NetworkSnapshot? Current { get; set; }

        /// <summary>Gets or sets controlled local reading behavior.</summary>
        internal Func<CancellationToken, IReadOnlyList<NetworkRoute>> Read { get; set; } = _ => [Route()];

        /// <summary>Creates the scenario with this setup's boundaries.</summary>
        internal RouteDiagnosticsCollector Collector(Func<DateTimeOffset>? clock = null)
        {
            var calls = 0;
            return new(this, this, clock ?? (() => calls++ == 0 ? Start : Start.AddSeconds(1)));
        }

        /// <summary>Returns controlled state without I/O.</summary>
        public NetworkSnapshot? Capture() => Current;

        /// <summary>Delegates local route reads to controlled behavior.</summary>
        IReadOnlyList<NetworkRoute> IRoutingTableReader.Read(CancellationToken cancellationToken) => Read(cancellationToken);

        /// <summary>Releases the test-owned generation source.</summary>
        public void Dispose() => Changed.Dispose();
    }
}
