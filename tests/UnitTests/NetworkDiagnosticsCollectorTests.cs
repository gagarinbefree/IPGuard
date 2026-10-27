using IPGuard.Application.Network;
using IPGuard.Domain;
using Xunit;

namespace UnitTests;

/// <summary>Exercises combined local observations without Windows calls or network access.</summary>
public sealed class NetworkDiagnosticsCollectorTests
{
    private static readonly DateTimeOffset Start = new(2026, 10, 25, 8, 0, 0, TimeSpan.Zero);

    /// <summary>Complete observations share the original generation, interval, and private collections.</summary>
    [Fact]
    public void CollectCopiesAllObservations()
    {
        using var setup = new Setup();
        var routes = new List<NetworkRoute> { RouteDiagnosticsCollectorTests.Route() };
        var connections = new List<RemoteAccessConnection> { new("provider", true, RemoteAccessState.Reconnecting, 0, 8192, 2) };
        setup.ReadRoutes = _ => routes;
        setup.ReadConnections = _ => connections;
        var result = setup.Collector().Collect(TestContext.Current.CancellationToken);
        var snapshot = Assert.IsType<NetworkDiagnosticsSnapshot>(result.Snapshot);
        routes.Clear();
        connections.Clear();
        Assert.Equal(NetworkDiagnosticsStatus.Completed, result.Status);
        Assert.Null(result.Error);
        Assert.Same(setup.Current, snapshot.Network);
        Assert.Same(setup.Proxy, snapshot.Proxy);
        Assert.Single(snapshot.Routes);
        Assert.Equal(RemoteAccessState.Reconnecting, Assert.Single(snapshot.Connections).State);
        Assert.Equal(Start, snapshot.StartedAt);
        Assert.Equal(Start, snapshot.CompletedAt);
        setup.Changed.Cancel();
        Assert.True(snapshot.Network.Invalidated.IsCancellationRequested);
    }

    /// <summary>Unknown families, empty observations, and false flags remain diagnostics rather than permission.</summary>
    [Fact]
    public void EmptyObservationsRemainRepresentable()
    {
        using var setup = new Setup();
        setup.Current = new(Guid.NewGuid(), IpFamilyAvailability.Unknown, IpFamilyAvailability.Unknown, setup.Changed.Token);
        var snapshot = Assert.IsType<NetworkDiagnosticsSnapshot>(setup.Collector().Collect(TestContext.Current.CancellationToken).Snapshot);
        Assert.Empty(snapshot.Routes);
        Assert.Empty(snapshot.Connections);
        Assert.False(snapshot.Proxy.ProcessProxy);
        Assert.Equal(IpFamilyAvailability.Unknown, snapshot.Network.Ipv6);
    }

    /// <summary>Invalid initial generations prevent every local read.</summary>
    [Theory]
    [InlineData("missing")]
    [InlineData("version")]
    [InlineData("token")]
    [InlineData("cancelled")]
    public void InvalidNetworkDoesNotRead(string condition)
    {
        using var setup = new Setup();
        setup.Current = condition switch
        {
            "missing" => null,
            "version" => new(Guid.Empty, IpFamilyAvailability.Unknown, IpFamilyAvailability.Unknown, setup.Changed.Token),
            "token" => new(Guid.NewGuid(), IpFamilyAvailability.Unknown, IpFamilyAvailability.Unknown, default),
            _ => setup.Current
        };
        if (condition == "cancelled") setup.Changed.Cancel();
        setup.ReadRoutes = _ => throw new InvalidOperationException("Must not read.");
        var result = setup.Collector().Collect(TestContext.Current.CancellationToken);
        Assert.Equal(NetworkDiagnosticsStatus.NetworkUnavailable, result.Status);
        Assert.Null(result.Snapshot);
        Assert.Null(result.Error);
    }

    /// <summary>Every local boundary rejects changes without forwarding partial observations.</summary>
    [Theory]
    [InlineData("routes", "cancel")]
    [InlineData("proxy", "cancel")]
    [InlineData("ras", "cancel")]
    [InlineData("proxy", "version")]
    [InlineData("proxy", "availability")]
    [InlineData("proxy", "token")]
    [InlineData("proxy", "missing")]
    public void ChangedGenerationDiscardsAll(string boundary, string change)
    {
        using var setup = new Setup();
        setup.BeforeRead = part =>
        {
            if (part != boundary) return;
            var original = setup.Current!;
            switch (change)
            {
                case "cancel": setup.Changed.Cancel(); break;
                case "version": setup.Current = new(Guid.NewGuid(), original.Ipv4, original.Ipv6, original.Invalidated); break;
                case "availability": setup.Current = new(original.Version, IpFamilyAvailability.Unavailable, original.Ipv6, original.Invalidated); break;
                case "token": setup.Current = new(original.Version, original.Ipv4, original.Ipv6, TestContext.Current.CancellationToken); break;
                case "missing": setup.Current = null; break;
            }
        };
        var result = setup.Collector().Collect(TestContext.Current.CancellationToken);
        Assert.Equal(NetworkDiagnosticsStatus.NetworkChanged, result.Status);
        Assert.Null(result.Snapshot);
        Assert.Equal(boundary == "routes" ? 1 : boundary == "proxy" ? 2 : 3, setup.Reads);
    }

    /// <summary>A failed reader or malformed result never leaves a usable subset.</summary>
    [Theory]
    [InlineData("routes", "throw")]
    [InlineData("proxy", "throw")]
    [InlineData("ras", "throw")]
    [InlineData("routes", "null")]
    [InlineData("proxy", "null")]
    [InlineData("ras", "null")]
    [InlineData("routes", "row")]
    [InlineData("ras", "row")]
    [InlineData("ras", "state")]
    public void BrokenReaderDiscardsAll(string boundary, string defect)
    {
        using var setup = new Setup();
        var failure = new IOException("Reader failed.");
        setup.BeforeRead = part => { if (part == boundary && defect == "throw") throw failure; };
        if (boundary == "routes" && defect != "throw") setup.ReadRoutes = _ => defect == "null" ? null! : [null!];
        if (boundary == "proxy" && defect == "null") setup.Proxy = null!;
        if (boundary == "ras" && defect != "throw") setup.ReadConnections = _ => defect switch
        {
            "null" => null!,
            "row" => [null!],
            _ => [new(null, false, (RemoteAccessState)999, 0, 999, 0)]
        };
        var result = setup.Collector().Collect(TestContext.Current.CancellationToken);
        Assert.Equal(NetworkDiagnosticsStatus.Failed, result.Status);
        Assert.Null(result.Snapshot);
        if (defect == "throw") Assert.Same(failure, result.Error);
        else Assert.IsType<InvalidDataException>(result.Error);
    }

    /// <summary>Age is exclusive and starts before routes, rather than after the last reader.</summary>
    [Theory]
    [InlineData("routes")]
    [InlineData("proxy")]
    [InlineData("ras")]
    public void DeadlineDiscardsSlowRead(string boundary)
    {
        using var setup = new Setup();
        setup.BeforeRead = part => { if (part == boundary) setup.Now = Start.AddSeconds(10); };
        var result = setup.Collector().Collect(TestContext.Current.CancellationToken);
        Assert.Equal(NetworkDiagnosticsStatus.Expired, result.Status);
        Assert.Null(result.Snapshot);
        Assert.Equal(boundary == "routes" ? 1 : boundary == "proxy" ? 2 : 3, setup.Reads);
    }

    /// <summary>A backward step is rejected even when still later than collection start.</summary>
    [Fact]
    public void IntermediateClockRollbackDiscardsAll()
    {
        using var setup = new Setup();
        setup.BeforeRead = part => setup.Now = Start.AddSeconds(part == "routes" ? 3 : 2);
        var result = setup.Collector().Collect(TestContext.Current.CancellationToken);
        Assert.Equal(NetworkDiagnosticsStatus.InvalidTimestamps, result.Status);
        Assert.Null(result.Snapshot);
        Assert.Equal(2, setup.Reads);
    }

    /// <summary>A generation cancelled by the final clock cannot be published.</summary>
    [Fact]
    public void FinalClockCannotHideCancellation()
    {
        using var setup = new Setup();
        var result = setup.Collector(() =>
        {
            if (setup.Reads == 3) setup.Changed.Cancel();
            return Start;
        }).Collect(TestContext.Current.CancellationToken);
        Assert.Equal(NetworkDiagnosticsStatus.NetworkChanged, result.Status);
        Assert.Null(result.Snapshot);
    }

    /// <summary>A nested route interval must fit inside its parent's observed interval, even after a brief clock rollback.</summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void RouteIntervalCannotEscapeParent(bool endsAfterParent)
    {
        using var setup = new Setup();
        var calls = 0;
        var result = setup.Collector(() => ++calls switch
        {
            2 => Start.AddSeconds(endsAfterParent ? 0 : -1),
            3 => Start.AddSeconds(endsAfterParent ? 3 : 0),
            _ => Start.AddSeconds(endsAfterParent && calls > 3 ? 2 : 0)
        }).Collect(TestContext.Current.CancellationToken);
        Assert.Equal(NetworkDiagnosticsStatus.InvalidTimestamps, result.Status);
        Assert.Null(result.Snapshot);
    }

    /// <summary>Caller cancellation wins before or during any reader, including an uncooperative return.</summary>
    [Theory]
    [InlineData("before")]
    [InlineData("routes")]
    [InlineData("proxy")]
    [InlineData("ras")]
    public void CallerCancellationPropagates(string boundary)
    {
        using var setup = new Setup();
        using var caller = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        if (boundary == "before") caller.Cancel();
        setup.BeforeRead = part => { if (part == boundary) caller.Cancel(); };
        Assert.ThrowsAny<OperationCanceledException>(() => setup.Collector().Collect(caller.Token));
    }

    /// <summary>Composes deterministic local readers without platform inheritance.</summary>
    internal sealed class Setup : INetworkSnapshotProvider, IRoutingTableReader, IProxySettingsReader, IRemoteAccessReader, IDisposable
    {
        /// <summary>Creates a live network generation.</summary>
        internal Setup() => Current = new(Guid.NewGuid(), IpFamilyAvailability.Available, IpFamilyAvailability.Available, Changed.Token);

        /// <summary>Gets the permanent network-change latch.</summary>
        internal CancellationTokenSource Changed { get; } = new();

        /// <summary>Gets or sets cached network state.</summary>
        internal NetworkSnapshot? Current { get; set; }

        /// <summary>Gets or sets the controlled wall clock.</summary>
        internal DateTimeOffset Now { get; set; } = Start;

        /// <summary>Gets or sets observed proxy flags.</summary>
        internal ProxySettings Proxy { get; set; } = new(false, false, false, false, false, false, false, false);

        /// <summary>Gets or sets route reading behavior.</summary>
        internal Func<CancellationToken, IReadOnlyList<NetworkRoute>> ReadRoutes { get; set; } = _ => [];

        /// <summary>Gets or sets RAS reading behavior.</summary>
        internal Func<CancellationToken, IReadOnlyList<RemoteAccessConnection>> ReadConnections { get; set; } = _ => [];

        /// <summary>Gets or sets a hook before each local reader.</summary>
        internal Action<string> BeforeRead { get; set; } = _ => { };

        /// <summary>Gets the number of attempted local reads.</summary>
        internal int Reads { get; private set; }

        /// <summary>Creates combined diagnostics with a ten-second exclusive age.</summary>
        internal NetworkDiagnosticsCollector Collector(Func<DateTimeOffset>? clock = null) => new(this, this, this, this, TimeSpan.FromSeconds(10), clock ?? (() => Now));

        /// <summary>Returns cached generation state.</summary>
        public NetworkSnapshot? Capture() => Current;

        /// <summary>Reads controlled routes after recording the boundary.</summary>
        IReadOnlyList<NetworkRoute> IRoutingTableReader.Read(CancellationToken cancellationToken)
        {
            Enter("routes");
            return ReadRoutes(cancellationToken);
        }

        /// <summary>Reads controlled proxy flags after recording the boundary.</summary>
        ProxySettings IProxySettingsReader.Read(CancellationToken cancellationToken)
        {
            Enter("proxy");
            return Proxy;
        }

        /// <summary>Reads controlled RAS observations after recording the boundary.</summary>
        IReadOnlyList<RemoteAccessConnection> IRemoteAccessReader.Read(CancellationToken cancellationToken)
        {
            Enter("ras");
            return ReadConnections(cancellationToken);
        }

        /// <summary>Records a local boundary before executing its controlled behavior.</summary>
        private void Enter(string part) { Reads++; BeforeRead(part); }

        /// <summary>Releases the test-owned generation source.</summary>
        public void Dispose() => Changed.Dispose();
    }
}
