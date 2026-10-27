using System.Net;
using System.Net.Sockets;
using IPGuard.Application.GeoIp;
using IPGuard.Application.Network;
using IPGuard.Application.PublicIp;
using IPGuard.Domain;

namespace UnitTests;

/// <summary>Composes real application collectors with controlled source, database, and local-reader boundaries.</summary>
internal sealed class NetworkCheckSetup : INetworkSnapshotProvider, IRoutingTableReader, IProxySettingsReader, IRemoteAccessReader,
    IPublicIpProbe, IDisposable
{
    internal static readonly DateTimeOffset Start = new(2026, 10, 27, 8, 0, 0, TimeSpan.Zero);

    /// <summary>Creates a live generation and four agreeing per-family source observations.</summary>
    internal NetworkCheckSetup()
    {
        Current = new(Guid.NewGuid(), IpFamilyAvailability.Available, IpFamilyAvailability.Available, Changed.Token);
        Reply = source => new(source, PublicIpReadStatus.Success,
            IPAddress.Parse(source.Family == AddressFamily.InterNetwork ? Ipv4 : Ipv6));
    }

    /// <summary>Gets the generation's permanent invalidation signal.</summary>
    internal CancellationTokenSource Changed { get; } = new();

    /// <summary>Gets or sets cached network state.</summary>
    internal NetworkSnapshot? Current { get; set; }

    /// <summary>Gets or sets controlled UTC time.</summary>
    internal DateTimeOffset Now { get; set; } = Start;

    /// <summary>Gets or sets the agreed public IPv4 address without changing local generation.</summary>
    internal string Ipv4 { get; set; } = "149.101.100.1";

    /// <summary>Gets or sets the agreed public IPv6 address without changing local generation.</summary>
    internal string Ipv6 { get; set; } = "2001:218::1";

    /// <summary>Gets or sets country evidence returned for either family.</summary>
    internal string Country { get; set; } = "US";

    /// <summary>Gets or sets the local database's exclusive freshness deadline.</summary>
    internal DateTimeOffset DatabaseDeadline { get; set; } = Start.AddDays(30);

    /// <summary>Gets or sets the database lookup outcome.</summary>
    internal GeoIpLookupStatus LookupStatus { get; set; } = GeoIpLookupStatus.Found;

    /// <summary>Gets or sets behavior at local reads and database open, lookup, and cleanup boundaries.</summary>
    internal Action<string> Boundary { get; set; } = _ => { };

    /// <summary>Gets or sets asynchronous source behavior, including deliberately uncooperative replies.</summary>
    internal Func<CancellationToken, Task> BeforeProbe { get; set; } = _ => Task.CompletedTask;

    /// <summary>Gets or sets each configured source's reply.</summary>
    internal Func<PublicIpSource, PublicIpReadResult> Reply { get; set; }

    /// <summary>Gets the number of public source batches started.</summary>
    internal int ProbeCalls => Volatile.Read(ref probeCalls);

    /// <summary>Gets the number of private database snapshots closed.</summary>
    internal int Disposals => Volatile.Read(ref disposals);

    private int probeCalls;
    private int disposals;

    /// <summary>Creates both child collectors and the outer scenario with one clock and a ten-second policy.</summary>
    internal NetworkCheckCollector Collector(Func<DateTimeOffset>? clock = null, IEnumerable<string>? allowedCountries = null)
    {
        Func<DateTimeOffset> utcNow = clock ?? (() => Now);
        var policy = new PublicIpPolicy(TimeSpan.FromSeconds(10), allowedCountries);
        var local = new NetworkDiagnosticsCollector(this, this, this, this, policy.MaximumEvidenceAge, utcNow);
        var assessor = new NetworkAssessor(this, this, Sources(), () => { Boundary("open"); return new Database(this); }, policy, utcNow);
        return new(local, assessor, this, policy, utcNow);
    }

    /// <summary>Defines independent configured operators for both address families.</summary>
    private static PublicIpSource[] Sources() => [Source("one", AddressFamily.InterNetwork), Source("two", AddressFamily.InterNetwork),
        Source("one", AddressFamily.InterNetworkV6), Source("two", AddressFamily.InterNetworkV6)];

    /// <summary>Creates a synthetic HTTPS endpoint which is never contacted.</summary>
    private static PublicIpSource Source(string name, AddressFamily family) => new(name,
        new Uri($"https://{name}-{family}.example/"), family);

    /// <summary>Returns cached state without I/O.</summary>
    public NetworkSnapshot? Capture() => Current;

    /// <summary>Returns one controlled route after the local boundary hook.</summary>
    IReadOnlyList<NetworkRoute> IRoutingTableReader.Read(CancellationToken cancellationToken)
    {
        Boundary("routes");
        return [RouteDiagnosticsCollectorTests.Route()];
    }

    /// <summary>Returns configured proxy flags without interpreting them as traffic coverage.</summary>
    ProxySettings IProxySettingsReader.Read(CancellationToken cancellationToken)
    {
        Boundary("proxy");
        return new(false, false, false, false, false, false, false, false);
    }

    /// <summary>Returns an empty RAS observation without asserting that no VPN exists.</summary>
    IReadOnlyList<RemoteAccessConnection> IRemoteAccessReader.Read(CancellationToken cancellationToken)
    {
        Boundary("ras");
        return [];
    }

    /// <summary>Returns controlled source attempts without DNS or HTTP.</summary>
    public async Task<IReadOnlyList<PublicIpReadResult>> ReadAllAsync(IEnumerable<PublicIpSource> sources, CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref probeCalls);
        await BeforeProbe(cancellationToken);
        return sources.Select(Reply).ToArray();
    }

    /// <summary>Releases the test-owned invalidation source.</summary>
    public void Dispose() => Changed.Dispose();

    /// <summary>Represents a newly owned database snapshot for exactly one assessment.</summary>
    private sealed class Database : IGeoIpCountryDatabase
    {
        private readonly NetworkCheckSetup setup;

        /// <summary>Captures immutable metadata at opening rather than sharing a mutable database across attempts.</summary>
        internal Database(NetworkCheckSetup setup)
        {
            this.setup = setup;
            Info = new("GeoIP2-Country", Start.AddDays(-1), setup.DatabaseDeadline, new string('A', 64));
        }

        /// <summary>Gets the immutable identity of this snapshot.</summary>
        public GeoIpDatabaseInfo Info { get; }

        /// <summary>Returns address-bound country evidence or a controlled unavailable result.</summary>
        public GeoIpLookupResult Lookup(IPAddress address, DateTimeOffset now)
        {
            setup.Boundary("lookup");
            return new(setup.LookupStatus, new GeoIpEvidence(address,
                setup.LookupStatus == GeoIpLookupStatus.Found ? setup.Country : null, Info.ValidUntil));
        }

        /// <summary>Records cleanup before its controlled callback.</summary>
        public void Dispose()
        {
            Interlocked.Increment(ref setup.disposals);
            setup.Boundary("close");
        }
    }
}
