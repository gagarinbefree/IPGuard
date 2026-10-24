using System.Net;
using System.Net.Sockets;
using IPGuard.Application.GeoIp;
using IPGuard.Application.PublicIp;
using IPGuard.Domain;

namespace IPGuard.Application.Network;

/// <summary>Combines generation-bound public addresses and one local database snapshot into domain prerequisites.</summary>
public sealed class NetworkAssessor
{
    private readonly PublicIpCollector collector;
    private readonly INetworkSnapshotProvider network;
    private readonly Func<IGeoIpCountryDatabase> openDatabase;
    private readonly PublicIpPolicy policy;
    private readonly Func<DateTimeOffset> utcNow;

    /// <summary>Composes existing boundaries without referencing HTTP, MMDB, Windows, or the desktop.</summary>
    public NetworkAssessor(IPublicIpProbe probe, INetworkSnapshotProvider network, IEnumerable<PublicIpSource> sources,
        Func<IGeoIpCountryDatabase> openDatabase, PublicIpPolicy policy, Func<DateTimeOffset>? utcNow = null)
    {
        ArgumentNullException.ThrowIfNull(network);
        ArgumentNullException.ThrowIfNull(openDatabase);
        ArgumentNullException.ThrowIfNull(policy);
        this.network = network;
        this.openDatabase = openDatabase;
        this.policy = policy;
        this.utcNow = utcNow ?? (() => DateTimeOffset.UtcNow);
        collector = new PublicIpCollector(probe, network, sources, this.utcNow);
    }

    /// <summary>Discards outdated or inconsistent evidence; caller cancellation propagates and no permit is created.</summary>
    public async Task<NetworkAssessmentResult> AssessAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        PublicIpCollectionResult? collection = null;
        PublicIpSnapshot? source = null;
        GeoIpDatabaseInfo? databaseInfo = null;
        try
        {
            collection = await collector.CollectAsync(cancellationToken).ConfigureAwait(false);
            if (collection.Status != PublicIpCollectionStatus.Completed)
            {
                NetworkAssessmentStatus status = collection.Status switch
                {
                    PublicIpCollectionStatus.NetworkChanged => NetworkAssessmentStatus.NetworkChanged,
                    PublicIpCollectionStatus.InvalidTimestamps => NetworkAssessmentStatus.InvalidTimestamps,
                    _ => NetworkAssessmentStatus.CollectionUnavailable
                };
                return new(status, collection: collection, error: collection.Error);
            }
            source = collection.Snapshot ?? throw new InvalidOperationException("Completed collection has no snapshot.");
            DateTimeOffset lastTime = source.CompletedAt;
            NetworkAssessmentStatus? discarded = Checkpoint(source, ref lastTime, cancellationToken);
            if (discarded.HasValue)
            {
                return new(discarded.Value, collection: collection);
            }

            PublicIpObservation[] ipv4 = Observations(source, AddressFamily.InterNetwork);
            PublicIpObservation[] ipv6 = Observations(source, AddressFamily.InterNetworkV6);
            IPAddress? address4 = AgreedAddress(ipv4, source.Network.Ipv4, AddressFamily.InterNetwork);
            IPAddress? address6 = AgreedAddress(ipv6, source.Network.Ipv6, AddressFamily.InterNetworkV6);
            GeoIpLookupResult? lookup4 = null;
            GeoIpLookupResult? lookup6 = null;
            Exception? databaseError = null;
            if (address4 is not null || address6 is not null)
            {
                IGeoIpCountryDatabase database = openDatabase() ?? throw new InvalidOperationException("The database factory returned null.");
                try
                {
                    GeoIpDatabaseInfo info = database.Info;
                    databaseInfo = info;
                    discarded = Checkpoint(source, ref lastTime, cancellationToken) ?? ValidateMetadata(info, lastTime);
                    if (!discarded.HasValue && address4 is not null)
                    {
                        discarded = ReadCountry(database, info, address4, source, ref lastTime, cancellationToken, out lookup4);
                        databaseError = lookup4?.Error;
                    }
                    if (!discarded.HasValue && address6 is not null)
                    {
                        discarded = ReadCountry(database, info, address6, source, ref lastTime, cancellationToken, out lookup6);
                        databaseError = lookup6?.Error;
                    }
                }
                catch (Exception error)
                {
                    databaseError = error;
                    throw;
                }
                finally
                {
                    try
                    {
                        database.Dispose();
                    }
                    catch (Exception cleanupError)
                    {
                        if (databaseError is not null)
                        {
                            throw new AggregateException("Assessing countries and closing the database failed.", databaseError, cleanupError);
                        }
                        throw;
                    }
                }
            }

            discarded = Checkpoint(source, ref lastTime, cancellationToken) ?? discarded;
            if (!discarded.HasValue && databaseInfo is not null)
            {
                discarded = ValidateMetadata(databaseInfo, lastTime);
            }
            if (discarded.HasValue)
            {
                GeoIpLookupResult? failedLookup = null;
                if (discarded == NetworkAssessmentStatus.GeoIpUnavailable)
                {
                    if (lookup4 is { Status: not GeoIpLookupStatus.Found }) failedLookup = lookup4;
                    else if (lookup6 is { Status: not GeoIpLookupStatus.Found }) failedLookup = lookup6;
                }
                return new(discarded.Value, collection: collection, database: databaseInfo, geoIpFailure: failedLookup, error: databaseError);
            }

            var evidence = new NetworkAssessment(source.Network.Version, source.StartedAt, lastTime,
                new IpFamilyEvidence(source.Network.Ipv4, ipv4, lookup4?.Evidence),
                new IpFamilyEvidence(source.Network.Ipv6, ipv6, lookup6?.Evidence));
            PublicIpDecision decision = policy.Evaluate(evidence, source.Network.Version, lastTime);
            var snapshot = new NetworkAssessmentSnapshot(evidence, decision, source.Network);
            return new(NetworkAssessmentStatus.Completed, snapshot, collection, databaseInfo);
        }
        catch (Exception error)
        {
            cancellationToken.ThrowIfCancellationRequested();
            NetworkAssessmentStatus status = source?.Network.Invalidated.IsCancellationRequested == true
                ? NetworkAssessmentStatus.NetworkChanged : NetworkAssessmentStatus.Failed;
            return new(status, collection: collection, database: databaseInfo, error: error);
        }
    }

    /// <summary>Rechecks the live network and the domain-owned age limit after each local boundary.</summary>
    private NetworkAssessmentStatus? Checkpoint(PublicIpSnapshot source, ref DateTimeOffset lastTime, CancellationToken cancellationToken)
    {
        NetworkSnapshot? current = network.Capture();
        DateTimeOffset now = utcNow();
        cancellationToken.ThrowIfCancellationRequested();
        if (!source.Network.MatchesCurrent(current))
        {
            return NetworkAssessmentStatus.NetworkChanged;
        }
        PublicIpDecisionReason? failure = policy.CheckInterval(source.StartedAt, lastTime, now);
        if (failure == PublicIpDecisionReason.InvalidTimestamps)
        {
            return NetworkAssessmentStatus.InvalidTimestamps;
        }
        if (failure == PublicIpDecisionReason.StaleAssessment)
        {
            return NetworkAssessmentStatus.EvidenceExpired;
        }
        lastTime = now;
        return null;
    }

    /// <summary>Reads one agreed address and validates the adapter contract before forwarding any country evidence.</summary>
    private NetworkAssessmentStatus? ReadCountry(IGeoIpCountryDatabase database, GeoIpDatabaseInfo info, IPAddress address,
        PublicIpSnapshot source, ref DateTimeOffset lastTime, CancellationToken cancellationToken, out GeoIpLookupResult? lookup)
    {
        string requestedAddress = address.ToString();
        lookup = database.Lookup(address, lastTime);
        NetworkAssessmentStatus? discarded = Checkpoint(source, ref lastTime, cancellationToken) ?? ValidateMetadata(info, lastTime);
        if (discarded.HasValue)
        {
            return discarded;
        }
        if (!SameDatabase(info, database.Info) || lookup is null || !Enum.IsDefined(lookup.Status)
            || lookup.Evidence is not { } evidence || evidence.Address != requestedAddress
            || evidence.DatabaseValidUntil != info.ValidUntil
            || (lookup.Status == GeoIpLookupStatus.Found && (evidence.CountryCode is null || lookup.Error is not null))
            || (lookup.Status != GeoIpLookupStatus.Found && evidence.CountryCode is not null))
        {
            return NetworkAssessmentStatus.InvalidGeoIpResult;
        }
        return lookup.Status == GeoIpLookupStatus.Found ? null : NetworkAssessmentStatus.GeoIpUnavailable;
    }

    /// <summary>Checks snapshot metadata and its build-based freshness without assuming an allowed country.</summary>
    private static NetworkAssessmentStatus? ValidateMetadata(GeoIpDatabaseInfo? info, DateTimeOffset now)
    {
        if (info is null || string.IsNullOrWhiteSpace(info.DatabaseType) || info.ValidUntil <= info.BuiltAt
            || info.Sha256 is not { Length: 64 } || !info.Sha256.All(char.IsAsciiHexDigit))
        {
            return NetworkAssessmentStatus.InvalidGeoIpResult;
        }
        return info.BuiltAt > now || info.ValidUntil <= now ? NetworkAssessmentStatus.GeoIpUnavailable : null;
    }

    /// <summary>Requires all lookups to describe the same immutable database identity and validity interval.</summary>
    private static bool SameDatabase(GeoIpDatabaseInfo expected, GeoIpDatabaseInfo? actual) => actual is not null
        && expected.DatabaseType == actual.DatabaseType && expected.BuiltAt == actual.BuiltAt && expected.ValidUntil == actual.ValidUntil
        && expected.Sha256.Equals(actual.Sha256, StringComparison.OrdinalIgnoreCase);

    /// <summary>Preserves all source observations for one family, including failed and conflicting replies.</summary>
    private static PublicIpObservation[] Observations(PublicIpSnapshot source, AddressFamily family) => source.Attempts
        .Where(attempt => attempt.Source.Family == family).Select(attempt => attempt.Observation).ToArray();

    /// <summary>Uses the shared domain consensus rule before selecting an address for local lookup.</summary>
    private static IPAddress? AgreedAddress(IReadOnlyList<PublicIpObservation> observations, IpFamilyAvailability availability,
        AddressFamily family) => availability == IpFamilyAvailability.Available && PublicIpConsensus.Check(observations, family) is null
            ? IPAddress.Parse(observations[0].Address!) : null;
}
