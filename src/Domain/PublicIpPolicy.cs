using System.Net.Sockets;

namespace IPGuard.Domain;

/// <summary>Evaluates address prerequisites without performing I/O or granting network access.</summary>
public sealed class PublicIpPolicy
{
    private readonly TimeSpan maximumEvidenceAge;
    private readonly HashSet<string> allowedCountries;

    /// <summary>Configures an exclusive evidence age limit and a country allowlist, defaulting to US only.</summary>
    public PublicIpPolicy(TimeSpan maximumEvidenceAge, IEnumerable<string>? allowedCountries = null)
    {
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(maximumEvidenceAge, TimeSpan.Zero);
        this.maximumEvidenceAge = maximumEvidenceAge;
        this.allowedCountries = new HashSet<string>(StringComparer.Ordinal);
        foreach (string country in allowedCountries ?? ["US"])
        {
            string? normalized = NormalizeCountry(country);
            if (normalized is null)
            {
                throw new ArgumentException("Country codes must contain two ASCII letters.", nameof(allowedCountries));
            }

            this.allowedCountries.Add(normalized);
        }
    }

    /// <summary>Gets the exclusive evidence age limit shared by collection and background expiry.</summary>
    public TimeSpan MaximumEvidenceAge => maximumEvidenceAge;

    /// <summary>Evaluates one immutable assessment against the current network generation and explicit clock.</summary>
    public PublicIpDecision Evaluate(NetworkAssessment? assessment, Guid currentNetworkVersion, DateTimeOffset now)
    {
        if (assessment is null)
        {
            return new(PublicIpDecisionReason.NoAssessment);
        }

        if (currentNetworkVersion == Guid.Empty || assessment.NetworkVersion != currentNetworkVersion)
        {
            return new(PublicIpDecisionReason.NetworkChanged);
        }

        PublicIpDecisionReason? intervalFailure = CheckInterval(assessment.StartedAt, assessment.CompletedAt, now);
        if (intervalFailure.HasValue)
        {
            return new(intervalFailure.Value);
        }

        PublicIpDecision? failure = EvaluateFamily(assessment.Ipv4, AddressFamily.InterNetwork, now)
            ?? EvaluateFamily(assessment.Ipv6, AddressFamily.InterNetworkV6, now);
        if (failure is not null)
        {
            return failure;
        }

        if (assessment.Ipv4?.Availability == IpFamilyAvailability.Unavailable
            && assessment.Ipv6?.Availability == IpFamilyAvailability.Unavailable)
        {
            return new(PublicIpDecisionReason.NoAvailableAddressFamily);
        }

        return new(PublicIpDecisionReason.EligibleForRouteValidation);
    }

    /// <summary>Checks an interval's order and exclusive age limit without needing country or source data.</summary>
    public PublicIpDecisionReason? CheckInterval(DateTimeOffset startedAt, DateTimeOffset completedAt, DateTimeOffset now)
    {
        if (startedAt > completedAt || completedAt > now)
        {
            return PublicIpDecisionReason.InvalidTimestamps;
        }
        return now - startedAt >= maximumEvidenceAge ? PublicIpDecisionReason.StaleAssessment : null;
    }

    /// <summary>Checks availability, independent agreement, and the address-bound country for one family.</summary>
    private PublicIpDecision? EvaluateFamily(IpFamilyEvidence? evidence, AddressFamily family, DateTimeOffset now)
    {
        if (evidence is null)
        {
            return new(PublicIpDecisionReason.UnknownAddressFamily, family);
        }

        if (evidence.Availability == IpFamilyAvailability.Unavailable)
        {
            return evidence.Observations.Count == 0 && evidence.GeoIp is null
                ? null
                : new(PublicIpDecisionReason.ConflictingFamilyEvidence, family);
        }

        if (evidence.Availability != IpFamilyAvailability.Available)
        {
            return new(PublicIpDecisionReason.UnknownAddressFamily, family);
        }

        PublicIpDecisionReason? sourceFailure = PublicIpConsensus.Check(evidence.Observations, family);
        if (sourceFailure.HasValue)
        {
            return new(sourceFailure.Value, family);
        }

        GeoIpEvidence? geoIp = evidence.GeoIp;
        if (geoIp?.DatabaseValidUntil is null)
        {
            return new(PublicIpDecisionReason.GeoIpUnavailable, family);
        }

        if (geoIp.Address != evidence.Observations[0].Address)
        {
            return new(PublicIpDecisionReason.GeoIpAddressMismatch, family);
        }

        if (geoIp.DatabaseValidUntil <= now)
        {
            return new(PublicIpDecisionReason.GeoIpDatabaseExpired, family);
        }

        string? country = NormalizeCountry(geoIp.CountryCode);
        if (country is null)
        {
            return new(PublicIpDecisionReason.UnknownCountry, family);
        }

        return allowedCountries.Contains(country) ? null : new(PublicIpDecisionReason.CountryNotAllowed, family);
    }

    /// <summary>Normalizes the supported code shape without treating malformed lookups as a country.</summary>
    private static string? NormalizeCountry(string? country)
    {
        string? normalized = country?.Trim();
        return normalized is { Length: 2 } && char.IsAsciiLetter(normalized[0]) && char.IsAsciiLetter(normalized[1])
            ? normalized.ToUpperInvariant()
            : null;
    }
}
