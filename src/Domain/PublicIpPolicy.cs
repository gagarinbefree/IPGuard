using System.Net;
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

        if (assessment.StartedAt > assessment.CompletedAt || assessment.CompletedAt > now)
        {
            return new(PublicIpDecisionReason.InvalidTimestamps);
        }

        if (now - assessment.StartedAt >= maximumEvidenceAge)
        {
            return new(PublicIpDecisionReason.StaleAssessment);
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

        PublicIpDecisionReason? sourceFailure = CheckSources(evidence.Observations, family);
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

    /// <summary>Requires every configured reply to succeed and agree, with at least two independent operators.</summary>
    private static PublicIpDecisionReason? CheckSources(IReadOnlyList<PublicIpObservation> observations, AddressFamily family)
    {
        var operators = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        string? agreedAddress = null;
        foreach (PublicIpObservation observation in observations)
        {
            if (string.IsNullOrWhiteSpace(observation.OperatorId))
            {
                return PublicIpDecisionReason.InvalidSource;
            }

            if (observation.Address is null)
            {
                return PublicIpDecisionReason.SourceFailed;
            }

            IPAddress address = IPAddress.Parse(observation.Address);
            if (address.AddressFamily != family || address.IsIPv4MappedToIPv6
                || (family == AddressFamily.InterNetworkV6 && address.ScopeId != 0))
            {
                return PublicIpDecisionReason.AddressFamilyMismatch;
            }

            if (agreedAddress is not null && agreedAddress != observation.Address)
            {
                return PublicIpDecisionReason.ConflictingAddresses;
            }

            agreedAddress = observation.Address;
            operators.Add(observation.OperatorId.Trim());
        }

        return operators.Count < 2 ? PublicIpDecisionReason.InsufficientSources : null;
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
