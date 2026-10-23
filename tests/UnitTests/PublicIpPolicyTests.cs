using System.Net;
using System.Net.Sockets;
using IPGuard.Domain;
using Xunit;

namespace UnitTests;

/// <summary>Checks deterministic address prerequisites without network, operating system, or filter access.</summary>
public sealed class PublicIpPolicyTests
{
    private static readonly Guid NetworkVersion = Guid.Parse("0db91b35-cf08-4a34-890a-18d456954694");
    private static readonly DateTimeOffset Now = new(2026, 10, 23, 12, 0, 0, TimeSpan.Zero);
    private static readonly TimeSpan MaximumAge = TimeSpan.FromMinutes(5);

    /// <summary>Agreement for both families produces eligibility, without an Allow result or side effects.</summary>
    [Fact]
    public void Evaluate_ConsistentUsAddresses_RequiresSeparateRouteValidation()
    {
        PublicIpDecision decision = Evaluate(ValidAssessment());

        Assert.True(decision.IsEligible);
        Assert.Equal(PublicIpDecisionReason.EligibleForRouteValidation, decision.Reason);
        Assert.Null(decision.Family);
    }

    /// <summary>Missing evidence never satisfies the address prerequisites.</summary>
    [Fact]
    public void Evaluate_NoAssessment_IsIneligible()
    {
        AssertDecision(PublicIpDecisionReason.NoAssessment, Evaluate(null));
    }

    /// <summary>VPN or interface changes invalidate results even when the replies themselves still agree.</summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Evaluate_ChangedOrMissingNetworkGeneration_IsIneligible(bool missing)
    {
        Guid current = missing ? Guid.Empty : Guid.NewGuid();
        var policy = new PublicIpPolicy(MaximumAge);

        AssertDecision(PublicIpDecisionReason.NetworkChanged, policy.Evaluate(ValidAssessment(), current, Now));
    }

    /// <summary>A check without its original generation cannot be reused after reconnect.</summary>
    [Fact]
    public void Evaluate_MissingAssessmentGeneration_IsIneligible()
    {
        var assessment = Assessment(ValidFamily(), UnavailableFamily(), generation: Guid.Empty);

        AssertDecision(PublicIpDecisionReason.NetworkChanged, Evaluate(assessment));
    }

    /// <summary>Both an inverted interval and a completion time in the future fail closed.</summary>
    [Theory]
    [InlineData(1, 0)]
    [InlineData(-1, 1)]
    [InlineData(2, 3)]
    public void Evaluate_InvalidInterval_IsIneligible(int startSeconds, int endSeconds)
    {
        var assessment = Assessment(ValidFamily(), UnavailableFamily(),
            start: Now.AddSeconds(startSeconds), end: Now.AddSeconds(endSeconds));

        AssertDecision(PublicIpDecisionReason.InvalidTimestamps, Evaluate(assessment));
    }

    /// <summary>The earliest collected evidence, rather than completion, sets the exclusive expiry boundary.</summary>
    [Theory]
    [InlineData(-1, true)]
    [InlineData(0, false)]
    [InlineData(1, false)]
    public void Evaluate_EvidenceAge_UsesExclusiveDeadline(int ticksAfterDeadline, bool eligible)
    {
        var assessment = Assessment(ValidFamily(), UnavailableFamily(),
            start: Now.Subtract(MaximumAge).AddTicks(-ticksAfterDeadline), end: Now);

        PublicIpDecision decision = Evaluate(assessment);

        Assert.Equal(eligible, decision.IsEligible);
        Assert.Equal(eligible ? PublicIpDecisionReason.EligibleForRouteValidation : PublicIpDecisionReason.StaleAssessment, decision.Reason);
    }

    /// <summary>A missing, unknown, or unrecognized family cannot silently bypass IPv6 checks.</summary>
    [Theory]
    [InlineData(-1)]
    [InlineData(0)]
    [InlineData(99)]
    public void Evaluate_UnassessedIpv6_IsIneligible(int state)
    {
        IpFamilyEvidence? ipv6 = state == -1 ? null : new((IpFamilyAvailability)state, []);

        AssertDecision(PublicIpDecisionReason.UnknownAddressFamily,
            Evaluate(Assessment(ValidFamily(), ipv6)), AddressFamily.InterNetworkV6);
    }

    /// <summary>A confirmed absence is acceptable only as an input prerequisite, never as route proof.</summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Evaluate_OneUnavailableFamily_CanBeEligible(bool ipv6Only)
    {
        var assessment = ipv6Only
            ? Assessment(UnavailableFamily(), ValidFamily("2606:4700:4700::1111"))
            : Assessment(ValidFamily(), UnavailableFamily());

        Assert.True(Evaluate(assessment).IsEligible);
    }

    /// <summary>A fully disconnected network has no eligible external address.</summary>
    [Fact]
    public void Evaluate_BothFamiliesUnavailable_IsIneligible()
    {
        AssertDecision(PublicIpDecisionReason.NoAvailableAddressFamily,
            Evaluate(Assessment(UnavailableFamily(), UnavailableFamily())));
    }

    /// <summary>Availability cannot contradict attached successful replies or a country lookup.</summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Evaluate_UnavailableFamilyWithEvidence_IsIneligible(bool lookupOnly)
    {
        var family = new IpFamilyEvidence(IpFamilyAvailability.Unavailable,
            lookupOnly ? [] : [Reply("operator-a")], lookupOnly ? Lookup() : null);

        AssertDecision(PublicIpDecisionReason.ConflictingFamilyEvidence,
            Evaluate(Assessment(family, UnavailableFamily())), AddressFamily.InterNetwork);
    }

    /// <summary>A single provider, including multiple endpoint names differing only in case, is insufficient.</summary>
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    public void Evaluate_FewerThanTwoIndependentOperators_IsIneligible(int count)
    {
        PublicIpObservation[] observations = count switch
        {
            0 => [],
            1 => [Reply("operator-a")],
            _ => [Reply("Operator-A"), Reply(" operator-a ")]
        };

        AssertFamilyDecision(PublicIpDecisionReason.InsufficientSources, observations);
    }

    /// <summary>An absent source identity cannot count toward independent agreement.</summary>
    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    public void Evaluate_MissingOperatorIdentity_IsIneligible(string operatorId)
    {
        AssertFamilyDecision(PublicIpDecisionReason.InvalidSource, [Reply("operator-a"), Reply(operatorId)]);
    }

    /// <summary>A failed DNS, HTTPS, timeout, or response validation request cannot be hidden by a successful quorum.</summary>
    [Fact]
    public void Evaluate_OneFailedSourceAmongSuccessfulSources_IsIneligible()
    {
        AssertFamilyDecision(PublicIpDecisionReason.SourceFailed,
            [Reply("operator-a"), Reply("operator-b"), new PublicIpObservation("operator-c", null)]);
    }

    /// <summary>Any conflicting response, including a duplicate operator, invalidates consensus.</summary>
    [Theory]
    [InlineData("operator-a")]
    [InlineData("operator-c")]
    public void Evaluate_AnyAddressDisagreement_IsIneligible(string conflictingOperator)
    {
        AssertFamilyDecision(PublicIpDecisionReason.ConflictingAddresses,
            [Reply("operator-a"), Reply("operator-b"), Reply(conflictingOperator, "8.8.8.8")]);
    }

    /// <summary>Wrong-family and mapped replies cannot be used as IPv4 consensus.</summary>
    [Theory]
    [InlineData("2606:4700:4700::1111")]
    [InlineData("::ffff:1.1.1.1")]
    public void Evaluate_WrongAddressFamily_IsIneligible(string address)
    {
        AssertFamilyDecision(PublicIpDecisionReason.AddressFamilyMismatch,
            [Reply("operator-a", address), Reply("operator-b", address)]);
    }

    /// <summary>Zone-scoped IPv6 evidence cannot identify a public external address.</summary>
    [Fact]
    public void Evaluate_ScopedIpv6_IsIneligible()
    {
        AssertDecision(PublicIpDecisionReason.AddressFamilyMismatch,
            Evaluate(Assessment(ValidFamily(), ValidFamily("2606:4700:4700::1111%3"))), AddressFamily.InterNetworkV6);
    }

    /// <summary>A missing or unusable local database result cannot produce eligibility.</summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Evaluate_MissingGeoIpOrDatabaseDeadline_IsIneligible(bool missingDeadline)
    {
        var family = new IpFamilyEvidence(IpFamilyAvailability.Available,
            [Reply("operator-a"), Reply("operator-b")],
            missingDeadline ? new GeoIpEvidence(IPAddress.Parse("1.1.1.1"), "US", null) : null);

        AssertDecision(PublicIpDecisionReason.GeoIpUnavailable,
            Evaluate(Assessment(family, UnavailableFamily())), AddressFamily.InterNetwork);
    }

    /// <summary>A successful old lookup cannot be reused after the public address changes.</summary>
    [Fact]
    public void Evaluate_GeoIpForAnotherAddress_IsIneligible()
    {
        var family = new IpFamilyEvidence(IpFamilyAvailability.Available,
            [Reply("operator-a", "8.8.8.8"), Reply("operator-b", "8.8.8.8")], Lookup());

        AssertDecision(PublicIpDecisionReason.GeoIpAddressMismatch,
            Evaluate(Assessment(family, UnavailableFamily())), AddressFamily.InterNetwork);
    }

    /// <summary>Country evidence expires at its database deadline, independently of the request age.</summary>
    [Theory]
    [InlineData(-1)]
    [InlineData(0)]
    public void Evaluate_ExpiredDatabase_IsIneligible(int ticksUntilExpiry)
    {
        var family = new IpFamilyEvidence(IpFamilyAvailability.Available,
            [Reply("operator-a"), Reply("operator-b")],
            new GeoIpEvidence(IPAddress.Parse("1.1.1.1"), "US", Now.AddTicks(ticksUntilExpiry)));

        AssertDecision(PublicIpDecisionReason.GeoIpDatabaseExpired,
            Evaluate(Assessment(family, UnavailableFamily())), AddressFamily.InterNetwork);
    }

    /// <summary>Unknown or malformed country results are distinct from a valid but disallowed country.</summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("USA")]
    [InlineData("U1")]
    [InlineData("ÜS")]
    [InlineData("Uſ")]
    public void Evaluate_UnknownCountry_IsIneligible(string? country)
    {
        AssertDecision(PublicIpDecisionReason.UnknownCountry,
            Evaluate(Assessment(ValidFamily(country: country), UnavailableFamily())), AddressFamily.InterNetwork);
    }

    /// <summary>IPv6 cannot escape country checks when IPv4 is already in the allowed country.</summary>
    [Theory]
    [InlineData("CA", PublicIpDecisionReason.CountryNotAllowed)]
    [InlineData(null, PublicIpDecisionReason.UnknownCountry)]
    public void Evaluate_Ipv4UsButIpv6NotAllowed_IsIneligible(string? ipv6Country, PublicIpDecisionReason reason)
    {
        AssertDecision(reason,
            Evaluate(Assessment(ValidFamily(), ValidFamily("2606:4700:4700::1111", ipv6Country))), AddressFamily.InterNetworkV6);
    }

    /// <summary>The default allowlist contains only US and handles ASCII casing consistently.</summary>
    [Theory]
    [InlineData("US", true)]
    [InlineData(" us ", true)]
    [InlineData("CA", false)]
    [InlineData("DE", false)]
    public void Evaluate_DefaultCountryPolicy_IsUsOnly(string country, bool eligible)
    {
        PublicIpDecision decision = Evaluate(Assessment(ValidFamily(country: country), UnavailableFamily()));

        Assert.Equal(eligible, decision.IsEligible);
        Assert.Equal(eligible ? PublicIpDecisionReason.EligibleForRouteValidation : PublicIpDecisionReason.CountryNotAllowed, decision.Reason);
    }

    /// <summary>Explicit countries replace the default and configuration edits cannot mutate an existing policy.</summary>
    [Fact]
    public void Evaluate_CustomAllowlist_IsCopiedAndReplacesDefault()
    {
        string[] countries = [" ca ", "CA"];
        var policy = new PublicIpPolicy(MaximumAge, countries);
        countries[0] = "US";
        countries[1] = "US";

        Assert.True(policy.Evaluate(Assessment(ValidFamily(country: "CA"), UnavailableFamily()), NetworkVersion, Now).IsEligible);
        AssertDecision(PublicIpDecisionReason.CountryNotAllowed, policy.Evaluate(ValidAssessment(), NetworkVersion, Now), AddressFamily.InterNetwork);
    }

    /// <summary>An explicitly empty allowlist denies every known country.</summary>
    [Fact]
    public void Evaluate_EmptyAllowlist_IsIneligible()
    {
        var policy = new PublicIpPolicy(MaximumAge, []);

        AssertDecision(PublicIpDecisionReason.CountryNotAllowed, policy.Evaluate(ValidAssessment(), NetworkVersion, Now), AddressFamily.InterNetwork);
    }

    /// <summary>A nonpositive lifetime would make freshness meaningless and is rejected at configuration time.</summary>
    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void Constructor_RejectsNonpositiveAge(int seconds)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new PublicIpPolicy(TimeSpan.FromSeconds(seconds)));
    }

    /// <summary>Malformed configured country codes fail during configuration, before policy evaluation.</summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("USA")]
    [InlineData("U1")]
    [InlineData("Uſ")]
    public void Constructor_RejectsMalformedCountry(string? country)
    {
        Assert.Throws<ArgumentException>(() => new PublicIpPolicy(MaximumAge, [country!]));
    }

    /// <summary>Source lists and mutable IPAddress instances cannot change previously captured evidence.</summary>
    [Fact]
    public void Evidence_CopiesMutableInputs()
    {
        var address = IPAddress.Parse("2606:4700:4700::1111");
        var observation = new PublicIpObservation("operator-a", address);
        var geoIp = new GeoIpEvidence(address, "US", Now.AddDays(1));
        var sources = new List<PublicIpObservation> { observation, Reply("operator-b", address.ToString()) };
        var family = new IpFamilyEvidence(IpFamilyAvailability.Available, sources, geoIp);
        sources.Clear();
        address.ScopeId = 7;

        Assert.Equal(2, family.Observations.Count);
        Assert.Equal("2606:4700:4700::1111", observation.Address);
        Assert.Equal(observation.Address, geoIp.Address);
        Assert.True(Evaluate(Assessment(UnavailableFamily(), family)).IsEligible);
    }

    /// <summary>Evaluates at a fixed time and generation with the default country configuration.</summary>
    private static PublicIpDecision Evaluate(NetworkAssessment? assessment) =>
        new PublicIpPolicy(MaximumAge).Evaluate(assessment, NetworkVersion, Now);

    /// <summary>Checks the reason, ineligibility, and failing family through the public result.</summary>
    private static void AssertDecision(PublicIpDecisionReason reason, PublicIpDecision decision, AddressFamily? family = null)
    {
        Assert.False(decision.IsEligible);
        Assert.Equal(reason, decision.Reason);
        Assert.Equal(family, decision.Family);
    }

    /// <summary>Checks a source-list failure for an otherwise valid IPv4 assessment.</summary>
    private static void AssertFamilyDecision(PublicIpDecisionReason reason, PublicIpObservation[] observations)
    {
        var family = new IpFamilyEvidence(IpFamilyAvailability.Available, observations, Lookup());
        AssertDecision(reason, Evaluate(Assessment(family, UnavailableFamily())), AddressFamily.InterNetwork);
    }

    /// <summary>Builds a fresh two-family US assessment.</summary>
    private static NetworkAssessment ValidAssessment() => Assessment(ValidFamily(), ValidFamily("2606:4700:4700::1111"));

    /// <summary>Builds a check interval while preserving explicit missing-family evidence.</summary>
    private static NetworkAssessment Assessment(IpFamilyEvidence? ipv4, IpFamilyEvidence? ipv6,
        Guid? generation = null, DateTimeOffset? start = null, DateTimeOffset? end = null) =>
        new(generation ?? NetworkVersion, start ?? Now.AddSeconds(-2), end ?? Now.AddSeconds(-1), ipv4, ipv6);

    /// <summary>Builds independent agreeing replies and a bound local lookup.</summary>
    private static IpFamilyEvidence ValidFamily(string address = "1.1.1.1", string? country = "US") =>
        new(IpFamilyAvailability.Available, [Reply("operator-a", address), Reply("operator-b", address)], Lookup(address, country));

    /// <summary>Represents an explicitly assessed family without a usable path.</summary>
    private static IpFamilyEvidence UnavailableFamily() => new(IpFamilyAvailability.Unavailable, []);

    /// <summary>Builds one successful normalized reply.</summary>
    private static PublicIpObservation Reply(string operatorId, string address = "1.1.1.1") =>
        new(operatorId, IPAddress.Parse(address));

    /// <summary>Builds a database result with a future database deadline.</summary>
    private static GeoIpEvidence Lookup(string address = "1.1.1.1", string? country = "US") =>
        new(IPAddress.Parse(address), country, Now.AddDays(1));
}
