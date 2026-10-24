using IPGuard.Domain;

namespace IPGuard.Application.Network;

/// <summary>Binds address-family availability to one network generation and its permanent invalidation signal.</summary>
/// <remarks>Availability is input for probe selection, not proof that all PowerShell traffic uses a verified exit.</remarks>
public sealed class NetworkSnapshot
{
    /// <summary>Captures atomic monitor output; unknown values remain representable and fail closed during collection.</summary>
    public NetworkSnapshot(Guid version, IpFamilyAvailability ipv4, IpFamilyAvailability ipv6, CancellationToken invalidated)
    {
        Version = version;
        Ipv4 = ipv4;
        Ipv6 = ipv6;
        Invalidated = invalidated;
    }

    /// <summary>Gets the generation identifier, which must never be reused after a network change.</summary>
    public Guid Version { get; }

    /// <summary>Gets IPv4 availability; failed HTTPS probes cannot establish unavailability.</summary>
    public IpFamilyAvailability Ipv4 { get; }

    /// <summary>Gets IPv6 availability; unknown differs from an explicitly unavailable family.</summary>
    public IpFamilyAvailability Ipv6 { get; }

    /// <summary>Gets the stable token that remains cancelled after this generation becomes obsolete.</summary>
    public CancellationToken Invalidated { get; }

    /// <summary>Compares captured state and its permanent latch with a newly captured generation.</summary>
    internal bool MatchesCurrent(NetworkSnapshot? current) => current is not null
        && Version == current.Version && Ipv4 == current.Ipv4 && Ipv6 == current.Ipv6
        && Invalidated == current.Invalidated && !Invalidated.IsCancellationRequested && !current.Invalidated.IsCancellationRequested;
}
