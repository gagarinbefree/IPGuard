using System.Net;
using System.Net.Sockets;

namespace IPGuard.Domain;

/// <summary>Owns source agreement rules shared by country lookup selection and final address policy.</summary>
public static class PublicIpConsensus
{
    /// <summary>Requires every reply to succeed and agree, with at least two independent configured operators.</summary>
    /// <remarks>Adapters remain responsible for validating public address ranges and including every configured attempt.</remarks>
    public static PublicIpDecisionReason? Check(IReadOnlyList<PublicIpObservation> observations, AddressFamily family)
    {
        ArgumentNullException.ThrowIfNull(observations);
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
}
