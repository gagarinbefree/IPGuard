using System.Net.Sockets;

namespace IPGuard.Infrastructure.PublicIp;

/// <summary>Defines a trusted operator identity and one HTTPS plaintext endpoint for one IP family.</summary>
public sealed class PublicIpSource
{
    /// <summary>Rejects credentials, fragments, insecure URLs, missing operators, and unsupported families.</summary>
    public PublicIpSource(string operatorId, Uri endpoint, AddressFamily family)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(operatorId);
        ArgumentNullException.ThrowIfNull(endpoint);
        if (!endpoint.IsAbsoluteUri || endpoint.Scheme != Uri.UriSchemeHttps
            || string.IsNullOrEmpty(endpoint.Host) || endpoint.UserInfo.Length != 0 || endpoint.Fragment.Length != 0)
        {
            throw new ArgumentException("A source must use an absolute HTTPS URL without credentials or a fragment.", nameof(endpoint));
        }

        if (family is not (AddressFamily.InterNetwork or AddressFamily.InterNetworkV6))
        {
            throw new ArgumentOutOfRangeException(nameof(family));
        }

        OperatorId = operatorId.Trim();
        Endpoint = endpoint;
        Family = family;
    }

    /// <summary>Gets the configured operator; response bodies cannot redefine independence.</summary>
    public string OperatorId { get; }

    /// <summary>Gets the exact HTTPS endpoint, without automatic redirect substitution.</summary>
    public Uri Endpoint { get; }

    /// <summary>Gets the mandatory connection and response address family.</summary>
    public AddressFamily Family { get; }
}
