using System.Net;

namespace IPGuard.Domain;

/// <summary>Captures one validated HTTPS source reply or a failed request.</summary>
/// <remarks>
/// The adapter must validate TLS, response format, and global routability before supplying an address.
/// Operator identity comes from trusted source configuration, never from a response body.
/// </remarks>
public sealed class PublicIpObservation
{
    /// <summary>Captures the independent source operator and an address; null denotes any request failure.</summary>
    public PublicIpObservation(string operatorId, IPAddress? address)
    {
        OperatorId = operatorId;
        Address = address?.ToString();
    }

    /// <summary>Gets the configured operator identity; different URLs from one operator are not independent.</summary>
    public string OperatorId { get; }

    /// <summary>Gets the immutable canonical address, or null when the request did not produce a usable reply.</summary>
    public string? Address { get; }
}
