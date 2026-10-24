using System.Net;
using IPGuard.Domain;

namespace IPGuard.Infrastructure.PublicIp;

/// <summary>Distinguishes successful observations from bounded operational failures.</summary>
public enum PublicIpReadStatus
{
    /// <summary>A valid candidate public unicast address was received.</summary>
    Success,
    /// <summary>The complete request and body deadline expired.</summary>
    TimedOut,
    /// <summary>The source hostname could not be resolved.</summary>
    NameResolutionFailed,
    /// <summary>The TLS handshake, certificate, or hostname check failed.</summary>
    TlsFailed,
    /// <summary>The connection or response stream failed.</summary>
    TransportFailed,
    /// <summary>The response did not have status 200.</summary>
    HttpRejected,
    /// <summary>The response type, size, syntax, family, or address range was rejected.</summary>
    InvalidResponse
}

/// <summary>Keeps failed attempts visible while exposing the domain's source observation.</summary>
public sealed class PublicIpReadResult
{
    /// <summary>Creates one diagnostic result; failed observations always contain a null address.</summary>
    internal PublicIpReadResult(PublicIpSource source, PublicIpReadStatus status, IPAddress? address = null,
        HttpStatusCode? httpStatus = null)
    {
        Source = source;
        Status = status;
        Observation = new PublicIpObservation(source.OperatorId, status == PublicIpReadStatus.Success ? address : null);
        HttpStatus = httpStatus;
    }

    /// <summary>Gets the attempted endpoint and configured independent operator.</summary>
    public PublicIpSource Source { get; }

    /// <summary>Gets the operational outcome, distinct from country and route eligibility.</summary>
    public PublicIpReadStatus Status { get; }

    /// <summary>Gets an immutable domain reply, including null for every failed attempt.</summary>
    public PublicIpObservation Observation { get; }

    /// <summary>Gets the received HTTP status, if headers were available.</summary>
    public HttpStatusCode? HttpStatus { get; }
}
