using IPGuard.Application.PublicIp;

namespace IPGuard.Infrastructure.PublicIp;

/// <summary>Separates direct validated HTTPS transport from bounded response interpretation.</summary>
public interface IPublicIpTransport
{
    /// <summary>Returns headers and a streaming body; the caller owns the response and its complete deadline.</summary>
    /// <remarks>Implementations must retain certificate validation and disable proxies, redirects, and family fallback.</remarks>
    Task<HttpResponseMessage> SendAsync(PublicIpSource source, CancellationToken cancellationToken);
}
