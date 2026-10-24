namespace IPGuard.Infrastructure.GeoIp;

/// <summary>Separates authenticated HTTPS transfer from gzip validation and local publication.</summary>
public interface IGeoIpDownloadTransport
{
    /// <summary>Returns streaming content from an allowed provider endpoint under the caller's deadline.</summary>
    Task<HttpResponseMessage> SendAsync(Uri endpoint, CancellationToken cancellationToken);
}
