using System.Net;
using System.Net.Http.Headers;

namespace IPGuard.Infrastructure.GeoIp;

/// <summary>Owns a direct HTTPS client restricted to official DB-IP monthly country archives.</summary>
public sealed class HttpsGeoIpDownloadTransport : IGeoIpDownloadTransport, IDisposable
{
    private readonly HttpClient client;

    /// <summary>Creates a client with system TLS validation and no redirects, proxy, or decompression.</summary>
    public HttpsGeoIpDownloadTransport() => client = new HttpClient(CreateHandler()) { Timeout = Timeout.InfiniteTimeSpan };

    /// <summary>Rejects endpoints outside the fixed provider scope before sending any request.</summary>
    public async Task<HttpResponseMessage> SendAsync(Uri endpoint, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        if (!DbIpCountryDownloader.IsTrustedEndpoint(endpoint))
        {
            throw new ArgumentException("Only official monthly DB-IP Country Lite HTTPS archives are allowed.", nameof(endpoint));
        }
        using var request = new HttpRequestMessage(HttpMethod.Get, endpoint);
        request.Headers.UserAgent.ParseAdd("IPGuard");
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/gzip"));
        request.Headers.CacheControl = new CacheControlHeaderValue { NoCache = true, NoStore = true };
        return await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Exposes transport settings to tests without making external requests.</summary>
    internal static SocketsHttpHandler CreateHandler() => new()
    {
        UseProxy = false,
        AllowAutoRedirect = false,
        UseCookies = false,
        AutomaticDecompression = DecompressionMethods.None,
        MaxResponseHeadersLength = 8,
        PooledConnectionLifetime = TimeSpan.FromMinutes(5)
    };

    /// <summary>Releases the owned HTTP client and handler.</summary>
    public void Dispose() => client.Dispose();
}
