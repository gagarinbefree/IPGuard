using System.Net;
using IPGuard.Infrastructure.GeoIp;
using Xunit;

namespace UnitTests;

/// <summary>Checks the provider trust boundary without making Internet requests.</summary>
public sealed class HttpsGeoIpDownloadTransportTests
{
    /// <summary>Canonical valid archive endpoints pass the scope check without starting a request.</summary>
    [Theory]
    [InlineData("https://download.db-ip.com/free/dbip-country-lite-2026-10.mmdb.gz")]
    [InlineData("https://download.db-ip.com/free/dbip-country-lite-2026-01.mmdb.gz")]
    [InlineData("https://DOWNLOAD.DB-IP.COM:443/free/dbip-country-lite-2026-12.mmdb.gz")]
    public void IsTrustedEndpoint_OfficialArchive_IsAccepted(string endpoint) =>
        Assert.True(DbIpCountryDownloader.IsTrustedEndpoint(new Uri(endpoint)));

    /// <summary>Transport settings preserve system certificate validation and prohibit implicit alternate sources.</summary>
    [Fact]
    public void CreateHandler_UsesDirectValidatedHttps()
    {
        using SocketsHttpHandler handler = HttpsGeoIpDownloadTransport.CreateHandler();

        Assert.False(handler.AllowAutoRedirect);
        Assert.False(handler.UseProxy);
        Assert.False(handler.UseCookies);
        Assert.Equal(DecompressionMethods.None, handler.AutomaticDecompression);
        Assert.Null(handler.SslOptions.RemoteCertificateValidationCallback);
        Assert.Null(handler.SslOptions.ClientCertificates);
        Assert.Equal(8, handler.MaxResponseHeadersLength);
    }

    /// <summary>Alternate hosts, schemes, credentials, ports, and paths cannot reach the HTTP client.</summary>
    [Theory]
    [InlineData("http://download.db-ip.com/free/dbip-country-lite-2026-10.mmdb.gz")]
    [InlineData("https://example.com/free/dbip-country-lite-2026-10.mmdb.gz")]
    [InlineData("https://download.db-ip.com.example.com/free/dbip-country-lite-2026-10.mmdb.gz")]
    [InlineData("https://user@download.db-ip.com/free/dbip-country-lite-2026-10.mmdb.gz")]
    [InlineData("https://download.db-ip.com:444/free/dbip-country-lite-2026-10.mmdb.gz")]
    [InlineData("https://download.db-ip.com/free/dbip-country-lite-2026-10.mmdb.gz?source=other")]
    [InlineData("https://download.db-ip.com/free/dbip-country-lite-2026-10.mmdb.gz#other")]
    [InlineData("https://download.db-ip.com/free/dbip-country-lite-2026-13.mmdb.gz")]
    [InlineData("https://download.db-ip.com/free/dbip-city-lite-2026-10.mmdb.gz")]
    [InlineData("/free/dbip-country-lite-2026-10.mmdb.gz")]
    public async Task SendAsync_UntrustedEndpoint_IsRejected(string endpoint)
    {
        using var transport = new HttpsGeoIpDownloadTransport();

        await Assert.ThrowsAsync<ArgumentException>(() => transport.SendAsync(new Uri(endpoint, UriKind.RelativeOrAbsolute),
            TestContext.Current.CancellationToken));
    }
}
