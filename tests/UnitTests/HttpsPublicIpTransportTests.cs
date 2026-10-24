using System.Net;
using System.Net.Sockets;
using IPGuard.Infrastructure.PublicIp;
using Xunit;

namespace UnitTests;

/// <summary>Protects transport settings that must not silently fall back to unsafe framework defaults.</summary>
public sealed class HttpsPublicIpTransportTests
{
    /// <summary>Source clients cannot use proxies, redirects, cookies, decompression, stale pooled sockets, or TLS bypasses.</summary>
    [Theory]
    [InlineData(AddressFamily.InterNetwork)]
    [InlineData(AddressFamily.InterNetworkV6)]
    public void CreateHandler_RetainsDirectValidatedFreshConnections(AddressFamily family)
    {
        using SocketsHttpHandler handler = HttpsPublicIpTransport.CreateHandler(family);

        Assert.False(handler.UseProxy);
        Assert.False(handler.AllowAutoRedirect);
        Assert.False(handler.UseCookies);
        Assert.Equal(DecompressionMethods.None, handler.AutomaticDecompression);
        Assert.Equal(TimeSpan.Zero, handler.PooledConnectionLifetime);
        Assert.NotNull(handler.ConnectCallback);
        Assert.Null(handler.SslOptions.RemoteCertificateValidationCallback);
        Assert.InRange(handler.MaxResponseHeadersLength, 1, 8);
    }

    /// <summary>An unspecified family must never create a dual-stack client.</summary>
    [Fact]
    public void CreateHandler_UnsupportedFamily_IsRejected()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => HttpsPublicIpTransport.CreateHandler(AddressFamily.Unspecified));
    }
}
