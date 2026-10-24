using System.IO.Pipes;
using System.Net;
using System.Net.Http.Headers;
using IPGuard.Infrastructure.GeoIp;
using Xunit;

namespace IntegrationTests;

/// <summary>Exercises cancellation of actual stalled asynchronous body reads without Internet requests.</summary>
public sealed class GeoIpDownloadTests
{
    /// <summary>The download deadline covers the complete body, and caller cancellation takes precedence.</summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task DownloadAsync_StalledBody_IsCancelled(bool callerCancels)
    {
        string pipeName = $"ipguard-geoip-{Guid.NewGuid():N}";
        using var server = new NamedPipeServerStream(pipeName, PipeDirection.Out, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
        using var client = new NamedPipeClientStream(".", pipeName, PipeDirection.In, PipeOptions.Asynchronous);
        Task connected = server.WaitForConnectionAsync(TestContext.Current.CancellationToken);
        await client.ConnectAsync(TestContext.Current.CancellationToken);
        await connected;
        using var caller = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        if (callerCancels) caller.CancelAfter(TimeSpan.FromMilliseconds(100));
        var transport = new PipeTransport(client);
        var downloader = new DbIpCountryDownloader(transport, callerCancels ? TimeSpan.FromSeconds(5) : TimeSpan.FromMilliseconds(100));
        using var destination = new MemoryStream();

        if (callerCancels)
        {
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => downloader.DownloadAsync(destination, DateTimeOffset.UtcNow, caller.Token));
        }
        else
        {
            await Assert.ThrowsAsync<TimeoutException>(() => downloader.DownloadAsync(destination, DateTimeOffset.UtcNow, caller.Token));
        }
        Assert.Empty(destination.ToArray());
    }

    /// <summary>Returns a local asynchronous pipe as an HTTP body without changing production TLS handling.</summary>
    private sealed class PipeTransport : IGeoIpDownloadTransport
    {
        private readonly Stream body;

        /// <summary>Captures an already connected read end whose peer does not send any bytes.</summary>
        internal PipeTransport(Stream body) => this.body = body;

        /// <summary>Returns streaming gzip headers immediately while body reads remain pending.</summary>
        public Task<HttpResponseMessage> SendAsync(Uri endpoint, CancellationToken cancellationToken)
        {
            var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(body) };
            response.Content.Headers.ContentType = new MediaTypeHeaderValue("application/gzip");
            return Task.FromResult(response);
        }
    }
}
