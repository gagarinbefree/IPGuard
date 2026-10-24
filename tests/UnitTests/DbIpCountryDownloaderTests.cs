using System.IO.Compression;
using System.Net;
using System.Net.Http.Headers;
using IPGuard.Infrastructure.GeoIp;
using Xunit;

namespace UnitTests;

/// <summary>Checks provider scope, complete gzip integrity, size limits, and cancellation without public requests.</summary>
public sealed class DbIpCountryDownloaderTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 1, 1, 0, 0, TimeSpan.FromHours(2));

    /// <summary>The request month is UTC and the destination contains decoded bytes while remaining open.</summary>
    [Fact]
    public async Task DownloadAsync_ValidArchive_UsesOfficialUtcMonth()
    {
        byte[] expected = [1, 2, 3, 4, 5];
        var transport = new FakeTransport((endpoint, _) =>
        {
            Assert.Equal("https://download.db-ip.com/free/dbip-country-lite-2026-10.mmdb.gz", endpoint.AbsoluteUri);
            return Task.FromResult(Response(Compress(expected)));
        });
        var downloader = new DbIpCountryDownloader(transport, TimeSpan.FromSeconds(5));
        using var destination = new MemoryStream();

        await downloader.DownloadAsync(destination, Now, TestContext.Current.CancellationToken);

        Assert.Equal(expected, destination.ToArray());
        Assert.True(destination.CanWrite);
        Assert.Equal("DBIP-Country-Lite", downloader.DatabaseType);
    }

    /// <summary>HTTP errors and redirects never produce an accepted database.</summary>
    [Theory]
    [InlineData(HttpStatusCode.Redirect)]
    [InlineData(HttpStatusCode.NotFound)]
    [InlineData(HttpStatusCode.PartialContent)]
    [InlineData(HttpStatusCode.InternalServerError)]
    public async Task DownloadAsync_RejectedHttpStatus_Fails(HttpStatusCode status)
    {
        using var destination = new MemoryStream();
        var downloader = Downloader(Response(Compress([1, 2, 3]), status));

        await Assert.ThrowsAsync<InvalidDataException>(() => downloader.DownloadAsync(destination, Now, TestContext.Current.CancellationToken));
        Assert.Empty(destination.ToArray());
    }

    /// <summary>Unexpected content types, transparent encodings, and oversized declared bodies are rejected.</summary>
    [Theory]
    [InlineData("type")]
    [InlineData("encoding")]
    [InlineData("length")]
    public async Task DownloadAsync_RejectedHeaders_FailsBeforeWriting(string invalid)
    {
        HttpResponseMessage response = Response(Compress([1, 2, 3]));
        if (invalid == "type") response.Content.Headers.ContentType = new MediaTypeHeaderValue("text/html");
        if (invalid == "encoding") response.Content.Headers.ContentEncoding.Add("gzip");
        if (invalid == "length") response.Content.Headers.ContentLength = 16 * 1024 * 1024 + 1;
        using var destination = new MemoryStream();

        await Assert.ThrowsAsync<InvalidDataException>(() => Downloader(response)
            .DownloadAsync(destination, Now, TestContext.Current.CancellationToken));
        Assert.Empty(destination.ToArray());
    }

    /// <summary>Truncation, footer corruption, trailing bytes, and empty decoded bodies cannot succeed.</summary>
    [Theory]
    [InlineData("truncated")]
    [InlineData("checksum")]
    [InlineData("size")]
    [InlineData("trailing")]
    [InlineData("empty")]
    [InlineData("not-gzip")]
    public async Task DownloadAsync_IncompleteOrCorruptArchive_Fails(string invalid)
    {
        byte[] bytes = Compress(invalid == "empty" ? [] : [1, 2, 3, 4, 5]);
        switch (invalid)
        {
            case "truncated": bytes = bytes[..^8]; break;
            case "checksum": bytes[^8] ^= 0xff; break;
            case "size": bytes[^4] ^= 0xff; break;
            case "trailing": bytes = [.. bytes, 42]; break;
            case "not-gzip": bytes = new byte[30]; break;
        }
        using var destination = new MemoryStream();

        await Assert.ThrowsAsync<InvalidDataException>(() => Downloader(Response(bytes))
            .DownloadAsync(destination, Now, TestContext.Current.CancellationToken));
    }

    /// <summary>The compressed byte cap is enforced even when Content-Length understates the actual body.</summary>
    [Fact]
    public async Task DownloadAsync_ActualArchiveTooLarge_Fails()
    {
        HttpResponseMessage response = Response(new byte[16 * 1024 * 1024 + 1]);
        response.Content.Headers.ContentLength = 1;
        using var destination = new MemoryStream();

        await Assert.ThrowsAsync<InvalidDataException>(() => Downloader(response)
            .DownloadAsync(destination, Now, TestContext.Current.CancellationToken));
        Assert.Empty(destination.ToArray());
    }

    /// <summary>A small compressed payload cannot expand beyond the MMDB file cap.</summary>
    [Fact]
    public async Task DownloadAsync_ExpansionTooLarge_FailsWithoutWritingPastLimit()
    {
        byte[] bytes = Compress(new byte[64 * 1024 * 1024 + 1]);
        using var destination = new MemoryStream();

        await Assert.ThrowsAsync<InvalidDataException>(() => Downloader(Response(bytes))
            .DownloadAsync(destination, Now, TestContext.Current.CancellationToken));
        Assert.True(destination.Length <= 64 * 1024 * 1024);
    }

    /// <summary>The deadline covers transport work, and caller cancellation remains a separate outcome.</summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task DownloadAsync_StalledTransport_UsesDeadlineOrCallerCancellation(bool callerCancels)
    {
        using var caller = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        var transport = new FakeTransport(async (_, token) =>
        {
            if (callerCancels) caller.Cancel();
            await Task.Delay(Timeout.InfiniteTimeSpan, token);
            throw new InvalidOperationException("Unreachable after cancellation");
        });
        var downloader = new DbIpCountryDownloader(transport, TimeSpan.FromMilliseconds(100));
        using var destination = new MemoryStream();

        if (callerCancels)
        {
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => downloader.DownloadAsync(destination, Now, caller.Token));
        }
        else
        {
            await Assert.ThrowsAsync<TimeoutException>(() => downloader.DownloadAsync(destination, Now, caller.Token));
        }
    }

    /// <summary>A pre-cancelled caller cannot start a provider request.</summary>
    [Fact]
    public async Task DownloadAsync_PreCancelled_DoesNotRequest()
    {
        using var caller = new CancellationTokenSource();
        caller.Cancel();
        var transport = new FakeTransport((_, _) => throw new InvalidOperationException("Must not request"));
        using var destination = new MemoryStream();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => new DbIpCountryDownloader(transport, TimeSpan.FromSeconds(1))
            .DownloadAsync(destination, Now, caller.Token));
    }

    /// <summary>Invalid deadlines cannot construct a downloader.</summary>
    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(long.MaxValue)]
    public void Constructor_InvalidTimeout_IsRejected(long ticks) => Assert.Throws<ArgumentOutOfRangeException>(() =>
        new DbIpCountryDownloader(new FakeTransport((_, _) => throw new InvalidOperationException()), TimeSpan.FromTicks(ticks)));

    /// <summary>Uses a controlled response and a finite deadline.</summary>
    private static DbIpCountryDownloader Downloader(HttpResponseMessage response) =>
        new(new FakeTransport((_, _) => Task.FromResult(response)), TimeSpan.FromSeconds(10));

    /// <summary>Creates a synthetic gzip HTTP response with an allowed binary content type.</summary>
    private static HttpResponseMessage Response(byte[] bytes, HttpStatusCode status = HttpStatusCode.OK)
    {
        var response = new HttpResponseMessage(status) { Content = new ByteArrayContent(bytes) };
        response.Content.Headers.ContentType = new MediaTypeHeaderValue("application/gzip");
        return response;
    }

    /// <summary>Creates a real gzip member, including its checksum and length trailer.</summary>
    private static byte[] Compress(byte[] bytes)
    {
        using var result = new MemoryStream();
        using (var gzip = new GZipStream(result, CompressionLevel.Fastest, leaveOpen: true)) gzip.Write(bytes);
        return result.ToArray();
    }

    /// <summary>Supplies a controlled transfer without replacing TLS validation in production.</summary>
    private sealed class FakeTransport : IGeoIpDownloadTransport
    {
        private readonly Func<Uri, CancellationToken, Task<HttpResponseMessage>> send;

        /// <summary>Captures per-request response or cancellation behavior.</summary>
        internal FakeTransport(Func<Uri, CancellationToken, Task<HttpResponseMessage>> send) => this.send = send;

        /// <summary>Invokes the configured transfer behavior.</summary>
        public Task<HttpResponseMessage> SendAsync(Uri endpoint, CancellationToken cancellationToken) => send(endpoint, cancellationToken);
    }
}
