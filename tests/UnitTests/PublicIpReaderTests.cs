using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Text;
using IPGuard.Application.PublicIp;
using IPGuard.Infrastructure.PublicIp;
using Xunit;

namespace UnitTests;

/// <summary>Checks bounded response interpretation, operational failures, and complete source collection through a fake transport.</summary>
public sealed class PublicIpReaderTests
{
    /// <summary>Successful plaintext becomes an immutable domain observation for the configured operator.</summary>
    [Theory]
    [InlineData("1.1.1.1\n", AddressFamily.InterNetwork, "1.1.1.1")]
    [InlineData("2606:4700:4700::1111", AddressFamily.InterNetworkV6, "2606:4700:4700::1111")]
    public async Task ReadAsync_ValidReply_ReturnsObservation(string body, AddressFamily family, string expected)
    {
        using var stream = new MemoryStream(Encoding.ASCII.GetBytes(body));
        var transport = new FakeTransport((_, _) => Task.FromResult(Response(stream)));
        var reader = new PublicIpReader(transport, TimeSpan.FromSeconds(5));

        PublicIpReadResult result = await reader.ReadAsync(Source(family: family), TestContext.Current.CancellationToken);

        Assert.Equal(PublicIpReadStatus.Success, result.Status);
        Assert.Equal(expected, result.Observation.Address);
        Assert.Equal("operator-a", result.Observation.OperatorId);
        Assert.Equal(HttpStatusCode.OK, result.HttpStatus);
        Assert.False(stream.CanRead);
    }

    /// <summary>Redirects, partial replies, errors, and bodyless success codes do not become observations.</summary>
    [Theory]
    [InlineData(301)]
    [InlineData(302)]
    [InlineData(204)]
    [InlineData(206)]
    [InlineData(429)]
    [InlineData(500)]
    public async Task ReadAsync_Non200Status_IsRejected(int status)
    {
        using var response = Response("1.1.1.1");
        response.StatusCode = (HttpStatusCode)status;

        PublicIpReadResult result = await Read(response);

        AssertFailure(PublicIpReadStatus.HttpRejected, result);
        Assert.Equal((HttpStatusCode)status, result.HttpStatus);
    }

    /// <summary>Only uncompressed plaintext is supported, without guessing formats from body contents.</summary>
    [Theory]
    [InlineData(null, null)]
    [InlineData("text/html", null)]
    [InlineData("application/json", null)]
    [InlineData("text/plain", "gzip")]
    public async Task ReadAsync_UnsupportedContent_IsRejected(string? mediaType, string? encoding)
    {
        using var response = Response("1.1.1.1");
        response.Content.Headers.ContentType = mediaType is null ? null : new MediaTypeHeaderValue(mediaType);
        if (encoding is not null)
        {
            response.Content.Headers.ContentEncoding.Add(encoding);
        }

        AssertFailure(PublicIpReadStatus.InvalidResponse, await Read(response));
    }

    /// <summary>Contradictory or unknown character encodings cannot be silently interpreted as ASCII.</summary>
    [Theory]
    [InlineData("utf-16")]
    [InlineData("utf-32")]
    [InlineData("unknown")]
    public async Task ReadAsync_UnsupportedCharset_IsRejected(string charset)
    {
        using var response = Response("1.1.1.1");
        response.Content.Headers.ContentType!.CharSet = charset;

        AssertFailure(PublicIpReadStatus.InvalidResponse, await Read(response));
    }

    /// <summary>The two supported ASCII-compatible encodings retain valid plaintext behavior.</summary>
    [Theory]
    [InlineData("utf-8")]
    [InlineData("\"US-ASCII\"")]
    public async Task ReadAsync_SupportedCharset_IsAccepted(string charset)
    {
        using var response = Response("1.1.1.1");
        response.Content.Headers.ContentType!.CharSet = charset;

        Assert.Equal(PublicIpReadStatus.Success, (await Read(response)).Status);
    }

    /// <summary>Invalid address syntax and nonpublic or wrong-family replies remain failed domain observations.</summary>
    [Theory]
    [InlineData("")]
    [InlineData("192.168.1.1")]
    [InlineData("{\"ip\":\"1.1.1.1\"}")]
    [InlineData("2606:4700:4700::1111")]
    public async Task ReadAsync_InvalidAddress_IsRejected(string body)
    {
        using var response = Response(body);

        AssertFailure(PublicIpReadStatus.InvalidResponse, await Read(response));
    }

    /// <summary>The real read cap applies even when a server lies about Content-Length.</summary>
    [Theory]
    [InlineData(1)]
    [InlineData(129)]
    public async Task ReadAsync_OversizedBody_IsRejected(long declaredLength)
    {
        using var response = Response("1.1.1.1".PadRight(129));
        response.Content.Headers.ContentLength = declaredLength;

        AssertFailure(PublicIpReadStatus.InvalidResponse, await Read(response));
    }

    /// <summary>DNS and TLS failures stay distinguishable without creating a successful observation.</summary>
    [Theory]
    [InlineData(HttpRequestError.NameResolutionError, PublicIpReadStatus.NameResolutionFailed)]
    [InlineData(HttpRequestError.SecureConnectionError, PublicIpReadStatus.TlsFailed)]
    [InlineData(HttpRequestError.ConnectionError, PublicIpReadStatus.TransportFailed)]
    public async Task ReadAsync_HttpFailure_ReportsCategory(HttpRequestError error, PublicIpReadStatus expected)
    {
        var transport = new FakeTransport((_, _) => throw new HttpRequestException(error, "Expected test failure."));
        var reader = new PublicIpReader(transport, TimeSpan.FromSeconds(5));

        AssertFailure(expected, await reader.ReadAsync(Source(), TestContext.Current.CancellationToken));
    }

    /// <summary>A failed response stream cannot reuse the previous successful public address.</summary>
    [Fact]
    public async Task ReadAsync_IoFailure_IsReported()
    {
        var transport = new FakeTransport((_, _) => throw new IOException("Expected test failure."));
        var reader = new PublicIpReader(transport, TimeSpan.FromSeconds(5));

        AssertFailure(PublicIpReadStatus.TransportFailed, await reader.ReadAsync(Source(), TestContext.Current.CancellationToken));
    }

    /// <summary>A stalled request honors the reader deadline rather than producing an address.</summary>
    [Fact]
    public async Task ReadAsync_DeadlineExpires_ReturnsTimeout()
    {
        var transport = new FakeTransport(WaitUntilCancelled);
        var reader = new PublicIpReader(transport, TimeSpan.FromMilliseconds(30));

        AssertFailure(PublicIpReadStatus.TimedOut, await reader.ReadAsync(Source(), TestContext.Current.CancellationToken));
    }

    /// <summary>Caller cancellation before sending does not contact a source or masquerade as a timeout.</summary>
    [Fact]
    public async Task ReadAsync_AlreadyCancelled_DoesNotSend()
    {
        bool sent = false;
        var transport = new FakeTransport((_, _) => { sent = true; return Task.FromResult(Response("1.1.1.1")); });
        var reader = new PublicIpReader(transport, TimeSpan.FromSeconds(5));
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => reader.ReadAsync(Source(), cancellation.Token));
        Assert.False(sent);
    }

    /// <summary>Cancellation after a source has started remains observable by orchestration.</summary>
    [Fact]
    public async Task ReadAsync_CallerCancelsInFlight_PropagatesCancellation()
    {
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var transport = new FakeTransport((source, token) => { started.SetResult(); return WaitUntilCancelled(source, token); });
        var reader = new PublicIpReader(transport, TimeSpan.FromSeconds(5));
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);

        Task<PublicIpReadResult> pending = reader.ReadAsync(Source(), cancellation.Token);
        await started.Task.WaitAsync(TestContext.Current.CancellationToken);
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => pending);
    }

    /// <summary>Cancellation remains observable even when the transport reports an I/O error while stopping.</summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ReadAsync_CancellationRacesWithIoFailure_PropagatesCancellation(bool httpError)
    {
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        var transport = new FakeTransport((_, _) =>
        {
            cancellation.Cancel();
            if (httpError)
            {
                throw new HttpRequestException("Expected test failure.");
            }

            throw new IOException("Expected test failure.");
        });
        var reader = new PublicIpReader(transport, TimeSpan.FromSeconds(5));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => reader.ReadAsync(Source(), cancellation.Token));
    }

    /// <summary>All attempts start, and failed or conflicting replies are retained in configured order.</summary>
    [Fact]
    public async Task ReadAllAsync_PreservesAllAttemptsWithoutQuorumShortCircuit()
    {
        int attempts = 0;
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var transport = new FakeTransport(async (source, token) =>
        {
            if (Interlocked.Increment(ref attempts) == 3)
            {
                started.SetResult();
            }

            await release.Task.WaitAsync(token);
            return source.OperatorId switch
            {
                "operator-a" => Response("1.1.1.1"),
                "operator-b" => Response("8.8.8.8"),
                _ => throw new HttpRequestException(HttpRequestError.NameResolutionError, "Expected test failure.")
            };
        });
        var reader = new PublicIpReader(transport, TimeSpan.FromSeconds(10));

        Task<IReadOnlyList<PublicIpReadResult>> pending = reader.ReadAllAsync(
            [Source(), Source("operator-b"), Source("operator-c")], TestContext.Current.CancellationToken);
        await started.Task.WaitAsync(TestContext.Current.CancellationToken);
        release.SetResult();
        IReadOnlyList<PublicIpReadResult> results = await pending;

        Assert.Equal(3, attempts);
        Assert.Equal(new[] { "operator-a", "operator-b", "operator-c" }, results.Select(result => result.Observation.OperatorId));
        Assert.Equal(new string?[] { "1.1.1.1", "8.8.8.8", null }, results.Select(result => result.Observation.Address));
        Assert.Equal(PublicIpReadStatus.NameResolutionFailed, results[2].Status);
    }

    /// <summary>Reader deadlines must be finite, positive, and supported by CancellationTokenSource timers.</summary>
    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(long.MaxValue)]
    public void Constructor_InvalidTimeout_IsRejected(long ticks)
    {
        var transport = new FakeTransport((_, _) => Task.FromResult(Response("1.1.1.1")));

        Assert.Throws<ArgumentOutOfRangeException>(() => new PublicIpReader(transport, TimeSpan.FromTicks(ticks)));
    }

    /// <summary>Checks that every failed attempt exports a null domain address.</summary>
    private static void AssertFailure(PublicIpReadStatus expected, PublicIpReadResult result)
    {
        Assert.Equal(expected, result.Status);
        Assert.Null(result.Observation.Address);
    }

    /// <summary>Reads a supplied response through the same bounded path as the real transport.</summary>
    private static Task<PublicIpReadResult> Read(HttpResponseMessage response) =>
        new PublicIpReader(new FakeTransport((_, _) => Task.FromResult(response)), TimeSpan.FromSeconds(5))
            .ReadAsync(Source(), TestContext.Current.CancellationToken);

    /// <summary>Creates trusted source configuration without resolving its reserved example hostname.</summary>
    private static PublicIpSource Source(string operatorId = "operator-a", AddressFamily family = AddressFamily.InterNetwork) =>
        new(operatorId, new Uri("https://source.example/"), family);

    /// <summary>Creates a small plaintext response with caller-owned bytes.</summary>
    private static HttpResponseMessage Response(string body) => Response(new MemoryStream(Encoding.ASCII.GetBytes(body)));

    /// <summary>Creates a streaming response whose disposal releases the supplied stream.</summary>
    private static HttpResponseMessage Response(Stream stream)
    {
        var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(stream) };
        response.Content.Headers.ContentType = new MediaTypeHeaderValue("text/plain");
        return response;
    }

    /// <summary>Models a cooperative transport that never produces headers before cancellation.</summary>
    private static async Task<HttpResponseMessage> WaitUntilCancelled(PublicIpSource source, CancellationToken cancellationToken)
    {
        await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
        throw new InvalidOperationException($"Unexpected completion for {source.OperatorId}.");
    }

    /// <summary>Implements the I/O boundary through composition without inheriting an HTTP handler.</summary>
    private sealed class FakeTransport : IPublicIpTransport
    {
        private readonly Func<PublicIpSource, CancellationToken, Task<HttpResponseMessage>> send;

        /// <summary>Captures controlled request behavior without owning network resources.</summary>
        internal FakeTransport(Func<PublicIpSource, CancellationToken, Task<HttpResponseMessage>> send) => this.send = send;

        /// <summary>Delegates one request to controlled test behavior.</summary>
        public Task<HttpResponseMessage> SendAsync(PublicIpSource source, CancellationToken cancellationToken) => send(source, cancellationToken);
    }
}
