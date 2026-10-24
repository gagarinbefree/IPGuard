using System.IO.Pipes;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using IPGuard.Infrastructure.PublicIp;
using Xunit;

namespace IntegrationTests;

/// <summary>Exercises local sockets, certificate rejection, and body cancellation without public services or filter changes.</summary>
public sealed class PublicIpNetworkTests
{
    /// <summary>Actual loopback sockets preserve the requested family and can carry bytes.</summary>
    [Theory]
    [InlineData(AddressFamily.InterNetwork)]
    [InlineData(AddressFamily.InterNetworkV6)]
    public async Task ConnectAsync_UsesOnlyRequestedFamily(AddressFamily family)
    {
        if (family == AddressFamily.InterNetworkV6 && !Socket.OSSupportsIPv6)
        {
            Assert.Skip("IPv6 sockets are unavailable on this machine.");
        }

        IPAddress address = family == AddressFamily.InterNetwork ? IPAddress.Loopback : IPAddress.IPv6Loopback;
        var listener = new TcpListener(address, 0);
        listener.Start();
        try
        {
            int port = ((IPEndPoint)listener.LocalEndpoint).Port;
            Task<TcpClient> accepted = listener.AcceptTcpClientAsync(TestContext.Current.CancellationToken).AsTask();
            await using Stream stream = await HttpsPublicIpTransport.ConnectAsync(new DnsEndPoint(address.ToString(), port),
                family, TestContext.Current.CancellationToken);
            using TcpClient peer = await accepted;

            await stream.WriteAsync(new byte[] { 42 }, TestContext.Current.CancellationToken);
            byte[] buffer = new byte[1];
            Assert.Equal(1, await peer.GetStream().ReadAsync(buffer, TestContext.Current.CancellationToken));
            Assert.Equal(42, buffer[0]);
            Assert.Equal(family, ((IPEndPoint)peer.Client.RemoteEndPoint!).AddressFamily);
        }
        finally
        {
            listener.Stop();
        }
    }

    /// <summary>IPv6 connection failure cannot fall back to an available IPv4 listener.</summary>
    [Fact]
    public async Task ConnectAsync_Ipv4LiteralForIpv6_DoesNotFallback()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try
        {
            int port = ((IPEndPoint)listener.LocalEndpoint).Port;
            await Assert.ThrowsAsync<SocketException>(async () =>
            {
                await using Stream stream = await HttpsPublicIpTransport.ConnectAsync(new DnsEndPoint("127.0.0.1", port),
                    AddressFamily.InterNetworkV6, TestContext.Current.CancellationToken);
            });
            Assert.False(listener.Pending());
        }
        finally
        {
            listener.Stop();
        }
    }

    /// <summary>A local self-signed server certificate is rejected without adding trust or disabling validation.</summary>
    [Fact]
    public async Task ReadAsync_UntrustedCertificate_ReturnsTlsFailure()
    {
        using RSA key = RSA.Create(2048);
        var request = new CertificateRequest("CN=localhost", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var names = new SubjectAlternativeNameBuilder();
        names.AddDnsName("localhost");
        request.CertificateExtensions.Add(names.Build());
        using X509Certificate2 certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(1));
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        cancellation.CancelAfter(TimeSpan.FromSeconds(15));
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try
        {
            Task server = ServeCertificateAsync(listener, certificate, cancellation.Token);
            using var transport = new HttpsPublicIpTransport();
            var reader = new PublicIpReader(transport, TimeSpan.FromSeconds(10));
            int port = ((IPEndPoint)listener.LocalEndpoint).Port;
            var source = new PublicIpSource("local-test", new Uri($"https://localhost:{port}/"), AddressFamily.InterNetwork);

            PublicIpReadResult result = await reader.ReadAsync(source, cancellation.Token);
            await server;

            Assert.Equal(PublicIpReadStatus.TlsFailed, result.Status);
            Assert.Null(result.Observation.Address);
        }
        finally
        {
            listener.Stop();
        }
    }

    /// <summary>The deadline cancels a real asynchronous body read even after successful headers have arrived.</summary>
    [Fact]
    public async Task ReadAsync_StalledBody_ExpiresCompleteDeadline()
    {
        string pipeName = $"IPGuard-PublicIp-{Guid.NewGuid():N}";
        using var writer = new NamedPipeServerStream(pipeName, PipeDirection.Out, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
        using var body = new NamedPipeClientStream(".", pipeName, PipeDirection.In, PipeOptions.Asynchronous);
        Task connected = writer.WaitForConnectionAsync(TestContext.Current.CancellationToken);
        await body.ConnectAsync(TestContext.Current.CancellationToken);
        await connected;
        using var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(body) };
        response.Content.Headers.ContentType = new MediaTypeHeaderValue("text/plain");
        var reader = new PublicIpReader(new ResponseTransport(response), TimeSpan.FromMilliseconds(50));
        var source = new PublicIpSource("local-test", new Uri("https://source.example/"), AddressFamily.InterNetwork);

        PublicIpReadResult result = await reader.ReadAsync(source, TestContext.Current.CancellationToken);

        Assert.Equal(PublicIpReadStatus.TimedOut, result.Status);
        Assert.Null(result.Observation.Address);
    }

    /// <summary>Offers an untrusted certificate; server completion alone cannot prove that the client accepted it.</summary>
    private static async Task ServeCertificateAsync(TcpListener listener, X509Certificate2 certificate, CancellationToken cancellationToken)
    {
        using TcpClient peer = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var tls = new SslStream(peer.GetStream(), leaveInnerStreamOpen: false);
        try
        {
            await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions { ServerCertificate = certificate }, cancellationToken);
        }
        catch (AuthenticationException)
        {
            // The peer can report certificate rejection before the server handshake completes.
        }
        catch (IOException)
        {
            // The peer can close the connection after rejecting the certificate.
        }
    }

    /// <summary>Supplies successful headers with a caller-provided asynchronous local body.</summary>
    private sealed class ResponseTransport : IPublicIpTransport
    {
        private readonly HttpResponseMessage response;

        /// <summary>Captures the response without taking ownership away from the reader.</summary>
        internal ResponseTransport(HttpResponseMessage response) => this.response = response;

        /// <summary>Returns headers immediately, allowing the reader to enforce the body deadline.</summary>
        public Task<HttpResponseMessage> SendAsync(PublicIpSource source, CancellationToken cancellationToken) => Task.FromResult(response);
    }
}
