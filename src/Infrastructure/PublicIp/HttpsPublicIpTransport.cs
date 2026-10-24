using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using IPGuard.Application.PublicIp;

namespace IPGuard.Infrastructure.PublicIp;

/// <summary>Owns direct HTTPS clients with strict per-family sockets and system certificate validation.</summary>
public sealed class HttpsPublicIpTransport : IPublicIpTransport, IDisposable
{
    private readonly HttpClient ipv4;
    private readonly HttpClient ipv6;

    /// <summary>Creates separate IPv4 and IPv6 clients without proxy or redirect fallback.</summary>
    public HttpsPublicIpTransport()
    {
        ipv4 = new HttpClient(CreateHandler(AddressFamily.InterNetwork)) { Timeout = Timeout.InfiniteTimeSpan };
        ipv6 = new HttpClient(CreateHandler(AddressFamily.InterNetworkV6)) { Timeout = Timeout.InfiniteTimeSpan };
    }

    /// <summary>Sends an HTTP/1.1 GET and returns streaming content under the caller's deadline.</summary>
    public async Task<HttpResponseMessage> SendAsync(PublicIpSource source, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(source);
        using var request = new HttpRequestMessage(HttpMethod.Get, source.Endpoint)
        {
            Version = HttpVersion.Version11,
            VersionPolicy = HttpVersionPolicy.RequestVersionExact
        };
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/plain"));
        request.Headers.UserAgent.ParseAdd("IPGuard");
        request.Headers.CacheControl = new CacheControlHeaderValue { NoCache = true, NoStore = true };
        HttpClient client = source.Family == AddressFamily.InterNetwork ? ipv4 : ipv6;
        return await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Releases both clients and their handlers.</summary>
    public void Dispose()
    {
        ipv4.Dispose();
        ipv6.Dispose();
    }

    /// <summary>Creates security-sensitive transport settings for one supported address family.</summary>
    internal static SocketsHttpHandler CreateHandler(AddressFamily family)
    {
        ValidateFamily(family);
        return new SocketsHttpHandler
        {
            UseProxy = false,
            AllowAutoRedirect = false,
            UseCookies = false,
            AutomaticDecompression = DecompressionMethods.None,
            MaxResponseHeadersLength = 8,
            PooledConnectionLifetime = TimeSpan.Zero,
            ConnectCallback = (context, token) => ConnectAsync(context.DnsEndPoint, family, token)
        };
    }

    /// <summary>Resolves and connects only within the requested family; owns and cleans up a failed socket.</summary>
    internal static async ValueTask<Stream> ConnectAsync(DnsEndPoint endpoint, AddressFamily family, CancellationToken cancellationToken)
    {
        ValidateFamily(family);
        cancellationToken.ThrowIfCancellationRequested();
        IPAddress[] resolved = IPAddress.TryParse(endpoint.Host, out IPAddress? literal)
            ? [literal]
            : await Dns.GetHostAddressesAsync(endpoint.Host, family, cancellationToken).ConfigureAwait(false);
        IPAddress[] addresses = resolved.Where(address => address.AddressFamily == family).ToArray();
        if (addresses.Length == 0)
        {
            throw new SocketException((int)SocketError.HostNotFound);
        }

        var socket = new Socket(family, SocketType.Stream, ProtocolType.Tcp);
        try
        {
            socket.NoDelay = true;
            if (family == AddressFamily.InterNetworkV6)
            {
                socket.DualMode = false;
            }

            await socket.ConnectAsync(addresses, endpoint.Port, cancellationToken).ConfigureAwait(false);
            return new NetworkStream(socket, ownsSocket: true);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    /// <summary>Prevents accidental construction of an unspecified or unrelated socket family.</summary>
    private static void ValidateFamily(AddressFamily family)
    {
        if (family is not (AddressFamily.InterNetwork or AddressFamily.InterNetworkV6))
        {
            throw new ArgumentOutOfRangeException(nameof(family));
        }
    }
}
