using System.Net;
using System.Net.Http.Headers;
using IPGuard.Application.PublicIp;

namespace IPGuard.Infrastructure.PublicIp;

/// <summary>Reads every configured source with a complete deadline and bounded plaintext interpretation.</summary>
public sealed class PublicIpReader : IPublicIpProbe
{
    private readonly IPublicIpTransport transport;
    private readonly TimeSpan timeout;

    /// <summary>Uses a caller-owned transport and a finite per-attempt timeout that includes body reading.</summary>
    public PublicIpReader(IPublicIpTransport transport, TimeSpan timeout)
    {
        ArgumentNullException.ThrowIfNull(transport);
        if (timeout <= TimeSpan.Zero || timeout.TotalMilliseconds > uint.MaxValue - 1L)
        {
            throw new ArgumentOutOfRangeException(nameof(timeout));
        }

        this.transport = transport;
        this.timeout = timeout;
    }

    /// <summary>Returns an observation or operational failure; caller cancellation is propagated.</summary>
    public async Task<PublicIpReadResult> ReadAsync(PublicIpSource source, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(source);
        cancellationToken.ThrowIfCancellationRequested();
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(timeout);
        try
        {
            using HttpResponseMessage response = await transport.SendAsync(source, deadline.Token).ConfigureAwait(false);
            deadline.Token.ThrowIfCancellationRequested();
            if (response.StatusCode != HttpStatusCode.OK)
            {
                return new(source, PublicIpReadStatus.HttpRejected, httpStatus: response.StatusCode);
            }

            if (!HasSupportedContentType(response.Content.Headers)
                || response.Content.Headers.ContentEncoding.Count != 0
                || response.Content.Headers.ContentLength > PublicAddressParser.MaximumBodyBytes)
            {
                return new(source, PublicIpReadStatus.InvalidResponse, httpStatus: response.StatusCode);
            }

            Stream body = await response.Content.ReadAsStreamAsync(deadline.Token).ConfigureAwait(false);
            byte[] bytes = new byte[PublicAddressParser.MaximumBodyBytes + 1];
            int count = 0;
            while (count < bytes.Length)
            {
                int read = await body.ReadAsync(bytes.AsMemory(count), deadline.Token).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                count += read;
            }

            deadline.Token.ThrowIfCancellationRequested();
            IPAddress? address = PublicAddressParser.Parse(bytes.AsSpan(0, count), source.Family);
            return new(source, address is null ? PublicIpReadStatus.InvalidResponse : PublicIpReadStatus.Success,
                address, response.StatusCode);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new(source, deadline.IsCancellationRequested ? PublicIpReadStatus.TimedOut : PublicIpReadStatus.TransportFailed);
        }
        catch (HttpRequestException error)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return new(source, error.HttpRequestError switch
            {
                HttpRequestError.NameResolutionError => PublicIpReadStatus.NameResolutionFailed,
                HttpRequestError.SecureConnectionError => PublicIpReadStatus.TlsFailed,
                _ => PublicIpReadStatus.TransportFailed
            });
        }
        catch (IOException)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return new(source, PublicIpReadStatus.TransportFailed);
        }
    }

    /// <summary>Starts every configured attempt and preserves input order, failures, and conflicting replies.</summary>
    public async Task<IReadOnlyList<PublicIpReadResult>> ReadAllAsync(IEnumerable<PublicIpSource> sources, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(sources);
        cancellationToken.ThrowIfCancellationRequested();
        PublicIpSource[] snapshot = sources.ToArray();
        Task<PublicIpReadResult>[] attempts = snapshot.Select(source => ReadAsync(source, cancellationToken)).ToArray();
        PublicIpReadResult[] results = await Task.WhenAll(attempts).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        return Array.AsReadOnly(results);
    }

    /// <summary>Accepts plaintext with an absent, UTF-8, or US-ASCII charset while rejecting contradictory encodings.</summary>
    private static bool HasSupportedContentType(HttpContentHeaders headers)
    {
        MediaTypeHeaderValue? contentType = headers.ContentType;
        if (contentType is null || !string.Equals(contentType.MediaType, "text/plain", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        string? charset = contentType.CharSet?.Trim('"');
        return charset is null || string.Equals(charset, "utf-8", StringComparison.OrdinalIgnoreCase)
            || string.Equals(charset, "us-ascii", StringComparison.OrdinalIgnoreCase);
    }
}
