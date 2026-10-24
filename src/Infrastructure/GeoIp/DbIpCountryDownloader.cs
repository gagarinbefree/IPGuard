using System.Buffers.Binary;
using System.Globalization;
using System.IO.Compression;
using System.IO.Hashing;
using System.Net;
using IPGuard.Application.GeoIp;

namespace IPGuard.Infrastructure.GeoIp;

/// <summary>Downloads only the official monthly DB-IP Country Lite gzip with bounded transfer and decoding.</summary>
public sealed class DbIpCountryDownloader : IGeoIpDatabaseDownload
{
    private readonly IGeoIpDownloadTransport transport;
    private readonly TimeSpan timeout;

    /// <summary>Uses a caller-owned HTTPS transport and a finite deadline for the entire download.</summary>
    public DbIpCountryDownloader(IGeoIpDownloadTransport transport, TimeSpan timeout)
    {
        ArgumentNullException.ThrowIfNull(transport);
        if (timeout <= TimeSpan.Zero || timeout.TotalMilliseconds > uint.MaxValue - 1L)
        {
            throw new ArgumentOutOfRangeException(nameof(timeout));
        }

        this.transport = transport;
        this.timeout = timeout;
    }

    /// <summary>Gets the required DB-IP Country Lite MMDB product.</summary>
    public string DatabaseType => "DBIP-Country-Lite";

    /// <summary>Writes a complete, bounded MMDB payload; the destination remains owned by the caller.</summary>
    public async Task DownloadAsync(Stream destination, DateTimeOffset now, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(destination);
        cancellationToken.ThrowIfCancellationRequested();
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(timeout);
        string month = now.UtcDateTime.ToString("yyyy-MM", CultureInfo.InvariantCulture);
        var endpoint = new Uri($"https://download.db-ip.com/free/dbip-country-lite-{month}.mmdb.gz");
        try
        {
            using HttpResponseMessage response = await transport.SendAsync(endpoint, deadline.Token).ConfigureAwait(false);
            deadline.Token.ThrowIfCancellationRequested();
            if (response.StatusCode != HttpStatusCode.OK || response.Content.Headers.ContentEncoding.Count != 0
                || response.Content.Headers.ContentLength > GeoIpFileLimits.MaximumArchiveBytes
                || response.Content.Headers.ContentType?.MediaType is not
                    ("application/gzip" or "application/x-gzip" or "application/octet-stream"))
            {
                throw new InvalidDataException("Expected a complete binary DB-IP gzip response with status 200.");
            }

            using MemoryStream archive = await ReadArchiveAsync(response.Content, deadline.Token).ConfigureAwait(false);
            await DecodeAsync(archive, destination, deadline.Token).ConfigureAwait(false);
            deadline.Token.ThrowIfCancellationRequested();
        }
        catch (Exception) when (cancellationToken.IsCancellationRequested)
        {
            throw new OperationCanceledException(cancellationToken);
        }
        catch (Exception error) when (deadline.IsCancellationRequested)
        {
            throw new TimeoutException("The complete GeoIP download deadline expired.", error);
        }
    }

    /// <summary>Recognizes only canonical monthly country archives on the fixed HTTPS provider origin.</summary>
    internal static bool IsTrustedEndpoint(Uri endpoint)
    {
        if (!endpoint.IsAbsoluteUri || endpoint.Scheme != Uri.UriSchemeHttps || endpoint.Port != 443
            || !endpoint.IdnHost.Equals("download.db-ip.com", StringComparison.OrdinalIgnoreCase)
            || endpoint.UserInfo.Length != 0 || endpoint.Query.Length != 0 || endpoint.Fragment.Length != 0)
        {
            return false;
        }

        const string prefix = "/free/dbip-country-lite-";
        const string suffix = ".mmdb.gz";
        string path = endpoint.AbsolutePath;
        return path.StartsWith(prefix, StringComparison.Ordinal) && path.EndsWith(suffix, StringComparison.Ordinal)
            && path.Length == prefix.Length + 7 + suffix.Length
            && DateOnly.TryParseExact(path.AsSpan(prefix.Length, 7), "yyyy-MM", CultureInfo.InvariantCulture,
                DateTimeStyles.None, out _);
    }

    /// <summary>Buffers at most the compressed limit and one detection byte, regardless of Content-Length.</summary>
    private static async Task<MemoryStream> ReadArchiveAsync(HttpContent content, CancellationToken cancellationToken)
    {
        var archive = new MemoryStream();
        try
        {
            Stream body = await content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
            byte[] buffer = new byte[64 * 1024];
            while (true)
            {
                int remaining = GeoIpFileLimits.MaximumArchiveBytes - checked((int)archive.Length);
                int count = await body.ReadAsync(buffer.AsMemory(0, Math.Min(buffer.Length, remaining + 1)), cancellationToken).ConfigureAwait(false);
                if (count == 0)
                {
                    break;
                }
                if (count > remaining)
                {
                    throw new InvalidDataException("The compressed GeoIP archive exceeds 16 MiB.");
                }
                archive.Write(buffer, 0, count);
            }
            archive.Position = 0;
            return archive;
        }
        catch
        {
            archive.Dispose();
            throw;
        }
    }

    /// <summary>Bounds expansion and verifies the complete gzip trailer, including truncated-trailer cases.</summary>
    private static async Task DecodeAsync(MemoryStream archive, Stream destination, CancellationToken cancellationToken)
    {
        if (archive.Length < 18)
        {
            throw new InvalidDataException("The gzip archive is incomplete.");
        }
        byte[] encoded = archive.GetBuffer();
        int trailer = checked((int)archive.Length) - 8;
        uint expectedCrc = BinaryPrimitives.ReadUInt32LittleEndian(encoded.AsSpan(trailer, 4));
        uint expectedLength = BinaryPrimitives.ReadUInt32LittleEndian(encoded.AsSpan(trailer + 4, 4));
        if (encoded[0] != 0x1f || encoded[1] != 0x8b || encoded[2] != 8)
        {
            throw new InvalidDataException("Expected gzip data using the deflate compression method.");
        }

        using var gzip = new GZipStream(archive, CompressionMode.Decompress, leaveOpen: true);
        var checksum = new Crc32();
        byte[] buffer = new byte[64 * 1024];
        int total = 0;
        while (true)
        {
            int count = await gzip.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (count == 0)
            {
                break;
            }
            if (count > GeoIpFileLimits.MaximumDatabaseBytes - total)
            {
                throw new InvalidDataException("The decoded GeoIP database exceeds 64 MiB.");
            }
            checksum.Append(buffer.AsSpan(0, count));
            await destination.WriteAsync(buffer.AsMemory(0, count), cancellationToken).ConfigureAwait(false);
            total += count;
        }

        if (total == 0 || expectedLength != total || checksum.GetCurrentHashAsUInt32() != expectedCrc)
        {
            throw new InvalidDataException("The gzip checksum or complete decoded length does not match its trailer.");
        }
    }
}
