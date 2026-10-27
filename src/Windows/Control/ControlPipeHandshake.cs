namespace IPGuard.Windows.Control;

/// <summary>Exchanges a fixed bounded protocol marker without accepting commands or variable-length data.</summary>
internal static class ControlPipeHandshake
{
    private static readonly byte[] Marker = "IPGuard.Control/1\n"u8.ToArray();

    /// <summary>Reads exactly one supported marker, rejecting truncation and unsupported peers.</summary>
    internal static async Task ReadAsync(Stream stream, CancellationToken cancellationToken)
    {
        var bytes = new byte[Marker.Length];
        await stream.ReadExactlyAsync(bytes, cancellationToken).ConfigureAwait(false);
        if (!bytes.AsSpan().SequenceEqual(Marker)) throw new InvalidDataException("Unsupported control pipe handshake.");
    }

    /// <summary>Writes and flushes the supported marker without taking ownership of the stream.</summary>
    internal static async Task WriteAsync(Stream stream, CancellationToken cancellationToken)
    {
        await stream.WriteAsync(Marker, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }
}
