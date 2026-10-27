using IPGuard.Application.Protection;
using System.Buffers.Binary;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace IPGuard.Infrastructure.Control;

/// <summary>Frames strict versioned JSON with bounded lengths over an already authenticated duplex stream.</summary>
public static class ProtectionControlProtocol
{
    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        AllowDuplicateProperties = false,
        RespectRequiredConstructorParameters = true,
        RespectNullableAnnotations = true,
        MaxDepth = 4,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase, allowIntegerValues: false) }
    };

    /// <summary>Writes one supported command without executable paths or configuration fields.</summary>
    public static Task WriteCommandAsync(Stream stream, ProtectionCommand command, CancellationToken cancellationToken)
        => WriteAsync(stream, new CommandFrame
        {
            Version = 1,
            Command = command switch
            {
                ProtectionCommand.Status => "status",
                ProtectionCommand.Recheck => "recheck",
                ProtectionCommand.Stop => "stop",
                _ => throw new ArgumentOutOfRangeException(nameof(command))
            }
        }, 256, cancellationToken);
    /// <summary>Reads one command, rejecting unknown, duplicate, omitted, oversized, or truncated fields.</summary>
    public static async Task<ProtectionCommand> ReadCommandAsync(Stream stream, CancellationToken cancellationToken)
    {
        var frame = await ReadAsync<CommandFrame>(stream, 256, cancellationToken).ConfigureAwait(false);
        if (frame.Version != 1) throw new InvalidDataException("Unsupported control protocol version.");
        return frame.Command switch
        {
            "status" => ProtectionCommand.Status,
            "recheck" => ProtectionCommand.Recheck,
            "stop" => ProtectionCommand.Stop,
            _ => throw new InvalidDataException("Unsupported control command.")
        };
    }
    /// <summary>Writes a diagnostic report without native exceptions or permission flags.</summary>
    public static Task WriteReportAsync(Stream stream, ProtectionControlReport report, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(report);
        return WriteAsync(stream, new ReportFrame { Version = 1, Report = report }, 4096, cancellationToken);
    }
    /// <summary>Reads a validated report and rejects incompatible or malformed data.</summary>
    public static async Task<ProtectionControlReport> ReadReportAsync(Stream stream, CancellationToken cancellationToken)
    {
        var frame = await ReadAsync<ReportFrame>(stream, 4096, cancellationToken).ConfigureAwait(false);
        if (frame.Version != 1 || frame.Report is null) throw new InvalidDataException("Unsupported control report.");
        return frame.Report;
    }

    /// <summary>Checks the unsigned length before allocating and accepts exactly one strict JSON frame.</summary>
    private static async Task<T> ReadAsync<T>(Stream stream, int maximumLength, CancellationToken cancellationToken) where T : class
    {
        var header = new byte[4];
        await stream.ReadExactlyAsync(header, cancellationToken).ConfigureAwait(false);
        var length = BinaryPrimitives.ReadUInt32BigEndian(header);
        if (length == 0 || length > maximumLength) throw new InvalidDataException("Invalid control frame length.");
        var bytes = new byte[(int)length];
        await stream.ReadExactlyAsync(bytes, cancellationToken).ConfigureAwait(false);
        try { return JsonSerializer.Deserialize<T>(bytes, Json) ?? throw new InvalidDataException("A control frame cannot be null."); }
        catch (JsonException error) { throw new InvalidDataException("Malformed control frame.", error); }
        catch (ArgumentException error) { throw new InvalidDataException("Contradictory control report.", error); }
    }

    /// <summary>Serializes a bounded frame completely before writing its header or body.</summary>
    private static async Task WriteAsync<T>(Stream stream, T frame, int maximumLength, CancellationToken cancellationToken)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(frame, Json);
        if (bytes.Length == 0 || bytes.Length > maximumLength) throw new InvalidDataException("Control frame exceeds its maximum size.");
        var header = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(header, (uint)bytes.Length);
        await stream.WriteAsync(header, cancellationToken).ConfigureAwait(false);
        await stream.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Defines the only fields accepted in an incoming command.</summary>
    private sealed class CommandFrame
    {
        /// <summary>Gets the required wire schema version.</summary>
        public required int Version { get; init; }
        /// <summary>Gets one exact supported operation name.</summary>
        public required string Command { get; init; }
    }

    /// <summary>Defines the only fields accepted in a diagnostic reply.</summary>
    private sealed class ReportFrame
    {
        /// <summary>Gets the required wire schema version.</summary>
        public required int Version { get; init; }
        /// <summary>Gets the required validated diagnostic report.</summary>
        public required ProtectionControlReport Report { get; init; }
    }
}
