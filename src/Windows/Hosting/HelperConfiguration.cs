using System.Text.Json;
using System.Text.Json.Serialization;
using IPGuard.Windows.Filtering;

namespace IPGuard.Windows.Hosting;

/// <summary>Contains the block-only helper scope and local diagnostic cadence from a protected file.</summary>
public sealed class HelperConfiguration
{
    internal const int MaximumBytes = 16384;
    /// <summary>Retains a private validated scope and timer interval.</summary>
    private HelperConfiguration(IReadOnlyList<string> paths, TimeSpan interval) { PowerShellPaths = paths; CheckInterval = interval; }
    /// <summary>Gets the immutable explicit PowerShell executable scope.</summary>
    public IReadOnlyList<string> PowerShellPaths { get; }
    /// <summary>Gets the local diagnostic refresh interval.</summary>
    public TimeSpan CheckInterval { get; }
    /// <summary>Reads strict bounded UTF-8 configuration; no defaults silently broaden or narrow the scope.</summary>
    public static HelperConfiguration Parse(ReadOnlySpan<byte> json)
    {
        if (json.Length is 0 or > MaximumBytes) throw new InvalidDataException("Helper configuration must be 1–16384 bytes.");
        try
        {
            var document = JsonSerializer.Deserialize<ConfigurationDocument>(json, new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
                AllowDuplicateProperties = false,
                RespectNullableAnnotations = true,
                MaxDepth = 4
            }) ?? throw new InvalidDataException("Helper configuration is missing.");
            if (document.Version != 1 || document.CheckIntervalSeconds is < 1 or > 3600 ||
                document.PowerShellPaths is not { Length: > 0 and <= 32 })
                throw new InvalidDataException("Unsupported helper configuration version, scope, or interval.");
            // WFP accepts more path forms; privileged configuration deliberately permits only local drive paths.
            foreach (var path in document.PowerShellPaths)
                if (path is null || path.Length < 4 || !char.IsAsciiLetter(path[0]) || path[1] != ':' || path[2] != '\\' ||
                    path.AsSpan(2).Contains(':') || path.Contains('/') || path.Contains("..", StringComparison.Ordinal))
                    throw new InvalidDataException("Helper scope requires ordinary absolute local drive paths.");
            var paths = WfpPowerShellScope.ValidatePaths(document.PowerShellPaths).ToArray();
            if (paths.Length != document.PowerShellPaths.Length)
                throw new InvalidDataException("Duplicate PowerShell paths are not supported.");
            return new(Array.AsReadOnly(paths), TimeSpan.FromSeconds(document.CheckIntervalSeconds));
        }
        catch (Exception error) when (error is JsonException or ArgumentException)
        { throw new InvalidDataException("Invalid helper configuration.", error); }
    }

    /// <summary>Defines the complete version-one helper file schema, separate from future user preferences.</summary>
    private sealed class ConfigurationDocument
    {
        /// <summary>Gets the required supported schema version.</summary>
        public required int Version { get; init; }
        /// <summary>Gets the explicitly installed PowerShell scope.</summary>
        public required string[] PowerShellPaths { get; init; }
        /// <summary>Gets the local diagnostic cadence in whole seconds.</summary>
        public required int CheckIntervalSeconds { get; init; }
    }
}
