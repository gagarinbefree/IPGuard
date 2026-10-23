using System.Security.Cryptography;

namespace IPGuard.Windows.Filtering;

/// <summary>Defines the shared PowerShell scope and deterministic baseline identities.</summary>
internal static class WfpPowerShellScope
{
    /// <summary>Rejects empty scope, relative paths, and executables outside the PowerShell contract.</summary>
    internal static IReadOnlyList<string> ValidatePaths(IEnumerable<string> executablePaths)
    {
        ArgumentNullException.ThrowIfNull(executablePaths);
        var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var path in executablePaths)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(path);
            string name = Path.GetFileName(path);
            if (!Path.IsPathFullyQualified(path) ||
                (!name.Equals("pwsh.exe", StringComparison.OrdinalIgnoreCase) &&
                 !name.Equals("powershell.exe", StringComparison.OrdinalIgnoreCase)))
            {
                throw new ArgumentException("Register a full path to powershell.exe or pwsh.exe.", nameof(executablePaths));
            }

            paths.Add(Path.GetFullPath(path));
        }

        if (paths.Count == 0)
        {
            throw new ArgumentException("At least one PowerShell executable is required.", nameof(executablePaths));
        }

        return paths.ToArray();
    }

    /// <summary>Builds stable application and layer identities, merging aliases with the same Windows ID.</summary>
    internal static IReadOnlyList<WfpBlockRule> CreateRules(IWfpSession session, IReadOnlyList<string> paths)
    {
        var rules = new Dictionary<Guid, WfpBlockRule>();
        foreach (var path in paths)
        {
            byte[] applicationId = session.GetApplicationId(path);
            if (applicationId.Length == 0)
            {
                throw new InvalidOperationException("Windows returned an empty application ID.");
            }

            foreach (var layer in WfpPolicyIds.Layers)
            {
                byte[] identity = [.. WfpPolicyIds.Provider.ToByteArray(), .. layer.ToByteArray(), .. applicationId];
                var key = new Guid(SHA256.HashData(identity).AsSpan(0, 16));
                rules.TryAdd(key, new WfpBlockRule(key, layer, applicationId));
            }
        }

        return rules.Values.ToArray();
    }
}
