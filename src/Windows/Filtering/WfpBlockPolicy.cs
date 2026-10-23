using System.Security.Cryptography;

namespace IPGuard.Windows.Filtering;

/// <summary>Installs and inspects a block baseline without providing an allow mode.</summary>
public sealed class WfpBlockPolicy
{
    private readonly Func<IWfpSession> _openSession;

    /// <summary>Selects Windows WFP; no native session is opened until an operation is requested.</summary>
    public WfpBlockPolicy() : this(NativeWfpSession.Open)
    {
    }

    /// <summary>Accepts a factory that creates a separately owned session for every operation.</summary>
    public WfpBlockPolicy(Func<IWfpSession> openSession)
    {
        ArgumentNullException.ThrowIfNull(openSession);
        _openSession = openSession;
    }

    /// <summary>Installs all required blocks atomically; failures must not leave partial changes.</summary>
    public void Install(IEnumerable<string> executablePaths)
    {
        var paths = ValidatePaths(executablePaths);
        using var session = _openSession();
        var rules = CreateRules(session, paths);
        WfpTransaction.Run(session, readOnly: false, () =>
        {
            session.EnsurePolicyOwner();
            foreach (var rule in rules)
            {
                session.EnsureBlock(rule);
            }
        });
    }

    /// <summary>Reads object presence without interpreting it as verified traffic blocking.</summary>
    public WfpBaselineInspection Inspect(IEnumerable<string> executablePaths)
    {
        var paths = ValidatePaths(executablePaths);
        int expected = paths.Count * WfpPolicyIds.Layers.Length;
        try
        {
            using var session = _openSession();
            var rules = CreateRules(session, paths);
            expected = rules.Count;
            bool ownerPresent = false;
            int matching = 0;
            WfpTransaction.Run(session, readOnly: true, () =>
            {
                ownerPresent = session.HasPolicyOwner();
                foreach (var rule in rules)
                {
                    if (session.IsBlockPresent(rule))
                    {
                        matching++;
                    }
                }
            });
            var state = ownerPresent && matching == expected ? WfpBaselineState.Present : WfpBaselineState.Incomplete;
            return new WfpBaselineInspection(state, expected, matching);
        }
        catch (Exception error)
        {
            return new WfpBaselineInspection(WfpBaselineState.Unknown, expected, 0, error.Message);
        }
    }

    /// <summary>Rejects empty scope, relative paths, and executables outside the PowerShell contract.</summary>
    private static IReadOnlyList<string> ValidatePaths(IEnumerable<string> executablePaths)
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
    private static IReadOnlyList<WfpBlockRule> CreateRules(IWfpSession session, IReadOnlyList<string> paths)
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
