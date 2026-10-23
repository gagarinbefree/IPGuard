namespace IPGuard.Windows.Filtering;

/// <summary>Installs, inspects, and explicitly uninstalls a block baseline without providing an allow mode.</summary>
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

    /// <summary>Removes all verified prototype baseline objects atomically, only for explicit uninstallation.</summary>
    /// <remarks>This intentionally removes protection; it is not a transition to the blocked state.</remarks>
    public void Uninstall()
    {
        var session = _openSession();
        WfpCleanup.Run(() =>
        {
            if (session.IsDynamic)
            {
                throw new InvalidOperationException("Uninstall requires a non-dynamic WFP session.");
            }

            WfpTransaction.Run(session, readOnly: false, () =>
            {
                var rules = session.GetBlocksForUninstall();
                foreach (var rule in rules)
                {
                    session.RemoveBlock(rule);
                }

                session.RemovePolicyOwner();
            });
        }, session.Dispose);
    }

    /// <summary>Installs all required blocks atomically; failures must not leave partial changes.</summary>
    public void Install(IEnumerable<string> executablePaths)
    {
        var paths = WfpPowerShellScope.ValidatePaths(executablePaths);
        using var session = _openSession();
        if (session.IsDynamic)
        {
            throw new InvalidOperationException("The persistent block baseline requires a non-dynamic WFP session.");
        }

        var rules = WfpPowerShellScope.CreateRules(session, paths);
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
        var paths = WfpPowerShellScope.ValidatePaths(executablePaths);
        int expected = paths.Count * WfpPolicyIds.Layers.Length;
        try
        {
            using var session = _openSession();
            var rules = WfpPowerShellScope.CreateRules(session, paths);
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
}
