using System.Runtime.ExceptionServices;

namespace IPGuard.Windows.Filtering;

/// <summary>Owns prototype permits until its dynamic session is closed.</summary>
/// <remarks>For isolated VM experiments only, with one owner and no concurrent calls. It does not validate routes, expire grants, or prove traffic enforcement.</remarks>
public sealed class WfpPermitLease : IDisposable
{
    private IWfpSession? _session;
    private Exception? _closeFailure;

    /// <summary>Takes ownership only after the entire grant has committed.</summary>
    private WfpPermitLease(IWfpSession session) => _session = session;

    /// <summary>Gets whether closing this lease's session has completed successfully.</summary>
    public bool IsClosed => _session is null;

    /// <summary>Creates prototype permits in a new native dynamic session.</summary>
    public static WfpPermitLease Open(IEnumerable<string> executablePaths) => Open(executablePaths, NativeWfpSession.OpenDynamic);

    /// <summary>Accepts a separately owned dynamic session factory for deterministic tests.</summary>
    public static WfpPermitLease Open(IEnumerable<string> executablePaths, Func<IWfpSession> openSession)
    {
        ArgumentNullException.ThrowIfNull(openSession);
        var paths = WfpPowerShellScope.ValidatePaths(executablePaths);
        var session = openSession();
        try
        {
            if (!session.IsDynamic)
            {
                throw new InvalidOperationException("Temporary permits require a dynamic WFP session.");
            }

            var rules = WfpPowerShellScope.CreateRules(session, paths);
            WfpTransaction.Run(session, readOnly: false, () =>
            {
                RequireBaseline(session, rules);
                foreach (var rule in rules)
                {
                    session.AddPermitFor(rule);
                }
            });
            return new WfpPermitLease(session);
        }
        catch (Exception operationError)
        {
            try
            {
                session.Dispose();
            }
            catch (Exception closeError)
            {
                throw new AggregateException("The WFP grant failed and session closure is unconfirmed.", operationError, closeError);
            }

            throw;
        }
    }

    /// <summary>Closes only this lease's session; an error leaves closure unconfirmed.</summary>
    /// <remarks>Later calls rethrow a previous close error without reusing the uncertain native handle.</remarks>
    public void Dispose()
    {
        if (_closeFailure is not null)
        {
            ExceptionDispatchInfo.Throw(_closeFailure);
        }

        if (_session is null)
        {
            return;
        }

        try
        {
            _session.Dispose();
        }
        catch (Exception error)
        {
            _closeFailure = error;
            throw;
        }

        _session = null;
    }

    /// <summary>Requires every owned block in the same write transaction before adding any permit.</summary>
    private static void RequireBaseline(IWfpSession session, IReadOnlyList<WfpBlockRule> rules)
    {
        if (!session.HasPolicyOwner())
        {
            throw new InvalidOperationException("The owned WFP block baseline is missing.");
        }

        foreach (var rule in rules)
        {
            if (!session.IsBlockPresent(rule))
            {
                throw new InvalidOperationException($"WFP block {rule.Key} is absent, disabled, or incompatible.");
            }
        }
    }
}
