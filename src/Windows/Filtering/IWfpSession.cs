namespace IPGuard.Windows.Filtering;

/// <summary>Exposes the WFP operations needed by a persistent block baseline.</summary>
/// <remarks>A session belongs to one operation and must not be shared between callers.</remarks>
public interface IWfpSession : IDisposable
{
    /// <summary>Resolves an executable path through the operating system's application ID API.</summary>
    byte[] GetApplicationId(string executablePath);

    /// <summary>Starts a consistent read snapshot or an atomic write transaction.</summary>
    void BeginTransaction(bool readOnly);

    /// <summary>Creates missing owned containers and rejects incompatible existing objects.</summary>
    void EnsurePolicyOwner();

    /// <summary>Checks the provider and sublayer without creating or changing objects.</summary>
    bool HasPolicyOwner();

    /// <summary>Adds a missing block or verifies that an existing filter matches it exactly.</summary>
    void EnsureBlock(WfpBlockRule rule);

    /// <summary>Checks the complete stored filter definition, including its enabled state.</summary>
    bool IsBlockPresent(WfpBlockRule rule);

    /// <summary>Commits the current transaction or throws when its result is not confirmed.</summary>
    void CommitTransaction();

    /// <summary>Aborts the current transaction or reports a rollback failure.</summary>
    void AbortTransaction();
}
