namespace IPGuard.Windows.Filtering;

/// <summary>Exposes the WFP operations needed by a block baseline and prototype permit lease.</summary>
/// <remarks>A session belongs to one owner and must not be used concurrently or shared between leases.</remarks>
public interface IWfpSession : IDisposable
{
    /// <summary>Gets whether objects added to this session disappear when it closes.</summary>
    bool IsDynamic { get; }

    /// <summary>Resolves an executable path through the operating system's application ID API.</summary>
    byte[] GetApplicationId(string executablePath);

    /// <summary>Starts a consistent read snapshot or an atomic write transaction.</summary>
    void BeginTransaction(bool readOnly);

    /// <summary>Creates missing owned containers and rejects incompatible existing objects.</summary>
    void EnsurePolicyOwner();

    /// <summary>Checks the provider and sublayer without creating or changing objects.</summary>
    bool HasPolicyOwner();

    /// <summary>Detects either owned container, including partial or disabled installations, for pristine-namespace checks.</summary>
    bool HasPolicyContainers();

    /// <summary>Adds a missing block or verifies that an existing filter matches it exactly.</summary>
    void EnsureBlock(WfpBlockRule rule);

    /// <summary>Checks the complete stored filter definition, including its enabled state.</summary>
    bool IsBlockPresent(WfpBlockRule rule);

    /// <summary>Adds and verifies a non-persistent soft permit above the matching baseline block.</summary>
    void AddPermitFor(WfpBlockRule baseline);

    /// <summary>Validates existing containers and every related filter before returning removable baseline blocks.</summary>
    /// <remarks>Call within an explicit write transaction. Rejects active permits and unknown or conflicting objects; does not resolve executable paths.</remarks>
    IReadOnlyList<WfpBlockRule> GetBlocksForUninstall();

    /// <summary>Deletes a verified baseline block if present and confirms its absence.</summary>
    void RemoveBlock(WfpBlockRule rule);

    /// <summary>Deletes verified owned sublayer and provider, rejecting any remaining references.</summary>
    void RemovePolicyOwner();

    /// <summary>Commits the current transaction or throws when its result is not confirmed.</summary>
    void CommitTransaction();

    /// <summary>Aborts the current transaction or reports a rollback failure.</summary>
    void AbortTransaction();
}
