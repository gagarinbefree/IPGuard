namespace IPGuard.Windows.Filtering;

/// <summary>Identifies one persistent application-specific block at an ALE layer.</summary>
public sealed class WfpBlockRule
{
    /// <summary>Creates a rule and takes an independent copy of its opaque application ID.</summary>
    public WfpBlockRule(Guid key, Guid layerKey, ReadOnlyMemory<byte> applicationId)
    {
        if (key == Guid.Empty)
        {
            throw new ArgumentException("A deterministic non-empty filter key is required.", nameof(key));
        }

        if (!WfpPolicyIds.Layers.Contains(layerKey))
        {
            throw new ArgumentException("The block must use a supported ALE authorization layer.", nameof(layerKey));
        }

        if (applicationId.IsEmpty)
        {
            throw new ArgumentException("An application-scoped block requires an application ID.", nameof(applicationId));
        }

        Key = key;
        LayerKey = layerKey;
        ApplicationId = applicationId.ToArray();
    }

    /// <summary>Gets the deterministic identifier within IPGuard's policy namespace.</summary>
    public Guid Key { get; }

    /// <summary>Gets the ALE authorization layer for this address family and direction.</summary>
    public Guid LayerKey { get; }

    /// <summary>Gets the application ID returned by Windows, rather than a manually encoded path.</summary>
    public ReadOnlyMemory<byte> ApplicationId { get; }
}
