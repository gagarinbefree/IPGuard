using System.Runtime.InteropServices;

namespace IPGuard.Windows.Filtering.Native;

/// <summary>Translates and verifies application-scoped blocks and prototype soft permits.</summary>
internal static class WfpNativeFilter
{
    private const uint UInt64Type = 4;
    private const uint ByteBlobType = 12;

    /// <summary>Copies a verified owned block, ignoring unrelated filters and rejecting unsafe related objects.</summary>
    internal static WfpBlockRule? GetBlockForUninstall(NativeFilter filter)
    {
        bool ownedProvider = filter.ProviderKey != 0 && Marshal.PtrToStructure<Guid>(filter.ProviderKey) == WfpPolicyIds.Provider;
        if (!ownedProvider && filter.SubLayerKey != WfpPolicyIds.SubLayer)
        {
            return null;
        }

        if (!WfpPolicyIds.Layers.Contains(filter.LayerKey) || filter.ConditionCount != 1 || filter.Conditions == 0)
        {
            throw UninstallConflict(filter.Key);
        }

        var condition = Marshal.PtrToStructure<NativeCondition>(filter.Conditions);
        if (condition.FieldKey != WfpPolicyIds.ApplicationId || condition.MatchType != 0 ||
            condition.Value.Type != ByteBlobType || condition.Value.Pointer == 0)
        {
            throw UninstallConflict(filter.Key);
        }

        byte[] applicationId = WfpNativeApplicationId.Copy(Marshal.PtrToStructure<NativeBlob>(condition.Value.Pointer));
        Guid key = WfpPowerShellScope.CreateKey(filter.LayerKey, applicationId);
        var rule = new WfpBlockRule(key, filter.LayerKey, applicationId);
        if (!MatchesForUninstall(filter, rule))
        {
            throw UninstallConflict(filter.Key);
        }

        return rule;
    }

    /// <summary>Allows only the disabled-state bit in addition to the exact persistent block schema.</summary>
    internal static bool MatchesForUninstall(NativeFilter filter, WfpBlockRule rule)
    {
        filter.Flags &= ~0x20u;
        return Matches(filter, rule);
    }

    /// <summary>Reports related filters that must not be deleted by this schema's uninstaller.</summary>
    private static InvalidOperationException UninstallConflict(Guid key) =>
        new($"WFP filter {key} is not a verified baseline block. Close permit owners and resolve unknown policy objects before uninstall.");

    /// <summary>Builds a non-persistent soft permit with a distinct session-owned key.</summary>
    internal static NativeFilter CreatePermit(WfpBlockRule baseline, Guid permitKey, NativeMemoryScope memory)
    {
        var filter = Create(baseline, memory);
        filter.Key = permitKey;
        filter.Flags = 0;
        filter.DisplayData.Name = memory.Text("IPGuard temporary permit prototype");
        filter.Weight = new NativeValue { Type = UInt64Type, Pointer = memory.Structure(WfpPolicyIds.PermitWeight) };
        filter.Action = new NativeAction { Type = WfpPolicyIds.Permit };
        return filter;
    }

    /// <summary>Verifies a session-owned soft permit independently of its baseline's key.</summary>
    internal static bool MatchesPermit(NativeFilter filter, WfpBlockRule baseline, Guid permitKey) =>
        filter.Key == permitKey && filter.Flags == 0 &&
        MatchesAction(filter, WfpPolicyIds.Permit, WfpPolicyIds.PermitWeight) && MatchesScope(filter, baseline);

    /// <summary>Builds an application-scoped persistent block with scope-owned pointers.</summary>
    internal static NativeFilter Create(WfpBlockRule rule, NativeMemoryScope memory)
    {
        var condition = new NativeCondition
        {
            FieldKey = WfpPolicyIds.ApplicationId,
            Value = new NativeValue { Type = ByteBlobType, Pointer = memory.Structure(memory.Blob(rule.ApplicationId.Span)) }
        };
        return new NativeFilter
        {
            Key = rule.Key,
            DisplayData = new NativeDisplayData { Name = memory.Text(WfpPolicyIds.DisplayName) },
            Flags = WfpPolicyIds.Persistent,
            ProviderKey = memory.Structure(WfpPolicyIds.Provider),
            ProviderData = memory.Blob(WfpPolicyIds.OwnerMarker),
            LayerKey = rule.LayerKey,
            SubLayerKey = WfpPolicyIds.SubLayer,
            Weight = new NativeValue { Type = UInt64Type, Pointer = memory.Structure(WfpPolicyIds.BlockWeight) },
            ConditionCount = 1,
            Conditions = memory.Structure(condition),
            Action = new NativeAction { Type = WfpPolicyIds.Block }
        };
    }

    /// <summary>Rejects filters whose action, ownership, persistence, weight, or conditions differ.</summary>
    internal static bool Matches(NativeFilter filter, WfpBlockRule rule) =>
        filter.Key == rule.Key && filter.Flags == WfpPolicyIds.Persistent &&
        MatchesAction(filter, WfpPolicyIds.Block, WfpPolicyIds.BlockWeight) && MatchesScope(filter, rule);

    /// <summary>Verifies a terminating action and its exact explicit arbitration weight.</summary>
    private static bool MatchesAction(NativeFilter filter, uint action, ulong weight) =>
        filter.Action.Type == action && filter.Action.Key == Guid.Empty &&
        filter.Weight.Type == UInt64Type && filter.Weight.Pointer != 0 &&
        Marshal.ReadInt64(filter.Weight.Pointer) == (long)weight;

    /// <summary>Requires the common owner, ALE scope, zero context, and single application equality condition.</summary>
    private static bool MatchesScope(NativeFilter filter, WfpBlockRule rule)
    {
        if (filter.ProviderKey == 0 || Marshal.PtrToStructure<Guid>(filter.ProviderKey) != WfpPolicyIds.Provider ||
            !BlobEquals(filter.ProviderData, WfpPolicyIds.OwnerMarker) ||
            filter.LayerKey != rule.LayerKey || filter.SubLayerKey != WfpPolicyIds.SubLayer ||
            filter.Context.Low != 0 || filter.Context.High != 0 ||
            filter.ConditionCount != 1 || filter.Conditions == 0)
        {
            return false;
        }

        var condition = Marshal.PtrToStructure<NativeCondition>(filter.Conditions);
        return condition.FieldKey == WfpPolicyIds.ApplicationId && condition.MatchType == 0 &&
            condition.Value.Type == ByteBlobType && condition.Value.Pointer != 0 &&
            BlobEquals(Marshal.PtrToStructure<NativeBlob>(condition.Value.Pointer), rule.ApplicationId.Span);
    }

    /// <summary>Compares an API-owned blob without interpreting the opaque application identity.</summary>
    internal static bool BlobEquals(NativeBlob blob, ReadOnlySpan<byte> expected)
    {
        if (blob.Size != expected.Length || blob.Data == 0)
        {
            return false;
        }

        byte[] actual = new byte[expected.Length];
        Marshal.Copy(blob.Data, actual, 0, actual.Length);
        return expected.SequenceEqual(actual);
    }
}
