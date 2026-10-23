using System.Runtime.InteropServices;

namespace IPGuard.Windows.Filtering.Native;

/// <summary>Translates and verifies the complete native block specification.</summary>
internal static class WfpNativeFilter
{
    private const uint UInt64Type = 4;
    private const uint ByteBlobType = 12;

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
    internal static bool Matches(NativeFilter filter, WfpBlockRule rule)
    {
        if (filter.Key != rule.Key || filter.Flags != WfpPolicyIds.Persistent ||
            filter.ProviderKey == 0 || Marshal.PtrToStructure<Guid>(filter.ProviderKey) != WfpPolicyIds.Provider ||
            !BlobEquals(filter.ProviderData, WfpPolicyIds.OwnerMarker) ||
            filter.LayerKey != rule.LayerKey || filter.SubLayerKey != WfpPolicyIds.SubLayer ||
            filter.Action.Type != WfpPolicyIds.Block || filter.Action.Key != Guid.Empty ||
            filter.Context.Low != 0 || filter.Context.High != 0 ||
            filter.Weight.Type != UInt64Type || filter.Weight.Pointer == 0 ||
            Marshal.ReadInt64(filter.Weight.Pointer) != (long)WfpPolicyIds.BlockWeight ||
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
