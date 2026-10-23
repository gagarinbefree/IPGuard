using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using IPGuard.Windows.Filtering;
using IPGuard.Windows.Filtering.Native;

namespace IntegrationTests.WfpVm;

/// <summary>Records actual related filter metadata in read-only transactions during an authorized VM test.</summary>
internal static class WfpVmEvidence
{
    /// <summary>Copies metadata before native page memory is freed and retains session-cleanup failures.</summary>
    internal static void RecordFilters(Action<string> record)
    {
        var session = (NativeWfpSession)NativeWfpSession.Open();
        WfpCleanup.Run(() => ReadSnapshot(session, record), session.Dispose);
    }

    /// <summary>Reads a fresh snapshot in a completed read-only transaction.</summary>
    private static void ReadSnapshot(NativeWfpSession session, Action<string> record) =>
        WfpTransaction.Run(session, readOnly: true, () => session.VisitPolicyFilters(filter => record(DescribeFilter(filter))));

    /// <summary>Serializes scalar fields and decoded conditions while native pointers remain valid.</summary>
    private static string DescribeFilter(NativeFilter filter) => JsonSerializer.Serialize(new
    {
        utc = DateTimeOffset.UtcNow,
        monotonicTicks = Stopwatch.GetTimestamp(),
        phase = "filter-snapshot",
        key = filter.Key,
        layer = filter.LayerKey,
        subLayer = filter.SubLayerKey,
        provider = filter.ProviderKey == 0 ? (Guid?)null : Marshal.PtrToStructure<Guid>(filter.ProviderKey),
        flags = filter.Flags,
        action = filter.Action.Type,
        weight = filter.Weight.Type == 4 && filter.Weight.Pointer != 0 ? (long?)Marshal.ReadInt64(filter.Weight.Pointer) : null,
        conditionCount = filter.ConditionCount,
        condition = ReadCondition(filter)
    });

    /// <summary>Describes the prototype's application condition without logging opaque native pointers.</summary>
    private static object? ReadCondition(NativeFilter filter)
    {
        if (filter.ConditionCount != 1 || filter.Conditions == 0)
        {
            return null;
        }

        var condition = Marshal.PtrToStructure<NativeCondition>(filter.Conditions);
        string? applicationHash = null;
        if (condition.Value.Type == 12 && condition.Value.Pointer != 0)
        {
            byte[] application = WfpNativeApplicationId.Copy(Marshal.PtrToStructure<NativeBlob>(condition.Value.Pointer));
            applicationHash = Convert.ToHexString(SHA256.HashData(application));
        }
        return new { field = condition.FieldKey, match = condition.MatchType, type = condition.Value.Type, applicationHash };
    }
}
