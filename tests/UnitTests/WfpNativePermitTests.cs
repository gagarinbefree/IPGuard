using System.Runtime.InteropServices;
using IPGuard.Windows.Filtering;
using IPGuard.Windows.Filtering.Native;
using Xunit;

namespace UnitTests;

/// <summary>Checks dynamic-session flags and native soft-permit definitions without writing policy.</summary>
public sealed class WfpNativePermitTests
{
    /// <summary>Only the permit owner uses FWPM_SESSION_FLAG_DYNAMIC.</summary>
    [Theory]
    [InlineData(false, 0u)]
    [InlineData(true, 1u)]
    public void SessionSettings_SelectTheRequiredObjectLifetime(bool dynamic, uint flags)
    {
        using var memory = new NativeMemoryScope();

        var settings = NativeWfpSession.CreateSettings(dynamic, memory);

        Assert.Equal(flags, settings.Flags);
        Assert.Equal(5_000u, settings.TransactionWaitMilliseconds);
        Assert.NotEqual(0, settings.DisplayData.Name);
    }

    /// <summary>The permit has its own key, no persistence or hard-permit flags, and outranks only its own baseline.</summary>
    [Fact]
    public void CreatePermit_IsTemporaryAndUsesTheBaselineScope()
    {
        using var memory = new NativeMemoryScope();
        var baseline = CreateBaseline();
        Guid key = Guid.NewGuid();

        var filter = WfpNativeFilter.CreatePermit(baseline, key, memory);

        Assert.Equal(key, filter.Key);
        Assert.NotEqual(baseline.Key, filter.Key);
        Assert.Equal(0u, filter.Flags);
        Assert.Equal(0x1002u, filter.Action.Type);
        Assert.Equal(baseline.LayerKey, filter.LayerKey);
        Assert.Equal(WfpPolicyIds.SubLayer, filter.SubLayerKey);
        Assert.True(Marshal.ReadInt64(filter.Weight.Pointer) > (long)WfpPolicyIds.BlockWeight);
        Assert.True(WfpNativeFilter.MatchesPermit(filter, baseline, key));
        Assert.False(WfpNativeFilter.Matches(filter, baseline));
    }

    /// <summary>A permit readback must reject permanent permissions, stronger rights, or changed scope.</summary>
    [Theory]
    [InlineData("persistent")]
    [InlineData("boot")]
    [InlineData("hard-permit")]
    [InlineData("disabled")]
    [InlineData("block")]
    [InlineData("key")]
    [InlineData("weight")]
    [InlineData("application")]
    public void MatchesPermit_RejectsUnsafeChanges(string change)
    {
        using var memory = new NativeMemoryScope();
        var baseline = CreateBaseline();
        Guid key = Guid.NewGuid();
        var filter = WfpNativeFilter.CreatePermit(baseline, key, memory);
        switch (change)
        {
            case "persistent": filter.Flags = 1; break;
            case "boot": filter.Flags = 2; break;
            case "hard-permit": filter.Flags = 8; break;
            case "disabled": filter.Flags = 0x20; break;
            case "block": filter.Action.Type = 0x1001; break;
            case "key": filter.Key = Guid.NewGuid(); break;
            case "weight": filter.Weight.Pointer = memory.Structure(WfpPolicyIds.BlockWeight); break;
            case "application":
                var condition = Marshal.PtrToStructure<NativeCondition>(filter.Conditions);
                condition.Value.Pointer = memory.Structure(memory.Blob([9, 8, 7, 6]));
                Marshal.StructureToPtr(condition, filter.Conditions, fDeleteOld: false);
                break;
        }

        Assert.False(WfpNativeFilter.MatchesPermit(filter, baseline, key));
    }

    /// <summary>Creates a baseline identity without accessing executable files or the network.</summary>
    private static WfpBlockRule CreateBaseline() => new(Guid.NewGuid(), WfpPolicyIds.Layers[0], new byte[] { 1, 2, 3, 4 });
}
