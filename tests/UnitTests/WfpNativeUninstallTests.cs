using System.Runtime.InteropServices;
using IPGuard.Windows.Filtering;
using IPGuard.Windows.Filtering.Native;
using Xunit;

namespace UnitTests;

/// <summary>Checks removal ownership against native definitions without invoking WFP.</summary>
public sealed class WfpNativeUninstallTests
{
    /// <summary>The persistent identity format remains compatible with already installed version-one blocks.</summary>
    [Fact]
    public void CreateKey_PreservesTheExistingStorageFormat()
    {
        Assert.Equal(new Guid("1953a590-ffba-9da8-a305-827cb25c1ed9"), WfpPowerShellScope.CreateKey(WfpPolicyIds.Layers[0], new byte[] { 1, 2, 3, 4 }));
    }

    /// <summary>Owned blocks can be removed whether enabled or disabled, without treating disabled blocks as enforcement.</summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void GetBlockForUninstall_AcceptsOnlyVerifiedBlocks(bool disabled)
    {
        using var memory = new NativeMemoryScope();
        var rule = CreateRule();
        var filter = WfpNativeFilter.Create(rule, memory);
        if (disabled)
        {
            filter.Flags |= 0x20;
        }

        var result = WfpNativeFilter.GetBlockForUninstall(filter);

        Assert.NotNull(result);
        Assert.Equal(rule.Key, result.Key);
        Assert.Equal(rule.LayerKey, result.LayerKey);
        Assert.Equal(rule.ApplicationId.ToArray(), result.ApplicationId.ToArray());
        Assert.True(WfpNativeFilter.MatchesForUninstall(filter, rule));
        Assert.Equal(!disabled, WfpNativeFilter.Matches(filter, rule));
    }

    /// <summary>Display names and copied markers do not make unrelated provider/sublayer objects removable.</summary>
    [Fact]
    public void GetBlockForUninstall_IgnoresUnrelatedFilters()
    {
        using var memory = new NativeMemoryScope();
        var filter = WfpNativeFilter.Create(CreateRule(), memory);
        filter.ProviderKey = memory.Structure(Guid.NewGuid());
        filter.SubLayerKey = Guid.NewGuid();

        Assert.Null(WfpNativeFilter.GetBlockForUninstall(filter));
    }

    /// <summary>Unknown fields, active permits, and partial ownership must stop the entire uninstall.</summary>
    [Theory]
    [InlineData("key")]
    [InlineData("marker")]
    [InlineData("provider")]
    [InlineData("missing-provider")]
    [InlineData("sublayer")]
    [InlineData("layer")]
    [InlineData("permit")]
    [InlineData("boot")]
    [InlineData("temporary")]
    [InlineData("conditions")]
    [InlineData("field")]
    [InlineData("not-equal")]
    [InlineData("empty-application")]
    [InlineData("application")]
    [InlineData("weight")]
    [InlineData("unknown-flags")]
    public void GetBlockForUninstall_RejectsRelatedConflicts(string change)
    {
        using var memory = new NativeMemoryScope();
        var filter = WfpNativeFilter.Create(CreateRule(), memory);
        var condition = Marshal.PtrToStructure<NativeCondition>(filter.Conditions);
        switch (change)
        {
            case "key": filter.Key = Guid.NewGuid(); break;
            case "marker": filter.ProviderData = memory.Blob([9]); break;
            case "provider": filter.ProviderKey = memory.Structure(Guid.NewGuid()); break;
            case "missing-provider": filter.ProviderKey = 0; break;
            case "sublayer": filter.SubLayerKey = Guid.NewGuid(); break;
            case "layer": filter.LayerKey = Guid.NewGuid(); break;
            case "permit": filter = WfpNativeFilter.CreatePermit(CreateRule(), Guid.NewGuid(), memory); break;
            case "boot": filter.Flags = 2; break;
            case "temporary": filter.Flags = 0; break;
            case "conditions": filter.ConditionCount = 0; break;
            case "field": condition.FieldKey = Guid.NewGuid(); break;
            case "not-equal": condition.MatchType = 1; break;
            case "empty-application": condition.Value.Pointer = memory.Structure(memory.Blob([])); break;
            case "application": condition.Value.Pointer = memory.Structure(memory.Blob([9, 8, 7, 6])); break;
            case "weight": filter.Weight.Pointer = memory.Structure(100UL); break;
            case "unknown-flags": filter.Flags |= 0x40; break;
        }
        if (change != "permit")
        {
            Marshal.StructureToPtr(condition, filter.Conditions, fDeleteOld: false);
        }

        Assert.Throws<InvalidOperationException>(() => WfpNativeFilter.GetBlockForUninstall(filter));
    }

    /// <summary>Snapshot identities remain valid after the native page is released or changed.</summary>
    [Fact]
    public void GetBlockForUninstall_CopiesApplicationBytes()
    {
        using var memory = new NativeMemoryScope();
        var filter = WfpNativeFilter.Create(CreateRule(), memory);
        var condition = Marshal.PtrToStructure<NativeCondition>(filter.Conditions);
        var blob = Marshal.PtrToStructure<NativeBlob>(condition.Value.Pointer);

        var result = WfpNativeFilter.GetBlockForUninstall(filter);
        Marshal.WriteByte(blob.Data, 99);

        Assert.NotNull(result);
        Assert.Equal(new byte[] { 1, 2, 3, 4 }, result.ApplicationId.ToArray());
    }

    /// <summary>A disabled provider remains owned, but unrelated or unknown metadata cannot be deleted.</summary>
    [Fact]
    public void ProviderOwnership_AllowsDisabledStateOnlyForUninstall()
    {
        using var memory = new NativeMemoryScope();
        var provider = WfpNativePolicyObjects.CreateProvider(memory);
        provider.Flags |= 0x10;

        Assert.True(WfpNativePolicyObjects.MatchesForUninstall(provider));
        Assert.False(WfpNativePolicyObjects.Matches(provider));

        provider.ProviderData = memory.Blob([9]);
        Assert.False(WfpNativePolicyObjects.MatchesForUninstall(provider));
        provider = WfpNativePolicyObjects.CreateProvider(memory);
        provider.Flags |= 0x40;
        Assert.False(WfpNativePolicyObjects.MatchesForUninstall(provider));
    }

    /// <summary>Builds a version-one identity independently of any current executable path.</summary>
    private static WfpBlockRule CreateRule()
    {
        byte[] application = [1, 2, 3, 4];
        Guid layer = WfpPolicyIds.Layers[0];
        return new WfpBlockRule(WfpPowerShellScope.CreateKey(layer, application), layer, application);
    }
}
