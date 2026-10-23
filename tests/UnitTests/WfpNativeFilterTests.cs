using System.Runtime.InteropServices;
using IPGuard.Windows.Filtering;
using IPGuard.Windows.Filtering.Native;
using Xunit;

namespace UnitTests;

/// <summary>Checks x64 ABI compatibility and rejects unsafe native filter definitions.</summary>
public sealed class WfpNativeFilterTests
{
    /// <summary>The layouts follow the x64 Windows SDK rather than managed field packing guesses.</summary>
    [Fact]
    public void NativeTypes_MatchWindowsX64Abi()
    {
        Assert.Equal(8, IntPtr.Size);
        Assert.Equal(16, Marshal.SizeOf<NativeBlob>());
        Assert.Equal(16, Marshal.SizeOf<NativeValue>());
        Assert.Equal(40, Marshal.SizeOf<NativeCondition>());
        Assert.Equal(200, Marshal.SizeOf<NativeFilter>());
        Assert.Equal(64, Marshal.SizeOf<NativeProvider>());
        Assert.Equal(72, Marshal.SizeOf<NativeSubLayer>());
        Assert.Equal(72, Marshal.SizeOf<NativeSession>());
        Assert.Equal(120, Marshal.OffsetOf<NativeFilter>(nameof(NativeFilter.Conditions)).ToInt32());
        Assert.Equal(152, Marshal.OffsetOf<NativeFilter>(nameof(NativeFilter.Context)).ToInt32());
        Assert.Equal(176, Marshal.OffsetOf<NativeFilter>(nameof(NativeFilter.Id)).ToInt32());
    }

    /// <summary>Marshalling produces a persistent block that can be verified from returned native memory.</summary>
    [Fact]
    public void Create_ProducesAnApplicationScopedBlock()
    {
        using var memory = new NativeMemoryScope();
        var rule = CreateRule();

        var filter = WfpNativeFilter.Create(rule, memory);

        Assert.Equal(1u, filter.Flags);
        Assert.Equal(0x1001u, filter.Action.Type);
        Assert.Equal(1u, filter.ConditionCount);
        var condition = Marshal.PtrToStructure<NativeCondition>(filter.Conditions);
        Assert.Equal(new Guid("d78e1e87-8644-4ea5-9437-d809ecefc971"), condition.FieldKey);
        Assert.Equal(0u, condition.MatchType);
        Assert.True(WfpNativeFilter.Matches(filter, rule));
    }

    /// <summary>A same-key filter is insufficient if any security-relevant field is different.</summary>
    [Theory]
    [InlineData("disabled")]
    [InlineData("temporary")]
    [InlineData("permit")]
    [InlineData("provider")]
    [InlineData("marker")]
    [InlineData("layer")]
    [InlineData("sublayer")]
    [InlineData("weight")]
    [InlineData("no-condition")]
    [InlineData("wrong-app")]
    [InlineData("not-equal")]
    [InlineData("wrong-field")]
    [InlineData("wrong-value-type")]
    [InlineData("action-key")]
    public void Matches_RejectsChangedSecurityFields(string change)
    {
        using var memory = new NativeMemoryScope();
        var rule = CreateRule();
        var filter = WfpNativeFilter.Create(rule, memory);
        var condition = Marshal.PtrToStructure<NativeCondition>(filter.Conditions);
        switch (change)
        {
            case "disabled": filter.Flags |= 0x20; break;
            case "temporary": filter.Flags = 0; break;
            case "permit": filter.Action.Type = 0x1002; break;
            case "provider": filter.ProviderKey = memory.Structure(Guid.NewGuid()); break;
            case "marker": filter.ProviderData = memory.Blob([9]); break;
            case "layer": filter.LayerKey = Guid.NewGuid(); break;
            case "sublayer": filter.SubLayerKey = Guid.NewGuid(); break;
            case "weight": filter.Weight.Pointer = memory.Structure(100UL); break;
            case "no-condition": filter.ConditionCount = 0; break;
            case "wrong-app": condition.Value.Pointer = memory.Structure(memory.Blob([8, 9, 10, 11])); break;
            case "not-equal": condition.MatchType = 1; break;
            case "wrong-field": condition.FieldKey = Guid.NewGuid(); break;
            case "wrong-value-type": condition.Value.Type = 0; break;
            case "action-key": filter.Action.Key = Guid.NewGuid(); break;
        }

        Marshal.StructureToPtr(condition, filter.Conditions, fDeleteOld: false);

        Assert.False(WfpNativeFilter.Matches(filter, rule));
    }

    /// <summary>Creates an opaque test identity without reading files or calling the filter engine.</summary>
    private static WfpBlockRule CreateRule() => new(Guid.NewGuid(), WfpPolicyIds.Layers[0], new byte[] { 1, 2, 3, 4 });
}
