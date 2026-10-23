using IPGuard.Windows.Filtering;
using IPGuard.Windows.Filtering.Native;
using Xunit;

namespace UnitTests;

/// <summary>Characterizes container ownership independently from native RPC calls.</summary>
public sealed class WfpNativePolicyObjectsTests
{
    /// <summary>New containers are persistent, carry an ownership marker, and do not create a service association.</summary>
    [Fact]
    public void Create_ProducesMatchingOwnedContainers()
    {
        using var memory = new NativeMemoryScope();
        var provider = WfpNativePolicyObjects.CreateProvider(memory);
        var layer = WfpNativePolicyObjects.CreateSubLayer(memory);

        Assert.True(WfpNativePolicyObjects.Matches(provider));
        Assert.True(WfpNativePolicyObjects.Matches(layer));
        Assert.Equal(0, provider.ServiceName);
    }

    /// <summary>Same-key providers are not accepted based solely on their identifier.</summary>
    [Theory]
    [InlineData("key")]
    [InlineData("disabled")]
    [InlineData("temporary")]
    [InlineData("service")]
    [InlineData("marker")]
    public void Provider_RejectsIncompatibleMetadata(string change)
    {
        using var memory = new NativeMemoryScope();
        var provider = WfpNativePolicyObjects.CreateProvider(memory);
        byte[] differentMarker = WfpPolicyIds.OwnerMarker.ToArray();
        differentMarker[0] ^= 0xff;
        switch (change)
        {
            case "key": provider.Key = Guid.NewGuid(); break;
            case "disabled": provider.Flags |= 0x10; break;
            case "temporary": provider.Flags = 0; break;
            case "service": provider.ServiceName = memory.Text("AnotherService"); break;
            case "marker": provider.ProviderData = memory.Blob(differentMarker); break;
        }

        Assert.False(WfpNativePolicyObjects.Matches(provider));
    }

    /// <summary>Every ownership and arbitration field of a same-key sublayer is verified.</summary>
    [Theory]
    [InlineData("key")]
    [InlineData("temporary")]
    [InlineData("provider")]
    [InlineData("missing-provider")]
    [InlineData("weight")]
    [InlineData("marker")]
    public void SubLayer_RejectsIncompatibleMetadata(string change)
    {
        using var memory = new NativeMemoryScope();
        var layer = WfpNativePolicyObjects.CreateSubLayer(memory);
        byte[] differentMarker = WfpPolicyIds.OwnerMarker.ToArray();
        differentMarker[0] ^= 0xff;
        switch (change)
        {
            case "key": layer.Key = Guid.NewGuid(); break;
            case "temporary": layer.Flags = 0; break;
            case "provider": layer.ProviderKey = memory.Structure(Guid.NewGuid()); break;
            case "missing-provider": layer.ProviderKey = 0; break;
            case "weight": layer.Weight = 1; break;
            case "marker": layer.ProviderData = memory.Blob(differentMarker); break;
        }

        Assert.False(WfpNativePolicyObjects.Matches(layer));
    }
}
