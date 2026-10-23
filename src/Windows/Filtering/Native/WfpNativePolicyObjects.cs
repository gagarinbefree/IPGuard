using System.Runtime.InteropServices;

namespace IPGuard.Windows.Filtering.Native;

/// <summary>Serializes and verifies IPGuard's persistent policy containers.</summary>
internal static class WfpNativePolicyObjects
{
    /// <summary>Creates a persistent provider without a service association.</summary>
    internal static NativeProvider CreateProvider(NativeMemoryScope memory) => new()
    {
        Key = WfpPolicyIds.Provider,
        DisplayData = new NativeDisplayData { Name = memory.Text(WfpPolicyIds.DisplayName) },
        Flags = WfpPolicyIds.Persistent,
        ProviderData = memory.Blob(WfpPolicyIds.OwnerMarker)
    };

    /// <summary>Creates the owned persistent sublayer at the prototype's arbitration weight.</summary>
    internal static NativeSubLayer CreateSubLayer(NativeMemoryScope memory) => new()
    {
        Key = WfpPolicyIds.SubLayer,
        DisplayData = new NativeDisplayData { Name = memory.Text(WfpPolicyIds.DisplayName) },
        Flags = WfpPolicyIds.Persistent,
        ProviderKey = memory.Structure(WfpPolicyIds.Provider),
        ProviderData = memory.Blob(WfpPolicyIds.OwnerMarker),
        Weight = WfpPolicyIds.SubLayerWeight
    };

    /// <summary>Rejects disabled providers, incompatible versions, and unexpected service ownership.</summary>
    internal static bool Matches(NativeProvider provider) =>
        provider.Key == WfpPolicyIds.Provider && provider.Flags == WfpPolicyIds.Persistent &&
        provider.ServiceName == 0 && WfpNativeFilter.BlobEquals(provider.ProviderData, WfpPolicyIds.OwnerMarker);

    /// <summary>Rejects sublayers with a different owner, persistence, schema marker, or weight.</summary>
    internal static bool Matches(NativeSubLayer layer) =>
        layer.Key == WfpPolicyIds.SubLayer && layer.Flags == WfpPolicyIds.Persistent &&
        layer.ProviderKey != 0 && Marshal.PtrToStructure<Guid>(layer.ProviderKey) == WfpPolicyIds.Provider &&
        layer.Weight == WfpPolicyIds.SubLayerWeight && WfpNativeFilter.BlobEquals(layer.ProviderData, WfpPolicyIds.OwnerMarker);
}
