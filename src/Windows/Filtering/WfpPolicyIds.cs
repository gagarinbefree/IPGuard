namespace IPGuard.Windows.Filtering;

/// <summary>Owns the prototype's identifiers and persistent block specification.</summary>
internal static class WfpPolicyIds
{
    internal static readonly Guid Provider = new("d0a56bb8-9945-44d0-aa1f-703b4faaf0be");
    internal static readonly Guid SubLayer = new("7ae517a7-b2f6-4a23-a040-e28ba7987de2");
    internal static readonly Guid ApplicationId = new("d78e1e87-8644-4ea5-9437-d809ecefc971");
    internal static readonly Guid[] Layers =
    [
        new("c38d57d1-05a7-4c33-904f-7fbceee60e82"),
        new("4a72393b-319f-44bc-84c3-ba54dcb3b6b4"),
        new("e1cd9fe7-f4b5-4273-96c0-592e487b8650"),
        new("a3b42c97-9f04-4672-b87e-cee9c483257f")
    ];
    internal static readonly byte[] OwnerMarker = "IPGuard.Wfp.BlockBaseline.v1"u8.ToArray();
    internal const string DisplayName = "IPGuard block baseline prototype";
    internal const uint Persistent = 1;
    internal const uint Block = 0x1001;
    internal const uint Permit = 0x1002;
    internal const ulong BlockWeight = 10;
    internal const ulong PermitWeight = 20;
    internal const ushort SubLayerWeight = 0x8000;
}
