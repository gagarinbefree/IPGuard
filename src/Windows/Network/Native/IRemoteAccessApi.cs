namespace IPGuard.Windows.Network.Native;

/// <summary>Separates RAS enumeration and borrowed connection handles from controlled lifecycle tests.</summary>
internal interface IRemoteAccessApi
{
    /// <summary>Enumerates into caller-owned memory; error 603 requests a larger buffer.</summary>
    uint Enumerate(nint buffer, ref uint bytes, out uint count);

    /// <summary>Reads status using a borrowed handle, which this adapter must never close or hang up.</summary>
    uint ReadStatus(nint connection, ref NativeRemoteStatus status);
}
