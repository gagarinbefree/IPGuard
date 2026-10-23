using System.Runtime.InteropServices;

namespace IPGuard.Windows.Filtering.Native;

/// <summary>Copies opaque application IDs before their API-owned memory is released.</summary>
internal static class WfpNativeApplicationId
{
    /// <summary>Rejects absent or oversized identities before copying their bytes into managed memory.</summary>
    internal static byte[] Copy(NativeBlob blob)
    {
        if (blob.Size == 0 || blob.Size > 65_536 || blob.Data == 0)
        {
            throw new InvalidOperationException("Windows returned an invalid application ID blob.");
        }

        byte[] applicationId = new byte[checked((int)blob.Size)];
        Marshal.Copy(blob.Data, applicationId, 0, applicationId.Length);
        return applicationId;
    }
}
