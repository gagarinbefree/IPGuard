using System.ComponentModel;

namespace IPGuard.Windows.Filtering.Native;

/// <summary>Preserves complete WFP and RPC error codes with the failing API name.</summary>
internal static class WfpNativeError
{
    /// <summary>Throws for an unsuccessful DWORD result without consulting GetLastError.</summary>
    internal static void Check(uint result, string operation)
    {
        if (result != 0)
        {
            throw new Win32Exception(unchecked((int)result), $"{operation} failed (0x{result:X8}).");
        }
    }
}
