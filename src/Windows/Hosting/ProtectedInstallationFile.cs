using Microsoft.Win32.SafeHandles;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace IPGuard.Windows.Hosting;

/// <summary>Reads installation metadata from an opened object rather than a second path lookup.</summary>
internal static class ProtectedInstallationFile
{
    /// <summary>Opens a non-reparse file or directory without allowing replacement while the handle is retained.</summary>
    internal static SafeFileHandle Open(string path, bool directory)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Windows installation security is required.");
        const uint readControlAndAttributes = 0x20080;
        const uint genericRead = 0x80000000;
        const uint openReparsePointAndBackupSemantics = 0x02200000;
        // Directory writers may coexist; validated ACLs protect children. Omitting share-delete pins the path chain.
        var handle = CreateFileW(path, directory ? readControlAndAttributes : genericRead,
            directory ? 3u : 1u, 0, 3, openReparsePointAndBackupSemantics, 0);
        if (handle.IsInvalid)
        {
            var error = Marshal.GetLastWin32Error(); handle.Dispose(); throw new Win32Exception(error);
        }
        try
        {
            if (!GetFileInformationByHandle(handle, out var info)) throw new Win32Exception(Marshal.GetLastWin32Error());
            ValidateMetadata((FileAttributes)info.Attributes, info.Links, directory);
            return handle;
        }
        catch { handle.Dispose(); throw; }
    }
    /// <summary>Reads the owner and DACL associated with the retained object.</summary>
    internal static byte[] ReadSecurity(SafeFileHandle handle)
    {
        uint result = GetSecurityInfo(handle, 1, 5, out _, out _, out _, out _, out var descriptor);
        try
        {
            if (result != 0) throw new Win32Exception(unchecked((int)result));
            if (descriptor == 0) throw new InvalidDataException("Windows returned no installation security descriptor.");
            uint length = GetSecurityDescriptorLength(descriptor);
            if (length is 0 or > 65536) throw new InvalidDataException("Unexpected installation security descriptor size.");
            var bytes = new byte[length];
            Marshal.Copy(descriptor, bytes, 0, bytes.Length);
            return bytes;
        }
        finally { if (descriptor != 0) LocalFree(descriptor); }
    }
    /// <summary>Rejects reparse objects, wrong object kinds, and multiply linked files.</summary>
    internal static void ValidateMetadata(FileAttributes attributes, uint links, bool directory)
    {
        if (attributes.HasFlag(FileAttributes.ReparsePoint) || attributes.HasFlag(FileAttributes.Directory) != directory ||
            (!directory && links != 1))
            throw new UnauthorizedAccessException("Installation objects must be non-reparse directories or single-link files.");
    }

    /// <summary>Matches the Windows BY_HANDLE_FILE_INFORMATION layout used for attributes and hard-link counts.</summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct FileInformation
    {
        internal uint Attributes;
        internal System.Runtime.InteropServices.ComTypes.FILETIME Created;
        internal System.Runtime.InteropServices.ComTypes.FILETIME Accessed;
        internal System.Runtime.InteropServices.ComTypes.FILETIME Written;
        internal uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
    }

    /// <summary>Opens metadata or read-only data with explicit sharing and no reparse traversal.</summary>
    [DllImport("kernel32.dll", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string path, uint access, uint share, nint security, uint creation, uint flags, nint template);
    /// <summary>Reads metadata for the actual retained object.</summary>
    [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out FileInformation information);
    /// <summary>Allocates the actual file-object owner and DACL descriptor using Windows security APIs.</summary>
    [DllImport("advapi32.dll", ExactSpelling = true)]
    private static extern uint GetSecurityInfo(SafeFileHandle handle, uint objectType, uint information,
        out nint owner, out nint group, out nint dacl, out nint sacl, out nint descriptor);
    /// <summary>Reads the self-relative descriptor size before copying it into managed memory.</summary>
    [DllImport("advapi32.dll", ExactSpelling = true)]
    private static extern uint GetSecurityDescriptorLength(nint descriptor);
    /// <summary>Releases memory allocated by GetSecurityInfo.</summary>
    [DllImport("kernel32.dll", ExactSpelling = true)]
    private static extern nint LocalFree(nint memory);
}
