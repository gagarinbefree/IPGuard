using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace IPGuard.Windows.Control;

/// <summary>Reads the logon SID that WindowsIdentity.Groups deliberately excludes.</summary>
[SupportedOSPlatform("windows")]
internal static class ControlLogonSid
{
    private const int TokenLogonSid = 28;
    private const int MaximumBufferSize = 1024;

    /// <summary>Reads TokenLogonSid with bounded caller-owned native storage and preserves native failures.</summary>
    internal static SecurityIdentifier Read(SafeAccessTokenHandle token)
    {
        if (GetTokenInformation(token, TokenLogonSid, 0, 0, out var required))
            throw new InvalidDataException("Unexpected empty token information.");
        var error = Marshal.GetLastWin32Error();
        if (error != 122) throw new Win32Exception(error);
        if (required < IntPtr.Size * 3 || required > MaximumBufferSize)
            throw new InvalidDataException("Unexpected logon token buffer size.");
        var buffer = Marshal.AllocHGlobal((int)required);
        try
        {
            if (!GetTokenInformation(token, TokenLogonSid, buffer, required, out var returned))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            if (returned > required) throw new InvalidDataException("Logon token data exceeds its allocation.");
            return Parse(buffer, (int)returned);
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    /// <summary>Copies a single enabled logon SID only when its header and complete SID stay inside the buffer.</summary>
    internal static SecurityIdentifier Parse(nint buffer, int length)
    {
        // TOKEN_GROUPS aligns its first SID_AND_ATTRIBUTES to pointer width, including trailing structure padding.
        var headerSize = IntPtr.Size * 3;
        if (buffer == 0 || length < headerSize || length > MaximumBufferSize || Marshal.ReadInt32(buffer) != 1)
            throw new InvalidDataException("One complete logon group is required.");
        var attributes = unchecked((uint)Marshal.ReadInt32(buffer, IntPtr.Size * 2));
        const uint requiredAttributes = 0xc0000004; // SE_GROUP_LOGON_ID and SE_GROUP_ENABLED, excluding deny-only.
        if ((attributes & 0xc0000014) != requiredAttributes)
            throw new InvalidDataException("An enabled non-deny-only logon group is required.");
        var offset = (long)Marshal.ReadIntPtr(buffer, IntPtr.Size) - (long)buffer;
        if (offset < headerSize || offset > length - 8)
            throw new InvalidDataException("The logon SID pointer is outside its buffer.");
        var bytes = new byte[length];
        Marshal.Copy(buffer, bytes, 0, length);
        SecurityIdentifier sid;
        try { sid = new SecurityIdentifier(bytes, (int)offset); }
        catch (ArgumentException error) { throw new InvalidDataException("The logon SID is malformed or truncated.", error); }
        if (!sid.IsWellKnown(WellKnownSidType.LogonIdsSid)) throw new InvalidDataException("A logon SID is required.");
        return sid;
    }

    /// <summary>Reads token data into caller-owned storage using TOKEN_QUERY access only.</summary>
    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetTokenInformation(SafeAccessTokenHandle token, int informationClass, nint buffer, uint length, out uint returnedLength);
}
