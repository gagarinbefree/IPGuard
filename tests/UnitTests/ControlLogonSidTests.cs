using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;
using IPGuard.Windows.Control;
using Xunit;

namespace UnitTests;

/// <summary>Checks native token parsing with owned memory instead of altering Windows identities.</summary>
[SupportedOSPlatform("windows")]
public sealed class ControlLogonSidTests
{
    /// <summary>A single enabled logon SID is copied independently of the native buffer lifetime.</summary>
    [Fact]
    public void ValidLogonSidIsCopied()
    {
        using var buffer = new TokenBuffer();
        Assert.Equal(new SecurityIdentifier("S-1-5-5-0-123"), ControlLogonSid.Parse(buffer.Pointer, buffer.Length));
    }

    /// <summary>Ambiguous groups, foreign pointers, malformed SIDs, and insufficient rights never become an identity.</summary>
    [Theory]
    [InlineData("count")]
    [InlineData("before")]
    [InlineData("after")]
    [InlineData("truncated")]
    [InlineData("disabled")]
    [InlineData("deny")]
    [InlineData("notLogon")]
    [InlineData("sid")]
    public void InvalidTokenBufferIsRejected(string change)
    {
        using var buffer = new TokenBuffer();
        var length = buffer.Length;
        if (change == "count") Marshal.WriteInt32(buffer.Pointer, 2);
        if (change == "before") Marshal.WriteIntPtr(buffer.Pointer, IntPtr.Size, buffer.Pointer);
        if (change == "after") Marshal.WriteIntPtr(buffer.Pointer, IntPtr.Size, buffer.Pointer + buffer.Length);
        if (change == "truncated") length--;
        if (change == "disabled") Marshal.WriteInt32(buffer.Pointer, IntPtr.Size * 2, unchecked((int)0xc0000000));
        if (change == "deny") Marshal.WriteInt32(buffer.Pointer, IntPtr.Size * 2, unchecked((int)0xc0000014));
        if (change == "notLogon") Marshal.WriteInt32(buffer.Pointer, IntPtr.Size * 2, 4);
        if (change == "sid") Marshal.WriteByte(buffer.Pointer, IntPtr.Size * 3, 0);
        Assert.Throws<InvalidDataException>(() => ControlLogonSid.Parse(buffer.Pointer, length));
    }

    /// <summary>Owns one synthetic TOKEN_GROUPS header and an inline logon SID.</summary>
    private sealed class TokenBuffer : IDisposable
    {
        /// <summary>Builds the documented pointer-aligned single-group representation.</summary>
        internal TokenBuffer()
        {
            var sid = new SecurityIdentifier("S-1-5-5-0-123");
            var bytes = new byte[sid.BinaryLength];
            sid.GetBinaryForm(bytes, 0);
            Length = IntPtr.Size * 3 + bytes.Length;
            Pointer = Marshal.AllocHGlobal(Length);
            Marshal.Copy(new byte[Length], 0, Pointer, Length);
            Marshal.WriteInt32(Pointer, 1);
            Marshal.WriteIntPtr(Pointer, IntPtr.Size, Pointer + IntPtr.Size * 3);
            Marshal.WriteInt32(Pointer, IntPtr.Size * 2, unchecked((int)0xc0000007));
            Marshal.Copy(bytes, 0, Pointer + IntPtr.Size * 3, bytes.Length);
        }
        /// <summary>Gets the test-owned native buffer address.</summary>
        internal nint Pointer { get; }
        /// <summary>Gets the full header and SID size in bytes.</summary>
        internal int Length { get; }
        /// <summary>Releases only this fixture's allocation.</summary>
        public void Dispose() => Marshal.FreeHGlobal(Pointer);
    }
}
