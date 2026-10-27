using System.ComponentModel;
using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace IPGuard.Windows.Control;

/// <summary>Defines GUI-logon and elevated-helper data access without granting clients new-instance rights.</summary>
[SupportedOSPlatform("windows")]
internal sealed class ControlPipeSecurity
{
    private static readonly SecurityIdentifier Network = new(WellKnownSidType.NetworkSid, null);
    private static readonly SecurityIdentifier Administrators = new(WellKnownSidType.BuiltinAdministratorsSid, null);
    private readonly SecurityIdentifier user;
    private readonly SecurityIdentifier logon;

    /// <summary>Captures the expected user and logon identities for descriptor validation.</summary>
    internal ControlPipeSecurity(SecurityIdentifier user, SecurityIdentifier logon)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(logon);
        if (!logon.IsWellKnown(WellKnownSidType.LogonIdsSid))
            throw new ArgumentException("A logon SID is required.", nameof(logon));
        this.user = user;
        this.logon = logon;
    }

    /// <summary>Reads the current token's user and unique logon SID, rejecting unavailable identities.</summary>
    internal static ControlPipeSecurity Current()
    {
        using var identity = WindowsIdentity.GetCurrent(TokenAccessLevels.Query);
        return FromIdentity(identity);
    }

    /// <summary>Uses the expected GUI process's logon SID, allowing linked elevated tokens to have a different logon.</summary>
    internal static ControlPipeSecurity ForServer(Process expectedServer)
    {
        const uint tokenQuery = 8;
        var opened = OpenProcessToken(expectedServer.SafeHandle, tokenQuery, out var token);
        var error = opened ? 0 : Marshal.GetLastWin32Error();
        using (token)
        {
            if (!opened) throw new Win32Exception(error);
            using var identity = new WindowsIdentity(token.DangerousGetHandle());
            using var caller = WindowsIdentity.GetCurrent(TokenAccessLevels.Query);
            if (identity.User != caller.User)
                throw new UnauthorizedAccessException("Control IPC requires the expected server and client to use the same account.");
            return FromIdentity(identity);
        }
    }

    /// <summary>Copies the user and exact logon identity while its token handle remains alive.</summary>
    private static ControlPipeSecurity FromIdentity(WindowsIdentity identity)
    {
        if (identity.User is not { } user)
            throw new UnauthorizedAccessException("A current user identity is required for control IPC.");
        return new(user, ControlLogonSid.Read(identity.AccessToken));
    }

    /// <summary>Denies network access and grants data rights only to the GUI logon and enabled administrators.</summary>
    internal PipeSecurity Create()
    {
        var security = new PipeSecurity();
        security.SetOwner(user);
        security.SetAccessRuleProtection(true, false);
        security.AddAccessRule(new PipeAccessRule(Network, PipeAccessRights.FullControl, AccessControlType.Deny));
        security.AddAccessRule(new PipeAccessRule(logon, PipeAccessRights.ReadWrite, AccessControlType.Allow));
        // Linked UAC tokens need not share a logon SID; the expected elevated client's enabled Administrators SID suffices.
        security.AddAccessRule(new PipeAccessRule(Administrators, PipeAccessRights.ReadWrite, AccessControlType.Allow));
        return security;
    }

    /// <summary>Rejects foreign owners, wider access, missing protection, or a different logon session.</summary>
    internal void Validate(byte[] descriptor)
    {
        ArgumentNullException.ThrowIfNull(descriptor);
        var raw = new RawSecurityDescriptor(descriptor, 0);
        var required = ControlFlags.DiscretionaryAclPresent | ControlFlags.DiscretionaryAclProtected;
        if (raw.Owner != user || (raw.ControlFlags & required) != required || raw.DiscretionaryAcl is not { Count: 3 } acl ||
            !Matches(acl[0], Network, AceQualifier.AccessDenied, (int)PipeAccessRights.FullControl))
            throw new UnauthorizedAccessException("Untrusted control pipe descriptor.");
        var remaining = new HashSet<SecurityIdentifier> { logon, Administrators };
        var rights = (int)(PipeAccessRights.ReadWrite | PipeAccessRights.Synchronize);
        for (var index = 1; index < acl.Count; index++)
        {
            if (acl[index] is not CommonAce ace || !remaining.Remove(ace.SecurityIdentifier) ||
                !Matches(ace, ace.SecurityIdentifier, AceQualifier.AccessAllowed, rights))
                throw new UnauthorizedAccessException("Unexpected control pipe data access rule.");
        }
    }

    /// <summary>Checks one explicit non-callback ACE without accepting wider or inherited rights.</summary>
    private static bool Matches(GenericAce entry, SecurityIdentifier sid, AceQualifier qualifier, int rights)
        => entry is CommonAce ace && !ace.IsCallback && ace.AceFlags == AceFlags.None &&
            ace.SecurityIdentifier == sid && ace.AceQualifier == qualifier && ace.AccessMask == rights;

    /// <summary>Opens the retained expected process token for read-only identity inspection.</summary>
    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(SafeProcessHandle process, uint desiredAccess, out SafeAccessTokenHandle token);
}
