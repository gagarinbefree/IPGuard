using System.Security.AccessControl;
using System.Security.Principal;
using System.Runtime.Versioning;

namespace IPGuard.Windows.Filtering;

/// <summary>Restricts ownership objects to enabled administrators and LocalSystem without repairing foreign descriptors.</summary>
[SupportedOSPlatform("windows")]
internal static class PolicyMutexSecurity
{
    private static readonly SecurityIdentifier Administrators = new(WellKnownSidType.BuiltinAdministratorsSid, null);
    private static readonly SecurityIdentifier SystemAccount = new(WellKnownSidType.LocalSystemSid, null);

    /// <summary>Creates a protected DACL and Administrators owner for a new runtime ownership mutex.</summary>
    internal static MutexSecurity Create()
    {
        var security = new MutexSecurity();
        security.SetOwner(Administrators);
        security.SetAccessRuleProtection(true, false);
        security.AddAccessRule(new MutexAccessRule(Administrators, MutexRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new MutexAccessRule(SystemAccount, MutexRights.FullControl, AccessControlType.Allow));
        return security;
    }

    /// <summary>Rejects untrusted ownership, inherited/null/extra ACEs, or any access beyond the exact trusted schema.</summary>
    internal static void Validate(byte[] descriptor)
    {
        ArgumentNullException.ThrowIfNull(descriptor);
        var security = new RawSecurityDescriptor(descriptor, 0);
        var required = ControlFlags.DiscretionaryAclPresent | ControlFlags.DiscretionaryAclProtected;
        if (security.Owner != Administrators || (security.ControlFlags & required) != required ||
            security.DiscretionaryAcl is not { Count: 2 } acl)
            throw new UnauthorizedAccessException("Untrusted policy ownership descriptor.");

        var remaining = new HashSet<SecurityIdentifier> { Administrators, SystemAccount };
        foreach (GenericAce entry in acl)
        {
            if (entry is not CommonAce ace || ace.IsCallback || ace.AceQualifier != AceQualifier.AccessAllowed ||
                ace.AceFlags != AceFlags.None || ace.AccessMask != (int)MutexRights.FullControl ||
                !remaining.Remove(ace.SecurityIdentifier))
                throw new UnauthorizedAccessException("Unexpected policy ownership access rule.");
        }
    }
}
