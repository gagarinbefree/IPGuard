using System.Runtime.Versioning;
using System.Security.AccessControl;

namespace IPGuard.Windows.Hosting;

/// <summary>Rejects writable or replaceable installation objects without attempting ACL repair.</summary>
[SupportedOSPlatform("windows")]
internal static class InstallationSecurity
{
    private static readonly HashSet<string> Trusted = ["S-1-5-18", "S-1-5-32-544",
        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"];

    /// <summary>Checks ownership and effective non-inherit-only grants; ancestors need replacement protection.</summary>
    internal static void Validate(byte[] descriptor, bool ancestor)
    {
        var raw = new RawSecurityDescriptor(descriptor, 0);
        if (raw.Owner is null || !Trusted.Contains(raw.Owner.Value) || raw.DiscretionaryAcl is null ||
            !raw.ControlFlags.HasFlag(ControlFlags.DiscretionaryAclPresent))
            throw new UnauthorizedAccessException("Installation ownership or discretionary access is untrusted.");
        const int replacement = 0x10000 | 0x40000 | 0x80000 | 0x40;
        const int writes = 0x2 | 0x4 | 0x10 | 0x100;
        const int genericMutation = unchecked((int)0x50000000); // GENERIC_WRITE and GENERIC_ALL must not bypass specific masks.
        int forbidden = replacement | genericMutation | (ancestor ? 0 : writes);
        foreach (GenericAce entry in raw.DiscretionaryAcl)
        {
            if (entry.AceFlags.HasFlag(AceFlags.InheritOnly)) continue;
            if (entry is not CommonAce ace || ace.IsCallback)
                throw new UnauthorizedAccessException("Unsupported installation access rule.");
            if (ace.AceQualifier == AceQualifier.AccessDenied) continue;
            if (ace.AceQualifier != AceQualifier.AccessAllowed ||
                (!Trusted.Contains(ace.SecurityIdentifier.Value) && (ace.AccessMask & forbidden) != 0))
                throw new UnauthorizedAccessException("Installation grants mutation to an untrusted principal.");
        }
    }
}
