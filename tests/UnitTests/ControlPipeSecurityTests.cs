using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using IPGuard.Windows.Control;
using Xunit;

namespace UnitTests;

/// <summary>Checks logon isolation and exact pipe access using descriptors in memory.</summary>
[SupportedOSPlatform("windows")]
public sealed class ControlPipeSecurityTests
{
    private const string User = "S-1-5-21-1-2-3-1001";
    private const string Logon = "S-1-5-5-0-123";

    /// <summary>Clients get data access while network tokens and additional server instances are excluded.</summary>
    [Fact]
    public void DescriptorHasOnlyRequiredAccess()
    {
        var schema = Schema();
        var descriptor = schema.Create();
        schema.Validate(descriptor.GetSecurityDescriptorBinaryForm());
        Assert.True(descriptor.AreAccessRulesProtected);
        var rules = descriptor.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<PipeAccessRule>().ToArray();
        Assert.Equal(3, rules.Length);
        var allow = Assert.Single(rules, rule => rule.AccessControlType == AccessControlType.Allow && rule.IdentityReference.Equals(new SecurityIdentifier(Logon)));
        Assert.Equal(new SecurityIdentifier(Logon), allow.IdentityReference);
        Assert.Equal(PipeAccessRights.ReadWrite | PipeAccessRights.Synchronize, allow.PipeAccessRights);
        Assert.Equal((PipeAccessRights)0, allow.PipeAccessRights & PipeAccessRights.CreateNewInstance);
        Assert.Single(rules, rule => rule.AccessControlType == AccessControlType.Deny &&
            rule.IdentityReference.Equals(new SecurityIdentifier(WellKnownSidType.NetworkSid, null)));
        var admin = Assert.Single(rules, rule => rule.AccessControlType == AccessControlType.Allow &&
            rule.IdentityReference.Equals(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null)));
        Assert.Equal(allow.PipeAccessRights, admin.PipeAccessRights);
    }

    /// <summary>A descriptor without the explicit elevated-client data ACE is not the supported channel schema.</summary>
    [Fact]
    public void MissingElevatedClientAccessIsRejected()
    {
        var raw = new RawSecurityDescriptor($"O:{User}D:P(D;;0x1f019f;;;NU)(A;;0x12019b;;;{Logon})");
        var bytes = new byte[raw.BinaryLength];
        raw.GetBinaryForm(bytes, 0);
        Assert.Throws<UnauthorizedAccessException>(() => Schema().Validate(bytes));
    }

    /// <summary>Foreign owners, changed sessions, broad grants, and inherited access cannot pass validation.</summary>
    [Theory]
    [InlineData("owner")]
    [InlineData("logon")]
    [InlineData("network")]
    [InlineData("protection")]
    [InlineData("instance")]
    [InlineData("extra")]
    [InlineData("callback")]
    [InlineData("null")]
    public void UnsafeDescriptorIsRejected(string change)
    {
        var raw = new RawSecurityDescriptor($"O:{User}D:P(D;;0x1f019f;;;NU)(A;;0x12019b;;;{Logon})(A;;0x12019b;;;BA)");
        if (change == "owner") raw.Owner = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        if (change == "logon") raw.DiscretionaryAcl![1] = Allow("S-1-5-5-0-124", 0x12019b);
        if (change == "network") raw.DiscretionaryAcl!.RemoveAce(0);
        if (change == "protection") raw.SetFlags(raw.ControlFlags & ~ControlFlags.DiscretionaryAclProtected);
        if (change == "instance") raw.DiscretionaryAcl![1] = Allow(Logon, 0x12019f);
        if (change == "extra") raw.DiscretionaryAcl!.InsertAce(2, Allow("S-1-1-0", 0x12019b));
        if (change == "callback") raw.DiscretionaryAcl![1] = new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, 0x12019b,
            new SecurityIdentifier(Logon), true, null);
        if (change == "null") raw.DiscretionaryAcl = null;
        var bytes = new byte[raw.BinaryLength];
        raw.GetBinaryForm(bytes, 0);
        var original = bytes.ToArray();
        Assert.Throws<UnauthorizedAccessException>(() => Schema().Validate(bytes));
        Assert.Equal(original, bytes);
    }

    /// <summary>Builds the expected synthetic token schema without reading or changing the real token.</summary>
    private static ControlPipeSecurity Schema() => new(new SecurityIdentifier(User), new SecurityIdentifier(Logon));

    /// <summary>Creates one untrusted ACE for access-widening tests.</summary>
    private static CommonAce Allow(string sid, int mask)
        => new(AceFlags.None, AceQualifier.AccessAllowed, mask, new SecurityIdentifier(sid), false, null);
}
