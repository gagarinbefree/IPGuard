using System.Runtime.Versioning;
using System.Security.AccessControl;
using IPGuard.Windows.Filtering;
using Xunit;

namespace UnitTests;

/// <summary>Checks the trusted mutex schema using descriptors in memory, without opening production objects.</summary>
[SupportedOSPlatform("windows")]
public sealed class PolicyMutexSecurityTests
{
    /// <summary>The generated schema permits only Administrators and LocalSystem and protects its DACL.</summary>
    [Fact]
    public void GeneratedDescriptorIsAccepted()
    {
        var security = PolicyMutexSecurity.Create();
        PolicyMutexSecurity.Validate(security.GetSecurityDescriptorBinaryForm());
        Assert.True(security.AreAccessRulesProtected);
    }

    /// <summary>Existing unsafe objects must be rejected without rewriting their descriptors.</summary>
    [Theory]
    [InlineData("O:SYD:P(A;;0x1f0001;;;SY)(A;;0x1f0001;;;BA)")]
    [InlineData("O:BAD:(A;;0x1f0001;;;SY)(A;;0x1f0001;;;BA)")]
    [InlineData("O:BAD:P(A;;0x1f0001;;;WD)(A;;0x1f0001;;;BA)")]
    [InlineData("O:BAD:P(A;;0x100001;;;SY)(A;;0x1f0001;;;BA)")]
    [InlineData("O:BAD:P(A;;0x1f0001;;;SY)(A;;0x1f0001;;;BA)(A;;0x1f0001;;;WD)")]
    [InlineData("O:BAD:P(D;;0x1f0001;;;SY)(A;;0x1f0001;;;BA)")]
    [InlineData("O:BAD:P(A;CI;0x1f0001;;;SY)(A;;0x1f0001;;;BA)")]
    public void UnsafeDescriptorIsRejected(string sddl)
    {
        var raw = new RawSecurityDescriptor(sddl);
        var bytes = new byte[raw.BinaryLength];
        raw.GetBinaryForm(bytes, 0);
        var original = bytes.ToArray();
        Assert.Throws<UnauthorizedAccessException>(() => PolicyMutexSecurity.Validate(bytes));
        Assert.Equal(original, bytes);
    }
}
