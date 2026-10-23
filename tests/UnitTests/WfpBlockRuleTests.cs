using IPGuard.Windows.Filtering;
using Xunit;

namespace UnitTests;

/// <summary>Checks that malformed rule identities cannot reach the native filter builder.</summary>
public sealed class WfpBlockRuleTests
{
    /// <summary>Missing keys, unsupported layers, and empty application IDs are rejected.</summary>
    [Theory]
    [InlineData("key")]
    [InlineData("layer")]
    [InlineData("application")]
    public void Constructor_RejectsInvalidIdentity(string invalid)
    {
        Guid key = invalid == "key" ? Guid.Empty : Guid.NewGuid();
        Guid layer = invalid == "layer" ? Guid.Empty : WfpPolicyIds.Layers[0];
        byte[] application = invalid == "application" ? [] : [1, 2];

        Assert.ThrowsAny<ArgumentException>(() => new WfpBlockRule(key, layer, application));
    }

    /// <summary>Later changes to the source buffer do not change an already planned rule.</summary>
    [Fact]
    public void Constructor_CopiesTheApplicationIdentity()
    {
        byte[] identity = [1, 2, 3];
        var rule = new WfpBlockRule(Guid.NewGuid(), WfpPolicyIds.Layers[0], identity);
        identity[0] = 9;

        Assert.Equal(new byte[] { 1, 2, 3 }, rule.ApplicationId.ToArray());
    }
}
