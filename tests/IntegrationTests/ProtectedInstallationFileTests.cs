using System.Runtime.Versioning;
using System.Security.AccessControl;
using IPGuard.Windows.Hosting;
using Xunit;

namespace IntegrationTests;

/// <summary>Checks read-only native file handles on unique ordinary test files without installing or elevating.</summary>
[SupportedOSPlatform("windows")]
public sealed class ProtectedInstallationFileTests
{
    /// <summary>Metadata refers to the retained file and its sharing contract prevents write or rename until disposal.</summary>
    [Fact]
    public void RetainedFileIsReadOnlyAndCannotBeReplaced()
    {
        string path = Path.Combine(Path.GetTempPath(), $"IPGuard.Tests.{Guid.NewGuid():N}.json");
        File.WriteAllText(path, "original");
        try
        {
            using (var handle = ProtectedInstallationFile.Open(path, false))
            {
                var raw = new RawSecurityDescriptor(ProtectedInstallationFile.ReadSecurity(handle), 0);
                Assert.NotNull(raw.Owner);
                Assert.NotNull(raw.DiscretionaryAcl);
                Assert.Throws<IOException>(() => File.WriteAllText(path, "changed"));
                Assert.Throws<IOException>(() => File.Move(path, path + ".moved"));
                Assert.Equal("original", File.ReadAllText(path));
            }
            File.WriteAllText(path, "after close");
            Assert.Equal("after close", File.ReadAllText(path));
        }
        finally { File.Delete(path); File.Delete(path + ".moved"); }
    }
}
