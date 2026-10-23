using IPGuard.Windows.Filtering;
using Xunit;

namespace IntegrationTests;

/// <summary>Exercises the real filename-to-App-ID API without creating filters or changing policy.</summary>
public sealed class WfpApplicationIdTests
{
    /// <summary>Repeated and case-varied Windows paths resolve to the same opaque identity.</summary>
    [Fact]
    public void ReadApplicationId_IsStableForWindowsPowerShell()
    {
        string path = Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe");
        Assert.True(File.Exists(path));

        byte[] first = NativeWfpSession.ReadApplicationId(path);
        byte[] second = NativeWfpSession.ReadApplicationId(path.ToUpperInvariant());

        Assert.NotEmpty(first);
        Assert.Equal(first, second);
        first[0] ^= 0xff;
        Assert.NotEqual(first, NativeWfpSession.ReadApplicationId(path));
    }
}
