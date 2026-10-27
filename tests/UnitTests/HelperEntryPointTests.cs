using IPGuard.Desktop;
using Xunit;

namespace UnitTests;

/// <summary>Checks safe helper rejection without initializing GUI, acquiring production ownership, or elevating.</summary>
public sealed class HelperEntryPointTests
{
    /// <summary>Unknown command lines return an argument failure without entering the GUI.</summary>
    [Theory]
    [InlineData("--unknown")]
    [InlineData("--helper")]
    [InlineData("--allow")]
    public async Task InvalidArgumentsHaveExplicitExitCode(string argument)
        => Assert.Equal(2, await HelperEntryPoint.RunAsync([argument]));

    /// <summary>The ordinary test process cannot be used as a trusted privileged helper installation.</summary>
    [Fact]
    public async Task UninstalledHostNeverReachesPolicyStartup()
        => Assert.Equal(3, await HelperEntryPoint.RunAsync(["--helper", "--pipe",
            "IPGuard.Control.0123456789abcdef0123456789abcdef", "--parent", "42"]));

    /// <summary>The executable dispatcher does not ignore unsupported helper arguments or open a GUI for them.</summary>
    [Fact]
    public void ExecutableRejectsUnknownMode()
        => Assert.Equal(2, Program.Main(["--unknown"]));
}
