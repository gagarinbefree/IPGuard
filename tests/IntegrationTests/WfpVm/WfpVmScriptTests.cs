using System.Diagnostics;
using Xunit;

namespace IntegrationTests.WfpVm;

/// <summary>Checks that launching the VM script without confirmations cannot enable a mutating test run.</summary>
public sealed class WfpVmScriptTests
{
    /// <summary>Missing command-line confirmations are rejected before creating results or invoking dotnet.</summary>
    [Fact]
    public async Task Script_RejectsMissingConfirmations()
    {
        var start = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe"))
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        start.ArgumentList.Add("-NoProfile");
        start.ArgumentList.Add("-NonInteractive");
        start.ArgumentList.Add("-ExecutionPolicy");
        start.ArgumentList.Add("Bypass");
        start.ArgumentList.Add("-File");
        start.ArgumentList.Add(Path.Combine(AppContext.BaseDirectory, "Test-WfpVm.ps1"));
        start.Environment[WfpVmGate.EnableVariable] = "0";
        using var process = Process.Start(start) ?? throw new InvalidOperationException("The script process could not be started.");
        var output = process.StandardOutput.ReadToEndAsync(TestContext.Current.CancellationToken);
        var error = process.StandardError.ReadToEndAsync(TestContext.Current.CancellationToken);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(20));
        try
        {
            await process.WaitForExitAsync(deadline.Token);
        }
        catch
        {
            process.Kill(entireProcessTree: true);
            throw;
        }

        Assert.NotEqual(0, process.ExitCode);
        Assert.Contains("ConfirmIsolatedVm", await output + await error);
    }
}
