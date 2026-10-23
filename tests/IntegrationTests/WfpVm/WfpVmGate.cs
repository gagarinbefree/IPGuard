using System.Runtime.InteropServices;
using System.Security.Principal;
using Xunit;

namespace IntegrationTests.WfpVm;

/// <summary>Allows mutating WFP tests only after explicit machine-bound VM authorization.</summary>
internal static class WfpVmGate
{
    internal const string EnableVariable = "IPGUARD_WFP_VM_ENABLE";
    internal const string ConfirmationVariable = "IPGUARD_WFP_VM_CONFIRMATION";
    internal const string MachineVariable = "IPGUARD_WFP_VM_MACHINE";
    internal const string SnapshotVariable = "IPGUARD_WFP_VM_SNAPSHOT";
    internal const string ResultsVariable = "IPGUARD_WFP_VM_RESULTS";
    internal const string Confirmation = "I_CONFIRM_THIS_IS_AN_ISOLATED_VM";

    /// <summary>Evaluates explicit authorization before checking elevation or executing a mutating callback.</summary>
    internal static void Run(Func<string, string?> readEnvironment, string machineName, bool windowsX64, Func<bool> isAdministrator, Action operation)
    {
        if (readEnvironment(EnableVariable) != "1")
        {
            Assert.Skip("WFP VM tests are disabled. Use scripts/Test-WfpVm.ps1 only inside the designated isolated VM.");
        }

        if (readEnvironment("GITHUB_ACTIONS") is not null || readEnvironment("CI") is not null)
        {
            Assert.Skip("WFP VM tests cannot run in CI.");
        }

        if (!windowsX64)
        {
            Assert.Skip("WFP VM tests require Windows x64.");
        }

        if (readEnvironment(ConfirmationVariable) != Confirmation ||
            !string.Equals(readEnvironment(MachineVariable), machineName, StringComparison.OrdinalIgnoreCase))
        {
            Assert.Skip("WFP VM tests require explicit isolated-VM confirmation bound to this machine name.");
        }

        if (string.IsNullOrWhiteSpace(readEnvironment(SnapshotVariable)))
        {
            Assert.Skip("WFP VM tests require confirmation of a restore checkpoint.");
        }

        string? results = readEnvironment(ResultsVariable);
        if (string.IsNullOrWhiteSpace(results) || !Path.IsPathFullyQualified(results))
        {
            Assert.Skip("WFP VM tests require an absolute results directory.");
        }

        bool elevated;
        try
        {
            elevated = isAdministrator();
        }
        catch (Exception error)
        {
            Assert.Skip($"WFP VM administrator check failed: {error.Message}");
            return;
        }

        if (!elevated)
        {
            Assert.Skip("WFP VM tests require an elevated administrator token.");
        }

        operation();
    }

    /// <summary>Reads the current process environment without enabling or changing any setting.</summary>
    internal static void RunCurrent(Action operation) => Run(Environment.GetEnvironmentVariable, Environment.MachineName,
        OperatingSystem.IsWindows() && RuntimeInformation.ProcessArchitecture == Architecture.X64, IsAdministrator, operation);

    /// <summary>Checks the effective Windows token without requesting elevation.</summary>
    private static bool IsAdministrator()
    {
        if (!OperatingSystem.IsWindows())
        {
            return false;
        }

        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }
}
