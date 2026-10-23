using Xunit;
using Xunit.Sdk;

namespace IntegrationTests.WfpVm;

/// <summary>Checks every VM authorization condition without reading real privilege state or changing policy.</summary>
public sealed class WfpVmGateTests
{
    /// <summary>All explicit confirmations and an elevated Windows x64 token allow the callback once.</summary>
    [Fact]
    public void Run_RequiresCompleteAuthorization()
    {
        var settings = AuthorizedSettings();
        int operations = 0;
        int privilegeChecks = 0;

        WfpVmGate.Run(settings.GetValueOrDefault, "VM-IPGUARD", true, () =>
        {
            privilegeChecks++;
            return true;
        }, () => operations++);

        Assert.Equal(1, operations);
        Assert.Equal(1, privilegeChecks);
    }

    /// <summary>No missing or malformed environment condition can reach elevation checks or mutations.</summary>
    [Theory]
    [InlineData("IPGUARD_WFP_VM_ENABLE", null)]
    [InlineData("IPGUARD_WFP_VM_ENABLE", "true")]
    [InlineData("IPGUARD_WFP_VM_ENABLE", "0")]
    [InlineData("IPGUARD_WFP_VM_CONFIRMATION", null)]
    [InlineData("IPGUARD_WFP_VM_CONFIRMATION", "yes")]
    [InlineData("IPGUARD_WFP_VM_MACHINE", null)]
    [InlineData("IPGUARD_WFP_VM_MACHINE", "ANOTHER-MACHINE")]
    [InlineData("IPGUARD_WFP_VM_SNAPSHOT", null)]
    [InlineData("IPGUARD_WFP_VM_SNAPSHOT", " ")]
    [InlineData("IPGUARD_WFP_VM_RESULTS", null)]
    [InlineData("IPGUARD_WFP_VM_RESULTS", "relative-results")]
    [InlineData("GITHUB_ACTIONS", "true")]
    [InlineData("CI", "true")]
    public void Run_InvalidSettingsNeverReachTheCallback(string name, string? value)
    {
        var settings = AuthorizedSettings();
        settings[name] = value;
        bool checkedPrivileges = false;
        bool mutated = false;

        var error = CaptureSkip(() => WfpVmGate.Run(settings.GetValueOrDefault, "VM-IPGUARD", true, () =>
        {
            checkedPrivileges = true;
            return true;
        }, () => mutated = true));

        Assert.Contains("WFP VM", error.Message);
        Assert.False(checkedPrivileges);
        Assert.False(mutated);
    }

    /// <summary>Administrative membership alone never authorizes tests on another platform.</summary>
    [Fact]
    public void Run_RejectsUnsupportedPlatformsBeforeCheckingPrivileges()
    {
        var settings = AuthorizedSettings();
        bool checkedPrivileges = false;

        CaptureSkip(() => WfpVmGate.Run(settings.GetValueOrDefault, "VM-IPGUARD", false, () =>
        {
            checkedPrivileges = true;
            return true;
        }, () => Assert.Fail("An unsupported host must not reach WFP.")));

        Assert.False(checkedPrivileges);
    }

    /// <summary>An unprivileged token cannot reach a policy operation even with explicit VM confirmation.</summary>
    [Fact]
    public void Run_RejectsMissingElevation()
    {
        var settings = AuthorizedSettings();

        var error = CaptureSkip(() => WfpVmGate.Run(settings.GetValueOrDefault, "VM-IPGUARD", true, () => false,
            () => Assert.Fail("An unprivileged token must not reach WFP.")));

        Assert.Contains("administrator", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>A privilege-query error produces an explicit denial rather than proceeding.</summary>
    [Fact]
    public void Run_PrivilegeFailureDeniesTheOperation()
    {
        var settings = AuthorizedSettings();

        var error = CaptureSkip(() => WfpVmGate.Run(settings.GetValueOrDefault, "VM-IPGUARD", true,
            () => throw new InvalidOperationException("token unavailable"), () => Assert.Fail("An unknown token must not reach WFP.")));

        Assert.Contains("token unavailable", error.Message);
    }

    /// <summary>Windows machine-name matching accepts case differences without accepting another machine.</summary>
    [Fact]
    public void Run_MatchesMachineNamesIgnoringCase()
    {
        var settings = AuthorizedSettings();
        bool ran = false;

        WfpVmGate.Run(settings.GetValueOrDefault, "vm-ipguard", true, () => true, () => ran = true);

        Assert.True(ran);
    }

    /// <summary>A failing policy callback is reported as a failed test and is never converted into a skip.</summary>
    [Fact]
    public void Run_DoesNotHideOperationErrors()
    {
        var settings = AuthorizedSettings();
        var failure = new InvalidOperationException("native policy failure");

        Assert.Same(failure, Assert.Throws<InvalidOperationException>(() =>
            WfpVmGate.Run(settings.GetValueOrDefault, "VM-IPGUARD", true, () => true, () => throw failure)));
    }

    /// <summary>Captures a skip for assertions; xUnit assertion helpers deliberately propagate dynamic skips.</summary>
    private static SkipException CaptureSkip(Action operation)
    {
        try
        {
            operation();
        }
        catch (SkipException error)
        {
            return error;
        }

        throw new InvalidOperationException("The VM gate unexpectedly allowed this operation.");
    }

    /// <summary>Creates test-only confirmations without modifying process environment variables.</summary>
    private static Dictionary<string, string?> AuthorizedSettings() => new()
    {
        [WfpVmGate.EnableVariable] = "1",
        [WfpVmGate.ConfirmationVariable] = WfpVmGate.Confirmation,
        [WfpVmGate.MachineVariable] = "VM-IPGUARD",
        [WfpVmGate.SnapshotVariable] = "Before-IPGuard",
        [WfpVmGate.ResultsVariable] = @"C:\VmResults"
    };
}
