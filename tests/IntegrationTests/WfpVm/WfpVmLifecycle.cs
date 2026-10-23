using IPGuard.Windows.Filtering;
using System.Text.Json;
using Xunit;

namespace IntegrationTests.WfpVm;

/// <summary>Exercises the prototype object lifecycle only in a pristine, exclusively used VM namespace.</summary>
internal sealed class WfpVmLifecycle
{
    private readonly Func<IWfpSession> _management;
    private readonly Func<IWfpSession> _permits;
    private readonly Action<string> _record;

    /// <summary>Composes real or fake WFP factories and a test-evidence sink.</summary>
    internal WfpVmLifecycle(Func<IWfpSession> management, Func<IWfpSession> permits, Action<string> record)
    {
        _management = management;
        _permits = permits;
        _record = record;
    }

    /// <summary>Tests baseline, permit, revoke, and uninstall; failures retain the baseline for investigation.</summary>
    internal void Run(string executablePath)
    {
        if (HasContainers())
        {
            throw new InvalidOperationException("The VM test requires a pristine IPGuard namespace. Restore its checkpoint before running again.");
        }

        var paths = new[] { executablePath };
        var policy = new WfpBlockPolicy(_management);
        policy.Install(paths);
        RequireBaseline(policy, paths, "baseline-installed");

        var lease = WfpPermitLease.Open(paths, _permits);
        WfpCleanup.Run(() =>
        {
            Assert.False(lease.IsClosed);
            RequireBaseline(policy, paths, "permit-open");
            Assert.Throws<InvalidOperationException>(policy.Uninstall);
            RequireBaseline(policy, paths, "active-permit-refuses-uninstall");
        }, lease.Dispose);

        Assert.True(lease.IsClosed);
        RequireBaseline(policy, paths, "permit-closed");
        policy.Uninstall();
        Assert.False(HasContainers());
        policy.Uninstall();
        Assert.False(HasContainers());
        _record(JsonSerializer.Serialize(new { utc = DateTimeOffset.UtcNow, phase = "complete", scope = "object-lifecycle-only" }));
    }

    /// <summary>Checks either container independently so a partial installation cannot be adopted by the test.</summary>
    private bool HasContainers()
    {
        var session = _management();
        bool present = false;
        WfpCleanup.Run(() => WfpTransaction.Run(session, readOnly: true, () => present = session.HasPolicyContainers()), session.Dispose);
        return present;
    }

    /// <summary>Records object evidence before checking that all four requested baseline rules still match.</summary>
    private void RequireBaseline(WfpBlockPolicy policy, string[] paths, string phase)
    {
        var inspection = policy.Inspect(paths);
        _record(JsonSerializer.Serialize(new
        {
            utc = DateTimeOffset.UtcNow,
            phase,
            state = inspection.State.ToString(),
            expectedRules = inspection.ExpectedRules,
            matchingRules = inspection.MatchingRules,
            error = inspection.Error
        }));
        Assert.Equal(WfpBaselineState.Present, inspection.State);
        Assert.Equal(4, inspection.ExpectedRules);
        Assert.Equal(4, inspection.MatchingRules);
    }
}
