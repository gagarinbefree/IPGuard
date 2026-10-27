using IPGuard.Application.Protection;

namespace IPGuard.Windows.Filtering;

/// <summary>Adapts persistent WFP blocks and strict readback without exposing permit or uninstall operations.</summary>
public sealed class WindowsBlockPolicy : IBlockPolicy
{
    private readonly IReadOnlyList<string> paths;
    private readonly WfpBlockPolicy policy;

    /// <summary>Validates and privately copies the configured PowerShell scope without opening WFP.</summary>
    public WindowsBlockPolicy(IEnumerable<string> executablePaths, WfpBlockPolicy? policy = null)
    {
        paths = WfpPowerShellScope.ValidatePaths(executablePaths);
        this.policy = policy ?? new WfpBlockPolicy();
    }

    /// <summary>Installs the persistent baseline on a worker; cancellation cannot interrupt an executing native transaction.</summary>
    public Task EnsureAsync(CancellationToken cancellationToken) => Task.Run(() =>
    {
        cancellationToken.ThrowIfCancellationRequested();
        policy.Install(paths);
        cancellationToken.ThrowIfCancellationRequested();
    }, cancellationToken);

    /// <summary>Inspects enabled required blocks and rejects related permits or unknown objects on a worker.</summary>
    public Task<BlockPolicyInspection> InspectAsync(CancellationToken cancellationToken) => Task.Run(() =>
    {
        cancellationToken.ThrowIfCancellationRequested();
        var result = policy.InspectBlockOnly(paths);
        cancellationToken.ThrowIfCancellationRequested();
        var state = result.State switch
        {
            WfpBaselineState.Present => BlockPolicyState.Present,
            WfpBaselineState.Incomplete => BlockPolicyState.Incomplete,
            _ => BlockPolicyState.Unknown
        };
        Exception? error = result.Failure;
        if (error is null && result.Error is not null) error = new InvalidOperationException(result.Error);
        return new BlockPolicyInspection(state, result.ExpectedRules, result.MatchingRules, error);
    }, cancellationToken);
}
