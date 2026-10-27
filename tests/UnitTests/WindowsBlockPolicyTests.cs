using System.ComponentModel;
using IPGuard.Application.Protection;
using IPGuard.Windows.Filtering;
using Xunit;

namespace UnitTests;

/// <summary>Exercises the real Windows adapter through fake WFP sessions without touching host policy.</summary>
public sealed class WindowsBlockPolicyTests
{
    /// <summary>The adapter privately owns its scope and uses strict block-only readback.</summary>
    [Fact]
    public async Task ScopeIsCopiedAndReadbackScansForPermits()
    {
        var paths = new List<string> { @"C:\Tools\pwsh.exe" };
        var session = new WfpBlockPolicyTests.RecordingSession();
        var adapter = new WindowsBlockPolicy(paths, new WfpBlockPolicy(() => session));
        paths.Clear();
        Assert.Empty(session.Events);
        await adapter.EnsureAsync(TestContext.Current.CancellationToken);
        var result = await adapter.InspectAsync(TestContext.Current.CancellationToken);
        Assert.Equal(BlockPolicyState.Present, result.State);
        Assert.Equal(4, result.ExpectedRules);
        Assert.Equal(4, result.MatchingRules);
        Assert.Null(result.Error);
        Assert.Contains("scan-blocks", session.Events);
    }

    /// <summary>Pre-cancelled operations must not open WFP sessions.</summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task PreCancellationDoesNotOpenSession(bool ensure)
    {
        var opens = 0;
        var adapter = new WindowsBlockPolicy([@"C:\Tools\pwsh.exe"], new WfpBlockPolicy(() =>
        {
            opens++;
            return new WfpBlockPolicyTests.RecordingSession();
        }));
        using var caller = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        caller.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => ensure ? adapter.EnsureAsync(caller.Token) : adapter.InspectAsync(caller.Token));
        Assert.Equal(0, opens);
    }

    /// <summary>Original access errors survive strict inspection instead of becoming successful block reports.</summary>
    [Fact]
    public async Task InspectionRetainsNativeFailure()
    {
        var session = new WfpBlockPolicyTests.RecordingSession { FailAt = "scan-blocks" };
        var adapter = new WindowsBlockPolicy([@"C:\Tools\pwsh.exe"], new WfpBlockPolicy(() => session));
        var result = await adapter.InspectAsync(TestContext.Current.CancellationToken);
        Assert.Equal(BlockPolicyState.Unknown, result.State);
        Assert.IsType<Win32Exception>(result.Error);
    }

    /// <summary>Cancellation after native commit propagates without deleting the committed persistent baseline.</summary>
    [Fact]
    public async Task CancellationAfterCommitKeepsBlocks()
    {
        using var caller = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        var session = new WfpBlockPolicyTests.RecordingSession();
        session.BeforeOperation = operation => { if (operation == "commit") caller.Cancel(); };
        var adapter = new WindowsBlockPolicy([@"C:\Tools\pwsh.exe"], new WfpBlockPolicy(() => session));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => adapter.EnsureAsync(caller.Token));
        Assert.Equal(4, session.Stored.Count);
    }

    /// <summary>The adapter rejects invalid executable scope before any native operation is possible.</summary>
    [Theory]
    [InlineData("pwsh.exe")]
    [InlineData(@"C:\Tools\curl.exe")]
    public void InvalidScopeIsRejected(string path)
        => Assert.Throws<ArgumentException>(() => new WindowsBlockPolicy([path]));
}
