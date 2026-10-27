using IPGuard.Application.Protection;
using IPGuard.Desktop.Lifetime;
using IPGuard.Desktop.ViewModels;
using Xunit;

namespace UnitTests;

/// <summary>Checks asynchronous shell commands without native windows, UAC, or filtering.</summary>
public sealed class ShellProtectionTests
{
    /// <summary>Startup is explicit; a completed command displays object inspection without claiming active filtering.</summary>
    [Fact]
    public async Task StartupUpdatesTruthfulStatus()
    {
        var rig = new Rig();
        await using var controller = rig.Controller();
        var model = new ShellViewModel(rig, controller);
        Assert.Equal(0, rig.Starts);
        Assert.False(model.RecheckCommand.CanExecute(null));
        await model.StartHelperCommand.ExecuteAsync(null);
        Assert.Equal(1, rig.Starts);
        Assert.Contains("helper", model.ProtectionTitle, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("4/4", model.PolicyDescription, StringComparison.Ordinal);
        Assert.DoesNotContain("Защита включена", model.ProtectionTitle, StringComparison.Ordinal);
        Assert.True(model.RecheckCommand.CanExecute(null));
        Assert.False(model.StartHelperCommand.CanExecute(null));
    }

    /// <summary>The UI can hide while startup is pending, and exit waits for the late session to close.</summary>
    [Fact]
    public async Task ExitWaitsForPendingStartupWithoutBlockingWindowCommands()
    {
        var rig = new Rig();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var connected = new TaskCompletionSource<IProtectionSession>(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var controller = new ProtectionSessionController(_ => { entered.TrySetResult(); return connected.Task; });
        var model = new ShellViewModel(rig, controller);
        var starting = model.StartHelperCommand.ExecuteAsync(null);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
        model.HideWindowCommand.Execute(null);
        Assert.Equal(1, rig.Hides);
        var exiting = model.ExitCommand.ExecuteAsync(null);
        Assert.False(exiting.IsCompleted);
        Assert.Equal(0, rig.Exits);
        connected.TrySetResult(rig);
        await starting;
        await exiting;
        Assert.Equal(1, rig.Disposals);
        Assert.Equal(1, rig.Exits);
    }

    /// <summary>Connection failure is rendered and commands complete without an unhandled async exception.</summary>
    [Fact]
    public async Task FailureDoesNotLeaveSuccessfulStatus()
    {
        var rig = new Rig();
        await using var controller = rig.Controller();
        var model = new ShellViewModel(rig, controller);
        await model.StartHelperCommand.ExecuteAsync(null);
        rig.Fail = true;
        await model.RecheckCommand.ExecuteAsync(null);
        Assert.Contains("неизвестно", model.PolicyDescription, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("не подключён", model.ProtectionTitle, StringComparison.OrdinalIgnoreCase);
        Assert.True(model.StartHelperCommand.CanExecute(null));
        Assert.False(model.RecheckCommand.CanExecute(null));
    }

    /// <summary>Cached refresh exposes worker changes without starting additional network or policy operations.</summary>
    [Fact]
    public async Task CachedRefreshNotifiesBindings()
    {
        var rig = new Rig();
        await using var controller = rig.Controller();
        var model = new ShellViewModel(rig, controller);
        await controller.StartAsync();
        model.RefreshStatus();
        Assert.Contains("4/4", model.PolicyDescription, StringComparison.Ordinal);
        Assert.Equal(1, rig.Exchanges);
    }

    /// <summary>Supplies a controlled connection and window host through composition.</summary>
    private sealed class Rig : IDesktopHost, IProtectionSession
    {
        /// <summary>Gets how many explicit starts were requested.</summary>
        internal int Starts { get; private set; }
        /// <summary>Gets the number of hidden-window requests.</summary>
        internal int Hides { get; private set; }
        /// <summary>Gets the number of explicit shutdown requests.</summary>
        internal int Exits { get; private set; }
        /// <summary>Gets how many exchanges were sent.</summary>
        internal int Exchanges { get; private set; }
        /// <summary>Gets the number of connection disposals.</summary>
        internal int Disposals { get; private set; }
        /// <summary>Gets or sets a controlled connection failure.</summary>
        internal bool Fail { get; set; }
        /// <summary>Composes a deferred factory without any native helper.</summary>
        internal ProtectionSessionController Controller() => new(_ => { Starts++; return Task.FromResult<IProtectionSession>(this); });
        /// <summary>Leaves visibility unchanged when a test does not observe it.</summary>
        public void ShowWindow() { }
        /// <summary>Records a hide operation independently of session startup.</summary>
        public void HideWindow() => Hides++;
        /// <summary>Records shutdown only after asynchronous cleanup.</summary>
        public void Shutdown() => Exits++;
        /// <summary>Supplies safe policy-object observations and terminal acknowledgements.</summary>
        public Task<ProtectionControlReport> SendAsync(ProtectionCommand command, CancellationToken token)
        {
            Exchanges++;
            if (Fail) throw new IOException("Controlled connection failure.");
            return Task.FromResult(new ProtectionControlReport(command == ProtectionCommand.Stop ? ProtectionPhase.Stopped : ProtectionPhase.Running,
                ProtectionReason.AssessmentUnavailable, BlockPolicyState.Present, 4, 4, DateTimeOffset.UtcNow, false));
        }
        /// <summary>Records connection cleanup without touching processes.</summary>
        public ValueTask DisposeAsync() { Disposals++; return ValueTask.CompletedTask; }
    }
}
