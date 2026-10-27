using Avalonia.Controls;
using Avalonia.Headless.XUnit;
using Avalonia.Threading;
using Avalonia.VisualTree;
using IPGuard.Application.Protection;
using IPGuard.Desktop.Hosting;
using IPGuard.Desktop.Lifetime;
using IPGuard.Desktop.ViewModels;
using IPGuard.Desktop.Views;
using Xunit;

namespace IntegrationTests;

/// <summary>Checks real declarative bindings and safe connector rejection without UAC or native policy changes.</summary>
public sealed class DesktopProtectionTests
{
    /// <summary>A normal test executable is rejected before any native helper process can start.</summary>
    [Fact]
    public async Task UninstalledConnectorDoesNotElevate()
        => await Assert.ThrowsAsync<UnauthorizedAccessException>(() => WindowsProtectionSession.ConnectAsync(TestContext.Current.CancellationToken));

    /// <summary>A cancelled startup is rejected before installation or elevation work.</summary>
    [Fact]
    public async Task CancelledConnectorDoesNotStartWork()
    {
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => WindowsProtectionSession.ConnectAsync(cancellation.Token));
    }

    /// <summary>Window bindings follow a fake authenticated session, while close hides and explicit exit drains Stop.</summary>
    [AvaloniaFact]
    public async Task WindowBindsSessionCommandsAndWaitsForExit()
    {
        var session = new Session();
        await using var controller = new ProtectionSessionController(_ => Task.FromResult<IProtectionSession>(session));
        var window = ShellWindow.Create();
        using var host = new AvaloniaDesktopHost(window, window.Close);
        var model = new ShellViewModel(host, controller);
        window.DataContext = model;
        window.Show();
        try
        {
            var start = Assert.Single(window.GetVisualDescendants().OfType<Button>(), button => button.Name == "StartHelperButton");
            var recheck = Assert.Single(window.GetVisualDescendants().OfType<Button>(), button => button.Name == "RecheckButton");
            var status = Assert.Single(window.GetVisualDescendants().OfType<TextBlock>(), text => text.Name == "PolicyStatus");
            Assert.Same(model.StartHelperCommand, start.Command);
            Assert.Same(model.RecheckCommand, recheck.Command);
            Assert.False(recheck.IsEffectivelyEnabled);
            await model.StartHelperCommand.ExecuteAsync(null);
            Dispatcher.UIThread.RunJobs();
            Assert.Contains("4/4", status.Text, StringComparison.Ordinal);
            Assert.False(start.IsEffectivelyEnabled);
            Assert.True(recheck.IsEffectivelyEnabled);
            window.Close();
            Assert.False(window.IsVisible);
            Assert.Equal(ProtectionSessionState.Connected, controller.Capture().State);
            host.ShowWindow();
            await model.ExitCommand.ExecuteAsync(null);
            Assert.Equal(ProtectionCommand.Stop, session.Commands[^1]);
            Assert.Equal(1, session.Disposals);
            Assert.False(window.IsVisible);
        }
        finally { host.Dispose(); window.Close(); }
    }

    /// <summary>Supplies policy object counts without creating real rules or child processes.</summary>
    private sealed class Session : IProtectionSession
    {
        /// <summary>Gets ordered logical operations.</summary>
        internal List<ProtectionCommand> Commands { get; } = [];
        /// <summary>Gets the number of connection closures.</summary>
        internal int Disposals { get; private set; }
        /// <summary>Returns a valid running or terminal policy-object report.</summary>
        public Task<ProtectionControlReport> SendAsync(ProtectionCommand command, CancellationToken token)
        {
            Commands.Add(command);
            return Task.FromResult(new ProtectionControlReport(command == ProtectionCommand.Stop ? ProtectionPhase.Stopped : ProtectionPhase.Running,
                ProtectionReason.AssessmentUnavailable, BlockPolicyState.Present, 4, 4, DateTimeOffset.UtcNow, false));
        }
        /// <summary>Records cleanup without altering filtering state.</summary>
        public ValueTask DisposeAsync() { Disposals++; return ValueTask.CompletedTask; }
    }
}
