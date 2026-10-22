using IPGuard.Desktop.Lifetime;
using IPGuard.Desktop.ViewModels;
using Xunit;

namespace UnitTests;

/// <summary>Verifies the distinction between window management and process shutdown.</summary>
public sealed class ShellViewModelTests
{
    /// <summary>Hiding the window keeps the process running.</summary>
    [Fact]
    public void HideWindow_HidesWindowWithoutShuttingDown()
    {
        var host = new RecordingDesktopHost();
        var model = new ShellViewModel(host);

        model.HideWindowCommand.Execute(null);

        Assert.Equal(["hide"], host.Actions);
    }

    /// <summary>The tray command restores the window without starting another process.</summary>
    [Fact]
    public void ShowWindow_RestoresWindowWithoutShuttingDown()
    {
        var host = new RecordingDesktopHost();
        var model = new ShellViewModel(host);

        model.ShowWindowCommand.Execute(null);

        Assert.Equal(["show"], host.Actions);
    }

    /// <summary>Only the explicit exit command requests application shutdown.</summary>
    [Fact]
    public void Exit_ShutsDownApplication()
    {
        var host = new RecordingDesktopHost();
        var model = new ShellViewModel(host);

        model.ExitCommand.Execute(null);

        Assert.Equal(["shutdown"], host.Actions);
    }

    /// <summary>Records observable shell actions without creating windows or accessing the OS.</summary>
    private sealed class RecordingDesktopHost : IDesktopHost
    {
        /// <summary>Gets the actions requested by the view model.</summary>
        public List<string> Actions { get; } = [];

        /// <inheritdoc />
        public void ShowWindow() => Actions.Add("show");

        /// <inheritdoc />
        public void HideWindow() => Actions.Add("hide");

        /// <inheritdoc />
        public void Shutdown() => Actions.Add("shutdown");
    }
}
