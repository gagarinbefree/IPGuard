using Avalonia.Controls;
using Avalonia.Headless.XUnit;
using Avalonia.Threading;
using IPGuard.Desktop.Lifetime;
using Xunit;

namespace IntegrationTests;

/// <summary>Verifies real Avalonia window handlers without a native desktop.</summary>
public sealed class DesktopLifetimeTests
{
    /// <summary>A window closed by the user can be reopened from the tray.</summary>
    [AvaloniaFact]
    public void ClosingWindow_HidesItAndAllowsReopening()
    {
        var window = new Window();
        using var host = new AvaloniaDesktopHost(window, () => Assert.Fail("Unexpected shutdown"));
        window.Show();

        window.Close();

        Assert.False(window.IsVisible);
        host.ShowWindow();
        Assert.True(window.IsVisible);
        host.Dispose();
        window.Close();
    }

    /// <summary>Minimizing hides the window in the tray without terminating the process.</summary>
    [AvaloniaFact]
    public void MinimizingWindow_HidesIt()
    {
        var window = new Window();
        using var host = new AvaloniaDesktopHost(window, () => Assert.Fail("Unexpected shutdown"));
        window.Show();

        window.WindowState = WindowState.Minimized;
        Dispatcher.UIThread.RunJobs();

        Assert.False(window.IsVisible);
        host.Dispose();
        window.Close();
    }

    /// <summary>Reopening restores the window to its normal state.</summary>
    [AvaloniaFact]
    public void ShowingMinimizedWindow_RestoresNormalState()
    {
        var window = new Window();
        using var host = new AvaloniaDesktopHost(window, () => { });
        window.Show();
        window.WindowState = WindowState.Minimized;
        window.Hide();

        host.ShowWindow();

        Assert.True(window.IsVisible);
        Assert.Equal(WindowState.Normal, window.WindowState);
        host.Dispose();
        window.Close();
    }

    /// <summary>Explicit exit closes the window instead of intercepting closure as a hide request.</summary>
    [AvaloniaFact]
    public void ExplicitExit_AllowsWindowToClose()
    {
        var window = new Window();
        var shutdownRequested = false;
        var closed = false;
        window.Closed += (_, _) => closed = true;
        using var host = new AvaloniaDesktopHost(window, () =>
        {
            shutdownRequested = true;
            window.Close();
        });
        window.Show();

        host.Shutdown();

        Assert.True(shutdownRequested);
        Assert.True(closed);
    }
}
