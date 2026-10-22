using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Headless.XUnit;
using IPGuard.Desktop;
using IPGuard.Desktop.ViewModels;
using Xunit;

namespace IntegrationTests;

/// <summary>Verifies application composition using real components and tray resource ownership.</summary>
public sealed class DesktopBootstrapperTests
{
    /// <summary>The window and tray share a view model, and window closure does not end the lifetime.</summary>
    [AvaloniaFact]
    public void Startup_ComposesWindowAndTrayWithExplicitLifetime()
    {
        var application = Avalonia.Application.Current!;
        var lifetime = new ClassicDesktopStyleApplicationLifetime();
        using var session = DesktopBootstrapper.Start(application, lifetime);

        Assert.Equal(ShutdownMode.OnExplicitShutdown, lifetime.ShutdownMode);
        Assert.NotNull(lifetime.MainWindow);
        var model = Assert.IsType<ShellViewModel>(lifetime.MainWindow.DataContext);
        var icons = TrayIcon.GetIcons(application);
        Assert.NotNull(icons);
        var icon = Assert.Single(icons);
        Assert.NotNull(icon.Icon);
        Assert.Same(model.ShowWindowCommand, icon.Command);
        Assert.NotNull(icon.Menu);
        session.Dispose();
        lifetime.MainWindow.Close();
    }

    /// <summary>Disposing the shell removes the tray icon and supports repeated cleanup.</summary>
    [AvaloniaFact]
    public void DisposingSession_RemovesTrayIcon()
    {
        var application = Avalonia.Application.Current!;
        var lifetime = new ClassicDesktopStyleApplicationLifetime();
        using var session = DesktopBootstrapper.Start(application, lifetime);
        var icons = TrayIcon.GetIcons(application);
        Assert.NotNull(icons);
        var icon = Assert.Single(icons);

        session.Dispose();
        session.Dispose();

        Assert.False(icon.IsVisible);
        Assert.Empty(TrayIcon.GetIcons(application)!);
        lifetime.MainWindow!.Close();
    }
}
