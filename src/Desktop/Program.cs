using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Styling;
using Avalonia.Themes.Fluent;

namespace IPGuard.Desktop;

/// <summary>Starts the desktop application without a background service or firewall changes.</summary>
public static class Program
{
    /// <summary>Runs the window and tray using the Avalonia desktop lifetime.</summary>
    /// <param name="args">Command-line arguments passed to the process.</param>
    /// <returns>The application exit code.</returns>
    [STAThread]
    public static int Main(string[] args) => BuildAvaloniaApp()
        .StartWithClassicDesktopLifetime(args, ShutdownMode.OnExplicitShutdown);

    /// <summary>Configures Avalonia through composition without an Application subclass.</summary>
    /// <returns>A builder configured to use the native desktop platform.</returns>
    public static AppBuilder BuildAvaloniaApp() => AppBuilder.Configure<Avalonia.Application>()
        .UsePlatformDetect()
        .AfterSetup(InitializeDesktop);

    /// <summary>Applies the theme and connects the shell after Avalonia initialization.</summary>
    private static void InitializeDesktop(AppBuilder builder)
    {
        var application = builder.Instance!;
        application.RequestedThemeVariant = ThemeVariant.Dark;
        application.Styles.Add(new FluentTheme());
        if (application.ApplicationLifetime is IClassicDesktopStyleApplicationLifetime lifetime)
        {
            DesktopBootstrapper.Start(application, lifetime);
        }
    }
}
