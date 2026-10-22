using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Platform;
using IPGuard.Desktop.Lifetime;
using IPGuard.Desktop.ViewModels;
using IPGuard.Desktop.Views;
using Microsoft.Extensions.DependencyInjection;

namespace IPGuard.Desktop;

/// <summary>Composes GUI dependencies without accessing the operating system's network policy.</summary>
public static class DesktopBootstrapper
{
    /// <summary>Creates the window, commands, and application-owned tray icon.</summary>
    /// <param name="application">The initialized Avalonia application.</param>
    /// <param name="lifetime">The desktop process lifetime.</param>
    /// <returns>The owner of shell resources that are released on exit.</returns>
    public static DesktopSession Start(Avalonia.Application application, IClassicDesktopStyleApplicationLifetime lifetime)
    {
        var services = new ServiceCollection();
        services.AddSingleton(_ => ShellWindow.Create());
        services.AddSingleton<IDesktopHost>(provider => new AvaloniaDesktopHost(
            provider.GetRequiredService<Window>(), () => lifetime.Shutdown()));
        services.AddSingleton<ShellViewModel>();
        services.AddSingleton(provider => CreateTrayIcon(provider.GetRequiredService<ShellViewModel>()));
        var provider = services.BuildServiceProvider(new ServiceProviderOptions
        {
            ValidateOnBuild = true,
            ValidateScopes = true
        });

        try
        {
            var window = provider.GetRequiredService<Window>();
            var icon = provider.GetRequiredService<TrayIcon>();
            window.DataContext = provider.GetRequiredService<ShellViewModel>();
            window.Icon = icon.Icon;
            lifetime.ShutdownMode = ShutdownMode.OnExplicitShutdown;
            lifetime.MainWindow = window;
            TrayIcon.SetIcons(application, new TrayIcons { icon });
            return new DesktopSession(application, lifetime, provider, icon);
        }
        catch
        {
            provider.Dispose();
            throw;
        }
    }

    /// <summary>Loads the embedded icon and connects the native menu to shell commands.</summary>
    private static TrayIcon CreateTrayIcon(ShellViewModel model)
    {
        using var stream = AssetLoader.Open(new Uri("avares://Desktop/Assets/ipguard.ico"));
        return new TrayIcon
        {
            Icon = new WindowIcon(stream),
            ToolTipText = "IPGuard — защита ещё не включена",
            Menu = TrayMenu.Create(model),
            Command = model.ShowWindowCommand,
            IsVisible = true
        };
    }
}
