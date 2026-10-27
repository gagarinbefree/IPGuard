using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Microsoft.Extensions.DependencyInjection;
using Avalonia.Threading;
using IPGuard.Desktop.ViewModels;

namespace IPGuard.Desktop.Lifetime;

/// <summary>Owns the window, tray, and dependency container resources.</summary>
public sealed class DesktopSession : IDisposable
{
    private readonly Avalonia.Application _application;
    private readonly IClassicDesktopStyleApplicationLifetime _lifetime;
    private readonly ServiceProvider _services;
    private readonly TrayIcon _icon;
    private bool _disposed;
    private readonly DispatcherTimer _refresh;
    private readonly ShellViewModel _model;

    /// <summary>Connects resource cleanup to the desktop lifetime's exit event.</summary>
    /// <param name="application">The owner of the tray icon collection.</param>
    /// <param name="lifetime">The source of application exit events.</param>
    /// <param name="services">The container that owns the window adapter and tray icon.</param>
    /// <param name="icon">The tray icon to remove on exit.</param>
    public DesktopSession(Avalonia.Application application, IClassicDesktopStyleApplicationLifetime lifetime,
        ServiceProvider services, TrayIcon icon)
    {
        _application = application;
        _lifetime = lifetime;
        _services = services;
        _icon = icon;
        _model = services.GetRequiredService<ShellViewModel>();
        _refresh = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(500) };
        _refresh.Tick += OnRefresh;
        _refresh.Start();
        _lifetime.Exit += OnExit;
    }

    /// <summary>Releases shell resources without changing network rules.</summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _refresh.Stop();
        _refresh.Tick -= OnRefresh;
        _lifetime.Exit -= OnExit;
        _icon.IsVisible = false;
        TrayIcon.GetIcons(_application)?.Remove(_icon);
        _services.Dispose();
    }

    /// <summary>Releases tray resources on explicit exit or normal OS shutdown.</summary>
    private void OnExit(object? sender, ControlledApplicationLifetimeExitEventArgs args) => Dispose();

    /// <summary>Updates presentation from cached data only; polling and native work stay on background workers.</summary>
    private void OnRefresh(object? sender, EventArgs args)
    {
        _model.RefreshStatus();
        _icon.ToolTipText = $"IPGuard — {_model.ProtectionTitle}";
    }
}
