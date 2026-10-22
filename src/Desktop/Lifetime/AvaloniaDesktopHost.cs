using Avalonia;
using Avalonia.Controls;

namespace IPGuard.Desktop.Lifetime;

/// <summary>Connects shell commands to an Avalonia window and process shutdown.</summary>
public sealed class AvaloniaDesktopHost : IDesktopHost, IDisposable
{
    private readonly Window _window;
    private readonly Action _shutdown;
    private bool _exitRequested;

    /// <summary>Attaches visibility management to an existing window.</summary>
    /// <param name="window">The application's single status window.</param>
    /// <param name="shutdown">The action that shuts down the desktop lifetime.</param>
    public AvaloniaDesktopHost(Window window, Action shutdown)
    {
        ArgumentNullException.ThrowIfNull(window);
        ArgumentNullException.ThrowIfNull(shutdown);
        _window = window;
        _shutdown = shutdown;
        _window.Closing += OnWindowClosing;
        _window.PropertyChanged += OnWindowPropertyChanged;
    }

    /// <inheritdoc />
    public void ShowWindow()
    {
        _window.WindowState = WindowState.Normal;
        _window.Show();
        _window.Activate();
    }

    /// <inheritdoc />
    public void HideWindow() => _window.Hide();

    /// <inheritdoc />
    public void Shutdown()
    {
        _exitRequested = true;
        _shutdown();
    }

    /// <summary>Detaches window event handlers when the owner releases this host.</summary>
    public void Dispose()
    {
        _window.Closing -= OnWindowClosing;
        _window.PropertyChanged -= OnWindowPropertyChanged;
    }

    /// <summary>Hides the window on normal close without preventing application or OS shutdown.</summary>
    private void OnWindowClosing(object? sender, WindowClosingEventArgs args)
    {
        if (_exitRequested || args.CloseReason is WindowCloseReason.ApplicationShutdown or WindowCloseReason.OSShutdown)
        {
            return;
        }

        args.Cancel = true;
        HideWindow();
    }

    /// <summary>Removes a minimized window from the taskbar while preserving access through the tray.</summary>
    private void OnWindowPropertyChanged(object? sender, AvaloniaPropertyChangedEventArgs args)
    {
        if (args.Property == Window.WindowStateProperty && _window.WindowState == WindowState.Minimized)
        {
            HideWindow();
        }
    }
}
