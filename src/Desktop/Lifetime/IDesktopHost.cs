namespace IPGuard.Desktop.Lifetime;

/// <summary>Provides window and process operations without exposing Avalonia to the view model.</summary>
public interface IDesktopHost
{
    /// <summary>Shows the window and restores it from its minimized state.</summary>
    void ShowWindow();

    /// <summary>Hides the window while keeping the process and tray icon active.</summary>
    void HideWindow();

    /// <summary>Shuts down the process following an explicit user request.</summary>
    void Shutdown();
}
