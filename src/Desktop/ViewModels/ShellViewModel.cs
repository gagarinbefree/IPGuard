using CommunityToolkit.Mvvm.Input;
using IPGuard.Desktop.Lifetime;

namespace IPGuard.Desktop.ViewModels;

/// <summary>Provides application shell commands without performing network operations.</summary>
public sealed class ShellViewModel
{
    /// <summary>Creates commands for window management and explicit application shutdown.</summary>
    /// <param name="host">The desktop application lifetime adapter.</param>
    public ShellViewModel(IDesktopHost host)
    {
        ArgumentNullException.ThrowIfNull(host);
        ShowWindowCommand = new RelayCommand(host.ShowWindow);
        HideWindowCommand = new RelayCommand(host.HideWindow);
        ExitCommand = new RelayCommand(host.Shutdown);
    }

    /// <summary>Opens the window from the system tray.</summary>
    public IRelayCommand ShowWindowCommand { get; }

    /// <summary>Hides the window without terminating the process.</summary>
    public IRelayCommand HideWindowCommand { get; }

    /// <summary>Exits the application following an explicit user action.</summary>
    public IRelayCommand ExitCommand { get; }

    /// <summary>Reports the current shell status before network policy enforcement is implemented.</summary>
    public string ProtectionTitle => "Защита ещё не включена";

    /// <summary>Explains the absence of network protection without claiming that traffic is blocked.</summary>
    public string ProtectionDescription => "IPGuard пока не ограничивает доступ PowerShell к сети.";
}
