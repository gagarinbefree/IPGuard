using Avalonia.Controls;
using IPGuard.Desktop.ViewModels;

namespace IPGuard.Desktop.Views;

/// <summary>Builds the tray menu from shell commands.</summary>
public static class TrayMenu
{
    /// <summary>Creates menu items for opening the window and explicitly exiting the application.</summary>
    /// <param name="model">The shared view model for the window and tray menu.</param>
    /// <returns>A native menu for the tray icon.</returns>
    public static NativeMenu Create(ShellViewModel model) => new()
    {
        Items =
        {
            new NativeMenuItem("Открыть IPGuard") { Command = model.ShowWindowCommand },
            new NativeMenuItemSeparator(),
            new NativeMenuItem("Выйти из IPGuard") { Command = model.ExitCommand }
        }
    };
}
