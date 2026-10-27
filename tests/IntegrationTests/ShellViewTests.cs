using Avalonia;
using Avalonia.Controls;
using Avalonia.Headless;
using Avalonia.Headless.XUnit;
using Avalonia.Input;
using Avalonia.Media.Imaging;
using Avalonia.VisualTree;
using IPGuard.Desktop.Lifetime;
using IPGuard.Application.Protection;
using IPGuard.Desktop.ViewModels;
using IPGuard.Desktop.Views;
using Xunit;

namespace IntegrationTests;

/// <summary>Verifies declarative window bindings and shared tray menu commands.</summary>
public sealed class ShellViewTests
{
    /// <summary>The initial screen does not present missing enforcement as active protection.</summary>
    [AvaloniaFact]
    public void Window_ShowsThatProtectionIsNotImplemented()
    {
        var window = ShellWindow.Create();
        using var host = new AvaloniaDesktopHost(window, () => { });
        window.DataContext = Model(host);
        window.Show();

        var status = Assert.Single(window.GetVisualDescendants().OfType<TextBlock>(),
            control => control.Name == "ProtectionStatus");

        Assert.Equal("Защита ещё не включена", status.Text);
        var previewPath = Environment.GetEnvironmentVariable("IPGUARD_PREVIEW_PATH");
        if (!string.IsNullOrWhiteSpace(previewPath))
        {
            using var frame = window.CaptureRenderedFrame();
            Assert.NotNull(frame);
            frame.Save(previewPath, PngBitmapEncoderOptions.Default);
        }

        host.Dispose();
        window.Close();
    }

    /// <summary>The hide button executes its bound view model command.</summary>
    [AvaloniaFact]
    public void HideButton_ExecutesBoundCommand()
    {
        var window = ShellWindow.Create();
        using var host = new AvaloniaDesktopHost(window, () => Assert.Fail("Unexpected shutdown"));
        window.DataContext = Model(host);
        window.Show();
        var button = Assert.Single(window.GetVisualDescendants().OfType<Button>(),
            control => control.Name == "HideWindowButton");

        var location = button.TranslatePoint(new Point(button.Bounds.Width / 2, button.Bounds.Height / 2), window);
        Assert.NotNull(location);
        window.MouseDown(location.Value, MouseButton.Left);
        window.MouseUp(location.Value, MouseButton.Left);

        Assert.False(window.IsVisible);
        host.Dispose();
        window.Close();
    }

    /// <summary>The tray menu exposes the same open and exit commands as the window.</summary>
    [AvaloniaFact]
    public void TrayMenu_UsesShellCommands()
    {
        var window = new Window();
        using var host = new AvaloniaDesktopHost(window, () => { });
        var model = Model(host);

        var menu = TrayMenu.Create(model);

        var commands = menu.Items.OfType<NativeMenuItem>().ToArray();
        Assert.Contains(commands, item => ReferenceEquals(item.Command, model.ShowWindowCommand));
        Assert.Contains(commands, item => ReferenceEquals(item.Command, model.ExitCommand));
    }
    /// <summary>Creates a passive test shell without native helper startup.</summary>
    private static ShellViewModel Model(IDesktopHost host)
        => new(host, new ProtectionSessionController(_ => throw new InvalidOperationException("Unexpected helper startup.")));
}
