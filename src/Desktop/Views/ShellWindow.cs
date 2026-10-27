using Avalonia;
using Avalonia.Controls;
using Avalonia.Data;
using Avalonia.Layout;
using Avalonia.Markup.Declarative;
using Avalonia.Media;
using IPGuard.Desktop.ViewModels;

namespace IPGuard.Desktop.Views;

/// <summary>Builds the status window by composing existing Avalonia controls.</summary>
public static class ShellWindow
{
    /// <summary>Creates a window whose bindings resolve the view model through DataContext.</summary>
    /// <returns>A new window without registering network rules.</returns>
    public static Window Create() => new Window
    {
        Title = "IPGuard",
        Width = 780,
        Height = 760,
        MinWidth = 640,
        MinHeight = 600,
        WindowStartupLocation = WindowStartupLocation.CenterScreen,
        Background = Brush.Parse("#10141D"),
        Content = new ScrollViewer().Content(
            new StackPanel()
                .Margin(new Thickness(32))
                .Spacing(24)
                .Children(CreateHeader(), CreateStatusCard(), CreateDetails(), CreateActions()))
    };

    /// <summary>Creates the application title and a brief description of its purpose.</summary>
    private static Control CreateHeader() => new StackPanel().Spacing(4).Children(
        new TextBlock().Text("IPGuard").FontSize(30).FontWeight(FontWeight.Bold),
        new TextBlock().Text("Контроль сетевого доступа PowerShell")
            .FontSize(15).Foreground(Brush.Parse("#A5AEC0")));

    /// <summary>Displays the unconfirmed protection status through view model bindings.</summary>
    private static Control CreateStatusCard() => new Border()
        .Background(Brush.Parse("#202636"))
        .BorderBrush(Brush.Parse("#715D35"))
        .BorderThickness(new Thickness(1))
        .CornerRadius(new CornerRadius(14))
        .Padding(new Thickness(24))
        .Child(new StackPanel().Spacing(12).Children(
            new TextBlock().Text("СОСТОЯНИЕ ЗАЩИТЫ").FontSize(12)
                .Foreground(Brush.Parse("#E9BA64")),
            new TextBlock().Name("ProtectionStatus")
                .Text(new Binding(nameof(ShellViewModel.ProtectionTitle)))
                .FontSize(25).FontWeight(FontWeight.SemiBold).TextWrapping(TextWrapping.Wrap),
            new TextBlock().Text(new Binding(nameof(ShellViewModel.ProtectionDescription)))
                .FontSize(15).TextWrapping(TextWrapping.Wrap)));

    /// <summary>Distinguishes unavailable measurements from the actual network filter state.</summary>
    private static Control CreateDetails() => new StackPanel().Spacing(12).Children(
        new TextBlock().Text("Диагностика").FontSize(18).FontWeight(FontWeight.SemiBold),
        new TextBlock().Text("Публичный IP: не проверен"),
        new TextBlock().Text("Страна и маршрут: не проверены"),
        new TextBlock().Name("PolicyStatus").Text(new Binding(nameof(ShellViewModel.PolicyDescription)))
            .TextWrapping(TextWrapping.Wrap),
        new TextBlock().Text("Состояние сетевой блокировки: неизвестно")
            .Foreground(Brush.Parse("#E9BA64")),
        new TextBlock().Text("Закрытие окна оставляет приложение в трее.")
            .TextWrapping(TextWrapping.Wrap).Foreground(Brush.Parse("#A5AEC0")));

    /// <summary>Separates explicit block-only startup and recheck from window hiding and terminal exit.</summary>
    private static Control CreateActions() => new StackPanel()
        .Spacing(12).Children(
            new TextBlock().Text("Блокирующий режим сохраняет правила после выхода. Разрешение по стране ещё недоступно.")
                .TextWrapping(TextWrapping.Wrap).Foreground(Brush.Parse("#A5AEC0")),
            new StackPanel().Orientation(Orientation.Horizontal).Spacing(12).Children(
                new Button().Name("StartHelperButton").Content("Запустить блокирующий режим")
                    .Command(new Binding(nameof(ShellViewModel.StartHelperCommand))),
                new Button().Name("RecheckButton").Content("Проверить снова")
                    .Command(new Binding(nameof(ShellViewModel.RecheckCommand)))),
            new StackPanel().Orientation(Orientation.Horizontal).Spacing(12).Children(
                new Button().Name("HideWindowButton").Content("Свернуть в трей")
                    .Command(new Binding(nameof(ShellViewModel.HideWindowCommand))),
                new Button().Name("ExitButton").Content("Выйти из IPGuard")
                    .Command(new Binding(nameof(ShellViewModel.ExitCommand)))));
}
