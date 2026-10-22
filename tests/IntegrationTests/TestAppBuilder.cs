using Avalonia;
using Avalonia.Headless;
using Avalonia.Headless.XUnit;
using Avalonia.Styling;
using Avalonia.Themes.Fluent;

[assembly: AvaloniaTestApplication(typeof(IntegrationTests.TestAppBuilder))]

namespace IntegrationTests;

/// <summary>Creates an isolated Avalonia platform without native windows or network rules.</summary>
public static class TestAppBuilder
{
    /// <summary>Configures real controls with a theme and in-memory rendering.</summary>
    /// <returns>An application builder for headless xUnit tests.</returns>
    public static AppBuilder BuildAvaloniaApp() =>
        AppBuilder.Configure<Avalonia.Application>()
            .UseSkia()
            .UseHeadless(new AvaloniaHeadlessPlatformOptions { UseHeadlessDrawing = false })
            .AfterSetup(builder =>
            {
                builder.Instance!.RequestedThemeVariant = ThemeVariant.Dark;
                builder.Instance.Styles.Add(new FluentTheme());
            });
}
