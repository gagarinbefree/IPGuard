using System.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using IPGuard.Application.Protection;
using IPGuard.Desktop.Lifetime;

namespace IPGuard.Desktop.ViewModels;

/// <summary>Presents cached helper observations and asynchronous commands without native policy access.</summary>
public sealed class ShellViewModel : INotifyPropertyChanged
{
    private readonly IDesktopHost host;
    private readonly ProtectionSessionController controller;
    private ProtectionSessionSnapshot snapshot;
    private string? commandError;

    /// <summary>Composes window operations and passive session coordination without starting a helper.</summary>
    public ShellViewModel(IDesktopHost host, ProtectionSessionController controller)
    {
        ArgumentNullException.ThrowIfNull(host);
        ArgumentNullException.ThrowIfNull(controller);
        this.host = host;
        this.controller = controller;
        snapshot = controller.Capture();
        ShowWindowCommand = new RelayCommand(host.ShowWindow);
        HideWindowCommand = new RelayCommand(host.HideWindow);
        StartHelperCommand = new AsyncRelayCommand(() => ExecuteAsync(controller.StartAsync),
            () => snapshot.State is ProtectionSessionState.Idle or ProtectionSessionState.Failed);
        RecheckCommand = new AsyncRelayCommand(() => ExecuteAsync(controller.RecheckAsync),
            () => snapshot.State == ProtectionSessionState.Connected);
        ExitCommand = new AsyncRelayCommand(ExitAsync);
    }

    /// <summary>Notifies bindings on the calling UI context; workers only update application snapshots.</summary>
    public event PropertyChangedEventHandler? PropertyChanged;
    /// <summary>Starts the explicitly requested helper session.</summary>
    public IAsyncRelayCommand StartHelperCommand { get; }
    /// <summary>Requests fresh diagnostics and a persistent baseline reconciliation.</summary>
    public IAsyncRelayCommand RecheckCommand { get; }

    /// <summary>Opens the window from the system tray.</summary>
    public IRelayCommand ShowWindowCommand { get; }

    /// <summary>Hides the window without terminating the process.</summary>
    public IRelayCommand HideWindowCommand { get; }

    /// <summary>Waits for connection cleanup before explicitly exiting the desktop.</summary>
    public IAsyncRelayCommand ExitCommand { get; }

    /// <summary>Describes connection activity separately from effective filtering.</summary>
    public string ProtectionTitle => snapshot.State switch
    {
        ProtectionSessionState.Starting => "Подключение helper…",
        ProtectionSessionState.Connected when snapshot.Report is not null => "Блокирующий режим: helper подключён",
        ProtectionSessionState.Connected => "Нет актуального ответа helper",
        ProtectionSessionState.Rechecking => "Повторная проверка…",
        ProtectionSessionState.Failed => "Helper не подключён",
        ProtectionSessionState.Stopping => "Завершение сессии…",
        ProtectionSessionState.Stopped => "Сессия завершена",
        _ => "Защита ещё не включена"
    };

    /// <summary>Explains errors and the block-only limitation without promising country-based authorization.</summary>
    public string ProtectionDescription => commandError ?? (snapshot.Error is not null
        ? "Нет подтверждённого состояния блокировки. Проверьте защищённую установку, запрос прав и соединение с helper."
        : snapshot.State switch
        {
            ProtectionSessionState.Idle => "IPGuard пока не ограничивает доступ PowerShell к сети.",
            ProtectionSessionState.Starting => "Проверяется установка и ожидается подключение. Запрос прав Windows может потребовать подтверждения.",
            ProtectionSessionState.Stopping => "Ожидается завершение команд и сохранение постоянных блокирующих правил.",
            ProtectionSessionState.Stopped => "Сессия закрыта. Постоянные правила не удаляются.",
            _ => "Режим устанавливает только блокирующие правила. Автоматическое разрешение по стране пока недоступно."
        });

    /// <summary>Displays last rule counts and time without presenting object presence as packet-level proof.</summary>
    public string PolicyDescription => snapshot.Report?.PolicyState is not null
        ? $"Проверка правил: {snapshot.Report.MatchingRules}/{snapshot.Report.ExpectedRules}; " +
          $"{snapshot.Report.PolicyObservedAt:yyyy-MM-dd HH:mm:ss} UTC"
        : "Проверка правил: неизвестно";

    /// <summary>Refreshes bindings from cached state only; the desktop timer calls this on the UI thread.</summary>
    public void RefreshStatus()
    {
        snapshot = controller.Capture();
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(null));
        StartHelperCommand.NotifyCanExecuteChanged();
        RecheckCommand.NotifyCanExecuteChanged();
    }

    /// <summary>Observes command failures and refreshes pending and completed states on the calling context.</summary>
    private async Task ExecuteAsync(Func<Task> action)
    {
        commandError = null;
        try
        {
            var pending = action();
            RefreshStatus();
            await pending;
        }
        catch (Exception) { commandError = "Команда не завершена. Состояние блокировки неизвестно."; }
        RefreshStatus();
    }

    /// <summary>Keeps the UI responsive until terminal session cleanup finishes.</summary>
    private async Task ExitAsync()
    {
        await ExecuteAsync(() => controller.StopAsync(CancellationToken.None));
        host.Shutdown();
    }
}
