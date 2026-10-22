# IPGuard

[![Tests](https://github.com/gagarinbefree/IPGuard/actions/workflows/tests.yml/badge.svg?branch=main&event=push)](https://github.com/gagarinbefree/IPGuard/actions/workflows/tests.yml)
[![Build and deploy](https://github.com/gagarinbefree/IPGuard/actions/workflows/windows.yml/badge.svg?branch=main)](https://github.com/gagarinbefree/IPGuard/actions/workflows/windows.yml)

IPGuard is a Windows desktop application with a status window and a system tray icon. Its goal is to control PowerShell network access based on the country associated with the computer's public IP address.

**Current stage: application shell. Network enforcement, public IP detection, and GeoIP lookup are not implemented yet. Running the application does not restrict PowerShell network access.** The interface explicitly reports that protection is unavailable and the network filter state is unknown.

## Requirements and startup

The current build requires Windows x64 and .NET SDK 10. Support for specific Windows 10/11 editions and network enforcement will be verified separately using the [VM test matrix](docs/vm-validation.md). The application does not require administrator privileges, create a Windows Service, or register automatic startup.

Run these commands from the repository root:

```powershell
dotnet restore IPGuard.slnx --locked-mode
dotnet build IPGuard.slnx --configuration Release --no-restore
dotnet test IPGuard.slnx --configuration Release --no-build --no-restore
dotnet run --project src/Desktop/Desktop.csproj --configuration Release --no-build --no-restore
```

Dependency versions are pinned in `Directory.Packages.props` and `packages.lock.json`. The SDK selection in `global.json` permits installed stable .NET 10 feature bands. To add or update a package, change its central version, restore without `--locked-mode`, and review the updated lock files.

Use the window buttons to hide the application in the tray or exit it explicitly. Closing or minimizing the window hides it while keeping the process running. Clicking the tray icon or choosing the menu action to open IPGuard restores the window. Explicit exit terminates the process and removes the icon. The current interface is in Russian.

There is no installer yet; run the build output directly. To remove the application, exit it and delete its files. It does not create network rules. Network policy installation instructions will accompany the enforcement implementation.

## Windows builds on GitHub

GitHub Actions has two sequential stages, each with its own status badge above. Both target **Windows x64 only**, using the `windows-2025` runner and the .NET 10 SDK selected by `global.json`.

1. [Tests](.github/workflows/tests.yml) runs on branch pushes, pull requests, and manual requests. It restores pinned packages in locked mode, compiles the test projects and their dependencies, and runs the safe unit and headless integration tests in Release. TRX reports are saved as `windows-test-results`, including when tests fail.
2. [Build and deploy](.github/workflows/windows.yml) starts after successful Tests for a push or manual run on this repository's `main` branch. It checks out the exact tested commit, builds the solution with a new version, publishes the desktop application, packages it with a SHA-256 checksum, and creates a [GitHub prerelease](https://github.com/gagarinbefree/IPGuard/releases). Failed tests prevent deployment. Pull requests and other branches do not publish releases.

The two workflows provide separate test and build/deployment badges. To retry the entire pipeline manually, run **Tests** on `main`; a successful run triggers Build and deploy. CI does not enable tests that modify Firewall/WFP. A successful run does not prove network enforcement or validation on every supported Windows version.

Each deployment uses version `0.1.<build-run-number>-preview.<attempt>`, for example `0.1.42-preview.1`. The build workflow's run number increases for new runs, and the attempt increases when a run is retried, so every deployment gets a different version and release tag. The version is embedded in assembly/product metadata and used in the ZIP name and `v<version>` tag. The Windows file version is `0.1.<build-run-number>.<attempt>`. Local builds default to `0.1.0-preview.local`. Releases remain prereleases while network protection is unfinished.

Download `IPGuard-<version>-windows-x64.zip` from the release, extract the entire archive, and run `Desktop.exe`; keep its DLLs and other files together. The adjacent `.sha256` file contains the archive checksum. The same ZIP and checksum are also saved as the `IPGuard-<version>-windows-x64` Actions artifact for 14 days, subject to repository policies. This is a framework-dependent build and requires the **.NET 10 runtime for Windows x64** on the target machine. It is not an installer or a self-contained executable.

To publish the same layout locally after building and testing:

```powershell
dotnet publish src/Desktop/Desktop.csproj --configuration Release --runtime win-x64 --self-contained false --no-build --no-restore --output artifacts/publish/win-x64
```

## Architecture

The GUI uses Avalonia 12.1.3, Avalonia.Markup.Declarative 12.1.1, and CommunityToolkit.Mvvm 8.4.2. Views are written in C#, without AXAML, WPF, or WinForms. Controls and `Avalonia.Application` are composed directly, without custom base classes.

| Project | Responsibility |
| --- | --- |
| `src/Desktop` | Entry point, dependency composition, window, view model, lifetime adapter, and tray. |
| `tests/UnitTests` | xUnit tests for view model commands through the desktop host interface. |
| `tests/IntegrationTests` | Safe headless tests for real controls, bindings, lifetime behavior, and dependency composition. |

`DesktopBootstrapper` registers dependencies. `ShellViewModel` exposes commands through CommunityToolkit.Mvvm without accessing the OS directly. `IDesktopHost` defines show, hide, and shutdown operations; `AvaloniaDesktopHost` implements them using the window and desktop lifetime. `DesktopSession` removes the icon and releases dependencies when the application exits.

The `Domain`, `Application`, `Infrastructure`, `Windows`, and `Cli` projects will be added when their code is needed. Empty projects and adapters for future operating systems are not created in advance. Network policy must remain shared between the GUI and CLI and independent of Avalonia.

## Contributing and creating forks

Before making changes, read [AGENTS.md](AGENTS.md) and the [development skill](skills/ipguard-development/SKILL.md). For new behavior, first add a failing test, then implement the smallest working change and refactor. Follow DRY, KISS, YAGNI, single responsibility, and the XML documentation requirements for classes, methods, and properties. Write all code comments, including test comments, and this README in English.

Use short commit messages with simple English words, such as `Add Windows build` or `Fix tray menu`.

To add a shell action, implement the operation in the appropriate component, expose a view model command, and bind it in `Views`. Test the command without a window and test interaction through the headless platform. Future network actions must call Application use cases instead of placing WFP rules in button handlers.

When changing views, use the API of the pinned Avalonia.Markup.Declarative version. The shell uses supported `Binding` instances with `nameof` and verifies them through pointer clicks in headless tests. Examples from the master branch may target a different API. See the [community library](https://github.com/AvaloniaCommunity/Avalonia.Markup.Declarative) and [Avalonia headless testing documentation](https://docs.avaloniaui.net/docs/testing/headless-xunit).

## Testing and limitations

A normal `dotnet test` run does not launch a native window, contact public IP services, or change Firewall/WFP. The current 3 unit tests and 9 integration tests cover the shell only. The headless platform does not verify native system tray clicks or the Explorer lifecycle.

To save a window preview from the headless test, provide an absolute output path whose parent directory exists:

```powershell
New-Item -ItemType Directory -Path artifacts -Force
$env:IPGUARD_PREVIEW_PATH = Join-Path (Get-Location) 'artifacts/desktop-preview.png'
try {
    dotnet test tests/IntegrationTests/IntegrationTests.csproj --configuration Release --no-build --no-restore --filter FullyQualifiedName~Window_ShowsThatProtectionIsNotImplemented
} finally {
    Remove-Item Env:IPGUARD_PREVIEW_PATH
}
```

Real network tests require an explicitly enabled mode in an isolated Windows VM. Neither these tests nor the network enforcement adapter exists at this stage. Even after implementation, blocking known PowerShell executable paths will not block child applications or unknown portable copies, and will not provide protection against a system administrator.

Research and remaining acceptance criteria: [technical decisions](docs/technical-research.md), [implementation plan](docs/implementation-plan.md), and [VM validation program](docs/vm-validation.md).
