# IPGuard

[![Tests](https://img.shields.io/github/check-runs/gagarinbefree/IPGuard/main?nameFilter=Test%20Windows%20x64&label=tests)](https://github.com/gagarinbefree/IPGuard/actions/workflows/windows.yml)
[![Build and deploy](https://img.shields.io/github/check-runs/gagarinbefree/IPGuard/main?nameFilter=Build%20and%20deploy%20Windows%20x64&label=build%20and%20deploy)](https://github.com/gagarinbefree/IPGuard/actions/workflows/windows.yml)
[![Latest release](https://img.shields.io/github/v/release/gagarinbefree/IPGuard?label=version)](https://github.com/gagarinbefree/IPGuard/releases/latest)

[Download the latest Windows x64 EXE](https://github.com/gagarinbefree/IPGuard/releases/latest/download/IPGuard-win-x64.exe)

IPGuard is a Windows desktop application with a status window and a system tray icon. Its goal is to control PowerShell network access based on the country associated with the computer's public IP address.

**Current stage: application shell and an unconnected WFP prototype for blocks, temporary permits, and policy removal. Running the application does not restrict PowerShell network access.** Public IP detection, GeoIP lookup, route validation, and protection lifecycle handling are not implemented yet. The interface explicitly reports that protection is unavailable and the network filter state is unknown.

## Requirements and startup

Building from source requires Windows x64 and the **.NET SDK 10.0.401** pinned in `global.json`. Release executables include the .NET runtime. Support for specific Windows 10/11 editions and network enforcement will be verified separately using the [VM test matrix](docs/vm-validation.md). The application does not require administrator privileges, create a Windows Service, or register automatic startup.

Run these commands from the repository root:

```powershell
dotnet restore IPGuard.slnx --locked-mode
dotnet build IPGuard.slnx --configuration Release --no-restore
dotnet test IPGuard.slnx --configuration Release --no-build --no-restore
dotnet run --project src/Desktop/Desktop.csproj --configuration Release --no-build --no-restore
```

Dependency versions are pinned in `Directory.Packages.props` and `packages.lock.json`. The SDK, single-file analyzer, and release runtime are pinned for reproducible restore and publication. To add or update a package or SDK, update the corresponding version, restore without `--locked-mode`, and review the updated lock files. Keep the Windows publish profile's runtime version up to date when shipping self-contained builds.

Use the window buttons to hide the application in the tray or exit it explicitly. Closing or minimizing the window hides it while keeping the process running. Clicking the tray icon or choosing the menu action to open IPGuard restores the window. Explicit exit terminates the process and removes the icon. The current interface is in Russian.

There is no installer yet; run the build output directly. To remove the application, exit it and delete its files. It does not create network rules. Network policy installation instructions will accompany the enforcement implementation.

## Windows builds on GitHub

The [Windows CI workflow](.github/workflows/windows.yml) has two sequential jobs, each with its own check status badge above. Both target **Windows x64 only**, using the `windows-2025` runner and the .NET 10 SDK selected by `global.json`.

1. **Test Windows x64** runs on branch pushes, pull requests, and manual requests. It restores pinned packages in locked mode, compiles the test projects and their dependencies, and runs the safe unit and headless integration tests in Release. TRX reports are saved as `windows-test-results`, including when tests fail.
2. **Build and deploy Windows x64** depends on successful tests through `needs: tests` and runs for pushes or manual runs on `main`. It checks out the same commit, builds a self-contained executable with a new version, verifies its file layout and version metadata, and creates a [GitHub Release](https://github.com/gagarinbefree/IPGuard/releases/latest) with the EXE, SHA-256 checksum, and generated release notes. Failed or cancelled tests prevent deployment. Pull requests and other branches do not publish releases.

Workflow concurrency is shared by both jobs: a new run for the same Git ref cancels the previous run, including running tests or a running build/deployment job. Branches and pull requests have separate concurrency groups. To retry the pipeline manually, run **Windows CI** on `main`. The badges use Shields.io check runs filtered by the individual job names on `main`.

CI does not enable tests that modify Firewall/WFP. A successful run does not prove network enforcement or validation on every supported Windows version.

Each deployment uses the Windows version `0.1.<run-number>.<attempt>`, for example `0.1.42.1`. The workflow's run number increases for new runs, and the attempt increases when a run is retried, so every deployment gets a different version and release tag. This version is embedded in assembly/product and Windows file metadata and appears in the `IPGuard v<version>` release title and `v<version>` tag. Local builds default to `0.1.0-preview.local`.

Download and run **[IPGuard-win-x64.exe](https://github.com/gagarinbefree/IPGuard/releases/latest/download/IPGuard-win-x64.exe)**. It is a single self-contained file with .NET 10.0.13 and native libraries included; a separate .NET installation is unnecessary. Native libraries are extracted to the .NET bundle cache on startup. `IPGuard-win-x64.exe.sha256` contains the checksum. Both files are also saved as the `IPGuard-<version>-windows-x64` Actions artifact for 14 days, subject to repository policies. This is a portable application shell; an installer and network enforcement are still under development.

The version badge and download link follow the latest release automatically. README updates do not require a bot commit. The workflow follows the test, publish, and release pattern in [AvaWeather](https://github.com/gagarinbefree/AvaWeather/blob/ccf1396f694eb166935d2fd14250a1022e4a0350/.github/workflows/dotnet-tests.yml), with Windows x64 as its current target.

To publish the same executable locally after testing:

```powershell
dotnet restore src/Desktop/Desktop.csproj --locked-mode -p:PublishProfile=Windows
dotnet publish src/Desktop/Desktop.csproj --configuration Release --no-restore -p:PublishProfile=Windows --output artifacts/publish/win-x64
```

## Architecture

The GUI uses Avalonia 12.1.3, Avalonia.Markup.Declarative 12.1.1, and CommunityToolkit.Mvvm 8.4.2. Views are written in C#, without AXAML, WPF, or WinForms. Controls and `Avalonia.Application` are composed directly, without custom base classes.

| Project | Responsibility |
| --- | --- |
| `src/Desktop` | Entry point, dependency composition, window, view model, lifetime adapter, and tray. |
| `src/Windows` | Prototype WFP baseline, permit lease, verified object selection for removal, native interop, application IDs, and inspection. |
| `tests/UnitTests` | Shell commands, baseline/permit/removal operations with fake sessions, handle lifetime, ownership checks, pointer-array traversal, and native layouts. |
| `tests/IntegrationTests` | Safe headless UI tests, App ID resolution, VM safety/scenario tests with fakes, and one explicitly gated native VM test. |

`DesktopBootstrapper` registers dependencies. `ShellViewModel` exposes commands through CommunityToolkit.Mvvm without accessing the OS directly. `IDesktopHost` defines show, hide, and shutdown operations; `AvaloniaDesktopHost` implements them using the window and desktop lifetime. `DesktopSession` removes the icon and releases dependencies when the application exits.

The `Domain`, `Application`, `Infrastructure`, and `Cli` projects will be added when their code is needed. Empty projects and adapters for future operating systems are not created in advance. Network policy must remain shared between the GUI and CLI and independent of Avalonia.

The Windows prototype is intentionally separate from desktop dependency registration. `WfpBlockPolicy` creates one management session per operation. `Install` validates full PowerShell paths and resolves Windows App IDs before starting a write transaction. It creates persistent owned provider/sublayer objects and four application-scoped Block filters: ALE connect and receive/accept for IPv4 and IPv6. It verifies ownership and existing filter definitions, rejects conflicts without replacing objects, and aborts the transaction when an operation fails. Rollback failures preserve both errors.

`Inspect` uses a read-only transaction and reports `Present`, `Incomplete`, or `Unknown`. These describe the stored objects. **`Present` does not mean traffic blocking has been verified**, and read or snapshot failures never produce a successful result.

`WfpBlockPolicy.Uninstall` is a prototype removal API intended only for explicit uninstallation in the isolated VM. It reads a fresh filter snapshot inside one write transaction and validates all related objects before deleting anything. Removal derives the existing version-one keys from stored opaque App IDs, so it does not require the executable files or the current path configuration. Only exact owned persistent blocks are accepted, with an exception for their disabled-state bit; disabled objects still do not count as active enforcement. Active Permit filters, unknown schemas, mismatched ownership, and foreign references prevent removal.

Blocks are deleted before the owned sublayer and provider. Each delete is followed by an absence check. Missing objects are tolerated without recreating them, and failures before commit attempt rollback of all staged changes. Unreadable dependent objects can prevent container deletion; they are not force-deleted. Operation, enumeration cleanup, rollback, and session-close errors remain visible. A close failure after a successful commit does not mean that removal was rolled back. **Uninstall intentionally removes protection and must never be used as the normal Block action.** It does not remove application files, manage startup, or replace the future installer.

`WfpPermitLease.Open` owns a separate dynamic session. In one write transaction it verifies all required baseline objects before adding any Permit. Permits use distinct keys, the same App ID and ALE layers, a higher weight in the same owned sublayer, and no persistent or hard-permit flags. Persistent blocks are retained. A failed grant attempts rollback of a started transaction and session closure; operation, rollback, and close errors remain observable. Baseline installation rejects dynamic sessions, and permit creation rejects non-dynamic sessions.

Disposing a lease closes only its own session. `IsClosed` becomes true only after successful session closure; it does not confirm traffic blocking or the absence of other owners' permits. A close error is preserved and rethrown on later disposal calls. The native handle is not reused after that error because its validity is undocumented; the actual BFE state remains unknown. A finalizer only attempts cleanup for a handle that has never been closed explicitly. [WFP session lifetimes](https://learn.microsoft.com/en-us/windows/win32/fwp/object-management) and [close results](https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmengineclose0) still require real VM validation.

The permit prototype is **for controlled VM experiments only**: it scopes by application, without proving or restricting a verified external route. It does not expire grants, handle a hung owner, or enforce a single owner across processes. Do not enable it as a production allow mode. The prototype has no boot-time policy or installer/uninstaller executable. Its mutating APIs, including removal, have not been run on the development machine or validated in a VM. Use only a disposable isolated administrator VM for future write experiments; the normal desktop executable has no reference to this adapter.

## Contributing and creating forks

Before making changes, read [AGENTS.md](AGENTS.md) and the [development skill](skills/ipguard-development/SKILL.md). For new behavior, first add a failing test, then implement the smallest working change and refactor. Follow DRY, KISS, YAGNI, single responsibility, and the XML documentation requirements for classes, methods, and properties. Write all code comments, including test comments, and this README in English.

Use short commit messages with simple English words, such as `Add Windows build` or `Fix tray menu`.

To add a shell action, implement the operation in the appropriate component, expose a view model command, and bind it in `Views`. Test the command without a window and test interaction through the headless platform. Future network actions must call Application use cases instead of placing WFP rules in button handlers.

When changing views, use the API of the pinned Avalonia.Markup.Declarative version. The shell uses supported `Binding` instances with `nameof` and verifies them through pointer clicks in headless tests. Examples from the master branch may target a different API. See the [community library](https://github.com/AvaloniaCommunity/Avalonia.Markup.Declarative) and [Avalonia headless testing documentation](https://docs.avaloniaui.net/docs/testing/headless-xunit).

For Windows filtering changes, keep native calls behind `IWfpSession` and test policy operations with a fake session. Extend the native serialization tests when changing fields or ownership metadata, and verify actual enforcement separately in the VM matrix. A fork that must coexist with IPGuard must choose its own provider/sublayer GUIDs and owner marker in `WfpPolicyIds`; these identifiers define policy ownership. Update the storage-key compatibility fixture deliberately when changing the namespace for a fork; shipped releases must preserve their existing key format.

## Testing and limitations

A normal `dotnet test` run does not launch a native window, contact public IP services, or change Firewall/WFP. It passes 129 unit tests and 36 safe integration tests, and **skips one native WFP VM test** with an explicit reason. The safe tests cover the shell, WFP transactions and permit lifetime through fakes, atomic uninstall, native handle errors, removal ownership, pointer-array traversal, x64 layouts, VM authorization, scenario cleanup, and real App ID resolution. The latter calls `FwpmGetAppIdFromFileName0` without adding policy objects. One safe test starts a hidden PowerShell process to verify that the VM script rejects missing confirmations. Native enumeration and deletion have not been executed on the development machine. The headless platform does not verify native system tray clicks or Explorer lifecycle.

The manual object test and its runner are described below. GitHub Actions explicitly disables VM mode, and the gate refuses to run when `CI` or `GITHUB_ACTIONS` is present. An ordinary successful CI run with a skipped VM test is not native WFP validation.

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

## Manual WFP object test in a disposable VM

The source includes one real mutating test, `WfpVmPolicyTests.PolicyObjects_CompleteRoundTrip`, tagged `Category=WfpVm`. **It has not been executed in a VM yet.** It checks creation, object readback, a temporary Permit, refusal to uninstall with active permits, confirmed session closure, and repeated uninstall. It creates rules only for a private copy of `powershell.exe` in the results directory. It does not execute that copy or send test traffic, so even a successful run proves only the object lifecycle.

Prepare an isolated Windows x64 VM with the pinned SDK, a host checkpoint, and console access independent of networking. Use an elevated terminal in that VM and replace the sample names with the real VM and checkpoint names:

```powershell
.\scripts\Test-WfpVm.ps1 -ConfirmIsolatedVm -ConfirmSnapshot -MachineName 'IPGuard-VM' -SnapshotName 'Before-IPGuard'
```

The switches attest isolation and an existing checkpoint; software inside the guest cannot verify those facts. The script also checks the machine name and elevation, temporarily sets the test authorization variables, and restores the previous environment and working directory. A missing, failed, skipped, or empty TRX report makes the script fail. It does not request UAC elevation or enable this mode in CI. Details of the environment protocol are in the [VM validation program](docs/vm-validation.md).

The test rejects any pre-existing IPGuard provider or sublayer, including partial installations, and serializes VM runs with a named mutex. It records OS edition, runtime and assembly version, executable hash, actual filter IDs/flags/conditions, and phase timestamps under `artifacts/wfp-vm/<run>/`, alongside TRX output. The PowerShell copy is retained as evidence. A scenario failure stops further removal; any installed baseline remains for investigation. Export the evidence and restore the checkpoint before retrying. Do not reset Firewall, force-delete unknown objects, or run cleanup against an existing installation.

Actual TCP/UDP enforcement tests, boot validation, process-crash recovery, and the complete enforcement lifecycle remain unimplemented. Presence tests and a successful build do not prove filter arbitration, activation after boot, revocation on process failure, or termination of existing flows. Blocking known PowerShell executable paths will not block child applications or unknown portable copies, and will not provide protection against a system administrator.

Research and remaining acceptance criteria: [technical decisions](docs/technical-research.md), [implementation plan](docs/implementation-plan.md), and [VM validation program](docs/vm-validation.md).
