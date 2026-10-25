# IPGuard

[![Tests](https://img.shields.io/github/check-runs/gagarinbefree/IPGuard/main?nameFilter=Test%20Windows%20x64&label=tests)](https://github.com/gagarinbefree/IPGuard/actions/workflows/windows.yml)
[![Build and deploy](https://img.shields.io/github/check-runs/gagarinbefree/IPGuard/main?nameFilter=Build%20and%20deploy%20Windows%20x64&label=build%20and%20deploy)](https://github.com/gagarinbefree/IPGuard/actions/workflows/windows.yml)
[![Latest release](https://img.shields.io/github/v/release/gagarinbefree/IPGuard?label=version)](https://github.com/gagarinbefree/IPGuard/releases/latest)

[Download the latest Windows x64 EXE](https://github.com/gagarinbefree/IPGuard/releases/latest/download/IPGuard-win-x64.exe)

IPGuard is a Windows desktop application with a status window and a system tray icon. Its goal is to control PowerShell network access based on the country associated with the computer's public IP address.

**Current stage: application shell, Windows network monitoring, periodic local route/proxy/RAS diagnostics with expiring snapshots, combined public IP and local GeoIP assessment, validated database updates, and an unconnected WFP prototype for blocks, temporary permits, and policy removal. Running the application does not restrict PowerShell network access.** Monitoring, diagnostics, assessment, and updating are not connected to the desktop. Periodic public IP assessment, route enforcement, and protection lifecycle handling are not implemented yet. The interface explicitly reports that protection is unavailable and the network filter state is unknown.

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
| `src/Domain` | Deterministic public IP prerequisites, shared source consensus, interval freshness, network generation, address-bound country, and both IP families. |
| `src/Application` | Combined address assessment, generation-bound public IP and local diagnostics, serial periodic diagnostic refresh, country database/download contracts, and cached network snapshots. |
| `src/Infrastructure` | Direct per-family HTTPS transport, public address parsing, source defaults, complete attempt results, local MMDB decoding, and staged database updates. |
| `src/Windows` | Cached network generations, native notifications, route/interface reads, limited WinHTTP/proxy/RAS reads, and prototype WFP baseline, permit lease, removal, application IDs, and inspection. |
| `tests/UnitTests` | Public IP eligibility, shell commands, baseline/permit/removal operations with fake sessions, handle lifetime, ownership checks, pointer-array traversal, and native layouts. |
| `tests/IntegrationTests` | Safe headless UI, local socket/TLS/body-deadline checks, App ID resolution, VM safety/scenario tests with fakes, and one explicitly gated native VM test. |

`DesktopBootstrapper` registers dependencies. `ShellViewModel` exposes commands through CommunityToolkit.Mvvm without accessing the OS directly. `IDesktopHost` defines show, hide, and shutdown operations; `AvaloniaDesktopHost` implements them using the window and desktop lifetime. `DesktopSession` removes the icon and releases dependencies when the application exits.

The `Cli` project will be added when its code is needed. Empty projects and adapters for future operating systems are not created in advance. Domain has no project dependencies; Application depends on Domain, Infrastructure depends on Application, and Windows implements Application's network boundary. Network policy must remain shared between the GUI and CLI and independent of Avalonia.

### Public IP prerequisites

`PublicIpPolicy` evaluates immutable `NetworkAssessment` evidence with an explicit current time and network generation. It has no package, GUI, Windows, HTTP, or WFP dependencies. The default country allowlist contains only `US`; an explicit allowlist replaces it, and an empty list accepts no country. Country codes must contain two ASCII letters; casing and surrounding whitespace are normalized.

Both IPv4 and IPv6 must be accounted for. Each available family needs successful, agreeing replies from at least two independent configured operators and a local GeoIP lookup bound to exactly that address. Two endpoints from the same operator count as one operator. Any failed or conflicting reply invalidates the assessment, even if two other sources agree. Missing or unknown families, wrong-family replies, scoped/mapped IPv6, stale evidence, expired database evidence, unknown countries, and changed network generations remain ineligible. Age is measured from the start of collection, with an exclusive deadline; late completion does not refresh old evidence.

The result exposes `Reason`, the failing `Family` when relevant, and `IsEligible`. **Eligibility is not permission to access the network.** The most favorable result is `EligibleForRouteValidation`; no Allow state or trusted-route switch exists. HTTPS agreement does not establish a common exit for arbitrary PowerShell traffic. A family reported as unavailable also needs enforcement confirmation before a future grant. There is no route enforcement implementation yet, and the desktop does not invoke this policy or open a permit.

These types describe internal adapter output, not untrusted HTTP response models. Adapters must validate TLS, response format, public address ranges, and source operator configuration; include every configured request attempt; establish database validity; and collect all evidence within the assessment interval. The domain checks address family and agreement but is not a global address-range classifier. The HTTPS, local database, and Windows monitoring adapters below produce evidence. Enforcement orchestration must separately recheck network generation and freshness when applying and revoking policy; a returned object cannot expire or revoke a permit on its own.

### HTTPS public IP adapters

`PublicIpReader` uses a caller-owned `IPublicIpTransport`. The real implementation, `HttpsPublicIpTransport`, validates certificates and hostnames through the system TLS stack, disables proxies, redirects, cookies, and decompression, and creates fresh connections. DNS and TCP are restricted to the requested family; failure of IPv6 does not fall back to IPv4. HTTP/1.1 is selected explicitly so the socket callback remains responsible for connections. The caller sets a finite deadline covering DNS, connection setup, TLS, headers, and body reading. Caller cancellation is propagated separately from a timed-out attempt.

Only status 200 and uncompressed `text/plain` are accepted. An absent charset, UTF-8, or US-ASCII is supported. The complete body is capped at 128 bytes regardless of Content-Length. Parsing rejects multiple addresses, JSON/HTML, BOMs, non-ASCII text, ambiguous IPv4 notation, scoped/mapped IPv6, wrong-family replies, and nonpublic ranges. A conservative IANA snapshot reviewed on 2026-10-24 rejects all IPv4 special-purpose ranges, multicast/reserved space, and IPv6 outside listed global-unicast allocations or inside excluded special ranges. This intentionally excludes some globally reachable special-purpose anycast addresses. The static snapshot needs review when allocations change; it does not prove BGP reachability or a common external exit.

`PublicIpSources.Defaults` provides two configured operators per family:

| Operator | IPv4 endpoint | IPv6 endpoint |
| --- | --- | --- |
| ipify | `https://api.ipify.org/` | `https://api6.ipify.org/` |
| ident.me | `https://4.ident.me/` | `https://6.ident.me/` |

Endpoint formats were checked against [ipify documentation](https://www.ipify.org/), [ident.me](https://www.ident.me/), and its [mirror's API documentation](https://api.tnedi.me/). ident.me and tnedi.me belong to the same operator group and must not count as independent sources. Defaults are configuration, not an assurance of source honesty or infrastructure independence. There were no live public endpoint calls from the application during this stage; test addresses are synthetic.

`ReadAllAsync` starts every supplied attempt and returns an immutable list in configuration order, including failed and conflicting replies. Results carry `PublicIpReadStatus`, optional HTTP status, and a domain `PublicIpObservation`; every failure has a null address. `PublicIpReader` implements Application's `IPublicIpProbe`. Shared `PublicIpSource`, `PublicIpReadStatus`, and `PublicIpReadResult` contracts are in `IPGuard.Application.PublicIp`; HTTP clients and parsing stay in Infrastructure. The domain remains the single owner of consensus and country rules.

### Collection and network changes

`PublicIpCollector` composes a probe, an `INetworkSnapshotProvider`, copied source configuration, and an injectable UTC clock. It captures the starting time and cached network state, probes only explicitly available families, then checks the network again before returning a `PublicIpSnapshot`. A known network requires a nonempty generation, explicit availability for both families, and a cancellable invalidation signal. Unknown state starts no requests. Failed HTTPS requests never establish family absence.

The provider must return an atomic cached snapshot. Every relevant route/interface/VPN change must permanently cancel the old signal and use a new generation, including disconnect/reconnect cycles. The signal is linked to in-flight probing. Late replies, changed generations, altered family availability, replacement signals, and clock rollback produce no snapshot. Missing, extra, reordered, substituted, or malformed probe results are rejected. Unexpected boundary failures retain the original exception in `Error`; caller cancellation is propagated. All request failures and conflicts remain visible when collection itself completes.

`Completed` means collection finished; it is not an access decision. The returned snapshot records its interval, network state, and immutable attempts. Its network invalidation token remains live after completion. Consumers must check that token, the current generation, and freshness again before using the data; a final capture cannot make future network changes impossible. The collector does not apply filters, schedule checks, perform GeoIP lookup, or establish an enforced exit. `NetworkAssessor` below extends its interval through local lookup. Enforcement orchestration is still required.

### Windows network generations

`WindowsNetworkMonitor` implements `INetworkSnapshotProvider`. Construct it with `using` to register Windows IP Helper notifications for routes, IP interfaces, and unicast addresses in both families. Registration precedes the first background read. `Capture()` only returns an atomic cached snapshot; it performs no OS or network I/O and returns null during refresh, after a read failure, or after disposal. Each published snapshot has a new version and one permanent cancellation token. A change first clears the cache and latches cancellation, then queues a serialized background read. Changes during reading discard that read; notification bursts are coalesced without reusing generations.

Family availability is deliberately conservative. An up, non-loopback interface with a configured unicast address selects that family's public IP probes. Private IPv4 and link-local IPv6 remain candidates, without a reachability claim. No candidate means `Unknown`, never proven `Unavailable`; an IPv4-only machine therefore cannot pass assessment until IPv6 absence is independently established. Loopback, unspecified, and IPv4-mapped IPv6 addresses do not select probes. Interface configuration does not establish a default route, VPN status, shared public exit, or coverage of every network compartment.

`Refresh()` invalidates evidence and requests a new read; it also permits an explicit retry after a notification fault. `LastError` retains read, notification, observer, or cleanup failures; a successful read clears previous errors. Source faults stay unknown even if an earlier refresh was already queued. `Dispose()` cancels the current generation and unregisters all native subscriptions. It does not wait for arbitrary token consumers; their exceptions are observed. Cancellation is latched synchronously through `CancelAsync`, with consumers running asynchronously so they can dispose the monitor outside the native callback stack. Failed native cancellation is reported, retains the delegate root, and can be retried with `Dispose()`. If initialization and cleanup both fail, both errors are reported and the remaining native root is retained until process exit.

The monitor does not discover public IP changes behind NAT, proxy-only changes, or all per-application VPN behavior. The local diagnostic loop below periodically rereads configured proxy and RAS observations; a periodic public IP assessment scheduler is still required. Notifications are asynchronous OS signals, not a kernel guarantee of instantaneous revocation. The monitor does not apply filters or terminate established connections. Safe integration tests exercise real registration/read/cleanup and controlled native-shaped changes; actual route/interface/VPN transitions require isolated VM validation. The desktop does not construct this component yet.

### Local route diagnostics

`WindowsRoutingTableReader` implements Application's `IRoutingTableReader` using read-only `GetIpForwardTable2(AF_UNSPEC)` and `GetIpInterfaceEntry` calls. It copies all observed IPv4/IPv6 routes, including specific routes, on-link and loopback entries, rather than inspecting default gateways alone. Each `NetworkRoute` preserves its destination CIDR, next hop including IPv6 scope, interface identity/index, route metric, interface metric, connection flag, disabled-default-route flag, and remaining route lifetime. Address text and returned lists are immutable. The metric sum uses 64 bits and is null when a component is unspecified; it does not rank routes or select an exit.

Interface metadata is cached by family, LUID, and index within one read only. A failed interface query, malformed address/prefix, identity mismatch, missing buffer, or table above 65,536 rows fails the entire read. Prefix validation rejects host bits instead of silently normalizing them. Every owned native table is released once, including on failure or cancellation; combined read/cleanup failures retain both errors. The adapter is verified for Windows x64. The native layouts were checked against Windows SDK 10.0.26100.0 and are protected by layout tests; a C++ compiler is not required to build IPGuard.

`RouteDiagnosticsCollector` composes this reader, `INetworkSnapshotProvider`, and an optional UTC clock. Call `Collect(cancellationToken)` off the UI thread: OS reads are synchronous, with cooperative cancellation between calls and rows, not interruption of a running native call. It copies complete diagnostics only within one observed generation, checks both captures and the original latch after the final clock read, and rejects clock rollback. Unknown family availability still permits diagnostics; a missing generation or unusable latch prevents reads. `RouteDiagnosticsResult` separates completion, unavailable/changed networks, invalid timestamps, and operational failure. Returned snapshots retain their interval and live invalidation token, which consumers must recheck along with age before use.

These are observations from the API caller's local context, not an atomic OS transaction or proof of coverage of all network compartments. Route and interface queries occur separately, and Windows notifications can arrive later. Empty tables, zero lifetimes, disconnected interfaces, default routes, and favorable metrics never prove an allowed PowerShell exit or family absence. Proxy redirects, per-application VPN behavior, source-specific routing, and a common public exit remain unverified. The collector does not change family availability, grant WFP permits, or contact public services. The desktop does not invoke it yet. Real route changes and enforcement require isolated VM validation.

### Proxy and remote-access observations

`WindowsProxySettingsReader` implements `IProxySettingsReader`. It reads the current user's active-connection configuration through `WinHttpGetIEProxyConfigForCurrentUser`, legacy WinHTTP registry defaults through `WinHttpGetDefaultProxyConfiguration`, and the current process's `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, and `NO_PROXY` variables. `ProxySettings` keeps eight independent flags for manual proxies, bypass settings, auto-detection, and a configured PAC URL. It does not retain proxy addresses, credentials, bypass contents, or PAC URLs. No WPAD lookup, PAC download/execution, HTTP request, or settings change is performed.

Registry defaults do not describe existing WinHTTP sessions; user settings and process variables do not describe every PowerShell process, explicit request proxy, user account, or third-party redirection. Missing user settings are an explicit read failure, not an empty configuration. Unknown/inconsistent legacy access types also fail. All returned native strings are released with `GlobalFree`, including partial results and cancellation; cleanup attempts every unique allocation and retains primary and cleanup errors. A cleanup failure prevents publication. Settings are read afresh on each call.

`WindowsRemoteAccessReader` implements `IRemoteAccessReader` using `RasEnumConnectionsW` and `RasGetConnectStatusW`. It returns immutable `RemoteAccessConnection` entries with an optional correlation ID, positive VPN-device classification, interpreted state, connection error, and raw provider states. It excludes entry names, phone numbers, phonebook paths, and endpoint addresses from its results. Connection errors remain distinct from API errors. IKEv2 dormant/reconnecting substates remain separate from `Connected`; unfamiliar states remain `Unknown`. Correlation IDs are not route interface IDs, and RAS logon-session LUIDs are not used to join routes.

RAS enumeration uses a bounded caller-owned buffer: at most 1,024 rows and four attempts. Invalid sizes/counts, unterminated device types, duplicate/missing handles, or failed status calls reject the whole observation. Borrowed RAS handles are never closed or disconnected. These limits belong to this adapter, not Windows. An empty RAS list cannot establish that no VPN is present: third-party/per-application implementations and connections not yet enumerated by RAS remain unverified. Even `Connected` does not establish split-tunnel coverage, a public exit, or an allowed country.

Both readers perform synchronous local calls and must run off the UI thread. Cancellation is cooperative between native calls and does not interrupt a running OS call. Standalone reader output has no network-generation or freshness guarantee. The combined collector below binds these observations to a generation and interval, but sequential OS reads are still not atomic. False proxy flags and an empty connection list never authorize access. Native transition tests with actual VPN connect/disconnect remain part of isolated VM validation.

### Periodic local diagnostics

`NetworkDiagnosticsCollector` composes `RouteDiagnosticsCollector`, `IProxySettingsReader`, `IRemoteAccessReader`, and cached network state. All local observations must fit within one live generation and an exclusive age limit measured before the first read. It rechecks the generation, cancellation, and clock after every reader, copies lists, and publishes no partial snapshot after failure, malformed output, expiry, or clock rollback. It uses the existing domain interval rule rather than introducing another freshness rule. Unknown IP-family availability still permits local diagnostics and never establishes public IP eligibility.

`NetworkDiagnosticsMonitor` starts collection on a background worker, coalesces refresh requests, and performs only one collection at a time. Periodic or manual refresh retires the previous observation before rereading settings, including proxy/RAS changes without a network notification. Each attempt also has an independent elapsed-time deadline armed before collection. Deadlines, generation invalidation, and disposal retire held observations through a permanent cancellation signal; late results from uncooperative readers are discarded. `Capture()` performs no OS reads: it rechecks cached generation, UTC ordering, and elapsed age before returning current observations. Timer callbacks are subject to runtime scheduling, so consumers must recheck both the observation token and its network token, and freshness immediately before use. These tokens do not revoke WFP permits.

Construct the collector with the local Windows adapters and the monitor with a refresh interval. For example, use `TimeSpan.FromSeconds(30)` for the collector's maximum age and `TimeSpan.FromSeconds(10)` for refresh. Both monitor timers support 1 through 4,294,967,294 milliseconds. The optional `TimeProvider` controls scheduling and elapsed time; pass its `GetUtcNow` to the collector to share its UTC clock. Tests use Microsoft's `FakeTimeProvider` without custom class inheritance. Reader/validation errors are exposed separately from cancellation callback failures, which remain latched in `LastError` across successful reads. `LastStatus` describes the latest attempt; only `Capture()` supplies current data.

Dispose the diagnostic monitor before its network provider. `Dispose()` invalidates data and stops scheduling without waiting for native readers or arbitrary consumer callbacks. A host can await `Completion` to wait for the serial reader to finish; cancellation callbacks are observed separately. No diagnostic snapshot proves a common PowerShell exit, absence of VPN/proxy use, or actual blocking. This loop does not invoke public IP or GeoIP assessment, update databases, create filters, or integrate with the GUI yet.

### Combined address assessment

`NetworkAssessor.AssessAsync(cancellationToken)` combines `PublicIpCollector`, one local database snapshot, and `PublicIpPolicy`. Its constructor takes the existing probe and network boundaries, configured sources, a database factory, the policy, and an optional clock. It has no Infrastructure, Windows, or GUI dependency. The factory transfers ownership of a new database snapshot for each call; the assessor closes it exactly once. Synchronous database opening and decoding must run off the UI thread when the scenario is integrated into the desktop.

Only an available family whose complete source set agrees is looked up. `PublicIpConsensus` owns the source rules used by both lookup selection and final policy, including operator independence. Failed and conflicting attempts remain in the diagnostic collection and the domain evidence; they are never replaced by a successful country. Unavailable families retain empty evidence. If no family has an agreed address, the database is not opened and the domain still returns a negative assessment.

The scenario checks the captured version, both availabilities, and the same live invalidation token before local work, after opening, after each lookup, and after closing the database. `PublicIpPolicy.CheckInterval` owns the shared exclusive age limit. Every checkpoint uses the start of source collection and rejects backward clock movement relative to the previous checkpoint. The final assessment interval includes opening, both lookups, and cleanup. Database identity and deadlines must remain consistent, and build-based validity is rechecked before returning. A result is bound to the original requested address even if a faulty adapter mutates its `IPAddress` argument.

`NetworkAssessmentResult.Status` separates completion from collection failures, network changes, invalid timestamps, stale evidence, unavailable GeoIP, invalid adapter output, and unexpected failures. Discarded results have no `Snapshot`. `Collection`, `Database`, `GeoIpFailure`, and `Error` retain diagnostics where available. Missing/corrupt database files, lookups reporting `UnknownCountry`, failed reads, expired/future metadata, mismatched lookup addresses or deadlines, and cleanup errors cannot publish a snapshot. Combined lookup and cleanup errors retain both original exceptions. Caller cancellation propagates.

A `Completed` result contains `Snapshot.Evidence` and its domain `Decision`; a foreign or malformed country or a source conflict can still produce a negative decision. **Even `EligibleForRouteValidation` does not authorize traffic.** `Snapshot.Network.Invalidated` stays live after return, while the recorded decision and timestamps do not update themselves. Consumers must recheck the current generation, token, and time and reevaluate policy before subsequent use. Publication cannot prevent a future network change. Database publication likewise does not mutate a completed assessment; scheduling another assessment after an update remains future orchestration work.

Safe composition tests connect the real response reader and MMDB decoder to this scenario using controlled HTTP replies and synthetic country data. They verify both-family country differences, absent countries, open failures, network invalidation during lookup, and replacement of the source file while one private database snapshot remains in use. These tests do not establish a common PowerShell exit, a real Windows monitor, or actual filter enforcement.

### Local country database

`IGeoIpCountryDatabase` in Application describes a reusable local snapshot. `MmdbCountryDatabase.Open(path, maximumAge)` loads a supplied MMDB file using the pinned Apache-2.0 [MaxMind.Db 5.2.0 reader](https://www.nuget.org/packages/MaxMind.Db/5.2.0). Loading is synchronous and must stay off the UI thread. The desktop executable does not download or bundle a database at this stage.

The download adapter uses [DB-IP Country Lite](https://db-ip.com/db/download/ip-to-country-lite), published monthly under CC BY 4.0 with attribution requirements and the MMDB [country.iso_code schema](https://db-ip.com/db/format/ip-to-country-lite/mmdb.html). **IP Geolocation by [DB-IP](https://db-ip.com/).** Keep provider attribution when distributing or displaying its data; the desktop needs attribution before GeoIP results are added to its UI. The reader also accepts compatible `GeoLite2-Country` and `GeoIP2-Country` product metadata; using those datasets requires observing their provider terms.

Opening rejects empty files, files larger than 64 MiB, unsupported products, non-2.0 format, and databases without IPv4/IPv6 support. The source is opened with write sharing disabled, hashed, and loaded through the same handle into a private snapshot, then closed. Replacing the source does not change an existing snapshot. `Info` records the product, build time, exclusive `build time + maximumAge` deadline, and SHA-256. The digest identifies loaded bytes; it does **not** authenticate the provider. File modification time does not extend validity. Opening validates metadata, not every record; a later decoding error faults the whole snapshot until explicitly reopened.

`Lookup(address, now)` makes no network requests. It rejects non-public candidate ranges, scoped/mapped IPv6, expired databases, and build dates in the future. Only `country.iso_code` is read; registered or represented country and continent are never substitutes. Missing records, malformed codes, and non-country placeholders produce no country evidence. Read failures latch with their original error, and disposal prevents further reads. Every result remains bound to the requested address and the actual freshness deadline. A fresh `US` result still requires source agreement, current network evidence, and enforced route validation; it does not open a permit.

Synthetic [MaxMind fixtures](tests/Fixtures/GeoIp/README.md) test the real decoder, including addresses whose country differs from registered country. They are not production geolocation data. `NetworkAssessor` extends collection timestamps through lookup and cleanup and rechecks the generation before returning. The consumer must recheck current time and generation when applying evidence later.

### Database updates

`DbIpCountryDownloader` implements `IGeoIpDatabaseDownload`. With a caller-owned `HttpsGeoIpDownloadTransport`, it requests only `https://download.db-ip.com/free/dbip-country-lite-<UTC yyyy-MM>.mmdb.gz`. The real transport uses system certificate and hostname validation, rejects other origins and paths, and disables redirects, proxies, cookies, and automatic decompression. Trust rests on that provider and the system HTTPS trust store. There is no independent provider signature check; CRC and SHA-256 do not establish authenticity.

One finite deadline covers headers, the complete compressed body, decompression, and destination writes. Only status 200 with a supported binary content type and no Content-Encoding is accepted. The body is limited to 16 MiB and decoded data to 64 MiB, regardless of Content-Length. The gzip checksum and decoded length are verified, including a missing-trailer case, using the pinned `System.IO.Hashing` CRC-32 implementation. Partial writes are private staging data and must never be opened as the active database. The downloader does not close the caller's destination stream, retry another host, or fall back to a previous month.

`GeoIpDatabaseUpdater(path, download, maximumAge)` requires an existing trusted local directory protected against other writers. It rejects linked files and directory components, serializes cooperating updaters through `<path>.update.lock`, and reads the active file's metadata and digest as the rollback floor. The lock file remains after release to preserve one coordination identity across calls and process restarts. The open lock handle, rather than file presence, indicates an update in progress.

The updater writes a uniquely named stage beside the target, flushes it to disk, and validates its size, MMDB metadata, provider product, build date, and freshness. An older build, different bytes with the same build date, or an active file changed outside the lock is a conflict. Identical fresh bytes return `Changed = false` without rewriting or extending validity. A corrupt or unreadable active file stops updating; it does not silently discard the rollback floor. Recovery from a corrupt baseline needs an explicit operator decision while protection remains blocked; a recovery command is not implemented yet.

Before committing, it rechecks time and cancellation. Publication uses one same-directory `File.Move(..., overwrite: true)`; there is no delete, truncate, or copy fallback. A cancellation observed before the final commit check leaves the active file unchanged. Once commit starts, successful publication is returned even if cancellation arrives afterward. Ordinary failures clean only the current operation's stage; cleanup errors retain the original failure too. A process crash can leave an orphan stage or an unlocked coordination file, neither of which is treated as active data or removed by a later update.

Publication and sharing failures are tested on Windows local files. Use a protected local filesystem; network shares, attacker-writable directories, power-loss durability, and crash-injection during rename have not been validated. Reparse-point checks do not replace directory ACLs. An already loaded database keeps its private snapshot after publication; consumers must explicitly reopen it. Candidate validation checks metadata, not every database record. Lookup faults still reject country evidence, and an update never grants network access.

A separate manual smoke check on 2026-10-24 downloaded the official October DB-IP database, validated and installed it, and performed both-family lookups of public test addresses. A second download returned unchanged with the same original build time and deadline. Provider data stays outside the repository and release EXE. Normal tests use controlled transfers and synthetic fixtures only. Scheduling updates and exposing them in the desktop/CLI remain unimplemented.

### Windows filtering prototype

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

For changes to address eligibility, add deterministic cases in `PublicIpPolicyTests` and keep `PublicIpPolicy` free of I/O. Source adapters should produce `PublicIpObservation` entries using configured operator identities; local database adapters should produce address-bound `GeoIpEvidence`. Reuse these prerequisites from Application scenarios. Do not translate `IsEligible` directly into `WfpPermitLease.Open`: granting access requires independently implemented and verified route enforcement and lifecycle control.

For collection changes, use controlled `IPublicIpProbe` and `INetworkSnapshotProvider` implementations in `PublicIpCollectorTests`, then verify composition with the real bounded reader in `PublicIpCollectionTests`. Keep source/result contracts in Application so scenarios do not reference Infrastructure. For monitoring changes, extend the Windows monitor, family-classification, and subscription unit tests, then the safe `WindowsNetworkMonitorTests` integration cases. Future OS adapters implement `INetworkSnapshotProvider` while preserving generation and invalidation semantics; a constant version or an uncancellable token cannot stand in for monitoring. Keep route mutations and actual VPN transitions in an isolated VM.

For route diagnostic changes, extend `RouteDiagnosticsCollectorTests`, `WindowsRoutingTableReaderTests`, and `NetworkRouteTests`, then verify actual read-only APIs in `WindowsRoutingTableTests`. Alternative OS adapters implement `IRoutingTableReader` without importing Windows structs into Application or Domain. Preserve complete reads, address immutability, generation invalidation, and explicit coverage limits; do not promote diagnostics to authorization.

For combined local diagnostics, extend `NetworkDiagnosticsCollectorTests` and `NetworkDiagnosticsMonitorTests`. Keep fake time and controlled reader barriers for expiry, refresh, cancellation, and shutdown races; do not add real delays or native mutations. `WindowsNetworkDiagnosticsTests` checks read-only composition with actual Windows adapters. Additional OS readers can use this Application collector and loop through the existing interfaces; public IP assessment and enforcement still require their own shared lifecycle composition.

For proxy/remote-access changes, extend `WindowsProxySettingsReaderTests`, `WindowsRemoteAccessReaderTests`, and `EnvironmentNativeLayoutTests`, then `WindowsEnvironmentReadersTests` for safe native reads. Keep alternative implementations behind `IProxySettingsReader` and `IRemoteAccessReader`. Preserve configuration errors, unknown provider states, privacy of raw settings, borrowed-handle ownership, and explicit provider coverage limits. Ordinary tests must not dial, disconnect, change proxies, resolve PAC, or create routes.

For combined assessment changes, extend `NetworkAssessorTests` for boundary failures and races, then `NetworkAssessmentTests` for real reader/decoder composition with controlled data. Keep consensus in `PublicIpConsensus` and interval age in `PublicIpPolicy.CheckInterval`. A database factory must return a separately owned snapshot on each call. Do not turn the recorded preliminary decision into a persistent permission or bypass the final generation and time checks.

For country lookup changes, keep `IGeoIpCountryDatabase` independent of the file format and provider. Extend unit coverage for stale, absent, and failed evidence, then exercise the real decoder with licensed synthetic fixtures. Keep country lookup separate from allowed-country policy and database updating. Never refresh build age from a download timestamp or reuse a prior successful country after an error.

For update changes, test transfer failures through `IGeoIpDownloadTransport` and real file publication with a synthetic `IGeoIpDatabaseDownload`. Preserve trusted-source checks, size/deadline limits, rollback protection, and the distinction between staging and active data. Ordinary tests must not download provider data or erase unrelated files. Keep the update directory protected; adapting a provider requires its own authenticated download and exact MMDB product identity.

For public IP transport changes, test response handling with a composed `IPublicIpTransport` fake, then retain local socket, TLS rejection, and stalled-body checks. Update `PublicAddressParser` and its range tests together after reviewing IANA changes. Keep all attempts visible; adding an endpoint from an existing operator does not create another independent operator. Do not add real public service dependencies to ordinary tests or weaken certificate validation to make tests pass.

To add a shell action, implement the operation in the appropriate component, expose a view model command, and bind it in `Views`. Test the command without a window and test interaction through the headless platform. Future network actions must call Application use cases instead of placing WFP rules in button handlers.

When changing views, use the API of the pinned Avalonia.Markup.Declarative version. The shell uses supported `Binding` instances with `nameof` and verifies them through pointer clicks in headless tests. Examples from the master branch may target a different API. See the [community library](https://github.com/AvaloniaCommunity/Avalonia.Markup.Declarative) and [Avalonia headless testing documentation](https://docs.avaloniaui.net/docs/testing/headless-xunit).

For Windows filtering changes, keep native calls behind `IWfpSession` and test policy operations with a fake session. Extend the native serialization tests when changing fields or ownership metadata, and verify actual enforcement separately in the VM matrix. A fork that must coexist with IPGuard must choose its own provider/sublayer GUIDs and owner marker in `WfpPolicyIds`; these identifiers define policy ownership. Update the storage-key compatibility fixture deliberately when changing the namespace for a fork; shipped releases must preserve their existing key format.

## Testing and limitations

A normal `dotnet test` run does not launch a native window, download provider databases, contact public IP services, or change Firewall/WFP. The suite includes 691 unit cases, 100 safe integration cases, and **one native WFP VM test that is skipped by default** with an explicit reason. Safe tests cover combined local diagnostics, periodic refresh with controlled time, independent expiry, late reads, reentrant retirement, read-only proxy/RAS/route/interface calls and network registration/cleanup, bounded native ownership, dormant/reconnecting states, conservative family candidates, generation and refresh races, in-flight cancellation, complete assessment intervals, real response/MMDB/policy composition, bounded gzip downloads, staged publication, rollback and update conflicts, local MMDB lookup and expiry, snapshot ownership and errors, complete source coverage, HTTPS parsing and failures, public IP prerequisites, the shell, WFP operations through fakes, native memory layouts, VM authorization, and read-only App ID resolution. The latter calls `FwpmGetAppIdFromFileName0` without adding policy objects. Tests do not change proxies/routes, run PAC, disable interfaces, or connect/disconnect VPNs on the host. Proxy and combined native-reader tests explicitly accept the documented missing-user-settings error as unavailable data, without producing settings or skipping cases. One safe test starts a hidden PowerShell process to verify that the VM script rejects missing confirmations. Native WFP enumeration and deletion have not been executed on the development machine. The headless platform does not verify native system tray clicks or Explorer lifecycle.

Network integration cases use local IPv4/IPv6 loopback, a temporary in-memory self-signed TLS server, and an asynchronous named-pipe body. They do not install certificates or change machine trust. The test environment must support IPv6 sockets and allow loopback connections. Missing IPv6 support or access denied is an explicit failure; these cases cannot silently skip in CI. Endpoint availability on the real Internet and full route enforcement require separate validation.

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
