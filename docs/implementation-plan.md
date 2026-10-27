# План реализации IPGuard

IPGuard — приложение с треем и GUI на .NET 10, Avalonia, Avalonia.Markup.Declarative и CommunityToolkit.Mvvm. Windows Service не создаётся. Все этапы подчиняются [AGENTS.md](../AGENTS.md), изменения поведения выполняются по [локальному skill TDD](../skills/ipguard-development/SKILL.md).

Решение называется `IPGuard`; проекты имеют короткие имена: `Domain`, `Application`, `Infrastructure`, `Windows`, `Desktop`, `Cli`, `UnitTests`, `IntegrationTests`. Проект создаётся при появлении нужного кода. Общие правила остаются в Domain/Application; зависимость от Avalonia и MVVM Toolkit ограничена Desktop.

## Результат шага 8b.3a: команды и lifecycle сессии

ProtectionRuntime объединяет OwnedBlockPolicy, общий BlockProtectionController и явно переданную очистку diagnostics. Constructor не выполняет I/O. Stop сразу делает controller terminal, выполняет одну финальную ensure/readback, затем закрывает diagnostics и только после этого освобождает owner. Отмена waiter отменяет только ожидание. Исходные policy/diagnostic/owner errors сохраняются в final snapshot; Dispose повторно не освобождает ресурсы и сообщает записанную ошибку. Потеря ownership отзывает cached policy observation без нового backend call. Native calls и diagnostic cleanup могут зависнуть; ownership не освобождается раньше их завершения.

ProtectionControlProtocol принимает только status/recheck/stop. Versioned JSON имеет четырёхбайтовую unsigned big-endian длину; request ограничен 256 bytes, report — 4096 bytes до allocation. Неизвестные/повторные/пропущенные поля, неподдерживаемая версия, integer command, payload с path/allow/uninstall, truncation и contradictory counts отвергаются. Ответ содержит только phase/reason, last-observed policy state/counts/UTC time и HasError; exception text, tokens и permission flags не сериализуются. Контракт счётчиков общий для backend validation и IPC report, без дублирования бизнес-правила.

ProtectionControlServer выполняет initial reconcile, затем serial commands с общим deadline 1 ms–1 minute на полный обмен. Status не пишет политику; Recheck использует тот же runtime. Stop подтверждается после финальной cleanup; EOF, malformed frame, idle timeout или cancellation закрывают transport и запускают final reconciliation независимо от request token. ProtectionControlCompletion хранит original transport/shutdown errors. Логический GUI client работает поверх GUI-owned server pipe из шага 8b.2; helper command server — поверх client pipe. ProtectionControlClient сериализует exchanges и закрывает неоднозначную connection после interrupted transaction, чтобы late reply не удовлетворил следующий запрос. Отмена queued call здоровое соединение не закрывает; Dispose прерывает active I/O и ждёт его выхода. Nonterminal Stop reply отвергается.

TDD: 38 unit и 8 safe integration случаев упали на compiled stubs и прошли после реализации. Regression воспроизвёл reentrant shutdown из cached reader: Capture держал runtime gate, возвратился Running вместо Stopped после timeout. Reader перенесён вне gate, terminal state перепроверяется, тест проходит. Ещё 4 характеризующих protocol случая проверяют exact command strings и полный malformed report; 1 integration case проверяет premature Stop acknowledgement. Итого 43 новых unit и 9 integration — проходят. Safe integration соединяет настоящие bound Windows pipes, framing, client/server, runtime и controller с non-native backend.

Полный локальный прогон после DRY refactor: 887 unit и 127 integration прошли; прежний IPv6 loopback получил WSAEACCES, один gated native WFP VM-тест пропущен. Locked restore, Release build (0 warnings/errors), solution whitespace verification и git diff check прошли. WFP, реальные VPN/proxy/routes и UAC не изменялись/не запускались. Native enforcement и boot coverage этим прогоном не подтверждаются.

Следующий шаг 8b.3b: trusted helper entry point, protected configuration/scope и UAC launcher без Windows Service, затем desktop composition и периодическая policy inspection. Этот шаг не запускает повышенный process, не устанавливает WFP и не добавляет условный helper, игнорирующий аргументы. В GUI backend не подключён. Mixed-elevation IPC, boot/crash/hang behavior и реальный enforcement остаются VM-проверками; route authorization и Permit отсутствуют.

## Результат шага 8b.2: локальный IPC transport

Реализован WindowsControlPipe: GUI-owned one-shot listener с уникальным именем, FirstPipeInstance и protected descriptor GUI user/logon SID плюс data-only Administrators ACE. Network SID получает deny, клиент не получает CreateNewInstance. CurrentUserOnly не используется, поскольку он требует одинакового elevation level. Нельзя также предполагать общий logon SID linked UAC tokens: client читает token доверенного GUI process с TOKEN_QUERY и требует тот же user account; protected ACL разрешает elevated client's Administrators SID. Client и server проверяют actual descriptor/peer PID, удерживают доверенный Process и отвергают exited peer до ожидания соединения. Client credentials ограничены Identification; фактический уровень подтверждён safe native test.

Фиксированный 18-byte version handshake и общий timeout 1 ms–1 minute не допускают unbounded frame allocation. Truncation, unsupported version, stalled input, cancellation, collision и wrong peer не возвращают stream. После success stream принадлежит caller; listener Dispose не закрывает уже переданный stream. Failed authentication закрывает listener, автоматического reconnect нет. Native token/ACL/process reads синхронны; будущий host должен перенести их с UI thread и отдельно отслеживать exit/hang.

TDD: 25 unit и 9 integration случаев сначала упали на compiled stubs. Первые unit прошли, native composition обнаружила, что WindowsIdentity.Groups исключает logon SID. Для GetTokenInformation(TokenLogonSid) сначала добавлены 9 падающих parser-тестов, затем bounded native read и проверка полного owned buffer. Дополнительный regression воспроизвёл ожидание timeout вместо раннего отказа для exited peer; исправлена initial liveness check. После исследования linked logon sessions два ACL-теста упали на старой схеме; data-only Administrators ACE и exact descriptor validation исправлены. Четыре характеризующих случая проверяют timeout bounds. Всего 39 новых unit и 10 integration — проходят, включая real child process, wrong PID с обеих сторон и Identification.

Полный локальный прогон: 844 unit и 118 integration прошли; прежний IPv6 loopback получил WSAEACCES, один gated native WFP VM-тест пропущен. Locked restore, Release build (0 warnings/errors), solution whitespace verification и git diff check прошли. На рабочей машине не запускался UAC, не открывался production policy mutex, не перечислялся и не менялся WFP; реальные proxy/VPN/routes не менялись.

Bounded commands, runtime composition и shutdown при disconnect реализованы в шаге 8b.3a выше. UAC startup, privileged helper entry point и защищённая конфигурация остаются шагом 8b.3b. Сам transport не вызывает WFP. Mixed-elevation pair, другой logon и remote-access rejection требуют isolated VM validation; обычный успешный CI не подтверждает эти сценарии. Desktop остаётся shell без подключения backend. Enforced route, installer/boot recovery, PowerShell discovery, periodic policy inspection и GUI/CLI также ещё не завершены.

## Результат шага 8b.1: защищённый единственный владелец

WindowsPolicyOwner координирует cooperating processes через фиксированный Global mutex с protected DACL и owner Administrators. Standard token не проходит public prerequisite; существующий unsafe descriptor отвергается без изменения. Захват, удержание и освобождение выполняются на одном dedicated thread; contention даёт null без ожидания, abandonment сохраняется как диагностика и требует новой сверки baseline. Отмена acquisition ждёт cleanup, но после handoff не становится скрытым lifetime token. Dispose отзывает Lost до native release; reentrant consumer callback не блокирует освобождение. Native/cleanup failures сохраняются, повторный Dispose не повторяет release.

Application получает IPolicyOwnership и OwnedBlockPolicy: wrapper сериализует backend calls, проверяет live latch до/после каждого вызова и удерживает owner до завершения uninterruptible operation. Dispose запрещает new/queued calls и освобождает lease ровно один раз. Хост должен сначала дождаться BlockProtectionController.StopAsync, затем закрыть OwnedBlockPolicy и завершить diagnostics. Нет Permit, force cleanup или изменения существующей WFP-политики.

TDD: 28 новых unit случаев упали на скомпилированных stubs и прошли после реализации. Четыре safe integration случая используют только unique test mutexes: cross-process contention, normal exit, process-death abandonment, unsafe ACL rejection без repair и protected creation либо точный native отказ текущему token. На локальном standard token подтверждён ERROR_INVALID_OWNER (1307), который MutexAcl возвращает как IOException; ожидание теста уточнено по фактическому Win32 contract. Elevated creation на локальной машине не запускался. Блокировка реального трафика этим не проверяется.

Полный локальный прогон: 805 unit и 108 integration прошли; прежний IPv6 loopback получил WSAEACCES, один gated native WFP VM-тест пропущен. Locked restore и Release build прошли с 0 warnings/errors. Avalonia build telemetry отключена штатной process environment variable, поскольку sandbox не разрешает запись её log вне workspace. Solution-level formatter не смог подключиться к build-host pipe; whitespace verification изменённых файлов в folder mode прошла. Реальные Firewall/WFP, VPN, proxy и routes не менялись; production mutex не открывался.

IPC transport реализован в шаге 8b.2 выше; privileged helper hosting без Windows Service, запуск/выход и composition diagnostics/controller/owner остаются шагом 8b.3. До подключения разрешений нужны enforced route model и isolated VM results. GUI по-прежнему shell без native policy backend; новый ownership не подключён к startup и prototype permit API. Hang handling, installer/recovery, PowerShell discovery, periodic policy inspection, GUI/CLI и полная VM-матрица остаются незавершёнными.

## Результат шага 8a: блокирующая координация и финальная сверка

Добавлены IBlockPolicy, INetworkDiagnosticsReader, BlockProtectionController и immutable ProtectionSnapshot. Контроллер разделяет phase, last-observed baseline objects/time, geography и причину отсутствия разрешения. Reconcile сериализует ensure/readback, отзывает старый inspection и запрашивает свежую диагностику. Ошибки/отмена/malformed backend results не возвращают прошлую успешную проверку. US eligibility остаётся RouteUnverified, отрицательная geography — AddressRejected; permit/uninstall API у контроллера отсутствует.

Stop сразу делает контроллер terminal, ждёт завершения уже выполняющегося блокирующего действия и запускает одну собственную финальную ensure/readback без удаления baseline. Отмена ожидания вызывающего не отменяет эту работу. Readback выполняется даже после ensure failure, обе ошибки сохраняются. Диагностический reader принадлежит хосту; контроллер не создаёт второй scheduler и не владеет lifetime monitor.

WindowsBlockPolicy использует реальные WfpBlockPolicy.Install и новый InspectBlockOnly на background tasks. Strict read-only transaction сверяет enabled required blocks и весь related namespace через существующий schema/ownership preflight; related Permit или unknown filter дают Unknown. Ничего не удаляется. WfpBaselineInspection сохраняет исходное exception, а не только message. Отмена после native commit не откатывает постоянную блокировку; выполняющийся native call не прерывается.

TDD: 40 новых unit случаев сначала упали на скомпилированных stubs и затем прошли. Дополнительный regression воспроизвёл late diagnostic failure после начала Stop; запись этого результата теперь защищена terminal state. Два safe integration случая объединяют настоящий coordinator, Windows adapter и transactions с in-memory IWfpSession: baseline остаётся, existing Permit не удаляется и не объявляется безопасным. Итого 41 новый unit и 2 integration; все проходят. Полный локальный прогон: 777 unit и 104 integration прошли; прежний IPv6 loopback — WSAEACCES, один gated native WFP VM-тест пропущен. Release build, locked restore и whitespace check прошли.

GUI по-прежнему не вызывает native policy backend, на рабочей машине WFP не перечислялся и не изменялся. Present — observation собственных объектов в завершённой транзакции, не доказанная блокировка пакетов, boot coverage или teardown существующих connections. Контроллер block-only; single owner across processes, privileged helper/IPC, зависание/авария, PowerShell discovery, периодическая сверка политики и UI hosting ещё не реализованы.

Единственный owner и проверка prerequisite реализованы в шаге 8b.1, IPC transport — в шаге 8b.2 выше; privileged hosting, lifetime диагностики/политики и запрос выхода остаются шагом 8b.3. До выдачи Permit нужны enforced route model и isolated VM results; GUI/CLI должны показывать только фактически доступное состояние. Затем installer/recovery и полная VM-матрица.

## Результат шага 7c.2: общий цикл local/public IP/GeoIP

NetworkCheckCollector объединяет существующие local collector и NetworkAssessor. Один outer generation/latch и interval начинаются до local reads; child intervals должны помещаться внутри него, а HTTP collection не перезапускает возраст. Итоговая PublicIpPolicy повторно оценивает обе семьи на полном интервале. Completed может содержать отрицательное решение по стране/источникам. При operational failure, network change, rollback или expiry Snapshot отсутствует; оригинальный Assessment сохраняет source/database/lookup diagnostics и не заменяет outer evidence.

NetworkDiagnosticsMonitor использует один serial lifecycle для local-only и full source через внутренний INetworkDiagnosticsSource. Async HTTPS batches ожидаются без параллельных попыток; late output после refresh/deadline/exit отбрасывается. Периодические full checks выявляют NAT-only смену public IP и страны без OS notification. LastFailure предоставляет причину unavailable outcome и очищается при повторной проверке/восстановлении. Earliest actual GeoIP deadline сокращает armed timer без продления исходного elapsed limit; отмена held observation не требует Capture. Общий NetworkEvidenceLifetime устраняет дублирование одинаковых generation/time checkpoints.

TDD: 30 новых collector и 9 monitor случаев прошли compiled Red → Green. Четыре дополнительных характеризующих случая проверили final outer boundary. Два regression-теста воспроизвели прежний пропуск rollback между route child и parent clock, после исправления проходят. Уточнённый тест GeoIP expiry сначала показал, что token отменялся лишь после Capture; timer теперь отзывает snapshot автоматически. Три safe integration случая объединяют настоящий PublicIpReader, MMDB decoder, domain policy и local diagnostics без реальных HTTP-запросов. Итого 45 новых unit и 3 integration; все проходят.

Полный локальный прогон: 736 unit и 102 integration прошли; прежний IPv6 loopback получил WSAEACCES, один native WFP VM-тест пропущен. Locked restore, Release build (0 warnings/errors), whitespace check прошли. Первый повторный запуск --no-build до завершения сборки взял старые assemblies; результат отброшен, последующие проверки выполнялись только после завершённого build. Реальные network settings, proxy/VPN/маршруты и WFP не менялись, внешние sources и базы не скачивались.

Eligibility по US остаётся только EligibleForRouteValidation. Common exit, enforcement и судьба установленных соединений не подтверждены этим циклом. GUI пока не создаёт collectors/monitor, сетевых ограничений нет.

Блокирующая координация реализована в шаге 8a выше, single ownership — в шаге 8b.1, IPC transport — в шаге 8b.2; privileged hosting и полный runtime lifecycle остаются шагом 8b.3. Реальные Permit возможны только после подтверждения маршрута и VM-проверки. Затем нужны GUI/CLI, installer/recovery и итоговая матрица VM.

## Результат шага 7c.1: периодические локальные диагностики

NetworkDiagnosticsCollector объединяет existing RouteDiagnosticsCollector, proxy и RAS readers. Общие generation/latch, start-to-completion interval и domain-owned exclusive age проверяются после каждой границы; список копируется, частичные результаты не публикуются. Ошибки, malformed/null results, network change, expiry и rollback имеют явные исходы. Unknown family остаётся диагностикой, не eligibility.

NetworkDiagnosticsMonitor выполняет initial/periodic/manual collection на одном background worker с coalescing очередью. Перепроверка сначала отзывает старые observations; late results отменённого reader отбрасываются. Independent elapsed deadline вооружается до collection, сетевой latch отзывает published observation, Capture заново проверяет cached generation, wall clock и elapsed age. Callback failures наблюдаются и сохраняются. Dispose не ждёт непрерываемый native read или consumer callback; Completion позволяет дождаться reader. Собственные классы не наследуются, platform dependencies остаются за существующими interfaces. FakeTimeProvider 10.9.0 добавлен только в UnitTests для deterministic timers.

TDD: 31 collector-случай сначала упал на скомпилированном stub, затем прошёл; 18 monitor-случаев аналогично прошли Red → Green. Дополнительные 2 regression-случая воспроизвели NullReferenceException при reentrant refresh/dispose из clock boundary и после исправления прошли. Добавлены 1 характеризующая проверка sub-millisecond timer и 1 safe integration тест композиции настоящих Windows readers. Итого 52 новых unit и 1 integration — все проходят.

Полный локальный прогон: 691 unit и 99 integration прошли; прежний IPv6 loopback получил WSAEACCES, один gated WFP VM-тест пропущен. Locked restore, Release build (0 warnings/errors), whitespace check прошли. Новый integration test, как и reader test, считает только точный documented missing-user-settings error явным Failed/unavailable без snapshot. Сетевые настройки, VPN, Firewall/WFP не менялись; внешние HTTPS sources не вызывались.

Срок/отмена — lifetime локальных данных, не enforcement. Timer callbacks не дают real-time guarantees; перед использованием нужны оба tokens и freshness. Sequential native reads не atomic, нет доказанного общего выхода PowerShell. GUI, публичные IP/GeoIP и WFP пока не используют этот loop.

Объединение с public IP/GeoIP реализовано в шаге 7c.2 выше. GUI/CLI, policy orchestration, installer/recovery и изолированная VM для реального enforcement остаются следующими этапами. Permit по диагностическим observations не выдаётся.

## Результат шага 7b.2: наблюдения proxy и RAS VPN

Добавлены IProxySettingsReader/IRemoteAccessReader, immutable модели и Windows-адаптеры реальных WinHTTP/RAS API. Proxy settings разделены на current-user active connection, legacy WinHTTP registry defaults и current-process environment. Результат содержит только flags, без proxy/PAC/credentials. RAS возвращает provider-visible связи, optional correlation ID, положительный VPN device marker, состояние, connection error и raw codes; имена/телефоны/endpoints исключены. Нативные дескрипторы заимствованы и не закрываются. GlobalFree проверяется для всех уникальных proxy allocations; первичные/cleanup ошибки сохраняются.

TDD: 19 скомпилированных proxy-случаев сначала упали на stub, затем прошли. 31 RAS-случай также прошёл Red; первая реализация дала 30 Green, а один тест неверно предполагал наследование InvalidDataException от IOException. Уточнены два строгих ожидания: malformed allocation — InvalidDataException, исчерпание попыток при churn — IOException. После исправления все проходят. Ещё 4 характеризующих unit-случая проверили SDK layout, cleanup failure после успеха, environment failure и свежие данные повторного read. Добавлены 2 safe integration проверки реальных native reads. Итого 56 новых случаев.

Полный локальный прогон: 639 unit и 98 интеграционных тестов прошли; прежний IPv6 loopback получил WSAEACCES, один нативный WFP VM-тест пропущен. Все новые случаи проходят. Locked restore и Release-сборка (0 warnings/errors) прошли. Нативные настройки только читались; proxy, маршруты, VPN и Firewall/WFP не изменялись, PAC/WPAD и публичные сервисы не вызывались.

Пустой RAS list не доказывает отсутствие VPN, false proxy flags не доказывают прямой PowerShell exit, Connected не доказывает общий маршрут. Dormant/reconnecting/unknown и connection error сохраняются отдельно. Reader observations пока не привязаны к поколению/сроку и не подключены к GUI. Реальные активные VPN transitions, session/per-app proxy и third-party VPN coverage остаются непроверенными; обычный integration test допускает только документированный missing-user-settings error как unavailable outcome, без подмены empty configuration.

Периодическое перечитывание и lifetime локальных наблюдений реализованы в шаге 7c.1 выше; public IP/GeoIP assessment ещё предстоит объединить с этим циклом. Этот шаг не выдаёт Permit.

## Результат шага 7b.1: диагностика локальных маршрутов

Добавлены переносимый контракт IRoutingTableReader, immutable NetworkRoute, RouteDiagnosticsCollector и WindowsRoutingTableReader с реальными GetIpForwardTable2/GetIpInterfaceEntry/FreeMibTable. Собираются IPv4/IPv6 defaults и specific routes, next hops со scope, interface identity/index, обе метрики, connection/default-route flags и remaining lifetime. Новые пакеты и проекты не понадобились; Domain и WFP не изменены.

TDD: 18 тестов collector сначала скомпилированы и упали на отсутствующем поведении, затем прошли. Следующие 17 случаев native adapter упали на stub; первая реализация прошла 16 из них. Тест host bits ожидал InvalidDataException, фактически parser молча нормализовал префикс. После явного сравнения исходного адреса с canonical base address он проходит. Ещё 13 характеризующих unit-случаев покрывают overflow/unknown metrics, mutable IPv6 address, mapped/mixed families, SDK layout, некорректные IPv6 prefixes и отмену во время cleanup. Добавлены 2 интеграционные проверки настоящих read-only API и monitor/collector. Итого 50 новых случаев.

Scope остаётся local caller context с неподтверждённым охватом compartments. Reserved API для переключения/чтения thread compartment не используются. Route/interface reads не являются одной OS transaction; notification может задержаться. Любая ошибка, смена observed generation, invalidation или clock rollback не даёт partial snapshot. Успешные данные не выбирают общий PowerShell exit, не доказывают отсутствие IPv6 и не выдают Permit. GUI по-прежнему не применяет защиту.

Полный локальный прогон: 585 unit и 96 интеграционных тестов прошли; один прежний IPv6 loopback получил WSAEACCES, один нативный WFP VM-тест явно пропущен. Все 50 новых случаев проходят. Locked restore и Release-сборка с 0 warnings/errors прошли. Нативные таблицы только читались; Firewall/WFP, маршруты, VPN и интерфейсы не менялись, публичные сервисы не вызывались.

Следующий шаг 7b.2 — диагностика VPN/proxy с явной неопределённостью и без заявления полного coverage, затем scheduler повторных публичных проверок. Разрешающий режим, installer/recovery и фактическая блокировка остаются зависимыми от проверки маршрута, оркестрации и изолированной VM.

## Результат шага 7a: реальный монитор сети Windows

WindowsNetworkMonitor реализует INetworkSnapshotProvider: три нативные read-only подписки на route/interface/unicast changes для обоих семейств, cached Capture без I/O, постоянная отмена прежнего поколения, сериализованное фоновое чтение и отбрасывание снимков, затронутых изменениями. Dispose отменяет состояние и снимает подписки вне monitor gate. CancelAsync не исполняет consumer callbacks на нативном стеке. Ошибки consumer наблюдаются, нативные roots освобождаются только после успешной отмены, частичные ошибки регистрации/cleanup сохраняются.

TDD: 11 скомпилированных тестов lifecycle сначала упали, затем прошли. Далее 27 тестов classification/native ownership упали на отсутствующем поведении и прошли после реализации. Отдельный регрессионный тест воспроизвёл race: queued initial read стирал notification fault (ожидалась ошибка, фактически null). Fault latch теперь удерживает unknown до явного Refresh. Ещё 4 характеризующих случая проверяют missing handle и запрет native cleanup на callback stack. Всего добавлены 43 unit и 7 интеграционных случаев; все 50 проходят. Интеграционные проверки включают настоящие registration/read/cleanup, controlled отмену collection по всем трём видам изменений и invalidation после возврата реальной MMDB-оценки.

Полный локальный прогон: 537 unit и 94 интеграционных теста прошли; 1 прежний IPv6 loopback получил WSAEACCES, 1 WFP VM-тест явно пропущен. Release-сборка — 0 warnings/errors. Firewall/WFP, маршруты, состояние интерфейсов и VPN рабочей машины не менялись; публичные IP-сервисы не вызывались.

Available означает configured candidate, а не доказанный Internet path. Отсутствующее семейство остаётся Unknown; IPv4-only компьютер пока не проходит полную оценку. Нативные изменения маршрутов/VPN не генерировались на рабочей машине и требуют VM. Public-IP смена за NAT и proxy-only изменения могут не вызвать эти уведомления. Монитор не выдаёт Permit и ещё не подключён к Desktop.

Следующий шаг 7b: read-only диагностика маршрутов, VPN/proxy и compartments, затем scheduler повторных публичных проверок и отзыв устаревших результатов. До доказанного маршрута, оркестрации WFP и испытаний в изолированной VM GUI остаётся оболочкой без сетевой защиты.

## Этапы и критерии приёмки

| Этап | Работа | Проверяемый результат |
| --- | --- | --- |
| 1. Исследование | Сравнить Firewall/WFP, сроки жизни фильтров, права, маршруты, существующие соединения и жизненный цикл GUI. | [Исследование](technical-research.md) и [матрица VM](vm-validation.md) содержат решения, источники и открытые условия выпуска. Анализ документации завершён; сетевые гарантии ещё не подтверждены. |
| 2. Структура и минимальный GUI | Создать основу решения, строгие настройки .NET 10, xUnit и минимальный Desktop с закреплённой совместимой связкой UI-пакетов. Через тесты определить поведение закрытия окна и Exit. | Сборка и безопасные тесты проходят; GUI показывает окно и трей без реальных изменений сети. Проверены декларативные привязки и подход с композицией без собственных иерархий классов. |
| 3. Прототип WFP | Написать падающие тесты контракта адаптера, затем минимальную реализацию постоянного Block и динамического Permit. Проверить runtime-привилегии без службы. | В разрешённой VM проверены приоритеты, падение процесса, загрузка и провайдер без service association. До этого модель остаётся прототипом; разрешающий режим выпуска не готов. |
| 4. Доменная политика | Реализовать решение по стране, свежести, конфликтам источников, обоим семействам адресов и достаточности маршрута. | Детерминированные xUnit-тесты подтверждают Block при любой неопределённости; причина решения пригодна для GUI и CLI. |
| 5. Публичные адреса | Реализовать независимые HTTPS-источники, ограничение времени, проверку TLS, формата адресов и согласованности результатов. | Тесты покрывают сбои, частичные ответы, IPv4/IPv6 и изменение версии сети во время запросов. Прокси не применяется неявно. |
| 6. GeoIP | Выбрать локальную базу, реализовать lookup, контроль актуальности, проверку и атомарное обновление. | Тесты проходят для неизвестного адреса, повреждённой/устаревшей базы и прерванного обновления. |
| 7. Маршруты и мониторинг | Реализовать снимок сети и уведомления, периодическую проверку, отмену старых результатов, VPN/proxy/IPv6 диагностику. | Смена сети отзывает прежнее решение; неподтверждённый общий выход остаётся Block. Нет эвристики, объявляющей HTTPS-адрес доказательством всего трафика. |
| 8. Управление политикой и процессами | Объединить проверки и WFP, определить владельца разрешения, завершение приложения и, если нужно, повышенный процесс без Windows Service. | Тесты покрывают гонки, ошибки применения, stale-result, выход и рестарт. Runtime-модель не оставляет независимые бессрочные Permit. |
| 9. GUI и CLI | Добавить экраны состояния и настроек, ручную перепроверку, структурированные журналы и общую диагностику. | ViewModel проверены без реальной сети; окно и трей отражают реальное доступное состояние. Сетевые операции не блокируют UI. |
| 10. Установка и удаление | Реализовать начальную политику, установку файлов, права, автозапуск при входе, обновление и удаление собственных объектов. | В VM проходят повторные и прерванные операции; после удаления чужие правила сохранены. Автозапуск не используется вместо защиты до входа пользователя. |
| 11. Полная проверка и README | Пройти матрицу VM, измерить переходы и поведение существующих соединений; описать использование и реальные способы расширения. | Указаны проверенные версии ОС и PowerShell, результаты, известные ограничения и инструкция создания форка. Статус готовности соответствует испытаниям. |

## Порядок проверок

В каждом шаге изменения поведения сначала запускается падающий тест, затем минимальная реализация и рефакторинг при зелёных тестах. После этапа запускаются безопасные тесты и сборка. Для документационного исследования тесты компилируемого кода не требуются.

На рефакторинге проверяются одна ответственность, композиция, DRY, KISS и YAGNI, а также XML-комментарии классов, методов и свойств. Новая точка расширения должна обслуживать текущую задачу; проекты и заглушки для будущих ОС не создаются.

Безопасные этапы 2, 4–7 и тесты ViewModel можно выполнять до появления VM. Реальные проверки этапа 3 и итоговая приёмка требуют условий из матрицы. До их выполнения не заявляется доказанный fail-closed и не выпускается рабочий режим разрешения.

## Результат этапа 2

Созданы Desktop, UnitTests и IntegrationTests; остальные проекты отложены до появления нужного кода. Реализованы окно, иконка и меню трея, скрытие при закрытии/сворачивании, восстановление и явный выход. Разметка Avalonia.Markup.Declarative, команды CommunityToolkit.Mvvm и DI работают без наследования собственных классов. В интерфейсе явно указано, что сетевой защиты ещё нет.

В TDD сначала наблюдались 3 падающих теста команд, затем 7 падающих headless-тестов окна и меню, затем 2 падающих теста композиции и владения иконкой. После реализации проходят 3 unit-теста и 9 интеграционных тестов. Тест кнопки использует события указателя headless-платформы; простое поднятие routed Click не заменяет настоящий клик.

Проверен нативный запуск Windows-процесса с окном IPGuard. Внешний вид проверен по изображению headless-рендеринга. Нативное взаимодействие с меню трея и Explorer остаётся отдельной ручной проверкой. Сетевые правила, BFE, права ОС и автозапуск не менялись.

Проверки Release: `dotnet build` — 0 ошибок и 0 предупреждений, `dotnet test --no-build --no-restore` — 12 пройденных тестов, `dotnet format whitespace --verify-no-changes --no-restore` — успешно. Зависимости восстановлены из локального NuGet-кеша; онлайн-аудит зависимостей при этой проверке не выполнялся. Из-за ограниченного места на диске для проверки сборки использовалась стандартная опция MSBuild `CreateHardLinksForCopyLocalIfPossible=true`; настройки исходного проекта ради этой машины не изменены.

## Промежуточный результат этапа 3: постоянный Block

На 2026-10-23 реализован безопасно проверяемый шаг 3a: проект Windows содержит настоящий адаптер user-mode WFP и отдельный контракт `IWfpSession`. GUI к нему не подключён. Для каждого переданного полного пути PowerShell устанавливаются четыре постоянных Block-фильтра: ALE connect и receive/accept для IPv4 и IPv6. App ID получается штатным API; идентификаторы фильтров стабильны. Provider, sublayer и фильтры имеют собственные идентификаторы и маркер версии. Несовместимые существующие объекты не заменяются.

Установка выполняется одной явной транзакцией; ошибка добавления или фиксации вызывает откат, ошибка отката сохраняется вместе с исходной. Отдельное чтение в read-only транзакции возвращает `Present`, `Incomplete` или `Unknown`: это состояние объектов, а не доказательство сетевой блокировки. Ошибка чтения не превращается в успешную проверку. Нативные структуры сверены с x64-заголовками Windows SDK 10.0.26100.0.

В TDD наблюдались падающие тесты отсутствующей транзакционной реализации, сериализации фильтров, неверных аргументов и разрешения App ID. Отдельный отрицательный тест обнаружил недостаточную проверку action union и прошёл после исправления. При рефакторинге проверки provider/sublayer защищены характеризующими тестами. Всего проходят 53 unit-теста и 10 интеграционных тестов; один интеграционный тест действительно вызывает `FwpmGetAppIdFromFileName0` для Windows PowerShell и освобождает результат, остальные проверяют GUI headless. Обычный запуск тестов не создаёт сетевые правила.

Release-сборка завершилась с 0 предупреждений и 0 ошибок; повторный безопасный набор из 63 тестов, `dotnet format whitespace --verify-no-changes --no-restore` и `git diff --check` проходят. Это проверка кода и контракта адаптера, а не подтверждение сетевой защиты.

На момент шага 3a динамический Permit и его отзыв были отложены до следующего шага, описанного ниже. Реальные вызовы создания WFP-объектов не запускались; приоритеты, сохранение блокировки и сетевой результат ещё не подтверждены.

## Промежуточный результат этапа 3: динамический Permit

Шаг 3b добавляет `WfpPermitLease`: отдельную динамическую сессию с транзакционной выдачей временных soft permit. До первого добавления проверяются все постоянные Block и их контейнеры. Permit имеет отдельный случайный ключ, больший вес в том же sublayer, тот же App ID и ALE-слой, без флагов persistent/boot-time/clear-action-right. Базовые объекты не меняются. Фабрика с неверным типом сессии отклоняется до операций с политикой.

Владельцем сессии после успешной фиксации становится lease; `Dispose` закрывает только эту сессию. `IsClosed` означает подтверждённое закрытие, а не доказанную блокировку трафика. Ошибка закрытия сохраняется и повторно выбрасывается при следующих вызовах `Dispose`; handle после ошибки не используется, поскольку его пригодность не документирована. Ошибки выдачи, отката и закрытия сохраняются совместно. Финализатор делает лишь резервную попытку очистки handle, для которого ещё не вызывалось явное закрытие.

В TDD сначала упали 16 тестов контракта lease, затем 15 тестов нативных флагов, сериализации и владения handle. Дополнительный падающий тест выявил отсутствие явного запрета устанавливать постоянный Block через динамическую сессию; проверка добавлена. Два уточнённых теста отдельно проверяют, что ошибка закрытия остаётся неподтверждённым состоянием и не приводит к повторному использованию handle. Проверены также оба имени PowerShell, неполный baseline, ошибки до и во время транзакции, разные владельцы и отсутствие изменений постоянных Block.

После реализации проходят 88 unit-тестов и 10 безопасных интеграционных тестов. Locked restore, Release-сборка (0 предупреждений и 0 ошибок), проверка форматирования и `git diff --check` успешны. Сетевые правила на рабочем компьютере не менялись.

На момент шага 3b удаление базовых объектов было отложено до следующего шага, описанного ниже. Permit пока ограничен только App ID и не подтверждает/не ограничивает внешний выход; он предназначен для будущих контролируемых VM-экспериментов и не подключён к GUI.

## Промежуточный результат этапа 3: удаление собственных объектов

Шаг 3c добавляет `WfpBlockPolicy.Uninstall`. В одной явной write-транзакции проверяются собственные контейнеры и свежий снимок всех доступных для чтения фильтров. Связанные фильтры должны полностью соответствовать постоянному Block версии 1, включая вычисляемый ключ и App ID. Только для удаления допускается дополнительный флаг disabled; проверка действующей блокировки по-прежнему его отвергает. Активный Permit, неизвестная схема или конфликт владельца прерывают операцию до первого удаления.

Удаление не зависит от наличия `powershell.exe`/`pwsh.exe` или прежней конфигурации путей. Сначала удаляются подтверждённые Block, затем sublayer и provider, с проверкой отсутствия после каждого удаления. Ссылки из оставшихся объектов не обходятся принудительно; ошибка удаления контейнера вызывает откат транзакции. Нельзя удалять чужие объекты по совпадению имени. Повторное удаление отсутствующих объектов не создаёт их заново. `Uninstall` намеренно снимает защиту, поэтому не используется как действие Block или обычный выход из приложения.

В TDD сначала упали 13 тестов удаления через fake-сессию. Затем упали 27 тестов нативного отбора и чтения страниц; один характеризующий тест совместимости формата ключа сразу прошёл. После реализации проходят 129 unit-тестов и 10 интеграционных тестов. Проверены откат, несколько ошибок очистки, закрытие после commit, disabled-объекты, конфликты схемы, независимость копии App ID и некорректные страницы. Реальные нативные перечисление и удаление не запускались.

Locked restore, Release-сборка (0 предупреждений и 0 ошибок), полный набор из 139 безопасных тестов, проверка форматирования и `git diff --check` прошли. Рабочая сетевая политика не менялась; это не проверка удаления или отката в реальном BFE.

На момент шага 3c явный режим испытаний был отложен до следующего шага. Матрица VM дополнена сценариями удаления; все её испытания остаются невыполненными.

## Промежуточный результат этапа 3: отдельный режим VM

Шаг 3d добавляет `scripts/Test-WfpVm.ps1` и один `Category=WfpVm` тест объектов. Режим требует явных подтверждений изоляции/снимка, совпадения имени VM, Windows x64 и административного токена. C#-проверка отказывает в CI и не обращается к проверке токена до прохождения остальных условий. Скрипт восстанавливает окружение и рабочую папку; пропущенный, отсутствующий или неуспешный TRX не выдаётся за пройденное VM-испытание.

Сценарий использует отдельную копию PowerShell и pristine namespace. Проверяются установка, чтение, динамический Permit, отказ удаления с активным разрешением, подтверждённое закрытие и повторное удаление. Named mutex сериализует VM-тесты, но не решает продуктовую задачу единственного владельца. В журнале сохраняются среда, хеш файла и фактические поля фильтров. При ошибке сценарий не продолжает удаление базовой защиты; снимок VM восстанавливает оператор.

В TDD сначала упали 19 тестов допуска, затем 6 тестов контроллера с fake-сессиями и тест отказа PowerShell-скрипта без подтверждений. После реализации проходят 129 unit-тестов и 36 безопасных интеграционных тестов. Один нативный тест явно пропущен. Дополнительно проверены синтаксис скрипта и обработка Passed/NotExecuted/Failed/пустого отчёта без включения VM-режима.

Locked restore, Release-сборка (0 предупреждений и 0 ошибок), полный набор тестов с TRX, проверка форматирования и `git diff --check` прошли. По самим TRX проверено, что пропущен именно `PolicyObjects_CompleteRoundTrip`; переменные VM-режима на рабочей машине остались незаданными. Сетевые правила не менялись.

Реальный object round-trip не выполнялся. Даже его будущий успех не докажет блокировку трафика. Этап 3 целиком не завершён: нужны TCP/UDP-проверки, нативное выполнение матрицы, права и загрузка/падение процесса. Не реализованы срок действия разрешения, защита от зависшего владельца, межпроцессный единственный владелец, boot-time политика и установщик. До появления подготовленной VM можно продолжать безопасную доменную политику этапа 4.

## Промежуточный результат этапа 4: предпосылки по публичным адресам

Шаг 4a создаёт проект Domain без сторонних пакетов, ссылок на Windows, GUI или сетевой транспорт. `PublicIpPolicy` проверяет неизменяемый `NetworkAssessment` относительно явно переданных времени и текущего поколения сети. Поколение после изменения VPN, интерфейсов или маршрутов должно изменяться будущим монитором. Старый результат не подходит даже при совпавших ответах источников.

Оба семейства должны быть учтены. Для доступного семейства нужны успешные согласованные ответы минимум двух независимых операторов и локальный GeoIP для того же адреса. Разные URL одного оператора не образуют независимые источники. Ошибка одного запроса не скрывается успешным кворумом. Неизвестное семейство, противоречивые данные отсутствующего семейства, чужое семейство адреса, mapped/scoped IPv6, отсутствие lookup, неизвестная страна, истёкшая база и несовпавший адрес lookup дают отрицательный результат. Срок общей свежести отсчитывается от начала сбора и имеет исключающую границу. По умолчанию принимается только US; явный пустой список не принимает страны.

Результат содержит причину и проблемное семейство. Положительный результат называется `EligibleForRouteValidation`, а `IsEligible` означает только выполнение предпосылок по IP. Домен не выдаёт Allow и не принимает фиктивный TrustedRoute. HTTPS-ответы и объявленная недоступность семейства не доказывают технически обеспеченный общий выход. Этап 4 в части окончательного решения вместе с маршрутом не завершён: он зависит от этапов 7–8. GUI и Permit к домену не подключались.

Контракты явно требуют, чтобы будущие адаптеры проверяли TLS, формат, глобальную маршрутизируемость адресов, операторов источников и актуальность локальной базы, включали все попытки и ограничивали их общим интервалом. Domain не заменяет эти адаптеры и не выдаёт проверку семейства за классификацию публичности адреса. Источники и GeoIP представлены синтетическими тестовыми данными; реальных запросов не было.

В TDD сначала упали 55 скомпилированных тестов отсутствующего поведения, затем они прошли после реализации. Дополнительные два падающих теста обнаружили преобразование Unicode `ſ` в ASCII `S`; исправление проверяет исходные символы до нормализации регистра. После исправления проходят 57 доменных тестов. Копируются список источников, allowlist и строковое представление изменяемого IPAddress, поэтому внешняя мутация не меняет снимок.

Locked restore, Release-сборка (0 предупреждений и 0 ошибок), 186 unit-тестов, 36 безопасных интеграционных тестов, проверка форматирования и `git diff --check` прошли. Единственный нативный VM-тест явно пропущен; реальные сетевые правила не менялись. Следующий независимый шаг — адаптеры публичного IP этапа 5 с проверкой ответов, таймаутов и всех настроенных источников.

## Промежуточный результат этапа 5: HTTPS-адаптеры

Шаг 5a создаёт Infrastructure со ссылкой только на Domain. Реализованы PublicIpSource, PublicIpSources.Defaults, HttpsPublicIpTransport, PublicIpReader и консервативный parser. Прямые HTTPS-запросы сохраняют системную проверку TLS и имени, не используют прокси, cookies, redirects или decompression. Для каждого семейства используется отдельный сокет без fallback; соединения между проверками не переиспользуются. Дедлайн включает тело, которое ограничено 128 байтами независимо от объявленной длины. Приняты только status 200, text/plain, ASCII-совместимая поддержанная кодировка и один IP допустимого диапазона.

Ошибки DNS, TLS, транспорта, таймаута, HTTP-статуса и валидации остаются отдельными результатами с null-адресом для Domain. Отмена вызывающего кода распространяется отдельно, в том числе при сопутствующей ошибке I/O. ReadAllAsync начинает все переданные попытки и сохраняет их порядок, отказы и конфликты. Политика согласия не дублируется в Infrastructure.

TDD: сначала упали 127 скомпилированных unit-тестов и 5 интеграционных сценариев. При дополнительном ревью упали 7 тестов кодировок, отмены и default sources; 2 характеризующих теста поддержанных кодировок сразу прошли. После реализации проходят 136 новых unit-тестов. Интеграционные сценарии используют loopback IPv4/IPv6, недоверенный сертификат только в памяти и асинхронный named pipe. Доверие ОС и Firewall не меняются, публичные сервисы из приложения не вызываются.

На рабочей машине первый прогон подтвердил IPv4, запрет fallback, отказ недоверенному TLS и дедлайн тела. IPv6 loopback получил WSAEACCES; отдельный прямой системный Socket без кода IPGuard получил тот же отказ. Тест не ослаблен и не превращён в skip. Его результат на Windows runner CI проверяется отдельно; локальное ограничение нельзя выдавать за успешную IPv6-проверку.

Итог локальных проверок: locked restore успешен, Release-сборка — 0 предупреждений и 0 ошибок, whitespace и `git diff --check` проходят. Полный набор: 322 unit и 40 интеграционных тестов прошли; 1 интеграционный IPv6-тест завершился тем же WSAEACCES, 1 нативный VM-тест явно пропущен. Отказ IPv6 не скрыт фильтром или изменением настройки теста. Для защиты от регрессии проверка остаётся в обычном наборе CI.

В окончательном тесте поддержка IPv6 — обязательное условие среды, проверяемое assertion. Удалён optional skip при отсутствии стека: успешный CI должен подтверждать реальный IPv6 loopback, а не только отсутствие ошибок остальных тестов. Это не обход локального WSAEACCES; такой отказ по-прежнему приводит к ошибке.

Default sources имеют по два настроенных оператора: ipify и ident.me. Документированы primary sources, дата snapshot диапазонов, границы формата и существующие пробелы. GUI не вызывает адаптер. На момент 5a обработка изменения поколения сети была отложена до следующего шага, описанного ниже; реальный монитор относится к этапу 7. GeoIP и разрешение сетевого доступа не реализованы этим шагом.

## Промежуточный результат этапа 5: сбор в одном поколении сети

Шаг 5b добавляет Application с зависимостью только от Domain. PublicIpSource и PublicIpReadResult/PublicIpReadStatus перенесены в Application без изменения правил чтения. IPublicIpProbe скрывает транспорт; PublicIpReader реализует этот контракт. После переноса прежние 136 тестов HTTPS проходят. Сценарии приложения не ссылаются на Infrastructure, Windows или Avalonia.

PublicIpCollector копирует конфигурацию, захватывает время и атомарный NetworkSnapshot, выбирает доступные семейства и связывает отмену запросов с сигналом поколения. После всех ответов повторно проверяются версия, обе доступности и тот же неотменённый сигнал. Неизвестное семейство, пустой Guid или неотменяемый token не допускают запросов. Неудачный запрос не превращается в «семейство недоступно». При обоих недоступных семействах получается пустой снимок без запросов; это данные для блокирующего решения Domain, а не разрешение.

Сигнал должен оставаться отменённым после изменения сети, в том числе после disconnect/reconnect. Поздние ответы, изменившиеся данные сети, неполный/переставленный/подменённый набор результатов и инверсия времени не публикуют снимок. Оригинальная неожиданная ошибка сохраняется в Error; отмена вызывающего кода имеет приоритет. Completed обозначает только окончание сбора. Снимок сохраняет живой сигнал инвалидирования, поэтому потребителю нужно перепроверять его, текущее поколение и свежесть перед использованием. Проверка в конце метода не устраняет будущие изменения сети.

TDD: сначала упали 41 скомпилированный unit-тест и 2 безопасных интеграционных теста. После реализации все прошли. Проверены отмена в полёте, поздние ответы, reconnect с прежним идентификатором и новым сигналом, изменения между последними чтениями, caller cancellation, ошибки каждой границы, rollback часов, копирование конфигурации и списка результатов. Интеграционные тесты соединяют реальный reader, контролируемый транспорт и Domain: конфликты сохраняются и дают отрицательное решение. Публичные HTTP-сервисы и WFP не вызываются.

Локальные проверки: locked restore успешен, Release-сборка — 0 предупреждений и 0 ошибок; whitespace и `git diff --check` проходят. Полный набор: 363 unit и 42 интеграционных теста прошли, один IPv6 loopback получил прежний WSAEACCES, один нативный VM-тест явно пропущен. Переменные VM-режима остались незаданными. IPv6-тест сохраняется обязательным в CI; локальное ограничение не выдаётся за успех и не обходится изменением Firewall.

Реальный Windows-монитор, GeoIP и окончательная сборка NetworkAssessment пока отсутствуют. Следующий шаг — локальная GeoIP-база этапа 6; её lookup должен входить в общий интервал и сохранять проверку поколения. Подключение к GUI, выдача Permit и жизненный цикл защиты остаются дальнейшими этапами.

## Промежуточный результат этапа 6: локальный lookup

Шаг 6a реализован отдельно от обновления: IGeoIpCountryDatabase и диагностические результаты находятся в Application, MmdbCountryDatabase/reader — в Infrastructure. Используется MaxMind.Db 5.2.0 с закреплёнными lock files. Предполагаемый источник рабочей базы — DB-IP Country Lite; в этом шаге поставляются только лицензированные synthetic fixtures для тестов, а не рабочие GeoIP-данные.

Снимок открывает ограниченный по размеру файл, проверяет country product/format 2.0/оба IP-семейства, фиксирует SHA-256 и время сборки, копирует содержимое в приватную память и освобождает исходный файл. Deadline отсчитывается от build timestamp, не от файловой даты. Lookup явно различает найденную/неизвестную страну, недопустимый адрес, старую/будущую базу и ошибку decoder. После ошибки прежняя страна не возвращается; требуется новый экземпляр. Dispose запрещает дальнейшие чтения. Общая классификация публичных адресов извлечена из существующего parser, без дублирования диапазонов.

TDD: 31 unit и 10 интеграционных тестов сначала скомпилированы и упали на NotImplementedException; после реализации все прошли. Ещё 3 unit и 3 интеграционных характеризующих случая проверили освобождение ресурсов, сохранение двух исключений, копирование mutable адреса, отсутствие country при наличии registered_country и пустой файл. Итого добавлено 47 случаев. Реальный MMDB decoder проверен на IPv4/IPv6 и country, отличающейся от registered_country. Работающий снимок продолжает читать прежние байты после замены источника; изменение mtime не освежает build timestamp.

Локальные проверки: locked restore успешен, Release-сборка — 0 предупреждений и 0 ошибок. Полный набор: 397 unit и 55 интеграционных тестов прошли, 1 прежний IPv6 loopback завершился WSAEACCES, 1 нативный VM-тест явно пропущен. IPv6-тест не ослаблен и остаётся обязательным в CI. Публичные IP-сервисы и mutating WFP API не вызывались; VM-режим не включался. SHA-256 не заявлен аутентификацией провайдера, а компиляция/lookup — доказательством блокировки.

Этап 6 ещё не завершён. Критерии следующих шагов:

- 6b: обновление через ограниченный HTTPS, доверие источнику, проверка кандидата и защита от отката, атомарная замена. Тесты: повреждённый/неполный download, прерванное обновление, stale/future metadata, сохранение прежнего пригодного снимка без продления его deadline.
- 6c: соединить PublicIpCollector с GeoIP в NetworkAssessment. Общий интервал включает lookup; смена поколения/отмена/истечение срока до публикации отбрасывают весь результат. Ошибка открытия или чтения базы даёт непригодные данные без положительного решения.

GUI, реальный Windows-монитор и выдача Permit не подключены. Свежая страна US остаётся только одним из предварительных условий; доказательство общего выхода и жизненный цикл блокировки относятся к дальнейшим этапам.

## Промежуточный результат этапа 6: обновление базы

Шаг 6b добавляет реальную загрузку DB-IP Country Lite и публикацию проверенного кандидата. Контракт IGeoIpDatabaseDownload и результат обновления находятся в Application. Infrastructure содержит ограниченный HTTPS transport, bounded gzip downloader и GeoIpDatabaseUpdater с реальной файловой блокировкой/переименованием. Общие ограничения размера извлечены из существующего reader, вместо копирования знания о предельном размере. Интеграционный проект явно ссылается на Domain, типы которого использует непосредственно.

Загрузка доверяет официальному HTTPS origin и системной проверке TLS, без redirect/proxy/другого месяца. CRC-32 проверяет целостность gzip, а не подлинность. Один deadline охватывает тело и распаковку; compressed/decoded лимиты действуют по фактическим байтам. Stage создаётся отдельно и flush-ится до проверки MMDB. Более старый build, одинаковый build с другим содержимым, stale/future metadata, другой product и изменение baseline вне update lock отклоняются. Повторный файл не обновляет deadline. Commit — одно same-directory переименование, без удаления или перезаписи активного файла по частям.

Постоянный .update.lock координирует writers через открытый эксклюзивный handle; оставшийся без handle файл не означает busy. Обычная отмена/ошибка до commit очищает только созданную stage; посторонние файлы не удаляются. Отказ доступа не интерпретируется как отсутствие rollback floor. При повреждённой active database updater прекращает работу; явный операторский recovery ещё не реализован. Безопасность каталога зависит от ACL, reparse-check их не заменяет. Полная crash/power-loss durability не заявляется и не проверена.

TDD: сначала скомпилированы и упали на отсутствующем поведении 33 unit и 20 интеграционных случаев. После реализации 19/20 интеграционных и все unit прошли; проверка отказа rename уточнена для двух допустимых Windows filesystem errors с неизменным требованием целого active file. Дополнительно 3 unit и 3 интеграционных характеризующих случая проверили разрешённый origin, таймаут/отмену реального асинхронного pipe body и сохранение чужой stage. Итого 59 новых случаев. Промежуточный запуск до завершения сборки использовал старые DLL и не принят как Green; после завершения сборки все 59 прошли.

Полный локальный набор: 433 unit и 78 интеграционных тестов прошли; 1 прежний IPv6 loopback получил WSAEACCES, 1 WFP VM-тест явно пропущен. Locked restore, Release-сборка (0 warnings/errors) и whitespace прошли. Проверки используют synthetic fixtures и controlled transfers, без публичных download в dotnet test и без mutating WFP API.

Отдельно вручную проверена реальная загрузка официальной October 2026 базы DB-IP: install Changed=true, metadata/product/hash успешно проверены, lookup публичных тестовых IPv4/IPv6 выполнен. Повторная загрузка дала Changed=false с прежними build timestamp/deadline. Реальные данные остаются в игнорируемом cache и не включены в EXE. Точные наблюдения и границы доверия записаны в technical-research.md.

Следующий шаг 6c: собрать NetworkAssessment из PublicIpCollector и локального GeoIP. Общий интервал должен включать lookup; смена сети, отмена, старые данные или ошибка базы перед публикацией отбрасывают результат. Далее остаются реальный Windows monitor, GUI/CLI, scheduler, installer/recovery и проверенное управление защитой. Сама загрузка GeoIP не разрешает сеть, а текущий GUI по-прежнему не применяет фильтры.

## Результат шага 6c: общая оценка публичных адресов

NetworkAssessor объединяет реальный collector, фабрику локальной базы и Domain policy через существующие контракты. Каждый вызов владеет одним отдельным снимком GeoIP для всех доступных согласованных адресов; disposal входит в общий интервал. Плохие source attempts сохраняются и оцениваются Domain, не превращаясь в разрешение по успешному GeoIP. Срок и поколение перепроверяются вокруг каждой локальной границы. Новые зависимости, проекты и GUI/WFP-вызовы не добавлены.

Для DRY существующие проверки согласия источников перенесены в PublicIpConsensus, а проверка временного интервала извлечена в PublicIpPolicy.CheckInterval. Оба владельца остаются в Domain. Сопоставление network snapshot/latch общее для collector и assessor. Правила разрешённых стран не дублируются; результат всё ещё ограничен EligibleForRouteValidation.

TDD: 55 новых unit-случаев сначала скомпилированы и упали на отсутствующем поведении, затем прошли вместе с 98 прежними policy/collector случаями. Ещё 6 unit-случаев покрывают откат часов внутри интервала, malformed country, ошибку в результате плюс cleanup failure и mutable IPv6 address. Последний отдельно упал: ожидался InvalidGeoIpResult, фактически был Completed с отрицательной Domain-оценкой. После фиксации исходной строки адреса перед lookup он проходит. Добавлены 9 интеграционных проверок настоящего reader/decoder/scenario на controlled data; все проходят. Итого 70 новых случаев.

Проверены время открытия/lookup/закрытия, exclusive deadlines, token/version/availability changes, invalidation в финальном clock callback, отказ открытия/чтения/cleanup, ошибочная привязка адреса/срока, metadata consistency, оба IP-семейства, unknown/foreign/malformed country, отсутствие записи при наличии registered_country и сохранение приватного снимка при замене исходного файла. Отрицательные и ошибочные данные не дают пригодного положительного snapshot. Completed может содержать отрицательное Domain-решение; это не доступ к сети.

Полный локальный прогон: 494 unit и 87 интеграционных тестов прошли; один прежний IPv6 loopback получил WSAEACCES, один нативный WFP VM-тест явно пропущен. Release-сборка — 0 warnings/errors, whitespace проходит. Ни публичные IP-сервисы/GeoIP-download, ни mutating Firewall/WFP API этим шагом не вызывались. Пропуск VM не заменяет проверку сетевой блокировки.

Следующий шаг — этап 7a: реальный Windows network monitor с atomic cached snapshot и постоянной отменой прежнего token на изменениях. Периодический scheduler, повторная оценка после обновления GeoIP, GUI/CLI и жизненный цикл защиты остаются дальнейшими шагами. До проверки маршрута и применения политики никакое IsEligible не открывает Permit. Возвращённые данные не обновляются автоматически; потребитель перепроверяет живой token, текущее поколение и время перед использованием.

## CI и публикация

GitHub Actions использует один workflow `Windows CI` с двумя последовательными заданиями: `Test Windows x64`, затем `Build and deploy Windows x64` через `needs: tests`. Второй этап допускает только успешные проверки `main` и собирает тот же commit SHA. Pull request и другие ветки не публикуют релиз. Отдельные плашки Shields.io в README отображают GitHub check runs по именам заданий.

Общий `concurrency` с ключом `windows-${{ github.ref }}` и `cancel-in-progress: true` отменяет предыдущий запуск целиком при новом коммите для той же ref. Это охватывает оба этапа, включая уже начавшуюся сборку. Разные ветки и pull request используют отдельные группы. Отменённый тестовый запуск не запускает публикацию и не продолжает загрузку TRX-артефакта. Два независимых workflow заменены единым, чтобы отмена не ждала завершения новых тестов.

Версия публикации и Windows-файла — `0.1.<run_number>.<run_attempt>`. Новый запуск и повторная попытка меняют версию. Результат — полноценный GitHub Release с заголовком `IPGuard v<version>`, сгенерированными заметками, отметкой Latest, автономным `IPGuard-win-x64.exe` и SHA-256; такие же файлы сохраняются в Actions artifacts. Локальная версия по умолчанию — `0.1.0-preview.local`. Состояние проекта по-прежнему определяется проверенными возможностями, а не наличием записи Release.

За образец взят `.github/workflows/dotnet-tests.yml` репозитория AvaWeather на коммите `ccf1396f694eb166935d2fd14250a1022e4a0350`. Перенесён подход «тесты → автономная публикация → GitHub Release» для Windows x64. Профиль `src/Desktop/Properties/PublishProfiles/Windows.pubxml` включает .NET 10.0.13 и нативные библиотеки в один EXE, без trimming. SDK закреплён на 10.0.401, build-only анализатор single-file закреплён в central packages. README использует динамическую плашку версии и постоянную ссылку на последний EXE; коммит от бота для обновления README не требуется.

Локально проверены locked restore, 12 безопасных тестов, Release-сборка без предупреждений, версии `0.1.42-preview.1` и `0.1.42-preview.2` в метаданных, версия опубликованных DLL и EXE, ZIP из 41 файла и совпадение SHA-256. PowerShell-блоки workflow проходят синтаксический разбор.

Предыдущая цепочка из двух workflow реально прошла на GitHub для коммита `b059c42`: тесты, сборка и публикация успешны. Создан полноценный prerelease `IPGuard 0.1.3-preview.1` с описанием, ZIP и SHA-256. Проверен скачанный архив: 41 файл, контрольная сумма совпадает с файлом релиза и digest GitHub, версии EXE и DLL соответствуют `0.1.3-preview.1`, Windows file version — `0.1.3.1`.

Общая отмена проверена реальными последовательными push: коммит `80ade9f` отменил запуск коммита `293c48a`, включая уже выполнявшийся шаг `Build Release`. Публикация отменённого запуска была пропущена. Запуск `80ade9f` завершился успешно. Проверка отмены не требовала изменения Firewall/WFP.

Автономная публикация по образцу AvaWeather проверена локально с .NET 10.0.13: ровно один EXE размером 104 019 714 байт, версия `0.1.42.2` в метаданных и совпадающий SHA-256. Проверка единственного EXE сначала обнаружила лишние native PDB из NuGet-пакетов; профиль исключает эти отладочные символы из публикации. После очистки выходной папки та же проверка проходит. Нативный запуск создал окно IPGuard без соседних DLL, при `DOTNET_ROOT_X64`, указывающем на пустую папку. Нативные библиотеки извлекались в отдельный временный кеш внутри рабочего каталога; запущенный для проверки процесс остановлен.
