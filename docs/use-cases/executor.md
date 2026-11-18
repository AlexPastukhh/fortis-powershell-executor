# Windows Executor — эксплуатационные сценарии

**Границы:** Windows PowerShell 5.1 под обычным пользователем, один loopback listener на порту 10443. Gateway подключается через host.docker.internal:10443 с mTLS. ASK не песочница и не автоматический анализ PowerShell; owner-only API не является машинным proxy.

<a id="uc-pse-001"></a>

## UC-PSE-001 — Проверка работающего Windows Executor

**Когда:** перед первым использованием, после запуска, смены source и для диагностики доступности.

**Как:**

1. Владелец проверяет чистый синхронизированный Windows fortis-powershell-executor/main, одобренный SHA, Script Center adapter, non-admin identity, защищённые TLS/secret-файлы и ровно один процесс. Проверяет, что процесс использует **прежнюю текущую SQLite**, а не новый пустой файл.
2. Баннер Owner-only: **OWNER_SHELL_MTLS_READY (no browser or machine API; do not run elevated)**. Баннер Machine ASK: **OWNER_SHELL_MTLS_READY (machine ASK proof verifier enabled; non-admin)**. Баннер не доказывает прохождение WebAuthn или один реальный effect.
3. Проверить сертификат SAN/CA и mTLS из фактического Gateway. TCP reachable не подтверждает TLS/идентичность. На текущем Windows-хосте netstat/Get-NetTCPConnection давали нулевые listen-count при работающем TCP: нельзя доверять им как единственному признаку остановки.
4. Читать SQLite агрегаты shell_receipts и shell_machine_bindings только через mode=ro и PRAGMA query_only=ON; сохранить старые owner-only receipts. Никаких SQL UPDATE/DELETE, смены DB или печати секретов.
5. Для controlled switch владелец независимо подтверждает отсутствие активной команды и detached children, мягко останавливает один экземпляр, проверяет Windows loopback TCP, только затем запускает один зарегистрированный Script Center entry. Не force-kill и не второй listener.

**Готово:** один non-admin процесс на проверенном source/config с прежней DB; Gateway mTLS verified. Host process/SQLite проверки и owner quiescence не подменяются TCP.

См. [API](../API.md), [Machine ASK](../MACHINE-ASK-V1.md), [Script Center launch](https://github.com/AlexPastukhh/script-control-center/blob/main/docs/OWNER-POWERSHELL-EXECUTOR-LAUNCH.md).

<a id="uc-pse-002"></a>

## UC-PSE-002 — Однократная команда через ASK-only V1

**Когда:** допущенный Repo actor хочет выполнить PowerShell на зарегистрированной Windows-цели.

**Как:**

1. Только штатный Repo PowerShellMachineClient; capabilities: configured=true, policy=ASK, machineExecutionAutoApprove=false, version=1. Клиент не выбирает URL, bearer, proof, identity или DB. Нельзя пользоваться Owner Portal PowerShell tab как машинным proxy.
2. Новый UUID + точный target windows-owner + полная команда создают Core PENDING. До решения owner нет dispatch. При транспортной неопределённости **только** readback исходного UUID; не submit повторно и не создавать новый UUID.
3. Владелец читает полную команду/actor/target/hash во вкладке **«На согласовании»**, подтверждает отдельным WebAuthn либо отклоняет. ИИ не принимает своё решение.
4. При Approve Gateway выдаёт короткоживущий proof, Windows проверяет mTLS, отдельный bearer, MAC, срок, actor/target/UUID/command digest и резервирует durable receipt до запуска. Ожидаемый Core audit: PENDING → APPROVED → DISPATCHED → EXECUTED; сверить bound result через typed readback и Windows SQLite read-only.
5. При Reject ожидается только PENDING → REJECTED без dispatch/Windows receipt. Проверять отдельно Core audit и Windows SQL-агрегаты.

**Готово:** exact-command EXECUTED с exit code/receipt или REJECTED без исполнения. Одна квитанция сама по себе не независимый подсчёт запусков PowerShell-процесса.

**Датированное evidence (2026-11-18):** одно Get-Date завершилось EXECUTED/exitCode=0, SHA/UUID совпали, Windows SQLite содержала одну machine-bound и одну прежнюю owner-only квитанцию. Reject доказан Core/audit без dispatch; Windows no-receipt readback ещё ожидается. В stderr успешной команды оставался CLIXML progress/символ замены, необходим отдельный разбор.

<a id="uc-pse-003"></a>

## UC-PSE-003 — UNCERTAIN, replay, restart и recovery

**Когда:** потерян ACK, timeout, crash, DISPATCHED/UNCERTAIN, чужой proof или требуется rollback.

**Как:**

1. **STOP** новым Windows-effects при неопределённом исходе. Читать исходный UUID/командный digest, Core audit, scoped machine GET, SQLite read-only и Windows process evidence. Не подменять статус, не retry эффекта и не делать новый UUID в обход блокировки.
2. Изменённая команда с прежним UUID — конфликт. Неверный/истёкший proof, Bearer, mTLS, Host, actor/target, Idempotency-Key — отказ до runner. Owner-only route не замена Machine ASK.
3. Состояния DISPATCHED/UNCERTAIN Windows SQLite блокируют дальнейший эффект. Отсутствие ACK, тайм-аут и nonzero exit **не доказывают отсутствия эффекта**; проверить возможные detached children.
4. Rollback сохраняет текущие TLS/config/ACL/SQLite, original receipts и единственный listener. Не восстанавливать старый DB snapshot; не путать Gateway Core UNCERTAIN/CLAIMED с Windows SQLite.
5. Fault injection lost ACK, timeout, forged proof, restart и replay проводить в изолированном тесте или отдельно разрешённом owner maintenance window. Не разрушать production только ради отметки PASS.

**Готово:** эффект подтверждён проверенным receipt либо остаётся UNKNOWN/UNCERTAIN без повтора. Отделять source/offline PASS от live PASS.

**Покрытие (2026-11-18):** 23/23 Executor и 35/35 Gateway offline tests, включая expiry, proof binding, replay, timeout blocking, restart retention. Live Gateway DENY для чужого target, approved flag, unknown field, empty command; no-client-cert TLS отвергнут. Live timeout/restart/forged-proof испытания не заявлены.
