# Fortis PowerShell Executor — backlog

<a id="executor-dynamic-ask"></a>

## Dynamic ASK внутри Executor (согласованная цель 2026-11-19)

**Status: PLANNED / NOT IMPLEMENTED.** Windows machine route реально активирован
в ASK-only режиме; 2026-11-18 владелец подтвердил `Get-Date` и Reject E2E.
Gateway `powershell.capabilities()` показывает configured=true, policy=ASK,
`machineExecutionAutoApprove=false`, version=1. Это не означает полную
fault-injection/restart acceptance и **не** означает наличие auto-ALLOW.
Текущий wire contract и baseline — [Machine ASK V1](MACHINE-ASK-V1.md),
а актуальные Gateway/release статусы и owner inventory — в
[Gateway current state](https://github.com/AlexPastukhh/fortis-approvals/blob/main/docs/guides/FORTIS-APPROVALS-SECURE-DEVELOPMENT.md).

**Общая модель внешнего `DENY/ASK/ALLOW` и итоговой матрицы** принадлежит
[Gateway PowerShell plan](https://github.com/AlexPastukhh/fortis-approvals/blob/main/docs/BACKLOG-IMPROVEMENTS.md#powershell-plan).
Не дублировать Gateway Dashboard и Core approvals здесь. **Executor владеет
только внутренними правилами команд**, отдельными от внешнего method policy.

### Контракт внутреннего решения

После внешнего `ALLOW` (или независимо от внешнего `ASK`, который остаётся
обязательным) Executor оценивает точные bytes команды, actor, target и
версионированный owner-managed profile и возвращает:

- `DENY` — нарушение жёсткого запрета: без исполнения даже после WebAuthn.
- `ASK` — разрешённый к рассмотрению, но потенциально опасный или
  неоднозначный запрос: нужен owner WebAuthn в **существующем Core**.
- `ALLOW` — строго доказанное совпадение с доверенным узким правилом:
  без ASK **только** когда внешний Gateway method policy тоже `ALLOW`.

Priority: `DENY > ASK > ALLOW`. Unknown/unparseable/dynamic/unsupported
syntax **не даёт ALLOW**. Одна команда и один Core requestId не создают
двойных подтверждений. Rule engine не делегирует право менять правила ИИ.

### План реализации (owner-managed, Windows-enforced)

- [ ] **EX-PS-01 Rules/settings storage:** owner-only редактор профилей команд
  и версионированное protected on-Windows хранилище с atomic write, strict
  schema, checksums, audit, backup/rollback, revocation и version/digest.
  Settings UI может быть интегрирован в owner portal/Script Center, но не
  имеет Repo machine-write API, не хранит секреты в Git и не создаёт вторую
  очередь ASK. Выбор профиля ИИ не может повысить себе привилегии.
- [ ] **EX-PS-02 Правила:** именованные типизированные операции/проверенные
  команды, явные cmdlet/verb/parameter/value ограничения, canonical paths,
  разрешённые roots, time/output ceilings и отдельные `DENY/ASK/ALLOW`
  dispositions. `ALLOW` допустим только для полностью проверенного профиля;
  в первоначальной миграции все неизвестные и старые requests остаются ASK
  либо DENY по owner policy, **не автоматически ALLOW**. Настройки не
  компилируются из текста, предоставленного ИИ.
- [ ] **EX-PS-03 Deterministic evaluator:** разбирать PowerShell 5.1 AST
  (или типизированные параметры без свободного скрипта), валидировать
  **всю** цепочку: aliases, pipes, expandable strings, variables,
  command substitution, scriptblocks, dynamic invocation, expression syntax,
  external executables, child processes, working directory, paths/reparse
  points, env, registry/network destinations. Неизвестные конструкции —
  ASK при явно допущенной owner risky-ветке, иначе DENY; никогда не ALLOW.
  Blocklist по строкам и PSScriptAnalyzer не являются enforcement.
- [ ] **EX-PS-04 Preflight:** authenticated read-only evaluate endpoint с
  versioned schema и deterministic result/justification/rule IDs,
  command SHA256, profile+policy digest, actor/target/UUID, TTL; **без запуска
  команды и без побочных эффектов**. Ограничить readback actor-scope, не
  публиковать protected policy для постороннего actor. Gateway использует
  результат в исходном Core flow; никакого прямого submit из ИИ к Windows.
- [ ] **EX-PS-05 Enforcement:** Windows route проверяет подписанный
  `owner-approved ASK` либо `policy-ALLOW` proof V2 и **заново** сверяет
  exact command, grants, evaluator decision, policy version/digest и все
  machine bindings **до** durable reserve/dispatch. Stale/unknown profile,
  несовпадающий hash/правило или невалидный proof — DENY/STOP. Внешний
  method ASK не может быть обойдён локальным ALLOW; Gateway подписывает
  итоговый method+command disposition. V1 proof/receipt остаётся совместим.
- [ ] **EX-PS-06 Безопасный rollout:** переход V1 ASK-only → V2 под
  отдельным owner-controlled release с default ASK (или DENY) до полного
  принятия ALLOW. Сохранить тот же Windows TLS/mTLS, bearer, existing owner
  API, machine actor/target, identity, **ту же receipt SQLite DB**, UUID
  idempotency, no replay on UNKNOWN и один listener. Никакого автоматического
  изменения установленного Windows процесса из source PR.
- [ ] **EX-PS-07 Tests/acceptance:** matrix outer/inward `DENY/ASK/ALLOW`
  совместно с Gateway; aliases, `&`, `Invoke-Expression`, `-EncodedCommand`,
  nested expressions, scriptblocks, pipelines, reparse/junction paths,
  network/external executable, child-process escapes, stale policy change,
  policy tampering, forgery, replay, concurrency, crash-after-reserve,
  lost ACK, timeout, same-DB recovery, actor/target separation. Отдельная
  изолированная Windows negative acceptance и explicit owner GO для ALLOW.

### Выбор инструментов

**Основной enforcement:** строгие типизированные операции и детерминированный
PowerShell AST evaluator. `PSScriptAnalyzer` или LLM могут объяснять риски,
но не принимают окончательного решения и не превращают DENY/UNKNOWN в ALLOW.
JEA требует отдельного PowerShell Remoting endpoint; CLM без системной App
Control не обеспечивает надёжную границу. Отдельная service identity, NTFS
ACL и WDAC/App Control/JEA рассматриваются как дополняющая OS isolation,
не как уже достигнутая sandbox. Проект отдельного container-control broker
принадлежит [Fortis Container](https://github.com/AlexPastukhh/fortis-container/blob/main/docs/BACKLOG-IMPROVEMENTS.md).

### Граница текущего протокола

`MACHINE-ASK-V1.md` — **документ принятого V1 wire contract**, а не план
будущего dynamic-ASK API. Старые формулировки «source-only, not installed»
относятся к состоянию 2026-11-17. Отдельные migration, V2 proof schema,
изменение Windows listener и source delivery требуют собственных review;
этот backlog не разрешает deployment, restart, cert rotation или ACL writes.
