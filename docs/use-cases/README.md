# Fortis PowerShell Executor — локальные Use Cases

Повторяемые сценарии установленного Windows Executor. Не заменяют Owner Portal, [API](../API.md), [Machine ASK V1](../MACHINE-ASK-V1.md) или [Script Center](https://github.com/AlexPastukhh/script-control-center/blob/main/docs/OWNER-POWERSHELL-EXECUTOR-LAUNCH.md). Source не равен live deployment.

| ID | Когда | Результат |
| --- | --- | --- |
| [UC-PSE-001](executor.md#uc-pse-001) | Проверить установленный Windows Executor | Единственный non-admin процесс, прежняя receipt DB, mTLS |
| [UC-PSE-002](executor.md#uc-pse-002) | Использовать Machine ASK V1 | Repo PENDING → Owner WebAuthn → exact receipt либо Reject без dispatch |
| [UC-PSE-003](executor.md#uc-pse-003) | UNCERTAIN, lost ACK, restart и восстановление | Исходный UUID, no replay, owner-controlled recovery |

Разработка: registered task worktree → tests → PR/CI → owner merge → отдельная Windows sync и owner rollout.
