# Windows Executor — owner-only API and Machine ASK V1

The owner-only protocol remains unchanged. The separate machine API is
**active in live ASK-only V1** (2026-11-18 Get-Date/Reject E2E); the source
launcher still requires an explicit protected opt-in on a **new install**.
See [Machine ASK V1](MACHINE-ASK-V1.md) for the existing machine wire
contract, not a second copy of it. Dynamic per-command ASK/ALLOW is
**planned only** in [Executor backlog](BACKLOG-IMPROVEMENTS.md#executor-dynamic-ask).

- Owner-managed Windows bind: 127.0.0.1:10443; Gateway uses
  https://host.docker.internal:10443 with the existing server identity.
- Mandatory TLS client certificate and independent Bearer credential.
- GET /owner-shell/v1/capabilities and /owner-shell/v1/results/<UUID>.
- POST /owner-shell/v1/execute accepts exactly command and requestId.
- Idempotency-Key must equal requestId. UUID binds the exact command digest.
- Command limit 8192 UTF-8 bytes, timeout 60 seconds, output bound 65536 bytes
  for each stdout/stderr stream. One PowerShell 5.1 process, no profile/stdin.
- Durable reserve before launch. Same UUID never launches a second execution;
  different content under that UUID is a conflict. UNCERTAIN/DISPATCHED blocks
  another effect on that receipt store until reviewed recovery.
- Nonzero exit is not proof that no side effect occurred.

The current Windows process has its user's ordinary permissions; this is not
a sandbox. The API itself cannot independently prove human approval.
Keep its TLS client key and bearer away from Repo machine callers.
Full Windows session/TLS/receipt/restart acceptance is separate from offline CI.
Gateway owner-session/Host/Origin/CSRF checks remain owned by fortis-approvals.
