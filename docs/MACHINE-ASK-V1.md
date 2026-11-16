# Windows Executor — Machine ASK V1 (source only)

**2026-11-17 status:** not installed or enabled on the owner's Windows. The existing owner-only Script Center registration supplies no machine options and continues to use its original TLS/config/receipt DB.

## Flow and trust

Fortis Repo AI → authenticated typed Gateway → original Core PENDING/ASK → Owner Portal strong WebAuthn → Gateway creates a short-lived, exact-command-bound signed proof → distinct Windows machine route verifies the proof → durable same-DB receipt reservation → one non-admin Windows PowerShell command.

All V1 machine commands require ASK, including diagnostics. There is no command allowlist, settings editor or automatic ALLOW. Approval permits arbitrary PowerShell under the current Windows user's rights; **not a sandbox**. Owner-editable constraints and optional narrow ASK/ALLOW belong to V2+.

## Machine protocol

- POST /machine-shell/v1/execute accepts only requestId, command and proof. It requires the separate machine Bearer, current mTLS, exact Host, and matching Idempotency-Key. Proof binds actor, target, exact UTF-8 command SHA256, UUID, Core-approved fingerprint, audience and lifetime.
- GET /machine-shell/v1/results/<UUID> returns only receipts bound to the registered machine actor and target, never existing owner-only receipts. The original owner-only GET/POST interface remains unchanged.
- No machine route is enabled without all four explicit CLI options: MachineBearerFile, MachineProofFile, MachineActor and MachineTarget. The launcher accepts them as an all-or-none optional group. Existing Script Center does not pass them.
- Proof uses HMAC-SHA256 and a distinct dedicated owner-managed 32+ byte key held by Gateway and Windows (not Repo). The bearer and proof key must differ from each other and the original owner secret. Key provisioning, revocation and rotation require owner review before any live activation.

## Installed data and recovery

The original Windows TLS files, existing protected config and **same current SQLite receipt DB** are retained. New authenticated machine execution only adds a shell_machine_bindings side table in that same DB; binding and DISPATCHED receipt reservation are one SQLite transaction. Historical owner-only receipts stay readable through owner route. An older UUID cannot be appropriated by machine. No second listener, no empty DB, no restore of an older receipt snapshot, no replay after timeout or lost ACK. Existing DISPATCHED/UNCERTAIN continues to block fresh effects.

The new machine files must be under protected %LOCALAPPDATA%\Fortis\OwnerShell, with owner-reviewed restrictive NTFS ACLs. Non-admin execution remains mandatory. No machine credential, private key, or receipt is checked into Git.

**STOP before production:** distinct protected credentials, cryptographic/security review, owner-supplied Script Center enablement, Windows source update, Gateway owner-controlled release, mTLS negative tests, strong WebAuthn/Reject tests, same-DB migration/restart tests and rollback. Source CI does not imply Windows installation.