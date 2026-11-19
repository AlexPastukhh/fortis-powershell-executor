# Windows Executor — Machine ASK V1 (accepted wire contract)

**Historical 2026-11-17:** the machine route was source-only and not yet
installed; that statement is not current. **2026-11-18:** owner-reported
Machine ASK activation with Get-Date/Reject E2E and verified receipts.
Full fault-injection/restart acceptance remains OPEN. For current Gateway
status use the [Gateway current-state guide](https://github.com/AlexPastukhh/fortis-approvals/blob/main/docs/guides/FORTIS-APPROVALS-SECURE-DEVELOPMENT.md).
This document describes **V1 protocol only**. Planned internal Dynamic ASK,
owner-editable command restrictions and narrow automatic ALLOW belong to
[Executor backlog](BACKLOG-IMPROVEMENTS.md#executor-dynamic-ask);
outer method `DENY/ASK/ALLOW` is owned by the
[Gateway plan](https://github.com/AlexPastukhh/fortis-approvals/blob/main/docs/BACKLOG-IMPROVEMENTS.md#powershell-plan).

## Flow and trust

Fortis Repo AI → authenticated typed Gateway → original Core PENDING/ASK → Owner Portal strong WebAuthn → Gateway creates a short-lived, exact-command-bound signed proof → distinct Windows machine route verifies the proof → durable same-DB receipt reservation → one non-admin Windows PowerShell command.

All **current V1** machine commands require ASK, including diagnostics.
There is no installed command allowlist, settings editor or automatic ALLOW.
Approval permits arbitrary PowerShell under the current Windows user's
rights; **not a sandbox**. The agreed **future** V2 architecture adds
outer method-policy plus Executor-only dynamic command-policy. See the
backlogs above for the implementation plan; do not alter V1 proof semantics.

## Machine protocol

- POST /machine-shell/v1/execute accepts only requestId, command and proof. It requires the separate machine Bearer, current mTLS, exact Host, and matching Idempotency-Key. Proof binds actor, target, exact UTF-8 command SHA256, UUID, Core-approved fingerprint, audience and lifetime.
- GET /machine-shell/v1/results/<UUID> returns only receipts bound to the registered machine actor and target, never existing owner-only receipts. The original owner-only GET/POST interface remains unchanged.
- A newly started machine route is not enabled without all four explicit CLI options: MachineBearerFile, MachineProofFile, MachineActor and MachineTarget. The launcher accepts them as an all-or-none optional group. The accepted owner setup/launch supplies these separately; historical Script Center versions did not.
- Proof uses HMAC-SHA256 and a distinct dedicated owner-managed 32+ byte key held by Gateway and Windows (not Repo). The bearer and proof key must differ from each other and the original owner secret. Key provisioning, revocation and rotation require owner review before any live activation.

## Installed data and recovery

The original Windows TLS files, existing protected config and **same current SQLite receipt DB** are retained. New authenticated machine execution only adds a shell_machine_bindings side table in that same DB; binding and DISPATCHED receipt reservation are one SQLite transaction. Historical owner-only receipts stay readable through owner route. An older UUID cannot be appropriated by machine. No second listener, no empty DB, no restore of an older receipt snapshot, no replay after timeout or lost ACK. Existing DISPATCHED/UNCERTAIN continues to block fresh effects.

The new machine files must be **direct children** of protected %LOCALAPPDATA%\Fortis\OwnerShell (not a nested directory or a similarly prefixed sibling), with owner-reviewed restrictive, non-inherited NTFS ACLs on the directory and both files. Non-admin execution remains mandatory. No machine credential, private key, or receipt is checked into Git.

**STOP before any NEW production release or V2 activation:** re-verify
protected credentials, source/installed identity, mTLS negative tests,
strong WebAuthn/Reject, forged/replayed proofs, same-DB migration/restart,
lost ACK and rollback under owner review. Existing positive live E2E is
not a substitute for these outstanding negatives. Source CI does not
install or restart Windows Executor.