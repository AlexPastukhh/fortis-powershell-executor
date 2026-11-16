# Source extraction and Windows handoff

Status: SOURCE CANDIDATE; no host installation/cutover is implied.

1. Owner creates the agreed repository with an initial main commit, chooses
   visibility/license, then provides its HTTPS URL. Follow UC-CONT-027 and
   typed Gateway bootstrap before importing this candidate into a task.
2. Import the exact reviewed candidate, preserve provenance, run source CI and
   Release Impact, obtain owner merge and sync the new Windows primary clone.
3. Update the Script Center adapter/resolver to validate the canonical
   %USERPROFILE%\Repos\fortis-powershell-executor clone and approved origin/main.
   It must retain existing setup/config/ACL/non-admin/port/source-change checks.
4. Keep the same cert/key/client CA/bearer files and SAME EXISTING SQLite DB,
   including historical receipts and unresolved states. Keep protected launch
   settings. No new empty DB, certificate issuance or forced setup.
5. Record the actual old source/identity/bind/config and in-flight/unresolved
   state. Perform reviewed quiescence and an owner-controlled switch with only
   one listener. Do not infer that a missing parent means no detached child.
6. Probe the unchanged API from Gateway, verify historical receipt reads and
   replay/conflict/timeout/restart behavior. A new harmless command uses a new
   UUID from the existing authenticated owner Portal.
7. Retire the old implementation only after live acceptance and retained
   rollback. Do not develop two authoritative copies.

Rollback stops the new listener before returning to the old source/launcher.
Use the same CURRENT receipt DB and TLS/config. Do not restore an older DB
snapshot that forgets newly reserved UUIDs or results. Ambiguity requires
reviewed recovery, not replay or manual ledger editing.

A source move with unchanged API/config does not need a Gateway image rebuild.
ASK-only machine execution is a separately reviewed, opt-in source stage (see docs/MACHINE-ASK-V1.md); owner-editable restrictions and selective ALLOW belong to V2+.
See the authoritative plan in fortis-approvals for owner release/acceptance.
