# Fortis PowerShell Executor

Standalone source for the existing Windows PowerShell 5.1 Executor.
Source extraction is not installation or live acceptance.

## Scope

The baseline accepts only the trusted Owner Portal transport using mTLS and
an independent bearer. It is one-shot, noninteractive and non-admin.
The owner-only interface remains separate from the machine route. Machine ASK
V1 **is enabled on the owner's Windows** (owner-reported Get-Date/Reject E2E,
2026-11-18, independently checked in Gateway/receipts). A fresh source install
is **disabled by default** until the owner provisions protected configuration;
this default is not the current live status. Full fault-injection/restart
acceptance remains open. See the frozen [Machine ASK V1](docs/MACHINE-ASK-V1.md)
and [Executor Use Cases](docs/use-cases/README.md).
The planned inner per-command `DENY/ASK/ALLOW` evaluator and owner settings
are specified **only** in [Executor backlog](docs/BACKLOG-IMPROVEMENTS.md#executor-dynamic-ask).
The common outer provider/method policy and approval precedence belong to the
[Gateway plan](https://github.com/AlexPastukhh/fortis-approvals/blob/main/docs/BACKLOG-IMPROVEMENTS.md#powershell-plan).

The runner is byte-identical to its recorded original Git blob.
Only package/test imports and the launcher module name are relocated.
Mirror, Browser Pull and Git synchronization are not runtime dependencies.
Gateway continues to use the same HTTPS API, not this Python package.

Run offline tests from this source root:

`python -B -m unittest discover -s tests -v`

Use the existing certificates, protected settings and SAME EXISTING receipt DB.
Do not start this candidate next to the old listener or create a replacement DB.
See [API](docs/API.md), [migration](docs/MIGRATION.md) and
[SOURCE-PROVENANCE.json](SOURCE-PROVENANCE.json).

No license is selected by this extraction tool. The owner controls repository
visibility and licensing during bootstrap. Historical source remains attributable
to the original repository/commit recorded in the provenance document.
