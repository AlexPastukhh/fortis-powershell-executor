# Fortis PowerShell Executor

Standalone source for the existing Windows PowerShell 5.1 Executor.
Source extraction is not installation or live acceptance.

## Scope

The baseline accepts only the trusted Owner Portal transport using mTLS and
an independent bearer. It is one-shot, noninteractive and non-admin.
It does not yet implement Repo machine ASK, an approval proof or command rules.
Those are the next stages in the [Gateway plan](https://github.com/AlexPastukhh/fortis-approvals/blob/main/docs/BACKLOG-IMPROVEMENTS.md#powershell-plan).

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
