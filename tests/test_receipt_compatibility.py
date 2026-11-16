"""Legacy ledger fixtures: no PowerShell or installed data is used."""
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from fortis_powershell_executor.owner_shell import ShellDenied, ShellWorker

RID = "12345678-1234-4234-8234-123456789abc"
OTHER = "22345678-1234-4234-8234-123456789abc"


class LegacyReceipts(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Path(self.tmp.name) / "existing.sqlite"
        self.calls = []
        with sqlite3.connect(self.db) as conn:
            conn.execute("CREATE TABLE shell_receipts (request_id TEXT PRIMARY KEY, "
                         "command_sha256 TEXT NOT NULL,state TEXT NOT NULL,result TEXT)")

    def worker(self):
        def runner(command):
            self.calls.append(command)
            raise AssertionError("legacy replay must not execute")
        return ShellWorker(self.db, runner=runner)

    def seed(self, state, result=None):
        digest = hashlib.sha256(b"Get-Date").hexdigest()
        with sqlite3.connect(self.db) as conn:
            conn.execute("INSERT INTO shell_receipts VALUES (?,?,?,?)",
                         (RID, digest, state, json.dumps(result) if result else None))

    def test_existing_receipt_is_returned_after_relocation_and_restart(self):
        result = {"requestId": RID, "state": "EXECUTED", "exitCode": 0,
                  "commandSha256": hashlib.sha256(b"Get-Date").hexdigest(),
                  "stdout": "old Windows result", "stderr": ""}
        self.seed("EXECUTED", result)
        self.assertEqual(result, self.worker().status(RID))
        self.assertEqual(result, self.worker().run(
            {"requestId": RID, "command": "Get-Date"}))
        with self.assertRaisesRegex(ShellDenied, "REQUEST_ID_CONFLICT"):
            self.worker().run({"requestId": RID, "command": "Get-Process"})
        self.assertEqual([], self.calls)

    def test_existing_unresolved_reservation_still_blocks_new_effect(self):
        for state in ("DISPATCHED", "UNCERTAIN"):
            with self.subTest(state=state):
                with sqlite3.connect(self.db) as conn:
                    conn.execute("DELETE FROM shell_receipts")
                self.seed(state)
                self.assertEqual(state, self.worker().status(RID)["state"])
                with self.assertRaisesRegex(ShellDenied, "SHELL_OPERATION_UNRESOLVED"):
                    self.worker().run({"requestId": OTHER, "command": "Get-Date"})
        self.assertEqual([], self.calls)


if __name__ == "__main__":
    unittest.main()
