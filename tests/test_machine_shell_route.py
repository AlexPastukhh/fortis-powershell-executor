"""In-process synthetic HTTP tests: NEVER launch Windows PowerShell."""
import hashlib
import hmac
import http.client
from http.server import ThreadingHTTPServer
import json
import tempfile
from pathlib import Path
import threading
import time
import unittest

from fortis_powershell_executor.owner_shell import ShellWorker, ShellHandler, ShellDenied
from fortis_powershell_executor.machine_proof import AUDIENCE, canonical

KEY = b"offline-fixture-machine-proof-key-32bytes"
BEARER = "offline-fixture-machine-bearer-32bytes"
OWNER_BEARER = "offline-fixture-legacy-owner-bearer-32bytes"
REQUEST_ID = "01234567-89ab-4def-8abc-0123456789ab"


def proof(command="Get-Date", *, actor="fortis-repo", target="windows-owner", request_id=REQUEST_ID,
          core_fingerprint="a"*64):
    now = int(time.time())
    claims = {
        "version":1, "audience":AUDIENCE, "requestId": request_id,
        "actor":actor,"target":target,"coreFingerprint":core_fingerprint,
        "commandSha256":hashlib.sha256(command.encode("utf-8")).hexdigest(),
        "issuedAt":now,"expiresAt":now+60,
        "nonce":"synthetic-proof-nonce-0123456789",
    }
    signature=hmac.new(KEY, b"fortis:machine-powershell:v1\n"+canonical(claims),
                       hashlib.sha256).hexdigest()
    return {"claims":claims,"mac":signature}


class MachineShellHTTPTests(unittest.TestCase):
    def setUp(self):
        self.t=tempfile.TemporaryDirectory()
        self.addCleanup(self.t.cleanup)
        self.calls=[]
        def runner(command):
            self.calls.append(command)
            return {"exitCode":0,"stdout":"fixture", "stderr":""}
        self.worker=ShellWorker(Path(self.t.name)/"original.sqlite3",runner=runner)
        self.server=ThreadingHTTPServer(("127.0.0.1",0),ShellHandler)
        self.server.daemon_threads=True
        self.server.worker=self.worker
        self.server.expected_host="host.docker.internal:10443"
        self.server.secret=OWNER_BEARER
        self.server.machine_enabled=True
        self.server.machine_bearer=BEARER
        self.server.machine_proof_key=KEY
        self.server.machine_actor="fortis-repo"
        self.server.machine_target="windows-owner"
        self.td=threading.Thread(target=self.server.serve_forever,daemon=True)
        self.td.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def call(self, path, body=None, token=BEARER, headers=None, method=None):
        conn=http.client.HTTPConnection("127.0.0.1",self.server.server_port,timeout=3)
        data=None if body is None else json.dumps(body, ensure_ascii=False, separators=(",",":")).encode()
        h={"Host":"host.docker.internal:10443","Authorization":"Bearer "+token}
        if body is not None:
            h.update({"Content-Type":"application/json","Idempotency-Key":body["requestId"]})
        h.update(headers or {})
        conn.request(method or ("POST" if body is not None else "GET"),path,body=data,headers=h)
        r=conn.getresponse()
        status=r.status
        obj=json.loads(r.read().decode())
        conn.close()
        return status,obj

    def body(self, command="Get-Date", *, nonce_proof=None):
        return {"requestId":REQUEST_ID, "command":command,
                "proof":nonce_proof or proof(command)}

    def test_machine_accepts_only_signed_approved_like_proof_once(self):
        self.assertEqual(self.call("/machine-shell/v1/execute",self.body())[0],200)
        self.assertEqual(self.calls,["Get-Date"])
        self.assertEqual(self.call("/machine-shell/v1/execute",self.body())[0],200)
        self.assertEqual(self.calls,["Get-Date"])
        s,body=self.call("/machine-shell/v1/results/"+REQUEST_ID)
        self.assertEqual((s,body["state"]), (200,"EXECUTED"))
        self.assertEqual(body["commandSha256"],hashlib.sha256(b"Get-Date").hexdigest())

    def test_missing_or_wrong_proof_never_executes(self):
        invalid=[
            {**self.body(),"proof":{}},
            self.body("Get-Location",nonce_proof=proof("Get-Date")),
            self.body(nonce_proof=proof(target="other")),
            self.body(nonce_proof=proof(actor="other")),
            self.body(nonce_proof=proof(core_fingerprint="g"*64)),
        ]
        for data in invalid:
            with self.subTest(data=data["proof"].get("claims",{}).get("target")):
                status,_=self.call("/machine-shell/v1/execute",data)
                self.assertEqual(status,403)
        self.assertEqual(self.calls,[])

    def test_bearer_wrong_host_content_type_and_idempotency_key(self):
        good=self.body()
        for kwargs in [
            {"token":"wrong"},
            {"headers":{"Host":"attacker.invalid"}},
            {"headers":{"Content-Type":"text/plain"}},
            {"headers":{"Idempotency-Key":"not-the-uuid"}},
        ]:
            with self.subTest(kwargs=kwargs):
                self.assertNotEqual(self.call("/machine-shell/v1/execute",good,**kwargs)[0],200)
        self.assertEqual(self.calls,[])

    def test_machine_credentials_cannot_use_legacy_owner_execution(self):
        owner_payload={"requestId":REQUEST_ID,"command":"Get-Date"}
        status,_=self.call("/owner-shell/v1/execute",owner_payload,token=BEARER)
        self.assertEqual(status,401)
        status,_=self.call("/owner-shell/v1/execute",owner_payload,token=OWNER_BEARER)
        self.assertEqual(status,200)
        self.assertEqual(self.calls,["Get-Date"])
        status,_=self.call("/machine-shell/v1/execute",self.body())
        self.assertEqual(status,409)  # old owner receipt cannot be adopted by machine
        self.assertEqual(self.calls,["Get-Date"])

    def test_distinct_actor_binding_and_no_effect_after_conflicting_proof(self):
        self.assertEqual(self.call("/machine-shell/v1/execute",self.body())[0],200)
        altered=self.body(nonce_proof=proof(core_fingerprint="f"*64))
        self.assertEqual(self.call("/machine-shell/v1/execute",altered)[0],409)
        self.assertEqual(self.calls,["Get-Date"])

    def test_machine_get_never_exposes_legacy_owner_receipt(self):
        owner_payload={"requestId":REQUEST_ID,"command":"Get-Date"}
        self.assertEqual(self.call("/owner-shell/v1/execute",owner_payload,
                                   token=OWNER_BEARER)[0],200)
        status,body=self.call("/machine-shell/v1/results/"+REQUEST_ID)
        self.assertEqual((status,body["state"]),(200,"NOT_FOUND"))
        self.assertEqual(self.worker.status(REQUEST_ID)["state"],"EXECUTED")
        self.assertEqual(self.calls,["Get-Date"])

    def test_machine_binding_table_is_additive_same_db_after_restart(self):
        self.assertEqual(self.call("/machine-shell/v1/execute",self.body())[0],200)
        old=ShellWorker(self.worker.path,runner=lambda _command:
                        self.fail("receipt was incorrectly replayed"))
        self.assertEqual(old.status(REQUEST_ID)["state"],"EXECUTED")
        self.assertEqual(old.machine_status(REQUEST_ID,actor="fortis-repo",
                                           target="windows-owner")["state"],"EXECUTED")
        self.assertEqual(old.machine_status(REQUEST_ID,actor="unknown",
                                           target="windows-owner")["state"],"NOT_FOUND")
        self.assertEqual(old.machine_status(REQUEST_ID,actor="fortis-repo",
                                           target="other")["state"],"NOT_FOUND")
        self.assertEqual(self.calls,["Get-Date"])

    def test_machine_route_disabled_by_default(self):
        self.server.machine_enabled=False
        status,_=self.call("/machine-shell/v1/execute",self.body())
        self.assertEqual(status,401)
        self.assertEqual(self.calls,[])


if __name__ == "__main__":
    unittest.main()
