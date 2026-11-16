"""Offline Windows owner shell worker/HTTP security tests; no PowerShell run."""
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest import mock

from fortis_powershell_executor.owner_shell import ShellDenied, ShellWorker, ShellHandler, exact_request

RID='12345678-1234-4234-8234-123456789abc'


class ShellWorkerTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.calls=[]
        def runner(command):
            self.calls.append(command)
            return {'exitCode':0,'stdout':'2026-11-08','stderr':'','stdoutTruncated':False,'stderrTruncated':False}
        self.worker=ShellWorker(Path(self.tmp.name)/'owner-shell.sqlite',runner=runner)

    def test_request_validation_and_exact_digest(self):
        for invalid in ({'requestId':RID,'command':' '},{'requestId':RID,'command':'\x00'},
                        {'requestId':RID,'command':'x'*8193},{'requestId':RID,'command':'ok','extra':'a'},
                        {'requestId':'wrong','command':'Get-Date'}):
            with self.subTest(invalid=invalid),self.assertRaises(ShellDenied):
                exact_request(invalid)
        assert exact_request({'requestId':RID,'command':'Get-Date'})['command']=='Get-Date'

    def test_durable_idempotent_and_changed_payload_rejected(self):
        body={'requestId':RID,'command':'Get-Date'}
        first=self.worker.run(body)
        self.assertEqual('EXECUTED',first['state'])
        self.assertEqual(first,self.worker.run(body))
        self.assertEqual(first,self.worker.status(RID))
        self.assertEqual(['Get-Date'],self.calls)
        self.assertEqual(64,len(first['commandSha256']))
        with self.assertRaisesRegex(ShellDenied,'REQUEST_ID_CONFLICT'):
            self.worker.run({**body,'command':'Remove-Item xyz'})
        self.assertEqual(['Get-Date'],self.calls)

    def test_failed_script_may_have_side_effects_never_retries(self):
        def runner(command):
            self.calls.append(command)
            return {'exitCode':1,'stdout':'','stderr':'failed'}
        self.worker.runner=runner
        first=self.worker.run({'requestId':RID,'command':'Write-Error x'})
        self.assertEqual('FAILED',first['state'])
        self.assertEqual(1,first['exitCode'])
        self.assertEqual(first,self.worker.run({'requestId':RID,'command':'Write-Error x'}))
        self.assertEqual(1,len(self.calls))

    def test_timeout_unknown_blocks_future_dispatch(self):
        def fail(_):
            raise TimeoutError()
        self.worker.runner=fail
        first=self.worker.run({'requestId':RID,'command':'while ($true) {}'})
        self.assertEqual('UNCERTAIN',first['state'])
        self.assertEqual(first,self.worker.status(RID))
        self.assertEqual(first,self.worker.run({'requestId':RID,'command':'while ($true) {}'}))
        with self.assertRaisesRegex(ShellDenied,'SHELL_OPERATION_UNRESOLVED'):
            self.worker.run({'requestId':'22345678-1234-4234-8234-123456789abc','command':'Get-Date'})

    def test_non_windows_runner_cannot_call_real_powershell(self):
        with mock.patch('fortis_powershell_executor.owner_shell.os.name','posix'):
            with self.assertRaisesRegex(ShellDenied,'WINDOWS_REQUIRED'):
                ShellWorker._powershell('Get-Date')


class ShellHttpTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        self.calls=[]
        self.worker=ShellWorker(Path(tmp.name)/'receipt.sqlite',runner=lambda s:self.record(s))
        self.server=ThreadingHTTPServer(('127.0.0.1',0),ShellHandler)
        self.server.worker=self.worker
        self.server.secret='s'*40
        self.server.expected_host='host.docker.internal:10443'
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True)
        self.thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.thread.join,2)
        self.addCleanup(self.server.shutdown)

    def record(self,cmd):
        self.calls.append(cmd)
        return {'exitCode':0,'stdout':'OK','stderr':''}

    def call(self,method,path,body=None,headers=None):
        conn=HTTPConnection('127.0.0.1',self.server.server_port,timeout=5)
        hdr={'Host':self.server.expected_host,'Authorization':'Bearer '+'s'*40}
        hdr.update(headers or {})
        conn.request(method,path,body=body,headers=hdr)
        response=conn.getresponse()
        status=response.status
        content=json.loads(response.read())
        conn.close()
        return status,content

    def test_service_bearer_and_host_enforced(self):
        for headers in ({'Authorization':''},{'Authorization':'Bearer wrong'},
                        {'Host':'evil.example'},{'Host':'127.0.0.1:10443'}):
            code,_=self.call('GET','/owner-shell/v1/capabilities',headers=headers)
            self.assertEqual(401,code)
        self.assertEqual(200,self.call('GET','/owner-shell/v1/capabilities')[0])
        self.assertEqual([],self.calls)

    def test_exact_json_uuid_and_one_shot(self):
        path='/owner-shell/v1/execute'
        payload=json.dumps({'requestId':RID,'command':'Get-Date'})
        hdr={'Content-Type':'application/json','Idempotency-Key':RID}
        for malformed,extra in [('{}',hdr),('{"requestId":"x","command":"foo"}',hdr),
                                (payload,{**hdr,'Idempotency-Key':'wrong'}),
                                (payload,{**hdr,'Content-Type':'text/plain'})]:
            code,_=self.call('POST',path,malformed,headers=extra)
            self.assertEqual(400,code)
        self.assertEqual([],self.calls)
        code,result=self.call('POST',path,payload,headers=hdr)
        self.assertEqual(200,code)
        self.assertEqual('EXECUTED',result['state'])
        self.assertEqual(1,len(self.calls))
        code,replay=self.call('POST',path,payload,headers=hdr)
        self.assertEqual(200,code)
        self.assertEqual(result,replay)
        self.assertEqual(1,len(self.calls))
        code,receipt=self.call('GET','/owner-shell/v1/results/'+RID)
        self.assertEqual(result,receipt)
        self.assertEqual(200,code)
        self.assertEqual(405,self.call('PUT',path)[0])


if __name__=='__main__':
    unittest.main()
