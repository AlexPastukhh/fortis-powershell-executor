"""Opt-in owner-only Windows PowerShell executor (NOT a browser or AI route).

This is intentionally a separate TLS/mTLS listener and receipt DB. A trusted
Owner Portal server may forward an authenticated owner's exact one-shot script.
No remote executor is enabled by the ordinary Mirror launcher.

WARNING: Arbitrary PowerShell runs with this service process's Windows user
permissions. This is not a sandbox, and a compromised mTLS client AND bearer
secret grants remote code execution. Never run the process as Administrator.
"""
import argparse
import base64
import ctypes
import hmac
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import ssl
import subprocess
import threading
from datetime import datetime, timezone

UUID = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z')
MAX_COMMAND_BYTES = 8192
MAX_CAPTURE_BYTES = 65536


class ShellDenied(ValueError):
    pass


def exact_request(payload):
    if (type(payload) is not dict or set(payload) != {'requestId', 'command'} or
            type(payload['requestId']) is not str or not UUID.fullmatch(payload['requestId']) or
            type(payload['command']) is not str or not payload['command'].strip() or
            '\x00' in payload['command'] or
            len(payload['command'].encode('utf-8')) > MAX_COMMAND_BYTES):
        raise ShellDenied('SHELL_REQUEST_INVALID')
    return payload


class ShellWorker:
    """Durable no-retry receipts for one-shot PowerShell operations."""
    def __init__(self, receipt_db, *, runner=None):
        self.path = Path(receipt_db)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()
        self.runner = runner or self._powershell
        with self._db() as db:
            db.execute('CREATE TABLE IF NOT EXISTS shell_receipts ('
                       'request_id TEXT PRIMARY KEY, command_sha256 TEXT NOT NULL, '
                       'state TEXT NOT NULL, result TEXT)')

    def _db(self):
        db = sqlite3.connect(str(self.path), timeout=15)
        db.execute('PRAGMA synchronous=FULL')
        return db

    @staticmethod
    def _powershell(command):
        if os.name != 'nt':
            raise ShellDenied('WINDOWS_REQUIRED')
        # Use UTF-8 for PowerShell's redirected stdout/stderr on Windows.
        wrapped = '[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)\n' + command
        encoded = base64.b64encode(wrapped.encode('utf-16le')).decode('ascii')
        # Fixed argv; never use shell=True or prepend interpreter code supplied
        # from the network. Script runs without a PowerShell profile or stdin.
        argv = ['powershell.exe', '-NoLogo', '-NoProfile', '-NonInteractive',
                '-EncodedCommand', encoded]
        # Do not inherit Gateway/Owner Portal environment variables or secrets.
        env = {key: value for key, value in os.environ.items()
               if not any(part in key.upper() for part in (
                   'TOKEN', 'SECRET', 'PASSWORD', 'FORTIS_', 'GITHUB_', 'GH_', 'AUTH', 'KEY'))}
        # A caller may still read files or launch children under this account.
        # This intentionally does not claim isolation or a security sandbox.
        # Limit captured output while actively draining both pipes. On large
        # output/timeout abort and mark outcome UNCERTAIN, never auto-retry.
        chunks = [[], []]
        counts = [0, 0]
        excessive = threading.Event()
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   env=env, cwd=str(Path.home()),
                                   creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        def drain(stream, index):
            try:
                while True:
                    block = stream.read(4096)
                    if not block:
                        break
                    counts[index] += len(block)
                    if counts[index] > MAX_CAPTURE_BYTES:
                        excessive.set()
                        process.kill()
                        break
                    chunks[index].append(block)
            except (OSError, ValueError):
                excessive.set()
        readers = [threading.Thread(target=drain, args=(stream,index), daemon=True)
                   for index,stream in enumerate((process.stdout, process.stderr))]
        for reader in readers:
            reader.start()
        try:
            code = process.wait(timeout=60)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)
            raise ShellDenied('SHELL_TIMEOUT_UNCERTAIN')
        finally:
            for reader in readers:
                reader.join(timeout=5)
            for stream in (process.stdout,process.stderr):
                stream.close()
        if excessive.is_set() or any(reader.is_alive() for reader in readers):
            raise ShellDenied('SHELL_OUTPUT_LIMIT_UNCERTAIN')
        return {'exitCode': code,
                'stdout': b''.join(chunks[0]).decode('utf-8-sig', errors='replace'),
                'stderr': b''.join(chunks[1]).decode('utf-8-sig', errors='replace'),
                'stdoutTruncated': False, 'stderrTruncated': False}

    def status(self, request_id):
        if type(request_id) is not str or not UUID.fullmatch(request_id):
            raise ShellDenied('REQUEST_ID_INVALID')
        with self._db() as db:
            row = db.execute('SELECT state,result FROM shell_receipts WHERE request_id=?', (request_id,)).fetchone()
        if row is None:
            return {'requestId': request_id, 'state': 'NOT_FOUND'}
        return json.loads(row[1]) if row[1] else {'requestId': request_id, 'state': row[0]}

    def run(self, payload):
        checked = exact_request(payload)
        request_id, command = checked['requestId'], checked['command']
        sha = hashlib.sha256(command.encode('utf-8')).hexdigest()
        with self.lock:
            with self._db() as db:
                db.execute('BEGIN IMMEDIATE')
                prior = db.execute('SELECT command_sha256,state,result FROM shell_receipts WHERE request_id=?',
                                   (request_id,)).fetchone()
                if prior is not None:
                    if prior[0] != sha:
                        raise ShellDenied('REQUEST_ID_CONFLICT')
                    return json.loads(prior[2]) if prior[2] else {'requestId':request_id,'state':prior[1]}
                # Prevent a concurrent separate process using the same receipt
                # store from dispatching another execution while a prior result
                # remains pending or ambiguous.
                unfinished = db.execute("SELECT count(*) FROM shell_receipts WHERE state IN ('DISPATCHED','UNCERTAIN')").fetchone()[0]
                if unfinished:
                    raise ShellDenied('SHELL_OPERATION_UNRESOLVED')
                db.execute('INSERT INTO shell_receipts VALUES (?,?,?,NULL)',
                           (request_id, sha, 'DISPATCHED'))
            try:
                result = self.runner(command)
                if (type(result) is not dict or type(result.get('exitCode')) is not int or
                        type(result.get('stdout')) is not str or type(result.get('stderr')) is not str):
                    raise ValueError('INVALID_RUNNER_RESULT')
                receipt = {'requestId': request_id, 'state': 'EXECUTED' if result['exitCode'] == 0 else 'FAILED',
                           'commandSha256': sha, 'exitCode': result['exitCode'],
                           'stdout': result['stdout'][:MAX_CAPTURE_BYTES],
                           'stderr': result['stderr'][:MAX_CAPTURE_BYTES],
                           'stdoutTruncated': bool(result.get('stdoutTruncated', False)),
                           'stderrTruncated': bool(result.get('stderrTruncated', False)),
                           'checkedAt': datetime.now(timezone.utc).isoformat(timespec='seconds')}
            except Exception:
                # Timeout can leave detached child processes; do not re-run.
                receipt = {'requestId': request_id, 'state': 'UNCERTAIN',
                           'commandSha256': sha, 'error': 'SHELL_OUTCOME_UNCONFIRMED',
                           'checkedAt': datetime.now(timezone.utc).isoformat(timespec='seconds')}
            with self._db() as db:
                db.execute('UPDATE shell_receipts SET state=?,result=? WHERE request_id=?',
                           (receipt['state'], json.dumps(receipt), request_id))
            return receipt


class ShellHandler(BaseHTTPRequestHandler):
    server_version = 'FortisOwnerShell/0.1'

    def log_message(self, *args):
        # Never log URLs, commands, credentials or outputs.
        return

    def reply(self, code, value):
        body = json.dumps(value, ensure_ascii=False).encode('utf-8')
        self.send_response(code)
        for key, value in [('Content-Type', 'application/json; charset=utf-8'),
                           ('Cache-Control', 'no-store'), ('X-Content-Type-Options', 'nosniff'),
                           ('Content-Length', str(len(body)))]:
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def authorized(self):
        if self.headers.get('Host') != self.server.expected_host:
            return False
        actual = self.headers.get('Authorization', '')
        return hmac.compare_digest(actual, 'Bearer ' + self.server.secret)

    def do_GET(self):
        if not self.authorized():
            self.reply(HTTPStatus.UNAUTHORIZED, {'error': 'OWNER_SHELL_AUTH_REQUIRED'})
            return
        if self.path == '/owner-shell/v1/capabilities':
            self.reply(HTTPStatus.OK, {'schemaVersion': 1, 'oneShot': True, 'windows': True,
                                       'analyzer': False, 'externalAI': False})
            return
        match = re.fullmatch(r'/owner-shell/v1/results/([0-9a-f-]{36})', self.path)
        if match:
            try:
                self.reply(HTTPStatus.OK, self.server.worker.status(match.group(1)))
            except ShellDenied as exc:
                self.reply(HTTPStatus.BAD_REQUEST, {'error': str(exc)})
            return
        self.reply(HTTPStatus.NOT_FOUND, {'error': 'ROUTE_NOT_FOUND'})

    def do_POST(self):
        if not self.authorized():
            self.reply(HTTPStatus.UNAUTHORIZED, {'error': 'OWNER_SHELL_AUTH_REQUIRED'})
            return
        if self.path != '/owner-shell/v1/execute':
            self.reply(HTTPStatus.NOT_FOUND, {'error': 'ROUTE_NOT_FOUND'})
            return
        if (self.headers.get('Content-Type') != 'application/json' or
                self.headers.get('Transfer-Encoding')):
            self.reply(HTTPStatus.BAD_REQUEST, {'error': 'SHELL_JSON_REQUIRED'})
            return
        try:
            n = int(self.headers.get('Content-Length', '0'))
            if not 0 < n <= 16000:
                raise ValueError()
            body = self.rfile.read(n)
            if len(body) != n:
                raise ValueError()
            def unique(pairs):
                result = {}
                for key, value in pairs:
                    if key in result:
                        raise ValueError()
                    result[key] = value
                return result
            payload = exact_request(json.loads(body, object_pairs_hook=unique))
            if payload['requestId'] != self.headers.get('Idempotency-Key'):
                raise ValueError()
        except (ValueError, TypeError, UnicodeError):
            self.reply(HTTPStatus.BAD_REQUEST, {'error': 'SHELL_REQUEST_INVALID'})
            return
        try:
            self.reply(HTTPStatus.OK, self.server.worker.run(payload))
        except ShellDenied as exc:
            self.reply(HTTPStatus.CONFLICT, {'error': str(exc)})

    def do_PUT(self):
        self.reply(HTTPStatus.METHOD_NOT_ALLOWED, {'error': 'METHOD_DENIED'})
    do_PATCH = do_DELETE = do_PUT


def start_owner_shell(bind, port, cert, key, client_ca, secret_file, receipt_db):
    if os.name != 'nt':
        raise ShellDenied('WINDOWS_REQUIRED')
    if ctypes.windll.shell32.IsUserAnAdmin():
        raise ShellDenied('OWNER_SHELL_ELEVATED_DENIED')
    if not all((cert, key, client_ca, secret_file, receipt_db)):
        raise ShellDenied('OWNER_SHELL_TLS_CONFIG_REQUIRED')
    secret = Path(secret_file).read_text(encoding='ascii').strip()
    if (not 32 <= len(secret) <= 256 or
            any(ord(c) < 33 or ord(c) > 126 for c in secret)):
        raise ShellDenied('OWNER_SHELL_SECRET_INVALID')
    listener = ThreadingHTTPServer((bind, port), ShellHandler)
    listener.daemon_threads = True
    listener.worker = ShellWorker(receipt_db)
    listener.expected_host = 'host.docker.internal:' + str(port)
    listener.secret = secret
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=cert, keyfile=key)
    context.load_verify_locations(cafile=client_ca)
    context.verify_mode = ssl.CERT_REQUIRED
    listener.socket = context.wrap_socket(listener.socket, server_side=True)
    return listener


def main(argv=None):
    parser = argparse.ArgumentParser(description='Opt-in dedicated Windows owner PowerShell executor')
    for name in ('bind', 'port', 'cert', 'key', 'client-ca', 'secret-file', 'receipt-db'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args(argv)
    if not 1024 <= int(args.port) <= 65535:
        parser.error('PORT_INVALID')
    with start_owner_shell(args.bind, int(args.port), args.cert, args.key, args.client_ca,
                           args.secret_file, args.receipt_db) as server:
        print('OWNER_SHELL_MTLS_READY (no browser or machine API; do not run elevated)', flush=True)
        server.serve_forever()


if __name__ == '__main__':
    main()
