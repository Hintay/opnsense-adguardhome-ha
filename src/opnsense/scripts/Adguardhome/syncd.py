#!/usr/local/bin/python3
"""Replicate AdGuard Home configuration over an authenticated TLS peer link."""

import argparse
import base64
import fcntl
import hashlib
import hmac
import http.client
import ipaddress
import json
import os
from pathlib import Path
import secrets
import select
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import syslog
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


ADGUARD_HOME = Path('/usr/local/AdGuardHome')
ADGUARD_CONFIG = ADGUARD_HOME / 'AdGuardHome.yaml'
ADGUARD_BINARY = Path('/usr/local/bin/adguardhome')
SETTINGS_PATH = Path('/usr/local/etc/adguardhome-sync.json')
CERTIFICATE_PATH = Path('/usr/local/etc/adguardhome-sync.pem')
LOCK_PATH = Path('/var/run/adguardhome-sync.lock')
MAX_CONFIG_BYTES = 8 * 1024 * 1024
RETRY_SECONDS = 300
TIMESTAMP_SKEW_SECONDS = 60
NONCE_TTL_SECONDS = 600


def log(priority, message):
    syslog.syslog(priority, message)


def run(*args, input_data=None, timeout=45):
    return subprocess.run(args, input=input_data, capture_output=True, timeout=timeout)


def atomic_write(path, content, mode=0o600):
    path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix='.' + path.name + '.', delete=False) as stream:
        stream.write(content)
        stream.flush()
        os.fchmod(stream.fileno(), mode)
        candidate = Path(stream.name)
    candidate.replace(path)


def sha256_bytes(content):
    return hashlib.sha256(content).hexdigest()


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def require_ipv4(value, name):
    try:
        address = ipaddress.ip_address(value)
    except ValueError as error:
        raise RuntimeError(name + ' is invalid.') from error
    if address.version != 4:
        raise RuntimeError(name + ' must be an IPv4 address.')
    return str(address)


def load_settings():
    try:
        raw = json.loads(SETTINGS_PATH.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError('Synchronization settings are unavailable.') from error
    if not isinstance(raw.get('enabled'), bool):
        raise RuntimeError('Synchronization enabled state is invalid.')
    if not raw['enabled']:
        return raw
    role = raw.get('role')
    if role not in ('source', 'receiver'):
        raise RuntimeError('Synchronization role is invalid.')
    raw['listen_address'] = require_ipv4(raw.get('listen_address'), 'Local state-sync address')
    raw['peer_address'] = require_ipv4(raw.get('peer_address'), 'Peer state-sync address')
    if raw['listen_address'] == raw['peer_address']:
        raise RuntimeError('State-sync peer addresses must differ.')
    try:
        raw['port'] = int(raw.get('port'))
    except (TypeError, ValueError) as error:
        raise RuntimeError('Synchronization port is invalid.') from error
    if not 1024 <= raw['port'] <= 65535:
        raise RuntimeError('Synchronization port is invalid.')
    secret = raw.get('secret')
    if not isinstance(secret, str) or not 32 <= len(secret) <= 256:
        raise RuntimeError('Pairing secret is invalid.')
    if role == 'source':
        fingerprint = raw.get('peer_fingerprint', '').lower().replace(':', '')
        if len(fingerprint) != 64 or any(char not in '0123456789abcdef' for char in fingerprint):
            raise RuntimeError('Peer certificate fingerprint is invalid.')
        raw['peer_fingerprint'] = fingerprint
    return raw


def certificate_fingerprint():
    if not CERTIFICATE_PATH.is_file():
        return None
    result = run('/usr/bin/openssl', 'x509', '-in', str(CERTIFICATE_PATH), '-outform', 'DER', timeout=20)
    if result.returncode:
        return None
    return sha256_bytes(result.stdout)


def ensure_certificate(settings):
    if CERTIFICATE_PATH.is_file():
        return certificate_fingerprint()
    command = [
        '/usr/bin/openssl', 'req', '-x509', '-newkey', 'rsa:3072', '-sha256', '-nodes', '-days', '3650',
        '-subj', '/CN=adguardhome-sync',
        '-addext', 'subjectAltName=IP:' + settings['listen_address'],
        '-keyout', str(CERTIFICATE_PATH), '-out', str(CERTIFICATE_PATH),
    ]
    result = run(*command, timeout=60)
    if result.returncode:
        detail = (result.stderr or result.stdout).decode(errors='replace').strip()[-300:]
        raise RuntimeError('Unable to create synchronization certificate: ' + detail)
    os.chmod(CERTIFICATE_PATH, 0o600)
    fingerprint = certificate_fingerprint()
    if fingerprint is None:
        raise RuntimeError('Unable to read synchronization certificate.')
    return fingerprint


def binary_path():
    if ADGUARD_BINARY.is_file() and os.access(ADGUARD_BINARY, os.X_OK):
        return ADGUARD_BINARY
    raise RuntimeError('AdGuard Home is not installed.')


def check_config(path):
    result = run(str(binary_path()), '--config', str(path), '--check-config', timeout=20)
    if result.returncode:
        detail = (result.stderr or result.stdout).decode(errors='replace').strip()[-500:]
        raise RuntimeError('AdGuard Home configuration validation failed: ' + detail)


def source_payload():
    if not ADGUARD_CONFIG.is_file():
        raise RuntimeError('AdGuard Home configuration is unavailable.')
    size = ADGUARD_CONFIG.stat().st_size
    if not 0 < size <= MAX_CONFIG_BYTES:
        raise RuntimeError('AdGuard Home configuration size is invalid.')
    check_config(ADGUARD_CONFIG)
    return ADGUARD_CONFIG.read_bytes()


def acquire_lock(action):
    LOCK_PATH.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    with LOCK_PATH.open('w') as stream:
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise RuntimeError('Another synchronization is already running.') from error
        return action()


def signature(settings, method, path, timestamp, nonce, digest):
    message = '\n'.join((method, path, timestamp, nonce, digest)).encode()
    return hmac.new(settings['secret'].encode(), message, hashlib.sha256).hexdigest()


def push_once(settings):
    if settings.get('role') != 'source':
        raise RuntimeError('This node is not the synchronization source.')
    payload = source_payload()
    timestamp = str(int(time.time()))
    nonce = secrets.token_urlsafe(24)
    digest = sha256_bytes(payload)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    connection = http.client.HTTPSConnection(settings['peer_address'], settings['port'], context=context, timeout=30)
    try:
        connection.connect()
        peer_certificate = connection.sock.getpeercert(binary_form=True)
        if not peer_certificate or sha256_bytes(peer_certificate) != settings['peer_fingerprint']:
            raise RuntimeError('Peer certificate fingerprint does not match.')
        headers = {
            'Content-Type': 'application/x-yaml',
            'Content-Length': str(len(payload)),
            'X-Adguardhome-Sync-Timestamp': timestamp,
            'X-Adguardhome-Sync-Nonce': nonce,
            'X-Adguardhome-Sync-Checksum': digest,
            'X-Adguardhome-Sync-Signature': signature(settings, 'PUT', '/v1/config', timestamp, nonce, digest),
        }
        connection.request('PUT', '/v1/config', body=payload, headers=headers)
        response = connection.getresponse()
        response_body = response.read(MAX_CONFIG_BYTES).decode(errors='replace')
    except (OSError, ssl.SSLError, http.client.HTTPException) as error:
        raise RuntimeError('Unable to contact synchronization peer: ' + str(error)) from error
    finally:
        connection.close()
    try:
        outcome = json.loads(response_body)
    except json.JSONDecodeError as error:
        raise RuntimeError('Synchronization peer returned an invalid response.') from error
    if response.status != 200 or outcome.get('status') not in ('updated', 'unchanged'):
        raise RuntimeError('Synchronization was rejected: ' + str(outcome.get('message', 'unknown error')))
    return outcome['status']


class Receiver(BaseHTTPRequestHandler):
    server_version = 'AdguardhomeSync/1.0'
    nonce_lock = threading.Lock()
    nonces = {}

    def log_message(self, _format, *_args):
        return

    def respond(self, status, body):
        encoded = json.dumps(body, separators=(',', ':')).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(encoded)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(encoded)

    def authorized(self, content):
        settings = self.server.settings
        if self.client_address[0] != settings['peer_address']:
            return False, 'Peer address is not allowed.'
        timestamp = self.headers.get('X-Adguardhome-Sync-Timestamp', '')
        nonce = self.headers.get('X-Adguardhome-Sync-Nonce', '')
        digest = self.headers.get('X-Adguardhome-Sync-Checksum', '')
        supplied = self.headers.get('X-Adguardhome-Sync-Signature', '')
        try:
            received_at = int(timestamp)
        except ValueError:
            return False, 'Timestamp is invalid.'
        if abs(time.time() - received_at) > TIMESTAMP_SKEW_SECONDS:
            return False, 'Timestamp is outside the permitted window.'
        if not 16 <= len(nonce) <= 128 or digest != sha256_bytes(content):
            return False, 'Request integrity check failed.'
        expected = signature(settings, 'PUT', self.path, timestamp, nonce, digest)
        if not hmac.compare_digest(supplied, expected):
            return False, 'Request authentication failed.'
        now = time.monotonic()
        with self.nonce_lock:
            type(self).nonces = {key: expiry for key, expiry in type(self).nonces.items() if expiry > now}
            if nonce in type(self).nonces:
                return False, 'Request replay was rejected.'
            type(self).nonces[nonce] = now + NONCE_TTL_SECONDS
        return True, None

    def do_GET(self):
        if self.path != '/v1/info':
            self.respond(404, {'status': 'failed', 'message': 'Not found.'})
            return
        self.respond(200, {
            'status': 'ok',
            'certificate_fingerprint': certificate_fingerprint(),
            'listen_address': self.server.settings['listen_address'],
            'port': self.server.settings['port'],
        })

    def do_PUT(self):
        if self.path != '/v1/config':
            self.respond(404, {'status': 'failed', 'message': 'Not found.'})
            return
        try:
            length = int(self.headers.get('Content-Length', ''))
        except ValueError:
            length = 0
        if not 0 < length <= MAX_CONFIG_BYTES:
            self.respond(413, {'status': 'failed', 'message': 'Configuration size is invalid.'})
            return
        content = self.rfile.read(length)
        allowed, detail = self.authorized(content)
        if not allowed:
            self.respond(403, {'status': 'failed', 'message': detail})
            return
        try:
            outcome = acquire_lock(lambda: apply_received_config(content))
            self.respond(200, {'status': outcome})
        except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
            log(syslog.LOG_ERR, 'AdGuard Home configuration synchronization failed: ' + str(error))
            self.respond(500, {'status': 'failed', 'message': str(error)})


def apply_received_config(content):
    if not ADGUARD_CONFIG.is_file():
        raise RuntimeError('AdGuard Home configuration is unavailable.')
    with tempfile.NamedTemporaryFile(dir=ADGUARD_HOME, prefix='.AdGuardHome.yaml.', delete=False) as stream:
        stream.write(content)
        stream.flush()
        os.fchmod(stream.fileno(), 0o600)
        candidate = Path(stream.name)
    try:
        check_config(candidate)
        if sha256_file(candidate) == sha256_file(ADGUARD_CONFIG):
            return 'unchanged'
        backup = ADGUARD_CONFIG.with_name('AdGuardHome.yaml.before-sync')
        shutil.copy2(ADGUARD_CONFIG, backup)
        os.chmod(backup, 0o600)
        stopped = run('/usr/sbin/service', 'adguardhome', 'onestop', timeout=20)
        if stopped.returncode:
            detail = stopped.stderr.decode(errors='replace').strip()[-300:]
            raise RuntimeError('Unable to stop standby AdGuard Home: ' + detail)
        candidate.replace(ADGUARD_CONFIG)
        candidate = None
        started = run('/usr/sbin/service', 'adguardhome', 'onestart', timeout=30)
        status = run('/usr/sbin/service', 'adguardhome', 'status', timeout=15)
        if started.returncode or status.returncode:
            run('/usr/sbin/service', 'adguardhome', 'onestop', timeout=20)
            shutil.copy2(backup, ADGUARD_CONFIG)
            os.chmod(ADGUARD_CONFIG, 0o600)
            run('/usr/sbin/service', 'adguardhome', 'onestart', timeout=30)
            detail = (started.stderr + status.stderr).decode(errors='replace').strip()[-500:]
            raise RuntimeError('Standby AdGuard Home did not restart; previous configuration was restored: ' + detail)
        return 'updated'
    finally:
        if candidate is not None:
            candidate.unlink(missing_ok=True)


def serve(settings):
    if settings.get('role') != 'receiver':
        raise RuntimeError('This node is not a synchronization receiver.')
    ensure_certificate(settings)
    class SyncServer(ThreadingHTTPServer):
        allow_reuse_address = True

    server = SyncServer((settings['listen_address'], settings['port']), Receiver)
    server.daemon_threads = True
    server.settings = settings
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(str(CERTIFICATE_PATH))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    log(syslog.LOG_NOTICE, 'AdGuard Home synchronization receiver is listening on ' + settings['listen_address'] + ':' + str(settings['port']) + '.')
    server.serve_forever(poll_interval=1)


def watch(settings):
    if settings.get('role') != 'source':
        raise RuntimeError('This node is not the synchronization source.')
    running = True

    def stop(*_):
        nonlocal running
        running = False

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    retry_at = 0
    last_signature = None

    def attempt():
        nonlocal retry_at
        try:
            status = acquire_lock(lambda: push_once(settings))
            log(syslog.LOG_NOTICE, 'AdGuard Home configuration synchronization ' + status + '.')
            retry_at = 0
        except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
            log(syslog.LOG_ERR, 'AdGuard Home configuration synchronization failed: ' + str(error))
            retry_at = time.monotonic() + RETRY_SECONDS

    attempt()
    descriptor = os.open(str(ADGUARD_CONFIG), os.O_RDONLY | os.O_CLOEXEC)
    queue = select.kqueue()
    try:
        event = select.kevent(descriptor, filter=select.KQ_FILTER_VNODE,
                              flags=select.KQ_EV_ADD | select.KQ_EV_ENABLE | select.KQ_EV_CLEAR,
                              fflags=(select.KQ_NOTE_WRITE | select.KQ_NOTE_EXTEND | select.KQ_NOTE_ATTRIB |
                                      select.KQ_NOTE_RENAME | select.KQ_NOTE_DELETE))
        queue.control([event], 0, 0)
        while running:
            timeout = 1.0
            if retry_at:
                timeout = min(timeout, max(0, retry_at - time.monotonic()))
            events = queue.control(None, 1, timeout)
            if not running:
                break
            if not events:
                if retry_at and time.monotonic() >= retry_at:
                    attempt()
                continue
            time.sleep(0.2)
            try:
                stat = ADGUARD_CONFIG.stat()
                current_signature = (stat.st_mtime_ns, stat.st_size)
            except OSError:
                current_signature = None
            if current_signature != last_signature:
                last_signature = current_signature
                attempt()
            os.close(descriptor)
            descriptor = os.open(str(ADGUARD_CONFIG), os.O_RDONLY | os.O_CLOEXEC)
            event = select.kevent(descriptor, filter=select.KQ_FILTER_VNODE,
                                  flags=select.KQ_EV_ADD | select.KQ_EV_ENABLE | select.KQ_EV_CLEAR,
                                  fflags=(select.KQ_NOTE_WRITE | select.KQ_NOTE_EXTEND | select.KQ_NOTE_ATTRIB |
                                          select.KQ_NOTE_RENAME | select.KQ_NOTE_DELETE))
            queue.control([event], 0, 0)
    finally:
        queue.close()
        os.close(descriptor)


def status():
    settings = load_settings()
    result = {'status': 'ok', 'enabled': settings.get('enabled', False)}
    if not settings.get('enabled'):
        return result
    fingerprint = (
        settings.get('peer_fingerprint')
        if settings['role'] == 'source'
        else certificate_fingerprint()
    )
    result.update({
        'role': settings['role'],
        'listen_address': settings['listen_address'],
        'peer_address': settings['peer_address'],
        'port': settings['port'],
        'certificate_fingerprint': fingerprint,
        'secret_configured': bool(settings.get('secret')),
    })
    return result


def main():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--run', action='store_true')
    group.add_argument('--sync', action='store_true')
    group.add_argument('--status', action='store_true')
    group.add_argument('--ensure-certificate', action='store_true')
    args = parser.parse_args()
    syslog.openlog('adguardhome-sync')
    if args.status:
        print(json.dumps(status(), separators=(',', ':')))
        return
    settings = load_settings()
    if not settings.get('enabled'):
        raise RuntimeError('Synchronization is disabled.')
    if args.ensure_certificate:
        if settings['role'] != 'receiver':
            raise RuntimeError('Only the synchronization receiver has a certificate.')
        print(json.dumps({'status': 'ok', 'certificate_fingerprint': ensure_certificate(settings)}))
    elif args.sync:
        print(json.dumps({'status': acquire_lock(lambda: push_once(settings))}))
    elif args.run:
        if settings['role'] == 'source':
            watch(settings)
        else:
            serve(settings)


if __name__ == '__main__':
    try:
        main()
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        print(json.dumps({'status': 'failed', 'message': str(error)}), file=sys.stderr)
        raise SystemExit(1)
