#!/usr/local/bin/python3
"""Replicate AdGuard Home configuration over an authenticated TLS peer link."""

import argparse
import copy
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

import yaml

SCRIPT_DIRECTORY = str(Path(__file__).resolve().parent)
if SCRIPT_DIRECTORY not in sys.path:
    sys.path.insert(0, SCRIPT_DIRECTORY)

import agh_api  # noqa: E402  sibling module in the plugin script directory
import api_account  # noqa: E402  sibling module in the plugin script directory
import merge  # noqa: E402  sibling module in the plugin script directory


ADGUARD_HOME = Path('/usr/local/AdGuardHome')
ADGUARD_CONFIG = ADGUARD_HOME / 'AdGuardHome.yaml'
BACKUP_CONFIG = ADGUARD_HOME / 'AdGuardHome.yaml.before-sync'
PENDING_CONFIG = ADGUARD_HOME / 'AdGuardHome.yaml.pending'
# The last payload both nodes agreed on, kept by each role under its own name.
BASE_PATH_RECEIVER = ADGUARD_HOME / 'AdGuardHome.yaml.last-source'
BASE_PATH_SOURCE = ADGUARD_HOME / 'AdGuardHome.yaml.last-pushed'
LOCAL_CHANGES_PREFIX = 'AdGuardHome.yaml.local-changes-'
LOCAL_CHANGES_KEEP = 5
ADGUARD_BINARY = Path('/usr/local/bin/adguardhome')
MODEL_SETTINGS_PATH = Path('/usr/local/etc/adguardhome-ha/opnsense.json')
SETTINGS_PATH = Path('/usr/local/etc/adguardhome-sync.json')
STATE_PATH = Path('/usr/local/etc/adguardhome-sync.state.json')
CERTIFICATE_PATH = Path('/usr/local/etc/adguardhome-sync.pem')
LOCK_PATH = Path('/var/run/adguardhome-sync.lock')
MAX_CONFIG_BYTES = 8 * 1024 * 1024
RETRY_SECONDS = 300
RECONCILE_SECONDS = 3600
TIMESTAMP_SKEW_SECONDS = 60
NONCE_TTL_SECONDS = 600
LIVENESS_SECONDS = 15
CONVERGENCE_SECONDS = 5
ACCEPTED_STATUSES = ('updated', 'unchanged', 'hot', 'staged')
TIMESTAMP_HEADER = 'X-Adguardhome-Sync-Timestamp'
NONCE_HEADER = 'X-Adguardhome-Sync-Nonce'
CHECKSUM_HEADER = 'X-Adguardhome-Sync-Checksum'
SIGNATURE_HEADER = 'X-Adguardhome-Sync-Signature'
CARP_MASTER_HEADER = 'X-Adguardhome-Sync-Carp-Master'
REFUSED_HINT = ('check that the peer is not also configured as a synchronization source '
                '(both nodes have hasync.synchronizetoip set)')

# Process wide result of the API self-check on the receiver.  The check is
# repeated (rate limited) while it keeps failing, because AdGuard Home may still
# be starting when the receiver comes up at boot.
API_STATE = {'ready': False, 'demoted': frozenset(), 'checked_at': 0.0, 'message': None}
API_RECHECK_SECONDS = 60


class ApplyFailure(RuntimeError):
    """A received configuration could not be applied."""

    def __init__(self, message, status='failed'):
        super().__init__(message)
        self.status = status


class ApiAccountUnavailable(RuntimeError):
    """The managed API account is not installed on this node yet."""


class PeerConfigUnavailable(RuntimeError):
    """The peer did not hand out its configuration, so no merge is possible."""


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


def require_ipv4(value, name):
    try:
        address = ipaddress.ip_address(value)
    except ValueError as error:
        raise RuntimeError(name + ' is invalid.') from error
    if address.version != 4:
        raise RuntimeError(name + ' must be an IPv4 address.')
    return str(address)


def optional_text(value, name, limit):
    if value is None:
        return ''
    if not isinstance(value, str) or len(value) > limit:
        raise RuntimeError(name + ' is invalid.')
    return value


def as_boolean(value, default):
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lower() in ('1', 'true', 'yes', 'on'):
        return True
    if isinstance(value, str) and value.strip().lower() in ('0', 'false', 'no', 'off'):
        return False
    return default


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
    fingerprint = str(raw.get('peer_fingerprint') or '').lower().replace(':', '')
    if fingerprint and (len(fingerprint) != 64 or any(char not in '0123456789abcdef' for char in fingerprint)):
        raise RuntimeError('Peer certificate fingerprint is invalid.')
    raw['peer_fingerprint'] = fingerprint
    raw['api_username'] = optional_text(raw.get('api_username'), 'AdGuard Home API user name', 128)
    raw['api_password'] = optional_text(raw.get('api_password'), 'AdGuard Home API password', 256)
    if not (raw['api_username'] and raw['api_password']):
        raw['api_username'] = ''
        raw['api_password'] = ''
    raw['hot_update'] = as_boolean(raw.get('hot_update'), True)
    raw['defer_while_master'] = as_boolean(raw.get('defer_while_master'), False)
    return raw


def api_mode(settings):
    """Configured credentials are a manual override of the managed account."""
    if settings.get('api_username') and settings.get('api_password'):
        return 'manual'
    return 'managed'


def api_configured(settings):
    """Report whether this node can reach the local API at all.

    Manual credentials always qualify; the managed account is available
    whenever the API update path itself is enabled.
    """
    if not settings.get('enabled', True):
        return False
    if api_mode(settings) == 'manual':
        return True
    return as_boolean(settings.get('hot_update'), True)


def resolve_api_credentials(settings, document):
    """Return the credentials the local API expects, for this configuration.

    An instance without administrators needs none at all.  A managed account
    that is not installed yet raises, so the caller falls back to the file
    route until the account has been written and AdGuard Home restarted.
    """
    if api_mode(settings) == 'manual':
        return settings.get('api_username', ''), settings.get('api_password', '')
    state = api_account.account_state(document, settings.get('secret') or '')
    if state == 'none':
        return None, None
    if state == 'present':
        username, password, _salt = api_account.derive_credentials(settings.get('secret') or '')
        return username, password
    raise ApiAccountUnavailable(
        'The managed AdGuard Home API account is not installed ({}).'.format(state))


def managed_account_wanted(settings):
    """Report whether this node should carry the managed service account."""
    return bool(settings.get('enabled')) and api_mode(settings) == 'managed' \
        and as_boolean(settings.get('hot_update'), True)


def read_state():
    try:
        state = json.loads(STATE_PATH.read_text(encoding='utf-8'))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {}
    return state if isinstance(state, dict) else {}


def write_state(**values):
    state = read_state()
    state.update(values)
    state['updated_at'] = int(time.time())
    atomic_write(STATE_PATH, json.dumps(state, separators=(',', ':')).encode(), 0o600)
    return state


def base_path(role):
    """Return the base document this role keeps."""
    return BASE_PATH_RECEIVER if role == 'receiver' else BASE_PATH_SOURCE


def read_base(path):
    """Return the stored base document, or None while there is none."""
    if not path.is_file():
        return None
    try:
        return read_config(path)
    except RuntimeError as error:
        log(syslog.LOG_WARNING, 'The stored synchronization base is unusable: ' + str(error))
        return None


def write_base(path, content):
    """Store the payload both nodes agreed on.

    Losing the base only costs the next merge its history, so a write failure
    is reported instead of failing the synchronization.
    """
    try:
        atomic_write(path, content, 0o600)
    except OSError as error:
        log(syslog.LOG_WARNING, 'The synchronization base could not be stored: ' + str(error))


def record_result(status, digest=None, error=None):
    values = {'last_result': status, 'last_error': error}
    if digest:
        values['last_applied_sha256'] = digest
        values['last_applied_at'] = int(time.time())
    return write_state(**values)


def certificate_fingerprint():
    if not CERTIFICATE_PATH.is_file():
        return None
    result = run('/usr/bin/openssl', 'x509', '-in', str(CERTIFICATE_PATH), '-outform', 'DER', timeout=20)
    if result.returncode:
        return None
    return sha256_bytes(result.stdout)


def create_certificate(settings):
    """Generate the receiver certificate atomically while the lock is held."""
    if CERTIFICATE_PATH.is_file():
        return certificate_fingerprint()
    CERTIFICATE_PATH.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=CERTIFICATE_PATH.parent,
                                     prefix='.' + CERTIFICATE_PATH.name + '.', delete=False) as stream:
        os.fchmod(stream.fileno(), 0o600)
        candidate = Path(stream.name)
    try:
        result = run(
            '/usr/bin/openssl', 'req', '-x509', '-newkey', 'rsa:3072', '-sha256', '-nodes', '-days', '3650',
            '-subj', '/CN=adguardhome-sync',
            '-addext', 'subjectAltName=IP:' + settings['listen_address'],
            '-keyout', str(candidate), '-out', str(candidate),
            timeout=120,
        )
        if result.returncode:
            detail = (result.stderr or result.stdout).decode(errors='replace').strip()[-300:]
            raise RuntimeError('Unable to create synchronization certificate: ' + detail)
        os.chmod(candidate, 0o600)
        os.replace(candidate, CERTIFICATE_PATH)
        candidate = None
    finally:
        if candidate is not None:
            candidate.unlink(missing_ok=True)
    fingerprint = certificate_fingerprint()
    if fingerprint is None:
        raise RuntimeError('Unable to read synchronization certificate.')
    return fingerprint


def ensure_certificate(settings):
    if CERTIFICATE_PATH.is_file():
        return certificate_fingerprint()
    return acquire_lock(lambda: create_certificate(settings))


def binary_path():
    if ADGUARD_BINARY.is_file() and os.access(ADGUARD_BINARY, os.X_OK):
        return ADGUARD_BINARY
    raise RuntimeError('AdGuard Home is not installed.')


def check_config(path):
    result = run(str(binary_path()), '--config', str(path), '--check-config', timeout=20)
    if result.returncode:
        detail = (result.stderr or result.stdout).decode(errors='replace').strip()[-500:]
        raise RuntimeError('AdGuard Home configuration validation failed: ' + detail)


def read_config(path):
    try:
        document = yaml.safe_load(path.read_text(encoding='utf-8'))
    except (OSError, UnicodeError, yaml.YAMLError) as error:
        raise RuntimeError('AdGuard Home configuration cannot be read.') from error
    if not isinstance(document, dict):
        raise RuntimeError('AdGuard Home configuration is not a mapping.')
    return document


def parse_config(content):
    try:
        document = yaml.safe_load(content.decode('utf-8'))
    except (UnicodeError, yaml.YAMLError) as error:
        raise RuntimeError('The received configuration cannot be parsed.') from error
    if not isinstance(document, dict):
        raise RuntimeError('The received configuration is not a mapping.')
    return document


def source_payload():
    if not ADGUARD_CONFIG.is_file():
        raise RuntimeError('AdGuard Home configuration is unavailable.')
    size = ADGUARD_CONFIG.stat().st_size
    if not 0 < size <= MAX_CONFIG_BYTES:
        raise RuntimeError('AdGuard Home configuration size is invalid.')
    check_config(ADGUARD_CONFIG)
    return ADGUARD_CONFIG.read_bytes()


LOCK_WAIT_SECONDS = 120


def acquire_lock(action, wait=0.0):
    """Run action under the synchronization lock.

    Interactive callers fail immediately when another synchronization runs;
    the daemon and the CARP hook pass a wait so that overlapping work (for
    example an account installation during a service restart) is serialized
    instead of being reported as a failure.
    """
    LOCK_PATH.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    deadline = time.monotonic() + wait
    with LOCK_PATH.open('w') as stream:
        while True:
            try:
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError as error:
                if time.monotonic() >= deadline:
                    raise RuntimeError('Another synchronization is already running.') from error
                time.sleep(0.5)
        return action()


def signature(settings, method, path, timestamp, nonce, digest):
    message = '\n'.join((method, path, timestamp, nonce, digest)).encode()
    return hmac.new(settings['secret'].encode(), message, hashlib.sha256).hexdigest()


def info_signature(settings, fingerprint, timestamp, nonce):
    message = '\n'.join((fingerprint, timestamp, nonce)).encode()
    return hmac.new(settings['secret'].encode(), message, hashlib.sha256).hexdigest()


def request_headers(settings, method, path, digest):
    timestamp = str(int(time.time()))
    nonce = secrets.token_urlsafe(24)
    headers = {
        TIMESTAMP_HEADER: timestamp,
        NONCE_HEADER: nonce,
        CHECKSUM_HEADER: digest,
        SIGNATURE_HEADER: signature(settings, method, path, timestamp, nonce, digest),
    }
    return headers, timestamp, nonce


def peer_connection(settings):
    """Open a TLS connection to the peer and report its certificate fingerprint."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    connection = http.client.HTTPSConnection(settings['peer_address'], settings['port'],
                                             context=context, timeout=30)
    try:
        connection.connect()
        certificate = connection.sock.getpeercert(binary_form=True)
    except ConnectionRefusedError as error:
        connection.close()
        raise RuntimeError('Unable to contact synchronization peer: {}; {}.'.format(error, REFUSED_HINT)) from error
    except (OSError, ssl.SSLError, http.client.HTTPException) as error:
        connection.close()
        raise RuntimeError('Unable to contact synchronization peer: ' + str(error)) from error
    if not certificate:
        connection.close()
        raise RuntimeError('The synchronization peer did not present a certificate.')
    return connection, sha256_bytes(certificate)


def peer_response(connection):
    try:
        response = connection.getresponse()
        body = response.read(MAX_CONFIG_BYTES).decode(errors='replace')
    except (OSError, ssl.SSLError, http.client.HTTPException) as error:
        raise RuntimeError('Unable to contact synchronization peer: ' + str(error)) from error
    try:
        outcome = json.loads(body)
    except json.JSONDecodeError as error:
        raise RuntimeError('Synchronization peer returned an invalid response.') from error
    if not isinstance(outcome, dict):
        raise RuntimeError('Synchronization peer returned an invalid response.')
    return response.status, outcome


def learn_fingerprint(settings):
    """Discover the peer certificate fingerprint and verify it with the shared secret."""
    connection, observed = peer_connection(settings)
    digest = sha256_bytes(b'')
    headers, timestamp, nonce = request_headers(settings, 'GET', '/v1/info', digest)
    try:
        connection.request('GET', '/v1/info', headers=headers)
        status, outcome = peer_response(connection)
    except (OSError, ssl.SSLError, http.client.HTTPException) as error:
        raise RuntimeError('Unable to contact synchronization peer: ' + str(error)) from error
    finally:
        connection.close()
    if status != 200:
        raise RuntimeError('The synchronization peer rejected the identity request: '
                           + str(outcome.get('message', 'unknown error')))
    reported = str(outcome.get('certificate_fingerprint') or '').lower()
    expected = info_signature(settings, reported, timestamp, nonce)
    if not hmac.compare_digest(str(outcome.get('info_signature', '')), expected):
        raise RuntimeError('The synchronization peer identity could not be verified with the pairing secret.')
    if reported != observed:
        raise RuntimeError('The synchronization peer reported a certificate it does not use.')
    write_state(learned_fingerprint=observed)
    log(syslog.LOG_NOTICE, 'Learned the synchronization peer certificate fingerprint ' + observed + '.')
    return observed


def pinned_fingerprint(settings):
    """A configured fingerprint always wins over a previously learned one."""
    configured = settings.get('peer_fingerprint') or ''
    if configured:
        return configured, True
    learned = str(read_state().get('learned_fingerprint') or '')
    return learned, False


def fetch_peer_config(settings, expected):
    """Read the receiver's running configuration for a three-way merge.

    The request is authenticated exactly like /v1/info.  Anything that keeps
    the configuration from arriving intact raises PeerConfigUnavailable, so the
    caller can push without a merge instead of failing the synchronization.
    """
    connection, observed = peer_connection(settings)
    digest = sha256_bytes(b'')
    headers, _timestamp, _nonce = request_headers(settings, 'GET', '/v1/config', digest)
    try:
        if observed != expected:
            raise PeerConfigUnavailable('The peer presented an unexpected certificate.')
        connection.request('GET', '/v1/config', headers=headers)
        response = connection.getresponse()
        status = response.status
        reported = response.headers.get(CHECKSUM_HEADER, '')
        master = response.headers.get(CARP_MASTER_HEADER)
        body = response.read(MAX_CONFIG_BYTES + 1)
    except (OSError, ssl.SSLError, http.client.HTTPException) as error:
        raise PeerConfigUnavailable('Unable to read the peer configuration: ' + str(error)) from error
    finally:
        connection.close()
    if status == 404:
        raise PeerConfigUnavailable('The synchronization peer does not offer its configuration.')
    if status != 200:
        raise PeerConfigUnavailable('The peer refused the configuration request: HTTP ' + str(status) + '.')
    if not 0 < len(body) <= MAX_CONFIG_BYTES:
        raise PeerConfigUnavailable('The peer configuration size is invalid.')
    if reported != sha256_bytes(body):
        raise PeerConfigUnavailable('The peer configuration checksum does not match.')
    try:
        document = parse_config(body)
    except RuntimeError as error:
        raise PeerConfigUnavailable(str(error)) from error
    return document, (True if master == '1' else False if master == '0' else None)


def source_is_master(document):
    """Report whether this source node currently serves DNS itself.

    A conflict is decided in favour of the node whose AdGuard Home answers
    clients.  A source whose bind hosts carry no CARP address at all can never
    lose that role, so it stays the authority and keeps winning as before.
    """
    command = run('/sbin/ifconfig', '-a', timeout=15)
    if command.returncode:
        return True
    hosts = {str(host) for host in agh_api.value_or(document, 'dns.bind_hosts', []) or []}
    if not hosts & parse_carp_addresses(command.stdout.decode(errors='replace')):
        return True
    return carp_master(document)


def merge_with_peer(settings, payload, expected):
    """Adopt the changes the receiver made on its own before pushing.

    Returns the payload to push and whether the merged configuration was only
    staged, in which case the push waits until this node installs it.
    """
    try:
        peer_document, peer_master = fetch_peer_config(settings, expected)
    except PeerConfigUnavailable as error:
        log(syslog.LOG_NOTICE, 'The receiver configuration was not read; pushing without a merge: ' + str(error))
        write_state(peer_carp_master=None)
        return payload, False
    write_state(peer_carp_master=peer_master)
    ours = parse_config(payload)
    merged, adopted, conflicts = merge.three_way(read_base(BASE_PATH_SOURCE), ours, peer_document,
                                                 source_is_master(ours))
    taken = sorted(path for path, (_ours, _theirs, winner) in conflicts.items() if winner == 'receiver')
    if conflicts:
        keys = sorted(conflicts)
        write_state(last_conflict={'at': int(time.time()), 'keys': keys,
                                   'winner': 'receiver' if taken else 'source'})
        log(syslog.LOG_WARNING, 'Both nodes changed {}; the {} value wins.'.format(
            ', '.join(keys[:20]), 'receiver' if taken else 'source'))
    if adopted:
        write_state(last_adopted={'at': int(time.time()), 'keys': adopted})
        log(syslog.LOG_NOTICE, 'Adopting the receiver changes to ' + ', '.join(adopted[:20]) + '.')
    if not (adopted or taken):
        return payload, False
    outcome = apply_document(merged, settings)
    if outcome == 'staged':
        log(syslog.LOG_NOTICE, 'The adopted configuration was staged until this node leaves the CARP master '
                               'role; it is pushed once it is installed.')
        return payload, True
    log(syslog.LOG_NOTICE, 'The receiver changes were adopted on the source (' + outcome + ').')
    return source_payload(), False


def push_once(settings):
    if settings.get('role') != 'source':
        raise RuntimeError('This node is not the synchronization source.')
    payload = source_payload()
    expected, configured = pinned_fingerprint(settings)
    if not expected:
        expected = learn_fingerprint(settings)
    payload, staged = merge_with_peer(settings, payload, expected)
    if staged:
        return 'staged'
    digest = sha256_bytes(payload)
    headers, _timestamp, _nonce = request_headers(settings, 'PUT', '/v1/config', digest)
    headers.update({'Content-Type': 'application/x-yaml', 'Content-Length': str(len(payload))})
    connection, observed = peer_connection(settings)
    try:
        if observed != expected:
            detail = ('Peer certificate fingerprint does not match the configured value.' if configured
                      else 'The synchronization peer presented a certificate that differs from the learned one; '
                           'clear the learned fingerprint only after confirming the peer was reinstalled.')
            log(syslog.LOG_ERR, detail + ' Presented ' + observed + ', expected ' + expected + '.')
            raise RuntimeError(detail)
        connection.request('PUT', '/v1/config', body=payload, headers=headers)
        status, outcome = peer_response(connection)
    except (OSError, ssl.SSLError, http.client.HTTPException) as error:
        raise RuntimeError('Unable to contact synchronization peer: ' + str(error)) from error
    finally:
        connection.close()
    if status != 200 or outcome.get('status') not in ACCEPTED_STATUSES:
        detail = outcome.get('message', outcome.get('status', 'unknown error'))
        raise RuntimeError('Synchronization was rejected: ' + str(detail))
    record_result(outcome['status'])
    if outcome['status'] != 'staged':
        # A staged payload is not in effect on the receiver yet, so it is not
        # the document both nodes agreed on: keeping the older base stops the
        # next merge from adopting the configuration the receiver still runs.
        write_base(BASE_PATH_SOURCE, payload)
    return outcome['status']


class SyncServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True
    settings = {}

    def verify_request(self, request, client_address):
        """Drop connections from anything but the peer before reading any bytes."""
        allowed = self.settings.get('peer_address')
        if allowed and client_address[0] != allowed:
            log(syslog.LOG_WARNING, 'Rejected a synchronization connection from ' + str(client_address[0]) + '.')
            return False
        return True


class Receiver(BaseHTTPRequestHandler):
    server_version = 'AdguardhomeSync/1.0'
    timeout = 30
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

    def authorized(self, method, content):
        settings = self.server.settings
        if self.client_address[0] != settings['peer_address']:
            return False, 'Peer address is not allowed.'
        timestamp = self.headers.get(TIMESTAMP_HEADER, '')
        nonce = self.headers.get(NONCE_HEADER, '')
        digest = self.headers.get(CHECKSUM_HEADER, '')
        supplied = self.headers.get(SIGNATURE_HEADER, '')
        try:
            received_at = int(timestamp)
        except ValueError:
            return False, 'Timestamp is invalid.'
        if abs(time.time() - received_at) > TIMESTAMP_SKEW_SECONDS:
            return False, 'Timestamp is outside the permitted window.'
        if not 16 <= len(nonce) <= 128 or digest != sha256_bytes(content):
            return False, 'Request integrity check failed.'
        expected = signature(settings, method, self.path, timestamp, nonce, digest)
        if not hmac.compare_digest(supplied, expected):
            return False, 'Request authentication failed.'
        now = time.monotonic()
        with self.nonce_lock:
            type(self).nonces = {key: expiry for key, expiry in type(self).nonces.items() if expiry > now}
            if nonce in type(self).nonces:
                return False, 'Request replay was rejected.'
            type(self).nonces[nonce] = now + NONCE_TTL_SECONDS
        return True, None

    def send_config(self):
        """Hand the running configuration to the source for a three-way merge.

        The source needs it to tell a local change on this node apart from a
        stale copy; it is the same document the source pushes here, so it is
        authenticated exactly like every other request and nothing else.
        """
        allowed, detail = self.authorized('GET', b'')
        if not allowed:
            self.respond(403, {'status': 'failed', 'message': detail})
            return
        try:
            payload = ADGUARD_CONFIG.read_bytes()
        except OSError:
            self.respond(500, {'status': 'failed', 'message': 'AdGuard Home configuration is unavailable.'})
            return
        if not 0 < len(payload) <= MAX_CONFIG_BYTES:
            self.respond(500, {'status': 'failed', 'message': 'AdGuard Home configuration size is invalid.'})
            return
        try:
            master = carp_master(parse_config(payload))
        except (OSError, RuntimeError, subprocess.TimeoutExpired):
            master = False
        self.send_response(200)
        self.send_header('Content-Type', 'application/x-yaml')
        self.send_header('Content-Length', str(len(payload)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header(CHECKSUM_HEADER, sha256_bytes(payload))
        self.send_header(CARP_MASTER_HEADER, '1' if master else '0')
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        if self.path == '/v1/config':
            self.send_config()
            return
        if self.path != '/v1/info':
            self.respond(404, {'status': 'failed', 'message': 'Not found.'})
            return
        allowed, detail = self.authorized('GET', b'')
        if not allowed:
            self.respond(403, {'status': 'failed', 'message': detail})
            return
        fingerprint = certificate_fingerprint() or ''
        timestamp = self.headers.get(TIMESTAMP_HEADER, '')
        nonce = self.headers.get(NONCE_HEADER, '')
        self.respond(200, {
            'status': 'ok',
            'certificate_fingerprint': fingerprint,
            'listen_address': self.server.settings['listen_address'],
            'port': self.server.settings['port'],
            'info_signature': info_signature(self.server.settings, fingerprint, timestamp, nonce),
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
        if len(content) != length:
            self.respond(400, {'status': 'failed', 'message': 'The request body is incomplete.'})
            return
        allowed, detail = self.authorized('PUT', content)
        if not allowed:
            self.respond(403, {'status': 'failed', 'message': detail})
            return
        try:
            outcome = acquire_lock(lambda: apply_received_config(content, self.server.settings))
            self.respond(200, {'status': outcome})
        except ApplyFailure as error:
            log(syslog.LOG_ERR, 'AdGuard Home configuration synchronization failed: ' + str(error))
            record_result(error.status, error=str(error))
            self.respond(500, {'status': error.status, 'message': str(error)})
        except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
            log(syslog.LOG_ERR, 'AdGuard Home configuration synchronization failed: ' + str(error))
            record_result('failed', error=str(error))
            self.respond(500, {'status': 'failed', 'message': str(error)})


def build_api(configuration, settings):
    username, password = resolve_api_credentials(settings, configuration)
    return agh_api.AdGuardApi(agh_api.api_base_url(configuration), username, password)


def startup_api_check(settings):
    """Confirm the local API exposes every mapped field before trusting it."""
    API_STATE.update({'ready': False, 'demoted': frozenset(), 'checked_at': time.monotonic(), 'message': None})
    if not api_configured(settings):
        log(syslog.LOG_NOTICE, 'The AdGuard Home API path is disabled; updates replace the file.')
        return
    try:
        configuration = read_config(ADGUARD_CONFIG)
        reachable, reason = local_api_reachable(configuration)
        if not reachable:
            API_STATE['message'] = reason
            log(syslog.LOG_WARNING, 'AdGuard Home API is unusable; updates replace the file: ' + reason)
            return
        api = build_api(configuration, settings)
        api('GET', '/status')
        demoted, warnings = agh_api.self_check(api)
    except ApiAccountUnavailable as error:
        API_STATE['message'] = str(error)
        log(syslog.LOG_NOTICE, str(error) + ' Updates replace the file until it is installed.')
        return
    except (OSError, RuntimeError, ValueError) as error:
        API_STATE['message'] = str(error)
        log(syslog.LOG_WARNING, 'AdGuard Home API self-check failed; updates replace the file: ' + str(error))
        return
    for warning in warnings:
        log(syslog.LOG_WARNING, 'AdGuard Home API self-check: ' + warning)
    API_STATE.update({'ready': True, 'demoted': frozenset(demoted)})
    log(syslog.LOG_NOTICE, 'AdGuard Home API self-check passed; {} key(s) require a file update.'.format(len(demoted)))


def hot_update_allowed(settings, plan, current=None):
    if not (as_boolean(settings.get('hot_update'), True) and api_configured(settings)):
        return False
    # CARP ownership can change at any time: a web interface bound to the
    # virtual address is local only while this node is master.  Re-evaluate on
    # every apply instead of trusting the state from the last self-check.
    if current is not None:
        reachable, reason = local_api_reachable(current)
        if not reachable:
            if API_STATE['ready']:
                log(syslog.LOG_NOTICE, 'AdGuard Home API is no longer local; updates replace the file: ' + reason)
            API_STATE.update({'ready': False, 'message': reason})
            return False
        if not API_STATE['ready'] and API_STATE.get('message') and API_STATE['message'].startswith(
                'The AdGuard Home web interface listens on the CARP address'):
            API_STATE['checked_at'] = 0.0  # became master: re-check right away
    if not API_STATE['ready'] and time.monotonic() - API_STATE['checked_at'] >= API_RECHECK_SECONDS:
        startup_api_check(settings)
    return API_STATE['ready'] and not plan['file']


def wait_for_convergence(source, timeout=None):
    """AdGuard Home rewrites its YAML after each API write; wait for that copy."""
    deadline = time.monotonic() + (CONVERGENCE_SECONDS if timeout is None else timeout)
    while True:
        try:
            remaining = agh_api.divergent(source, read_config(ADGUARD_CONFIG))
        except RuntimeError as error:
            return [str(error)]
        if not remaining or time.monotonic() >= deadline:
            return remaining
        time.sleep(0.5)


def apply_through_api(source, current, settings, plan):
    try:
        agh_api.apply(source, current, build_api(current, settings), plan)
    except (agh_api.ApiError, OSError, RuntimeError, ValueError) as error:
        log(syslog.LOG_WARNING, 'AdGuard Home hot update failed: ' + str(error))
        return False
    remaining = wait_for_convergence(source)
    if remaining:
        log(syslog.LOG_WARNING, 'AdGuard Home hot update did not converge for keys: ' + ', '.join(remaining[:20]))
        return False
    log(syslog.LOG_NOTICE, 'AdGuard Home configuration was updated through the API without an interruption.')
    return True


def candidate_document(source, current, settings=None):
    """Overlay the receiver node-local keys onto the received configuration."""
    document = copy.deepcopy(source)
    for path in agh_api.LOCAL_KEYS:
        value = agh_api.lookup(current, path)
        if value is agh_api.MISSING:
            agh_api.remove(document, path)
        else:
            agh_api.assign(document, path, copy.deepcopy(value))
    # A file replacement must not drop the managed service account.  The entry
    # is invisible to the difference, so re-adding it never causes a diff.
    settings = settings if isinstance(settings, dict) else {}
    if managed_account_wanted(settings) and api_account.users_of(current):
        document = api_account.ensure_account(document, settings.get('secret') or '')[0]
    return document


def write_candidate(content):
    with tempfile.NamedTemporaryFile(dir=ADGUARD_HOME, prefix='.AdGuardHome.yaml.', delete=False) as stream:
        stream.write(content)
        stream.flush()
        os.fchmod(stream.fileno(), 0o600)
        return Path(stream.name)


def plugin_enabled():
    """Report whether the plugin keeps AdGuard Home running on this node."""
    try:
        document = json.loads(MODEL_SETTINGS_PATH.read_text(encoding='utf-8'))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return True
    general = document.get('general') if isinstance(document, dict) else None
    if not isinstance(general, dict) or 'enabled' not in general:
        return True
    return general.get('enabled') is True


def listen_targets(document):
    hosts = agh_api.value_or(document, 'dns.bind_hosts', []) or []
    try:
        port = int(agh_api.value_or(document, 'dns.port', 53))
    except (TypeError, ValueError):
        return []
    return [(str(host), port) for host in hosts]


def tcp_reachable(target, timeout=2):
    try:
        with socket.create_connection(target, timeout=timeout):
            return True
    except OSError:
        return False


def served_targets(targets):
    """Return the targets this host itself is listening on.

    The bind addresses are usually CARP virtual addresses, which cannot be
    probed with a TCP connection from the backup node; inspect the local
    sockets instead and fall back to connecting only where sockstat is missing.
    """
    if not targets:
        return []
    listeners = agh_api.local_listeners(targets[0][1])
    if listeners is None:
        return [target for target in targets if tcp_reachable((agh_api.loopback(target[0]), target[1]))]
    return [target for target in targets if agh_api.host_served(target[0], listeners)]


def wait_for_listeners(targets, expected=True, timeout=None):
    """Wait for the DNS listeners to appear or disappear on this host."""
    deadline = time.monotonic() + (LIVENESS_SECONDS if timeout is None else timeout)
    while True:
        served = served_targets(targets)
        if (len(served) == len(targets)) if expected else not served:
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.5)


def stop_service(targets):
    result = run('/usr/sbin/service', 'adguardhome', 'onestop', timeout=20)
    if wait_for_listeners(targets, expected=False, timeout=10):
        return
    detail = (result.stderr or result.stdout).decode(errors='replace').strip()[-300:]
    raise RuntimeError('Unable to stop standby AdGuard Home: ' + detail)


def start_service():
    return run('/usr/sbin/service', 'adguardhome', 'onestart', timeout=30)


def restore_backup(targets):
    """Put the previous configuration back and report whether DNS recovered."""
    run('/usr/sbin/service', 'adguardhome', 'onestop', timeout=20)
    shutil.copy2(BACKUP_CONFIG, ADGUARD_CONFIG)
    os.chmod(ADGUARD_CONFIG, 0o600)
    start_service()
    return wait_for_listeners(targets)


def install_candidate(candidate, document):
    """Replace the active configuration and confirm DNS still answers."""
    targets = listen_targets(document)
    if not plugin_enabled():
        candidate.replace(ADGUARD_CONFIG)
        os.chmod(ADGUARD_CONFIG, 0o600)
        log(syslog.LOG_NOTICE, 'AdGuard Home configuration was replaced while the service is disabled.')
        return
    stop_service(targets)
    candidate.replace(ADGUARD_CONFIG)
    os.chmod(ADGUARD_CONFIG, 0o600)
    started = start_service()
    if wait_for_listeners(targets):
        return
    detail = (started.stderr or started.stdout).decode(errors='replace').strip()[-300:]
    log(syslog.LOG_ERR, 'Standby AdGuard Home did not answer after the update: ' + detail)
    if restore_backup(targets):
        raise ApplyFailure('Standby AdGuard Home did not restart; previous configuration was restored: ' + detail)
    log(syslog.LOG_CRIT, 'Standby AdGuard Home did not answer with the restored configuration either.')
    raise ApplyFailure('Standby AdGuard Home did not restart and the restored configuration did not recover: '
                       + detail, status='failed_unrecoverable')


def install_document(document):
    """Validate, back up and install a locally built configuration."""
    candidate = write_candidate(yaml.safe_dump(document, sort_keys=False, allow_unicode=True).encode())
    try:
        check_config(candidate)
        shutil.copy2(ADGUARD_CONFIG, BACKUP_CONFIG)
        os.chmod(BACKUP_CONFIG, 0o600)
        install_candidate(candidate, document)
        candidate = None
    finally:
        if candidate is not None:
            candidate.unlink(missing_ok=True)


def ensure_api_account(settings, only_when_backup=False):
    """Install or withdraw the managed API account on this node.

    AdGuard Home has no API to change its administrators, so the account is
    written into AdGuardHome.yaml and the service is restarted once.  Both
    roles carry it: the receiver applies what the source pushes through its own
    API, and the source applies what it adopts from the receiver the same way.

    With only_when_backup the restart is deferred while this node owns the DNS
    CARP address, so the account is installed automatically the next time the
    node serves no clients; an explicit apply passes False and restarts anyway.
    """
    result = {'status': 'unchanged', 'api_mode': api_mode(settings)}
    if not ADGUARD_CONFIG.is_file():
        return result
    document = read_config(ADGUARD_CONFIG)
    if only_when_backup and carp_master(document):
        state = (api_account.account_state(document, settings.get('secret') or '')
                 if managed_account_wanted(settings) else 'manual')
        result['api_account_state'] = state
        needs_change = (state in ('missing', 'stale')) if managed_account_wanted(settings) \
            else api_account.managed_index(api_account.users_of(document)) >= 0
        if needs_change:
            result['status'] = 'deferred'
            log(syslog.LOG_NOTICE, 'The managed AdGuard Home API account change waits until this node '
                                   'leaves the CARP master role.')
        return result
    if managed_account_wanted(settings):
        state = api_account.account_state(document, settings.get('secret') or '')
        result['api_account_state'] = state
        if state in ('present', 'none'):
            return result
        updated, changed = api_account.ensure_account(document, settings.get('secret') or '')
        outcome = 'updated'
    else:
        updated, changed = api_account.remove_account(document)
        outcome = 'removed'
    if not changed:
        return result
    install_document(updated)
    log(syslog.LOG_NOTICE, 'The managed AdGuard Home API account was ' + outcome + '.')
    result['status'] = outcome
    if outcome == 'updated':
        result['api_account_state'] = 'present'
    return result


def parse_carp_addresses(text):
    """Collect every local address that belongs to a CARP virtual host."""
    addresses = set()
    for line in text.splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[0] in ('inet', 'inet6') and 'vhid' in fields:
            addresses.add(fields[1].split('%', 1)[0])
    return addresses


def api_locally_reachable(document, carp_addresses, carp_masters):
    """Report whether this node can reach its own web interface.

    A CARP virtual address is only delivered locally while this node is the
    master; on the backup a connection to it ends up at the peer's AdGuard
    Home, which makes the hot update path unusable and trips the peer's login
    limiter.  Returns (reachable, message).
    """
    host, _port = agh_api.host_and_port(agh_api.value_or(document, 'http.address', ''))
    host = host.strip('[]').split('%', 1)[0]
    if host in ('', '0.0.0.0', '::', '127.0.0.1', '::1') or host not in carp_addresses:
        return True, None
    if host in carp_masters:
        return True, None
    return False, ('The AdGuard Home web interface listens on the CARP address {}, which this node only '
                   'reaches while it is CARP master. Hot updates apply while master; as backup, changes '
                   'replace the file and restart AdGuard Home, which serves no clients then.'.format(host))


def local_api_reachable(document):
    command = run('/sbin/ifconfig', '-a', timeout=15)
    if command.returncode:
        return True, None
    text = command.stdout.decode(errors='replace')
    return api_locally_reachable(document, parse_carp_addresses(text), parse_carp_master_addresses(text))


def parse_carp_master_addresses(text):
    """Collect the local addresses whose CARP virtual host is currently master."""
    masters = set()
    addresses = {}
    virtual_hosts = set()

    def flush():
        masters.update(address for address, vhid in addresses.items() if vhid in virtual_hosts)
        addresses.clear()
        virtual_hosts.clear()

    for line in text.splitlines():
        if line and not line[0].isspace():
            flush()
            continue
        fields = line.split()
        if len(fields) >= 2 and fields[0] in ('inet', 'inet6') and 'vhid' in fields:
            index = fields.index('vhid') + 1
            if index < len(fields):
                addresses[fields[1].split('%', 1)[0]] = fields[index]
        elif len(fields) >= 4 and fields[0] == 'carp:' and fields[1] == 'MASTER' and fields[2] == 'vhid':
            virtual_hosts.add(fields[3])
    flush()
    return masters


def carp_master(document):
    command = run('/sbin/ifconfig', '-a', timeout=15)
    if command.returncode:
        return False
    masters = parse_carp_master_addresses(command.stdout.decode(errors='replace'))
    hosts = {str(host) for host in agh_api.value_or(document, 'dns.bind_hosts', []) or []}
    return bool(hosts & masters)


def apply_file_route(source, current, settings, digest, defer=True):
    """Validate, back up and install the received configuration as a file."""
    document = candidate_document(source, current, settings)
    candidate = write_candidate(yaml.safe_dump(document, sort_keys=False, allow_unicode=True).encode())
    try:
        check_config(candidate)
        shutil.copy2(ADGUARD_CONFIG, BACKUP_CONFIG)
        os.chmod(BACKUP_CONFIG, 0o600)
        if defer and as_boolean(settings.get('defer_while_master'), False) and carp_master(current):
            candidate.replace(PENDING_CONFIG)
            os.chmod(PENDING_CONFIG, 0o600)
            candidate = None
            write_state(last_result='staged', last_error=None, pending_sha256=digest)
            log(syslog.LOG_NOTICE, 'AdGuard Home configuration was staged until this node leaves the CARP master role.')
            return 'staged'
        install_candidate(candidate, document)
        candidate = None
        record_result('updated', digest=digest)
        return 'updated'
    finally:
        if candidate is not None:
            candidate.unlink(missing_ok=True)


def prune_local_changes(keep=LOCAL_CHANGES_KEEP):
    """Keep only the newest copies of overwritten local configurations."""
    existing = sorted(ADGUARD_HOME.glob(LOCAL_CHANGES_PREFIX + '*'))
    for path in existing[:-keep] if keep else existing:
        path.unlink(missing_ok=True)


def keep_local_changes():
    """Copy the running configuration aside before the source replaces it."""
    path = ADGUARD_HOME / (LOCAL_CHANGES_PREFIX + time.strftime('%Y%m%d-%H%M%S'))
    shutil.copy2(ADGUARD_CONFIG, path)
    os.chmod(path, 0o600)
    prune_local_changes()
    return path


def protect_local_changes(source, current):
    """Preserve the local changes the received configuration is about to undo.

    A source of this version has merged them already, but an older one, or an
    edit made between its merge and this push, is only visible here.  Nothing
    is refused: the source stays authoritative, the previous file is kept.
    """
    base = read_base(BASE_PATH_RECEIVER)
    if base is None:
        return []
    overwritten = merge.differing(merge.drift(base, current), current, source)
    if not overwritten:
        return []
    try:
        backup = str(keep_local_changes())
    except OSError as error:
        log(syslog.LOG_WARNING, 'The local AdGuard Home configuration could not be copied aside: ' + str(error))
        backup = None
    write_state(last_overwritten={'at': int(time.time()), 'keys': overwritten, 'backup': backup})
    log(syslog.LOG_WARNING, 'The received configuration overwrites local changes to '
        + ', '.join(overwritten[:20]) + '; the previous file was kept as ' + str(backup) + '.')
    return overwritten


def apply_document(target_document, settings, *, defer=True, digest=None):
    """Adopt a document on this node, through the local API where possible.

    Both roles use this: the receiver for a payload from the source and the
    source for the result of a merge with the receiver.  Returns 'unchanged',
    'hot', 'updated' or 'staged'.
    """
    settings = settings if isinstance(settings, dict) else {}
    current = read_config(ADGUARD_CONFIG)
    _difference, plan = agh_api.classify(target_document, current, API_STATE['demoted'])
    if not (plan['hot'] or plan['reconf'] or plan['file']):
        return 'unchanged'
    if hot_update_allowed(settings, plan, current) and apply_through_api(target_document, current, settings, plan):
        return 'hot'
    return apply_file_route(target_document, current, settings, digest, defer=defer)


def apply_received_config(content, settings=None):
    """Decide how to adopt a received configuration and apply it."""
    settings = settings if isinstance(settings, dict) else {}
    if not ADGUARD_CONFIG.is_file():
        raise RuntimeError('AdGuard Home configuration is unavailable.')
    digest = sha256_bytes(content)
    if digest == read_state().get('last_applied_sha256'):
        # An upgraded node has a recorded digest but no base document yet.
        if not BASE_PATH_RECEIVER.is_file():
            write_base(BASE_PATH_RECEIVER, content)
        return 'unchanged'
    source = parse_config(content)
    protect_local_changes(source, read_config(ADGUARD_CONFIG))
    outcome = apply_document(source, settings, digest=digest)
    if outcome in ('unchanged', 'hot'):
        record_result(outcome, digest=digest)
    if outcome != 'staged':
        write_base(BASE_PATH_RECEIVER, content)
    return outcome


def apply_pending(settings):
    """Install a configuration that was staged while this node was CARP master."""
    if not PENDING_CONFIG.is_file():
        return 'unchanged'
    content = PENDING_CONFIG.read_bytes()
    source = parse_config(content)
    current = read_config(ADGUARD_CONFIG)
    outcome = apply_file_route(source, current, settings, sha256_bytes(content), defer=False)
    PENDING_CONFIG.unlink(missing_ok=True)
    write_state(pending_sha256=None)
    if settings.get('role') == 'receiver':
        write_base(BASE_PATH_RECEIVER, content)
    return outcome


def serve(settings):
    if settings.get('role') != 'receiver':
        raise RuntimeError('This node is not a synchronization receiver.')
    ensure_certificate(settings)
    startup_api_check(settings)
    server = SyncServer((settings['listen_address'], settings['port']), Receiver)
    server.settings = settings
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(str(CERTIFICATE_PATH))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    log(syslog.LOG_NOTICE, 'AdGuard Home synchronization receiver is listening on '
        + settings['listen_address'] + ':' + str(settings['port']) + '.')
    server.serve_forever(poll_interval=1)


def watch_event(descriptor):
    return select.kevent(descriptor, filter=select.KQ_FILTER_VNODE,
                         flags=select.KQ_EV_ADD | select.KQ_EV_ENABLE | select.KQ_EV_CLEAR,
                         fflags=(select.KQ_NOTE_WRITE | select.KQ_NOTE_EXTEND | select.KQ_NOTE_ATTRIB |
                                 select.KQ_NOTE_RENAME | select.KQ_NOTE_DELETE))


def close_descriptor(descriptor):
    if descriptor >= 0:
        try:
            os.close(descriptor)
        except OSError:
            pass
    return -1


def register_watch(queue, descriptor):
    """Reopen the configuration file and watch it again, tolerating removal."""
    descriptor = close_descriptor(descriptor)
    try:
        descriptor = os.open(str(ADGUARD_CONFIG), os.O_RDONLY | os.O_CLOEXEC)
        queue.control([watch_event(descriptor)], 0, 0)
    except OSError as error:
        log(syslog.LOG_WARNING, 'Unable to watch the AdGuard Home configuration: ' + str(error))
        return close_descriptor(descriptor)
    return descriptor


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
    last_attempt = 0.0
    last_signature = None

    def attempt():
        nonlocal retry_at, last_attempt
        last_attempt = time.monotonic()
        try:
            status = acquire_lock(lambda: push_once(settings), wait=LOCK_WAIT_SECONDS)
            log(syslog.LOG_NOTICE, 'AdGuard Home configuration synchronization ' + status + '.')
            retry_at = 0
        except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
            log(syslog.LOG_ERR, 'AdGuard Home configuration synchronization failed: ' + str(error))
            write_state(last_result='failed', last_error=str(error))
            retry_at = time.monotonic() + RETRY_SECONDS

    attempt()
    descriptor = -1
    queue = select.kqueue()
    try:
        while running:
            if descriptor < 0:
                descriptor = register_watch(queue, descriptor)
            timeout = 1.0
            if retry_at:
                timeout = min(timeout, max(0, retry_at - time.monotonic()))
            events = queue.control(None, 1, timeout)
            if not running:
                break
            if not events:
                if retry_at and time.monotonic() >= retry_at:
                    attempt()
                elif not retry_at and time.monotonic() - last_attempt >= RECONCILE_SECONDS:
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
            descriptor = register_watch(queue, descriptor)
    finally:
        queue.close()
        close_descriptor(descriptor)


def observed_account_state(settings):
    """Report the managed account state for the status page.

    Both roles apply configuration through their own API, so both carry the
    managed account and the state is meaningful on either node.
    """
    if not settings.get('enabled'):
        return ''
    if api_mode(settings) == 'manual':
        return 'manual'
    try:
        return api_account.account_state(read_config(ADGUARD_CONFIG), settings.get('secret') or '')
    except (OSError, RuntimeError, ValueError):
        return 'unknown'


def status():
    settings = load_settings()
    state = read_state()
    peer_master = state.get('peer_carp_master')
    result = {
        'status': 'ok',
        'enabled': settings.get('enabled', False),
        'pending_config': PENDING_CONFIG.is_file(),
        'learned_fingerprint': state.get('learned_fingerprint') or None,
        # 'configured' when the operator pinned the peer certificate by hand (learning is then never used),
        # 'learned' when the fingerprint came from the authenticated discovery, null otherwise.
        'fingerprint_source': ('configured' if settings.get('peer_fingerprint')
                               else 'learned' if state.get('learned_fingerprint') else None),
        'api_configured': api_configured(settings),
        'api_message': None,
        'api_mode': api_mode(settings),
        'last_result': state.get('last_result') or None,
        'last_error': state.get('last_error') or None,
        'base_present': base_path(settings.get('role')).is_file(),
        'last_adopted': state.get('last_adopted') or None,
        'last_conflict': state.get('last_conflict') or None,
        'last_overwritten': state.get('last_overwritten') or None,
        'peer_carp_master': peer_master if settings.get('role') == 'source'
        and isinstance(peer_master, bool) else None,
    }
    if not settings.get('enabled'):
        return result
    fingerprint = (
        (settings.get('peer_fingerprint') or state.get('learned_fingerprint'))
        if settings['role'] == 'source'
        else certificate_fingerprint()
    )
    if settings['role'] == 'receiver' and ADGUARD_CONFIG.is_file():
        try:
            reachable, reason = local_api_reachable(read_config(ADGUARD_CONFIG))
            result['api_message'] = None if reachable else reason
        except RuntimeError as error:
            result['api_message'] = str(error)
    result.update({
        'role': settings['role'],
        'listen_address': settings['listen_address'],
        'peer_address': settings['peer_address'],
        'port': settings['port'],
        'certificate_fingerprint': fingerprint,
        'secret_configured': bool(settings.get('secret')),
        'hot_update': settings.get('hot_update', True),
        'defer_while_master': settings.get('defer_while_master', False),
        'api_account_state': observed_account_state(settings),
    })
    return result


def main():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--run', action='store_true')
    group.add_argument('--sync', action='store_true')
    group.add_argument('--apply-pending', action='store_true')
    group.add_argument('--status', action='store_true')
    group.add_argument('--ensure-certificate', action='store_true')
    group.add_argument('--ensure-api-account', action='store_true')
    parser.add_argument('--when-backup', action='store_true',
                        help='with --ensure-api-account: defer the restart while this node is CARP master')
    args = parser.parse_args()
    syslog.openlog('adguardhome-sync')
    if args.status:
        print(json.dumps(status(), separators=(',', ':')))
        return
    settings = load_settings()
    if args.ensure_api_account:
        # Disabling synchronization must still withdraw the managed account.
        print(json.dumps(acquire_lock(lambda: ensure_api_account(settings, only_when_backup=args.when_backup),
                                      wait=LOCK_WAIT_SECONDS), separators=(',', ':')))
        return
    if not settings.get('enabled'):
        raise RuntimeError('Synchronization is disabled.')
    if args.ensure_certificate:
        if settings['role'] != 'receiver':
            raise RuntimeError('Only the synchronization receiver has a certificate.')
        print(json.dumps({'status': 'ok', 'certificate_fingerprint': ensure_certificate(settings)}))
    elif args.sync:
        print(json.dumps({'status': acquire_lock(lambda: push_once(settings), wait=60)}))
    elif args.apply_pending:
        print(json.dumps({'status': acquire_lock(lambda: apply_pending(settings), wait=60)}))
    elif args.run:
        # Install a missing managed account on the way up when it costs nothing
        # (this node is not CARP master); never let it keep the daemon from starting.
        try:
            outcome = acquire_lock(lambda: ensure_api_account(settings, only_when_backup=True), wait=LOCK_WAIT_SECONDS)
            if outcome.get('status') not in ('unchanged', 'deferred'):
                log(syslog.LOG_NOTICE, 'Managed AdGuard Home API account at start-up: ' + str(outcome.get('status')))
        except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
            log(syslog.LOG_WARNING, 'The managed AdGuard Home API account could not be prepared: ' + str(error))
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
