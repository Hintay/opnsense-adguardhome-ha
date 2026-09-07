#!/usr/local/bin/python3
"""Verify that the synchronization receiver rejects everything but a valid push."""

import hashlib
import hmac
import http.client
import importlib.util
import json
from pathlib import Path
import secrets
import ssl
import subprocess
import tempfile
import threading
import time


SYNC_MODULE = Path(__file__).resolve().parents[1] / 'src/opnsense/scripts/Adguardhome/syncd.py'
SECRET = 'receiver-test-secret-' + ('y' * 40)
PAYLOAD = b'dns:\n  bind_hosts:\n  - 0.0.0.0\n  port: 53\n'


def load_module():
    specification = importlib.util.spec_from_file_location('syncd', SYNC_MODULE)
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def client_context():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def start_receiver(syncd, settings):
    server = syncd.SyncServer((settings['listen_address'], 0), syncd.Receiver)
    server.settings = settings
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(str(syncd.CERTIFICATE_PATH))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    settings['port'] = server.server_address[1]
    threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.05}, daemon=True).start()
    return server


def call(syncd, port, method, path, content=b'', secret=SECRET, timestamp=None,
         nonce=None, checksum=None, content_length=None):
    """Send one signed request and return the status and the decoded body."""
    timestamp = str(int(time.time())) if timestamp is None else str(timestamp)
    nonce = secrets.token_urlsafe(24) if nonce is None else nonce
    digest = hashlib.sha256(content).hexdigest() if checksum is None else checksum
    message = '\n'.join((method, path, timestamp, nonce, digest)).encode()
    connection = http.client.HTTPSConnection('127.0.0.1', port, context=client_context(), timeout=10)
    try:
        connection.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
        connection.putheader('Content-Type', 'application/x-yaml')
        connection.putheader('Content-Length', str(len(content) if content_length is None else content_length))
        connection.putheader(syncd.TIMESTAMP_HEADER, timestamp)
        connection.putheader(syncd.NONCE_HEADER, nonce)
        connection.putheader(syncd.CHECKSUM_HEADER, digest)
        connection.putheader(syncd.SIGNATURE_HEADER,
                             hmac.new(secret.encode(), message, hashlib.sha256).hexdigest())
        connection.endheaders(message_body=content or None)
        response = connection.getresponse()
        return response.status, json.loads(response.read().decode()), nonce, timestamp
    finally:
        connection.close()


def test_requests(syncd, port, applied):
    status, body, nonce, _ = call(syncd, port, 'PUT', '/v1/config', PAYLOAD)
    assert status == 200 and body['status'] == 'hot', (status, body)
    assert applied == [PAYLOAD], applied

    status, body, _, _stamp = call(syncd, port, 'PUT', '/v1/config', PAYLOAD, nonce=nonce)
    assert status == 403 and 'replay' in body['message'].lower(), (status, body)

    status, body, _, _stamp = call(syncd, port, 'PUT', '/v1/config', PAYLOAD, timestamp=int(time.time()) - 3600)
    assert status == 403 and 'Timestamp' in body['message'], (status, body)

    status, body, _, _stamp = call(syncd, port, 'PUT', '/v1/config', PAYLOAD, secret='wrong-secret-' + ('z' * 40))
    assert status == 403 and 'authentication' in body['message'], (status, body)

    status, body, _, _stamp = call(syncd, port, 'PUT', '/v1/config', PAYLOAD,
                                   checksum=hashlib.sha256(b'other').hexdigest())
    assert status == 403 and 'integrity' in body['message'], (status, body)

    status, body, _, _stamp = call(syncd, port, 'PUT', '/v1/config', PAYLOAD,
                                   content_length=syncd.MAX_CONFIG_BYTES + 1)
    assert status == 413, (status, body)

    status, body, _, _stamp = call(syncd, port, 'PUT', '/v1/settings', PAYLOAD)
    assert status == 404, (status, body)
    assert applied == [PAYLOAD], applied


def fetch(syncd, port, path, secret=SECRET, signed=True):
    """Send one GET and return the status, the headers and the raw body."""
    timestamp = str(int(time.time()))
    nonce = secrets.token_urlsafe(24)
    digest = hashlib.sha256(b'').hexdigest()
    message = '\n'.join(('GET', path, timestamp, nonce, digest)).encode()
    connection = http.client.HTTPSConnection('127.0.0.1', port, context=client_context(), timeout=10)
    try:
        connection.putrequest('GET', path, skip_host=True, skip_accept_encoding=True)
        if signed:
            connection.putheader(syncd.TIMESTAMP_HEADER, timestamp)
            connection.putheader(syncd.NONCE_HEADER, nonce)
            connection.putheader(syncd.CHECKSUM_HEADER, digest)
            connection.putheader(syncd.SIGNATURE_HEADER,
                                 hmac.new(secret.encode(), message, hashlib.sha256).hexdigest())
        connection.endheaders()
        response = connection.getresponse()
        return response.status, dict(response.headers), response.read()
    finally:
        connection.close()


def test_config_endpoint(syncd, port):
    """The source reads the receiver configuration through GET /v1/config."""
    status, _headers, body = fetch(syncd, port, '/v1/config', signed=False)
    assert status == 403, (status, body)
    status, _headers, body = fetch(syncd, port, '/v1/config', secret='wrong-secret-' + ('z' * 40))
    assert status == 403, (status, body)

    for master, expected in ((True, '1'), (False, '0')):
        syncd.carp_master = lambda _document, value=master: value
        status, headers, body = fetch(syncd, port, '/v1/config')
        assert status == 200, (status, body)
        assert body == syncd.ADGUARD_CONFIG.read_bytes(), body
        assert headers['Content-Type'] == 'application/x-yaml', headers
        assert headers[syncd.CHECKSUM_HEADER] == hashlib.sha256(body).hexdigest(), headers
        assert headers[syncd.CARP_MASTER_HEADER] == expected, headers

    # An unreadable configuration is reported instead of served empty.
    syncd.ADGUARD_CONFIG.rename(syncd.ADGUARD_CONFIG.with_suffix('.moved'))
    try:
        status, _headers, body = fetch(syncd, port, '/v1/config')
        assert status == 500, (status, body)
    finally:
        syncd.ADGUARD_CONFIG.with_suffix('.moved').rename(syncd.ADGUARD_CONFIG)


def test_info(syncd, port, settings):
    status, body, nonce, stamp = call(syncd, port, 'GET', '/v1/info')
    assert status == 200 and body['status'] == 'ok', (status, body)
    expected = syncd.info_signature(settings, body['certificate_fingerprint'], stamp, nonce)
    assert body['info_signature'] == expected, (body, expected)
    assert body['certificate_fingerprint'] == syncd.certificate_fingerprint(), body

    # An unsigned request must not disclose the fingerprint.
    connection = http.client.HTTPSConnection('127.0.0.1', port, context=client_context(), timeout=10)
    try:
        connection.request('GET', '/v1/info')
        response = connection.getresponse()
        assert response.status == 403, response.status
    finally:
        connection.close()


def test_learned_fingerprint(syncd, settings):
    """The source learns the fingerprint from a signed /v1/info answer."""
    source = dict(settings)
    source['peer_address'] = '127.0.0.1'
    learned = syncd.learn_fingerprint(source)
    assert learned == syncd.certificate_fingerprint(), learned
    assert syncd.read_state()['learned_fingerprint'] == learned


def test_peer_address(syncd):
    server = syncd.SyncServer.__new__(syncd.SyncServer)
    server.settings = {'peer_address': '10.99.99.99'}
    assert syncd.SyncServer.verify_request(server, None, ('127.0.0.1', 40000)) is False
    assert syncd.SyncServer.verify_request(server, None, ('10.99.99.99', 40000)) is True


def test_rejected_connection(syncd, settings):
    spoofed = dict(settings)
    spoofed['peer_address'] = '10.99.99.99'
    server = start_receiver(syncd, spoofed)
    try:
        call(syncd, spoofed['port'], 'PUT', '/v1/config', PAYLOAD)
    except (OSError, http.client.HTTPException, ssl.SSLError):
        pass
    else:
        raise RuntimeError('The receiver accepted a connection from another address.')
    finally:
        server.shutdown()
        server.server_close()


def main():
    syncd = load_module()
    applied = []
    with tempfile.TemporaryDirectory(prefix='adguardhome-sync-receiver-') as directory:
        root = Path(directory)
        syncd.CERTIFICATE_PATH = root / 'receiver.pem'
        syncd.LOCK_PATH = root / 'sync.lock'
        syncd.STATE_PATH = root / 'state.json'
        syncd.ADGUARD_HOME = root
        syncd.ADGUARD_CONFIG = root / 'AdGuardHome.yaml'
        syncd.BASE_PATH_RECEIVER = root / 'AdGuardHome.yaml.last-source'
        syncd.BASE_PATH_SOURCE = root / 'AdGuardHome.yaml.last-pushed'
        syncd.ADGUARD_CONFIG.write_bytes(PAYLOAD)
        subprocess.run([
            '/usr/bin/openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-nodes', '-days', '1',
            '-subj', '/CN=sync-test', '-addext', 'subjectAltName=IP:127.0.0.1',
            '-keyout', str(syncd.CERTIFICATE_PATH), '-out', str(syncd.CERTIFICATE_PATH),
        ], check=True, capture_output=True)

        def fake_apply(content, _settings=None):
            applied.append(content)
            return 'hot'

        syncd.apply_received_config = fake_apply
        settings = {
            'enabled': True,
            'role': 'receiver',
            'listen_address': '127.0.0.1',
            'peer_address': '127.0.0.1',
            'port': 0,
            'secret': SECRET,
        }
        server = start_receiver(syncd, settings)
        try:
            test_requests(syncd, settings['port'], applied)
            test_config_endpoint(syncd, settings['port'])
            test_info(syncd, settings['port'], settings)
            test_learned_fingerprint(syncd, settings)
        finally:
            server.shutdown()
            server.server_close()
        test_peer_address(syncd)
        test_rejected_connection(syncd, settings)
    print('syncd receiver tests passed')


if __name__ == '__main__':
    main()
