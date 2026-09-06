#!/usr/local/bin/python3
"""Exercise the synchronization protocol without touching the installed service."""

import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time


SYNC_MODULE = Path(__file__).resolve().parents[1] / 'src/opnsense/scripts/Adguardhome/syncd.py'


def load_module():
    spec = importlib.util.spec_from_file_location('syncd', SYNC_MODULE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    syncd = load_module()
    with tempfile.TemporaryDirectory(prefix='adguardhome-sync-e2e-') as directory:
        root = Path(directory)
        syncd.ADGUARD_HOME = root
        syncd.ADGUARD_CONFIG = root / 'AdGuardHome.yaml'
        syncd.ADGUARD_BINARY = root / 'AdGuardHome'
        syncd.CERTIFICATE_PATH = root / 'receiver.pem'
        syncd.LOCK_PATH = root / 'sync.lock'
        syncd.ADGUARD_CONFIG.write_text('old: configuration\n')
        receiver_config = root / 'receiver-AdGuardHome.yaml'
        receiver_config.write_text('old: configuration\n')
        syncd.ADGUARD_BINARY.write_text('placeholder')
        syncd.ADGUARD_BINARY.chmod(0o755)
        subprocess.run([
            '/usr/bin/openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-nodes', '-days', '1',
            '-subj', '/CN=sync-test', '-addext', 'subjectAltName=IP:127.0.0.1',
            '-keyout', str(syncd.CERTIFICATE_PATH), '-out', str(syncd.CERTIFICATE_PATH),
        ], check=True, capture_output=True)
        syncd.check_config = lambda path: None
        original_run = syncd.run

        def fake_run(*args, **kwargs):
            if args[:2] == ('/usr/sbin/service', 'adguardhome'):
                return subprocess.CompletedProcess(args, 0, b'', b'')
            return original_run(*args, **kwargs)

        syncd.run = fake_run

        def apply_to_receiver(content):
            if receiver_config.read_bytes() == content:
                return 'unchanged'
            receiver_config.write_bytes(content)
            return 'updated'

        syncd.apply_received_config = apply_to_receiver
        shared_secret = 'test-secret-' + ('x' * 48)
        receiver = {
            'enabled': True,
            'role': 'receiver',
            'listen_address': '127.0.0.1',
            'peer_address': '127.0.0.1',
            'port': 19443,
            'secret': shared_secret,
        }
        thread = threading.Thread(target=syncd.serve, args=(receiver,), daemon=True)
        thread.start()
        time.sleep(0.25)
        source = {
            'enabled': True,
            'role': 'source',
            'listen_address': '127.0.0.1',
            'peer_address': '127.0.0.1',
            'port': 19443,
            'secret': shared_secret,
            'peer_fingerprint': syncd.certificate_fingerprint(),
        }
        syncd.ADGUARD_CONFIG.write_text('new: configuration\n')
        if syncd.push_once(source) != 'updated':
            raise RuntimeError('The peer did not report an update.')
        if receiver_config.read_text() != 'new: configuration\n':
            raise RuntimeError('The received configuration was not applied.')
        if syncd.push_once(source) != 'unchanged':
            raise RuntimeError('The peer did not recognize an unchanged configuration.')
        rejected = dict(source)
        rejected['secret'] = 'wrong-secret-' + ('x' * 48)
        try:
            syncd.push_once(rejected)
        except RuntimeError:
            pass
        else:
            raise RuntimeError('The receiver accepted an incorrect pairing secret.')
    print('syncd e2e passed')


if __name__ == '__main__':
    main()
