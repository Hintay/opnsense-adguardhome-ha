#!/usr/local/bin/python3
"""Verify DNS listener configuration parsing, service state and updates."""

import contextlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile

import yaml


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / 'src/opnsense/scripts/Adguardhome/dns_settings.py'


def load_module():
    specification = importlib.util.spec_from_file_location('adguardhome_dns_settings', MODULE_PATH)
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def dead_pid():
    child = subprocess.Popen([sys.executable, '-c', 'pass'])
    child.wait()
    return child.pid


def unused_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(('127.0.0.1', 0))
        return probe.getsockname()[1]


def service_recorder(module, state):
    """Replace service() with a recorder that maintains the pid file like the daemon does."""
    def fake_service(action):
        state['calls'].append(action)
        if action == 'onestart' and state['starts']:
            module.PID_PATH.write_text('{}\n'.format(os.getpid()), encoding='utf-8')
        elif action == 'onestop':
            module.PID_PATH.unlink(missing_ok=True)
        return subprocess.CompletedProcess(('/usr/sbin/service', 'adguardhome', action), 0, b'', b'')

    module.service = fake_service


def check_is_running(module):
    module.PID_PATH.unlink(missing_ok=True)
    assert module.is_running() is False
    module.PID_PATH.write_text('not-a-pid\n', encoding='utf-8')
    assert module.is_running() is False
    module.PID_PATH.write_text('{}\n'.format(dead_pid()), encoding='utf-8')
    assert module.is_running() is False
    module.PID_PATH.write_text('{}\n'.format(os.getpid()), encoding='utf-8')
    assert module.is_running() is True
    module.PID_PATH.unlink()


def check_wait_serving(module, port):
    assert module.wait_serving(['127.0.0.1'], port, timeout=2) is True
    assert module.wait_serving(['0.0.0.0'], port, timeout=2) is True
    assert module.wait_serving(['198.51.100.7', '127.0.0.1'], port, timeout=2) is True
    assert module.wait_serving(['127.0.0.1'], unused_port(), timeout=0.5) is False


def check_reconcile_service(module, state):
    module.PID_PATH.unlink(missing_ok=True)
    state['calls'] = []
    module.reconcile_service(True)
    assert state['calls'] == ['onestart']
    assert module.is_running() is True
    state['calls'] = []
    module.reconcile_service(True)
    assert state['calls'] == []
    module.reconcile_service(False)
    assert state['calls'] == ['onestop']
    assert module.is_running() is False
    state['calls'] = []
    module.reconcile_service(False)
    assert state['calls'] == []


def check_failed_start(module, state):
    state['starts'] = False
    module.PID_PATH.unlink(missing_ok=True)
    try:
        module.start_service()
    except RuntimeError as error:
        assert 'did not start' in str(error)
    else:
        raise RuntimeError('A failed service start was not detected.')
    state['starts'] = True
    try:
        module.start_service(['127.0.0.1'], unused_port())
    except RuntimeError as error:
        assert 'did not answer' in str(error)
    else:
        raise RuntimeError('A service that did not bind was not detected.')


def check_failed_apply(module, state):
    """A start failure has to restore the backup and report that the restart failed as well."""
    previous = module.ADGUARD_CONFIG.read_text(encoding='utf-8')
    model = json.loads(module.MODEL_SETTINGS_PATH.read_text(encoding='utf-8'))
    model['general']['dns_port'] = str(unused_port())
    module.MODEL_SETTINGS_PATH.write_text(json.dumps(model), encoding='utf-8')
    module.PID_PATH.write_text('{}\n'.format(os.getpid()), encoding='utf-8')
    state['starts'] = False
    try:
        module.apply_unlocked()
    except RuntimeError as error:
        assert 'could not be restarted either' in str(error)
    else:
        raise RuntimeError('A failed configuration update was not reported.')
    assert module.ADGUARD_CONFIG.read_text(encoding='utf-8') == previous
    state['starts'] = True


def check_resolver_warnings(module, directory):
    resolv = directory / 'resolv.conf'
    module.RESOLV_CONF = resolv
    resolv.write_text('nameserver 127.0.0.1\n', encoding='utf-8')
    original = module.agh_api.local_listeners
    try:
        module.agh_api.local_listeners = lambda port: {'192.0.2.8'}
        assert module.resolver_warnings(['192.0.2.8'], 53)[0]['code'] == 'resolver_loopback'
        assert module.resolver_warnings(['192.0.2.8', '127.0.0.1'], 53) == []      # loopback bound
        assert module.resolver_warnings(['0.0.0.0'], 53) == []                    # wildcard bound
        module.agh_api.local_listeners = lambda port: {'127.0.0.1'}
        assert module.resolver_warnings(['192.0.2.8'], 53) == []                  # Unbound serves it
        module.agh_api.local_listeners = lambda port: None
        assert module.resolver_warnings(['192.0.2.8'], 53) == []                  # no sockstat: stay quiet
        resolv.write_text('nameserver 192.0.2.53\n', encoding='utf-8')
        module.agh_api.local_listeners = lambda port: set()
        assert module.resolver_warnings(['192.0.2.8'], 53) == []                  # resolver not on loopback
    finally:
        module.agh_api.local_listeners = original


def main():
    module = load_module()
    with tempfile.TemporaryDirectory(prefix='adguardhome-dns-settings-') as temporary:
        directory = Path(temporary)
        module.ADGUARD_HOME = directory
        module.ADGUARD_CONFIG = directory / 'AdGuardHome.yaml'
        module.ADGUARD_BINARY = directory / 'adguardhome'
        module.BACKUP_CONFIG = directory / 'AdGuardHome.yaml.before-opnsense'
        module.MODEL_SETTINGS_PATH = directory / 'opnsense.json'
        module.RESOLV_CONF = directory / 'resolv.conf'  # absent until the resolver check writes it
        module.PID_PATH = directory / 'adguardhome.pid'
        with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as listener:
            listener.bind(('127.0.0.1', 0))
            listener.listen(4)
            port = listener.getsockname()[1]
            module.ADGUARD_CONFIG.write_text(
                'dns:\n  bind_hosts:\n    - 192.0.2.1\n  port: 53\n', encoding='utf-8')
            module.MODEL_SETTINGS_PATH.write_text(json.dumps({
                'general': {
                    'enabled': True,
                    'bind_hosts': '127.0.0.1,fd00::8',
                    'dns_port': str(port),
                },
                'interfaces': [
                    {'name': 'lan', 'device': 'vtnet0', 'description': 'LAN'},
                ],
            }), encoding='utf-8')
            module.ADGUARD_BINARY.write_text('#!/bin/sh\nexit 0\n', encoding='utf-8')
            module.ADGUARD_BINARY.chmod(0o755)
            assert module.binary_path() == module.ADGUARD_BINARY
            module.check_candidate = lambda _candidate: None
            state = {'calls': [], 'starts': True}
            service_recorder(module, state)
            # Keep the waiting loops short, the real implementations stay in use.
            module.wait_until_running = lambda timeout=1: module.is_running()
            check_is_running(module)
            check_wait_serving(module, port)
            check_resolver_warnings(module, directory)
            check_reconcile_service(module, state)
            check_failed_start(module, state)
            assert module.interface_labels() == {'vtnet0': 'LAN'}
            module.available_addresses = lambda: {'192.0.2.1': '192.0.2.1 (LAN)'}
            assert module.get_settings() == {
                'status': 'ok',
                'bind_hosts': ['192.0.2.1'],
                'port': 53,
                'available_hosts': {'192.0.2.1': '192.0.2.1 (LAN)'},
                'warnings': [],
            }
            assert module.apply_unlocked() == 'updated'
            updated = yaml.safe_load(module.ADGUARD_CONFIG.read_text(encoding='utf-8'))
            assert updated['dns']['bind_hosts'] == ['127.0.0.1', 'fd00::8']
            assert updated['dns']['port'] == port
            assert module.apply_unlocked() == 'unchanged'
            check_failed_apply(module, state)
            try:
                module.normalize_hosts(['invalid'])
            except ValueError:
                pass
            else:
                raise RuntimeError('An invalid DNS listen address was accepted.')
    print('DNS settings test passed')


if __name__ == '__main__':
    main()
