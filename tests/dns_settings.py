#!/usr/local/bin/python3
"""Verify DNS listener configuration parsing and updates."""

import importlib.util
import json
from pathlib import Path
import tempfile

import yaml


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / 'src/opnsense/scripts/Adguardhome/dns_settings.py'


def load_module():
    specification = importlib.util.spec_from_file_location('adguardhome_dns_settings', MODULE_PATH)
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def main():
    module = load_module()
    with tempfile.TemporaryDirectory(prefix='adguardhome-dns-settings-') as temporary:
        directory = Path(temporary)
        module.ADGUARD_HOME = directory
        module.ADGUARD_CONFIG = directory / 'AdGuardHome.yaml'
        module.ADGUARD_BINARY = directory / 'adguardhome'
        module.BACKUP_CONFIG = directory / 'AdGuardHome.yaml.before-opnsense'
        module.MODEL_SETTINGS_PATH = directory / 'opnsense.json'
        module.ADGUARD_CONFIG.write_text('dns:\n  bind_hosts:\n    - 192.0.2.1\n  port: 53\n', encoding='utf-8')
        module.MODEL_SETTINGS_PATH.write_text(json.dumps({
            'general': {
                'enabled': True,
                'bind_hosts': '192.0.2.8,fd00::8',
                'dns_port': '5353',
            },
            'interfaces': [
                {'name': 'lan', 'device': 'vtnet0', 'description': 'LAN'},
            ],
        }), encoding='utf-8')
        module.ADGUARD_BINARY.write_text('#!/bin/sh\nexit 0\n', encoding='utf-8')
        module.ADGUARD_BINARY.chmod(0o755)
        assert module.binary_path() == module.ADGUARD_BINARY
        module.is_running = lambda: True
        module.stop_service = lambda: None
        module.start_service = lambda: None
        module.check_candidate = lambda _candidate: None
        assert module.interface_labels() == {'vtnet0': 'LAN'}
        module.available_addresses = lambda: {'192.0.2.1': '192.0.2.1 (LAN)'}
        assert module.get_settings() == {
            'status': 'ok',
            'bind_hosts': ['192.0.2.1'],
            'port': 53,
            'available_hosts': {'192.0.2.1': '192.0.2.1 (LAN)'},
        }
        assert module.apply_unlocked() == 'updated'
        updated = yaml.safe_load(module.ADGUARD_CONFIG.read_text(encoding='utf-8'))
        assert updated['dns']['bind_hosts'] == ['192.0.2.8', 'fd00::8']
        assert updated['dns']['port'] == 5353
        try:
            module.normalize_hosts(['invalid'])
        except ValueError:
            pass
        else:
            raise RuntimeError('An invalid DNS listen address was accepted.')
    print('DNS settings test passed')


if __name__ == '__main__':
    main()
