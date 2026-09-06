#!/usr/local/bin/python3
"""Verify synchronization role detection from OPNsense HA settings."""

import importlib.util
import json
from pathlib import Path
import tempfile


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / 'src/opnsense/scripts/Adguardhome/settings.py'


def load_module():
    specification = importlib.util.spec_from_file_location('adguardhome_settings', MODULE_PATH)
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def configuration(target):
    return json.dumps({
        'sync': {
            'enabled': True,
            'port': '9443',
            'secret': '0123456789abcdef0123456789abcdef',
            'peer_fingerprint': 'a' * 64,
            'synchronization_target': target,
        }
    })


def settings_for(module, directory, target):
    config_path = directory / 'opnsense.json'
    config_path.write_text(configuration(target), encoding='utf-8')
    module.MODEL_SETTINGS_PATH = config_path
    module.state_sync_addresses = lambda: ('10.0.2.1', '10.0.2.2')
    return module.build_settings()


def main():
    module = load_module()
    with tempfile.TemporaryDirectory(prefix='adguardhome-settings-') as temporary:
        directory = Path(temporary)
        assert settings_for(module, directory, '10.0.2.2')['role'] == 'source'
        assert settings_for(module, directory, '')['role'] == 'receiver'
        try:
            settings_for(module, directory, '10.0.2.3')
        except ValueError as error:
            assert 'does not match' in str(error)
        else:
            raise RuntimeError('A mismatched HA target was accepted.')
    print('settings role detection test passed')


if __name__ == '__main__':
    main()
