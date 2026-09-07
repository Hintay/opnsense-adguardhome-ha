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


def configuration(target, **overrides):
    sync = {
        'enabled': True,
        'port': '9443',
        'secret': '0123456789abcdef0123456789abcdef',
        'peer_fingerprint': 'a' * 64,
        'synchronization_target': target,
        'api_username': 'admin',
        'api_password': 'password',
        'hot_update': True,
        'defer_while_master': False,
    }
    sync.update(overrides)
    return json.dumps({'sync': sync})


def settings_for(module, directory, target, **overrides):
    config_path = directory / 'opnsense.json'
    config_path.write_text(configuration(target, **overrides), encoding='utf-8')
    module.MODEL_SETTINGS_PATH = config_path
    module.state_sync_addresses = lambda: ('10.0.2.1', '10.0.2.2')
    return module.build_settings()


def test_roles(module, directory):
    assert settings_for(module, directory, '10.0.2.2')['role'] == 'source'
    assert settings_for(module, directory, '')['role'] == 'receiver'
    # A source without a pinned fingerprint learns it from the peer at runtime.
    assert settings_for(module, directory, '10.0.2.2', peer_fingerprint='')['peer_fingerprint'] == ''
    try:
        settings_for(module, directory, '10.0.2.2', peer_fingerprint='not-a-fingerprint')
    except ValueError as error:
        assert 'fingerprint' in str(error)
    else:
        raise RuntimeError('An invalid fingerprint was accepted.')
    try:
        settings_for(module, directory, '10.0.2.3')
    except ValueError as error:
        assert 'does not match' in str(error)
        assert 'Synchronize Config to IP' in str(error)
        assert '10.0.2.2' in str(error) and '10.0.2.3' in str(error)
    else:
        raise RuntimeError('A mismatched HA target was accepted.')


def test_api_settings(module, directory):
    settings = settings_for(module, directory, '')
    assert settings['api_username'] == 'admin'
    assert settings['api_password'] == 'password'
    assert settings['api_mode'] == 'manual'
    assert settings['hot_update'] is True
    assert settings['defer_while_master'] is False
    # Incomplete credentials fall back to the managed service account.
    partial = settings_for(module, directory, '', api_password='')
    assert partial['api_username'] == '' and partial['api_password'] == ''
    assert partial['api_mode'] == 'managed'
    assert settings_for(module, directory, '', api_username='')['api_mode'] == 'managed'
    # The switches keep their documented defaults when the model omits them.
    defaults = settings_for(module, directory, '', hot_update=None, defer_while_master=None)
    assert defaults['hot_update'] is True
    assert defaults['defer_while_master'] is False
    strings = settings_for(module, directory, '', hot_update='0', defer_while_master='1')
    assert strings['hot_update'] is False
    assert strings['defer_while_master'] is True
    try:
        settings_for(module, directory, '', api_username='admin:root')
    except ValueError as error:
        assert 'user name' in str(error)
    else:
        raise RuntimeError('A user name with a colon was accepted.')
    try:
        settings_for(module, directory, '', api_username=['admin'])
    except ValueError as error:
        assert 'user name' in str(error)
    else:
        raise RuntimeError('An invalid API user name was accepted.')


def test_disabled(module, directory):
    config_path = directory / 'opnsense.json'
    config_path.write_text(json.dumps({'sync': {'enabled': False}}), encoding='utf-8')
    module.MODEL_SETTINGS_PATH = config_path
    assert module.build_settings() == {'enabled': False}


def main():
    module = load_module()
    with tempfile.TemporaryDirectory(prefix='adguardhome-settings-') as temporary:
        directory = Path(temporary)
        test_roles(module, directory)
        test_api_settings(module, directory)
        test_disabled(module, directory)
    print('settings role detection test passed')


if __name__ == '__main__':
    main()
