#!/usr/local/bin/python3
"""Render safe local synchronization settings from generated OPNsense data."""

import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


MODEL_SETTINGS_PATH = Path('/usr/local/etc/adguardhome-ha/opnsense.json')
SETTINGS_PATH = Path('/usr/local/etc/adguardhome-sync.json')
RC_PATH = Path('/etc/rc.conf.d/adguardhome_sync')


def model_settings():
    try:
        settings = json.loads(MODEL_SETTINGS_PATH.read_text(encoding='utf-8'))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError('The generated OPNsense settings are unavailable.') from error
    if not isinstance(settings, dict) or not isinstance(settings.get('sync'), dict):
        raise ValueError('The generated synchronization settings are invalid.')
    return settings['sync']


def command_output(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT)


def state_sync_addresses():
    details = command_output('/sbin/ifconfig', 'pfsync0')
    match = re.search(r'syncdev:\s*(\S+)\s+syncpeer:\s*([0-9.]+)', details)
    if not match:
        raise ValueError('The state synchronization interface is unavailable.')
    interface, peer = match.groups()
    peer = str(ipaddress.IPv4Address(peer))
    addresses = command_output('/sbin/ifconfig', interface)
    local = re.search(r'^\s*inet\s+([0-9.]+)\s+netmask', addresses, re.MULTILINE)
    if not local:
        raise ValueError('The state synchronization interface has no IPv4 address.')
    local_address = str(ipaddress.IPv4Address(local.group(1)))
    if local_address == peer:
        raise ValueError('The state synchronization peer addresses are invalid.')
    return local_address, peer


def text_value(value, name, limit, strip=True):
    """Accept an optional short text setting from the generated model data."""
    if value is None:
        return ''
    if not isinstance(value, str):
        raise ValueError(name + ' is invalid.')
    value = value.strip() if strip else value
    if len(value) > limit:
        raise ValueError(name + ' is invalid.')
    return value


def boolean_value(value, default):
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lower() in ('1', 'true', 'yes', 'on'):
        return True
    if isinstance(value, str) and value.strip().lower() in ('0', 'false', 'no', 'off'):
        return False
    return default


def build_settings():
    configured = model_settings()
    enabled = configured.get('enabled') is True
    if not enabled:
        return {'enabled': False}
    try:
        port = int(configured.get('port', '9443'))
    except (TypeError, ValueError) as error:
        raise ValueError('Synchronization port is invalid.') from error
    if not 1024 <= port <= 65535:
        raise ValueError('Synchronization port is invalid.')
    secret = configured.get('secret', '')
    if not isinstance(secret, str):
        raise ValueError('Pairing secret is invalid.')
    if not 32 <= len(secret) <= 256:
        raise ValueError('Pairing secret is invalid.')
    local, peer = state_sync_addresses()
    synchronization_target = configured.get('synchronization_target', '')
    if not isinstance(synchronization_target, str):
        raise ValueError('The HA configuration synchronization target is invalid.')
    synchronization_target = synchronization_target.strip()
    if synchronization_target:
        try:
            synchronization_target = str(ipaddress.IPv4Address(synchronization_target))
        except ipaddress.AddressValueError as error:
            raise ValueError('The HA configuration synchronization target is invalid.') from error
        if synchronization_target != peer:
            raise ValueError(
                'The HA configuration synchronization target does not match the state-sync peer: '
                'System > High Availability > Settings > Synchronize Config to IP must be the peer\'s '
                'pfsync address {}, currently {}.'.format(peer, synchronization_target)
            )
        role = 'source'
    else:
        role = 'receiver'
    peer_fingerprint = configured.get('peer_fingerprint', '')
    if not isinstance(peer_fingerprint, str):
        raise ValueError('Peer certificate fingerprint is invalid.')
    peer_fingerprint = peer_fingerprint.lower().replace(':', '')
    if peer_fingerprint and not re.fullmatch(r'[0-9a-f]{64}', peer_fingerprint):
        raise ValueError('Peer certificate fingerprint is invalid.')
    api_username = text_value(configured.get('api_username', ''), 'The AdGuard Home API user name', 128)
    if ':' in api_username:
        raise ValueError('The AdGuard Home API user name is invalid.')
    api_password = text_value(configured.get('api_password', ''), 'The AdGuard Home API password', 256, strip=False)
    # Configured credentials are a manual override; otherwise the plugin manages
    # a dedicated administrator derived from the pairing secret.
    if not (api_username and api_password):
        api_username = ''
        api_password = ''
    return {
        'enabled': True,
        'role': role,
        'listen_address': local,
        'peer_address': peer,
        'port': port,
        'secret': secret,
        'peer_fingerprint': peer_fingerprint,
        'api_username': api_username,
        'api_password': api_password,
        'api_mode': 'manual' if (api_username and api_password) else 'managed',
        'hot_update': boolean_value(configured.get('hot_update'), True),
        'defer_while_master': boolean_value(configured.get('defer_while_master'), False),
    }


def atomic_write(path, content, mode):
    path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix='.' + path.name + '.', delete=False) as stream:
        stream.write(content)
        stream.flush()
        os.fchmod(stream.fileno(), mode)
        candidate = Path(stream.name)
    candidate.replace(path)


def render():
    settings = build_settings()
    atomic_write(SETTINGS_PATH, json.dumps(settings, separators=(',', ':')).encode(), 0o600)
    enabled = settings.get('enabled', False)
    atomic_write(RC_PATH, ('adguardhome_sync_enable="{}"\n'.format('YES' if enabled else 'NO')).encode(), 0o644)
    return settings


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--render', action='store_true')
    args = parser.parse_args()
    if not args.render:
        parser.error('an action is required')
    print(json.dumps(render(), separators=(',', ':')))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(json.dumps({'status': 'failed', 'message': str(error)}), file=sys.stderr)
        raise SystemExit(1)
