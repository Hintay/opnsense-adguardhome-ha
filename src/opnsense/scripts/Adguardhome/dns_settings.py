#!/usr/local/bin/python3
"""Read and safely apply AdGuard Home DNS listener settings."""

import argparse
import copy
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import time

import yaml


MODEL_SETTINGS_PATH = Path('/usr/local/etc/adguardhome-ha/opnsense.json')
ADGUARD_HOME = Path('/usr/local/AdGuardHome')
ADGUARD_CONFIG = ADGUARD_HOME / 'AdGuardHome.yaml'
ADGUARD_BINARY = Path('/usr/local/bin/adguardhome')
BACKUP_CONFIG = ADGUARD_HOME / 'AdGuardHome.yaml.before-opnsense'
SYNC_SETTINGS = Path('/usr/local/etc/adguardhome-sync.json')
LOCK_PATH = Path('/var/run/adguardhome-sync.lock')


def run(*args, timeout=45):
    return subprocess.run(args, capture_output=True, timeout=timeout)


def model_settings(required=True):
    try:
        settings = json.loads(MODEL_SETTINGS_PATH.read_text(encoding='utf-8'))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        if not required:
            return {}
        raise ValueError('The generated OPNsense settings are unavailable.') from error
    if not isinstance(settings, dict):
        if not required:
            return {}
        raise ValueError('The generated OPNsense settings are invalid.')
    return settings


def normalize_hosts(values):
    if not isinstance(values, list) or not values:
        raise ValueError('At least one DNS listen address is required.')
    result = []
    for value in values:
        try:
            address = str(ipaddress.ip_address(str(value).strip()))
        except ValueError as error:
            raise ValueError('A DNS listen address is invalid.') from error
        if address not in result:
            result.append(address)
    return result


def normalize_port(value):
    try:
        port = int(value)
    except (TypeError, ValueError) as error:
        raise ValueError('The DNS listen port is invalid.') from error
    if not 1 <= port <= 65535:
        raise ValueError('The DNS listen port is invalid.')
    return port


def read_yaml():
    if not ADGUARD_CONFIG.is_file():
        raise ValueError('AdGuard Home configuration is unavailable.')
    try:
        raw = yaml.safe_load(ADGUARD_CONFIG.read_text(encoding='utf-8'))
    except (OSError, UnicodeError, yaml.YAMLError) as error:
        raise ValueError('AdGuard Home configuration cannot be read.') from error
    if not isinstance(raw, dict) or not isinstance(raw.get('dns'), dict):
        raise ValueError('AdGuard Home DNS configuration is unavailable.')
    settings = {
        'bind_hosts': normalize_hosts(raw['dns'].get('bind_hosts')),
        'port': normalize_port(raw['dns'].get('port')),
    }
    return raw, settings


def desired_settings():
    configured = model_settings().get('general')
    if not isinstance(configured, dict):
        raise ValueError('The generated DNS settings are invalid.')
    enabled = configured.get('enabled') is True
    hosts_value = configured.get('bind_hosts', '')
    if not isinstance(hosts_value, str):
        raise ValueError('The generated DNS listen addresses are invalid.')
    hosts = [item for item in hosts_value.split(',') if item.strip()]
    if not hosts:
        _, current = read_yaml()
        hosts = current['bind_hosts']
    port_text = configured.get('dns_port', '')
    if not port_text:
        _, current = read_yaml()
        port_text = current['port']
    return {
        'enabled': enabled,
        'bind_hosts': normalize_hosts(hosts),
        'port': normalize_port(port_text),
    }


def interface_labels():
    interfaces = model_settings(required=False).get('interfaces', [])
    if not isinstance(interfaces, list):
        return {}
    result = {}
    for interface in interfaces:
        if not isinstance(interface, dict):
            continue
        device = interface.get('device', '')
        description = interface.get('description', '') or interface.get('name', '').upper()
        if not isinstance(device, str) or not device:
            continue
        if not isinstance(description, str):
            description = device
        result[device] = description
    return result


def available_addresses():
    result = {
        '0.0.0.0': '0.0.0.0 (IPv4)',
        '::': ':: (IPv6)',
    }
    command = run('/sbin/ifconfig', '-a', timeout=15)
    if command.returncode:
        return result
    labels = interface_labels()
    interface = None
    for line in command.stdout.decode(errors='replace').splitlines():
        if line and not line[0].isspace():
            interface = line.split(':', 1)[0]
            continue
        fields = line.split()
        if interface is None or len(fields) < 2 or fields[0] not in ('inet', 'inet6'):
            continue
        value = fields[1].split('%', 1)[0]
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            continue
        if address.is_link_local or address.is_multicast or address.is_unspecified:
            continue
        canonical = str(address)
        label = labels.get(interface, interface)
        result[canonical] = '{} ({})'.format(canonical, label)
    return result


def synchronization_role():
    try:
        value = json.loads(SYNC_SETTINGS.read_text(encoding='utf-8'))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    role = value.get('role')
    return role if role in ('source', 'receiver') else None


def write_candidate(configuration):
    mode = stat.S_IMODE(ADGUARD_CONFIG.stat().st_mode)
    with tempfile.NamedTemporaryFile(dir=ADGUARD_HOME, prefix='.AdGuardHome.yaml.', delete=False) as stream:
        candidate = Path(stream.name)
        content = yaml.safe_dump(configuration, allow_unicode=True, sort_keys=False).encode()
        stream.write(content)
        stream.flush()
        os.fchmod(stream.fileno(), mode)
    return candidate


def binary_path():
    if ADGUARD_BINARY.is_file() and os.access(ADGUARD_BINARY, os.X_OK):
        return ADGUARD_BINARY
    raise RuntimeError('AdGuard Home is not installed.')


def check_candidate(candidate):
    result = run(str(binary_path()), '--config', str(candidate), '--check-config', timeout=30)
    if result.returncode:
        detail = (result.stderr or result.stdout).decode(errors='replace').strip()[-500:]
        raise RuntimeError('AdGuard Home configuration validation failed: ' + detail)


def service(action):
    return run('/usr/sbin/service', 'adguardhome', action, timeout=30)


def is_running():
    result = service('onestatus')
    return result.returncode == 0


def wait_until_running(timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if is_running():
            return True
        time.sleep(0.25)
    return False


def stop_service():
    result = service('onestop')
    if result.returncode and is_running():
        detail = (result.stderr or result.stdout).decode(errors='replace').strip()[-300:]
        raise RuntimeError('Unable to stop AdGuard Home: ' + detail)


def start_service():
    result = service('onestart')
    if result.returncode or not wait_until_running():
        detail = (result.stderr or result.stdout).decode(errors='replace').strip()[-300:]
        raise RuntimeError('AdGuard Home did not start: ' + detail)


def restore(configuration_was_running):
    if is_running():
        service('onestop')
    shutil.copy2(BACKUP_CONFIG, ADGUARD_CONFIG)
    os.chmod(ADGUARD_CONFIG, 0o600)
    if configuration_was_running:
        start_service()


def reconcile_service(enabled):
    running = is_running()
    if enabled and not running:
        start_service()
    elif not enabled and running:
        stop_service()


def apply_unlocked():
    current_yaml, current = read_yaml()
    desired = desired_settings()
    changed = current['bind_hosts'] != desired['bind_hosts'] or current['port'] != desired['port']
    if not changed:
        reconcile_service(desired['enabled'])
        return 'unchanged'

    candidate_yaml = copy.deepcopy(current_yaml)
    candidate_yaml['dns']['bind_hosts'] = desired['bind_hosts']
    candidate_yaml['dns']['port'] = desired['port']
    candidate = write_candidate(candidate_yaml)
    was_running = is_running()
    backup_created = False
    try:
        check_candidate(candidate)
        shutil.copy2(ADGUARD_CONFIG, BACKUP_CONFIG)
        os.chmod(BACKUP_CONFIG, 0o600)
        backup_created = True
        if was_running:
            stop_service()
        candidate.replace(ADGUARD_CONFIG)
        candidate = None
        if desired['enabled']:
            start_service()
        return 'updated'
    except (OSError, RuntimeError, subprocess.TimeoutExpired):
        if backup_created:
            restore(was_running)
        raise
    finally:
        if candidate is not None:
            candidate.unlink(missing_ok=True)


def apply():
    LOCK_PATH.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    with LOCK_PATH.open('w') as stream:
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise RuntimeError('Another configuration operation is already running.') from error
        result = apply_unlocked()
    return {
        'status': result,
        'synchronization_role': synchronization_role(),
    }


def get_settings():
    _, settings = read_yaml()
    return {'status': 'ok', **settings, 'available_hosts': available_addresses()}


def main():
    parser = argparse.ArgumentParser()
    actions = parser.add_mutually_exclusive_group(required=True)
    actions.add_argument('--get', action='store_true')
    actions.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    result = get_settings() if args.get else apply()
    print(json.dumps(result, separators=(',', ':')))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        print(json.dumps({'status': 'failed', 'message': str(error)}, separators=(',', ':')))
        raise SystemExit(1)
