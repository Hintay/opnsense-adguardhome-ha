#!/usr/local/bin/python3
"""Apply and control the independent AdGuard Home synchronization service."""

import argparse
import json
import subprocess
import sys


SETTINGS = '/usr/local/opnsense/scripts/Adguardhome/settings.py'
SYNCD = '/usr/local/opnsense/scripts/Adguardhome/syncd.py'


def run(*args, timeout=60):
    return subprocess.run(args, capture_output=True, timeout=timeout)


def result_of(command):
    completed = run(*command)
    if completed.returncode:
        detail = (completed.stderr or completed.stdout).decode(errors='replace').strip()[-500:]
        raise RuntimeError(detail or 'The command failed.')
    return completed.stdout.decode(errors='replace').strip()


def render():
    return json.loads(result_of((SETTINGS, '--render')))


def service(action):
    return result_of(('/usr/sbin/service', 'adguardhome_sync', action))


def apply():
    settings = render()
    if settings.get('enabled'):
        service('onerestart')
        if settings.get('role') == 'receiver':
            result_of((SYNCD, '--ensure-certificate'))
    else:
        service('onestop')
    return {'status': 'ok', 'enabled': settings.get('enabled', False), 'role': settings.get('role')}


def status():
    output = result_of((SYNCD, '--status'))
    response = json.loads(output)
    running = run('/usr/sbin/service', 'adguardhome_sync', 'onestatus').returncode == 0
    response['service_running'] = running
    return response


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=('apply', 'start', 'restart', 'stop', 'status', 'sync'))
    args = parser.parse_args()
    if args.action == 'apply':
        result = apply()
    elif args.action == 'status':
        result = status()
    elif args.action == 'sync':
        result = json.loads(result_of((SYNCD, '--sync')))
    else:
        render()
        service('one' + args.action)
        result = status()
    print(json.dumps(result, separators=(',', ':')))


if __name__ == '__main__':
    try:
        main()
    except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as error:
        print(json.dumps({'status': 'failed', 'message': str(error)}), file=sys.stderr)
        raise SystemExit(1)
