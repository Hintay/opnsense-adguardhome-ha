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


def result_of(command, timeout=60):
    completed = run(*command, timeout=timeout)
    if completed.returncode:
        detail = (completed.stderr or completed.stdout).decode(errors='replace').strip()[-500:]
        raise RuntimeError(detail or 'The command failed.')
    return completed.stdout.decode(errors='replace').strip()


def render():
    return json.loads(result_of((SETTINGS, '--render')))


def service(action):
    return result_of(('/usr/sbin/service', 'adguardhome_sync', action))


def stop_service():
    """Stop the daemon, tolerating one that is not running (e.g. right after a package upgrade)."""
    completed = run('/usr/sbin/service', 'adguardhome_sync', 'onestop')
    if completed.returncode and run('/usr/sbin/service', 'adguardhome_sync', 'onestatus').returncode == 0:
        detail = (completed.stderr or completed.stdout).decode(errors='replace').strip()[-300:]
        raise RuntimeError(detail or 'Unable to stop the synchronization service.')


def ensure_api_account():
    """Install or withdraw the managed AdGuard Home service account.

    A node that cannot carry the account must not fail the whole apply, so the
    outcome is only reported.
    """
    try:
        # Installing the account stops and starts AdGuard Home once.
        outcome = json.loads(result_of((SYNCD, '--ensure-api-account'), timeout=180))
    except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as error:
        return {'api_account': 'failed', 'api_account_message': str(error)}
    outcome = outcome if isinstance(outcome, dict) else {}
    return {'api_account': outcome.get('status', 'unchanged')}


def apply():
    settings = render()
    result = {'status': 'ok', 'enabled': settings.get('enabled', False), 'role': settings.get('role')}
    # Stop the daemon first: installing the managed account restarts AdGuard
    # Home and must not race with the daemon's start-up push for the lock.
    stop_service()
    # The account is derived from the pairing secret and lives on both nodes,
    # because both apply configuration through their own API; disabling
    # synchronization withdraws it again.
    result.update(ensure_api_account())
    if settings.get('enabled'):
        if settings.get('role') == 'receiver':
            result_of((SYNCD, '--ensure-certificate'))
        service('onestart')
    return result


def apply_pending():
    return json.loads(result_of((SYNCD, '--apply-pending')))


def ensure_account():
    """Install the managed account when this node is not CARP master (CARP hook)."""
    return json.loads(result_of((SYNCD, '--ensure-api-account', '--when-backup'), timeout=180))


def status():
    output = result_of((SYNCD, '--status'))
    response = json.loads(output)
    running = run('/usr/sbin/service', 'adguardhome_sync', 'onestatus').returncode == 0
    response['service_running'] = running
    return response


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=('apply', 'apply_pending', 'ensure_account', 'start', 'restart', 'stop', 'status', 'sync'))
    args = parser.parse_args()
    if args.action == 'apply':
        result = apply()
    elif args.action == 'apply_pending':
        result = apply_pending()
    elif args.action == 'ensure_account':
        result = ensure_account()
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
