#!/usr/local/bin/python3
"""Exercise the managed AdGuard Home service account derivation and bookkeeping."""

import base64
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / 'src/opnsense/scripts/Adguardhome/api_account.py'
SECRET = 'pairing-secret-' + ('a' * 32)
OTHER_SECRET = 'pairing-secret-' + ('b' * 32)
# A stand-in hash keeps the bookkeeping tests independent of the PHP helper.
FAKE_HASH = '$2y$10$' + ('z' * 53)


def load_module():
    specification = importlib.util.spec_from_file_location('api_account', MODULE_PATH)
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


api_account = load_module()


def document(users):
    """A fragment shaped like AdGuardHome.yaml."""
    return {
        'http': {'address': '127.0.0.1:3000'},
        'users': users,
        'dns': {'bind_hosts': ['0.0.0.0'], 'port': 53},
    }


def test_derivation():
    username, password, salt = api_account.derive_credentials(SECRET)
    assert username == 'opnsense-ha', username
    assert len(password) == 43, password
    assert re.fullmatch(r'[A-Za-z0-9_-]{43}', password), password
    assert len(salt) == 22, salt
    assert re.fullmatch(r'[./A-Za-z0-9]{22}', salt), salt
    # Deterministic for one secret, different for another.
    assert api_account.derive_credentials(SECRET) == (username, password, salt)
    other = api_account.derive_credentials(OTHER_SECRET)
    assert other[1] != password and other[2] != salt, other
    # The password and the salt come from different key material.
    assert base64.urlsafe_b64decode(password + '=') != api_account.hkdf(SECRET, api_account.SALT_INFO)
    assert api_account.hkdf(SECRET, 'a', 48) != api_account.hkdf(SECRET, 'b', 48)
    assert len(api_account.hkdf(SECRET, 'a', 48)) == 48
    assert api_account.hkdf(SECRET, 'a', 48)[:32] == api_account.hkdf(SECRET, 'a')


def php_available():
    return bool(shutil.which('php') or Path('/usr/local/bin/php').is_file())


def test_hash():
    if not php_available():
        print('api_account: PHP is unavailable; the bcrypt helper tests were skipped')
        return
    hashed = api_account.derive_hash(SECRET)
    assert hashed.startswith('$2y$10$') and len(hashed) == 60, hashed
    assert api_account.derive_hash(SECRET) == hashed
    assert api_account.derive_hash(OTHER_SECRET) != hashed
    _username, password, _salt = api_account.derive_credentials(SECRET)
    check = subprocess.run(
        [shutil.which('php') or '/usr/local/bin/php', '-r',
         'echo password_verify($argv[1], $argv[2]) ? "yes" : "no";', '--', password, hashed],
        capture_output=True, timeout=60,
    )
    assert check.returncode == 0, check.stderr
    assert check.stdout.decode().strip() == 'yes', check.stdout
    wrong = subprocess.run(
        [shutil.which('php') or '/usr/local/bin/php', '-r',
         'echo password_verify($argv[1], $argv[2]) ? "yes" : "no";', '--', password + 'x', hashed],
        capture_output=True, timeout=60,
    )
    assert wrong.stdout.decode().strip() == 'no', wrong.stdout
    # Malformed input is refused instead of producing a weak hash.
    helper = subprocess.run(
        [shutil.which('php') or '/usr/local/bin/php', str(api_account.HASH_HELPER)],
        input=json.dumps({'password': 'secret', 'salt': 'too-short'}).encode(),
        capture_output=True, timeout=60,
    )
    assert helper.returncode == 1, helper.stdout


def test_states():
    api_account._HASHES[SECRET] = FAKE_HASH
    admin = {'name': 'admin', 'password': '$2y$10$admin'}
    managed = {'name': 'opnsense-ha', 'password': FAKE_HASH}
    # An instance without administrators needs no authentication at all.
    assert api_account.account_state(document([]), SECRET) == 'none'
    assert api_account.account_state({'users': None}, SECRET) == 'none'
    assert api_account.account_state({}, SECRET) == 'none'
    assert api_account.account_state(document([dict(admin)]), SECRET) == 'missing'
    assert api_account.account_state(document([dict(admin), dict(managed)]), SECRET) == 'present'
    # A name collision with a foreign password is stale, never present.
    collision = document([dict(admin), {'name': 'opnsense-ha', 'password': '$2y$10$someone-else'}])
    assert api_account.account_state(collision, SECRET) == 'stale'


def test_ensure_and_remove():
    api_account._HASHES[SECRET] = FAKE_HASH
    admin = {'name': 'admin', 'password': '$2y$10$admin'}

    # An empty list is never populated; that would lock the web interface.
    empty = document([])
    result, changed = api_account.ensure_account(empty, SECRET)
    assert changed is False and result['users'] == [], result
    assert empty['users'] == []

    installed, changed = api_account.ensure_account(document([dict(admin)]), SECRET)
    assert changed is True, installed
    assert installed['users'] == [admin, {'name': 'opnsense-ha', 'password': FAKE_HASH}], installed
    again, changed = api_account.ensure_account(installed, SECRET)
    assert changed is False and again == installed, again

    # A colliding entry has its password replaced, the other users are kept.
    collision = document([dict(admin), {'name': 'opnsense-ha', 'password': '$2y$10$someone-else'},
                          {'name': 'operator', 'password': '$2y$10$operator'}])
    repaired, changed = api_account.ensure_account(collision, SECRET)
    assert changed is True, repaired
    assert [entry['name'] for entry in repaired['users']] == ['admin', 'opnsense-ha', 'operator']
    assert repaired['users'][1]['password'] == FAKE_HASH, repaired
    assert repaired['users'][0] == admin and repaired['users'][2]['password'] == '$2y$10$operator'
    assert collision['users'][1]['password'] == '$2y$10$someone-else', 'the input was modified'

    removed, changed = api_account.remove_account(repaired)
    assert changed is True, removed
    assert [entry['name'] for entry in removed['users']] == ['admin', 'operator']
    again, changed = api_account.remove_account(removed)
    assert changed is False and again == removed, again
    assert api_account.remove_account({'users': []}) == ({'users': []}, False)


def test_strip():
    api_account._HASHES[SECRET] = FAKE_HASH
    admin = {'name': 'admin', 'password': '$2y$10$admin'}
    source = document([dict(admin)])
    receiver = document([dict(admin), {'name': 'opnsense-ha', 'password': FAKE_HASH}])
    assert api_account.strip_managed(receiver) == source
    assert api_account.strip_managed(source) == source
    assert receiver['users'][1]['name'] == 'opnsense-ha', 'the input was modified'
    assert api_account.strip_managed({'users': 'broken'}) == {'users': 'broken'}


def main():
    test_derivation()
    test_hash()
    test_states()
    test_ensure_and_remove()
    test_strip()
    print('api_account tests passed')


if __name__ == '__main__':
    main()
