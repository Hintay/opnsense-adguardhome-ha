#!/usr/local/bin/python3
"""Derive and maintain the managed AdGuard Home API service account.

The API hot update path needs an administrator of the local AdGuard Home web
interface.  Instead of asking the operator for credentials, the plugin derives
a dedicated account from the pairing secret that both nodes already share.

AdGuard Home keeps its administrators in the users list of AdGuardHome.yaml as
bcrypt hashes and offers no API to change them, so installing the account is a
file write followed by a restart.  An empty users list disables authentication
completely; adding an account there would lock the operator out of the web
interface, so the managed entry is only ever placed next to existing
administrators and no other entry is ever touched.
"""

import base64
import copy
import hashlib
import hmac
import json
import os
from pathlib import Path
import shutil
import subprocess


MANAGED_USER = 'opnsense-ha'
PASSWORD_INFO = 'adguardhome-api-password'
SALT_INFO = 'adguardhome-api-salt'
HASH_HELPER = Path(__file__).resolve().parent / 'bcrypt_hash.php'
PHP_BINARY = Path('/usr/local/bin/php')
SALT_LENGTH = 22
HASH_TIMEOUT = 30

# Deriving a hash costs a bcrypt round and a PHP start-up; the pairing secret
# does not change while the daemon runs, so the result is cached in-process.
_HASHES = {}


class AccountError(RuntimeError):
    """The managed service account could not be derived."""


def hkdf(secret, info, length=32):
    """Derive key material from the pairing secret (RFC 5869, SHA-256)."""
    digest_size = hashlib.sha256().digest_size
    if not 1 <= length <= 255 * digest_size:
        raise ValueError('The requested key length is invalid.')
    prk = hmac.new(bytes(digest_size), str(secret).encode(), hashlib.sha256).digest()
    material = b''
    block = b''
    counter = 1
    while len(material) < length:
        block = hmac.new(prk, block + info.encode() + bytes([counter]), hashlib.sha256).digest()
        material += block
        counter += 1
    return material[:length]


def derive_credentials(secret):
    """Return the user name, the password and the bcrypt salt of the account."""
    password = base64.urlsafe_b64encode(hkdf(secret, PASSWORD_INFO)).decode().rstrip('=')
    # bcrypt uses the "./A-Za-z0-9" alphabet, which is base64 with '+' as '.'.
    salt = base64.b64encode(hkdf(secret, SALT_INFO, 16)).decode().replace('+', '.')[:SALT_LENGTH]
    return MANAGED_USER, password, salt


def php_binary():
    if PHP_BINARY.is_file() and os.access(PHP_BINARY, os.X_OK):
        return str(PHP_BINARY)
    found = shutil.which('php')
    if not found:
        raise AccountError('PHP is unavailable; the managed API account cannot be derived.')
    return found


def derive_hash(secret):
    """Return the bcrypt hash AdGuard Home stores for the managed account."""
    if secret in _HASHES:
        return _HASHES[secret]
    _username, password, salt = derive_credentials(secret)
    request = json.dumps({'password': password, 'salt': salt}).encode()
    try:
        result = subprocess.run([php_binary(), str(HASH_HELPER)], input=request,
                                capture_output=True, timeout=HASH_TIMEOUT)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise AccountError('The managed API account hash could not be derived: ' + str(error)) from error
    if result.returncode:
        detail = (result.stderr or result.stdout).decode(errors='replace').strip()[-200:]
        raise AccountError('The managed API account hash could not be derived: ' + detail)
    hashed = result.stdout.decode(errors='replace').strip()
    if not hashed.startswith('$2y$10$') or len(hashed) != 60:
        raise AccountError('The managed API account hash is malformed.')
    _HASHES[secret] = hashed
    return hashed


def users_of(document):
    users = document.get('users') if isinstance(document, dict) else None
    return users if isinstance(users, list) else []


def managed_index(users):
    for index, entry in enumerate(users):
        if isinstance(entry, dict) and entry.get('name') == MANAGED_USER:
            return index
    return -1


def account_state(document, secret):
    """Classify the managed account in an AdGuardHome.yaml document.

    none     the instance has no administrators, so the API needs no credentials
    present  the managed account exists with the derived password
    missing  other administrators exist but the managed account does not
    stale    the managed account exists with a different password
    """
    users = users_of(document)
    if not users:
        return 'none'
    index = managed_index(users)
    if index < 0:
        return 'missing'
    return 'present' if users[index].get('password') == derive_hash(secret) else 'stale'


def ensure_account(document, secret):
    """Return a copy carrying the managed account, and whether it changed."""
    result = copy.deepcopy(document) if isinstance(document, dict) else {}
    users = result.get('users')
    # An empty list means AdGuard Home requires no authentication at all; adding
    # an administrator there would lock the operator out of the web interface.
    if not isinstance(users, list) or not users:
        return result, False
    hashed = derive_hash(secret)
    index = managed_index(users)
    if index < 0:
        users.append({'name': MANAGED_USER, 'password': hashed})
        return result, True
    if isinstance(users[index], dict) and users[index].get('password') == hashed:
        return result, False
    users[index] = {'name': MANAGED_USER, 'password': hashed}
    return result, True


def remove_account(document):
    """Return a copy without the managed account, and whether it changed."""
    result = copy.deepcopy(document) if isinstance(document, dict) else {}
    users = result.get('users')
    if not isinstance(users, list):
        return result, False
    index = managed_index(users)
    if index < 0:
        return result, False
    users.pop(index)
    return result, True


def strip_managed(document):
    """Return a copy where the managed account never counts as a difference."""
    return remove_account(document)[0]
