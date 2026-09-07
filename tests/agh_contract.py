#!/usr/local/bin/python3
"""Contract test against a real AdGuard Home executable.

The test is skipped unless ADGUARDHOME_BIN points at an AdGuard Home binary:

    ADGUARDHOME_BIN=/usr/local/bin/adguardhome python3 tests/agh_contract.py

It starts the executable in a temporary work directory on loopback high ports,
installs the managed service account the plugin derives from the pairing
secret, changes every mapped configuration key through the REST API and
verifies that the rewritten AdGuardHome.yaml matches the source configuration.
A second scenario confirms that an instance without administrators answers its
API without any credentials at all.
"""

import copy
import functools
import http.server
import importlib.util
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading
import time

import yaml


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / 'src/opnsense/scripts/Adguardhome/agh_api.py'
USER = 'admin'
PASSWORD = 'testpass123'
SECRET = 'contract-pairing-secret-' + ('c' * 32)
# Fallback bcrypt hash of PASSWORD, used when htpasswd is unavailable.
PASSWORD_HASH = '$2y$10$g3l.UgHOgbLsHb0AaIqaiewtcVTmWn25A6cxUo2x6JWd2RffWPHZO'
BLOCK_LIST = '! Title: contract\n||contract-blocked.invalid^\n'
ALLOW_LIST = '! Title: contract allow\n@@||contract-allowed.invalid^\n'


def load_module():
    specification = importlib.util.spec_from_file_location('agh_api', MODULE_PATH)
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def free_port():
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        return probe.getsockname()[1]


def password_hash():
    htpasswd = shutil.which('htpasswd') or '/usr/sbin/htpasswd'
    if not Path(htpasswd).is_file():
        return PASSWORD_HASH
    result = subprocess.run([htpasswd, '-nbB', '-C', '10', USER, PASSWORD], capture_output=True)
    if result.returncode:
        return PASSWORD_HASH
    return result.stdout.decode().strip().split(':', 1)[1]


def seed_configuration(web_port, dns_port, users=None):
    """A minimal configuration; AdGuard Home fills in every other default."""
    return {
        'http': {'address': '127.0.0.1:{}'.format(web_port)},
        'users': [{'name': USER, 'password': password_hash()}] if users is None else users,
        'dns': {'bind_hosts': ['127.0.0.1'], 'port': dns_port},
        'clients': {'persistent': [{'name': 'contract', 'ids': ['192.0.2.77']}]},
        'schema_version': 34,
    }


class QuietFiles(http.server.SimpleHTTPRequestHandler):
    def log_message(self, _format, *_args):
        return


def serve_lists(directory):
    """Serve the filter lists that AdGuard Home downloads when they are added."""
    directory.mkdir(parents=True, exist_ok=True)
    (directory / 'block.txt').write_text(BLOCK_LIST, encoding='utf-8')
    (directory / 'allow.txt').write_text(ALLOW_LIST, encoding='utf-8')
    handler = functools.partial(QuietFiles, directory=str(directory))
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.05}, daemon=True).start()
    return server, 'http://127.0.0.1:{}'.format(server.server_address[1])


def start_adguard(binary, workdir, config_path):
    process = subprocess.Popen(
        [binary, '-c', str(config_path), '-w', str(workdir), '--no-check-update'],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    return process


def stop_adguard(process):
    process.terminate()
    try:
        process.wait(timeout=15)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=15)


def wait_for_api(api, process, timeout=60):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError('AdGuard Home exited with status {}.'.format(process.returncode))
        try:
            api('GET', '/status')
            return
        except RuntimeError:  # any API or transport error means "not ready yet"
            time.sleep(0.5)
    raise RuntimeError('AdGuard Home did not answer on its API.')


def fixture(agh_api, current, list_base, upstream_file):
    """Change every mapped key of the running configuration."""
    document = copy.deepcopy(current)
    values = {
        'dns.upstream_dns': ['1.1.1.1'],
        'dns.upstream_dns_file': str(upstream_file),
        'dns.bootstrap_dns': ['9.9.9.9'],
        'dns.fallback_dns': ['8.8.4.4'],
        'dns.upstream_mode': 'parallel',
        'dns.upstream_timeout': '15s',
        'dns.ratelimit': 25,
        'dns.ratelimit_subnet_len_ipv4': 25,
        'dns.ratelimit_subnet_len_ipv6': 60,
        'dns.ratelimit_whitelist': ['192.0.2.1'],
        'dns.cache_enabled': False,
        'dns.cache_size': 8388608,
        'dns.cache_ttl_min': 60,
        'dns.cache_ttl_max': 3600,
        'dns.cache_optimistic': True,
        'dns.edns_client_subnet.enabled': True,
        'dns.edns_client_subnet.use_custom': True,
        'dns.edns_client_subnet.custom_ip': '192.0.2.9',
        'dns.use_private_ptr_resolvers': False,
        'dns.local_ptr_upstreams': ['192.0.2.53'],
        'dns.aaaa_disabled': True,
        'dns.enable_dnssec': True,
        'dns.anonymize_client_ip': True,
        'dns.allowed_clients': [],
        'dns.disallowed_clients': ['192.0.2.5'],
        'dns.blocked_hosts': ['version.bind', 'contract.invalid'],
        'filtering.protection_enabled': False,
        'filtering.blocking_mode': 'custom_ip',
        'filtering.blocking_ipv4': '192.0.2.10',
        'filtering.blocking_ipv6': '2001:db8::10',
        'filtering.blocked_response_ttl': 20,
        'filtering.filtering_enabled': False,
        'filtering.filters_update_interval': 12,
        'filtering.safebrowsing_enabled': True,
        'filtering.parental_enabled': True,
        'querylog.enabled': False,
        'querylog.interval': '2160h',
        'querylog.ignored': ['ignored.invalid'],
        'statistics.enabled': False,
        'statistics.interval': '72h',
        'statistics.ignored': ['stats.invalid'],
        'user_rules': ['||contract.example^', '@@||allowed.example^'],
        'filtering.rewrites': [{'domain': 'contract.lan', 'answer': '192.0.2.1'}],
        'filtering.blocked_services': {'schedule': {'time_zone': 'Local'}, 'ids': ['tiktok']},
        'filters': [{'enabled': True, 'url': list_base + '/block.txt', 'name': 'contract block'}],
        'whitelist_filters': [{'enabled': True, 'url': list_base + '/allow.txt', 'name': 'contract allow'}],
    }
    for field in agh_api.SAFE_SEARCH_FIELDS:
        values['filtering.safe_search.' + field] = True
    for path, value in values.items():
        agh_api.assign(document, path, value)
    clients = document['clients']['persistent']
    if not clients:
        raise RuntimeError('The seeded persistent client is missing.')
    clients[0]['ids'] = ['192.0.2.78']
    return document


def wait_for_yaml(agh_api, source, config_path, timeout=20):
    deadline = time.monotonic() + timeout
    while True:
        current = yaml.safe_load(config_path.read_text(encoding='utf-8'))
        remaining = agh_api.divergent(source, current)
        if not remaining or time.monotonic() >= deadline:
            return remaining
        time.sleep(0.5)


def install_managed_account(agh_api, binary, workdir, config_path, process, base_url):
    """Install the derived service account the same way --ensure-api-account does."""
    api_account = agh_api.api_account
    current = yaml.safe_load(config_path.read_text(encoding='utf-8'))
    if api_account.account_state(current, SECRET) != 'missing':
        raise RuntimeError('A seeded administrator was not reported as a missing managed account.')
    updated, changed = api_account.ensure_account(current, SECRET)
    if not changed:
        raise RuntimeError('The managed account was not added to the seeded administrators.')
    # AdGuard Home has no API for its users, so the file is written while the
    # service is stopped and the service is restarted afterwards.
    stop_adguard(process)
    config_path.write_text(yaml.safe_dump(updated, sort_keys=False), encoding='utf-8')
    process = start_adguard(binary, workdir, config_path)
    username, password, _salt = api_account.derive_credentials(SECRET)
    managed = agh_api.AdGuardApi(base_url, username, password)
    try:
        wait_for_api(managed, process)
        rewritten = yaml.safe_load(config_path.read_text(encoding='utf-8'))
        if api_account.account_state(rewritten, SECRET) != 'present':
            raise RuntimeError('AdGuard Home did not keep the managed account.')
        # The administrator that was there before still works.
        agh_api.AdGuardApi(base_url, USER, PASSWORD)('GET', '/status')
        # Authentication is really enforced; a wrong password is refused.
        for credentials in ((username, 'wrong-' + password), (None, None)):
            try:
                agh_api.AdGuardApi(base_url, *credentials)('GET', '/status')
            except agh_api.ApiError:
                continue
            raise RuntimeError('The API accepted {}.'.format(
                'no credentials' if credentials[0] is None else 'a wrong password'))
    except BaseException:
        stop_adguard(process)
        raise
    print('agh contract: the managed account and the original administrator both authenticate')
    return process, managed


def run_open_instance(binary):
    """An instance without administrators answers its API without credentials."""
    agh_api = load_module()
    with tempfile.TemporaryDirectory(prefix='adguardhome-contract-open-') as temporary:
        workdir = Path(temporary)
        config_path = workdir / 'AdGuardHome.yaml'
        web_port, dns_port = free_port(), free_port()
        config_path.write_text(yaml.safe_dump(seed_configuration(web_port, dns_port, users=[]), sort_keys=False))
        base_url = 'http://127.0.0.1:{}'.format(web_port)
        process = start_adguard(binary, workdir, config_path)
        try:
            api = agh_api.AdGuardApi(base_url)
            wait_for_api(api, process)
            current = yaml.safe_load(config_path.read_text(encoding='utf-8'))
            if agh_api.api_account.account_state(current, SECRET) != 'none':
                raise RuntimeError('An instance without administrators was not recognized.')
            if not isinstance(api('GET', '/status'), dict):
                raise RuntimeError('The unauthenticated status call returned no document.')
            # Populating the empty list would lock the web interface; it must not happen.
            if agh_api.api_account.ensure_account(current, SECRET)[1]:
                raise RuntimeError('The empty administrator list was populated.')
            print('agh contract: an instance without administrators answers without credentials')
        finally:
            stop_adguard(process)


def run_contract(binary):
    agh_api = load_module()
    with tempfile.TemporaryDirectory(prefix='adguardhome-contract-') as temporary:
        workdir = Path(temporary)
        config_path = workdir / 'AdGuardHome.yaml'
        web_port, dns_port = free_port(), free_port()
        config_path.write_text(yaml.safe_dump(seed_configuration(web_port, dns_port), sort_keys=False))
        upstream_file = workdir / 'upstreams.txt'
        upstream_file.write_text('1.1.1.1\n', encoding='utf-8')
        lists, list_base = serve_lists(workdir / 'lists')
        process = start_adguard(binary, workdir, config_path)
        base_url = 'http://127.0.0.1:{}'.format(web_port)
        api = agh_api.AdGuardApi(base_url, USER, PASSWORD)
        try:
            wait_for_api(api, process)
            process, api = install_managed_account(agh_api, binary, workdir, config_path, process, base_url)
            demoted, warnings = agh_api.self_check(api)
            if demoted:
                raise RuntimeError('The API does not expose every mapped field: {} ({})'.format(
                    sorted(demoted), warnings))
            current = yaml.safe_load(config_path.read_text(encoding='utf-8'))
            source = fixture(agh_api, current, list_base, upstream_file)
            _difference, plan = agh_api.classify(source, current)
            if plan['file']:
                raise RuntimeError('The fixture changed unmapped keys: {}'.format(plan['file']))
            if not plan['hot'] or not plan['reconf']:
                raise RuntimeError('The fixture did not exercise both update classes.')
            agh_api.apply(source, current, api, plan)
            remaining = wait_for_yaml(agh_api, source, config_path)
            if remaining:
                current = yaml.safe_load(config_path.read_text(encoding='utf-8'))
                details = {key: (agh_api.lookup(agh_api.strip_generated(source), key),
                                 agh_api.lookup(agh_api.strip_generated(current), key)) for key in remaining}
                raise RuntimeError('These mapped keys did not converge (source, receiver): {}'.format(details))
            print('agh contract test passed ({} hot, {} batched keys)'.format(
                len(plan['hot']), len(plan['reconf'])))
        finally:
            lists.shutdown()
            lists.server_close()
            stop_adguard(process)


def main():
    binary = os.environ.get('ADGUARDHOME_BIN', '').strip()
    if not binary:
        print('agh contract test skipped; set ADGUARDHOME_BIN to run it')
        return
    if not (Path(binary).is_file() and os.access(binary, os.X_OK)):
        raise SystemExit('ADGUARDHOME_BIN does not point at an executable.')
    run_contract(binary)
    run_open_instance(binary)


if __name__ == '__main__':
    main()
