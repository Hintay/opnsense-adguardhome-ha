#!/usr/local/bin/python3
"""Exercise the synchronization protocol without touching the installed service."""

import hashlib
import importlib.util
import json
from pathlib import Path
import ssl
import subprocess
import tempfile
import threading
import time

import yaml


SYNC_MODULE = Path(__file__).resolve().parents[1] / 'src/opnsense/scripts/Adguardhome/syncd.py'
# A stand-in for the derived bcrypt hash; the derivation itself is covered by
# tests/api_account.py and does not need the PHP helper here.
MANAGED_HASH = '$2y$10$' + ('m' * 53)


def load_module():
    spec = importlib.util.spec_from_file_location('syncd', SYNC_MODULE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def receiver_config():
    """A configuration shaped like AdGuardHome.yaml, as the receiver stores it."""
    return {
        'http': {'address': '10.0.2.2:3000', 'session_ttl': '720h'},
        'users': [{'name': 'admin', 'password': '$2y$10$hash'}],
        'dns': {
            'bind_hosts': ['127.0.0.1'],
            'port': 5353,
            'upstream_dns': ['9.9.9.9'],
            'allowed_clients': [],
            'disallowed_clients': [],
            'blocked_hosts': [],
        },
        'filtering': {'filtering_enabled': True, 'filters_update_interval': 24},
        'user_rules': ['||one.example.invalid^'],
        'filters': [],
        'whitelist_filters': [],
        'clients': {'runtime_sources': {'arp': True}, 'persistent': []},
        'querylog': {'dir_path': '/var/log/receiver', 'enabled': True, 'interval': '24h', 'ignored': []},
        'statistics': {'dir_path': '', 'enabled': True, 'interval': '24h', 'ignored': []},
        'log': {'verbose': False},
        'os': {'user': ''},
        'schema_version': 34,
    }


def sync_protocol_test(syncd, root):
    """The original end to end exchange with a stubbed apply step."""
    receiver_path = root / 'receiver-AdGuardHome.yaml'
    receiver_path.write_text('old: configuration\n')
    syncd.ADGUARD_CONFIG.write_text('old: configuration\n')

    def apply_to_receiver(content, _settings=None):
        if receiver_path.read_bytes() == content:
            return 'unchanged'
        receiver_path.write_bytes(content)
        return 'updated'

    original_apply = syncd.apply_received_config
    syncd.apply_received_config = apply_to_receiver
    shared_secret = 'test-secret-' + ('x' * 48)
    receiver = {
        'enabled': True,
        'role': 'receiver',
        'listen_address': '127.0.0.1',
        'peer_address': '127.0.0.1',
        'port': 19443,
        'secret': shared_secret,
    }
    thread = threading.Thread(target=syncd.serve, args=(receiver,), daemon=True)
    thread.start()
    time.sleep(0.25)
    source = {
        'enabled': True,
        'role': 'source',
        'listen_address': '127.0.0.1',
        'peer_address': '127.0.0.1',
        'port': 19443,
        'secret': shared_secret,
        'peer_fingerprint': syncd.certificate_fingerprint(),
    }
    syncd.ADGUARD_CONFIG.write_text('new: configuration\n')
    if syncd.push_once(source) != 'updated':
        raise RuntimeError('The peer did not report an update.')
    if receiver_path.read_text() != 'new: configuration\n':
        raise RuntimeError('The received configuration was not applied.')
    if syncd.push_once(source) != 'unchanged':
        raise RuntimeError('The peer did not recognize an unchanged configuration.')
    rejected = dict(source)
    rejected['secret'] = 'wrong-secret-' + ('x' * 48)
    try:
        syncd.push_once(rejected)
    except RuntimeError:
        pass
    else:
        raise RuntimeError('The receiver accepted an incorrect pairing secret.')
    learned = dict(source)
    learned['peer_fingerprint'] = ''
    if syncd.push_once(learned) != 'unchanged':
        raise RuntimeError('The source did not learn the peer certificate fingerprint.')
    if syncd.read_state().get('learned_fingerprint') != source['peer_fingerprint']:
        raise RuntimeError('The learned certificate fingerprint was not stored.')
    syncd.apply_received_config = original_apply


def apply_settings(**overrides):
    settings = {
        'enabled': True,
        'role': 'receiver',
        'listen_address': '10.0.2.2',
        'peer_address': '10.0.2.1',
        'port': 19443,
        'secret': 'test-secret-' + ('x' * 48),
        'api_username': 'admin',
        'api_password': 'password',
        'hot_update': True,
        'defer_while_master': False,
    }
    settings.update(overrides)
    return settings


def payload_of(document):
    return yaml.safe_dump(document, sort_keys=False, allow_unicode=True).encode()


def prepare_receiver(syncd, checks):
    syncd.ADGUARD_CONFIG.write_bytes(payload_of(receiver_config()))
    syncd.STATE_PATH.unlink(missing_ok=True)
    syncd.PENDING_CONFIG.unlink(missing_ok=True)
    syncd.BASE_PATH_RECEIVER.unlink(missing_ok=True)
    syncd.BASE_PATH_SOURCE.unlink(missing_ok=True)
    checks.clear()


def apply_pipeline_test(syncd, root):
    """The receiver decision pipeline: unchanged, hot fallback, staging."""
    checks = []
    syncd.check_config = lambda path: checks.append(path)
    syncd.wait_for_listeners = lambda *args, **kwargs: True
    syncd.API_STATE.update({'ready': True, 'demoted': frozenset()})
    settings = apply_settings()
    agh_api = syncd.agh_api

    # A payload that was applied before is recognized by its digest alone.
    prepare_receiver(syncd, checks)
    payload = payload_of(receiver_config())
    syncd.write_state(last_applied_sha256=hashlib.sha256(payload).hexdigest())
    if syncd.apply_received_config(payload, settings) != 'unchanged':
        raise RuntimeError('A known digest was not recognized.')
    if checks:
        raise RuntimeError('A known digest still ran the configuration validator.')

    # Only node-local differences are never applied.
    prepare_receiver(syncd, checks)
    local_only = receiver_config()
    local_only['http']['address'] = '10.0.2.1:3000'
    local_only['dns']['bind_hosts'] = ['10.0.2.1']
    local_only['querylog']['dir_path'] = '/var/log/source'
    if syncd.apply_received_config(payload_of(local_only), settings) != 'unchanged':
        raise RuntimeError('A node-local difference was applied.')
    if checks:
        raise RuntimeError('A node-local difference ran the configuration validator.')

    # A hot change that does not converge falls back to the file route.
    prepare_receiver(syncd, checks)
    document = receiver_config()
    document['user_rules'] = ['||two.example.invalid^']
    document['http']['address'] = '10.0.2.1:3000'
    document['dns']['bind_hosts'] = ['10.0.2.1']
    original_apply = agh_api.apply
    calls = []
    agh_api.apply = lambda *args, **kwargs: calls.append(args)
    syncd.CONVERGENCE_SECONDS = 0
    try:
        outcome = syncd.apply_received_config(payload_of(document), settings)
    finally:
        agh_api.apply = original_apply
    if outcome != 'updated':
        raise RuntimeError('The hot update did not fall back to the file route: ' + outcome)
    if not calls:
        raise RuntimeError('The hot update was never attempted.')
    installed = yaml.safe_load(syncd.ADGUARD_CONFIG.read_text())
    if installed['user_rules'] != ['||two.example.invalid^']:
        raise RuntimeError('The file route did not install the received rules.')
    if installed['http']['address'] != '10.0.2.2:3000' or installed['dns']['bind_hosts'] != ['127.0.0.1']:
        raise RuntimeError('The file route did not preserve the node-local settings.')
    if not syncd.BACKUP_CONFIG.is_file():
        raise RuntimeError('The file route did not create a backup.')
    state = syncd.read_state()
    if state['last_result'] != 'updated' or not state['last_applied_sha256']:
        raise RuntimeError('The file route did not record its result.')
    if syncd.apply_received_config(payload_of(document), settings) != 'unchanged':
        raise RuntimeError('An applied payload was not recognized on the next push.')

    # The same difference is adopted through the API when it converges.
    prepare_receiver(syncd, checks)
    converging = receiver_config()
    converging['user_rules'] = ['||three.example.invalid^']

    def converge(source, current, api, plan):
        syncd.ADGUARD_CONFIG.write_bytes(payload_of(source))

    agh_api.apply = converge
    try:
        outcome = syncd.apply_received_config(payload_of(converging), settings)
    finally:
        agh_api.apply = original_apply
    if outcome != 'hot':
        raise RuntimeError('A converging update was not reported as hot: ' + outcome)
    if checks:
        raise RuntimeError('The hot route ran the configuration validator.')
    if syncd.read_state()['last_result'] != 'hot':
        raise RuntimeError('The hot route did not record its result.')


def staging_test(syncd, root):
    """A CARP master stages the configuration until it becomes backup."""
    checks = []
    syncd.check_config = lambda path: checks.append(path)
    syncd.wait_for_listeners = lambda *args, **kwargs: True
    syncd.API_STATE.update({'ready': False, 'demoted': frozenset()})
    settings = apply_settings(defer_while_master=True, api_username='', api_password='')
    prepare_receiver(syncd, checks)
    syncd.carp_master = lambda document: True
    document = receiver_config()
    document['dns']['upstream_dns'] = ['1.1.1.1']
    before = syncd.ADGUARD_CONFIG.read_bytes()
    if syncd.apply_received_config(payload_of(document), settings) != 'staged':
        raise RuntimeError('The configuration was not staged while this node is master.')
    if syncd.ADGUARD_CONFIG.read_bytes() != before:
        raise RuntimeError('A staged configuration replaced the active file.')
    if not syncd.PENDING_CONFIG.is_file():
        raise RuntimeError('The staged configuration was not written.')
    if syncd.read_state()['last_result'] != 'staged':
        raise RuntimeError('The staged result was not recorded.')
    if syncd.apply_pending(settings) != 'updated':
        raise RuntimeError('The staged configuration was not applied.')
    if syncd.PENDING_CONFIG.exists():
        raise RuntimeError('The staged configuration was not removed.')
    installed = yaml.safe_load(syncd.ADGUARD_CONFIG.read_text())
    if installed['dns']['upstream_dns'] != ['1.1.1.1']:
        raise RuntimeError('The staged configuration was not installed.')
    if syncd.apply_pending(settings) != 'unchanged':
        raise RuntimeError('An empty staging area reported work.')
    syncd.carp_master = lambda document: False


def managed_account_test(syncd, root):
    """The managed service account is installed, preserved and withdrawn."""
    checks = []
    syncd.check_config = lambda path: checks.append(path)
    syncd.wait_for_listeners = lambda *args, **kwargs: True
    # Keep the API self-check from probing a local AdGuard Home that is absent.
    syncd.API_STATE.update({'ready': False, 'demoted': frozenset(), 'checked_at': time.monotonic()})
    api_account = syncd.api_account
    settings = apply_settings(api_username='', api_password='')
    secret = settings['secret']
    api_account._HASHES[secret] = MANAGED_HASH
    prepare_receiver(syncd, checks)

    if syncd.api_mode(settings) != 'managed' or not syncd.api_configured(settings):
        raise RuntimeError('An empty credential pair did not select the managed account.')
    if syncd.api_mode(apply_settings()) != 'manual':
        raise RuntimeError('Configured credentials did not override the managed account.')
    current = syncd.read_config(syncd.ADGUARD_CONFIG)
    if api_account.account_state(current, secret) != 'missing':
        raise RuntimeError('The seeded receiver already carries a managed account.')
    try:
        syncd.resolve_api_credentials(settings, current)
    except syncd.ApiAccountUnavailable:
        pass
    else:
        raise RuntimeError('An uninstalled account was reported as usable.')

    if syncd.ensure_api_account(settings)['status'] != 'updated':
        raise RuntimeError('The managed account was not installed.')
    installed = syncd.read_config(syncd.ADGUARD_CONFIG)
    if api_account.account_state(installed, secret) != 'present':
        raise RuntimeError('The installed configuration has no managed account.')
    if [entry['name'] for entry in installed['users']] != ['admin', 'opnsense-ha']:
        raise RuntimeError('The managed account did not join the existing administrators.')
    username, password = syncd.resolve_api_credentials(settings, installed)
    if (username, password) != api_account.derive_credentials(secret)[:2]:
        raise RuntimeError('The derived credentials were not used.')
    if syncd.ensure_api_account(settings)['status'] != 'unchanged':
        raise RuntimeError('An installed account was written again.')

    # A file replacement from the source must not remove the account again.
    document = receiver_config()
    document['user_rules'] = ['||four.example.invalid^']
    if syncd.apply_received_config(payload_of(document), settings) != 'updated':
        raise RuntimeError('The file route did not install the received configuration.')
    replaced = syncd.read_config(syncd.ADGUARD_CONFIG)
    if api_account.account_state(replaced, secret) != 'present':
        raise RuntimeError('The file route dropped the managed account.')
    if replaced['user_rules'] != ['||four.example.invalid^']:
        raise RuntimeError('The file route did not install the received rules.')
    if syncd.agh_api.divergent(document, replaced):
        raise RuntimeError('The managed account counts as a difference.')

    # An instance without administrators is never given one.
    open_document = syncd.read_config(syncd.ADGUARD_CONFIG)
    open_document['users'] = []
    if api_account.account_state(open_document, secret) != 'none':
        raise RuntimeError('An instance without administrators was not recognized.')
    if syncd.resolve_api_credentials(settings, open_document) != (None, None):
        raise RuntimeError('An unauthenticated instance was given credentials.')
    if api_account.ensure_account(open_document, secret)[1]:
        raise RuntimeError('An empty administrator list was populated.')

    # Manual credentials, a disabled API path and disabled synchronization all
    # withdraw the account again.
    for withdrawn in (apply_settings(), apply_settings(api_username='', api_password='', hot_update=False),
                      {'enabled': False}):
        syncd.ensure_api_account(settings)
        if syncd.ensure_api_account(withdrawn)['status'] != 'removed':
            raise RuntimeError('The managed account was not withdrawn: ' + str(withdrawn))
        if api_account.account_state(syncd.read_config(syncd.ADGUARD_CONFIG), secret) != 'missing':
            raise RuntimeError('The withdrawn account is still installed.')
        if syncd.ensure_api_account(withdrawn)['status'] != 'unchanged':
            raise RuntimeError('An absent account was withdrawn twice.')
    # The source applies what it adopts from the receiver through its own API,
    # so it carries the account as well.
    if syncd.ensure_api_account(apply_settings(role='source', api_username='',
                                               api_password=''))['status'] != 'updated':
        raise RuntimeError('The synchronization source did not install the managed account.')
    if api_account.account_state(syncd.read_config(syncd.ADGUARD_CONFIG), secret) != 'present':
        raise RuntimeError('The managed account is missing on the source.')


def restore_test(syncd, root):
    """A standby that does not answer after the update gets its backup back."""
    checks = []
    syncd.check_config = lambda path: checks.append(path)
    syncd.API_STATE.update({'ready': False, 'demoted': frozenset()})
    settings = apply_settings(api_username='', api_password='')
    prepare_receiver(syncd, checks)
    before = syncd.ADGUARD_CONFIG.read_bytes()
    probes = []

    def listeners(targets, expected=True, timeout=None):
        probes.append(expected)
        # The stop probe succeeds, the first liveness probe fails, the restore recovers.
        return expected is False or probes.count(True) > 1

    syncd.wait_for_listeners = listeners
    document = receiver_config()
    document['dns']['upstream_dns'] = ['8.8.8.8']
    try:
        syncd.apply_received_config(payload_of(document), settings)
    except syncd.ApplyFailure as error:
        if error.status != 'failed':
            raise RuntimeError('An unexpected failure status: ' + error.status)
    else:
        raise RuntimeError('A dead standby was reported as updated.')
    if syncd.ADGUARD_CONFIG.read_bytes() != before:
        raise RuntimeError('The previous configuration was not restored.')
    syncd.wait_for_listeners = lambda *args, **kwargs: True


IFCONFIG = """igb0: flags=8963<UP,BROADCAST,RUNNING> metric 0 mtu 1500
	ether 00:11:22:33:44:55
	inet 192.168.1.2 netmask 0xffffff00 broadcast 192.168.1.255
	inet 192.168.1.1 netmask 0xffffff00 broadcast 192.168.1.255 vhid 1
	inet6 fd00::1 prefixlen 64 vhid 1
	carp: MASTER vhid 1 advbase 1 advskew 0
igb1: flags=8843<UP,BROADCAST,RUNNING> metric 0 mtu 1500
	inet 10.0.0.1 netmask 0xffffff00 broadcast 10.0.0.255 vhid 2
	carp: BACKUP vhid 2 advbase 1 advskew 100
"""


def carp_parser_test(syncd):
    masters = syncd.parse_carp_master_addresses(IFCONFIG)
    if masters != {'192.168.1.1', 'fd00::1'}:
        raise RuntimeError('The CARP master addresses were not recognized: ' + str(masters))


def local_changes_test(syncd, root):
    """Only the newest copies of an overwritten configuration are kept."""
    for stale in syncd.ADGUARD_HOME.glob(syncd.LOCAL_CHANGES_PREFIX + '*'):
        stale.unlink()
    syncd.ADGUARD_CONFIG.write_bytes(payload_of(receiver_config()))
    for index in range(8):
        (syncd.ADGUARD_HOME / (syncd.LOCAL_CHANGES_PREFIX + '20260101-0000{:02d}'.format(index))).write_bytes(b'old')
    kept = syncd.keep_local_changes()
    remaining = sorted(path.name for path in syncd.ADGUARD_HOME.glob(syncd.LOCAL_CHANGES_PREFIX + '*'))
    if len(remaining) != syncd.LOCAL_CHANGES_KEEP:
        raise RuntimeError('The overwritten configurations were not pruned: ' + str(remaining))
    if kept.name not in remaining or kept.read_bytes() != syncd.ADGUARD_CONFIG.read_bytes():
        raise RuntimeError('The running configuration was not copied aside.')
    if kept.stat().st_mode & 0o777 != 0o600:
        raise RuntimeError('The copy of the overwritten configuration is not private.')


def source_master_test(syncd):
    """A source without a CARP bind host always wins a conflict."""
    original_run = syncd.run
    original_master = syncd.carp_master
    syncd.run = lambda *args, **kwargs: subprocess.CompletedProcess(args, 0, IFCONFIG.encode(), b'')
    asked = []
    syncd.carp_master = lambda document: asked.append(document) or False
    try:
        if not syncd.source_is_master({'dns': {'bind_hosts': ['10.0.0.7']}}):
            raise RuntimeError('A source without a CARP address lost the conflict.')
        if asked:
            raise RuntimeError('A source without a CARP address consulted the CARP state.')
        if syncd.source_is_master({'dns': {'bind_hosts': ['10.0.0.1']}}):
            raise RuntimeError('A source on a backup CARP address won the conflict.')
        syncd.carp_master = lambda document: True
        if not syncd.source_is_master({'dns': {'bind_hosts': ['192.168.1.1']}}):
            raise RuntimeError('A source on a master CARP address lost the conflict.')
    finally:
        syncd.run = original_run
        syncd.carp_master = original_master


def node(root, name):
    """One fully isolated syncd instance standing in for a single node."""
    module = load_module()
    home = root / name
    home.mkdir()
    module.ADGUARD_HOME = home
    module.ADGUARD_CONFIG = home / 'AdGuardHome.yaml'
    module.BACKUP_CONFIG = home / 'AdGuardHome.yaml.before-sync'
    module.PENDING_CONFIG = home / 'AdGuardHome.yaml.pending'
    module.BASE_PATH_RECEIVER = home / 'AdGuardHome.yaml.last-source'
    module.BASE_PATH_SOURCE = home / 'AdGuardHome.yaml.last-pushed'
    module.ADGUARD_BINARY = home / 'AdGuardHome'
    module.CERTIFICATE_PATH = home / 'receiver.pem'
    module.LOCK_PATH = home / 'sync.lock'
    module.STATE_PATH = home / 'state.json'
    module.MODEL_SETTINGS_PATH = home / 'opnsense.json'
    module.MODEL_SETTINGS_PATH.write_text(json.dumps({'general': {'enabled': True}}))
    module.check_config = lambda path: None
    module.wait_for_listeners = lambda *args, **kwargs: True
    module.carp_master = lambda document: False
    module.API_STATE.update({'ready': False, 'demoted': frozenset(), 'checked_at': time.monotonic()})
    original_run = module.run

    def fake_run(*args, **kwargs):
        if args[:2] == ('/usr/sbin/service', 'adguardhome'):
            return subprocess.CompletedProcess(args, 0, b'', b'')
        return original_run(*args, **kwargs)

    module.run = fake_run
    return module


def serve_receiver(module, settings):
    """Start the real TLS receiver of one node on an ephemeral port."""
    subprocess.run([
        '/usr/bin/openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-nodes', '-days', '1',
        '-subj', '/CN=sync-test', '-addext', 'subjectAltName=IP:127.0.0.1',
        '-keyout', str(module.CERTIFICATE_PATH), '-out', str(module.CERTIFICATE_PATH),
    ], check=True, capture_output=True)
    server = module.SyncServer((settings['listen_address'], 0), module.Receiver)
    server.settings = settings
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(str(module.CERTIFICATE_PATH))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    settings['port'] = server.server_address[1]
    threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.05}, daemon=True).start()
    return server


def node_config(address, log_directory, rules):
    """The same configuration as the peer, with this node's own local keys."""
    document = receiver_config()
    document['http']['address'] = address + ':3000'
    document['dns']['bind_hosts'] = [address]
    document['querylog']['dir_path'] = log_directory
    document['user_rules'] = rules
    return document


def source_config(rules):
    return node_config('10.0.2.1', '/var/log/source', rules)


def receiver_config_with(rules):
    return node_config('10.0.2.2', '/var/log/receiver', rules)


def seed(source, receiver, base, ours, theirs):
    """Put both nodes into a known state before one push."""
    for module in (source, receiver):
        module.STATE_PATH.unlink(missing_ok=True)
        module.PENDING_CONFIG.unlink(missing_ok=True)
        module.BASE_PATH_SOURCE.unlink(missing_ok=True)
        module.BASE_PATH_RECEIVER.unlink(missing_ok=True)
        for stale in module.ADGUARD_HOME.glob(module.LOCAL_CHANGES_PREFIX + '*'):
            stale.unlink()
    source.ADGUARD_CONFIG.write_bytes(payload_of(ours))
    receiver.ADGUARD_CONFIG.write_bytes(payload_of(theirs))
    if base is not None:
        source.BASE_PATH_SOURCE.write_bytes(payload_of(base))
        receiver.BASE_PATH_RECEIVER.write_bytes(payload_of(base))


def rules_of(module):
    return yaml.safe_load(module.ADGUARD_CONFIG.read_text())['user_rules']


def local_changes(module):
    return sorted(module.ADGUARD_HOME.glob(module.LOCAL_CHANGES_PREFIX + '*'))


BASE_RULES = ['||base.example.invalid^']
SOURCE_RULES = ['||source.example.invalid^']
RECEIVER_RULES = ['||receiver.example.invalid^']


def adoption_test(source, receiver, settings):
    """The receiver changed the configuration alone, so the source adopts it."""
    base = source_config(BASE_RULES)
    seed(source, receiver, base, base, receiver_config_with(RECEIVER_RULES))
    source.source_is_master = lambda document: True
    receiver.carp_master = lambda document: True
    status = source.push_once(settings)
    if status != 'unchanged':
        raise RuntimeError('The adopted configuration was pushed as a change: ' + status)
    if rules_of(source) != RECEIVER_RULES:
        raise RuntimeError('The receiver rules were not adopted: ' + str(rules_of(source)))
    state = source.read_state()
    if state.get('last_adopted', {}).get('keys') != ['user_rules']:
        raise RuntimeError('The adoption was not recorded: ' + str(state.get('last_adopted')))
    if state.get('last_conflict') or state.get('peer_carp_master') is not True:
        raise RuntimeError('The peer state was not recorded: ' + str(state))
    installed = yaml.safe_load(source.ADGUARD_CONFIG.read_text())
    if installed['dns']['bind_hosts'] != ['10.0.2.1'] or installed['querylog']['dir_path'] != '/var/log/source':
        raise RuntimeError('The adoption replaced the node-local settings of the source.')
    if source.BASE_PATH_SOURCE.read_bytes() != source.ADGUARD_CONFIG.read_bytes():
        raise RuntimeError('The pushed payload was not stored as the new base.')
    if receiver.read_state().get('last_overwritten') or local_changes(receiver):
        raise RuntimeError('The receiver backed up a configuration it kept.')
    receiver.carp_master = lambda document: False


def conflict_test(source, receiver, settings, source_master):
    """Both nodes changed the same leaf; the CARP master wins."""
    seed(source, receiver, source_config(BASE_RULES), source_config(SOURCE_RULES),
         receiver_config_with(RECEIVER_RULES))
    before = receiver.ADGUARD_CONFIG.read_bytes()
    source.source_is_master = lambda document: source_master
    status = source.push_once(settings)
    state = source.read_state()
    conflict = state.get('last_conflict') or {}
    if conflict.get('keys') != ['user_rules']:
        raise RuntimeError('The conflict was not recorded: ' + str(conflict))
    if conflict.get('winner') != ('source' if source_master else 'receiver'):
        raise RuntimeError('The wrong side won the conflict: ' + str(conflict))
    if state.get('last_adopted'):
        raise RuntimeError('A conflict was reported as an adoption.')
    if source_master:
        if status != 'updated':
            raise RuntimeError('The winning source did not update the receiver: ' + status)
        if rules_of(source) != SOURCE_RULES or rules_of(receiver) != SOURCE_RULES:
            raise RuntimeError('The source value did not win.')
        overwritten = receiver.read_state().get('last_overwritten') or {}
        if overwritten.get('keys') != ['user_rules']:
            raise RuntimeError('The receiver did not record the overwritten keys: ' + str(overwritten))
        backup = Path(overwritten.get('backup') or '')
        if local_changes(receiver) != [backup] or backup.read_bytes() != before:
            raise RuntimeError('The receiver did not keep its own configuration.')
        return
    if status != 'unchanged':
        raise RuntimeError('The receiver value was pushed back as a change: ' + status)
    if rules_of(source) != RECEIVER_RULES or rules_of(receiver) != RECEIVER_RULES:
        raise RuntimeError('The receiver value did not win.')
    if receiver.read_state().get('last_overwritten') or local_changes(receiver):
        raise RuntimeError('The receiver backed up a configuration it kept.')


def first_push_test(source, receiver, settings):
    """Without a base document nothing is adopted and the base is written."""
    seed(source, receiver, None, source_config(SOURCE_RULES), receiver_config_with(RECEIVER_RULES))
    source.source_is_master = lambda document: False
    status = source.push_once(settings)
    if status != 'updated':
        raise RuntimeError('The first push did not update the receiver: ' + status)
    state = source.read_state()
    if state.get('last_adopted') or state.get('last_conflict'):
        raise RuntimeError('A push without a base adopted something.')
    if rules_of(source) != SOURCE_RULES or rules_of(receiver) != SOURCE_RULES:
        raise RuntimeError('The first push did not replace the receiver configuration.')
    if source.BASE_PATH_SOURCE.read_bytes() != source.ADGUARD_CONFIG.read_bytes():
        raise RuntimeError('The first push did not store a base document.')
    if receiver.BASE_PATH_RECEIVER.read_bytes() != source.ADGUARD_CONFIG.read_bytes():
        raise RuntimeError('The receiver did not store the applied payload as its base.')
    if local_changes(receiver):
        raise RuntimeError('A push without a base copied the receiver configuration aside.')


def old_receiver_test(source, receiver, settings):
    """A receiver without GET /v1/config is pushed to exactly as before."""
    base = source_config(BASE_RULES)
    seed(source, receiver, base, base, receiver_config_with(RECEIVER_RULES))
    source.source_is_master = lambda document: False
    original = receiver.Receiver.send_config
    receiver.Receiver.send_config = lambda self: self.respond(404, {'status': 'failed', 'message': 'Not found.'})
    try:
        status = source.push_once(settings)
    finally:
        receiver.Receiver.send_config = original
    if status != 'updated':
        raise RuntimeError('The push to an old receiver failed: ' + status)
    if rules_of(source) != BASE_RULES:
        raise RuntimeError('An unreadable peer configuration still changed the source.')
    state = source.read_state()
    if state.get('last_adopted') or state.get('last_conflict'):
        raise RuntimeError('An unreadable peer configuration was merged.')
    if state.get('peer_carp_master') is not None:
        raise RuntimeError('An unread peer reported a CARP state: ' + str(state.get('peer_carp_master')))
    # The receiver still protects the changes such a source overwrites.
    overwritten = receiver.read_state().get('last_overwritten') or {}
    if overwritten.get('keys') != ['user_rules'] or not local_changes(receiver):
        raise RuntimeError('The receiver did not protect its local changes: ' + str(overwritten))


def staged_peer_test(source, receiver, settings, receiver_settings):
    """A payload the receiver only staged is not the agreed base yet."""
    base = source_config(BASE_RULES)
    seed(source, receiver, base, source_config(SOURCE_RULES), receiver_config_with(BASE_RULES))
    source.source_is_master = lambda document: True
    receiver.carp_master = lambda document: True
    receiver_settings['defer_while_master'] = True
    try:
        if source.push_once(settings) != 'staged':
            raise RuntimeError('The receiver did not stage the pushed configuration.')
        if source.BASE_PATH_SOURCE.read_bytes() != payload_of(base):
            raise RuntimeError('A staged payload was stored as the agreed base.')
        if not receiver.PENDING_CONFIG.is_file() or rules_of(receiver) != BASE_RULES:
            raise RuntimeError('The staged payload was applied right away.')
        # The next round must not adopt the configuration the receiver still runs.
        if source.push_once(settings) != 'staged':
            raise RuntimeError('The second push was not staged as well.')
        if rules_of(source) != SOURCE_RULES or source.read_state().get('last_adopted'):
            raise RuntimeError('The source reverted to the configuration the receiver still runs.')
        if receiver.apply_pending(receiver_settings) != 'updated':
            raise RuntimeError('The staged payload was not installed.')
        if rules_of(receiver) != SOURCE_RULES:
            raise RuntimeError('The installed payload is not the pushed one.')
        if source.push_once(settings) != 'unchanged':
            raise RuntimeError('The installed payload was pushed again as a change.')
        if source.BASE_PATH_SOURCE.read_bytes() != source.ADGUARD_CONFIG.read_bytes():
            raise RuntimeError('The agreed base was not stored after the receiver caught up.')
    finally:
        receiver_settings['defer_while_master'] = False
        receiver.carp_master = lambda document: False


def merge_tests(root):
    """Two independent nodes exchanging configuration over the real protocol."""
    source = node(root, 'source')
    receiver = node(root, 'receiver')
    shared_secret = 'merge-secret-' + ('x' * 48)
    receiver_settings = {
        'enabled': True,
        'role': 'receiver',
        'listen_address': '127.0.0.1',
        'peer_address': '127.0.0.1',
        'port': 0,
        'secret': shared_secret,
        'hot_update': False,
        'defer_while_master': False,
    }
    receiver.ADGUARD_CONFIG.write_bytes(payload_of(receiver_config_with(RECEIVER_RULES)))
    server = serve_receiver(receiver, receiver_settings)
    source_settings = dict(receiver_settings, role='source', port=receiver_settings['port'],
                           peer_fingerprint=receiver.certificate_fingerprint())
    try:
        adoption_test(source, receiver, source_settings)
        conflict_test(source, receiver, source_settings, True)
        conflict_test(source, receiver, source_settings, False)
        first_push_test(source, receiver, source_settings)
        old_receiver_test(source, receiver, source_settings)
        staged_peer_test(source, receiver, source_settings, receiver_settings)
    finally:
        server.shutdown()
        server.server_close()


def lock_wait_test(syncd):
    """A waiting caller serializes behind the lock; a non-waiting one fails."""
    import fcntl
    holder = syncd.LOCK_PATH.open('w')
    fcntl.flock(holder, fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        try:
            syncd.acquire_lock(lambda: 'ran')
        except RuntimeError as error:
            assert 'already running' in str(error)
        else:
            raise AssertionError('a non-waiting caller acquired a held lock')
        threading.Timer(0.8, lambda: fcntl.flock(holder, fcntl.LOCK_UN)).start()
        started = time.monotonic()
        assert syncd.acquire_lock(lambda: 'ran', wait=5) == 'ran'
        assert time.monotonic() - started >= 0.5
    finally:
        holder.close()


def deferred_account_test(syncd, root):
    """only_when_backup defers the install while this node is CARP master."""
    secret = 'deferred-secret-' + ('d' * 40)
    settings = {'enabled': True, 'role': 'receiver', 'secret': secret, 'hot_update': True,
                'api_username': '', 'api_password': ''}
    syncd.ADGUARD_CONFIG.write_text('users:\n  - name: admin\n    password: $2y$05$x\ndns:\n  bind_hosts:\n    - 192.0.2.8\n  port: 53\n')
    installed = []
    original_install = syncd.install_document
    syncd.install_document = lambda document: installed.append(document)
    original_master = syncd.carp_master
    # The gating logic is independent of bcrypt; do not require PHP here.
    original_hash = syncd.api_account.derive_hash
    syncd.api_account.derive_hash = lambda secret: '$2y$10$' + ('h' * 53)
    try:
        syncd.carp_master = lambda document: True
        outcome = syncd.ensure_api_account(settings, only_when_backup=True)
        assert outcome['status'] == 'deferred' and not installed, outcome
        syncd.carp_master = lambda document: False
        outcome = syncd.ensure_api_account(settings, only_when_backup=True)
        assert outcome['status'] == 'updated' and len(installed) == 1, outcome
        syncd.carp_master = lambda document: True
        outcome = syncd.ensure_api_account(settings)
        assert outcome['status'] == 'updated' and len(installed) == 2, outcome  # explicit apply restarts anyway
    finally:
        syncd.install_document = original_install
        syncd.carp_master = original_master
        syncd.api_account.derive_hash = original_hash


def main():
    syncd = load_module()
    with tempfile.TemporaryDirectory(prefix='adguardhome-sync-e2e-') as directory:
        root = Path(directory)
        syncd.ADGUARD_HOME = root
        syncd.ADGUARD_CONFIG = root / 'AdGuardHome.yaml'
        syncd.BACKUP_CONFIG = root / 'AdGuardHome.yaml.before-sync'
        syncd.PENDING_CONFIG = root / 'AdGuardHome.yaml.pending'
        syncd.BASE_PATH_RECEIVER = root / 'AdGuardHome.yaml.last-source'
        syncd.BASE_PATH_SOURCE = root / 'AdGuardHome.yaml.last-pushed'
        syncd.ADGUARD_BINARY = root / 'AdGuardHome'
        syncd.CERTIFICATE_PATH = root / 'receiver.pem'
        syncd.LOCK_PATH = root / 'sync.lock'
        syncd.STATE_PATH = root / 'state.json'
        syncd.MODEL_SETTINGS_PATH = root / 'opnsense.json'
        syncd.MODEL_SETTINGS_PATH.write_text(json.dumps({'general': {'enabled': True}}))
        syncd.ADGUARD_BINARY.write_text('placeholder')
        syncd.ADGUARD_BINARY.chmod(0o755)
        subprocess.run([
            '/usr/bin/openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-nodes', '-days', '1',
            '-subj', '/CN=sync-test', '-addext', 'subjectAltName=IP:127.0.0.1',
            '-keyout', str(syncd.CERTIFICATE_PATH), '-out', str(syncd.CERTIFICATE_PATH),
        ], check=True, capture_output=True)
        syncd.check_config = lambda path: None
        original_run = syncd.run

        def fake_run(*args, **kwargs):
            if args[:2] == ('/usr/sbin/service', 'adguardhome'):
                return subprocess.CompletedProcess(args, 0, b'', b'')
            return original_run(*args, **kwargs)

        syncd.run = fake_run
        carp_parser_test(syncd)
        source_master_test(syncd)
        sync_protocol_test(syncd, root)
        apply_pipeline_test(syncd, root)
        managed_account_test(syncd, root)
        deferred_account_test(syncd, root)
        lock_wait_test(syncd)
        staging_test(syncd, root)
        restore_test(syncd, root)
        local_changes_test(syncd, root)
    with tempfile.TemporaryDirectory(prefix='adguardhome-sync-merge-') as directory:
        merge_tests(Path(directory))
    print('syncd e2e passed')


if __name__ == '__main__':
    main()
