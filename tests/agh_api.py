#!/usr/local/bin/python3
"""Exercise the semantic difference and the AdGuard Home API client."""

import base64
import copy
import importlib.util
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import threading


MODULE_PATH = Path(__file__).resolve().parents[1] / 'src/opnsense/scripts/Adguardhome/agh_api.py'


def load_module():
    specification = importlib.util.spec_from_file_location('agh_api', MODULE_PATH)
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


agh_api = load_module()
DNS_YAML = {field: leaf for leaf, (field, _restart) in agh_api.DNSCFG.items()}


def base_config():
    """A small configuration shaped like AdGuardHome.yaml schema 34."""
    return {
        'http': {'pprof': {'port': 6060, 'enabled': False}, 'address': '0.0.0.0:3000', 'session_ttl': '720h'},
        'users': [{'name': 'admin', 'password': '$2y$10$fakehash'}],
        'auth_attempts': 5,
        'block_auth_min': 15,
        'http_proxy': '',
        'theme': 'auto',
        'dns': {
            'bind_hosts': ['0.0.0.0'],
            'port': 53,
            'anonymize_client_ip': False,
            'ratelimit': 20,
            'ratelimit_subnet_len_ipv4': 24,
            'ratelimit_subnet_len_ipv6': 56,
            'ratelimit_whitelist': [],
            'upstream_dns': ['https://dns10.quad9.net/dns-query'],
            'upstream_dns_file': '',
            'bootstrap_dns': ['9.9.9.10'],
            'fallback_dns': [],
            'upstream_mode': 'load_balance',
            'upstream_timeout': '10s',
            'use_private_ptr_resolvers': True,
            'local_ptr_upstreams': [],
            'allowed_clients': [],
            'disallowed_clients': [],
            'blocked_hosts': ['version.bind'],
            'cache_enabled': True,
            'cache_size': 4194304,
            'cache_ttl_min': 0,
            'cache_ttl_max': 0,
            'cache_optimistic': False,
            'edns_client_subnet': {'custom_ip': '', 'enabled': False, 'use_custom': False},
            'aaaa_disabled': False,
            'enable_dnssec': False,
        },
        'filtering': {
            'blocked_services': {'schedule': {'time_zone': 'Local'}, 'ids': []},
            'protection_disabled_until': None,
            'safe_search': {'enabled': False, 'bing': True, 'duckduckgo': True, 'google': True,
                            'pixabay': True, 'yandex': True, 'youtube': True},
            'rewrites': [{'domain': 'router.lan', 'answer': '192.168.1.1'}],
            'safebrowsing_enabled': False,
            'parental_enabled': False,
            'filtering_enabled': True,
            'filters_update_interval': 24,
            'protection_enabled': True,
            'blocking_mode': 'default',
            'blocking_ipv4': '',
            'blocking_ipv6': '',
            'blocked_response_ttl': 10,
        },
        'filters': [{'enabled': True, 'url': 'https://example.invalid/a.txt', 'name': 'A',
                     'id': 1, 'rules_count': 12, 'last_updated': '2026-01-01T00:00:00Z'}],
        'whitelist_filters': [],
        'user_rules': ['||ads.example.invalid^'],
        'clients': {
            'runtime_sources': {'whois': True, 'arp': True, 'rdns': True, 'dhcp': True, 'hosts': True},
            'persistent': [{
                'name': 'desk', 'ids': ['192.168.1.5'], 'tags': [], 'upstreams': [],
                'uid': 'aaaaaaaa-0000-0000-0000-000000000000',
                'use_global_settings': True, 'filtering_enabled': False,
                'safe_search': {'enabled': False, 'bing': False, 'duckduckgo': False, 'google': False,
                                'pixabay': False, 'yandex': False, 'youtube': False},
                'blocked_services': {'schedule': {'time_zone': 'Local'}, 'ids': []},
            }],
        },
        'querylog': {'dir_path': '', 'ignored': [], 'interval': '2160h', 'enabled': True, 'file_enabled': True},
        'statistics': {'dir_path': '', 'ignored': [], 'interval': '24h', 'enabled': True},
        'log': {'file': '', 'verbose': False},
        'os': {'group': '', 'user': '', 'rlimit_nofile': 0},
        'schema_version': 34,
    }


def changed_config():
    """Change one key of every supported class."""
    config = base_config()
    config['http']['address'] = '127.0.0.1:8080'          # local
    config['dns']['bind_hosts'] = ['10.0.0.1']            # local
    config['log']['verbose'] = True                       # local
    config['schema_version'] = 34
    config['clients']['persistent'][0]['uid'] = 'bbbbbbbb-0000-0000-0000-000000000000'
    config['user_rules'] = ['||ads.example.invalid^', '@@||good.example.invalid^']
    config['filters'].append({'enabled': True, 'url': 'https://example.invalid/b.txt', 'name': 'B',
                              'id': 7, 'rules_count': 3, 'last_updated': '2026-02-02T00:00:00Z'})
    config['filtering']['rewrites'] = [{'domain': 'nas.lan', 'answer': '192.168.1.9'}]
    config['filtering']['blocked_services'] = {'schedule': {'time_zone': 'Local'}, 'ids': ['tiktok']}
    config['filtering']['safe_search']['enabled'] = True
    config['filtering']['filtering_enabled'] = False
    config['filtering']['safebrowsing_enabled'] = True
    config['filtering']['blocking_mode'] = 'nxdomain'     # hot dns_config field
    config['dns']['allowed_clients'] = ['192.168.1.0/24']
    config['dns']['upstream_dns'] = ['1.1.1.1']           # restartable dns_config field
    config['dns']['upstream_timeout'] = '15s'
    config['dns']['cache_size'] = 8388608
    config['querylog']['enabled'] = False
    config['statistics']['interval'] = '72h'
    config['clients']['persistent'][0]['ids'] = ['192.168.1.6']
    return config


class FakeAdGuard(BaseHTTPRequestHandler):
    """Enough of the AdGuard Home API to record calls and mutate a configuration."""

    def log_message(self, _format, *_args):
        return

    def body(self):
        length = int(self.headers.get('Content-Length') or 0)
        return json.loads(self.rfile.read(length)) if length else None

    def reply(self, status, payload=None):
        encoded = json.dumps(payload if payload is not None else {}).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self):
        config = self.server.config
        self.server.authorizations.append(self.headers.get('Authorization'))
        views = {
            '/control/status': {'running': True, 'version': 'v0.107.79'},
            '/control/dns_info': self.server.dns_info(),
            '/control/filtering/status': {
                'enabled': config['filtering']['filtering_enabled'],
                'interval': config['filtering']['filters_update_interval'],
                'filters': config['filters'],
                'whitelist_filters': config['whitelist_filters'],
                'user_rules': config['user_rules'],
            },
            '/control/safesearch/status': dict(config['filtering']['safe_search']),
            '/control/querylog/config': {
                'enabled': config['querylog']['enabled'],
                'interval': agh_api.duration_milliseconds(config['querylog']['interval']),
                'anonymize_client_ip': config['dns']['anonymize_client_ip'],
                'ignored': config['querylog']['ignored'],
                'ignored_enabled': config['querylog'].get('ignored_enabled', False),
            },
            '/control/stats/config': {
                'enabled': config['statistics']['enabled'],
                'interval': agh_api.duration_milliseconds(config['statistics']['interval']),
                'ignored': config['statistics']['ignored'],
                'ignored_enabled': config['statistics'].get('ignored_enabled', False),
            },
        }
        self.server.calls.append(('GET', self.path, None))
        if self.path not in views:
            self.reply(404, {'message': 'not found'})
            return
        payload = views[self.path]
        for field in self.server.hidden_fields:
            payload.pop(field, None)
        self.reply(200, payload)

    def do_PUT(self):
        self.dispatch('PUT')

    def do_POST(self):
        self.dispatch('POST')

    def dispatch(self, method):
        body = self.body()
        self.server.authorizations.append(self.headers.get('Authorization'))
        self.server.calls.append((method, self.path, body))
        handler = getattr(self.server, 'handle_' + self.path.replace('/control/', '').replace('/', '_'), None)
        if handler is None:
            self.reply(404, {'message': 'not found'})
            return
        handler(body)
        self.reply(200, {})


class FakeServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, config):
        super().__init__(('127.0.0.1', 0), FakeAdGuard)
        self.config = config
        self.calls = []
        self.authorizations = []
        self.hidden_fields = ()
        self.next_filter_id = 100

    @property
    def base_url(self):
        return 'http://127.0.0.1:{}'.format(self.server_address[1])

    def dns_info(self):
        info = {}
        for field, leaf in DNS_YAML.items():
            value = agh_api.lookup(self.config, leaf)
            if value is agh_api.MISSING:
                continue
            info[field] = int(agh_api.duration_seconds(value)) if leaf == 'dns.upstream_timeout' else value
        return info

    # --- mutating endpoints -------------------------------------------------
    def handle_filtering_set_rules(self, body):
        self.config['user_rules'] = list(body['rules'])

    def handle_rewrite_add(self, body):
        self.config['filtering']['rewrites'].append({'domain': body['domain'], 'answer': body['answer']})

    def handle_rewrite_delete(self, body):
        self.config['filtering']['rewrites'] = [
            entry for entry in self.config['filtering']['rewrites']
            if (entry['domain'], entry['answer']) != (body['domain'], body['answer'])
        ]

    def filter_key(self, body):
        return 'whitelist_filters' if body.get('whitelist') else 'filters'

    def handle_filtering_add_url(self, body):
        self.next_filter_id += 1
        self.config[self.filter_key(body)].append({
            'enabled': True, 'url': body['url'], 'name': body['name'],
            'id': self.next_filter_id, 'rules_count': 0, 'last_updated': '2026-03-03T00:00:00Z',
        })

    def handle_filtering_remove_url(self, body):
        key = self.filter_key(body)
        self.config[key] = [entry for entry in self.config[key] if entry['url'] != body['url']]

    def handle_filtering_set_url(self, body):
        for entry in self.config[self.filter_key(body)]:
            if entry['url'] == body['url']:
                entry.update({'name': body['data']['name'], 'enabled': body['data']['enabled']})

    def handle_clients_add(self, body):
        self.config['clients']['persistent'].append(self.stored_client(body))

    def handle_clients_update(self, body):
        self.config['clients']['persistent'] = [
            self.stored_client(body['data']) if client['name'] == body['name'] else client
            for client in self.config['clients']['persistent']
        ]

    def handle_clients_delete(self, body):
        self.config['clients']['persistent'] = [
            client for client in self.config['clients']['persistent'] if client['name'] != body['name']
        ]

    @staticmethod
    def stored_client(body):
        client = {key: value for key, value in body.items()
                  if key not in ('blocked_services', 'blocked_services_schedule')}
        client['blocked_services'] = {
            'schedule': body.get('blocked_services_schedule') or {'time_zone': 'Local'},
            'ids': body.get('blocked_services') or [],
        }
        client['uid'] = 'generated-by-adguard'
        return client

    def handle_blocked_services_update(self, body):
        self.config['filtering']['blocked_services'] = {'schedule': body['schedule'], 'ids': body['ids']}

    def handle_safesearch_settings(self, body):
        self.config['filtering']['safe_search'].update(body)

    def handle_filtering_config(self, body):
        self.config['filtering']['filtering_enabled'] = body['enabled']
        self.config['filtering']['filters_update_interval'] = body['interval']

    def handle_safebrowsing_enable(self, _body):
        self.config['filtering']['safebrowsing_enabled'] = True

    def handle_safebrowsing_disable(self, _body):
        self.config['filtering']['safebrowsing_enabled'] = False

    def handle_parental_enable(self, _body):
        self.config['filtering']['parental_enabled'] = True

    def handle_parental_disable(self, _body):
        self.config['filtering']['parental_enabled'] = False

    def handle_querylog_config_update(self, body):
        self.config['querylog']['enabled'] = body['enabled']
        self.config['querylog']['ignored'] = body['ignored']
        self.config['querylog']['interval'] = self.duration_text(body['interval'])
        self.config['dns']['anonymize_client_ip'] = body['anonymize_client_ip']
        self.config['querylog']['ignored_enabled'] = body.get('ignored_enabled', False)

    def handle_stats_config_update(self, body):
        self.config['statistics']['enabled'] = body['enabled']
        self.config['statistics']['ignored'] = body['ignored']
        self.config['statistics']['ignored_enabled'] = body.get('ignored_enabled', False)
        self.config['statistics']['interval'] = self.duration_text(body['interval'])

    @staticmethod
    def duration_text(milliseconds):
        hours = milliseconds / 3600000.0
        return '{}h'.format(int(hours)) if hours == int(hours) else '{}s'.format(milliseconds // 1000)

    def handle_access_set(self, body):
        for field in agh_api.ACCESS_FIELDS:
            self.config['dns'][field] = body[field]

    def handle_dns_config(self, body):
        for field, value in body.items():
            leaf = DNS_YAML[field]
            agh_api.assign(self.config, leaf, '{}s'.format(value) if leaf == 'dns.upstream_timeout' else value)


def serving(config):
    server = FakeServer(config)
    threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.05}, daemon=True).start()
    return server


def test_classification():
    source = changed_config()
    current = base_config()
    difference, plan = agh_api.classify(source, current)
    assert 'http.address' in plan['local'], plan
    assert 'dns.bind_hosts' in plan['local'], plan
    assert 'log.verbose' in plan['local'], plan
    assert 'clients.persistent' not in plan['local'], plan
    for path in ('user_rules', 'filters', 'filtering.rewrites', 'filtering.blocked_services.ids',
                 'filtering.safe_search.enabled', 'clients.persistent', 'dns.allowed_clients',
                 'filtering.filtering_enabled', 'filtering.safebrowsing_enabled',
                 'filtering.blocking_mode', 'querylog.enabled', 'statistics.interval'):
        assert path in plan['hot'], (path, plan)
    for path in ('dns.upstream_dns', 'dns.upstream_timeout', 'dns.cache_size'):
        assert path in plan['reconf'], (path, plan)
    assert not plan['file'], plan
    assert 'schema_version' not in difference, difference
    # A generated identifier alone is never a difference.
    only_uid = base_config()
    only_uid['clients']['persistent'][0]['uid'] = 'cccccccc-0000-0000-0000-000000000000'
    only_uid['filters'][0]['rules_count'] = 99
    _difference, plan = agh_api.classify(only_uid, base_config())
    assert plan == {'local': [], 'hot': [], 'reconf': [], 'file': []}, plan
    # Unmapped keys, and demoted keys, need the file route.
    unmapped = base_config()
    unmapped['users'][0]['password'] = '$2y$10$other'
    unmapped['tls'] = {'enabled': True}
    _difference, plan = agh_api.classify(unmapped, base_config())
    assert plan['file'] == ['tls.enabled', 'users'], plan
    demoted = agh_api.classify(changed_config(), base_config(), demoted=('filtering.safe_search',))[1]
    assert 'filtering.safe_search.enabled' in demoted['file'], demoted


def test_conversions():
    assert agh_api.to_api('dns.upstream_timeout', '15s') == 15
    assert agh_api.to_api('dns.upstream_timeout', 15) == 15
    assert agh_api.to_api('dns.upstream_timeout', '1m30s') == 90
    assert agh_api.to_api('dns.upstream_mode', None) == 'load_balance'
    assert agh_api.to_api('dns.upstream_mode', 'parallel') == 'parallel'
    assert agh_api.to_api('dns.cache_size', 4) == 4
    assert agh_api.duration_milliseconds('2160h') == 7776000000
    assert agh_api.duration_milliseconds('500ms') == 500
    assert agh_api.api_base_url({'http': {'address': '0.0.0.0:3000'}}) == 'http://127.0.0.1:3000'
    assert agh_api.api_base_url({'http': {'address': '[::]:3000'}}) == 'http://127.0.0.1:3000'
    assert agh_api.api_base_url({'http': {'address': '192.168.1.1:8080'}}) == 'http://192.168.1.1:8080'
    assert agh_api.api_base_url({'http': {'address': '0.0.0.0:3000'},
                                 'tls': {'force_https': True, 'port_https': 4443}}) == 'https://127.0.0.1:4443'


def test_apply_and_convergence():
    receiver = base_config()
    server = serving(receiver)
    try:
        api = agh_api.AdGuardApi(server.base_url, 'admin', 'secret')
        source = changed_config()
        _difference, plan = agh_api.classify(source, receiver)
        agh_api.apply(source, receiver, api, plan)
        dns_config_calls = [call for call in server.calls if call[1] == '/control/dns_config']
        assert len(dns_config_calls) == 1, server.calls
        body = dns_config_calls[0][2]
        assert body['upstream_timeout'] == 15, body
        assert body['upstream_dns'] == ['1.1.1.1'], body
        assert body['blocking_mode'] == 'nxdomain', body
        remaining = agh_api.divergent(source, server.config)
        assert not remaining, remaining
        # A configuration that is already in place issues no calls at all.
        again = agh_api.AdGuardApi(server.base_url, 'admin', 'secret')
        _difference, plan = agh_api.classify(source, server.config)
        assert not (plan['hot'] or plan['reconf'] or plan['file']), plan
        agh_api.apply(source, server.config, again, plan)
        assert again.calls == [], again.calls
    finally:
        server.shutdown()
        server.server_close()


def test_unauthenticated_client():
    """An instance without administrators is addressed without credentials."""
    server = serving(base_config())
    try:
        agh_api.AdGuardApi(server.base_url)('GET', '/status')
        assert server.authorizations == [None], server.authorizations
        agh_api.AdGuardApi(server.base_url, '', '')('GET', '/status')
        assert server.authorizations == [None, None], server.authorizations
        agh_api.AdGuardApi(server.base_url, 'admin', 'secret')('GET', '/status')
        assert server.authorizations[2] == 'Basic ' + base64.b64encode(b'admin:secret').decode(), \
            server.authorizations
    finally:
        server.shutdown()
        server.server_close()


def test_managed_user_is_never_a_difference():
    """The managed service account is invisible to the comparison."""
    source = base_config()
    receiver = base_config()
    receiver['users'].append({'name': 'opnsense-ha', 'password': '$2y$10$managed'})
    stripped = agh_api.strip_generated(receiver)
    assert [entry['name'] for entry in stripped['users']] == ['admin'], stripped['users']
    assert [entry['name'] for entry in receiver['users']] == ['admin', 'opnsense-ha']
    _difference, plan = agh_api.classify(source, receiver)
    assert plan == {'local': [], 'hot': [], 'reconf': [], 'file': []}, plan
    assert not agh_api.divergent(source, receiver)
    # A source that carries one does not push it onto the receiver either.
    _difference, plan = agh_api.classify(receiver, source)
    assert plan == {'local': [], 'hot': [], 'reconf': [], 'file': []}, plan


def test_divergence_detects_drift():
    source = changed_config()
    stubborn = copy.deepcopy(source)
    stubborn['dns']['cache_size'] = 1
    stubborn['http']['address'] = '127.0.0.1:9999'
    remaining = agh_api.divergent(source, stubborn)
    assert remaining == ['dns.cache_size'], remaining


def test_self_check():
    server = serving(base_config())
    try:
        api = agh_api.AdGuardApi(server.base_url, 'admin', 'secret')
        demoted, warnings = agh_api.self_check(api)
        assert not demoted, (demoted, warnings)
        assert not warnings, warnings
        server.hidden_fields = ('upstream_timeout', 'ignored')
        demoted, warnings = agh_api.self_check(agh_api.AdGuardApi(server.base_url, 'admin', 'secret'))
        assert 'dns.upstream_timeout' in demoted, demoted
        assert 'querylog.ignored' in demoted, demoted
        assert 'statistics.ignored' in demoted, demoted
        assert len(warnings) == 3, warnings
    finally:
        server.shutdown()
        server.server_close()


def test_api_errors():
    server = serving(base_config())
    try:
        api = agh_api.AdGuardApi(server.base_url, 'admin', 'secret')
        try:
            api('POST', '/does/not/exist', {})
        except agh_api.ApiError:
            pass
        else:
            raise RuntimeError('An unknown endpoint was accepted.')
    finally:
        server.shutdown()
        server.server_close()
    unreachable = agh_api.AdGuardApi('http://127.0.0.1:1', 'admin', 'secret', timeout=2)
    try:
        unreachable('GET', '/status')
    except agh_api.ApiError:
        pass
    else:
        raise RuntimeError('An unreachable instance was accepted.')


def main():
    test_classification()
    test_conversions()
    test_apply_and_convergence()
    test_unauthenticated_client()
    test_managed_user_is_never_a_difference()
    test_divergence_detects_drift()
    test_self_check()
    test_api_errors()
    print('agh_api tests passed')


if __name__ == '__main__':
    main()
