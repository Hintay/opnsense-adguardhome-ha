#!/usr/local/bin/python3
"""AdGuard Home REST API client and semantic configuration difference.

The synchronization receiver uses this module to adopt a configuration through
the REST API of the running AdGuard Home instance instead of replacing
AdGuardHome.yaml and restarting the service.  Every differing YAML leaf is
classified as:

    local   node-local, never synchronized
    hot     applied by an API call that does not touch the DNS listeners
    reconf  applied by the single batched /dns_config call
    file    no API exists, the caller must fall back to file replacement

AdGuard Home rewrites AdGuardHome.yaml after every API write, so the caller can
verify convergence by reading the file again.
"""

import base64
import copy
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

SCRIPT_DIRECTORY = str(Path(__file__).resolve().parent)
if SCRIPT_DIRECTORY not in sys.path:
    sys.path.insert(0, SCRIPT_DIRECTORY)

import api_account  # noqa: E402  sibling module in the plugin script directory


MISSING = object()

# Node-local keys are never synchronized and always keep the receiver's value.
LOCAL_KEYS = (
    'http.address',
    'http.session_ttl',
    'http.pprof',
    'dns.bind_hosts',
    'dns.port',
    'log',
    'os',
    'querylog.dir_path',
    'statistics.dir_path',
    'schema_version',
    'auth_attempts',
    'block_auth_min',
    'http_proxy',
    'clients.runtime_sources',
    'filtering.protection_disabled_until',
)

# YAML leaf -> (/dns_config field, listener rebuild).  Fields that rebuild the
# listeners are batched with the remaining ones into exactly one POST.
DNSCFG = {
    'dns.upstream_dns': ('upstream_dns', True),
    'dns.upstream_dns_file': ('upstream_dns_file', True),
    'dns.bootstrap_dns': ('bootstrap_dns', True),
    'dns.fallback_dns': ('fallback_dns', True),
    'dns.upstream_mode': ('upstream_mode', False),
    'dns.upstream_timeout': ('upstream_timeout', True),
    'dns.ratelimit': ('ratelimit', True),
    'dns.ratelimit_subnet_len_ipv4': ('ratelimit_subnet_len_ipv4', True),
    'dns.ratelimit_subnet_len_ipv6': ('ratelimit_subnet_len_ipv6', True),
    'dns.ratelimit_whitelist': ('ratelimit_whitelist', True),
    'dns.cache_enabled': ('cache_enabled', True),
    'dns.cache_size': ('cache_size', True),
    'dns.cache_ttl_min': ('cache_ttl_min', True),
    'dns.cache_ttl_max': ('cache_ttl_max', True),
    'dns.cache_optimistic': ('cache_optimistic', True),
    'dns.edns_client_subnet.enabled': ('edns_cs_enabled', True),
    'dns.edns_client_subnet.use_custom': ('edns_cs_use_custom', True),
    'dns.edns_client_subnet.custom_ip': ('edns_cs_custom_ip', False),
    'dns.use_private_ptr_resolvers': ('use_private_ptr_resolvers', True),
    'dns.local_ptr_upstreams': ('local_ptr_upstreams', True),
    'dns.aaaa_disabled': ('disable_ipv6', False),
    'dns.enable_dnssec': ('dnssec_enabled', False),
    'filtering.protection_enabled': ('protection_enabled', False),
    'filtering.blocking_mode': ('blocking_mode', False),
    'filtering.blocking_ipv4': ('blocking_ipv4', False),
    'filtering.blocking_ipv6': ('blocking_ipv6', False),
    'filtering.blocked_response_ttl': ('blocked_response_ttl', False),
}

FILTERING_CONFIG = {
    'filtering.filtering_enabled': 'enabled',
    'filtering.filters_update_interval': 'interval',
}
QUERYLOG_CONFIG = {
    'querylog.enabled': 'enabled',
    'querylog.interval': 'interval',
    'querylog.ignored': 'ignored',
    'querylog.ignored_enabled': 'ignored_enabled',
    'dns.anonymize_client_ip': 'anonymize_client_ip',
}
STATISTICS_CONFIG = {
    'statistics.enabled': 'enabled',
    'statistics.interval': 'interval',
    'statistics.ignored': 'ignored',
    'statistics.ignored_enabled': 'ignored_enabled',
}
# Go durations that AdGuard Home rewrites in its own notation (for example 2160h -> 90d);
# they are compared by value, not by spelling.
DURATION_KEYS = ('querylog.interval', 'statistics.interval', 'dns.upstream_timeout')
ACCESS_FIELDS = ('allowed_clients', 'disallowed_clients', 'blocked_hosts')
SAFE_SEARCH_FIELDS = ('enabled', 'bing', 'duckduckgo', 'google', 'pixabay', 'yandex', 'youtube')
TOGGLE_ENDPOINTS = {
    'filtering.safebrowsing_enabled': 'safebrowsing',
    'filtering.parental_enabled': 'parental',
}

# Collections reconciled as a set through their own endpoints.
HOT_COLLECTIONS = (
    'user_rules',
    'filters',
    'whitelist_filters',
    'filtering.rewrites',
    'filtering.blocked_services',
    'filtering.safe_search',
    'clients.persistent',
)
HOT_FIELDS = frozenset(
    set(FILTERING_CONFIG)
    | set(QUERYLOG_CONFIG)
    | set(STATISTICS_CONFIG)
    | set(TOGGLE_ENDPOINTS)
    | {'dns.' + field for field in ACCESS_FIELDS}
)

# Volatile members that AdGuard Home generates itself and that must never count
# as a difference between the two nodes.
GENERATED_FILTER_FIELDS = ('id', 'rules_count', 'last_updated')
GENERATED_CLIENT_FIELDS = ('uid',)

# Startup self-check: endpoint -> {API field: YAML keys demoted when it is absent}.
SELF_CHECK = (
    ('/dns_info', dict(
        [(field, (leaf,)) for leaf, (field, _restart) in DNSCFG.items()]
    )),
    ('/filtering/status', {
        'enabled': ('filtering.filtering_enabled',),
        'interval': ('filtering.filters_update_interval',),
        'filters': ('filters',),
        'whitelist_filters': ('whitelist_filters',),
        'user_rules': ('user_rules',),
    }),
    # Settings are read back through /safesearch/status; /safesearch/settings only accepts PUT.
    ('/safesearch/status', dict(
        [(field, ('filtering.safe_search.' + field,)) for field in SAFE_SEARCH_FIELDS]
    )),
    ('/querylog/config', {
        'enabled': ('querylog.enabled',),
        'interval': ('querylog.interval',),
        'ignored': ('querylog.ignored',),
        'ignored_enabled': ('querylog.ignored_enabled',),
        'anonymize_client_ip': ('dns.anonymize_client_ip',),
    }),
    ('/stats/config', {
        'enabled': ('statistics.enabled',),
        'interval': ('statistics.interval',),
        'ignored': ('statistics.ignored',),
        'ignored_enabled': ('statistics.ignored_enabled',),
    }),
)

DURATION_UNITS = {'ns': 1e-9, 'us': 1e-6, 'ms': 1e-3, 's': 1.0, 'm': 60.0, 'h': 3600.0, 'd': 86400.0}


class ApiError(RuntimeError):
    """An AdGuard Home API request could not be completed."""


def leaves(value, prefix=''):
    """Yield every (dotted path, value) leaf of a nested mapping."""
    if isinstance(value, dict):
        for key, item in value.items():
            yield from leaves(item, '{}.{}'.format(prefix, key) if prefix else str(key))
    else:
        yield prefix, value


def lookup(configuration, path):
    """Return the value at a dotted path or MISSING."""
    current = configuration
    for key in path.split('.'):
        if not isinstance(current, dict) or key not in current:
            return MISSING
        current = current[key]
    return current


def assign(configuration, path, value):
    keys = path.split('.')
    current = configuration
    for key in keys[:-1]:
        if not isinstance(current.get(key), dict):
            current[key] = {}
        current = current[key]
    current[keys[-1]] = value


def remove(configuration, path):
    keys = path.split('.')
    current = configuration
    for key in keys[:-1]:
        if not isinstance(current, dict) or key not in current:
            return
        current = current[key]
    if isinstance(current, dict):
        current.pop(keys[-1], None)


def matches(path, keys):
    return any(path == key or path.startswith(key + '.') for key in keys)


def is_local(path):
    return matches(path, LOCAL_KEYS)


def strip_generated(configuration):
    """Return a copy without the members AdGuard Home generates by itself."""
    result = copy.deepcopy(configuration) if isinstance(configuration, dict) else {}
    # The managed service account is node-local and never a difference.
    result = api_account.strip_managed(result)
    for client in (result.get('clients') or {}).get('persistent') or []:
        if isinstance(client, dict):
            for field in GENERATED_CLIENT_FIELDS:
                client.pop(field, None)
    for key in ('filters', 'whitelist_filters'):
        for entry in result.get(key) or []:
            if isinstance(entry, dict):
                for field in GENERATED_FILTER_FIELDS:
                    entry.pop(field, None)
    # AdGuard Home adds enabled: true to every rewrite it writes.
    for entry in (result.get('filtering') or {}).get('rewrites') or []:
        if isinstance(entry, dict):
            entry.setdefault('enabled', True)
    for path in DURATION_KEYS:
        value = lookup(result, path)
        if value is not MISSING and value is not None:
            try:
                assign(result, path, duration_seconds(value))
            except ValueError:
                pass
    return result


def duration_seconds(value):
    """Convert a Go duration string, or a plain number, to seconds."""
    if isinstance(value, bool):
        raise ValueError('A duration cannot be a boolean.')
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip()
    if not text:
        raise ValueError('A duration cannot be empty.')
    total = 0.0
    number = ''
    index = 0
    while index < len(text):
        character = text[index]
        if character.isdigit() or character in '.+-':
            number += character
            index += 1
            continue
        unit = ''
        while index < len(text) and not (text[index].isdigit() or text[index] in '.+-'):
            unit += text[index]
            index += 1
        if not number or unit not in DURATION_UNITS:
            raise ValueError('Unsupported duration: ' + text)
        total += float(number) * DURATION_UNITS[unit]
        number = ''
    if number:
        total += float(number)
    return total


def duration_milliseconds(value):
    return int(round(duration_seconds(value) * 1000))


def to_api(leaf, value):
    """Convert a YAML value to the representation the API expects."""
    if leaf == 'dns.upstream_mode':
        return value or 'load_balance'
    if leaf == 'dns.upstream_timeout':
        return int(round(duration_seconds(value)))
    return value


def key_class(path, demoted=()):
    if is_local(path):
        return 'local'
    if matches(path, demoted):
        return 'file'
    if path in DNSCFG:
        return 'reconf' if DNSCFG[path][1] else 'hot'
    if path in HOT_FIELDS or matches(path, HOT_COLLECTIONS):
        return 'hot'
    return 'file'


def classify(source, current, demoted=()):
    """Return the leaf difference and the class plan between two configurations."""
    source = strip_generated(source)
    current = strip_generated(current)
    difference = {}
    for path, value in leaves(source):
        present = lookup(current, path)
        if present != value:
            difference[path] = (present, value)
    plan = {'local': [], 'hot': [], 'reconf': [], 'file': []}
    for path in sorted(difference):
        plan[key_class(path, demoted)].append(path)
    return difference, plan


def divergent(source, current):
    """Return the non-local source leaves the receiver has not adopted."""
    source = strip_generated(source)
    current = strip_generated(current)
    return sorted(
        path for path, value in leaves(source)
        if not is_local(path) and lookup(current, path) != value
    )


def value_or(configuration, path, default):
    value = lookup(configuration, path)
    return default if value is MISSING else value


def filter_body(entry):
    return {
        'name': entry.get('name', ''),
        'url': entry.get('url', ''),
        'enabled': bool(entry.get('enabled', True)),
    }


def client_body(client):
    """Convert a YAML persistent client into the API representation."""
    body = {
        key: value for key, value in client.items()
        if key not in GENERATED_CLIENT_FIELDS and key not in ('blocked_services', 'safe_search')
    }
    services = client.get('blocked_services') or {}
    body['blocked_services'] = services.get('ids') or []
    body['blocked_services_schedule'] = services.get('schedule') or {'time_zone': 'Local'}
    if client.get('safe_search'):
        body['safe_search'] = client['safe_search']
    return body


def apply_user_rules(source, api):
    api('POST', '/filtering/set_rules', {'rules': value_or(source, 'user_rules', []) or []})


def apply_rewrites(source, current, api):
    def entries(configuration):
        items = value_or(configuration, 'filtering.rewrites', []) or []
        return {
            (entry.get('domain'), entry.get('answer')): bool(entry.get('enabled', True))
            for entry in items if isinstance(entry, dict)
        }

    wanted = entries(source)
    present = entries(current)
    for domain, answer in sorted(set(present) - set(wanted)):
        api('POST', '/rewrite/delete', {'domain': domain, 'answer': answer})
    for domain, answer in sorted(set(wanted) - set(present)):
        api('POST', '/rewrite/add', {'domain': domain, 'answer': answer})
    for domain, answer in sorted(set(wanted) & set(present)):
        if wanted[(domain, answer)] != present[(domain, answer)]:
            api('PUT', '/rewrite/update', {
                'target': {'domain': domain, 'answer': answer},
                'update': {'domain': domain, 'answer': answer, 'enabled': wanted[(domain, answer)]},
            })
    # Newly added rewrites are enabled; disable the ones the source keeps disabled.
    for domain, answer in sorted(set(wanted) - set(present)):
        if not wanted[(domain, answer)]:
            api('PUT', '/rewrite/update', {
                'target': {'domain': domain, 'answer': answer},
                'update': {'domain': domain, 'answer': answer, 'enabled': False},
            })


def apply_filter_lists(source, current, api, key, whitelist):
    wanted = {entry.get('url'): entry for entry in value_or(source, key, []) or [] if isinstance(entry, dict)}
    present = {entry.get('url'): entry for entry in value_or(current, key, []) or [] if isinstance(entry, dict)}
    for url in sorted(set(present) - set(wanted)):
        api('POST', '/filtering/remove_url', {'url': url, 'whitelist': whitelist})
    for url in sorted(wanted):
        entry = wanted[url]
        if url not in present:
            api('POST', '/filtering/add_url', {'name': entry.get('name', ''), 'url': url, 'whitelist': whitelist})
        elif filter_body(present[url]) != filter_body(entry):
            api('POST', '/filtering/set_url', {'url': url, 'whitelist': whitelist, 'data': filter_body(entry)})


def apply_clients(source, current, api):
    wanted = {
        client.get('name'): client
        for client in value_or(source, 'clients.persistent', []) or [] if isinstance(client, dict)
    }
    present = {
        client.get('name'): client
        for client in value_or(current, 'clients.persistent', []) or [] if isinstance(client, dict)
    }
    for name in sorted(set(present) - set(wanted)):
        api('POST', '/clients/delete', {'name': name})
    for name in sorted(wanted):
        client = wanted[name]
        if name not in present:
            api('POST', '/clients/add', client_body(client))
        elif present[name] != client:
            api('POST', '/clients/update', {'name': name, 'data': client_body(client)})


def apply_querylog(source, api):
    api('PUT', '/querylog/config/update', {
        'enabled': bool(value_or(source, 'querylog.enabled', True)),
        'interval': duration_milliseconds(value_or(source, 'querylog.interval', '24h')),
        'anonymize_client_ip': bool(value_or(source, 'dns.anonymize_client_ip', False)),
        'ignored': value_or(source, 'querylog.ignored', []) or [],
        'ignored_enabled': bool(value_or(source, 'querylog.ignored_enabled', False)),
    })


def apply_statistics(source, api):
    api('PUT', '/stats/config/update', {
        'enabled': bool(value_or(source, 'statistics.enabled', True)),
        'interval': duration_milliseconds(value_or(source, 'statistics.interval', '24h')),
        'ignored': value_or(source, 'statistics.ignored', []) or [],
        'ignored_enabled': bool(value_or(source, 'statistics.ignored_enabled', False)),
    })


def apply(source, current, api, plan):
    """Apply the hot and reconf parts of a plan, ending with one /dns_config call."""
    source = strip_generated(source)
    current = strip_generated(current)
    hot = set(plan.get('hot') or ())
    reconf = set(plan.get('reconf') or ())
    if any(matches(path, ('user_rules',)) for path in hot):
        apply_user_rules(source, api)
    if any(matches(path, ('filtering.rewrites',)) for path in hot):
        apply_rewrites(source, current, api)
    for key, whitelist in (('filters', False), ('whitelist_filters', True)):
        if any(matches(path, (key,)) for path in hot):
            apply_filter_lists(source, current, api, key, whitelist)
    if any(matches(path, ('clients.persistent',)) for path in hot):
        apply_clients(source, current, api)
    if any(matches(path, ('filtering.blocked_services',)) for path in hot):
        services = value_or(source, 'filtering.blocked_services', {}) or {}
        api('PUT', '/blocked_services/update', {
            'schedule': services.get('schedule') or {'time_zone': 'Local'},
            'ids': services.get('ids') or [],
        })
    if any(matches(path, ('filtering.safe_search',)) for path in hot):
        api('PUT', '/safesearch/settings', value_or(source, 'filtering.safe_search', {}) or {})
    if any(path in FILTERING_CONFIG for path in hot):
        api('POST', '/filtering/config', {
            'enabled': bool(value_or(source, 'filtering.filtering_enabled', True)),
            'interval': value_or(source, 'filtering.filters_update_interval', 24),
        })
    for path, endpoint in sorted(TOGGLE_ENDPOINTS.items()):
        if path in hot:
            api('POST', '/{}/{}'.format(endpoint, 'enable' if lookup(source, path) else 'disable'))
    if any(path in QUERYLOG_CONFIG for path in hot):
        apply_querylog(source, api)
    if any(path in STATISTICS_CONFIG for path in hot):
        apply_statistics(source, api)
    if any(path in ('dns.' + field for field in ACCESS_FIELDS) for path in hot):
        api('POST', '/access/set', {
            field: value_or(source, 'dns.' + field, []) or [] for field in ACCESS_FIELDS
        })
    # One batched /dns_config call keeps the listener rebuild down to a single event.
    body = {DNSCFG[path][0]: to_api(path, lookup(source, path)) for path in sorted(hot | reconf) if path in DNSCFG}
    if body:
        api('POST', '/dns_config', body)


def local_listeners(port):
    """Return the local addresses with a listening socket on port, or None without sockstat.

    Probing a CARP virtual address with a TCP connection is misleading on the
    backup node: IPv4 reaches the master's daemon and IPv6 does not connect at
    all.  sockstat(1) reports what this host's processes actually bind.
    """
    sockstat = shutil.which('sockstat') or '/usr/bin/sockstat'
    if not os.path.exists(sockstat):
        return None
    try:
        result = subprocess.run([sockstat, '-46l', '-p', str(port)], capture_output=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode:
        return None
    listeners = set()
    for line in result.stdout.decode(errors='replace').splitlines()[1:]:
        fields = line.split()
        if len(fields) < 6:
            continue
        host, _separator, bound_port = fields[5].rpartition(':')
        if bound_port != str(port):
            continue
        listeners.add(host.strip('[]').split('%', 1)[0])
    return listeners


def host_served(host, listeners):
    """Report whether a bind address is covered by the local listeners."""
    if '*' in listeners:
        return True
    if host in ('0.0.0.0', '::', ''):
        return bool(listeners)
    return host.split('%', 1)[0] in listeners


def host_and_port(address, default_port='3000'):
    """Split an AdGuard Home listen address into a host and a port."""
    text = str(address or '').strip()
    if text.startswith('['):
        host, _, remainder = text[1:].partition(']')
        port = remainder.lstrip(':') or default_port
    elif text.count(':') > 1:
        host, port = text, default_port
    elif ':' in text:
        host, _, port = text.rpartition(':')
    else:
        host, port = text, default_port
    return host or '127.0.0.1', port or default_port


def loopback(host):
    return '127.0.0.1' if host in ('', '0.0.0.0', '::', '[::]') else host


def api_base_url(configuration):
    """Return the local base URL of the AdGuard Home web interface."""
    tls = configuration.get('tls') if isinstance(configuration, dict) else None
    tls = tls if isinstance(tls, dict) else {}
    if tls.get('force_https') and tls.get('port_https'):
        return 'https://127.0.0.1:{}'.format(tls['port_https'])
    http_section = configuration.get('http') if isinstance(configuration, dict) else None
    host, port = host_and_port((http_section or {}).get('address'))
    host = loopback(host)
    if ':' in host:
        host = '[{}]'.format(host)
    return 'http://{}:{}'.format(host, port)


class AdGuardApi:
    """Minimal AdGuard Home REST API client using HTTP Basic authentication.

    An instance without administrators accepts, and requires, no credentials;
    the client then sends no Authorization header at all.
    """

    def __init__(self, base_url, username=None, password=None, timeout=60):
        self.base_url = str(base_url).rstrip('/')
        self.timeout = timeout
        self.calls = []
        self.headers = {'Content-Type': 'application/json'}
        if username:
            token = base64.b64encode('{}:{}'.format(username, password or '').encode()).decode()
            self.headers['Authorization'] = 'Basic ' + token
        if self.base_url.startswith('https://'):
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            self.opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context))
        else:
            self.opener = urllib.request.build_opener()

    def __call__(self, method, path, body=None):
        # AdGuard Home rejects a JSON content type on requests without a body (HTTP 415).
        headers = dict(self.headers)
        if body is None:
            headers.pop('Content-Type', None)
        request = urllib.request.Request(
            self.base_url + '/control' + path,
            method=method,
            data=json.dumps(body).encode() if body is not None else None,
            headers=headers,
        )
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                status, content = response.status, response.read()
        except urllib.error.HTTPError as error:
            status, content = error.code, error.read()
        except (urllib.error.URLError, OSError, ssl.SSLError) as error:
            self.calls.append((method, path, 0))
            raise ApiError('{} {} failed: {}'.format(method, path, error)) from error
        self.calls.append((method, path, status))
        if status >= 300:
            raise ApiError('{} {} returned {}: {}'.format(
                method, path, status, content[:200].decode(errors='replace')))
        text = content.strip()
        if text[:1] in (b'{', b'['):
            try:
                return json.loads(text)
            except json.JSONDecodeError as error:
                raise ApiError('{} {} returned invalid JSON.'.format(method, path)) from error
        return None


def self_check(api):
    """Verify that the running instance exposes every mapped API field.

    Returns the YAML keys that must be demoted to the file class and the human
    readable warnings describing why.
    """
    demoted = set()
    warnings = []
    for endpoint, fields in SELF_CHECK:
        try:
            response = api('GET', endpoint)
        except ApiError as error:
            demoted.update(key for keys in fields.values() for key in keys)
            warnings.append('{} is unavailable: {}'.format(endpoint, error))
            continue
        if not isinstance(response, dict):
            demoted.update(key for keys in fields.values() for key in keys)
            warnings.append('{} returned an unexpected document.'.format(endpoint))
            continue
        absent = sorted(field for field in fields if field not in response)
        if absent:
            demoted.update(key for field in absent for key in fields[field])
            warnings.append('{} does not report {}.'.format(endpoint, ', '.join(absent)))
    return demoted, warnings
