#!/usr/local/bin/python3
"""Exercise the three-way merge between the source and the receiver."""

import copy
import importlib.util
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / 'src/opnsense/scripts/Adguardhome/merge.py'


def load_module(name):
    specification = importlib.util.spec_from_file_location(name, MODULE_PATH.with_name(name + '.py'))
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


merge = load_module('merge')
agh_api = merge.agh_api
MISSING = agh_api.MISSING


def document(**leaves):
    """A configuration shaped like AdGuardHome.yaml with the given leaves set."""
    result = {
        'http': {'address': '10.0.2.1:3000'},
        'users': [{'name': 'admin', 'password': '$2y$10$hash'}],
        'dns': {
            'bind_hosts': ['10.0.2.1'],
            'port': 53,
            'upstream_dns': ['9.9.9.9'],
        },
        'filtering': {'blocking_mode': 'default', 'filtering_enabled': True},
        'user_rules': ['||one.example.invalid^'],
        'filters': [],
        'querylog': {'dir_path': '/var/log/source', 'enabled': True, 'interval': '24h'},
        'schema_version': 34,
    }
    for path, value in leaves.items():
        path = path.replace('__', '.')
        if value is MISSING:
            agh_api.remove(result, path)
        else:
            agh_api.assign(result, path, copy.deepcopy(value))
    return result


# leaf value in base, ours and theirs -> merged value, adopted, conflict winner.
ROWS = (
    ('unchanged everywhere', 'a', 'a', 'a', True, 'a', False, None),
    ('only they changed it', 'a', 'a', 'b', True, 'b', True, None),
    ('only we changed it', 'a', 'b', 'a', True, 'b', False, None),
    ('both made the same change', 'a', 'b', 'b', True, 'b', False, None),
    ('conflict while we are master', 'a', 'b', 'c', True, 'b', False, 'source'),
    ('conflict while they are master', 'a', 'b', 'c', False, 'c', False, 'receiver'),
    ('they removed the leaf', 'a', 'a', MISSING, True, MISSING, True, None),
    ('they added the leaf', MISSING, MISSING, 'b', True, 'b', True, None),
    ('we removed the leaf', 'a', MISSING, 'a', True, MISSING, False, None),
    ('conflicting removal, we win', 'a', MISSING, 'c', True, MISSING, False, 'source'),
    ('conflicting removal, they win', 'a', MISSING, 'c', False, 'c', False, 'receiver'),
)

# The rows run against a scalar leaf and against a list leaf, which must be
# adopted or kept as one value instead of being merged member by member.
LEAVES = (
    ('filtering.blocking_mode', {'a': 'default', 'b': 'nxdomain', 'c': 'refused'}),
    ('user_rules', {'a': ['||one.example.invalid^'],
                    'b': ['||two.example.invalid^', '||three.example.invalid^'],
                    'c': ['||one.example.invalid^', '||four.example.invalid^']}),
)


def value_of(values, marker):
    return MISSING if marker is MISSING else values[marker]


def test_rows():
    for leaf, values in LEAVES:
        for name, base, ours, theirs, master, expected, adopts, winner in ROWS:
            documents = [document(**{leaf.replace('.', '__'): value_of(values, marker)})
                         for marker in (base, ours, theirs)]
            merged, adopted, conflicts = merge.three_way(*documents, master)
            label = '{} ({})'.format(name, leaf)
            if agh_api.lookup(merged, leaf) != value_of(values, expected):
                raise RuntimeError('The merged value is wrong for ' + label)
            if adopted != ([leaf] if adopts else []):
                raise RuntimeError('The adopted leaves are wrong for {}: {}'.format(label, adopted))
            if winner is None:
                if conflicts:
                    raise RuntimeError('An unexpected conflict for {}: {}'.format(label, sorted(conflicts)))
                continue
            if sorted(conflicts) != [leaf]:
                raise RuntimeError('The conflict was not reported for ' + label)
            reported = conflicts[leaf]
            if reported[2] != winner:
                raise RuntimeError('The wrong side won {}: {}'.format(label, reported[2]))
            if reported[:2] != (value_of(values, ours), value_of(values, theirs)):
                raise RuntimeError('The conflicting values are wrong for ' + label)


def test_local_keys_are_never_touched():
    base = document()
    ours = document()
    theirs = document(http__address='10.0.2.2:3000', dns__bind_hosts=['10.0.2.2'], dns__port=5353,
                      querylog__dir_path='/var/log/receiver', schema_version=35,
                      filtering__blocking_mode='nxdomain')
    merged, adopted, conflicts = merge.three_way(base, ours, theirs, True)
    if adopted != ['filtering.blocking_mode'] or conflicts:
        raise RuntimeError('A node-local difference was merged: ' + str(adopted))
    for leaf in ('http.address', 'dns.bind_hosts', 'dns.port', 'querylog.dir_path', 'schema_version'):
        if agh_api.lookup(merged, leaf) != agh_api.lookup(ours, leaf):
            raise RuntimeError('The node-local leaf ' + leaf + ' was replaced.')
    if merge.drift(base, theirs) != ['filtering.blocking_mode']:
        raise RuntimeError('A node-local difference counts as drift.')


def test_generated_members_are_ignored():
    """Volatile members and duration spellings never look like a change."""
    base = document(filters=[{'name': 'A', 'url': 'https://example.invalid/a.txt', 'enabled': True,
                              'id': 1, 'rules_count': 10, 'last_updated': '2026-01-01T00:00:00Z'}])
    ours = copy.deepcopy(base)
    theirs = document(filters=[{'name': 'A', 'url': 'https://example.invalid/a.txt', 'enabled': True,
                                'id': 7, 'rules_count': 4096, 'last_updated': '2026-09-08T10:00:00Z'}],
                      querylog__interval='1440m',
                      users=[{'name': 'admin', 'password': '$2y$10$hash'},
                             {'name': 'opnsense-ha', 'password': '$2y$10$managed'}])
    merged, adopted, conflicts = merge.three_way(base, ours, theirs, True)
    if adopted or conflicts:
        raise RuntimeError('A generated member was treated as a change: ' + str(adopted or conflicts))
    if merged['filters'][0]['id'] != 1 or merged['users'] != ours['users']:
        raise RuntimeError('A generated member was copied from the peer.')
    if merge.drift(base, theirs):
        raise RuntimeError('A generated member counts as drift: ' + str(merge.drift(base, theirs)))


def test_adopted_values_keep_their_notation():
    """An adopted leaf is written the way the peer's AdGuard Home wrote it."""
    base = document()
    ours = document()
    theirs = document(querylog__interval='72h', filters=[{'name': 'B', 'url': 'https://example.invalid/b.txt',
                                                          'enabled': True, 'id': 7, 'rules_count': 3}])
    merged, adopted, _conflicts = merge.three_way(base, ours, theirs, True)
    if adopted != ['filters', 'querylog.interval']:
        raise RuntimeError('The adopted leaves are wrong: ' + str(adopted))
    if merged['querylog']['interval'] != '72h':
        raise RuntimeError('An adopted duration was rewritten: ' + str(merged['querylog']['interval']))
    if merged['filters'] != theirs['filters']:
        raise RuntimeError('An adopted list was not taken as a whole.')


def test_without_a_base():
    ours = document(user_rules=['||ours.example.invalid^'])
    theirs = document(user_rules=['||theirs.example.invalid^'], filtering__blocking_mode='nxdomain')
    merged, adopted, conflicts = merge.three_way(None, ours, theirs, False)
    if adopted or conflicts:
        raise RuntimeError('A merge without a base adopted something.')
    if merged != ours:
        raise RuntimeError('A merge without a base changed the document.')
    if merged is ours:
        raise RuntimeError('A merge without a base returned the caller document itself.')


def test_drift_and_differing():
    base = document()
    current = document(user_rules=['||local.example.invalid^'], dns__bind_hosts=['10.0.2.9'],
                       filtering__filtering_enabled=False)
    local = merge.drift(base, current)
    if local != ['filtering.filtering_enabled', 'user_rules']:
        raise RuntimeError('The drift is wrong: ' + str(local))
    if merge.drift(base, base):
        raise RuntimeError('An unchanged document reports drift.')
    # Only the leaves the incoming document really replaces are reported.
    incoming = document(user_rules=['||local.example.invalid^'])
    if merge.differing(local, current, incoming) != ['filtering.filtering_enabled']:
        raise RuntimeError('An unchanged leaf was reported as overwritten.')
    if merge.differing(local, current, current):
        raise RuntimeError('A document was reported as differing from itself.')


def main():
    test_rows()
    test_local_keys_are_never_touched()
    test_generated_members_are_ignored()
    test_adopted_values_keep_their_notation()
    test_without_a_base()
    test_drift_and_differing()
    print('merge tests passed')


if __name__ == '__main__':
    main()
