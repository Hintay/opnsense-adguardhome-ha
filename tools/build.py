#!/usr/local/bin/python3
"""Build the OPNsense plugin without bundling the AdGuard Home executable."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
PACKAGE_NAME = 'os-adguardhome-ha'
PKG = '/usr/local/sbin/pkg'


def output(*args):
    return subprocess.check_output(args, text=True).strip()


def file_hash(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def makefile_value(name, default=None):
    content = (ROOT / 'Makefile').read_text(encoding='utf-8')
    match = re.search(r'^{}\s*=\s*(\S+)'.format(re.escape(name)), content, re.MULTILINE)
    if match:
        return match.group(1)
    if default is not None:
        return default
    raise RuntimeError('{} is missing from Makefile.'.format(name))


def plugin_version():
    version = makefile_value('PLUGIN_VERSION')
    revision = makefile_value('PLUGIN_REVISION', '0')
    return version if revision in ('', '0') else '{}_{}'.format(version, revision)


def package_metadata(path):
    try:
        name, version, origin = output(PKG, 'query', '-F', str(path), '%n|%v|%o').split('|')
    except (subprocess.CalledProcessError, ValueError) as error:
        raise RuntimeError('Unable to read the AdGuard Home package metadata.') from error
    if name != 'adguardhome':
        raise RuntimeError('The supplied dependency package is not named adguardhome.')
    return name, version, origin


def installed_metadata(package):
    name, version, origin = output(PKG, 'query', '%n|%v|%o', package).split('|')
    return name, version, origin


def collect_files(prefix, stage):
    files = {}
    for path in sorted(prefix.rglob('*')):
        if not path.is_file():
            continue
        executable = path.read_bytes().startswith(b'#!')
        path.chmod(0o755 if executable else 0o644)
        files['/' + path.relative_to(stage).as_posix()] = file_hash(path)
    return files


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--adguardhome-package', type=Path, required=True)
    parser.add_argument('--opnsense-version')
    parser.add_argument('--output', type=Path, default=ROOT / 'dist')
    args = parser.parse_args()
    if os.uname().sysname != 'FreeBSD':
        raise SystemExit('Run this builder on OPNsense or FreeBSD.')
    dependency_package = args.adguardhome_package.resolve()
    if not dependency_package.is_file():
        raise SystemExit('The AdGuard Home dependency package is unavailable.')
    dependency = package_metadata(dependency_package)
    args.output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='adguardhome-ha-plugin-') as temporary:
        temporary = Path(temporary)
        stage = temporary / 'root'
        prefix = stage / 'usr/local'
        shutil.copytree(
            ROOT / 'src',
            prefix,
            ignore=shutil.ignore_patterns('__pycache__', '*.pyc', '*.pyo'),
        )
        license_path = prefix / 'share/licenses' / PACKAGE_NAME / 'LICENSE'
        license_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / 'LICENSE', license_path)
        dependencies = {}
        package_binary = output(PKG, 'which', '-q', str(Path(sys.executable).resolve()))
        yaml_module = output(sys.executable, '-c', 'import yaml; print(yaml.__file__)')
        yaml_package = output(PKG, 'which', '-q', yaml_module)
        for package in (package_binary, yaml_package):
            name, version, origin = installed_metadata(package)
            dependencies[name] = {'version': version, 'origin': origin}
        if args.opnsense_version:
            dependencies['opnsense'] = {
                'version': args.opnsense_version,
                'origin': 'opnsense/opnsense',
            }
        else:
            name, version, origin = installed_metadata('opnsense')
            dependencies[name] = {'version': version, 'origin': origin}
        dependencies[dependency[0]] = {'version': dependency[1], 'origin': dependency[2]}
        scripts = {
            name: (ROOT / 'pkg' / name).read_text(encoding='utf-8')
            for name in ('pre-install', 'post-install', 'pre-deinstall', 'post-deinstall')
        }
        manifest = {
            'name': PACKAGE_NAME,
            'version': plugin_version(),
            'origin': 'opnsense/os-adguardhome-ha',
            'comment': 'AdGuard Home with authenticated state-sync replication',
            'desc': 'OPNsense integration for AdGuard Home with authenticated configuration replication over the state-synchronization network.',
            'maintainer': makefile_value('PLUGIN_MAINTAINER'),
            'www': makefile_value('PLUGIN_WWW'),
            'prefix': '/usr/local',
            'abi': output(PKG, 'config', 'ABI'),
            'licenses': ['BSD2CLAUSE'],
            'licenselogic': 'single',
            'deps': dependencies,
            'files': collect_files(prefix, stage),
            'scripts': scripts,
        }
        manifest_path = temporary / 'manifest.json'
        manifest_path.write_text(json.dumps(manifest), encoding='utf-8')
        subprocess.run([PKG, 'create', '-M', str(manifest_path), '-r', str(stage), '-o', str(args.output)], check=True)
    print(args.output / '{}-{}.pkg'.format(PACKAGE_NAME, plugin_version()))


if __name__ == '__main__':
    main()
