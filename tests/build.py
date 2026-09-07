#!/usr/local/bin/python3
"""Verify that the plugin package depends on but does not contain AdGuard Home."""

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
PKG = '/usr/local/sbin/pkg'


def file_hash(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def create_dependency(directory):
    stage = directory / 'dependency-root'
    executable = stage / 'usr/local/bin/adguardhome'
    executable.parent.mkdir(parents=True)
    executable.write_text('#!/bin/sh\nexit 0\n', encoding='utf-8')
    executable.chmod(0o755)
    manifest = {
        'name': 'adguardhome',
        'version': '0.0.test',
        'origin': 'www/adguardhome',
        'comment': 'Synthetic AdGuard Home dependency',
        'desc': 'Synthetic package used only by the plugin package test.',
        'maintainer': 'N/A',
        'www': 'https://github.com/AdguardTeam/AdGuardHome',
        'prefix': '/usr/local',
        'abi': subprocess.check_output([PKG, 'config', 'ABI'], text=True).strip(),
        'licenses': ['GPLv3'],
        'licenselogic': 'single',
        'files': {'/usr/local/bin/adguardhome': file_hash(executable)},
    }
    manifest_path = directory / 'dependency.json'
    manifest_path.write_text(json.dumps(manifest), encoding='utf-8')
    output = directory / 'dependency'
    output.mkdir()
    subprocess.run([PKG, 'create', '-M', str(manifest_path), '-r', str(stage), '-o', str(output)], check=True)
    return output / 'adguardhome-0.0.test.pkg'


def main():
    for script in ('settings.py', 'dns_settings.py'):
        content = (ROOT / 'src/opnsense/scripts/Adguardhome' / script).read_text(encoding='utf-8')
        if '/conf/config.xml' in content or 'ElementTree' in content:
            raise RuntimeError(script + ' directly reads the OPNsense configuration file.')
    with tempfile.TemporaryDirectory(prefix='adguardhome-ha-package-test-') as temporary:
        temporary = Path(temporary)
        dependency = create_dependency(temporary)
        output = temporary / 'dist'
        subprocess.run([
            sys.executable, str(ROOT / 'tools/build.py'),
            '--adguardhome-package', str(dependency),
            '--opnsense-version', '26.7',
            '--output', str(output),
        ], check=True)
        package = output / 'os-adguardhome-ha-1.1.pkg'
        if not package.is_file():
            raise RuntimeError('The plugin package was not created.')
        manifest = json.loads(subprocess.check_output(['tar', '-xOf', str(package), '+COMPACT_MANIFEST'], text=True))
        if manifest.get('www') != 'https://github.com/Hintay/opnsense-adguardhome-ha':
            raise RuntimeError('The plugin package has an unexpected project URL.')
        if 'conflicts' in manifest:
            raise RuntimeError('The plugin package contains unsupported conflict metadata.')
        annotations = manifest.get('annotations', {})
        if annotations.get('product_id') != 'os-adguardhome-ha':
            raise RuntimeError('The plugin package is missing its OPNsense product metadata.')
        if annotations.get('product_version') != '1.1':
            raise RuntimeError('The plugin package has an unexpected OPNsense product version.')
        if 'os-adguardhome-maxit' not in annotations.get('product_conflicts', '').split():
            raise RuntimeError('The plugin package does not replace the previous AdGuard Home plugin.')
        contents = subprocess.check_output([PKG, 'info', '-lF', str(package)], text=True)
        if '/usr/local/bin/adguardhome' in contents or '/usr/local/AdGuardHome/AdGuardHome' in contents:
            raise RuntimeError('The plugin package contains an AdGuard Home executable.')
        if '/usr/local/opnsense/scripts/Adguardhome/dns_settings.py' not in contents:
            raise RuntimeError('The plugin package is missing its OPNsense integration.')
        if '/usr/local/opnsense/version/adguardhome-ha' not in contents:
            raise RuntimeError('The plugin package is missing its OPNsense product file.')
        if '/usr/local/share/licenses/os-adguardhome-ha/LICENSE' not in contents:
            raise RuntimeError('The plugin package is missing the BSD 2-Clause license.')
        dependencies = subprocess.check_output([PKG, 'info', '-dF', str(package)], text=True)
        if 'adguardhome-0.0.test' not in dependencies:
            raise RuntimeError('The plugin package does not depend on adguardhome.')
        if '__pycache__' in contents or '.pyc' in contents:
            raise RuntimeError('The plugin package contains Python bytecode cache files.')
    print('plugin package build test passed')


if __name__ == '__main__':
    main()
