#!/usr/bin/env python3
"""Validate plugin metadata and an optional Git tag."""

import argparse
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]


def makefile_value(name, default=None):
    content = (ROOT / 'Makefile').read_text(encoding='utf-8')
    match = re.search(r'^{}\s*=\s*(\S+)'.format(re.escape(name)), content, re.MULTILINE)
    if match:
        return match.group(1)
    return default


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--tag')
    args = parser.parse_args()
    if makefile_value('PLUGIN_NAME') != 'adguardhome-ha':
        raise SystemExit('Unexpected plugin package name.')
    if makefile_value('PLUGIN_DEPENDS') != 'adguardhome':
        raise SystemExit('The plugin must declare the unversioned adguardhome dependency.')
    if makefile_value('PLUGIN_WWW') != 'https://github.com/Hintay/opnsense-adguardhome-ha':
        raise SystemExit('Unexpected plugin project URL.')
    version = makefile_value('PLUGIN_VERSION')
    revision = makefile_value('PLUGIN_REVISION', '0')
    package_version = version if revision in ('', '0') else '{}_{}'.format(version, revision)
    if args.tag and args.tag != 'v' + package_version:
        raise SystemExit('The tag must be v{}.'.format(package_version))
    forbidden = (
        ROOT / 'src/usr/local/bin/adguardhome',
        ROOT / 'src/AdGuardHome/AdGuardHome',
    )
    if any(path.exists() for path in forbidden):
        raise SystemExit('The plugin source contains an AdGuard Home executable.')
    print(package_version)


if __name__ == '__main__':
    main()
