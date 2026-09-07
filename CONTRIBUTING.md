# Contributing

## Repository information

- Repository name: `opnsense-adguardhome-ha`
- Description: `AdGuard Home integration and authenticated configuration synchronization for OPNsense high-availability pairs.`
- Homepage: `https://hintay.github.io/opnsense-adguardhome-ha/`
- Default branch: `main`
- Topics: `opnsense`, `adguard-home`, `dns`, `high-availability`, `freebsd`, `carp`, `pfsync`

Use Conventional Commits for commit messages, for example:

```text
feat: add AdGuard Home high-availability plugin
fix: preserve DNS listener selection
docs: clarify package repository installation
```

## Build and test

The plugin builder never downloads or embeds AdGuard Home. Provide an existing `adguardhome` package so its package metadata can be recorded as a dependency:

```sh
python3 tools/check_release.py
python3 tools/build.py \
  --adguardhome-package /path/to/adguardhome-VERSION.pkg \
  --opnsense-version 26.7
python3 tests/settings.py
python3 tests/dns_settings.py
python3 tests/merge.py
python3 tests/api_account.py
python3 tests/agh_api.py
python3 tests/syncd_receiver.py
python3 tests/syncd_e2e.py
python3 tests/build.py
ADGUARDHOME_BIN=/path/to/adguardhome python3 tests/agh_contract.py
```

`tests/agh_contract.py` starts the given AdGuard Home executable on loopback high ports and requires every setting that the API hot-update mapping in `src/opnsense/scripts/Adguardhome/agh_api.py` knows to converge through the API. It is skipped when `ADGUARDHOME_BIN` is unset and runs in the release workflow against the runtime package being published, so a new AdGuard Home release that renames an API field or changes a value notation fails the release instead of silently falling back to file replacement on installed systems.

Run the build and tests on the FreeBSD release used by the target OPNsense version. Build output is written to `dist/` and is not committed. The Python tests also run on macOS or Linux with PyYAML installed.

## Versions

The plugin version is defined by `PLUGIN_VERSION` and optional `PLUGIN_REVISION` in `Makefile`. Release tags use the generated package version:

```text
v1.0
v1.0_1
```

The source declares the unversioned dependency `PLUGIN_DEPENDS= adguardhome`. FreeBSD package metadata records the runtime version used during the build.

## GitHub Actions

The repository contains these workflows:

- `ci.yml` tests the services and package assembly on FreeBSD.
- `release.yml` publishes a tagged plugin package and invokes the repository publisher.
- `publish-repository.yml` assembles and signs the public package repository.

Configure these repository settings:

- Variable `ADGUARDHOME_PACKAGE_REPOSITORY`: `Hintay/opnsense-adguardhome-runtime`.
- Secret `PKG_REPOSITORY_SIGNING_KEY`: RSA private key used by `pkg repo`.
- Optional secret `PACKAGE_READ_TOKEN`: needed only when either source repository is private.

Enable GitHub Pages with **GitHub Actions** as its source. The publisher uses the latest `.pkg` release asset from each repository, writes a signed package index, and deploys it to `https://hintay.github.io/opnsense-adguardhome-ha/`.

The publisher runs after a plugin release, after an `adguardhome-published` repository dispatch from the runtime repository, or when started manually. It does not use a scheduled trigger. Historical packages remain attached to their GitHub Releases and are not added to the active package index.

## Release

1. Confirm that CI passes on `main`.
2. Confirm that the runtime repository has a current package release.
3. Create and push a tag matching the plugin package version.
4. Verify the GitHub Release assets and the Pages deployment.
5. Install from the published repository on a compatible OPNsense test system.
