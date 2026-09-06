# AdGuard Home High Availability for OPNsense

AdGuard Home High Availability adds AdGuard Home service management and authenticated configuration synchronization to the OPNsense web interface.

This repository also publishes the package feed used to install and update both the plugin and the AdGuard Home runtime:

- Project: [github.com/Hintay/opnsense-adguardhome-ha](https://github.com/Hintay/opnsense-adguardhome-ha)
- Package repository: [hintay.github.io/opnsense-adguardhome-ha](https://hintay.github.io/opnsense-adguardhome-ha/)
- Runtime source: [github.com/Hintay/opnsense-adguardhome-runtime](https://github.com/Hintay/opnsense-adguardhome-runtime)

This is an independent community project. It is not part of the official OPNsense package repository and is not affiliated with or endorsed by Deciso B.V. or AdGuard Software Ltd.

## Features

- Manages AdGuard Home through the standard OPNsense service controls.
- Configures one or more IPv4 or IPv6 DNS listen addresses and the DNS port.
- Offers addresses assigned to OPNsense interfaces, including CARP addresses.
- Synchronizes `AdGuardHome.yaml` between an OPNsense high-availability pair.
- Uses the OPNsense state synchronization network for synchronization traffic.
- Authenticates synchronization with a pairing secret and a pinned TLS certificate fingerprint.
- Validates received configuration before applying it and restores the previous file if AdGuard Home cannot restart.
- Provides runtime status, OPNsense log tables, and English and Simplified Chinese interfaces.

## Compatibility

The current packages target OPNsense 26.7 on `FreeBSD:15:amd64`. Both high-availability nodes should run the same OPNsense release and plugin version. A new package build is required when OPNsense changes its FreeBSD ABI.

The package feed contains:

| Package | Purpose |
| --- | --- |
| `os-adguardhome-ha` | OPNsense UI, service integration, and configuration synchronization |
| `adguardhome` | Official AdGuard Home FreeBSD amd64 executable |

Installing `os-adguardhome-ha` automatically installs `adguardhome` from the same package repository.

## How high availability works

AdGuard Home does not provide a native cluster. This plugin combines two independent AdGuard Home instances with the existing OPNsense high-availability configuration.

Both nodes run AdGuard Home and keep the same configuration. DNS clients use a shared CARP address rather than either node's individual address. The current CARP master owns that address and answers DNS requests. After OPNsense moves the CARP address to the other node, new DNS requests are handled by the AdGuard Home instance already running there.

Configuration synchronization is one-way. The OPNsense node configured with **Synchronize Config to IP** sends `AdGuardHome.yaml` to its peer before a failover is needed. Changing the CARP master does not change which node supplies the configuration.

A shared CARP address is required for a stable DNS endpoint. Without one, the plugin can still synchronize configuration, but clients do not automatically move between DNS servers. The plugin does not create CARP addresses or trigger a CARP failover when only the AdGuard Home service becomes unavailable.

Query logs, statistics, cache entries, and active connections are local to each node. New DNS requests continue after CARP failover, while requests already in progress may need to retry.

## Requirements

- Two compatible OPNsense amd64 systems.
- OPNsense state synchronization configured between the nodes.
- A working `pfsync0` interface with an IPv4 address and an IPv4 `syncpeer`.
- **Synchronize Config to IP** configured on the node that supplies the AdGuard Home configuration.
- The selected synchronization TCP port allowed between the state synchronization addresses.
- Shared CARP addresses configured separately when DNS failover is required.

The plugin does not create CARP addresses, configure `pfsync0`, add firewall rules, manage PPPoE sessions, or change the OPNsense high-availability configuration.

## Installation

Run these commands in an OPNsense shell:

```sh
install -d -m 0755 /usr/local/etc/pkg/keys
fetch -o /usr/local/etc/pkg/keys/adguardhome-ha.pub \
  https://hintay.github.io/opnsense-adguardhome-ha/adguardhome-ha.pub
fetch -o /usr/local/etc/pkg/repos/adguardhome-ha.conf \
  https://hintay.github.io/opnsense-adguardhome-ha/adguardhome-ha.conf
pkg update -f
pkg install os-adguardhome-ha
```

Refresh the OPNsense browser session after installation, then open **Services > AdGuard Home**.

On a new installation, start AdGuard Home once from the page header. Open its setup page on TCP port `3000`, finish the initial setup, and return to the OPNsense settings page.

Do not lock either package when using this repository. Package locks prevent updates.

## DNS service setup

Open **Services > AdGuard Home > Settings** on each node.

1. Enable AdGuard Home.
2. Select one or more DNS listen addresses.
3. Set the DNS listen port. DNS normally uses port `53`.
4. Select **Save and apply**.

For DNS failover, select the same shared CARP IPv4 and IPv6 addresses on both nodes. CARP controls which node owns the addresses, while AdGuard Home can remain running on both nodes.

Only one DNS service can use an address and port combination. Stop Unbound DNS or Dnsmasq, or configure it to use different addresses or ports.

## Configuration synchronization

Open **Services > AdGuard Home > Synchronize Config** on both nodes.

The node with an OPNsense **Synchronize Config to IP** target supplies the configuration. The peer without that target receives it. A CARP state change does not reverse the synchronization direction.

Configure the receiving node first:

1. Generate a pairing secret and copy it before saving.
2. Enable configuration synchronization.
3. Enter the synchronization port and pairing secret.
4. Select **Save and apply**.
5. Copy the certificate fingerprint shown under **Runtime**.

Then configure the source node:

1. Enable configuration synchronization.
2. Enter the same port and pairing secret.
3. Paste the receiver certificate fingerprint.
4. Select **Save and apply**.
5. Select **Synchronize now** and confirm that the result is `updated` or `unchanged`.

The complete `AdGuardHome.yaml` file is synchronized. This includes filters, rewrites, clients, upstream servers, DNS listeners, UI authentication, and other settings stored in that file. Query logs, statistics, cache data, downloaded filter contents, and external certificate files are not copied. Referenced files must exist at the same paths on both nodes.

The source sends the file after it changes and once when the synchronization service starts. Failed automatic attempts retry after five minutes. The receiver continues serving DNS with its last valid configuration while the source is unavailable.

## Updating

Check and install updates through OPNsense package management:

```sh
pkg update
pkg upgrade
```

The plugin and runtime use separate version numbers. AdGuard Home's built-in executable updater is disabled because the `adguardhome` package owns the executable and supplies updates through this repository.

## Logs and troubleshooting

Use these OPNsense pages:

- **Services > AdGuard Home > Settings** for DNS service settings.
- **Services > AdGuard Home > Synchronize Config** for synchronization settings and runtime status.
- **Services > AdGuard Home > Log File** for synchronization logs.

Useful shell commands:

```sh
service adguardhome onestatus
service adguardhome_sync onestatus
configctl adguardhomesync status
configctl adguardhomesync sync
pkg info adguardhome os-adguardhome-ha
```

Configuration backups are stored at:

```text
/usr/local/AdGuardHome/AdGuardHome.yaml.before-opnsense
/usr/local/AdGuardHome/AdGuardHome.yaml.before-sync
```

These files can contain credentials and should be protected like the active configuration.

## Migrating from another AdGuard Home plugin

Back up `/usr/local/AdGuardHome/AdGuardHome.yaml`, stop AdGuard Home, and remove the previous plugin before installing this package. Plugins that provide the same service or executable cannot be installed together.

This plugin requires the executable at `/usr/local/bin/adguardhome` and does not support executable paths used by older bundled packages.

## Security

Keep the synchronization listener on the state synchronization network. Protect the pairing secret, repository signing key, AdGuard Home configuration, and backup files. Restrict access to the AdGuard Home administration interface and keep OPNsense and both packages current.

Security reports are described in [SECURITY.md](SECURITY.md).

## License

The plugin is licensed under the BSD 2-Clause License. See [LICENSE](LICENSE) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). The installed package includes the license at `/usr/local/share/licenses/os-adguardhome-ha/LICENSE`. AdGuard Home is distributed separately under GPLv3.

Development and release instructions are in [CONTRIBUTING.md](CONTRIBUTING.md).
