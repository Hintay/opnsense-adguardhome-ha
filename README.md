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
- Applies synchronized changes through the local AdGuard Home API without restarting DNS whenever the API supports them (filters, rules, rewrites, clients, blocked services, upstreams and most DNS settings).
- Falls back to replacing `AdGuardHome.yaml` and restarting AdGuard Home for settings the API cannot change, validates the file first, verifies that DNS is listening afterwards, and restores the previous file if it is not.
- Can defer such restarts while the receiving node owns the DNS CARP address and apply them when the node becomes backup.
- Learns the receiver certificate fingerprint automatically through the shared pairing secret when it is not entered manually.
- Keeps node-local settings (DNS listen addresses and port, web interface address, log and data paths) on each node.
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

The receiver compares the received file with its running configuration and chooses one of two update modes:

- **API hot update.** When the local AdGuard Home API is usable and every changed setting can be set through it, the receiver applies the changes through the API. Filters, custom rules, rewrites, clients, blocked services and most DNS settings are applied without any DNS interruption; changing upstreams, cache or rate limiting rebuilds the DNS listeners for about 100 ms. The receiver reads its configuration file back afterwards and only reports success when every change is present; otherwise it falls back to the file mode.
- **File replacement.** Settings without an API (for example TLS ports, web interface, users, DNS64, ipset) are applied by validating the file with `--check-config`, stopping AdGuard Home, replacing the file and starting it again. This interrupts DNS on the receiving node for the duration of the restart. If the receiving node is currently the CARP master and **Defer restarts while CARP master** is enabled, the change is staged instead and applied when the node becomes backup or when **Apply pending now** is selected.

Node-local settings are never overwritten by synchronization: DNS listen addresses and port, the web interface address, log settings and data directories always keep the receiver's own values.

### API credentials

The receiver needs access to its local AdGuard Home API for hot updates. Three cases are handled automatically:

- **Managed service account (default).** When the AdGuard Home web interface has authentication enabled, the plugin adds an administrator named `opnsense-ha` to each node's `AdGuardHome.yaml` the first time synchronization is applied, restarting AdGuard Home once. Its password and bcrypt salt are derived from the pairing secret, so nothing new is stored in the OPNsense configuration and rotating the pairing secret rotates the account. Existing users are kept; the account is only appended, and it is removed again (with one more restart) when synchronization or API updates are disabled. The entry never counts as a difference between the nodes, and a file replacement from the source does not remove it.
- **Own credentials.** Enter an AdGuard Home user and password under **Synchronize Config** to use them instead of the managed account.
- **No authentication.** When AdGuard Home has no users configured, its API needs no credentials and the plugin never adds a user, so the web interface stays open as before.

When the AdGuard Home web interface is bound to a CARP address (for example `192.168.51.8:3000`), the receiver can only reach its own API while it is the CARP master, because FreeBSD routes connections to a backup CARP address to the current master. The plugin detects this on every update: while the receiver is master, changes are applied through the API without interruption; while it is backup, changes replace the file and restart AdGuard Home, which serves no clients in that state. No configuration change is required for this; binding the web interface to `0.0.0.0` or a node-local address enables API updates in both states.

AdGuard Home has no user roles; any API account is an administrator. The managed account gives no more access than the pairing secret already implies, because the secret is what both nodes trust each other with.

A shared CARP address is required for a stable DNS endpoint. Without one, the plugin can still synchronize configuration, but clients do not automatically move between DNS servers. The plugin does not create CARP addresses or trigger a CARP failover when only the AdGuard Home service becomes unavailable.

Query logs, statistics, cache entries, and active connections are local to each node. New DNS requests continue after CARP failover, while requests already in progress may need to retry.

## Requirements

- Two compatible OPNsense amd64 systems.
- OPNsense state synchronization configured between the nodes.
- A working `pfsync0` interface with an IPv4 address and an IPv4 `syncpeer`.
- **Synchronize Config to IP** configured on the node that supplies the AdGuard Home configuration.
- The selected synchronization TCP port allowed between the state synchronization addresses.
- Shared CARP addresses configured separately when DNS failover is required.
- AdGuard Home web interface authentication enabled on the receiving node when API hot updates should use the managed service account (see below); optionally an AdGuard Home administrator user of your own instead.

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

Configure the source node first:

1. Generate a pairing secret.
2. Enable configuration synchronization and enter the synchronization port.
3. Optionally enter an AdGuard Home administrator user and password of your own for API hot updates, and choose whether restarts should be deferred while this node is CARP master.
4. Select **Save and apply**.

Then configure the receiving node with the same port, pairing secret and API credentials, and select **Save and apply**. The plugin registers its synchronization settings with OPNsense high availability: enable **AdGuard Home synchronization settings** under **System > High Availability > Settings** and select **Synchronize and reconfigure** on the **Status** page to copy them to the peer instead of entering them twice. Note that OPNsense copies these settings on demand, not automatically on save, and that **Synchronize and restart all services** restarts every service on the peer.

The source node learns the receiver certificate fingerprint on the first connection. The receiver signs its fingerprint with the pairing secret, and the source pins the fingerprint after verifying that signature. To pin a fingerprint manually instead, copy the value shown under **Runtime** on the receiver into **Peer certificate fingerprint** on the source; a manually entered fingerprint always takes precedence.

Select **Synchronize now** on the source and confirm that the result is `hot`, `updated`, `unchanged` or `staged`.

Everything in `AdGuardHome.yaml` is synchronized except the node-local settings listed above. This includes filters, rewrites, clients, upstream servers, UI authentication, and other settings stored in that file. Query logs, statistics, cache data, downloaded filter contents, and external certificate files are not copied. Referenced files must exist at the same paths on both nodes. Because UI authentication is synchronized, the API credentials are the same on both nodes.

### Changes made on the receiver are merged back

Synchronization stays one-way, but changes made on the receiving node are not lost. Both nodes remember the last synchronized configuration. Before every push the source reads the receiver's current configuration through the authenticated synchronization link and performs a three-way comparison against that remembered base:

| Source since last sync | Receiver since last sync | Result |
| --- | --- | --- |
| unchanged | unchanged | nothing to do |
| unchanged | changed | the receiver's values are merged back into the source, applied to its AdGuard Home and then pushed |
| changed | unchanged | normal push |
| changed | changed | conflict: the node that currently owns the DNS CARP address wins; the other node's values are recorded |

This covers the common failover case: the source is down, the receiver is CARP master and the only reachable web interface, changes are made there, and when the source returns it merges those changes back before it pushes anything. Comparison happens per setting; a list such as the custom rules counts as one setting, so a conflict on the same list is decided as a whole. Node-local settings are never merged. The result of the last merge-back or conflict is shown under **Runtime**.

The receiver also protects itself: when an incoming push would replace settings that were changed locally since the last synchronization, it first saves its current file as `/usr/local/AdGuardHome/AdGuardHome.yaml.local-changes-<timestamp>` (the five most recent are kept) and reports the replaced settings under **Runtime**.

The source sends the file after it changes, once when the synchronization service starts, once an hour as a consistency check, and after every CARP state change of the node. Failed automatic attempts retry after five minutes. The receiver continues serving DNS with its last valid configuration while the source is unavailable. The receiver remembers the checksum of the last applied file, so repeated pushes of the same content are reported as `unchanged` even though AdGuard Home rewrites its configuration file on every start.

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
configctl adguardhomesync apply_pending
pkg info adguardhome os-adguardhome-ha
```

`configctl adguardhomesync status` reports the update mode, the last synchronization result and error, whether a staged configuration is waiting, and the learned peer fingerprint.

Configuration backups and state are stored at:

```text
/usr/local/AdGuardHome/AdGuardHome.yaml.before-opnsense
/usr/local/AdGuardHome/AdGuardHome.yaml.before-sync
/usr/local/AdGuardHome/AdGuardHome.yaml.pending
/usr/local/AdGuardHome/AdGuardHome.yaml.last-source
/usr/local/AdGuardHome/AdGuardHome.yaml.last-pushed
/usr/local/AdGuardHome/AdGuardHome.yaml.local-changes-<timestamp>
/usr/local/etc/adguardhome-sync.state.json
```

These files can contain credentials and should be protected like the active configuration.

## Migrating from another AdGuard Home plugin

Back up `/usr/local/AdGuardHome/AdGuardHome.yaml`, stop AdGuard Home, and remove the previous plugin before installing this package. Plugins that provide the same service or executable cannot be installed together.

This plugin requires the executable at `/usr/local/bin/adguardhome` and does not support executable paths used by older bundled packages.

## Security

Keep the synchronization listener on the state synchronization network; the receiver only accepts connections from the configured state synchronization peer and authenticates every request with the pairing secret. Protect the pairing secret (it also derives the managed `opnsense-ha` API account), any AdGuard Home API credentials you enter, the repository signing key, the AdGuard Home configuration, and the backup files. Restrict access to the AdGuard Home administration interface and keep OPNsense and both packages current.

Security reports are described in [SECURITY.md](SECURITY.md).

## License

The plugin is licensed under the BSD 2-Clause License. See [LICENSE](LICENSE) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). The installed package includes the license at `/usr/local/share/licenses/os-adguardhome-ha/LICENSE`. AdGuard Home is distributed separately under GPLv3.

Development and release instructions are in [CONTRIBUTING.md](CONTRIBUTING.md).
