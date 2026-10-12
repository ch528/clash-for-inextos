# Clash for iNextOS 1.0.0

Clash for iNextOS manages Mihomo's lifecycle, subscriptions, and device level network settings on iNextOS. Zashboard provides proxy groups, node selection, connections, rules, traffic detail, and Mihomo logs through an authenticated same-origin proxy.

## Navigation

- 概览: service state, mode, subscription, traffic, and device details.
- 订阅: save, validate, update, activate, schedule refreshes, and show provider quota/expiry metadata when supplied.
- Mihomo 控制台: open the pinned Zashboard release.
- 网络代理: configure and test TUN, then confirm or recover the network.
- 更新: check stable releases for Clash for iNextOS, Mihomo, Zashboard, and Geo data. The application package is verified against its fixed public GitHub release source and can be installed with automatic package rollback on a failed health check.
- 设置: administrator account, browser appearance, portable backup/restore, public IPv6 and HTTPS certificate status, advanced local ports, diagnostics, support-bundle download, and recent system events.
- 关于: component versions, runtime details, and licenses.

## Security boundary

The Web backend runs as `inextos-clash` with an empty capability set. The Mihomo TUN service is a separate systemd unit with `CAP_NET_ADMIN`; it is started only through the fixed root helper actions. Controller and Mixed Port stay bound to loopback. The controller secret remains server side.

Portable backups include subscription URLs and node credentials. Keep exported
files private. They exclude the administrator hash, Controller secret, and TLS
private key; restore preview validates the generated configs and apply leaves
Mihomo stopped with TUN disabled.

See [SECURITY.md](SECURITY.md), [NETWORK.md](NETWORK.md), and [TUN.md](TUN.md) before enabling network interception.

## Paths

- Program, Web UI, and Zashboard: `/opt/inextos-clash/`
- Application configuration: `/etc/inextos-clash/`
- Credentials, subscriptions, and runtime state: `/var/lib/inextos-clash/`
- Backend runtime files: `/run/inextos-clash/`
- Privileged helper socket: `/run/inextos-clash-helper/helper.sock`

`apt remove` keeps the application configuration and data. `apt purge` removes the application-owned configuration and data only.
