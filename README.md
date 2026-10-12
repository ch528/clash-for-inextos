# Clash for iNextOS

Clash for iNextOS is an ARM64 management application for Mihomo on iNextOS. It provides a web interface for subscriptions, proxy groups, runtime controls, backups, diagnostics, and component updates. Zashboard is served through the authenticated backend, which keeps the Mihomo controller secret on the device.

## Device and access

- Target: FriendlyElec NanoPi R5S running iNextOS.
- Internal iNextOS desktop shortcut: use the device's LAN address on port `18080` in `桌面内` mode.
- Separate HTTPS entry: port `8844`, served by the existing iNextOS Nginx configuration.
- Backend controller and Mihomo mixed port bind to loopback. TUN is opt-in and runs through a separate privileged helper.

The in-app update center checks stable application releases from [GitHub Releases](https://github.com/ch528/clash-for-inextos/releases). Downloads are checked against the release SHA-256 digest before installation; failed health checks restore the prior package.

TUN, LAN transparent proxying, and DNS takeover are separate opt-in settings. LAN and DNS use Mihomo's Linux TUN and auto-redirect support; all remain off by default and use the four-minute recovery window. See [docs/NETWORK.md](docs/NETWORK.md) and [docs/TUN.md](docs/TUN.md) for their scope and safeguards.

## Build and verify

Run backend checks from `backend/`:

```sh
go test ./...
go test -race ./...
go vet ./...
```

Build the frontend with pnpm:

```sh
pnpm --dir web build
```

Build the Debian package after the frontend build, with Go, `dpkg-deb`, and the pinned Mihomo binary available:

```sh
TARGET_ARCH=arm64 MIHOMO_BIN=/path/to/mihomo PACKAGE_VERSION=1.0.0-36 packaging/build-arm64.sh
```

When `PACKAGE_VERSION` is `1.0.0-N` and `VERSION` is unset, the About page displays `1.0.N` (for example, package revision `1.0.0-36` displays as `1.0.36`). The package is written to `build/`. Verify the package architecture, extracted binary hashes, bundled licenses, and runtime behavior before distributing it. See [docs/INSTALL.md](docs/INSTALL.md) and [docs/UPGRADE.md](docs/UPGRADE.md).

## Project documentation

- [Installation](docs/INSTALL.md) · [Upgrade](docs/UPGRADE.md) · [Recovery](docs/RECOVERY.md)
- [Network behavior](docs/NETWORK.md) · [TUN safety](docs/TUN.md) · [Security](docs/SECURITY.md)
- [Backend API](docs/backend-api.md) · [iNextOS shortcut](docs/inextos-shortcut.md)
