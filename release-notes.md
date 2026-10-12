# Clash for iNextOS 1.0.0

Final ARM64 release for iNextOS on the NanoPi R5S.

- Manage Mihomo, subscriptions, proxy groups, backups, diagnostics, and component updates from the local web interface.
- Download and refresh subscriptions through the active Mihomo proxy when available, then use a bounded direct fallback. In Rule mode, rule providers without their own proxy follow the subscription's final policy group.
- Verify public subscription and rule-provider destinations, test downloaded configurations before activation, and preserve the working configuration when an update fails.
- Install application updates from GitHub Releases after checking the SHA-256 digest, Debian package identity, and ARM64 architecture. The updater supports the final transition from `1.0.N` development builds to `1.0.0` and retains a rollback package.
- Configure IPv4/IPv6 TUN routing, MTU, Auto Route, Auto Redirect, and Strict Route. LAN proxy and DNS takeover remain opt-in and protected by the four-minute recovery window.
- Open Clash from the iNextOS desktop in an internal window through the existing shortcut integration. Public HTTPS on port `8844` remains a separate entry point.
- Use the upstream Zashboard proxy-group icons and the aligned, responsive subscription controls.

Debian package: `inextos-clash_1.0.0_arm64.deb` (ARM64). The About page reports version `1.0.0`.
