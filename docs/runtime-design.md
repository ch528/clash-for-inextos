# Phase 3 — Isolated Mihomo Runtime

## Development layout

The tracked repository is `/root/inextos-clash-dev/source`. Runtime files are staged separately under `/root/inextos-clash-dev/build/devroot` using the intended installation layout:

```text
opt/inextos-clash/bin/mihomo
opt/inextos-clash/bin/inextos-clash-server
opt/inextos-clash/web/
etc/inextos-clash/app.json
etc/inextos-clash/mihomo/minimal-safe.yaml
var/lib/inextos-clash/state/
var/lib/inextos-clash/mihomo/
```

Nothing in this phase is installed into `/usr/bin`, `/usr/local/bin`, `/opt`, `/etc`, or `/var/lib`. The production systemd identity is designed as `inextos-clash:inextos-clash` with no `CAP_NET_ADMIN`; this development phase does not create the account or service.

## Upstream and binary provenance

- `wnlen/clash-for-linux` remains pinned at `42c26d8ad44373980ef3e6c4113de3beedb3d876`.
- That commit's architecture/version rule selects `mihomo-linux-arm64-v1.19.23.gz` for this device.
- Release asset: [Mihomo v1.19.23](https://github.com/MetaCubeX/mihomo/releases/tag/v1.19.23).
- The GitHub release API supplied a SHA-256 digest for the compressed asset; both that value and the observed binary SHA-256 are recorded in `phase3-5-test-report.md`.
- Go is only a temporary build tool under `/root/inextos-clash-dev/tools`; it is not installed system-wide.

## Ports and configuration

The runtime allocator probes TCP and, for Mixed Port, UDP listeners before selecting a port. Mixed Port candidates are `17890–17920`; External Controller candidates are `9091–9120`, with `9091` first as requested. The selection is persisted to `state/runtime.json` and returned by the API for the UI to display.

The generated initial config uses `bind-address: 127.0.0.1`, `allow-lan: false`, and `external-controller: 127.0.0.1:<selected port>`. It sets `tun.enable: false`, IPv6 off, contains no DNS section, and routes `MATCH` to `DIRECT`. No subscription is imported on first start.

The Controller key is generated from 32 random bytes, stored as hex in `state/controller-secret` with mode `0600`, and written into the Mihomo config file with mode `0600`. The backend does not return the key in any API response.

The backend is started directly with the Mihomo binary and fixed `-f <config> -d <runtime-dir>` arguments. The upstream `install.sh` and `clashon` are not used.
