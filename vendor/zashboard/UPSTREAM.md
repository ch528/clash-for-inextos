# Zashboard pinned release

- Upstream: https://github.com/Zephyruso/zashboard
- Tag: `v3.29.1`
- Release asset: https://github.com/Zephyruso/zashboard/releases/download/v3.29.1/dist.zip
- SHA-256: `4f16cce229e223bd07b5a3daccfbfb8bf349d7335572d412959284ab6c9bab50`
- Release commit shown by GitHub: `50717b0`

The archive contains the built static site under `dist/`, including
`THIRD_PARTY_NOTICES.md`. The Debian package installs these files unchanged
under `/opt/inextos-clash/dashboard/`. The application adds a same-origin
bootstrap path at request time and reverse-proxies the API through its
authenticated Backend; it does not put the Mihomo Controller secret in the
browser.

This release documents the `disableUpgradeCore` and `disableTunMode` URL
parameters. The integration sets both parameters to `1`.
