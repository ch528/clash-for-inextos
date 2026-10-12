# Upgrade

The formal package `inextos-clash_1.0.0_arm64.deb` upgrades earlier releases in place. It also supports the final transition from a `1.0.0-N` development package, even though Debian sorts that revision above `1.0.0`. It retains `/etc/inextos-clash/app.yaml`, administrator credentials, runtime port selection and controller secret under `/var/lib/inextos-clash/state`, subscription records, downloaded subscription configurations, Mihomo data, and certificates outside the package directories.

```sh
sudo apt install --allow-downgrades ./inextos-clash_1.0.0_arm64.deb
sudo inextos-clash version
sudo systemctl status inextos-clash.service inextos-clash-helper.service
```

The package restarts its own management service. It does not reboot the router or modify sing-box, Docker, IPTV, Nginx configuration, or RoceOS data.

The Update Center can also install a newer stable package from the public
`ch528/clash-for-inextos` release source. It verifies the GitHub asset digest,
Debian package identity, version, and ARM64 architecture before installation.
The final `1.0.0` release is explicitly ordered after the `1.0.N` development
builds by the app updater; its verified package installation permits the
corresponding Debian version downgrade.
If the currently installed development build was never published as a GitHub
release, stage its exact ARM64 `.deb` as the root-only file
`/var/lib/inextos-clash-app-update/rollback-source.deb` before starting the
transition. The updater validates this copy and keeps it as the rollback
package. Published current versions are fetched from their GitHub release.
The updater keeps the currently installed release package for rollback, keeps
the existing `app.yaml`, restarts the management service without rebooting the
router, and restores the previous package if the health check fails. Network
capture must be off before starting an application update.
