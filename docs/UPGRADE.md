# Upgrade

The Debian package `inextos-clash_1.0.0-35_arm64.deb` upgrades an earlier package in place. Substitute the Debian revision in the filename when using a later package. It retains `/etc/inextos-clash/app.yaml`, administrator credentials, runtime port selection and controller secret under `/var/lib/inextos-clash/state`, subscription records, downloaded subscription configurations, Mihomo data, and certificates outside the package directories.

```sh
sudo apt install ./inextos-clash_1.0.0-35_arm64.deb
sudo inextos-clash version
sudo systemctl status inextos-clash.service inextos-clash-helper.service
```

The package restarts its own management service. It does not reboot the router or modify sing-box, Docker, IPTV, Nginx configuration, or RoceOS data.

The Update Center can also install a newer stable package from the public
`ch528/clash-for-inextos` release source. It verifies the GitHub asset digest,
Debian package identity, version, and ARM64 architecture before installation.
The updater keeps the currently installed release package for rollback, keeps
the existing `app.yaml`, restarts the management service without rebooting the
router, and restores the previous package if the health check fails. Network
capture must be off before starting an application update.
