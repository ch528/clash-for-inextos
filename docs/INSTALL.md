# Install

Target: NanoPi R5S, iNextOS 2.9.5, ARM64.

```sh
sudo apt install ./inextos-clash_1.0.0-31_arm64.deb
sudo inextos-clash ports
```

The filename includes the Debian revision; substitute the revision of the package you are installing.

When `VERSION` is unset, a Debian revision `1.0.0-N` is shown in About as `1.0.N` (for example, `1.0.0-31` appears as `1.0.31`).

The package enables the unprivileged management service and the fixed-action helper. It does not enable TUN or LAN interception by default.

On a trusted LAN URL, create the administrator directly. On the public HTTPS URL, first run:

```sh
sudo inextos-clash setup-open
```

The public initialization window closes after ten minutes or immediately after the first administrator is created. Use a username of 3–32 ASCII letters, digits, dot, underscore, or hyphen; passwords must contain at least 8 characters.

For the iNextOS application shortcut, follow [inextos-shortcut.md](inextos-shortcut.md).
