# iNextOS Desktop shortcut

Create the shortcut through the signed-in iNextOS Desktop UI. Do not edit the RoceOS SQLite database. Package removal does not delete the shortcut; remove it manually in the same UI.

## Values

- **Name:** `Clash`
- **URL:** `http://<router-LAN-address>:18080/`. Use the router's current LAN address; the packaged app configuration lists the address used by its iNextOS Desktop integration.
- **Icon:** Use the package's custom `inextos-clash.png` icon in the shortcut's image picker. If the field accepts an image URL, use the same host and backend port with `/icon-128.png`.
- **Open Mode:** Choose `桌面内` to open an internal desktop window.

The public HTTPS entry on port `8844` is a separate access path and remains independent from the internal desktop shortcut.
