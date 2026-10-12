# Network helper implementation

The fixed-action root helper listens on /run/inextos-clash-helper/helper.sock, owned by root:inextos-clash with mode 0660. The directory is root-owned mode 0750. The request is a single JSON object with one action and a 4 KiB limit.

Allowed actions are Mihomo start/stop/restart, TUN status/diagnostics/enable/disable, and network rollback preparation, confirmation, abort, and rollback. The settings API validates network input in the unprivileged Backend; the helper receives no user-supplied command or arguments. Helper actions invoke a fixed systemctl unit/action list without a shell.

The Backend remains unprivileged with no capabilities. Only inextos-clash-mihomo.service receives CAP_NET_ADMIN and /dev/net/tun; it runs as inextos-clash, not root. The helper itself has no CAP_NET_ADMIN.

Before any unconfirmed TUN, LAN proxy, or DNS takeover enable, the helper snapshots the prior generated config and runtime state and arms inextos-clash-network-rollback.timer for four minutes. The rollback stops only the dedicated Mihomo unit, restores those application files with every capture flag off, and restarts the Backend. Mihomo owns cleanup of its TUN routes and auto-redirect rules. The helper never flushes nftables or edits routes/rules directly.
